//! Incremental declared-name resolution driven by a single proxy event loop.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use proofbound_runtime_core::{
    AddressScope, EgressName, PinnedAnswer, PinnedResolution, ResolutionPolicy, ServiceName,
    Sha256Digest, answer_is_admissible,
};
use sha2::{Digest as _, Sha256};

use super::budget::ProxyBudget;
use super::dns::{
    DnsAddressRecord, DnsCnameRecord, DnsQuery, DnsRecordType, DnsWireError, parse_dns_response,
};

/// One response message identity, retained without packet bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsMessageFact {
    pub identity: Sha256Digest,
    pub size: u16,
    pub finished_ms: u64,
}

/// A terminal address with its record and alias-chain expiry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsAnswerFact {
    pub address: IpAddr,
    pub ttl_seconds: u32,
    pub record_expiry_ms: u64,
    pub effective_expiry_ms: u64,
    pub message_identity: Sha256Digest,
    pub admissible: bool,
}

/// One closed resolution outcome retained even when no address is usable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsResolutionOutcome {
    Answered,
    Failed,
    NoAdmissibleAnswer,
}

impl DnsResolutionOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::Failed => "failed",
            Self::NoAdmissibleAnswer => "no-admissible-answer",
        }
    }
}

/// One complete resolution result ready for scope and attempt decisions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsResolutionFacts {
    pub index: u16,
    pub name: EgressName,
    pub triggering_connection: u64,
    pub started_ms: u64,
    pub finished_ms: u64,
    pub messages: Vec<DnsMessageFact>,
    pub cname_chain: Vec<DnsCnameRecord>,
    pub answers: Vec<DnsAnswerFact>,
    pub outcome: DnsResolutionOutcome,
}

impl DnsResolutionFacts {
    #[must_use]
    pub fn pinned(&self) -> PinnedResolution {
        PinnedResolution {
            name: self.name.clone(),
            triggering_connection: self.triggering_connection,
            answers: self
                .answers
                .iter()
                .filter(|answer| answer.admissible)
                .map(|answer| PinnedAnswer {
                    address: answer.address,
                    effective_expiry_ms: answer.effective_expiry_ms,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug)]
struct ResolutionSlot {
    current: Option<DnsResolutionFacts>,
    in_flight: Option<u16>,
    waiters: Vec<u16>,
}

/// The three outcomes of asking for a declared name's current resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolutionRequest {
    Reuse(DnsResolutionFacts),
    Wait,
    Start,
}

/// One current record and at most one in-flight request per declared name.
#[derive(Clone, Debug, Default)]
pub struct ResolutionCoordinator {
    names: BTreeMap<EgressName, ResolutionSlot>,
}

impl ResolutionCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Only a caller that has already matched a declared endpoint may enter.
    /// The event loop must call `started` after reserving its resolution bound.
    pub fn request(
        &mut self,
        name: &EgressName,
        connection: u16,
        attempt_start_ms: u64,
    ) -> ResolutionRequest {
        let slot = self.names.entry(name.clone()).or_insert(ResolutionSlot {
            current: None,
            in_flight: None,
            waiters: Vec::new(),
        });
        if let Some(current) = &slot.current
            && current.outcome == DnsResolutionOutcome::Answered
            && current
                .answers
                .iter()
                .any(|answer| answer.admissible && answer.effective_expiry_ms > attempt_start_ms)
        {
            return ResolutionRequest::Reuse(current.clone());
        }
        if !slot.waiters.contains(&connection) {
            slot.waiters.push(connection);
        }
        if slot.in_flight.is_some() {
            ResolutionRequest::Wait
        } else {
            ResolutionRequest::Start
        }
    }

    /// Marks the single started resolution after its budget reservation.
    pub fn started(&mut self, name: &EgressName, index: u16) -> Result<(), DnsResolutionError> {
        let slot = self
            .names
            .get_mut(name)
            .ok_or(DnsResolutionError::NoQueryPending)?;
        if slot.in_flight.is_some() || slot.waiters.is_empty() {
            return Err(DnsResolutionError::QueryPending);
        }
        slot.in_flight = Some(index);
        Ok(())
    }

    /// Publishes a complete record to all waiting connections exactly once.
    pub fn complete(&mut self, facts: DnsResolutionFacts) -> Result<Vec<u16>, DnsResolutionError> {
        let slot = self
            .names
            .get_mut(&facts.name)
            .ok_or(DnsResolutionError::NoQueryPending)?;
        if slot.in_flight != Some(facts.index) {
            return Err(DnsResolutionError::NoQueryPending);
        }
        slot.in_flight = None;
        slot.current = Some(facts);
        Ok(std::mem::take(&mut slot.waiters))
    }

    /// Releases waiters when a resolution cannot start or its transport fails.
    #[must_use]
    pub fn abort(&mut self, name: &EgressName) -> Vec<u16> {
        let Some(slot) = self.names.get_mut(name) else {
            return Vec::new();
        };
        slot.in_flight = None;
        std::mem::take(&mut slot.waiters)
    }
}

/// A fail-closed incremental resolution outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsResolutionError {
    Deadline,
    QueryPending,
    NoQueryPending,
    Complete,
    MessageLimit,
    ResolutionLimit,
    Wire(DnsWireError),
    CnameConflict,
    CnameDepth,
    CnameLoop,
    AnswerCount,
    NoAnswer,
    NoAdmissibleAnswer,
}

impl From<DnsWireError> for DnsResolutionError {
    fn from(error: DnsWireError) -> Self {
        Self::Wire(error)
    }
}

#[derive(Clone, Debug)]
struct FamilyState {
    current: ServiceName,
    visited: BTreeSet<ServiceName>,
    chain: Vec<DnsCnameRecord>,
    answers: Vec<DnsAddressRecord>,
    complete: bool,
}

impl FamilyState {
    fn new(initial: &ServiceName) -> Self {
        Self {
            current: initial.clone(),
            visited: BTreeSet::from([initial.clone()]),
            chain: Vec::new(),
            answers: Vec::new(),
            complete: false,
        }
    }
}

/// One at-a-time A then AAAA state machine. The caller drives TCP without
/// blocking other tunnels and supplies unpredictable transaction identifiers.
#[derive(Clone, Debug)]
pub struct DnsResolutionMachine {
    index: u16,
    name: EgressName,
    scope: AddressScope,
    triggering_connection: u64,
    started_ms: u64,
    deadline_ms: u64,
    maximum_cname_depth: u16,
    maximum_answer_count: u16,
    maximum_response_bytes: u64,
    ipv4: FamilyState,
    ipv6: FamilyState,
    pending: Option<DnsQuery>,
    messages: Vec<DnsMessageFact>,
    finished_ms: Option<u64>,
}

impl DnsResolutionMachine {
    #[must_use]
    pub const fn name(&self) -> &EgressName {
        &self.name
    }

    #[must_use]
    pub const fn index(&self) -> u16 {
        self.index
    }

    #[must_use]
    pub const fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }

    /// Starts only after a declared endpoint has matched a client request.
    pub fn new(
        name: EgressName,
        scope: AddressScope,
        triggering_connection: u64,
        started_ms: u64,
        policy: &ResolutionPolicy,
        budget: &mut ProxyBudget,
    ) -> Result<Self, DnsResolutionError> {
        let initial = ServiceName::new(name.as_str().to_owned())
            .map_err(|_| DnsResolutionError::CnameConflict)?;
        let deadline_ms = started_ms
            .checked_add(policy.resolution_deadline_ms())
            .ok_or(DnsResolutionError::Deadline)?;
        let index = budget
            .begin_resolution()
            .map_err(|_| DnsResolutionError::ResolutionLimit)?;
        Ok(Self {
            index,
            name,
            scope,
            triggering_connection,
            started_ms,
            deadline_ms,
            maximum_cname_depth: policy.maximum_cname_depth(),
            maximum_answer_count: policy.maximum_answer_count(),
            maximum_response_bytes: policy.maximum_response_bytes(),
            ipv4: FamilyState::new(&initial),
            ipv6: FamilyState::new(&initial),
            pending: None,
            messages: Vec::new(),
            finished_ms: None,
        })
    }

    /// Allocates one bounded query; the event loop sends its TCP frame.
    pub fn issue_query(
        &mut self,
        transaction: u16,
        now_ms: u64,
        budget: &mut ProxyBudget,
    ) -> Result<DnsQuery, DnsResolutionError> {
        if now_ms >= self.deadline_ms {
            return Err(DnsResolutionError::Deadline);
        }
        if self.pending.is_some() {
            return Err(DnsResolutionError::QueryPending);
        }
        let (family, record_type) = if !self.ipv4.complete {
            (&self.ipv4, DnsRecordType::A)
        } else if !self.ipv6.complete {
            (&self.ipv6, DnsRecordType::Aaaa)
        } else {
            return Err(DnsResolutionError::Complete);
        };
        budget
            .can_issue_dns_query()
            .map_err(|_| DnsResolutionError::MessageLimit)?;
        let query = DnsQuery::new(family.current.clone(), record_type, transaction);
        self.pending = Some(query.clone());
        Ok(query)
    }

    /// Accepts one complete, length-checked TCP response for the pending query.
    pub fn accept_response(
        &mut self,
        bytes: &[u8],
        finished_ms: u64,
        budget: &mut ProxyBudget,
    ) -> Result<(), DnsResolutionError> {
        if finished_ms >= self.deadline_ms {
            return Err(DnsResolutionError::Deadline);
        }
        let query = self
            .pending
            .take()
            .ok_or(DnsResolutionError::NoQueryPending)?;
        if bytes.is_empty() || bytes.len() as u64 > self.maximum_response_bytes {
            return Err(DnsResolutionError::Wire(DnsWireError::TooLarge));
        }
        budget
            .record_dns_message()
            .map_err(|_| DnsResolutionError::MessageLimit)?;
        self.messages.push(DnsMessageFact {
            identity: Sha256Digest::from_bytes(Sha256::digest(bytes).into()),
            size: u16::try_from(bytes.len())
                .map_err(|_| DnsResolutionError::Wire(DnsWireError::TooLarge))?,
            finished_ms,
        });
        let response = parse_dns_response(&query, bytes, self.maximum_response_bytes, finished_ms)?;
        let family = if query.record_type() == DnsRecordType::A {
            &mut self.ipv4
        } else {
            &mut self.ipv6
        };
        let answers = response
            .addresses
            .into_iter()
            .filter(|answer| answer.owner == family.current)
            .collect::<Vec<_>>();
        if answers.len() > usize::from(self.maximum_answer_count) {
            return Err(DnsResolutionError::AnswerCount);
        }
        let aliases = response.cnames.get(&family.current);
        if !answers.is_empty() && aliases.is_some_and(|records| !records.is_empty()) {
            return Err(DnsResolutionError::CnameConflict);
        }
        let alias = match aliases {
            None => None,
            Some(records) if records.is_empty() => None,
            Some(records) if records.len() == 1 => Some(records[0].clone()),
            Some(_) => return Err(DnsResolutionError::CnameConflict),
        };
        if !answers.is_empty() {
            family.answers = answers;
            family.complete = true;
        } else if let Some(alias) = alias {
            if family.chain.len() >= usize::from(self.maximum_cname_depth) {
                return Err(DnsResolutionError::CnameDepth);
            }
            if !family.visited.insert(alias.target.clone()) {
                return Err(DnsResolutionError::CnameLoop);
            }
            family.current = alias.target.clone();
            family.chain.push(alias);
        } else {
            family.complete = true;
        }
        if self.ipv4.complete && self.ipv6.complete {
            self.finished_ms = Some(finished_ms);
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.finished_ms.is_some()
    }

    /// Reconciles both families, duplicate addresses, CNAME expiry, and scope.
    pub fn finish(&self) -> Result<DnsResolutionFacts, DnsResolutionError> {
        let finished_ms = self.finished_ms.ok_or(DnsResolutionError::QueryPending)?;
        let selected_chain = if self.ipv4.answers.is_empty() {
            &self.ipv6.chain
        } else {
            &self.ipv4.chain
        };
        for candidate in [&self.ipv4.chain, &self.ipv6.chain] {
            if !candidate.is_empty() && !same_path(candidate, selected_chain) {
                return Err(DnsResolutionError::CnameConflict);
            }
        }
        let mut chain = selected_chain.clone();
        if same_path(&self.ipv4.chain, &self.ipv6.chain) && !self.ipv4.chain.is_empty() {
            for (index, link) in chain.iter_mut().enumerate() {
                if self.ipv4.chain[index].expiry_ms <= self.ipv6.chain[index].expiry_ms {
                    *link = self.ipv4.chain[index].clone();
                } else {
                    *link = self.ipv6.chain[index].clone();
                }
            }
        }
        let terminal = chain
            .last()
            .map(|link| &link.target)
            .unwrap_or(&self.ipv4.current);
        let mut answers = self
            .ipv4
            .answers
            .iter()
            .cloned()
            .chain(self.ipv6.answers.iter().cloned())
            .filter(|answer| &answer.owner == terminal)
            .collect::<Vec<_>>();
        if answers.len() > usize::from(self.maximum_answer_count) {
            return Err(DnsResolutionError::AnswerCount);
        }
        answers.sort_unstable_by(|left, right| {
            address_key(left.address)
                .cmp(&address_key(right.address))
                .then(left.record_expiry_ms.cmp(&right.record_expiry_ms))
                .then(left.message_identity.cmp(&right.message_identity))
        });
        answers.dedup_by(|left, right| left.address == right.address);
        let alias_expiry = chain.iter().map(|link| link.expiry_ms).min();
        let answers = answers
            .into_iter()
            .map(|answer| DnsAnswerFact {
                address: answer.address,
                ttl_seconds: answer.ttl_seconds,
                record_expiry_ms: answer.record_expiry_ms,
                effective_expiry_ms: alias_expiry
                    .map(|expiry| expiry.min(answer.record_expiry_ms))
                    .unwrap_or(answer.record_expiry_ms),
                message_identity: answer.message_identity,
                admissible: answer_is_admissible(answer.address, self.scope),
            })
            .collect::<Vec<_>>();
        let outcome = if answers.is_empty() {
            DnsResolutionOutcome::Failed
        } else if answers.iter().any(|answer| answer.admissible) {
            DnsResolutionOutcome::Answered
        } else {
            DnsResolutionOutcome::NoAdmissibleAnswer
        };
        Ok(DnsResolutionFacts {
            index: self.index,
            name: self.name.clone(),
            triggering_connection: self.triggering_connection,
            started_ms: self.started_ms,
            finished_ms,
            messages: self.messages.clone(),
            cname_chain: chain,
            answers,
            outcome,
        })
    }

    /// Closes an incomplete resolution after transport or wire failure while
    /// retaining every bounded response message already observed.
    #[must_use]
    pub fn fail(self, finished_ms: u64) -> DnsResolutionFacts {
        let cname_chain = if self.ipv4.chain.is_empty() {
            self.ipv6.chain
        } else {
            self.ipv4.chain
        };
        DnsResolutionFacts {
            index: self.index,
            name: self.name,
            triggering_connection: self.triggering_connection,
            started_ms: self.started_ms,
            finished_ms,
            messages: self.messages,
            cname_chain,
            answers: Vec::new(),
            outcome: DnsResolutionOutcome::Failed,
        }
    }
}

fn same_path(left: &[DnsCnameRecord], right: &[DnsCnameRecord]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.owner == right.owner && left.target == right.target)
}

fn address_key(address: IpAddr) -> (u8, [u8; 16]) {
    match address {
        IpAddr::V4(a) => {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&a.octets());
            (0, bytes)
        }
        IpAddr::V6(a) => (1, a.octets()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofbound_runtime_core::{
        AddressOrder, EgressLimits, NetworkSupportPath, ResolverAddress, ResolverEndpoint, TcpPort,
        TunnelDecision, TunnelTarget, decide_tunnel,
    };

    #[test]
    fn concurrent_waiters_share_one_resolution_and_expiry_forces_refresh() {
        let name = EgressName::new("api.example").unwrap();
        let mut coordinator = ResolutionCoordinator::new();
        assert_eq!(coordinator.request(&name, 1, 10), ResolutionRequest::Start);
        coordinator.started(&name, 1).unwrap();
        assert_eq!(coordinator.request(&name, 2, 10), ResolutionRequest::Wait);
        let facts = DnsResolutionFacts {
            index: 1,
            name: name.clone(),
            triggering_connection: 1,
            started_ms: 10,
            finished_ms: 11,
            messages: Vec::new(),
            cname_chain: Vec::new(),
            answers: vec![DnsAnswerFact {
                address: "8.8.8.8".parse().unwrap(),
                ttl_seconds: 1,
                record_expiry_ms: 20,
                effective_expiry_ms: 20,
                message_identity: Sha256Digest::from_bytes([0; 32]),
                admissible: true,
            }],
            outcome: DnsResolutionOutcome::Answered,
        };
        assert_eq!(coordinator.complete(facts.clone()), Ok(vec![1, 2]));
        assert_eq!(
            coordinator.request(&name, 3, 19),
            ResolutionRequest::Reuse(facts)
        );
        assert_eq!(coordinator.request(&name, 4, 20), ResolutionRequest::Start);
        assert_eq!(coordinator.abort(&name), vec![4]);
    }

    fn policy() -> ResolutionPolicy {
        ResolutionPolicy::new(
            ResolverEndpoint::new(
                ResolverAddress::Ipv4([8, 8, 8, 8]),
                TcpPort::new(53).unwrap(),
            ),
            NetworkSupportPath::new("/etc/resolv.conf").unwrap(),
            4,
            16,
            512,
            1000,
            100,
            AddressOrder::Ipv4ThenIpv6Lexicographic,
        )
        .unwrap()
    }

    fn budget() -> ProxyBudget {
        ProxyBudget::new(EgressLimits {
            connections: 10,
            concurrent_connections: 2,
            attempts_per_connection: 2,
            resolutions: 10,
            dns_messages: 20,
            client_to_remote_bytes: 100,
            remote_to_client_bytes: 100,
            connection_idle_ms: 1000,
        })
    }

    fn response(query: &DnsQuery, data: Option<&[u8]>, ttl: u32) -> Vec<u8> {
        let mut bytes = query.tcp_frame()[2..].to_vec();
        bytes[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        if let Some(data) = data {
            bytes[6..8].copy_from_slice(&1_u16.to_be_bytes());
            bytes.extend_from_slice(&[0xc0, 0x0c]);
            let kind: u16 = match query.record_type() {
                DnsRecordType::A => 1,
                DnsRecordType::Aaaa => 28,
            };
            bytes.extend_from_slice(&kind.to_be_bytes());
            bytes.extend_from_slice(&1_u16.to_be_bytes());
            bytes.extend_from_slice(&ttl.to_be_bytes());
            bytes.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(data);
        }
        bytes
    }

    fn cname_response(query: &DnsQuery, target: &str, ttl: u32) -> Vec<u8> {
        let mut data = Vec::new();
        for label in target.split('.') {
            data.push(u8::try_from(label.len()).unwrap());
            data.extend_from_slice(label.as_bytes());
        }
        data.push(0);
        let mut bytes = query.tcp_frame()[2..].to_vec();
        bytes[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[0xc0, 0x0c]);
        bytes.extend_from_slice(&5_u16.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&ttl.to_be_bytes());
        bytes.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&data);
        bytes
    }

    #[test]
    fn zero_ttl_is_retained_for_the_triggering_connection() {
        let name = EgressName::new("api.example").unwrap();
        let mut budget = budget();
        let mut machine = DnsResolutionMachine::new(
            name.clone(),
            AddressScope::Global,
            7,
            10,
            &policy(),
            &mut budget,
        )
        .unwrap();
        let a = machine.issue_query(1, 10, &mut budget).unwrap();
        machine
            .accept_response(&response(&a, Some(&[8, 8, 8, 8]), 0), 20, &mut budget)
            .unwrap();
        let aaaa = machine.issue_query(2, 20, &mut budget).unwrap();
        assert_eq!(aaaa.record_type(), DnsRecordType::Aaaa);
        machine
            .accept_response(&response(&aaaa, None, 0), 21, &mut budget)
            .unwrap();
        let facts = machine.finish().unwrap();
        assert_eq!(facts.answers[0].effective_expiry_ms, 20);
        assert_eq!(facts.pinned().triggering_connection, 7);
        assert_eq!(budget.totals().dns_messages, 2);
        assert_eq!(facts.messages.len(), 2);
        let pinned = facts.pinned();
        let target = TunnelTarget::DnsName(name);
        let authority = super::super::tests::golden_authority();
        assert!(matches!(
            decide_tunnel(
                &authority,
                7,
                &target,
                TcpPort::new(443).unwrap(),
                Some(&EgressName::new("api.example").unwrap()),
                Some(&pinned),
                100
            ),
            TunnelDecision::Attempts { .. }
        ));
        assert!(matches!(
            decide_tunnel(
                &authority,
                8,
                &target,
                TcpPort::new(443).unwrap(),
                Some(&EgressName::new("api.example").unwrap()),
                Some(&pinned),
                100
            ),
            TunnelDecision::Denied(_)
        ));
    }

    #[test]
    fn malformed_dns_response_is_still_counted_and_identified() {
        let mut budget = budget();
        let mut machine = DnsResolutionMachine::new(
            EgressName::new("api.example").unwrap(),
            AddressScope::Global,
            1,
            10,
            &policy(),
            &mut budget,
        )
        .unwrap();
        machine.issue_query(17, 10, &mut budget).unwrap();
        let malformed = [0u8; 12];
        assert!(matches!(
            machine.accept_response(&malformed, 11, &mut budget),
            Err(DnsResolutionError::Wire(_))
        ));
        let failed = machine.fail(11);
        assert_eq!(failed.outcome, DnsResolutionOutcome::Failed);
        assert_eq!(failed.messages.len(), 1);
        assert_eq!(failed.messages[0].size, 12);
        assert_eq!(budget.totals().dns_messages, 1);
    }

    #[test]
    fn special_answer_never_becomes_a_pinned_attempt() {
        let name = EgressName::new("api.example").unwrap();
        let mut budget = budget();
        let mut machine = DnsResolutionMachine::new(
            name,
            AddressScope::GlobalOrPrivate,
            1,
            0,
            &policy(),
            &mut budget,
        )
        .unwrap();
        let a = machine.issue_query(1, 0, &mut budget).unwrap();
        machine
            .accept_response(&response(&a, Some(&[127, 0, 0, 1]), 30), 1, &mut budget)
            .unwrap();
        let aaaa = machine.issue_query(2, 1, &mut budget).unwrap();
        machine
            .accept_response(&response(&aaaa, None, 0), 2, &mut budget)
            .unwrap();
        let facts = machine.finish().unwrap();
        assert_eq!(facts.outcome, DnsResolutionOutcome::NoAdmissibleAnswer);
        assert_eq!(facts.answers.len(), 1);
        assert!(!facts.answers[0].admissible);
        assert!(facts.pinned().answers.is_empty());
    }

    #[test]
    fn cname_chain_binds_the_effective_expiry() {
        let name = EgressName::new("api.example").unwrap();
        let mut budget = budget();
        let mut machine =
            DnsResolutionMachine::new(name, AddressScope::Global, 1, 0, &policy(), &mut budget)
                .unwrap();
        let first = machine.issue_query(1, 0, &mut budget).unwrap();
        machine
            .accept_response(&cname_response(&first, "edge.example", 1), 10, &mut budget)
            .unwrap();
        let terminal = machine.issue_query(2, 10, &mut budget).unwrap();
        assert_eq!(terminal.name().as_str(), "edge.example");
        machine
            .accept_response(
                &response(&terminal, Some(&[8, 8, 8, 8]), 60),
                20,
                &mut budget,
            )
            .unwrap();
        let ipv6 = machine.issue_query(3, 20, &mut budget).unwrap();
        machine
            .accept_response(&cname_response(&ipv6, "edge.example", 1), 30, &mut budget)
            .unwrap();
        let ipv6_alias = machine.issue_query(4, 30, &mut budget).unwrap();
        machine
            .accept_response(&response(&ipv6_alias, None, 0), 40, &mut budget)
            .unwrap();
        let facts = machine.finish().unwrap();
        assert_eq!(facts.cname_chain.len(), 1);
        assert_eq!(facts.answers[0].record_expiry_ms, 60_020);
        assert_eq!(facts.answers[0].effective_expiry_ms, 1010);
    }
}
