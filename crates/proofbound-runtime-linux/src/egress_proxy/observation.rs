//! Bounded proxy records before deterministic receipt encoding.

use std::collections::BTreeSet;
use std::net::IpAddr;

use proofbound_runtime_core::{Sha256Digest, TcpPort};
use sha2::{Digest as _, Sha256};

use super::budget::{ProxyBudget, ProxyLimit, ProxyTotals};
use super::resolution::{DnsResolutionFacts, DnsResolutionOutcome};

const RETAINED_REJECTIONS: usize = 256;
const MAX_TARGET_BYTES: usize = 8192;

/// One closed rejection reason from Specification 0017.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectionReason {
    MethodNotConnect,
    RequestMalformed,
    RequestHeadTooLarge,
    TargetNoncanonical,
    EndpointUndeclared,
    LimitConnections,
    LimitConcurrentConnections,
    LimitResolutions,
    LimitDnsMessages,
    LimitBytesExhausted,
}

impl RejectionReason {
    pub const ALL: [Self; 10] = [
        Self::MethodNotConnect,
        Self::RequestMalformed,
        Self::RequestHeadTooLarge,
        Self::TargetNoncanonical,
        Self::EndpointUndeclared,
        Self::LimitConnections,
        Self::LimitConcurrentConnections,
        Self::LimitResolutions,
        Self::LimitDnsMessages,
        Self::LimitBytesExhausted,
    ];

    const fn index(self) -> usize {
        match self {
            Self::MethodNotConnect => 0,
            Self::RequestMalformed => 1,
            Self::RequestHeadTooLarge => 2,
            Self::TargetNoncanonical => 3,
            Self::EndpointUndeclared => 4,
            Self::LimitConnections => 5,
            Self::LimitConcurrentConnections => 6,
            Self::LimitResolutions => 7,
            Self::LimitDnsMessages => 8,
            Self::LimitBytesExhausted => 9,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MethodNotConnect => "method-not-connect",
            Self::RequestMalformed => "request-malformed",
            Self::RequestHeadTooLarge => "request-head-too-large",
            Self::TargetNoncanonical => "target-noncanonical",
            Self::EndpointUndeclared => "endpoint-undeclared",
            Self::LimitConnections => "limit-connections",
            Self::LimitConcurrentConnections => "limit-concurrent-connections",
            Self::LimitResolutions => "limit-resolutions",
            Self::LimitDnsMessages => "limit-dns-messages",
            Self::LimitBytesExhausted => "limit-bytes-exhausted",
        }
    }

    #[must_use]
    pub const fn is_authority(self) -> bool {
        matches!(
            self,
            Self::MethodNotConnect
                | Self::RequestMalformed
                | Self::RequestHeadTooLarge
                | Self::TargetNoncanonical
                | Self::EndpointUndeclared
        )
    }
}

impl From<ProxyLimit> for RejectionReason {
    fn from(reason: ProxyLimit) -> Self {
        match reason {
            ProxyLimit::Connections => Self::LimitConnections,
            ProxyLimit::Concurrent => Self::LimitConcurrentConnections,
            ProxyLimit::Resolutions => Self::LimitResolutions,
            ProxyLimit::DnsMessages => Self::LimitDnsMessages,
            ProxyLimit::ClientBytes | ProxyLimit::RemoteBytes => Self::LimitBytesExhausted,
        }
    }
}

impl From<super::RequestRejection> for RejectionReason {
    fn from(reason: super::RequestRejection) -> Self {
        match reason {
            super::RequestRejection::MethodNotConnect => Self::MethodNotConnect,
            super::RequestRejection::RequestMalformed => Self::RequestMalformed,
            super::RequestRejection::RequestHeadTooLarge => Self::RequestHeadTooLarge,
            super::RequestRejection::TargetNoncanonical => Self::TargetNoncanonical,
            super::RequestRejection::EndpointUndeclared => Self::EndpointUndeclared,
        }
    }
}

/// The target form observed from a client request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetKind {
    DnsName,
    Ipv4,
    Ipv6,
    Unparsed,
}

/// A rejection stores only a digest and length of child-chosen target bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectionFact {
    pub sequence: u64,
    pub time_ms: u64,
    pub reason: RejectionReason,
    pub target_kind: TargetKind,
    pub port: Option<TcpPort>,
    pub target_length: u16,
    pub target_sha256: Sha256Digest,
}

/// The closed SNI result that may appear in a final connection record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SniObservation {
    NotInspected,
    Matched,
    DeniedAbsent,
    DeniedMismatch,
    DeniedEch,
    DeniedMalformed,
    DeniedTooLarge,
}

impl SniObservation {
    #[must_use]
    pub const fn is_denied(self) -> bool {
        !matches!(self, Self::NotInspected | Self::Matched)
    }
}

/// One numeric attempt result; a DNS attempt also names its answer index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptResult {
    Connected,
    Refused,
    TimedOut,
    Unreachable,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptFact {
    pub answer_index: Option<u16>,
    pub address: IpAddr,
    pub started_ms: u64,
    pub result: AttemptResult,
}

/// One closed reason for a final proxied connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseReason {
    ClientClosed,
    RemoteClosed,
    Reset,
    IdleTimeout,
    ClientByteLimit,
    RemoteByteLimit,
    ProxyDraining,
    SniDenied,
    ResolutionFailed,
    NoAdmissibleAnswer,
    ConnectFailed,
}

/// Complete observations of one declared-endpoint connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionFact {
    pub index: u16,
    pub endpoint_index: u16,
    pub open_sequence: u64,
    pub close_sequence: u64,
    pub accepted_ms: u64,
    pub resolution_index: Option<u16>,
    pub sni_result: SniObservation,
    pub attempts: Vec<AttemptFact>,
    pub selected_attempt: Option<u16>,
    pub client_to_remote_bytes: u64,
    pub remote_to_client_bytes: u64,
    pub close_reason: CloseReason,
}

/// A connection token cannot be fabricated outside this module.
#[derive(Debug)]
pub struct OpenConnection {
    index: u16,
    endpoint_index: u16,
    open_sequence: u64,
    accepted_ms: u64,
}

impl OpenConnection {
    #[must_use]
    pub const fn index(&self) -> u16 {
        self.index
    }
}

/// Facts supplied when one connection reaches a terminal reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionTerminal {
    pub resolution_index: Option<u16>,
    pub sni_result: SniObservation,
    pub attempts: Vec<AttemptFact>,
    pub selected_attempt: Option<u16>,
    pub client_to_remote_bytes: u64,
    pub remote_to_client_bytes: u64,
    pub close_reason: CloseReason,
}

/// A local accounting failure prevents a reusable observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyRecordError {
    SequenceOverflow,
    RejectionOverflow,
    TargetTooLong,
    EndpointUnknown,
    ConnectionUnknown,
    AttemptBound,
    AttemptSelection,
    SniRelation,
    CounterMismatch,
}

/// Produces ordered, bounded connection, resolution, and rejection records.
#[derive(Clone, Debug, Default)]
pub struct ProxyObservationLedger {
    event_sequence: u64,
    open: BTreeSet<u16>,
    connections: Vec<ConnectionFact>,
    resolutions: Vec<DnsResolutionFacts>,
    rejections: Vec<RejectionFact>,
    rejection_total: u64,
    rejection_reason_counts: [u64; 10],
}

impl ProxyObservationLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn next_sequence(&mut self) -> Result<u64, ProxyRecordError> {
        self.event_sequence = self
            .event_sequence
            .checked_add(1)
            .ok_or(ProxyRecordError::SequenceOverflow)?;
        Ok(self.event_sequence)
    }

    /// Counts a declared endpoint connection and retains its open sequence.
    pub fn open_connection(
        &mut self,
        budget: &mut ProxyBudget,
        endpoint_index: usize,
        endpoint_count: usize,
        accepted_ms: u64,
    ) -> Result<Result<OpenConnection, ProxyLimit>, ProxyRecordError> {
        if endpoint_index >= endpoint_count || endpoint_index > usize::from(u16::MAX) {
            return Err(ProxyRecordError::EndpointUnknown);
        }
        let index = match budget.open_connection() {
            Ok(index) => index,
            Err(limit) => return Ok(Err(limit)),
        };
        let open_sequence = self.next_sequence()?;
        self.open.insert(index);
        Ok(Ok(OpenConnection {
            index,
            endpoint_index: u16::try_from(endpoint_index)
                .map_err(|_| ProxyRecordError::EndpointUnknown)?,
            open_sequence,
            accepted_ms,
        }))
    }

    /// Completes one connection exactly once and returns the record for output.
    pub fn close_connection(
        &mut self,
        budget: &mut ProxyBudget,
        open: OpenConnection,
        terminal: ConnectionTerminal,
    ) -> Result<ConnectionFact, ProxyRecordError> {
        if !self.open.contains(&open.index) {
            return Err(ProxyRecordError::ConnectionUnknown);
        }
        if terminal.attempts.len() > usize::from(budget.limits().attempts_per_connection) {
            return Err(ProxyRecordError::AttemptBound);
        }
        let connected = terminal
            .attempts
            .iter()
            .enumerate()
            .filter(|(_, attempt)| attempt.result == AttemptResult::Connected)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if connected.len() > 1
            || terminal.selected_attempt.map(usize::from) != connected.first().copied()
            || connected
                .first()
                .is_some_and(|index| *index + 1 != terminal.attempts.len())
            || (terminal.selected_attempt.is_none()
                && (terminal.client_to_remote_bytes != 0 || terminal.remote_to_client_bytes != 0))
        {
            return Err(ProxyRecordError::AttemptSelection);
        }
        if terminal.sni_result.is_denied()
            && (terminal.resolution_index.is_some()
                || !terminal.attempts.is_empty()
                || terminal.close_reason != CloseReason::SniDenied)
        {
            return Err(ProxyRecordError::SniRelation);
        }
        if !budget.close_connection() {
            return Err(ProxyRecordError::ConnectionUnknown);
        }
        self.open.remove(&open.index);
        let fact = ConnectionFact {
            index: open.index,
            endpoint_index: open.endpoint_index,
            open_sequence: open.open_sequence,
            close_sequence: self.next_sequence()?,
            accepted_ms: open.accepted_ms,
            resolution_index: terminal.resolution_index,
            sni_result: terminal.sni_result,
            attempts: terminal.attempts,
            selected_attempt: terminal.selected_attempt,
            client_to_remote_bytes: terminal.client_to_remote_bytes,
            remote_to_client_bytes: terminal.remote_to_client_bytes,
            close_reason: terminal.close_reason,
        };
        self.connections.push(fact.clone());
        Ok(fact)
    }

    /// Retains one complete resolution, including a denied or failed outcome.
    pub fn record_resolution(&mut self, fact: DnsResolutionFacts) {
        self.resolutions.push(fact);
    }

    /// Counts every rejection while retaining only the first 256 records.
    pub fn record_rejection(
        &mut self,
        time_ms: u64,
        reason: RejectionReason,
        target_kind: TargetKind,
        port: Option<TcpPort>,
        exact_target_bytes: &[u8],
    ) -> Result<Option<RejectionFact>, ProxyRecordError> {
        if exact_target_bytes.len() > MAX_TARGET_BYTES {
            return Err(ProxyRecordError::TargetTooLong);
        }
        self.rejection_total = self
            .rejection_total
            .checked_add(1)
            .ok_or(ProxyRecordError::RejectionOverflow)?;
        self.rejection_reason_counts[reason.index()] = self.rejection_reason_counts[reason.index()]
            .checked_add(1)
            .ok_or(ProxyRecordError::RejectionOverflow)?;
        let fact = RejectionFact {
            sequence: self.next_sequence()?,
            time_ms,
            reason,
            target_kind,
            port,
            target_length: u16::try_from(exact_target_bytes.len())
                .map_err(|_| ProxyRecordError::TargetTooLong)?,
            target_sha256: Sha256Digest::from_bytes(Sha256::digest(exact_target_bytes).into()),
        };
        if self.rejections.len() == RETAINED_REJECTIONS {
            return Ok(None);
        }
        self.rejections.push(fact.clone());
        Ok(Some(fact))
    }

    /// Checks producer-side totals before a final report is encoded.
    pub fn verify_totals(&self, budget: &ProxyBudget) -> Result<(), ProxyRecordError> {
        let totals = budget.totals();
        let completed =
            u64::try_from(self.connections.len()).map_err(|_| ProxyRecordError::CounterMismatch)?;
        let expected_events = completed
            .checked_mul(2)
            .and_then(|events| events.checked_add(self.rejection_total))
            .ok_or(ProxyRecordError::CounterMismatch)?;
        let mut connection_indices = self.connections.iter().map(|c| c.index).collect::<Vec<_>>();
        connection_indices.sort_unstable();
        let mut resolution_indices = self.resolutions.iter().map(|r| r.index).collect::<Vec<_>>();
        resolution_indices.sort_unstable();
        let mut seen_sequences = BTreeSet::new();
        for connection in &self.connections {
            if connection.open_sequence >= connection.close_sequence
                || connection.close_sequence > self.event_sequence
                || !seen_sequences.insert(connection.open_sequence)
                || !seen_sequences.insert(connection.close_sequence)
            {
                return Err(ProxyRecordError::CounterMismatch);
            }
        }
        for rejection in &self.rejections {
            if rejection.sequence > self.event_sequence
                || !seen_sequences.insert(rejection.sequence)
            {
                return Err(ProxyRecordError::CounterMismatch);
            }
        }
        let dns_messages: usize = self
            .resolutions
            .iter()
            .try_fold(0usize, |sum, resolution| {
                sum.checked_add(resolution.messages.len())
                    .ok_or(ProxyRecordError::CounterMismatch)
            })?;
        let client_bytes: u64 = self.connections.iter().try_fold(0u64, |sum, connection| {
            sum.checked_add(connection.client_to_remote_bytes)
                .ok_or(ProxyRecordError::CounterMismatch)
        })?;
        let remote_bytes: u64 = self.connections.iter().try_fold(0u64, |sum, connection| {
            sum.checked_add(connection.remote_to_client_bytes)
                .ok_or(ProxyRecordError::CounterMismatch)
        })?;
        let reason_total = self
            .rejection_reason_counts
            .iter()
            .try_fold(0u64, |sum, count| {
                sum.checked_add(*count)
                    .ok_or(ProxyRecordError::CounterMismatch)
            })?;
        let retained_counts_valid = RejectionReason::ALL.iter().all(|reason| {
            let retained = self
                .rejections
                .iter()
                .filter(|fact| fact.reason == *reason)
                .count() as u64;
            retained <= self.rejection_reason_counts[reason.index()]
        });
        if !self.open.is_empty()
            || totals.active != 0
            || self.connections.len() != usize::from(totals.connections)
            || self.resolutions.len() != usize::from(totals.resolutions)
            || self.event_sequence != expected_events
            || connection_indices != (1..=totals.connections).collect::<Vec<_>>()
            || resolution_indices != (1..=totals.resolutions).collect::<Vec<_>>()
            || reason_total != self.rejection_total
            || !retained_counts_valid
            || dns_messages != usize::from(totals.dns_messages)
            || client_bytes != totals.client_bytes
            || remote_bytes != totals.remote_bytes
            || self.rejections.len()
                != usize::try_from(self.rejection_total.min(RETAINED_REJECTIONS as u64))
                    .map_err(|_| ProxyRecordError::CounterMismatch)?
        {
            return Err(ProxyRecordError::CounterMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn connections(&self) -> &[ConnectionFact] {
        &self.connections
    }

    #[must_use]
    pub fn resolutions(&self) -> &[DnsResolutionFacts] {
        &self.resolutions
    }

    #[must_use]
    pub fn rejections(&self) -> &[RejectionFact] {
        &self.rejections
    }

    #[must_use]
    pub const fn rejection_total(&self) -> u64 {
        self.rejection_total
    }

    #[must_use]
    pub const fn event_sequence(&self) -> u64 {
        self.event_sequence
    }

    #[must_use]
    pub const fn rejection_reason_counts(&self) -> &[u64; 10] {
        &self.rejection_reason_counts
    }

    #[must_use]
    pub fn limit_events(&self, budget: &ProxyBudget) -> BTreeSet<ProxyLimit> {
        budget.events().clone()
    }

    #[must_use]
    pub const fn totals(&self, budget: &ProxyBudget) -> ProxyTotals {
        budget.totals()
    }

    #[must_use]
    pub fn has_sni_denial(&self) -> bool {
        self.connections
            .iter()
            .any(|connection| connection.sni_result.is_denied())
    }

    #[must_use]
    pub fn has_authority_rejection(&self) -> bool {
        self.rejection_reason_counts[..5]
            .iter()
            .any(|count| *count != 0)
    }

    #[must_use]
    pub fn all_resolutions_answered(&self) -> bool {
        self.resolutions
            .iter()
            .all(|resolution| resolution.outcome == DnsResolutionOutcome::Answered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofbound_runtime_core::EgressLimits;

    fn budget() -> ProxyBudget {
        ProxyBudget::new(EgressLimits {
            connections: 2,
            concurrent_connections: 1,
            attempts_per_connection: 2,
            resolutions: 1,
            dns_messages: 2,
            client_to_remote_bytes: 5,
            remote_to_client_bytes: 5,
            connection_idle_ms: 1000,
        })
    }

    #[test]
    fn rejected_requests_are_counted_separately_from_connections() {
        let mut ledger = ProxyObservationLedger::new();
        let budget = budget();
        let rejection = ledger
            .record_rejection(
                1,
                RejectionReason::EndpointUndeclared,
                TargetKind::DnsName,
                TcpPort::new(443).ok(),
                b"other.example",
            )
            .unwrap()
            .unwrap();
        assert_eq!(rejection.sequence, 1);
        assert_eq!(rejection.target_length, 13);
        assert_eq!(budget.totals().connections, 0);
        assert_eq!(ledger.rejection_total(), 1);
        assert!(ledger.has_authority_rejection());
        assert_eq!(ledger.verify_totals(&budget), Ok(()));
    }

    #[test]
    fn authority_class_survives_retention_limit_without_misclassifying_limit_only() {
        let mut ledger = ProxyObservationLedger::new();
        for time in 0..=RETAINED_REJECTIONS {
            let retained = ledger
                .record_rejection(
                    time as u64,
                    RejectionReason::LimitConnections,
                    TargetKind::Unparsed,
                    None,
                    b"",
                )
                .unwrap();
            assert_eq!(retained.is_some(), time < RETAINED_REJECTIONS);
        }
        assert_eq!(ledger.rejections().len(), RETAINED_REJECTIONS);
        assert_eq!(ledger.rejection_total(), 257);
        assert_eq!(
            ledger.rejection_reason_counts()[RejectionReason::LimitConnections.index()],
            257
        );
        assert!(!ledger.has_authority_rejection());
        ledger
            .record_rejection(
                258,
                RejectionReason::EndpointUndeclared,
                TargetKind::DnsName,
                TcpPort::new(443).ok(),
                b"other.example",
            )
            .unwrap();
        assert!(ledger.has_authority_rejection());
        assert_eq!(ledger.verify_totals(&budget()), Ok(()));
    }

    #[test]
    fn declared_connection_has_ordered_sequences_and_exact_totals() {
        let mut ledger = ProxyObservationLedger::new();
        let mut budget = budget();
        let open = ledger
            .open_connection(&mut budget, 0, 1, 10)
            .unwrap()
            .unwrap();
        let attempt = AttemptFact {
            answer_index: None,
            address: "192.0.2.10".parse().unwrap(),
            started_ms: 11,
            result: AttemptResult::Connected,
        };
        assert_eq!(budget.grant_client_bytes(3).permitted, 3);
        let fact = ledger
            .close_connection(
                &mut budget,
                open,
                ConnectionTerminal {
                    resolution_index: None,
                    sni_result: SniObservation::NotInspected,
                    attempts: vec![attempt],
                    selected_attempt: Some(0),
                    client_to_remote_bytes: 3,
                    remote_to_client_bytes: 0,
                    close_reason: CloseReason::ClientClosed,
                },
            )
            .unwrap();
        assert_eq!((fact.open_sequence, fact.close_sequence), (1, 2));
        assert_eq!(ledger.verify_totals(&budget), Ok(()));
    }
}
