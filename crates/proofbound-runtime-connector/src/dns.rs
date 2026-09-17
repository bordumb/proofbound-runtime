use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use proofbound_runtime_core::{
    AuthenticatedServiceSession, ResolutionPolicy, ResolverAddress, ServiceName, Sha256Digest,
    TcpPort,
};
use sha2::{Digest as _, Sha256};

const DNS_HEADER_BYTES: usize = 12;
const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_AAAA: u16 = 28;
const MAX_DNS_NAME_POINTERS: usize = 128;

/// Records one bounded DNS response without retaining its packet bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsMessageObservation {
    identity: Sha256Digest,
    size: u64,
    observed_ns: u64,
}

impl DnsMessageObservation {
    /// Returns the SHA-256 identity of the complete DNS response bytes.
    #[must_use]
    pub const fn identity(&self) -> Sha256Digest {
        self.identity
    }

    /// Returns the DNS response size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns the connector-relative monotonic observation time.
    #[must_use]
    pub const fn observed_ns(&self) -> u64 {
        self.observed_ns
    }
}

/// Records one canonical terminal address answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsAnswer {
    name: ServiceName,
    address: IpAddr,
    message_identity: Sha256Digest,
    ttl_seconds: u32,
    record_expires_ns: u64,
    effective_expires_ns: u64,
}

/// Records one validated CNAME link and its effective lifetime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsCnameObservation {
    owner: ServiceName,
    target: ServiceName,
    message_identity: Sha256Digest,
    ttl_seconds: u32,
    expires_ns: u64,
}

impl DnsCnameObservation {
    /// Returns the alias owner name.
    #[must_use]
    pub const fn owner(&self) -> &ServiceName {
        &self.owner
    }

    /// Returns the alias target name.
    #[must_use]
    pub const fn target(&self) -> &ServiceName {
        &self.target
    }

    /// Returns the DNS response identity that supplied the alias.
    #[must_use]
    pub const fn message_identity(&self) -> Sha256Digest {
        self.message_identity
    }

    /// Returns the positive alias TTL in seconds.
    #[must_use]
    pub const fn ttl_seconds(&self) -> u32 {
        self.ttl_seconds
    }

    /// Returns the connector-relative monotonic alias expiry time.
    #[must_use]
    pub const fn expires_ns(&self) -> u64 {
        self.expires_ns
    }
}

impl DnsAnswer {
    /// Returns the terminal DNS owner name.
    #[must_use]
    pub const fn name(&self) -> &ServiceName {
        &self.name
    }

    /// Returns the canonical numeric address.
    #[must_use]
    pub const fn address(&self) -> IpAddr {
        self.address
    }

    /// Returns the response identity that supplied this answer.
    #[must_use]
    pub const fn message_identity(&self) -> Sha256Digest {
        self.message_identity
    }

    /// Returns the positive TTL in seconds.
    #[must_use]
    pub const fn ttl_seconds(&self) -> u32 {
        self.ttl_seconds
    }

    /// Returns the expiry derived from the terminal record TTL.
    #[must_use]
    pub const fn record_expires_ns(&self) -> u64 {
        self.record_expires_ns
    }

    /// Returns the earliest terminal-record or alias-chain expiry.
    #[must_use]
    pub const fn effective_expires_ns(&self) -> u64 {
        self.effective_expires_ns
    }

    /// Returns the service endpoint that uses the declared port.
    #[must_use]
    pub const fn endpoint(&self, port: TcpPort) -> SocketAddr {
        SocketAddr::new(self.address, port.get())
    }
}

/// Contains the complete bounded result of one service-name resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsResolution {
    started: Instant,
    authority: AuthenticatedServiceSession,
    messages: Vec<DnsMessageObservation>,
    cname_chain: Vec<DnsCnameObservation>,
    answers: Vec<DnsAnswer>,
}

impl DnsResolution {
    /// Returns the complete service authority that produced this resolution.
    #[must_use]
    pub const fn authority(&self) -> &AuthenticatedServiceSession {
        &self.authority
    }

    /// Returns the declared service port.
    #[must_use]
    pub const fn port(&self) -> TcpPort {
        self.authority.port()
    }

    /// Returns every observed DNS response in order.
    #[must_use]
    pub fn messages(&self) -> &[DnsMessageObservation] {
        &self.messages
    }

    /// Returns the validated service-to-terminal alias links.
    ///
    /// The result is empty when the declared service has direct address data.
    #[must_use]
    pub fn cname_chain(&self) -> &[DnsCnameObservation] {
        &self.cname_chain
    }

    /// Returns the canonical unique terminal address set.
    #[must_use]
    pub fn answers(&self) -> &[DnsAnswer] {
        &self.answers
    }

    pub(crate) fn elapsed_ns(&self) -> u64 {
        elapsed_ns(self.started)
    }

    pub(crate) fn remaining_until(&self, deadline_ns: u64) -> Option<Duration> {
        deadline_ns
            .checked_sub(self.elapsed_ns())
            .map(Duration::from_nanos)
            .filter(|duration| !duration.is_zero())
    }
}

/// Identifies one fail-closed resolver error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsError {
    /// The operating-system random source was unavailable.
    RandomUnavailable,
    /// The declared resolver could not be reached before its deadline.
    ResolverUnavailable,
    /// A DNS request could not be sent completely.
    RequestFailed,
    /// A DNS response did not arrive completely before its deadline.
    ResponseFailed,
    /// A DNS response exceeded the declared byte bound.
    ResponseTooLarge,
    /// The DNS-message count exceeded the declared bound.
    MessageLimit,
    /// The total resolution deadline expired.
    Deadline,
    /// A DNS response was malformed or did not match its query.
    MalformedResponse,
    /// The resolver returned a terminal DNS failure.
    ResolverFailure,
    /// A CNAME chain looped, conflicted, or exceeded its bound.
    InvalidCnameChain,
    /// The terminal answer inventory was empty or exceeded its bound.
    InvalidAnswerSet,
    /// A DNS answer was already expired or had a zero TTL.
    ExpiredAnswer,
}

impl DnsError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RandomUnavailable => "network.resolver.random-unavailable",
            Self::ResolverUnavailable => "network.resolver.endpoint-unavailable",
            Self::RequestFailed => "network.resolver.request-failed",
            Self::ResponseFailed => "network.resolver.response-failed",
            Self::ResponseTooLarge => "network.resolver.response-too-large",
            Self::MessageLimit => "network.limit.dns-messages",
            Self::Deadline => "network.resolver.deadline",
            Self::MalformedResponse => "network.resolver.response-malformed",
            Self::ResolverFailure => "network.resolver.response-failure",
            Self::InvalidCnameChain => "network.resolver.cname-invalid",
            Self::InvalidAnswerSet => "network.resolver.answer-set-invalid",
            Self::ExpiredAnswer => "network.resolver.answer-expired",
        }
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for DnsError {}

/// Resolves one declared service through only the declared TCP resolver.
///
/// The returned set is sorted as IPv4 then IPv6 in ascending network-byte
/// order. This function does not consult the system resolver, host files,
/// search domains, proxies, or environment configuration.
pub fn resolve_service(authority: &AuthenticatedServiceSession) -> Result<DnsResolution, DnsError> {
    let service = authority.service();
    let policy = authority.resolution();
    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_millis(policy.resolution_deadline_ms()))
        .ok_or(DnsError::Deadline)?;
    let mut state = ResolverState {
        started,
        deadline,
        policy,
        maximum_messages: authority.limits().dns_messages(),
        messages: Vec::new(),
    };
    let ipv4 = resolve_record_type(&mut state, service, DNS_TYPE_A)?;
    let ipv6 = resolve_record_type(&mut state, service, DNS_TYPE_AAAA)?;
    let chain = reconcile_chains(service, &ipv4, &ipv6, policy.maximum_cname_depth())?;
    let terminal = chain
        .last()
        .map(DnsCnameObservation::target)
        .unwrap_or(service);

    let mut answers = ipv4
        .answers
        .into_iter()
        .chain(ipv6.answers)
        .filter(|answer| &answer.name == terminal)
        .collect::<Vec<_>>();
    canonicalize_answers(&mut answers);
    apply_chain_expiry(&mut answers, &chain);
    if answers.is_empty() || answers.len() > usize::from(policy.maximum_answer_count()) {
        return Err(DnsError::InvalidAnswerSet);
    }
    if answers
        .iter()
        .any(|answer| answer.effective_expires_ns <= elapsed_ns(started))
    {
        return Err(DnsError::ExpiredAnswer);
    }

    Ok(DnsResolution {
        started,
        authority: authority.clone(),
        messages: state.messages,
        cname_chain: chain,
        answers,
    })
}

struct ResolverState<'a> {
    started: Instant,
    deadline: Instant,
    policy: &'a ResolutionPolicy,
    maximum_messages: u16,
    messages: Vec<DnsMessageObservation>,
}

#[derive(Default)]
struct RecordResolution {
    chain: Vec<DnsCnameObservation>,
    answers: Vec<DnsAnswer>,
}

fn resolve_record_type(
    state: &mut ResolverState<'_>,
    service: &ServiceName,
    record_type: u16,
) -> Result<RecordResolution, DnsError> {
    let mut current = service.clone();
    let mut chain = Vec::new();
    let mut seen = BTreeSet::from([service.as_str().to_owned()]);
    loop {
        if chain.len() > usize::from(state.policy.maximum_cname_depth()) {
            return Err(DnsError::InvalidCnameChain);
        }
        let response = exchange_query(state, &current, record_type)?;
        let (mut answers, alias) = validated_owner_records(response, &current)?;
        if !answers.is_empty() {
            if answers.len() > usize::from(state.policy.maximum_answer_count()) {
                return Err(DnsError::InvalidAnswerSet);
            }
            canonicalize_answers(&mut answers);
            return Ok(RecordResolution { chain, answers });
        }
        let Some(record) = alias else {
            return Ok(RecordResolution {
                chain,
                answers: Vec::new(),
            });
        };
        if chain.len() >= usize::from(state.policy.maximum_cname_depth()) {
            return Err(DnsError::InvalidCnameChain);
        }
        let next = record.target.clone();
        if !seen.insert(next.as_str().to_owned()) {
            return Err(DnsError::InvalidCnameChain);
        }
        chain.push(record);
        current = next;
    }
}

fn reconcile_chains(
    service: &ServiceName,
    ipv4: &RecordResolution,
    ipv6: &RecordResolution,
    maximum_depth: u16,
) -> Result<Vec<DnsCnameObservation>, DnsError> {
    let chain = if ipv4.answers.is_empty() {
        &ipv6.chain
    } else if ipv6.answers.is_empty() {
        &ipv4.chain
    } else if same_cname_path(&ipv4.chain, &ipv6.chain) {
        &ipv4.chain
    } else {
        return Err(DnsError::InvalidCnameChain);
    };
    if chain.len() > usize::from(maximum_depth)
        || chain
            .first()
            .is_some_and(|record| record.owner() != service)
    {
        return Err(DnsError::InvalidCnameChain);
    }
    for candidate in [&ipv4.chain, &ipv6.chain] {
        if !candidate.is_empty() && !same_cname_path(candidate, chain) {
            return Err(DnsError::InvalidCnameChain);
        }
    }
    merge_cname_observations(&ipv4.chain, &ipv6.chain)
}

fn same_cname_path(left: &[DnsCnameObservation], right: &[DnsCnameObservation]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.owner == right.owner && left.target == right.target)
}

fn merge_cname_observations(
    ipv4: &[DnsCnameObservation],
    ipv6: &[DnsCnameObservation],
) -> Result<Vec<DnsCnameObservation>, DnsError> {
    if ipv4.is_empty() {
        return Ok(ipv6.to_vec());
    }
    if ipv6.is_empty() {
        return Ok(ipv4.to_vec());
    }
    if !same_cname_path(ipv4, ipv6) {
        return Err(DnsError::InvalidCnameChain);
    }
    Ok(ipv4
        .iter()
        .zip(ipv6)
        .map(|(ipv4, ipv6)| {
            if ipv4.expires_ns <= ipv6.expires_ns {
                ipv4.clone()
            } else {
                ipv6.clone()
            }
        })
        .collect())
}

#[derive(Debug, Eq, PartialEq)]
struct ParsedResponse {
    cnames: BTreeMap<ServiceName, Vec<DnsCnameObservation>>,
    addresses: Vec<DnsAnswer>,
}

fn validated_owner_records(
    response: ParsedResponse,
    current: &ServiceName,
) -> Result<(Vec<DnsAnswer>, Option<DnsCnameObservation>), DnsError> {
    let answers = response
        .addresses
        .into_iter()
        .filter(|answer| &answer.name == current)
        .collect::<Vec<_>>();
    let aliases = response.cnames.get(current);
    if !answers.is_empty() && aliases.is_some_and(|records| !records.is_empty()) {
        return Err(DnsError::InvalidCnameChain);
    }
    let alias = match aliases {
        None => None,
        Some(records) if records.is_empty() => None,
        Some(records) if records.len() == 1 => Some(records[0].clone()),
        Some(_) => return Err(DnsError::InvalidCnameChain),
    };
    Ok((answers, alias))
}

fn apply_chain_expiry(answers: &mut [DnsAnswer], chain: &[DnsCnameObservation]) {
    let alias_expiry = chain.iter().map(DnsCnameObservation::expires_ns).min();
    for answer in answers {
        let record_expiry = answer.record_expires_ns;
        answer.effective_expires_ns = alias_expiry
            .map(|expiry| record_expiry.min(expiry))
            .unwrap_or(record_expiry);
    }
}

fn canonicalize_answers(answers: &mut Vec<DnsAnswer>) {
    answers.sort_unstable_by(|left, right| {
        address_key(left.address)
            .cmp(&address_key(right.address))
            .then(left.record_expires_ns.cmp(&right.record_expires_ns))
            .then(left.message_identity.cmp(&right.message_identity))
            .then(left.ttl_seconds.cmp(&right.ttl_seconds))
    });
    answers.dedup_by(|left, right| left.address == right.address);
}

fn exchange_query(
    state: &mut ResolverState<'_>,
    name: &ServiceName,
    record_type: u16,
) -> Result<ParsedResponse, DnsError> {
    if state.messages.len() >= usize::from(state.maximum_messages) {
        return Err(DnsError::MessageLimit);
    }
    let transaction = random_transaction_id()?;
    let query = encode_query(transaction, name, record_type)?;
    let attempt_deadline = Instant::now()
        .checked_add(Duration::from_millis(state.policy.attempt_deadline_ms()))
        .map(|deadline| deadline.min(state.deadline))
        .ok_or(DnsError::Deadline)?;
    let timeout = remaining_until(attempt_deadline)?;
    let endpoint = resolver_socket(state.policy);
    let mut stream = TcpStream::connect_timeout(&endpoint, timeout)
        .map_err(|_| DnsError::ResolverUnavailable)?;
    let length = u16::try_from(query.len()).map_err(|_| DnsError::RequestFailed)?;
    write_all_until(&mut stream, &length.to_be_bytes(), attempt_deadline)?;
    write_all_until(&mut stream, &query, attempt_deadline)?;

    let mut length_bytes = [0_u8; 2];
    read_exact_until(&mut stream, &mut length_bytes, attempt_deadline)?;
    let response_length = usize::from(u16::from_be_bytes(length_bytes));
    if response_length == 0
        || u64::try_from(response_length).unwrap_or(u64::MAX)
            > state.policy.maximum_response_bytes()
    {
        return Err(DnsError::ResponseTooLarge);
    }
    let mut response = vec![0_u8; response_length];
    read_exact_until(&mut stream, &mut response, attempt_deadline)?;
    if Instant::now() >= attempt_deadline {
        return Err(DnsError::Deadline);
    }
    let observed_ns = elapsed_ns(state.started);
    let identity = digest(&response);
    let parsed = parse_response(
        &response,
        transaction,
        name,
        record_type,
        identity,
        observed_ns,
    )?;
    state.messages.push(DnsMessageObservation {
        identity,
        size: u64::try_from(response.len()).map_err(|_| DnsError::ResponseTooLarge)?,
        observed_ns,
    });
    Ok(parsed)
}

fn remaining_until(deadline: Instant) -> Result<Duration, DnsError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(DnsError::Deadline)?;
    if remaining.is_zero() {
        Err(DnsError::Deadline)
    } else {
        Ok(remaining)
    }
}

fn write_all_until(
    stream: &mut TcpStream,
    mut input: &[u8],
    deadline: Instant,
) -> Result<(), DnsError> {
    while !input.is_empty() {
        let remaining = remaining_until(deadline)?;
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|_| DnsError::RequestFailed)?;
        let written = stream.write(input).map_err(|error| {
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) {
                DnsError::Deadline
            } else {
                DnsError::RequestFailed
            }
        })?;
        if written == 0 {
            return Err(DnsError::RequestFailed);
        }
        input = &input[written..];
    }
    if Instant::now() >= deadline {
        Err(DnsError::Deadline)
    } else {
        Ok(())
    }
}

fn read_exact_until(
    stream: &mut TcpStream,
    mut output: &mut [u8],
    deadline: Instant,
) -> Result<(), DnsError> {
    while !output.is_empty() {
        let remaining = remaining_until(deadline)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| DnsError::ResponseFailed)?;
        let read = stream.read(output).map_err(|error| {
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) {
                DnsError::Deadline
            } else {
                DnsError::ResponseFailed
            }
        })?;
        if read == 0 {
            return Err(DnsError::ResponseFailed);
        }
        output = &mut output[read..];
    }
    if Instant::now() >= deadline {
        Err(DnsError::Deadline)
    } else {
        Ok(())
    }
}

fn resolver_socket(policy: &ResolutionPolicy) -> SocketAddr {
    let endpoint = policy.endpoint();
    let address = match endpoint.address() {
        ResolverAddress::Ipv4(bytes) => IpAddr::V4(Ipv4Addr::from(bytes)),
        ResolverAddress::Ipv6(bytes) => IpAddr::V6(Ipv6Addr::from(bytes)),
    };
    SocketAddr::new(address, endpoint.port().get())
}

fn random_transaction_id() -> Result<u16, DnsError> {
    let mut bytes = [0_u8; 2];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|_| DnsError::RandomUnavailable)?;
    Ok(u16::from_be_bytes(bytes))
}

fn encode_query(
    transaction: u16,
    name: &ServiceName,
    record_type: u16,
) -> Result<Vec<u8>, DnsError> {
    let mut query = Vec::with_capacity(DNS_HEADER_BYTES + name.as_str().len() + 6);
    query.extend_from_slice(&transaction.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    for label in name.as_str().split('.') {
        query.push(u8::try_from(label.len()).map_err(|_| DnsError::MalformedResponse)?);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&record_type.to_be_bytes());
    query.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(query)
}

fn parse_response(
    bytes: &[u8],
    expected_transaction: u16,
    expected_name: &ServiceName,
    expected_type: u16,
    message_identity: Sha256Digest,
    observed_ns: u64,
) -> Result<ParsedResponse, DnsError> {
    if bytes.len() < DNS_HEADER_BYTES || read_u16(bytes, 0)? != expected_transaction {
        return Err(DnsError::MalformedResponse);
    }
    let flags = read_u16(bytes, 2)?;
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 || flags & 0x0200 != 0 {
        return Err(DnsError::MalformedResponse);
    }
    if flags & 0x000f != 0 {
        return Err(DnsError::ResolverFailure);
    }
    let questions = usize::from(read_u16(bytes, 4)?);
    let answers = usize::from(read_u16(bytes, 6)?);
    let authority = usize::from(read_u16(bytes, 8)?);
    let additional = usize::from(read_u16(bytes, 10)?);
    if questions != 1 {
        return Err(DnsError::MalformedResponse);
    }
    let mut cursor = DNS_HEADER_BYTES;
    let (question, next) = read_name(bytes, cursor)?;
    cursor = next;
    if question != expected_name.as_str()
        || read_u16(bytes, cursor)? != expected_type
        || read_u16(bytes, cursor + 2)? != DNS_CLASS_IN
    {
        return Err(DnsError::MalformedResponse);
    }
    cursor = cursor.checked_add(4).ok_or(DnsError::MalformedResponse)?;

    let mut cnames = BTreeMap::<ServiceName, Vec<DnsCnameObservation>>::new();
    let mut addresses = Vec::new();
    for index in 0..answers.saturating_add(authority).saturating_add(additional) {
        let is_answer = index < answers;
        let (owner_text, next) = read_name(bytes, cursor)?;
        cursor = next;
        let record_type = read_u16(bytes, cursor)?;
        let class = read_u16(bytes, cursor + 2)?;
        let ttl = read_u32(bytes, cursor + 4)?;
        let data_length = usize::from(read_u16(bytes, cursor + 8)?);
        cursor = cursor.checked_add(10).ok_or(DnsError::MalformedResponse)?;
        let data_end = cursor
            .checked_add(data_length)
            .filter(|end| *end <= bytes.len())
            .ok_or(DnsError::MalformedResponse)?;
        if is_answer && class == DNS_CLASS_IN {
            let owner = ServiceName::new(owner_text).map_err(|_| DnsError::MalformedResponse)?;
            match record_type {
                DNS_TYPE_CNAME => {
                    let (target, consumed) = read_name(bytes, cursor)?;
                    if consumed != data_end {
                        return Err(DnsError::MalformedResponse);
                    }
                    let target =
                        ServiceName::new(target).map_err(|_| DnsError::MalformedResponse)?;
                    let record = cname_observation(
                        owner.clone(),
                        target,
                        message_identity,
                        ttl,
                        observed_ns,
                    )?;
                    cnames.entry(owner).or_default().push(record);
                }
                DNS_TYPE_A if expected_type == DNS_TYPE_A && data_length == 4 => {
                    let raw: [u8; 4] = bytes[cursor..data_end]
                        .try_into()
                        .map_err(|_| DnsError::MalformedResponse)?;
                    addresses.push(answer(
                        owner,
                        IpAddr::V4(Ipv4Addr::from(raw)),
                        message_identity,
                        ttl,
                        observed_ns,
                    )?);
                }
                DNS_TYPE_AAAA if expected_type == DNS_TYPE_AAAA && data_length == 16 => {
                    let raw: [u8; 16] = bytes[cursor..data_end]
                        .try_into()
                        .map_err(|_| DnsError::MalformedResponse)?;
                    addresses.push(answer(
                        owner,
                        IpAddr::V6(Ipv6Addr::from(raw)),
                        message_identity,
                        ttl,
                        observed_ns,
                    )?);
                }
                DNS_TYPE_A | DNS_TYPE_AAAA if record_type == expected_type => {
                    return Err(DnsError::MalformedResponse);
                }
                _ => {}
            }
        }
        cursor = data_end;
    }
    if cursor != bytes.len() {
        return Err(DnsError::MalformedResponse);
    }
    for targets in cnames.values_mut() {
        targets.sort_unstable_by(|left, right| {
            left.target
                .cmp(&right.target)
                .then(left.expires_ns.cmp(&right.expires_ns))
                .then(left.message_identity.cmp(&right.message_identity))
                .then(left.ttl_seconds.cmp(&right.ttl_seconds))
        });
        targets.dedup_by(|left, right| left.target == right.target);
    }
    Ok(ParsedResponse { cnames, addresses })
}

fn cname_observation(
    owner: ServiceName,
    target: ServiceName,
    message_identity: Sha256Digest,
    ttl_seconds: u32,
    observed_ns: u64,
) -> Result<DnsCnameObservation, DnsError> {
    let expires_ns = expiry(ttl_seconds, observed_ns)?;
    Ok(DnsCnameObservation {
        owner,
        target,
        message_identity,
        ttl_seconds,
        expires_ns,
    })
}

fn answer(
    name: ServiceName,
    address: IpAddr,
    message_identity: Sha256Digest,
    ttl_seconds: u32,
    observed_ns: u64,
) -> Result<DnsAnswer, DnsError> {
    let record_expires_ns = expiry(ttl_seconds, observed_ns)?;
    Ok(DnsAnswer {
        name,
        address,
        message_identity,
        ttl_seconds,
        record_expires_ns,
        effective_expires_ns: record_expires_ns,
    })
}

fn expiry(ttl_seconds: u32, observed_ns: u64) -> Result<u64, DnsError> {
    if ttl_seconds == 0 {
        return Err(DnsError::ExpiredAnswer);
    }
    u64::from(ttl_seconds)
        .checked_mul(1_000_000_000)
        .and_then(|ttl| observed_ns.checked_add(ttl))
        .ok_or(DnsError::ExpiredAnswer)
}

fn read_name(bytes: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut next = None;
    let mut visited = BTreeSet::new();
    for _ in 0..MAX_DNS_NAME_POINTERS {
        let length = *bytes.get(cursor).ok_or(DnsError::MalformedResponse)?;
        if length & 0xc0 == 0xc0 {
            let low = *bytes.get(cursor + 1).ok_or(DnsError::MalformedResponse)?;
            let pointer = usize::from((u16::from(length & 0x3f) << 8) | u16::from(low));
            if pointer >= bytes.len() || !visited.insert(pointer) {
                return Err(DnsError::MalformedResponse);
            }
            next.get_or_insert(cursor + 2);
            cursor = pointer;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(DnsError::MalformedResponse);
        }
        cursor += 1;
        if length == 0 {
            let end = next.unwrap_or(cursor);
            let name = labels.join(".");
            if name.len() > 253 {
                return Err(DnsError::MalformedResponse);
            }
            return Ok((name, end));
        }
        let end = cursor
            .checked_add(usize::from(length))
            .filter(|end| *end <= bytes.len())
            .ok_or(DnsError::MalformedResponse)?;
        let label = core::str::from_utf8(&bytes[cursor..end])
            .map_err(|_| DnsError::MalformedResponse)?
            .to_ascii_lowercase();
        if label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(DnsError::MalformedResponse);
        }
        labels.push(label);
        cursor = end;
    }
    Err(DnsError::MalformedResponse)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DnsError> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .and_then(|value| value.try_into().ok())
        .ok_or(DnsError::MalformedResponse)?;
    Ok(u16::from_be_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DnsError> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|value| value.try_into().ok())
        .ok_or(DnsError::MalformedResponse)?;
    Ok(u32::from_be_bytes(value))
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn address_key(address: IpAddr) -> (u8, [u8; 16]) {
    match address {
        IpAddr::V4(address) => {
            let mut bytes = [0_u8; 16];
            bytes[..4].copy_from_slice(&address.octets());
            (0, bytes)
        }
        IpAddr::V6(address) => (1, address.octets()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofbound_runtime_core::{
        AddressOrder, ChildChannelDescriptor, LocalChannelProtocol, MinimumTlsVersion,
        NetworkSupportPath, ResolverEndpoint, RevocationPolicy, ServiceNameVerification,
        ServiceSessionLimits, TlsPolicy,
    };

    fn authority(service: &str, dns_messages: u16) -> AuthenticatedServiceSession {
        let service = ServiceName::new(service).expect("valid service");
        let resolution = ResolutionPolicy::new(
            ResolverEndpoint::new(
                ResolverAddress::Ipv4([192, 0, 2, 53]),
                TcpPort::new(53).expect("valid resolver port"),
            ),
            NetworkSupportPath::new("/etc/proofbound/resolver.conf").expect("valid path"),
            4,
            4,
            4096,
            1000,
            100,
            AddressOrder::Ipv4ThenIpv6Lexicographic,
        )
        .expect("valid resolution policy");
        let tls = TlsPolicy::new(
            NetworkSupportPath::new("/etc/proofbound/roots.pem").expect("valid path"),
            MinimumTlsVersion::Tls13,
            ServiceNameVerification::DnsSanExact,
            RevocationPolicy::NotCheckedRecordedAssumption,
        );
        let limits = ServiceSessionLimits::new(2000, 3000, 4096, 4096, dns_messages, 4, 262_144, 4)
            .expect("valid limits");
        AuthenticatedServiceSession::new(
            service,
            TcpPort::new(443).expect("valid service port"),
            resolution,
            tls,
            limits,
            NetworkSupportPath::new("/usr/libexec/proofbound-connector").expect("valid path"),
            vec![NetworkSupportPath::new("/usr/lib").expect("valid path")],
            LocalChannelProtocol::UnixStreamV1,
            ChildChannelDescriptor::new(9).expect("valid descriptor"),
            None,
        )
        .expect("valid authority")
    }

    fn encoded_name(name: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        for label in name.split('.') {
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }
        encoded.push(0);
        encoded
    }

    fn response_with_records(
        transaction: u16,
        question_type: u16,
        records: &[(u16, u32, Vec<u8>)],
    ) -> Vec<u8> {
        let name = ServiceName::new("api.example.com").expect("valid name");
        let query = encode_query(transaction, &name, question_type).expect("query encodes");
        let mut message = Vec::new();
        message.extend_from_slice(&transaction.to_be_bytes());
        message.extend_from_slice(&0x8180_u16.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&(records.len() as u16).to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&query[DNS_HEADER_BYTES..]);
        for (record_type, ttl, data) in records {
            message.extend_from_slice(&[0xc0, 0x0c]);
            message.extend_from_slice(&record_type.to_be_bytes());
            message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
            message.extend_from_slice(&ttl.to_be_bytes());
            message.extend_from_slice(&(data.len() as u16).to_be_bytes());
            message.extend_from_slice(data);
        }
        message
    }

    fn response(transaction: u16, answer_type: u16, answer: &[u8], ttl: u32) -> Vec<u8> {
        response_with_records(
            transaction,
            answer_type,
            &[(answer_type, ttl, answer.to_vec())],
        )
    }

    #[test]
    fn parses_one_exact_a_answer() {
        let transaction = 0x1234;
        let bytes = response(transaction, DNS_TYPE_A, &[192, 0, 2, 7], 60);
        let service = ServiceName::new("api.example.com").expect("valid name");
        let parsed = parse_response(&bytes, transaction, &service, DNS_TYPE_A, digest(&bytes), 5)
            .expect("response parses");
        assert_eq!(parsed.addresses.len(), 1);
        assert_eq!(parsed.addresses[0].address(), "192.0.2.7".parse().unwrap());
        assert_eq!(parsed.addresses[0].record_expires_ns(), 60_000_000_005);
        assert_eq!(parsed.addresses[0].effective_expires_ns(), 60_000_000_005);
    }

    #[test]
    fn rejects_transaction_substitution() {
        let bytes = response(0x1234, DNS_TYPE_A, &[192, 0, 2, 7], 60);
        let service = ServiceName::new("api.example.com").expect("valid name");
        assert_eq!(
            parse_response(&bytes, 0x4321, &service, DNS_TYPE_A, digest(&bytes), 5),
            Err(DnsError::MalformedResponse)
        );
    }

    #[test]
    fn rejects_zero_ttl() {
        let transaction = 0x1234;
        let bytes = response(transaction, DNS_TYPE_AAAA, &[0; 16], 0);
        let service = ServiceName::new("api.example.com").expect("valid name");
        assert_eq!(
            parse_response(
                &bytes,
                transaction,
                &service,
                DNS_TYPE_AAAA,
                digest(&bytes),
                5,
            ),
            Err(DnsError::ExpiredAnswer)
        );
    }

    #[test]
    fn rejects_zero_cname_ttl() {
        let transaction = 0x1234;
        let bytes = response_with_records(
            transaction,
            DNS_TYPE_A,
            &[(DNS_TYPE_CNAME, 0, encoded_name("edge.example.com"))],
        );
        let service = ServiceName::new("api.example.com").expect("valid name");
        assert_eq!(
            parse_response(&bytes, transaction, &service, DNS_TYPE_A, digest(&bytes), 5),
            Err(DnsError::ExpiredAnswer)
        );
    }

    #[test]
    fn rejects_cname_and_address_coexistence() {
        let transaction = 0x1234;
        let bytes = response_with_records(
            transaction,
            DNS_TYPE_A,
            &[
                (DNS_TYPE_CNAME, 30, encoded_name("edge.example.com")),
                (DNS_TYPE_A, 60, vec![192, 0, 2, 7]),
            ],
        );
        let service = ServiceName::new("api.example.com").expect("valid name");
        let parsed = parse_response(&bytes, transaction, &service, DNS_TYPE_A, digest(&bytes), 5)
            .expect("wire response is structurally valid");
        assert_eq!(
            validated_owner_records(parsed, &service),
            Err(DnsError::InvalidCnameChain)
        );
    }

    #[test]
    fn cname_ttl_limits_terminal_answer_expiry() {
        let owner = ServiceName::new("api.example.com").expect("valid owner");
        let target = ServiceName::new("edge.example.com").expect("valid target");
        let identity = digest(b"dns-message");
        let chain = vec![
            cname_observation(owner, target.clone(), identity, 5, 10).expect("CNAME is valid"),
        ];
        let mut answers = vec![
            answer(
                target,
                "192.0.2.7".parse().expect("valid address"),
                identity,
                60,
                10,
            )
            .expect("answer is valid"),
        ];
        apply_chain_expiry(&mut answers, &chain);
        assert_eq!(answers[0].record_expires_ns(), 60_000_000_010);
        assert_eq!(answers[0].effective_expires_ns(), 5_000_000_010);
    }

    #[test]
    fn shortest_cross_family_cname_ttl_limits_every_answer() {
        let owner = ServiceName::new("api.example.com").expect("valid owner");
        let target = ServiceName::new("edge.example.com").expect("valid target");
        let ipv4_identity = digest(b"ipv4-dns-message");
        let ipv6_identity = digest(b"ipv6-dns-message");
        let ipv4 = RecordResolution {
            chain: vec![
                cname_observation(owner.clone(), target.clone(), ipv4_identity, 60, 10)
                    .expect("CNAME is valid"),
            ],
            answers: vec![
                answer(
                    target.clone(),
                    "192.0.2.7".parse().expect("valid address"),
                    ipv4_identity,
                    120,
                    10,
                )
                .expect("answer is valid"),
            ],
        };
        let ipv6 = RecordResolution {
            chain: vec![
                cname_observation(owner.clone(), target.clone(), ipv6_identity, 1, 20)
                    .expect("CNAME is valid"),
            ],
            answers: vec![
                answer(
                    target,
                    "2001:db8::7".parse().expect("valid address"),
                    ipv6_identity,
                    120,
                    20,
                )
                .expect("answer is valid"),
            ],
        };
        let chain = reconcile_chains(&owner, &ipv4, &ipv6, 4).expect("chains agree");
        let mut answers = ipv4
            .answers
            .into_iter()
            .chain(ipv6.answers)
            .collect::<Vec<_>>();
        canonicalize_answers(&mut answers);
        apply_chain_expiry(&mut answers, &chain);
        assert_eq!(chain[0].expires_ns(), 1_000_000_020);
        assert!(
            answers
                .iter()
                .all(|answer| answer.effective_expires_ns() == 1_000_000_020)
        );
    }

    #[test]
    fn duplicate_address_uses_earliest_terminal_expiry() {
        let name = ServiceName::new("api.example.com").expect("valid name");
        let address = "192.0.2.7".parse().expect("valid address");
        let mut answers = vec![
            answer(name.clone(), address, digest(b"later"), 60, 10).expect("answer is valid"),
            answer(name, address, digest(b"earlier"), 5, 20).expect("answer is valid"),
        ];
        canonicalize_answers(&mut answers);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].record_expires_ns(), 5_000_000_020);
        assert_eq!(answers[0].effective_expires_ns(), 5_000_000_020);
    }

    #[test]
    fn expired_absolute_deadline_fails_closed() {
        assert_eq!(
            remaining_until(Instant::now() - Duration::from_millis(1)),
            Err(DnsError::Deadline)
        );
    }

    #[test]
    fn rejects_compression_pointer_loop() {
        let bytes = [0xc0, 0x00];
        assert_eq!(read_name(&bytes, 0), Err(DnsError::MalformedResponse));
    }

    #[test]
    fn address_order_is_ipv4_then_ipv6() {
        let mut addresses = [
            "2001:db8::2".parse().unwrap(),
            "192.0.2.9".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
        ];
        addresses.sort_by_key(|address| address_key(*address));
        assert_eq!(
            addresses,
            [
                "192.0.2.1".parse().unwrap(),
                "192.0.2.9".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn resolution_retains_complete_service_and_limit_authority() {
        let authority = authority("api.example.com", 4);
        let resolution = DnsResolution {
            started: Instant::now(),
            authority: authority.clone(),
            messages: Vec::new(),
            cname_chain: Vec::new(),
            answers: Vec::new(),
        };
        assert_eq!(resolution.authority(), &authority);
        assert_eq!(resolution.authority().service().as_str(), "api.example.com");
        assert_eq!(resolution.authority().limits().dns_messages(), 4);
    }
}
