use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use proofbound_runtime_core::{
    ResolutionPolicy, ResolverAddress, ServiceName, Sha256Digest, TcpPort,
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
    expires_ns: u64,
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

    /// Returns the connector-relative monotonic expiry time.
    #[must_use]
    pub const fn expires_ns(&self) -> u64 {
        self.expires_ns
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
    port: TcpPort,
    attempt_deadline_ms: u64,
    messages: Vec<DnsMessageObservation>,
    cname_chain: Vec<ServiceName>,
    answers: Vec<DnsAnswer>,
}

impl DnsResolution {
    /// Returns the declared service port.
    #[must_use]
    pub const fn port(&self) -> TcpPort {
        self.port
    }

    /// Returns the per-endpoint connection deadline in milliseconds.
    #[must_use]
    pub const fn attempt_deadline_ms(&self) -> u64 {
        self.attempt_deadline_ms
    }

    /// Returns every observed DNS response in order.
    #[must_use]
    pub fn messages(&self) -> &[DnsMessageObservation] {
        &self.messages
    }

    /// Returns the complete nonempty service-to-terminal CNAME chain.
    #[must_use]
    pub fn cname_chain(&self) -> &[ServiceName] {
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
pub fn resolve_service(
    service: &ServiceName,
    port: TcpPort,
    policy: &ResolutionPolicy,
    maximum_messages: u16,
) -> Result<DnsResolution, DnsError> {
    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_millis(policy.resolution_deadline_ms()))
        .ok_or(DnsError::Deadline)?;
    let mut state = ResolverState {
        started,
        deadline,
        policy,
        maximum_messages,
        messages: Vec::new(),
    };
    let ipv4 = resolve_record_type(&mut state, service, DNS_TYPE_A)?;
    let ipv6 = resolve_record_type(&mut state, service, DNS_TYPE_AAAA)?;
    let chain = reconcile_chains(service, &ipv4, &ipv6, policy.maximum_cname_depth())?;
    let terminal = chain.last().ok_or(DnsError::InvalidCnameChain)?;

    let mut answers = ipv4
        .answers
        .into_iter()
        .chain(ipv6.answers)
        .filter(|answer| &answer.name == terminal)
        .collect::<Vec<_>>();
    answers
        .sort_unstable_by(|left, right| address_key(left.address).cmp(&address_key(right.address)));
    answers.dedup_by(|left, right| left.address == right.address);
    if answers.is_empty() || answers.len() > usize::from(policy.maximum_answer_count()) {
        return Err(DnsError::InvalidAnswerSet);
    }
    if answers
        .iter()
        .any(|answer| answer.expires_ns <= elapsed_ns(started))
    {
        return Err(DnsError::ExpiredAnswer);
    }

    Ok(DnsResolution {
        started,
        port,
        attempt_deadline_ms: policy.attempt_deadline_ms(),
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
    chain: Vec<ServiceName>,
    answers: Vec<DnsAnswer>,
}

fn resolve_record_type(
    state: &mut ResolverState<'_>,
    service: &ServiceName,
    record_type: u16,
) -> Result<RecordResolution, DnsError> {
    let mut chain = vec![service.clone()];
    let mut seen = BTreeSet::from([service.as_str().to_owned()]);
    loop {
        if chain.len().saturating_sub(1) > usize::from(state.policy.maximum_cname_depth()) {
            return Err(DnsError::InvalidCnameChain);
        }
        let current = chain.last().ok_or(DnsError::InvalidCnameChain)?.clone();
        let response = exchange_query(state, &current, record_type)?;
        let mut answers = response
            .addresses
            .into_iter()
            .filter(|answer| answer.name == current)
            .collect::<Vec<_>>();
        if !answers.is_empty() {
            answers.sort_unstable_by(|left, right| {
                address_key(left.address).cmp(&address_key(right.address))
            });
            answers.dedup_by(|left, right| left.address == right.address);
            return Ok(RecordResolution { chain, answers });
        }
        let Some(targets) = response.cnames.get(&current) else {
            return Ok(RecordResolution {
                chain,
                answers: Vec::new(),
            });
        };
        if targets.len() != 1 {
            return Err(DnsError::InvalidCnameChain);
        }
        let next = targets[0].clone();
        if !seen.insert(next.as_str().to_owned()) {
            return Err(DnsError::InvalidCnameChain);
        }
        chain.push(next);
    }
}

fn reconcile_chains(
    service: &ServiceName,
    ipv4: &RecordResolution,
    ipv6: &RecordResolution,
    maximum_depth: u16,
) -> Result<Vec<ServiceName>, DnsError> {
    let chain = if ipv4.answers.is_empty() {
        &ipv6.chain
    } else if ipv6.answers.is_empty() {
        &ipv4.chain
    } else if ipv4.chain == ipv6.chain {
        &ipv4.chain
    } else {
        return Err(DnsError::InvalidCnameChain);
    };
    if chain.first() != Some(service)
        || chain.is_empty()
        || chain.len().saturating_sub(1) > usize::from(maximum_depth)
    {
        return Err(DnsError::InvalidCnameChain);
    }
    for candidate in [&ipv4.chain, &ipv6.chain] {
        if candidate.len() > 1 && candidate != chain {
            return Err(DnsError::InvalidCnameChain);
        }
    }
    Ok(chain.clone())
}

#[derive(Debug, Eq, PartialEq)]
struct ParsedResponse {
    cnames: BTreeMap<ServiceName, Vec<ServiceName>>,
    addresses: Vec<DnsAnswer>,
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
    let timeout = remaining_timeout(state.deadline, state.policy.attempt_deadline_ms())?;
    let endpoint = resolver_socket(state.policy);
    let mut stream = TcpStream::connect_timeout(&endpoint, timeout)
        .map_err(|_| DnsError::ResolverUnavailable)?;
    let remaining = remaining_timeout(state.deadline, state.policy.attempt_deadline_ms())?;
    stream
        .set_read_timeout(Some(remaining))
        .and_then(|()| stream.set_write_timeout(Some(remaining)))
        .map_err(|_| DnsError::ResolverUnavailable)?;
    let length = u16::try_from(query.len()).map_err(|_| DnsError::RequestFailed)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(&query))
        .map_err(|_| DnsError::RequestFailed)?;

    let mut length_bytes = [0_u8; 2];
    stream
        .read_exact(&mut length_bytes)
        .map_err(|_| DnsError::ResponseFailed)?;
    let response_length = usize::from(u16::from_be_bytes(length_bytes));
    if response_length == 0
        || u64::try_from(response_length).unwrap_or(u64::MAX)
            > state.policy.maximum_response_bytes()
    {
        return Err(DnsError::ResponseTooLarge);
    }
    let mut response = vec![0_u8; response_length];
    stream
        .read_exact(&mut response)
        .map_err(|_| DnsError::ResponseFailed)?;
    if Instant::now() >= state.deadline {
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

fn remaining_timeout(deadline: Instant, attempt_ms: u64) -> Result<Duration, DnsError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(DnsError::Deadline)?;
    let timeout = remaining.min(Duration::from_millis(attempt_ms));
    if timeout.is_zero() {
        Err(DnsError::Deadline)
    } else {
        Ok(timeout)
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

    let mut cnames = BTreeMap::<ServiceName, Vec<ServiceName>>::new();
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
                    cnames.entry(owner).or_default().push(target);
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
        targets.sort_unstable();
        targets.dedup();
    }
    Ok(ParsedResponse { cnames, addresses })
}

fn answer(
    name: ServiceName,
    address: IpAddr,
    message_identity: Sha256Digest,
    ttl_seconds: u32,
    observed_ns: u64,
) -> Result<DnsAnswer, DnsError> {
    if ttl_seconds == 0 {
        return Err(DnsError::ExpiredAnswer);
    }
    let expires_ns = u64::from(ttl_seconds)
        .checked_mul(1_000_000_000)
        .and_then(|ttl| observed_ns.checked_add(ttl))
        .ok_or(DnsError::ExpiredAnswer)?;
    Ok(DnsAnswer {
        name,
        address,
        message_identity,
        ttl_seconds,
        expires_ns,
    })
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

    fn response(transaction: u16, answer_type: u16, answer: &[u8], ttl: u32) -> Vec<u8> {
        let name = ServiceName::new("api.example.com").expect("valid name");
        let query = encode_query(transaction, &name, answer_type).expect("query encodes");
        let mut message = Vec::new();
        message.extend_from_slice(&transaction.to_be_bytes());
        message.extend_from_slice(&0x8180_u16.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&query[DNS_HEADER_BYTES..]);
        message.extend_from_slice(&[0xc0, 0x0c]);
        message.extend_from_slice(&answer_type.to_be_bytes());
        message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        message.extend_from_slice(&ttl.to_be_bytes());
        message.extend_from_slice(&(answer.len() as u16).to_be_bytes());
        message.extend_from_slice(answer);
        message
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
        assert_eq!(parsed.addresses[0].expires_ns(), 60_000_000_005);
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
}
