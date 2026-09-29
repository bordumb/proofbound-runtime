//! Bounded DNS-over-TCP wire facts for proxy-owned declared-name resolution.
//!
//! The record and compression checks follow the Specification 0016 resolver.
//! This profile retains TTL zero for the triggering connection only; the
//! existing authenticated-service connector continues to reject TTL zero.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proofbound_runtime_core::{EgressName, ServiceName, Sha256Digest};
use sha2::{Digest as _, Sha256};

const DNS_HEADER_BYTES: usize = 12;
const DNS_CLASS_IN: u16 = 1;
const MAX_DNS_NAME_POINTERS: usize = 128;

/// The only DNS record types the proxy queries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsRecordType {
    A,
    Aaaa,
}

impl DnsRecordType {
    const fn number(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

/// One declared query bound to a caller-supplied random transaction ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuery {
    name: ServiceName,
    record_type: DnsRecordType,
    transaction: u16,
}

impl DnsQuery {
    #[must_use]
    pub const fn new(name: ServiceName, record_type: DnsRecordType, transaction: u16) -> Self {
        Self {
            name,
            record_type,
            transaction,
        }
    }

    /// Converts a validated declared endpoint name to the DNS wire grammar.
    #[must_use]
    pub fn for_declared(name: &EgressName, record_type: DnsRecordType, transaction: u16) -> Self {
        Self::new(
            ServiceName::new(name.as_str().to_owned()).expect("egress name is a service name"),
            record_type,
            transaction,
        )
    }

    #[must_use]
    pub const fn name(&self) -> &ServiceName {
        &self.name
    }

    #[must_use]
    pub const fn record_type(&self) -> DnsRecordType {
        self.record_type
    }

    /// Encodes exactly one length-prefixed DNS-over-TCP request.
    #[must_use]
    pub fn tcp_frame(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(DNS_HEADER_BYTES + self.name.as_str().len() + 6);
        message.extend_from_slice(&self.transaction.to_be_bytes());
        message.extend_from_slice(&0x0100_u16.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&[0; 6]);
        for label in self.name.as_str().split('.') {
            message.push(u8::try_from(label.len()).expect("validated DNS label length"));
            message.extend_from_slice(label.as_bytes());
        }
        message.push(0);
        message.extend_from_slice(&self.record_type.number().to_be_bytes());
        message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        let mut frame = Vec::with_capacity(message.len() + 2);
        frame.extend_from_slice(
            &u16::try_from(message.len())
                .expect("validated DNS name bounds query size")
                .to_be_bytes(),
        );
        frame.extend_from_slice(&message);
        frame
    }
}

/// A closed parser outcome for one DNS response message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsWireError {
    TooLarge,
    Malformed,
    QueryMismatch,
    Truncated,
    ResolverFailure,
    ExpiryOverflow,
}

impl DnsWireError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooLarge => "network.egress.dns.response-too-large",
            Self::Malformed => "network.egress.dns.response-malformed",
            Self::QueryMismatch => "network.egress.dns.query-mismatch",
            Self::Truncated => "network.egress.dns.response-truncated",
            Self::ResolverFailure => "network.egress.dns.resolver-failure",
            Self::ExpiryOverflow => "network.egress.dns.expiry-overflow",
        }
    }
}

/// One response-bound terminal A or AAAA record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsAddressRecord {
    pub owner: ServiceName,
    pub address: IpAddr,
    pub ttl_seconds: u32,
    pub record_expiry_ms: u64,
    pub message_identity: Sha256Digest,
}

/// One response-bound alias edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsCnameRecord {
    pub owner: ServiceName,
    pub target: ServiceName,
    pub ttl_seconds: u32,
    pub expiry_ms: u64,
    pub message_identity: Sha256Digest,
}

/// Records exact response identity and validated answer facts, never packet bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsWireResponse {
    pub identity: Sha256Digest,
    pub size: u16,
    pub finished_ms: u64,
    pub addresses: Vec<DnsAddressRecord>,
    pub cnames: BTreeMap<ServiceName, Vec<DnsCnameRecord>>,
}

/// Decode one complete DNS message received over the declared TCP resolver.
///
/// The caller must validate the two-byte TCP length before allocation. This
/// decoder independently enforces the declared response bound.
pub fn parse_dns_response(
    query: &DnsQuery,
    bytes: &[u8],
    maximum_response_bytes: u64,
    finished_ms: u64,
) -> Result<DnsWireResponse, DnsWireError> {
    if bytes.len() > usize::try_from(maximum_response_bytes).unwrap_or(usize::MAX)
        || bytes.len() > usize::from(u16::MAX)
    {
        return Err(DnsWireError::TooLarge);
    }
    if bytes.len() < DNS_HEADER_BYTES {
        return Err(DnsWireError::Malformed);
    }
    if read_u16(bytes, 0)? != query.transaction {
        return Err(DnsWireError::QueryMismatch);
    }
    let flags = read_u16(bytes, 2)?;
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 {
        return Err(DnsWireError::Malformed);
    }
    if flags & 0x0200 != 0 {
        return Err(DnsWireError::Truncated);
    }
    if flags & 0x000f != 0 {
        return Err(DnsWireError::ResolverFailure);
    }
    let questions = usize::from(read_u16(bytes, 4)?);
    let answers = usize::from(read_u16(bytes, 6)?);
    let authority = usize::from(read_u16(bytes, 8)?);
    let additional = usize::from(read_u16(bytes, 10)?);
    if questions != 1 {
        return Err(DnsWireError::Malformed);
    }
    let record_count = answers
        .checked_add(authority)
        .and_then(|n| n.checked_add(additional))
        .ok_or(DnsWireError::Malformed)?;
    if record_count > bytes.len() / 11 {
        return Err(DnsWireError::Malformed);
    }
    let mut cursor = DNS_HEADER_BYTES;
    let (question, next) = read_name(bytes, cursor)?;
    cursor = next;
    if question != query.name
        || read_u16(bytes, cursor)? != query.record_type.number()
        || read_u16(bytes, cursor + 2)? != DNS_CLASS_IN
    {
        return Err(DnsWireError::QueryMismatch);
    }
    cursor = cursor.checked_add(4).ok_or(DnsWireError::Malformed)?;
    let identity = Sha256Digest::from_bytes(Sha256::digest(bytes).into());
    let mut addresses = Vec::new();
    let mut cnames = BTreeMap::<ServiceName, Vec<DnsCnameRecord>>::new();
    for index in 0..record_count {
        let is_answer = index < answers;
        let (owner, next) = read_name(bytes, cursor)?;
        cursor = next;
        let kind = read_u16(bytes, cursor)?;
        let class = read_u16(bytes, cursor + 2)?;
        let ttl_seconds = read_u32(bytes, cursor + 4)?;
        let data_length = usize::from(read_u16(bytes, cursor + 8)?);
        cursor = cursor.checked_add(10).ok_or(DnsWireError::Malformed)?;
        let data_end = cursor
            .checked_add(data_length)
            .filter(|end| *end <= bytes.len())
            .ok_or(DnsWireError::Malformed)?;
        if is_answer && class == DNS_CLASS_IN {
            match kind {
                5 => {
                    let (target, consumed) = read_name(bytes, cursor)?;
                    if consumed != data_end {
                        return Err(DnsWireError::Malformed);
                    }
                    let expiry_ms = expiry(ttl_seconds, finished_ms)?;
                    cnames
                        .entry(owner.clone())
                        .or_default()
                        .push(DnsCnameRecord {
                            owner,
                            target,
                            ttl_seconds,
                            expiry_ms,
                            message_identity: identity,
                        });
                }
                1 if query.record_type == DnsRecordType::A && data_length == 4 => {
                    let raw: [u8; 4] = bytes[cursor..data_end]
                        .try_into()
                        .map_err(|_| DnsWireError::Malformed)?;
                    addresses.push(DnsAddressRecord {
                        owner,
                        address: IpAddr::V4(Ipv4Addr::from(raw)),
                        ttl_seconds,
                        record_expiry_ms: expiry(ttl_seconds, finished_ms)?,
                        message_identity: identity,
                    });
                }
                28 if query.record_type == DnsRecordType::Aaaa && data_length == 16 => {
                    let raw: [u8; 16] = bytes[cursor..data_end]
                        .try_into()
                        .map_err(|_| DnsWireError::Malformed)?;
                    addresses.push(DnsAddressRecord {
                        owner,
                        address: IpAddr::V6(Ipv6Addr::from(raw)),
                        ttl_seconds,
                        record_expiry_ms: expiry(ttl_seconds, finished_ms)?,
                        message_identity: identity,
                    });
                }
                1 | 28 if kind == query.record_type.number() => {
                    return Err(DnsWireError::Malformed);
                }
                _ => {}
            }
        }
        cursor = data_end;
    }
    if cursor != bytes.len() {
        return Err(DnsWireError::Malformed);
    }
    for records in cnames.values_mut() {
        records.sort_unstable_by(|a, b| {
            a.target
                .cmp(&b.target)
                .then(a.expiry_ms.cmp(&b.expiry_ms))
                .then(a.message_identity.cmp(&b.message_identity))
        });
        records.dedup_by(|a, b| a.target == b.target);
    }
    Ok(DnsWireResponse {
        identity,
        size: u16::try_from(bytes.len()).map_err(|_| DnsWireError::TooLarge)?,
        finished_ms,
        addresses,
        cnames,
    })
}

fn expiry(ttl_seconds: u32, finished_ms: u64) -> Result<u64, DnsWireError> {
    u64::from(ttl_seconds)
        .checked_mul(1000)
        .and_then(|ttl| finished_ms.checked_add(ttl))
        .ok_or(DnsWireError::ExpiryOverflow)
}

fn read_name(bytes: &[u8], start: usize) -> Result<(ServiceName, usize), DnsWireError> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut next = None;
    let mut visited = std::collections::BTreeSet::new();
    for _ in 0..MAX_DNS_NAME_POINTERS {
        let length = *bytes.get(cursor).ok_or(DnsWireError::Malformed)?;
        if length & 0xc0 == 0xc0 {
            let low = *bytes.get(cursor + 1).ok_or(DnsWireError::Malformed)?;
            let pointer = usize::from((u16::from(length & 0x3f) << 8) | u16::from(low));
            if pointer >= bytes.len() || !visited.insert(pointer) {
                return Err(DnsWireError::Malformed);
            }
            next.get_or_insert(cursor + 2);
            cursor = pointer;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(DnsWireError::Malformed);
        }
        cursor += 1;
        if length == 0 {
            return ServiceName::new(labels.join("."))
                .map(|name| (name, next.unwrap_or(cursor)))
                .map_err(|_| DnsWireError::Malformed);
        }
        let end = cursor
            .checked_add(usize::from(length))
            .filter(|end| *end <= bytes.len())
            .ok_or(DnsWireError::Malformed)?;
        let label = core::str::from_utf8(&bytes[cursor..end])
            .map_err(|_| DnsWireError::Malformed)?
            .to_ascii_lowercase();
        labels.push(label);
        cursor = end;
    }
    Err(DnsWireError::Malformed)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DnsWireError> {
    let value: [u8; 2] = bytes
        .get(offset..offset.saturating_add(2))
        .and_then(|slice| slice.try_into().ok())
        .ok_or(DnsWireError::Malformed)?;
    Ok(u16::from_be_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DnsWireError> {
    let value: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|slice| slice.try_into().ok())
        .ok_or(DnsWireError::Malformed)?;
    Ok(u32::from_be_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(query: &DnsQuery, ttl: u32, address: [u8; 4]) -> Vec<u8> {
        let mut bytes = query.tcp_frame()[2..].to_vec();
        bytes[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[0xc0, 0x0c]);
        bytes.extend_from_slice(&[0, 1, 0, 1]);
        bytes.extend_from_slice(&ttl.to_be_bytes());
        bytes.extend_from_slice(&4_u16.to_be_bytes());
        bytes.extend_from_slice(&address);
        bytes
    }

    #[test]
    fn query_is_exact_tcp_frame_and_response_retains_zero_ttl() {
        let name = ServiceName::new("api.example").unwrap();
        let query = DnsQuery::new(name, DnsRecordType::A, 0x1234);
        let frame = query.tcp_frame();
        assert_eq!(
            usize::from(u16::from_be_bytes([frame[0], frame[1]])),
            frame.len() - 2
        );
        let response = reply(&query, 0, [8, 8, 8, 8]);
        let facts = parse_dns_response(&query, &response, 512, 100).unwrap();
        assert_eq!(facts.addresses.len(), 1);
        assert_eq!(facts.addresses[0].record_expiry_ms, 100);
        assert_eq!(facts.addresses[0].ttl_seconds, 0);
        assert_eq!(
            facts.addresses[0].address,
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn reply_must_bind_query_and_fit_bound() {
        let query = DnsQuery::new(
            ServiceName::new("api.example").unwrap(),
            DnsRecordType::A,
            1,
        );
        let mut response = reply(&query, 5, [8, 8, 8, 8]);
        assert_eq!(
            parse_dns_response(&query, &response, 12, 0),
            Err(DnsWireError::TooLarge)
        );
        response[0] = 9;
        assert_eq!(
            parse_dns_response(&query, &response, 512, 0),
            Err(DnsWireError::QueryMismatch)
        );
    }

    #[test]
    fn compression_cycles_and_truncated_records_fail_closed() {
        let query = DnsQuery::new(
            ServiceName::new("api.example").unwrap(),
            DnsRecordType::A,
            1,
        );
        let mut response = reply(&query, 5, [8, 8, 8, 8]);
        let pointer = response.len() - 16;
        response[pointer..pointer + 2].copy_from_slice(&[0xc0, u8::try_from(pointer).unwrap()]);
        assert_eq!(
            parse_dns_response(&query, &response, 512, 0),
            Err(DnsWireError::Malformed)
        );
        let mut response = reply(&query, 5, [8, 8, 8, 8]);
        response.pop();
        assert_eq!(
            parse_dns_response(&query, &response, 512, 0),
            Err(DnsWireError::Malformed)
        );
    }
}
