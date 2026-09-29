//! Pure bounded parsers and admission for the proposed declared-egress proxy.

#[path = "egress_proxy/budget.rs"]
mod budget;
pub use budget::{ByteGrant, ProxyBudget, ProxyLimit, ProxyTotals};
#[path = "egress_proxy/dns.rs"]
mod dns;
pub use dns::{
    DnsAddressRecord, DnsCnameRecord, DnsQuery, DnsRecordType, DnsWireError, DnsWireResponse,
    parse_dns_response,
};
#[path = "egress_proxy/observation.rs"]
mod observation;
pub use observation::{
    AttemptFact, AttemptResult, CloseReason, ConnectionFact, ConnectionTerminal, OpenConnection,
    ProxyObservationLedger, ProxyRecordError, RejectionFact, RejectionReason, SniObservation,
    TargetKind,
};
#[path = "egress_proxy/lifecycle.rs"]
mod lifecycle;
pub use lifecycle::{ProxyFailure, ProxyLifecycle, ProxyPhase, ProxyPhaseError};
#[path = "egress_proxy/resolution.rs"]
mod resolution;
pub use resolution::{
    DnsAnswerFact, DnsMessageFact, DnsResolutionError, DnsResolutionFacts, DnsResolutionMachine,
    DnsResolutionOutcome, ResolutionCoordinator, ResolutionRequest,
};
#[path = "egress_proxy/session.rs"]
mod session;
pub use session::{ProxySession, RejectedRequest, SessionEvent};
#[cfg(target_os = "linux")]
#[path = "egress_proxy/engine.rs"]
mod engine;
#[cfg(target_os = "linux")]
#[path = "egress_proxy/relay.rs"]
mod relay;
#[cfg(target_os = "linux")]
pub use engine::{EgressProxyEngine, EgressProxyEngineError, ProxyReportEvent};
#[cfg(target_os = "linux")]
#[path = "egress_proxy/report.rs"]
mod report;
#[cfg(target_os = "linux")]
pub use report::{MAX_PROXY_REPORT_BYTES, ProxyReportError, encode_proxy_report};
#[cfg(target_os = "linux")]
#[path = "egress_proxy/transport.rs"]
mod transport;
#[cfg(target_os = "linux")]
pub use relay::{RelayPair, RelayReady, RelayStep};
#[cfg(target_os = "linux")]
pub use transport::{
    DnsPollOutcome, DnsTcpExchange, DnsTransportError, PendingTcpConnect, poll_connect_attempts,
    poll_dns_exchanges,
};

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr as _;

use proofbound_runtime_core::{
    EgressAuthority, EgressDestination, EgressName, SniBinding, TcpPort, TunnelDecision,
    TunnelDenial, TunnelTarget, decide_tunnel,
};

pub const MAX_CONNECT_HEAD_BYTES: usize = 8192;
pub const MAX_CLIENT_HELLO_BYTES: usize = 16_384;
pub const MAX_CLIENT_HELLO_RECORDS: usize = 4;

/// Fixed proxy response bytes. No child-provided header or error text is sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyStatus {
    Established,
    BadRequest,
    Forbidden,
    MethodNotAllowed,
    TooManyRequests,
    BadGateway,
}

impl ProxyStatus {
    #[must_use]
    pub const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Established => b"HTTP/1.1 200 Connection established\r\n\r\n",
            Self::BadRequest => b"HTTP/1.1 400 Bad Request\r\n\r\n",
            Self::Forbidden => b"HTTP/1.1 403 Forbidden\r\n\r\n",
            Self::MethodNotAllowed => b"HTTP/1.1 405 Method Not Allowed\r\n\r\n",
            Self::TooManyRequests => b"HTTP/1.1 429 Too Many Requests\r\n\r\n",
            Self::BadGateway => b"HTTP/1.1 502 Bad Gateway\r\n\r\n",
        }
    }

    #[must_use]
    pub const fn from_rejection(rejection: RequestRejection) -> Self {
        match rejection {
            RequestRejection::MethodNotConnect => Self::MethodNotAllowed,
            RequestRejection::EndpointUndeclared => Self::Forbidden,
            RequestRejection::RequestMalformed
            | RequestRejection::RequestHeadTooLarge
            | RequestRejection::TargetNoncanonical => Self::BadRequest,
        }
    }
}

/// A complete canonical CONNECT head and its first tunneled byte offset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectHead {
    pub target: TunnelTarget,
    pub port: TcpPort,
    pub payload_offset: usize,
}

/// One fail-closed CONNECT parser outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectParseError {
    Incomplete,
    HeadTooLarge,
    MethodNotConnect,
    Malformed,
    NonCanonicalTarget,
}

impl ConnectParseError {
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::MethodNotConnect => 405,
            Self::Incomplete | Self::HeadTooLarge | Self::Malformed | Self::NonCanonicalTarget => {
                400
            }
        }
    }
}

/// Parse exactly one HTTP/1.0 or HTTP/1.1 CONNECT head.
///
/// Bytes after the head terminator are left untouched for the tunnel.
pub fn parse_connect_head(input: &[u8]) -> Result<ConnectHead, ConnectParseError> {
    let terminator = input
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4);
    let Some(end) = terminator else {
        return if input.len() >= MAX_CONNECT_HEAD_BYTES {
            Err(ConnectParseError::HeadTooLarge)
        } else {
            Err(ConnectParseError::Incomplete)
        };
    };
    if end > MAX_CONNECT_HEAD_BYTES {
        return Err(ConnectParseError::HeadTooLarge);
    }
    let head = &input[..end];
    let mut lines = head.split(|byte| *byte == b'\n');
    let request = lines.next().ok_or(ConnectParseError::Malformed)?;
    let request = request
        .strip_suffix(b"\r")
        .ok_or(ConnectParseError::Malformed)?;
    let mut words = request.split(|byte| *byte == b' ');
    let method = words.next().ok_or(ConnectParseError::Malformed)?;
    if method != b"CONNECT" {
        return Err(ConnectParseError::MethodNotConnect);
    }
    let authority = words.next().ok_or(ConnectParseError::Malformed)?;
    let version = words.next().ok_or(ConnectParseError::Malformed)?;
    if words.next().is_some() || !matches!(version, b"HTTP/1.0" | b"HTTP/1.1") {
        return Err(ConnectParseError::Malformed);
    }
    let (target, port) = parse_authority(authority)?;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let line = line
            .strip_suffix(b"\r")
            .ok_or(ConnectParseError::Malformed)?;
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err(ConnectParseError::Malformed);
        };
        if colon == 0
            || !line[..colon].iter().all(|byte| is_http_token(*byte))
            || !line[colon + 1..]
                .iter()
                .all(|byte| *byte == b'\t' || (0x20..=0x7e).contains(byte))
        {
            return Err(ConnectParseError::Malformed);
        }
    }
    Ok(ConnectHead {
        target,
        port,
        payload_offset: end,
    })
}

fn is_http_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn parse_authority(authority: &[u8]) -> Result<(TunnelTarget, TcpPort), ConnectParseError> {
    if authority.is_empty() || !authority.is_ascii() {
        return Err(ConnectParseError::NonCanonicalTarget);
    }
    if authority[0] == b'[' {
        let close = authority
            .iter()
            .position(|byte| *byte == b']')
            .ok_or(ConnectParseError::NonCanonicalTarget)?;
        if authority.get(close + 1) != Some(&b':') {
            return Err(ConnectParseError::NonCanonicalTarget);
        }
        let address = std::str::from_utf8(&authority[1..close])
            .map_err(|_| ConnectParseError::NonCanonicalTarget)?;
        if address.contains('%') {
            return Err(ConnectParseError::NonCanonicalTarget);
        }
        let parsed =
            Ipv6Addr::from_str(address).map_err(|_| ConnectParseError::NonCanonicalTarget)?;
        if parsed.to_ipv4_mapped().is_some() {
            return Err(ConnectParseError::NonCanonicalTarget);
        }
        let port = parse_port(&authority[close + 2..])?;
        return Ok((TunnelTarget::Ipv6(parsed.octets()), port));
    }
    let colon = authority
        .iter()
        .rposition(|byte| *byte == b':')
        .ok_or(ConnectParseError::NonCanonicalTarget)?;
    let host = std::str::from_utf8(&authority[..colon])
        .map_err(|_| ConnectParseError::NonCanonicalTarget)?;
    let port = parse_port(&authority[colon + 1..])?;
    if host.contains(':') || host.is_empty() {
        return Err(ConnectParseError::NonCanonicalTarget);
    }
    if let Ok(address) = Ipv4Addr::from_str(host) {
        if address.to_string() != host {
            return Err(ConnectParseError::NonCanonicalTarget);
        }
        return Ok((TunnelTarget::Ipv4(address.octets()), port));
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(ConnectParseError::NonCanonicalTarget);
    }
    let lowercase = host.to_ascii_lowercase();
    let name = EgressName::new(lowercase).map_err(|_| ConnectParseError::NonCanonicalTarget)?;
    Ok((TunnelTarget::DnsName(name), port))
}

fn parse_port(bytes: &[u8]) -> Result<TcpPort, ConnectParseError> {
    if bytes.is_empty() || bytes.len() > 5 || (bytes.len() > 1 && bytes[0] == b'0') {
        return Err(ConnectParseError::NonCanonicalTarget);
    }
    if !bytes.iter().all(u8::is_ascii_digit) {
        return Err(ConnectParseError::NonCanonicalTarget);
    }
    let port = std::str::from_utf8(bytes)
        .map_err(|_| ConnectParseError::NonCanonicalTarget)?
        .parse::<u16>()
        .map_err(|_| ConnectParseError::NonCanonicalTarget)?;
    TcpPort::new(port).map_err(|_| ConnectParseError::NonCanonicalTarget)
}

/// A bounded first-ClientHello parse result. No TLS authentication is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SniParseError {
    Incomplete,
    TooLarge,
    TooManyRecords,
    Malformed,
    Absent,
    EncryptedClientHello,
}

/// Read only the plaintext SNI from the first TLS ClientHello.
///
/// The caller must retain and forward the original bytes unchanged after a
/// successful decision. This parser never authenticates the remote peer.
pub fn parse_client_hello_sni(input: &[u8]) -> Result<EgressName, SniParseError> {
    let mut cursor = 0;
    let mut record_count = 0;
    let mut handshake = Vec::new();
    while cursor < input.len() && record_count < MAX_CLIENT_HELLO_RECORDS {
        if input.len() - cursor < 5 {
            return Err(SniParseError::Incomplete);
        }
        let header = &input[cursor..cursor + 5];
        if header[0] != 22 || header[1] != 3 || !(1..=3).contains(&header[2]) {
            return Err(SniParseError::Malformed);
        }
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if length == 0 || length > MAX_CLIENT_HELLO_BYTES {
            return Err(SniParseError::TooLarge);
        }
        cursor += 5;
        if input.len() - cursor < length {
            return Err(SniParseError::Incomplete);
        }
        if handshake.len().saturating_add(length) > MAX_CLIENT_HELLO_BYTES {
            return Err(SniParseError::TooLarge);
        }
        handshake.extend_from_slice(&input[cursor..cursor + length]);
        cursor += length;
        record_count += 1;
        if handshake.len() >= 4 {
            if handshake[0] != 1 {
                return Err(SniParseError::Malformed);
            }
            let declared = (usize::from(handshake[1]) << 16)
                | (usize::from(handshake[2]) << 8)
                | usize::from(handshake[3]);
            if declared > MAX_CLIENT_HELLO_BYTES - 4 {
                return Err(SniParseError::TooLarge);
            }
            if handshake.len() >= declared + 4 {
                return parse_client_hello_body(&handshake[4..4 + declared]);
            }
        }
    }
    if record_count == MAX_CLIENT_HELLO_RECORDS {
        Err(SniParseError::TooManyRecords)
    } else {
        Err(SniParseError::Incomplete)
    }
}

fn parse_client_hello_body(mut body: &[u8]) -> Result<EgressName, SniParseError> {
    take_tls(&mut body, 2)?; // legacy_version
    take_tls(&mut body, 32)?; // random
    let session_length = usize::from(take_tls(&mut body, 1)?[0]);
    if session_length > 32 {
        return Err(SniParseError::Malformed);
    }
    take_tls(&mut body, session_length)?;
    let cipher_length = tls_u16(&mut body)?;
    if cipher_length == 0 || cipher_length % 2 != 0 {
        return Err(SniParseError::Malformed);
    }
    take_tls(&mut body, cipher_length)?;
    let compression_length = usize::from(take_tls(&mut body, 1)?[0]);
    if compression_length == 0 {
        return Err(SniParseError::Malformed);
    }
    take_tls(&mut body, compression_length)?;
    let extension_length = tls_u16(&mut body)?;
    let mut extensions = take_tls(&mut body, extension_length)?;
    if !body.is_empty() {
        return Err(SniParseError::Malformed);
    }
    let mut seen = BTreeSet::new();
    let mut name = None;
    while !extensions.is_empty() {
        let kind = tls_u16(&mut extensions)?;
        let length = tls_u16(&mut extensions)?;
        let value = take_tls(&mut extensions, length)?;
        if !seen.insert(kind) {
            return Err(SniParseError::Malformed);
        }
        if kind == 0xfe0d {
            return Err(SniParseError::EncryptedClientHello);
        }
        if kind == 0 {
            name = Some(parse_server_name_extension(value)?);
        }
    }
    name.ok_or(SniParseError::Absent)
}

fn parse_server_name_extension(mut value: &[u8]) -> Result<EgressName, SniParseError> {
    let length = tls_u16(&mut value)?;
    if value.len() != length {
        return Err(SniParseError::Malformed);
    }
    let kind = take_tls(&mut value, 1)?[0];
    if kind != 0 {
        return Err(SniParseError::Malformed);
    }
    let name_length = tls_u16(&mut value)?;
    let name = take_tls(&mut value, name_length)?;
    if !value.is_empty() || !name.is_ascii() {
        return Err(SniParseError::Malformed);
    }
    let name = std::str::from_utf8(name).map_err(|_| SniParseError::Malformed)?;
    EgressName::new(name.to_ascii_lowercase()).map_err(|_| SniParseError::Malformed)
}

fn tls_u16(input: &mut &[u8]) -> Result<usize, SniParseError> {
    let bytes = take_tls(input, 2)?;
    Ok(usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
}

fn take_tls<'a>(input: &mut &'a [u8], size: usize) -> Result<&'a [u8], SniParseError> {
    if input.len() < size {
        return Err(SniParseError::Malformed);
    }
    let (head, tail) = input.split_at(size);
    *input = tail;
    Ok(head)
}

/// A request rejection that can be retained without storing child-chosen text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestRejection {
    MethodNotConnect,
    RequestMalformed,
    RequestHeadTooLarge,
    TargetNoncanonical,
    EndpointUndeclared,
}

impl RequestRejection {
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::MethodNotConnect => 405,
            Self::EndpointUndeclared => 403,
            Self::RequestMalformed | Self::RequestHeadTooLarge | Self::TargetNoncanonical => 400,
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
        }
    }
}

impl RequestRejection {
    fn from_complete_error(error: ConnectParseError) -> Self {
        match error {
            ConnectParseError::Incomplete | ConnectParseError::Malformed => Self::RequestMalformed,
            ConnectParseError::HeadTooLarge => Self::RequestHeadTooLarge,
            ConnectParseError::MethodNotConnect => Self::MethodNotConnect,
            ConnectParseError::NonCanonicalTarget => Self::TargetNoncanonical,
        }
    }
}

/// An admitted required-SNI request. The caller sends 200 before reading TLS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwaitSni {
    endpoint_index: usize,
    head: ConnectHead,
}

impl AwaitSni {
    #[must_use]
    pub const fn endpoint_index(&self) -> usize {
        self.endpoint_index
    }

    #[must_use]
    pub const fn payload_offset(&self) -> usize {
        self.head.payload_offset
    }
}

/// A pure first-stage decision. It performs no DNS or remote socket operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyAdmission {
    Incomplete,
    Rejected(RequestRejection),
    AwaitSni(AwaitSni),
    Destination(TunnelDecision),
}

/// Require a declared endpoint before any DNS lookup or remote connection.
///
/// A required-SNI endpoint cannot produce `Destination` in this stage.
pub fn admit_connect(
    authority: &EgressAuthority,
    input: &[u8],
    connection_id: u64,
    now_ms: u64,
) -> ProxyAdmission {
    let head = match parse_connect_head(input) {
        Ok(head) => head,
        Err(ConnectParseError::Incomplete) => return ProxyAdmission::Incomplete,
        Err(error) => {
            return ProxyAdmission::Rejected(RequestRejection::from_complete_error(error));
        }
    };
    let endpoint = authority
        .endpoints()
        .iter()
        .enumerate()
        .find(|(_, endpoint)| {
            endpoint.port == head.port
                && match (&endpoint.destination, &head.target) {
                    (EgressDestination::DnsName { name, .. }, TunnelTarget::DnsName(target)) => {
                        name == target
                    }
                    (EgressDestination::Ipv4(address), TunnelTarget::Ipv4(target)) => {
                        address == target
                    }
                    (EgressDestination::Ipv6(address), TunnelTarget::Ipv6(target)) => {
                        address == target
                    }
                    _ => false,
                }
        });
    let Some((endpoint_index, endpoint)) = endpoint else {
        return ProxyAdmission::Rejected(RequestRejection::EndpointUndeclared);
    };
    if matches!(endpoint.tls_sni, SniBinding::Required(_)) {
        return ProxyAdmission::AwaitSni(AwaitSni {
            endpoint_index,
            head,
        });
    }
    let decision = decide_tunnel(
        authority,
        connection_id,
        &head.target,
        head.port,
        None,
        None,
        now_ms,
    );
    match decision {
        TunnelDecision::Denied(TunnelDenial::Undeclared) => {
            ProxyAdmission::Rejected(RequestRejection::EndpointUndeclared)
        }
        _ => ProxyAdmission::Destination(decision),
    }
}

/// A closed first-ClientHello result for a required-SNI endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SniResult {
    Incomplete,
    Matched,
    DeniedAbsent,
    DeniedMismatch,
    DeniedEch,
    DeniedMalformed,
    DeniedTooLarge,
}

impl SniResult {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Incomplete => "incomplete",
            Self::Matched => "matched",
            Self::DeniedAbsent => "denied-absent",
            Self::DeniedMismatch => "denied-mismatch",
            Self::DeniedEch => "denied-ech",
            Self::DeniedMalformed => "denied-malformed",
            Self::DeniedTooLarge => "denied-too-large",
        }
    }
}

/// Bind the first ClientHello before authorizing resolution or an attempt.
///
/// `Incomplete` requests more buffered bytes; every `Denied*` result closes
/// the client without contacting any remote address.
pub fn admit_sni(
    authority: &EgressAuthority,
    awaiting: &AwaitSni,
    input: &[u8],
    connection_id: u64,
    now_ms: u64,
) -> Result<TunnelDecision, SniResult> {
    let Some(endpoint) = authority.endpoints().get(awaiting.endpoint_index) else {
        return Err(SniResult::DeniedMalformed);
    };
    let SniBinding::Required(expected) = &endpoint.tls_sni else {
        return Err(SniResult::DeniedMalformed);
    };
    let name = parse_client_hello_sni(input).map_err(|error| match error {
        SniParseError::Incomplete => SniResult::Incomplete,
        SniParseError::TooLarge | SniParseError::TooManyRecords => SniResult::DeniedTooLarge,
        SniParseError::Malformed => SniResult::DeniedMalformed,
        SniParseError::Absent => SniResult::DeniedAbsent,
        SniParseError::EncryptedClientHello => SniResult::DeniedEch,
    })?;
    if &name != expected {
        return Err(SniResult::DeniedMismatch);
    }
    let decision = decide_tunnel(
        authority,
        connection_id,
        &awaiting.head.target,
        awaiting.head.port,
        Some(&name),
        None,
        now_ms,
    );
    match decision {
        TunnelDecision::Denied(_) => Err(SniResult::DeniedMalformed),
        _ => Ok(decision),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_parser_keeps_payload_and_canonical_target() {
        let request = b"CONNECT API.EXAMPLE:443 HTTP/1.1\r\nHost: ignored\r\n\r\nhello";
        let head = parse_connect_head(request).unwrap();
        assert_eq!(&request[head.payload_offset..], b"hello");
        assert_eq!(head.port.get(), 443);
        assert_eq!(
            head.target,
            TunnelTarget::DnsName(EgressName::new("api.example").unwrap())
        );
        assert_eq!(
            parse_connect_head(b"CONNECT [2001:db8::1]:443 HTTP/1.0\r\n\r\n")
                .unwrap()
                .target,
            TunnelTarget::Ipv6("2001:db8::1".parse::<Ipv6Addr>().unwrap().octets())
        );
        assert_eq!(
            parse_connect_head(b"CONNECT [2001:0DB8:0:0:0:0:0:1]:443 HTTP/1.0\r\n\r\n")
                .unwrap()
                .target,
            TunnelTarget::Ipv6("2001:db8::1".parse::<Ipv6Addr>().unwrap().octets())
        );
    }

    #[test]
    fn connect_parser_rejects_bypass_forms() {
        for request in [
            b"GET http://api.example/ HTTP/1.1\r\n\r\n".as_slice(),
            b"CONNECT api.example:0443 HTTP/1.1\r\n\r\n",
            b"CONNECT 127.000.0.1:443 HTTP/1.1\r\n\r\n",
            b"CONNECT [::ffff:127.0.0.1]:443 HTTP/1.1\r\n\r\n",
            b"CONNECT [fe80::1%eth0]:443 HTTP/1.1\r\n\r\n",
            b"CONNECT api.example:443 HTTP/2\r\n\r\n",
            b"CONNECT api.example:443 HTTP/1.1\r\nBad Header\r\n\r\n",
            b"CONNECT api.example:443 HTTP/1.1\r\n folded: x\r\n\r\n",
        ] {
            assert!(parse_connect_head(request).is_err());
        }
    }

    #[test]
    fn proxy_status_lines_are_closed_and_header_free() {
        for (status, expected) in [
            (ProxyStatus::Established, "200 Connection established"),
            (ProxyStatus::BadRequest, "400 Bad Request"),
            (ProxyStatus::Forbidden, "403 Forbidden"),
            (ProxyStatus::MethodNotAllowed, "405 Method Not Allowed"),
            (ProxyStatus::TooManyRequests, "429 Too Many Requests"),
            (ProxyStatus::BadGateway, "502 Bad Gateway"),
        ] {
            let wire = std::str::from_utf8(status.bytes()).unwrap();
            assert_eq!(wire, format!("HTTP/1.1 {expected}\r\n\r\n"));
        }
    }

    fn hello(extension: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // cipher suites
        body.extend_from_slice(&[1, 0]); // compression methods
        body.extend_from_slice(&u16::try_from(extension.len()).unwrap().to_be_bytes());
        body.extend_from_slice(extension);
        let mut handshake = vec![1, 0, 0, u8::try_from(body.len()).unwrap()];
        handshake.extend_from_slice(&body);
        handshake
    }

    fn sni_extension(name: &[u8]) -> Vec<u8> {
        let list_length = u16::try_from(name.len() + 3).unwrap();
        let mut value = Vec::new();
        value.extend_from_slice(&list_length.to_be_bytes());
        value.push(0);
        value.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        value.extend_from_slice(name);
        let mut extension = vec![0, 0];
        extension.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        extension.extend_from_slice(&value);
        extension
    }

    fn record(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    #[test]
    fn client_hello_sni_can_cross_records() {
        let handshake = hello(&sni_extension(b"API.EXAMPLE"));
        let mut wire = record(&handshake[..8]);
        wire.extend_from_slice(&record(&handshake[8..]));
        assert_eq!(
            parse_client_hello_sni(&wire),
            Ok(EgressName::new("api.example").unwrap())
        );
    }

    #[test]
    fn retained_fuzz_seeds_reach_the_intended_parser_outcomes() {
        assert!(
            parse_connect_head(include_bytes!("../../../tools/fuzz/corpus/connect/valid")).is_ok()
        );
        for (seed, expected) in [
            (
                include_bytes!("../../../tools/fuzz/corpus/connect/noncanonical").as_slice(),
                ConnectParseError::NonCanonicalTarget,
            ),
            (
                include_bytes!("../../../tools/fuzz/corpus/connect/malformed").as_slice(),
                ConnectParseError::Malformed,
            ),
            (
                include_bytes!("../../../tools/fuzz/corpus/connect/incomplete").as_slice(),
                ConnectParseError::Incomplete,
            ),
            (
                include_bytes!("../../../tools/fuzz/corpus/connect/oversized").as_slice(),
                ConnectParseError::HeadTooLarge,
            ),
        ] {
            assert_eq!(parse_connect_head(seed), Err(expected));
        }

        let name = EgressName::new("api.example").unwrap();
        for seed in [
            include_bytes!("../../../tools/fuzz/corpus/client-hello/valid").as_slice(),
            include_bytes!("../../../tools/fuzz/corpus/client-hello/split-records").as_slice(),
        ] {
            assert_eq!(parse_client_hello_sni(seed), Ok(name.clone()));
        }
        assert_eq!(
            parse_client_hello_sni(include_bytes!(
                "../../../tools/fuzz/corpus/client-hello/truncated"
            )),
            Err(SniParseError::Incomplete)
        );
        assert_eq!(
            parse_client_hello_sni(include_bytes!(
                "../../../tools/fuzz/corpus/client-hello/wrong-content-type"
            )),
            Err(SniParseError::Malformed)
        );
    }

    pub(super) fn golden_authority() -> EgressAuthority {
        let encoded = include_str!("../../../schemas/vectors/v3/execution-plan-egress.cbor.hex");
        let hex = encoded
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        let bytes = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        proofbound_runtime_core::parse_egress_execution_plan(&bytes)
            .unwrap()
            .egress()
            .clone()
    }

    #[test]
    fn admission_denies_undeclared_before_sni_and_dns() {
        let authority = golden_authority();
        assert_eq!(
            admit_connect(
                &authority,
                b"CONNECT other.example:443 HTTP/1.1\r\n\r\n",
                1,
                0
            ),
            ProxyAdmission::Rejected(RequestRejection::EndpointUndeclared)
        );
        assert_eq!(
            admit_connect(&authority, b"CONNECT api.example:443 HTTP/1.1\r\n", 1, 0),
            ProxyAdmission::Incomplete
        );
        assert_eq!(
            admit_connect(
                &authority,
                b"GET http://api.example/ HTTP/1.1\r\n\r\n",
                1,
                0
            ),
            ProxyAdmission::Rejected(RequestRejection::MethodNotConnect)
        );
    }

    #[test]
    fn required_sni_blocks_resolution_until_matched() {
        let authority = golden_authority();
        let ProxyAdmission::AwaitSni(awaiting) = admit_connect(
            &authority,
            b"CONNECT api.example:443 HTTP/1.1\r\n\r\n",
            1,
            0,
        ) else {
            panic!("required SNI must defer DNS and remote attempts")
        };
        let mismatch = record(&hello(&sni_extension(b"other.example")));
        assert_eq!(
            admit_sni(&authority, &awaiting, &mismatch, 1, 0),
            Err(SniResult::DeniedMismatch)
        );
        let matched = record(&hello(&sni_extension(b"API.EXAMPLE")));
        assert_eq!(
            admit_sni(&authority, &awaiting, &matched[..4], 1, 0),
            Err(SniResult::Incomplete)
        );
        assert_eq!(
            admit_sni(&authority, &awaiting, &matched, 1, 0),
            Ok(TunnelDecision::NeedsResolution { endpoint_index: 0 })
        );
    }

    #[test]
    fn session_sends_established_before_sni_and_keeps_original_hello() {
        let authority = golden_authority();
        let tls = record(&hello(&sni_extension(b"API.EXAMPLE")));
        let mut wire = b"CONNECT api.example:443 HTTP/1.1\r\n\r\n".to_vec();
        wire.extend_from_slice(&tls);
        let mut session = ProxySession::new();
        assert_eq!(
            session.push(&authority, &wire[..11], 1, 0),
            SessionEvent::NeedMore
        );
        assert_eq!(
            session.push(&authority, &wire[11..], 1, 0),
            SessionEvent::EstablishedAwaitSni { endpoint_index: 0 }
        );
        let SessionEvent::Ready {
            endpoint_index,
            decision,
            payload,
            sni_matched,
        } = session.push(&authority, b"", 1, 0)
        else {
            panic!("matched SNI must admit after the established event")
        };
        assert!(matches!(decision, TunnelDecision::NeedsResolution { .. }));
        assert_eq!(endpoint_index, 0);
        assert!(sni_matched);
        assert_eq!(payload, tls);
        assert_eq!(
            session.push(&authority, b"", 1, 0),
            SessionEvent::AlreadyFinished
        );
    }

    #[test]
    fn session_denies_mismatched_sni_before_any_destination() {
        let authority = golden_authority();
        let tls = record(&hello(&sni_extension(b"other.example")));
        let mut session = ProxySession::new();
        assert_eq!(
            session.push(
                &authority,
                b"CONNECT api.example:443 HTTP/1.1\r\n\r\n",
                1,
                0
            ),
            SessionEvent::EstablishedAwaitSni { endpoint_index: 0 }
        );
        assert_eq!(
            session.push(&authority, &tls, 1, 0),
            SessionEvent::SniDenied(SniResult::DeniedMismatch)
        );
    }

    #[test]
    fn oversized_early_hello_still_follows_established_status() {
        let authority = golden_authority();
        let mut request = b"CONNECT api.example:443 HTTP/1.1\r\n\r\n".to_vec();
        request.resize(
            request.len() + MAX_CLIENT_HELLO_BYTES + 5 * MAX_CLIENT_HELLO_RECORDS + 1,
            0,
        );
        let mut session = ProxySession::new();
        assert_eq!(
            session.push(&authority, &request, 1, 0),
            SessionEvent::EstablishedAwaitSni { endpoint_index: 0 }
        );
        assert_eq!(
            session.push(&authority, b"", 1, 0),
            SessionEvent::SniDenied(SniResult::DeniedTooLarge)
        );
    }

    #[test]
    fn session_rejection_preserves_only_bounded_target_bytes_for_digest() {
        let authority = golden_authority();
        let mut session = ProxySession::new();
        assert_eq!(
            session.push(
                &authority,
                b"CONNECT Other.Example:443 HTTP/1.1\r\n\r\n",
                1,
                0,
            ),
            SessionEvent::Rejected(RejectedRequest {
                reason: RequestRejection::EndpointUndeclared,
                target_kind: TargetKind::DnsName,
                port: TcpPort::new(443).ok(),
                exact_target_bytes: b"Other.Example:443".to_vec(),
            })
        );
    }

    #[test]
    fn literal_without_sni_selects_only_the_declared_address() {
        let original = golden_authority();
        let authority = EgressAuthority::new(
            vec![proofbound_runtime_core::EgressEndpoint {
                destination: EgressDestination::Ipv4([192, 0, 2, 10]),
                port: TcpPort::new(443).unwrap(),
                tls_sni: SniBinding::NotInspected,
            }],
            original.resolver().clone(),
            original.limits(),
            original.proxy_executable().clone(),
            original.proxy_runtime_read().to_vec(),
            original.proxy_environment().to_vec(),
            &[],
        )
        .unwrap();
        assert_eq!(
            admit_connect(&authority, b"CONNECT 192.0.2.10:443 HTTP/1.1\r\n\r\n", 1, 0),
            ProxyAdmission::Destination(TunnelDecision::Attempts {
                endpoint_index: 0,
                addresses: vec!["192.0.2.10".parse().unwrap()],
            })
        );
        assert_eq!(
            admit_connect(&authority, b"CONNECT 192.0.2.11:443 HTTP/1.1\r\n\r\n", 1, 0),
            ProxyAdmission::Rejected(RequestRejection::EndpointUndeclared)
        );
    }

    #[test]
    fn client_hello_rejects_missing_duplicate_and_ech_names() {
        let absent = record(&hello(&[]));
        assert_eq!(parse_client_hello_sni(&absent), Err(SniParseError::Absent));
        let extension = sni_extension(b"api.example");
        let duplicate = record(&hello(
            &[extension.as_slice(), extension.as_slice()].concat(),
        ));
        assert_eq!(
            parse_client_hello_sni(&duplicate),
            Err(SniParseError::Malformed)
        );
        let ech = record(&hello(
            &[extension.as_slice(), &[0xfe, 0x0d, 0, 0]].concat(),
        ));
        assert_eq!(
            parse_client_hello_sni(&ech),
            Err(SniParseError::EncryptedClientHello)
        );
    }
}
