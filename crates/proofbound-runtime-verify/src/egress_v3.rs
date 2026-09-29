//! Independent, verifier-owned relations for a declared-egress observation.
//!
//! This module uses only the verifier's deterministic CBOR tree. It never
//! imports the producer's endpoint, proxy, or observation implementation.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::cbor::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressError {
    Structure,
    EndpointUnknown,
    ResolutionMismatch,
    AnswerUnknown,
    AnswerExpired,
    AddressScope,
    AttemptBound,
    SniUnbound,
    SequenceInvalid,
    ConcurrencyExceeded,
    CounterMismatch,
    LimitExceeded,
    LimitEventMismatch,
    BoundaryInvalid,
    BindingMismatch,
    PhaseInvalid,
    ReasonMismatch,
}

impl EgressError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Structure => "verify.network.egress.structure-invalid",
            Self::EndpointUnknown => "verify.network.egress.endpoint-unknown",
            Self::ResolutionMismatch => "verify.network.egress.resolution-mismatch",
            Self::AnswerUnknown => "verify.network.egress.answer-unknown",
            Self::AnswerExpired => "verify.network.egress.answer-expired",
            Self::AddressScope => "verify.network.egress.address-scope",
            Self::AttemptBound => "verify.network.egress.attempt-bound",
            Self::SniUnbound => "verify.network.egress.sni-unbound",
            Self::SequenceInvalid => "verify.network.egress.sequence-invalid",
            Self::ConcurrencyExceeded => "verify.network.egress.concurrency-exceeded",
            Self::CounterMismatch => "verify.network.egress.counter-mismatch",
            Self::LimitExceeded => "verify.network.egress.limit-exceeded",
            Self::LimitEventMismatch => "verify.network.egress.limit-event-mismatch",
            Self::BoundaryInvalid => "verify.network.egress.boundary-invalid",
            Self::BindingMismatch => "verify.network.egress.binding-mismatch",
            Self::PhaseInvalid => "verify.network.egress.phase-invalid",
            Self::ReasonMismatch => "verify.network.egress.reason-mismatch",
        }
    }
}

impl core::fmt::Display for EgressError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for EgressError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressDecision {
    pub authority_rejection: bool,
    pub sni_denied: bool,
    pub limit_reached: bool,
    pub proxy_failed: bool,
    pub cleanup_incomplete: bool,
    pub proxy_executable_sha256: [u8; 32],
    pub proxy_runtime_closure_sha256: Vec<[u8; 32]>,
    pub resolver_configuration_sha256: [u8; 32],
}

/// Independently validates one deterministic CBOR observation fragment.
pub fn verify_egress_observation_fragment(
    bytes: &[u8],
    policy_sha256: &[u8; 32],
) -> Result<EgressDecision, EgressError> {
    let value = crate::cbor::decode(bytes).map_err(|_| EgressError::Structure)?;
    verify_observation(&value, policy_sha256)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Destination {
    Name { name: String, private: bool },
    Ip(Vec<u8>),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Endpoint {
    destination: Destination,
    port: u16,
    sni: Option<String>,
    sni_required: bool,
}

fn valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 || !name.is_ascii() || name.ends_with('.') {
        return false;
    }
    let labels = name.split('.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels
            .last()
            .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    labels.into_iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && label
                .as_bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn valid_path(path: &str) -> bool {
    path.starts_with('/')
        && path != "/"
        && !path.as_bytes().contains(&0)
        && !path
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
}

#[derive(Clone, Debug)]
struct Answer {
    address: Vec<u8>,
    effective_expiry_ms: u64,
    admissible: bool,
}

#[derive(Clone, Debug)]
struct Resolution {
    name: String,
    triggering_connection: u64,
    outcome: String,
    answers: Vec<Answer>,
}

const REJECTION_REASONS: [&str; 10] = [
    "method-not-connect",
    "request-malformed",
    "request-head-too-large",
    "target-noncanonical",
    "endpoint-undeclared",
    "limit-connections",
    "limit-concurrent-connections",
    "limit-resolutions",
    "limit-dns-messages",
    "limit-bytes-exhausted",
];

fn map<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a [(String, Value)], EgressError> {
    let Value::Map(fields) = value else {
        return Err(EgressError::Structure);
    };
    if fields.len() != keys.len() || fields.iter().any(|(key, _)| !keys.contains(&key.as_str())) {
        return Err(EgressError::Structure);
    }
    Ok(fields)
}

fn field<'a>(fields: &'a [(String, Value)], key: &str) -> Result<&'a Value, EgressError> {
    fields
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
        .ok_or(EgressError::Structure)
}

fn array(value: &Value) -> Result<&[Value], EgressError> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(EgressError::Structure),
    }
}

fn number(value: &Value) -> Result<u64, EgressError> {
    match value {
        Value::Unsigned(number) => Ok(*number),
        _ => Err(EgressError::Structure),
    }
}

fn optional_number(value: &Value) -> Result<Option<u64>, EgressError> {
    match value {
        Value::Null => Ok(None),
        Value::Unsigned(number) => Ok(Some(*number)),
        _ => Err(EgressError::Structure),
    }
}

fn string(value: &Value) -> Result<&str, EgressError> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(EgressError::Structure),
    }
}

fn bytes(value: &Value, length: usize) -> Result<&[u8], EgressError> {
    match value {
        Value::Bytes(bytes) if bytes.len() == length => Ok(bytes),
        _ => Err(EgressError::Structure),
    }
}

fn boolean(value: &Value) -> Result<bool, EgressError> {
    match value {
        Value::Bool(value) => Ok(*value),
        _ => Err(EgressError::Structure),
    }
}

fn ip_address(value: &Value) -> Result<Vec<u8>, EgressError> {
    let fields = map(value, &["family", "bytes"])?;
    let family = string(field(fields, "family")?)?;
    let length = match family {
        "ipv4" => 4,
        "ipv6" => 16,
        _ => return Err(EgressError::Structure),
    };
    Ok(bytes(field(fields, "bytes")?, length)?.to_vec())
}

fn endpoint(value: &Value) -> Result<Endpoint, EgressError> {
    let fields = map(value, &["destination", "port", "protocol", "tls_sni"])?;
    let port = number(field(fields, "port")?)?;
    if !(1..=65535).contains(&port) || string(field(fields, "protocol")?)? != "tcp" {
        return Err(EgressError::Structure);
    }
    let destination_fields = match field(fields, "destination")? {
        Value::Map(fields) => fields.as_slice(),
        _ => return Err(EgressError::Structure),
    };
    let kind = string(field(destination_fields, "kind")?)?;
    let destination = match kind {
        "dns-name" => {
            let fields = map(
                field(fields, "destination")?,
                &["kind", "name", "address_scope"],
            )?;
            let name = string(field(fields, "name")?)?;
            if !valid_name(name) {
                return Err(EgressError::Structure);
            }
            let private = match string(field(fields, "address_scope")?)? {
                "global" => false,
                "global-or-private" => true,
                _ => return Err(EgressError::Structure),
            };
            Destination::Name {
                name: name.to_owned(),
                private,
            }
        }
        "ipv4" | "ipv6" => {
            let fields = map(field(fields, "destination")?, &["kind", "bytes"])?;
            let length = if kind == "ipv4" { 4 } else { 16 };
            let address = bytes(field(fields, "bytes")?, length)?;
            let invalid = if kind == "ipv4" {
                let address = Ipv4Addr::new(address[0], address[1], address[2], address[3]);
                address.is_unspecified() || address.is_multicast() || address.is_broadcast()
            } else {
                let address = Ipv6Addr::from(
                    <[u8; 16]>::try_from(address).map_err(|_| EgressError::Structure)?,
                );
                address.is_unspecified()
                    || address.is_multicast()
                    || address.to_ipv4_mapped().is_some()
                    || (address.octets()[..12] == [0; 12] && !address.is_loopback())
            };
            if invalid {
                return Err(EgressError::AddressScope);
            }
            Destination::Ip(address.to_vec())
        }
        _ => return Err(EgressError::Structure),
    };
    let sni = match field(fields, "tls_sni")? {
        Value::Text(text) if text == "not-inspected" => None,
        value => {
            let binding = map(value, &["mode", "name"])?;
            if string(field(binding, "mode")?)? != "required" {
                return Err(EgressError::Structure);
            }
            let name = string(field(binding, "name")?)?;
            if !valid_name(name) {
                return Err(EgressError::Structure);
            }
            if let Destination::Name {
                name: destination_name,
                ..
            } = &destination
                && name != destination_name
            {
                return Err(EgressError::SniUnbound);
            }
            Some(name.to_owned())
        }
    };
    Ok(Endpoint {
        destination,
        port: port as u16,
        sni_required: sni.is_some(),
        sni,
    })
}

fn resolution(
    value: &Value,
    max_response_bytes: u64,
    max_cname_depth: usize,
    max_answer_count: usize,
) -> Result<Resolution, EgressError> {
    let fields = map(
        value,
        &[
            "index",
            "name",
            "triggering_connection",
            "started_ms",
            "finished_ms",
            "messages",
            "cname_links",
            "answers",
            "outcome",
        ],
    )?;
    let _index = number(field(fields, "index")?)?;
    let name = string(field(fields, "name")?)?;
    if !valid_name(name) {
        return Err(EgressError::Structure);
    }
    let triggering_connection = number(field(fields, "triggering_connection")?)?;
    let started = number(field(fields, "started_ms")?)?;
    let finished = number(field(fields, "finished_ms")?)?;
    if finished < started {
        return Err(EgressError::SequenceInvalid);
    }
    let messages = array(field(fields, "messages")?)?;
    if messages.len() > 8192 {
        return Err(EgressError::LimitExceeded);
    }
    let mut message_digests = BTreeSet::new();
    for message in messages {
        let message = map(message, &["sha256", "size", "finished_ms"])?;
        let digest: [u8; 32] = bytes(field(message, "sha256")?, 32)?
            .try_into()
            .map_err(|_| EgressError::Structure)?;
        message_digests.insert(digest);
        if !(1..=max_response_bytes).contains(&number(field(message, "size")?)?)
            || !(started..=finished).contains(&number(field(message, "finished_ms")?)?)
        {
            return Err(EgressError::ResolutionMismatch);
        }
    }
    let links = array(field(fields, "cname_links")?)?;
    if links.len() > max_cname_depth {
        return Err(EgressError::LimitExceeded);
    }
    let mut previous_target = name;
    for link in links {
        let link = map(
            link,
            &["owner", "target", "ttl", "expiry_ms", "message_sha256"],
        )?;
        for key in ["owner", "target"] {
            let text = string(field(link, key)?)?;
            if !valid_name(text) {
                return Err(EgressError::Structure);
            }
        }
        if string(field(link, "owner")?)? != previous_target {
            return Err(EgressError::ResolutionMismatch);
        }
        previous_target = string(field(link, "target")?)?;
        number(field(link, "ttl")?)?;
        if number(field(link, "expiry_ms")?)? < started {
            return Err(EgressError::AnswerExpired);
        }
        let digest: [u8; 32] = bytes(field(link, "message_sha256")?, 32)?
            .try_into()
            .map_err(|_| EgressError::Structure)?;
        if !message_digests.contains(&digest) {
            return Err(EgressError::ResolutionMismatch);
        }
    }
    let answers = array(field(fields, "answers")?)?;
    if answers.len() > max_answer_count {
        return Err(EgressError::LimitExceeded);
    }
    let answers = answers
        .iter()
        .map(|answer| {
            let answer = map(
                answer,
                &[
                    "address",
                    "ttl",
                    "record_expiry_ms",
                    "effective_expiry_ms",
                    "message_sha256",
                    "admissible",
                ],
            )?;
            let address = ip_address(field(answer, "address")?)?;
            number(field(answer, "ttl")?)?;
            let record_expiry = number(field(answer, "record_expiry_ms")?)?;
            let effective_expiry = number(field(answer, "effective_expiry_ms")?)?;
            if effective_expiry > record_expiry {
                return Err(EgressError::AnswerExpired);
            }
            let digest: [u8; 32] = bytes(field(answer, "message_sha256")?, 32)?
                .try_into()
                .map_err(|_| EgressError::Structure)?;
            if !message_digests.contains(&digest) {
                return Err(EgressError::ResolutionMismatch);
            }
            Ok(Answer {
                address,
                effective_expiry_ms: effective_expiry,
                admissible: boolean(field(answer, "admissible")?)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let outcome = string(field(fields, "outcome")?)?;
    if !["answered", "failed", "no-admissible-answer"].contains(&outcome) {
        return Err(EgressError::Structure);
    }
    if (outcome == "failed" && !answers.is_empty())
        || (outcome == "answered" && !answers.iter().any(|answer| answer.admissible))
        || (outcome == "no-admissible-answer"
            && (answers.is_empty() || answers.iter().any(|answer| answer.admissible)))
    {
        return Err(EgressError::ResolutionMismatch);
    }
    Ok(Resolution {
        name: name.to_owned(),
        triggering_connection,
        outcome: outcome.to_owned(),
        answers,
    })
}

fn admissible_address(address: &[u8], private_allowed: bool) -> bool {
    let class = if address.len() == 4 {
        let b = address;
        if b[0] == 0
            || b[0] == 127
            || (b[0] == 169 && b[1] == 254)
            || (b[0] == 192 && b[1] == 0 && (b[2] == 0 || b[2] == 2))
            || (b[0] == 198 && (b[1] == 18 || b[1] == 19))
            || (b[0] == 198 && b[1] == 51 && b[2] == 100)
            || (b[0] == 203 && b[1] == 0 && b[2] == 113)
            || b[0] >= 224
        {
            0
        } else if b[0] == 10
            || (b[0] == 100 && (64..=127).contains(&b[1]))
            || (b[0] == 172 && (16..=31).contains(&b[1]))
            || (b[0] == 192 && b[1] == 168)
        {
            1
        } else {
            2
        }
    } else if address.len() == 16 {
        let b = address;
        if b == [0; 16]
            || b == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
            || b[0] == 0xff
            || (b[..10] == [0; 10] && b[10..12] == [0xff, 0xff])
            || (b[..4] == [0, 0x64, 0xff, 0x9b] && b[4..12] == [0; 8])
            || (b[0] == 1 && b[1..8] == [0; 7])
            || (b[0] == 0x20 && b[1] == 1 && b[2] <= 1)
            || b[..4] == [0x20, 1, 0x0d, 0xb8]
            || (b[0] == 0xfe && b[1] & 0xc0 == 0x80)
        {
            0
        } else if b[0] & 0xfe == 0xfc {
            1
        } else {
            2
        }
    } else {
        return false;
    };
    class == 2 || (class == 1 && private_allowed)
}

fn check_boundary(value: &Value) -> Result<(), EgressError> {
    let fields = map(
        value,
        &[
            "user_namespace",
            "child_network_namespace",
            "supervisor_network_namespace",
            "uid_map",
            "gid_map",
            "interfaces",
            "routes",
            "listener",
            "landlock_abi",
            "landlock_handled_network",
            "child_filter_sha256",
            "proxy_filter_sha256",
        ],
    )?;
    let namespace = |key: &str| -> Result<(u64, u64), EgressError> {
        let entry = map(field(fields, key)?, &["device", "inode"])?;
        Ok((
            number(field(entry, "device")?)?,
            number(field(entry, "inode")?)?,
        ))
    };
    let user = namespace("user_namespace")?;
    let child = namespace("child_network_namespace")?;
    let supervisor = namespace("supervisor_network_namespace")?;
    if user.0 == 0 || user.1 == 0 || child.0 == 0 || child.1 == 0 || child == supervisor {
        return Err(EgressError::BoundaryInvalid);
    }
    for name in ["uid_map", "gid_map"] {
        let mapping = map(field(fields, name)?, &["inside", "outside", "length"])?;
        let inside = number(field(mapping, "inside")?)?;
        let outside = number(field(mapping, "outside")?)?;
        if inside == 0
            || inside > u32::MAX.into()
            || inside != outside
            || number(field(mapping, "length")?)? != 1
        {
            return Err(EgressError::BoundaryInvalid);
        }
    }
    let interfaces = array(field(fields, "interfaces")?)?;
    if interfaces != [Value::Text("lo".to_owned())] {
        return Err(EgressError::BoundaryInvalid);
    }
    for route in array(field(fields, "routes")?)? {
        let route = map(
            route,
            &["family", "destination", "prefix_length", "interface"],
        )?;
        let family = string(field(route, "family")?)?;
        let address = ip_address(field(route, "destination")?)?;
        let prefix = number(field(route, "prefix_length")?)?;
        if string(field(route, "interface")?)? != "lo"
            || !match family {
                "ipv4" => address.len() == 4 && address[0] == 127 && (8..=32).contains(&prefix),
                "ipv6" => {
                    address == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] && prefix == 128
                }
                _ => false,
            }
        {
            return Err(EgressError::BoundaryInvalid);
        }
    }
    let listener = map(field(fields, "listener")?, &["address", "port", "backlog"])?;
    if bytes(field(listener, "address")?, 4)? != [127, 0, 0, 1]
        || number(field(listener, "port")?)? != 3128
        || number(field(listener, "backlog")?)? != 128
        || !(9..=11).contains(&number(field(fields, "landlock_abi")?)?)
    {
        return Err(EgressError::BoundaryInvalid);
    }
    let handled = array(field(fields, "landlock_handled_network")?)?;
    if handled
        != [
            Value::Text("tcp-bind".to_owned()),
            Value::Text("tcp-connect".to_owned()),
        ]
    {
        return Err(EgressError::BoundaryInvalid);
    }
    bytes(field(fields, "child_filter_sha256")?, 32)?;
    bytes(field(fields, "proxy_filter_sha256")?, 32)?;
    Ok(())
}

struct ProxyDecision {
    failed: bool,
    executable: [u8; 32],
    closure: Vec<[u8; 32]>,
    resolver: [u8; 32],
}

fn check_proxy(value: &Value) -> Result<ProxyDecision, EgressError> {
    let fields = map(
        value,
        &[
            "executable",
            "runtime_closure",
            "resolver_configuration",
            "generation",
            "readiness_binding",
            "phases",
            "terminal_reason",
            "failure_reason",
        ],
    )?;
    let artifact = |value: &Value| -> Result<[u8; 32], EgressError> {
        let artifact = map(value, &["sha256", "size", "mode"])?;
        let digest: [u8; 32] = bytes(field(artifact, "sha256")?, 32)?
            .try_into()
            .map_err(|_| EgressError::Structure)?;
        number(field(artifact, "size")?)?;
        if number(field(artifact, "mode")?)? > 4095 {
            return Err(EgressError::Structure);
        }
        Ok(digest)
    };
    let executable = artifact(field(fields, "executable")?)?;
    let closure = array(field(fields, "runtime_closure")?)?
        .iter()
        .map(artifact)
        .collect::<Result<Vec<_>, _>>()?;
    let resolver = artifact(field(fields, "resolver_configuration")?)?;
    if number(field(fields, "generation")?)? == 0 {
        return Err(EgressError::BindingMismatch);
    }
    bytes(field(fields, "readiness_binding")?, 32)?;
    let phases = array(field(fields, "phases")?)?
        .iter()
        .map(string)
        .collect::<Result<Vec<_>, _>>()?;
    let failed = match phases.as_slice() {
        ["created", "ready", "serving", "draining", "closed"] => false,
        ["created", "failed"]
        | ["created", "ready", "failed"]
        | ["created", "ready", "serving", "failed"]
        | ["created", "ready", "serving", "draining", "failed"] => true,
        _ => return Err(EgressError::PhaseInvalid),
    };
    let terminal = string(field(fields, "terminal_reason")?)?;
    match (failed, terminal, field(fields, "failure_reason")?) {
        (false, "closed", Value::Null) => Ok(ProxyDecision {
            failed: false,
            executable,
            closure,
            resolver,
        }),
        (true, "failed", Value::Text(reason))
            if [
                "bootstrap",
                "confinement",
                "protocol",
                "transport",
                "report",
                "deadline",
            ]
            .contains(&reason.as_str()) =>
        {
            Ok(ProxyDecision {
                failed: true,
                executable,
                closure,
                resolver,
            })
        }
        _ => Err(EgressError::PhaseInvalid),
    }
}

fn checked_sum(values: impl IntoIterator<Item = u64>) -> Result<u64, EgressError> {
    values.into_iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(value).ok_or(EgressError::CounterMismatch)
    })
}

/// Validates the complete bounded observation, independently of the producer.
pub(crate) fn verify_observation(
    value: &Value,
    policy_sha256: &[u8; 32],
) -> Result<EgressDecision, EgressError> {
    let root = map(
        value,
        &[
            "schema",
            "authority",
            "policy_sha256",
            "boundary",
            "proxy",
            "resolutions",
            "connections",
            "rejections",
            "counters",
            "limit_events",
            "cleanup",
        ],
    )?;
    if string(field(root, "schema")?)? != "proofbound-runtime-egress-observation/1"
        || bytes(field(root, "policy_sha256")?, 32)? != policy_sha256
    {
        return Err(EgressError::BindingMismatch);
    }
    let authority = map(
        field(root, "authority")?,
        &[
            "endpoints",
            "resolver",
            "limits",
            "proxy_executable",
            "proxy_runtime_read",
            "proxy_environment",
        ],
    )?;
    let endpoints = array(field(authority, "endpoints")?)?;
    if endpoints.is_empty() || endpoints.len() > 256 {
        return Err(EgressError::Structure);
    }
    let endpoints = endpoints
        .iter()
        .map(endpoint)
        .collect::<Result<Vec<_>, _>>()?;
    if endpoints.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(EgressError::EndpointUnknown);
    }
    for (index, left) in endpoints.iter().enumerate() {
        for right in &endpoints[index + 1..] {
            if left.destination == right.destination && left.port == right.port {
                return Err(EgressError::EndpointUnknown);
            }
            if let (
                Destination::Name {
                    name: left_name,
                    private: left_scope,
                },
                Destination::Name {
                    name: right_name,
                    private: right_scope,
                },
            ) = (&left.destination, &right.destination)
                && left_name == right_name
                && left_scope != right_scope
            {
                return Err(EgressError::EndpointUnknown);
            }
        }
    }
    let limits = map(
        field(authority, "limits")?,
        &[
            "connections",
            "concurrent_connections",
            "attempts_per_connection",
            "resolutions",
            "dns_messages",
            "client_to_remote_bytes",
            "remote_to_client_bytes",
            "connection_idle_ms",
        ],
    )?;
    let bound = |name| number(field(limits, name)?);
    let connection_bound = bound("connections")?;
    let concurrent_bound = bound("concurrent_connections")?;
    let attempt_bound = bound("attempts_per_connection")?;
    let resolution_bound = bound("resolutions")?;
    let dns_bound = bound("dns_messages")?;
    let client_bound = bound("client_to_remote_bytes")?;
    let remote_bound = bound("remote_to_client_bytes")?;
    let idle_bound = bound("connection_idle_ms")?;
    if !(1..=8192).contains(&connection_bound)
        || !(1..=512).contains(&concurrent_bound)
        || !(1..=4).contains(&attempt_bound)
        || !(1..=1024).contains(&resolution_bound)
        || !(2..=8192).contains(&dns_bound)
        || !(1..=1_u64 << 40).contains(&client_bound)
        || !(1..=1_u64 << 40).contains(&remote_bound)
        || !(1..=3_600_000).contains(&idle_bound)
    {
        return Err(EgressError::LimitExceeded);
    }
    let resolver = map(
        field(authority, "resolver")?,
        &[
            "address",
            "port",
            "configuration",
            "maximum_cname_depth",
            "maximum_answer_count",
            "maximum_response_bytes",
            "resolution_deadline_ms",
            "attempt_deadline_ms",
            "address_order",
        ],
    )?;
    ip_address(field(resolver, "address")?)?;
    if !(1..=65535).contains(&number(field(resolver, "port")?)?)
        || !(1..=4).contains(&number(field(resolver, "maximum_cname_depth")?)?)
        || !(1..=16).contains(&number(field(resolver, "maximum_answer_count")?)?)
        || !(1..=65535).contains(&number(field(resolver, "maximum_response_bytes")?)?)
        || !(1..=60000).contains(&number(field(resolver, "resolution_deadline_ms")?)?)
        || !(1..=60000).contains(&number(field(resolver, "attempt_deadline_ms")?)?)
        || string(field(resolver, "address_order")?)? != "ipv4-then-ipv6-lexicographic"
        || attempt_bound > number(field(resolver, "maximum_answer_count")?)?
        || number(field(resolver, "attempt_deadline_ms")?)?
            > number(field(resolver, "resolution_deadline_ms")?)?
    {
        return Err(EgressError::Structure);
    }
    let configuration = string(field(resolver, "configuration")?)?;
    let proxy_executable = string(field(authority, "proxy_executable")?)?;
    if !valid_path(configuration) || !valid_path(proxy_executable) {
        return Err(EgressError::Structure);
    }
    let read_paths = array(field(authority, "proxy_runtime_read")?)?;
    if read_paths
        .iter()
        .any(|item| !string(item).is_ok_and(valid_path))
    {
        return Err(EgressError::Structure);
    }
    let variables = array(field(authority, "proxy_environment")?)?;
    if variables.is_empty() || variables.len() > 6 {
        return Err(EgressError::Structure);
    }
    let mut previous = "";
    for variable in variables {
        let variable = string(variable)?;
        if variable <= previous
            || ![
                "HTTPS_PROXY",
                "https_proxy",
                "HTTP_PROXY",
                "http_proxy",
                "ALL_PROXY",
                "all_proxy",
            ]
            .contains(&variable)
        {
            return Err(EgressError::Structure);
        }
        previous = variable;
    }
    check_boundary(field(root, "boundary")?)?;
    let proxy = check_proxy(field(root, "proxy")?)?;

    let resolution_values = array(field(root, "resolutions")?)?;
    if resolution_values.len() > resolution_bound as usize {
        return Err(EgressError::LimitExceeded);
    }
    let mut resolutions = Vec::with_capacity(resolution_values.len());
    let mut dns_messages = 0_u64;
    for (position, value) in resolution_values.iter().enumerate() {
        let fields = map(
            value,
            &[
                "index",
                "name",
                "triggering_connection",
                "started_ms",
                "finished_ms",
                "messages",
                "cname_links",
                "answers",
                "outcome",
            ],
        )?;
        if number(field(fields, "index")?)? != position as u64 + 1 {
            return Err(EgressError::ResolutionMismatch);
        }
        dns_messages = dns_messages
            .checked_add(array(field(fields, "messages")?)?.len() as u64)
            .ok_or(EgressError::CounterMismatch)?;
        resolutions.push(resolution(
            value,
            number(field(resolver, "maximum_response_bytes")?)?,
            number(field(resolver, "maximum_cname_depth")?)? as usize,
            number(field(resolver, "maximum_answer_count")?)? as usize,
        )?);
    }
    let connection_values = array(field(root, "connections")?)?;
    if connection_values.len() > connection_bound as usize {
        return Err(EgressError::LimitExceeded);
    }
    for (index, record) in resolutions.iter().enumerate() {
        let triggering = connection_values
            .get(
                record
                    .triggering_connection
                    .checked_sub(1)
                    .ok_or(EgressError::ResolutionMismatch)? as usize,
            )
            .ok_or(EgressError::ResolutionMismatch)?;
        let triggering = map(
            triggering,
            &[
                "index",
                "endpoint_index",
                "open_sequence",
                "close_sequence",
                "accepted_ms",
                "resolution_index",
                "sni_result",
                "attempts",
                "selected_attempt",
                "client_to_remote_bytes",
                "remote_to_client_bytes",
                "close_reason",
            ],
        )?;
        let endpoint_index = number(field(triggering, "endpoint_index")?)? as usize;
        if optional_number(field(triggering, "resolution_index")?)? != Some(index as u64 + 1) {
            return Err(EgressError::ResolutionMismatch);
        }
        let Some(Endpoint {
            destination: Destination::Name { name, private },
            ..
        }) = endpoints.get(endpoint_index)
        else {
            return Err(EgressError::ResolutionMismatch);
        };
        if name != &record.name
            || record
                .answers
                .iter()
                .any(|answer| answer.admissible != admissible_address(&answer.address, *private))
        {
            return Err(EgressError::ResolutionMismatch);
        }
    }
    let mut events = Vec::with_capacity(connection_values.len() * 2 + 256);
    let mut client_bytes = Vec::with_capacity(connection_values.len());
    let mut remote_bytes = Vec::with_capacity(connection_values.len());
    let mut sni_denied = false;
    let mut client_limited = false;
    let mut remote_limited = false;
    for (position, value) in connection_values.iter().enumerate() {
        let connection = map(
            value,
            &[
                "index",
                "endpoint_index",
                "open_sequence",
                "close_sequence",
                "accepted_ms",
                "resolution_index",
                "sni_result",
                "attempts",
                "selected_attempt",
                "client_to_remote_bytes",
                "remote_to_client_bytes",
                "close_reason",
            ],
        )?;
        if number(field(connection, "index")?)? != position as u64 + 1 {
            return Err(EgressError::SequenceInvalid);
        }
        let endpoint_index = number(field(connection, "endpoint_index")?)?;
        let endpoint = endpoints
            .get(endpoint_index as usize)
            .ok_or(EgressError::EndpointUnknown)?;
        let open = number(field(connection, "open_sequence")?)?;
        let close = number(field(connection, "close_sequence")?)?;
        if open >= close {
            return Err(EgressError::SequenceInvalid);
        }
        events.push((open, 1_i32));
        events.push((close, -1_i32));
        let accepted = number(field(connection, "accepted_ms")?)?;
        let resolution_index = optional_number(field(connection, "resolution_index")?)?;
        let sni = string(field(connection, "sni_result")?)?;
        let denied_sni = sni.starts_with("denied-");
        if ![
            "not-inspected",
            "matched",
            "denied-absent",
            "denied-mismatch",
            "denied-ech",
            "denied-malformed",
            "denied-too-large",
        ]
        .contains(&sni)
            || (endpoint.sni_required && !denied_sni && sni != "matched")
            || (!endpoint.sni_required && sni != "not-inspected")
        {
            return Err(EgressError::SniUnbound);
        }
        sni_denied |= denied_sni;
        let attempts = array(field(connection, "attempts")?)?;
        if attempts.len() as u64 > attempt_bound {
            return Err(EgressError::AttemptBound);
        }
        let selected = optional_number(field(connection, "selected_attempt")?)?;
        let close_reason = string(field(connection, "close_reason")?)?;
        if ![
            "client-closed",
            "remote-closed",
            "reset",
            "idle-timeout",
            "client-byte-limit",
            "remote-byte-limit",
            "proxy-draining",
            "sni-denied",
            "resolution-failed",
            "no-admissible-answer",
            "connect-failed",
        ]
        .contains(&close_reason)
        {
            return Err(EgressError::ReasonMismatch);
        }
        if denied_sni != (close_reason == "sni-denied")
            || (denied_sni && (resolution_index.is_some() || !attempts.is_empty()))
        {
            return Err(EgressError::SniUnbound);
        }
        let resolution = match (&endpoint.destination, resolution_index) {
            (Destination::Name { name, .. }, Some(index)) => {
                let found = resolutions
                    .get(
                        index
                            .checked_sub(1)
                            .ok_or(EgressError::ResolutionMismatch)?
                            as usize,
                    )
                    .ok_or(EgressError::ResolutionMismatch)?;
                if found.name != *name {
                    return Err(EgressError::ResolutionMismatch);
                }
                Some(found)
            }
            (Destination::Name { .. }, None) if attempts.is_empty() => None,
            (Destination::Name { .. }, None) => return Err(EgressError::ResolutionMismatch),
            (Destination::Ip(_), None) => None,
            (Destination::Ip(_), Some(_)) => return Err(EgressError::ResolutionMismatch),
        };
        if (close_reason == "resolution-failed"
            && resolution.is_none_or(|item| item.outcome != "failed"))
            || (close_reason == "no-admissible-answer"
                && resolution.is_none_or(|item| item.outcome != "no-admissible-answer"))
        {
            return Err(EgressError::ResolutionMismatch);
        }
        let mut connected = Vec::new();
        for (attempt_index, attempt) in attempts.iter().enumerate() {
            let attempt = map(
                attempt,
                &["answer_index", "address", "started_ms", "result"],
            )?;
            let answer_index = optional_number(field(attempt, "answer_index")?)?;
            let address = ip_address(field(attempt, "address")?)?;
            let started = number(field(attempt, "started_ms")?)?;
            if started < accepted {
                return Err(EgressError::SequenceInvalid);
            }
            let result = string(field(attempt, "result")?)?;
            if !["connected", "refused", "timed-out", "unreachable", "failed"].contains(&result) {
                return Err(EgressError::Structure);
            }
            if result == "connected" {
                connected.push(attempt_index as u64);
            }
            match (&endpoint.destination, resolution) {
                (Destination::Ip(expected), None)
                    if answer_index.is_none() && address == *expected => {}
                (Destination::Name { private, .. }, Some(record)) => {
                    let index = answer_index.ok_or(EgressError::AnswerUnknown)?;
                    let answer = record
                        .answers
                        .get(index as usize)
                        .ok_or(EgressError::AnswerUnknown)?;
                    if address != answer.address {
                        return Err(EgressError::AnswerUnknown);
                    }
                    if !answer.admissible || !admissible_address(&address, *private) {
                        return Err(EgressError::AddressScope);
                    }
                    if record.triggering_connection != position as u64 + 1
                        && started > answer.effective_expiry_ms
                    {
                        return Err(EgressError::AnswerExpired);
                    }
                }
                _ => return Err(EgressError::AnswerUnknown),
            }
        }
        if connected.len() > 1
            || selected != connected.first().copied()
            || selected.is_some_and(|index| index as usize + 1 != attempts.len())
        {
            return Err(EgressError::AttemptBound);
        }
        let client = number(field(connection, "client_to_remote_bytes")?)?;
        let remote = number(field(connection, "remote_to_client_bytes")?)?;
        if selected.is_none() && (client != 0 || remote != 0) {
            return Err(EgressError::CounterMismatch);
        }
        client_bytes.push(client);
        remote_bytes.push(remote);
        client_limited |= close_reason == "client-byte-limit";
        remote_limited |= close_reason == "remote-byte-limit";
    }

    let rejections = array(field(root, "rejections")?)?;
    if rejections.len() > 256 {
        return Err(EgressError::LimitExceeded);
    }
    let mut retained_counts = BTreeMap::<&str, u64>::new();
    for rejection in rejections {
        let rejection = map(
            rejection,
            &[
                "sequence",
                "time_ms",
                "reason",
                "target_kind",
                "port",
                "target_length",
                "target_sha256",
            ],
        )?;
        events.push((number(field(rejection, "sequence")?)?, 0));
        number(field(rejection, "time_ms")?)?;
        let reason = string(field(rejection, "reason")?)?;
        if !REJECTION_REASONS.contains(&reason) {
            return Err(EgressError::ReasonMismatch);
        }
        *retained_counts.entry(reason).or_default() += 1;
        if !["dns-name", "ipv4", "ipv6", "unparsed"]
            .contains(&string(field(rejection, "target_kind")?)?)
            || optional_number(field(rejection, "port")?)?
                .is_some_and(|port| !(1..=65535).contains(&port))
            || number(field(rejection, "target_length")?)? > 8192
        {
            return Err(EgressError::Structure);
        }
        bytes(field(rejection, "target_sha256")?, 32)?;
    }
    events.sort_unstable_by_key(|event| event.0);
    if events.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(EgressError::SequenceInvalid);
    }
    let mut active = 0_i64;
    let mut peak = 0_i64;
    for (_, change) in &events {
        active += i64::from(*change);
        if active < 0 {
            return Err(EgressError::SequenceInvalid);
        }
        peak = peak.max(active);
    }
    if active != 0 || peak as u64 > concurrent_bound {
        return Err(EgressError::ConcurrencyExceeded);
    }

    let counters = map(
        field(root, "counters")?,
        &[
            "connections",
            "resolutions",
            "dns_messages",
            "client_to_remote_bytes",
            "remote_to_client_bytes",
            "rejections",
            "rejection_reason_counts",
        ],
    )?;
    let rejection_total = number(field(counters, "rejections")?)?;
    let event_count = (connection_values.len() as u64)
        .checked_mul(2)
        .and_then(|count| count.checked_add(rejection_total))
        .ok_or(EgressError::CounterMismatch)?;
    if events
        .last()
        .is_some_and(|(sequence, _)| *sequence > event_count)
        || (rejection_total <= 256
            && events
                .iter()
                .enumerate()
                .any(|(position, (sequence, _))| *sequence != position as u64 + 1))
    {
        return Err(EgressError::SequenceInvalid);
    }
    let client_total = checked_sum(client_bytes)?;
    let remote_total = checked_sum(remote_bytes)?;
    if number(field(counters, "connections")?)? != connection_values.len() as u64
        || number(field(counters, "resolutions")?)? != resolutions.len() as u64
        || number(field(counters, "dns_messages")?)? != dns_messages
        || number(field(counters, "client_to_remote_bytes")?)? != client_total
        || number(field(counters, "remote_to_client_bytes")?)? != remote_total
        || rejections.len() as u64 != rejection_total.min(256)
    {
        return Err(EgressError::CounterMismatch);
    }
    if dns_messages > dns_bound || client_total > client_bound || remote_total > remote_bound {
        return Err(EgressError::LimitExceeded);
    }
    let reason_counts = map(
        field(counters, "rejection_reason_counts")?,
        &REJECTION_REASONS,
    )?;
    let mut counts = BTreeMap::new();
    for reason in REJECTION_REASONS {
        let count = number(field(reason_counts, reason)?)?;
        if count < retained_counts.get(reason).copied().unwrap_or_default() {
            return Err(EgressError::CounterMismatch);
        }
        counts.insert(reason, count);
    }
    if checked_sum(counts.values().copied())? != rejection_total {
        return Err(EgressError::CounterMismatch);
    }
    let authority_rejection = REJECTION_REASONS[..5]
        .iter()
        .any(|reason| counts[reason] > 0);
    let mut expected_events = BTreeSet::new();
    for (reason, event) in [
        ("limit-connections", "egress-limit-connections"),
        ("limit-concurrent-connections", "egress-limit-concurrent"),
        ("limit-resolutions", "egress-limit-resolutions"),
        ("limit-dns-messages", "egress-limit-dns-messages"),
    ] {
        if counts[reason] > 0 {
            expected_events.insert(event);
        }
    }
    if (client_limited || counts["limit-bytes-exhausted"] > 0) && client_total == client_bound {
        expected_events.insert("egress-limit-client-bytes");
    }
    if (remote_limited || counts["limit-bytes-exhausted"] > 0) && remote_total == remote_bound {
        expected_events.insert("egress-limit-remote-bytes");
    }
    if (client_limited && client_total != client_bound)
        || (remote_limited && remote_total != remote_bound)
        || (counts["limit-bytes-exhausted"] > 0
            && client_total != client_bound
            && remote_total != remote_bound)
    {
        return Err(EgressError::LimitEventMismatch);
    }
    let recorded_events = array(field(root, "limit_events")?)?
        .iter()
        .map(string)
        .collect::<Result<Vec<_>, _>>()?;
    if recorded_events != expected_events.iter().copied().collect::<Vec<_>>() {
        return Err(EgressError::LimitEventMismatch);
    }
    let cleanup = map(
        field(root, "cleanup")?,
        &["proxy_reaped", "proxy_cgroup_removed", "listener_closed"],
    )?;
    let mut cleanup_incomplete = false;
    for name in ["proxy_reaped", "proxy_cgroup_removed", "listener_closed"] {
        cleanup_incomplete |= !boolean(field(cleanup, name)?)?;
    }
    Ok(EgressDecision {
        authority_rejection,
        sni_denied,
        limit_reached: !expected_events.is_empty(),
        proxy_failed: proxy.failed,
        cleanup_incomplete,
        proxy_executable_sha256: proxy.executable,
        proxy_runtime_closure_sha256: proxy.closure,
        resolver_configuration_sha256: proxy.resolver,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(entries: Vec<(&str, Value)>) -> Value {
        Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    fn text(value: &str) -> Value {
        Value::Text(value.to_owned())
    }

    fn number(value: u64) -> Value {
        Value::Unsigned(value)
    }

    fn ip() -> Value {
        object(vec![
            ("family", text("ipv4")),
            ("bytes", Value::Bytes(vec![8, 8, 8, 8])),
        ])
    }

    fn artifact() -> Value {
        object(vec![
            ("sha256", Value::Bytes(vec![2; 32])),
            ("size", number(1)),
            ("mode", number(0o555)),
        ])
    }

    fn namespace(inode: u64) -> Value {
        object(vec![("device", number(4)), ("inode", number(inode))])
    }

    fn identity_map() -> Value {
        object(vec![
            ("inside", number(1000)),
            ("outside", number(1000)),
            ("length", number(1)),
        ])
    }

    fn empty_observation() -> Value {
        let reasons = object(
            REJECTION_REASONS
                .into_iter()
                .map(|reason| (reason, number(0)))
                .collect(),
        );
        object(vec![
            ("schema", text("proofbound-runtime-egress-observation/1")),
            ("policy_sha256", Value::Bytes(vec![1; 32])),
            (
                "authority",
                object(vec![
                    (
                        "endpoints",
                        Value::Array(vec![object(vec![
                            (
                                "destination",
                                object(vec![
                                    ("kind", text("ipv4")),
                                    ("bytes", Value::Bytes(vec![8, 8, 8, 8])),
                                ]),
                            ),
                            ("port", number(443)),
                            ("protocol", text("tcp")),
                            ("tls_sni", text("not-inspected")),
                        ])]),
                    ),
                    (
                        "resolver",
                        object(vec![
                            ("address", ip()),
                            ("port", number(53)),
                            ("configuration", text("/etc/resolv.conf")),
                            ("maximum_cname_depth", number(4)),
                            ("maximum_answer_count", number(16)),
                            ("maximum_response_bytes", number(65535)),
                            ("resolution_deadline_ms", number(1000)),
                            ("attempt_deadline_ms", number(1000)),
                            ("address_order", text("ipv4-then-ipv6-lexicographic")),
                        ]),
                    ),
                    (
                        "limits",
                        object(vec![
                            ("connections", number(4)),
                            ("concurrent_connections", number(2)),
                            ("attempts_per_connection", number(2)),
                            ("resolutions", number(4)),
                            ("dns_messages", number(8)),
                            ("client_to_remote_bytes", number(100)),
                            ("remote_to_client_bytes", number(100)),
                            ("connection_idle_ms", number(1000)),
                        ]),
                    ),
                    ("proxy_executable", text("/bin/pbr-egress-proxy")),
                    ("proxy_runtime_read", Value::Array(Vec::new())),
                    ("proxy_environment", Value::Array(vec![text("HTTP_PROXY")])),
                ]),
            ),
            (
                "boundary",
                object(vec![
                    ("user_namespace", namespace(7)),
                    ("child_network_namespace", namespace(8)),
                    ("supervisor_network_namespace", namespace(9)),
                    ("uid_map", identity_map()),
                    ("gid_map", identity_map()),
                    ("interfaces", Value::Array(vec![text("lo")])),
                    ("routes", Value::Array(Vec::new())),
                    (
                        "listener",
                        object(vec![
                            ("address", Value::Bytes(vec![127, 0, 0, 1])),
                            ("port", number(3128)),
                            ("backlog", number(128)),
                        ]),
                    ),
                    ("landlock_abi", number(9)),
                    (
                        "landlock_handled_network",
                        Value::Array(vec![text("tcp-bind"), text("tcp-connect")]),
                    ),
                    ("child_filter_sha256", Value::Bytes(vec![3; 32])),
                    ("proxy_filter_sha256", Value::Bytes(vec![4; 32])),
                ]),
            ),
            (
                "proxy",
                object(vec![
                    ("executable", artifact()),
                    ("runtime_closure", Value::Array(Vec::new())),
                    ("resolver_configuration", artifact()),
                    ("generation", number(1)),
                    ("readiness_binding", Value::Bytes(vec![5; 32])),
                    (
                        "phases",
                        Value::Array(
                            ["created", "ready", "serving", "draining", "closed"]
                                .map(text)
                                .into(),
                        ),
                    ),
                    ("terminal_reason", text("closed")),
                    ("failure_reason", Value::Null),
                ]),
            ),
            ("resolutions", Value::Array(Vec::new())),
            ("connections", Value::Array(Vec::new())),
            ("rejections", Value::Array(Vec::new())),
            (
                "counters",
                object(vec![
                    ("connections", number(0)),
                    ("resolutions", number(0)),
                    ("dns_messages", number(0)),
                    ("client_to_remote_bytes", number(0)),
                    ("remote_to_client_bytes", number(0)),
                    ("rejections", number(0)),
                    ("rejection_reason_counts", reasons),
                ]),
            ),
            ("limit_events", Value::Array(Vec::new())),
            (
                "cleanup",
                object(vec![
                    ("proxy_reaped", Value::Bool(true)),
                    ("proxy_cgroup_removed", Value::Bool(true)),
                    ("listener_closed", Value::Bool(true)),
                ]),
            ),
        ])
    }

    fn field_mut<'a>(value: &'a mut Value, path: &[&str]) -> &'a mut Value {
        let Value::Map(fields) = value else {
            panic!("path crosses a non-map");
        };
        let next = &mut fields.iter_mut().find(|(key, _)| key == path[0]).unwrap().1;
        if path.len() == 1 {
            next
        } else {
            field_mut(next, &path[1..])
        }
    }

    #[test]
    fn observation_mutations_fail_at_the_independent_relation() {
        let original = empty_observation();
        let mut changed = original.clone();
        *field_mut(&mut changed, &["policy_sha256"]) = Value::Bytes(vec![9; 32]);
        assert_eq!(
            verify_observation(&changed, &[1; 32]),
            Err(EgressError::BindingMismatch)
        );

        let mut changed = original.clone();
        *field_mut(&mut changed, &["boundary", "supervisor_network_namespace"]) = namespace(8);
        assert_eq!(
            verify_observation(&changed, &[1; 32]),
            Err(EgressError::BoundaryInvalid)
        );

        let mut changed = original.clone();
        *field_mut(&mut changed, &["proxy", "phases"]) =
            Value::Array(vec![text("created"), text("ready"), text("closed")]);
        assert_eq!(
            verify_observation(&changed, &[1; 32]),
            Err(EgressError::PhaseInvalid)
        );

        let mut changed = original.clone();
        *field_mut(&mut changed, &["authority", "limits", "connections"]) = number(0);
        assert_eq!(
            verify_observation(&changed, &[1; 32]),
            Err(EgressError::LimitExceeded)
        );

        let mut changed = original.clone();
        *field_mut(&mut changed, &["limit_events"]) =
            Value::Array(vec![text("egress-limit-connections")]);
        assert_eq!(
            verify_observation(&changed, &[1; 32]),
            Err(EgressError::LimitEventMismatch)
        );

        let mut changed = original.clone();
        let Value::Array(endpoints) = field_mut(&mut changed, &["authority", "endpoints"]) else {
            panic!()
        };
        endpoints.push(endpoints[0].clone());
        assert_eq!(
            verify_observation(&changed, &[1; 32]),
            Err(EgressError::EndpointUnknown)
        );

        let mut changed = original.clone();
        let Value::Array(endpoints) = field_mut(&mut changed, &["authority", "endpoints"]) else {
            panic!()
        };
        *field_mut(&mut endpoints[0], &["destination", "bytes"]) = Value::Bytes(vec![224, 0, 0, 1]);
        assert_eq!(
            verify_observation(&changed, &[1; 32]),
            Err(EgressError::AddressScope)
        );

        let mut changed = original;
        *field_mut(&mut changed, &["cleanup", "listener_closed"]) = Value::Bool(false);
        assert!(
            verify_observation(&changed, &[1; 32])
                .unwrap()
                .cleanup_incomplete
        );
    }

    fn failed_resolution_observation() -> Value {
        let mut observation = empty_observation();
        let Value::Array(endpoints) = field_mut(&mut observation, &["authority", "endpoints"])
        else {
            panic!()
        };
        *field_mut(&mut endpoints[0], &["destination"]) = object(vec![
            ("kind", text("dns-name")),
            ("name", text("api.example")),
            ("address_scope", text("global")),
        ]);
        *field_mut(&mut observation, &["resolutions"]) = Value::Array(vec![object(vec![
            ("index", number(1)),
            ("name", text("api.example")),
            ("triggering_connection", number(1)),
            ("started_ms", number(1)),
            ("finished_ms", number(2)),
            ("messages", Value::Array(Vec::new())),
            ("cname_links", Value::Array(Vec::new())),
            ("answers", Value::Array(Vec::new())),
            ("outcome", text("failed")),
        ])]);
        *field_mut(&mut observation, &["connections"]) = Value::Array(vec![object(vec![
            ("index", number(1)),
            ("endpoint_index", number(0)),
            ("open_sequence", number(1)),
            ("close_sequence", number(2)),
            ("accepted_ms", number(0)),
            ("resolution_index", number(1)),
            ("sni_result", text("not-inspected")),
            ("attempts", Value::Array(Vec::new())),
            ("selected_attempt", Value::Null),
            ("client_to_remote_bytes", number(0)),
            ("remote_to_client_bytes", number(0)),
            ("close_reason", text("resolution-failed")),
        ])]);
        *field_mut(&mut observation, &["counters", "connections"]) = number(1);
        *field_mut(&mut observation, &["counters", "resolutions"]) = number(1);
        observation
    }

    #[test]
    fn one_based_connection_and_resolution_indices_bind_to_the_trigger() {
        let observation = failed_resolution_observation();
        assert!(verify_observation(&observation, &[1; 32]).is_ok());

        let mut changed = observation.clone();
        let Value::Array(resolutions) = field_mut(&mut changed, &["resolutions"]) else {
            panic!()
        };
        *field_mut(&mut resolutions[0], &["triggering_connection"]) = number(2);
        assert_eq!(
            verify_observation(&changed, &[1; 32]),
            Err(EgressError::ResolutionMismatch)
        );

        let mut changed = observation;
        let Value::Array(connections) = field_mut(&mut changed, &["connections"]) else {
            panic!()
        };
        *field_mut(&mut connections[0], &["index"]) = number(0);
        assert_eq!(
            verify_observation(&changed, &[1; 32]),
            Err(EgressError::SequenceInvalid)
        );
    }

    fn answered_resolution_observation() -> Value {
        let mut observation = failed_resolution_observation();
        let Value::Array(resolutions) = field_mut(&mut observation, &["resolutions"]) else {
            panic!()
        };
        let record = &mut resolutions[0];
        *field_mut(record, &["messages"]) = Value::Array(vec![object(vec![
            ("sha256", Value::Bytes(vec![6; 32])),
            ("size", number(64)),
            ("finished_ms", number(2)),
        ])]);
        *field_mut(record, &["answers"]) = Value::Array(vec![object(vec![
            ("address", ip()),
            ("ttl", number(1)),
            ("record_expiry_ms", number(1002)),
            ("effective_expiry_ms", number(1002)),
            ("message_sha256", Value::Bytes(vec![6; 32])),
            ("admissible", Value::Bool(true)),
        ])]);
        *field_mut(record, &["outcome"]) = text("answered");
        let Value::Array(connections) = field_mut(&mut observation, &["connections"]) else {
            panic!()
        };
        let connection = &mut connections[0];
        *field_mut(connection, &["attempts"]) = Value::Array(vec![object(vec![
            ("answer_index", number(0)),
            ("address", ip()),
            ("started_ms", number(3)),
            ("result", text("connected")),
        ])]);
        *field_mut(connection, &["selected_attempt"]) = number(0);
        *field_mut(connection, &["client_to_remote_bytes"]) = number(1);
        *field_mut(connection, &["close_reason"]) = text("remote-closed");
        *field_mut(&mut observation, &["counters", "dns_messages"]) = number(1);
        *field_mut(&mut observation, &["counters", "client_to_remote_bytes"]) = number(1);
        observation
    }

    #[test]
    fn answer_attempt_and_sni_relations_reject_substitution() {
        let observation = answered_resolution_observation();
        assert!(verify_observation(&observation, &[1; 32]).is_ok());

        let mut changed = observation.clone();
        let Value::Array(connections) = field_mut(&mut changed, &["connections"]) else {
            panic!()
        };
        let Value::Array(attempts) = field_mut(&mut connections[0], &["attempts"]) else {
            panic!()
        };
        *field_mut(&mut attempts[0], &["answer_index"]) = number(1);
        assert_eq!(
            verify_observation(&changed, &[1; 32]),
            Err(EgressError::AnswerUnknown)
        );

        let mut changed = observation.clone();
        let Value::Array(connections) = field_mut(&mut changed, &["connections"]) else {
            panic!()
        };
        *field_mut(&mut connections[0], &["selected_attempt"]) = number(1);
        assert_eq!(
            verify_observation(&changed, &[1; 32]),
            Err(EgressError::AttemptBound)
        );

        let mut changed = observation.clone();
        let Value::Array(endpoints) = field_mut(&mut changed, &["authority", "endpoints"]) else {
            panic!()
        };
        *field_mut(&mut endpoints[0], &["tls_sni"]) = object(vec![
            ("mode", text("required")),
            ("name", text("api.example")),
        ]);
        assert_eq!(
            verify_observation(&changed, &[1; 32]),
            Err(EgressError::SniUnbound)
        );

        let mut changed = observation;
        let Value::Array(resolutions) = field_mut(&mut changed, &["resolutions"]) else {
            panic!()
        };
        let Value::Array(answers) = field_mut(&mut resolutions[0], &["answers"]) else {
            panic!()
        };
        *field_mut(&mut answers[0], &["message_sha256"]) = Value::Bytes(vec![7; 32]);
        assert_eq!(
            verify_observation(&changed, &[1; 32]),
            Err(EgressError::ResolutionMismatch)
        );
    }

    #[test]
    fn reused_dns_answer_must_not_expire_before_attempt() {
        let mut observation = answered_resolution_observation();
        let Value::Array(connections) = field_mut(&mut observation, &["connections"]) else {
            panic!()
        };
        let mut reused = connections[0].clone();
        *field_mut(&mut reused, &["index"]) = number(2);
        *field_mut(&mut reused, &["open_sequence"]) = number(3);
        *field_mut(&mut reused, &["close_sequence"]) = number(4);
        *field_mut(&mut reused, &["accepted_ms"]) = number(1002);
        let Value::Array(attempts) = field_mut(&mut reused, &["attempts"]) else {
            panic!()
        };
        *field_mut(&mut attempts[0], &["started_ms"]) = number(1002);
        *field_mut(&mut attempts[0], &["result"]) = text("refused");
        *field_mut(&mut reused, &["selected_attempt"]) = Value::Null;
        *field_mut(&mut reused, &["client_to_remote_bytes"]) = number(0);
        *field_mut(&mut reused, &["close_reason"]) = text("connect-failed");
        connections.push(reused);
        *field_mut(&mut observation, &["counters", "connections"]) = number(2);
        assert!(verify_observation(&observation, &[1; 32]).is_ok());

        let Value::Array(connections) = field_mut(&mut observation, &["connections"]) else {
            panic!()
        };
        let Value::Array(attempts) = field_mut(&mut connections[1], &["attempts"]) else {
            panic!()
        };
        *field_mut(&mut attempts[0], &["started_ms"]) = number(1003);
        assert_eq!(
            verify_observation(&observation, &[1; 32]),
            Err(EgressError::AnswerExpired)
        );
    }

    #[test]
    fn dns_attempt_cannot_select_an_inadmissible_address() {
        let mut observation = answered_resolution_observation();
        let private = object(vec![
            ("family", text("ipv4")),
            ("bytes", Value::Bytes(vec![10, 0, 0, 1])),
        ]);
        let Value::Array(resolutions) = field_mut(&mut observation, &["resolutions"]) else {
            panic!()
        };
        let Value::Array(answers) = field_mut(&mut resolutions[0], &["answers"]) else {
            panic!()
        };
        let mut blocked = answers[0].clone();
        *field_mut(&mut blocked, &["address"]) = private.clone();
        *field_mut(&mut blocked, &["admissible"]) = Value::Bool(false);
        answers.push(blocked);
        let Value::Array(connections) = field_mut(&mut observation, &["connections"]) else {
            panic!()
        };
        let Value::Array(attempts) = field_mut(&mut connections[0], &["attempts"]) else {
            panic!()
        };
        *field_mut(&mut attempts[0], &["answer_index"]) = number(1);
        *field_mut(&mut attempts[0], &["address"]) = private;
        assert_eq!(
            verify_observation(&observation, &[1; 32]),
            Err(EgressError::AddressScope)
        );
    }

    #[test]
    fn verifier_recomputes_peak_concurrency_from_sequences() {
        let mut observation = answered_resolution_observation();
        let Value::Array(connections) = field_mut(&mut observation, &["connections"]) else {
            panic!()
        };
        let mut second = connections[0].clone();
        *field_mut(&mut second, &["index"]) = number(2);
        *field_mut(&mut second, &["open_sequence"]) = number(3);
        *field_mut(&mut second, &["close_sequence"]) = number(4);
        connections.push(second);
        *field_mut(&mut observation, &["counters", "connections"]) = number(2);
        *field_mut(&mut observation, &["counters", "client_to_remote_bytes"]) = number(2);
        *field_mut(
            &mut observation,
            &["authority", "limits", "concurrent_connections"],
        ) = number(1);
        assert!(verify_observation(&observation, &[1; 32]).is_ok());

        let Value::Array(connections) = field_mut(&mut observation, &["connections"]) else {
            panic!()
        };
        *field_mut(&mut connections[0], &["close_sequence"]) = number(4);
        *field_mut(&mut connections[1], &["open_sequence"]) = number(2);
        *field_mut(&mut connections[1], &["close_sequence"]) = number(3);
        assert_eq!(
            verify_observation(&observation, &[1; 32]),
            Err(EgressError::ConcurrencyExceeded)
        );
    }

    #[test]
    fn empty_closed_observation_is_valid_but_forged_counter_is_not() {
        let mut value = empty_observation();
        assert_eq!(
            verify_observation(&value, &[1; 32]),
            Ok(EgressDecision {
                authority_rejection: false,
                sni_denied: false,
                limit_reached: false,
                proxy_failed: false,
                cleanup_incomplete: false,
                proxy_executable_sha256: [2; 32],
                proxy_runtime_closure_sha256: Vec::new(),
                resolver_configuration_sha256: [2; 32],
            })
        );
        let Value::Map(root) = &mut value else {
            panic!()
        };
        let Value::Map(counters) = &mut root
            .iter_mut()
            .find(|(key, _)| key == "counters")
            .unwrap()
            .1
        else {
            panic!()
        };
        counters
            .iter_mut()
            .find(|(key, _)| key == "connections")
            .unwrap()
            .1 = number(1);
        assert_eq!(
            verify_observation(&value, &[1; 32]),
            Err(EgressError::CounterMismatch)
        );
    }
}
