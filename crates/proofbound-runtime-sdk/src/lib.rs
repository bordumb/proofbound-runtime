#![forbid(unsafe_code)]

//! Convenience construction and projection decoding for Proofbound Runtime.
//!
//! This crate never executes a workload or embeds Runtime verification and
//! Linux-boundary semantics. Execution remains a separate `pbr` process.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use serde_json::{Map, Value};

const PLAN_SCHEMA: &str = "proofbound-runtime-plan/2";
const RESULT_SCHEMA: &str = "proofbound-runtime-run-result/2";
const RESOURCE_QUANTUM: u64 = 65_536;
const MAX_RESOURCE_BYTES: u64 = 1_099_511_627_776;

/// Closed logical inputs for one version 2 execution plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanV2Input {
    pub id: String,
    pub executable: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    pub read: Vec<String>,
    pub runtime_read: Vec<String>,
    pub write: Vec<String>,
    pub execute: Vec<String>,
    pub environment: Vec<String>,
    pub processes: u32,
    pub wall_time_ms: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub memory_bytes: u64,
    pub swap_bytes: u64,
}

/// Closed network-authority inputs for one version 2 execution plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkAuthorityV2Input {
    /// Denies network access.
    Deny,
    /// Permits one bounded connector-owned authenticated service session.
    AuthenticatedServiceSession(Box<ServiceSessionV2Input>),
}

/// Selects one numeric resolver address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolverAddressV2Input {
    /// Contains four IPv4 network-order bytes.
    Ipv4([u8; 4]),
    /// Contains sixteen IPv6 network-order bytes.
    Ipv6([u8; 16]),
}

/// Contains the bounded DNS inputs for one service session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionV2Input {
    pub address: ResolverAddressV2Input,
    pub port: u16,
    pub configuration: String,
    pub maximum_cname_depth: u16,
    pub maximum_answer_count: u16,
    pub maximum_response_bytes: u64,
    pub resolution_deadline_ms: u64,
    pub attempt_deadline_ms: u64,
}

/// Contains the closed TLS inputs for one service session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsV2Input {
    pub trust_root_set: String,
    pub minimum_version: String,
}

/// Contains the bounded session inputs for one service session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceSessionLimitsV2Input {
    pub setup_time_ms: u64,
    pub session_time_ms: u64,
    pub child_to_service_bytes: u64,
    pub service_to_child_bytes: u64,
    pub dns_messages: u16,
    pub endpoint_attempts: u16,
    pub tls_handshake_bytes: u64,
}

/// Identifies an optional service-bound credential source without its value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialSourceV2Input {
    pub id: String,
    pub service: String,
    pub environment: String,
}

/// Contains one complete authenticated-service-session plan input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceSessionV2Input {
    pub service: String,
    pub port: u16,
    pub resolution: ResolutionV2Input,
    pub tls: TlsV2Input,
    pub limits: ServiceSessionLimitsV2Input,
    pub connector_executable: String,
    pub connector_runtime_read: Vec<String>,
    pub child_descriptor: u16,
    pub credential_source: Option<CredentialSourceV2Input>,
}

/// One semantically validated deterministic-CBOR version 2 plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanV2 {
    bytes: Vec<u8>,
}

impl PlanV2 {
    /// Validates the closed public input and encodes deterministic-CBOR bytes.
    pub fn new(input: PlanV2Input) -> Result<Self, SdkError> {
        Self::new_with_network(input, NetworkAuthorityV2Input::Deny)
    }

    /// Validates a plan and its explicit closed network authority.
    pub fn new_with_network(
        input: PlanV2Input,
        network: NetworkAuthorityV2Input,
    ) -> Result<Self, SdkError> {
        validate_plan_input(&input)?;
        validate_network_input(&input, &network)?;
        let network = encode_network_input(network);
        let value = Cbor::Map(vec![
            ("id", Cbor::Text(input.id)),
            ("schema", Cbor::Text(PLAN_SCHEMA.to_owned())),
            (
                "limits",
                Cbor::Map(vec![
                    ("processes", Cbor::Unsigned(u64::from(input.processes))),
                    ("swap_bytes", Cbor::Unsigned(input.swap_bytes)),
                    ("stderr_bytes", Cbor::Unsigned(input.stderr_bytes)),
                    ("stdout_bytes", Cbor::Unsigned(input.stdout_bytes)),
                    ("memory_bytes", Cbor::Unsigned(input.memory_bytes)),
                    ("wall_time_ms", Cbor::Unsigned(input.wall_time_ms)),
                ]),
            ),
            (
                "command",
                Cbor::Map(vec![
                    ("arguments", text_array(input.arguments)),
                    ("executable", Cbor::Text(input.executable)),
                    ("working_directory", Cbor::Text(input.working_directory)),
                ]),
            ),
            (
                "authority",
                Cbor::Map(vec![
                    ("read", text_array(input.read)),
                    ("write", text_array(input.write)),
                    ("execute", text_array(input.execute)),
                    ("network", network),
                    ("environment", text_array(input.environment)),
                    ("runtime_read", text_array(input.runtime_read)),
                ]),
            ),
        ]);
        let mut bytes = Vec::new();
        encode(&value, &mut bytes)?;
        Ok(Self { bytes })
    }

    /// Returns the exact deterministic-CBOR plan bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the validated wrapper and returns its exact bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Closed child outcome projected by `pbr run`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunOutcome {
    Exited { code: u8 },
    Signaled { signal: u8 },
    TimedOut,
    Denied,
    LauncherFailed,
    Incomplete,
}

/// Strictly decoded JSON control projection from `pbr run`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunResultProjection {
    receipt: String,
    execution_id: [u8; 16],
    commitment: [u8; 32],
    outcome: RunOutcome,
}

impl RunResultProjection {
    /// Decodes one closed result object. The JSON bytes are display/control
    /// data and are never returned as receipt verification input.
    pub fn from_json(input: &[u8]) -> Result<Self, SdkError> {
        let value: Value = serde_json::from_slice(input).map_err(|_| SdkError::ResultMalformed)?;
        let mut root = object(value)?;
        require_keys(
            &root,
            &["commitment", "execution_id", "outcome", "receipt", "schema"],
        )?;
        if text(take(&mut root, "schema")?)? != RESULT_SCHEMA {
            return Err(SdkError::ResultSchema);
        }
        let receipt = text(take(&mut root, "receipt")?)?.to_owned();
        if receipt.is_empty() {
            return Err(SdkError::ResultField);
        }
        let commitment = decode_prefixed::<32>(text(take(&mut root, "commitment")?)?)?;
        let execution_id = decode_prefixed::<16>(text(take(&mut root, "execution_id")?)?)?;
        if execution_id[6] >> 4 != 4 || execution_id[8] >> 6 != 2 {
            return Err(SdkError::ResultField);
        }
        let outcome = decode_outcome(take(&mut root, "outcome")?)?;
        Ok(Self {
            receipt,
            execution_id,
            commitment,
            outcome,
        })
    }

    #[must_use]
    pub fn receipt(&self) -> &str {
        &self.receipt
    }

    #[must_use]
    pub fn execution_id(&self) -> &[u8; 16] {
        &self.execution_id
    }

    #[must_use]
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    #[must_use]
    pub fn outcome(&self) -> &RunOutcome {
        &self.outcome
    }
}

/// Stable SDK construction and projection errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdkError {
    PlanId,
    PlanShape,
    PlanDuplicate,
    PlanField,
    PlanRuntimeRead,
    PlanLimit,
    PlanLimitQuantum,
    PlanNetwork,
    CborBound,
    ResultMalformed,
    ResultSchema,
    ResultUnknownField,
    ResultField,
}

impl SdkError {
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::PlanId => "sdk.plan.id-invalid",
            Self::PlanShape => "sdk.plan.shape-invalid",
            Self::PlanDuplicate => "sdk.plan.duplicate",
            Self::PlanField => "sdk.plan.field-invalid",
            Self::PlanRuntimeRead => "sdk.plan.runtime-read-not-absolute",
            Self::PlanLimit => "sdk.plan.limit-invalid",
            Self::PlanLimitQuantum => "sdk.plan.limit-not-quantized",
            Self::PlanNetwork => "sdk.plan.network-invalid",
            Self::CborBound => "sdk.plan.cbor-bound",
            Self::ResultMalformed => "sdk.result.malformed-json",
            Self::ResultSchema => "sdk.result.schema-unsupported",
            Self::ResultUnknownField => "sdk.result.unknown-field",
            Self::ResultField => "sdk.result.field-invalid",
        }
    }
}

impl fmt::Display for SdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for SdkError {}

#[derive(Clone, Debug)]
enum Cbor {
    Unsigned(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(&'static str, Cbor)>),
}

fn text_array(values: Vec<String>) -> Cbor {
    Cbor::Array(values.into_iter().map(Cbor::Text).collect())
}

fn encode(value: &Cbor, output: &mut Vec<u8>) -> Result<(), SdkError> {
    match value {
        Cbor::Unsigned(value) => encode_argument(0, *value, output),
        Cbor::Bytes(value) => {
            encode_argument(2, value.len() as u64, output)?;
            output.extend_from_slice(value);
            Ok(())
        }
        Cbor::Text(value) => {
            encode_argument(3, value.len() as u64, output)?;
            output.extend_from_slice(value.as_bytes());
            Ok(())
        }
        Cbor::Array(values) => {
            encode_argument(4, values.len() as u64, output)?;
            for value in values {
                encode(value, output)?;
            }
            Ok(())
        }
        Cbor::Map(entries) => {
            let mut encoded = entries
                .iter()
                .map(|(key, value)| {
                    let mut key_bytes = Vec::new();
                    encode(&Cbor::Text((*key).to_owned()), &mut key_bytes)?;
                    let mut value_bytes = Vec::new();
                    encode(value, &mut value_bytes)?;
                    Ok((key_bytes, value_bytes))
                })
                .collect::<Result<Vec<_>, SdkError>>()?;
            encoded.sort_by(|left, right| left.0.cmp(&right.0));
            encode_argument(5, encoded.len() as u64, output)?;
            for (key, value) in encoded {
                output.extend_from_slice(&key);
                output.extend_from_slice(&value);
            }
            Ok(())
        }
    }
}

fn encode_argument(major: u8, value: u64, output: &mut Vec<u8>) -> Result<(), SdkError> {
    match value {
        0..=23 => output.push((major << 5) | value as u8),
        24..=0xff => {
            output.push((major << 5) | 24);
            output.push(value as u8);
        }
        0x100..=0xffff => {
            output.push((major << 5) | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push((major << 5) | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push((major << 5) | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
    Ok(())
}

fn require_unique(values: &[String]) -> Result<(), SdkError> {
    if values.iter().collect::<BTreeSet<_>>().len() == values.len() {
        Ok(())
    } else {
        Err(SdkError::PlanDuplicate)
    }
}

fn validate_plan_input(input: &PlanV2Input) -> Result<(), SdkError> {
    if !valid_plan_id(&input.id) {
        return Err(SdkError::PlanId);
    }
    if !valid_required_text(&input.executable) || !valid_required_text(&input.working_directory) {
        return Err(SdkError::PlanField);
    }
    if input.arguments.iter().any(|value| value.contains('\0')) {
        return Err(SdkError::PlanField);
    }
    for values in [
        &input.read,
        &input.runtime_read,
        &input.write,
        &input.execute,
        &input.environment,
    ] {
        if values.iter().any(|value| value.contains('\0')) {
            return Err(SdkError::PlanField);
        }
        require_unique(values)?;
    }
    if input
        .environment
        .iter()
        .any(|name| name.is_empty() || name.contains('='))
    {
        return Err(SdkError::PlanField);
    }
    if input
        .runtime_read
        .iter()
        .any(|value| !Path::new(value).is_absolute())
    {
        return Err(SdkError::PlanRuntimeRead);
    }
    if input.write.len() != 1 || input.execute.len() != 1 || input.execute[0] != input.executable {
        return Err(SdkError::PlanShape);
    }
    if input.processes == 0
        || input.wall_time_ms == 0
        || !(RESOURCE_QUANTUM..=MAX_RESOURCE_BYTES).contains(&input.memory_bytes)
        || input.swap_bytes > MAX_RESOURCE_BYTES
    {
        return Err(SdkError::PlanLimit);
    }
    if !input.memory_bytes.is_multiple_of(RESOURCE_QUANTUM)
        || !input.swap_bytes.is_multiple_of(RESOURCE_QUANTUM)
    {
        return Err(SdkError::PlanLimitQuantum);
    }
    Ok(())
}

fn validate_network_input(
    plan: &PlanV2Input,
    network: &NetworkAuthorityV2Input,
) -> Result<(), SdkError> {
    let NetworkAuthorityV2Input::AuthenticatedServiceSession(session) = network else {
        return Ok(());
    };
    if !valid_service_name(&session.service)
        || session.port == 0
        || session.resolution.port == 0
        || !canonical_absolute_path(&session.resolution.configuration)
        || session.resolution.maximum_cname_depth == 0
        || session.resolution.maximum_answer_count == 0
        || session.resolution.maximum_response_bytes == 0
        || session.resolution.resolution_deadline_ms == 0
        || session.resolution.attempt_deadline_ms == 0
        || session.resolution.attempt_deadline_ms > session.resolution.resolution_deadline_ms
        || !canonical_absolute_path(&session.tls.trust_root_set)
        || !matches!(session.tls.minimum_version.as_str(), "tls-1.2" | "tls-1.3")
        || !canonical_absolute_path(&session.connector_executable)
        || session
            .connector_runtime_read
            .iter()
            .any(|path| !canonical_absolute_path(path))
        || session.child_descriptor < 3
    {
        return Err(SdkError::PlanNetwork);
    }
    require_unique(&session.connector_runtime_read)?;
    let limits = &session.limits;
    if limits.setup_time_ms == 0
        || limits.session_time_ms == 0
        || limits.child_to_service_bytes == 0
        || limits.service_to_child_bytes == 0
        || limits.dns_messages < 2
        || limits.endpoint_attempts == 0
        || limits.tls_handshake_bytes == 0
        || limits.endpoint_attempts > session.resolution.maximum_answer_count
        || session.resolution.resolution_deadline_ms > limits.setup_time_ms
    {
        return Err(SdkError::PlanNetwork);
    }
    if let Some(source) = &session.credential_source
        && (!valid_credential_source_id(&source.id)
            || source.service != session.service
            || !plan.environment.contains(&source.environment))
    {
        return Err(SdkError::PlanNetwork);
    }
    Ok(())
}

fn encode_network_input(network: NetworkAuthorityV2Input) -> Cbor {
    match network {
        NetworkAuthorityV2Input::Deny => Cbor::Text("deny".to_owned()),
        NetworkAuthorityV2Input::AuthenticatedServiceSession(session) => {
            let (family, bytes) = match session.resolution.address {
                ResolverAddressV2Input::Ipv4(bytes) => ("ipv4", bytes.to_vec()),
                ResolverAddressV2Input::Ipv6(bytes) => ("ipv6", bytes.to_vec()),
            };
            let mut entries = vec![
                (
                    "mode",
                    Cbor::Text("authenticated-service-session".to_owned()),
                ),
                (
                    "service",
                    Cbor::Map(vec![
                        ("name", Cbor::Text(session.service.clone())),
                        ("port", Cbor::Unsigned(u64::from(session.port))),
                    ]),
                ),
                (
                    "resolver",
                    Cbor::Map(vec![
                        (
                            "address",
                            Cbor::Map(vec![
                                ("family", Cbor::Text(family.to_owned())),
                                ("bytes", Cbor::Bytes(bytes)),
                            ]),
                        ),
                        ("port", Cbor::Unsigned(u64::from(session.resolution.port))),
                        (
                            "configuration",
                            Cbor::Text(session.resolution.configuration),
                        ),
                        (
                            "maximum_cname_depth",
                            Cbor::Unsigned(u64::from(session.resolution.maximum_cname_depth)),
                        ),
                        (
                            "maximum_answer_count",
                            Cbor::Unsigned(u64::from(session.resolution.maximum_answer_count)),
                        ),
                        (
                            "maximum_response_bytes",
                            Cbor::Unsigned(session.resolution.maximum_response_bytes),
                        ),
                        (
                            "resolution_deadline_ms",
                            Cbor::Unsigned(session.resolution.resolution_deadline_ms),
                        ),
                        (
                            "attempt_deadline_ms",
                            Cbor::Unsigned(session.resolution.attempt_deadline_ms),
                        ),
                        (
                            "address_order",
                            Cbor::Text("ipv4-then-ipv6-lexicographic".to_owned()),
                        ),
                    ]),
                ),
                (
                    "tls",
                    Cbor::Map(vec![
                        ("trust_root_set", Cbor::Text(session.tls.trust_root_set)),
                        ("minimum_version", Cbor::Text(session.tls.minimum_version)),
                        (
                            "service_name_verification",
                            Cbor::Text("dns-san-exact".to_owned()),
                        ),
                        (
                            "revocation",
                            Cbor::Text("not-checked-recorded-assumption".to_owned()),
                        ),
                        ("session_resumption", Cbor::Text("deny".to_owned())),
                        ("early_data", Cbor::Text("deny".to_owned())),
                    ]),
                ),
                (
                    "limits",
                    Cbor::Map(vec![
                        (
                            "setup_time_ms",
                            Cbor::Unsigned(session.limits.setup_time_ms),
                        ),
                        (
                            "session_time_ms",
                            Cbor::Unsigned(session.limits.session_time_ms),
                        ),
                        (
                            "child_to_service_bytes",
                            Cbor::Unsigned(session.limits.child_to_service_bytes),
                        ),
                        (
                            "service_to_child_bytes",
                            Cbor::Unsigned(session.limits.service_to_child_bytes),
                        ),
                        (
                            "dns_messages",
                            Cbor::Unsigned(u64::from(session.limits.dns_messages)),
                        ),
                        (
                            "endpoint_attempts",
                            Cbor::Unsigned(u64::from(session.limits.endpoint_attempts)),
                        ),
                        (
                            "tls_handshake_bytes",
                            Cbor::Unsigned(session.limits.tls_handshake_bytes),
                        ),
                    ]),
                ),
                (
                    "connector_executable",
                    Cbor::Text(session.connector_executable),
                ),
                (
                    "connector_runtime_read",
                    text_array(session.connector_runtime_read),
                ),
                (
                    "local_channel",
                    Cbor::Map(vec![
                        ("protocol", Cbor::Text("unix-stream-v1".to_owned())),
                        (
                            "child_descriptor",
                            Cbor::Unsigned(u64::from(session.child_descriptor)),
                        ),
                    ]),
                ),
            ];
            if let Some(source) = session.credential_source {
                entries.push((
                    "credential_source",
                    Cbor::Map(vec![
                        ("id", Cbor::Text(source.id)),
                        ("service", Cbor::Text(source.service)),
                        ("environment", Cbor::Text(source.environment)),
                    ]),
                ));
            }
            Cbor::Map(entries)
        }
    }
}

fn canonical_absolute_path(value: &str) -> bool {
    if value.contains('\0') {
        return false;
    }
    let path = Path::new(value);
    path.is_absolute()
        && (value == "/"
            || value.strip_prefix('/').is_some_and(|suffix| {
                !suffix
                    .split('/')
                    .any(|component| component.is_empty() || matches!(component, "." | ".."))
            }))
}

fn valid_service_name(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 253
        || value.ends_with('.')
        || value.parse::<std::net::IpAddr>().is_ok()
        || value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return false;
    }
    value.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes.first() != Some(&b'-')
            && bytes.last() != Some(&b'-')
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    })
}

fn valid_credential_source_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes.first().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

fn valid_required_text(value: &str) -> bool {
    !value.is_empty() && !value.contains('\0')
}

fn valid_plan_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    let endpoint = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    endpoint(bytes[0])
        && endpoint(bytes[bytes.len() - 1])
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn object(value: Value) -> Result<Map<String, Value>, SdkError> {
    value.as_object().cloned().ok_or(SdkError::ResultField)
}

fn require_keys(root: &Map<String, Value>, expected: &[&str]) -> Result<(), SdkError> {
    let actual = root.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(SdkError::ResultUnknownField)
    }
}

fn take(root: &mut Map<String, Value>, name: &str) -> Result<Value, SdkError> {
    root.remove(name).ok_or(SdkError::ResultField)
}

fn text(value: Value) -> Result<String, SdkError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(SdkError::ResultField)
}

fn decode_outcome(value: Value) -> Result<RunOutcome, SdkError> {
    let mut outcome = object(value)?;
    let kind = outcome
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(SdkError::ResultField)?
        .to_owned();
    match kind.as_str() {
        "exited" => {
            require_keys(&outcome, &["code", "kind"])?;
            let code = take(&mut outcome, "code")?
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or(SdkError::ResultField)?;
            Ok(RunOutcome::Exited { code })
        }
        "signaled" => {
            require_keys(&outcome, &["kind", "signal"])?;
            let signal = take(&mut outcome, "signal")?
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or(SdkError::ResultField)?;
            Ok(RunOutcome::Signaled { signal })
        }
        "timed-out" | "denied" | "launcher-failed" | "incomplete" => {
            require_keys(&outcome, &["kind"])?;
            Ok(match kind.as_str() {
                "timed-out" => RunOutcome::TimedOut,
                "denied" => RunOutcome::Denied,
                "launcher-failed" => RunOutcome::LauncherFailed,
                "incomplete" => RunOutcome::Incomplete,
                _ => unreachable!(),
            })
        }
        _ => Err(SdkError::ResultField),
    }
}

fn decode_prefixed<const N: usize>(value: String) -> Result<[u8; N], SdkError> {
    let value = value.strip_prefix("hex:").ok_or(SdkError::ResultField)?;
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SdkError::ResultField);
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(output)
}

fn nibble(value: u8) -> Result<u8, SdkError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(SdkError::ResultField),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden_input() -> PlanV2Input {
        PlanV2Input {
            id: "golden-v2".to_owned(),
            executable: "bin/hello".to_owned(),
            arguments: Vec::new(),
            working_directory: ".".to_owned(),
            read: Vec::new(),
            runtime_read: Vec::new(),
            write: vec!["out".to_owned()],
            execute: vec!["bin/hello".to_owned()],
            environment: Vec::new(),
            processes: 2,
            wall_time_ms: 1_000,
            stdout_bytes: 1_024,
            stderr_bytes: 1_024,
            memory_bytes: 65_536,
            swap_bytes: 0,
        }
    }

    fn service_session() -> NetworkAuthorityV2Input {
        NetworkAuthorityV2Input::AuthenticatedServiceSession(Box::new(ServiceSessionV2Input {
            service: "api.anthropic.com".to_owned(),
            port: 443,
            resolution: ResolutionV2Input {
                address: ResolverAddressV2Input::Ipv4([1, 1, 1, 1]),
                port: 53,
                configuration: "/etc/proofbound/resolver.conf".to_owned(),
                maximum_cname_depth: 8,
                maximum_answer_count: 16,
                maximum_response_bytes: 65_536,
                resolution_deadline_ms: 5_000,
                attempt_deadline_ms: 1_000,
            },
            tls: TlsV2Input {
                trust_root_set: "/etc/ssl/certs/ca-certificates.crt".to_owned(),
                minimum_version: "tls-1.3".to_owned(),
            },
            limits: ServiceSessionLimitsV2Input {
                setup_time_ms: 10_000,
                session_time_ms: 30_000,
                child_to_service_bytes: 1_048_576,
                service_to_child_bytes: 1_048_576,
                dns_messages: 4,
                endpoint_attempts: 4,
                tls_handshake_bytes: 262_144,
            },
            connector_executable: "/usr/libexec/proofbound-connector".to_owned(),
            connector_runtime_read: vec!["/usr/lib".to_owned()],
            child_descriptor: 9,
            credential_source: Some(CredentialSourceV2Input {
                id: "anthropic-test".to_owned(),
                service: "api.anthropic.com".to_owned(),
                environment: "API_KEY".to_owned(),
            }),
        }))
    }

    #[test]
    fn rust_plan_matches_the_frozen_v2_golden() {
        let plan = PlanV2::new(golden_input()).expect("golden plan validates");
        let expected = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/vectors/v2/execution-plan.cbor.hex"
        ))
        .split_whitespace()
        .collect::<String>();
        assert_eq!(hex(plan.as_bytes()), expected);
    }

    #[test]
    fn duplicate_or_mismatched_authority_is_rejected_before_encoding() {
        let mut duplicate = golden_input();
        duplicate.read = vec!["input".to_owned(), "input".to_owned()];
        assert_eq!(PlanV2::new(duplicate), Err(SdkError::PlanDuplicate));
        let mut mismatch = golden_input();
        mismatch.execute = vec!["bin/other".to_owned()];
        assert_eq!(PlanV2::new(mismatch), Err(SdkError::PlanShape));
    }

    #[test]
    fn service_session_encoding_is_closed_and_validated() {
        let mut input = golden_input();
        input.environment.push("API_KEY".to_owned());
        let plan = PlanV2::new_with_network(input.clone(), service_session())
            .expect("service session validates");
        let expected = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/vectors/v2/execution-plan-service-session.cbor.hex"
        ))
        .split_whitespace()
        .collect::<String>();
        assert_eq!(hex(plan.as_bytes()), expected);

        let NetworkAuthorityV2Input::AuthenticatedServiceSession(mut invalid) = service_session()
        else {
            unreachable!()
        };
        invalid.service = "API.anthropic.com".to_owned();
        assert_eq!(
            PlanV2::new_with_network(
                input.clone(),
                NetworkAuthorityV2Input::AuthenticatedServiceSession(invalid)
            ),
            Err(SdkError::PlanNetwork)
        );

        let NetworkAuthorityV2Input::AuthenticatedServiceSession(mut invalid) = service_session()
        else {
            unreachable!()
        };
        invalid.limits.setup_time_ms = invalid.resolution.resolution_deadline_ms - 1;
        assert_eq!(
            PlanV2::new_with_network(
                input.clone(),
                NetworkAuthorityV2Input::AuthenticatedServiceSession(invalid)
            ),
            Err(SdkError::PlanNetwork)
        );

        let NetworkAuthorityV2Input::AuthenticatedServiceSession(mut invalid) = service_session()
        else {
            unreachable!()
        };
        invalid.limits.dns_messages = 1;
        assert_eq!(
            PlanV2::new_with_network(
                input,
                NetworkAuthorityV2Input::AuthenticatedServiceSession(invalid)
            ),
            Err(SdkError::PlanNetwork)
        );

        let mut input = golden_input();
        input.environment.push("API_KEY".to_owned());
        let NetworkAuthorityV2Input::AuthenticatedServiceSession(mut invalid) = service_session()
        else {
            unreachable!()
        };
        invalid
            .credential_source
            .as_mut()
            .expect("fixture source")
            .service = "other.example.com".to_owned();
        assert_eq!(
            PlanV2::new_with_network(
                input.clone(),
                NetworkAuthorityV2Input::AuthenticatedServiceSession(invalid)
            ),
            Err(SdkError::PlanNetwork)
        );

        let NetworkAuthorityV2Input::AuthenticatedServiceSession(mut invalid) = service_session()
        else {
            unreachable!()
        };
        invalid
            .credential_source
            .as_mut()
            .expect("fixture source")
            .environment = "MISSING_KEY".to_owned();
        assert_eq!(
            PlanV2::new_with_network(
                input.clone(),
                NetworkAuthorityV2Input::AuthenticatedServiceSession(invalid)
            ),
            Err(SdkError::PlanNetwork)
        );

        let NetworkAuthorityV2Input::AuthenticatedServiceSession(mut invalid) = service_session()
        else {
            unreachable!()
        };
        invalid.connector_runtime_read = vec!["/usr/\0lib".to_owned()];
        assert_eq!(
            PlanV2::new_with_network(
                input,
                NetworkAuthorityV2Input::AuthenticatedServiceSession(invalid)
            ),
            Err(SdkError::PlanNetwork)
        );
    }

    #[test]
    fn resolver_address_width_is_fixed_by_the_public_type() {
        let ResolverAddressV2Input::Ipv4(ipv4) = ResolverAddressV2Input::Ipv4([1, 1, 1, 1]) else {
            unreachable!()
        };
        let ResolverAddressV2Input::Ipv6(ipv6) = ResolverAddressV2Input::Ipv6([0; 16]) else {
            unreachable!()
        };
        assert_eq!(ipv4.len(), 4);
        assert_eq!(ipv6.len(), 16);
    }

    #[test]
    fn standalone_validator_rejects_every_bounded_input_class() {
        let mut invalid_id = golden_input();
        invalid_id.id = "Uppercase".to_owned();
        assert_eq!(PlanV2::new(invalid_id), Err(SdkError::PlanId));

        let mut invalid_text = golden_input();
        invalid_text.arguments = vec!["nul\0argument".to_owned()];
        assert_eq!(PlanV2::new(invalid_text), Err(SdkError::PlanField));

        let mut relative_runtime = golden_input();
        relative_runtime.runtime_read = vec!["relative".to_owned()];
        assert_eq!(
            PlanV2::new(relative_runtime),
            Err(SdkError::PlanRuntimeRead)
        );

        let mut zero_processes = golden_input();
        zero_processes.processes = 0;
        assert_eq!(PlanV2::new(zero_processes), Err(SdkError::PlanLimit));

        let mut unquantized = golden_input();
        unquantized.memory_bytes += 1;
        assert_eq!(PlanV2::new(unquantized), Err(SdkError::PlanLimitQuantum));
    }

    #[test]
    fn run_result_projection_is_closed_and_validates_external_identities() {
        let input = br#"{"schema":"proofbound-runtime-run-result/2","outcome":{"kind":"exited","code":0},"receipt":"receipt.cbor","commitment":"hex:0909090909090909090909090909090909090909090909090909090909090909","execution_id":"hex:00000000000040008000000000000000"}"#;
        let result = RunResultProjection::from_json(input).expect("projection validates");
        assert_eq!(result.outcome(), &RunOutcome::Exited { code: 0 });
        assert_eq!(result.receipt(), "receipt.cbor");

        let unknown = input
            .strip_suffix(b"}")
            .unwrap()
            .iter()
            .copied()
            .chain(b",\"verified\":true}".iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(
            RunResultProjection::from_json(&unknown),
            Err(SdkError::ResultUnknownField)
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
