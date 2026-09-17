use core::fmt;
use std::path::{Component, Path};

use serde::Deserialize;
use toml::{Table, Value};

use crate::wire_v2::{self, Value as CborValue};
use crate::{
    AddressOrder, AuthenticatedServiceSession, AuthorityError, AuthorityPath, AuthorityPlan,
    ChildChannelDescriptor, CredentialSource, CredentialSourceId, EnvironmentName, FileAccess,
    LocalChannelProtocol, MemoryByteLimit, MinimumTlsVersion, NetworkAuthorityError,
    NetworkSupportPath, OutputByteLimit, PathAuthority, PathRole, ProcessLimit, ResolutionPolicy,
    ResolverAddress, ResolverEndpoint, ResourceLimits, RevocationPolicy, ServiceName,
    ServiceNameVerification, ServiceSessionLimits, SwapByteLimit, TcpPort, TlsPolicy,
};

const PLAN_SCHEMA: &str = "proofbound-runtime-plan/1";
const PLAN_SCHEMA_V2: &str = "proofbound-runtime-plan/2";

/// Contains a validated execution-plan identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PlanId(String);

impl PlanId {
    /// Validates a stable version 1 plan identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, PlanError> {
        let value = value.into();
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 128
            || !bytes.first().is_some_and(u8::is_ascii_lowercase_or_digit)
            || !bytes.last().is_some_and(u8::is_ascii_lowercase_or_digit)
            || !bytes.iter().all(|byte| {
                byte.is_ascii_lowercase_or_digit() || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(PlanError::InvalidPlanId);
        }
        Ok(Self(value))
    }

    /// Returns the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

trait AsciiPlanByte {
    fn is_ascii_lowercase_or_digit(&self) -> bool;
}

impl AsciiPlanByte for u8 {
    fn is_ascii_lowercase_or_digit(&self) -> bool {
        self.is_ascii_lowercase() || self.is_ascii_digit()
    }
}

/// Contains one validated command argument.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandArgument(String);

impl CommandArgument {
    /// Rejects an argument that contains a null byte.
    pub fn new(value: impl Into<String>) -> Result<Self, PlanError> {
        let value = value.into();
        if value.as_bytes().contains(&0) {
            return Err(PlanError::ArgumentContainsNull);
        }
        Ok(Self(value))
    }

    /// Returns the argument text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Contains the exact command declared by an execution plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionCommand {
    executable: AuthorityPath,
    arguments: Vec<CommandArgument>,
    working_directory: AuthorityPath,
}

impl ExecutionCommand {
    /// Returns the declared executable path.
    #[must_use]
    pub fn executable(&self) -> &AuthorityPath {
        &self.executable
    }

    /// Returns the exact argument list.
    #[must_use]
    pub fn arguments(&self) -> &[CommandArgument] {
        &self.arguments
    }

    /// Returns the declared working directory.
    #[must_use]
    pub fn working_directory(&self) -> &AuthorityPath {
        &self.working_directory
    }
}

/// Contains one validated version 1 execution plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionPlan {
    id: PlanId,
    command: ExecutionCommand,
    authority: AuthorityPlan,
}

/// Contains one validated service-session plan before native implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceExecutionPlan {
    base: ExecutionPlan,
    service_session: AuthenticatedServiceSession,
}

impl ServiceExecutionPlan {
    /// Returns the child execution plan with direct network authority denied.
    #[must_use]
    pub const fn base(&self) -> &ExecutionPlan {
        &self.base
    }

    /// Returns the separate connector-owned service-session authority.
    #[must_use]
    pub const fn service_session(&self) -> &AuthenticatedServiceSession {
        &self.service_session
    }
}

enum ParsedExecutionPlan {
    Deny(ExecutionPlan),
    Service(ServiceExecutionPlan),
}

impl ExecutionPlan {
    /// Returns the plan identifier.
    #[must_use]
    pub fn id(&self) -> &PlanId {
        &self.id
    }

    /// Returns the exact declared command.
    #[must_use]
    pub fn command(&self) -> &ExecutionCommand {
        &self.command
    }

    /// Returns the validated authority plan.
    #[must_use]
    pub fn authority(&self) -> &AuthorityPlan {
        &self.authority
    }
}

/// Identifies invalid execution-plan input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanError {
    /// The input is not valid TOML.
    MalformedToml,
    /// A closed table contains an unknown field.
    UnknownField,
    /// A required field is absent or has the wrong type.
    InvalidSchema,
    /// The plan schema version is unsupported.
    UnsupportedVersion,
    /// A valid version 1 plan cannot be used for a new execution.
    ExecutionObsolete,
    /// Version 2 bytes are not one admitted deterministic-CBOR item.
    MalformedCbor,
    /// The plan identifier is invalid.
    InvalidPlanId,
    /// A command argument contains a null byte.
    ArgumentContainsNull,
    /// The initial release does not support the requested network mode.
    UnsupportedNetwork,
    /// One authenticated-service-session field is invalid.
    NetworkAuthority(NetworkAuthorityError),
    /// A service-session support path is not canonical and absolute.
    NetworkSupportPathInvalid,
    /// The credential source names an environment variable outside authority.
    CredentialEnvironmentMissing,
    /// The command executable has no exact execute-authority entry.
    ExecutableAuthorityMissing,
    /// The plan does not contain exactly one executable authority entry.
    ExecutableAuthorityCount,
    /// The plan does not contain exactly one output-root authority entry.
    OutputRootAuthorityCount,
    /// A runtime-library path is not a canonical absolute path.
    RuntimeLibraryPathInvalid,
    /// One authority value is invalid.
    Authority(AuthorityError),
}

impl PlanError {
    /// Returns the stable machine code for this error.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::MalformedToml => "plan.schema.malformed-toml",
            Self::UnknownField => "plan.schema.unknown-field",
            Self::InvalidSchema => "plan.schema.invalid",
            Self::UnsupportedVersion => "plan.schema.unsupported-version",
            Self::ExecutionObsolete => "plan.schema.execution-obsolete",
            Self::MalformedCbor => "plan.schema.malformed-cbor",
            Self::InvalidPlanId => "plan.id.invalid",
            Self::ArgumentContainsNull => "plan.command.argument.null",
            Self::UnsupportedNetwork => "plan.authority.network.unsupported",
            Self::NetworkAuthority(error) => error.code(),
            Self::NetworkSupportPathInvalid => "plan.authority.network.path.external-invalid",
            Self::CredentialEnvironmentMissing => {
                "plan.authority.network.credential-source.environment-missing"
            }
            Self::ExecutableAuthorityMissing => "plan.authority.executable.missing",
            Self::ExecutableAuthorityCount => "plan.authority.executable.count",
            Self::OutputRootAuthorityCount => "plan.authority.output-root.count",
            Self::RuntimeLibraryPathInvalid => "plan.authority.runtime-library.external-invalid",
            Self::Authority(error) => match error {
                AuthorityError::ZeroProcessLimit => "plan.limits.processes.zero",
                AuthorityError::ZeroWallTimeLimit => "plan.limits.wall_time.zero",
                _ => error.code(),
            },
        }
    }
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PlanError {}

impl From<AuthorityError> for PlanError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}

impl From<NetworkAuthorityError> for PlanError {
    fn from(error: NetworkAuthorityError) -> Self {
        if error == NetworkAuthorityError::InvalidSupportPath {
            Self::NetworkSupportPathInvalid
        } else {
            Self::NetworkAuthority(error)
        }
    }
}

/// Parses strict version 1 TOML into validated domain types.
pub fn parse_execution_plan(input: &str) -> Result<ExecutionPlan, PlanError> {
    let value = toml::from_str::<Value>(input).map_err(|_| PlanError::MalformedToml)?;
    validate_closed_tables(&value)?;
    let wire: WirePlan = value.try_into().map_err(|_| PlanError::InvalidSchema)?;
    if wire.schema != PLAN_SCHEMA {
        return Err(PlanError::UnsupportedVersion);
    }
    if wire.authority.network != "deny" {
        return Err(PlanError::UnsupportedNetwork);
    }
    if wire.authority.execute.len() != 1 {
        return Err(PlanError::ExecutableAuthorityCount);
    }
    if wire.authority.write.len() != 1 {
        return Err(PlanError::OutputRootAuthorityCount);
    }

    let id = PlanId::new(wire.id)?;
    let executable = AuthorityPath::new(wire.command.executable)?;
    let working_directory = AuthorityPath::new(wire.command.working_directory)?;
    let arguments = wire
        .command
        .arguments
        .into_iter()
        .map(CommandArgument::new)
        .collect::<Result<Vec<_>, _>>()?;

    let mut paths = Vec::new();
    append_paths(
        &mut paths,
        wire.authority.read,
        FileAccess::Read,
        PathRole::ProjectInput,
    )?;
    append_runtime_library_paths(&mut paths, wire.authority.runtime_read)?;
    append_paths(
        &mut paths,
        wire.authority.write,
        FileAccess::Write,
        PathRole::OutputRoot,
    )?;
    append_paths(
        &mut paths,
        wire.authority.execute,
        FileAccess::Execute,
        PathRole::RuntimeExecutable,
    )?;
    if !paths
        .iter()
        .any(|entry| entry.access() == FileAccess::Execute && entry.path() == &executable)
    {
        return Err(PlanError::ExecutableAuthorityMissing);
    }

    let environment = wire
        .authority
        .environment
        .into_iter()
        .map(EnvironmentName::new)
        .collect::<Result<Vec<_>, _>>()?;
    let limits = ResourceLimits::new(
        ProcessLimit::new(wire.limits.processes)?,
        WallTimeLimit::from_milliseconds(wire.limits.wall_time_ms)?,
        OutputByteLimit::new(wire.limits.stdout_bytes),
        OutputByteLimit::new(wire.limits.stderr_bytes),
    );

    Ok(ExecutionPlan {
        id,
        command: ExecutionCommand {
            executable,
            arguments,
            working_directory,
        },
        authority: AuthorityPlan::new(paths, environment, limits),
    })
}

/// Parses the only plan format accepted for a new version 2 execution.
///
/// A valid legacy TOML plan receives its migration-specific diagnostic. Every
/// accepted v2 value is one complete deterministic-CBOR item with closed
/// text-key maps; JSON and TOML projections are never accepted as v2 wire.
pub fn parse_execution_plan_for_execution(input: &[u8]) -> Result<ExecutionPlan, PlanError> {
    if let Ok(text) = core::str::from_utf8(input)
        && parse_execution_plan(text).is_ok()
    {
        return Err(PlanError::ExecutionObsolete);
    }
    match parse_execution_plan_contract_v2(input)? {
        ParsedExecutionPlan::Deny(plan) => Ok(plan),
        ParsedExecutionPlan::Service(_) => Err(PlanError::UnsupportedNetwork),
    }
}

/// Parses the proposed service-session plan without authorizing execution.
///
/// The production execution parser continues to reject this profile until the
/// native connector, launcher, receipt, and verifier waves are admitted.
pub fn parse_service_execution_plan(input: &[u8]) -> Result<ServiceExecutionPlan, PlanError> {
    match parse_execution_plan_contract_v2(input)? {
        ParsedExecutionPlan::Service(plan) => Ok(plan),
        ParsedExecutionPlan::Deny(_) => Err(PlanError::UnsupportedNetwork),
    }
}

fn parse_execution_plan_contract_v2(input: &[u8]) -> Result<ParsedExecutionPlan, PlanError> {
    let mut root = cbor_map(wire_v2::decode(input).map_err(|_| PlanError::MalformedCbor)?)?;
    let schema = cbor_text(take(&mut root, "schema")?)?;
    if schema != PLAN_SCHEMA_V2 {
        return Err(PlanError::UnsupportedVersion);
    }
    let id = PlanId::new(cbor_text(take(&mut root, "id")?)?)?;
    let mut command = cbor_map(take(&mut root, "command")?)?;
    let executable = AuthorityPath::new(cbor_text(take(&mut command, "executable")?)?)?;
    let working_directory =
        AuthorityPath::new(cbor_text(take(&mut command, "working_directory")?)?)?;
    let arguments = cbor_text_array(take(&mut command, "arguments")?)?
        .into_iter()
        .map(CommandArgument::new)
        .collect::<Result<Vec<_>, _>>()?;
    require_empty(command)?;

    let mut authority = cbor_map(take(&mut root, "authority")?)?;
    let network_value = take(&mut authority, "network")?;
    let environment = cbor_text_array(take(&mut authority, "environment")?)?
        .into_iter()
        .map(EnvironmentName::new)
        .collect::<Result<Vec<_>, _>>()?;
    let read = cbor_text_array(take(&mut authority, "read")?)?;
    let runtime_read = cbor_text_array(take(&mut authority, "runtime_read")?)?;
    let write = cbor_text_array(take(&mut authority, "write")?)?;
    let execute = cbor_text_array(take(&mut authority, "execute")?)?;
    require_empty(authority)?;
    if execute.len() != 1 {
        return Err(PlanError::ExecutableAuthorityCount);
    }
    if write.len() != 1 {
        return Err(PlanError::OutputRootAuthorityCount);
    }
    let network = parse_network_authority(network_value, &environment)?;

    let mut limits = cbor_map(take(&mut root, "limits")?)?;
    let resource_limits = ResourceLimits::new_v2(
        ProcessLimit::new(cbor_u32(take(&mut limits, "processes")?)?)?,
        WallTimeLimit::from_milliseconds(cbor_u64(take(&mut limits, "wall_time_ms")?)?)?,
        OutputByteLimit::new(cbor_u64(take(&mut limits, "stdout_bytes")?)?),
        OutputByteLimit::new(cbor_u64(take(&mut limits, "stderr_bytes")?)?),
        MemoryByteLimit::new(cbor_u64(take(&mut limits, "memory_bytes")?)?)?,
        SwapByteLimit::new(cbor_u64(take(&mut limits, "swap_bytes")?)?)?,
    );
    require_empty(limits)?;
    require_empty(root)?;

    let mut paths = Vec::new();
    append_paths(&mut paths, read, FileAccess::Read, PathRole::ProjectInput)?;
    append_runtime_library_paths(&mut paths, runtime_read)?;
    append_paths(&mut paths, write, FileAccess::Write, PathRole::OutputRoot)?;
    append_paths(
        &mut paths,
        execute,
        FileAccess::Execute,
        PathRole::RuntimeExecutable,
    )?;
    if !paths
        .iter()
        .any(|entry| entry.access() == FileAccess::Execute && entry.path() == &executable)
    {
        return Err(PlanError::ExecutableAuthorityMissing);
    }

    let base = ExecutionPlan {
        id,
        command: ExecutionCommand {
            executable,
            arguments,
            working_directory,
        },
        authority: AuthorityPlan::new(paths, environment, resource_limits),
    };
    Ok(match network {
        ParsedNetworkAuthority::Deny => ParsedExecutionPlan::Deny(base),
        ParsedNetworkAuthority::Service(service_session) => {
            ParsedExecutionPlan::Service(ServiceExecutionPlan {
                base,
                service_session,
            })
        }
    })
}

type CborMap = Vec<(String, CborValue)>;

fn cbor_map(value: CborValue) -> Result<CborMap, PlanError> {
    match value {
        CborValue::Map(value) => Ok(value),
        _ => Err(PlanError::InvalidSchema),
    }
}

fn take(map: &mut CborMap, key: &str) -> Result<CborValue, PlanError> {
    let index = map
        .iter()
        .position(|(candidate, _)| candidate == key)
        .ok_or(PlanError::InvalidSchema)?;
    Ok(map.remove(index).1)
}

fn require_empty(map: CborMap) -> Result<(), PlanError> {
    if map.is_empty() {
        Ok(())
    } else {
        Err(PlanError::UnknownField)
    }
}

fn cbor_text(value: CborValue) -> Result<String, PlanError> {
    match value {
        CborValue::Text(value) => Ok(value),
        _ => Err(PlanError::InvalidSchema),
    }
}

fn cbor_text_array(value: CborValue) -> Result<Vec<String>, PlanError> {
    match value {
        CborValue::Array(values) => values.into_iter().map(cbor_text).collect(),
        _ => Err(PlanError::InvalidSchema),
    }
}

fn cbor_u64(value: CborValue) -> Result<u64, PlanError> {
    match value {
        CborValue::Unsigned(value) => Ok(value),
        _ => Err(PlanError::InvalidSchema),
    }
}

fn cbor_u32(value: CborValue) -> Result<u32, PlanError> {
    u32::try_from(cbor_u64(value)?).map_err(|_| PlanError::InvalidSchema)
}

fn cbor_u16(value: CborValue) -> Result<u16, PlanError> {
    u16::try_from(cbor_u64(value)?).map_err(|_| PlanError::InvalidSchema)
}

fn cbor_bytes(value: CborValue) -> Result<Vec<u8>, PlanError> {
    match value {
        CborValue::Bytes(value) => Ok(value),
        _ => Err(PlanError::InvalidSchema),
    }
}

fn parse_network_authority(
    value: CborValue,
    environment: &[EnvironmentName],
) -> Result<ParsedNetworkAuthority, PlanError> {
    if let CborValue::Text(mode) = value {
        return if mode == "deny" {
            Ok(ParsedNetworkAuthority::Deny)
        } else {
            Err(PlanError::UnsupportedNetwork)
        };
    }
    let mut network = cbor_map(value)?;
    if cbor_text(take(&mut network, "mode")?)? != "authenticated-service-session" {
        return Err(PlanError::UnsupportedNetwork);
    }

    let mut service = cbor_map(take(&mut network, "service")?)?;
    let service_name = ServiceName::new(cbor_text(take(&mut service, "name")?)?)?;
    let service_port = TcpPort::new(cbor_u16(take(&mut service, "port")?)?)?;
    require_empty(service)?;

    let mut resolver = cbor_map(take(&mut network, "resolver")?)?;
    let mut resolver_address = cbor_map(take(&mut resolver, "address")?)?;
    let family = cbor_text(take(&mut resolver_address, "family")?)?;
    let address_bytes = cbor_bytes(take(&mut resolver_address, "bytes")?)?;
    require_empty(resolver_address)?;
    let address = match family.as_str() {
        "ipv4" => ResolverAddress::Ipv4(
            address_bytes
                .try_into()
                .map_err(|_| PlanError::InvalidSchema)?,
        ),
        "ipv6" => ResolverAddress::Ipv6(
            address_bytes
                .try_into()
                .map_err(|_| PlanError::InvalidSchema)?,
        ),
        _ => return Err(PlanError::InvalidSchema),
    };
    let resolver_port = TcpPort::new(cbor_u16(take(&mut resolver, "port")?)?)?;
    let resolver_configuration =
        NetworkSupportPath::new(cbor_text(take(&mut resolver, "configuration")?)?)?;
    let maximum_cname_depth = cbor_u16(take(&mut resolver, "maximum_cname_depth")?)?;
    let maximum_answer_count = cbor_u16(take(&mut resolver, "maximum_answer_count")?)?;
    let maximum_response_bytes = cbor_u64(take(&mut resolver, "maximum_response_bytes")?)?;
    let resolution_deadline_ms = cbor_u64(take(&mut resolver, "resolution_deadline_ms")?)?;
    let attempt_deadline_ms = cbor_u64(take(&mut resolver, "attempt_deadline_ms")?)?;
    let address_order = match cbor_text(take(&mut resolver, "address_order")?)?.as_str() {
        "ipv4-then-ipv6-lexicographic" => AddressOrder::Ipv4ThenIpv6Lexicographic,
        _ => return Err(PlanError::InvalidSchema),
    };
    require_empty(resolver)?;
    let resolution = ResolutionPolicy::new(
        ResolverEndpoint::new(address, resolver_port),
        resolver_configuration,
        maximum_cname_depth,
        maximum_answer_count,
        maximum_response_bytes,
        resolution_deadline_ms,
        attempt_deadline_ms,
        address_order,
    )?;

    let mut tls = cbor_map(take(&mut network, "tls")?)?;
    let trust_root_set = NetworkSupportPath::new(cbor_text(take(&mut tls, "trust_root_set")?)?)?;
    let minimum_version = match cbor_text(take(&mut tls, "minimum_version")?)?.as_str() {
        "tls-1.2" => MinimumTlsVersion::Tls12,
        "tls-1.3" => MinimumTlsVersion::Tls13,
        _ => return Err(PlanError::InvalidSchema),
    };
    let service_name_verification =
        match cbor_text(take(&mut tls, "service_name_verification")?)?.as_str() {
            "dns-san-exact" => ServiceNameVerification::DnsSanExact,
            _ => return Err(PlanError::InvalidSchema),
        };
    let revocation = match cbor_text(take(&mut tls, "revocation")?)?.as_str() {
        "not-checked-recorded-assumption" => RevocationPolicy::NotCheckedRecordedAssumption,
        _ => return Err(PlanError::InvalidSchema),
    };
    if cbor_text(take(&mut tls, "session_resumption")?)? != "deny"
        || cbor_text(take(&mut tls, "early_data")?)? != "deny"
    {
        return Err(PlanError::InvalidSchema);
    }
    require_empty(tls)?;
    let tls = TlsPolicy::new(
        trust_root_set,
        minimum_version,
        service_name_verification,
        revocation,
    );

    let mut session_limits = cbor_map(take(&mut network, "limits")?)?;
    let limits = ServiceSessionLimits::new(
        cbor_u64(take(&mut session_limits, "setup_time_ms")?)?,
        cbor_u64(take(&mut session_limits, "session_time_ms")?)?,
        cbor_u64(take(&mut session_limits, "child_to_service_bytes")?)?,
        cbor_u64(take(&mut session_limits, "service_to_child_bytes")?)?,
        cbor_u16(take(&mut session_limits, "dns_messages")?)?,
        cbor_u16(take(&mut session_limits, "endpoint_attempts")?)?,
        cbor_u64(take(&mut session_limits, "tls_handshake_bytes")?)?,
        maximum_answer_count,
    )?;
    require_empty(session_limits)?;

    let connector_executable =
        NetworkSupportPath::new(cbor_text(take(&mut network, "connector_executable")?)?)?;
    let connector_runtime_read = cbor_text_array(take(&mut network, "connector_runtime_read")?)?
        .into_iter()
        .map(NetworkSupportPath::new)
        .collect::<Result<Vec<_>, _>>()?;

    let mut local_channel = cbor_map(take(&mut network, "local_channel")?)?;
    let protocol = match cbor_text(take(&mut local_channel, "protocol")?)?.as_str() {
        "unix-stream-v1" => LocalChannelProtocol::UnixStreamV1,
        _ => return Err(PlanError::InvalidSchema),
    };
    let child_descriptor =
        ChildChannelDescriptor::new(cbor_u16(take(&mut local_channel, "child_descriptor")?)?)?;
    require_empty(local_channel)?;

    let credential_source = take_optional(&mut network, "credential_source")
        .map(|value| parse_credential_source(value, &service_name, environment))
        .transpose()?;
    require_empty(network)?;

    Ok(ParsedNetworkAuthority::Service(
        AuthenticatedServiceSession::new(
            service_name,
            service_port,
            resolution,
            tls,
            limits,
            connector_executable,
            connector_runtime_read,
            protocol,
            child_descriptor,
            credential_source,
        )?,
    ))
}

enum ParsedNetworkAuthority {
    Deny,
    Service(AuthenticatedServiceSession),
}

fn parse_credential_source(
    value: CborValue,
    service: &ServiceName,
    environment: &[EnvironmentName],
) -> Result<CredentialSource, PlanError> {
    let mut source = cbor_map(value)?;
    let id = CredentialSourceId::new(cbor_text(take(&mut source, "id")?)?)?;
    let bound_service = ServiceName::new(cbor_text(take(&mut source, "service")?)?)?;
    let environment_name = EnvironmentName::new(cbor_text(take(&mut source, "environment")?)?)?;
    require_empty(source)?;
    if !environment.contains(&environment_name) {
        return Err(PlanError::CredentialEnvironmentMissing);
    }
    CredentialSource::new(id, bound_service, environment_name, service).map_err(Into::into)
}

fn take_optional(map: &mut CborMap, key: &str) -> Option<CborValue> {
    if let Some(index) = map.iter().position(|(candidate, _)| candidate == key) {
        Some(map.remove(index).1)
    } else {
        None
    }
}

fn append_paths(
    output: &mut Vec<PathAuthority>,
    paths: Vec<String>,
    access: FileAccess,
    role: PathRole,
) -> Result<(), PlanError> {
    for path in paths {
        output.push(PathAuthority::new(AuthorityPath::new(path)?, access, role));
    }
    Ok(())
}

fn append_runtime_library_paths(
    output: &mut Vec<PathAuthority>,
    paths: Vec<String>,
) -> Result<(), PlanError> {
    for path in paths {
        let path = AuthorityPath::new(path)?;
        let filesystem_path = Path::new(path.as_str());
        if !filesystem_path.is_absolute()
            || filesystem_path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(PlanError::RuntimeLibraryPathInvalid);
        }
        output.push(PathAuthority::new(
            path,
            FileAccess::Read,
            PathRole::RuntimeLibrary,
        ));
    }
    Ok(())
}

fn validate_closed_tables(value: &Value) -> Result<(), PlanError> {
    let root = value.as_table().ok_or(PlanError::InvalidSchema)?;
    reject_unknown(root, &["schema", "id", "command", "authority", "limits"])?;
    reject_unknown(
        table(root, "command")?,
        &["executable", "arguments", "working_directory"],
    )?;
    reject_unknown(
        table(root, "authority")?,
        &[
            "network",
            "environment",
            "read",
            "runtime_read",
            "write",
            "execute",
        ],
    )?;
    reject_unknown(
        table(root, "limits")?,
        &["wall_time_ms", "stdout_bytes", "stderr_bytes", "processes"],
    )
}

fn table<'a>(parent: &'a Table, key: &str) -> Result<&'a Table, PlanError> {
    parent
        .get(key)
        .and_then(Value::as_table)
        .ok_or(PlanError::InvalidSchema)
}

fn reject_unknown(table: &Table, allowed: &[&str]) -> Result<(), PlanError> {
    if table.keys().any(|key| !allowed.contains(&key.as_str())) {
        Err(PlanError::UnknownField)
    } else {
        Ok(())
    }
}

#[derive(Deserialize)]
struct WirePlan {
    schema: String,
    id: String,
    command: WireCommand,
    authority: WireAuthority,
    limits: WireLimits,
}

#[derive(Deserialize)]
struct WireCommand {
    executable: String,
    arguments: Vec<String>,
    working_directory: String,
}

#[derive(Deserialize)]
struct WireAuthority {
    network: String,
    environment: Vec<String>,
    read: Vec<String>,
    runtime_read: Vec<String>,
    write: Vec<String>,
    execute: Vec<String>,
}

#[derive(Deserialize)]
struct WireLimits {
    wall_time_ms: u64,
    stdout_bytes: u64,
    stderr_bytes: u64,
    processes: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryByteLimit, SwapByteLimit, normalize_authority};

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = core::str::from_utf8(pair).expect("fixture is ASCII");
                u8::from_str_radix(text, 16).expect("fixture is hexadecimal")
            })
            .collect()
    }

    fn value_map<const N: usize>(entries: [(&str, CborValue); N]) -> CborValue {
        CborValue::Map(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    fn service_plan(
        service_name: &str,
        credential_service: &str,
        include_environment: bool,
        address_bytes: Vec<u8>,
        resolution_deadline_ms: u64,
        setup_time_ms: u64,
        connector_runtime_read: &str,
    ) -> Vec<u8> {
        let environment = if include_environment {
            vec![CborValue::Text("API_KEY".to_owned())]
        } else {
            Vec::new()
        };
        let network = value_map([
            (
                "mode",
                CborValue::Text("authenticated-service-session".to_owned()),
            ),
            (
                "service",
                value_map([
                    ("name", CborValue::Text(service_name.to_owned())),
                    ("port", CborValue::Unsigned(443)),
                ]),
            ),
            (
                "resolver",
                value_map([
                    (
                        "address",
                        value_map([
                            ("family", CborValue::Text("ipv4".to_owned())),
                            ("bytes", CborValue::Bytes(address_bytes)),
                        ]),
                    ),
                    ("port", CborValue::Unsigned(53)),
                    (
                        "configuration",
                        CborValue::Text("/etc/proofbound/resolver.conf".to_owned()),
                    ),
                    ("maximum_cname_depth", CborValue::Unsigned(8)),
                    ("maximum_answer_count", CborValue::Unsigned(16)),
                    ("maximum_response_bytes", CborValue::Unsigned(65_536)),
                    (
                        "resolution_deadline_ms",
                        CborValue::Unsigned(resolution_deadline_ms),
                    ),
                    ("attempt_deadline_ms", CborValue::Unsigned(1_000)),
                    (
                        "address_order",
                        CborValue::Text("ipv4-then-ipv6-lexicographic".to_owned()),
                    ),
                ]),
            ),
            (
                "tls",
                value_map([
                    (
                        "trust_root_set",
                        CborValue::Text("/etc/ssl/certs/ca-certificates.crt".to_owned()),
                    ),
                    ("minimum_version", CborValue::Text("tls-1.3".to_owned())),
                    (
                        "service_name_verification",
                        CborValue::Text("dns-san-exact".to_owned()),
                    ),
                    (
                        "revocation",
                        CborValue::Text("not-checked-recorded-assumption".to_owned()),
                    ),
                    ("session_resumption", CborValue::Text("deny".to_owned())),
                    ("early_data", CborValue::Text("deny".to_owned())),
                ]),
            ),
            (
                "limits",
                value_map([
                    ("setup_time_ms", CborValue::Unsigned(setup_time_ms)),
                    ("session_time_ms", CborValue::Unsigned(30_000)),
                    ("child_to_service_bytes", CborValue::Unsigned(1_048_576)),
                    ("service_to_child_bytes", CborValue::Unsigned(1_048_576)),
                    ("dns_messages", CborValue::Unsigned(4)),
                    ("endpoint_attempts", CborValue::Unsigned(4)),
                    ("tls_handshake_bytes", CborValue::Unsigned(262_144)),
                ]),
            ),
            (
                "connector_executable",
                CborValue::Text("/usr/libexec/proofbound-connector".to_owned()),
            ),
            (
                "connector_runtime_read",
                CborValue::Array(vec![CborValue::Text(connector_runtime_read.to_owned())]),
            ),
            (
                "local_channel",
                value_map([
                    ("protocol", CborValue::Text("unix-stream-v1".to_owned())),
                    ("child_descriptor", CborValue::Unsigned(9)),
                ]),
            ),
            (
                "credential_source",
                value_map([
                    ("id", CborValue::Text("anthropic-test".to_owned())),
                    ("service", CborValue::Text(credential_service.to_owned())),
                    ("environment", CborValue::Text("API_KEY".to_owned())),
                ]),
            ),
        ]);
        let plan = value_map([
            ("schema", CborValue::Text(PLAN_SCHEMA_V2.to_owned())),
            ("id", CborValue::Text("service-session".to_owned())),
            (
                "command",
                value_map([
                    ("executable", CborValue::Text("bin/client".to_owned())),
                    ("arguments", CborValue::Array(Vec::new())),
                    ("working_directory", CborValue::Text(".".to_owned())),
                ]),
            ),
            (
                "authority",
                value_map([
                    ("network", network),
                    ("environment", CborValue::Array(environment)),
                    ("read", CborValue::Array(Vec::new())),
                    ("runtime_read", CborValue::Array(Vec::new())),
                    (
                        "write",
                        CborValue::Array(vec![CborValue::Text("out".to_owned())]),
                    ),
                    (
                        "execute",
                        CborValue::Array(vec![CborValue::Text("bin/client".to_owned())]),
                    ),
                ]),
            ),
            (
                "limits",
                value_map([
                    ("processes", CborValue::Unsigned(2)),
                    ("wall_time_ms", CborValue::Unsigned(30_000)),
                    ("stdout_bytes", CborValue::Unsigned(4_096)),
                    ("stderr_bytes", CborValue::Unsigned(4_096)),
                    ("memory_bytes", CborValue::Unsigned(65_536)),
                    ("swap_bytes", CborValue::Unsigned(0)),
                ]),
            ),
        ]);
        wire_v2::encode(&plan).expect("fixture encodes")
    }

    #[test]
    fn parses_the_registered_version_two_cbor_plan() {
        let encoded = decode_hex(include_str!(
            "../../../schemas/vectors/v2/execution-plan.cbor.hex"
        ));
        let plan = parse_execution_plan_for_execution(&encoded).expect("golden plan is valid");

        assert_eq!(plan.id().as_str(), "golden-v2");
        assert_eq!(plan.command().executable().as_str(), "bin/hello");
        assert_eq!(
            plan.authority().limits().memory().map(MemoryByteLimit::get),
            Some(65_536)
        );
        assert_eq!(
            plan.authority().limits().swap().map(SwapByteLimit::get),
            Some(0)
        );
    }

    #[test]
    fn execution_rejects_legacy_plan_with_the_migration_code() {
        let legacy = r#"
schema = "proofbound-runtime-plan/1"
id = "legacy"
[command]
executable = "/bin/tool"
arguments = []
working_directory = "."
[authority]
network = "deny"
environment = []
read = []
runtime_read = []
write = ["out"]
execute = ["/bin/tool"]
[limits]
wall_time_ms = 1
stdout_bytes = 0
stderr_bytes = 0
processes = 1
"#;
        let error = parse_execution_plan_for_execution(legacy.as_bytes())
            .expect_err("version 1 execution is obsolete");
        assert_eq!(error, PlanError::ExecutionObsolete);
        assert_eq!(error.code(), "plan.schema.execution-obsolete");
    }

    #[test]
    fn parses_the_closed_service_session_without_authorizing_execution() {
        let encoded = decode_hex(include_str!(
            "../../../schemas/vectors/v2/execution-plan-service-session.cbor.hex"
        ));
        let plan =
            parse_service_execution_plan(&encoded).expect("service-session fixture is valid");
        let session = plan.service_session();
        assert_eq!(session.service().as_str(), "api.anthropic.com");
        assert_eq!(session.port().get(), 443);
        assert_eq!(session.child_descriptor().get(), 9);
        let normalized = normalize_authority(plan.base().authority().clone())
            .expect("child authority normalizes");
        assert_eq!(normalized.network(), crate::NetworkMode::Deny);
        assert_eq!(
            parse_execution_plan_for_execution(&encoded),
            Err(PlanError::UnsupportedNetwork)
        );
    }

    #[test]
    fn rejects_service_name_and_credential_environment_substitution() {
        assert_eq!(
            parse_service_execution_plan(&service_plan(
                "API.anthropic.com",
                "API.anthropic.com",
                true,
                vec![1, 1, 1, 1],
                5_000,
                10_000,
                "/usr/lib",
            )),
            Err(PlanError::NetworkAuthority(
                NetworkAuthorityError::InvalidServiceName
            ))
        );
        assert_eq!(
            parse_service_execution_plan(&service_plan(
                "api.anthropic.com",
                "api.anthropic.com",
                false,
                vec![1, 1, 1, 1],
                5_000,
                10_000,
                "/usr/lib",
            )),
            Err(PlanError::CredentialEnvironmentMissing)
        );
        assert_eq!(
            parse_service_execution_plan(&service_plan(
                "api.anthropic.com",
                "api.example.com",
                true,
                vec![1, 1, 1, 1],
                5_000,
                10_000,
                "/usr/lib",
            )),
            Err(PlanError::NetworkAuthority(
                NetworkAuthorityError::CredentialServiceMismatch
            ))
        );
        assert_eq!(
            parse_service_execution_plan(&service_plan(
                "api.anthropic.com",
                "api.anthropic.com",
                true,
                vec![1, 1, 1],
                5_000,
                10_000,
                "/usr/lib",
            )),
            Err(PlanError::InvalidSchema)
        );
        assert_eq!(
            parse_service_execution_plan(&service_plan(
                "api.anthropic.com",
                "api.anthropic.com",
                true,
                vec![1, 1, 1, 1],
                5_000,
                4_999,
                "/usr/lib",
            )),
            Err(PlanError::NetworkAuthority(
                NetworkAuthorityError::ResolutionDeadlineExceedsSetup
            ))
        );
        assert_eq!(
            parse_service_execution_plan(&service_plan(
                "api.anthropic.com",
                "api.anthropic.com",
                true,
                vec![1, 1, 1, 1],
                5_000,
                10_000,
                "/usr//lib",
            )),
            Err(PlanError::NetworkSupportPathInvalid)
        );
        assert_eq!(
            parse_service_execution_plan(&service_plan(
                "api.anthropic.com",
                "api.anthropic.com",
                true,
                vec![1, 1, 1, 1],
                5_000,
                10_000,
                "/usr/./lib",
            )),
            Err(PlanError::NetworkSupportPathInvalid)
        );
    }

    #[test]
    fn rejects_missing_executable_authority() {
        let plan = r#"
schema = "proofbound-runtime-plan/1"
id = "test.missing-execute"
[command]
executable = "/bin/tool"
arguments = []
working_directory = "."
[authority]
network = "deny"
environment = []
read = []
runtime_read = []
write = ["out"]
execute = ["/bin/other"]
[limits]
wall_time_ms = 1
stdout_bytes = 0
stderr_bytes = 0
processes = 1
"#;
        assert_eq!(
            parse_execution_plan(plan),
            Err(PlanError::ExecutableAuthorityMissing)
        );
    }
}
