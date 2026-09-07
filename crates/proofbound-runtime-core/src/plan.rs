use core::fmt;
use std::path::{Component, Path};

use serde::Deserialize;
use toml::{Table, Value};

use crate::{
    AuthorityError, AuthorityPath, AuthorityPlan, EnvironmentName, FileAccess, OutputByteLimit,
    PathAuthority, PathRole, ProcessLimit, ResourceLimits, WallTimeLimit,
};

const PLAN_SCHEMA: &str = "proofbound-runtime-plan/1";

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
    /// The plan identifier is invalid.
    InvalidPlanId,
    /// A command argument contains a null byte.
    ArgumentContainsNull,
    /// The initial release does not support the requested network mode.
    UnsupportedNetwork,
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
            Self::InvalidPlanId => "plan.id.invalid",
            Self::ArgumentContainsNull => "plan.command.argument.null",
            Self::UnsupportedNetwork => "plan.authority.network.unsupported",
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
