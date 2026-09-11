use core::fmt;

use crate::wire_v2::{self, Value};
use crate::{
    EnvironmentName, FileAccess, NormalizedAuthority, PathAuthority, PathRole, ResourceLimits,
};

const POLICY_MODEL_VERSION_V1: &str = "proofbound-runtime-linux-policy/1";
const POLICY_MODEL_VERSION_V2: &str = "proofbound-runtime-linux-policy/2";

/// Identifies a failure to encode the closed version 2 policy wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyEncodingError {
    /// Legacy policies do not have a version 2 CBOR representation.
    UnsupportedVersion,
    /// The deterministic encoder rejected an internally constructed value.
    CanonicalEncoding,
}

impl fmt::Display for PolicyEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedVersion => "policy.schema.unsupported-version",
            Self::CanonicalEncoding => "policy.encoding.canonical-failed",
        })
    }
}

impl std::error::Error for PolicyEncodingError {}

/// Contains the complete Landlock input for a supported policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemPolicy {
    rules: Vec<PathAuthority>,
}

impl FilesystemPolicy {
    /// Returns the exact requested filesystem rules.
    #[must_use]
    pub fn rules(&self) -> &[PathAuthority] {
        &self.rules
    }
}

/// Selects the closed seccomp profile for version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeccompPolicy {
    /// Denies every network syscall in the registered version 1 set.
    DenyNetworkV1,
}

/// Contains the registered cgroup and supervisor limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CgroupPolicy {
    limits: ResourceLimits,
}

impl CgroupPolicy {
    /// Returns the exact resource limits from the normalized plan.
    #[must_use]
    pub const fn limits(self) -> ResourceLimits {
        self.limits
    }
}

/// Requires privilege removal before boundary installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoNewPrivileges {
    /// Requires `PR_SET_NO_NEW_PRIVS` before child execution.
    Required,
}

/// Contains the complete platform-neutral meaning of one Linux policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledPolicy {
    filesystem: FilesystemPolicy,
    environment: Vec<EnvironmentName>,
    network: SeccompPolicy,
    cgroup: CgroupPolicy,
    no_new_privileges: NoNewPrivileges,
}

impl CompiledPolicy {
    /// Returns the exact Landlock input.
    #[must_use]
    pub const fn filesystem(&self) -> &FilesystemPolicy {
        &self.filesystem
    }

    /// Returns the exact environment-name allow-list.
    #[must_use]
    pub fn environment(&self) -> &[EnvironmentName] {
        &self.environment
    }

    /// Returns the closed seccomp profile.
    #[must_use]
    pub const fn network(&self) -> SeccompPolicy {
        self.network
    }

    /// Returns the registered cgroup and supervisor limits.
    #[must_use]
    pub const fn cgroup(&self) -> CgroupPolicy {
        self.cgroup
    }

    /// Returns the privilege-removal requirement.
    #[must_use]
    pub const fn no_new_privileges(&self) -> NoNewPrivileges {
        self.no_new_privileges
    }

    /// Returns the policy model selected by the complete resource profile.
    #[must_use]
    pub fn model_version(&self) -> &'static str {
        if self.cgroup.limits.is_version_two() {
            POLICY_MODEL_VERSION_V2
        } else {
            POLICY_MODEL_VERSION_V1
        }
    }

    /// Encodes one complete version 2 policy as deterministic CBOR.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PolicyEncodingError> {
        if !self.cgroup.limits.is_version_two() {
            return Err(PolicyEncodingError::UnsupportedVersion);
        }
        wire_v2::encode(&self.wire_value()).map_err(|_| PolicyEncodingError::CanonicalEncoding)
    }

    fn wire_value(&self) -> Value {
        let limits = self.cgroup.limits;
        map([
            ("schema", text(POLICY_MODEL_VERSION_V2)),
            (
                "cgroup",
                map([
                    (
                        "pids.max",
                        Value::Unsigned(u64::from(limits.processes().get())),
                    ),
                    (
                        "memory.max",
                        Value::Unsigned(limits.memory().expect("v2 profile").get()),
                    ),
                    ("memory.oom.group", Value::Unsigned(1)),
                    (
                        "memory.swap.max",
                        Value::Unsigned(limits.swap().expect("v2 profile").get()),
                    ),
                    ("stderr_bytes", Value::Unsigned(limits.stderr().get())),
                    ("stdout_bytes", Value::Unsigned(limits.stdout().get())),
                    (
                        "wall_time_ms",
                        Value::Unsigned(limits.wall_time().milliseconds()),
                    ),
                ]),
            ),
            ("network", text("deny-network-v1")),
            (
                "filesystem",
                Value::Array(
                    self.filesystem
                        .rules
                        .iter()
                        .map(|rule| {
                            map([
                                ("path", text(rule.path().as_str())),
                                ("role", text(path_role_name(rule.role()))),
                                ("access", text(file_access_name(rule.access()))),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "environment",
                Value::Array(
                    self.environment
                        .iter()
                        .map(|name| text(name.as_str()))
                        .collect(),
                ),
            ),
            ("no_new_privileges", Value::Bool(true)),
        ])
    }

    /// Reports whether this policy adds no modeled authority.
    #[must_use]
    pub fn is_no_more_permissive_than(&self, authority: &NormalizedAuthority) -> bool {
        self.filesystem
            .rules
            .iter()
            .all(|rule| authority.paths().contains(rule))
            && self
                .environment
                .iter()
                .all(|name| authority.environment().contains(name))
            && self
                .cgroup
                .limits
                .is_no_more_permissive_than(authority.limits())
            && self.network == SeccompPolicy::DenyNetworkV1
            && self.no_new_privileges == NoNewPrivileges::Required
    }
}

fn map<const N: usize>(entries: [(&str, Value); N]) -> Value {
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

const fn file_access_name(access: FileAccess) -> &'static str {
    match access {
        FileAccess::Read => "read",
        FileAccess::Write => "write",
        FileAccess::Execute => "execute",
    }
}

const fn path_role_name(role: PathRole) -> &'static str {
    match role {
        PathRole::ProjectInput => "project-input",
        PathRole::OutputRoot => "output-root",
        PathRole::RuntimeExecutable => "runtime-executable",
        PathRole::RuntimeLoaderExecutable => "runtime-loader-executable",
        PathRole::RuntimeLibrary => "runtime-library",
    }
}

/// Compiles normalized authority into the closed version 1 Linux policy model.
///
/// This pure function preserves the exact normalized filesystem, environment,
/// and limit inputs. Version 1 maps denied network authority to its only
/// supported seccomp profile and requires `no_new_privs`.
#[must_use]
pub fn compile_policy(authority: NormalizedAuthority) -> CompiledPolicy {
    let (paths, environment, limits, _) = authority.into_parts();
    CompiledPolicy {
        filesystem: FilesystemPolicy { rules: paths },
        environment,
        network: SeccompPolicy::DenyNetworkV1,
        cgroup: CgroupPolicy { limits },
        no_new_privileges: NoNewPrivileges::Required,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthorityPath, AuthorityPlan, EnvironmentName, FileAccess, OutputByteLimit, PathAuthority,
        PathRole, ProcessLimit, WallTimeLimit, normalize_authority,
        parse_execution_plan_for_execution,
    };

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

    #[test]
    fn version_two_policy_matches_the_registered_cbor_vector() {
        let plan_bytes = decode_hex(include_str!(
            "../../../schemas/vectors/v2/execution-plan.cbor.hex"
        ));
        let plan = parse_execution_plan_for_execution(&plan_bytes).expect("golden plan is valid");
        let authority = normalize_authority(plan.authority().clone()).expect("plan normalizes");
        let policy = compile_policy(authority);

        assert_eq!(policy.model_version(), "proofbound-runtime-linux-policy/2");
        assert_eq!(policy.cgroup().limits().memory().unwrap().get(), 65_536);
        assert_eq!(policy.cgroup().limits().swap().unwrap().get(), 0);
        assert_eq!(
            policy.canonical_bytes().expect("policy encodes"),
            decode_hex(include_str!(
                "../../../schemas/vectors/v2/compiled-policy.cbor.hex"
            ))
        );
    }

    #[test]
    fn compilation_preserves_exact_normalized_authority() {
        let read = PathAuthority::new(
            AuthorityPath::new("src").expect("fixture path is valid"),
            FileAccess::Read,
            PathRole::ProjectInput,
        );
        let limits = ResourceLimits::new(
            ProcessLimit::new(2).expect("fixture process limit is valid"),
            WallTimeLimit::from_milliseconds(100).expect("fixture wall time is valid"),
            OutputByteLimit::new(200),
            OutputByteLimit::new(300),
        );
        let authority = normalize_authority(AuthorityPlan::new(
            vec![read.clone(), read],
            vec![
                EnvironmentName::new("PATH").expect("fixture name is valid"),
                EnvironmentName::new("PATH").expect("fixture name is valid"),
            ],
            limits,
        ))
        .expect("fixture authority normalizes");

        let policy = compile_policy(authority.clone());
        assert_eq!(policy.filesystem().rules(), authority.paths());
        assert_eq!(policy.environment(), authority.environment());
        assert_eq!(policy.cgroup().limits(), authority.limits());
        assert_eq!(policy.network(), SeccompPolicy::DenyNetworkV1);
        assert_eq!(policy.no_new_privileges(), NoNewPrivileges::Required);
        assert!(policy.is_no_more_permissive_than(&authority));
    }
}
