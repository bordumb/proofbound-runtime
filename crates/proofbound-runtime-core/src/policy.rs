use crate::{EnvironmentName, NormalizedAuthority, PathAuthority, ResourceLimits};

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

/// Compiles normalized authority into the closed version 1 Linux policy model.
///
/// This pure function preserves the exact normalized filesystem, environment,
/// and limit inputs. Version 1 maps denied network authority to its only
/// supported seccomp profile and requires `no_new_privs`.
#[must_use]
pub fn compile_policy(authority: &NormalizedAuthority) -> CompiledPolicy {
    CompiledPolicy {
        filesystem: FilesystemPolicy {
            rules: authority.paths().to_vec(),
        },
        environment: authority.environment().to_vec(),
        network: SeccompPolicy::DenyNetworkV1,
        cgroup: CgroupPolicy {
            limits: authority.limits(),
        },
        no_new_privileges: NoNewPrivileges::Required,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthorityPath, AuthorityPlan, EnvironmentName, FileAccess, OutputByteLimit, PathAuthority,
        PathRole, ProcessLimit, WallTimeLimit, normalize_authority,
    };

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

        let policy = compile_policy(&authority);
        assert_eq!(policy.filesystem().rules(), authority.paths());
        assert_eq!(policy.environment(), authority.environment());
        assert_eq!(policy.cgroup().limits(), authority.limits());
        assert_eq!(policy.network(), SeccompPolicy::DenyNetworkV1);
        assert_eq!(policy.no_new_privileges(), NoNewPrivileges::Required);
        assert!(policy.is_no_more_permissive_than(&authority));
    }
}
