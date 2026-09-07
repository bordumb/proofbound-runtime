use crate::{EnvironmentName, PathAuthority, ResourceLimits};

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
}
