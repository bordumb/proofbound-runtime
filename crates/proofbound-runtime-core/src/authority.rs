use core::fmt;

/// Identifies one file operation that the child can perform.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FileAccess {
    /// Permits file reads.
    Read,
    /// Permits file writes.
    Write,
    /// Permits execution of one file.
    Execute,
}

/// Identifies why a path is present in an authority plan.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PathRole {
    /// Contains project input.
    ProjectInput,
    /// Contains output from one execution.
    OutputRoot,
    /// Identifies the registered executable.
    RuntimeExecutable,
    /// Identifies the registered runtime loader executable.
    RuntimeLoaderExecutable,
    /// Contains a registered runtime library.
    RuntimeLibrary,
}

/// Contains one validated path from an authority plan.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AuthorityPath(String);

impl AuthorityPath {
    /// Validates one path.
    ///
    /// This function rejects an empty path and a path that contains a null byte.
    pub fn new(value: impl Into<String>) -> Result<Self, AuthorityError> {
        let value = value.into();
        if value.is_empty() {
            return Err(AuthorityError::EmptyPath);
        }
        if value.as_bytes().contains(&0) {
            return Err(AuthorityError::PathContainsNull);
        }
        Ok(Self(value))
    }

    /// Returns the validated path text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reports whether two validated paths contain the same bytes.
    pub(crate) fn same_value(&self, other: &Self) -> bool {
        bytes_same(self.0.as_bytes(), other.0.as_bytes())
    }

    /// Reports whether this path precedes another path in canonical order.
    pub(crate) fn comes_before(&self, other: &Self) -> bool {
        bytes_come_before(self.0.as_bytes(), other.0.as_bytes())
    }
}

/// Contains one validated environment variable name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentName(String);

impl EnvironmentName {
    /// Validates one environment variable name.
    ///
    /// This function rejects an empty name, a null byte, and an equals sign.
    pub fn new(value: impl Into<String>) -> Result<Self, AuthorityError> {
        let value = value.into();
        if value.is_empty() {
            return Err(AuthorityError::EmptyEnvironmentName);
        }
        if value.as_bytes().contains(&0) {
            return Err(AuthorityError::EnvironmentNameContainsNull);
        }
        if value.as_bytes().contains(&b'=') {
            return Err(AuthorityError::EnvironmentNameContainsEquals);
        }
        Ok(Self(value))
    }

    /// Returns the validated environment variable name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reports whether two validated names contain the same bytes.
    pub(crate) fn same_value(&self, other: &Self) -> bool {
        bytes_same(self.0.as_bytes(), other.0.as_bytes())
    }

    /// Reports whether this name precedes another name in canonical order.
    pub(crate) fn comes_before(&self, other: &Self) -> bool {
        bytes_come_before(self.0.as_bytes(), other.0.as_bytes())
    }
}

// Concrete byte operations keep the translated decision closure free of local
// comparison-trait implementations.
fn bytes_same(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

fn bytes_come_before(left: &[u8], right: &[u8]) -> bool {
    let common_length = if left.len() < right.len() {
        left.len()
    } else {
        right.len()
    };
    let mut index = 0;
    while index < common_length {
        if left[index] != right[index] {
            return left[index] < right[index];
        }
        index += 1;
    }
    left.len() < right.len()
}

/// Contains one filesystem authority entry.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PathAuthority {
    path: AuthorityPath,
    access: FileAccess,
    role: PathRole,
}

impl PathAuthority {
    /// Creates one filesystem authority entry.
    #[must_use]
    pub fn new(path: AuthorityPath, access: FileAccess, role: PathRole) -> Self {
        Self { path, access, role }
    }

    /// Returns the path.
    #[must_use]
    pub fn path(&self) -> &AuthorityPath {
        &self.path
    }

    /// Returns the permitted file operation.
    #[must_use]
    pub fn access(&self) -> FileAccess {
        self.access
    }

    /// Returns the path role.
    #[must_use]
    pub fn role(&self) -> PathRole {
        self.role
    }

    /// Reports whether two path entries contain the same authority.
    pub(crate) fn same_value(&self, other: &Self) -> bool {
        self.path.same_value(&other.path)
            && file_access_rank(self.access) == file_access_rank(other.access)
            && path_role_rank(self.role) == path_role_rank(other.role)
    }

    /// Reports whether this entry precedes another entry in canonical order.
    pub(crate) fn comes_before(&self, other: &Self) -> bool {
        if !self.path.same_value(&other.path) {
            return self.path.comes_before(&other.path);
        }
        let access = file_access_rank(self.access);
        let other_access = file_access_rank(other.access);
        if access != other_access {
            return access < other_access;
        }
        path_role_rank(self.role) < path_role_rank(other.role)
    }
}

fn file_access_rank(access: FileAccess) -> u8 {
    match access {
        FileAccess::Read => 0,
        FileAccess::Write => 1,
        FileAccess::Execute => 2,
    }
}

fn path_role_rank(role: PathRole) -> u8 {
    match role {
        PathRole::ProjectInput => 0,
        PathRole::OutputRoot => 1,
        PathRole::RuntimeExecutable => 2,
        PathRole::RuntimeLoaderExecutable => 3,
        PathRole::RuntimeLibrary => 4,
    }
}

/// Contains the maximum number of child processes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProcessLimit(u32);

impl ProcessLimit {
    /// Validates a process limit.
    pub fn new(value: u32) -> Result<Self, AuthorityError> {
        if value == 0 {
            return Err(AuthorityError::ZeroProcessLimit);
        }
        Ok(Self(value))
    }

    /// Returns the maximum process count.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }
}

/// Contains a wall-time limit in milliseconds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WallTimeLimit(u64);

impl WallTimeLimit {
    /// Validates a wall-time limit in milliseconds.
    pub fn from_milliseconds(value: u64) -> Result<Self, AuthorityError> {
        if value == 0 {
            return Err(AuthorityError::ZeroWallTimeLimit);
        }
        Ok(Self(value))
    }

    /// Returns the wall-time limit in milliseconds.
    #[must_use]
    pub fn milliseconds(self) -> u64 {
        self.0
    }
}

/// Contains an output limit in bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OutputByteLimit(u64);

impl OutputByteLimit {
    /// Creates an output limit in bytes.
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the output limit in bytes.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Contains the resource limits for one execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    processes: ProcessLimit,
    wall_time: WallTimeLimit,
    stdout: OutputByteLimit,
    stderr: OutputByteLimit,
}

impl ResourceLimits {
    /// Creates one resource-limit set.
    #[must_use]
    pub fn new(
        processes: ProcessLimit,
        wall_time: WallTimeLimit,
        stdout: OutputByteLimit,
        stderr: OutputByteLimit,
    ) -> Self {
        Self {
            processes,
            wall_time,
            stdout,
            stderr,
        }
    }

    /// Returns the process limit.
    #[must_use]
    pub fn processes(self) -> ProcessLimit {
        self.processes
    }

    /// Returns the wall-time limit.
    #[must_use]
    pub fn wall_time(self) -> WallTimeLimit {
        self.wall_time
    }

    /// Returns the standard-output limit.
    #[must_use]
    pub fn stdout(self) -> OutputByteLimit {
        self.stdout
    }

    /// Returns the standard-error limit.
    #[must_use]
    pub fn stderr(self) -> OutputByteLimit {
        self.stderr
    }

    /// Reports whether this limit set permits no more use than another set.
    #[must_use]
    pub fn is_no_more_permissive_than(self, other: Self) -> bool {
        self.processes <= other.processes
            && self.wall_time <= other.wall_time
            && self.stdout <= other.stdout
            && self.stderr <= other.stderr
    }
}

/// Identifies the network authority for one execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkMode {
    /// Denies network access.
    Deny,
}

/// Contains one validated authority plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityPlan {
    paths: Vec<PathAuthority>,
    environment: Vec<EnvironmentName>,
    limits: ResourceLimits,
    network: NetworkMode,
}

impl AuthorityPlan {
    /// Creates one validated authority plan.
    #[must_use]
    pub fn new(
        paths: Vec<PathAuthority>,
        environment: Vec<EnvironmentName>,
        limits: ResourceLimits,
    ) -> Self {
        Self {
            paths,
            environment,
            limits,
            network: NetworkMode::Deny,
        }
    }

    /// Returns the filesystem authority entries.
    #[must_use]
    pub fn paths(&self) -> &[PathAuthority] {
        &self.paths
    }

    /// Returns the permitted environment variable names.
    #[must_use]
    pub fn environment(&self) -> &[EnvironmentName] {
        &self.environment
    }

    /// Returns the resource limits.
    #[must_use]
    pub fn limits(&self) -> ResourceLimits {
        self.limits
    }

    /// Returns the network mode.
    #[must_use]
    pub fn network(&self) -> NetworkMode {
        self.network
    }

    /// Separates this plan into its normalized fields.
    pub(crate) fn into_parts(
        self,
    ) -> (
        Vec<PathAuthority>,
        Vec<EnvironmentName>,
        ResourceLimits,
        NetworkMode,
    ) {
        (self.paths, self.environment, self.limits, self.network)
    }
}

/// Identifies invalid authority input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityError {
    /// The path is empty.
    EmptyPath,
    /// The path contains a null byte.
    PathContainsNull,
    /// The environment variable name is empty.
    EmptyEnvironmentName,
    /// The environment variable name contains a null byte.
    EnvironmentNameContainsNull,
    /// The environment variable name contains an equals sign.
    EnvironmentNameContainsEquals,
    /// The process limit is zero.
    ZeroProcessLimit,
    /// The wall-time limit is zero.
    ZeroWallTimeLimit,
}

impl AuthorityError {
    /// Returns the stable machine code for this error.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::EmptyPath => "authority.path.empty",
            Self::PathContainsNull => "authority.path.null",
            Self::EmptyEnvironmentName => "authority.environment.empty",
            Self::EnvironmentNameContainsNull => "authority.environment.null",
            Self::EnvironmentNameContainsEquals => "authority.environment.equals",
            Self::ZeroProcessLimit => "authority.limit.processes.zero",
            Self::ZeroWallTimeLimit => "authority.limit.wall_time.zero",
        }
    }
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for AuthorityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_security_strings() {
        assert_eq!(AuthorityPath::new(""), Err(AuthorityError::EmptyPath));
        assert_eq!(
            AuthorityPath::new("a\0b"),
            Err(AuthorityError::PathContainsNull)
        );
        assert_eq!(
            EnvironmentName::new("A=B"),
            Err(AuthorityError::EnvironmentNameContainsEquals)
        );
    }

    #[test]
    fn compares_limits_by_permitted_use() {
        let smaller = ResourceLimits::new(
            ProcessLimit::new(1).expect("valid fixture"),
            WallTimeLimit::from_milliseconds(10).expect("valid fixture"),
            OutputByteLimit::new(2),
            OutputByteLimit::new(3),
        );
        let larger = ResourceLimits::new(
            ProcessLimit::new(2).expect("valid fixture"),
            WallTimeLimit::from_milliseconds(20).expect("valid fixture"),
            OutputByteLimit::new(4),
            OutputByteLimit::new(6),
        );
        assert!(smaller.is_no_more_permissive_than(larger));
        assert!(!larger.is_no_more_permissive_than(smaller));
    }

    #[test]
    fn concrete_comparison_matches_domain_order() {
        let text_values = ["A", "PATH", "é", "𐀀"];
        for left in text_values {
            for right in text_values {
                let left = EnvironmentName::new(left).expect("valid fixture");
                let right = EnvironmentName::new(right).expect("valid fixture");
                assert_eq!(left.same_value(&right), left == right);
                assert_eq!(left.comes_before(&right), left < right);
            }
        }

        let accesses = [FileAccess::Read, FileAccess::Write, FileAccess::Execute];
        let roles = [
            PathRole::ProjectInput,
            PathRole::OutputRoot,
            PathRole::RuntimeExecutable,
            PathRole::RuntimeLoaderExecutable,
            PathRole::RuntimeLibrary,
        ];
        let mut authorities = Vec::new();
        for path in ["A", "src", "é"] {
            for access in accesses {
                for role in roles {
                    authorities.push(PathAuthority::new(
                        AuthorityPath::new(path).expect("valid fixture"),
                        access,
                        role,
                    ));
                }
            }
        }
        for left in &authorities {
            for right in &authorities {
                assert_eq!(left.same_value(right), left == right);
                assert_eq!(left.comes_before(right), left < right);
            }
        }
    }
}
