use crate::{AuthorityPlan, EnvironmentName, NetworkMode, PathAuthority, ResourceLimits};

/// Contains authority entries in canonical order without duplicates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedAuthority {
    paths: Vec<PathAuthority>,
    environment: Vec<EnvironmentName>,
    limits: ResourceLimits,
    network: NetworkMode,
}

impl NormalizedAuthority {
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

    /// Reports whether this authority grants no more access than a plan.
    #[must_use]
    pub fn is_subset_of(&self, plan: &AuthorityPlan) -> bool {
        self.paths.iter().all(|item| plan.paths().contains(item))
            && self
                .environment
                .iter()
                .all(|name| plan.environment().contains(name))
            && self.limits.is_no_more_permissive_than(plan.limits())
            && self.network == plan.network()
    }

    /// Converts this value to an authority plan.
    #[must_use]
    pub fn to_plan(&self) -> AuthorityPlan {
        AuthorityPlan::new(self.paths.clone(), self.environment.clone(), self.limits)
    }

    /// Reports whether all entries have canonical order and no duplicates.
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        is_strictly_sorted(&self.paths) && is_strictly_sorted(&self.environment)
    }
}

/// Normalizes a validated authority plan.
///
/// This function sorts and deduplicates exact entries. It does not resolve
/// paths or add platform closure entries.
#[must_use]
pub fn normalize_authority(plan: AuthorityPlan) -> NormalizedAuthority {
    let (mut paths, mut environment, limits, network) = plan.into_parts();
    sort_and_deduplicate_paths(&mut paths);
    sort_and_deduplicate_environment(&mut environment);
    NormalizedAuthority {
        paths,
        environment,
        limits,
        network,
    }
}

fn sort_and_deduplicate_paths(items: &mut Vec<PathAuthority>) {
    deduplicate_paths(items);
    for index in 1..items.len() {
        let mut cursor = index;
        while cursor > 0 && items[cursor].comes_before(&items[cursor - 1]) {
            items.swap(cursor, cursor - 1);
            cursor -= 1;
        }
    }
}

fn deduplicate_paths(items: &mut Vec<PathAuthority>) {
    let mut write = 0;
    for read in 0..items.len() {
        if !path_prefix_contains(items, write, read) {
            if write != read {
                items.swap(write, read);
            }
            write += 1;
        }
    }
    items.truncate(write);
}

fn path_prefix_contains(items: &[PathAuthority], end: usize, candidate: usize) -> bool {
    let mut index = 0;
    while index < end {
        if items[index].same_value(&items[candidate]) {
            return true;
        }
        index += 1;
    }
    false
}

fn sort_and_deduplicate_environment(items: &mut Vec<EnvironmentName>) {
    deduplicate_environment(items);
    for index in 1..items.len() {
        let mut cursor = index;
        while cursor > 0 && items[cursor].comes_before(&items[cursor - 1]) {
            items.swap(cursor, cursor - 1);
            cursor -= 1;
        }
    }
}

fn deduplicate_environment(items: &mut Vec<EnvironmentName>) {
    let mut write = 0;
    for read in 0..items.len() {
        if !environment_prefix_contains(items, write, read) {
            if write != read {
                items.swap(write, read);
            }
            write += 1;
        }
    }
    items.truncate(write);
}

fn environment_prefix_contains(items: &[EnvironmentName], end: usize, candidate: usize) -> bool {
    let mut index = 0;
    while index < end {
        if items[index].same_value(&items[candidate]) {
            return true;
        }
        index += 1;
    }
    false
}

fn is_strictly_sorted<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(kani)]
mod kani_harnesses {
    use crate::{
        AuthorityPath, AuthorityPlan, EnvironmentName, FileAccess, OutputByteLimit, PathAuthority,
        PathRole, ProcessLimit, ResourceLimits, WallTimeLimit, normalize_authority,
    };

    fn path_from(selector: bool) -> PathAuthority {
        if selector {
            PathAuthority::new(
                AuthorityPath::new("b").expect("catalog paths are valid"),
                FileAccess::Read,
                PathRole::ProjectInput,
            )
        } else {
            PathAuthority::new(
                AuthorityPath::new("a").expect("catalog paths are valid"),
                FileAccess::Write,
                PathRole::OutputRoot,
            )
        }
    }

    fn environment_from(selector: bool) -> EnvironmentName {
        EnvironmentName::new(if selector { "LANG" } else { "PATH" })
            .expect("catalog names are valid")
    }

    #[kani::proof]
    #[kani::unwind(5)]
    fn normalization_does_not_amplify_bounded_catalog() {
        let plan = AuthorityPlan::new(
            vec![path_from(kani::any()), path_from(kani::any())],
            vec![environment_from(kani::any()), environment_from(kani::any())],
            ResourceLimits::new(
                ProcessLimit::new(1).expect("nonzero fixture"),
                WallTimeLimit::from_milliseconds(1).expect("nonzero fixture"),
                OutputByteLimit::new(1),
                OutputByteLimit::new(1),
            ),
        );
        let normalized = normalize_authority(plan.clone());
        assert!(normalized.is_subset_of(&plan));
        assert!(normalized.is_canonical());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthorityPath, EnvironmentName, FileAccess, OutputByteLimit, PathRole, ProcessLimit,
        WallTimeLimit,
    };

    fn limits() -> ResourceLimits {
        ResourceLimits::new(
            ProcessLimit::new(2).expect("valid fixture"),
            WallTimeLimit::from_milliseconds(100).expect("valid fixture"),
            OutputByteLimit::new(200),
            OutputByteLimit::new(300),
        )
    }

    fn path(value: &str, access: FileAccess, role: PathRole) -> PathAuthority {
        PathAuthority::new(
            AuthorityPath::new(value).expect("valid fixture"),
            access,
            role,
        )
    }

    #[test]
    fn sorts_and_deduplicates_without_amplification() {
        let src = path("src", FileAccess::Read, PathRole::ProjectInput);
        let out = path("out", FileAccess::Write, PathRole::OutputRoot);
        let plan = AuthorityPlan::new(
            vec![src.clone(), out.clone(), src.clone()],
            vec![
                EnvironmentName::new("PATH").expect("valid fixture"),
                EnvironmentName::new("LANG").expect("valid fixture"),
                EnvironmentName::new("PATH").expect("valid fixture"),
            ],
            limits(),
        );
        let normalized = normalize_authority(plan.clone());
        assert_eq!(normalized.paths(), &[out, src]);
        assert_eq!(
            normalized.environment(),
            &[
                EnvironmentName::new("LANG").expect("valid fixture"),
                EnvironmentName::new("PATH").expect("valid fixture"),
            ]
        );
        assert!(normalized.is_subset_of(&plan));
        assert!(normalized.is_canonical());
    }

    #[test]
    fn normalization_is_idempotent() {
        let plan = AuthorityPlan::new(
            vec![
                path("src", FileAccess::Read, PathRole::ProjectInput),
                path("src", FileAccess::Read, PathRole::ProjectInput),
            ],
            vec![],
            limits(),
        );
        let once = normalize_authority(plan);
        assert_eq!(normalize_authority(once.to_plan()), once);
    }
}
