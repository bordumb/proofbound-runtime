#![forbid(unsafe_code)]

//! Contains the bounded policy-compilation proof harness.

#[cfg(kani)]
use proofbound_runtime_core::{
    AuthorityPath, EnvironmentName, FileAccess, NormalizedAuthority, OutputByteLimit,
    PathAuthority, PathRole, ProcessLimit, ResourceLimits, WallTimeLimit, compile_policy,
};

#[cfg(kani)]
fn path_from(selector: bool) -> PathAuthority {
    if selector {
        PathAuthority::new(
            AuthorityPath::new("b").expect("catalog path is valid"),
            FileAccess::Read,
            PathRole::ProjectInput,
        )
    } else {
        PathAuthority::new(
            AuthorityPath::new("a").expect("catalog path is valid"),
            FileAccess::Write,
            PathRole::OutputRoot,
        )
    }
}

#[cfg(kani)]
fn environment_from(selector: bool) -> EnvironmentName {
    EnvironmentName::new(if selector { "LANG" } else { "PATH" }).expect("catalog name is valid")
}

#[cfg(kani)]
#[kani::proof]
#[kani::unwind(5)]
fn policy_compilation_does_not_amplify_bounded_catalog() {
    let authority = NormalizedAuthority::from_canonical_catalog_for_model_check(
        vec![path_from(kani::any())],
        vec![environment_from(kani::any())],
        ResourceLimits::new(
            ProcessLimit::new(1).expect("catalog process limit is valid"),
            WallTimeLimit::from_milliseconds(1).expect("catalog wall time is valid"),
            OutputByteLimit::new(1),
            OutputByteLimit::new(1),
        ),
    );
    let policy = compile_policy(&authority);
    assert!(policy.is_no_more_permissive_than(&authority));
    assert_eq!(policy.filesystem().rules(), authority.paths());
    assert_eq!(policy.environment(), authority.environment());
    assert_eq!(policy.cgroup().limits(), authority.limits());
}
