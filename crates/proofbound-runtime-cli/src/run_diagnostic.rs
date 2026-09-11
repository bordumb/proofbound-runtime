//! Defines the closed diagnostic boundary for `pbr run`.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

/// Identifies the execution phase that stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunPhase {
    ReceiptTarget,
    PlanInput,
    PlanValidation,
    AuthorityNormalization,
    PlanRoot,
    HostCapabilities,
    OutputRoot,
    WorkingDirectory,
    ExecutableClosure,
    ReadAuthority,
    RuntimeIdentity,
    LauncherIdentity,
    Environment,
    PolicyCompilation,
    ExecutionIdentity,
    Cgroup,
    LauncherRequest,
    IdentityRevalidation,
    LauncherProtocol,
    OutputInventory,
    ReceiptConstruction,
    ReceiptPublication,
    ResultProjection,
}

impl RunPhase {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 23] = [
        Self::ReceiptTarget,
        Self::PlanInput,
        Self::PlanValidation,
        Self::AuthorityNormalization,
        Self::PlanRoot,
        Self::HostCapabilities,
        Self::OutputRoot,
        Self::WorkingDirectory,
        Self::ExecutableClosure,
        Self::ReadAuthority,
        Self::RuntimeIdentity,
        Self::LauncherIdentity,
        Self::Environment,
        Self::PolicyCompilation,
        Self::ExecutionIdentity,
        Self::Cgroup,
        Self::LauncherRequest,
        Self::IdentityRevalidation,
        Self::LauncherProtocol,
        Self::OutputInventory,
        Self::ReceiptConstruction,
        Self::ReceiptPublication,
        Self::ResultProjection,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptTarget => "receipt-target",
            Self::PlanInput => "plan-input",
            Self::PlanValidation => "plan-validation",
            Self::AuthorityNormalization => "authority-normalization",
            Self::PlanRoot => "plan-root",
            Self::HostCapabilities => "host-capabilities",
            Self::OutputRoot => "output-root",
            Self::WorkingDirectory => "working-directory",
            Self::ExecutableClosure => "executable-closure",
            Self::ReadAuthority => "read-authority",
            Self::RuntimeIdentity => "runtime-identity",
            Self::LauncherIdentity => "launcher-identity",
            Self::Environment => "environment",
            Self::PolicyCompilation => "policy-compilation",
            Self::ExecutionIdentity => "execution-identity",
            Self::Cgroup => "cgroup",
            Self::LauncherRequest => "launcher-request",
            Self::IdentityRevalidation => "identity-revalidation",
            Self::LauncherProtocol => "launcher-protocol",
            Self::OutputInventory => "output-inventory",
            Self::ReceiptConstruction => "receipt-construction",
            Self::ReceiptPublication => "receipt-publication",
            Self::ResultProjection => "result-projection",
        }
    }
}

/// Identifies the Runtime invariant that failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunRule {
    ReceiptTargetValid,
    PlanSourceReadable,
    PlanValid,
    AuthorityNormalized,
    PlanRootConfined,
    HostSupported,
    OutputRootFresh,
    WorkingDirectoryResolved,
    ExecutableClosureResolved,
    ReadAuthorityResolved,
    RuntimeIdentityObserved,
    LauncherIdentityObserved,
    EnvironmentRepresentable,
    PolicyIdentityConstructed,
    ExecutionIdentityCreated,
    CgroupBoundaryPrepared,
    LauncherRequestConstructed,
    ArtifactIdentitiesStable,
    LauncherBoundaryComplete,
    OutputInventoryStable,
    ReceiptConstructed,
    ReceiptPublished,
    RunResultRepresentable,
}

impl RunRule {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 23] = [
        Self::ReceiptTargetValid,
        Self::PlanSourceReadable,
        Self::PlanValid,
        Self::AuthorityNormalized,
        Self::PlanRootConfined,
        Self::HostSupported,
        Self::OutputRootFresh,
        Self::WorkingDirectoryResolved,
        Self::ExecutableClosureResolved,
        Self::ReadAuthorityResolved,
        Self::RuntimeIdentityObserved,
        Self::LauncherIdentityObserved,
        Self::EnvironmentRepresentable,
        Self::PolicyIdentityConstructed,
        Self::ExecutionIdentityCreated,
        Self::CgroupBoundaryPrepared,
        Self::LauncherRequestConstructed,
        Self::ArtifactIdentitiesStable,
        Self::LauncherBoundaryComplete,
        Self::OutputInventoryStable,
        Self::ReceiptConstructed,
        Self::ReceiptPublished,
        Self::RunResultRepresentable,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptTargetValid => "receipt-target-valid",
            Self::PlanSourceReadable => "plan-source-readable",
            Self::PlanValid => "plan-valid",
            Self::AuthorityNormalized => "authority-normalized",
            Self::PlanRootConfined => "plan-root-confined",
            Self::HostSupported => "host-supported",
            Self::OutputRootFresh => "output-root-fresh",
            Self::WorkingDirectoryResolved => "working-directory-resolved",
            Self::ExecutableClosureResolved => "executable-closure-resolved",
            Self::ReadAuthorityResolved => "read-authority-resolved",
            Self::RuntimeIdentityObserved => "runtime-identity-observed",
            Self::LauncherIdentityObserved => "launcher-identity-observed",
            Self::EnvironmentRepresentable => "environment-representable",
            Self::PolicyIdentityConstructed => "policy-identity-constructed",
            Self::ExecutionIdentityCreated => "execution-identity-created",
            Self::CgroupBoundaryPrepared => "cgroup-boundary-prepared",
            Self::LauncherRequestConstructed => "launcher-request-constructed",
            Self::ArtifactIdentitiesStable => "artifact-identities-stable",
            Self::LauncherBoundaryComplete => "launcher-boundary-complete",
            Self::OutputInventoryStable => "output-inventory-stable",
            Self::ReceiptConstructed => "receipt-constructed",
            Self::ReceiptPublished => "receipt-published",
            Self::RunResultRepresentable => "run-result-representable",
        }
    }
}

/// Contains one typed `pbr run` orchestration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunError {
    exit_code: u8,
    phase: RunPhase,
    rule: RunRule,
    code: &'static str,
}

impl RunError {
    pub(crate) const fn invalid(phase: RunPhase, rule: RunRule, code: &'static str) -> Self {
        Self::new(2, phase, rule, code)
    }

    pub(crate) const fn unsupported(phase: RunPhase, rule: RunRule, code: &'static str) -> Self {
        Self::new(3, phase, rule, code)
    }

    pub(crate) const fn identity(phase: RunPhase, rule: RunRule, code: &'static str) -> Self {
        Self::new(4, phase, rule, code)
    }

    pub(crate) const fn launcher(phase: RunPhase, rule: RunRule, code: &'static str) -> Self {
        Self::new(5, phase, rule, code)
    }

    pub(crate) const fn receipt(phase: RunPhase, rule: RunRule, code: &'static str) -> Self {
        Self::new(6, phase, rule, code)
    }

    const fn new(exit_code: u8, phase: RunPhase, rule: RunRule, code: &'static str) -> Self {
        Self {
            exit_code,
            phase,
            rule,
            code,
        }
    }

    pub const fn exit_code(self) -> u8 {
        self.exit_code
    }

    pub(crate) const fn phase(self) -> RunPhase {
        self.phase
    }

    pub(crate) const fn rule(self) -> RunRule {
        self.rule
    }

    pub const fn code(self) -> &'static str {
        self.code
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn phase_and_rule_names_are_unique_and_bounded() {
        for names in [
            RunPhase::ALL.map(RunPhase::as_str).as_slice(),
            RunRule::ALL.map(RunRule::as_str).as_slice(),
        ] {
            assert_eq!(
                names.iter().copied().collect::<BTreeSet<_>>().len(),
                names.len()
            );
            for name in names {
                assert!(!name.is_empty());
                assert!(name.len() <= 64);
                assert!(name.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'-'));
            }
        }
    }
}
