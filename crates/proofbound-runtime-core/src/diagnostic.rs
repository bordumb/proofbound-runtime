//! Defines closed diagnostic-profile vocabulary without observer effects.

use core::fmt;

/// Identifies whether Runtime executes for production evidence or diagnostics.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ExecutionProfile {
    /// Installs the production boundary and may produce a production receipt.
    Production,
    /// Installs the declared boundary with a separate non-reusable observer.
    Diagnostic,
}

impl ExecutionProfile {
    /// Parses one closed execution-profile name.
    pub fn parse(value: &str) -> Result<Self, DiagnosticTypeError> {
        match value {
            "production" => Ok(Self::Production),
            "diagnostic" => Ok(Self::Diagnostic),
            _ => Err(DiagnosticTypeError::ExecutionProfileUnsupported),
        }
    }

    /// Returns the stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Diagnostic => "diagnostic",
        }
    }
}

/// Identifies one diagnostic observer implementation contract.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DiagnosticObserverMechanism {
    /// Uses the reviewed Linux ptrace syscall-observation protocol.
    LinuxPtraceSyscallV1,
}

impl DiagnosticObserverMechanism {
    /// Parses one closed observer mechanism name.
    pub fn parse(value: &str) -> Result<Self, DiagnosticTypeError> {
        match value {
            "linux-ptrace-syscall-v1" => Ok(Self::LinuxPtraceSyscallV1),
            _ => Err(DiagnosticTypeError::ObserverMechanismUnsupported),
        }
    }

    /// Returns the stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LinuxPtraceSyscallV1 => "linux-ptrace-syscall-v1",
        }
    }
}

/// Identifies where one plan-draft item came from.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DraftProvenance {
    /// A person supplied the item.
    HumanAuthored,
    /// Bounded static executable discovery supplied the item.
    StaticExecutableClosure,
    /// One diagnostic execution supplied the item.
    DiagnosticRuntimeObservation,
    /// One identified Capsec source report supplied the item.
    CapsecSourceObservation,
    /// The selected Runtime platform profile requires the item.
    PlatformRequiredClosure,
}

impl DraftProvenance {
    /// Parses one closed provenance name.
    pub fn parse(value: &str) -> Result<Self, DiagnosticTypeError> {
        match value {
            "human-authored" => Ok(Self::HumanAuthored),
            "static-executable-closure" => Ok(Self::StaticExecutableClosure),
            "diagnostic-runtime-observation" => Ok(Self::DiagnosticRuntimeObservation),
            "capsec-source-observation" => Ok(Self::CapsecSourceObservation),
            "platform-required-closure" => Ok(Self::PlatformRequiredClosure),
            _ => Err(DiagnosticTypeError::DraftProvenanceUnsupported),
        }
    }

    /// Returns the stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HumanAuthored => "human-authored",
            Self::StaticExecutableClosure => "static-executable-closure",
            Self::DiagnosticRuntimeObservation => "diagnostic-runtime-observation",
            Self::CapsecSourceObservation => "capsec-source-observation",
            Self::PlatformRequiredClosure => "platform-required-closure",
        }
    }
}

/// Identifies how precisely an observed object was resolved.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObservationResolution {
    /// The stopped tracee exposes the object selected by the kernel.
    KernelSelected,
    /// A bounded supervisor check found one candidate without observed drift.
    StableCandidate,
    /// The observer could not identify one object.
    Unresolved,
    /// The output policy requires the value to be hidden.
    Redacted,
}

impl ObservationResolution {
    /// Parses one closed resolution name.
    pub fn parse(value: &str) -> Result<Self, DiagnosticTypeError> {
        match value {
            "kernel-selected" => Ok(Self::KernelSelected),
            "stable-candidate" => Ok(Self::StableCandidate),
            "unresolved" => Ok(Self::Unresolved),
            "redacted" => Ok(Self::Redacted),
            _ => Err(DiagnosticTypeError::ObservationResolutionUnsupported),
        }
    }

    /// Returns the stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KernelSelected => "kernel-selected",
            Self::StableCandidate => "stable-candidate",
            Self::Unresolved => "unresolved",
            Self::Redacted => "redacted",
        }
    }
}

/// Identifies whether the observer retained its complete declared event set.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DiagnosticCompletion {
    /// No registered gap occurred.
    Complete,
    /// One or more registered gaps occurred.
    Incomplete,
}

impl DiagnosticCompletion {
    /// Parses one closed completion name.
    pub fn parse(value: &str) -> Result<Self, DiagnosticTypeError> {
        match value {
            "complete" => Ok(Self::Complete),
            "incomplete" => Ok(Self::Incomplete),
            _ => Err(DiagnosticTypeError::CompletionUnsupported),
        }
    }

    /// Returns the stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
        }
    }
}

/// Identifies invalid closed diagnostic vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticTypeError {
    /// The execution profile is not supported.
    ExecutionProfileUnsupported,
    /// The observer mechanism is not supported.
    ObserverMechanismUnsupported,
    /// The draft provenance is not supported.
    DraftProvenanceUnsupported,
    /// The observation resolution is not supported.
    ObservationResolutionUnsupported,
    /// The completion value is not supported.
    CompletionUnsupported,
}

impl DiagnosticTypeError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ExecutionProfileUnsupported => "diagnostic.profile.unsupported",
            Self::ObserverMechanismUnsupported => "diagnostic.observer.unsupported",
            Self::DraftProvenanceUnsupported => "diagnostic.provenance.unsupported",
            Self::ObservationResolutionUnsupported => "diagnostic.resolution.unsupported",
            Self::CompletionUnsupported => "diagnostic.completion.unsupported",
        }
    }
}

impl fmt::Display for DiagnosticTypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for DiagnosticTypeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_diagnostic_vocabulary_round_trips() {
        for value in [ExecutionProfile::Production, ExecutionProfile::Diagnostic] {
            assert_eq!(ExecutionProfile::parse(value.as_str()), Ok(value));
        }
        assert_eq!(
            DiagnosticObserverMechanism::parse(
                DiagnosticObserverMechanism::LinuxPtraceSyscallV1.as_str()
            ),
            Ok(DiagnosticObserverMechanism::LinuxPtraceSyscallV1)
        );
        for value in [
            DraftProvenance::HumanAuthored,
            DraftProvenance::StaticExecutableClosure,
            DraftProvenance::DiagnosticRuntimeObservation,
            DraftProvenance::CapsecSourceObservation,
            DraftProvenance::PlatformRequiredClosure,
        ] {
            assert_eq!(DraftProvenance::parse(value.as_str()), Ok(value));
        }
        for value in [
            ObservationResolution::KernelSelected,
            ObservationResolution::StableCandidate,
            ObservationResolution::Unresolved,
            ObservationResolution::Redacted,
        ] {
            assert_eq!(ObservationResolution::parse(value.as_str()), Ok(value));
        }
        for value in [
            DiagnosticCompletion::Complete,
            DiagnosticCompletion::Incomplete,
        ] {
            assert_eq!(DiagnosticCompletion::parse(value.as_str()), Ok(value));
        }
    }

    #[test]
    fn unknown_diagnostic_vocabulary_fails_closed() {
        assert_eq!(
            ExecutionProfile::parse("best-effort"),
            Err(DiagnosticTypeError::ExecutionProfileUnsupported)
        );
        assert_eq!(
            DiagnosticObserverMechanism::parse("seccomp-notify"),
            Err(DiagnosticTypeError::ObserverMechanismUnsupported)
        );
        assert_eq!(
            DraftProvenance::parse("inferred-safe"),
            Err(DiagnosticTypeError::DraftProvenanceUnsupported)
        );
        assert_eq!(
            ObservationResolution::parse("probably-resolved"),
            Err(DiagnosticTypeError::ObservationResolutionUnsupported)
        );
        assert_eq!(
            DiagnosticCompletion::parse("mostly-complete"),
            Err(DiagnosticTypeError::CompletionUnsupported)
        );
    }
}
