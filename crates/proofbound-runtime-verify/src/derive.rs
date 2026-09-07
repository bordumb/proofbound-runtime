use core::num::NonZeroU32;

/// Reports the verifier's view of boundary installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryState {
    /// The receipt contains a valid installation acknowledgement.
    Installed,
    /// The receipt does not contain a valid installation acknowledgement.
    Incomplete,
}

/// Reports the verifier's view of one execution result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeState {
    /// The child exited with the specified exit code.
    Exited {
        /// Contains the recorded exit code.
        code: i32,
    },
    /// A signal stopped the child.
    Signaled {
        /// Contains the nonzero signal number.
        signal: NonZeroU32,
    },
    /// The supervisor stopped the child at the wall-time limit.
    TimedOut,
    /// The installed boundary denied a child operation.
    Denied,
    /// The launcher failed before child execution.
    LauncherFailed,
    /// The receipt does not contain a terminal execution result.
    Incomplete,
}

/// Reports the verifier's view of one captured stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureState {
    /// The stream inventory is complete.
    Complete,
    /// The stream inventory reached its registered byte limit.
    Truncated,
}

/// Reports the result of structural receipt validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StructureState {
    /// The receipt has the registered structure.
    Valid,
    /// The receipt is missing structure or contains invalid structure.
    Malformed,
}

/// Contains independently decoded eligibility inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EligibilityInput {
    boundary: BoundaryState,
    outcome: OutcomeState,
    stdout: CaptureState,
    stderr: CaptureState,
    structure: StructureState,
}

impl EligibilityInput {
    /// Creates one complete verifier input.
    #[must_use]
    pub fn new(
        boundary: BoundaryState,
        outcome: OutcomeState,
        stdout: CaptureState,
        stderr: CaptureState,
        structure: StructureState,
    ) -> Self {
        Self {
            boundary,
            outcome,
            stdout,
            stderr,
            structure,
        }
    }
}

/// Identifies one independently derived reuse failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureReason {
    /// The receipt does not confirm the complete boundary.
    BoundaryIncomplete,
    /// The child returned a nonzero exit code.
    ExitCodeNonzero,
    /// A signal stopped the child.
    ProcessSignaled,
    /// The supervisor stopped the child at the wall-time limit.
    TimedOut,
    /// The installed boundary denied a child operation.
    Denied,
    /// The launcher failed before child execution.
    LauncherFailed,
    /// The receipt does not contain a terminal execution result.
    ExecutionIncomplete,
    /// Standard-output capture reached its registered byte limit.
    StandardOutputTruncated,
    /// Standard-error capture reached its registered byte limit.
    StandardErrorTruncated,
    /// Structural receipt validation failed.
    ReceiptMalformed,
}

impl FailureReason {
    /// Returns the stable version 1 wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BoundaryIncomplete => "boundary-incomplete",
            Self::ExitCodeNonzero => "exit-code-nonzero",
            Self::ProcessSignaled => "process-signaled",
            Self::TimedOut => "timed-out",
            Self::Denied => "denied",
            Self::LauncherFailed => "launcher-failed",
            Self::ExecutionIncomplete => "execution-incomplete",
            Self::StandardOutputTruncated => "stdout-truncated",
            Self::StandardErrorTruncated => "stderr-truncated",
            Self::ReceiptMalformed => "receipt-malformed",
        }
    }
}

/// Contains one or more independently derived failures in canonical order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureReasons(Vec<FailureReason>);

impl FailureReasons {
    /// Returns the failures in canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[FailureReason] {
        &self.0
    }
}

/// Reports the verifier's independent reuse decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EligibilityDecision {
    /// The receipt satisfies every version 1 reuse condition.
    Reusable,
    /// The receipt fails one or more version 1 reuse conditions.
    NonReusable(FailureReasons),
}

/// Derives reuse eligibility without using producer semantics.
#[must_use]
pub fn derive_eligibility(input: &EligibilityInput) -> EligibilityDecision {
    let mut failures = Vec::new();

    match input.boundary {
        BoundaryState::Installed => {}
        BoundaryState::Incomplete => failures.push(FailureReason::BoundaryIncomplete),
    }

    match input.outcome {
        OutcomeState::Exited { code: 0 } => {}
        OutcomeState::Exited { .. } => failures.push(FailureReason::ExitCodeNonzero),
        OutcomeState::Signaled { .. } => failures.push(FailureReason::ProcessSignaled),
        OutcomeState::TimedOut => failures.push(FailureReason::TimedOut),
        OutcomeState::Denied => failures.push(FailureReason::Denied),
        OutcomeState::LauncherFailed => failures.push(FailureReason::LauncherFailed),
        OutcomeState::Incomplete => failures.push(FailureReason::ExecutionIncomplete),
    }

    match input.stdout {
        CaptureState::Complete => {}
        CaptureState::Truncated => failures.push(FailureReason::StandardOutputTruncated),
    }
    match input.stderr {
        CaptureState::Complete => {}
        CaptureState::Truncated => failures.push(FailureReason::StandardErrorTruncated),
    }
    match input.structure {
        StructureState::Valid => {}
        StructureState::Malformed => failures.push(FailureReason::ReceiptMalformed),
    }

    if failures.is_empty() {
        EligibilityDecision::Reusable
    } else {
        EligibilityDecision::NonReusable(FailureReasons(failures))
    }
}
