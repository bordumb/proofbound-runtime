//! Defines the closed execution-outcome vocabulary used by the runtime core.

pub use proofbound_runtime_receipt::{ExecutionOutcome, SignalNumber};

/// Identifies the wire-level kind of one execution outcome.
///
/// The payload-bearing `ExecutionOutcome` remains the source of the exit code
/// or signal number. This closed kind is for dispatch and serialization only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionOutcomeKind {
    /// The child exited and supplied an exit code.
    Exited,
    /// A nonzero signal stopped the child.
    Signaled,
    /// The supervisor stopped the child at the wall-time limit.
    TimedOut,
    /// The installed boundary denied a child operation.
    Denied,
    /// The launcher failed before it started the child.
    LauncherFailed,
    /// The supervisor did not observe a terminal result.
    Incomplete,
}

impl ExecutionOutcomeKind {
    /// Returns the stable version 1 wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exited => "exited",
            Self::Signaled => "signaled",
            Self::TimedOut => "timed-out",
            Self::Denied => "denied",
            Self::LauncherFailed => "launcher-failed",
            Self::Incomplete => "incomplete",
        }
    }
}

/// Returns the closed kind of an execution outcome without discarding its
/// payload in the caller.
#[must_use]
pub const fn execution_outcome_kind(outcome: ExecutionOutcome) -> ExecutionOutcomeKind {
    match outcome {
        ExecutionOutcome::Exited { .. } => ExecutionOutcomeKind::Exited,
        ExecutionOutcome::Signaled { .. } => ExecutionOutcomeKind::Signaled,
        ExecutionOutcome::TimedOut => ExecutionOutcomeKind::TimedOut,
        ExecutionOutcome::Denied => ExecutionOutcomeKind::Denied,
        ExecutionOutcome::LauncherFailed => ExecutionOutcomeKind::LauncherFailed,
        ExecutionOutcome::Incomplete => ExecutionOutcomeKind::Incomplete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_outcome_has_its_exact_wire_kind() {
        let cases = [
            (ExecutionOutcome::Exited { code: 0 }, "exited"),
            (
                ExecutionOutcome::Signaled {
                    signal: SignalNumber::MIN,
                },
                "signaled",
            ),
            (ExecutionOutcome::TimedOut, "timed-out"),
            (ExecutionOutcome::Denied, "denied"),
            (ExecutionOutcome::LauncherFailed, "launcher-failed"),
            (ExecutionOutcome::Incomplete, "incomplete"),
        ];

        for (outcome, expected) in cases {
            assert_eq!(execution_outcome_kind(outcome).as_str(), expected);
        }
    }

    #[test]
    fn signal_numbers_are_nonzero_by_construction() {
        assert_eq!(SignalNumber::new(0), None);
        let signal = SignalNumber::new(u32::MAX).expect("nonzero signal is valid");
        assert_eq!(signal.get(), u32::MAX);
    }
}
