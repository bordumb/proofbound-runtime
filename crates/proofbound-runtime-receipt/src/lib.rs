#![forbid(unsafe_code)]

//! Defines the pure receipt eligibility decision boundary.

use core::num::NonZeroU32;

/// Reports whether the launcher installed the complete boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryInstallation {
    /// The launcher installed the complete boundary.
    Installed,
    /// The launcher did not confirm the complete boundary.
    Incomplete,
}

/// Contains a nonzero process signal number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalNumber(u32);

impl SignalNumber {
    /// The smallest valid signal number.
    pub const MIN: Self = Self(1);

    /// Creates a signal number when `value` is nonzero.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    /// Creates a signal number from the standard-library nonzero carrier.
    #[must_use]
    pub const fn from_nonzero(value: NonZeroU32) -> Self {
        Self(value.get())
    }

    /// Returns the nonzero numeric value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Reports the observed result of one execution attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionOutcome {
    /// The child exited with the specified exit code.
    Exited {
        /// Contains the observed process exit code.
        code: i32,
    },
    /// The child stopped because it received a signal.
    Signaled {
        /// Contains the nonzero signal number.
        signal: SignalNumber,
    },
    /// The supervisor stopped the child at the wall-time limit.
    TimedOut,
    /// The installed boundary denied the child operation.
    Denied,
    /// The launcher failed before it started the child.
    LauncherFailed,
    /// The supervisor did not observe a terminal execution result.
    Incomplete,
}

/// Reports whether one captured stream contains all observed bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamCapture {
    /// The capture contains all observed bytes.
    Complete,
    /// The capture reached its registered byte limit.
    Truncated,
}

/// Reports whether receipt structure validation completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptStructure {
    /// The receipt has the registered structure.
    Valid,
    /// The receipt is missing required structure or contains invalid structure.
    Malformed,
}

/// Contains the facts that determine reuse eligibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptFacts {
    boundary: BoundaryInstallation,
    outcome: ExecutionOutcome,
    stdout: StreamCapture,
    stderr: StreamCapture,
    structure: ReceiptStructure,
}

impl ReceiptFacts {
    /// Creates one complete eligibility input.
    #[must_use]
    pub fn new(
        boundary: BoundaryInstallation,
        outcome: ExecutionOutcome,
        stdout: StreamCapture,
        stderr: StreamCapture,
        structure: ReceiptStructure,
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

/// Identifies one reason that prevents receipt reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonReusableReason {
    /// The launcher did not confirm the complete boundary.
    BoundaryIncomplete,
    /// The child returned a nonzero exit code.
    ExitCodeNonzero,
    /// A signal stopped the child.
    ProcessSignaled,
    /// The supervisor stopped the child at the wall-time limit.
    TimedOut,
    /// The installed boundary denied a child operation.
    Denied,
    /// The launcher failed before it started the child.
    LauncherFailed,
    /// The supervisor did not observe a terminal execution result.
    ExecutionIncomplete,
    /// Standard-output capture reached its byte limit.
    StandardOutputTruncated,
    /// Standard-error capture reached its byte limit.
    StandardErrorTruncated,
    /// Receipt structure validation failed.
    ReceiptMalformed,
}

/// Contains one or more reasons in canonical order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonReusableReasons(Vec<NonReusableReason>);

impl NonReusableReasons {
    /// Returns the reasons in canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[NonReusableReason] {
        &self.0
    }
}

/// Reports whether a receipt can be reused as execution evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiptEligibility {
    /// The receipt satisfies every version 1 reuse condition.
    Reusable,
    /// The receipt does not satisfy one or more reuse conditions.
    NonReusable(NonReusableReasons),
}

/// Derives receipt reuse eligibility from typed execution facts.
///
/// The returned reasons use the canonical order from specification 0001.
#[must_use]
pub fn derive_receipt_eligibility(facts: &ReceiptFacts) -> ReceiptEligibility {
    let mut reasons = Vec::new();

    if facts.boundary == BoundaryInstallation::Incomplete {
        reasons.push(NonReusableReason::BoundaryIncomplete);
    }

    match facts.outcome {
        ExecutionOutcome::Exited { code: 0 } => {}
        ExecutionOutcome::Exited { .. } => reasons.push(NonReusableReason::ExitCodeNonzero),
        ExecutionOutcome::Signaled { .. } => reasons.push(NonReusableReason::ProcessSignaled),
        ExecutionOutcome::TimedOut => reasons.push(NonReusableReason::TimedOut),
        ExecutionOutcome::Denied => reasons.push(NonReusableReason::Denied),
        ExecutionOutcome::LauncherFailed => reasons.push(NonReusableReason::LauncherFailed),
        ExecutionOutcome::Incomplete => reasons.push(NonReusableReason::ExecutionIncomplete),
    }

    if facts.stdout == StreamCapture::Truncated {
        reasons.push(NonReusableReason::StandardOutputTruncated);
    }
    if facts.stderr == StreamCapture::Truncated {
        reasons.push(NonReusableReason::StandardErrorTruncated);
    }
    if facts.structure == ReceiptStructure::Malformed {
        reasons.push(NonReusableReason::ReceiptMalformed);
    }

    if reasons.is_empty() {
        ReceiptEligibility::Reusable
    } else {
        ReceiptEligibility::NonReusable(NonReusableReasons(reasons))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOUNDARIES: [BoundaryInstallation; 2] = [
        BoundaryInstallation::Installed,
        BoundaryInstallation::Incomplete,
    ];
    const OUTCOMES: [(ExecutionOutcome, Option<NonReusableReason>); 8] = [
        (ExecutionOutcome::Exited { code: 0 }, None),
        (
            ExecutionOutcome::Exited { code: 1 },
            Some(NonReusableReason::ExitCodeNonzero),
        ),
        (
            ExecutionOutcome::Exited { code: -1 },
            Some(NonReusableReason::ExitCodeNonzero),
        ),
        (
            ExecutionOutcome::Signaled {
                signal: SignalNumber::MIN,
            },
            Some(NonReusableReason::ProcessSignaled),
        ),
        (
            ExecutionOutcome::TimedOut,
            Some(NonReusableReason::TimedOut),
        ),
        (ExecutionOutcome::Denied, Some(NonReusableReason::Denied)),
        (
            ExecutionOutcome::LauncherFailed,
            Some(NonReusableReason::LauncherFailed),
        ),
        (
            ExecutionOutcome::Incomplete,
            Some(NonReusableReason::ExecutionIncomplete),
        ),
    ];
    const CAPTURES: [StreamCapture; 2] = [StreamCapture::Complete, StreamCapture::Truncated];
    const STRUCTURES: [ReceiptStructure; 2] =
        [ReceiptStructure::Valid, ReceiptStructure::Malformed];

    #[test]
    fn only_complete_zero_exit_is_reusable_across_finite_state_catalog() {
        for boundary in BOUNDARIES {
            for (outcome, outcome_reason) in OUTCOMES {
                for stdout in CAPTURES {
                    for stderr in CAPTURES {
                        for structure in STRUCTURES {
                            let facts =
                                ReceiptFacts::new(boundary, outcome, stdout, stderr, structure);
                            let mut expected_reasons = Vec::new();
                            if boundary == BoundaryInstallation::Incomplete {
                                expected_reasons.push(NonReusableReason::BoundaryIncomplete);
                            }
                            if let Some(reason) = outcome_reason {
                                expected_reasons.push(reason);
                            }
                            if stdout == StreamCapture::Truncated {
                                expected_reasons.push(NonReusableReason::StandardOutputTruncated);
                            }
                            if stderr == StreamCapture::Truncated {
                                expected_reasons.push(NonReusableReason::StandardErrorTruncated);
                            }
                            if structure == ReceiptStructure::Malformed {
                                expected_reasons.push(NonReusableReason::ReceiptMalformed);
                            }

                            match derive_receipt_eligibility(&facts) {
                                ReceiptEligibility::Reusable => assert!(
                                    expected_reasons.is_empty(),
                                    "unexpected reusable decision for {facts:?}"
                                ),
                                ReceiptEligibility::NonReusable(reasons) => assert_eq!(
                                    reasons.as_slice(),
                                    expected_reasons,
                                    "unexpected reasons for {facts:?}"
                                ),
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn retains_all_applicable_reasons_in_canonical_order() {
        let facts = ReceiptFacts::new(
            BoundaryInstallation::Incomplete,
            ExecutionOutcome::LauncherFailed,
            StreamCapture::Truncated,
            StreamCapture::Truncated,
            ReceiptStructure::Malformed,
        );
        let ReceiptEligibility::NonReusable(reasons) = derive_receipt_eligibility(&facts) else {
            panic!("invalid execution facts must not be reusable");
        };
        assert_eq!(
            reasons.as_slice(),
            &[
                NonReusableReason::BoundaryIncomplete,
                NonReusableReason::LauncherFailed,
                NonReusableReason::StandardOutputTruncated,
                NonReusableReason::StandardErrorTruncated,
                NonReusableReason::ReceiptMalformed,
            ]
        );
    }
}
