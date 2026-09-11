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

/// Identifies one terminal cgroup resource event retained by version 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitEvent {
    MemoryHigh,
    MemoryMax,
    MemoryOom,
    MemoryOomKill,
    MemoryOomGroupKill,
    SwapMax,
    SwapFail,
}

/// Contains the canonical set of terminal resource events.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LimitEvents {
    memory_high: bool,
    memory_max: bool,
    memory_oom: bool,
    memory_oom_kill: bool,
    memory_oom_group_kill: bool,
    swap_max: bool,
    swap_fail: bool,
}

impl LimitEvents {
    /// Canonicalizes an event collection and removes duplicates.
    #[must_use]
    pub fn new(events: &[LimitEvent]) -> Self {
        let mut present = Self::default();
        for event in events {
            match event {
                LimitEvent::MemoryHigh => present.memory_high = true,
                LimitEvent::MemoryMax => present.memory_max = true,
                LimitEvent::MemoryOom => present.memory_oom = true,
                LimitEvent::MemoryOomKill => present.memory_oom_kill = true,
                LimitEvent::MemoryOomGroupKill => present.memory_oom_group_kill = true,
                LimitEvent::SwapMax => present.swap_max = true,
                LimitEvent::SwapFail => present.swap_fail = true,
            }
        }
        present
    }

    /// Reports whether the canonical set contains an event.
    #[must_use]
    pub const fn contains(self, event: LimitEvent) -> bool {
        match event {
            LimitEvent::MemoryHigh => self.memory_high,
            LimitEvent::MemoryMax => self.memory_max,
            LimitEvent::MemoryOom => self.memory_oom,
            LimitEvent::MemoryOomKill => self.memory_oom_kill,
            LimitEvent::MemoryOomGroupKill => self.memory_oom_group_kill,
            LimitEvent::SwapMax => self.swap_max,
            LimitEvent::SwapFail => self.swap_fail,
        }
    }

    /// Reports whether no registered event occurred.
    #[must_use]
    pub fn is_empty(self) -> bool {
        !self.memory_high
            && !self.memory_max
            && !self.memory_oom
            && !self.memory_oom_kill
            && !self.memory_oom_group_kill
            && !self.swap_max
            && !self.swap_fail
    }
}

/// Contains the facts that determine reuse eligibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptFacts {
    boundary: BoundaryInstallation,
    outcome: ExecutionOutcome,
    stdout: StreamCapture,
    stderr: StreamCapture,
    structure: ReceiptStructure,
    limit_events: LimitEvents,
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
            limit_events: LimitEvents::default(),
        }
    }

    /// Creates one complete version 2 eligibility input.
    #[must_use]
    pub fn new_v2(
        boundary: BoundaryInstallation,
        outcome: ExecutionOutcome,
        stdout: StreamCapture,
        stderr: StreamCapture,
        structure: ReceiptStructure,
        limit_events: LimitEvents,
    ) -> Self {
        Self {
            boundary,
            outcome,
            stdout,
            stderr,
            structure,
            limit_events,
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
    MemoryHigh,
    MemoryMax,
    MemoryOom,
    MemoryOomKill,
    MemoryOomGroupKill,
    SwapMax,
    SwapFail,
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
    /// The receipt satisfies every reuse condition for its represented facts.
    Reusable,
    /// The receipt does not satisfy one or more reuse conditions.
    NonReusable(NonReusableReasons),
}

fn append_reason(
    mut reasons: Vec<NonReusableReason>,
    present: bool,
    reason: NonReusableReason,
) -> Vec<NonReusableReason> {
    if present {
        reasons.push(reason);
    }
    reasons
}

fn append_limit_event_reasons(
    reasons: Vec<NonReusableReason>,
    events: LimitEvents,
) -> Vec<NonReusableReason> {
    let reasons = append_reason(
        reasons,
        events.contains(LimitEvent::MemoryHigh),
        NonReusableReason::MemoryHigh,
    );
    let reasons = append_reason(
        reasons,
        events.contains(LimitEvent::MemoryMax),
        NonReusableReason::MemoryMax,
    );
    let reasons = append_reason(
        reasons,
        events.contains(LimitEvent::MemoryOom),
        NonReusableReason::MemoryOom,
    );
    let reasons = append_reason(
        reasons,
        events.contains(LimitEvent::MemoryOomKill),
        NonReusableReason::MemoryOomKill,
    );
    let reasons = append_reason(
        reasons,
        events.contains(LimitEvent::MemoryOomGroupKill),
        NonReusableReason::MemoryOomGroupKill,
    );
    let reasons = append_reason(
        reasons,
        events.contains(LimitEvent::SwapMax),
        NonReusableReason::SwapMax,
    );
    append_reason(
        reasons,
        events.contains(LimitEvent::SwapFail),
        NonReusableReason::SwapFail,
    )
}

fn append_outcome_reason(
    mut reasons: Vec<NonReusableReason>,
    outcome: ExecutionOutcome,
) -> Vec<NonReusableReason> {
    match outcome {
        ExecutionOutcome::Exited { code: 0 } => {}
        ExecutionOutcome::Exited { .. } => reasons.push(NonReusableReason::ExitCodeNonzero),
        ExecutionOutcome::Signaled { .. } => reasons.push(NonReusableReason::ProcessSignaled),
        ExecutionOutcome::TimedOut => reasons.push(NonReusableReason::TimedOut),
        ExecutionOutcome::Denied => reasons.push(NonReusableReason::Denied),
        ExecutionOutcome::LauncherFailed => reasons.push(NonReusableReason::LauncherFailed),
        ExecutionOutcome::Incomplete => reasons.push(NonReusableReason::ExecutionIncomplete),
    }
    reasons
}

/// Derives receipt reuse eligibility from typed execution facts.
///
/// The returned reasons use the canonical order from specification 0001.
#[must_use]
pub fn derive_receipt_eligibility(facts: &ReceiptFacts) -> ReceiptEligibility {
    let reasons = append_reason(
        Vec::new(),
        facts.boundary == BoundaryInstallation::Incomplete,
        NonReusableReason::BoundaryIncomplete,
    );
    let reasons = append_outcome_reason(reasons, facts.outcome);
    let reasons = append_reason(
        reasons,
        facts.stdout == StreamCapture::Truncated,
        NonReusableReason::StandardOutputTruncated,
    );
    let reasons = append_reason(
        reasons,
        facts.stderr == StreamCapture::Truncated,
        NonReusableReason::StandardErrorTruncated,
    );
    let reasons = append_reason(
        reasons,
        facts.structure == ReceiptStructure::Malformed,
        NonReusableReason::ReceiptMalformed,
    );
    let reasons = append_limit_event_reasons(reasons, facts.limit_events);

    if reasons.is_empty() {
        ReceiptEligibility::Reusable
    } else {
        ReceiptEligibility::NonReusable(NonReusableReasons(reasons))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_resource_limit_event_forces_nonreuse_in_canonical_order() {
        let events = LimitEvents::new(&[
            LimitEvent::SwapFail,
            LimitEvent::MemoryOomKill,
            LimitEvent::MemoryHigh,
        ]);
        let facts = ReceiptFacts::new_v2(
            BoundaryInstallation::Installed,
            ExecutionOutcome::Exited { code: 0 },
            StreamCapture::Complete,
            StreamCapture::Complete,
            ReceiptStructure::Valid,
            events,
        );
        let ReceiptEligibility::NonReusable(reasons) = derive_receipt_eligibility(&facts) else {
            panic!("a resource limit event must make the receipt non-reusable");
        };
        assert_eq!(
            reasons.as_slice(),
            &[
                NonReusableReason::MemoryHigh,
                NonReusableReason::MemoryOomKill,
                NonReusableReason::SwapFail,
            ]
        );
    }

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
