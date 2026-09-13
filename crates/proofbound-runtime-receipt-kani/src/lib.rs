#![forbid(unsafe_code)]

//! Contains the bounded receipt eligibility proof harness.

#[cfg(kani)]
use proofbound_runtime_core::{
    BoundaryInstallation, ExecutionOutcome, LimitEvent, LimitEvents, NonReusableReason,
    ReceiptEligibility, ReceiptFacts, ReceiptStructure, SignalNumber, StreamCapture,
    derive_receipt_eligibility,
};

#[cfg(kani)]
#[kani::proof]
fn receipt_eligibility_is_exact_for_exit_zero() {
    check_receipt_eligibility(ExecutionOutcome::Exited { code: 0 });
}

#[cfg(kani)]
#[kani::proof]
fn receipt_eligibility_is_exact_for_exit_nonzero() {
    let code: i32 = kani::any();
    kani::assume(code != 0);
    check_receipt_eligibility(ExecutionOutcome::Exited { code });
}

#[cfg(kani)]
#[kani::proof]
fn receipt_eligibility_is_exact_for_signaled() {
    check_receipt_eligibility(ExecutionOutcome::Signaled {
        signal: SignalNumber::MIN,
    });
}

#[cfg(kani)]
#[kani::proof]
fn receipt_eligibility_is_exact_for_timed_out() {
    check_receipt_eligibility(ExecutionOutcome::TimedOut);
}

#[cfg(kani)]
#[kani::proof]
fn receipt_eligibility_is_exact_for_denied() {
    check_receipt_eligibility(ExecutionOutcome::Denied);
}

#[cfg(kani)]
#[kani::proof]
fn receipt_eligibility_is_exact_for_launcher_failed() {
    check_receipt_eligibility(ExecutionOutcome::LauncherFailed);
}

#[cfg(kani)]
#[kani::proof]
fn receipt_eligibility_is_exact_for_incomplete() {
    check_receipt_eligibility(ExecutionOutcome::Incomplete);
}

#[cfg(kani)]
fn check_receipt_eligibility(outcome: ExecutionOutcome) {
    let boundary = if kani::any() {
        BoundaryInstallation::Installed
    } else {
        BoundaryInstallation::Incomplete
    };
    let stdout = if kani::any() {
        StreamCapture::Complete
    } else {
        StreamCapture::Truncated
    };
    let stderr = if kani::any() {
        StreamCapture::Complete
    } else {
        StreamCapture::Truncated
    };
    let structure = if kani::any() {
        ReceiptStructure::Valid
    } else {
        ReceiptStructure::Malformed
    };
    let memory_high: bool = kani::any();
    let memory_max: bool = kani::any();
    let memory_oom: bool = kani::any();
    let memory_oom_kill: bool = kani::any();
    let memory_oom_group_kill: bool = kani::any();
    let swap_max: bool = kani::any();
    let swap_fail: bool = kani::any();
    let events = canonical_limit_events(
        memory_high,
        memory_max,
        memory_oom,
        memory_oom_kill,
        memory_oom_group_kill,
        swap_max,
        swap_fail,
    );
    let facts = ReceiptFacts::new_v2(boundary, outcome, stdout, stderr, structure, events);
    let outcome_reason = match outcome {
        ExecutionOutcome::Exited { code: 0 } => None,
        ExecutionOutcome::Exited { .. } => Some(NonReusableReason::ExitCodeNonzero),
        ExecutionOutcome::Signaled { .. } => Some(NonReusableReason::ProcessSignaled),
        ExecutionOutcome::TimedOut => Some(NonReusableReason::TimedOut),
        ExecutionOutcome::Denied => Some(NonReusableReason::Denied),
        ExecutionOutcome::LauncherFailed => Some(NonReusableReason::LauncherFailed),
        ExecutionOutcome::Incomplete => Some(NonReusableReason::ExecutionIncomplete),
    };
    let expected_reason_count = usize::from(boundary == BoundaryInstallation::Incomplete)
        + usize::from(outcome_reason.is_some())
        + usize::from(stdout == StreamCapture::Truncated)
        + usize::from(stderr == StreamCapture::Truncated)
        + usize::from(structure == ReceiptStructure::Malformed)
        + usize::from(memory_high)
        + usize::from(memory_max)
        + usize::from(memory_oom)
        + usize::from(memory_oom_kill)
        + usize::from(memory_oom_group_kill)
        + usize::from(swap_max)
        + usize::from(swap_fail);

    match derive_receipt_eligibility(&facts) {
        ReceiptEligibility::Reusable => assert_eq!(expected_reason_count, 0),
        ReceiptEligibility::NonReusable(actual) => {
            let actual = actual.as_slice();
            assert_eq!(actual.len(), expected_reason_count);
            let mut index = 0;
            assert_reason(
                boundary == BoundaryInstallation::Incomplete,
                actual,
                &mut index,
                NonReusableReason::BoundaryIncomplete,
            );
            if let Some(reason) = outcome_reason {
                assert_eq!(actual[index], reason);
                index += 1;
            }
            assert_reason(
                stdout == StreamCapture::Truncated,
                actual,
                &mut index,
                NonReusableReason::StandardOutputTruncated,
            );
            assert_reason(
                stderr == StreamCapture::Truncated,
                actual,
                &mut index,
                NonReusableReason::StandardErrorTruncated,
            );
            assert_reason(
                structure == ReceiptStructure::Malformed,
                actual,
                &mut index,
                NonReusableReason::ReceiptMalformed,
            );
            assert_reason(
                memory_high,
                actual,
                &mut index,
                NonReusableReason::MemoryHigh,
            );
            assert_reason(memory_max, actual, &mut index, NonReusableReason::MemoryMax);
            assert_reason(memory_oom, actual, &mut index, NonReusableReason::MemoryOom);
            assert_reason(
                memory_oom_kill,
                actual,
                &mut index,
                NonReusableReason::MemoryOomKill,
            );
            assert_reason(
                memory_oom_group_kill,
                actual,
                &mut index,
                NonReusableReason::MemoryOomGroupKill,
            );
            assert_reason(swap_max, actual, &mut index, NonReusableReason::SwapMax);
            assert_reason(swap_fail, actual, &mut index, NonReusableReason::SwapFail);
            assert_eq!(index, actual.len());
        }
    }
}

#[cfg(kani)]
fn canonical_limit_events(
    memory_high: bool,
    memory_max: bool,
    memory_oom: bool,
    memory_oom_kill: bool,
    memory_oom_group_kill: bool,
    swap_max: bool,
    swap_fail: bool,
) -> LimitEvents {
    let filler = if memory_high {
        Some(LimitEvent::MemoryHigh)
    } else if memory_max {
        Some(LimitEvent::MemoryMax)
    } else if memory_oom {
        Some(LimitEvent::MemoryOom)
    } else if memory_oom_kill {
        Some(LimitEvent::MemoryOomKill)
    } else if memory_oom_group_kill {
        Some(LimitEvent::MemoryOomGroupKill)
    } else if swap_max {
        Some(LimitEvent::SwapMax)
    } else if swap_fail {
        Some(LimitEvent::SwapFail)
    } else {
        None
    };
    let Some(filler) = filler else {
        return LimitEvents::new(&[]);
    };
    LimitEvents::new(&[
        if memory_high {
            LimitEvent::MemoryHigh
        } else {
            filler
        },
        if memory_max {
            LimitEvent::MemoryMax
        } else {
            filler
        },
        if memory_oom {
            LimitEvent::MemoryOom
        } else {
            filler
        },
        if memory_oom_kill {
            LimitEvent::MemoryOomKill
        } else {
            filler
        },
        if memory_oom_group_kill {
            LimitEvent::MemoryOomGroupKill
        } else {
            filler
        },
        if swap_max {
            LimitEvent::SwapMax
        } else {
            filler
        },
        if swap_fail {
            LimitEvent::SwapFail
        } else {
            filler
        },
    ])
}

#[cfg(kani)]
fn assert_reason(
    expected: bool,
    actual: &[NonReusableReason],
    index: &mut usize,
    reason: NonReusableReason,
) {
    if expected {
        assert_eq!(actual[*index], reason);
        *index += 1;
    }
}
