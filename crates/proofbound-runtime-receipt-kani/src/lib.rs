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
fn receipt_eligibility_is_exact_for_bounded_state_model() {
    let boundary = if kani::any() {
        BoundaryInstallation::Installed
    } else {
        BoundaryInstallation::Incomplete
    };
    let outcome_selector: u8 = kani::any();
    kani::assume(outcome_selector < 6);
    let outcome = match outcome_selector {
        0 => ExecutionOutcome::Exited { code: kani::any() },
        1 => ExecutionOutcome::Signaled {
            signal: SignalNumber::MIN,
        },
        2 => ExecutionOutcome::TimedOut,
        3 => ExecutionOutcome::Denied,
        4 => ExecutionOutcome::LauncherFailed,
        _ => ExecutionOutcome::Incomplete,
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
    let mut events = Vec::new();
    if memory_high {
        events.push(LimitEvent::MemoryHigh);
    }
    if memory_max {
        events.push(LimitEvent::MemoryMax);
    }
    if memory_oom {
        events.push(LimitEvent::MemoryOom);
    }
    if memory_oom_kill {
        events.push(LimitEvent::MemoryOomKill);
    }
    if memory_oom_group_kill {
        events.push(LimitEvent::MemoryOomGroupKill);
    }
    if swap_max {
        events.push(LimitEvent::SwapMax);
    }
    if swap_fail {
        events.push(LimitEvent::SwapFail);
    }
    let facts = ReceiptFacts::new_v2(
        boundary,
        outcome,
        stdout,
        stderr,
        structure,
        LimitEvents::new(&events),
    );
    let mut expected_reasons = Vec::new();
    if boundary == BoundaryInstallation::Incomplete {
        expected_reasons.push(NonReusableReason::BoundaryIncomplete);
    }
    match outcome {
        ExecutionOutcome::Exited { code: 0 } => {}
        ExecutionOutcome::Exited { .. } => {
            expected_reasons.push(NonReusableReason::ExitCodeNonzero);
        }
        ExecutionOutcome::Signaled { .. } => {
            expected_reasons.push(NonReusableReason::ProcessSignaled);
        }
        ExecutionOutcome::TimedOut => expected_reasons.push(NonReusableReason::TimedOut),
        ExecutionOutcome::Denied => expected_reasons.push(NonReusableReason::Denied),
        ExecutionOutcome::LauncherFailed => {
            expected_reasons.push(NonReusableReason::LauncherFailed);
        }
        ExecutionOutcome::Incomplete => {
            expected_reasons.push(NonReusableReason::ExecutionIncomplete);
        }
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
    if memory_high {
        expected_reasons.push(NonReusableReason::MemoryHigh);
    }
    if memory_max {
        expected_reasons.push(NonReusableReason::MemoryMax);
    }
    if memory_oom {
        expected_reasons.push(NonReusableReason::MemoryOom);
    }
    if memory_oom_kill {
        expected_reasons.push(NonReusableReason::MemoryOomKill);
    }
    if memory_oom_group_kill {
        expected_reasons.push(NonReusableReason::MemoryOomGroupKill);
    }
    if swap_max {
        expected_reasons.push(NonReusableReason::SwapMax);
    }
    if swap_fail {
        expected_reasons.push(NonReusableReason::SwapFail);
    }

    match derive_receipt_eligibility(&facts) {
        ReceiptEligibility::Reusable => assert!(expected_reasons.is_empty()),
        ReceiptEligibility::NonReusable(actual) => {
            assert_eq!(actual.as_slice(), expected_reasons.as_slice());
        }
    }
}
