#![forbid(unsafe_code)]

//! Contains the bounded receipt eligibility proof harness.

#[cfg(kani)]
use proofbound_runtime_core::{
    BoundaryInstallation, ExecutionOutcome, NonReusableReason, ReceiptEligibility, ReceiptFacts,
    ReceiptStructure, SignalNumber, StreamCapture, derive_receipt_eligibility,
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
    let facts = ReceiptFacts::new(boundary, outcome, stdout, stderr, structure);
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

    match derive_receipt_eligibility(&facts) {
        ReceiptEligibility::Reusable => assert!(expected_reasons.is_empty()),
        ReceiptEligibility::NonReusable(actual) => {
            assert_eq!(actual.as_slice(), expected_reasons.as_slice());
        }
    }
}
