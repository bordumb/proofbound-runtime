use std::{fs, num::NonZeroU32, path::Path};

use proofbound_runtime_verify::{
    BoundaryState, CaptureState, EligibilityDecision, EligibilityInput, FailureReason,
    OutcomeState, StructureState, derive_eligibility,
};
use serde_json::{Value, json};

const SCHEMA: &str = "proofbound-runtime-receipt-eligibility-vectors/1";

#[test]
fn independent_verifier_accepts_registered_receipt_eligibility_vectors() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = root.join("tests/conformance/receipt/positive/eligibility-v1.json");
    let bytes = fs::read(&path).expect("readable receipt eligibility catalog");
    let catalog: Value = serde_json::from_slice(&bytes).expect("valid JSON catalog");
    assert_eq!(text(&catalog, "schema"), SCHEMA);

    for case in array(&catalog, "cases") {
        let id = text(case, "id");
        let input = decode_input(object(case, "input"));
        assert_eq!(
            encode(&derive_eligibility(&input)),
            case["expected"],
            "independent receipt eligibility vector {id}"
        );
    }
}

fn decode_input(input: &Value) -> EligibilityInput {
    let boundary = match text(input, "boundary") {
        "installed" => BoundaryState::Installed,
        "incomplete" => BoundaryState::Incomplete,
        value => panic!("unsupported boundary fixture value: {value}"),
    };
    let outcome = object(input, "outcome");
    let outcome = match text(outcome, "kind") {
        "exited" => OutcomeState::Exited {
            code: i32::try_from(integer(outcome, "code")).expect("fixture exit code fits i32"),
        },
        "signaled" => OutcomeState::Signaled {
            signal: NonZeroU32::new(
                u32::try_from(unsigned_integer(outcome, "signal"))
                    .expect("fixture signal fits u32"),
            )
            .expect("fixture signal is nonzero"),
        },
        "timed-out" => OutcomeState::TimedOut,
        "denied" => OutcomeState::Denied,
        "launcher-failed" => OutcomeState::LauncherFailed,
        "incomplete" => OutcomeState::Incomplete,
        value => panic!("unsupported outcome fixture value: {value}"),
    };
    EligibilityInput::new(
        boundary,
        outcome,
        capture(input, "stdout"),
        capture(input, "stderr"),
        match text(input, "structure") {
            "valid" => StructureState::Valid,
            "malformed" => StructureState::Malformed,
            value => panic!("unsupported structure fixture value: {value}"),
        },
    )
}

fn capture(input: &Value, key: &str) -> CaptureState {
    match text(input, key) {
        "complete" => CaptureState::Complete,
        "truncated" => CaptureState::Truncated,
        value => panic!("unsupported capture fixture value: {value}"),
    }
}

fn encode(decision: &EligibilityDecision) -> Value {
    match decision {
        EligibilityDecision::Reusable => json!({ "status": "reusable", "reasons": [] }),
        EligibilityDecision::NonReusable(reasons) => json!({
            "status": "non-reusable",
            "reasons": reasons.as_slice().iter().map(reason_text).collect::<Vec<_>>()
        }),
    }
}

fn reason_text(reason: &FailureReason) -> &'static str {
    match reason {
        FailureReason::BoundaryIncomplete => "boundary-incomplete",
        FailureReason::ExitCodeNonzero => "exit-code-nonzero",
        FailureReason::ProcessSignaled => "process-signaled",
        FailureReason::TimedOut => "timed-out",
        FailureReason::Denied => "denied",
        FailureReason::LauncherFailed => "launcher-failed",
        FailureReason::ExecutionIncomplete => "execution-incomplete",
        FailureReason::StandardOutputTruncated => "stdout-truncated",
        FailureReason::StandardErrorTruncated => "stderr-truncated",
        FailureReason::ReceiptMalformed => "receipt-malformed",
    }
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .filter(|item| item.is_object())
        .expect("fixture field is an object")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .expect("fixture field is an array")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .expect("fixture field is text")
}

fn integer(value: &Value, key: &str) -> i64 {
    value
        .get(key)
        .and_then(Value::as_i64)
        .expect("fixture field is a signed integer")
}

fn unsigned_integer(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .expect("fixture field is an unsigned integer")
}
