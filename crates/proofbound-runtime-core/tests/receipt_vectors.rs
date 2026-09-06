use std::{fs, num::NonZeroU32, path::Path};

use proofbound_runtime_core::{
    BoundaryInstallation, ExecutionOutcome, NonReusableReason, ReceiptEligibility, ReceiptFacts,
    ReceiptStructure, StreamCapture, derive_receipt_eligibility,
};
use serde_json::{Value, json};

const SCHEMA: &str = "proofbound-runtime-receipt-eligibility-vectors/1";

#[test]
fn producer_accepts_registered_receipt_eligibility_vectors() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = root.join("tests/conformance/receipt/positive/eligibility-v1.json");
    let bytes = fs::read(&path).expect("readable receipt eligibility catalog");
    let catalog: Value = serde_json::from_slice(&bytes).expect("valid JSON catalog");
    assert_eq!(text(&catalog, "schema"), SCHEMA);

    for case in array(&catalog, "cases") {
        let id = text(case, "id");
        let facts = parse_facts(object(case, "input"));
        assert_eq!(
            encode(&derive_receipt_eligibility(&facts)),
            case["expected"],
            "receipt eligibility vector {id}"
        );
    }
}

fn parse_facts(input: &Value) -> ReceiptFacts {
    let boundary = match text(input, "boundary") {
        "installed" => BoundaryInstallation::Installed,
        "incomplete" => BoundaryInstallation::Incomplete,
        value => panic!("unsupported boundary fixture value: {value}"),
    };
    let outcome = object(input, "outcome");
    let outcome = match text(outcome, "kind") {
        "exited" => ExecutionOutcome::Exited {
            code: i32::try_from(integer(outcome, "code")).expect("fixture exit code fits i32"),
        },
        "signaled" => ExecutionOutcome::Signaled {
            signal: NonZeroU32::new(
                u32::try_from(unsigned_integer(outcome, "signal"))
                    .expect("fixture signal fits u32"),
            )
            .expect("fixture signal is nonzero"),
        },
        "timed-out" => ExecutionOutcome::TimedOut,
        "denied" => ExecutionOutcome::Denied,
        "launcher-failed" => ExecutionOutcome::LauncherFailed,
        "incomplete" => ExecutionOutcome::Incomplete,
        value => panic!("unsupported outcome fixture value: {value}"),
    };
    ReceiptFacts::new(
        boundary,
        outcome,
        capture(input, "stdout"),
        capture(input, "stderr"),
        match text(input, "structure") {
            "valid" => ReceiptStructure::Valid,
            "malformed" => ReceiptStructure::Malformed,
            value => panic!("unsupported structure fixture value: {value}"),
        },
    )
}

fn capture(input: &Value, key: &str) -> StreamCapture {
    match text(input, key) {
        "complete" => StreamCapture::Complete,
        "truncated" => StreamCapture::Truncated,
        value => panic!("unsupported stream capture fixture value: {value}"),
    }
}

fn encode(eligibility: &ReceiptEligibility) -> Value {
    match eligibility {
        ReceiptEligibility::Reusable => json!({ "status": "reusable", "reasons": [] }),
        ReceiptEligibility::NonReusable(reasons) => json!({
            "status": "non-reusable",
            "reasons": reasons.as_slice().iter().map(reason_text).collect::<Vec<_>>()
        }),
    }
}

fn reason_text(reason: &NonReusableReason) -> &'static str {
    match reason {
        NonReusableReason::BoundaryIncomplete => "boundary-incomplete",
        NonReusableReason::ExitCodeNonzero => "exit-code-nonzero",
        NonReusableReason::ProcessSignaled => "process-signaled",
        NonReusableReason::TimedOut => "timed-out",
        NonReusableReason::Denied => "denied",
        NonReusableReason::LauncherFailed => "launcher-failed",
        NonReusableReason::ExecutionIncomplete => "execution-incomplete",
        NonReusableReason::StandardOutputTruncated => "stdout-truncated",
        NonReusableReason::StandardErrorTruncated => "stderr-truncated",
        NonReusableReason::ReceiptMalformed => "receipt-malformed",
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
