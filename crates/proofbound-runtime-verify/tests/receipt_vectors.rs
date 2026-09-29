use std::{fs, num::NonZeroU32, path::Path};

use proofbound_runtime_verify::{
    BoundaryState, CaptureState, EligibilityDecision, EligibilityInput, FailureReason,
    OutcomeState, ReceiptCommitment, StructureState, ValidationError, VerifyError,
    derive_eligibility, verify_egress_observation_fragment, verify_receipt,
};
use serde_json::{Value, json};

const SCHEMA: &str = "proofbound-runtime-receipt-eligibility-vectors/1";

#[test]
fn version_two_wire_golden_is_a_semantically_valid_reusable_receipt() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = fs::read_to_string(root.join("schemas/vectors/v2/execution-receipt.cbor.hex"))
        .expect("v2 receipt golden reads");
    let bytes = text
        .trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("hex pair"), 16)
                .expect("golden is hex")
        })
        .collect::<Vec<_>>();

    verify_receipt(&bytes, ReceiptCommitment::for_bytes(&bytes))
        .expect("v2 receipt golden verifies independently");
}

#[test]
fn version_three_deny_receipt_and_egress_observation_have_independent_decoders() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let decode_hex = |path: &str| {
        let text = fs::read_to_string(root.join(path)).expect("golden reads");
        text.trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(core::str::from_utf8(pair).expect("hex pair"), 16)
                    .expect("golden is hex")
            })
            .collect::<Vec<_>>()
    };
    let deny = decode_hex("schemas/vectors/v3/execution-receipt.cbor.hex");
    verify_receipt(&deny, ReceiptCommitment::for_bytes(&deny))
        .expect("v3 deny receipt verifies independently");
    let observation = decode_hex("schemas/vectors/v3/egress-observation.cbor.hex");
    let policy =
        decode_hex_digest("a1f3213efa75646da3c7ad99e04c89b5ae712a22dbfa9c55af33f2c98209ab3c");
    let decision = verify_egress_observation_fragment(&observation, &policy)
        .expect("v3 egress observation verifies independently");
    assert!(decision.authority_rejection);
    assert!(!decision.proxy_failed);
}

#[test]
fn version_three_declared_egress_receipt_derives_non_reuse_independently() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text =
        fs::read_to_string(root.join("schemas/vectors/v3/execution-receipt-egress.cbor.hex"))
            .expect("declared-egress receipt golden reads");
    let bytes = text
        .trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("hex pair"), 16)
                .expect("golden is hex")
        })
        .collect::<Vec<_>>();
    let report = verify_receipt(&bytes, ReceiptCommitment::for_bytes(&bytes))
        .expect("declared-egress receipt verifies independently");
    let EligibilityDecision::NonReusable(reasons) = report.eligibility() else {
        panic!("declared authority rejection must prevent reuse");
    };
    assert_eq!(reasons.as_slice(), [FailureReason::EgressRequestDenied]);

    let proxy_digest =
        decode_hex_digest("1241936d4dd3aad68fe7bfbdfe854b935926bc678fc72377e15166078916227a");
    let offset = bytes
        .windows(proxy_digest.len())
        .position(|window| window == proxy_digest)
        .expect("observation contains proxy executable identity");
    let mut substituted = bytes.clone();
    substituted[offset] ^= 1;
    assert_eq!(
        verify_receipt(&substituted, ReceiptCommitment::for_bytes(&substituted)),
        Err(VerifyError::Validation(ValidationError::TcbRoleMissing)),
    );
}

#[test]
fn version_three_declared_egress_success_is_reusable() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = fs::read_to_string(
        root.join("schemas/vectors/v3/execution-receipt-egress-success.cbor.hex"),
    )
    .expect("declared-egress success golden reads");
    let bytes = text
        .trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("hex pair"), 16)
                .expect("golden is hex")
        })
        .collect::<Vec<_>>();
    let report = verify_receipt(&bytes, ReceiptCommitment::for_bytes(&bytes))
        .expect("declared-egress success verifies independently");
    assert_eq!(report.eligibility(), &EligibilityDecision::Reusable);
}

fn decode_hex_digest(text: &str) -> [u8; 32] {
    let mut output = [0; 32];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        output[index] = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    output
}

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
        FailureReason::MemoryHigh => "memory-high",
        FailureReason::MemoryMax => "memory-max",
        FailureReason::MemoryOom => "memory-oom",
        FailureReason::MemoryOomKill => "memory-oom-kill",
        FailureReason::MemoryOomGroupKill => "memory-oom-group-kill",
        FailureReason::SwapMax => "swap-max",
        FailureReason::SwapFail => "swap-fail",
        FailureReason::EgressRequestDenied => "egress-request-denied",
        FailureReason::EgressSniDenied => "egress-sni-denied",
        FailureReason::EgressLimitReached => "egress-limit-reached",
        FailureReason::EgressProxyFailed => "egress-proxy-failed",
        FailureReason::EgressCleanupIncomplete => "egress-cleanup-incomplete",
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
