//! Executes the frozen malicious-carrier receipt corpus.

use serde::Deserialize;
use serde_json::Value;

use crate::test_support::{bytes, receipt};
use crate::{ReceiptCommitment, verify_receipt};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttackCatalog {
    schema: String,
    cases: Vec<AttackCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttackCase {
    id: String,
    mutation: String,
    detection: Detection,
    expected_error: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Detection {
    LocalStructure,
    LocalCanonical,
    ExternalCommitment,
}

fn catalog() -> AttackCatalog {
    toml::from_str(include_str!(
        "../../../tests/attacks/receipt/receipt-v1.toml"
    ))
    .expect("receipt carrier attack catalog is valid")
}

#[test]
fn frozen_carrier_attack_catalog_is_closed() {
    let catalog = catalog();
    assert_eq!(catalog.schema, "proofbound-runtime-receipt-attacks/1");
    assert_eq!(catalog.cases.len(), 22);
    assert_eq!(count(&catalog, Detection::LocalStructure), 3);
    assert_eq!(count(&catalog, Detection::LocalCanonical), 2);
    assert_eq!(count(&catalog, Detection::ExternalCommitment), 17);
    for case in catalog.cases {
        assert!(!case.id.is_empty());
        assert!(!case.mutation.is_empty());
        assert!(!case.expected_error.is_empty());
    }
}

fn count(catalog: &AttackCatalog, detection: Detection) -> usize {
    catalog
        .cases
        .iter()
        .filter(|case| case.detection == detection)
        .count()
}

#[test]
fn verifier_rejects_every_registered_carrier_attack() {
    for case in catalog().cases {
        let original = original_for(&case.mutation);
        let original_bytes = bytes(&original);
        let commitment = ReceiptCommitment::for_bytes(&original_bytes);
        let mutated = mutate(&case.mutation, original, &original_bytes);
        assert_ne!(
            mutated, original_bytes,
            "attack {} must alter bytes",
            case.id
        );
        let error = verify_receipt(&mutated, commitment)
            .expect_err("every registered malicious-carrier mutation must fail");
        assert_eq!(error.code(), case.expected_error, "attack {}", case.id);
    }
}

fn original_for(mutation: &str) -> Value {
    let mut value = receipt();
    match mutation {
        "mark-truncated-stdout-complete" => {
            value["streams"]["stdout"]["capture"] = Value::String("truncated".to_owned());
            non_reusable(&mut value, &["stdout-truncated"]);
        }
        "mark-truncated-stderr-complete" => {
            value["streams"]["stderr"]["capture"] = Value::String("truncated".to_owned());
            non_reusable(&mut value, &["stderr-truncated"]);
        }
        "replace-non-reusable-eligibility" => {
            value["outcome"] = serde_json::json!({"kind": "denied"});
            non_reusable(&mut value, &["denied"]);
        }
        _ => {}
    }
    value
}

fn non_reusable(value: &mut Value, reasons: &[&str]) {
    value["eligibility"] = serde_json::json!({
        "status": "non-reusable",
        "reasons": reasons
    });
}

fn mutate(mutation: &str, mut value: Value, original: &[u8]) -> Vec<u8> {
    match mutation {
        "omit-plan" => remove(&mut value, "plan"),
        "substitute-normalized-plan-identity" => {
            value["plan"]["normalized"]["sha256"] = digest("0")
        }
        "omit-policy" => remove(&mut value, "policy"),
        "substitute-policy-identity" => value["policy"]["identity"]["sha256"] = digest("0"),
        "substitute-platform-capability" => {
            value["platform"]["kernel_release"] = Value::String("6.13.0".to_owned())
        }
        "substitute-runtime-identity" => value["runtime"]["runtime"]["sha256"] = digest("0"),
        "substitute-launcher-identity" => value["runtime"]["launcher"]["sha256"] = digest("0"),
        "substitute-executable-identity" => value["command"]["executable"]["sha256"] = digest("0"),
        "omit-required-loader" => value["command"]["loader"] = Value::Null,
        "substitute-working-directory-identity" => {
            value["command"]["working_directory"]["sha256"] = digest("0")
        }
        "substitute-input-identity" => value["inputs"][1]["sha256"] = digest("0"),
        "substitute-output-root-identity" => value["output_root"]["sha256"] = digest("0"),
        "substitute-output-artifact-identity" => value["outputs"][0]["sha256"] = digest("0"),
        "mark-truncated-stdout-complete" => {
            value["streams"]["stdout"]["capture"] = Value::String("complete".to_owned())
        }
        "mark-truncated-stderr-complete" => {
            value["streams"]["stderr"]["capture"] = Value::String("complete".to_owned())
        }
        "replace-non-reusable-eligibility" => {
            value["eligibility"] = serde_json::json!({"status": "reusable", "reasons": []})
        }
        "duplicate-policy-field" => return duplicate_policy(original),
        "reorder-object-members" => return reorder_schema_first(original),
        "substitute-schema-version" => {
            value["schema"] = Value::String("proofbound-runtime-receipt/2".to_owned())
        }
        "substitute-execution-id" => {
            value["execution_id"] = Value::String("ffeeddcc-bbaa-4988-8899-001122334455".to_owned())
        }
        "remove-inherited-assumption" => {
            value["assumptions"]
                .as_array_mut()
                .expect("fixture assumptions are an array")
                .pop();
        }
        "remove-trusted-computing-base-role" => {
            value["trusted_computing_base"]
                .as_array_mut()
                .expect("fixture TCB is an array")
                .pop();
        }
        other => panic!("unimplemented registered mutation: {other}"),
    }
    bytes(&value)
}

fn remove(value: &mut Value, key: &str) {
    value
        .as_object_mut()
        .expect("fixture receipt is an object")
        .remove(key)
        .expect("registered field exists");
}

fn digest(marker: &str) -> Value {
    Value::String(marker.repeat(64))
}

fn duplicate_policy(original: &[u8]) -> Vec<u8> {
    String::from_utf8(original.to_vec())
        .expect("fixture is UTF-8")
        .replacen("\"policy\":{", "\"policy\":{},\"policy\":{", 1)
        .into_bytes()
}

fn reorder_schema_first(original: &[u8]) -> Vec<u8> {
    let canonical = String::from_utf8(original.to_vec()).expect("fixture is UTF-8");
    let schema = "\"schema\":\"proofbound-runtime-receipt/1\"";
    let without_schema = canonical.replacen(&format!(",{schema}"), "", 1);
    format!("{{{schema},{}", &without_schema[1..]).into_bytes()
}
