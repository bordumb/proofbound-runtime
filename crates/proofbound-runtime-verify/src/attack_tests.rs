//! Executes the frozen malicious-carrier receipt corpus.

use serde::Deserialize;
use serde_json::Value;

use crate::cbor::Value as Cbor;
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceAttackCatalog {
    schema: String,
    cases: Vec<ResourceAttackCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceAttackCase {
    id: String,
    path: String,
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

fn resource_catalog() -> ResourceAttackCatalog {
    toml::from_str(include_str!(
        "../../../tests/attacks/receipt/resources-v2.toml"
    ))
    .expect("version 2 resource attack catalog is valid")
}

#[test]
fn frozen_v2_resource_attack_catalog_is_closed() {
    let expected = [
        "configured-processes",
        "configured-memory",
        "configured-swap",
        "configured-oom-group",
        "terminal-memory-peak",
        "terminal-swap-peak",
        "terminal-memory-low",
        "terminal-memory-high",
        "terminal-memory-max",
        "terminal-memory-oom",
        "terminal-memory-oom-kill",
        "terminal-memory-oom-group-kill",
        "terminal-swap-max",
        "terminal-swap-fail",
        "derived-limit-events",
        "derived-outcome",
        "derived-nonreuse-reason",
    ];
    let catalog = resource_catalog();
    assert_eq!(
        catalog.schema,
        "proofbound-runtime-receipt-resource-attacks/2"
    );
    assert_eq!(catalog.cases.len(), expected.len());
    for (case, expected_id) in catalog.cases.iter().zip(expected) {
        assert_eq!(case.id, expected_id);
        assert!(!case.path.is_empty());
        assert!(!case.expected_error.is_empty());
    }
}

#[test]
fn verifier_rejects_every_v2_resource_mutation() {
    let original = v2_golden_bytes();
    verify_receipt(&original, ReceiptCommitment::for_bytes(&original))
        .expect("the independently decoded version 2 golden verifies");
    let original_commitment = ReceiptCommitment::for_bytes(&original);

    for case in resource_catalog().cases {
        let mut value = crate::cbor::decode(&original).expect("golden CBOR decodes");
        mutate_cbor_path(&mut value, &case.path);
        let mutated = encode_cbor(&value);
        assert_ne!(mutated, original, "attack {} must alter bytes", case.id);
        let error = verify_receipt(&mutated, original_commitment)
            .expect_err("every committed resource mutation must fail");
        assert_eq!(error.code(), case.expected_error, "attack {}", case.id);
    }
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

fn v2_golden_bytes() -> Vec<u8> {
    let encoded = include_str!("../../../schemas/vectors/v2/execution-receipt.cbor.hex");
    let digits = encoded
        .bytes()
        .filter(|byte| byte.is_ascii_hexdigit())
        .collect::<Vec<_>>();
    assert_eq!(digits.len() % 2, 0, "golden hex must contain byte pairs");
    digits
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("hex digits are UTF-8");
            u8::from_str_radix(text, 16).expect("golden contains hexadecimal digits")
        })
        .collect()
}

fn mutate_cbor_path(value: &mut Cbor, path: &str) {
    let mut components = path
        .strip_prefix('/')
        .expect("registered path begins with slash")
        .split('/');
    mutate_cbor_components(value, &mut components, path, path);
}

fn mutate_cbor_components<'a>(
    value: &mut Cbor,
    components: &mut impl Iterator<Item = &'a str>,
    path: &str,
    full_path: &str,
) {
    let Some(component) = components.next() else {
        if matches!(
            full_path,
            "/resources/configured/memory.max" | "/resources/configured/memory.swap.max"
        ) {
            let Cbor::Unsigned(number) = value else {
                panic!("registered byte limit is not unsigned");
            };
            *number = number.checked_add(65_536).expect("golden limit increments");
        } else {
            mutate_cbor_value(value);
        }
        return;
    };
    let Cbor::Map(fields) = value else {
        panic!("registered path {path} traverses a non-map value");
    };
    let field = fields
        .iter_mut()
        .find(|(name, _)| name == component)
        .unwrap_or_else(|| panic!("registered path {path} names a missing field"));
    mutate_cbor_components(&mut field.1, components, path, full_path);
}

fn mutate_cbor_value(value: &mut Cbor) {
    match value {
        Cbor::Unsigned(number) => *number = number.checked_add(1).expect("golden value increments"),
        Cbor::Negative(number) => *number = number.checked_add(1).expect("golden value increments"),
        Cbor::Bytes(bytes) => bytes.push(0),
        Cbor::Text(text) => text.push_str("-mutated"),
        Cbor::Array(values) => values.push(Cbor::Text("memory-max".to_owned())),
        Cbor::Map(fields) => mutate_cbor_value(
            &mut fields
                .first_mut()
                .expect("registered map mutation is nonempty")
                .1,
        ),
        Cbor::Bool(value) => *value = !*value,
        Cbor::Null => *value = Cbor::Bool(false),
    }
}

fn encode_cbor(value: &Cbor) -> Vec<u8> {
    let mut output = Vec::new();
    encode_cbor_item(value, &mut output);
    output
}

fn encode_cbor_item(value: &Cbor, output: &mut Vec<u8>) {
    match value {
        Cbor::Unsigned(value) => encode_cbor_argument(0, *value, output),
        Cbor::Negative(value) => encode_cbor_argument(1, *value, output),
        Cbor::Bytes(value) => {
            encode_cbor_argument(2, value.len() as u64, output);
            output.extend_from_slice(value);
        }
        Cbor::Text(value) => {
            encode_cbor_argument(3, value.len() as u64, output);
            output.extend_from_slice(value.as_bytes());
        }
        Cbor::Array(values) => {
            encode_cbor_argument(4, values.len() as u64, output);
            for value in values {
                encode_cbor_item(value, output);
            }
        }
        Cbor::Map(fields) => {
            encode_cbor_argument(5, fields.len() as u64, output);
            for (name, value) in fields {
                encode_cbor_item(&Cbor::Text(name.clone()), output);
                encode_cbor_item(value, output);
            }
        }
        Cbor::Bool(false) => output.push(0xf4),
        Cbor::Bool(true) => output.push(0xf5),
        Cbor::Null => output.push(0xf6),
    }
}

fn encode_cbor_argument(major: u8, value: u64, output: &mut Vec<u8>) {
    if value < 24 {
        output.push((major << 5) | value as u8);
    } else if let Ok(value) = u8::try_from(value) {
        output.extend_from_slice(&[(major << 5) | 24, value]);
    } else if let Ok(value) = u16::try_from(value) {
        output.push((major << 5) | 25);
        output.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        output.push((major << 5) | 26);
        output.extend_from_slice(&value.to_be_bytes());
    } else {
        output.push((major << 5) | 27);
        output.extend_from_slice(&value.to_be_bytes());
    }
}
