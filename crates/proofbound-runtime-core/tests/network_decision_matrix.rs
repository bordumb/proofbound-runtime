//! Fail closed when the pre-registered network decision domain is incomplete.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const MATRIX_TEXT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../experiments/network_authority/decision-matrix.toml"
));
const INVENTORY_TEXT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../experiments/network_authority/decision-matrix-inventory.txt"
));
const ARCHITECTURES: [&str; 2] = ["aarch64", "x86_64"];
const OUTCOMES: [&str; 4] = [
    "allowed",
    "denied",
    "exposes-limitation",
    "unsupported-before-launch",
];
const STAGES: [&str; 9] = [
    "application-protocol",
    "child-boundary",
    "cleanup",
    "lifecycle",
    "plan",
    "prelaunch",
    "resolver",
    "routing",
    "tls",
];
const SLICES: [&str; 3] = [
    "bypass-lifecycle",
    "resolution-indirection",
    "routing-transport",
];
const FIXTURES: [&str; 7] = [
    "dual-stack-tls",
    "lifecycle",
    "proxy-service",
    "publication",
    "redirect-service",
    "scripted-dns",
    "socket-bypass",
];
const ATTEMPTED_AUTHORITIES: [&str; 13] = [
    "application-operation",
    "boundary-lifecycle",
    "child-network",
    "connection-count",
    "inherited-socket",
    "kernel-async",
    "local-socket",
    "process-tree",
    "resolver-policy",
    "result-publication",
    "routing-endpoint",
    "service-session",
    "subject-identity",
];
const PARENT_ROWS: [&str; 24] = [
    "address-encodings",
    "ambient-overrides",
    "bind-listen",
    "broker-connector-crash",
    "cleanup-failure",
    "cname-allowed",
    "cname-undeclared",
    "direct-tcp-other-port",
    "direct-udp",
    "dns-answer-change",
    "exact-service",
    "inherited-internet-socket",
    "install-race",
    "io-uring",
    "literal-ip",
    "process-tree",
    "proxy-tunnel",
    "redirect",
    "resolver-failures",
    "result-replacement",
    "subject-substitution",
    "undeclared-service-443",
    "unix-sockets",
    "wrong-certificate",
];
const MECHANISMS: [&str; 4] = [
    "cgroup-endpoint",
    "explicit-broker",
    "landlock-port",
    "preconnected-channel",
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Matrix {
    schema: String,
    architectures: Vec<String>,
    outcomes: Vec<String>,
    stages: Vec<String>,
    slices: Vec<String>,
    fixtures: Vec<String>,
    attempted_authorities: Vec<String>,
    parent_rows: Vec<String>,
    mechanisms: Vec<Mechanism>,
    cases: Vec<Case>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mechanism {
    id: String,
    service_identity_enforcement: String,
    may_enter_adr_comparison: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    slice: String,
    parent_rows: Vec<String>,
    fixture: String,
    attempted_authority: String,
    authority_exposure: bool,
    maximum_seconds: i64,
    expectations: Vec<String>,
}

fn set(values: impl IntoIterator<Item = impl AsRef<str>>) -> BTreeSet<String> {
    values
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect()
}

fn exact_domain(actual: &[String], expected: &[&str], label: &str, errors: &mut Vec<String>) {
    if actual.len() != expected.len() || set(actual) != set(expected) {
        errors.push(format!("domain.{label}"));
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn parse_expectation(value: &str) -> Option<(&str, &str, &str)> {
    let (mechanism, rest) = value.split_once('=')?;
    let (outcome, stage) = rest.split_once('@')?;
    if mechanism.is_empty() || outcome.is_empty() || stage.is_empty() || stage.contains(['=', '@'])
    {
        return None;
    }
    Some((mechanism, outcome, stage))
}

fn validate(matrix: &Matrix, inventory: &str) -> Vec<String> {
    let mut errors = Vec::new();
    if matrix.schema != "proofbound-runtime-network-decision-matrix/1" {
        errors.push("schema".to_owned());
    }
    exact_domain(
        &matrix.architectures,
        &ARCHITECTURES,
        "architectures",
        &mut errors,
    );
    exact_domain(&matrix.outcomes, &OUTCOMES, "outcomes", &mut errors);
    exact_domain(&matrix.stages, &STAGES, "stages", &mut errors);
    exact_domain(&matrix.slices, &SLICES, "slices", &mut errors);
    exact_domain(&matrix.fixtures, &FIXTURES, "fixtures", &mut errors);
    exact_domain(
        &matrix.attempted_authorities,
        &ATTEMPTED_AUTHORITIES,
        "attempted-authorities",
        &mut errors,
    );
    exact_domain(
        &matrix.parent_rows,
        &PARENT_ROWS,
        "parent-rows",
        &mut errors,
    );

    let mechanism_ids = matrix
        .mechanisms
        .iter()
        .map(|mechanism| mechanism.id.as_str())
        .collect::<Vec<_>>();
    if mechanism_ids.len() != MECHANISMS.len() || set(&mechanism_ids) != set(MECHANISMS) {
        errors.push("mechanisms.identity".to_owned());
    }
    for mechanism in &matrix.mechanisms {
        let trusted = mechanism.service_identity_enforcement == "trusted-mediator";
        let untrusted = mechanism.service_identity_enforcement == "untrusted-child";
        if (!trusted && !untrusted) || mechanism.may_enter_adr_comparison != trusted {
            errors.push(format!("mechanism.eligibility.{}", mechanism.id));
        }
    }

    let known_outcomes = set(&matrix.outcomes);
    let known_stages = set(&matrix.stages);
    let known_slices = set(&matrix.slices);
    let known_fixtures = set(&matrix.fixtures);
    let known_authorities = set(&matrix.attempted_authorities);
    let known_rows = set(&matrix.parent_rows);
    let known_mechanisms = set(&mechanism_ids);
    let mut case_ids = BTreeSet::new();
    let mut covered_rows = BTreeSet::new();
    let mut slice_counts: BTreeMap<&str, usize> = BTreeMap::new();

    for case in &matrix.cases {
        if !valid_id(&case.id) || !case_ids.insert(case.id.as_str()) {
            errors.push(format!("case.identity.{}", case.id));
        }
        if !known_slices.contains(&case.slice) {
            errors.push(format!("case.slice.{}", case.id));
        } else {
            *slice_counts.entry(&case.slice).or_default() += 1;
        }
        if !known_fixtures.contains(&case.fixture) {
            errors.push(format!("case.fixture.{}", case.id));
        }
        if !known_authorities.contains(&case.attempted_authority) {
            errors.push(format!("case.authority.{}", case.id));
        }
        if !(1..=60).contains(&case.maximum_seconds) {
            errors.push(format!("case.deadline.{}", case.id));
        }
        if case.parent_rows.is_empty() || set(&case.parent_rows).len() != case.parent_rows.len() {
            errors.push(format!("case.parent-rows.{}", case.id));
        }
        for row in &case.parent_rows {
            if known_rows.contains(row) {
                covered_rows.insert(row.clone());
            } else {
                errors.push(format!("case.parent-row.{}.{}", case.id, row));
            }
        }

        let mut expectations = BTreeMap::new();
        let mut exposes = false;
        for raw in &case.expectations {
            let Some((mechanism, outcome, stage)) = parse_expectation(raw) else {
                errors.push(format!("expectation.grammar.{}", case.id));
                continue;
            };
            if !known_mechanisms.contains(mechanism)
                || expectations.insert(mechanism, (outcome, stage)).is_some()
            {
                errors.push(format!("expectation.mechanism.{}.{}", case.id, mechanism));
            }
            if !known_outcomes.contains(outcome) {
                errors.push(format!("expectation.outcome.{}.{}", case.id, outcome));
            }
            if !known_stages.contains(stage) {
                errors.push(format!("expectation.stage.{}.{}", case.id, stage));
            }
            exposes |= outcome == "exposes-limitation";
        }
        if set(expectations.keys().copied()) != known_mechanisms {
            errors.push(format!("expectation.coverage.{}", case.id));
        }
        if exposes != case.authority_exposure {
            errors.push(format!("expectation.exposure.{}", case.id));
        }
    }

    if covered_rows != known_rows {
        errors.push("coverage.parent-rows".to_owned());
    }
    if matrix
        .slices
        .iter()
        .any(|slice| slice_counts.get(slice.as_str()).copied().unwrap_or(0) == 0)
    {
        errors.push("coverage.slices".to_owned());
    }
    let generated_inventory = matrix
        .cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    if generated_inventory != inventory {
        errors.push("inventory.drift".to_owned());
    }
    errors.sort();
    errors.dedup();
    errors
}

fn repository_matrix() -> Matrix {
    toml::from_str(MATRIX_TEXT).expect("decision matrix must decode")
}

#[test]
fn repository_network_decision_domain_is_complete() {
    assert_eq!(
        validate(&repository_matrix(), INVENTORY_TEXT),
        Vec::<String>::new()
    );
}

#[test]
fn duplicate_case_and_missing_mechanism_fail_closed() {
    let mut matrix = repository_matrix();
    matrix.cases.push(matrix.cases[0].clone());
    matrix.cases[0].expectations.pop();
    let errors = validate(&matrix, INVENTORY_TEXT);
    assert!(
        errors
            .iter()
            .any(|error| error.starts_with("case.identity."))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.starts_with("expectation.coverage."))
    );
}

#[test]
fn unknown_domain_and_untrusted_eligibility_fail_closed() {
    let mut matrix = repository_matrix();
    matrix.cases[0].expectations[0] = "landlock-port=success@magic".to_owned();
    matrix.mechanisms[0].may_enter_adr_comparison = true;
    let errors = validate(&matrix, INVENTORY_TEXT);
    assert!(
        errors
            .iter()
            .any(|error| error.starts_with("expectation.outcome."))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.starts_with("expectation.stage."))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.starts_with("mechanism.eligibility."))
    );
}

#[test]
fn parent_coverage_exposure_and_inventory_drift_fail_closed() {
    let mut matrix = repository_matrix();
    matrix.cases.retain(|case| {
        !case
            .parent_rows
            .iter()
            .any(|row| row == "result-replacement")
    });
    matrix.cases[0].authority_exposure = true;
    let errors = validate(&matrix, "wrong\n");
    assert!(errors.contains(&"coverage.parent-rows".to_owned()));
    assert!(
        errors
            .iter()
            .any(|error| error.starts_with("expectation.exposure."))
    );
    assert!(errors.contains(&"inventory.drift".to_owned()));
}
