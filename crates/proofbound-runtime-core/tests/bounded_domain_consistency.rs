//! Fail closed when duplicated bounded-domain declarations diverge.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const DOMAIN_FIELDS: [&str; 4] = ["id", "description", "cardinality", "ordering_key"];

#[derive(Clone, Debug, Eq, PartialEq)]
struct Domain {
    id: String,
    description: String,
    cardinality: i64,
    ordering_key: Vec<i64>,
}

#[derive(Clone, Debug)]
struct Manifest {
    path: PathBuf,
    value: toml::Value,
}

fn diagnostic(code: &str, detail: &str) -> String {
    format!("bounded-domain check failed: {code}: {detail}")
}

fn relative_name(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn load_manifests(root: &Path, directory: &str) -> (Vec<Manifest>, Vec<String>) {
    let manifest_root = root.join(directory);
    let mut paths = match fs::read_dir(&manifest_root) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "toml")
            })
            .collect::<Vec<_>>(),
        Err(error) => {
            return (
                Vec::new(),
                vec![diagnostic(
                    "manifest.invalid",
                    &format!("{directory} cannot be read ({})", error.kind()),
                )],
            );
        }
    };
    paths.sort();

    let mut manifests = Vec::new();
    let mut errors = Vec::new();
    for path in paths {
        let decoded = fs::read_to_string(&path)
            .map_err(|error| error.kind())
            .and_then(|text| {
                toml::from_str::<toml::Value>(&text).map_err(|_| std::io::ErrorKind::InvalidData)
            });
        match decoded {
            Ok(value) => manifests.push(Manifest { path, value }),
            Err(kind) => errors.push(diagnostic(
                "manifest.invalid",
                &format!("{} cannot be decoded ({kind})", relative_name(root, &path)),
            )),
        }
    }
    (manifests, errors)
}

fn table<'a>(value: &'a toml::Value, name: &str) -> Option<&'a toml::Table> {
    value.get(name)?.as_table()
}

fn nonempty_string(value: Option<&toml::Value>) -> Option<&str> {
    value?.as_str().filter(|value| !value.is_empty())
}

fn string_array(value: Option<&toml::Value>) -> Option<Vec<&str>> {
    value?.as_array()?.iter().map(toml::Value::as_str).collect()
}

fn parse_domain(
    raw: Option<&toml::Value>,
    owner: &str,
    source: &str,
) -> (Option<Domain>, Vec<String>) {
    let Some(raw) = raw else {
        return (
            None,
            vec![diagnostic("domain.missing", &format!("{owner} {source}"))],
        );
    };
    let Some(domain) = raw.as_table() else {
        return (
            None,
            vec![diagnostic(
                "domain.invalid",
                &format!("{owner} {source} is not a table"),
            )],
        );
    };
    let actual_fields = domain.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_fields = DOMAIN_FIELDS.into_iter().collect::<BTreeSet<_>>();
    if actual_fields != expected_fields {
        return (
            None,
            vec![diagnostic(
                "domain.invalid",
                &format!("{owner} {source} has a non-closed field set"),
            )],
        );
    }

    let Some(id) = nonempty_string(domain.get("id")) else {
        return invalid_domain(owner, source);
    };
    let Some(description) = nonempty_string(domain.get("description")) else {
        return invalid_domain(owner, source);
    };
    let Some(cardinality) = domain.get("cardinality").and_then(toml::Value::as_integer) else {
        return invalid_domain(owner, source);
    };
    let Some(ordering_key) = domain.get("ordering_key").and_then(toml::Value::as_array) else {
        return invalid_domain(owner, source);
    };
    let ordering_key = ordering_key
        .iter()
        .map(toml::Value::as_integer)
        .collect::<Option<Vec<_>>>();
    let Some(ordering_key) = ordering_key else {
        return invalid_domain(owner, source);
    };
    let unique = ordering_key.iter().copied().collect::<BTreeSet<_>>();
    if cardinality <= 0
        || ordering_key.is_empty()
        || ordering_key.iter().any(|value| *value < 0)
        || unique.len() != ordering_key.len()
    {
        return invalid_domain(owner, source);
    }

    (
        Some(Domain {
            id: id.to_owned(),
            description: description.to_owned(),
            cardinality,
            ordering_key,
        }),
        Vec::new(),
    )
}

fn invalid_domain(owner: &str, source: &str) -> (Option<Domain>, Vec<String>) {
    (
        None,
        vec![diagnostic(
            "domain.invalid",
            &format!("{owner} {source} has an invalid typed field"),
        )],
    )
}

fn first_domain_difference(left: &Domain, right: &Domain) -> Option<&'static str> {
    if left.id != right.id {
        Some("id")
    } else if left.description != right.description {
        Some("description")
    } else if left.cardinality != right.cardinality {
        Some("cardinality")
    } else if left.ordering_key != right.ordering_key {
        Some("ordering_key")
    } else {
        None
    }
}

enum ModelPath {
    Valid(PathBuf),
    Missing(PathBuf),
    Invalid(&'static str),
}

fn checked_model_path(root: &Path, raw: Option<&toml::Value>) -> ModelPath {
    let Some(raw) = nonempty_string(raw) else {
        return ModelPath::Invalid("operation manifest is not a non-empty string");
    };
    let relative = Path::new(raw);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return ModelPath::Invalid("operation manifest is not a confined relative path");
    }
    if relative
        .strip_prefix(Path::new("proofbound/model-checks"))
        .is_err()
    {
        return ModelPath::Invalid("operation manifest is outside proofbound/model-checks");
    }

    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return ModelPath::Invalid("operation manifest has a non-normal component");
        };
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return ModelPath::Invalid("operation manifest traverses a symlink");
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return ModelPath::Missing(root.join(relative));
            }
            Err(_) => return ModelPath::Invalid("operation manifest path cannot be inspected"),
        }
    }
    match fs::symlink_metadata(&current) {
        Ok(metadata) if metadata.is_file() => ModelPath::Valid(current),
        Ok(_) => ModelPath::Invalid("operation manifest is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ModelPath::Missing(current),
        Err(_) => ModelPath::Invalid("operation manifest path cannot be inspected"),
    }
}

fn manifest_id<'a>(
    root: &Path,
    manifest: &'a Manifest,
    expected_schema: &str,
    kind: &str,
) -> (Option<&'a str>, Vec<String>) {
    let id = nonempty_string(manifest.value.get("id"));
    if manifest.value.get("schema").and_then(toml::Value::as_str) != Some(expected_schema)
        || id.is_none()
    {
        return (
            None,
            vec![diagnostic(
                "manifest.invalid",
                &format!(
                    "{} is not a valid {kind} identity",
                    relative_name(root, &manifest.path)
                ),
            )],
        );
    }
    (id, Vec::new())
}

fn validate(root: &Path) -> Vec<String> {
    let (claims, mut errors) = load_manifests(root, "claims");
    let (evidence_units, evidence_errors) = load_manifests(root, "proofbound/evidence");
    errors.extend(evidence_errors);

    let mut claims_by_id: BTreeMap<&str, Vec<&Manifest>> = BTreeMap::new();
    for claim in &claims {
        let (id, identity_errors) = manifest_id(root, claim, "proofbound-claim/1", "claim");
        errors.extend(identity_errors);
        if let Some(id) = id {
            claims_by_id.entry(id).or_default().push(claim);
        }
    }
    for (claim_id, matches) in &claims_by_id {
        if matches.len() > 1 {
            errors.push(diagnostic("claim.id-duplicate", claim_id));
        }
    }

    let mut bounded_by_id: BTreeMap<&str, Vec<&Manifest>> = BTreeMap::new();
    for evidence in &evidence_units {
        if evidence.value.get("kind").and_then(toml::Value::as_str) != Some("bounded-check") {
            continue;
        }
        let (id, identity_errors) = manifest_id(
            root,
            evidence,
            "proofbound-evidence-unit/1",
            "bounded evidence",
        );
        errors.extend(identity_errors);
        if let Some(id) = id {
            bounded_by_id.entry(id).or_default().push(evidence);
        }
    }
    for (evidence_id, matches) in &bounded_by_id {
        if matches.len() > 1 {
            errors.push(diagnostic("evidence.id-duplicate", evidence_id));
        }
    }

    for (claim_id, claim_matches) in claims_by_id {
        if claim_matches.len() != 1 {
            continue;
        }
        let claim = claim_matches[0];
        let Some(references) = string_array(claim.value.get("evidence")) else {
            errors.push(diagnostic(
                "manifest.invalid",
                &format!("claim {claim_id} evidence"),
            ));
            continue;
        };
        let mut bounded_references = references
            .into_iter()
            .filter_map(|reference| reference.strip_prefix("bounded-check:"))
            .collect::<Vec<_>>();
        bounded_references.sort_unstable();
        let mut seen = BTreeSet::new();

        for evidence_id in bounded_references {
            let display_id = if evidence_id.is_empty() {
                "<empty>"
            } else {
                evidence_id
            };
            let owner = format!("claim {claim_id} evidence {display_id}");
            if evidence_id.is_empty() || !seen.insert(evidence_id) {
                errors.push(diagnostic("reference.invalid", &owner));
                continue;
            }

            let Some(evidence_matches) = bounded_by_id.get(evidence_id) else {
                errors.push(diagnostic("evidence.missing", &owner));
                continue;
            };
            if evidence_matches.len() != 1 {
                continue;
            }
            let evidence = evidence_matches[0];

            match string_array(evidence.value.get("claims")) {
                Some(evidence_claims) if !evidence_claims.contains(&claim_id) => {
                    errors.push(diagnostic("evidence.claim-missing", &owner));
                }
                None => errors.push(diagnostic(
                    "manifest.invalid",
                    &format!("{owner} evidence claims"),
                )),
                Some(_) => {}
            }

            let (claim_domain, claim_errors) =
                parse_domain(claim.value.get("bounded_domain"), &owner, "claim domain");
            let (evidence_domain, evidence_domain_errors) = parse_domain(
                evidence.value.get("bounded_domain"),
                &owner,
                "evidence domain",
            );
            errors.extend(claim_errors);
            errors.extend(evidence_domain_errors);
            if let (Some(claim_domain), Some(evidence_domain)) = (&claim_domain, &evidence_domain)
                && let Some(field) = first_domain_difference(claim_domain, evidence_domain)
            {
                errors.push(diagnostic(
                    "domain.mismatch",
                    &format!("{owner} claim/evidence field {field}"),
                ));
            }

            let operation = table(&evidence.value, "operation");
            let Some(operation) = operation else {
                errors.push(diagnostic(
                    "manifest.invalid",
                    &format!("{owner} operation"),
                ));
                continue;
            };
            let model_path = match checked_model_path(root, operation.get("manifest")) {
                ModelPath::Valid(path) => path,
                ModelPath::Missing(path) => {
                    errors.push(diagnostic(
                        "model.missing",
                        &format!("{owner} {}", relative_name(root, &path)),
                    ));
                    continue;
                }
                ModelPath::Invalid(reason) => {
                    errors.push(diagnostic(
                        "model.path-invalid",
                        &format!("{owner} {reason}"),
                    ));
                    continue;
                }
            };
            let model_value = match fs::read_to_string(&model_path)
                .map_err(|error| error.kind())
                .and_then(|text| {
                    toml::from_str::<toml::Value>(&text)
                        .map_err(|_| std::io::ErrorKind::InvalidData)
                }) {
                Ok(value) => value,
                Err(kind) => {
                    errors.push(diagnostic(
                        "manifest.invalid",
                        &format!("{owner} model cannot be decoded ({kind})"),
                    ));
                    continue;
                }
            };
            if model_value.get("schema").and_then(toml::Value::as_str)
                != Some("proofbound-model-check-unit/1")
                || model_value.get("id").and_then(toml::Value::as_str) != Some(evidence_id)
            {
                errors.push(diagnostic("model.identity-mismatch", &owner));
                continue;
            }
            match string_array(model_value.get("claims")) {
                Some(model_claims) if !model_claims.contains(&claim_id) => {
                    errors.push(diagnostic("model.claim-missing", &owner));
                }
                None => errors.push(diagnostic(
                    "manifest.invalid",
                    &format!("{owner} model claims"),
                )),
                Some(_) => {}
            }
            let (model_domain, model_errors) =
                parse_domain(model_value.get("domain"), &owner, "model domain");
            errors.extend(model_errors);
            if let (Some(evidence_domain), Some(model_domain)) = (&evidence_domain, &model_domain)
                && let Some(field) = first_domain_difference(evidence_domain, model_domain)
            {
                errors.push(diagnostic(
                    "domain.mismatch",
                    &format!("{owner} evidence/model field {field}"),
                ));
            }
        }
    }

    errors
}

#[test]
fn repository_bounded_domains_are_consistent() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let errors = validate(&root);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[cfg(test)]
mod falsifiers {
    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    const DOMAIN: &str = r#"
id = "finite-catalog"
description = "Two exact finite cases."
cardinality = 2
ordering_key = [0, 1]
"#;

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "proofbound-runtime-bounded-domain-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(root.join("claims")).unwrap();
            fs::create_dir_all(root.join("proofbound/evidence")).unwrap();
            fs::create_dir_all(root.join("proofbound/model-checks")).unwrap();
            Self { root }
        }

        fn claim(&self, filename: &str, claim_id: &str, references: &[&str], domain: Option<&str>) {
            let references = references
                .iter()
                .map(|reference| format!("\"{reference}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let domain = domain
                .map(|domain| format!("\n[bounded_domain]\n{domain}"))
                .unwrap_or_default();
            fs::write(
                self.root.join("claims").join(filename),
                format!(
                    "schema = \"proofbound-claim/1\"\nid = \"{claim_id}\"\nevidence = [{references}]\n{domain}"
                ),
            )
            .unwrap();
        }

        fn evidence(
            &self,
            filename: &str,
            evidence_id: &str,
            claims: &[&str],
            domain: Option<&str>,
            manifest: &str,
        ) {
            let claims = claims
                .iter()
                .map(|claim| format!("\"{claim}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let domain = domain
                .map(|domain| format!("\n[bounded_domain]\n{domain}"))
                .unwrap_or_default();
            fs::write(
                self.root.join("proofbound/evidence").join(filename),
                format!(
                    "schema = \"proofbound-evidence-unit/1\"\nid = \"{evidence_id}\"\nkind = \"bounded-check\"\nclaims = [{claims}]\n\n[operation]\nmanifest = \"{manifest}\"\n{domain}"
                ),
            )
            .unwrap();
        }

        fn model(&self, filename: &str, model_id: &str, claims: &[&str], domain: Option<&str>) {
            let claims = claims
                .iter()
                .map(|claim| format!("\"{claim}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let domain = domain
                .map(|domain| format!("\n[domain]\n{domain}"))
                .unwrap_or_default();
            fs::write(
                self.root.join("proofbound/model-checks").join(filename),
                format!(
                    "schema = \"proofbound-model-check-unit/1\"\nid = \"{model_id}\"\nclaims = [{claims}]\n{domain}"
                ),
            )
            .unwrap();
        }

        fn complete(&self) {
            self.claim(
                "CLAIM-001.toml",
                "CLAIM-001",
                &["bounded-check:bounds"],
                Some(DOMAIN),
            );
            self.evidence(
                "bounds.toml",
                "bounds",
                &["CLAIM-001"],
                Some(DOMAIN),
                "proofbound/model-checks/bounds.toml",
            );
            self.model("bounds.toml", "bounds", &["CLAIM-001"], Some(DOMAIN));
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn codes(errors: &[String]) -> Vec<&str> {
        errors
            .iter()
            .map(|error| error.split(": ").nth(1).unwrap())
            .collect()
    }

    #[test]
    fn exact_match_passes() {
        let fixture = Fixture::new();
        fixture.complete();
        assert!(validate(&fixture.root).is_empty());
    }

    #[test]
    fn each_claim_domain_field_mismatch_fails() {
        let mutations = [
            ("id", DOMAIN.replacen("finite-catalog", "other-catalog", 1)),
            (
                "description",
                DOMAIN.replacen("Two exact finite cases.", "A different population.", 1),
            ),
            (
                "cardinality",
                DOMAIN.replacen("cardinality = 2", "cardinality = 3", 1),
            ),
            (
                "ordering_key",
                DOMAIN.replacen("ordering_key = [0, 1]", "ordering_key = [1, 0]", 1),
            ),
        ];
        for (field, changed) in mutations {
            let fixture = Fixture::new();
            fixture.claim(
                "CLAIM-001.toml",
                "CLAIM-001",
                &["bounded-check:bounds"],
                Some(&changed),
            );
            fixture.evidence(
                "bounds.toml",
                "bounds",
                &["CLAIM-001"],
                Some(DOMAIN),
                "proofbound/model-checks/bounds.toml",
            );
            fixture.model("bounds.toml", "bounds", &["CLAIM-001"], Some(DOMAIN));
            let errors = validate(&fixture.root);
            assert_eq!(codes(&errors), ["domain.mismatch"]);
            assert!(errors[0].contains(&format!("field {field}")));
        }
    }

    #[test]
    fn model_domain_mismatch_fails() {
        let fixture = Fixture::new();
        fixture.complete();
        let changed = DOMAIN.replacen("cardinality = 2", "cardinality = 4", 1);
        fixture.model("bounds.toml", "bounds", &["CLAIM-001"], Some(&changed));
        let errors = validate(&fixture.root);
        assert_eq!(codes(&errors), ["domain.mismatch"]);
        assert!(errors[0].contains("evidence/model field cardinality"));
    }

    #[test]
    fn cross_claim_evidence_substitution_fails() {
        let fixture = Fixture::new();
        fixture.complete();
        fixture.evidence(
            "bounds.toml",
            "bounds",
            &["OTHER-002"],
            Some(DOMAIN),
            "proofbound/model-checks/bounds.toml",
        );
        assert!(codes(&validate(&fixture.root)).contains(&"evidence.claim-missing"));
    }

    #[test]
    fn mixed_domains_fail_in_stable_reference_order() {
        let fixture = Fixture::new();
        fixture.claim(
            "CLAIM-001.toml",
            "CLAIM-001",
            &["bounded-check:zeta", "bounded-check:alpha"],
            Some(DOMAIN),
        );
        fixture.evidence(
            "alpha.toml",
            "alpha",
            &["CLAIM-001"],
            Some(DOMAIN),
            "proofbound/model-checks/alpha.toml",
        );
        fixture.model("alpha.toml", "alpha", &["CLAIM-001"], Some(DOMAIN));
        let changed = DOMAIN.replacen("finite-catalog", "other-catalog", 1);
        fixture.evidence(
            "zeta.toml",
            "zeta",
            &["CLAIM-001"],
            Some(&changed),
            "proofbound/model-checks/zeta.toml",
        );
        fixture.model("zeta.toml", "zeta", &["CLAIM-001"], Some(&changed));
        let errors = validate(&fixture.root);
        assert_eq!(codes(&errors), ["domain.mismatch"]);
        assert!(errors[0].contains("evidence zeta"));
    }

    #[test]
    fn missing_and_invalid_domains_fail() {
        let fixture = Fixture::new();
        fixture.complete();
        fixture.claim(
            "CLAIM-001.toml",
            "CLAIM-001",
            &["bounded-check:bounds"],
            None,
        );
        assert_eq!(codes(&validate(&fixture.root)), ["domain.missing"]);

        let fixture = Fixture::new();
        fixture.complete();
        let invalid = DOMAIN.replacen("ordering_key = [0, 1]", "ordering_key = [0, 0]", 1);
        fixture.evidence(
            "bounds.toml",
            "bounds",
            &["CLAIM-001"],
            Some(&invalid),
            "proofbound/model-checks/bounds.toml",
        );
        assert_eq!(codes(&validate(&fixture.root)), ["domain.invalid"]);
    }

    #[test]
    fn model_paths_fail_closed() {
        let cases = [
            ("/tmp/bounds.toml", "model.path-invalid"),
            (
                "proofbound/model-checks/../../bounds.toml",
                "model.path-invalid",
            ),
            ("claims/CLAIM-001.toml", "model.path-invalid"),
            ("proofbound/model-checks/missing.toml", "model.missing"),
        ];
        for (path, expected) in cases {
            let fixture = Fixture::new();
            fixture.complete();
            fixture.evidence("bounds.toml", "bounds", &["CLAIM-001"], Some(DOMAIN), path);
            assert!(codes(&validate(&fixture.root)).contains(&expected));
        }

        let fixture = Fixture::new();
        fixture.complete();
        fixture.evidence(
            "bounds.toml",
            "bounds",
            &["CLAIM-001"],
            Some(DOMAIN),
            "proofbound/model-checks/link/bounds.toml",
        );
        std::os::unix::fs::symlink(
            fixture.root.join("proofbound/model-checks"),
            fixture.root.join("proofbound/model-checks/link"),
        )
        .unwrap();
        assert!(codes(&validate(&fixture.root)).contains(&"model.path-invalid"));
    }

    #[test]
    fn duplicate_claim_and_evidence_identities_fail() {
        let fixture = Fixture::new();
        fixture.complete();
        fixture.claim(
            "duplicate.toml",
            "CLAIM-001",
            &["bounded-check:bounds"],
            Some(DOMAIN),
        );
        fixture.evidence(
            "duplicate.toml",
            "bounds",
            &["CLAIM-001"],
            Some(DOMAIN),
            "proofbound/model-checks/bounds.toml",
        );
        assert_eq!(
            codes(&validate(&fixture.root)),
            ["claim.id-duplicate", "evidence.id-duplicate"]
        );
    }

    #[test]
    fn claim_without_bounded_evidence_needs_no_domain() {
        let fixture = Fixture::new();
        fixture.claim("CLAIM-001.toml", "CLAIM-001", &["example-test:one"], None);
        assert!(validate(&fixture.root).is_empty());
    }

    #[test]
    fn model_identity_and_claim_binding_fail_closed() {
        let fixture = Fixture::new();
        fixture.complete();
        fixture.model("bounds.toml", "other", &["CLAIM-001"], Some(DOMAIN));
        assert_eq!(codes(&validate(&fixture.root)), ["model.identity-mismatch"]);

        let fixture = Fixture::new();
        fixture.complete();
        fixture.model("bounds.toml", "bounds", &["OTHER-002"], Some(DOMAIN));
        assert_eq!(codes(&validate(&fixture.root)), ["model.claim-missing"]);
    }
}
