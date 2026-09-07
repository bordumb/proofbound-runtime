#![forbid(unsafe_code)]

//! Validates and composes exact Proofbound release and Runtime execution facts.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const COMPOSITION_SCHEMA: &str = "proofbound-runtime-composed-receipt/1";
const COMPOSITION_DOMAIN: &[u8] = b"proofbound-runtime-composed-receipt/1\n";
const RELEASE_ENVELOPE_SCHEMA: &str = "proofbound-release-envelope/3";
const RELEASE_REPORT_SCHEMA: &str = "proofbound-verification-report/1";
const COMPILED_RELEASE_SCHEMA: &str = "proofbound-compiled-release/3";
const RELEASE_MANIFEST_SCHEMA: &str = "proofbound-runtime-release-manifest/1";
const EXECUTION_RECEIPT_SCHEMA: &str = "proofbound-runtime-receipt/1";

/// One exact byte carrier supplied to the pure composition boundary.
#[derive(Clone, Copy)]
pub struct ArtifactBytes<'a> {
    /// Stable logical name used in the composed receipt.
    pub name: &'a str,
    /// Exact carrier bytes.
    pub bytes: &'a [u8],
}

/// All independently obtained inputs needed for one composition.
pub struct CompositionInputs<'a> {
    pub release_envelope: ArtifactBytes<'a>,
    pub compiled_release: ArtifactBytes<'a>,
    pub release_verification: ArtifactBytes<'a>,
    pub release_verifier: ArtifactBytes<'a>,
    pub release_tcb_ledger: ArtifactBytes<'a>,
    pub runtime_manifest: ArtifactBytes<'a>,
    pub runtime: ArtifactBytes<'a>,
    pub launcher: ArtifactBytes<'a>,
    pub execution_verifier: ArtifactBytes<'a>,
    pub composer: ArtifactBytes<'a>,
    pub execution_receipt: ArtifactBytes<'a>,
    pub execution_verification: ArtifactBytes<'a>,
    pub expected_execution_commitment: &'a str,
    pub expected_execution_id: &'a str,
}

/// One fail-closed composition failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositionError {
    SchemaInvalid,
    ReleaseClaimOmitted,
    ReleaseSubstituted,
    ReleaseDowngraded,
    BundleSubstituted,
    BundleRoleMismatch,
    ExecutionReplayed,
    AssumptionOmitted,
    TrustedComputingBaseOmitted,
    ExecutionInvalid,
    CompositionMismatch,
}

impl CompositionError {
    /// Returns the stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SchemaInvalid => "composition.schema.invalid",
            Self::ReleaseClaimOmitted => "composition.release.claim-omitted",
            Self::ReleaseSubstituted => "composition.release.substituted",
            Self::ReleaseDowngraded => "composition.release.downgraded",
            Self::BundleSubstituted => "composition.bundle.substituted",
            Self::BundleRoleMismatch => "composition.bundle.role-mismatch",
            Self::ExecutionReplayed => "composition.execution.replayed",
            Self::AssumptionOmitted => "composition.assumption.omitted",
            Self::TrustedComputingBaseOmitted => "composition.tcb.omitted",
            Self::ExecutionInvalid => "composition.execution.invalid",
            Self::CompositionMismatch => "composition.receipt.mismatch",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEnvelope {
    payload: String,
    payload_sha256: String,
    schema: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimStatus {
    assumption: String,
    assumptions: Vec<String>,
    claim_id: String,
    formal: String,
    linkage: String,
    policy_admitted: bool,
    public_statement: String,
    undischarged_premises: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseReport {
    claims: Vec<ClaimStatus>,
    not_proved_out_of_scope: Value,
    payload_sha256: String,
    project: String,
    project_revision: String,
    publication_blocked: bool,
    schema: String,
    trust_boundary: String,
    verdict: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompiledRelease {
    assumptions: Value,
    claims: Value,
    closures: Value,
    evidence: Value,
    graph: Value,
    graph_sha256: String,
    policies: Value,
    premises: Value,
    project: String,
    project_revision: String,
    project_tier: u8,
    reported_statuses: Vec<ClaimStatus>,
    schema: String,
    sealed_files: Value,
    tree_state: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TcbLedger {
    components: Vec<ReleaseTcbComponent>,
    schema: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseTcbComponent {
    identity_sha256: String,
    name: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeManifest {
    architecture: String,
    artifacts: Vec<ManifestArtifact>,
    schema: String,
    target: String,
    toolchain: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestArtifact {
    name: String,
    sha256: String,
    size: u64,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireArtifact {
    mode: u16,
    role: String,
    sha256: String,
    size: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRuntime {
    launcher: WireArtifact,
    runtime: WireArtifact,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTcbEntry {
    identity: String,
    role: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEligibility {
    reasons: Vec<String>,
    status: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionReceipt {
    assumptions: Vec<String>,
    boundary: Value,
    command: Value,
    eligibility: WireEligibility,
    environment: Value,
    execution_id: String,
    inputs: Value,
    observations: Value,
    outcome: Value,
    output_root: Value,
    outputs: Value,
    plan: Value,
    platform: Value,
    policy: Value,
    producer: WireArtifact,
    product_version: String,
    runtime: WireRuntime,
    schema: String,
    streams: Value,
    trusted_computing_base: Vec<WireTcbEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionVerification {
    eligibility: WireEligibility,
    receipt_commitment: String,
    valid: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactIdentity {
    name: String,
    sha256: String,
    size: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InheritedEntry {
    id: String,
    origins: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ComposedTcbEntry {
    identity: String,
    origins: Vec<String>,
    role: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseIdentity {
    envelope: ArtifactIdentity,
    payload_sha256: String,
    project: String,
    project_revision: String,
    verification_report: ArtifactIdentity,
    verifier: ArtifactIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeBundleIdentity {
    architecture: String,
    artifacts: Vec<ArtifactIdentity>,
    manifest: ArtifactIdentity,
    target: String,
    toolchain: String,
    version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutionIdentity {
    commitment: String,
    eligibility: String,
    execution_id: String,
    receipt: ArtifactIdentity,
    verification_report: ArtifactIdentity,
    verifier: ArtifactIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ComposedEligibility {
    status: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ComposedReceipt {
    assumptions: Vec<InheritedEntry>,
    claims: Vec<ClaimStatus>,
    composition_id: String,
    eligibility: ComposedEligibility,
    execution: ExecutionIdentity,
    not_proved_out_of_scope: Value,
    release: ReleaseIdentity,
    runtime_bundle: RuntimeBundleIdentity,
    schema: String,
    trusted_computing_base: Vec<ComposedTcbEntry>,
}

/// Produces canonical bytes for one exact, successfully verified composition.
pub fn compose(inputs: &CompositionInputs<'_>) -> Result<Vec<u8>, CompositionError> {
    let release_envelope: ReleaseEnvelope = parse(inputs.release_envelope.bytes)?;
    let release_report: ReleaseReport = parse(inputs.release_verification.bytes)?;
    let compiled: CompiledRelease = parse(inputs.compiled_release.bytes)?;
    let release_tcb: TcbLedger = parse(inputs.release_tcb_ledger.bytes)?;
    let manifest: RuntimeManifest = parse(inputs.runtime_manifest.bytes)?;
    let execution: ExecutionReceipt = parse(inputs.execution_receipt.bytes)?;
    let execution_verification: ExecutionVerification = parse(inputs.execution_verification.bytes)?;

    validate_release(&release_envelope, &release_report, &compiled, inputs)?;
    let bundle_artifacts = validate_bundle(&manifest, inputs)?;
    validate_execution(
        &execution,
        &execution_verification,
        &bundle_artifacts,
        inputs,
    )?;

    let assumptions = inherited_assumptions(&release_report.claims, &execution.assumptions);
    let trusted_computing_base = inherited_tcb(&release_tcb, &execution.trusted_computing_base)?;
    let mut receipt = ComposedReceipt {
        assumptions,
        claims: release_report.claims,
        composition_id: String::new(),
        eligibility: ComposedEligibility {
            status: "composed".to_owned(),
        },
        execution: ExecutionIdentity {
            commitment: inputs.expected_execution_commitment.to_owned(),
            eligibility: "reusable".to_owned(),
            execution_id: execution.execution_id,
            receipt: artifact_identity(inputs.execution_receipt),
            verification_report: artifact_identity(inputs.execution_verification),
            verifier: artifact_identity(inputs.execution_verifier),
        },
        not_proved_out_of_scope: release_report.not_proved_out_of_scope,
        release: ReleaseIdentity {
            envelope: artifact_identity(inputs.release_envelope),
            payload_sha256: release_envelope.payload_sha256,
            project: release_report.project,
            project_revision: release_report.project_revision,
            verification_report: artifact_identity(inputs.release_verification),
            verifier: artifact_identity(inputs.release_verifier),
        },
        runtime_bundle: RuntimeBundleIdentity {
            architecture: manifest.architecture,
            artifacts: bundle_artifacts,
            manifest: artifact_identity(inputs.runtime_manifest),
            target: manifest.target,
            toolchain: manifest.toolchain,
            version: manifest.version,
        },
        schema: COMPOSITION_SCHEMA.to_owned(),
        trusted_computing_base,
    };
    receipt.composition_id = composition_identity(&receipt)?;
    canonical_bytes(&receipt)
}

/// Independently recomputes a composition and compares its complete canonical
/// bytes, returning specific omission and downgrade failures first.
pub fn verify_composed_receipt(
    bytes: &[u8],
    inputs: &CompositionInputs<'_>,
) -> Result<(), CompositionError> {
    let actual: ComposedReceipt = parse(bytes)?;
    let expected_bytes = compose(inputs)?;
    let expected: ComposedReceipt = parse(&expected_bytes)?;
    if actual.assumptions != expected.assumptions {
        return Err(CompositionError::AssumptionOmitted);
    }
    if actual.trusted_computing_base != expected.trusted_computing_base {
        return Err(CompositionError::TrustedComputingBaseOmitted);
    }
    if actual.claims != expected.claims {
        return Err(CompositionError::ReleaseDowngraded);
    }
    if bytes != expected_bytes {
        return Err(CompositionError::CompositionMismatch);
    }
    Ok(())
}

fn validate_release(
    envelope: &ReleaseEnvelope,
    report: &ReleaseReport,
    compiled: &CompiledRelease,
    inputs: &CompositionInputs<'_>,
) -> Result<(), CompositionError> {
    if envelope.schema != RELEASE_ENVELOPE_SCHEMA
        || envelope.payload != "compiled-receipt.json"
        || report.schema != RELEASE_REPORT_SCHEMA
        || report.verdict != "receipt-consistent"
        || report.trust_boundary.is_empty()
        || compiled.schema != COMPILED_RELEASE_SCHEMA
        || compiled.tree_state != "clean"
        || compiled.project_tier > 3
        || compiled.graph_sha256.is_empty()
    {
        return Err(CompositionError::SchemaInvalid);
    }
    let compiled_digest = digest_text(inputs.compiled_release.bytes);
    if envelope.payload_sha256 != compiled_digest
        || report.payload_sha256 != envelope.payload_sha256
        || report.project != compiled.project
        || report.project_revision != compiled.project_revision
    {
        return Err(CompositionError::ReleaseSubstituted);
    }
    let reported_ids = claim_ids(&report.claims)?;
    let compiled_ids = claim_ids(&compiled.reported_statuses)?;
    if compiled_ids.is_empty() {
        return Err(CompositionError::SchemaInvalid);
    }
    if reported_ids != compiled_ids {
        return Err(CompositionError::ReleaseClaimOmitted);
    }
    if report.claims != compiled.reported_statuses {
        return Err(CompositionError::ReleaseDowngraded);
    }
    let _preserved_release_fields = (
        &compiled.assumptions,
        &compiled.claims,
        &compiled.closures,
        &compiled.evidence,
        &compiled.graph,
        &compiled.policies,
        &compiled.premises,
        &compiled.sealed_files,
        report.publication_blocked,
    );
    Ok(())
}

fn claim_ids(claims: &[ClaimStatus]) -> Result<BTreeSet<&str>, CompositionError> {
    let ids = claims
        .iter()
        .map(|claim| claim.claim_id.as_str())
        .collect::<BTreeSet<_>>();
    if ids.len() != claims.len() {
        return Err(CompositionError::SchemaInvalid);
    }
    Ok(ids)
}

fn validate_bundle(
    manifest: &RuntimeManifest,
    inputs: &CompositionInputs<'_>,
) -> Result<Vec<ArtifactIdentity>, CompositionError> {
    if manifest.schema != RELEASE_MANIFEST_SCHEMA
        || manifest.toolchain.is_empty()
        || manifest.version.is_empty()
        || !matches!(manifest.architecture.as_str(), "aarch64" | "x86_64")
        || !matches!(
            manifest.target.as_str(),
            "aarch64-unknown-linux-gnu" | "x86_64-unknown-linux-gnu"
        )
    {
        return Err(CompositionError::SchemaInvalid);
    }
    let expected = [
        ("pbr", inputs.runtime),
        ("pbr-native-launcher", inputs.launcher),
        ("pbr-verify", inputs.execution_verifier),
        ("pbr-compose", inputs.composer),
    ];
    if manifest.artifacts.len() != expected.len() {
        return Err(CompositionError::BundleRoleMismatch);
    }
    let mut identities = Vec::with_capacity(expected.len());
    for (registered, (name, bytes)) in manifest.artifacts.iter().zip(expected) {
        if registered.name != name || bytes.name != name {
            return Err(CompositionError::BundleRoleMismatch);
        }
        let size = u64::try_from(bytes.bytes.len()).map_err(|_| CompositionError::SchemaInvalid)?;
        if registered.sha256 != digest_hex(bytes.bytes) || registered.size != size {
            return Err(CompositionError::BundleSubstituted);
        }
        identities.push(artifact_identity(bytes));
    }
    Ok(identities)
}

fn validate_execution(
    receipt: &ExecutionReceipt,
    verification: &ExecutionVerification,
    bundle_artifacts: &[ArtifactIdentity],
    inputs: &CompositionInputs<'_>,
) -> Result<(), CompositionError> {
    if receipt.schema != EXECUTION_RECEIPT_SCHEMA
        || receipt.product_version.is_empty()
        || !verification.valid
        || verification.eligibility.status != "reusable"
        || !verification.eligibility.reasons.is_empty()
        || receipt.eligibility.status != "reusable"
        || !receipt.eligibility.reasons.is_empty()
        || verification.receipt_commitment != inputs.expected_execution_commitment
        || digest_text(inputs.execution_receipt.bytes) != inputs.expected_execution_commitment
    {
        return Err(CompositionError::ExecutionInvalid);
    }
    if receipt.execution_id != inputs.expected_execution_id {
        return Err(CompositionError::ExecutionReplayed);
    }
    validate_wire_artifact(
        &receipt.runtime.runtime,
        "runtime-binary",
        &bundle_artifacts[0],
    )?;
    validate_wire_artifact(
        &receipt.runtime.launcher,
        "launcher-binary",
        &bundle_artifacts[1],
    )?;
    validate_wire_artifact(&receipt.producer, "runtime-binary", &bundle_artifacts[0])?;
    for (role, artifact) in [
        ("runtime-binary", &bundle_artifacts[0]),
        ("launcher-binary", &bundle_artifacts[1]),
    ] {
        let raw_digest = artifact.sha256.trim_start_matches("sha256:");
        if !receipt
            .trusted_computing_base
            .iter()
            .any(|entry| entry.role == role && entry.identity == raw_digest)
        {
            return Err(CompositionError::TrustedComputingBaseOmitted);
        }
    }
    let _closed_fields = (
        &receipt.boundary,
        &receipt.command,
        &receipt.environment,
        &receipt.inputs,
        &receipt.observations,
        &receipt.outcome,
        &receipt.output_root,
        &receipt.outputs,
        &receipt.plan,
        &receipt.platform,
        &receipt.policy,
        &receipt.streams,
    );
    Ok(())
}

fn validate_wire_artifact(
    wire: &WireArtifact,
    role: &str,
    expected: &ArtifactIdentity,
) -> Result<(), CompositionError> {
    if wire.role != role {
        return Err(CompositionError::BundleRoleMismatch);
    }
    if wire.sha256 != expected.sha256 || wire.size != expected.size || wire.mode == 0 {
        return Err(CompositionError::BundleSubstituted);
    }
    Ok(())
}

fn inherited_assumptions(claims: &[ClaimStatus], execution: &[String]) -> Vec<InheritedEntry> {
    let mut origins: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for claim in claims {
        for assumption in &claim.assumptions {
            origins
                .entry(assumption.clone())
                .or_default()
                .insert("release".to_owned());
        }
    }
    for assumption in execution {
        origins
            .entry(assumption.clone())
            .or_default()
            .insert("execution".to_owned());
    }
    origins
        .into_iter()
        .map(|(id, origins)| InheritedEntry {
            id,
            origins: origins.into_iter().collect(),
        })
        .collect()
}

fn inherited_tcb(
    release: &TcbLedger,
    execution: &[WireTcbEntry],
) -> Result<Vec<ComposedTcbEntry>, CompositionError> {
    if release.schema != "proofbound-tcb-ledger/1" || release.components.is_empty() {
        return Err(CompositionError::SchemaInvalid);
    }
    let mut entries: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for component in &release.components {
        if component.name.is_empty()
            || component.version.is_empty()
            || !is_digest(&component.identity_sha256)
        {
            return Err(CompositionError::SchemaInvalid);
        }
        entries
            .entry((
                "proofbound-component".to_owned(),
                format!(
                    "{}@{}#{}",
                    component.name, component.version, component.identity_sha256
                ),
            ))
            .or_default()
            .insert("release".to_owned());
    }
    for entry in execution {
        if entry.role.is_empty() || entry.identity.is_empty() {
            return Err(CompositionError::SchemaInvalid);
        }
        entries
            .entry((entry.role.clone(), entry.identity.clone()))
            .or_default()
            .insert("execution".to_owned());
    }
    Ok(entries
        .into_iter()
        .map(|((role, identity), origins)| ComposedTcbEntry {
            identity,
            origins: origins.into_iter().collect(),
            role,
        })
        .collect())
}

fn composition_identity(receipt: &ComposedReceipt) -> Result<String, CompositionError> {
    let mut value = serde_json::to_value(receipt).map_err(|_| CompositionError::SchemaInvalid)?;
    value
        .as_object_mut()
        .ok_or(CompositionError::SchemaInvalid)?
        .remove("composition_id");
    let body = serde_json::to_vec(&value).map_err(|_| CompositionError::SchemaInvalid)?;
    let mut hasher = Sha256::new();
    hasher.update(COMPOSITION_DOMAIN);
    hasher.update(body);
    Ok(format!("sha256:{}", hex_digest(&hasher.finalize())))
}

fn canonical_bytes(receipt: &ComposedReceipt) -> Result<Vec<u8>, CompositionError> {
    let value = serde_json::to_value(receipt).map_err(|_| CompositionError::SchemaInvalid)?;
    serde_json::to_vec(&value).map_err(|_| CompositionError::SchemaInvalid)
}

fn artifact_identity(artifact: ArtifactBytes<'_>) -> ArtifactIdentity {
    ArtifactIdentity {
        name: artifact.name.to_owned(),
        sha256: digest_text(artifact.bytes),
        size: artifact.bytes.len().to_string(),
    }
}

fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, CompositionError> {
    serde_json::from_slice(bytes).map_err(|_| CompositionError::SchemaInvalid)
}

fn digest_hex(bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(bytes))
}

fn digest_text(bytes: &[u8]) -> String {
    format!("sha256:{}", digest_hex(bytes))
}

fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde_json::{Value, json};

    use super::*;

    const EXECUTION_ID: &str = "00112233-4455-4677-8899-aabbccddeeff";

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
        expected_error: String,
    }

    struct Fixture {
        release_envelope: Vec<u8>,
        compiled_release: Vec<u8>,
        release_verification: Vec<u8>,
        release_verifier: Vec<u8>,
        release_tcb_ledger: Vec<u8>,
        runtime_manifest: Vec<u8>,
        runtime: Vec<u8>,
        launcher: Vec<u8>,
        execution_verifier: Vec<u8>,
        composer: Vec<u8>,
        execution_receipt: Vec<u8>,
        execution_verification: Vec<u8>,
        commitment: String,
        expected_execution_id: String,
    }

    impl Fixture {
        fn new() -> Self {
            let runtime = b"exact-pbr".to_vec();
            let launcher = b"exact-launcher".to_vec();
            let execution_verifier = b"exact-pbr-verify".to_vec();
            let composer = b"exact-pbr-compose".to_vec();
            let runtime_digest = digest_hex(&runtime);
            let launcher_digest = digest_hex(&launcher);
            let verifier_digest = digest_hex(&execution_verifier);
            let composer_digest = digest_hex(&composer);
            let claim = json!({
                "assumption": "ASSUMED",
                "assumptions": ["PBR-TOOLCHAIN-AX-003"],
                "claim_id": "PBR-TEST-001",
                "formal": "TESTED",
                "linkage": "MODEL_ONLY",
                "policy_admitted": true,
                "public_statement": "The frozen fixture remains bounded.",
                "undischarged_premises": []
            });
            let compiled_release = canonical_json(json!({
                "assumptions": [],
                "claims": [],
                "closures": [],
                "evidence": [],
                "graph": {},
                "graph_sha256": digest_text(b"graph"),
                "policies": [],
                "premises": [],
                "project": "proofbound-runtime",
                "project_revision": "0123456789abcdef0123456789abcdef01234567",
                "project_tier": 3,
                "reported_statuses": [claim.clone()],
                "schema": COMPILED_RELEASE_SCHEMA,
                "sealed_files": [],
                "tree_state": "clean"
            }));
            let payload_digest = digest_text(&compiled_release);
            let release_envelope = canonical_json(json!({
                "payload": "compiled-receipt.json",
                "payload_sha256": payload_digest,
                "schema": RELEASE_ENVELOPE_SCHEMA
            }));
            let release_verification = canonical_json(json!({
                "claims": [claim],
                "not_proved_out_of_scope": {
                    "assumptions": ["PBR-TEST-001: PBR-TOOLCHAIN-AX-003"],
                    "exclusions": [],
                    "open_obligations": ["PBR-TEST-001: exact release linkage"],
                    "undischarged_premises": []
                },
                "payload_sha256": payload_digest,
                "project": "proofbound-runtime",
                "project_revision": "0123456789abcdef0123456789abcdef01234567",
                "publication_blocked": false,
                "schema": RELEASE_REPORT_SCHEMA,
                "trust_boundary": "Receipt-consistent only.",
                "verdict": "receipt-consistent"
            }));
            let release_tcb_ledger = canonical_json(json!({
                "components": [{
                    "identity_sha256": digest_text(b"proofbound-verifier"),
                    "name": "proofbound-verify",
                    "version": "0.0.1"
                }],
                "schema": "proofbound-tcb-ledger/1"
            }));
            let runtime_manifest = canonical_json(json!({
                "architecture": "x86_64",
                "artifacts": [
                    {"name": "pbr", "sha256": runtime_digest, "size": runtime.len()},
                    {"name": "pbr-native-launcher", "sha256": launcher_digest, "size": launcher.len()},
                    {"name": "pbr-verify", "sha256": verifier_digest, "size": execution_verifier.len()},
                    {"name": "pbr-compose", "sha256": composer_digest, "size": composer.len()}
                ],
                "schema": RELEASE_MANIFEST_SCHEMA,
                "target": "x86_64-unknown-linux-gnu",
                "toolchain": "rustc fixture",
                "version": "0.1.0"
            }));
            let wire_artifact = |role: &str, digest: &str, size: usize| {
                json!({
                    "mode": 493,
                    "role": role,
                    "sha256": format!("sha256:{digest}"),
                    "size": size.to_string()
                })
            };
            let execution_receipt = canonical_json(json!({
                "assumptions": [
                    "PBR-HOST-AX-002",
                    "PBR-LINUX-AX-001",
                    "PBR-TOOLCHAIN-AX-003"
                ],
                "boundary": {},
                "command": {},
                "eligibility": {"reasons": [], "status": "reusable"},
                "environment": [],
                "execution_id": EXECUTION_ID,
                "inputs": [],
                "observations": {},
                "outcome": {},
                "output_root": {},
                "outputs": [],
                "plan": {},
                "platform": {},
                "policy": {},
                "producer": wire_artifact("runtime-binary", &runtime_digest, runtime.len()),
                "product_version": "0.1.0",
                "runtime": {
                    "launcher": wire_artifact("launcher-binary", &launcher_digest, launcher.len()),
                    "runtime": wire_artifact("runtime-binary", &runtime_digest, runtime.len())
                },
                "schema": EXECUTION_RECEIPT_SCHEMA,
                "streams": {},
                "trusted_computing_base": [
                    {"identity": runtime_digest, "role": "runtime-binary"},
                    {"identity": launcher_digest, "role": "launcher-binary"},
                    {"identity": "PBR-TOOLCHAIN-AX-003", "role": "rust-toolchain"}
                ]
            }));
            let commitment = digest_text(&execution_receipt);
            let execution_verification = canonical_json(json!({
                "eligibility": {"reasons": [], "status": "reusable"},
                "receipt_commitment": commitment,
                "valid": true
            }));
            Self {
                release_envelope,
                compiled_release,
                release_verification,
                release_verifier: b"proofbound-verifier".to_vec(),
                release_tcb_ledger,
                runtime_manifest,
                runtime,
                launcher,
                execution_verifier,
                composer,
                execution_receipt,
                execution_verification,
                commitment,
                expected_execution_id: EXECUTION_ID.to_owned(),
            }
        }

        fn inputs(&self) -> CompositionInputs<'_> {
            CompositionInputs {
                release_envelope: named("release.json", &self.release_envelope),
                compiled_release: named("compiled-receipt.json", &self.compiled_release),
                release_verification: named(
                    "proofbound-verification.json",
                    &self.release_verification,
                ),
                release_verifier: named("proofbound-verify", &self.release_verifier),
                release_tcb_ledger: named("tcb-ledger.json", &self.release_tcb_ledger),
                runtime_manifest: named("RELEASE-MANIFEST.json", &self.runtime_manifest),
                runtime: named("pbr", &self.runtime),
                launcher: named("pbr-native-launcher", &self.launcher),
                execution_verifier: named("pbr-verify", &self.execution_verifier),
                composer: named("pbr-compose", &self.composer),
                execution_receipt: named("execution-receipt.json", &self.execution_receipt),
                execution_verification: named(
                    "execution-verification.json",
                    &self.execution_verification,
                ),
                expected_execution_commitment: &self.commitment,
                expected_execution_id: &self.expected_execution_id,
            }
        }

        fn mutate_json(&mut self, field: FixtureField, mutation: impl FnOnce(&mut Value)) {
            let bytes = match field {
                FixtureField::Envelope => &mut self.release_envelope,
                FixtureField::Report => &mut self.release_verification,
                FixtureField::Manifest => &mut self.runtime_manifest,
                FixtureField::Execution => &mut self.execution_receipt,
            };
            let mut value: Value = serde_json::from_slice(bytes).expect("fixture JSON parses");
            mutation(&mut value);
            *bytes = canonical_json(value);
            if matches!(field, FixtureField::Execution) {
                self.commitment = digest_text(bytes);
                self.execution_verification = canonical_json(json!({
                    "eligibility": {"reasons": [], "status": "reusable"},
                    "receipt_commitment": self.commitment,
                    "valid": true
                }));
            }
        }
    }

    #[derive(Clone, Copy)]
    enum FixtureField {
        Envelope,
        Report,
        Manifest,
        Execution,
    }

    fn named<'a>(name: &'a str, bytes: &'a [u8]) -> ArtifactBytes<'a> {
        ArtifactBytes { name, bytes }
    }

    fn canonical_json(value: Value) -> Vec<u8> {
        serde_json::to_vec(&value).expect("fixture JSON encodes")
    }

    fn mutate_composed(bytes: &[u8], mutation: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut value: Value = serde_json::from_slice(bytes).expect("composed JSON parses");
        mutation(&mut value);
        canonical_json(value)
    }

    #[test]
    fn frozen_attack_catalog_is_closed() {
        let catalog: AttackCatalog =
            toml::from_str(include_str!("../../../tests/attacks/composition/v1.toml"))
                .expect("composition attack catalog parses");
        assert_eq!(catalog.schema, "proofbound-runtime-composition-attacks/1");
        assert_eq!(catalog.cases.len(), 12);
        for (index, case) in catalog.cases.into_iter().enumerate() {
            assert_eq!(case.id, format!("PBR-COMP-{:03}", index + 1));
            assert!(!case.mutation.is_empty());
            assert!(!case.expected_error.is_empty());
        }
    }

    #[test]
    fn valid_chain_is_canonical_and_self_verifying() {
        let fixture = Fixture::new();
        let bytes = compose(&fixture.inputs()).expect("valid chain composes");
        let value: Value = serde_json::from_slice(&bytes).expect("output parses");
        assert_eq!(value["schema"], COMPOSITION_SCHEMA);
        assert_eq!(value["eligibility"]["status"], "composed");
        assert_eq!(value["claims"][0]["linkage"], "MODEL_ONLY");
        assert_eq!(value["execution"]["execution_id"], EXECUTION_ID);
        assert_eq!(serde_json::to_vec(&value).unwrap(), bytes);
        verify_composed_receipt(&bytes, &fixture.inputs()).expect("output independently agrees");
    }

    #[test]
    fn release_omission_substitution_and_downgrade_fail_closed() {
        let mut omitted = Fixture::new();
        omitted.mutate_json(FixtureField::Report, |value| {
            value["claims"] = json!([]);
        });
        assert_eq!(
            compose(&omitted.inputs()).unwrap_err(),
            CompositionError::ReleaseClaimOmitted
        );

        let mut substituted = Fixture::new();
        substituted.mutate_json(FixtureField::Envelope, |value| {
            value["payload_sha256"] = Value::String(digest_text(b"substitute"));
        });
        assert_eq!(
            compose(&substituted.inputs()).unwrap_err(),
            CompositionError::ReleaseSubstituted
        );

        let mut downgraded = Fixture::new();
        downgraded.mutate_json(FixtureField::Report, |value| {
            value["claims"][0]["linkage"] = Value::String("ARTIFACT_BOUND".to_owned());
        });
        assert_eq!(
            compose(&downgraded.inputs()).unwrap_err(),
            CompositionError::ReleaseDowngraded
        );
    }

    #[test]
    fn bundle_substitution_and_role_swap_fail_closed() {
        let mut substituted = Fixture::new();
        substituted.runtime.push(b'!');
        assert_eq!(
            compose(&substituted.inputs()).unwrap_err(),
            CompositionError::BundleSubstituted
        );

        let mut swapped = Fixture::new();
        swapped.mutate_json(FixtureField::Manifest, |value| {
            value["artifacts"][0]["name"] = Value::String("pbr-native-launcher".to_owned());
        });
        assert_eq!(
            compose(&swapped.inputs()).unwrap_err(),
            CompositionError::BundleRoleMismatch
        );
    }

    #[test]
    fn execution_replay_and_unknown_fields_fail_closed() {
        let mut replayed = Fixture::new();
        replayed.expected_execution_id = "ffeeddcc-bbaa-4998-8877-665544332211".to_owned();
        assert_eq!(
            compose(&replayed.inputs()).unwrap_err(),
            CompositionError::ExecutionReplayed
        );

        let mut unknown = Fixture::new();
        unknown.mutate_json(FixtureField::Execution, |value| {
            value["unknown"] = Value::Bool(true);
        });
        assert_eq!(
            compose(&unknown.inputs()).unwrap_err(),
            CompositionError::SchemaInvalid
        );
    }

    #[test]
    fn composed_assumption_tcb_and_status_mutations_fail_closed() {
        let fixture = Fixture::new();
        let bytes = compose(&fixture.inputs()).expect("valid chain composes");

        let assumption = mutate_composed(&bytes, |value| {
            value["assumptions"]
                .as_array_mut()
                .expect("assumptions array")
                .remove(0);
        });
        assert_eq!(
            verify_composed_receipt(&assumption, &fixture.inputs()).unwrap_err(),
            CompositionError::AssumptionOmitted
        );

        let tcb = mutate_composed(&bytes, |value| {
            value["trusted_computing_base"]
                .as_array_mut()
                .expect("TCB array")
                .remove(0);
        });
        assert_eq!(
            verify_composed_receipt(&tcb, &fixture.inputs()).unwrap_err(),
            CompositionError::TrustedComputingBaseOmitted
        );

        let promoted = mutate_composed(&bytes, |value| {
            value["claims"][0]["linkage"] = Value::String("ARTIFACT_BOUND".to_owned());
        });
        assert_eq!(
            verify_composed_receipt(&promoted, &fixture.inputs()).unwrap_err(),
            CompositionError::ReleaseDowngraded
        );
    }
}
