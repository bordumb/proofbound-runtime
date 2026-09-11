#![forbid(unsafe_code)]

//! Validates and composes exact Proofbound release and Runtime execution facts.

mod cbor_decode;
mod cbor_encode;

use std::collections::{BTreeMap, BTreeSet};

use proofbound_runtime_verify::{ReceiptCommitment, decode_receipt, verify_receipt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const COMPOSITION_SCHEMA: &str = "proofbound-runtime-composed-receipt/1";
const COMPOSITION_DOMAIN: &[u8] = b"proofbound-runtime-composed-receipt/1\n";
const COMPOSITION_SCHEMA_V2: &str = "proofbound-runtime-composed-receipt/2";
const COMPOSITION_DOMAIN_V2: &[u8] = b"proofbound-runtime-composed-receipt/2\n";
const RELEASE_ENVELOPE_SCHEMA: &str = "proofbound-release-envelope/6";
const RELEASE_REPORT_SCHEMA: &str = "proofbound-verification-report/3";
const COMPILED_RELEASE_SCHEMA: &str = "proofbound-compiled-release/6";
const RELEASE_MANIFEST_SCHEMA: &str = "proofbound-runtime-release-manifest/1";
const EXECUTION_RECEIPT_SCHEMA: &str = "proofbound-runtime-receipt/1";
const EXECUTION_RECEIPT_SCHEMA_V2: &str = "proofbound-runtime-execution-receipt/2";

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
    pub release_observation_inputs: ArtifactBytes<'a>,
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
    ReleaseContextMismatch,
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
            Self::ReleaseContextMismatch => "composition.release.context-mismatch",
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
    #[serde(default)]
    artifact_observations: Vec<ArtifactObservation>,
    assumption: String,
    assumptions: Vec<String>,
    claim_id: String,
    formal: String,
    linkage: String,
    policy_admitted: bool,
    public_statement: String,
    undischarged_premises: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactObservation {
    artifact: ObservedArtifact,
    dependencies: Vec<String>,
    evidence: String,
    identity: String,
    platform: ObservedPlatform,
    procedure: ObservedArtifact,
    semantic_kind: String,
    subject_role: String,
    toolchain_closure: ToolchainClosure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservedArtifact {
    logical_name: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservedPlatform {
    architecture: String,
    operating_system: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ToolchainClosure {
    kind: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResidualObligations {
    assumptions: Vec<String>,
    exclusions: Vec<String>,
    open_obligations: Vec<String>,
    undischarged_premises: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseReport {
    claims: Vec<ClaimStatus>,
    evidence_context: Option<String>,
    not_proved_out_of_scope: ResidualObligations,
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
    evidence_context: Option<String>,
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

#[derive(Clone, Deserialize)]
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

struct ExecutionFacts {
    assumptions: Vec<String>,
    eligibility: WireEligibility,
    execution_id: String,
    producer: WireArtifact,
    product_version: String,
    runtime: WireRuntime,
    schema: String,
    trusted_computing_base: Vec<WireTcbEntry>,
    version_two: bool,
}

impl From<ExecutionReceipt> for ExecutionFacts {
    fn from(receipt: ExecutionReceipt) -> Self {
        let _closed_fields = (
            receipt.boundary,
            receipt.command,
            receipt.environment,
            receipt.inputs,
            receipt.observations,
            receipt.outcome,
            receipt.output_root,
            receipt.outputs,
            receipt.plan,
            receipt.platform,
            receipt.policy,
            receipt.streams,
        );
        Self {
            assumptions: receipt.assumptions,
            eligibility: receipt.eligibility,
            execution_id: receipt.execution_id,
            producer: receipt.producer,
            product_version: receipt.product_version,
            runtime: receipt.runtime,
            schema: receipt.schema,
            trusted_computing_base: receipt.trusted_computing_base,
            version_two: false,
        }
    }
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
    evidence_context: String,
    observation_inputs: ArtifactIdentity,
    payload_sha256: String,
    project: String,
    project_revision: String,
    verification_report: ArtifactIdentity,
    verification_verdict: String,
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
    not_proved_out_of_scope: ResidualObligations,
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
    let execution = parse_execution_facts(inputs)?;
    let execution_verification: ExecutionVerification = parse(inputs.execution_verification.bytes)?;

    let evidence_context = validate_release(&release_envelope, &release_report, &compiled, inputs)?;
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
            evidence_context,
            observation_inputs: artifact_identity(inputs.release_observation_inputs),
            payload_sha256: release_envelope.payload_sha256,
            project: release_report.project,
            project_revision: release_report.project_revision,
            verification_report: artifact_identity(inputs.release_verification),
            verification_verdict: release_report.verdict,
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
        schema: if execution.version_two {
            COMPOSITION_SCHEMA_V2.to_owned()
        } else {
            COMPOSITION_SCHEMA.to_owned()
        },
        trusted_computing_base,
    };
    if execution.version_two {
        receipt.composition_id = composition_identity_v2(&receipt)?;
        canonical_v2_bytes(&receipt)
    } else {
        receipt.composition_id = composition_identity(&receipt)?;
        canonical_bytes(&receipt)
    }
}

fn parse_execution_facts(
    inputs: &CompositionInputs<'_>,
) -> Result<ExecutionFacts, CompositionError> {
    if inputs.execution_receipt.bytes.first() == Some(&b'{') {
        let receipt: ExecutionReceipt = parse(inputs.execution_receipt.bytes)?;
        return Ok(receipt.into());
    }

    let expected = ReceiptCommitment::parse(inputs.expected_execution_commitment)
        .map_err(|_| CompositionError::ExecutionInvalid)?;
    let _report = verify_receipt(inputs.execution_receipt.bytes, expected)
        .map_err(|_| CompositionError::ExecutionInvalid)?;
    let decoded = decode_receipt(inputs.execution_receipt.bytes)
        .map_err(|_| CompositionError::ExecutionInvalid)?;
    let facts = decoded.composition_facts();
    if !facts.version_two {
        return Err(CompositionError::ExecutionInvalid);
    }
    Ok(ExecutionFacts {
        assumptions: facts.assumptions,
        eligibility: WireEligibility {
            reasons: Vec::new(),
            status: if facts.reusable {
                "reusable".to_owned()
            } else {
                "non-reusable".to_owned()
            },
        },
        execution_id: facts.execution_id,
        producer: WireArtifact {
            mode: facts.producer.mode,
            role: facts.producer.role.to_owned(),
            sha256: facts.producer.sha256,
            size: facts.producer.size,
        },
        product_version: facts.product_version,
        runtime: WireRuntime {
            launcher: WireArtifact {
                mode: facts.launcher.mode,
                role: facts.launcher.role.to_owned(),
                sha256: facts.launcher.sha256,
                size: facts.launcher.size,
            },
            runtime: WireArtifact {
                mode: facts.runtime.mode,
                role: facts.runtime.role.to_owned(),
                sha256: facts.runtime.sha256,
                size: facts.runtime.size,
            },
        },
        schema: facts.schema,
        trusted_computing_base: facts
            .trusted_computing_base
            .into_iter()
            .map(|entry| WireTcbEntry {
                identity: entry.identity,
                role: entry.role,
            })
            .collect(),
        version_two: true,
    })
}

/// Independently recomputes a composition and compares its complete canonical
/// bytes, returning specific omission and downgrade failures first.
pub fn verify_composed_receipt(
    bytes: &[u8],
    inputs: &CompositionInputs<'_>,
) -> Result<(), CompositionError> {
    let actual = parse_composed_receipt(bytes)?;
    let expected_bytes = compose(inputs)?;
    let expected = parse_composed_receipt(&expected_bytes)?;
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

/// Returns the noncommitted JSON projection of one decoded composed receipt.
/// The returned view is for display only and is never a verification input.
pub fn project_composed_receipt(bytes: &[u8]) -> Result<Value, CompositionError> {
    if bytes.first() == Some(&b'{') {
        let value: Value = parse(bytes)?;
        let receipt: ComposedReceipt =
            serde_json::from_value(value.clone()).map_err(|_| CompositionError::SchemaInvalid)?;
        if receipt.schema != COMPOSITION_SCHEMA {
            return Err(CompositionError::SchemaInvalid);
        }
        Ok(value)
    } else {
        let value =
            cbor_decode::project_composed_v2(bytes).map_err(|_| CompositionError::SchemaInvalid)?;
        if value.get("schema").and_then(Value::as_str) != Some(COMPOSITION_SCHEMA_V2) {
            return Err(CompositionError::SchemaInvalid);
        }
        Ok(value)
    }
}

fn parse_composed_receipt(bytes: &[u8]) -> Result<ComposedReceipt, CompositionError> {
    if bytes.first() == Some(&b'{') {
        let receipt: ComposedReceipt = parse(bytes)?;
        if receipt.schema != COMPOSITION_SCHEMA {
            return Err(CompositionError::SchemaInvalid);
        }
        Ok(receipt)
    } else {
        let value = cbor_decode::decode_composed_v2_model(bytes)
            .map_err(|_| CompositionError::SchemaInvalid)?;
        let receipt: ComposedReceipt =
            serde_json::from_value(value).map_err(|_| CompositionError::SchemaInvalid)?;
        if receipt.schema != COMPOSITION_SCHEMA_V2 {
            return Err(CompositionError::SchemaInvalid);
        }
        Ok(receipt)
    }
}

fn validate_release(
    envelope: &ReleaseEnvelope,
    report: &ReleaseReport,
    compiled: &CompiledRelease,
    inputs: &CompositionInputs<'_>,
) -> Result<String, CompositionError> {
    if matches!(
        envelope.schema.as_str(),
        "proofbound-release-envelope/3"
            | "proofbound-release-envelope/4"
            | "proofbound-release-envelope/5"
    ) || matches!(
        report.schema.as_str(),
        "proofbound-verification-report/1" | "proofbound-verification-report/2"
    ) || matches!(
        compiled.schema.as_str(),
        "proofbound-compiled-release/3"
            | "proofbound-compiled-release/4"
            | "proofbound-compiled-release/5"
    ) || matches!(
        report.verdict.as_str(),
        "receipt-consistent" | "record-consistent"
    ) {
        return Err(CompositionError::ReleaseDowngraded);
    }
    if envelope.schema != RELEASE_ENVELOPE_SCHEMA
        || envelope.payload != "compiled-receipt.json"
        || report.schema != RELEASE_REPORT_SCHEMA
        || report.verdict != "bytes-observed"
        || report.trust_boundary.is_empty()
        || compiled.schema != COMPILED_RELEASE_SCHEMA
        || compiled.tree_state != "clean"
        || compiled.project_tier > 3
        || compiled.graph_sha256.is_empty()
        || inputs.release_observation_inputs.name != "proofbound-observation-inputs.json"
        || inputs.release_observation_inputs.bytes.is_empty()
    {
        return Err(CompositionError::SchemaInvalid);
    }
    let context = report
        .evidence_context
        .as_deref()
        .filter(|context| valid_context_name(context))
        .ok_or(CompositionError::ReleaseContextMismatch)?;
    if compiled.evidence_context.as_deref() != Some(context) {
        return Err(CompositionError::ReleaseContextMismatch);
    }
    let compiled_digest =
        domain_digest_text(COMPILED_RELEASE_SCHEMA, inputs.compiled_release.bytes);
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
    Ok(context.to_owned())
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
    receipt: &ExecutionFacts,
    verification: &ExecutionVerification,
    bundle_artifacts: &[ArtifactIdentity],
    inputs: &CompositionInputs<'_>,
) -> Result<(), CompositionError> {
    let expected_schema = if receipt.version_two {
        EXECUTION_RECEIPT_SCHEMA_V2
    } else {
        EXECUTION_RECEIPT_SCHEMA
    };
    if receipt.schema != expected_schema
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
    let expected_sha256 = expected
        .sha256
        .strip_prefix("sha256:")
        .ok_or(CompositionError::SchemaInvalid)?;
    if wire.sha256 != expected_sha256 || wire.size != expected.size || wire.mode == 0 {
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

fn composition_identity_v2(receipt: &ComposedReceipt) -> Result<String, CompositionError> {
    let mut value = serde_json::to_value(receipt).map_err(|_| CompositionError::SchemaInvalid)?;
    value
        .as_object_mut()
        .ok_or(CompositionError::SchemaInvalid)?
        .remove("composition_id");
    let body =
        cbor_encode::encode_composed_v2(&value).map_err(|_| CompositionError::SchemaInvalid)?;
    let mut hasher = Sha256::new();
    hasher.update(COMPOSITION_DOMAIN_V2);
    hasher.update(body);
    Ok(format!("sha256:{}", hex_digest(&hasher.finalize())))
}

fn canonical_bytes(receipt: &ComposedReceipt) -> Result<Vec<u8>, CompositionError> {
    let value = serde_json::to_value(receipt).map_err(|_| CompositionError::SchemaInvalid)?;
    serde_json::to_vec(&value).map_err(|_| CompositionError::SchemaInvalid)
}

fn canonical_v2_bytes(receipt: &ComposedReceipt) -> Result<Vec<u8>, CompositionError> {
    let value = serde_json::to_value(receipt).map_err(|_| CompositionError::SchemaInvalid)?;
    cbor_encode::encode_composed_v2(&value).map_err(|_| CompositionError::SchemaInvalid)
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

fn domain_digest_text(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    format!("sha256:{}", hex_digest(&hasher.finalize()))
}

fn valid_context_name(value: &str) -> bool {
    value.len() <= 128
        && value.split('-').enumerate().all(|(index, segment)| {
            !segment.is_empty()
                && (index != 0
                    || segment
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_lowercase))
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
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
        release_observation_inputs: Vec<u8>,
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
            let artifact_observation = json!({
                "artifact": {
                    "logical_name": "dist/release-observation/x86_64/pbr",
                    "sha256": digest_text(&runtime),
                    "size_bytes": runtime.len()
                },
                "dependencies": [digest_text(b"runtime evidence")],
                "evidence": digest_text(b"observation evidence"),
                "identity": digest_text(b"observation relation"),
                "platform": {
                    "architecture": "x86_64",
                    "operating_system": "linux"
                },
                "procedure": {
                    "logical_name": "crates/proofbound-runtime-compose/tests/release_observation.rs",
                    "sha256": digest_text(b"observation procedure"),
                    "size_bytes": 21
                },
                "semantic_kind": "example-test",
                "subject_role": "runtime-release",
                "toolchain_closure": {
                    "kind": "toolchain",
                    "sha256": digest_text(b"toolchain closure")
                }
            });
            let claim = json!({
                "artifact_observations": [artifact_observation],
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
                "evidence": [{
                    "record": {
                        "artifact_binding": {
                            "artifact": {
                                "logical_name": "dist/release-observation/x86_64/pbr",
                                "sha256": digest_text(&runtime),
                                "size_bytes": runtime.len()
                            },
                            "theorem_evidence": digest_text(b"theorem evidence")
                        },
                        "claim_ids": ["PBR-TEST-001"],
                        "evidence_context": "release-linux-x86-64",
                        "kind": "artifact-soundness",
                        "outcome": "passed",
                        "schema": "proofbound-evidence/5"
                    },
                    "sha256": digest_text(b"artifact evidence")
                }],
                "evidence_context": "release-linux-x86-64",
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
            let payload_digest = domain_digest_text(COMPILED_RELEASE_SCHEMA, &compiled_release);
            let release_envelope = canonical_json(json!({
                "payload": "compiled-receipt.json",
                "payload_sha256": payload_digest,
                "schema": RELEASE_ENVELOPE_SCHEMA
            }));
            let release_verification = canonical_json(json!({
                "claims": [claim],
                "evidence_context": "release-linux-x86-64",
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
                "trust_boundary": "Exact observation bytes were supplied externally.",
                "verdict": "bytes-observed"
            }));
            let release_observation_inputs = canonical_json(json!({
                "observations": [{
                    "artifact_path": "dist/release-observation/x86_64/pbr",
                    "claim_id": "PBR-TEST-001",
                    "platform": {
                        "architecture": "x86_64",
                        "operating_system": "linux"
                    },
                    "procedure_path": "crates/proofbound-runtime-compose/tests/release_observation.rs",
                    "subject_role": "runtime-release"
                }],
                "schema": "proofbound-observation-inputs/1"
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
                    "sha256": digest,
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
                release_observation_inputs,
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
                release_observation_inputs: named(
                    "proofbound-observation-inputs.json",
                    &self.release_observation_inputs,
                ),
                release_tcb_ledger: named("tcb-ledger.json", &self.release_tcb_ledger),
                runtime_manifest: named("RELEASE-MANIFEST.json", &self.runtime_manifest),
                runtime: named("pbr", &self.runtime),
                launcher: named("pbr-native-launcher", &self.launcher),
                execution_verifier: named("pbr-verify", &self.execution_verifier),
                composer: named("pbr-compose", &self.composer),
                execution_receipt: named(
                    if self.execution_receipt.first() == Some(&b'{') {
                        "execution-receipt.json"
                    } else {
                        "execution-receipt.cbor"
                    },
                    &self.execution_receipt,
                ),
                execution_verification: named(
                    "execution-verification.json",
                    &self.execution_verification,
                ),
                expected_execution_commitment: &self.commitment,
                expected_execution_id: &self.expected_execution_id,
            }
        }

        fn upgrade_execution_to_v2(&mut self) {
            self.execution_receipt = decode_hex(include_str!(
                "../../../schemas/vectors/v2/execution-receipt.cbor.hex"
            ));
            self.commitment = digest_text(&self.execution_receipt);
            self.execution_verification = canonical_json(json!({
                "eligibility": {"reasons": [], "status": "reusable"},
                "receipt_commitment": self.commitment,
                "valid": true
            }));
        }

        fn mutate_json(&mut self, field: FixtureField, mutation: impl FnOnce(&mut Value)) {
            let bytes = match field {
                FixtureField::Envelope => &mut self.release_envelope,
                FixtureField::Compiled => &mut self.compiled_release,
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
        Compiled,
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

    fn decode_hex(text: &str) -> Vec<u8> {
        text.trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(core::str::from_utf8(pair).expect("hex pair"), 16)
                    .expect("fixture is hex")
            })
            .collect()
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
        assert_eq!(catalog.cases.len(), 16);
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
        assert_eq!(value["release"]["evidence_context"], "release-linux-x86-64");
        assert_eq!(value["release"]["verification_verdict"], "bytes-observed");
        assert_eq!(
            value["claims"][0]["artifact_observations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(value["execution"]["execution_id"], EXECUTION_ID);
        assert_eq!(serde_json::to_vec(&value).unwrap(), bytes);
        verify_composed_receipt(&bytes, &fixture.inputs()).expect("output independently agrees");
    }

    #[test]
    fn version_two_execution_composes_to_deterministic_cbor_and_json_view() {
        let mut fixture = Fixture::new();
        fixture.upgrade_execution_to_v2();
        let bytes = compose(&fixture.inputs()).expect("valid v2 chain composes");
        assert_ne!(bytes.first(), Some(&b'{'));

        let projection = project_composed_receipt(&bytes).expect("v2 composition projects");
        assert_eq!(projection["schema"], COMPOSITION_SCHEMA_V2);
        assert_eq!(
            projection["execution"]["execution_id"],
            "hex:00112233445546778899aabbccddeeff"
        );
        assert_eq!(
            projection["execution"]["receipt"]["name"],
            "execution-receipt.cbor"
        );
        assert!(
            projection["composition_id"]
                .as_str()
                .is_some_and(|value| value.starts_with("hex:"))
        );
        assert!(projection["not_proved_out_of_scope"].is_object());
        verify_composed_receipt(&bytes, &fixture.inputs()).expect("v2 output independently agrees");
    }

    #[test]
    fn composed_v2_producer_and_decoder_match_the_frozen_golden() {
        let bytes = decode_hex(include_str!(
            "../../../schemas/vectors/v2/composed-receipt.cbor.hex"
        ));
        let expected: Value = serde_json::from_str(include_str!(
            "../../../schemas/vectors/v2/composed-receipt.projection.json"
        ))
        .expect("projection JSON parses");
        assert_eq!(project_composed_receipt(&bytes), Ok(expected));

        let model = parse_composed_receipt(&bytes).expect("golden model decodes");
        assert_eq!(canonical_v2_bytes(&model), Ok(bytes));
    }

    #[test]
    fn composed_v2_decoder_rejects_noncanonical_carriers() {
        for attack in [
            vec![0x18, 0x17],
            vec![0x9f, 0xff],
            vec![0xa1, 0x00, 0x00],
            vec![0xa2, 0x61, b'b', 0x00, 0x61, b'a', 0x00],
            vec![0xa2, 0x61, b'a', 0x00, 0x61, b'a', 0x01],
        ] {
            assert_eq!(
                project_composed_receipt(&attack),
                Err(CompositionError::SchemaInvalid)
            );
        }
    }

    #[test]
    fn composed_v2_assumption_tcb_and_status_mutations_fail_closed() {
        let mut fixture = Fixture::new();
        fixture.upgrade_execution_to_v2();
        let bytes = compose(&fixture.inputs()).expect("valid v2 chain composes");
        let model = parse_composed_receipt(&bytes).expect("v2 model decodes");

        let mut assumption = model.clone();
        assumption.assumptions.remove(0);
        let assumption = canonical_v2_bytes(&assumption).expect("forgery encodes");
        assert_eq!(
            verify_composed_receipt(&assumption, &fixture.inputs()),
            Err(CompositionError::AssumptionOmitted)
        );

        let mut tcb = model.clone();
        tcb.trusted_computing_base.remove(0);
        let tcb = canonical_v2_bytes(&tcb).expect("forgery encodes");
        assert_eq!(
            verify_composed_receipt(&tcb, &fixture.inputs()),
            Err(CompositionError::TrustedComputingBaseOmitted)
        );

        let mut promoted = model;
        promoted.claims[0].linkage = "ARTIFACT_BOUND".to_owned();
        let promoted = canonical_v2_bytes(&promoted).expect("forgery encodes");
        assert_eq!(
            verify_composed_receipt(&promoted, &fixture.inputs()),
            Err(CompositionError::ReleaseDowngraded)
        );
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
    fn contextual_release_downgrade_substitution_and_observation_loss_fail_closed() {
        let mut unframed = Fixture::new();
        let plain_digest = digest_text(&unframed.compiled_release);
        unframed.mutate_json(FixtureField::Envelope, |value| {
            value["payload_sha256"] = Value::String(plain_digest.clone());
        });
        unframed.mutate_json(FixtureField::Report, |value| {
            value["payload_sha256"] = Value::String(plain_digest);
        });
        assert_eq!(
            compose(&unframed.inputs()).unwrap_err(),
            CompositionError::ReleaseSubstituted
        );

        let mut downgraded = Fixture::new();
        downgraded.mutate_json(FixtureField::Envelope, |value| {
            value["schema"] = Value::String("proofbound-release-envelope/5".to_owned());
        });
        assert_eq!(
            compose(&downgraded.inputs()).unwrap_err(),
            CompositionError::ReleaseDowngraded
        );

        let mut downgraded_payload = Fixture::new();
        downgraded_payload.mutate_json(FixtureField::Compiled, |value| {
            value["schema"] = Value::String("proofbound-compiled-release/5".to_owned());
        });
        assert_eq!(
            compose(&downgraded_payload.inputs()).unwrap_err(),
            CompositionError::ReleaseDowngraded
        );

        let mut substituted = Fixture::new();
        substituted.mutate_json(FixtureField::Report, |value| {
            value["evidence_context"] = Value::String("release-linux-aarch64".to_owned());
        });
        assert_eq!(
            compose(&substituted.inputs()).unwrap_err(),
            CompositionError::ReleaseContextMismatch
        );

        let mut omitted = Fixture::new();
        omitted.mutate_json(FixtureField::Report, |value| {
            value["claims"][0]["artifact_observations"] = json!([]);
        });
        assert_eq!(
            compose(&omitted.inputs()).unwrap_err(),
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

        let mut prefixed_execution_digest = Fixture::new();
        prefixed_execution_digest.mutate_json(FixtureField::Execution, |value| {
            let digest = value["runtime"]["runtime"]["sha256"]
                .as_str()
                .unwrap()
                .to_owned();
            value["runtime"]["runtime"]["sha256"] = Value::String(format!("sha256:{digest}"));
        });
        assert_eq!(
            compose(&prefixed_execution_digest.inputs()).unwrap_err(),
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
