#![forbid(unsafe_code)]

//! Adopter-owned acceptance policy decoding, evaluation, and decision encoding.

mod cbor;

use std::collections::BTreeSet;

use proofbound_runtime_compose::{AcceptanceClaimFacts, ReleaseAcceptanceFacts};
use proofbound_runtime_verify::ReceiptAcceptanceFacts;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const POLICY_SCHEMA: &str = "proofbound-runtime-acceptance-policy/1";
const DECISION_SCHEMA: &str = "proofbound-runtime-acceptance-decision/1";
const POLICY_DOMAIN: &[u8] = b"proofbound-runtime-acceptance-policy/1\0";
const DECISION_DOMAIN: &[u8] = b"proofbound-runtime-acceptance-decision/1\0";

/// A malformed or semantically invalid acceptance input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptanceError {
    MalformedPolicy,
    InvalidPolicy,
    InvalidIdentity,
    InvalidDecision,
    EncodingFailed,
}

impl AcceptanceError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MalformedPolicy => "acceptance.policy.malformed-cbor",
            Self::InvalidPolicy => "acceptance.policy.invalid",
            Self::InvalidIdentity => "acceptance.identity.invalid",
            Self::InvalidDecision => "acceptance.decision.invalid",
            Self::EncodingFailed => "acceptance.decision.encoding-failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptancePolicy {
    schema: String,
    release: ReleasePolicy,
    execution: ExecutionPolicy,
    reject_if_present: RejectPolicy,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionPolicy {
    plan_id: String,
    platform: PlatformPolicy,
    resources: ResourcePolicy,
    executable: ExecutablePolicy,
    eligibility: String,
    freshness: FreshnessPolicy,
    policy_sha256: String,
    runtime_version: String,
    receipt_schema: String,
    policy_model_version: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformPolicy {
    architecture: String,
    operating_system: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourcePolicy {
    #[serde(rename = "pids.max")]
    pids_max: u32,
    #[serde(rename = "memory.max")]
    memory_max: u64,
    #[serde(rename = "memory.oom.group")]
    memory_oom_group: u8,
    #[serde(rename = "memory.swap.max")]
    memory_swap_max: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutablePolicy {
    mode: u16,
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshnessPolicy {
    mode: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasePolicy {
    claims: Vec<ClaimPolicy>,
    project: String,
    payload_sha256: String,
    evidence_context: String,
    project_revision: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimPolicy {
    formal: String,
    linkage: String,
    claim_id: String,
    assumption: String,
    policy_admitted: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectPolicy {
    tcb_roles: Vec<String>,
    exclusions: Vec<String>,
    assumptions: Vec<String>,
    open_obligations: Vec<String>,
}

/// One strictly decoded acceptance policy and its exact-byte identity.
#[derive(Debug)]
pub struct DecodedPolicy {
    policy: AcceptancePolicy,
    identity: String,
    identity_matches: bool,
}

impl DecodedPolicy {
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }
}

/// Strictly decodes deterministic-CBOR policy bytes and retains whether the
/// independently supplied identity selects those exact bytes.
pub fn decode_policy(
    bytes: &[u8],
    expected_identity: &str,
) -> Result<DecodedPolicy, AcceptanceError> {
    if !is_digest(expected_identity) {
        return Err(AcceptanceError::InvalidIdentity);
    }
    let value = cbor::decode_model(bytes).map_err(|_| AcceptanceError::MalformedPolicy)?;
    let policy: AcceptancePolicy =
        serde_json::from_value(value).map_err(|_| AcceptanceError::InvalidPolicy)?;
    validate_policy(&policy)?;
    let identity = domain_digest(POLICY_DOMAIN, bytes);
    Ok(DecodedPolicy {
        identity_matches: identity == expected_identity,
        identity,
        policy,
    })
}

fn validate_policy(policy: &AcceptancePolicy) -> Result<(), AcceptanceError> {
    let execution = &policy.execution;
    let release = &policy.release;
    if policy.schema != POLICY_SCHEMA
        || execution.receipt_schema != "proofbound-runtime-execution-receipt/2"
        || execution.policy_model_version != "proofbound-runtime-linux-policy/2"
        || execution.platform.operating_system != "linux"
        || !matches!(
            execution.platform.architecture.as_str(),
            "x86_64" | "aarch64"
        )
        || !matches!(execution.eligibility.as_str(), "reusable" | "non-reusable")
        || execution.freshness.mode != "not-required"
        || execution.plan_id.is_empty()
        || execution.plan_id.len() > 128
        || execution.runtime_version.is_empty()
        || execution.executable.mode == 0
        || execution.executable.mode > 0o7777
        || execution.resources.pids_max == 0
        || !(65_536..=1_099_511_627_776).contains(&execution.resources.memory_max)
        || execution.resources.memory_swap_max > 1_099_511_627_776
        || execution.resources.memory_max % 65_536 != 0
        || execution.resources.memory_swap_max % 65_536 != 0
        || execution.resources.memory_oom_group != 1
        || !is_digest(&execution.executable.sha256)
        || !is_digest(&execution.policy_sha256)
        || release.project.is_empty()
        || release.evidence_context.is_empty()
        || release.evidence_context.len() > 128
        || !is_digest(&release.payload_sha256)
        || !is_hex_exact(&release.project_revision, 20)
        || release.claims.is_empty()
        || !strict_by(&release.claims, |claim| claim.claim_id.as_str())
        || !release.claims.iter().all(valid_claim_policy)
        || !strict_strings(&policy.reject_if_present.assumptions)
        || !strict_strings(&policy.reject_if_present.exclusions)
        || !strict_strings(&policy.reject_if_present.open_obligations)
        || !strict_strings(&policy.reject_if_present.tcb_roles)
    {
        return Err(AcceptanceError::InvalidPolicy);
    }
    Ok(())
}

fn valid_claim_policy(claim: &ClaimPolicy) -> bool {
    !claim.claim_id.is_empty()
        && matches!(
            claim.formal.as_str(),
            "PROVED" | "BOUNDED_CHECKED" | "TESTED" | "OPEN" | "INVALID"
        )
        && matches!(
            claim.linkage.as_str(),
            "REFINED" | "ARTIFACT_BOUND" | "TRANSCRIBED" | "MODEL_ONLY" | "INVALID"
        )
        && matches!(claim.assumption.as_str(), "NONE" | "ASSUMED" | "INVALID")
}

fn strict_strings(values: &[String]) -> bool {
    values.iter().all(|value| !value.is_empty())
        && values
            .windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
}

fn strict_by<'a, T>(values: &'a [T], key: impl Fn(&'a T) -> &'a str) -> bool {
    values
        .windows(2)
        .all(|pair| key(&pair[0]).as_bytes() < key(&pair[1]).as_bytes())
}

/// Closed, stably ordered rejection reasons.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RejectionReason {
    PolicyIdentityMismatch,
    InputVerificationFailed,
    CompositionMissing,
    ExecutionSchemaMismatch,
    RuntimeVersionMismatch,
    PlatformMismatch,
    ArchitectureMismatch,
    PlanIdMismatch,
    ExecutableMismatch,
    AuthorityMismatch,
    ResourceMismatch,
    EligibilityMismatch,
    FreshnessPolicyUnsupported,
    ReleaseProjectMismatch,
    ReleaseRevisionMismatch,
    ReleasePayloadMismatch,
    ReleaseContextMismatch,
    ClaimMissing,
    ClaimFormalMismatch,
    ClaimLinkageMismatch,
    ClaimAssumptionMismatch,
    ClaimPolicyMismatch,
    ForbiddenAssumption,
    ForbiddenExclusion,
    ForbiddenOpenObligation,
    ForbiddenTcbRole,
}

impl RejectionReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyIdentityMismatch => "policy-identity-mismatch",
            Self::InputVerificationFailed => "input-verification-failed",
            Self::CompositionMissing => "composition-missing",
            Self::ExecutionSchemaMismatch => "execution-schema-mismatch",
            Self::RuntimeVersionMismatch => "runtime-version-mismatch",
            Self::PlatformMismatch => "platform-mismatch",
            Self::ArchitectureMismatch => "architecture-mismatch",
            Self::PlanIdMismatch => "plan-id-mismatch",
            Self::ExecutableMismatch => "executable-mismatch",
            Self::AuthorityMismatch => "authority-mismatch",
            Self::ResourceMismatch => "resource-mismatch",
            Self::EligibilityMismatch => "eligibility-mismatch",
            Self::FreshnessPolicyUnsupported => "freshness-policy-unsupported",
            Self::ReleaseProjectMismatch => "release-project-mismatch",
            Self::ReleaseRevisionMismatch => "release-revision-mismatch",
            Self::ReleasePayloadMismatch => "release-payload-mismatch",
            Self::ReleaseContextMismatch => "release-context-mismatch",
            Self::ClaimMissing => "claim-missing",
            Self::ClaimFormalMismatch => "claim-formal-mismatch",
            Self::ClaimLinkageMismatch => "claim-linkage-mismatch",
            Self::ClaimAssumptionMismatch => "claim-assumption-mismatch",
            Self::ClaimPolicyMismatch => "claim-policy-mismatch",
            Self::ForbiddenAssumption => "forbidden-assumption",
            Self::ForbiddenExclusion => "forbidden-exclusion",
            Self::ForbiddenOpenObligation => "forbidden-open-obligation",
            Self::ForbiddenTcbRole => "forbidden-tcb-role",
        }
    }
}

/// Exact bytes consumed or produced by one decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DecisionInput {
    pub role: String,
    pub size: u64,
    pub sha256: String,
}

impl DecisionInput {
    #[must_use]
    pub fn new(role: &str, bytes: &[u8]) -> Self {
        Self {
            role: role.to_owned(),
            size: bytes.len() as u64,
            sha256: digest(bytes),
        }
    }
}

/// Verified facts and exact identities supplied to policy evaluation.
pub struct EvaluationInputs<'a> {
    pub execution: &'a ReceiptAcceptanceFacts,
    pub release: &'a ReleaseAcceptanceFacts,
    pub expected_execution_commitment: &'a str,
    pub expected_execution_id: &'a str,
    pub composition_id: &'a str,
    pub artifacts: Vec<DecisionInput>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct WireDecision {
    schema: String,
    status: String,
    inputs: Vec<DecisionInput>,
    reasons: Vec<RejectionReason>,
    decision_id: String,
    execution_id: String,
    composition_id: Option<String>,
    policy_identity: String,
    execution_commitment: String,
}

/// One canonical adopter decision.
pub struct AcceptanceDecision {
    wire: WireDecision,
    bytes: Vec<u8>,
}

impl AcceptanceDecision {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.wire.decision_id
    }
    #[must_use]
    pub fn accepted(&self) -> bool {
        self.wire.status == "accepted"
    }
    #[must_use]
    pub fn reasons(&self) -> &[RejectionReason] {
        &self.wire.reasons
    }
    pub fn projection(&self) -> Result<Value, AcceptanceError> {
        cbor::project_json(&self.bytes).map_err(|_| AcceptanceError::InvalidDecision)
    }
}

/// Evaluates every policy clause and returns one deterministic decision.
pub fn evaluate(
    policy: &DecodedPolicy,
    inputs: EvaluationInputs<'_>,
) -> Result<AcceptanceDecision, AcceptanceError> {
    if !is_digest(inputs.expected_execution_commitment)
        || !is_digest(inputs.composition_id)
        || !is_uuid(inputs.expected_execution_id)
    {
        return Err(AcceptanceError::InvalidIdentity);
    }
    let mut reasons = BTreeSet::new();
    if !policy.identity_matches {
        reasons.insert(RejectionReason::PolicyIdentityMismatch);
    }
    evaluate_execution(
        &policy.policy.execution,
        inputs.execution,
        inputs.release,
        &mut reasons,
    );
    evaluate_release(
        &policy.policy.release,
        &policy.policy.reject_if_present,
        inputs.release,
        &mut reasons,
    );
    if inputs.execution.execution_id != inputs.expected_execution_id {
        reasons.insert(RejectionReason::InputVerificationFailed);
    }
    let reasons = reasons.into_iter().collect::<Vec<_>>();
    let mut wire = WireDecision {
        schema: DECISION_SCHEMA.to_owned(),
        status: if reasons.is_empty() {
            "accepted"
        } else {
            "rejected"
        }
        .to_owned(),
        inputs: inputs.artifacts,
        reasons,
        decision_id: String::new(),
        execution_id: inputs.expected_execution_id.to_owned(),
        composition_id: Some(inputs.composition_id.to_owned()),
        policy_identity: policy.identity.clone(),
        execution_commitment: inputs.expected_execution_commitment.to_owned(),
    };
    validate_artifacts(&wire.inputs)?;
    let mut value = serde_json::to_value(&wire).map_err(|_| AcceptanceError::EncodingFailed)?;
    value
        .as_object_mut()
        .ok_or(AcceptanceError::EncodingFailed)?
        .remove("decision_id");
    wire.decision_id = domain_digest(
        DECISION_DOMAIN,
        &cbor::encode_model(&value).map_err(|_| AcceptanceError::EncodingFailed)?,
    );
    let value = serde_json::to_value(&wire).map_err(|_| AcceptanceError::EncodingFailed)?;
    let bytes = cbor::encode_model(&value).map_err(|_| AcceptanceError::EncodingFailed)?;
    Ok(AcceptanceDecision { wire, bytes })
}

fn evaluate_execution(
    policy: &ExecutionPolicy,
    actual: &ReceiptAcceptanceFacts,
    release: &ReleaseAcceptanceFacts,
    reasons: &mut BTreeSet<RejectionReason>,
) {
    if actual.schema != policy.receipt_schema {
        reasons.insert(RejectionReason::ExecutionSchemaMismatch);
    }
    if actual.runtime_version != policy.runtime_version
        || release.runtime_bundle_version != policy.runtime_version
    {
        reasons.insert(RejectionReason::RuntimeVersionMismatch);
    }
    if actual.operating_system != policy.platform.operating_system {
        reasons.insert(RejectionReason::PlatformMismatch);
    }
    if actual.architecture != policy.platform.architecture
        || release.runtime_bundle_architecture != policy.platform.architecture
    {
        reasons.insert(RejectionReason::ArchitectureMismatch);
    }
    if actual.plan_id != policy.plan_id {
        reasons.insert(RejectionReason::PlanIdMismatch);
    }
    if actual.executable.mode != policy.executable.mode
        || actual.executable.size.parse::<u64>().ok() != Some(policy.executable.size)
        || !same_digest(&actual.executable.sha256, &policy.executable.sha256)
    {
        reasons.insert(RejectionReason::ExecutableMismatch);
    }
    if actual.policy_model_version != policy.policy_model_version
        || !same_digest(&actual.policy_sha256, &policy.policy_sha256)
    {
        reasons.insert(RejectionReason::AuthorityMismatch);
    }
    if actual.pids_max != policy.resources.pids_max
        || actual.memory_max != policy.resources.memory_max
        || actual.memory_oom_group != policy.resources.memory_oom_group
        || actual.memory_swap_max != policy.resources.memory_swap_max
    {
        reasons.insert(RejectionReason::ResourceMismatch);
    }
    let eligibility = if actual.reusable {
        "reusable"
    } else {
        "non-reusable"
    };
    if eligibility != policy.eligibility {
        reasons.insert(RejectionReason::EligibilityMismatch);
    }
    if policy.freshness.mode != "not-required" {
        reasons.insert(RejectionReason::FreshnessPolicyUnsupported);
    }
}

fn evaluate_release(
    policy: &ReleasePolicy,
    reject: &RejectPolicy,
    actual: &ReleaseAcceptanceFacts,
    reasons: &mut BTreeSet<RejectionReason>,
) {
    if actual.project != policy.project {
        reasons.insert(RejectionReason::ReleaseProjectMismatch);
    }
    if actual.project_revision != policy.project_revision {
        reasons.insert(RejectionReason::ReleaseRevisionMismatch);
    }
    if actual.payload_sha256 != policy.payload_sha256 {
        reasons.insert(RejectionReason::ReleasePayloadMismatch);
    }
    if actual.evidence_context != policy.evidence_context {
        reasons.insert(RejectionReason::ReleaseContextMismatch);
    }
    for required in &policy.claims {
        let Some(claim) = actual
            .claims
            .iter()
            .find(|claim| claim.claim_id == required.claim_id)
        else {
            reasons.insert(RejectionReason::ClaimMissing);
            continue;
        };
        compare_claim(required, claim, reasons);
    }
    if intersects(&reject.assumptions, &actual.assumptions) {
        reasons.insert(RejectionReason::ForbiddenAssumption);
    }
    if intersects(&reject.exclusions, &actual.exclusions) {
        reasons.insert(RejectionReason::ForbiddenExclusion);
    }
    if intersects(&reject.open_obligations, &actual.open_obligations) {
        reasons.insert(RejectionReason::ForbiddenOpenObligation);
    }
    if intersects(&reject.tcb_roles, &actual.tcb_roles) {
        reasons.insert(RejectionReason::ForbiddenTcbRole);
    }
}

fn compare_claim(
    required: &ClaimPolicy,
    actual: &AcceptanceClaimFacts,
    reasons: &mut BTreeSet<RejectionReason>,
) {
    if actual.formal != required.formal {
        reasons.insert(RejectionReason::ClaimFormalMismatch);
    }
    if actual.linkage != required.linkage {
        reasons.insert(RejectionReason::ClaimLinkageMismatch);
    }
    if actual.assumption != required.assumption {
        reasons.insert(RejectionReason::ClaimAssumptionMismatch);
    }
    if actual.policy_admitted != required.policy_admitted {
        reasons.insert(RejectionReason::ClaimPolicyMismatch);
    }
}

fn intersects(forbidden: &[String], actual: &[String]) -> bool {
    forbidden.iter().any(|value| actual.contains(value))
}

const INPUT_ROLES: [&str; 14] = [
    "acceptance-policy",
    "release-envelope",
    "compiled-release",
    "release-verification",
    "release-verifier",
    "release-observation-inputs",
    "release-tcb-ledger",
    "runtime-manifest",
    "runtime",
    "launcher",
    "execution-verifier",
    "composer",
    "execution-receipt",
    "execution-verification",
];

fn validate_artifacts(artifacts: &[DecisionInput]) -> Result<(), AcceptanceError> {
    if artifacts.len() != INPUT_ROLES.len()
        || artifacts
            .iter()
            .zip(INPUT_ROLES)
            .any(|(artifact, role)| artifact.role != role || !is_digest(&artifact.sha256))
    {
        return Err(AcceptanceError::InvalidDecision);
    }
    Ok(())
}

fn same_digest(actual: &str, expected: &str) -> bool {
    actual == expected
        || expected
            .strip_prefix("sha256:")
            .is_some_and(|expected| actual == expected)
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    format!("sha256:{}", hex(&hasher.finalize()))
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

fn is_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| is_hex_exact(hex, 32))
}

fn is_hex_exact(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| value.as_bytes().get(index) == Some(&b'-'))
        && value.bytes().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_digit()
                || (b'a'..=b'f').contains(&byte)
        })
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofbound_runtime_compose::{AcceptanceClaimFacts, ReleaseAcceptanceFacts};
    use proofbound_runtime_verify::{CompositionArtifact, ReceiptAcceptanceFacts};

    #[test]
    fn policy_golden_decodes_with_exact_identity() {
        let bytes = bytes_from_hex(include_str!(
            "../../../schemas/vectors/v2/acceptance-policy.cbor.hex"
        ));
        let expected = domain_digest(POLICY_DOMAIN, &bytes);
        let policy = decode_policy(&bytes, &expected).expect("golden policy decodes");
        assert!(policy.identity_matches);
        assert_eq!(policy.identity(), expected);
    }

    #[test]
    fn policy_decoder_rejects_json_and_noncanonical_cbor() {
        assert_eq!(
            decode_policy(b"{}", &format!("sha256:{}", "0".repeat(64))).unwrap_err(),
            AcceptanceError::MalformedPolicy
        );
        assert_eq!(
            decode_policy(
                &[0xa1, 0x61, b'a', 0x18, 0x00],
                &format!("sha256:{}", "0".repeat(64))
            )
            .unwrap_err(),
            AcceptanceError::MalformedPolicy
        );
    }

    #[test]
    fn decision_golden_round_trips_through_the_strict_codec() {
        let bytes = bytes_from_hex(include_str!(
            "../../../schemas/vectors/v2/acceptance-decision.cbor.hex"
        ));
        let model = cbor::decode_model(&bytes).expect("golden decision decodes");
        assert_eq!(
            cbor::encode_model(&model).expect("golden decision encodes"),
            bytes
        );
    }

    #[test]
    fn exact_verified_facts_are_accepted_and_bound() {
        let policy_bytes = bytes_from_hex(include_str!(
            "../../../schemas/vectors/v2/acceptance-policy.cbor.hex"
        ));
        let identity = domain_digest(POLICY_DOMAIN, &policy_bytes);
        let policy = decode_policy(&policy_bytes, &identity).expect("policy decodes");
        let execution = execution_facts();
        let release = release_facts();
        let commitment = digest(b"receipt");
        let composition = digest(b"composition");
        let decision = evaluate(
            &policy,
            EvaluationInputs {
                execution: &execution,
                release: &release,
                expected_execution_commitment: &commitment,
                expected_execution_id: "00112233-4455-4677-8899-aabbccddeeff",
                composition_id: &composition,
                artifacts: input_artifacts(&policy_bytes),
            },
        )
        .expect("decision encodes");
        assert!(decision.accepted());
        assert!(decision.reasons().is_empty());
        assert_eq!(decision.projection().unwrap()["status"], "accepted");
    }

    #[test]
    fn policy_reports_all_independent_mismatches() {
        let policy_bytes = bytes_from_hex(include_str!(
            "../../../schemas/vectors/v2/acceptance-policy.cbor.hex"
        ));
        let policy = decode_policy(&policy_bytes, &format!("sha256:{}", "0".repeat(64)))
            .expect("policy decodes");
        let mut execution = execution_facts();
        execution.plan_id = "substituted".to_owned();
        execution.memory_max += 65_536;
        let mut release = release_facts();
        release.claims[0].formal = "TESTED".to_owned();
        release.assumptions.push("PBR-UNREVIEWED-AX-999".to_owned());
        let decision = evaluate(
            &policy,
            EvaluationInputs {
                execution: &execution,
                release: &release,
                expected_execution_commitment: &digest(b"receipt"),
                expected_execution_id: "00112233-4455-4677-8899-aabbccddeeff",
                composition_id: &digest(b"composition"),
                artifacts: input_artifacts(&policy_bytes),
            },
        )
        .expect("rejection encodes");
        assert!(!decision.accepted());
        assert_eq!(
            decision.reasons(),
            &[
                RejectionReason::PolicyIdentityMismatch,
                RejectionReason::PlanIdMismatch,
                RejectionReason::ResourceMismatch,
                RejectionReason::ClaimFormalMismatch,
                RejectionReason::ForbiddenAssumption,
            ]
        );
    }

    fn execution_facts() -> ReceiptAcceptanceFacts {
        ReceiptAcceptanceFacts {
            schema: "proofbound-runtime-execution-receipt/2".to_owned(),
            runtime_version: "0.2.0".to_owned(),
            execution_id: "00112233-4455-4677-8899-aabbccddeeff".to_owned(),
            plan_id: "golden-v2".to_owned(),
            operating_system: "linux".to_owned(),
            architecture: "x86_64",
            executable: CompositionArtifact {
                mode: 0o755,
                role: "runtime-executable",
                sha256: digest(b"golden executable"),
                size: b"golden executable".len().to_string(),
            },
            policy_sha256: digest(b"golden policy"),
            policy_model_version: "proofbound-runtime-linux-policy/2".to_owned(),
            pids_max: 2,
            memory_max: 65_536,
            memory_oom_group: 1,
            memory_swap_max: 0,
            reusable: true,
            assumptions: Vec::new(),
            tcb_roles: Vec::new(),
        }
    }

    fn release_facts() -> ReleaseAcceptanceFacts {
        ReleaseAcceptanceFacts {
            composition_id: digest(b"composition"),
            project: "proofbound-runtime".to_owned(),
            project_revision: "11".repeat(20),
            payload_sha256: digest(b"golden release payload"),
            evidence_context: "release-linux-x86-64-runtime".to_owned(),
            runtime_bundle_version: "0.2.0".to_owned(),
            runtime_bundle_architecture: "x86_64".to_owned(),
            claims: vec![
                AcceptanceClaimFacts {
                    claim_id: "PBR-AUTH-001".to_owned(),
                    formal: "PROVED".to_owned(),
                    linkage: "ARTIFACT_BOUND".to_owned(),
                    assumption: "ASSUMED".to_owned(),
                    policy_admitted: true,
                },
                AcceptanceClaimFacts {
                    claim_id: "PBR-RESOURCE-010".to_owned(),
                    formal: "TESTED".to_owned(),
                    linkage: "ARTIFACT_BOUND".to_owned(),
                    assumption: "ASSUMED".to_owned(),
                    policy_admitted: true,
                },
            ],
            assumptions: Vec::new(),
            exclusions: Vec::new(),
            open_obligations: Vec::new(),
            tcb_roles: Vec::new(),
        }
    }

    fn input_artifacts(policy: &[u8]) -> Vec<DecisionInput> {
        INPUT_ROLES
            .iter()
            .map(|role| {
                DecisionInput::new(
                    role,
                    if *role == "acceptance-policy" {
                        policy
                    } else {
                        role.as_bytes()
                    },
                )
            })
            .collect()
    }

    fn bytes_from_hex(text: &str) -> Vec<u8> {
        text.trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid hex"),
        }
    }
}
