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
const POLICY_SCHEMA_V2: &str = "proofbound-runtime-acceptance-policy/2";
const DECISION_SCHEMA: &str = "proofbound-runtime-acceptance-decision/2";
const DECISION_SCHEMA_V3: &str = "proofbound-runtime-acceptance-decision/3";
const POLICY_DOMAIN: &[u8] = b"proofbound-runtime-acceptance-policy/1\0";
const POLICY_DOMAIN_V2: &[u8] = b"proofbound-runtime-acceptance-policy/2\0";
const DECISION_DOMAIN: &[u8] = b"proofbound-runtime-acceptance-decision/2\0";
const DECISION_DOMAIN_V3: &[u8] = b"proofbound-runtime-acceptance-decision/3\0";

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
    #[serde(default)]
    network: Option<Value>,
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
    directory_sha256: String,
    project: String,
    payload_sha256: String,
    evidence_context: String,
    project_revision: String,
    verifier_sha256: String,
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
    let identity = domain_digest(
        if policy.schema == POLICY_SCHEMA_V2 {
            POLICY_DOMAIN_V2
        } else {
            POLICY_DOMAIN
        },
        bytes,
    );
    Ok(DecodedPolicy {
        identity_matches: identity == expected_identity,
        identity,
        policy,
    })
}

fn validate_policy(policy: &AcceptancePolicy) -> Result<(), AcceptanceError> {
    let execution = &policy.execution;
    let release = &policy.release;
    let version_two = policy.schema == POLICY_SCHEMA_V2;
    if !matches!(policy.schema.as_str(), POLICY_SCHEMA | POLICY_SCHEMA_V2)
        || execution.receipt_schema
            != if version_two {
                "proofbound-runtime-execution-receipt/3"
            } else {
                "proofbound-runtime-execution-receipt/2"
            }
        || execution.policy_model_version
            != if version_two {
                "proofbound-runtime-linux-policy/3"
            } else {
                "proofbound-runtime-linux-policy/2"
            }
        || (version_two
            && execution
                .network
                .as_ref()
                .is_none_or(|value| !valid_network_predicate(value)))
        || (!version_two && execution.network.is_some())
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
        || !execution.resources.memory_max.is_multiple_of(65_536)
        || !execution.resources.memory_swap_max.is_multiple_of(65_536)
        || execution.resources.memory_oom_group != 1
        || !is_digest(&execution.executable.sha256)
        || !is_digest(&execution.policy_sha256)
        || release.project.is_empty()
        || release.evidence_context.is_empty()
        || release.evidence_context.len() > 128
        || !is_digest(&release.payload_sha256)
        || !is_digest(&release.directory_sha256)
        || !is_digest(&release.verifier_sha256)
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

fn valid_network_predicate(value: &Value) -> bool {
    if value == "deny" {
        return true;
    }
    let Some(map) = value.as_object() else {
        return false;
    };
    if map.len() != 4
        || map.get("mode").and_then(Value::as_str) != Some("declared-egress")
        || !matches!(
            map.get("relation").and_then(Value::as_str),
            Some("equal" | "subset")
        )
        || map
            .get("proxy_executable_sha256")
            .and_then(Value::as_str)
            .is_none_or(|value| !is_digest(value))
    {
        return false;
    }
    let Some(endpoints) = map.get("endpoints").and_then(Value::as_array) else {
        return false;
    };
    if endpoints.is_empty() || endpoints.len() > 256 || !endpoints.iter().all(valid_egress_endpoint)
    {
        return false;
    }
    let keys = endpoints
        .iter()
        .map(endpoint_sort_key)
        .collect::<Option<Vec<_>>>();
    keys.is_some_and(|keys| keys.windows(2).all(|pair| pair[0] < pair[1]))
        && endpoints.iter().all(|endpoint| {
            let destination = &endpoint["destination"];
            let Some(name) = destination.get("name").and_then(Value::as_str) else {
                return true;
            };
            endpoints.iter().all(|other| {
                other["destination"]["name"] != name
                    || other["destination"]["address_scope"] == destination["address_scope"]
            })
        })
}

fn endpoint_sort_key(value: &Value) -> Option<(u8, String, u64)> {
    let destination = value.get("destination")?;
    let kind = destination.get("kind")?.as_str()?;
    let (rank, target) = match kind {
        "dns-name" => (0, destination.get("name")?.as_str()?),
        "ipv4" => (1, destination.get("bytes")?.as_str()?),
        "ipv6" => (2, destination.get("bytes")?.as_str()?),
        _ => return None,
    };
    Some((rank, target.to_owned(), value.get("port")?.as_u64()?))
}

fn valid_egress_endpoint(value: &Value) -> bool {
    let Some(map) = value.as_object() else {
        return false;
    };
    if map.len() != 4
        || map.get("protocol").and_then(Value::as_str) != Some("tcp")
        || !matches!(map.get("port").and_then(Value::as_u64), Some(1..=65535))
    {
        return false;
    }
    let Some(destination) = map.get("destination").and_then(Value::as_object) else {
        return false;
    };
    let destination_valid = match destination.get("kind").and_then(Value::as_str) {
        Some("dns-name") => {
            destination.len() == 3
                && destination
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(valid_egress_name)
                && matches!(
                    destination.get("address_scope").and_then(Value::as_str),
                    Some("global" | "global-or-private")
                )
        }
        Some(kind @ ("ipv4" | "ipv6")) => {
            destination.len() == 2
                && destination
                    .get("bytes")
                    .and_then(Value::as_str)
                    .is_some_and(|value| valid_egress_literal(kind, value))
        }
        _ => false,
    };
    let sni_valid = match map.get("tls_sni") {
        Some(Value::String(value)) => value == "not-inspected",
        Some(Value::Object(sni)) => {
            sni.len() == 2
                && sni.get("mode").and_then(Value::as_str) == Some("required")
                && sni
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(valid_egress_name)
        }
        _ => false,
    };
    destination_valid
        && sni_valid
        && (destination.get("kind").and_then(Value::as_str) != Some("dns-name")
            || map
                .get("tls_sni")
                .and_then(Value::as_object)
                .is_none_or(|sni| sni.get("name") == destination.get("name")))
}

fn valid_egress_literal(kind: &str, value: &str) -> bool {
    let Some(raw) = value.strip_prefix("hex:") else {
        return false;
    };
    if raw.len() != if kind == "ipv4" { 8 } else { 32 }
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return false;
    }
    let bytes = raw
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    if kind == "ipv4" {
        let address = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
        !address.is_unspecified() && !address.is_multicast() && bytes != [255; 4]
    } else {
        let octets: [u8; 16] = bytes.try_into().expect("checked IPv6 byte length");
        let address = std::net::Ipv6Addr::from(octets);
        !address.is_unspecified()
            && !address.is_multicast()
            && address.to_ipv4_mapped().is_none()
            && (octets[..12] != [0; 12] || address.is_loopback())
    }
}

fn valid_egress_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.is_ascii()
        && name.split('.').count() >= 2
        && name
            .split('.')
            .next_back()
            .is_some_and(|label| !label.bytes().all(|byte| byte.is_ascii_digit()))
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RejectionReason {
    PolicyIdentityMismatch,
    ReleaseVerificationFailed,
    ExecutionVerificationFailed,
    DiagnosticProfileNotReusable,
    InputVerificationFailed,
    CompositionMissing,
    ExecutionReplay,
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
    ReleaseDirectoryMismatch,
    ReleaseVerifierMismatch,
    ClaimMissing,
    ClaimFormalMismatch,
    ClaimLinkageMismatch,
    ClaimAssumptionMismatch,
    ClaimPolicyMismatch,
    ForbiddenAssumption,
    ForbiddenExclusion,
    ForbiddenOpenObligation,
    ForbiddenTcbRole,
    NetworkModeMismatch,
    EgressEndpointNotAllowed,
    EgressProxyIdentityMismatch,
}

impl RejectionReason {
    const fn is_egress(self) -> bool {
        matches!(
            self,
            Self::NetworkModeMismatch
                | Self::EgressEndpointNotAllowed
                | Self::EgressProxyIdentityMismatch
        )
    }

    /// Returns the complete closed reason vocabulary in canonical order.
    #[must_use]
    pub const fn all_codes() -> &'static [&'static str] {
        &[
            "architecture-mismatch",
            "authority-mismatch",
            "claim-assumption-mismatch",
            "claim-formal-mismatch",
            "claim-linkage-mismatch",
            "claim-missing",
            "claim-policy-mismatch",
            "composition-missing",
            "diagnostic-profile-not-reusable",
            "egress-endpoint-not-allowed",
            "egress-proxy-identity-mismatch",
            "eligibility-mismatch",
            "executable-mismatch",
            "execution-replay",
            "execution-schema-mismatch",
            "execution-verification-failed",
            "forbidden-assumption",
            "forbidden-exclusion",
            "forbidden-open-obligation",
            "forbidden-tcb-role",
            "freshness-policy-unsupported",
            "input-verification-failed",
            "network-mode-mismatch",
            "plan-id-mismatch",
            "platform-mismatch",
            "policy-identity-mismatch",
            "release-context-mismatch",
            "release-directory-mismatch",
            "release-payload-mismatch",
            "release-project-mismatch",
            "release-revision-mismatch",
            "release-verification-failed",
            "release-verifier-mismatch",
            "resource-mismatch",
            "runtime-version-mismatch",
        ]
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyIdentityMismatch => "policy-identity-mismatch",
            Self::ReleaseVerificationFailed => "release-verification-failed",
            Self::ExecutionVerificationFailed => "execution-verification-failed",
            Self::DiagnosticProfileNotReusable => "diagnostic-profile-not-reusable",
            Self::InputVerificationFailed => "input-verification-failed",
            Self::CompositionMissing => "composition-missing",
            Self::ExecutionReplay => "execution-replay",
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
            Self::ReleaseDirectoryMismatch => "release-directory-mismatch",
            Self::ReleaseVerifierMismatch => "release-verifier-mismatch",
            Self::ClaimMissing => "claim-missing",
            Self::ClaimFormalMismatch => "claim-formal-mismatch",
            Self::ClaimLinkageMismatch => "claim-linkage-mismatch",
            Self::ClaimAssumptionMismatch => "claim-assumption-mismatch",
            Self::ClaimPolicyMismatch => "claim-policy-mismatch",
            Self::ForbiddenAssumption => "forbidden-assumption",
            Self::ForbiddenExclusion => "forbidden-exclusion",
            Self::ForbiddenOpenObligation => "forbidden-open-obligation",
            Self::ForbiddenTcbRole => "forbidden-tcb-role",
            Self::NetworkModeMismatch => "network-mode-mismatch",
            Self::EgressEndpointNotAllowed => "egress-endpoint-not-allowed",
            Self::EgressProxyIdentityMismatch => "egress-proxy-identity-mismatch",
        }
    }
}

impl Ord for RejectionReason {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_str().as_bytes().cmp(other.as_str().as_bytes())
    }
}

impl PartialOrd for RejectionReason {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Exact bytes consumed or produced by one decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
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
    pub proofbound_release_sha256: &'a str,
    pub proofbound_verifier_sha256: &'a str,
    pub artifacts: Vec<DecisionInput>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
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

/// Strictly decodes, checks, and returns the non-authoritative JSON projection
/// of one canonical decision.
pub fn project_decision(bytes: &[u8]) -> Result<Value, AcceptanceError> {
    let value = cbor::decode_model(bytes).map_err(|_| AcceptanceError::InvalidDecision)?;
    let wire: WireDecision =
        serde_json::from_value(value).map_err(|_| AcceptanceError::InvalidDecision)?;
    if !matches!(wire.schema.as_str(), DECISION_SCHEMA | DECISION_SCHEMA_V3)
        || !is_digest(&wire.decision_id)
        || !is_digest(&wire.policy_identity)
        || !is_digest(&wire.execution_commitment)
        || !is_uuid(&wire.execution_id)
        || wire
            .composition_id
            .as_deref()
            .is_some_and(|value| !is_digest(value))
        || !wire.reasons.windows(2).all(|pair| pair[0] < pair[1])
        || (wire.schema == DECISION_SCHEMA && wire.reasons.iter().any(|reason| reason.is_egress()))
        || (wire.status == "accepted"
            && (!wire.reasons.is_empty() || wire.composition_id.is_none()))
        || (wire.status == "rejected" && wire.reasons.is_empty())
        || !matches!(wire.status.as_str(), "accepted" | "rejected")
    {
        return Err(AcceptanceError::InvalidDecision);
    }
    validate_artifacts(&wire.inputs)?;
    let mut body = serde_json::to_value(&wire).map_err(|_| AcceptanceError::InvalidDecision)?;
    body.as_object_mut()
        .ok_or(AcceptanceError::InvalidDecision)?
        .remove("decision_id");
    let encoded = cbor::encode_model(&body).map_err(|_| AcceptanceError::InvalidDecision)?;
    let domain = if wire.schema == DECISION_SCHEMA_V3 {
        DECISION_DOMAIN_V3
    } else {
        DECISION_DOMAIN
    };
    if domain_digest(domain, &encoded) != wire.decision_id {
        return Err(AcceptanceError::InvalidDecision);
    }
    cbor::project_json(bytes).map_err(|_| AcceptanceError::InvalidDecision)
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
        inputs.proofbound_release_sha256,
        inputs.proofbound_verifier_sha256,
        &mut reasons,
    );
    if inputs.execution.execution_id != inputs.expected_execution_id {
        reasons.insert(RejectionReason::InputVerificationFailed);
    }
    build_decision(
        policy,
        inputs.expected_execution_commitment,
        inputs.expected_execution_id,
        Some(inputs.composition_id),
        inputs.artifacts,
        reasons.into_iter().collect(),
    )
}

/// Produces a canonical rejection when either independent verifier or the
/// composition boundary rejects its raw inputs. No unverified facts are used.
pub fn reject_unverified(
    policy: &DecodedPolicy,
    expected_execution_commitment: &str,
    expected_execution_id: &str,
    artifacts: Vec<DecisionInput>,
    reason: RejectionReason,
) -> Result<AcceptanceDecision, AcceptanceError> {
    let mut reasons = vec![reason];
    if !policy.identity_matches {
        reasons.push(RejectionReason::PolicyIdentityMismatch);
        reasons.sort_unstable();
    }
    build_decision(
        policy,
        expected_execution_commitment,
        expected_execution_id,
        None,
        artifacts,
        reasons,
    )
}

fn build_decision(
    policy: &DecodedPolicy,
    expected_execution_commitment: &str,
    expected_execution_id: &str,
    composition_id: Option<&str>,
    artifacts: Vec<DecisionInput>,
    reasons: Vec<RejectionReason>,
) -> Result<AcceptanceDecision, AcceptanceError> {
    if !is_digest(expected_execution_commitment)
        || composition_id.is_some_and(|value| !is_digest(value))
        || !is_uuid(expected_execution_id)
    {
        return Err(AcceptanceError::InvalidIdentity);
    }
    if policy.policy.schema == POLICY_SCHEMA && reasons.iter().any(|reason| reason.is_egress()) {
        return Err(AcceptanceError::InvalidDecision);
    }
    let mut wire = WireDecision {
        schema: if policy.policy.schema == POLICY_SCHEMA_V2 {
            DECISION_SCHEMA_V3
        } else {
            DECISION_SCHEMA
        }
        .to_owned(),
        status: if reasons.is_empty() {
            "accepted"
        } else {
            "rejected"
        }
        .to_owned(),
        inputs: artifacts,
        reasons,
        decision_id: String::new(),
        execution_id: expected_execution_id.to_owned(),
        composition_id: composition_id.map(str::to_owned),
        policy_identity: policy.identity.clone(),
        execution_commitment: expected_execution_commitment.to_owned(),
    };
    validate_artifacts(&wire.inputs)?;
    let mut value = serde_json::to_value(&wire).map_err(|_| AcceptanceError::EncodingFailed)?;
    value
        .as_object_mut()
        .ok_or(AcceptanceError::EncodingFailed)?
        .remove("decision_id");
    wire.decision_id = domain_digest(
        if policy.policy.schema == POLICY_SCHEMA_V2 {
            DECISION_DOMAIN_V3
        } else {
            DECISION_DOMAIN
        },
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
    if let Some(network) = &policy.network {
        evaluate_network(network, actual.network.as_ref(), reasons);
    }
}

fn evaluate_network(
    policy: &Value,
    actual: Option<&Value>,
    reasons: &mut BTreeSet<RejectionReason>,
) {
    let Some(actual) = actual else {
        reasons.insert(RejectionReason::NetworkModeMismatch);
        return;
    };
    let mode = actual.get("mode").and_then(Value::as_str);
    if policy == "deny" {
        if mode != Some("deny") {
            reasons.insert(RejectionReason::NetworkModeMismatch);
        }
        return;
    }
    if mode != Some("declared-egress") {
        reasons.insert(RejectionReason::NetworkModeMismatch);
        return;
    }
    let Some(observation) = actual.get("observation") else {
        reasons.insert(RejectionReason::InputVerificationFailed);
        return;
    };
    let Some(expected) = policy.get("endpoints").and_then(Value::as_array) else {
        return;
    };
    let Some(observed) = observation
        .pointer("/authority/endpoints")
        .and_then(Value::as_array)
    else {
        reasons.insert(RejectionReason::InputVerificationFailed);
        return;
    };
    let expected_set = expected
        .iter()
        .map(Value::to_string)
        .collect::<BTreeSet<_>>();
    let observed_set = observed
        .iter()
        .map(Value::to_string)
        .collect::<BTreeSet<_>>();
    let relation = policy.get("relation").and_then(Value::as_str);
    if !observed_set.is_subset(&expected_set)
        || (relation == Some("equal") && observed_set != expected_set)
    {
        reasons.insert(RejectionReason::EgressEndpointNotAllowed);
    }
    let pinned = policy
        .get("proxy_executable_sha256")
        .and_then(Value::as_str);
    let observed = observation
        .pointer("/proxy/executable/sha256")
        .and_then(Value::as_str);
    if pinned.and_then(digest_body) != observed.and_then(digest_body) {
        reasons.insert(RejectionReason::EgressProxyIdentityMismatch);
    }
}

fn digest_body(value: &str) -> Option<&str> {
    value
        .strip_prefix("sha256:")
        .or_else(|| value.strip_prefix("hex:"))
}

fn evaluate_release(
    policy: &ReleasePolicy,
    reject: &RejectPolicy,
    actual: &ReleaseAcceptanceFacts,
    proofbound_release_sha256: &str,
    proofbound_verifier_sha256: &str,
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
    if !same_digest(proofbound_release_sha256, &policy.directory_sha256) {
        reasons.insert(RejectionReason::ReleaseDirectoryMismatch);
    }
    if !same_digest(proofbound_verifier_sha256, &policy.verifier_sha256) {
        reasons.insert(RejectionReason::ReleaseVerifierMismatch);
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

const INPUT_ROLES: [&str; 15] = [
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
    "acceptor",
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
    use serde::Deserialize;

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
        expected_reason: String,
    }

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
    fn version_two_policy_golden_decodes_with_its_own_domain() {
        let bytes = bytes_from_hex(include_str!(
            "../../../schemas/vectors/v3/acceptance-policy.cbor.hex"
        ));
        let expected = domain_digest(POLICY_DOMAIN_V2, &bytes);
        let policy = decode_policy(&bytes, &expected).expect("version two policy decodes");
        assert!(policy.identity_matches);
        assert_eq!(policy.policy.schema, POLICY_SCHEMA_V2);
        assert_eq!(
            policy.policy.execution.network,
            Some(Value::String("deny".to_owned()))
        );
    }

    #[test]
    fn version_two_deny_policy_rejects_egress_receipt() {
        let bytes = bytes_from_hex(include_str!(
            "../../../schemas/vectors/v3/acceptance-policy.cbor.hex"
        ));
        let policy = decode_policy(&bytes, &domain_digest(POLICY_DOMAIN_V2, &bytes))
            .expect("version two policy decodes");
        let mut execution = execution_facts();
        execution.schema = "proofbound-runtime-execution-receipt/3".to_owned();
        execution.policy_model_version = "proofbound-runtime-linux-policy/3".to_owned();
        execution.network = Some(serde_json::json!({
            "mode": "declared-egress",
            "observation": {"authority": {"endpoints": []}, "proxy": {"executable": {"sha256": format!("hex:{}", "1".repeat(64))}}}
        }));
        let decision = evaluate(
            &policy,
            EvaluationInputs {
                execution: &execution,
                release: &release_facts(),
                expected_execution_commitment: &digest(b"receipt"),
                expected_execution_id: "00112233-4455-4677-8899-aabbccddeeff",
                composition_id: &digest(b"composition"),
                proofbound_release_sha256: &digest(b"golden Proofbound release directory"),
                proofbound_verifier_sha256: &digest(b"golden Proofbound verifier"),
                artifacts: input_artifacts(&bytes),
            },
        )
        .expect("decision encodes");
        assert_eq!(decision.wire.schema, DECISION_SCHEMA_V3);
        assert!(
            decision
                .reasons()
                .contains(&RejectionReason::NetworkModeMismatch)
        );
        assert!(!decision.accepted());
        project_decision(decision.bytes()).expect("version three decision verifies");
    }

    #[test]
    fn declared_egress_policy_checks_endpoint_relation_and_exact_proxy() {
        let golden = bytes_from_hex(include_str!(
            "../../../schemas/vectors/v3/acceptance-policy.cbor.hex"
        ));
        let mut model = cbor::decode_model(&golden).expect("policy model decodes");
        let endpoint = serde_json::json!({
            "destination": {"kind": "ipv4", "bytes": "hex:01010101"},
            "port": 443,
            "protocol": "tcp",
            "tls_sni": "not-inspected"
        });
        let proxy_digest = digest(b"exact proxy");
        model["execution"]["network"] = serde_json::json!({
            "mode": "declared-egress",
            "endpoints": [endpoint.clone()],
            "relation": "equal",
            "proxy_executable_sha256": proxy_digest
        });
        let policy_bytes = cbor::encode_model(&model).expect("policy encodes");
        let policy = decode_policy(
            &policy_bytes,
            &domain_digest(POLICY_DOMAIN_V2, &policy_bytes),
        )
        .expect("declared egress policy decodes");
        let mut execution = execution_facts();
        execution.schema = "proofbound-runtime-execution-receipt/3".to_owned();
        execution.policy_model_version = "proofbound-runtime-linux-policy/3".to_owned();
        execution.network = Some(serde_json::json!({
            "mode": "declared-egress",
            "observation": {
                "authority": {"endpoints": [endpoint]},
                "proxy": {"executable": {"sha256": format!("hex:{}", digest_body(&proxy_digest).unwrap())}}
            }
        }));
        let decide = |facts: &ReceiptAcceptanceFacts| {
            evaluate(
                &policy,
                EvaluationInputs {
                    execution: facts,
                    release: &release_facts(),
                    expected_execution_commitment: &digest(b"receipt"),
                    expected_execution_id: "00112233-4455-4677-8899-aabbccddeeff",
                    composition_id: &digest(b"composition"),
                    proofbound_release_sha256: &digest(b"golden Proofbound release directory"),
                    proofbound_verifier_sha256: &digest(b"golden Proofbound verifier"),
                    artifacts: input_artifacts(&policy_bytes),
                },
            )
            .expect("decision encodes")
        };
        assert!(decide(&execution).accepted());
        execution.network.as_mut().unwrap()["observation"]["authority"]["endpoints"] =
            serde_json::json!([]);
        assert!(
            decide(&execution)
                .reasons()
                .contains(&RejectionReason::EgressEndpointNotAllowed)
        );
        execution.network.as_mut().unwrap()["observation"]["authority"]["endpoints"] =
            model["execution"]["network"]["endpoints"].clone();
        execution.network.as_mut().unwrap()["observation"]["proxy"]["executable"]["sha256"] =
            serde_json::json!(format!("hex:{}", "0".repeat(64)));
        assert!(
            decide(&execution)
                .reasons()
                .contains(&RejectionReason::EgressProxyIdentityMismatch)
        );

        execution.network.as_mut().unwrap()["mode"] = serde_json::json!("deny");
        assert!(
            decide(&execution)
                .reasons()
                .contains(&RejectionReason::NetworkModeMismatch)
        );

        // An attacker cannot turn an exact endpoint relation into subset
        // without changing the policy identity selected by the caller.
        model["execution"]["network"]["relation"] = serde_json::json!("subset");
        let downgraded_bytes = cbor::encode_model(&model).expect("policy re-encodes");
        let downgraded = decode_policy(
            &downgraded_bytes,
            &domain_digest(POLICY_DOMAIN_V2, &policy_bytes),
        )
        .expect("policy decodes with mismatched identity");
        let decision = evaluate(
            &downgraded,
            EvaluationInputs {
                execution: &execution,
                release: &release_facts(),
                expected_execution_commitment: &digest(b"receipt"),
                expected_execution_id: "00112233-4455-4677-8899-aabbccddeeff",
                composition_id: &digest(b"composition"),
                proofbound_release_sha256: &digest(b"golden Proofbound release directory"),
                proofbound_verifier_sha256: &digest(b"golden Proofbound verifier"),
                artifacts: input_artifacts(&downgraded_bytes),
            },
        )
        .expect("decision encodes");
        assert!(
            decision
                .reasons()
                .contains(&RejectionReason::PolicyIdentityMismatch)
        );
    }

    #[test]
    fn version_two_policy_rejects_endpoints_outside_the_plan_domain() {
        let golden = bytes_from_hex(include_str!(
            "../../../schemas/vectors/v3/acceptance-policy.cbor.hex"
        ));
        let mut model = cbor::decode_model(&golden).expect("policy model decodes");
        let base = serde_json::json!({
            "mode": "declared-egress",
            "endpoints": [{
                "destination": {"kind": "dns-name", "name": "api.example", "address_scope": "global"},
                "port": 443,
                "protocol": "tcp",
                "tls_sni": "not-inspected"
            }],
            "relation": "equal",
            "proxy_executable_sha256": digest(b"exact proxy")
        });
        for invalid in [
            serde_json::json!({"kind": "dns-name", "name": "localhost", "address_scope": "global"}),
            serde_json::json!({"kind": "dns-name", "name": "api.123", "address_scope": "global"}),
            serde_json::json!({"kind": "ipv4", "bytes": "hex:00000000"}),
            serde_json::json!({"kind": "ipv4", "bytes": "hex:ffffffff"}),
            serde_json::json!({"kind": "ipv6", "bytes": "hex:00000000000000000000ffff01020304"}),
        ] {
            let mut network = base.clone();
            network["endpoints"][0]["destination"] = invalid;
            model["execution"]["network"] = network;
            let bytes = cbor::encode_model(&model).expect("policy encodes");
            assert_eq!(
                decode_policy(&bytes, &domain_digest(POLICY_DOMAIN_V2, &bytes)).unwrap_err(),
                AcceptanceError::InvalidPolicy
            );
        }
        let mut network = base;
        network["endpoints"][0]["tls_sni"] =
            serde_json::json!({"mode": "required", "name": "other.example"});
        model["execution"]["network"] = network;
        let bytes = cbor::encode_model(&model).expect("policy encodes");
        assert_eq!(
            decode_policy(&bytes, &domain_digest(POLICY_DOMAIN_V2, &bytes)).unwrap_err(),
            AcceptanceError::InvalidPolicy
        );

        let mut network = serde_json::json!({
            "mode": "declared-egress",
            "endpoints": [
                {"destination": {"kind": "ipv4", "bytes": "hex:01010101"}, "port": 443, "protocol": "tcp", "tls_sni": "not-inspected"},
                {"destination": {"kind": "dns-name", "name": "api.example", "address_scope": "global"}, "port": 443, "protocol": "tcp", "tls_sni": "not-inspected"}
            ],
            "relation": "equal",
            "proxy_executable_sha256": digest(b"exact proxy")
        });
        model["execution"]["network"] = network.clone();
        let bytes = cbor::encode_model(&model).expect("policy encodes");
        assert_eq!(
            decode_policy(&bytes, &domain_digest(POLICY_DOMAIN_V2, &bytes)).unwrap_err(),
            AcceptanceError::InvalidPolicy
        );

        network["endpoints"] = serde_json::json!([
            {"destination": {"kind": "dns-name", "name": "api.example", "address_scope": "global"}, "port": 443, "protocol": "tcp", "tls_sni": "not-inspected"},
            {"destination": {"kind": "dns-name", "name": "api.example", "address_scope": "global-or-private"}, "port": 8443, "protocol": "tcp", "tls_sni": "not-inspected"}
        ]);
        model["execution"]["network"] = network;
        let bytes = cbor::encode_model(&model).expect("policy encodes");
        assert_eq!(
            decode_policy(&bytes, &domain_digest(POLICY_DOMAIN_V2, &bytes)).unwrap_err(),
            AcceptanceError::InvalidPolicy
        );
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
        for incomplete_large_container in [
            [0x9a, 0x00, 0x0f, 0x42, 0x40],
            [0xba, 0x00, 0x0f, 0x42, 0x40],
        ] {
            assert_eq!(
                decode_policy(
                    &incomplete_large_container,
                    &format!("sha256:{}", "0".repeat(64))
                )
                .unwrap_err(),
                AcceptanceError::MalformedPolicy
            );
        }
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
    fn version_three_decision_golden_has_a_valid_identity() {
        let bytes = bytes_from_hex(include_str!(
            "../../../schemas/vectors/v3/acceptance-decision.cbor.hex"
        ));
        let projected = project_decision(&bytes).expect("version three golden decision verifies");
        assert_eq!(projected["schema"], DECISION_SCHEMA_V3);
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
                proofbound_release_sha256: &digest(b"golden Proofbound release directory"),
                proofbound_verifier_sha256: &digest(b"golden Proofbound verifier"),
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
                proofbound_release_sha256: &digest(b"substituted Proofbound release directory"),
                proofbound_verifier_sha256: &digest(b"substituted Proofbound verifier"),
                artifacts: input_artifacts(&policy_bytes),
            },
        )
        .expect("rejection encodes");
        assert!(!decision.accepted());
        assert_eq!(
            decision.reasons(),
            &[
                RejectionReason::ClaimFormalMismatch,
                RejectionReason::ForbiddenAssumption,
                RejectionReason::PlanIdMismatch,
                RejectionReason::PolicyIdentityMismatch,
                RejectionReason::ReleaseDirectoryMismatch,
                RejectionReason::ReleaseVerifierMismatch,
                RejectionReason::ResourceMismatch,
            ]
        );
    }

    #[test]
    fn registered_attack_catalog_is_closed_and_complete() {
        let catalog: AttackCatalog =
            toml::from_str(include_str!("../../../tests/attacks/acceptance/v1.toml"))
                .expect("attack catalog is closed TOML");
        assert_eq!(catalog.schema, "proofbound-runtime-acceptance-attacks/1");
        assert!(
            RejectionReason::all_codes()
                .windows(2)
                .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
        );
        assert_eq!(
            catalog
                .cases
                .iter()
                .map(|case| case.id.as_str())
                .collect::<Vec<_>>(),
            [
                "claim-omission",
                "executable-substitution",
                "resource-substitution",
                "facet-downgrade",
                "execution-replay",
                "stale-policy",
                "assumption-loss",
                "forged-acceptance",
            ]
        );
        assert!(catalog.cases.iter().all(|case| {
            !case.mutation.is_empty()
                && (case.expected_reason.starts_with("acceptance.")
                    || RejectionReason::all_codes().contains(&case.expected_reason.as_str()))
        }));
    }

    #[test]
    fn omission_substitution_and_replay_are_independent_rejections() {
        let policy_bytes = bytes_from_hex(include_str!(
            "../../../schemas/vectors/v2/acceptance-policy.cbor.hex"
        ));
        let identity = domain_digest(POLICY_DOMAIN, &policy_bytes);
        let policy = decode_policy(&policy_bytes, &identity).expect("policy decodes");

        let execution = execution_facts();
        let mut omitted = release_facts();
        omitted.claims.remove(0);
        assert_decision_reasons(
            &policy,
            &execution,
            &omitted,
            "00112233-4455-4677-8899-aabbccddeeff",
            &policy_bytes,
            &[RejectionReason::ClaimMissing],
        );

        let mut substituted = execution_facts();
        substituted.executable.sha256 = digest(b"substituted executable");
        assert_decision_reasons(
            &policy,
            &substituted,
            &release_facts(),
            "00112233-4455-4677-8899-aabbccddeeff",
            &policy_bytes,
            &[RejectionReason::ExecutableMismatch],
        );

        assert_decision_reasons(
            &policy,
            &execution,
            &release_facts(),
            "11112233-4455-4677-8899-aabbccddeeff",
            &policy_bytes,
            &[RejectionReason::InputVerificationFailed],
        );
    }

    #[test]
    fn reusable_policy_rejects_verified_non_reusable_execution_by_policy() {
        let policy_bytes = bytes_from_hex(include_str!(
            "../../../schemas/vectors/v2/acceptance-policy.cbor.hex"
        ));
        let identity = domain_digest(POLICY_DOMAIN, &policy_bytes);
        let policy = decode_policy(&policy_bytes, &identity).expect("policy decodes");
        let mut execution = execution_facts();
        execution.reusable = false;

        assert_decision_reasons(
            &policy,
            &execution,
            &release_facts(),
            "00112233-4455-4677-8899-aabbccddeeff",
            &policy_bytes,
            &[RejectionReason::EligibilityMismatch],
        );
    }

    #[test]
    fn forged_acceptance_fails_closed() {
        let mut forged = bytes_from_hex(include_str!(
            "../../../schemas/vectors/v2/acceptance-decision.cbor.hex"
        ));
        let offset = forged
            .windows(b"accepted".len())
            .position(|window| window == b"accepted")
            .expect("golden contains accepted status");
        forged[offset..offset + 8].copy_from_slice(b"rejected");
        assert_eq!(
            project_decision(&forged),
            Err(AcceptanceError::InvalidDecision)
        );
    }

    fn assert_decision_reasons(
        policy: &DecodedPolicy,
        execution: &ReceiptAcceptanceFacts,
        release: &ReleaseAcceptanceFacts,
        expected_execution_id: &str,
        policy_bytes: &[u8],
        expected: &[RejectionReason],
    ) {
        let decision = evaluate(
            policy,
            EvaluationInputs {
                execution,
                release,
                expected_execution_commitment: &digest(b"receipt"),
                expected_execution_id,
                composition_id: &digest(b"composition"),
                proofbound_release_sha256: &digest(b"golden Proofbound release directory"),
                proofbound_verifier_sha256: &digest(b"golden Proofbound verifier"),
                artifacts: input_artifacts(policy_bytes),
            },
        )
        .expect("decision encodes");
        assert_eq!(decision.reasons(), expected);
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
            network: None,
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
