//! Strictly decodes the closed version 1 execution-receipt structure.

use core::fmt;
use core::num::NonZeroU32;

use serde::Deserialize;

use crate::{BoundaryState, CaptureState, EligibilityInput, OutcomeState, StructureState};

const RECEIPT_SCHEMA: &str = "proofbound-runtime-receipt/1";
const POLICY_MODEL_VERSION: &str = "proofbound-runtime-linux-policy/1";

/// Identifies one strict receipt-decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The input is not one complete JSON value.
    MalformedJson,
    /// The input is not one deterministic CBOR item.
    MalformedCbor,
    /// The value does not have the closed version 1 structure.
    InvalidSchema,
    /// The receipt schema version is unsupported.
    UnsupportedVersion,
}

impl DecodeError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MalformedJson => "receipt.schema.malformed-json",
            Self::MalformedCbor => "receipt.schema.malformed-cbor",
            Self::InvalidSchema => "receipt.schema.invalid",
            Self::UnsupportedVersion => "receipt.schema.unsupported-version",
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for DecodeError {}

/// Contains the eligibility value recorded by the producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordedEligibility {
    /// The producer recorded a reusable receipt.
    Reusable,
    /// The producer recorded every listed non-reuse reason.
    NonReusable(Vec<WireReason>),
}

/// One artifact identity exposed to independent receipt consumers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositionArtifact {
    pub mode: u16,
    pub role: &'static str,
    pub sha256: String,
    pub size: String,
}

/// One trusted-computing-base entry exposed to independent receipt consumers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositionTcbEntry {
    pub identity: String,
    pub role: String,
}

/// The closed receipt facts needed by release composition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptCompositionFacts {
    pub assumptions: Vec<String>,
    pub execution_id: String,
    pub producer: CompositionArtifact,
    pub product_version: String,
    pub reusable: bool,
    pub runtime: CompositionArtifact,
    pub launcher: CompositionArtifact,
    pub schema: String,
    pub trusted_computing_base: Vec<CompositionTcbEntry>,
    pub version_two: bool,
}

/// Closed, verifier-decoded execution facts used by an adopter acceptance
/// policy. These values come from the strict receipt codec, never from the
/// JSON inspection projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptAcceptanceFacts {
    pub schema: String,
    pub runtime_version: String,
    pub execution_id: String,
    pub plan_id: String,
    pub operating_system: String,
    pub architecture: &'static str,
    pub executable: CompositionArtifact,
    pub policy_sha256: String,
    pub policy_model_version: String,
    pub pids_max: u32,
    pub memory_max: u64,
    pub memory_oom_group: u8,
    pub memory_swap_max: u64,
    pub reusable: bool,
    pub assumptions: Vec<String>,
    pub tcb_roles: Vec<String>,
}

/// Contains one independently decoded version 1 receipt.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedReceipt {
    value: serde_json::Value,
    wire: WireReceipt,
    eligibility_input: EligibilityInput,
    recorded_eligibility: RecordedEligibility,
    version_two: bool,
    resources: Option<WireResources>,
    plan_limits: Option<WirePlanLimits>,
}

impl DecodedReceipt {
    /// Returns the complete decoded JSON tree for later independent checks.
    #[must_use]
    pub const fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub(crate) const fn wire(&self) -> &WireReceipt {
        &self.wire
    }

    /// Returns the closed inputs for independent eligibility derivation.
    #[must_use]
    pub const fn eligibility_input(&self) -> EligibilityInput {
        self.eligibility_input
    }

    /// Returns the producer-recorded eligibility value.
    #[must_use]
    pub const fn recorded_eligibility(&self) -> &RecordedEligibility {
        &self.recorded_eligibility
    }

    /// Projects only typed facts needed by a receipt composer. This is not the
    /// JSON inspection projection and retains the independently decoded wire
    /// identities directly.
    #[must_use]
    pub fn composition_facts(&self) -> ReceiptCompositionFacts {
        ReceiptCompositionFacts {
            assumptions: self.wire.assumptions.clone(),
            execution_id: self.wire.execution_id.clone(),
            producer: composition_artifact(&self.wire.producer),
            product_version: self.wire.product_version.clone(),
            reusable: matches!(self.recorded_eligibility, RecordedEligibility::Reusable),
            runtime: composition_artifact(&self.wire.runtime.runtime),
            launcher: composition_artifact(&self.wire.runtime.launcher),
            schema: self.wire.schema.clone(),
            trusted_computing_base: self
                .wire
                .trusted_computing_base
                .iter()
                .map(|entry| CompositionTcbEntry {
                    identity: entry.identity.clone(),
                    role: entry.role.clone(),
                })
                .collect(),
            version_two: self.version_two,
        }
    }

    /// Projects the closed version 2 fields required by acceptance policy.
    /// Version 1 receipts predate the acceptance contract and return `None`.
    #[must_use]
    pub fn acceptance_facts(&self) -> Option<ReceiptAcceptanceFacts> {
        let resources = self.resources.as_ref()?;
        Some(ReceiptAcceptanceFacts {
            schema: self.wire.schema.clone(),
            runtime_version: self.wire.product_version.clone(),
            execution_id: self.wire.execution_id.clone(),
            plan_id: self.wire.plan.id.clone(),
            operating_system: self.wire.platform.operating_system.clone(),
            architecture: match self.wire.platform.architecture {
                WireArchitecture::X86_64 => "x86_64",
                WireArchitecture::Aarch64 => "aarch64",
            },
            executable: composition_artifact(&self.wire.command.executable),
            policy_sha256: self.wire.boundary.policy_sha256.clone(),
            policy_model_version: self.wire.policy.model_version.clone(),
            pids_max: resources.processes,
            memory_max: resources.memory,
            memory_oom_group: 1,
            memory_swap_max: resources.swap,
            reusable: matches!(self.recorded_eligibility, RecordedEligibility::Reusable),
            assumptions: self.wire.assumptions.clone(),
            tcb_roles: self
                .wire
                .trusted_computing_base
                .iter()
                .map(|entry| entry.role.clone())
                .collect(),
        })
    }

    pub(crate) const fn is_version_two(&self) -> bool {
        self.version_two
    }

    pub(crate) fn from_v2(
        value: serde_json::Value,
        wire: WireReceipt,
        eligibility_input: EligibilityInput,
        recorded_eligibility: RecordedEligibility,
        resources: WireResources,
        plan_limits: WirePlanLimits,
    ) -> Self {
        Self {
            value,
            wire,
            eligibility_input,
            recorded_eligibility,
            version_two: true,
            resources: Some(resources),
            plan_limits: Some(plan_limits),
        }
    }

    pub(crate) const fn resources(&self) -> Option<&WireResources> {
        self.resources.as_ref()
    }

    pub(crate) const fn plan_limits(&self) -> Option<&WirePlanLimits> {
        self.plan_limits.as_ref()
    }
}

fn composition_artifact(wire: &WireArtifact) -> CompositionArtifact {
    CompositionArtifact {
        mode: wire.mode,
        role: wire_artifact_role(wire.role),
        sha256: wire.sha256.clone(),
        size: wire.size.clone(),
    }
}

const fn wire_artifact_role(role: WireArtifactRole) -> &'static str {
    match role {
        WireArtifactRole::ExecutionPlan => "execution-plan",
        WireArtifactRole::NormalizedPlan => "normalized-plan",
        WireArtifactRole::CompiledPolicy => "compiled-policy",
        WireArtifactRole::RuntimeBinary => "runtime-binary",
        WireArtifactRole::LauncherBinary => "launcher-binary",
        WireArtifactRole::VerifierBinary => "verifier-binary",
        WireArtifactRole::RuntimeExecutable => "runtime-executable",
        WireArtifactRole::RuntimeLoaderExecutable => "runtime-loader-executable",
        WireArtifactRole::RuntimeLibrary => "runtime-library",
        WireArtifactRole::WorkingDirectory => "working-directory",
        WireArtifactRole::ProjectInput => "project-input",
        WireArtifactRole::OutputRoot => "output-root",
        WireArtifactRole::StandardOutput => "standard-output",
        WireArtifactRole::StandardError => "standard-error",
        WireArtifactRole::OutputArtifact => "output-artifact",
    }
}

/// Decodes exactly one closed version 1 execution receipt.
pub fn decode_receipt(input: &[u8]) -> Result<DecodedReceipt, DecodeError> {
    if input.first() != Some(&b'{') {
        return crate::decode_v2::decode_v2_receipt(input);
    }
    decode_v1_receipt(input)
}

fn decode_v1_receipt(input: &[u8]) -> Result<DecodedReceipt, DecodeError> {
    let value: serde_json::Value = serde_json::from_slice(input).map_err(classify_json_error)?;
    let wire: WireReceipt =
        serde_json::from_value(value.clone()).map_err(|_| DecodeError::InvalidSchema)?;

    if wire.schema != RECEIPT_SCHEMA {
        return Err(DecodeError::UnsupportedVersion);
    }
    if wire.policy.model_version != POLICY_MODEL_VERSION
        || wire.platform.operating_system != "linux"
        || wire.observations.clock != "linux-monotonic"
    {
        return Err(DecodeError::InvalidSchema);
    }

    let boundary = match wire.boundary.state {
        WireBoundaryState::Installed => BoundaryState::Installed,
        WireBoundaryState::Incomplete => BoundaryState::Incomplete,
    };
    let outcome = match wire.outcome {
        WireOutcome::Exited { code } => OutcomeState::Exited { code },
        WireOutcome::Signaled { signal } => OutcomeState::Signaled {
            signal: NonZeroU32::new(signal).ok_or(DecodeError::InvalidSchema)?,
        },
        WireOutcome::TimedOut => OutcomeState::TimedOut,
        WireOutcome::Denied => OutcomeState::Denied,
        WireOutcome::LauncherFailed => OutcomeState::LauncherFailed,
        WireOutcome::Incomplete => OutcomeState::Incomplete,
    };
    let stdout = capture_state(wire.streams.stdout.capture);
    let stderr = capture_state(wire.streams.stderr.capture);
    let recorded_eligibility = match wire.eligibility.status {
        WireEligibilityStatus::Reusable if wire.eligibility.reasons.is_empty() => {
            RecordedEligibility::Reusable
        }
        WireEligibilityStatus::NonReusable if !wire.eligibility.reasons.is_empty() => {
            RecordedEligibility::NonReusable(wire.eligibility.reasons.clone())
        }
        _ => return Err(DecodeError::InvalidSchema),
    };

    Ok(DecodedReceipt {
        value,
        wire,
        eligibility_input: EligibilityInput::new(
            boundary,
            outcome,
            stdout,
            stderr,
            StructureState::Valid,
        ),
        recorded_eligibility,
        version_two: false,
        resources: None,
        plan_limits: None,
    })
}

fn classify_json_error(error: serde_json::Error) -> DecodeError {
    if error.is_syntax() || error.is_eof() || error.is_io() {
        DecodeError::MalformedJson
    } else {
        DecodeError::InvalidSchema
    }
}

fn capture_state(capture: WireCapture) -> CaptureState {
    match capture {
        WireCapture::Complete => CaptureState::Complete,
        WireCapture::Truncated => CaptureState::Truncated,
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireReceipt {
    pub(crate) schema: String,
    pub(crate) product_version: String,
    pub(crate) execution_id: String,
    pub(crate) plan: WirePlan,
    pub(crate) policy: WirePolicy,
    pub(crate) platform: WirePlatform,
    pub(crate) runtime: WireRuntime,
    pub(crate) command: WireCommand,
    pub(crate) inputs: Vec<WireArtifact>,
    pub(crate) environment: Vec<String>,
    pub(crate) output_root: WireArtifact,
    pub(crate) boundary: WireBoundary,
    pub(crate) observations: WireObservations,
    pub(crate) streams: WireStreams,
    pub(crate) outcome: WireOutcome,
    pub(crate) outputs: Vec<WireArtifact>,
    pub(crate) eligibility: WireEligibility,
    pub(crate) producer: WireArtifact,
    pub(crate) assumptions: Vec<String>,
    pub(crate) trusted_computing_base: Vec<WireTcbEntry>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct WireResources {
    pub(crate) processes: u32,
    pub(crate) memory: u64,
    pub(crate) swap: u64,
    pub(crate) memory_peak: u64,
    pub(crate) swap_peak: u64,
    pub(crate) memory_events: [u64; 6],
    pub(crate) swap_events: [u64; 2],
    pub(crate) limit_events: Vec<WireReason>,
    pub(crate) observations_complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WirePlanLimits {
    pub(crate) processes: u32,
    pub(crate) wall_time_ms: u64,
    pub(crate) stdout_bytes: u64,
    pub(crate) stderr_bytes: u64,
    pub(crate) memory: u64,
    pub(crate) swap: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WirePlan {
    pub(crate) id: String,
    pub(crate) source: WireArtifact,
    pub(crate) normalized: WireArtifact,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WirePolicy {
    pub(crate) identity: WireArtifact,
    pub(crate) model_version: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WirePlatform {
    pub(crate) operating_system: String,
    pub(crate) architecture: WireArchitecture,
    pub(crate) kernel_release: String,
    pub(crate) landlock_abi: u32,
    pub(crate) seccomp_features: Vec<String>,
    pub(crate) cgroup_controllers: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WireArchitecture {
    X86_64,
    Aarch64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireRuntime {
    pub(crate) runtime: WireArtifact,
    pub(crate) launcher: WireArtifact,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireCommand {
    pub(crate) executable: WireArtifact,
    pub(crate) loader: Option<WireArtifact>,
    pub(crate) working_directory: WireArtifact,
    pub(crate) arguments_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireArtifact {
    pub(crate) role: WireArtifactRole,
    pub(crate) sha256: String,
    pub(crate) size: String,
    pub(crate) mode: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WireArtifactRole {
    ExecutionPlan,
    NormalizedPlan,
    CompiledPolicy,
    RuntimeBinary,
    LauncherBinary,
    VerifierBinary,
    RuntimeExecutable,
    RuntimeLoaderExecutable,
    RuntimeLibrary,
    WorkingDirectory,
    ProjectInput,
    OutputRoot,
    StandardOutput,
    StandardError,
    OutputArtifact,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireBoundary {
    pub(crate) state: WireBoundaryState,
    pub(crate) execution_id: String,
    pub(crate) policy_sha256: String,
    pub(crate) cgroup: WireCgroup,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WireBoundaryState {
    Installed,
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireCgroup {
    pub(crate) mount_id: String,
    pub(crate) inode: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireObservations {
    pub(crate) clock: String,
    pub(crate) started_ns: String,
    pub(crate) finished_ns: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireStreams {
    pub(crate) stdout: WireStream,
    pub(crate) stderr: WireStream,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireStream {
    pub(crate) artifact: WireArtifact,
    pub(crate) capture: WireCapture,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WireCapture {
    Complete,
    Truncated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum WireOutcome {
    Exited { code: i32 },
    Signaled { signal: u32 },
    TimedOut,
    Denied,
    LauncherFailed,
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireEligibility {
    pub(crate) status: WireEligibilityStatus,
    pub(crate) reasons: Vec<WireReason>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WireEligibilityStatus {
    Reusable,
    NonReusable,
}

/// Identifies one closed version 1 recorded non-reuse reason.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum WireReason {
    /// Boundary acknowledgement is incomplete.
    BoundaryIncomplete,
    /// Child exit code is nonzero.
    ExitCodeNonzero,
    /// A signal stopped the child.
    ProcessSignaled,
    /// Wall time expired.
    TimedOut,
    /// The installed boundary denied an operation.
    Denied,
    /// The launcher failed.
    LauncherFailed,
    /// No terminal outcome was observed.
    ExecutionIncomplete,
    /// Standard output was truncated.
    StdoutTruncated,
    /// Standard error was truncated.
    StderrTruncated,
    /// Receipt structure is malformed.
    ReceiptMalformed,
    /// A memory-high event occurred.
    MemoryHigh,
    /// A memory-max event occurred.
    MemoryMax,
    /// A memory OOM event occurred.
    MemoryOom,
    /// A memory OOM kill occurred.
    MemoryOomKill,
    /// A group OOM kill occurred.
    MemoryOomGroupKill,
    /// A swap-max event occurred.
    SwapMax,
    /// A swap-fail event occurred.
    SwapFail,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireTcbEntry {
    pub(crate) role: String,
    pub(crate) identity: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{bytes, receipt};

    #[test]
    fn decodes_the_complete_closed_receipt_shape() {
        let decoded = decode_receipt(&bytes(&receipt())).expect("fixture receipt decodes");
        assert_eq!(
            decoded.recorded_eligibility(),
            &RecordedEligibility::Reusable
        );
        assert_eq!(
            decoded.eligibility_input(),
            EligibilityInput::new(
                BoundaryState::Installed,
                OutcomeState::Exited { code: 0 },
                CaptureState::Complete,
                CaptureState::Complete,
                StructureState::Valid,
            )
        );
        assert_eq!(decoded.value()["schema"], RECEIPT_SCHEMA);
    }

    #[test]
    fn rejects_unknown_fields_and_enum_values() {
        let mut unknown_field = receipt();
        unknown_field["unexpected"] = serde_json::Value::Bool(true);
        assert_eq!(
            decode_receipt(&bytes(&unknown_field)),
            Err(DecodeError::InvalidSchema)
        );

        let mut unknown_outcome = receipt();
        unknown_outcome["outcome"]["kind"] = serde_json::Value::String("other".to_owned());
        assert_eq!(
            decode_receipt(&bytes(&unknown_outcome)),
            Err(DecodeError::InvalidSchema)
        );
    }

    #[test]
    fn rejects_unknown_versions_and_malformed_json() {
        let mut unknown_version = receipt();
        unknown_version["schema"] =
            serde_json::Value::String("proofbound-runtime-receipt/2".to_owned());
        assert_eq!(
            decode_receipt(&bytes(&unknown_version)),
            Err(DecodeError::UnsupportedVersion)
        );
        assert_eq!(
            decode_receipt(br#"{"schema":"#),
            Err(DecodeError::MalformedJson)
        );
    }

    #[test]
    fn rejects_zero_signal_and_inconsistent_eligibility_shape() {
        let mut zero_signal = receipt();
        zero_signal["outcome"] = serde_json::json!({"kind": "signaled", "signal": 0});
        assert_eq!(
            decode_receipt(&bytes(&zero_signal)),
            Err(DecodeError::InvalidSchema)
        );

        let mut forged_shape = receipt();
        forged_shape["eligibility"]["reasons"] = serde_json::json!(["denied"]);
        assert_eq!(
            decode_receipt(&bytes(&forged_shape)),
            Err(DecodeError::InvalidSchema)
        );
    }
}
