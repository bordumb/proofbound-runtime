//! Independently validates receipt identities and semantic relationships.

use core::cmp::Ordering;
use core::fmt;

use crate::decode::{
    DecodedReceipt, RecordedEligibility, WireArtifact, WireArtifactRole, WireReason, WireTcbEntry,
};
use crate::{EligibilityDecision, FailureReason, derive_eligibility};

const REQUIRED_ASSUMPTIONS: [&str; 3] = [
    "PBR-HOST-AX-002",
    "PBR-LINUX-AX-001",
    "PBR-TOOLCHAIN-AX-003",
];

const ALWAYS_REQUIRED_TCB_ROLES: [TcbRole; 12] = [
    TcbRole::HostHardwareFirmware,
    TcbRole::LinuxKernel,
    TcbRole::Landlock,
    TcbRole::Seccomp,
    TcbRole::CgroupV2,
    TcbRole::NoNewPrivileges,
    TcbRole::Filesystem,
    TcbRole::RuntimeBinary,
    TcbRole::LauncherBinary,
    TcbRole::RustToolchain,
    TcbRole::CryptographicDigest,
    TcbRole::RuntimeExecutable,
];

/// Identifies one independent semantic receipt-validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// The producer version does not have the closed version 1 grammar.
    InvalidProductVersion,
    /// An execution identifier is not lowercase RFC 4122 version 4 text.
    InvalidExecutionId,
    /// The plan identifier is empty or exceeds the version 1 limit.
    InvalidPlanId,
    /// An environment name is empty or contains a forbidden byte.
    InvalidEnvironmentName,
    /// Required platform information is empty or unavailable.
    InvalidPlatform,
    /// A digest is not exactly 64 lowercase hexadecimal characters.
    InvalidDigest,
    /// An unsigned decimal string is not canonical or exceeds `u64`.
    InvalidUnsignedDecimal,
    /// An artifact mode exceeds the version 1 Unix mode range.
    InvalidMode,
    /// An artifact appears in a field that does not admit its role.
    RoleMismatch,
    /// A string set is empty, duplicated, or out of canonical order.
    SetNotCanonical,
    /// An artifact list is duplicated or out of canonical order.
    ArtifactListNotCanonical,
    /// The boundary identifies a different execution.
    ExecutionIdentityMismatch,
    /// The boundary identifies a different policy digest.
    PolicyIdentityMismatch,
    /// The producer identity differs from the runtime identity.
    ProducerIdentityMismatch,
    /// The finish observation precedes the start observation.
    ObservationOrder,
    /// A required runtime assumption is absent.
    AssumptionMissing,
    /// A trusted-computing-base role is outside the closed version 1 set.
    UnsupportedTcbRole,
    /// The trusted-computing-base inventory is empty, duplicated, or unordered.
    TcbNotCanonical,
    /// A required trusted-computing-base role is absent.
    TcbRoleMissing,
    /// Recorded eligibility differs from independent derivation.
    EligibilityMismatch,
    /// The recorded version 2 limit-event set does not match terminal counters.
    ResourceEventsMismatch,
    /// Configured values or terminal peaks contradict the normalized plan limits.
    ResourcePlanMismatch,
}

impl ValidationError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidProductVersion => "receipt.product-version.invalid",
            Self::InvalidExecutionId => "receipt.execution-id.invalid",
            Self::InvalidPlanId => "receipt.plan-id.invalid",
            Self::InvalidEnvironmentName => "receipt.environment-name.invalid",
            Self::InvalidPlatform => "receipt.platform.invalid",
            Self::InvalidDigest => "receipt.identity.digest.invalid",
            Self::InvalidUnsignedDecimal => "receipt.identity.decimal.invalid",
            Self::InvalidMode => "receipt.identity.mode.invalid",
            Self::RoleMismatch => "receipt.role.mismatch",
            Self::SetNotCanonical => "receipt.set.not-canonical",
            Self::ArtifactListNotCanonical => "receipt.artifact-list.not-canonical",
            Self::ExecutionIdentityMismatch => "receipt.identity.execution-mismatch",
            Self::PolicyIdentityMismatch => "receipt.identity.policy-mismatch",
            Self::ProducerIdentityMismatch => "receipt.identity.producer-mismatch",
            Self::ObservationOrder => "receipt.observation.order",
            Self::AssumptionMissing => "receipt.assumption.missing",
            Self::UnsupportedTcbRole => "receipt.tcb.role.unsupported",
            Self::TcbNotCanonical => "receipt.tcb.not-canonical",
            Self::TcbRoleMissing => "receipt.tcb.role.missing",
            Self::EligibilityMismatch => "receipt.eligibility.mismatch",
            Self::ResourceEventsMismatch => "receipt.resources.events-mismatch",
            Self::ResourcePlanMismatch => "receipt.resources.plan-mismatch",
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ValidationError {}

/// Independently validates every version 1 identity and relationship.
pub fn validate_receipt(receipt: &DecodedReceipt) -> Result<(), ValidationError> {
    let wire = receipt.wire();
    require_product_version(&wire.product_version)?;
    require_execution_id(&wire.execution_id)?;
    require_plan_id(&wire.plan.id)?;
    if wire.platform.kernel_release.is_empty() || wire.platform.landlock_abi == 0 {
        return Err(ValidationError::InvalidPlatform);
    }
    let _architecture = wire.platform.architecture;

    require_artifact(&wire.plan.source, WireArtifactRole::ExecutionPlan)?;
    require_artifact(&wire.plan.normalized, WireArtifactRole::NormalizedPlan)?;
    require_artifact(&wire.policy.identity, WireArtifactRole::CompiledPolicy)?;
    require_artifact(&wire.runtime.runtime, WireArtifactRole::RuntimeBinary)?;
    require_artifact(&wire.runtime.launcher, WireArtifactRole::LauncherBinary)?;
    require_artifact(
        &wire.command.executable,
        WireArtifactRole::RuntimeExecutable,
    )?;
    if let Some(loader) = &wire.command.loader {
        require_artifact(loader, WireArtifactRole::RuntimeLoaderExecutable)?;
    }
    require_artifact(
        &wire.command.working_directory,
        WireArtifactRole::WorkingDirectory,
    )?;
    require_digest(&wire.command.arguments_sha256)?;
    require_artifact(&wire.output_root, WireArtifactRole::OutputRoot)?;
    require_artifact(
        &wire.streams.stdout.artifact,
        WireArtifactRole::StandardOutput,
    )?;
    require_artifact(
        &wire.streams.stderr.artifact,
        WireArtifactRole::StandardError,
    )?;
    require_artifact(&wire.producer, WireArtifactRole::RuntimeBinary)?;

    validate_artifact_list(&wire.inputs, |role| {
        matches!(
            role,
            WireArtifactRole::ProjectInput | WireArtifactRole::RuntimeLibrary
        )
    })?;
    validate_artifact_list(&wire.outputs, |role| {
        role == WireArtifactRole::OutputArtifact
    })?;
    validate_string_set(&wire.environment)?;
    if wire
        .environment
        .iter()
        .any(|name| name.as_bytes().contains(&0) || name.as_bytes().contains(&b'='))
    {
        return Err(ValidationError::InvalidEnvironmentName);
    }
    validate_string_set(&wire.platform.seccomp_features)?;
    validate_string_set(&wire.platform.cgroup_controllers)?;
    validate_string_set(&wire.assumptions)?;

    require_digest(&wire.boundary.policy_sha256)?;
    require_execution_id(&wire.boundary.execution_id)?;
    let _mount_id = parse_decimal(&wire.boundary.cgroup.mount_id)?;
    let _inode = parse_decimal(&wire.boundary.cgroup.inode)?;
    let started = parse_decimal(&wire.observations.started_ns)?;
    let finished = parse_decimal(&wire.observations.finished_ns)?;
    if finished < started {
        return Err(ValidationError::ObservationOrder);
    }

    if wire.boundary.execution_id != wire.execution_id {
        return Err(ValidationError::ExecutionIdentityMismatch);
    }
    if wire.boundary.policy_sha256 != wire.policy.identity.sha256 {
        return Err(ValidationError::PolicyIdentityMismatch);
    }
    if wire.producer != wire.runtime.runtime {
        return Err(ValidationError::ProducerIdentityMismatch);
    }
    for required in REQUIRED_ASSUMPTIONS {
        if wire
            .assumptions
            .binary_search_by(|value| value.as_str().cmp(required))
            .is_err()
        {
            return Err(ValidationError::AssumptionMissing);
        }
    }

    validate_tcb(receipt)?;
    validate_resources(receipt)?;
    validate_eligibility(receipt)
}

fn validate_resources(receipt: &DecodedReceipt) -> Result<(), ValidationError> {
    let Some(resources) = receipt.resources() else {
        return if receipt.is_version_two() {
            Err(ValidationError::ResourceEventsMismatch)
        } else {
            Ok(())
        };
    };
    if !receipt.is_version_two() {
        return Err(ValidationError::ResourceEventsMismatch);
    }
    let plan = receipt
        .plan_limits()
        .ok_or(ValidationError::ResourcePlanMismatch)?;
    let _supervisor_limits = (plan.wall_time_ms, plan.stdout_bytes, plan.stderr_bytes);
    if (resources.processes, resources.memory, resources.swap)
        != (plan.processes, plan.memory, plan.swap)
    {
        return Err(ValidationError::ResourcePlanMismatch);
    }
    if !resources.observations_complete {
        return if resources.limit_events.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::ResourceEventsMismatch)
        };
    }
    if (resources.memory_peak > plan.memory && resources.memory_events[2] == 0)
        || (resources.swap_peak > plan.swap
            && resources.swap_events[0] == 0
            && resources.swap_events[1] == 0)
    {
        return Err(ValidationError::ResourcePlanMismatch);
    }
    let expected = [
        (resources.memory_events[1] != 0, WireReason::MemoryHigh),
        (resources.memory_events[2] != 0, WireReason::MemoryMax),
        (resources.memory_events[3] != 0, WireReason::MemoryOom),
        (resources.memory_events[4] != 0, WireReason::MemoryOomKill),
        (
            resources.memory_events[5] != 0,
            WireReason::MemoryOomGroupKill,
        ),
        (resources.swap_events[0] != 0, WireReason::SwapMax),
        (resources.swap_events[1] != 0, WireReason::SwapFail),
    ]
    .into_iter()
    .filter_map(|(present, reason)| present.then_some(reason))
    .collect::<Vec<_>>();
    if resources.limit_events != expected {
        return Err(ValidationError::ResourceEventsMismatch);
    }
    Ok(())
}

fn require_product_version(value: &str) -> Result<(), ValidationError> {
    let mut components = value.split('.');
    for _ in 0..3 {
        let component = components
            .next()
            .ok_or(ValidationError::InvalidProductVersion)?;
        if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ValidationError::InvalidProductVersion);
        }
    }
    if components.next().is_some() {
        return Err(ValidationError::InvalidProductVersion);
    }
    Ok(())
}

fn require_plan_id(value: &str) -> Result<(), ValidationError> {
    let bytes = value.as_bytes();
    let is_lowercase_or_digit = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes.first().is_some_and(is_lowercase_or_digit)
        || !bytes.last().is_some_and(is_lowercase_or_digit)
        || !bytes
            .iter()
            .all(|byte| is_lowercase_or_digit(byte) || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ValidationError::InvalidPlanId);
    }
    Ok(())
}

fn require_execution_id(value: &str) -> Result<(), ValidationError> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || !bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'),
        })
        || bytes[14] != b'4'
        || !matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
    {
        return Err(ValidationError::InvalidExecutionId);
    }
    Ok(())
}

fn require_artifact(
    artifact: &WireArtifact,
    role: WireArtifactRole,
) -> Result<(), ValidationError> {
    validate_artifact(artifact)?;
    if artifact.role != role {
        return Err(ValidationError::RoleMismatch);
    }
    Ok(())
}

fn validate_artifact(artifact: &WireArtifact) -> Result<(), ValidationError> {
    require_digest(&artifact.sha256)?;
    let _size = parse_decimal(&artifact.size)?;
    if artifact.mode > 0o7777 {
        return Err(ValidationError::InvalidMode);
    }
    Ok(())
}

fn require_digest(value: &str) -> Result<(), ValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ValidationError::InvalidDigest);
    }
    Ok(())
}

fn parse_decimal(value: &str) -> Result<u64, ValidationError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ValidationError::InvalidUnsignedDecimal);
    }
    value
        .parse()
        .map_err(|_| ValidationError::InvalidUnsignedDecimal)
}

fn validate_string_set(values: &[String]) -> Result<(), ValidationError> {
    if values.iter().any(String::is_empty) || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ValidationError::SetNotCanonical);
    }
    Ok(())
}

fn validate_artifact_list(
    artifacts: &[WireArtifact],
    role_allowed: impl Fn(WireArtifactRole) -> bool,
) -> Result<(), ValidationError> {
    for artifact in artifacts {
        validate_artifact(artifact)?;
        if !role_allowed(artifact.role) {
            return Err(ValidationError::RoleMismatch);
        }
    }
    if artifacts
        .windows(2)
        .any(|pair| artifact_order(&pair[0], &pair[1]) != Ordering::Less)
    {
        return Err(ValidationError::ArtifactListNotCanonical);
    }
    Ok(())
}

fn artifact_order(left: &WireArtifact, right: &WireArtifact) -> Ordering {
    left.role
        .cmp(&right.role)
        .then_with(|| left.sha256.cmp(&right.sha256))
        .then_with(|| {
            parse_decimal(&left.size)
                .expect("validated artifact size")
                .cmp(&parse_decimal(&right.size).expect("validated artifact size"))
        })
        .then_with(|| left.mode.cmp(&right.mode))
}

fn validate_tcb(receipt: &DecodedReceipt) -> Result<(), ValidationError> {
    let wire = receipt.wire();
    if wire.trusted_computing_base.is_empty() {
        return Err(ValidationError::TcbNotCanonical);
    }
    let mut parsed = Vec::with_capacity(wire.trusted_computing_base.len());
    for entry in &wire.trusted_computing_base {
        if entry.identity.is_empty() {
            return Err(ValidationError::TcbNotCanonical);
        }
        parsed.push((parse_tcb_role(entry)?, entry.identity.as_str()));
    }
    if parsed.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ValidationError::TcbNotCanonical);
    }
    for role in ALWAYS_REQUIRED_TCB_ROLES {
        require_tcb_role(&parsed, role)?;
    }
    if wire.command.loader.is_some() {
        require_tcb_role(&parsed, TcbRole::RuntimeLoaderExecutable)?;
    }
    if wire
        .inputs
        .iter()
        .any(|artifact| artifact.role == WireArtifactRole::RuntimeLibrary)
    {
        require_tcb_role(&parsed, TcbRole::RuntimeLibrary)?;
    }
    Ok(())
}

fn parse_tcb_role(entry: &WireTcbEntry) -> Result<TcbRole, ValidationError> {
    match entry.role.as_str() {
        "host-hardware-firmware" => Ok(TcbRole::HostHardwareFirmware),
        "linux-kernel" => Ok(TcbRole::LinuxKernel),
        "landlock" => Ok(TcbRole::Landlock),
        "seccomp" => Ok(TcbRole::Seccomp),
        "cgroup-v2" => Ok(TcbRole::CgroupV2),
        "no-new-privileges" => Ok(TcbRole::NoNewPrivileges),
        "filesystem" => Ok(TcbRole::Filesystem),
        "runtime-binary" => Ok(TcbRole::RuntimeBinary),
        "launcher-binary" => Ok(TcbRole::LauncherBinary),
        "rust-toolchain" => Ok(TcbRole::RustToolchain),
        "cryptographic-digest" => Ok(TcbRole::CryptographicDigest),
        "runtime-executable" => Ok(TcbRole::RuntimeExecutable),
        "runtime-loader-executable" => Ok(TcbRole::RuntimeLoaderExecutable),
        "runtime-library" => Ok(TcbRole::RuntimeLibrary),
        _ => Err(ValidationError::UnsupportedTcbRole),
    }
}

fn require_tcb_role(entries: &[(TcbRole, &str)], required: TcbRole) -> Result<(), ValidationError> {
    if entries.iter().any(|(role, _)| *role == required) {
        Ok(())
    } else {
        Err(ValidationError::TcbRoleMissing)
    }
}

fn validate_eligibility(receipt: &DecodedReceipt) -> Result<(), ValidationError> {
    let derived = derive_eligibility(&receipt.eligibility_input());
    match (receipt.recorded_eligibility(), derived) {
        (RecordedEligibility::Reusable, EligibilityDecision::Reusable) => Ok(()),
        (RecordedEligibility::NonReusable(recorded), EligibilityDecision::NonReusable(derived))
            if recorded.as_slice()
                == derived
                    .as_slice()
                    .iter()
                    .copied()
                    .map(reason_from_failure)
                    .collect::<Vec<_>>() =>
        {
            Ok(())
        }
        _ => Err(ValidationError::EligibilityMismatch),
    }
}

const fn reason_from_failure(reason: FailureReason) -> WireReason {
    match reason {
        FailureReason::BoundaryIncomplete => WireReason::BoundaryIncomplete,
        FailureReason::ExitCodeNonzero => WireReason::ExitCodeNonzero,
        FailureReason::ProcessSignaled => WireReason::ProcessSignaled,
        FailureReason::TimedOut => WireReason::TimedOut,
        FailureReason::Denied => WireReason::Denied,
        FailureReason::LauncherFailed => WireReason::LauncherFailed,
        FailureReason::ExecutionIncomplete => WireReason::ExecutionIncomplete,
        FailureReason::StandardOutputTruncated => WireReason::StdoutTruncated,
        FailureReason::StandardErrorTruncated => WireReason::StderrTruncated,
        FailureReason::ReceiptMalformed => WireReason::ReceiptMalformed,
        FailureReason::MemoryHigh => WireReason::MemoryHigh,
        FailureReason::MemoryMax => WireReason::MemoryMax,
        FailureReason::MemoryOom => WireReason::MemoryOom,
        FailureReason::MemoryOomKill => WireReason::MemoryOomKill,
        FailureReason::MemoryOomGroupKill => WireReason::MemoryOomGroupKill,
        FailureReason::SwapMax => WireReason::SwapMax,
        FailureReason::SwapFail => WireReason::SwapFail,
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum TcbRole {
    HostHardwareFirmware,
    LinuxKernel,
    Landlock,
    Seccomp,
    CgroupV2,
    NoNewPrivileges,
    Filesystem,
    RuntimeBinary,
    LauncherBinary,
    RustToolchain,
    CryptographicDigest,
    RuntimeExecutable,
    RuntimeLoaderExecutable,
    RuntimeLibrary,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode_receipt;
    use crate::test_support::{artifact, bytes, receipt};

    fn validate(value: &serde_json::Value) -> Result<(), ValidationError> {
        let decoded = decode_receipt(&bytes(value)).expect("mutation preserves closed schema");
        validate_receipt(&decoded)
    }

    #[test]
    fn accepts_a_complete_independently_validated_receipt() {
        assert_eq!(validate(&receipt()), Ok(()));
    }

    #[test]
    fn rejects_invalid_identity_grammars() {
        let mut digest = receipt();
        digest["plan"]["source"]["sha256"] = serde_json::json!("A".repeat(64));
        assert_eq!(validate(&digest), Err(ValidationError::InvalidDigest));

        let mut decimal = receipt();
        decimal["inputs"][0]["size"] = serde_json::json!("01");
        assert_eq!(
            validate(&decimal),
            Err(ValidationError::InvalidUnsignedDecimal)
        );

        let mut execution = receipt();
        execution["execution_id"] = serde_json::json!("00112233-4455-0677-8899-aabbccddeeff");
        assert_eq!(
            validate(&execution),
            Err(ValidationError::InvalidExecutionId)
        );

        let mut plan = receipt();
        plan["plan"]["id"] = serde_json::json!("Invalid Plan");
        assert_eq!(validate(&plan), Err(ValidationError::InvalidPlanId));

        let mut environment = receipt();
        environment["environment"] = serde_json::json!(["PATH=value"]);
        assert_eq!(
            validate(&environment),
            Err(ValidationError::InvalidEnvironmentName)
        );
    }

    #[test]
    fn rejects_role_substitution_and_noncanonical_artifact_lists() {
        let mut role = receipt();
        role["output_root"]["role"] = serde_json::json!("project-input");
        assert_eq!(validate(&role), Err(ValidationError::RoleMismatch));

        let mut artifacts = receipt();
        artifacts["inputs"] = serde_json::json!([
            artifact("project-input", "b"),
            artifact("project-input", "a")
        ]);
        assert_eq!(
            validate(&artifacts),
            Err(ValidationError::ArtifactListNotCanonical)
        );
    }

    #[test]
    fn rejects_relationship_substitution() {
        let mut execution = receipt();
        execution["boundary"]["execution_id"] =
            serde_json::json!("ffeeddcc-bbaa-4988-8899-001122334455");
        assert_eq!(
            validate(&execution),
            Err(ValidationError::ExecutionIdentityMismatch)
        );

        let mut policy = receipt();
        policy["boundary"]["policy_sha256"] = serde_json::json!("f".repeat(64));
        assert_eq!(
            validate(&policy),
            Err(ValidationError::PolicyIdentityMismatch)
        );

        let mut producer = receipt();
        producer["producer"]["sha256"] = serde_json::json!("f".repeat(64));
        assert_eq!(
            validate(&producer),
            Err(ValidationError::ProducerIdentityMismatch)
        );
    }

    #[test]
    fn rejects_premise_loss_and_unknown_tcb_roles() {
        let mut assumption = receipt();
        assumption["assumptions"] = serde_json::json!(["PBR-HOST-AX-002", "PBR-LINUX-AX-001"]);
        assert_eq!(
            validate(&assumption),
            Err(ValidationError::AssumptionMissing)
        );

        let mut tcb = receipt();
        tcb["trusted_computing_base"][0]["role"] = serde_json::json!("other");
        assert_eq!(validate(&tcb), Err(ValidationError::UnsupportedTcbRole));
    }

    #[test]
    fn rejects_observation_and_eligibility_forgery() {
        let mut time = receipt();
        time["observations"]["finished_ns"] = serde_json::json!("2");
        assert_eq!(validate(&time), Err(ValidationError::ObservationOrder));

        let mut eligibility = receipt();
        eligibility["outcome"] = serde_json::json!({"kind": "denied"});
        assert_eq!(
            validate(&eligibility),
            Err(ValidationError::EligibilityMismatch)
        );
    }
}
