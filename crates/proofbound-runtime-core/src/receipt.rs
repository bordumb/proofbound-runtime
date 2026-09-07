//! Defines typed execution-receipt construction and eligibility derivation.

use core::fmt;

pub use proofbound_runtime_receipt::{
    BoundaryInstallation, NonReusableReason, NonReusableReasons, ReceiptEligibility, ReceiptFacts,
    ReceiptStructure, StreamCapture, derive_receipt_eligibility,
};

use crate::{
    ArtifactIdentity, ArtifactRole, EnvironmentName, ErrorClass, ExecutionOutcome, MachineError,
    PlanId, Sha256Digest,
};

/// The only execution-receipt schema emitted by version 1.
pub const EXECUTION_RECEIPT_SCHEMA: &str = "proofbound-runtime-receipt/1";

/// The only compiled-policy model accepted by version 1 receipts.
pub const POLICY_MODEL_VERSION: &str = "proofbound-runtime-linux-policy/1";

/// Contains an RFC 4122 version 4 execution identifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExecutionId([u8; 16]);

impl ExecutionId {
    /// Validates the version and variant bits of an execution identifier.
    pub const fn from_bytes(bytes: [u8; 16]) -> Result<Self, ReceiptError> {
        if bytes[6] & 0xf0 != 0x40 || bytes[8] & 0xc0 != 0x80 {
            return Err(ReceiptError::InvalidExecutionId);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Selects one supported Linux architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Architecture {
    /// The x86-64 architecture.
    X86_64,
    /// The 64-bit Arm architecture.
    Aarch64,
}

impl Architecture {
    /// Returns the stable version 1 wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

/// Contains the source and normalized identities of one execution plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptPlan {
    id: PlanId,
    source: ArtifactIdentity,
    normalized: ArtifactIdentity,
}

impl ReceiptPlan {
    /// Validates the required plan artifact roles.
    pub fn new(
        id: PlanId,
        source: ArtifactIdentity,
        normalized: ArtifactIdentity,
    ) -> Result<Self, ReceiptError> {
        require_role(
            &source,
            ArtifactRole::ExecutionPlan,
            ReceiptArtifactField::PlanSource,
        )?;
        require_role(
            &normalized,
            ArtifactRole::NormalizedPlan,
            ReceiptArtifactField::NormalizedPlan,
        )?;
        Ok(Self {
            id,
            source,
            normalized,
        })
    }
}

/// Contains the identity and model version of one compiled policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptPolicy {
    identity: ArtifactIdentity,
}

impl ReceiptPolicy {
    /// Validates the compiled-policy role.
    pub fn new(identity: ArtifactIdentity) -> Result<Self, ReceiptError> {
        require_role(
            &identity,
            ArtifactRole::CompiledPolicy,
            ReceiptArtifactField::Policy,
        )?;
        Ok(Self { identity })
    }
}

/// Contains the identified supported Linux platform for one execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformIdentity {
    architecture: Architecture,
    kernel_release: String,
    landlock_abi: u32,
    seccomp_features: Vec<String>,
    cgroup_controllers: Vec<String>,
}

impl PlatformIdentity {
    /// Validates nonempty platform text and canonicalizes both feature sets.
    pub fn new(
        architecture: Architecture,
        kernel_release: impl Into<String>,
        landlock_abi: u32,
        seccomp_features: Vec<String>,
        cgroup_controllers: Vec<String>,
    ) -> Result<Self, ReceiptError> {
        let kernel_release = kernel_release.into();
        if kernel_release.is_empty() || landlock_abi == 0 {
            return Err(ReceiptError::InvalidPlatform);
        }
        Ok(Self {
            architecture,
            kernel_release,
            landlock_abi,
            seccomp_features: canonical_string_set(seccomp_features)?,
            cgroup_controllers: canonical_string_set(cgroup_controllers)?,
        })
    }
}

/// Contains the runtime and launcher identities used for one execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeIdentity {
    runtime: ArtifactIdentity,
    launcher: ArtifactIdentity,
}

impl RuntimeIdentity {
    /// Validates the runtime and launcher roles.
    pub fn new(
        runtime: ArtifactIdentity,
        launcher: ArtifactIdentity,
    ) -> Result<Self, ReceiptError> {
        require_role(
            &runtime,
            ArtifactRole::RuntimeBinary,
            ReceiptArtifactField::Runtime,
        )?;
        require_role(
            &launcher,
            ArtifactRole::LauncherBinary,
            ReceiptArtifactField::Launcher,
        )?;
        Ok(Self { runtime, launcher })
    }
}

/// Contains the executable closure and argument identity for one command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptCommand {
    executable: ArtifactIdentity,
    loader: Option<ArtifactIdentity>,
    working_directory: ArtifactIdentity,
    arguments_sha256: Sha256Digest,
}

impl ReceiptCommand {
    /// Validates all required command artifact roles.
    pub fn new(
        executable: ArtifactIdentity,
        loader: Option<ArtifactIdentity>,
        working_directory: ArtifactIdentity,
        arguments_sha256: Sha256Digest,
    ) -> Result<Self, ReceiptError> {
        require_role(
            &executable,
            ArtifactRole::RuntimeExecutable,
            ReceiptArtifactField::Executable,
        )?;
        if let Some(loader) = &loader {
            require_role(
                loader,
                ArtifactRole::RuntimeLoaderExecutable,
                ReceiptArtifactField::Loader,
            )?;
        }
        require_role(
            &working_directory,
            ArtifactRole::WorkingDirectory,
            ReceiptArtifactField::WorkingDirectory,
        )?;
        Ok(Self {
            executable,
            loader,
            working_directory,
            arguments_sha256,
        })
    }
}

/// Identifies one cgroup by mount and inode identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CgroupIdentity {
    mount_id: u64,
    inode: u64,
}

impl CgroupIdentity {
    /// Creates one observed cgroup identity.
    #[must_use]
    pub const fn new(mount_id: u64, inode: u64) -> Self {
        Self { mount_id, inode }
    }
}

/// Contains the launcher's boundary-installation acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundaryRecord {
    state: BoundaryInstallation,
    execution_id: ExecutionId,
    policy_sha256: Sha256Digest,
    cgroup: CgroupIdentity,
}

impl BoundaryRecord {
    /// Creates one typed boundary record.
    #[must_use]
    pub const fn new(
        state: BoundaryInstallation,
        execution_id: ExecutionId,
        policy_sha256: Sha256Digest,
        cgroup: CgroupIdentity,
    ) -> Self {
        Self {
            state,
            execution_id,
            policy_sha256,
            cgroup,
        }
    }
}

/// Contains monotonic start and finish observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionObservations {
    started_ns: u64,
    finished_ns: u64,
}

impl ExecutionObservations {
    /// Rejects a finish observation that precedes the start observation.
    pub const fn new(started_ns: u64, finished_ns: u64) -> Result<Self, ReceiptError> {
        if finished_ns < started_ns {
            return Err(ReceiptError::ObservationOrder);
        }
        Ok(Self {
            started_ns,
            finished_ns,
        })
    }
}

/// Contains one bounded stream identity and capture state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamRecord {
    artifact: ArtifactIdentity,
    capture: StreamCapture,
}

impl StreamRecord {
    /// Validates the stream artifact role.
    fn new(
        artifact: ArtifactIdentity,
        capture: StreamCapture,
        role: ArtifactRole,
        field: ReceiptArtifactField,
    ) -> Result<Self, ReceiptError> {
        require_role(&artifact, role, field)?;
        Ok(Self { artifact, capture })
    }
}

/// Contains both bounded output streams.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptStreams {
    stdout: StreamRecord,
    stderr: StreamRecord,
}

impl ReceiptStreams {
    /// Validates the standard-output and standard-error roles.
    pub fn new(
        stdout: ArtifactIdentity,
        stdout_capture: StreamCapture,
        stderr: ArtifactIdentity,
        stderr_capture: StreamCapture,
    ) -> Result<Self, ReceiptError> {
        Ok(Self {
            stdout: StreamRecord::new(
                stdout,
                stdout_capture,
                ArtifactRole::StandardOutput,
                ReceiptArtifactField::StandardOutput,
            )?,
            stderr: StreamRecord::new(
                stderr,
                stderr_capture,
                ArtifactRole::StandardError,
                ReceiptArtifactField::StandardError,
            )?,
        })
    }
}

/// Contains one nonempty trusted-computing-base entry.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TrustedComputingBaseEntry {
    role: String,
    identity: String,
}

impl TrustedComputingBaseEntry {
    /// Validates a trusted-computing-base role and identity.
    pub fn new(role: impl Into<String>, identity: impl Into<String>) -> Result<Self, ReceiptError> {
        let role = role.into();
        let identity = identity.into();
        if role.is_empty() || identity.is_empty() {
            return Err(ReceiptError::EmptyText);
        }
        Ok(Self { role, identity })
    }
}

/// Contains every caller-supplied field required to construct a receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionReceiptParts {
    /// Fresh execution identity.
    pub execution_id: ExecutionId,
    /// Source and normalized plan identities.
    pub plan: ReceiptPlan,
    /// Compiled policy identity.
    pub policy: ReceiptPolicy,
    /// Identified Linux platform.
    pub platform: PlatformIdentity,
    /// Runtime and launcher identities.
    pub runtime: RuntimeIdentity,
    /// Executable closure and argument identity.
    pub command: ReceiptCommand,
    /// Registered input and runtime-library identities.
    pub inputs: Vec<ArtifactIdentity>,
    /// Allowed environment names without values.
    pub environment: Vec<EnvironmentName>,
    /// Fresh output-root identity.
    pub output_root: ArtifactIdentity,
    /// Boundary-installation acknowledgement.
    pub boundary: BoundaryRecord,
    /// Monotonic execution observations.
    pub observations: ExecutionObservations,
    /// Bounded output streams.
    pub streams: ReceiptStreams,
    /// Observed execution outcome.
    pub outcome: ExecutionOutcome,
    /// Produced output identities.
    pub outputs: Vec<ArtifactIdentity>,
    /// Identity of the receipt producer.
    pub producer: ArtifactIdentity,
    /// Inherited assumption identifiers.
    pub assumptions: Vec<String>,
    /// Trusted computing base identities.
    pub trusted_computing_base: Vec<TrustedComputingBaseEntry>,
}

/// Contains one complete typed version 1 execution receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionReceipt {
    parts: ExecutionReceiptParts,
    environment: Vec<String>,
    assumptions: Vec<String>,
    eligibility: ReceiptEligibility,
}

impl ExecutionReceipt {
    /// Validates all roles and relationships, canonicalizes sets and artifact
    /// inventories, and derives reuse eligibility.
    pub fn new(mut parts: ExecutionReceiptParts) -> Result<Self, ReceiptError> {
        require_input_roles(&parts.inputs)?;
        require_roles(
            &parts.outputs,
            ArtifactRole::OutputArtifact,
            ReceiptArtifactField::Output,
        )?;
        require_role(
            &parts.output_root,
            ArtifactRole::OutputRoot,
            ReceiptArtifactField::OutputRoot,
        )?;
        require_role(
            &parts.producer,
            ArtifactRole::RuntimeBinary,
            ReceiptArtifactField::Producer,
        )?;

        if parts.boundary.execution_id != parts.execution_id {
            return Err(ReceiptError::IdentityMismatch(
                ReceiptIdentityField::Execution,
            ));
        }
        if parts.boundary.policy_sha256 != parts.policy.identity.digest() {
            return Err(ReceiptError::IdentityMismatch(ReceiptIdentityField::Policy));
        }
        if parts.producer != parts.runtime.runtime {
            return Err(ReceiptError::IdentityMismatch(
                ReceiptIdentityField::Producer,
            ));
        }

        parts.inputs.sort();
        reject_duplicate_artifacts(&parts.inputs)?;
        parts.outputs.sort();
        reject_duplicate_artifacts(&parts.outputs)?;
        parts.trusted_computing_base.sort();
        reject_duplicates(&parts.trusted_computing_base)?;
        if parts.trusted_computing_base.is_empty() {
            return Err(ReceiptError::TrustedComputingBaseEmpty);
        }

        let environment = canonical_string_set(
            parts
                .environment
                .iter()
                .map(|name| name.as_str().to_owned())
                .collect(),
        )?;
        let assumptions = canonical_string_set(core::mem::take(&mut parts.assumptions))?;
        let facts = ReceiptFacts::new(
            parts.boundary.state,
            parts.outcome,
            parts.streams.stdout.capture,
            parts.streams.stderr.capture,
            ReceiptStructure::Valid,
        );
        let eligibility = derive_receipt_eligibility(&facts);

        Ok(Self {
            parts,
            environment,
            assumptions,
            eligibility,
        })
    }

    /// Returns the internally derived reuse eligibility.
    #[must_use]
    pub const fn eligibility(&self) -> &ReceiptEligibility {
        &self.eligibility
    }
}

/// Identifies the receipt field whose artifact role is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptArtifactField {
    /// Source plan.
    PlanSource,
    /// Normalized plan.
    NormalizedPlan,
    /// Compiled policy.
    Policy,
    /// Runtime binary.
    Runtime,
    /// Launcher binary.
    Launcher,
    /// Runtime executable.
    Executable,
    /// Runtime loader executable.
    Loader,
    /// Working-directory inventory.
    WorkingDirectory,
    /// Registered input or runtime library.
    Input,
    /// Fresh output root.
    OutputRoot,
    /// Captured standard output.
    StandardOutput,
    /// Captured standard error.
    StandardError,
    /// Produced output artifact.
    Output,
    /// Receipt producer.
    Producer,
}

/// Identifies a mismatched receipt relationship.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptIdentityField {
    /// Boundary and top-level execution identities differ.
    Execution,
    /// Boundary and compiled-policy identities differ.
    Policy,
    /// Producer and runtime identities differ.
    Producer,
}

/// Identifies invalid execution-receipt construction input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptError {
    /// The execution identifier is not RFC 4122 version 4.
    InvalidExecutionId,
    /// Platform identity is empty or reports Landlock ABI zero.
    InvalidPlatform,
    /// A security-relevant string is empty.
    EmptyText,
    /// A set contains a duplicate value.
    DuplicateSetValue,
    /// An artifact inventory contains a duplicate identity.
    DuplicateArtifact,
    /// A required artifact has the wrong role.
    RoleMismatch(ReceiptArtifactField),
    /// Two copies of one required identity differ.
    IdentityMismatch(ReceiptIdentityField),
    /// Finish time precedes start time.
    ObservationOrder,
    /// The trusted computing base contains no entry.
    TrustedComputingBaseEmpty,
}

impl ReceiptError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidExecutionId => "receipt.execution-id.invalid",
            Self::InvalidPlatform => "receipt.platform.invalid",
            Self::EmptyText => "receipt.text.empty",
            Self::DuplicateSetValue => "receipt.set.duplicate",
            Self::DuplicateArtifact => "receipt.artifact.duplicate",
            Self::RoleMismatch(_) => "receipt.role.mismatch",
            Self::IdentityMismatch(ReceiptIdentityField::Execution) => {
                "receipt.identity.execution-mismatch"
            }
            Self::IdentityMismatch(ReceiptIdentityField::Policy) => {
                "receipt.identity.policy-mismatch"
            }
            Self::IdentityMismatch(ReceiptIdentityField::Producer) => {
                "receipt.identity.producer-mismatch"
            }
            Self::ObservationOrder => "receipt.observation.order",
            Self::TrustedComputingBaseEmpty => "receipt.tcb.empty",
        }
    }
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ReceiptError {}

impl MachineError for ReceiptError {
    fn machine_code(&self) -> &'static str {
        (*self).code()
    }

    fn error_class(&self) -> ErrorClass {
        ErrorClass::ReceiptConstruction
    }
}

fn require_role(
    artifact: &ArtifactIdentity,
    expected: ArtifactRole,
    field: ReceiptArtifactField,
) -> Result<(), ReceiptError> {
    if artifact.role() == expected {
        Ok(())
    } else {
        Err(ReceiptError::RoleMismatch(field))
    }
}

fn require_roles(
    artifacts: &[ArtifactIdentity],
    expected: ArtifactRole,
    field: ReceiptArtifactField,
) -> Result<(), ReceiptError> {
    for artifact in artifacts {
        require_role(artifact, expected, field)?;
    }
    Ok(())
}

fn require_input_roles(artifacts: &[ArtifactIdentity]) -> Result<(), ReceiptError> {
    for artifact in artifacts {
        if !matches!(
            artifact.role(),
            ArtifactRole::ProjectInput | ArtifactRole::RuntimeLibrary
        ) {
            return Err(ReceiptError::RoleMismatch(ReceiptArtifactField::Input));
        }
    }
    Ok(())
}

fn canonical_string_set(mut values: Vec<String>) -> Result<Vec<String>, ReceiptError> {
    if values.iter().any(String::is_empty) {
        return Err(ReceiptError::EmptyText);
    }
    values.sort();
    reject_duplicates(&values)?;
    Ok(values)
}

fn reject_duplicate_artifacts(values: &[ArtifactIdentity]) -> Result<(), ReceiptError> {
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        Err(ReceiptError::DuplicateArtifact)
    } else {
        Ok(())
    }
}

fn reject_duplicates<T: PartialEq>(values: &[T]) -> Result<(), ReceiptError> {
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        Err(ReceiptError::DuplicateSetValue)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FileMode;

    fn artifact(role: ArtifactRole, marker: u8) -> ArtifactIdentity {
        ArtifactIdentity::new(
            role,
            Sha256Digest::from_bytes([marker; 32]),
            u64::from(marker),
            FileMode::new(0o640).expect("fixture mode is valid"),
        )
    }

    fn execution_id() -> ExecutionId {
        ExecutionId::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
        .expect("fixture is an RFC 4122 version 4 identifier")
    }

    fn parts() -> ExecutionReceiptParts {
        let execution_id = execution_id();
        let runtime = artifact(ArtifactRole::RuntimeBinary, 4);
        let policy = artifact(ArtifactRole::CompiledPolicy, 3);
        ExecutionReceiptParts {
            execution_id,
            plan: ReceiptPlan::new(
                PlanId::new("fixture.plan").expect("fixture plan id is valid"),
                artifact(ArtifactRole::ExecutionPlan, 1),
                artifact(ArtifactRole::NormalizedPlan, 2),
            )
            .expect("fixture plan roles are valid"),
            policy: ReceiptPolicy::new(policy.clone()).expect("fixture policy role is valid"),
            platform: PlatformIdentity::new(
                Architecture::X86_64,
                "6.12.0",
                6,
                vec!["tsync".to_owned(), "log".to_owned()],
                vec!["pids".to_owned(), "memory".to_owned()],
            )
            .expect("fixture platform is valid"),
            runtime: RuntimeIdentity::new(
                runtime.clone(),
                artifact(ArtifactRole::LauncherBinary, 5),
            )
            .expect("fixture runtime roles are valid"),
            command: ReceiptCommand::new(
                artifact(ArtifactRole::RuntimeExecutable, 6),
                Some(artifact(ArtifactRole::RuntimeLoaderExecutable, 7)),
                artifact(ArtifactRole::WorkingDirectory, 8),
                Sha256Digest::from_bytes([9; 32]),
            )
            .expect("fixture command roles are valid"),
            inputs: vec![
                artifact(ArtifactRole::ProjectInput, 11),
                artifact(ArtifactRole::RuntimeLibrary, 10),
            ],
            environment: vec![
                EnvironmentName::new("PATH").expect("fixture name is valid"),
                EnvironmentName::new("LANG").expect("fixture name is valid"),
            ],
            output_root: artifact(ArtifactRole::OutputRoot, 12),
            boundary: BoundaryRecord::new(
                BoundaryInstallation::Installed,
                execution_id,
                policy.digest(),
                CgroupIdentity::new(13, 14),
            ),
            observations: ExecutionObservations::new(15, 16)
                .expect("fixture observation order is valid"),
            streams: ReceiptStreams::new(
                artifact(ArtifactRole::StandardOutput, 17),
                StreamCapture::Complete,
                artifact(ArtifactRole::StandardError, 18),
                StreamCapture::Complete,
            )
            .expect("fixture stream roles are valid"),
            outcome: ExecutionOutcome::Exited { code: 0 },
            outputs: vec![artifact(ArtifactRole::OutputArtifact, 19)],
            producer: runtime,
            assumptions: vec!["PBR-LINUX-AX-001".to_owned(), "PBR-HOST-AX-002".to_owned()],
            trusted_computing_base: vec![
                TrustedComputingBaseEntry::new("kernel", "linux:6.12.0")
                    .expect("fixture TCB entry is valid"),
            ],
        }
    }

    #[test]
    fn constructor_derives_reuse_and_canonicalizes_sets() {
        let receipt = ExecutionReceipt::new(parts()).expect("fixture receipt is valid");
        assert_eq!(receipt.eligibility(), &ReceiptEligibility::Reusable);
        assert_eq!(receipt.environment, ["LANG", "PATH"]);
        assert_eq!(receipt.assumptions, ["PBR-HOST-AX-002", "PBR-LINUX-AX-001"]);
        assert_eq!(receipt.parts.inputs[0].role(), ArtifactRole::RuntimeLibrary);
    }

    #[test]
    fn constructor_rejects_identity_substitution() {
        let mut input = parts();
        input.boundary.execution_id = ExecutionId::from_bytes([
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x49, 0x88, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
            0x33, 0x22,
        ])
        .expect("fixture is an RFC 4122 version 4 identifier");
        let error = ExecutionReceipt::new(input).expect_err("substitution must fail");
        assert_eq!(error.code(), "receipt.identity.execution-mismatch");
        assert_eq!(error.error_class().exit_code(), 6);
    }

    #[test]
    fn constructor_rejects_wrong_roles_and_duplicate_sets() {
        assert_eq!(
            ReceiptPolicy::new(artifact(ArtifactRole::ProjectInput, 1)),
            Err(ReceiptError::RoleMismatch(ReceiptArtifactField::Policy))
        );
        let mut input = parts();
        input.assumptions = vec!["same".to_owned(), "same".to_owned()];
        assert_eq!(
            ExecutionReceipt::new(input),
            Err(ReceiptError::DuplicateSetValue)
        );
    }

    #[test]
    fn execution_id_rejects_non_v4_values() {
        assert_eq!(
            ExecutionId::from_bytes([0; 16]),
            Err(ReceiptError::InvalidExecutionId)
        );
    }
}
