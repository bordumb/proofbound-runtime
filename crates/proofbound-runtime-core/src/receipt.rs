//! Defines typed execution-receipt construction and eligibility derivation.

use core::fmt;
use core::fmt::Write as _;

use proofbound_runtime_binding::{ReceiptBindingParts, construct_and_project_receipt_binding};
use serde::Serialize;

pub use proofbound_runtime_receipt::{
    BoundaryInstallation, LimitEvent, LimitEvents, NonReusableReason, NonReusableReasons,
    ReceiptEligibility, ReceiptFacts, ReceiptStructure, StreamCapture, derive_receipt_eligibility,
};

use crate::{
    ArtifactIdentity, ArtifactRole, EnvironmentName, ErrorClass, ExecutionOutcome, MachineError,
    MemoryByteLimit, PlanId, ProcessLimit, ResourceLimits, Sha256Digest, SwapByteLimit,
};

/// The only execution-receipt schema emitted by version 1.
pub const EXECUTION_RECEIPT_SCHEMA: &str = "proofbound-runtime-receipt/1";

/// The execution-receipt schema emitted for complete version 2 resources.
pub const EXECUTION_RECEIPT_V2_SCHEMA: &str = "proofbound-runtime-execution-receipt/2";

/// The only compiled-policy model accepted by version 1 receipts.
pub const POLICY_MODEL_VERSION: &str = "proofbound-runtime-linux-policy/1";

/// The compiled-policy model bound into version 2 receipts.
pub const POLICY_MODEL_VERSION_V2: &str = "proofbound-runtime-linux-policy/2";

/// The assumptions that every version 1 runtime receipt must inherit.
pub const REQUIRED_RUNTIME_ASSUMPTIONS: [&str; 3] = [
    "PBR-HOST-AX-002",
    "PBR-LINUX-AX-001",
    "PBR-TOOLCHAIN-AX-003",
];

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

    /// Returns the canonical lowercase RFC 4122 text carried on version 1 wires.
    #[must_use]
    pub fn to_text(self) -> String {
        let mut output = String::with_capacity(36);
        for (index, byte) in self.0.into_iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                output.push('-');
            }
            write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
        }
        output
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

    /// Returns the kernel mount identifier.
    #[must_use]
    pub const fn mount_id(self) -> u64 {
        self.mount_id
    }

    /// Returns the cgroup directory inode.
    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode
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

/// Contains the checked terminal deltas from `memory.events.local`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptMemoryEvents {
    low: u64,
    high: u64,
    max: u64,
    oom: u64,
    oom_kill: u64,
    oom_group_kill: u64,
}

impl ReceiptMemoryEvents {
    /// Creates the complete closed memory-event counter set.
    #[must_use]
    pub const fn new(
        low: u64,
        high: u64,
        max: u64,
        oom: u64,
        oom_kill: u64,
        oom_group_kill: u64,
    ) -> Self {
        Self {
            low,
            high,
            max,
            oom,
            oom_kill,
            oom_group_kill,
        }
    }

    #[must_use]
    pub const fn low(self) -> u64 {
        self.low
    }
    #[must_use]
    pub const fn high(self) -> u64 {
        self.high
    }
    #[must_use]
    pub const fn max(self) -> u64 {
        self.max
    }
    #[must_use]
    pub const fn oom(self) -> u64 {
        self.oom
    }
    #[must_use]
    pub const fn oom_kill(self) -> u64 {
        self.oom_kill
    }
    #[must_use]
    pub const fn oom_group_kill(self) -> u64 {
        self.oom_group_kill
    }
}

/// Contains the checked terminal deltas from `memory.swap.events`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptSwapEvents {
    max: u64,
    fail: u64,
}

impl ReceiptSwapEvents {
    /// Creates the complete closed swap-event counter set.
    #[must_use]
    pub const fn new(max: u64, fail: u64) -> Self {
        Self { max, fail }
    }
    #[must_use]
    pub const fn max(self) -> u64 {
        self.max
    }
    #[must_use]
    pub const fn fail(self) -> u64 {
        self.fail
    }
}

/// Contains exact configured limits and terminal observations for version 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptResources {
    processes: ProcessLimit,
    memory: MemoryByteLimit,
    swap: SwapByteLimit,
    memory_oom_group: u64,
    memory_peak_bytes: u64,
    swap_peak_bytes: u64,
    memory_events: ReceiptMemoryEvents,
    swap_events: ReceiptSwapEvents,
    limit_events: LimitEvents,
}

impl ReceiptResources {
    /// Validates a complete v2 limit profile and derives its event set.
    pub fn new(
        limits: ResourceLimits,
        memory_peak_bytes: u64,
        swap_peak_bytes: u64,
        memory_events: ReceiptMemoryEvents,
        swap_events: ReceiptSwapEvents,
    ) -> Result<Self, ReceiptError> {
        let memory = limits
            .memory()
            .ok_or(ReceiptError::ResourceProfileIncomplete)?;
        let swap = limits
            .swap()
            .ok_or(ReceiptError::ResourceProfileIncomplete)?;
        Self::from_configured(
            limits.processes(),
            memory,
            swap,
            1,
            memory_peak_bytes,
            swap_peak_bytes,
            memory_events,
            swap_events,
        )
    }

    /// Builds version 2 resources from the exact installed-control readbacks.
    pub fn from_configured(
        processes: ProcessLimit,
        memory: MemoryByteLimit,
        swap: SwapByteLimit,
        memory_oom_group: u64,
        memory_peak_bytes: u64,
        swap_peak_bytes: u64,
        memory_events: ReceiptMemoryEvents,
        swap_events: ReceiptSwapEvents,
    ) -> Result<Self, ReceiptError> {
        if memory_oom_group != 1 {
            return Err(ReceiptError::ConfiguredResourcesInvalid);
        }
        let mut events = Vec::new();
        for (present, event) in [
            (memory_events.high != 0, LimitEvent::MemoryHigh),
            (memory_events.max != 0, LimitEvent::MemoryMax),
            (memory_events.oom != 0, LimitEvent::MemoryOom),
            (memory_events.oom_kill != 0, LimitEvent::MemoryOomKill),
            (
                memory_events.oom_group_kill != 0,
                LimitEvent::MemoryOomGroupKill,
            ),
            (swap_events.max != 0, LimitEvent::SwapMax),
            (swap_events.fail != 0, LimitEvent::SwapFail),
        ] {
            if present {
                events.push(event);
            }
        }
        Ok(Self {
            processes,
            memory,
            swap,
            memory_oom_group,
            memory_peak_bytes,
            swap_peak_bytes,
            memory_events,
            swap_events,
            limit_events: LimitEvents::new(&events),
        })
    }

    #[must_use]
    pub const fn processes(self) -> ProcessLimit {
        self.processes
    }
    #[must_use]
    pub const fn memory(self) -> MemoryByteLimit {
        self.memory
    }
    #[must_use]
    pub const fn swap(self) -> SwapByteLimit {
        self.swap
    }
    #[must_use]
    pub const fn memory_oom_group(self) -> u64 {
        self.memory_oom_group
    }
    #[must_use]
    pub const fn memory_peak_bytes(self) -> u64 {
        self.memory_peak_bytes
    }
    #[must_use]
    pub const fn swap_peak_bytes(self) -> u64 {
        self.swap_peak_bytes
    }
    #[must_use]
    pub const fn memory_events(self) -> ReceiptMemoryEvents {
        self.memory_events
    }
    #[must_use]
    pub const fn swap_events(self) -> ReceiptSwapEvents {
        self.swap_events
    }
    #[must_use]
    pub const fn limit_events(self) -> LimitEvents {
        self.limit_events
    }
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

/// Identifies one closed trusted-computing-base role.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TrustedComputingBaseRole {
    /// Host hardware and firmware.
    HostHardwareFirmware,
    /// The identified Linux kernel.
    LinuxKernel,
    /// Landlock filesystem mediation.
    Landlock,
    /// Seccomp syscall mediation.
    Seccomp,
    /// Cgroup v2 resource and process accounting.
    CgroupV2,
    /// `PR_SET_NO_NEW_PRIVS` behavior.
    NoNewPrivileges,
    /// Filesystem identity and descriptor behavior.
    Filesystem,
    /// The exact runtime binary.
    RuntimeBinary,
    /// The exact launcher binary.
    LauncherBinary,
    /// Rust compiler, linker, standard library, and dependencies.
    RustToolchain,
    /// The SHA-256 implementation used for artifact identities.
    CryptographicDigest,
    /// The exact child executable.
    RuntimeExecutable,
    /// The exact loader used by the child.
    RuntimeLoaderExecutable,
    /// One or more exact runtime libraries used by the child.
    RuntimeLibrary,
}

impl TrustedComputingBaseRole {
    /// Returns the stable version 1 wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostHardwareFirmware => "host-hardware-firmware",
            Self::LinuxKernel => "linux-kernel",
            Self::Landlock => "landlock",
            Self::Seccomp => "seccomp",
            Self::CgroupV2 => "cgroup-v2",
            Self::NoNewPrivileges => "no-new-privileges",
            Self::Filesystem => "filesystem",
            Self::RuntimeBinary => "runtime-binary",
            Self::LauncherBinary => "launcher-binary",
            Self::RustToolchain => "rust-toolchain",
            Self::CryptographicDigest => "cryptographic-digest",
            Self::RuntimeExecutable => "runtime-executable",
            Self::RuntimeLoaderExecutable => "runtime-loader-executable",
            Self::RuntimeLibrary => "runtime-library",
        }
    }
}

/// Contains one nonempty trusted-computing-base entry.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TrustedComputingBaseEntry {
    role: TrustedComputingBaseRole,
    identity: String,
}

impl TrustedComputingBaseEntry {
    /// Validates a trusted-computing-base role and identity.
    pub fn new(
        role: TrustedComputingBaseRole,
        identity: impl Into<String>,
    ) -> Result<Self, ReceiptError> {
        let identity = identity.into();
        if identity.is_empty() {
            return Err(ReceiptError::EmptyText);
        }
        Ok(Self { role, identity })
    }

    /// Returns the closed trusted-computing-base role.
    #[must_use]
    pub const fn role(&self) -> TrustedComputingBaseRole {
        self.role
    }

    /// Returns the identified implementation or artifact.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
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
    /// Exact version 2 configured and terminal resource facts; absent for v1.
    pub resources: Option<ReceiptResources>,
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
        for required in REQUIRED_RUNTIME_ASSUMPTIONS {
            if assumptions
                .binary_search_by(|value| value.as_str().cmp(required))
                .is_err()
            {
                return Err(ReceiptError::AssumptionMissing);
            }
        }
        require_tcb_roles(&parts)?;
        let facts = match parts.resources {
            Some(resources) => ReceiptFacts::new_v2(
                parts.boundary.state,
                parts.outcome,
                parts.streams.stdout.capture,
                parts.streams.stderr.capture,
                ReceiptStructure::Valid,
                resources.limit_events,
            ),
            None => ReceiptFacts::new(
                parts.boundary.state,
                parts.outcome,
                parts.streams.stdout.capture,
                parts.streams.stderr.capture,
                ReceiptStructure::Valid,
            ),
        };
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

    /// Returns the canonical RFC 8785-compatible version 1 JSON bytes.
    ///
    /// The wire domain contains no floating-point values. All object names are
    /// ASCII, every 64-bit counter is a decimal string, and conversion through
    /// `serde_json::Value` sorts every object key before compact encoding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReceiptError> {
        if self.parts.resources.is_some() {
            return canonical_v2_bytes(self);
        }
        let wire = WireExecutionReceipt::from(self);
        let parts = ReceiptBindingParts {
            assumptions: canonical_field_bytes(&wire.assumptions)?,
            boundary: canonical_field_bytes(&wire.boundary)?,
            command: canonical_field_bytes(&wire.command)?,
            eligibility: canonical_field_bytes(&wire.eligibility)?,
            environment: canonical_field_bytes(&wire.environment)?,
            execution_id: canonical_field_bytes(&wire.execution_id)?,
            inputs: canonical_field_bytes(&wire.inputs)?,
            observations: canonical_field_bytes(&wire.observations)?,
            outcome: canonical_field_bytes(&wire.outcome)?,
            output_root: canonical_field_bytes(&wire.output_root)?,
            outputs: canonical_field_bytes(&wire.outputs)?,
            plan: canonical_field_bytes(&wire.plan)?,
            platform: canonical_field_bytes(&wire.platform)?,
            policy: canonical_field_bytes(&wire.policy)?,
            producer: canonical_field_bytes(&wire.producer)?,
            product_version: canonical_field_bytes(&wire.product_version)?,
            resources: None,
            runtime: canonical_field_bytes(&wire.runtime)?,
            schema: canonical_field_bytes(&wire.schema)?,
            streams: canonical_field_bytes(&wire.streams)?,
            trusted_computing_base: canonical_field_bytes(&wire.trusted_computing_base)?,
        };
        encode_binding(construct_and_project_receipt_binding(parts))
    }
}

fn canonical_v2_bytes(receipt: &ExecutionReceipt) -> Result<Vec<u8>, ReceiptError> {
    let parts = canonical_v2_binding_parts(receipt)?;
    encode_v2_binding(construct_and_project_receipt_binding(parts))
}

fn canonical_v2_binding_parts(
    receipt: &ExecutionReceipt,
) -> Result<ReceiptBindingParts, ReceiptError> {
    use crate::wire_v2::Value as Cbor;

    let parts = &receipt.parts;
    let resources = parts
        .resources
        .ok_or(ReceiptError::ResourceProfileIncomplete)?;
    let value = Cbor::Map(vec![
        ("plan".to_owned(), cbor_plan(&parts.plan)),
        (
            "schema".to_owned(),
            Cbor::Text(EXECUTION_RECEIPT_V2_SCHEMA.to_owned()),
        ),
        (
            "inputs".to_owned(),
            Cbor::Array(parts.inputs.iter().map(cbor_artifact).collect()),
        ),
        (
            "policy".to_owned(),
            Cbor::Map(vec![
                ("identity".to_owned(), cbor_artifact(&parts.policy.identity)),
                (
                    "model_version".to_owned(),
                    Cbor::Text(POLICY_MODEL_VERSION_V2.to_owned()),
                ),
            ]),
        ),
        (
            "runtime".to_owned(),
            Cbor::Map(vec![
                ("runtime".to_owned(), cbor_artifact(&parts.runtime.runtime)),
                (
                    "launcher".to_owned(),
                    cbor_artifact(&parts.runtime.launcher),
                ),
            ]),
        ),
        ("streams".to_owned(), cbor_streams(&parts.streams)),
        ("command".to_owned(), cbor_command(&parts.command)),
        ("outcome".to_owned(), cbor_outcome(parts.outcome)),
        (
            "outputs".to_owned(),
            Cbor::Array(parts.outputs.iter().map(cbor_artifact).collect()),
        ),
        ("boundary".to_owned(), cbor_boundary(&parts.boundary)),
        ("producer".to_owned(), cbor_artifact(&parts.producer)),
        ("platform".to_owned(), cbor_platform(&parts.platform)),
        ("resources".to_owned(), cbor_resources(resources)),
        (
            "eligibility".to_owned(),
            cbor_eligibility(&receipt.eligibility),
        ),
        (
            "environment".to_owned(),
            cbor_text_array(receipt.environment.iter().map(String::as_str)),
        ),
        (
            "execution_id".to_owned(),
            Cbor::Bytes(parts.execution_id.0.to_vec()),
        ),
        (
            "observations".to_owned(),
            Cbor::Map(vec![
                ("clock".to_owned(), Cbor::Text("linux-monotonic".to_owned())),
                (
                    "started_ns".to_owned(),
                    Cbor::Unsigned(parts.observations.started_ns),
                ),
                (
                    "finished_ns".to_owned(),
                    Cbor::Unsigned(parts.observations.finished_ns),
                ),
            ]),
        ),
        (
            "product_version".to_owned(),
            Cbor::Text(env!("CARGO_PKG_VERSION").to_owned()),
        ),
        (
            "assumptions".to_owned(),
            cbor_text_array(receipt.assumptions.iter().map(String::as_str)),
        ),
        ("output_root".to_owned(), cbor_artifact(&parts.output_root)),
        (
            "trusted_computing_base".to_owned(),
            Cbor::Array(
                parts
                    .trusted_computing_base
                    .iter()
                    .map(|entry| {
                        Cbor::Map(vec![
                            (
                                "role".to_owned(),
                                Cbor::Text(entry.role.as_str().to_owned()),
                            ),
                            ("identity".to_owned(), Cbor::Text(entry.identity.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]);
    let Cbor::Map(mut fields) = value else {
        return Err(ReceiptError::CanonicalEncoding);
    };
    let parts = ReceiptBindingParts {
        assumptions: take_cbor_field(&mut fields, "assumptions")?,
        boundary: take_cbor_field(&mut fields, "boundary")?,
        command: take_cbor_field(&mut fields, "command")?,
        eligibility: take_cbor_field(&mut fields, "eligibility")?,
        environment: take_cbor_field(&mut fields, "environment")?,
        execution_id: take_cbor_field(&mut fields, "execution_id")?,
        inputs: take_cbor_field(&mut fields, "inputs")?,
        observations: take_cbor_field(&mut fields, "observations")?,
        outcome: take_cbor_field(&mut fields, "outcome")?,
        output_root: take_cbor_field(&mut fields, "output_root")?,
        outputs: take_cbor_field(&mut fields, "outputs")?,
        plan: take_cbor_field(&mut fields, "plan")?,
        platform: take_cbor_field(&mut fields, "platform")?,
        policy: take_cbor_field(&mut fields, "policy")?,
        producer: take_cbor_field(&mut fields, "producer")?,
        product_version: take_cbor_field(&mut fields, "product_version")?,
        resources: Some(take_cbor_field(&mut fields, "resources")?),
        runtime: take_cbor_field(&mut fields, "runtime")?,
        schema: take_cbor_field(&mut fields, "schema")?,
        streams: take_cbor_field(&mut fields, "streams")?,
        trusted_computing_base: take_cbor_field(&mut fields, "trusted_computing_base")?,
    };
    if fields.is_empty() {
        Ok(parts)
    } else {
        Err(ReceiptError::CanonicalEncoding)
    }
}

fn take_cbor_field(
    fields: &mut Vec<(String, crate::wire_v2::Value)>,
    name: &str,
) -> Result<Vec<u8>, ReceiptError> {
    let index = fields
        .iter()
        .position(|(field, _)| field == name)
        .ok_or(ReceiptError::CanonicalEncoding)?;
    let (_, value) = fields.remove(index);
    crate::wire_v2::encode(&value).map_err(|_| ReceiptError::CanonicalEncoding)
}

fn encode_v2_binding(parts: ReceiptBindingParts) -> Result<Vec<u8>, ReceiptError> {
    let resources = parts
        .resources
        .ok_or(ReceiptError::ResourceProfileIncomplete)?;
    crate::wire_v2::encode_bound_map(vec![
        ("assumptions".to_owned(), parts.assumptions),
        ("boundary".to_owned(), parts.boundary),
        ("command".to_owned(), parts.command),
        ("eligibility".to_owned(), parts.eligibility),
        ("environment".to_owned(), parts.environment),
        ("execution_id".to_owned(), parts.execution_id),
        ("inputs".to_owned(), parts.inputs),
        ("observations".to_owned(), parts.observations),
        ("outcome".to_owned(), parts.outcome),
        ("output_root".to_owned(), parts.output_root),
        ("outputs".to_owned(), parts.outputs),
        ("plan".to_owned(), parts.plan),
        ("platform".to_owned(), parts.platform),
        ("policy".to_owned(), parts.policy),
        ("producer".to_owned(), parts.producer),
        ("product_version".to_owned(), parts.product_version),
        ("resources".to_owned(), resources),
        ("runtime".to_owned(), parts.runtime),
        ("schema".to_owned(), parts.schema),
        ("streams".to_owned(), parts.streams),
        (
            "trusted_computing_base".to_owned(),
            parts.trusted_computing_base,
        ),
    ])
    .map_err(|_| ReceiptError::CanonicalEncoding)
}

fn cbor_artifact(identity: &ArtifactIdentity) -> crate::wire_v2::Value {
    use crate::wire_v2::Value as Cbor;
    Cbor::Map(vec![
        (
            "mode".to_owned(),
            Cbor::Unsigned(u64::from(identity.mode().get())),
        ),
        (
            "role".to_owned(),
            Cbor::Text(identity.role().as_str().to_owned()),
        ),
        ("size".to_owned(), Cbor::Unsigned(identity.size())),
        (
            "sha256".to_owned(),
            Cbor::Bytes(identity.digest().as_bytes().to_vec()),
        ),
    ])
}

fn cbor_plan(plan: &ReceiptPlan) -> crate::wire_v2::Value {
    use crate::wire_v2::Value as Cbor;
    Cbor::Map(vec![
        ("id".to_owned(), Cbor::Text(plan.id.as_str().to_owned())),
        ("source".to_owned(), cbor_artifact(&plan.source)),
        ("normalized".to_owned(), cbor_artifact(&plan.normalized)),
    ])
}

fn cbor_command(command: &ReceiptCommand) -> crate::wire_v2::Value {
    use crate::wire_v2::Value as Cbor;
    Cbor::Map(vec![
        (
            "loader".to_owned(),
            command.loader.as_ref().map_or(Cbor::Null, cbor_artifact),
        ),
        ("executable".to_owned(), cbor_artifact(&command.executable)),
        (
            "arguments_sha256".to_owned(),
            Cbor::Bytes(command.arguments_sha256.as_bytes().to_vec()),
        ),
        (
            "working_directory".to_owned(),
            cbor_artifact(&command.working_directory),
        ),
    ])
}

fn cbor_boundary(boundary: &BoundaryRecord) -> crate::wire_v2::Value {
    use crate::wire_v2::Value as Cbor;
    Cbor::Map(vec![
        (
            "state".to_owned(),
            Cbor::Text(boundary_wire_name(boundary.state).to_owned()),
        ),
        (
            "cgroup".to_owned(),
            Cbor::Map(vec![
                ("inode".to_owned(), Cbor::Unsigned(boundary.cgroup.inode)),
                (
                    "mount_id".to_owned(),
                    Cbor::Unsigned(boundary.cgroup.mount_id),
                ),
            ]),
        ),
        (
            "execution_id".to_owned(),
            Cbor::Bytes(boundary.execution_id.0.to_vec()),
        ),
        (
            "policy_sha256".to_owned(),
            Cbor::Bytes(boundary.policy_sha256.as_bytes().to_vec()),
        ),
    ])
}

fn cbor_platform(platform: &PlatformIdentity) -> crate::wire_v2::Value {
    use crate::wire_v2::Value as Cbor;
    Cbor::Map(vec![
        (
            "architecture".to_owned(),
            Cbor::Text(platform.architecture.as_str().to_owned()),
        ),
        (
            "landlock_abi".to_owned(),
            Cbor::Unsigned(u64::from(platform.landlock_abi)),
        ),
        (
            "kernel_release".to_owned(),
            Cbor::Text(platform.kernel_release.clone()),
        ),
        (
            "operating_system".to_owned(),
            Cbor::Text("linux".to_owned()),
        ),
        (
            "seccomp_features".to_owned(),
            cbor_text_array(platform.seccomp_features.iter().map(String::as_str)),
        ),
        (
            "cgroup_controllers".to_owned(),
            cbor_text_array(platform.cgroup_controllers.iter().map(String::as_str)),
        ),
    ])
}

fn cbor_streams(streams: &ReceiptStreams) -> crate::wire_v2::Value {
    use crate::wire_v2::Value as Cbor;
    let stream = |record: &StreamRecord| {
        Cbor::Map(vec![
            (
                "capture".to_owned(),
                Cbor::Text(stream_capture_wire_name(record.capture).to_owned()),
            ),
            ("artifact".to_owned(), cbor_artifact(&record.artifact)),
        ])
    };
    Cbor::Map(vec![
        ("stderr".to_owned(), stream(&streams.stderr)),
        ("stdout".to_owned(), stream(&streams.stdout)),
    ])
}

fn cbor_outcome(outcome: ExecutionOutcome) -> crate::wire_v2::Value {
    use crate::wire_v2::Value as Cbor;
    let mut fields = Vec::new();
    match outcome {
        ExecutionOutcome::Exited { code } => {
            fields.push(("kind".to_owned(), Cbor::Text("exited".to_owned())));
            let code = if code >= 0 {
                Cbor::Unsigned(u64::try_from(code).expect("nonnegative i32 fits u64"))
            } else {
                Cbor::Negative(u64::try_from(-1_i64 - i64::from(code)).expect("i32 fits u64"))
            };
            fields.push(("code".to_owned(), code));
        }
        ExecutionOutcome::Signaled { signal } => {
            fields.push(("kind".to_owned(), Cbor::Text("signaled".to_owned())));
            fields.push(("signal".to_owned(), Cbor::Unsigned(u64::from(signal.get()))));
        }
        ExecutionOutcome::TimedOut => {
            fields.push(("kind".to_owned(), Cbor::Text("timed-out".to_owned())))
        }
        ExecutionOutcome::Denied => {
            fields.push(("kind".to_owned(), Cbor::Text("denied".to_owned())))
        }
        ExecutionOutcome::LauncherFailed => {
            fields.push(("kind".to_owned(), Cbor::Text("launcher-failed".to_owned())))
        }
        ExecutionOutcome::Incomplete => {
            fields.push(("kind".to_owned(), Cbor::Text("incomplete".to_owned())))
        }
    }
    Cbor::Map(fields)
}

fn cbor_resources(resources: ReceiptResources) -> crate::wire_v2::Value {
    use crate::wire_v2::Value as Cbor;
    let memory = resources.memory_events;
    let swap = resources.swap_events;
    Cbor::Map(vec![
        (
            "terminal".to_owned(),
            Cbor::Map(vec![
                (
                    "swap_events".to_owned(),
                    Cbor::Map(vec![
                        ("max".to_owned(), Cbor::Unsigned(swap.max)),
                        ("fail".to_owned(), Cbor::Unsigned(swap.fail)),
                    ]),
                ),
                (
                    "memory_events".to_owned(),
                    Cbor::Map(vec![
                        ("low".to_owned(), Cbor::Unsigned(memory.low)),
                        ("oom".to_owned(), Cbor::Unsigned(memory.oom)),
                        ("high".to_owned(), Cbor::Unsigned(memory.high)),
                        ("max".to_owned(), Cbor::Unsigned(memory.max)),
                        ("oom_kill".to_owned(), Cbor::Unsigned(memory.oom_kill)),
                        (
                            "oom_group_kill".to_owned(),
                            Cbor::Unsigned(memory.oom_group_kill),
                        ),
                    ]),
                ),
                (
                    "swap_peak_bytes".to_owned(),
                    Cbor::Unsigned(resources.swap_peak_bytes),
                ),
                (
                    "memory_peak_bytes".to_owned(),
                    Cbor::Unsigned(resources.memory_peak_bytes),
                ),
            ]),
        ),
        (
            "configured".to_owned(),
            Cbor::Map(vec![
                (
                    "pids.max".to_owned(),
                    Cbor::Unsigned(u64::from(resources.processes.get())),
                ),
                (
                    "memory.max".to_owned(),
                    Cbor::Unsigned(resources.memory.get()),
                ),
                (
                    "memory.oom.group".to_owned(),
                    Cbor::Unsigned(resources.memory_oom_group),
                ),
                (
                    "memory.swap.max".to_owned(),
                    Cbor::Unsigned(resources.swap.get()),
                ),
            ]),
        ),
        (
            "limit_events".to_owned(),
            Cbor::Array(
                canonical_limit_events(resources.limit_events)
                    .into_iter()
                    .map(|event| Cbor::Text(event.to_owned()))
                    .collect(),
            ),
        ),
    ])
}

fn canonical_limit_events(events: LimitEvents) -> Vec<&'static str> {
    [
        (LimitEvent::MemoryHigh, "memory-high"),
        (LimitEvent::MemoryMax, "memory-max"),
        (LimitEvent::MemoryOom, "memory-oom"),
        (LimitEvent::MemoryOomKill, "memory-oom-kill"),
        (LimitEvent::MemoryOomGroupKill, "memory-oom-group-kill"),
        (LimitEvent::SwapMax, "swap-max"),
        (LimitEvent::SwapFail, "swap-fail"),
    ]
    .into_iter()
    .filter_map(|(event, name)| events.contains(event).then_some(name))
    .collect()
}

fn cbor_eligibility(eligibility: &ReceiptEligibility) -> crate::wire_v2::Value {
    use crate::wire_v2::Value as Cbor;
    let (status, reasons) = match eligibility {
        ReceiptEligibility::Reusable => ("reusable", Vec::new()),
        ReceiptEligibility::NonReusable(reasons) => (
            "non-reusable",
            reasons
                .as_slice()
                .iter()
                .copied()
                .map(non_reusable_reason_wire_name)
                .collect(),
        ),
    };
    Cbor::Map(vec![
        ("status".to_owned(), Cbor::Text(status.to_owned())),
        (
            "reasons".to_owned(),
            Cbor::Array(
                reasons
                    .into_iter()
                    .map(|reason| Cbor::Text(reason.to_owned()))
                    .collect(),
            ),
        ),
    ])
}

fn cbor_text_array<'a>(values: impl Iterator<Item = &'a str>) -> crate::wire_v2::Value {
    use crate::wire_v2::Value as Cbor;
    Cbor::Array(values.map(|value| Cbor::Text(value.to_owned())).collect())
}

fn canonical_field_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ReceiptError> {
    let value = serde_json::to_value(value).map_err(|_| ReceiptError::CanonicalEncoding)?;
    serde_json::to_vec(&value).map_err(|_| ReceiptError::CanonicalEncoding)
}

fn encode_binding(parts: ReceiptBindingParts) -> Result<Vec<u8>, ReceiptError> {
    let mut output = Vec::new();
    output.push(b'{');
    append_bound_field(&mut output, b"\"assumptions\":", parts.assumptions, false);
    append_bound_field(&mut output, b"\"boundary\":", parts.boundary, true);
    append_bound_field(&mut output, b"\"command\":", parts.command, true);
    append_bound_field(&mut output, b"\"eligibility\":", parts.eligibility, true);
    append_bound_field(&mut output, b"\"environment\":", parts.environment, true);
    append_bound_field(&mut output, b"\"execution_id\":", parts.execution_id, true);
    append_bound_field(&mut output, b"\"inputs\":", parts.inputs, true);
    append_bound_field(&mut output, b"\"observations\":", parts.observations, true);
    append_bound_field(&mut output, b"\"outcome\":", parts.outcome, true);
    append_bound_field(&mut output, b"\"output_root\":", parts.output_root, true);
    append_bound_field(&mut output, b"\"outputs\":", parts.outputs, true);
    append_bound_field(&mut output, b"\"plan\":", parts.plan, true);
    append_bound_field(&mut output, b"\"platform\":", parts.platform, true);
    append_bound_field(&mut output, b"\"policy\":", parts.policy, true);
    append_bound_field(&mut output, b"\"producer\":", parts.producer, true);
    append_bound_field(
        &mut output,
        b"\"product_version\":",
        parts.product_version,
        true,
    );
    append_bound_field(&mut output, b"\"runtime\":", parts.runtime, true);
    append_bound_field(&mut output, b"\"schema\":", parts.schema, true);
    append_bound_field(&mut output, b"\"streams\":", parts.streams, true);
    append_bound_field(
        &mut output,
        b"\"trusted_computing_base\":",
        parts.trusted_computing_base,
        true,
    );
    output.push(b'}');
    serde_json::from_slice::<serde_json::Value>(&output)
        .map_err(|_| ReceiptError::CanonicalEncoding)?;
    Ok(output)
}

fn append_bound_field(output: &mut Vec<u8>, name: &[u8], value: Vec<u8>, comma: bool) {
    if comma {
        output.push(b',');
    }
    output.extend_from_slice(name);
    output.extend(value);
}

/// Constructs one complete execution receipt through the translation boundary.
///
/// Keeping this boundary as a free function gives the source-refinement tool a
/// stable production entry point while preserving `ExecutionReceipt::new` as
/// the single implementation of construction semantics.
pub fn construct_execution_receipt(
    parts: ExecutionReceiptParts,
) -> Result<ExecutionReceipt, ReceiptError> {
    ExecutionReceipt::new(parts)
}

#[derive(Serialize)]
struct WireArtifact {
    mode: u16,
    role: &'static str,
    sha256: String,
    size: String,
}

impl From<&ArtifactIdentity> for WireArtifact {
    fn from(identity: &ArtifactIdentity) -> Self {
        Self {
            mode: identity.mode().get(),
            role: identity.role().as_str(),
            sha256: identity.digest().to_hex(),
            size: identity.size().to_string(),
        }
    }
}

#[derive(Serialize)]
struct WirePlan {
    id: String,
    normalized: WireArtifact,
    source: WireArtifact,
}

#[derive(Serialize)]
struct WirePolicy {
    identity: WireArtifact,
    model_version: &'static str,
}

#[derive(Serialize)]
struct WirePlatform {
    architecture: &'static str,
    cgroup_controllers: Vec<String>,
    kernel_release: String,
    landlock_abi: u32,
    operating_system: &'static str,
    seccomp_features: Vec<String>,
}

#[derive(Serialize)]
struct WireRuntime {
    launcher: WireArtifact,
    runtime: WireArtifact,
}

#[derive(Serialize)]
struct WireCommand {
    arguments_sha256: String,
    executable: WireArtifact,
    loader: Option<WireArtifact>,
    working_directory: WireArtifact,
}

#[derive(Serialize)]
struct WireCgroupIdentity {
    inode: String,
    mount_id: String,
}

#[derive(Serialize)]
struct WireBoundary {
    cgroup: WireCgroupIdentity,
    execution_id: String,
    policy_sha256: String,
    state: &'static str,
}

#[derive(Serialize)]
struct WireObservations {
    clock: &'static str,
    finished_ns: String,
    started_ns: String,
}

#[derive(Serialize)]
struct WireStream {
    artifact: WireArtifact,
    capture: &'static str,
}

#[derive(Serialize)]
struct WireStreams {
    stderr: WireStream,
    stdout: WireStream,
}

#[derive(Serialize)]
#[serde(tag = "kind")]
enum WireOutcome {
    #[serde(rename = "exited")]
    Exited { code: i32 },
    #[serde(rename = "signaled")]
    Signaled { signal: u32 },
    #[serde(rename = "timed-out")]
    TimedOut,
    #[serde(rename = "denied")]
    Denied,
    #[serde(rename = "launcher-failed")]
    LauncherFailed,
    #[serde(rename = "incomplete")]
    Incomplete,
}

impl From<ExecutionOutcome> for WireOutcome {
    fn from(outcome: ExecutionOutcome) -> Self {
        match outcome {
            ExecutionOutcome::Exited { code } => Self::Exited { code },
            ExecutionOutcome::Signaled { signal } => Self::Signaled {
                signal: signal.get(),
            },
            ExecutionOutcome::TimedOut => Self::TimedOut,
            ExecutionOutcome::Denied => Self::Denied,
            ExecutionOutcome::LauncherFailed => Self::LauncherFailed,
            ExecutionOutcome::Incomplete => Self::Incomplete,
        }
    }
}

#[derive(Serialize)]
struct WireEligibility {
    reasons: Vec<&'static str>,
    status: &'static str,
}

impl From<&ReceiptEligibility> for WireEligibility {
    fn from(eligibility: &ReceiptEligibility) -> Self {
        match eligibility {
            ReceiptEligibility::Reusable => Self {
                reasons: Vec::new(),
                status: "reusable",
            },
            ReceiptEligibility::NonReusable(reasons) => Self {
                reasons: reasons
                    .as_slice()
                    .iter()
                    .copied()
                    .map(non_reusable_reason_wire_name)
                    .collect(),
                status: "non-reusable",
            },
        }
    }
}

fn non_reusable_reason_wire_name(reason: NonReusableReason) -> &'static str {
    match reason {
        NonReusableReason::BoundaryIncomplete => "boundary-incomplete",
        NonReusableReason::ExitCodeNonzero => "exit-code-nonzero",
        NonReusableReason::ProcessSignaled => "process-signaled",
        NonReusableReason::TimedOut => "timed-out",
        NonReusableReason::Denied => "denied",
        NonReusableReason::LauncherFailed => "launcher-failed",
        NonReusableReason::ExecutionIncomplete => "execution-incomplete",
        NonReusableReason::StandardOutputTruncated => "stdout-truncated",
        NonReusableReason::StandardErrorTruncated => "stderr-truncated",
        NonReusableReason::ReceiptMalformed => "receipt-malformed",
        NonReusableReason::MemoryHigh => "memory-high",
        NonReusableReason::MemoryMax => "memory-max",
        NonReusableReason::MemoryOom => "memory-oom",
        NonReusableReason::MemoryOomKill => "memory-oom-kill",
        NonReusableReason::MemoryOomGroupKill => "memory-oom-group-kill",
        NonReusableReason::SwapMax => "swap-max",
        NonReusableReason::SwapFail => "swap-fail",
    }
}

#[derive(Serialize)]
struct WireTrustedComputingBaseEntry {
    identity: String,
    role: String,
}

#[derive(Serialize)]
struct WireExecutionReceipt {
    assumptions: Vec<String>,
    boundary: WireBoundary,
    command: WireCommand,
    eligibility: WireEligibility,
    environment: Vec<String>,
    execution_id: String,
    inputs: Vec<WireArtifact>,
    observations: WireObservations,
    outcome: WireOutcome,
    output_root: WireArtifact,
    outputs: Vec<WireArtifact>,
    plan: WirePlan,
    platform: WirePlatform,
    policy: WirePolicy,
    producer: WireArtifact,
    product_version: &'static str,
    runtime: WireRuntime,
    schema: &'static str,
    streams: WireStreams,
    trusted_computing_base: Vec<WireTrustedComputingBaseEntry>,
}

impl From<&ExecutionReceipt> for WireExecutionReceipt {
    fn from(receipt: &ExecutionReceipt) -> Self {
        let parts = &receipt.parts;
        Self {
            assumptions: receipt.assumptions.clone(),
            boundary: WireBoundary {
                cgroup: WireCgroupIdentity {
                    inode: parts.boundary.cgroup.inode.to_string(),
                    mount_id: parts.boundary.cgroup.mount_id.to_string(),
                },
                execution_id: parts.boundary.execution_id.to_text(),
                policy_sha256: parts.boundary.policy_sha256.to_hex(),
                state: boundary_wire_name(parts.boundary.state),
            },
            command: WireCommand {
                arguments_sha256: parts.command.arguments_sha256.to_hex(),
                executable: WireArtifact::from(&parts.command.executable),
                loader: parts.command.loader.as_ref().map(WireArtifact::from),
                working_directory: WireArtifact::from(&parts.command.working_directory),
            },
            eligibility: WireEligibility::from(&receipt.eligibility),
            environment: receipt.environment.clone(),
            execution_id: parts.execution_id.to_text(),
            inputs: parts.inputs.iter().map(WireArtifact::from).collect(),
            observations: WireObservations {
                clock: "linux-monotonic",
                finished_ns: parts.observations.finished_ns.to_string(),
                started_ns: parts.observations.started_ns.to_string(),
            },
            outcome: WireOutcome::from(parts.outcome),
            output_root: WireArtifact::from(&parts.output_root),
            outputs: parts.outputs.iter().map(WireArtifact::from).collect(),
            plan: WirePlan {
                id: parts.plan.id.as_str().to_owned(),
                normalized: WireArtifact::from(&parts.plan.normalized),
                source: WireArtifact::from(&parts.plan.source),
            },
            platform: WirePlatform {
                architecture: parts.platform.architecture.as_str(),
                cgroup_controllers: parts.platform.cgroup_controllers.clone(),
                kernel_release: parts.platform.kernel_release.clone(),
                landlock_abi: parts.platform.landlock_abi,
                operating_system: "linux",
                seccomp_features: parts.platform.seccomp_features.clone(),
            },
            policy: WirePolicy {
                identity: WireArtifact::from(&parts.policy.identity),
                model_version: POLICY_MODEL_VERSION,
            },
            producer: WireArtifact::from(&parts.producer),
            product_version: env!("CARGO_PKG_VERSION"),
            runtime: WireRuntime {
                launcher: WireArtifact::from(&parts.runtime.launcher),
                runtime: WireArtifact::from(&parts.runtime.runtime),
            },
            schema: EXECUTION_RECEIPT_SCHEMA,
            streams: WireStreams {
                stderr: WireStream {
                    artifact: WireArtifact::from(&parts.streams.stderr.artifact),
                    capture: stream_capture_wire_name(parts.streams.stderr.capture),
                },
                stdout: WireStream {
                    artifact: WireArtifact::from(&parts.streams.stdout.artifact),
                    capture: stream_capture_wire_name(parts.streams.stdout.capture),
                },
            },
            trusted_computing_base: parts
                .trusted_computing_base
                .iter()
                .map(|entry| WireTrustedComputingBaseEntry {
                    identity: entry.identity.clone(),
                    role: entry.role.as_str().to_owned(),
                })
                .collect(),
        }
    }
}

fn boundary_wire_name(state: BoundaryInstallation) -> &'static str {
    match state {
        BoundaryInstallation::Installed => "installed",
        BoundaryInstallation::Incomplete => "incomplete",
    }
}

fn stream_capture_wire_name(capture: StreamCapture) -> &'static str {
    match capture {
        StreamCapture::Complete => "complete",
        StreamCapture::Truncated => "truncated",
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
    /// A registered runtime assumption is absent.
    AssumptionMissing,
    /// Version 2 receipt resources were built from a legacy limit profile.
    ResourceProfileIncomplete,
    /// Installed version 2 cgroup controls were not the closed configured profile.
    ConfiguredResourcesInvalid,
    /// A required trusted-computing-base role is absent.
    TrustedComputingBaseRoleMissing,
    /// Canonical JSON encoding failed.
    CanonicalEncoding,
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
            Self::AssumptionMissing => "receipt.assumption.missing",
            Self::ResourceProfileIncomplete => "receipt.resources.incomplete",
            Self::ConfiguredResourcesInvalid => "receipt.resources.configured-invalid",
            Self::TrustedComputingBaseRoleMissing => "receipt.tcb.role.missing",
            Self::CanonicalEncoding => "receipt.canonical.encoding-failed",
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

fn require_tcb_roles(parts: &ExecutionReceiptParts) -> Result<(), ReceiptError> {
    const ALWAYS_REQUIRED: [TrustedComputingBaseRole; 12] = [
        TrustedComputingBaseRole::HostHardwareFirmware,
        TrustedComputingBaseRole::LinuxKernel,
        TrustedComputingBaseRole::Landlock,
        TrustedComputingBaseRole::Seccomp,
        TrustedComputingBaseRole::CgroupV2,
        TrustedComputingBaseRole::NoNewPrivileges,
        TrustedComputingBaseRole::Filesystem,
        TrustedComputingBaseRole::RuntimeBinary,
        TrustedComputingBaseRole::LauncherBinary,
        TrustedComputingBaseRole::RustToolchain,
        TrustedComputingBaseRole::CryptographicDigest,
        TrustedComputingBaseRole::RuntimeExecutable,
    ];

    for role in ALWAYS_REQUIRED {
        require_tcb_role(&parts.trusted_computing_base, role)?;
    }
    if parts.command.loader.is_some() {
        require_tcb_role(
            &parts.trusted_computing_base,
            TrustedComputingBaseRole::RuntimeLoaderExecutable,
        )?;
    }
    if parts
        .inputs
        .iter()
        .any(|identity| identity.role() == ArtifactRole::RuntimeLibrary)
    {
        require_tcb_role(
            &parts.trusted_computing_base,
            TrustedComputingBaseRole::RuntimeLibrary,
        )?;
    }
    Ok(())
}

fn require_tcb_role(
    entries: &[TrustedComputingBaseEntry],
    required: TrustedComputingBaseRole,
) -> Result<(), ReceiptError> {
    if entries.iter().any(|entry| entry.role == required) {
        Ok(())
    } else {
        Err(ReceiptError::TrustedComputingBaseRoleMissing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileMode, OutputByteLimit, WallTimeLimit};

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
            resources: None,
            outputs: vec![artifact(ArtifactRole::OutputArtifact, 19)],
            producer: runtime,
            assumptions: REQUIRED_RUNTIME_ASSUMPTIONS
                .into_iter()
                .rev()
                .map(str::to_owned)
                .collect(),
            trusted_computing_base: [
                TrustedComputingBaseRole::HostHardwareFirmware,
                TrustedComputingBaseRole::LinuxKernel,
                TrustedComputingBaseRole::Landlock,
                TrustedComputingBaseRole::Seccomp,
                TrustedComputingBaseRole::CgroupV2,
                TrustedComputingBaseRole::NoNewPrivileges,
                TrustedComputingBaseRole::Filesystem,
                TrustedComputingBaseRole::RuntimeBinary,
                TrustedComputingBaseRole::LauncherBinary,
                TrustedComputingBaseRole::RustToolchain,
                TrustedComputingBaseRole::CryptographicDigest,
                TrustedComputingBaseRole::RuntimeExecutable,
                TrustedComputingBaseRole::RuntimeLoaderExecutable,
                TrustedComputingBaseRole::RuntimeLibrary,
            ]
            .into_iter()
            .map(|role| {
                TrustedComputingBaseEntry::new(role, format!("{}:fixture", role.as_str()))
                    .expect("fixture TCB entry is valid")
            })
            .collect(),
        }
    }

    #[test]
    fn constructor_derives_reuse_and_canonicalizes_sets() {
        let receipt = ExecutionReceipt::new(parts()).expect("fixture receipt is valid");
        assert_eq!(receipt.eligibility(), &ReceiptEligibility::Reusable);
        assert_eq!(receipt.environment, ["LANG", "PATH"]);
        assert_eq!(receipt.assumptions, REQUIRED_RUNTIME_ASSUMPTIONS);
        assert_eq!(receipt.parts.inputs[0].role(), ArtifactRole::RuntimeLibrary);
    }

    #[test]
    fn version_two_resources_drive_receipt_eligibility() {
        let mut input = parts();
        input.resources = Some(
            ReceiptResources::new(
                ResourceLimits::new_v2(
                    ProcessLimit::new(2).expect("valid process limit"),
                    WallTimeLimit::from_milliseconds(1_000).expect("valid wall limit"),
                    OutputByteLimit::new(1_024),
                    OutputByteLimit::new(2_048),
                    MemoryByteLimit::new(65_536).expect("valid memory limit"),
                    SwapByteLimit::new(0).expect("valid swap limit"),
                ),
                32_768,
                0,
                ReceiptMemoryEvents::new(0, 1, 0, 0, 0, 0),
                ReceiptSwapEvents::new(0, 0),
            )
            .expect("complete v2 resources"),
        );
        let receipt = ExecutionReceipt::new(input).expect("v2 receipt is valid");
        let ReceiptEligibility::NonReusable(reasons) = receipt.eligibility() else {
            panic!("memory.high must force nonreuse");
        };
        assert_eq!(reasons.as_slice(), &[NonReusableReason::MemoryHigh]);
    }

    #[test]
    fn version_two_receipt_is_deterministic_cbor_with_closed_resource_object() {
        let mut input = parts();
        input.resources = Some(
            ReceiptResources::new(
                ResourceLimits::new_v2(
                    ProcessLimit::new(2).expect("valid process limit"),
                    WallTimeLimit::from_milliseconds(1_000).expect("valid wall limit"),
                    OutputByteLimit::new(1_024),
                    OutputByteLimit::new(2_048),
                    MemoryByteLimit::new(65_536).expect("valid memory limit"),
                    SwapByteLimit::new(0).expect("valid swap limit"),
                ),
                32_768,
                0,
                ReceiptMemoryEvents::new(0, 0, 0, 0, 0, 0),
                ReceiptSwapEvents::new(0, 0),
            )
            .expect("complete v2 resources"),
        );
        let receipt = ExecutionReceipt::new(input).expect("v2 receipt is valid");
        let bytes = receipt.canonical_bytes().expect("v2 receipt encodes");
        assert_ne!(bytes.first(), Some(&b'{'));
        let decoded = crate::wire_v2::decode(&bytes).expect("producer CBOR decodes strictly");
        assert_eq!(crate::wire_v2::encode(&decoded), Ok(bytes));
        let crate::wire_v2::Value::Map(fields) = decoded else {
            panic!("receipt must be a CBOR map");
        };
        assert_eq!(
            fields
                .iter()
                .find(|(key, _)| key == "schema")
                .map(|(_, value)| value),
            Some(&crate::wire_v2::Value::Text(
                "proofbound-runtime-execution-receipt/2".to_owned()
            ))
        );
        assert!(fields.iter().any(|(key, _)| key == "resources"));
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
    fn canonical_bytes_are_stable_sorted_and_schema_complete() {
        let receipt = ExecutionReceipt::new(parts()).expect("fixture receipt is valid");
        let first = receipt.canonical_bytes().expect("fixture encodes");
        let second = receipt.canonical_bytes().expect("fixture re-encodes");
        let reference = serde_json::to_vec(
            &serde_json::to_value(WireExecutionReceipt::from(&receipt))
                .expect("wire projection serializes"),
        )
        .expect("canonical reference serializes");
        assert_eq!(first, second);
        assert_eq!(first, reference);
        assert!(!first.ends_with(b"\n"));

        let text = String::from_utf8(first.clone()).expect("JSON is UTF-8");
        assert!(text.starts_with("{\"assumptions\":"));
        assert!(text.ends_with("}]}") || text.ends_with("}]}"));
        assert!(text.contains("\"execution_id\":\"00112233-4455-4677-8899-aabbccddeeff\""));
        assert!(text.contains("\"outcome\":{\"code\":0,\"kind\":\"exited\"}"));
        assert!(text.contains("\"eligibility\":{\"reasons\":[],\"status\":\"reusable\"}"));
        assert!(text.contains("\"size\":\"19\""));

        let value: serde_json::Value =
            serde_json::from_slice(&first).expect("canonical bytes decode");
        assert_eq!(
            serde_json::to_vec(&value).expect("decoded value re-encodes"),
            first
        );
        let object = value.as_object().expect("receipt is an object");
        assert_eq!(object.len(), 20);
        assert_eq!(object["schema"], EXECUTION_RECEIPT_SCHEMA);
        assert_eq!(object["policy"]["model_version"], POLICY_MODEL_VERSION);
    }

    #[test]
    fn execution_id_rejects_non_v4_values() {
        assert_eq!(
            ExecutionId::from_bytes([0; 16]),
            Err(ReceiptError::InvalidExecutionId)
        );
    }

    #[test]
    fn constructor_rejects_assumption_and_tcb_role_loss() {
        let mut missing_assumption = parts();
        missing_assumption
            .assumptions
            .retain(|value| value != "PBR-HOST-AX-002");
        assert_eq!(
            ExecutionReceipt::new(missing_assumption),
            Err(ReceiptError::AssumptionMissing)
        );

        let mut missing_tcb_role = parts();
        missing_tcb_role
            .trusted_computing_base
            .retain(|entry| entry.role != TrustedComputingBaseRole::Seccomp);
        assert_eq!(
            ExecutionReceipt::new(missing_tcb_role),
            Err(ReceiptError::TrustedComputingBaseRoleMissing)
        );
    }
}
