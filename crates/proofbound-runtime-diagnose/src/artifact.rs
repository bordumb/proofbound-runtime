//! Constructs the closed diagnostic receipt.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use proofbound_runtime_core::{
    Architecture, DiagnosticCompletion, ExecutionId, FileMode, ObservationResolution, Sha256Digest,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::canonical::{BoundedCanonicalJson, CanonicalWriteError};

/// Identifies the diagnostic receipt schema.
pub const DIAGNOSTIC_RECEIPT_SCHEMA: &str = "proofbound-runtime-diagnostic-receipt/1";

/// Identifies one artifact role in a diagnostic receipt.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DiagnosticArtifactRole {
    /// Contains the seed execution plan.
    ExecutionPlan,
    /// Contains the command executable.
    RuntimeExecutable,
    /// Contains the production Runtime binary.
    RuntimeBinary,
    /// Contains the production launcher binary.
    LauncherBinary,
    /// Contains the separate diagnostic observer.
    DiagnosticObserver,
}

impl DiagnosticArtifactRole {
    /// Returns the stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionPlan => "execution-plan",
            Self::RuntimeExecutable => "runtime-executable",
            Self::RuntimeBinary => "runtime-binary",
            Self::LauncherBinary => "launcher-binary",
            Self::DiagnosticObserver => "diagnostic-observer",
        }
    }
}

/// Contains one exact diagnostic artifact identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DiagnosticArtifactIdentity {
    role: DiagnosticArtifactRole,
    digest: Sha256Digest,
    size_bytes: u64,
    mode: FileMode,
}

impl DiagnosticArtifactIdentity {
    /// Creates an identity for a nonempty artifact.
    pub fn new(
        role: DiagnosticArtifactRole,
        digest: Sha256Digest,
        size_bytes: u64,
        mode: FileMode,
    ) -> Result<Self, DiagnosticArtifactError> {
        if size_bytes == 0 {
            return Err(DiagnosticArtifactError::ArtifactEmpty);
        }
        Ok(Self {
            role,
            digest,
            size_bytes,
            mode,
        })
    }

    /// Returns the artifact role.
    #[must_use]
    pub const fn role(&self) -> DiagnosticArtifactRole {
        self.role
    }

    /// Returns the SHA-256 identity.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    fn to_value(&self) -> Value {
        json!({
            "mode": format!("{:04o}", self.mode.get()),
            "role": self.role.as_str(),
            "sha256": format!("sha256:{}", self.digest.to_hex()),
            "size_bytes": self.size_bytes,
        })
    }
}

/// Contains the supported Linux platform identity for one diagnostic run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticPlatform {
    architecture: Architecture,
    kernel_release: String,
    landlock_abi: u32,
}

impl DiagnosticPlatform {
    /// Creates a supported diagnostic platform identity.
    pub fn new(
        architecture: Architecture,
        kernel_release: impl Into<String>,
        landlock_abi: u32,
    ) -> Result<Self, DiagnosticArtifactError> {
        let kernel_release = kernel_release.into();
        if kernel_release.is_empty()
            || kernel_release.len() > 256
            || !(3..=11).contains(&landlock_abi)
        {
            return Err(DiagnosticArtifactError::PlatformInvalid);
        }
        Ok(Self {
            architecture,
            kernel_release,
            landlock_abi,
        })
    }

    fn to_value(&self) -> Value {
        json!({
            "architecture": self.architecture.as_str(),
            "kernel_release": self.kernel_release,
            "landlock_abi": self.landlock_abi,
            "operating_system": "linux",
        })
    }

    const fn architecture(&self) -> Architecture {
        self.architecture
    }
}

/// Fixes every collection and output bound for one diagnostic run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationBounds {
    /// Maximum total event count.
    pub event_count: u64,
    /// Maximum event count for one process.
    pub event_count_per_process: u64,
    /// Maximum diagnostic output bytes.
    pub output_bytes: u64,
    /// Maximum bytes in one retained path.
    pub path_bytes: u64,
    /// Maximum observed process count.
    pub process_count: u64,
    /// Maximum retained socket-address bytes.
    pub socket_address_bytes: u64,
    /// Maximum followed symlink count.
    pub symlink_hops: u64,
    /// Maximum bytes read from one tracee string.
    pub tracee_string_bytes: u64,
}

impl ObservationBounds {
    /// Validates every diagnostic bound.
    pub fn validate(self) -> Result<Self, DiagnosticArtifactError> {
        if !(1..=1_048_576).contains(&self.event_count)
            || !(1..=1_048_576).contains(&self.event_count_per_process)
            || !(1024..=67_108_864).contains(&self.output_bytes)
            || !(1..=1_048_576).contains(&self.path_bytes)
            || !(1..=4096).contains(&self.process_count)
            || !(1..=4096).contains(&self.socket_address_bytes)
            || !(1..=40).contains(&self.symlink_hops)
            || !(1..=1_048_576).contains(&self.tracee_string_bytes)
        {
            return Err(DiagnosticArtifactError::BoundInvalid);
        }
        Ok(self)
    }

    fn to_value(self) -> Value {
        json!({
            "event_count": self.event_count,
            "event_count_per_process": self.event_count_per_process,
            "output_bytes": self.output_bytes,
            "path_bytes": self.path_bytes,
            "process_count": self.process_count,
            "socket_address_bytes": self.socket_address_bytes,
            "symlink_hops": self.symlink_hops,
            "tracee_string_bytes": self.tracee_string_bytes,
        })
    }
}

/// Identifies one explicit observer coverage gap.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DiagnosticGap {
    /// The observed architecture is not supported.
    ArchitectureUnsupported,
    /// One traced child was lost.
    ChildLost,
    /// The total event bound was reached.
    EventLimit,
    /// One process event bound was reached.
    EventPerProcessLimit,
    /// One observed object identity changed.
    IdentityDrift,
    /// The observer failed after target release.
    ObserverFailed,
    /// The diagnostic output bound was reached.
    OutputLimit,
    /// A retained path reached its bound.
    PathLimit,
    /// The process count bound was reached.
    ProcessLimit,
    /// A socket address reached its bound.
    SocketAddressLimit,
    /// A tracee string reached its bound.
    StringLimit,
    /// Symlink resolution reached its bound.
    SymlinkLimit,
    /// The observer found an unsupported syscall form.
    SyscallUnsupported,
    /// The observer could not read required tracee memory.
    TraceeMemoryReadFailed,
    /// The observer found an unexpected trace stop.
    UnexpectedStop,
}

impl DiagnosticGap {
    /// Returns the stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArchitectureUnsupported => "architecture-unsupported",
            Self::ChildLost => "child-lost",
            Self::EventLimit => "event-limit",
            Self::EventPerProcessLimit => "event-per-process-limit",
            Self::IdentityDrift => "identity-drift",
            Self::ObserverFailed => "observer-failed",
            Self::OutputLimit => "output-limit",
            Self::PathLimit => "path-limit",
            Self::ProcessLimit => "process-limit",
            Self::SocketAddressLimit => "socket-address-limit",
            Self::StringLimit => "string-limit",
            Self::SymlinkLimit => "symlink-limit",
            Self::SyscallUnsupported => "syscall-unsupported",
            Self::TraceeMemoryReadFailed => "tracee-memory-read-failed",
            Self::UnexpectedStop => "unexpected-stop",
        }
    }
}

/// Identifies one observed syscall family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DiagnosticEventClass {
    /// A `bind` operation.
    Bind,
    /// A `clone` operation.
    Clone,
    /// A `connect` operation.
    Connect,
    /// A `creat` operation.
    Creat,
    /// An `execve` operation.
    Execve,
    /// An `execveat` operation.
    Execveat,
    /// A `fork` operation.
    Fork,
    /// A `newfstatat` operation.
    Newfstatat,
    /// An `open` operation.
    Open,
    /// An `openat` operation.
    Openat,
    /// An `openat2` operation.
    Openat2,
    /// A `readlink` operation.
    Readlink,
    /// A `readlinkat` operation.
    Readlinkat,
    /// A `sendto` operation.
    Sendto,
    /// A `socket` operation.
    Socket,
    /// A `statx` operation.
    Statx,
    /// A `vfork` operation.
    Vfork,
}

impl DiagnosticEventClass {
    /// Returns the stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Clone => "clone",
            Self::Connect => "connect",
            Self::Creat => "creat",
            Self::Execve => "execve",
            Self::Execveat => "execveat",
            Self::Fork => "fork",
            Self::Newfstatat => "newfstatat",
            Self::Open => "open",
            Self::Openat => "openat",
            Self::Openat2 => "openat2",
            Self::Readlink => "readlink",
            Self::Readlinkat => "readlinkat",
            Self::Sendto => "sendto",
            Self::Socket => "socket",
            Self::Statx => "statx",
            Self::Vfork => "vfork",
        }
    }

    const fn operand_kind(self) -> OperandKind {
        match self {
            Self::Bind | Self::Connect | Self::Sendto => OperandKind::SocketAddress,
            Self::Socket => OperandKind::SocketCreate,
            Self::Clone | Self::Fork | Self::Vfork => OperandKind::ProcessCreate,
            Self::Creat
            | Self::Execve
            | Self::Execveat
            | Self::Newfstatat
            | Self::Open
            | Self::Openat
            | Self::Openat2
            | Self::Readlink
            | Self::Readlinkat
            | Self::Statx => OperandKind::Path,
        }
    }

    /// Reports whether this event attempts network or local socket use.
    #[must_use]
    pub const fn is_network(self) -> bool {
        matches!(
            self,
            Self::Bind | Self::Connect | Self::Sendto | Self::Socket
        )
    }

    /// Reports whether the event selects an executable image.
    #[must_use]
    pub const fn is_execute(self) -> bool {
        matches!(self, Self::Execve | Self::Execveat)
    }

    /// Reports whether the event can produce a read candidate.
    #[must_use]
    pub const fn is_read_candidate(self) -> bool {
        matches!(
            self,
            Self::Newfstatat
                | Self::Open
                | Self::Openat
                | Self::Openat2
                | Self::Readlink
                | Self::Readlinkat
                | Self::Statx
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperandKind {
    Path,
    ProcessCreate,
    SocketAddress,
    SocketCreate,
}

/// Contains one observed filesystem object identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedObjectIdentity {
    device_major: u32,
    device_minor: u32,
    inode: u64,
    mode: u32,
    mount_id: u64,
}

impl ObservedObjectIdentity {
    /// Creates an observed object identity.
    pub fn new(
        device_major: u32,
        device_minor: u32,
        inode: u64,
        mode: u32,
        mount_id: u64,
    ) -> Result<Self, DiagnosticArtifactError> {
        if mode > 0o777_777 {
            return Err(DiagnosticArtifactError::EventInvalid);
        }
        Ok(Self {
            device_major,
            device_minor,
            inode,
            mode,
            mount_id,
        })
    }

    fn to_value(&self) -> Value {
        json!({
            "device_major": self.device_major,
            "device_minor": self.device_minor,
            "inode": self.inode,
            "mode": format!("{:06o}", self.mode),
            "mount_id": self.mount_id,
        })
    }
}

/// Identifies one retained socket-address family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SocketAddressFamily {
    Inet,
    Inet6,
    Netlink,
    Other,
    Unix,
}

impl SocketAddressFamily {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Inet => "inet",
            Self::Inet6 => "inet6",
            Self::Netlink => "netlink",
            Self::Other => "other",
            Self::Unix => "unix",
        }
    }
}

/// Contains bounded raw socket-address bytes without interpreting remote identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedSocketAddress {
    family: SocketAddressFamily,
    bytes: Vec<u8>,
}

impl ObservedSocketAddress {
    /// Creates one socket address. The receipt constructor applies its declared bound.
    pub fn new(
        family: SocketAddressFamily,
        bytes: Vec<u8>,
    ) -> Result<Self, DiagnosticArtifactError> {
        if bytes.len() > 4096 {
            return Err(DiagnosticArtifactError::SocketAddressInvalid);
        }
        Ok(Self { family, bytes })
    }

    fn to_value(&self) -> Value {
        json!({
            "bytes_hex": encode_hex(&self.bytes),
            "family": self.family.as_str(),
            "length_bytes": self.bytes.len(),
        })
    }
}

/// Contains the closed operands for one observed event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationOperands {
    /// Contains operands for one path operation.
    Path {
        /// Contains the requested output buffer size when applicable.
        buffer_bytes: Option<u64>,
        /// Contains the directory descriptor when applicable.
        directory_fd: Option<i32>,
        /// Contains open or lookup flags when applicable.
        flags: Option<u64>,
        /// Contains a stat mask when applicable.
        mask: Option<u64>,
        /// Contains creation mode bits when applicable.
        mode: Option<u64>,
        /// Contains the bounded supplied path when output policy permits it.
        path: Option<String>,
        /// Contains `openat2` resolution flags when applicable.
        resolve: Option<u64>,
        /// Contains the followed symlink count when resolution observed it.
        symlink_hops: Option<u64>,
    },
    /// Contains operands for one process-creation operation.
    ProcessCreate {
        /// Contains process-creation flags when applicable.
        flags: Option<u64>,
    },
    /// Contains operands for an operation on one existing socket.
    SocketAddress {
        /// Contains bounded address bytes when output policy permits them.
        address: Option<ObservedSocketAddress>,
        /// Contains the socket descriptor number.
        descriptor: u32,
        /// Contains the attempted payload size without payload bytes.
        payload_bytes: Option<u64>,
    },
    /// Contains operands for one socket-creation operation.
    SocketCreate {
        /// Contains the address-family number.
        domain: u32,
        /// Contains the protocol number.
        protocol: u32,
        /// Contains the socket-type number.
        socket_type: u32,
    },
}

impl ObservationOperands {
    const fn kind(&self) -> OperandKind {
        match self {
            Self::Path { .. } => OperandKind::Path,
            Self::ProcessCreate { .. } => OperandKind::ProcessCreate,
            Self::SocketAddress { .. } => OperandKind::SocketAddress,
            Self::SocketCreate { .. } => OperandKind::SocketCreate,
        }
    }

    /// Returns the retained path operand when this is a path event.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::Path { path, .. } => path.as_deref(),
            _ => None,
        }
    }

    /// Returns path open flags when this is a path event.
    #[must_use]
    pub const fn path_flags(&self) -> Option<u64> {
        match self {
            Self::Path { flags, .. } => *flags,
            _ => None,
        }
    }

    const fn retains_redacted_target(&self) -> bool {
        match self {
            Self::Path { path, .. } => path.is_some(),
            Self::SocketAddress { address, .. } => address.is_some(),
            Self::ProcessCreate { .. } | Self::SocketCreate { .. } => false,
        }
    }

    const fn has_complete_path_observation(&self) -> bool {
        matches!(
            self,
            Self::Path {
                path: Some(_),
                symlink_hops: Some(_),
                ..
            }
        )
    }

    fn validate_bounds(&self, bounds: ObservationBounds) -> Result<(), DiagnosticArtifactError> {
        match self {
            Self::Path {
                path, symlink_hops, ..
            } => {
                if path
                    .as_ref()
                    .is_some_and(|value| value.len() as u64 > bounds.path_bytes)
                {
                    return Err(DiagnosticArtifactError::PathBoundExceeded);
                }
                if path
                    .as_ref()
                    .is_some_and(|value| value.len() as u64 > bounds.tracee_string_bytes)
                {
                    return Err(DiagnosticArtifactError::TraceeStringBoundExceeded);
                }
                if symlink_hops.is_some_and(|value| value > bounds.symlink_hops) {
                    return Err(DiagnosticArtifactError::SymlinkBoundExceeded);
                }
            }
            Self::SocketAddress { address, .. } => {
                if address
                    .as_ref()
                    .is_some_and(|value| value.bytes.len() as u64 > bounds.socket_address_bytes)
                {
                    return Err(DiagnosticArtifactError::SocketAddressBoundExceeded);
                }
            }
            Self::ProcessCreate { .. } | Self::SocketCreate { .. } => {}
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        match self {
            Self::Path {
                buffer_bytes,
                directory_fd,
                flags,
                mask,
                mode,
                path,
                resolve,
                symlink_hops,
            } => json!({
                "buffer_bytes": buffer_bytes,
                "directory_fd": directory_fd,
                "flags": flags,
                "kind": "path",
                "mask": mask,
                "mode": mode,
                "path": path,
                "resolve": resolve,
                "symlink_hops": symlink_hops,
            }),
            Self::ProcessCreate { flags } => json!({
                "flags": flags,
                "kind": "process-create",
            }),
            Self::SocketAddress {
                address,
                descriptor,
                payload_bytes,
            } => json!({
                "address": address.as_ref().map(ObservedSocketAddress::to_value),
                "descriptor": descriptor,
                "kind": "socket-address",
                "payload_bytes": payload_bytes,
            }),
            Self::SocketCreate {
                domain,
                protocol,
                socket_type,
            } => json!({
                "domain": domain,
                "kind": "socket-create",
                "protocol": protocol,
                "socket_type": socket_type,
            }),
        }
    }
}

/// Contains either one nonnegative syscall result or one positive error number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationOutcome {
    /// The syscall returned a nonnegative result.
    Returned(u64),
    /// The syscall failed with a positive error number.
    Failed(u32),
}

impl ObservationOutcome {
    fn validate(self) -> Result<Self, DiagnosticArtifactError> {
        if matches!(self, Self::Failed(0)) {
            return Err(DiagnosticArtifactError::OutcomeInvalid);
        }
        Ok(self)
    }
}

/// Contains one validated bounded diagnostic event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticEvent {
    sequence: u64,
    process: u32,
    architecture: Architecture,
    class: DiagnosticEventClass,
    operands: ObservationOperands,
    outcome: ObservationOutcome,
    resolution: ObservationResolution,
    resolved_path: Option<String>,
    object_before: Option<ObservedObjectIdentity>,
    object_after: Option<ObservedObjectIdentity>,
}

impl DiagnosticEvent {
    /// Creates one event and validates its class, outcome, and resolution state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        process: u32,
        architecture: Architecture,
        class: DiagnosticEventClass,
        operands: ObservationOperands,
        outcome: ObservationOutcome,
        resolution: ObservationResolution,
        resolved_path: Option<String>,
        object_before: Option<ObservedObjectIdentity>,
        object_after: Option<ObservedObjectIdentity>,
    ) -> Result<Self, DiagnosticArtifactError> {
        if process == 0 || class.operand_kind() != operands.kind() {
            return Err(DiagnosticArtifactError::EventInvalid);
        }
        let outcome = outcome.validate()?;
        match resolution {
            ObservationResolution::KernelSelected => {
                if !matches!(outcome, ObservationOutcome::Returned(_))
                    || resolved_path.is_none()
                    || object_after.is_none()
                    || !operands.has_complete_path_observation()
                {
                    return Err(DiagnosticArtifactError::ResolutionInvalid);
                }
            }
            ObservationResolution::StableCandidate => {
                if !matches!(outcome, ObservationOutcome::Failed(_))
                    || resolved_path.is_none()
                    || object_before.is_none()
                    || object_before != object_after
                    || !operands.has_complete_path_observation()
                {
                    return Err(DiagnosticArtifactError::ResolutionInvalid);
                }
            }
            ObservationResolution::Unresolved => {
                if resolved_path.is_some() {
                    return Err(DiagnosticArtifactError::ResolutionInvalid);
                }
            }
            ObservationResolution::Redacted => {
                if resolved_path.is_some()
                    || object_before.is_some()
                    || object_after.is_some()
                    || operands.retains_redacted_target()
                {
                    return Err(DiagnosticArtifactError::ResolutionInvalid);
                }
            }
        }
        if resolved_path
            .as_ref()
            .is_some_and(|path| !is_normalized_absolute_path(path))
        {
            return Err(DiagnosticArtifactError::ResolutionInvalid);
        }
        Ok(Self {
            sequence,
            process,
            architecture,
            class,
            operands,
            outcome,
            resolution,
            resolved_path,
            object_before,
            object_after,
        })
    }

    /// Returns the event sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the observed process identifier.
    #[must_use]
    pub const fn process(&self) -> u32 {
        self.process
    }

    /// Returns the event class.
    #[must_use]
    pub const fn class(&self) -> DiagnosticEventClass {
        self.class
    }

    /// Returns the event operands.
    #[must_use]
    pub const fn operands(&self) -> &ObservationOperands {
        &self.operands
    }

    /// Returns the syscall outcome.
    #[must_use]
    pub const fn outcome(&self) -> ObservationOutcome {
        self.outcome
    }

    /// Returns the resolution state.
    #[must_use]
    pub const fn resolution(&self) -> ObservationResolution {
        self.resolution
    }

    /// Returns the resolved path when the resolution state permits one.
    #[must_use]
    pub fn resolved_path(&self) -> Option<&str> {
        self.resolved_path.as_deref()
    }

    fn validate_bounds(&self, bounds: ObservationBounds) -> Result<(), DiagnosticArtifactError> {
        self.operands.validate_bounds(bounds)?;
        if self
            .resolved_path
            .as_ref()
            .is_some_and(|value| value.len() as u64 > bounds.path_bytes)
        {
            return Err(DiagnosticArtifactError::PathBoundExceeded);
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        let (result, error) = match self.outcome {
            ObservationOutcome::Returned(value) => (Some(value), None),
            ObservationOutcome::Failed(value) => (None, Some(value)),
        };
        json!({
            "architecture": self.architecture.as_str(),
            "class": self.class.as_str(),
            "error": error,
            "object_after": self.object_after.as_ref().map(ObservedObjectIdentity::to_value),
            "object_before": self.object_before.as_ref().map(ObservedObjectIdentity::to_value),
            "operands": self.operands.to_value(),
            "process": self.process,
            "resolution": self.resolution.as_str(),
            "resolved_path": self.resolved_path,
            "result": result,
            "sequence": self.sequence,
        })
    }
}

/// Identifies one trusted diagnostic role.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DiagnosticTcbRole {
    /// Trusts the separate observer implementation.
    DiagnosticObserver,
    /// Trusts filesystem behavior used by the diagnostic path.
    Filesystem,
    /// Trusts the host hardware.
    Hardware,
    /// Trusts the identified Linux kernel.
    LinuxKernel,
    /// Trusts the production launcher boundary implementation.
    RuntimeLauncher,
    /// Trusts the diagnostic supervisor implementation.
    RuntimeSupervisor,
}

impl DiagnosticTcbRole {
    const ALL: [Self; 6] = [
        Self::DiagnosticObserver,
        Self::Filesystem,
        Self::Hardware,
        Self::LinuxKernel,
        Self::RuntimeLauncher,
        Self::RuntimeSupervisor,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::DiagnosticObserver => "diagnostic-observer",
            Self::Filesystem => "filesystem",
            Self::Hardware => "hardware",
            Self::LinuxKernel => "linux-kernel",
            Self::RuntimeLauncher => "runtime-launcher",
            Self::RuntimeSupervisor => "runtime-supervisor",
        }
    }
}

/// Contains one identified trusted diagnostic role.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DiagnosticTcbEntry {
    role: DiagnosticTcbRole,
    identity: String,
}

impl DiagnosticTcbEntry {
    /// Creates a trusted-role entry with bounded nonempty identity text.
    pub fn new(
        role: DiagnosticTcbRole,
        identity: impl Into<String>,
    ) -> Result<Self, DiagnosticArtifactError> {
        let identity = identity.into();
        if identity.is_empty() || identity.len() > 512 {
            return Err(DiagnosticArtifactError::TrustedRoleInvalid);
        }
        Ok(Self { role, identity })
    }

    fn to_value(&self) -> Value {
        json!({"identity": self.identity, "role": self.role.as_str()})
    }
}

/// Contains all typed inputs to one diagnostic receipt.
pub struct DiagnosticReceiptParts {
    /// Identifies the observed execution.
    pub execution_id: ExecutionId,
    /// Identifies the diagnostic seed plan.
    pub seed_plan: DiagnosticArtifactIdentity,
    /// Identifies the observed executable.
    pub target: DiagnosticArtifactIdentity,
    /// Identifies the Runtime binary.
    pub runtime: DiagnosticArtifactIdentity,
    /// Identifies the Linux launcher binary.
    pub launcher: DiagnosticArtifactIdentity,
    /// Identifies the separate diagnostic observer.
    pub observer: DiagnosticArtifactIdentity,
    /// Identifies the observed Linux platform.
    pub platform: DiagnosticPlatform,
    /// Contains the exact observed command arguments.
    pub arguments: Vec<String>,
    /// Contains registered environment names without their values.
    pub environment_names: Vec<String>,
    /// Declares every observation bound.
    pub bounds: ObservationBounds,
    /// Contains events in observation order.
    pub events: Vec<DiagnosticEvent>,
    /// States whether observation completed within every bound.
    pub completion: DiagnosticCompletion,
    /// Contains explicit coverage gaps.
    pub gaps: Vec<DiagnosticGap>,
    /// Identifies every trusted diagnostic role.
    pub trusted_computing_base: Vec<DiagnosticTcbEntry>,
    /// Contains registered diagnostic assumptions.
    pub assumptions: Vec<String>,
}

/// Contains canonical bytes for one non-reusable diagnostic receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticReceipt {
    bytes: Vec<u8>,
    commitment: Sha256Digest,
    seed_plan_digest: Sha256Digest,
    arguments: Vec<String>,
    environment_names: Vec<String>,
    events: Vec<DiagnosticEvent>,
    gaps: Vec<DiagnosticGap>,
    output_bound: u64,
}

impl DiagnosticReceipt {
    /// Constructs and canonically encodes one diagnostic receipt.
    pub fn construct(mut parts: DiagnosticReceiptParts) -> Result<Self, DiagnosticArtifactError> {
        require_role(&parts.seed_plan, DiagnosticArtifactRole::ExecutionPlan)?;
        require_role(&parts.target, DiagnosticArtifactRole::RuntimeExecutable)?;
        require_role(&parts.runtime, DiagnosticArtifactRole::RuntimeBinary)?;
        require_role(&parts.launcher, DiagnosticArtifactRole::LauncherBinary)?;
        require_role(&parts.observer, DiagnosticArtifactRole::DiagnosticObserver)?;
        let bounds = parts.bounds.validate()?;
        validate_arguments(&parts.arguments)?;
        parts.environment_names = canonical_environment_names(parts.environment_names)?;
        parts.gaps.sort_unstable_by_key(|gap| gap.as_str());
        parts.gaps.dedup();
        validate_events(
            &parts.events,
            bounds,
            parts.platform.architecture(),
            &parts.gaps,
        )?;
        if parts.gaps.len() > 64
            || matches!(parts.completion, DiagnosticCompletion::Complete) != parts.gaps.is_empty()
        {
            return Err(DiagnosticArtifactError::CompletionInvalid);
        }
        parts.trusted_computing_base.sort();
        validate_tcb(&parts.trusted_computing_base)?;
        parts.assumptions = canonical_nonempty_text_set(parts.assumptions, 64, 256)?;

        let seed_plan_digest = parts.seed_plan.digest();
        let bytes = encode_receipt(&parts, bounds)?;
        let commitment = sha256(&bytes);
        Ok(Self {
            bytes,
            commitment,
            seed_plan_digest,
            arguments: parts.arguments,
            environment_names: parts.environment_names,
            events: parts.events,
            gaps: parts.gaps,
            output_bound: bounds.output_bytes,
        })
    }

    /// Returns the canonical JSON bytes without a trailing newline.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the SHA-256 commitment to the exact canonical bytes.
    #[must_use]
    pub const fn commitment(&self) -> Sha256Digest {
        self.commitment
    }

    /// Returns the seed-plan digest.
    #[must_use]
    pub const fn seed_plan_digest(&self) -> Sha256Digest {
        self.seed_plan_digest
    }

    /// Returns the exact command arguments for the observed path.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// Returns the sorted registered environment names.
    #[must_use]
    pub fn environment_names(&self) -> &[String] {
        &self.environment_names
    }

    /// Returns the ordered diagnostic events.
    #[must_use]
    pub fn events(&self) -> &[DiagnosticEvent] {
        &self.events
    }

    /// Returns the sorted coverage gaps.
    #[must_use]
    pub fn gaps(&self) -> &[DiagnosticGap] {
        &self.gaps
    }

    /// Returns the maximum canonical diagnostic artifact size in bytes.
    #[must_use]
    pub const fn output_bound(&self) -> u64 {
        self.output_bound
    }
}

fn encode_receipt(
    parts: &DiagnosticReceiptParts,
    bounds: ObservationBounds,
) -> Result<Vec<u8>, DiagnosticArtifactError> {
    let mut output = BoundedCanonicalJson::new(bounds.output_bytes).map_err(map_write_error)?;
    output.raw(b"{\"arguments\":").map_err(map_write_error)?;
    output.value(&parts.arguments).map_err(map_write_error)?;
    output.raw(b",\"assumptions\":").map_err(map_write_error)?;
    output.value(&parts.assumptions).map_err(map_write_error)?;
    output.raw(b",\"bounds\":").map_err(map_write_error)?;
    output.value(&bounds.to_value()).map_err(map_write_error)?;
    output.raw(b",\"completion\":").map_err(map_write_error)?;
    output
        .value(parts.completion.as_str())
        .map_err(map_write_error)?;
    output
        .raw(b",\"environment_names\":")
        .map_err(map_write_error)?;
    output
        .value(&parts.environment_names)
        .map_err(map_write_error)?;
    output.raw(b",\"events\":").map_err(map_write_error)?;
    output
        .sequence(parts.events.iter().map(DiagnosticEvent::to_value))
        .map_err(map_write_error)?;
    output.raw(b",\"execution_id\":").map_err(map_write_error)?;
    output
        .value(&parts.execution_id.to_text())
        .map_err(map_write_error)?;
    output
        .raw(b",\"execution_profile\":\"diagnostic\",\"gaps\":")
        .map_err(map_write_error)?;
    output
        .sequence(parts.gaps.iter().map(|gap| gap.as_str()))
        .map_err(map_write_error)?;
    output.raw(b",\"launcher\":").map_err(map_write_error)?;
    output
        .value(&parts.launcher.to_value())
        .map_err(map_write_error)?;
    output
        .raw(b",\"mechanism\":\"linux-ptrace-syscall-v1\",\"observer\":")
        .map_err(map_write_error)?;
    output
        .value(&parts.observer.to_value())
        .map_err(map_write_error)?;
    output.raw(b",\"platform\":").map_err(map_write_error)?;
    output
        .value(&parts.platform.to_value())
        .map_err(map_write_error)?;
    output
        .raw(b",\"reusable\":false,\"runtime\":")
        .map_err(map_write_error)?;
    output
        .value(&parts.runtime.to_value())
        .map_err(map_write_error)?;
    output
        .raw(b",\"safe_policy\":false,\"schema\":")
        .map_err(map_write_error)?;
    output
        .value(DIAGNOSTIC_RECEIPT_SCHEMA)
        .map_err(map_write_error)?;
    output.raw(b",\"seed_plan\":").map_err(map_write_error)?;
    output
        .value(&parts.seed_plan.to_value())
        .map_err(map_write_error)?;
    output.raw(b",\"target\":").map_err(map_write_error)?;
    output
        .value(&parts.target.to_value())
        .map_err(map_write_error)?;
    output
        .raw(b",\"trusted_computing_base\":")
        .map_err(map_write_error)?;
    output
        .sequence(
            parts
                .trusted_computing_base
                .iter()
                .map(DiagnosticTcbEntry::to_value),
        )
        .map_err(map_write_error)?;
    output.raw(b"}").map_err(map_write_error)?;
    Ok(output.finish())
}

fn map_write_error(error: CanonicalWriteError) -> DiagnosticArtifactError {
    match error {
        CanonicalWriteError::BoundExceeded => DiagnosticArtifactError::OutputBoundExceeded,
        CanonicalWriteError::EncodingFailed => DiagnosticArtifactError::CanonicalEncodingFailed,
    }
}

/// Identifies invalid diagnostic artifact construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticArtifactError {
    /// One required artifact identity is empty.
    ArtifactEmpty,
    /// One artifact has the wrong closed role.
    ArtifactRoleInvalid,
    /// The platform identity is invalid.
    PlatformInvalid,
    /// One observation bound is invalid.
    BoundInvalid,
    /// One command argument is invalid.
    ArgumentInvalid,
    /// One environment name is invalid.
    EnvironmentNameInvalid,
    /// One diagnostic event is internally inconsistent.
    EventInvalid,
    /// Diagnostic event order is invalid.
    EventOrderInvalid,
    /// The event count exceeds its bound.
    EventBoundExceeded,
    /// The observed process count exceeds its bound.
    ProcessBoundExceeded,
    /// One observed path exceeds its bound.
    PathBoundExceeded,
    /// One resolution exceeds the symlink-hop bound.
    SymlinkBoundExceeded,
    /// One retained tracee string exceeds its byte bound.
    TraceeStringBoundExceeded,
    /// One socket address is invalid.
    SocketAddressInvalid,
    /// One socket address exceeds its bound.
    SocketAddressBoundExceeded,
    /// One event outcome is invalid.
    OutcomeInvalid,
    /// One path resolution result is inconsistent.
    ResolutionInvalid,
    /// Completion and coverage gaps are inconsistent.
    CompletionInvalid,
    /// One trusted-computing-base role is invalid.
    TrustedRoleInvalid,
    /// One registered assumption is invalid.
    AssumptionInvalid,
    /// Canonical output exceeds the declared byte bound.
    OutputBoundExceeded,
    /// Canonical JSON encoding failed.
    CanonicalEncodingFailed,
}

impl DiagnosticArtifactError {
    /// Returns the stable machine error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ArtifactEmpty => "diagnostic.artifact.empty",
            Self::ArtifactRoleInvalid => "diagnostic.artifact.role-invalid",
            Self::PlatformInvalid => "diagnostic.platform.invalid",
            Self::BoundInvalid => "diagnostic.bound.invalid",
            Self::ArgumentInvalid => "diagnostic.argument.invalid",
            Self::EnvironmentNameInvalid => "diagnostic.environment-name.invalid",
            Self::EventInvalid => "diagnostic.event.invalid",
            Self::EventOrderInvalid => "diagnostic.event.order-invalid",
            Self::EventBoundExceeded => "diagnostic.event.bound-exceeded",
            Self::ProcessBoundExceeded => "diagnostic.process.bound-exceeded",
            Self::PathBoundExceeded => "diagnostic.path.bound-exceeded",
            Self::SymlinkBoundExceeded => "diagnostic.symlink.bound-exceeded",
            Self::TraceeStringBoundExceeded => "diagnostic.tracee-string.bound-exceeded",
            Self::SocketAddressInvalid => "diagnostic.socket-address.invalid",
            Self::SocketAddressBoundExceeded => "diagnostic.socket-address.bound-exceeded",
            Self::OutcomeInvalid => "diagnostic.outcome.invalid",
            Self::ResolutionInvalid => "diagnostic.resolution.invalid",
            Self::CompletionInvalid => "diagnostic.completion.invalid",
            Self::TrustedRoleInvalid => "diagnostic.trusted-role.invalid",
            Self::AssumptionInvalid => "diagnostic.assumption.invalid",
            Self::OutputBoundExceeded => "diagnostic.output.bound-exceeded",
            Self::CanonicalEncodingFailed => "diagnostic.canonical-json.failed",
        }
    }
}

impl fmt::Display for DiagnosticArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for DiagnosticArtifactError {}

fn require_role(
    artifact: &DiagnosticArtifactIdentity,
    expected: DiagnosticArtifactRole,
) -> Result<(), DiagnosticArtifactError> {
    if artifact.role() != expected {
        return Err(DiagnosticArtifactError::ArtifactRoleInvalid);
    }
    Ok(())
}

fn validate_arguments(arguments: &[String]) -> Result<(), DiagnosticArtifactError> {
    if arguments.len() > 256
        || arguments
            .iter()
            .any(|value| value.len() > 65_536 || value.as_bytes().contains(&0))
    {
        return Err(DiagnosticArtifactError::ArgumentInvalid);
    }
    Ok(())
}

fn canonical_environment_names(
    values: Vec<String>,
) -> Result<Vec<String>, DiagnosticArtifactError> {
    let mut output = BTreeSet::new();
    for value in values {
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 256
            || !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
            || !bytes[1..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            return Err(DiagnosticArtifactError::EnvironmentNameInvalid);
        }
        output.insert(value);
    }
    if output.len() > 256 {
        return Err(DiagnosticArtifactError::EnvironmentNameInvalid);
    }
    Ok(output.into_iter().collect())
}

fn validate_events(
    events: &[DiagnosticEvent],
    bounds: ObservationBounds,
    architecture: Architecture,
    gaps: &[DiagnosticGap],
) -> Result<(), DiagnosticArtifactError> {
    if events.len() as u64 > bounds.event_count {
        return Err(DiagnosticArtifactError::EventBoundExceeded);
    }
    let mut previous = None;
    let mut processes = BTreeMap::<u32, u64>::new();
    for event in events {
        if event.architecture != architecture {
            return Err(DiagnosticArtifactError::EventInvalid);
        }
        if previous.is_some_and(|value| event.sequence() <= value) {
            return Err(DiagnosticArtifactError::EventOrderInvalid);
        }
        previous = Some(event.sequence());
        event.validate_bounds(bounds)?;
        let count = processes.entry(event.process()).or_default();
        *count += 1;
        if *count > bounds.event_count_per_process {
            return Err(DiagnosticArtifactError::EventBoundExceeded);
        }
    }
    if processes.len() as u64 > bounds.process_count {
        return Err(DiagnosticArtifactError::ProcessBoundExceeded);
    }
    let event_limit_reached = events.len() as u64 == bounds.event_count;
    let per_process_limit_reached = processes
        .values()
        .any(|count| *count == bounds.event_count_per_process);
    let process_limit_reached = processes.len() as u64 == bounds.process_count;
    if (gaps.contains(&DiagnosticGap::EventLimit) && !event_limit_reached)
        || (gaps.contains(&DiagnosticGap::EventPerProcessLimit) && !per_process_limit_reached)
        || (gaps.contains(&DiagnosticGap::ProcessLimit) && !process_limit_reached)
    {
        return Err(DiagnosticArtifactError::CompletionInvalid);
    }
    Ok(())
}

pub(crate) fn is_normalized_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.first() != Some(&b'/')
        || bytes.contains(&0)
        || (bytes.len() > 1 && bytes.last() == Some(&b'/'))
        || path.contains("//")
    {
        return false;
    }
    path == "/"
        || path
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn validate_tcb(entries: &[DiagnosticTcbEntry]) -> Result<(), DiagnosticArtifactError> {
    if entries.len() != DiagnosticTcbRole::ALL.len() {
        return Err(DiagnosticArtifactError::TrustedRoleInvalid);
    }
    let roles = entries
        .iter()
        .map(|entry| entry.role)
        .collect::<BTreeSet<_>>();
    if roles != DiagnosticTcbRole::ALL.into_iter().collect() {
        return Err(DiagnosticArtifactError::TrustedRoleInvalid);
    }
    Ok(())
}

fn canonical_nonempty_text_set(
    values: Vec<String>,
    maximum_count: usize,
    maximum_bytes: usize,
) -> Result<Vec<String>, DiagnosticArtifactError> {
    let output = values.into_iter().collect::<BTreeSet<_>>();
    if output.is_empty()
        || output.len() > maximum_count
        || output
            .iter()
            .any(|value| value.is_empty() || value.len() > maximum_bytes)
    {
        return Err(DiagnosticArtifactError::AssumptionInvalid);
    }
    Ok(output.into_iter().collect())
}

fn sha256(bytes: &[u8]) -> Sha256Digest {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    Sha256Digest::from_bytes(digest)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn artifact(
        role: DiagnosticArtifactRole,
        byte: u8,
        size: u64,
        mode: u16,
    ) -> DiagnosticArtifactIdentity {
        DiagnosticArtifactIdentity::new(
            role,
            digest(byte),
            size,
            FileMode::new(mode).expect("fixture mode"),
        )
        .expect("fixture artifact")
    }

    pub(crate) fn fixture_parts() -> DiagnosticReceiptParts {
        let object =
            ObservedObjectIdentity::new(8, 1, 42, 0o100644, 7).expect("fixture object identity");
        let path_event = DiagnosticEvent::new(
            0,
            1000,
            Architecture::X86_64,
            DiagnosticEventClass::Openat,
            ObservationOperands::Path {
                buffer_bytes: None,
                directory_fd: Some(-100),
                flags: Some(0),
                mask: None,
                mode: None,
                path: Some("config".to_owned()),
                resolve: None,
                symlink_hops: Some(0),
            },
            ObservationOutcome::Failed(13),
            ObservationResolution::StableCandidate,
            Some("/workspace/config".to_owned()),
            Some(object.clone()),
            Some(object),
        )
        .expect("fixture path event");
        let socket_event = DiagnosticEvent::new(
            1,
            1000,
            Architecture::X86_64,
            DiagnosticEventClass::Connect,
            ObservationOperands::SocketAddress {
                address: Some(
                    ObservedSocketAddress::new(
                        SocketAddressFamily::Inet,
                        vec![2, 0, 1, 187, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                    )
                    .expect("fixture socket address"),
                ),
                descriptor: 3,
                payload_bytes: None,
            },
            ObservationOutcome::Failed(1),
            ObservationResolution::Unresolved,
            None,
            None,
            None,
        )
        .expect("fixture socket event");
        let trusted_computing_base = [
            (DiagnosticTcbRole::Filesystem, "fixture-filesystem"),
            (DiagnosticTcbRole::Hardware, "fixture-hardware"),
            (DiagnosticTcbRole::LinuxKernel, "fixture-kernel"),
            (DiagnosticTcbRole::RuntimeLauncher, "fixture-launcher"),
            (DiagnosticTcbRole::DiagnosticObserver, "fixture-observer"),
            (DiagnosticTcbRole::RuntimeSupervisor, "fixture-supervisor"),
        ]
        .into_iter()
        .map(|(role, identity)| {
            DiagnosticTcbEntry::new(role, identity).expect("fixture trusted role")
        })
        .collect();
        DiagnosticReceiptParts {
            execution_id: ExecutionId::from_bytes([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ])
            .expect("fixture execution identifier"),
            seed_plan: artifact(DiagnosticArtifactRole::ExecutionPlan, 0x44, 4, 0o644),
            target: artifact(DiagnosticArtifactRole::RuntimeExecutable, 0x55, 5, 0o755),
            runtime: artifact(DiagnosticArtifactRole::RuntimeBinary, 0x11, 1, 0o755),
            launcher: artifact(DiagnosticArtifactRole::LauncherBinary, 0x22, 2, 0o755),
            observer: artifact(DiagnosticArtifactRole::DiagnosticObserver, 0x33, 3, 0o755),
            platform: DiagnosticPlatform::new(Architecture::X86_64, "fixture", 11)
                .expect("fixture platform"),
            arguments: vec!["--fixture".to_owned(), "π".to_owned()],
            environment_names: vec!["LANG".to_owned()],
            bounds: ObservationBounds {
                event_count: 2,
                event_count_per_process: 256,
                output_bytes: 1_048_576,
                path_bytes: 4096,
                process_count: 16,
                socket_address_bytes: 128,
                symlink_hops: 40,
                tracee_string_bytes: 4096,
            },
            events: vec![path_event, socket_event],
            completion: DiagnosticCompletion::Incomplete,
            gaps: vec![DiagnosticGap::EventLimit],
            trusted_computing_base,
            assumptions: vec!["PBR-HOST-AX-002".to_owned()],
        }
    }

    pub(crate) fn fixture_receipt() -> DiagnosticReceipt {
        DiagnosticReceipt::construct(fixture_parts()).expect("fixture receipt")
    }

    #[test]
    fn receipt_constructor_enforces_bounds_order_and_completion() {
        let receipt = fixture_receipt();
        assert_eq!(receipt.events().len(), 2);
        assert_eq!(receipt.gaps(), &[DiagnosticGap::EventLimit]);

        let event = DiagnosticEvent::new(
            0,
            1,
            Architecture::X86_64,
            DiagnosticEventClass::Socket,
            ObservationOperands::Path {
                buffer_bytes: None,
                directory_fd: None,
                flags: None,
                mask: None,
                mode: None,
                path: None,
                resolve: None,
                symlink_hops: None,
            },
            ObservationOutcome::Returned(3),
            ObservationResolution::Unresolved,
            None,
            None,
            None,
        );
        assert_eq!(event, Err(DiagnosticArtifactError::EventInvalid));

        let drift_before =
            ObservedObjectIdentity::new(8, 1, 1, 0o100644, 7).expect("before identity");
        let drift_after =
            ObservedObjectIdentity::new(8, 1, 2, 0o100644, 7).expect("after identity");
        let drift = DiagnosticEvent::new(
            0,
            1,
            Architecture::X86_64,
            DiagnosticEventClass::Open,
            ObservationOperands::Path {
                buffer_bytes: None,
                directory_fd: None,
                flags: Some(0),
                mask: None,
                mode: None,
                path: Some("candidate".to_owned()),
                resolve: None,
                symlink_hops: Some(0),
            },
            ObservationOutcome::Failed(13),
            ObservationResolution::StableCandidate,
            Some("/workspace/candidate".to_owned()),
            Some(drift_before),
            Some(drift_after),
        );
        assert_eq!(drift, Err(DiagnosticArtifactError::ResolutionInvalid));
    }

    #[test]
    fn receipt_constructor_rejects_bound_and_gap_inconsistency() {
        let mut inconsistent_gap = fixture_parts();
        inconsistent_gap.bounds.event_count = 3;
        assert_eq!(
            DiagnosticReceipt::construct(inconsistent_gap),
            Err(DiagnosticArtifactError::CompletionInvalid)
        );

        let mut naturally_at_capacity = fixture_parts();
        naturally_at_capacity.completion = DiagnosticCompletion::Complete;
        naturally_at_capacity.gaps.clear();
        assert!(DiagnosticReceipt::construct(naturally_at_capacity).is_ok());

        let mut total_overflow = fixture_parts();
        total_overflow.bounds.event_count = 1;
        assert_eq!(
            DiagnosticReceipt::construct(total_overflow),
            Err(DiagnosticArtifactError::EventBoundExceeded)
        );

        let mut per_process_overflow = fixture_parts();
        per_process_overflow.bounds.event_count_per_process = 1;
        assert_eq!(
            DiagnosticReceipt::construct(per_process_overflow),
            Err(DiagnosticArtifactError::EventBoundExceeded)
        );

        let mut process_overflow = fixture_parts();
        process_overflow.events[1].process = 1001;
        process_overflow.bounds.process_count = 1;
        assert_eq!(
            DiagnosticReceipt::construct(process_overflow),
            Err(DiagnosticArtifactError::ProcessBoundExceeded)
        );

        let mut per_process_gap_without_exhaustion = fixture_parts();
        per_process_gap_without_exhaustion
            .gaps
            .push(DiagnosticGap::EventPerProcessLimit);
        assert_eq!(
            DiagnosticReceipt::construct(per_process_gap_without_exhaustion),
            Err(DiagnosticArtifactError::CompletionInvalid)
        );

        let mut process_gap_without_exhaustion = fixture_parts();
        process_gap_without_exhaustion
            .gaps
            .push(DiagnosticGap::ProcessLimit);
        assert_eq!(
            DiagnosticReceipt::construct(process_gap_without_exhaustion),
            Err(DiagnosticArtifactError::CompletionInvalid)
        );

        let mut wrong_order = fixture_parts();
        wrong_order.events[0].sequence = 2;
        assert_eq!(
            DiagnosticReceipt::construct(wrong_order),
            Err(DiagnosticArtifactError::EventOrderInvalid)
        );

        let mut symlink_overflow = fixture_parts();
        symlink_overflow.bounds.symlink_hops = 1;
        let ObservationOperands::Path { symlink_hops, .. } =
            &mut symlink_overflow.events[0].operands
        else {
            panic!("fixture path operands")
        };
        *symlink_hops = Some(2);
        assert_eq!(
            DiagnosticReceipt::construct(symlink_overflow),
            Err(DiagnosticArtifactError::SymlinkBoundExceeded)
        );

        let mut path_overflow = fixture_parts();
        path_overflow.bounds.path_bytes = 5;
        assert_eq!(
            DiagnosticReceipt::construct(path_overflow),
            Err(DiagnosticArtifactError::PathBoundExceeded)
        );

        let mut string_overflow = fixture_parts();
        string_overflow.bounds.tracee_string_bytes = 5;
        assert_eq!(
            DiagnosticReceipt::construct(string_overflow),
            Err(DiagnosticArtifactError::TraceeStringBoundExceeded)
        );

        let mut socket_overflow = fixture_parts();
        socket_overflow.bounds.socket_address_bytes = 8;
        assert_eq!(
            DiagnosticReceipt::construct(socket_overflow),
            Err(DiagnosticArtifactError::SocketAddressBoundExceeded)
        );

        let mut output_overflow = fixture_parts();
        output_overflow.bounds.output_bytes = 1024;
        assert_eq!(
            DiagnosticReceipt::construct(output_overflow),
            Err(DiagnosticArtifactError::OutputBoundExceeded)
        );
    }

    #[test]
    fn redaction_and_path_normalization_fail_closed() {
        let redacted_socket = DiagnosticEvent::new(
            0,
            1000,
            Architecture::X86_64,
            DiagnosticEventClass::Connect,
            ObservationOperands::SocketAddress {
                address: Some(
                    ObservedSocketAddress::new(
                        SocketAddressFamily::Inet,
                        vec![2, 0, 1, 187, 127, 0, 0, 1],
                    )
                    .expect("fixture socket address"),
                ),
                descriptor: 3,
                payload_bytes: None,
            },
            ObservationOutcome::Failed(1),
            ObservationResolution::Redacted,
            None,
            None,
            None,
        );
        assert_eq!(
            redacted_socket,
            Err(DiagnosticArtifactError::ResolutionInvalid)
        );

        let object =
            ObservedObjectIdentity::new(8, 1, 42, 0o100644, 7).expect("fixture object identity");
        for operands in [
            ObservationOperands::Path {
                buffer_bytes: None,
                directory_fd: None,
                flags: Some(0),
                mask: None,
                mode: None,
                path: None,
                resolve: None,
                symlink_hops: Some(0),
            },
            ObservationOperands::Path {
                buffer_bytes: None,
                directory_fd: None,
                flags: Some(0),
                mask: None,
                mode: None,
                path: Some("config".to_owned()),
                resolve: None,
                symlink_hops: None,
            },
        ] {
            let incomplete_path = DiagnosticEvent::new(
                0,
                1000,
                Architecture::X86_64,
                DiagnosticEventClass::Open,
                operands,
                ObservationOutcome::Failed(13),
                ObservationResolution::StableCandidate,
                Some("/workspace/config".to_owned()),
                Some(object.clone()),
                Some(object.clone()),
            );
            assert_eq!(
                incomplete_path,
                Err(DiagnosticArtifactError::ResolutionInvalid)
            );
        }
        let traversal = DiagnosticEvent::new(
            0,
            1000,
            Architecture::X86_64,
            DiagnosticEventClass::Open,
            ObservationOperands::Path {
                buffer_bytes: None,
                directory_fd: None,
                flags: Some(0),
                mask: None,
                mode: None,
                path: Some("../etc".to_owned()),
                resolve: None,
                symlink_hops: Some(1),
            },
            ObservationOutcome::Failed(13),
            ObservationResolution::StableCandidate,
            Some("/workspace/../etc".to_owned()),
            Some(object.clone()),
            Some(object),
        );
        assert_eq!(traversal, Err(DiagnosticArtifactError::ResolutionInvalid));
    }

    #[test]
    fn receipt_bytes_match_the_canonical_contract_vector() {
        assert_eq!(
            fixture_receipt().as_bytes(),
            include_bytes!("../../../schemas/vectors/diagnostic/diagnostic-receipt.json")
                .strip_suffix(b"\n")
                .unwrap_or(include_bytes!(
                    "../../../schemas/vectors/diagnostic/diagnostic-receipt.json"
                ))
        );
    }
}
