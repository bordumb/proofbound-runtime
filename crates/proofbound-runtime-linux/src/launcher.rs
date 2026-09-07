//! Defines the paused launcher and its private version 1 protocol.

use core::fmt;
use core::num::NonZeroU32;
use std::collections::BTreeMap;

use proofbound_runtime_core::{
    ArtifactIdentity, ArtifactRole, CgroupIdentity, ExecutionId, FileMode, Sha256Digest,
};

use crate::{LandlockAccess, LandlockBoundary, LockedPrivileges, SeccompBoundary};

/// The largest accepted private protocol packet, in bytes.
pub const MAX_LAUNCHER_FRAME_BYTES: usize = 1024 * 1024;
const MAX_COLLECTION_ITEMS: usize = 4096;
const MAX_NESTING_DEPTH: usize = 32;

const INSTALL_SCHEMA: &str = "proofbound-runtime-launcher-install/1";
const BOUNDARY_SCHEMA: &str = "proofbound-runtime-launcher-boundary-installed/1";
const FAILURE_SCHEMA: &str = "proofbound-runtime-launcher-failure/1";

/// Contains the three identities that bind every launcher message to one run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LauncherIdentity {
    execution_id: ExecutionId,
    policy_id: Sha256Digest,
    cgroup_id: CgroupIdentity,
}

impl LauncherIdentity {
    /// Creates one launcher protocol identity tuple.
    #[must_use]
    pub const fn new(
        execution_id: ExecutionId,
        policy_id: Sha256Digest,
        cgroup_id: CgroupIdentity,
    ) -> Self {
        Self {
            execution_id,
            policy_id,
            cgroup_id,
        }
    }

    /// Returns the execution identifier.
    #[must_use]
    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }

    /// Returns the compiled-policy digest.
    #[must_use]
    pub const fn policy_id(self) -> Sha256Digest {
        self.policy_id
    }

    /// Returns the cgroup mount-and-inode identity.
    #[must_use]
    pub const fn cgroup_id(self) -> CgroupIdentity {
        self.cgroup_id
    }

    fn verify(self, expected: Self) -> Result<(), LauncherError> {
        if self.execution_id != expected.execution_id {
            return Err(LauncherError::ExecutionIdentityMismatch);
        }
        if self.policy_id != expected.policy_id {
            return Err(LauncherError::PolicyIdentityMismatch);
        }
        if self.cgroup_id != expected.cgroup_id {
            return Err(LauncherError::CgroupIdentityMismatch);
        }
        Ok(())
    }
}

/// Contains one descriptor-based filesystem rule sent to the launcher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LauncherFilesystemRule {
    descriptor: u32,
    access: Vec<LandlockAccess>,
}

impl LauncherFilesystemRule {
    /// Creates one nonempty rule and rejects duplicate access classes.
    pub fn new(descriptor: u32, mut access: Vec<LandlockAccess>) -> Result<Self, LauncherError> {
        if descriptor > i32::MAX as u32 || access.is_empty() {
            return Err(LauncherError::Malformed);
        }
        access.sort_unstable_by_key(|item| access_rank(*item));
        if access.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(LauncherError::Malformed);
        }
        Ok(Self { descriptor, access })
    }

    /// Returns the inherited descriptor number.
    #[must_use]
    pub const fn descriptor(&self) -> u32 {
        self.descriptor
    }

    /// Returns the canonical nonempty access set.
    #[must_use]
    pub fn access(&self) -> &[LandlockAccess] {
        &self.access
    }
}

/// Contains a validated supervisor-to-launcher install request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallRequest {
    identity: LauncherIdentity,
    executable_id: ArtifactIdentity,
    executable_fd: u32,
    working_directory_fd: u32,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    filesystem: Vec<LauncherFilesystemRule>,
    seccomp_program: Vec<u8>,
    close_file_descriptors_from: u32,
}

impl InstallRequest {
    /// Creates one closed version 1 install request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: LauncherIdentity,
        executable_id: ArtifactIdentity,
        executable_fd: u32,
        working_directory_fd: u32,
        arguments: Vec<String>,
        environment: BTreeMap<String, String>,
        mut filesystem: Vec<LauncherFilesystemRule>,
        seccomp_program: Vec<u8>,
        close_file_descriptors_from: u32,
    ) -> Result<Self, LauncherError> {
        if executable_id.role() != ArtifactRole::RuntimeExecutable
            || executable_fd < 3
            || working_directory_fd < 3
            || executable_fd > i32::MAX as u32
            || working_directory_fd > i32::MAX as u32
            || close_file_descriptors_from > i32::MAX as u32
            || close_file_descriptors_from < 3
            || executable_fd >= close_file_descriptors_from
            || working_directory_fd >= close_file_descriptors_from
            || arguments.is_empty()
            || arguments.len() > MAX_COLLECTION_ITEMS
            || environment.len() > MAX_COLLECTION_ITEMS
            || filesystem.is_empty()
            || filesystem.len() > MAX_COLLECTION_ITEMS
            || seccomp_program.is_empty()
        {
            return Err(LauncherError::Malformed);
        }
        filesystem.sort_unstable_by_key(LauncherFilesystemRule::descriptor);
        let executable_rule_is_closed = filesystem.iter().any(|rule| {
            rule.descriptor == executable_fd
                && rule.access.as_slice() == [LandlockAccess::Read, LandlockAccess::Execute]
        });
        if filesystem
            .windows(2)
            .any(|pair| pair[0].descriptor == pair[1].descriptor)
            || filesystem
                .iter()
                .any(|rule| rule.descriptor < 3 || rule.descriptor >= close_file_descriptors_from)
            || !executable_rule_is_closed
        {
            return Err(LauncherError::Malformed);
        }
        if arguments.iter().any(|value| value.as_bytes().contains(&0))
            || environment.iter().any(|(name, value)| {
                name.is_empty()
                    || name.len() > 255
                    || name.as_bytes().contains(&0)
                    || name.as_bytes().contains(&b'=')
                    || value.as_bytes().contains(&0)
            })
        {
            return Err(LauncherError::Malformed);
        }
        Ok(Self {
            identity,
            executable_id,
            executable_fd,
            working_directory_fd,
            arguments,
            environment,
            filesystem,
            seccomp_program,
            close_file_descriptors_from,
        })
    }

    /// Returns the message identity tuple.
    #[must_use]
    pub const fn identity(&self) -> LauncherIdentity {
        self.identity
    }

    /// Returns the expected executable identity.
    #[must_use]
    pub const fn executable_id(&self) -> &ArtifactIdentity {
        &self.executable_id
    }

    /// Returns the inherited executable descriptor number.
    #[must_use]
    pub const fn executable_fd(&self) -> u32 {
        self.executable_fd
    }

    /// Returns the inherited working-directory descriptor number.
    #[must_use]
    pub const fn working_directory_fd(&self) -> u32 {
        self.working_directory_fd
    }

    /// Returns the exact child argument list.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// Returns the complete child environment.
    #[must_use]
    pub const fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    /// Returns the descriptor-based filesystem rules.
    #[must_use]
    pub fn filesystem(&self) -> &[LauncherFilesystemRule] {
        &self.filesystem
    }

    /// Returns the exact registered seccomp program bytes.
    #[must_use]
    pub fn seccomp_program(&self) -> &[u8] {
        &self.seccomp_program
    }

    /// Returns the first descriptor number that must be closed.
    #[must_use]
    pub const fn close_file_descriptors_from(&self) -> u32 {
        self.close_file_descriptors_from
    }
}

/// Identifies the launcher stage that reported a failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LauncherStage {
    /// The launcher could not decode the install request.
    Decode,
    /// A message or artifact identity did not match.
    Identity,
    /// A declared descriptor was absent or invalid.
    FileDescriptors,
    /// The launcher could not remove ambient privilege.
    Privileges,
    /// The launcher could not install or verify `no_new_privs`.
    NoNewPrivileges,
    /// The launcher could not install the Landlock ruleset.
    Landlock,
    /// The launcher could not install the seccomp filter.
    Seccomp,
    /// The launcher could not emit its boundary acknowledgement.
    Acknowledgement,
    /// The final working-directory or exec handoff failed.
    Exec,
}

impl LauncherStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Decode => "decode",
            Self::Identity => "identity",
            Self::FileDescriptors => "file-descriptors",
            Self::Privileges => "privileges",
            Self::NoNewPrivileges => "no-new-privileges",
            Self::Landlock => "landlock",
            Self::Seccomp => "seccomp",
            Self::Acknowledgement => "acknowledgement",
            Self::Exec => "exec",
        }
    }

    fn parse(value: &str) -> Result<Self, LauncherError> {
        match value {
            "decode" => Ok(Self::Decode),
            "identity" => Ok(Self::Identity),
            "file-descriptors" => Ok(Self::FileDescriptors),
            "privileges" => Ok(Self::Privileges),
            "no-new-privileges" => Ok(Self::NoNewPrivileges),
            "landlock" => Ok(Self::Landlock),
            "seccomp" => Ok(Self::Seccomp),
            "acknowledgement" => Ok(Self::Acknowledgement),
            "exec" => Ok(Self::Exec),
            _ => Err(LauncherError::Malformed),
        }
    }
}

/// Contains a typed launcher failure bound to one execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LauncherFailure {
    identity: LauncherIdentity,
    stage: LauncherStage,
    error_code: String,
}

impl LauncherFailure {
    /// Creates one failure with a nonempty bounded machine code.
    pub fn new(
        identity: LauncherIdentity,
        stage: LauncherStage,
        error_code: impl Into<String>,
    ) -> Result<Self, LauncherError> {
        let error_code = error_code.into();
        if error_code.is_empty() || error_code.len() > 128 || error_code.as_bytes().contains(&0) {
            return Err(LauncherError::Malformed);
        }
        Ok(Self {
            identity,
            stage,
            error_code,
        })
    }

    /// Returns the message identity tuple.
    #[must_use]
    pub const fn identity(&self) -> LauncherIdentity {
        self.identity
    }

    /// Returns the failed launcher stage.
    #[must_use]
    pub const fn stage(&self) -> LauncherStage {
        self.stage
    }

    /// Returns the stable underlying error code.
    #[must_use]
    pub fn error_code(&self) -> &str {
        &self.error_code
    }
}

/// Contains a typed boundary acknowledgement bound to one execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundaryInstalled {
    identity: LauncherIdentity,
}

impl BoundaryInstalled {
    /// Returns the message identity tuple.
    #[must_use]
    pub const fn identity(self) -> LauncherIdentity {
        self.identity
    }
}

/// Contains one closed version 1 launcher message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LauncherMessage {
    /// Requests installation of one exact compiled policy.
    Install(InstallRequest),
    /// Confirms that every required boundary was installed.
    BoundaryInstalled(BoundaryInstalled),
    /// Reports a typed launcher failure before child execution.
    Failure(LauncherFailure),
}

/// Identifies a private launcher protocol or sequence failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LauncherError {
    /// The host operating system is not Linux.
    UnsupportedOperatingSystem,
    /// The private channel pair could not be created.
    ChannelCreationFailed,
    /// One private packet could not be received.
    ChannelReadFailed,
    /// No private packet arrived before the monotonic deadline.
    ChannelTimeout,
    /// One private packet could not be sent.
    ChannelWriteFailed,
    /// The launcher could not stop before supervisor placement.
    PauseFailed,
    /// The channel ended before a message arrived.
    Eof,
    /// A CBOR item ended before its declared content.
    Truncated,
    /// A packet exceeded the registered one-mebibyte limit.
    FrameTooLarge,
    /// A packet was not a closed version 1 CBOR message.
    Malformed,
    /// A valid message did not use deterministic CBOR bytes.
    NonCanonical,
    /// A CBOR map contained the same key more than once.
    DuplicateKey,
    /// Bytes followed the one permitted CBOR item.
    TrailingData,
    /// The message schema version was not version 1.
    UnsupportedVersion,
    /// The compiled-policy identity did not match the supervisor value.
    PolicyIdentityMismatch,
    /// The cgroup identity did not match the supervisor value.
    CgroupIdentityMismatch,
    /// The execution identity did not match the supervisor value.
    ExecutionIdentityMismatch,
    /// The seccomp bytes did not match the registered profile.
    SeccompProgramMismatch,
    /// A required descriptor was invalid or outside the retained range.
    FileDescriptorInvalid,
    /// The executable descriptor identity changed before exec.
    ExecutableIdentityMismatch,
    /// Ambient privilege removal did not complete.
    PrivilegeInstallationFailed,
    /// Landlock installation did not complete.
    LandlockInstallationFailed,
    /// Seccomp installation did not complete.
    SeccompInstallationFailed,
    /// The launcher could not enter the registered working directory.
    WorkingDirectoryFailed,
    /// Descriptor-relative exec was denied by the installed boundary or host.
    ExecPermissionDenied,
    /// Descriptor-relative exec was rejected as an impermissible operation.
    ExecOperationNotPermitted,
    /// Descriptor-relative exec could not resolve a required image component.
    ExecNotFound,
    /// Descriptor-relative exec rejected the executable image format.
    ExecFormatInvalid,
    /// Descriptor-relative exec failed.
    ExecFailed,
    /// Code attempted to acknowledge before boundary installation.
    BoundaryNotInstalled,
    /// Code attempted to authorize exec before acknowledgement.
    AcknowledgementMissing,
    /// A protocol message or state transition was not expected.
    UnexpectedMessage,
}

impl LauncherError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "launcher.os.unsupported",
            Self::ChannelCreationFailed => "launcher.channel.creation-failed",
            Self::ChannelReadFailed => "launcher.channel.read-failed",
            Self::ChannelTimeout => "launcher.channel.timeout",
            Self::ChannelWriteFailed => "launcher.channel.write-failed",
            Self::PauseFailed => "launcher.pause.failed",
            Self::Eof => "launcher.protocol.eof",
            Self::Truncated => "launcher.protocol.truncated",
            Self::FrameTooLarge => "launcher.protocol.frame-too-large",
            Self::Malformed => "launcher.protocol.malformed",
            Self::NonCanonical => "launcher.protocol.non-canonical",
            Self::DuplicateKey => "launcher.protocol.duplicate-key",
            Self::TrailingData => "launcher.protocol.trailing-data",
            Self::UnsupportedVersion => "launcher.protocol.unsupported-version",
            Self::PolicyIdentityMismatch => "launcher.identity.policy-mismatch",
            Self::CgroupIdentityMismatch => "launcher.identity.cgroup-mismatch",
            Self::ExecutionIdentityMismatch => "launcher.identity.execution-mismatch",
            Self::SeccompProgramMismatch => "launcher.identity.seccomp-program-mismatch",
            Self::FileDescriptorInvalid => "launcher.file-descriptor.invalid",
            Self::ExecutableIdentityMismatch => "launcher.identity.executable-mismatch",
            Self::PrivilegeInstallationFailed => "launcher.privileges.installation-failed",
            Self::LandlockInstallationFailed => "launcher.landlock.installation-failed",
            Self::SeccompInstallationFailed => "launcher.seccomp.installation-failed",
            Self::WorkingDirectoryFailed => "launcher.working-directory.failed",
            Self::ExecPermissionDenied => "launcher.exec.permission-denied",
            Self::ExecOperationNotPermitted => "launcher.exec.operation-not-permitted",
            Self::ExecNotFound => "launcher.exec.not-found",
            Self::ExecFormatInvalid => "launcher.exec.format-invalid",
            Self::ExecFailed => "launcher.exec.failed",
            Self::BoundaryNotInstalled => "launcher.sequence.boundary-not-installed",
            Self::AcknowledgementMissing => "launcher.sequence.acknowledgement-missing",
            Self::UnexpectedMessage => "launcher.sequence.unexpected-message",
        }
    }
}

impl fmt::Display for LauncherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for LauncherError {}

/// Owns one endpoint of a private packet-preserving launcher channel.
#[derive(Debug)]
pub struct LauncherChannel {
    #[cfg(target_os = "linux")]
    descriptor: std::os::fd::OwnedFd,
}

impl LauncherChannel {
    /// Creates a close-on-exec Unix sequence-packet channel pair.
    pub fn pair() -> Result<(Self, Self), LauncherError> {
        #[cfg(target_os = "linux")]
        {
            let (first, second) = crate::sys::private_socket_pair()
                .map_err(|_| LauncherError::ChannelCreationFailed)?;
            Ok((Self { descriptor: first }, Self { descriptor: second }))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(LauncherError::UnsupportedOperatingSystem)
        }
    }

    /// Sends one complete canonical message as one packet.
    pub fn send(&self, message: &LauncherMessage) -> Result<(), LauncherError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd as _;

            let bytes = encode_launcher_message(message)?;
            crate::sys::send_packet(self.descriptor.as_raw_fd(), &bytes)
                .map_err(|_| LauncherError::ChannelWriteFailed)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = message;
            Err(LauncherError::UnsupportedOperatingSystem)
        }
    }

    /// Receives and validates one complete canonical message packet.
    pub fn receive(&self) -> Result<LauncherMessage, LauncherError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd as _;

            let mut buffer = vec![0; MAX_LAUNCHER_FRAME_BYTES];
            let received = crate::sys::receive_packet(self.descriptor.as_raw_fd(), &mut buffer)
                .map_err(|_| LauncherError::ChannelReadFailed)?;
            if received == 0 {
                return Err(LauncherError::Eof);
            }
            if received > buffer.len() {
                return Err(LauncherError::FrameTooLarge);
            }
            buffer.truncate(received);
            decode_launcher_message(&buffer)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(LauncherError::UnsupportedOperatingSystem)
        }
    }

    /// Receives one complete message before a monotonic timeout expires.
    pub fn receive_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<LauncherMessage, LauncherError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd as _;

            if !crate::sys::wait_readable(self.descriptor.as_raw_fd(), timeout)
                .map_err(|_| LauncherError::ChannelReadFailed)?
            {
                return Err(LauncherError::ChannelTimeout);
            }
            self.receive()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = timeout;
            Err(LauncherError::UnsupportedOperatingSystem)
        }
    }

    /// Takes one inherited descriptor and restores close-on-exec ownership.
    ///
    /// This function closes the supplied descriptor after it creates an owned
    /// close-on-exec duplicate. The hidden launcher entry point calls it once.
    pub fn from_inherited_descriptor(descriptor: u32) -> Result<Self, LauncherError> {
        #[cfg(target_os = "linux")]
        {
            let descriptor =
                i32::try_from(descriptor).map_err(|_| LauncherError::FileDescriptorInvalid)?;
            let descriptor = crate::sys::take_inherited_descriptor(descriptor)
                .map_err(|_| LauncherError::FileDescriptorInvalid)?;
            Ok(Self { descriptor })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = descriptor;
            Err(LauncherError::UnsupportedOperatingSystem)
        }
    }

    /// Borrows the channel descriptor for a controlled process handoff.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.descriptor.as_fd()
    }

    #[cfg(target_os = "linux")]
    fn raw_descriptor(&self) -> i32 {
        use std::os::fd::AsRawFd as _;
        self.descriptor.as_raw_fd()
    }
}

/// Stops the launcher until its supervisor places it in the fresh cgroup.
pub fn pause_for_supervisor() -> Result<(), LauncherError> {
    #[cfg(target_os = "linux")]
    {
        crate::sys::pause_current_process().map_err(|_| LauncherError::PauseFailed)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(LauncherError::UnsupportedOperatingSystem)
    }
}

/// Runs the complete trusted launcher sequence and performs descriptor-relative exec.
///
/// The caller must invoke this function at launcher process entry. The function
/// stops the process before it reads the private policy channel. It returns only
/// after a launcher failure or an exec failure.
pub fn run_launcher(
    channel: &LauncherChannel,
    expected: LauncherIdentity,
    architecture: crate::Architecture,
    landlock_abi: NonZeroU32,
) -> Result<(), LauncherError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsFd as _;

        pause_for_supervisor()?;
        let prepared = receive_install_request(channel, expected).map_err(|error| {
            report_failure(channel, expected, stage_for_protocol_error(error), error)
        })?;
        let request = prepared.request();
        if channel.raw_descriptor() < 0 {
            return Err(report_failure(
                channel,
                expected,
                LauncherStage::FileDescriptors,
                LauncherError::FileDescriptorInvalid,
            ));
        }
        let expected_program = crate::compile_deny_network_program(
            proofbound_runtime_core::SeccompPolicy::DenyNetworkV1,
            architecture,
        )
        .map_err(|_| {
            report_failure(
                channel,
                expected,
                LauncherStage::Seccomp,
                LauncherError::SeccompInstallationFailed,
            )
        })?;
        if request.seccomp_program() != expected_program {
            return Err(report_failure(
                channel,
                expected,
                LauncherStage::Identity,
                LauncherError::SeccompProgramMismatch,
            ));
        }
        mark_declared_descriptors_close_on_exec(request).map_err(|error| {
            report_failure(channel, expected, LauncherStage::FileDescriptors, error)
        })?;
        crate::revalidate_inherited_executable(request.executable_fd(), request.executable_id())
            .map_err(|_| {
                report_failure(
                    channel,
                    expected,
                    LauncherStage::Identity,
                    LauncherError::ExecutableIdentityMismatch,
                )
            })?;
        let arguments = build_arguments(request)
            .map_err(|error| report_failure(channel, expected, LauncherStage::Exec, error))?;
        let environment = build_environment(request)
            .map_err(|error| report_failure(channel, expected, LauncherStage::Exec, error))?;
        let retained_descriptors = core::iter::once(request.executable_fd())
            .chain(core::iter::once(request.working_directory_fd()))
            .chain(request.filesystem().iter().map(|rule| rule.descriptor()))
            .map(|descriptor| descriptor as i32)
            .chain(core::iter::once(channel.raw_descriptor()))
            .collect::<Vec<_>>();
        crate::sys::close_descriptors_except(&retained_descriptors).map_err(|_| {
            report_failure(
                channel,
                expected,
                LauncherStage::FileDescriptors,
                LauncherError::FileDescriptorInvalid,
            )
        })?;
        let locked = crate::lock_privileges().map_err(|privilege_error| {
            report_failure(
                channel,
                expected,
                privilege_stage(privilege_error),
                LauncherError::PrivilegeInstallationFailed,
            )
        })?;
        let landlock = {
            let descriptor_rules = duplicate_rule_descriptors(request).map_err(|error| {
                report_failure(channel, expected, LauncherStage::FileDescriptors, error)
            })?;
            let mut rules = Vec::new();
            for (descriptor, access) in &descriptor_rules {
                for access in access {
                    rules.push(crate::LandlockRule::new(descriptor.as_fd(), *access));
                }
            }
            crate::install_landlock(landlock_abi, &locked, &rules).map_err(|_| {
                report_failure(
                    channel,
                    expected,
                    LauncherStage::Landlock,
                    LauncherError::LandlockInstallationFailed,
                )
            })?
        };
        let seccomp = crate::install_deny_network(
            proofbound_runtime_core::SeccompPolicy::DenyNetworkV1,
            architecture,
            &locked,
            &landlock,
        )
        .map_err(|_| {
            report_failure(
                channel,
                expected,
                LauncherStage::Seccomp,
                LauncherError::SeccompInstallationFailed,
            )
        })?;
        let installed = prepared
            .record_boundary_installed(&locked, &landlock, &seccomp)
            .map_err(|error| {
                report_failure(channel, expected, LauncherStage::Acknowledgement, error)
            })?;
        let authorization = installed
            .acknowledge(channel)
            .map_err(|error| {
                report_failure(channel, expected, LauncherStage::Acknowledgement, error)
            })?
            .authorize_exec()
            .map_err(|error| report_failure(channel, expected, LauncherStage::Exec, error))?;
        debug_assert!(authorization.is_authorized());
        crate::revalidate_inherited_executable(
            authorization.request().executable_fd(),
            authorization.request().executable_id(),
        )
        .map_err(|_| {
            report_failure(
                channel,
                expected,
                LauncherStage::Identity,
                LauncherError::ExecutableIdentityMismatch,
            )
        })?;
        crate::sys::change_directory(authorization.request().working_directory_fd() as i32)
            .map_err(|_| {
                report_failure(
                    channel,
                    expected,
                    LauncherStage::Exec,
                    LauncherError::WorkingDirectoryFailed,
                )
            })?;
        crate::sys::execveat(
            authorization.request().executable_fd() as i32,
            &arguments,
            &environment,
        )
        .map_err(|error| {
            let error = match error.raw_os_error() {
                Some(libc::EACCES) => LauncherError::ExecPermissionDenied,
                Some(libc::EPERM) => LauncherError::ExecOperationNotPermitted,
                Some(libc::ENOENT) => LauncherError::ExecNotFound,
                Some(libc::ENOEXEC) => LauncherError::ExecFormatInvalid,
                _ => LauncherError::ExecFailed,
            };
            report_failure(channel, expected, LauncherStage::Exec, error)
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (channel, expected, architecture, landlock_abi);
        Err(LauncherError::UnsupportedOperatingSystem)
    }
}

#[cfg(target_os = "linux")]
fn duplicate_rule_descriptors(
    request: &InstallRequest,
) -> Result<Vec<(std::os::fd::OwnedFd, Vec<LandlockAccess>)>, LauncherError> {
    request
        .filesystem()
        .iter()
        .map(|rule| {
            let descriptor = crate::sys::duplicate_descriptor(rule.descriptor() as i32)
                .map_err(|_| LauncherError::FileDescriptorInvalid)?;
            Ok((descriptor, rule.access().to_vec()))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn mark_declared_descriptors_close_on_exec(request: &InstallRequest) -> Result<(), LauncherError> {
    let descriptors = core::iter::once(request.executable_fd())
        .chain(core::iter::once(request.working_directory_fd()))
        .chain(request.filesystem().iter().map(|rule| rule.descriptor()));
    for descriptor in descriptors {
        crate::sys::set_descriptor_close_on_exec(descriptor as i32)
            .map_err(|_| LauncherError::FileDescriptorInvalid)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn build_arguments(request: &InstallRequest) -> Result<Vec<std::ffi::CString>, LauncherError> {
    request
        .arguments()
        .iter()
        .map(String::as_str)
        .map(|value| std::ffi::CString::new(value).map_err(|_| LauncherError::Malformed))
        .collect()
}

#[cfg(target_os = "linux")]
fn build_environment(request: &InstallRequest) -> Result<Vec<std::ffi::CString>, LauncherError> {
    request
        .environment()
        .iter()
        .map(|(name, value)| {
            std::ffi::CString::new(format!("{name}={value}")).map_err(|_| LauncherError::Malformed)
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn stage_for_protocol_error(error: LauncherError) -> LauncherStage {
    match error {
        LauncherError::PolicyIdentityMismatch
        | LauncherError::CgroupIdentityMismatch
        | LauncherError::ExecutionIdentityMismatch
        | LauncherError::ExecutableIdentityMismatch
        | LauncherError::SeccompProgramMismatch => LauncherStage::Identity,
        _ => LauncherStage::Decode,
    }
}

#[cfg(target_os = "linux")]
fn privilege_stage(error: crate::PrivilegeError) -> LauncherStage {
    match error {
        crate::PrivilegeError::NoNewPrivilegesInstallFailed
        | crate::PrivilegeError::NoNewPrivilegesVerificationFailed => {
            LauncherStage::NoNewPrivileges
        }
        _ => LauncherStage::Privileges,
    }
}

#[cfg(target_os = "linux")]
fn report_failure(
    channel: &LauncherChannel,
    identity: LauncherIdentity,
    stage: LauncherStage,
    error: LauncherError,
) -> LauncherError {
    if let Ok(failure) = LauncherFailure::new(identity, stage, error.code()) {
        let _ = channel.send(&LauncherMessage::Failure(failure));
    }
    error
}

/// Waits for the only valid first launcher message and checks its identities.
pub fn receive_install_request(
    channel: &LauncherChannel,
    expected: LauncherIdentity,
) -> Result<PreparedLauncher, LauncherError> {
    let LauncherMessage::Install(request) = channel.receive()? else {
        return Err(LauncherError::UnexpectedMessage);
    };
    request.identity.verify(expected)?;
    Ok(PreparedLauncher {
        request,
        sequence: SequenceState::InstallValidated,
    })
}

/// Contains an identity-checked request before boundary installation.
#[derive(Debug)]
pub struct PreparedLauncher {
    request: InstallRequest,
    sequence: SequenceState,
}

impl PreparedLauncher {
    /// Returns the validated request that the launcher must install.
    #[must_use]
    pub const fn request(&self) -> &InstallRequest {
        &self.request
    }

    /// Records the complete boundary only from all three production witnesses.
    pub fn record_boundary_installed(
        self,
        _privileges: &LockedPrivileges,
        _landlock: &LandlockBoundary,
        seccomp: &SeccompBoundary,
    ) -> Result<InstalledLauncher, LauncherError> {
        if self.request.seccomp_program != seccomp.program() {
            return Err(LauncherError::SeccompProgramMismatch);
        }
        Ok(InstalledLauncher {
            identity: self.request.identity,
            request: self.request,
            sequence: advance_sequence(self.sequence, SequenceEvent::BoundariesInstalled)?,
        })
    }
}

/// Contains a request after all irreversible launcher boundaries were observed.
#[derive(Debug)]
pub struct InstalledLauncher {
    identity: LauncherIdentity,
    request: InstallRequest,
    sequence: SequenceState,
}

impl InstalledLauncher {
    /// Emits the only valid boundary acknowledgement and advances the state.
    pub fn acknowledge(
        self,
        channel: &LauncherChannel,
    ) -> Result<AcknowledgedLauncher, LauncherError> {
        channel.send(&LauncherMessage::BoundaryInstalled(BoundaryInstalled {
            identity: self.identity,
        }))?;
        Ok(AcknowledgedLauncher {
            request: self.request,
            sequence: advance_sequence(self.sequence, SequenceEvent::AcknowledgementEmitted)?,
        })
    }
}

/// Contains a request after its boundary acknowledgement was emitted.
#[derive(Debug)]
pub struct AcknowledgedLauncher {
    request: InstallRequest,
    sequence: SequenceState,
}

impl AcknowledgedLauncher {
    /// Consumes the acknowledgement state and authorizes the exec handoff.
    pub fn authorize_exec(self) -> Result<ExecAuthorization, LauncherError> {
        Ok(ExecAuthorization {
            request: self.request,
            sequence: advance_sequence(self.sequence, SequenceEvent::ExecAuthorized)?,
        })
    }
}

/// Authorizes one exec handoff after complete boundary installation and acknowledgement.
#[derive(Debug)]
pub struct ExecAuthorization {
    request: InstallRequest,
    sequence: SequenceState,
}

impl ExecAuthorization {
    /// Returns the fully validated request for the final descriptor-relative exec.
    #[must_use]
    pub const fn request(&self) -> &InstallRequest {
        &self.request
    }

    /// Reports that the complete launch sequence authorized exec.
    #[must_use]
    pub fn is_authorized(&self) -> bool {
        self.sequence == SequenceState::ExecAuthorized
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SequenceState {
    InstallValidated,
    BoundariesInstalled,
    Acknowledged,
    ExecAuthorized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SequenceEvent {
    BoundariesInstalled,
    AcknowledgementEmitted,
    ExecAuthorized,
}

fn advance_sequence(
    state: SequenceState,
    event: SequenceEvent,
) -> Result<SequenceState, LauncherError> {
    match (state, event) {
        (SequenceState::InstallValidated, SequenceEvent::BoundariesInstalled) => {
            Ok(SequenceState::BoundariesInstalled)
        }
        (SequenceState::BoundariesInstalled, SequenceEvent::AcknowledgementEmitted) => {
            Ok(SequenceState::Acknowledged)
        }
        (SequenceState::Acknowledged, SequenceEvent::ExecAuthorized) => {
            Ok(SequenceState::ExecAuthorized)
        }
        (SequenceState::InstallValidated, SequenceEvent::AcknowledgementEmitted) => {
            Err(LauncherError::BoundaryNotInstalled)
        }
        (_, SequenceEvent::ExecAuthorized) => Err(LauncherError::AcknowledgementMissing),
        _ => Err(LauncherError::UnexpectedMessage),
    }
}

/// Verifies a launcher response against the expected execution identities.
pub fn verify_launcher_response(
    message: &LauncherMessage,
    expected: LauncherIdentity,
) -> Result<(), LauncherError> {
    match message {
        LauncherMessage::BoundaryInstalled(installed) => installed.identity.verify(expected),
        LauncherMessage::Failure(failure) => failure.identity.verify(expected),
        LauncherMessage::Install(_) => Err(LauncherError::UnexpectedMessage),
    }
}

/// Encodes one launcher message as deterministic CBOR bytes.
pub fn encode_launcher_message(message: &LauncherMessage) -> Result<Vec<u8>, LauncherError> {
    let value = message_to_value(message);
    let mut output = Vec::new();
    encode_value(&value, &mut output)?;
    if output.len() > MAX_LAUNCHER_FRAME_BYTES {
        return Err(LauncherError::FrameTooLarge);
    }
    Ok(output)
}

/// Decodes one closed deterministic CBOR launcher message.
pub fn decode_launcher_message(input: &[u8]) -> Result<LauncherMessage, LauncherError> {
    if input.is_empty() {
        return Err(LauncherError::Eof);
    }
    if input.len() > MAX_LAUNCHER_FRAME_BYTES {
        return Err(LauncherError::FrameTooLarge);
    }
    let mut decoder = Decoder::new(input);
    let value = decoder.value(0)?;
    if decoder.position != input.len() {
        return Err(LauncherError::TrailingData);
    }
    let message = value_to_message(&value)?;
    let canonical = encode_launcher_message(&message)?;
    if canonical != input {
        return Err(LauncherError::NonCanonical);
    }
    Ok(message)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Value {
    Unsigned(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Self>),
    Map(Vec<(String, Self)>),
}

fn encode_value(value: &Value, output: &mut Vec<u8>) -> Result<(), LauncherError> {
    match value {
        Value::Unsigned(number) => encode_header(0, *number, output),
        Value::Bytes(bytes) => {
            encode_header(
                2,
                u64::try_from(bytes.len()).map_err(|_| LauncherError::FrameTooLarge)?,
                output,
            );
            output.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            encode_header(
                3,
                u64::try_from(text.len()).map_err(|_| LauncherError::FrameTooLarge)?,
                output,
            );
            output.extend_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            encode_header(
                4,
                u64::try_from(items.len()).map_err(|_| LauncherError::FrameTooLarge)?,
                output,
            );
            for item in items {
                encode_value(item, output)?;
            }
        }
        Value::Map(entries) => {
            let mut entries = entries.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| canonical_key_order(&left.0, &right.0));
            encode_header(
                5,
                u64::try_from(entries.len()).map_err(|_| LauncherError::FrameTooLarge)?,
                output,
            );
            for (key, value) in entries {
                encode_value(&Value::Text(key.clone()), output)?;
                encode_value(value, output)?;
            }
        }
    }
    if output.len() > MAX_LAUNCHER_FRAME_BYTES {
        return Err(LauncherError::FrameTooLarge);
    }
    Ok(())
}

fn encode_header(major: u8, value: u64, output: &mut Vec<u8>) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | u8::try_from(value).expect("small value fits u8")),
        24..=0xff => {
            output.push(prefix | 24);
            output.push(u8::try_from(value).expect("one-byte value fits u8"));
        }
        0x100..=0xffff => {
            output.push(prefix | 25);
            output.extend_from_slice(
                &u16::try_from(value)
                    .expect("two-byte value fits u16")
                    .to_be_bytes(),
            );
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 26);
            output.extend_from_slice(
                &u32::try_from(value)
                    .expect("four-byte value fits u32")
                    .to_be_bytes(),
            );
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn canonical_key_order(left: &str, right: &str) -> std::cmp::Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

struct Decoder<'input> {
    input: &'input [u8],
    position: usize,
}

impl<'input> Decoder<'input> {
    const fn new(input: &'input [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn value(&mut self, depth: usize) -> Result<Value, LauncherError> {
        if depth >= MAX_NESTING_DEPTH {
            return Err(LauncherError::Malformed);
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        if additional == 31 {
            return Err(LauncherError::NonCanonical);
        }
        let argument = self.argument(additional)?;
        match major {
            0 => Ok(Value::Unsigned(argument)),
            2 => Ok(Value::Bytes(self.bytes(argument)?.to_vec())),
            3 => {
                let bytes = self.bytes(argument)?;
                let text = std::str::from_utf8(bytes).map_err(|_| LauncherError::Malformed)?;
                Ok(Value::Text(text.to_owned()))
            }
            4 => {
                let count = bounded_count(argument)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let count = bounded_count(argument)?;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    let Value::Text(key) = self.value(depth + 1)? else {
                        return Err(LauncherError::Malformed);
                    };
                    if entries.iter().any(|(existing, _)| existing == &key) {
                        return Err(LauncherError::DuplicateKey);
                    }
                    let value = self.value(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            _ => Err(LauncherError::Malformed),
        }
    }

    fn argument(&mut self, additional: u8) -> Result<u64, LauncherError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => Ok(u64::from(self.byte()?)),
            25 => Ok(u64::from(u16::from_be_bytes(self.array()?))),
            26 => Ok(u64::from(u32::from_be_bytes(self.array()?))),
            27 => Ok(u64::from_be_bytes(self.array()?)),
            _ => Err(LauncherError::Malformed),
        }
    }

    fn byte(&mut self) -> Result<u8, LauncherError> {
        let byte = self
            .input
            .get(self.position)
            .copied()
            .ok_or(LauncherError::Truncated)?;
        self.position += 1;
        Ok(byte)
    }

    fn array<const SIZE: usize>(&mut self) -> Result<[u8; SIZE], LauncherError> {
        let bytes = self.bytes(SIZE as u64)?;
        bytes.try_into().map_err(|_| LauncherError::Truncated)
    }

    fn bytes(&mut self, length: u64) -> Result<&'input [u8], LauncherError> {
        let length = usize::try_from(length).map_err(|_| LauncherError::FrameTooLarge)?;
        let end = self
            .position
            .checked_add(length)
            .ok_or(LauncherError::FrameTooLarge)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(LauncherError::Truncated)?;
        self.position = end;
        Ok(bytes)
    }
}

fn bounded_count(value: u64) -> Result<usize, LauncherError> {
    let count = usize::try_from(value).map_err(|_| LauncherError::FrameTooLarge)?;
    if count > MAX_COLLECTION_ITEMS {
        Err(LauncherError::FrameTooLarge)
    } else {
        Ok(count)
    }
}

fn message_to_value(message: &LauncherMessage) -> Value {
    match message {
        LauncherMessage::Install(request) => {
            let mut entries = identity_entries(request.identity);
            entries.extend([
                ("schema".to_owned(), text(INSTALL_SCHEMA)),
                (
                    "executable_id".to_owned(),
                    artifact_value(&request.executable_id),
                ),
                (
                    "executable_fd".to_owned(),
                    Value::Unsigned(u64::from(request.executable_fd)),
                ),
                (
                    "working_directory_fd".to_owned(),
                    Value::Unsigned(u64::from(request.working_directory_fd)),
                ),
                (
                    "arguments".to_owned(),
                    Value::Array(request.arguments.iter().map(|item| text(item)).collect()),
                ),
                (
                    "environment".to_owned(),
                    Value::Map(
                        request
                            .environment
                            .iter()
                            .map(|(name, value)| (name.clone(), text(value)))
                            .collect(),
                    ),
                ),
                (
                    "filesystem".to_owned(),
                    Value::Array(
                        request
                            .filesystem
                            .iter()
                            .map(filesystem_rule_value)
                            .collect(),
                    ),
                ),
                (
                    "seccomp_program".to_owned(),
                    Value::Bytes(request.seccomp_program.clone()),
                ),
                (
                    "close_file_descriptors_from".to_owned(),
                    Value::Unsigned(u64::from(request.close_file_descriptors_from)),
                ),
            ]);
            Value::Map(entries)
        }
        LauncherMessage::BoundaryInstalled(installed) => {
            let mut entries = identity_entries(installed.identity);
            entries.extend([
                ("schema".to_owned(), text(BOUNDARY_SCHEMA)),
                ("state".to_owned(), text("installed")),
            ]);
            Value::Map(entries)
        }
        LauncherMessage::Failure(failure) => {
            let mut entries = identity_entries(failure.identity);
            entries.extend([
                ("schema".to_owned(), text(FAILURE_SCHEMA)),
                ("stage".to_owned(), text(failure.stage.as_str())),
                ("error_code".to_owned(), text(&failure.error_code)),
            ]);
            Value::Map(entries)
        }
    }
}

fn identity_entries(identity: LauncherIdentity) -> Vec<(String, Value)> {
    vec![
        (
            "execution_id".to_owned(),
            Value::Bytes(identity.execution_id.as_bytes().to_vec()),
        ),
        ("policy_id".to_owned(), digest_value(identity.policy_id)),
        ("cgroup_id".to_owned(), cgroup_value(identity.cgroup_id)),
    ]
}

fn digest_value(digest: Sha256Digest) -> Value {
    Value::Map(vec![
        ("algorithm".to_owned(), text("sha256")),
        (
            "digest".to_owned(),
            Value::Bytes(digest.as_bytes().to_vec()),
        ),
    ])
}

fn cgroup_value(identity: CgroupIdentity) -> Value {
    Value::Map(vec![
        ("mount_id".to_owned(), Value::Unsigned(identity.mount_id())),
        ("inode".to_owned(), Value::Unsigned(identity.inode())),
    ])
}

fn artifact_value(identity: &ArtifactIdentity) -> Value {
    Value::Map(vec![
        ("role".to_owned(), text(identity.role().as_str())),
        ("digest".to_owned(), digest_value(identity.digest())),
        ("size".to_owned(), Value::Unsigned(identity.size())),
        (
            "mode".to_owned(),
            Value::Unsigned(u64::from(identity.mode().get())),
        ),
    ])
}

fn filesystem_rule_value(rule: &LauncherFilesystemRule) -> Value {
    Value::Map(vec![
        ("fd".to_owned(), Value::Unsigned(u64::from(rule.descriptor))),
        (
            "access".to_owned(),
            Value::Array(
                rule.access
                    .iter()
                    .map(|item| text(access_name(*item)))
                    .collect(),
            ),
        ),
    ])
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn value_to_message(value: &Value) -> Result<LauncherMessage, LauncherError> {
    let map = as_map(value)?;
    let schema = as_text(field(map, "schema")?)?;
    match schema {
        INSTALL_SCHEMA => decode_install(map).map(LauncherMessage::Install),
        BOUNDARY_SCHEMA => decode_boundary(map).map(LauncherMessage::BoundaryInstalled),
        FAILURE_SCHEMA => decode_failure(map).map(LauncherMessage::Failure),
        _ => Err(LauncherError::UnsupportedVersion),
    }
}

fn decode_install(map: &[(String, Value)]) -> Result<InstallRequest, LauncherError> {
    require_keys(
        map,
        &[
            "schema",
            "execution_id",
            "policy_id",
            "cgroup_id",
            "executable_id",
            "executable_fd",
            "working_directory_fd",
            "arguments",
            "environment",
            "filesystem",
            "seccomp_program",
            "close_file_descriptors_from",
        ],
    )?;
    let identity = decode_identity(map)?;
    let executable_id = decode_artifact(field(map, "executable_id")?)?;
    let executable_fd = as_u32(field(map, "executable_fd")?)?;
    let working_directory_fd = as_u32(field(map, "working_directory_fd")?)?;
    let arguments = as_array(field(map, "arguments")?)?
        .iter()
        .map(|value| as_text(value).map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    let environment = as_map(field(map, "environment")?)?
        .iter()
        .map(|(name, value)| Ok((name.clone(), as_text(value)?.to_owned())))
        .collect::<Result<BTreeMap<_, _>, LauncherError>>()?;
    let filesystem = as_array(field(map, "filesystem")?)?
        .iter()
        .map(decode_filesystem_rule)
        .collect::<Result<Vec<_>, _>>()?;
    let seccomp_program = as_bytes(field(map, "seccomp_program")?)?.to_vec();
    let close_file_descriptors_from = as_u32(field(map, "close_file_descriptors_from")?)?;
    InstallRequest::new(
        identity,
        executable_id,
        executable_fd,
        working_directory_fd,
        arguments,
        environment,
        filesystem,
        seccomp_program,
        close_file_descriptors_from,
    )
}

fn decode_boundary(map: &[(String, Value)]) -> Result<BoundaryInstalled, LauncherError> {
    require_keys(
        map,
        &["schema", "execution_id", "policy_id", "cgroup_id", "state"],
    )?;
    if as_text(field(map, "state")?)? != "installed" {
        return Err(LauncherError::Malformed);
    }
    Ok(BoundaryInstalled {
        identity: decode_identity(map)?,
    })
}

fn decode_failure(map: &[(String, Value)]) -> Result<LauncherFailure, LauncherError> {
    require_keys(
        map,
        &[
            "schema",
            "execution_id",
            "policy_id",
            "cgroup_id",
            "stage",
            "error_code",
        ],
    )?;
    LauncherFailure::new(
        decode_identity(map)?,
        LauncherStage::parse(as_text(field(map, "stage")?)?)?,
        as_text(field(map, "error_code")?)?,
    )
}

fn decode_identity(map: &[(String, Value)]) -> Result<LauncherIdentity, LauncherError> {
    let execution_bytes: [u8; 16] = as_bytes(field(map, "execution_id")?)?
        .try_into()
        .map_err(|_| LauncherError::Malformed)?;
    let execution_id =
        ExecutionId::from_bytes(execution_bytes).map_err(|_| LauncherError::Malformed)?;
    Ok(LauncherIdentity::new(
        execution_id,
        decode_digest(field(map, "policy_id")?)?,
        decode_cgroup(field(map, "cgroup_id")?)?,
    ))
}

fn decode_digest(value: &Value) -> Result<Sha256Digest, LauncherError> {
    let map = as_map(value)?;
    require_keys(map, &["algorithm", "digest"])?;
    if as_text(field(map, "algorithm")?)? != "sha256" {
        return Err(LauncherError::Malformed);
    }
    let bytes: [u8; 32] = as_bytes(field(map, "digest")?)?
        .try_into()
        .map_err(|_| LauncherError::Malformed)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn decode_cgroup(value: &Value) -> Result<CgroupIdentity, LauncherError> {
    let map = as_map(value)?;
    require_keys(map, &["mount_id", "inode"])?;
    Ok(CgroupIdentity::new(
        as_unsigned(field(map, "mount_id")?)?,
        as_unsigned(field(map, "inode")?)?,
    ))
}

fn decode_artifact(value: &Value) -> Result<ArtifactIdentity, LauncherError> {
    let map = as_map(value)?;
    require_keys(map, &["role", "digest", "size", "mode"])?;
    if as_text(field(map, "role")?)? != ArtifactRole::RuntimeExecutable.as_str() {
        return Err(LauncherError::Malformed);
    }
    let mode = u16::try_from(as_unsigned(field(map, "mode")?)?)
        .ok()
        .and_then(|value| FileMode::new(value).ok())
        .ok_or(LauncherError::Malformed)?;
    Ok(ArtifactIdentity::new(
        ArtifactRole::RuntimeExecutable,
        decode_digest(field(map, "digest")?)?,
        as_unsigned(field(map, "size")?)?,
        mode,
    ))
}

fn decode_filesystem_rule(value: &Value) -> Result<LauncherFilesystemRule, LauncherError> {
    let map = as_map(value)?;
    require_keys(map, &["fd", "access"])?;
    let access = as_array(field(map, "access")?)?
        .iter()
        .map(|value| parse_access(as_text(value)?))
        .collect::<Result<Vec<_>, _>>()?;
    LauncherFilesystemRule::new(as_u32(field(map, "fd")?)?, access)
}

fn require_keys(map: &[(String, Value)], expected: &[&str]) -> Result<(), LauncherError> {
    if map.len() != expected.len()
        || expected
            .iter()
            .any(|expected| !map.iter().any(|(actual, _)| actual == expected))
    {
        return Err(LauncherError::Malformed);
    }
    Ok(())
}

fn field<'value>(
    map: &'value [(String, Value)],
    name: &str,
) -> Result<&'value Value, LauncherError> {
    map.iter()
        .find_map(|(key, value)| (key == name).then_some(value))
        .ok_or(LauncherError::Malformed)
}

fn as_map(value: &Value) -> Result<&[(String, Value)], LauncherError> {
    match value {
        Value::Map(value) => Ok(value),
        _ => Err(LauncherError::Malformed),
    }
}

fn as_array(value: &Value) -> Result<&[Value], LauncherError> {
    match value {
        Value::Array(value) => Ok(value),
        _ => Err(LauncherError::Malformed),
    }
}

fn as_text(value: &Value) -> Result<&str, LauncherError> {
    match value {
        Value::Text(value) => Ok(value),
        _ => Err(LauncherError::Malformed),
    }
}

fn as_bytes(value: &Value) -> Result<&[u8], LauncherError> {
    match value {
        Value::Bytes(value) => Ok(value),
        _ => Err(LauncherError::Malformed),
    }
}

fn as_unsigned(value: &Value) -> Result<u64, LauncherError> {
    match value {
        Value::Unsigned(value) => Ok(*value),
        _ => Err(LauncherError::Malformed),
    }
}

fn as_u32(value: &Value) -> Result<u32, LauncherError> {
    u32::try_from(as_unsigned(value)?).map_err(|_| LauncherError::Malformed)
}

const fn access_rank(access: LandlockAccess) -> u8 {
    match access {
        LandlockAccess::Read => 0,
        LandlockAccess::Write => 1,
        LandlockAccess::Execute => 2,
    }
}

const fn access_name(access: LandlockAccess) -> &'static str {
    match access {
        LandlockAccess::Read => "read",
        LandlockAccess::Write => "write",
        LandlockAccess::Execute => "execute",
    }
}

fn parse_access(value: &str) -> Result<LandlockAccess, LauncherError> {
    match value {
        "read" => Ok(LandlockAccess::Read),
        "write" => Ok(LandlockAccess::Write),
        "execute" => Ok(LandlockAccess::Execute),
        _ => Err(LauncherError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTACK_CATALOG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/attacks/launcher/protocol-v1.toml"
    ));

    fn identity(seed: u8) -> LauncherIdentity {
        let mut execution = [seed; 16];
        execution[6] = 0x40;
        execution[8] = 0x80;
        LauncherIdentity::new(
            ExecutionId::from_bytes(execution).expect("fixture execution ID is version 4"),
            Sha256Digest::from_bytes([seed; 32]),
            CgroupIdentity::new(u64::from(seed), u64::from(seed) + 1),
        )
    }

    fn install_request() -> InstallRequest {
        let executable = ArtifactIdentity::new(
            ArtifactRole::RuntimeExecutable,
            Sha256Digest::from_bytes([7; 32]),
            12,
            FileMode::new(0o755).expect("fixture mode is valid"),
        );
        InstallRequest::new(
            identity(1),
            executable,
            3,
            4,
            vec!["agent".to_owned(), "--check".to_owned()],
            BTreeMap::from([
                ("LANG".to_owned(), "C.UTF-8".to_owned()),
                ("PATH".to_owned(), "/usr/bin".to_owned()),
            ]),
            vec![
                LauncherFilesystemRule::new(3, vec![LandlockAccess::Read, LandlockAccess::Execute])
                    .expect("fixture rule is valid"),
                LauncherFilesystemRule::new(5, vec![LandlockAccess::Read])
                    .expect("fixture rule is valid"),
            ],
            vec![1, 2, 3, 4],
            32,
        )
        .expect("fixture request is valid")
    }

    fn install_message() -> LauncherMessage {
        LauncherMessage::Install(install_request())
    }

    #[test]
    fn all_message_variants_round_trip_canonically() {
        let identity = identity(1);
        let messages = [
            install_message(),
            LauncherMessage::BoundaryInstalled(BoundaryInstalled { identity }),
            LauncherMessage::Failure(
                LauncherFailure::new(identity, LauncherStage::Landlock, "landlock.denied")
                    .expect("fixture failure is valid"),
            ),
        ];
        for message in messages {
            let first = encode_launcher_message(&message).expect("message encodes");
            let decoded = decode_launcher_message(&first).expect("canonical message decodes");
            let second = encode_launcher_message(&decoded).expect("decoded message re-encodes");
            assert_eq!(decoded, message);
            assert_eq!(second, first);
        }
    }

    #[test]
    fn protocol_rejects_empty_truncated_malformed_and_trailing_frames() {
        assert_eq!(decode_launcher_message(&[]), Err(LauncherError::Eof));

        let mut truncated = encode_launcher_message(&install_message()).expect("fixture encodes");
        truncated.pop();
        assert_eq!(
            decode_launcher_message(&truncated),
            Err(LauncherError::Truncated)
        );
        assert_eq!(
            decode_launcher_message(&[0x1c]),
            Err(LauncherError::Malformed)
        );

        let mut trailing = encode_launcher_message(&install_message()).expect("fixture encodes");
        trailing.push(0);
        assert_eq!(
            decode_launcher_message(&trailing),
            Err(LauncherError::TrailingData)
        );
    }

    #[test]
    fn protocol_rejects_noncanonical_and_duplicate_map_keys() {
        let canonical = encode_launcher_message(&install_message()).expect("fixture encodes");
        assert_eq!(canonical[0], 0xac);

        let mut noncanonical = vec![0xb8, 12];
        noncanonical.extend_from_slice(&canonical[1..]);
        assert_eq!(
            decode_launcher_message(&noncanonical),
            Err(LauncherError::NonCanonical)
        );

        let mut duplicate = canonical;
        duplicate[0] = 0xad;
        encode_value(&text("schema"), &mut duplicate).expect("duplicate key encodes");
        encode_value(&text(INSTALL_SCHEMA), &mut duplicate).expect("duplicate value encodes");
        assert_eq!(
            decode_launcher_message(&duplicate),
            Err(LauncherError::DuplicateKey)
        );

        let mut value = message_to_value(&install_message());
        let Value::Map(entries) = &mut value else {
            panic!("install message must be a map");
        };
        let (_, Value::Array(rules)) = entries
            .iter_mut()
            .find(|(key, _)| key == "filesystem")
            .expect("filesystem exists")
        else {
            panic!("filesystem must be an array");
        };
        rules.reverse();
        let mut reordered_rules = Vec::new();
        encode_value(&value, &mut reordered_rules).expect("mutated value encodes");
        assert_eq!(
            decode_launcher_message(&reordered_rules),
            Err(LauncherError::NonCanonical)
        );
    }

    #[test]
    fn protocol_rejects_unknown_schema_versions() {
        let mut value = message_to_value(&install_message());
        let Value::Map(entries) = &mut value else {
            panic!("install message must be a map");
        };
        let schema = entries
            .iter_mut()
            .find(|(key, _)| key == "schema")
            .expect("schema exists");
        schema.1 = text("proofbound-runtime-launcher-install/2");
        let mut bytes = Vec::new();
        encode_value(&value, &mut bytes).expect("mutated value encodes");
        assert_eq!(
            decode_launcher_message(&bytes),
            Err(LauncherError::UnsupportedVersion)
        );
    }

    #[test]
    fn install_request_rejects_descriptors_outside_the_retained_range() {
        let mut request = install_request();
        request.close_file_descriptors_from = request.executable_fd;
        assert_eq!(
            InstallRequest::new(
                request.identity,
                request.executable_id,
                request.executable_fd,
                request.working_directory_fd,
                request.arguments,
                request.environment,
                request.filesystem,
                request.seccomp_program,
                request.close_file_descriptors_from,
            ),
            Err(LauncherError::Malformed)
        );
    }

    #[test]
    fn install_request_requires_exact_executable_read_execute_closure() {
        fn rebuild(request: InstallRequest) -> Result<InstallRequest, LauncherError> {
            InstallRequest::new(
                request.identity,
                request.executable_id,
                request.executable_fd,
                request.working_directory_fd,
                request.arguments,
                request.environment,
                request.filesystem,
                request.seccomp_program,
                request.close_file_descriptors_from,
            )
        }

        let mut execute_only = install_request();
        execute_only.filesystem[0] = LauncherFilesystemRule::new(3, vec![LandlockAccess::Execute])
            .expect("execute-only rule is structurally valid");
        assert_eq!(rebuild(execute_only), Err(LauncherError::Malformed));

        let mut writable = install_request();
        writable.filesystem[0] = LauncherFilesystemRule::new(
            3,
            vec![
                LandlockAccess::Read,
                LandlockAccess::Write,
                LandlockAccess::Execute,
            ],
        )
        .expect("writable executable rule is structurally valid");
        assert_eq!(rebuild(writable), Err(LauncherError::Malformed));

        let mut wrong_descriptor = install_request();
        wrong_descriptor.filesystem[0] =
            LauncherFilesystemRule::new(6, vec![LandlockAccess::Read, LandlockAccess::Execute])
                .expect("wrong-descriptor rule is structurally valid");
        assert_eq!(rebuild(wrong_descriptor), Err(LauncherError::Malformed));
    }

    #[test]
    fn retained_descriptor_set_is_exact_not_threshold_based() {
        let request = install_request();
        let retained = core::iter::once(request.executable_fd())
            .chain(core::iter::once(request.working_directory_fd()))
            .chain(request.filesystem().iter().map(|rule| rule.descriptor()))
            .collect::<Vec<_>>();
        assert!(retained.iter().all(|descriptor| {
            *descriptor >= 3 && *descriptor < request.close_file_descriptors_from()
        }));
        assert!(
            (3..request.close_file_descriptors_from())
                .any(|descriptor| !retained.contains(&descriptor))
        );
    }

    #[test]
    fn every_identity_substitution_has_a_distinct_failure() {
        let expected = identity(1);
        let execution = LauncherIdentity::new(
            identity(2).execution_id(),
            expected.policy_id(),
            expected.cgroup_id(),
        );
        let policy = LauncherIdentity::new(
            expected.execution_id(),
            identity(2).policy_id(),
            expected.cgroup_id(),
        );
        let cgroup = LauncherIdentity::new(
            expected.execution_id(),
            expected.policy_id(),
            identity(2).cgroup_id(),
        );
        assert_eq!(
            execution.verify(expected),
            Err(LauncherError::ExecutionIdentityMismatch)
        );
        assert_eq!(
            policy.verify(expected),
            Err(LauncherError::PolicyIdentityMismatch)
        );
        assert_eq!(
            cgroup.verify(expected),
            Err(LauncherError::CgroupIdentityMismatch)
        );
    }

    #[test]
    fn sequence_rejects_acknowledgement_forgery_and_omission() {
        assert_eq!(
            advance_sequence(
                SequenceState::InstallValidated,
                SequenceEvent::AcknowledgementEmitted,
            ),
            Err(LauncherError::BoundaryNotInstalled)
        );
        assert_eq!(
            advance_sequence(
                SequenceState::BoundariesInstalled,
                SequenceEvent::ExecAuthorized,
            ),
            Err(LauncherError::AcknowledgementMissing)
        );
    }

    #[test]
    fn unsupported_hosts_never_create_a_channel_or_positive_pause_evidence() {
        if !cfg!(target_os = "linux") {
            assert!(matches!(
                LauncherChannel::pair(),
                Err(LauncherError::UnsupportedOperatingSystem)
            ));
            assert_eq!(
                pause_for_supervisor(),
                Err(LauncherError::UnsupportedOperatingSystem)
            );
        }
    }

    #[test]
    fn frozen_launcher_attack_catalog_is_closed() {
        let expected_ids = [
            "empty-channel",
            "truncated-install-request",
            "malformed-cbor",
            "non-canonical-cbor",
            "duplicate-map-key",
            "trailing-data",
            "unknown-version",
            "policy-substitution",
            "cgroup-substitution",
            "execution-substitution",
            "acknowledgement-forgery",
            "acknowledgement-omission",
            "executable-closure-substitution",
        ];
        assert!(ATTACK_CATALOG.starts_with("schema = \"proofbound-runtime-launcher-attacks/1\""));
        assert_eq!(
            ATTACK_CATALOG.matches("[[cases]]").count(),
            expected_ids.len()
        );
        for id in expected_ids {
            assert!(ATTACK_CATALOG.contains(&format!("id = \"{id}\"")));
        }
    }

    #[test]
    fn error_codes_are_unique_and_stable() {
        let mut codes = [
            LauncherError::UnsupportedOperatingSystem,
            LauncherError::ChannelCreationFailed,
            LauncherError::ChannelReadFailed,
            LauncherError::ChannelTimeout,
            LauncherError::ChannelWriteFailed,
            LauncherError::PauseFailed,
            LauncherError::Eof,
            LauncherError::Truncated,
            LauncherError::FrameTooLarge,
            LauncherError::Malformed,
            LauncherError::NonCanonical,
            LauncherError::DuplicateKey,
            LauncherError::TrailingData,
            LauncherError::UnsupportedVersion,
            LauncherError::PolicyIdentityMismatch,
            LauncherError::CgroupIdentityMismatch,
            LauncherError::ExecutionIdentityMismatch,
            LauncherError::SeccompProgramMismatch,
            LauncherError::FileDescriptorInvalid,
            LauncherError::ExecutableIdentityMismatch,
            LauncherError::PrivilegeInstallationFailed,
            LauncherError::LandlockInstallationFailed,
            LauncherError::SeccompInstallationFailed,
            LauncherError::WorkingDirectoryFailed,
            LauncherError::ExecPermissionDenied,
            LauncherError::ExecOperationNotPermitted,
            LauncherError::ExecNotFound,
            LauncherError::ExecFormatInvalid,
            LauncherError::ExecFailed,
            LauncherError::BoundaryNotInstalled,
            LauncherError::AcknowledgementMissing,
            LauncherError::UnexpectedMessage,
        ]
        .map(LauncherError::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
    }
}
