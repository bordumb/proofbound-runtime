//! Supervises one paused launcher, bounded streams, timeout, and cleanup.

use core::fmt;
#[cfg(any(test, target_os = "linux"))]
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;

use proofbound_runtime_core::{
    BoundaryInstallation, ExecutionOutcome, ResourceLimits, StreamCapture,
};
#[cfg(any(test, target_os = "linux"))]
use proofbound_runtime_core::{OutputByteLimit, SignalNumber};

use crate::{FreshCgroup, InstallRequest, LauncherError, LauncherFailure, LauncherIdentity};
#[cfg(target_os = "linux")]
use crate::{LauncherChannel, LauncherMessage};

#[cfg(target_os = "linux")]
const SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_millis(1);
#[cfg(any(test, target_os = "linux"))]
const LINUX_SIGNAL_SYS: u32 = 31;

/// Contains one bounded standard-stream capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedStream {
    bytes: Vec<u8>,
    capture: StreamCapture,
}

impl CapturedStream {
    /// Returns the retained prefix of the observed stream.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reports whether bytes after the retained prefix were discarded.
    #[must_use]
    pub const fn capture(&self) -> StreamCapture {
        self.capture
    }
}

/// Contains the complete observable result of one supervised process tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisedExecution {
    boundary: BoundaryInstallation,
    outcome: ExecutionOutcome,
    stdout: CapturedStream,
    stderr: CapturedStream,
    launcher_failure: Option<LauncherFailure>,
    elapsed: Duration,
    timings: SupervisorTimings,
}

impl SupervisedExecution {
    /// Returns the observed boundary acknowledgement state.
    #[must_use]
    pub const fn boundary(&self) -> BoundaryInstallation {
        self.boundary
    }

    /// Returns the closed execution outcome.
    #[must_use]
    pub const fn outcome(&self) -> ExecutionOutcome {
        self.outcome
    }

    /// Returns the bounded standard-output capture.
    #[must_use]
    pub const fn stdout(&self) -> &CapturedStream {
        &self.stdout
    }

    /// Returns the bounded standard-error capture.
    #[must_use]
    pub const fn stderr(&self) -> &CapturedStream {
        &self.stderr
    }

    /// Returns a typed pre-exec launcher failure, if one was reported.
    #[must_use]
    pub const fn launcher_failure(&self) -> Option<&LauncherFailure> {
        self.launcher_failure.as_ref()
    }

    /// Returns elapsed monotonic supervisor time.
    #[must_use]
    pub const fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Returns non-overlapping operational timings for the supervisor phases.
    #[must_use]
    pub const fn timings(&self) -> SupervisorTimings {
        self.timings
    }
}

/// Non-overlapping operational timings for one successful supervisor return.
///
/// These values are benchmark telemetry only. They are not receipt facts or
/// launcher-protocol fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisorTimings {
    launcher_creation: Duration,
    boundary_installation: Duration,
    process_execution: Duration,
    cleanup: Duration,
    stream_collection: Duration,
}

impl SupervisorTimings {
    const fn new(
        launcher_creation: Duration,
        boundary_installation: Duration,
        process_execution: Duration,
        cleanup: Duration,
        stream_collection: Duration,
    ) -> Self {
        Self {
            launcher_creation,
            boundary_installation,
            process_execution,
            cleanup,
            stream_collection,
        }
    }

    /// Returns time through creation and observation of the stopped launcher.
    #[must_use]
    pub const fn launcher_creation(self) -> Duration {
        self.launcher_creation
    }

    /// Returns time from the stopped launcher through its boundary response.
    #[must_use]
    pub const fn boundary_installation(self) -> Duration {
        self.boundary_installation
    }

    /// Returns time from the boundary response through terminal child status.
    #[must_use]
    pub const fn process_execution(self) -> Duration {
        self.process_execution
    }

    /// Returns time spent draining the exact cgroup and waiting for the child.
    #[must_use]
    pub const fn cleanup(self) -> Duration {
        self.cleanup
    }

    /// Returns time spent joining the already-running bounded stream drains.
    #[must_use]
    pub const fn stream_collection(self) -> Duration {
        self.stream_collection
    }

    /// Returns the sum of all reported non-overlapping intervals.
    #[must_use]
    pub fn total(self) -> Duration {
        [
            self.launcher_creation,
            self.boundary_installation,
            self.process_execution,
            self.cleanup,
            self.stream_collection,
        ]
        .into_iter()
        .fold(Duration::ZERO, Duration::saturating_add)
    }
}

/// Identifies one supervisor lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorError {
    /// The host operating system is not Linux.
    UnsupportedOperatingSystem,
    /// A declared inherited descriptor was absent or duplicated.
    DescriptorSetInvalid,
    /// The launcher process could not be created.
    SpawnFailed,
    /// The launcher did not enter its initial stopped state.
    PauseNotObserved,
    /// The stopped launcher could not be placed in the fresh cgroup.
    CgroupPlacementFailed,
    /// The launcher could not be resumed after cgroup placement.
    ResumeFailed,
    /// The private install request could not be sent.
    ProtocolSendFailed,
    /// The launcher acknowledgement was absent or invalid.
    ProtocolFailed,
    /// The child process status could not be observed.
    WaitFailed,
    /// A standard-stream reader failed or panicked.
    StreamReadFailed,
    /// The process tree or fresh cgroup could not be cleaned up.
    CleanupFailed,
}

impl SupervisorError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "supervisor.os.unsupported",
            Self::DescriptorSetInvalid => "supervisor.descriptor-set.invalid",
            Self::SpawnFailed => "supervisor.spawn.failed",
            Self::PauseNotObserved => "supervisor.pause.not-observed",
            Self::CgroupPlacementFailed => "supervisor.cgroup.placement-failed",
            Self::ResumeFailed => "supervisor.resume.failed",
            Self::ProtocolSendFailed => "supervisor.protocol.send-failed",
            Self::ProtocolFailed => "supervisor.protocol.failed",
            Self::WaitFailed => "supervisor.wait.failed",
            Self::StreamReadFailed => "supervisor.stream.read-failed",
            Self::CleanupFailed => "supervisor.cleanup.failed",
        }
    }
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for SupervisorError {}

/// Starts the identified runtime binary in hidden launcher mode and supervises it.
///
/// Every descriptor in `inherited_descriptors` stays close-on-exec in the
/// supervisor. A child-only pre-exec hook clears that flag before the trusted
/// launcher image starts.
pub fn supervise_launcher(
    launcher_program: &Path,
    request: InstallRequest,
    cgroup: FreshCgroup,
    limits: ResourceLimits,
    inherited_descriptors: &[std::os::fd::BorrowedFd<'_>],
    architecture: crate::Architecture,
    landlock_abi: core::num::NonZeroU32,
) -> Result<SupervisedExecution, SupervisorError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        use std::process::{Command, Stdio};

        validate_descriptor_set(&request, inherited_descriptors)?;
        if request.identity().cgroup_id() != cgroup.identity()
            || request.close_file_descriptors_from() <= 2
        {
            return Err(SupervisorError::DescriptorSetInvalid);
        }
        let start = std::time::Instant::now();
        let deadline = start
            .checked_add(Duration::from_millis(limits.wall_time().milliseconds()))
            .ok_or(SupervisorError::WaitFailed)?;
        let (supervisor_channel, launcher_channel) =
            LauncherChannel::pair().map_err(|_| SupervisorError::SpawnFailed)?;
        let launcher_channel_fd = launcher_channel.as_fd().as_raw_fd();
        let mut command = Command::new(launcher_program);
        command
            .args(bootstrap_arguments(
                launcher_channel_fd,
                request.identity(),
                architecture,
                landlock_abi,
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut inherited = inherited_descriptors
            .iter()
            .map(|descriptor| descriptor.as_raw_fd())
            .collect::<Vec<_>>();
        inherited.push(launcher_channel_fd);
        crate::sys::inherit_descriptors_for_exec(&mut command, inherited);
        let child = command.spawn().map_err(|_| SupervisorError::SpawnFailed)?;
        let mut child = ChildGuard(child);
        drop(launcher_channel);

        let stdout = child.0.stdout.take().ok_or(SupervisorError::SpawnFailed)?;
        let stderr = child.0.stderr.take().ok_or(SupervisorError::SpawnFailed)?;
        let stdout_reader = spawn_capture(stdout, limits.stdout())
            .map_err(|_| SupervisorError::StreamReadFailed)?;
        let stderr_reader = spawn_capture(stderr, limits.stderr())
            .map_err(|_| SupervisorError::StreamReadFailed)?;

        let lifecycle = supervise_lifecycle(
            &mut child.0,
            &supervisor_channel,
            &request,
            &cgroup,
            deadline,
            start,
        );
        if lifecycle.is_err() {
            let _ = child.0.kill();
        }
        let cleanup_start = std::time::Instant::now();
        let cleanup = cgroup.cleanup();
        let _ = child.0.wait();
        let cleanup_elapsed = cleanup_start.elapsed();
        let stream_start = std::time::Instant::now();
        let stdout = join_capture(stdout_reader)?;
        let stderr = join_capture(stderr_reader)?;
        let stream_collection_elapsed = stream_start.elapsed();
        if cleanup.is_err() {
            return Err(SupervisorError::CleanupFailed);
        }
        let lifecycle = lifecycle?;
        Ok(SupervisedExecution {
            boundary: lifecycle.boundary,
            outcome: lifecycle.outcome,
            stdout,
            stderr,
            launcher_failure: lifecycle.launcher_failure,
            elapsed: start.elapsed(),
            timings: SupervisorTimings::new(
                lifecycle.launcher_creation,
                lifecycle.boundary_installation,
                lifecycle.process_execution,
                cleanup_elapsed,
                stream_collection_elapsed,
            ),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            launcher_program,
            request,
            cgroup,
            limits,
            inherited_descriptors,
            architecture,
            landlock_abi,
        );
        Err(SupervisorError::UnsupportedOperatingSystem)
    }
}

#[cfg(target_os = "linux")]
struct LifecycleResult {
    boundary: BoundaryInstallation,
    outcome: ExecutionOutcome,
    launcher_failure: Option<LauncherFailure>,
    launcher_creation: Duration,
    boundary_installation: Duration,
    process_execution: Duration,
}

#[cfg(target_os = "linux")]
struct ChildGuard(std::process::Child);

#[cfg(target_os = "linux")]
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(target_os = "linux")]
fn validate_descriptor_set(
    request: &InstallRequest,
    descriptors: &[std::os::fd::BorrowedFd<'_>],
) -> Result<(), SupervisorError> {
    use std::os::fd::AsRawFd as _;

    let mut actual = descriptors
        .iter()
        .map(|descriptor| descriptor.as_raw_fd())
        .collect::<Vec<_>>();
    actual.sort_unstable();
    if actual.iter().any(|descriptor| *descriptor < 0)
        || actual.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(SupervisorError::DescriptorSetInvalid);
    }
    let mut required = core::iter::once(request.executable_fd())
        .chain(core::iter::once(request.working_directory_fd()))
        .chain(request.filesystem().iter().map(|rule| rule.descriptor()))
        .map(|descriptor| {
            i32::try_from(descriptor).map_err(|_| SupervisorError::DescriptorSetInvalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    required.sort_unstable();
    required.dedup();
    if actual != required {
        return Err(SupervisorError::DescriptorSetInvalid);
    }
    Ok(())
}

/// Contains the closed hidden-launcher bootstrap arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LauncherBootstrap {
    channel_descriptor: u32,
    identity: LauncherIdentity,
    architecture: crate::Architecture,
    landlock_abi: core::num::NonZeroU32,
}

impl LauncherBootstrap {
    /// Returns the inherited private-channel descriptor.
    #[must_use]
    pub const fn channel_descriptor(self) -> u32 {
        self.channel_descriptor
    }

    /// Returns the independently supplied execution identity tuple.
    #[must_use]
    pub const fn identity(self) -> LauncherIdentity {
        self.identity
    }

    /// Returns the supported audit architecture.
    #[must_use]
    pub const fn architecture(self) -> crate::Architecture {
        self.architecture
    }

    /// Returns the reviewed Landlock ABI.
    #[must_use]
    pub const fn landlock_abi(self) -> core::num::NonZeroU32 {
        self.landlock_abi
    }
}

/// Parses the closed hidden-launcher command-line bootstrap.
pub fn parse_launcher_bootstrap(args: &[String]) -> Result<LauncherBootstrap, LauncherError> {
    if args.len() != 8 || args[0] != "__proofbound_launcher_v1" {
        return Err(LauncherError::Malformed);
    }
    let channel_descriptor = args[1]
        .parse::<u32>()
        .map_err(|_| LauncherError::Malformed)?;
    let execution_bytes = decode_hex::<16>(&args[2])?;
    let execution_id = proofbound_runtime_core::ExecutionId::from_bytes(execution_bytes)
        .map_err(|_| LauncherError::Malformed)?;
    let policy_id = proofbound_runtime_core::Sha256Digest::from_bytes(decode_hex::<32>(&args[3])?);
    let mount_id = args[4]
        .parse::<u64>()
        .map_err(|_| LauncherError::Malformed)?;
    let inode = args[5]
        .parse::<u64>()
        .map_err(|_| LauncherError::Malformed)?;
    let architecture = match args[6].as_str() {
        "x86_64" => crate::Architecture::X86_64,
        "aarch64" => crate::Architecture::Aarch64,
        _ => return Err(LauncherError::Malformed),
    };
    let landlock_abi = args[7]
        .parse::<core::num::NonZeroU32>()
        .map_err(|_| LauncherError::Malformed)?;
    Ok(LauncherBootstrap {
        channel_descriptor,
        identity: LauncherIdentity::new(
            execution_id,
            policy_id,
            proofbound_runtime_core::CgroupIdentity::new(mount_id, inode),
        ),
        architecture,
        landlock_abi,
    })
}

#[cfg(any(test, target_os = "linux"))]
fn bootstrap_arguments(
    channel_descriptor: i32,
    identity: LauncherIdentity,
    architecture: crate::Architecture,
    landlock_abi: core::num::NonZeroU32,
) -> Vec<String> {
    vec![
        "__proofbound_launcher_v1".to_owned(),
        channel_descriptor.to_string(),
        encode_hex(identity.execution_id().as_bytes()),
        encode_hex(identity.policy_id().as_bytes()),
        identity.cgroup_id().mount_id().to_string(),
        identity.cgroup_id().inode().to_string(),
        architecture.as_str().to_owned(),
        landlock_abi.to_string(),
    ]
}

#[cfg(any(test, target_os = "linux"))]
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex<const SIZE: usize>(value: &str) -> Result<[u8; SIZE], LauncherError> {
    if value.len() != SIZE * 2 {
        return Err(LauncherError::Malformed);
    }
    let mut decoded = [0; SIZE];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> Result<u8, LauncherError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(LauncherError::Malformed),
    }
}

#[cfg(target_os = "linux")]
fn supervise_lifecycle(
    child: &mut std::process::Child,
    channel: &LauncherChannel,
    request: &InstallRequest,
    cgroup: &FreshCgroup,
    deadline: std::time::Instant,
    supervisor_start: std::time::Instant,
) -> Result<LifecycleResult, SupervisorError> {
    wait_for_pause(child.id(), deadline)?;
    let launcher_ready = std::time::Instant::now();
    cgroup
        .place_process(child.id())
        .map_err(|_| SupervisorError::CgroupPlacementFailed)?;
    crate::sys::continue_process(child.id()).map_err(|_| SupervisorError::ResumeFailed)?;
    channel
        .send(&LauncherMessage::Install(request.clone()))
        .map_err(|_| SupervisorError::ProtocolSendFailed)?;
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let response = match channel.receive_timeout(remaining) {
        Ok(response) => response,
        Err(LauncherError::ChannelTimeout) => {
            let _ = child.kill();
            let boundary_complete = std::time::Instant::now();
            return Ok(LifecycleResult {
                boundary: BoundaryInstallation::Incomplete,
                outcome: ExecutionOutcome::TimedOut,
                launcher_failure: None,
                launcher_creation: launcher_ready.duration_since(supervisor_start),
                boundary_installation: boundary_complete.duration_since(launcher_ready),
                process_execution: Duration::ZERO,
            });
        }
        Err(_) => return Err(SupervisorError::ProtocolFailed),
    };
    crate::verify_launcher_response(&response, request.identity())
        .map_err(|_| SupervisorError::ProtocolFailed)?;
    let boundary_complete = std::time::Instant::now();
    match response {
        LauncherMessage::BoundaryInstalled(_) => {
            let outcome = monitor_process(child, deadline)?;
            let launcher_failure = receive_late_failure(channel, request.identity())?;
            let process_complete = std::time::Instant::now();
            if launcher_failure.is_some() {
                Ok(LifecycleResult {
                    boundary: BoundaryInstallation::Installed,
                    outcome: ExecutionOutcome::LauncherFailed,
                    launcher_failure,
                    launcher_creation: launcher_ready.duration_since(supervisor_start),
                    boundary_installation: boundary_complete.duration_since(launcher_ready),
                    process_execution: process_complete.duration_since(boundary_complete),
                })
            } else {
                Ok(LifecycleResult {
                    boundary: BoundaryInstallation::Installed,
                    outcome,
                    launcher_failure: None,
                    launcher_creation: launcher_ready.duration_since(supervisor_start),
                    boundary_installation: boundary_complete.duration_since(launcher_ready),
                    process_execution: process_complete.duration_since(boundary_complete),
                })
            }
        }
        LauncherMessage::Failure(failure) => {
            let _ = monitor_process(child, deadline)?;
            let process_complete = std::time::Instant::now();
            Ok(LifecycleResult {
                boundary: BoundaryInstallation::Incomplete,
                outcome: ExecutionOutcome::LauncherFailed,
                launcher_failure: Some(failure),
                launcher_creation: launcher_ready.duration_since(supervisor_start),
                boundary_installation: boundary_complete.duration_since(launcher_ready),
                process_execution: process_complete.duration_since(boundary_complete),
            })
        }
        LauncherMessage::Install(_) => Err(SupervisorError::ProtocolFailed),
    }
}

#[cfg(target_os = "linux")]
fn wait_for_pause(process_id: u32, deadline: std::time::Instant) -> Result<(), SupervisorError> {
    loop {
        if crate::sys::process_is_stopped(process_id)
            .map_err(|_| SupervisorError::PauseNotObserved)?
        {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(SupervisorError::PauseNotObserved);
        }
        std::thread::sleep(SUPERVISOR_POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
fn monitor_process(
    child: &mut std::process::Child,
    deadline: std::time::Instant,
) -> Result<ExecutionOutcome, SupervisorError> {
    use std::os::unix::process::ExitStatusExt as _;

    loop {
        if let Some(status) = child.try_wait().map_err(|_| SupervisorError::WaitFailed)? {
            let signal = status.signal().and_then(|value| u32::try_from(value).ok());
            return Ok(classify_process_result(status.code(), signal, false, false));
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            return Ok(ExecutionOutcome::TimedOut);
        }
        std::thread::sleep(SUPERVISOR_POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
fn receive_late_failure(
    channel: &LauncherChannel,
    expected: LauncherIdentity,
) -> Result<Option<LauncherFailure>, SupervisorError> {
    match channel.receive_timeout(Duration::ZERO) {
        Ok(LauncherMessage::Failure(failure)) => {
            crate::verify_launcher_response(&LauncherMessage::Failure(failure.clone()), expected)
                .map_err(|_| SupervisorError::ProtocolFailed)?;
            Ok(Some(failure))
        }
        Ok(_) => Err(SupervisorError::ProtocolFailed),
        Err(LauncherError::ChannelTimeout | LauncherError::Eof) => Ok(None),
        Err(_) => Err(SupervisorError::ProtocolFailed),
    }
}

#[cfg(any(test, target_os = "linux"))]
fn classify_process_result(
    exit_code: Option<i32>,
    signal: Option<u32>,
    timed_out: bool,
    launcher_failed: bool,
) -> ExecutionOutcome {
    if launcher_failed {
        ExecutionOutcome::LauncherFailed
    } else if timed_out {
        ExecutionOutcome::TimedOut
    } else if signal == Some(LINUX_SIGNAL_SYS) {
        ExecutionOutcome::Denied
    } else if let Some(signal) = signal.and_then(SignalNumber::new) {
        ExecutionOutcome::Signaled { signal }
    } else if let Some(code) = exit_code {
        ExecutionOutcome::Exited { code }
    } else {
        ExecutionOutcome::Incomplete
    }
}

#[cfg(target_os = "linux")]
fn spawn_capture<R>(
    reader: R,
    limit: OutputByteLimit,
) -> io::Result<std::thread::JoinHandle<io::Result<CapturedStream>>>
where
    R: Read + Send + 'static,
{
    std::thread::Builder::new()
        .name("proofbound-stream-drain".to_owned())
        .spawn(move || capture_stream(reader, limit))
}

#[cfg(target_os = "linux")]
fn join_capture(
    handle: std::thread::JoinHandle<io::Result<CapturedStream>>,
) -> Result<CapturedStream, SupervisorError> {
    handle
        .join()
        .map_err(|_| SupervisorError::StreamReadFailed)?
        .map_err(|_| SupervisorError::StreamReadFailed)
}

#[cfg(any(test, target_os = "linux"))]
fn capture_stream(mut reader: impl Read, limit: OutputByteLimit) -> io::Result<CapturedStream> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut buffer = [0; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = limit
            .get()
            .saturating_sub(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let retained = count.min(usize::try_from(remaining).unwrap_or(usize::MAX));
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained < count;
    }
    Ok(CapturedStream {
        bytes,
        capture: if truncated {
            StreamCapture::Truncated
        } else {
            StreamCapture::Complete
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofbound_runtime_core::{CgroupIdentity, ExecutionId, Sha256Digest};

    const ATTACK_CATALOG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/attacks/supervisor/lifecycle-v1.toml"
    ));

    fn identity() -> LauncherIdentity {
        let mut execution = [3; 16];
        execution[6] = 0x40;
        execution[8] = 0x80;
        LauncherIdentity::new(
            ExecutionId::from_bytes(execution).expect("fixture execution ID is version 4"),
            Sha256Digest::from_bytes([4; 32]),
            CgroupIdentity::new(5, 6),
        )
    }

    #[test]
    fn bounded_capture_retains_prefix_and_drains_the_complete_input() {
        let complete =
            capture_stream(&b"abc"[..], OutputByteLimit::new(3)).expect("capture must succeed");
        assert_eq!(complete.bytes(), b"abc");
        assert_eq!(complete.capture(), StreamCapture::Complete);

        let truncated =
            capture_stream(&b"abcdef"[..], OutputByteLimit::new(3)).expect("capture must succeed");
        assert_eq!(truncated.bytes(), b"abc");
        assert_eq!(truncated.capture(), StreamCapture::Truncated);

        let zero =
            capture_stream(&b"x"[..], OutputByteLimit::new(0)).expect("capture must succeed");
        assert!(zero.bytes().is_empty());
        assert_eq!(zero.capture(), StreamCapture::Truncated);
    }

    #[test]
    fn outcome_classification_is_closed_and_precedence_is_explicit() {
        assert_eq!(
            classify_process_result(Some(0), None, false, false),
            ExecutionOutcome::Exited { code: 0 }
        );
        assert_eq!(
            classify_process_result(None, Some(9), false, false),
            ExecutionOutcome::Signaled {
                signal: SignalNumber::new(9).expect("signal is nonzero"),
            }
        );
        assert_eq!(
            classify_process_result(None, Some(LINUX_SIGNAL_SYS), false, false),
            ExecutionOutcome::Denied
        );
        assert_eq!(
            classify_process_result(Some(0), None, true, false),
            ExecutionOutcome::TimedOut
        );
        assert_eq!(
            classify_process_result(Some(0), None, true, true),
            ExecutionOutcome::LauncherFailed
        );
        assert_eq!(
            classify_process_result(None, None, false, false),
            ExecutionOutcome::Incomplete
        );
    }

    #[test]
    fn supervisor_timings_preserve_non_overlapping_phase_intervals() {
        let timings = SupervisorTimings::new(
            Duration::from_nanos(11),
            Duration::from_nanos(13),
            Duration::from_nanos(17),
            Duration::from_nanos(19),
            Duration::from_nanos(23),
        );

        assert_eq!(timings.launcher_creation(), Duration::from_nanos(11));
        assert_eq!(timings.boundary_installation(), Duration::from_nanos(13));
        assert_eq!(timings.process_execution(), Duration::from_nanos(17));
        assert_eq!(timings.cleanup(), Duration::from_nanos(19));
        assert_eq!(timings.stream_collection(), Duration::from_nanos(23));
        assert_eq!(
            timings.total(),
            Duration::from_nanos(11 + 13 + 17 + 19 + 23)
        );
    }

    #[test]
    fn hidden_launcher_bootstrap_round_trips_exactly() {
        let identity = identity();
        let arguments = bootstrap_arguments(
            9,
            identity,
            crate::Architecture::Aarch64,
            core::num::NonZeroU32::new(11).expect("ABI is nonzero"),
        );
        let decoded = parse_launcher_bootstrap(&arguments).expect("bootstrap parses");
        assert_eq!(decoded.channel_descriptor(), 9);
        assert_eq!(decoded.identity(), identity);
        assert_eq!(decoded.architecture(), crate::Architecture::Aarch64);
        assert_eq!(decoded.landlock_abi().get(), 11);

        let mut noncanonical = arguments;
        noncanonical[3].replace_range(0..1, "A");
        assert_eq!(
            parse_launcher_bootstrap(&noncanonical),
            Err(LauncherError::Malformed)
        );
    }

    #[test]
    fn frozen_supervisor_attack_catalog_is_closed() {
        let expected_ids = [
            "launcher-not-paused",
            "launcher-not-in-cgroup",
            "missing-boundary-acknowledgement",
            "extra-inherited-descriptor",
            "declared-descriptor-leak",
            "stdout-over-limit",
            "stderr-over-limit",
            "wall-time-over-limit",
            "seccomp-sigsys",
            "ordinary-signal",
            "lingering-descendant",
        ];
        assert!(ATTACK_CATALOG.starts_with("schema = \"proofbound-runtime-supervisor-attacks/1\""));
        assert_eq!(
            ATTACK_CATALOG.matches("[[attack]]").count(),
            expected_ids.len()
        );
        for id in expected_ids {
            assert!(ATTACK_CATALOG.contains(&format!("id = \"{id}\"")));
        }
    }

    #[test]
    fn error_codes_are_unique_and_stable() {
        let mut codes = [
            SupervisorError::UnsupportedOperatingSystem,
            SupervisorError::DescriptorSetInvalid,
            SupervisorError::SpawnFailed,
            SupervisorError::PauseNotObserved,
            SupervisorError::CgroupPlacementFailed,
            SupervisorError::ResumeFailed,
            SupervisorError::ProtocolSendFailed,
            SupervisorError::ProtocolFailed,
            SupervisorError::WaitFailed,
            SupervisorError::StreamReadFailed,
            SupervisorError::CleanupFailed,
        ]
        .map(SupervisorError::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
    }
}
