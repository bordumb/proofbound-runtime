//! Starts one diagnostic trace without adding authority to the child.

use core::fmt;
use std::collections::BTreeMap;
use std::io;
use std::num::NonZeroU32;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use proofbound_runtime_core::{
    ArtifactRole, OutputByteLimit, ResourceLimits, StreamCapture, WallTimeLimit,
};

use crate::{
    Architecture, ExecRelease, FreshCgroup, InstallRequest, LauncherChannel, LauncherError,
    LauncherMessage, ResolvedFile, ResourceObservation, TerminalResources,
};

const TRACE_POLL_INTERVAL: Duration = Duration::from_millis(1);
const TRACE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const SIGNAL_STOP: i32 = 19;
const SIGNAL_TRAP: i32 = 5;
const SIGNAL_SYSCALL: i32 = SIGNAL_TRAP | 0x80;
const MAX_TRACE_PROCESS_LIMIT: u32 = 4096;
const MAX_TRACE_PATH_BYTES: u32 = 1_048_576;
const MAX_TRACE_SOCKET_ADDRESS_BYTES: u32 = 4096;
const TRACE_MEMORY_CHUNK_BYTES: usize = 256;
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// Identifies one Linux process that can enter the trace protocol.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TraceProcessId(NonZeroU32);

impl TraceProcessId {
    /// Creates one process identifier in the Linux positive PID range.
    pub const fn new(value: u32) -> Result<Self, TraceStartupError> {
        match NonZeroU32::new(value) {
            Some(value) if value.get() <= i32::MAX as u32 => Ok(Self(value)),
            _ => Err(TraceStartupError::ProcessIdInvalid),
        }
    }

    /// Returns the operating-system process identifier.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Contains the maximum retained process count for one active trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceProcessLimit(NonZeroU32);

impl TraceProcessLimit {
    /// Creates one nonzero diagnostic process limit.
    pub const fn new(value: u64) -> Result<Self, TraceStartupError> {
        if value == 0 || value > MAX_TRACE_PROCESS_LIMIT as u64 {
            return Err(TraceStartupError::ProcessLimitInvalid);
        }
        match NonZeroU32::new(value as u32) {
            Some(value) => Ok(Self(value)),
            None => Err(TraceStartupError::ProcessLimitInvalid),
        }
    }

    /// Returns the maximum retained process count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    #[cfg(target_os = "linux")]
    const fn drain_capacity(self) -> usize {
        self.0.get() as usize * 2
    }
}

/// Contains the exact per-operand memory-read limits for one active trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceCaptureLimits {
    path_bytes: NonZeroU32,
    socket_address_bytes: NonZeroU32,
    tracee_string_bytes: NonZeroU32,
}

/// Contains the standard-stream byte limits for one diagnostic trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceOutputLimits {
    stdout: OutputByteLimit,
    stderr: OutputByteLimit,
}

impl TraceOutputLimits {
    /// Creates independent standard-output and standard-error byte limits.
    #[must_use]
    pub fn new(stdout: OutputByteLimit, stderr: OutputByteLimit) -> Self {
        Self { stdout, stderr }
    }

    /// Returns the standard-output byte limit.
    #[must_use]
    pub fn stdout(self) -> OutputByteLimit {
        self.stdout
    }

    /// Returns the standard-error byte limit.
    #[must_use]
    pub fn stderr(self) -> OutputByteLimit {
        self.stderr
    }
}

impl TraceCaptureLimits {
    /// Creates nonzero path, socket-address, and tracee-string limits in bytes.
    pub const fn new(
        path_bytes: u64,
        socket_address_bytes: u64,
        tracee_string_bytes: u64,
    ) -> Result<Self, TraceStartupError> {
        if path_bytes == 0
            || path_bytes > MAX_TRACE_PATH_BYTES as u64
            || socket_address_bytes == 0
            || socket_address_bytes > MAX_TRACE_SOCKET_ADDRESS_BYTES as u64
            || tracee_string_bytes == 0
            || tracee_string_bytes > MAX_TRACE_PATH_BYTES as u64
        {
            return Err(TraceStartupError::CaptureLimitInvalid);
        }
        let Some(path_bytes) = NonZeroU32::new(path_bytes as u32) else {
            return Err(TraceStartupError::CaptureLimitInvalid);
        };
        let Some(socket_address_bytes) = NonZeroU32::new(socket_address_bytes as u32) else {
            return Err(TraceStartupError::CaptureLimitInvalid);
        };
        let Some(tracee_string_bytes) = NonZeroU32::new(tracee_string_bytes as u32) else {
            return Err(TraceStartupError::CaptureLimitInvalid);
        };
        Ok(Self {
            path_bytes,
            socket_address_bytes,
            tracee_string_bytes,
        })
    }

    const fn path_bytes(self) -> usize {
        self.path_bytes.get() as usize
    }

    const fn socket_address_bytes(self) -> usize {
        self.socket_address_bytes.get() as usize
    }

    const fn tracee_string_bytes(self) -> usize {
        self.tracee_string_bytes.get() as usize
    }
}

/// Contains one absolute monotonic deadline for trace execution or cleanup.
#[derive(Clone, Copy, Debug)]
struct TraceDeadline(Instant);

impl TraceDeadline {
    /// Creates a deadline after one nonzero duration.
    fn after(duration: Duration) -> Result<Self, TraceStartupError> {
        if duration.is_zero() {
            return Err(TraceStartupError::DeadlineInvalid);
        }
        Instant::now()
            .checked_add(duration)
            .map(Self)
            .ok_or(TraceStartupError::DeadlineInvalid)
    }

    fn expired(self) -> bool {
        Instant::now() >= self.0
    }

    const fn instant(self) -> Instant {
        self.0
    }

    fn cleanup() -> Result<Self, TraceObservationError> {
        Instant::now()
            .checked_add(TRACE_DRAIN_TIMEOUT)
            .map(Self)
            .ok_or(TraceObservationError::DrainFailed)
    }
}

/// Contains one command and its live inherited descriptors before spawn.
#[derive(Debug)]
pub struct PreparedTraceCommand<'descriptor> {
    command: Command,
    launcher: &'descriptor ResolvedFile,
    supervisor_channel: LauncherChannel,
    launcher_channel: LauncherChannel,
    request: InstallRequest,
    cgroup: FreshCgroup,
    wall_time: WallTimeLimit,
    output_limits: TraceOutputLimits,
    _descriptors: Vec<BorrowedFd<'descriptor>>,
}

impl PreparedTraceCommand<'_> {
    /// Spawns exactly one child whose first exec requests tracing.
    pub fn spawn(mut self) -> Result<SpawnedTrace, TraceStartupError> {
        self.launcher
            .revalidate_identity()
            .map_err(|_| TraceStartupError::LauncherIdentityInvalid)?;
        self.cgroup
            .revalidate_resources()
            .map_err(|_| TraceStartupError::CgroupIdentityMismatch)?;
        self.cgroup
            .revalidate_fresh()
            .map_err(|_| TraceStartupError::CgroupNotFresh)?;
        let deadline = TraceDeadline::after(Duration::from_millis(self.wall_time.milliseconds()))?;
        let child = self
            .command
            .spawn()
            .map_err(|_| TraceStartupError::SpawnFailed)?;
        let mut child = TraceChild::new(child);
        let process = TraceProcessId::new(child.0.id())?;
        self.cgroup
            .place_process(process.get())
            .map_err(|_| TraceStartupError::CgroupPlacementFailed)?;
        let streams = TraceStreamReaders::start(&mut child, self.output_limits)?;
        drop(self.launcher_channel);
        Ok(SpawnedTrace {
            session: TraceSession {
                _child: child,
                cgroup: Some(self.cgroup),
                streams,
                process,
                channel: self.supervisor_channel,
                request: self.request,
                deadline,
            },
        })
    }
}

/// Prepares one exact launcher session whose first exec requests tracing.
pub fn prepare_traced_launcher<'descriptor>(
    launcher: &'descriptor ResolvedFile,
    request: InstallRequest,
    inherited_descriptors: &[BorrowedFd<'descriptor>],
    architecture: Architecture,
    landlock_abi: NonZeroU32,
    cgroup: FreshCgroup,
    limits: ResourceLimits,
) -> Result<PreparedTraceCommand<'descriptor>, TraceStartupError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        use std::process::Stdio;

        if launcher.identity().role() != ArtifactRole::LauncherBinary
            || launcher.identity().mode().get() & 0o111 == 0
        {
            return Err(TraceStartupError::LauncherIdentityInvalid);
        }
        launcher
            .revalidate_identity()
            .map_err(|_| TraceStartupError::LauncherIdentityInvalid)?;
        crate::supervisor::validate_descriptor_set(&request, inherited_descriptors)
            .map_err(|_| TraceStartupError::DescriptorSetInvalid)?;
        let configured = cgroup
            .revalidate_resources()
            .map_err(|_| TraceStartupError::CgroupIdentityMismatch)?;
        cgroup
            .revalidate_fresh()
            .map_err(|_| TraceStartupError::CgroupNotFresh)?;
        if request.identity().cgroup_id() != cgroup.identity()
            || configured.processes() != limits.processes()
            || Some(configured.memory()) != limits.memory()
            || Some(configured.swap()) != limits.swap()
            || configured.memory_oom_group() != 1
        {
            return Err(TraceStartupError::CgroupIdentityMismatch);
        }
        let launcher_fd = launcher.as_fd().as_raw_fd();
        if launcher_fd < 3 {
            return Err(TraceStartupError::DescriptorSetInvalid);
        }
        let (supervisor_channel, launcher_channel) =
            LauncherChannel::pair().map_err(|_| TraceStartupError::ChannelCreationFailed)?;
        let supervisor_channel_fd = supervisor_channel.as_fd().as_raw_fd();
        let launcher_channel_fd = launcher_channel.as_fd().as_raw_fd();
        if supervisor_channel_fd < 3 || launcher_channel_fd < 3 {
            return Err(TraceStartupError::DescriptorSetInvalid);
        }
        let mut command = Command::new(format!("/proc/self/fd/{launcher_fd}"));
        command
            .args(crate::supervisor::bootstrap_arguments(
                launcher_channel_fd,
                request.identity(),
                architecture,
                landlock_abi,
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut descriptors = inherited_descriptors
            .iter()
            .map(|descriptor| descriptor.as_raw_fd())
            .collect::<Vec<_>>();
        descriptors.push(launcher_fd);
        descriptors.push(launcher_channel_fd);
        crate::sys::prepare_traced_exec(&mut command, descriptors);
        let mut retained_descriptors = inherited_descriptors.to_vec();
        retained_descriptors.push(launcher.as_fd());
        Ok(PreparedTraceCommand {
            command,
            launcher,
            supervisor_channel,
            launcher_channel,
            request,
            cgroup,
            wall_time: limits.wall_time(),
            output_limits: TraceOutputLimits::new(limits.stdout(), limits.stderr()),
            _descriptors: retained_descriptors,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            launcher,
            request,
            inherited_descriptors,
            architecture,
            landlock_abi,
            cgroup,
            limits,
        );
        Err(TraceStartupError::UnsupportedOperatingSystem)
    }
}

#[derive(Debug)]
struct TraceChild(Child, TraceChildCleanupState);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TraceChildCleanupState {
    Live,
    IdentityStableHandleOwned,
    ReapedByTraceWait,
}

impl TraceChildCleanupState {
    const fn requires_cleanup(self) -> bool {
        matches!(self, Self::Live)
    }

    fn record_trace_wait_reap(&mut self) {
        *self = Self::ReapedByTraceWait;
    }

    fn record_identity_stable_handle(&mut self) {
        *self = Self::IdentityStableHandleOwned;
    }
}

impl TraceChild {
    const fn new(child: Child) -> Self {
        Self(child, TraceChildCleanupState::Live)
    }

    fn disarm_after_trace_wait(&mut self) {
        self.1.record_trace_wait_reap();
    }

    fn disarm_after_identity_stable_handle(&mut self) {
        self.1.record_identity_stable_handle();
    }

    fn terminate_and_wait(&mut self) {
        if !self.1.requires_cleanup() {
            return;
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
        self.1.record_trace_wait_reap();
    }
}

impl Drop for TraceChild {
    fn drop(&mut self) {
        self.terminate_and_wait();
    }
}

#[derive(Debug)]
struct TraceStreamReaders {
    stdout: Option<std::thread::JoinHandle<io::Result<TraceCapturedStream>>>,
    stderr: Option<std::thread::JoinHandle<io::Result<TraceCapturedStream>>>,
    cancellation: Arc<AtomicBool>,
}

impl TraceStreamReaders {
    fn start(child: &mut TraceChild, limits: TraceOutputLimits) -> Result<Self, TraceStartupError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (child, limits);
            Err(TraceStartupError::UnsupportedOperatingSystem)
        }
        #[cfg(target_os = "linux")]
        {
            let stdout = child
                .0
                .stdout
                .take()
                .ok_or(TraceStartupError::StreamUnavailable)?;
            let stderr = child
                .0
                .stderr
                .take()
                .ok_or(TraceStartupError::StreamUnavailable)?;
            crate::sys::set_nonblocking(stdout.as_raw_fd())
                .map_err(|_| TraceStartupError::StreamConfigurationFailed)?;
            crate::sys::set_nonblocking(stderr.as_raw_fd())
                .map_err(|_| TraceStartupError::StreamConfigurationFailed)?;
            let cancellation = Arc::new(AtomicBool::new(false));
            let stdout =
                spawn_trace_capture("stdout", stdout, limits.stdout(), Arc::clone(&cancellation))?;
            let stderr = match spawn_trace_capture(
                "stderr",
                stderr,
                limits.stderr(),
                Arc::clone(&cancellation),
            ) {
                Ok(stderr) => stderr,
                Err(error) => {
                    cancellation.store(true, Ordering::Release);
                    child.terminate_and_wait();
                    let _ = stdout.join();
                    return Err(error);
                }
            };
            Ok(Self {
                stdout: Some(stdout),
                stderr: Some(stderr),
                cancellation,
            })
        }
    }

    fn finish_before(
        &mut self,
        deadline: Instant,
    ) -> Result<TraceOutputCapture, TraceObservationError> {
        while !self.capture_threads_finished() {
            if Instant::now() >= deadline {
                self.cancel_and_join();
                return Err(TraceObservationError::StreamDrainTimedOut);
            }
            std::thread::sleep(TRACE_POLL_INTERVAL);
        }
        if Instant::now() >= deadline {
            self.cancel_and_join();
            return Err(TraceObservationError::StreamDrainTimedOut);
        }
        let stdout = join_trace_capture(self.stdout.take());
        let stderr = join_trace_capture(self.stderr.take());
        if Instant::now() >= deadline {
            return Err(TraceObservationError::StreamDrainTimedOut);
        }
        Ok(TraceOutputCapture {
            stdout: stdout?,
            stderr: stderr?,
        })
    }

    fn capture_threads_finished(&self) -> bool {
        self.stdout
            .as_ref()
            .is_none_or(std::thread::JoinHandle::is_finished)
            && self
                .stderr
                .as_ref()
                .is_none_or(std::thread::JoinHandle::is_finished)
    }

    fn cancel_and_join(&mut self) {
        self.cancellation.store(true, Ordering::Release);
        if let Some(stdout) = self.stdout.take() {
            let _ = stdout.join();
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join();
        }
    }
}

impl Drop for TraceStreamReaders {
    fn drop(&mut self) {
        self.cancel_and_join();
    }
}

#[cfg(target_os = "linux")]
fn spawn_trace_capture(
    name: &str,
    reader: impl io::Read + Send + 'static,
    limit: OutputByteLimit,
    cancellation: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<io::Result<TraceCapturedStream>>, TraceStartupError> {
    std::thread::Builder::new()
        .name(format!("proofbound-diagnostic-{name}-drain"))
        .spawn(move || capture_trace_stream(reader, limit, &cancellation))
        .map_err(|_| TraceStartupError::StreamDrainStartFailed)
}

fn join_trace_capture(
    handle: Option<std::thread::JoinHandle<io::Result<TraceCapturedStream>>>,
) -> Result<TraceCapturedStream, TraceObservationError> {
    handle
        .ok_or(TraceObservationError::StreamReadFailed)?
        .join()
        .map_err(|_| TraceObservationError::StreamReadFailed)?
        .map_err(|_| TraceObservationError::StreamReadFailed)
}

#[cfg(any(test, target_os = "linux"))]
fn capture_trace_stream(
    mut reader: impl io::Read,
    limit: OutputByteLimit,
    cancellation: &AtomicBool,
) -> io::Result<TraceCapturedStream> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut buffer = [0; 8192];
    loop {
        if cancellation.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "diagnostic stream drain cancelled",
            ));
        }
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(TRACE_POLL_INTERVAL);
                continue;
            }
            Err(error) => return Err(error),
        };
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
    Ok(TraceCapturedStream {
        bytes,
        capture: if truncated {
            StreamCapture::Truncated
        } else {
            StreamCapture::Complete
        },
    })
}

#[derive(Debug)]
struct TraceSession {
    _child: TraceChild,
    cgroup: Option<FreshCgroup>,
    streams: TraceStreamReaders,
    process: TraceProcessId,
    channel: LauncherChannel,
    request: InstallRequest,
    deadline: TraceDeadline,
}

impl TraceSession {
    fn revalidate_cgroup(&self) -> Result<(), TraceStartupError> {
        self.cgroup
            .as_ref()
            .ok_or(TraceStartupError::CgroupIdentityMismatch)?
            .revalidate_resources()
            .map(|_| ())
            .map_err(|_| TraceStartupError::CgroupIdentityMismatch)
    }

    fn finish_terminal(
        &mut self,
        deadline: TraceDeadline,
    ) -> Result<TraceTerminalCapture, TraceObservationError> {
        if deadline.expired() {
            self.streams.cancel_and_join();
            return Err(TraceObservationError::DrainTimedOut);
        }
        let resources = self.cgroup.take().map_or_else(
            || Err(TraceObservationError::ResourceCleanupFailed),
            |cgroup| {
                cgroup
                    .finish_before(deadline.instant())
                    .map_err(|_| TraceObservationError::ResourceCleanupFailed)
            },
        );
        let output = self.streams.finish_before(deadline.instant());
        let resources = match resources? {
            ResourceObservation::Complete(resources) => resources,
            ResourceObservation::Legacy | ResourceObservation::Incomplete(_) => {
                return Err(TraceObservationError::ResourceObservationIncomplete);
            }
        };
        Ok(TraceTerminalCapture {
            resources,
            output: output?,
        })
    }

    fn record_root_reaped(&mut self) {
        self._child.disarm_after_trace_wait();
    }

    fn record_root_identity_stable_handle(&mut self) {
        self._child.disarm_after_identity_stable_handle();
    }
}

/// Owns the exact spawned child before its mandatory post-exec trace stop.
#[derive(Debug)]
pub struct SpawnedTrace {
    session: TraceSession,
}

impl SpawnedTrace {
    /// Returns the exact spawned process identifier.
    #[must_use]
    pub const fn process(&self) -> TraceProcessId {
        self.session.process
    }

    /// Waits for the exact post-exec trace stop of the spawned child.
    pub fn wait_for_initial_exec_stop(mut self) -> Result<InitialExecStop, TraceStartupError> {
        let deadline = self.session.deadline;
        wait_for_exact_stop(&mut self.session, deadline, SIGNAL_TRAP, 0)?;
        Ok(InitialExecStop {
            session: self.session,
        })
    }
}

/// Owns the exact child at the mandatory post-exec trace stop.
#[derive(Debug)]
pub struct InitialExecStop {
    session: TraceSession,
}

impl InitialExecStop {
    /// Resumes the trusted launcher until its declared self-stop.
    pub fn continue_to_launcher_pause(mut self) -> Result<LauncherPause, TraceStartupError> {
        if self.session.deadline.expired() {
            return Err(TraceStartupError::WaitTimedOut);
        }
        continue_trace(self.session.process)?;
        let deadline = self.session.deadline;
        wait_for_exact_stop(&mut self.session, deadline, SIGNAL_STOP, 0)?;
        Ok(LauncherPause {
            session: self.session,
        })
    }
}

/// Owns the launcher at its pre-policy self-stop.
#[derive(Debug)]
pub struct LauncherPause {
    session: TraceSession,
}

impl LauncherPause {
    /// Returns the exact stopped launcher process identifier.
    #[must_use]
    pub const fn process(&self) -> TraceProcessId {
        self.session.process
    }

    /// Resumes trusted launcher code for production-boundary installation.
    pub fn continue_for_boundary(self) -> Result<BoundaryRunning, TraceStartupError> {
        if self.session.deadline.expired() {
            return Err(TraceStartupError::WaitTimedOut);
        }
        continue_trace(self.session.process)?;
        self.session
            .channel
            .send(&LauncherMessage::Install(self.session.request.clone()))
            .map_err(|_| TraceStartupError::InstallSendFailed)?;
        Ok(BoundaryRunning {
            session: self.session,
        })
    }
}

/// Owns a launcher that can install its production boundary but cannot exec.
#[derive(Debug)]
pub struct BoundaryRunning {
    session: TraceSession,
}

impl BoundaryRunning {
    /// Receives the exact boundary acknowledgement and stops before release.
    pub fn receive_acknowledgement_and_stop(
        mut self,
    ) -> Result<AcknowledgedTraceStop, TraceStartupError> {
        if self.session.deadline.expired() {
            return Err(TraceStartupError::AcknowledgementTimedOut);
        }
        let response = self
            .session
            .channel
            .receive_timeout(
                self.session
                    .deadline
                    .0
                    .saturating_duration_since(Instant::now()),
            )
            .map_err(map_acknowledgement_receive_error)?;
        match response {
            LauncherMessage::BoundaryInstalled(acknowledgement) => {
                if acknowledgement.identity() != self.session.request.identity() {
                    return Err(TraceStartupError::BoundaryIdentityMismatch);
                }
            }
            LauncherMessage::Failure(failure) => {
                if failure.identity() != self.session.request.identity() {
                    return Err(TraceStartupError::BoundaryIdentityMismatch);
                }
                return Err(TraceStartupError::LauncherReportedFailure);
            }
            LauncherMessage::Install(_) | LauncherMessage::ExecRelease(_) => {
                return Err(TraceStartupError::AcknowledgementInvalid);
            }
        }
        if self.session.deadline.expired() {
            return Err(TraceStartupError::AcknowledgementTimedOut);
        }
        stop_trace(self.session.process)?;
        let deadline = self.session.deadline;
        wait_for_exact_stop(&mut self.session, deadline, SIGNAL_STOP, 0)?;
        Ok(AcknowledgedTraceStop {
            session: self.session,
        })
    }
}

/// Owns an acknowledged launcher stopped before the supervisor release.
#[derive(Debug)]
pub struct AcknowledgedTraceStop {
    session: TraceSession,
}

impl AcknowledgedTraceStop {
    /// Installs the exact closed diagnostic process-tree trace options.
    pub fn install_options(self) -> Result<TraceReady, TraceStartupError> {
        if self.session.deadline.expired() {
            return Err(TraceStartupError::WaitTimedOut);
        }
        #[cfg(target_os = "linux")]
        {
            let options = crate::sys::install_diagnostic_trace_options(self.session.process.get())
                .map_err(|_| TraceStartupError::OptionsInstallFailed)?;
            if self.session.deadline.expired() {
                return Err(TraceStartupError::WaitTimedOut);
            }
            Ok(TraceReady {
                session: self.session,
                options,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(TraceStartupError::UnsupportedOperatingSystem)
        }
    }
}

/// Owns a stopped launcher with the exact trace options installed.
#[derive(Debug)]
pub struct TraceReady {
    session: TraceSession,
    options: u32,
}

impl TraceReady {
    /// Returns the exact option bits installed for this trace session.
    #[must_use]
    pub const fn options(&self) -> u32 {
        self.options
    }

    /// Sends the bound exec release and starts syscall-stop observation.
    pub fn release(
        self,
        process_limit: TraceProcessLimit,
        capture_limits: TraceCaptureLimits,
    ) -> Result<ActiveTrace, TraceStartupError> {
        if self.session.deadline.expired() {
            return Err(TraceStartupError::WaitTimedOut);
        }
        self.session.revalidate_cgroup()?;
        if self.session.deadline.expired() {
            return Err(TraceStartupError::WaitTimedOut);
        }
        self.session
            .channel
            .send(&LauncherMessage::ExecRelease(ExecRelease::new(
                self.session.request.identity(),
            )))
            .map_err(|_| TraceStartupError::ReleaseSendFailed)?;
        #[cfg(target_os = "linux")]
        {
            let root = self.session.process;
            let process_handle = crate::sys::trace_open_process_handle(root.get())
                .map_err(|_| TraceStartupError::ProcessHandleFailed)?;
            if self.session.deadline.expired() {
                return Err(TraceStartupError::WaitTimedOut);
            }
            crate::sys::trace_syscall(root.get()).map_err(|_| TraceStartupError::ResumeFailed)?;
            self.session.record_root_identity_stable_handle();
            Ok(ActiveTrace {
                session: self.session,
                processes: BTreeMap::from([(root, TraceeState::observing(root))]),
                process_handles: BTreeMap::from([(root, process_handle)]),
                held_process: None,
                must_drain: false,
                process_limit,
                tree_reconciliation_failed: false,
                capture_limits,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (process_limit, capture_limits);
            Err(TraceStartupError::UnsupportedOperatingSystem)
        }
    }
}

/// Identifies an active diagnostic process-tree trace.
#[derive(Debug)]
pub struct ActiveTrace {
    session: TraceSession,
    processes: BTreeMap<TraceProcessId, TraceeState>,
    process_handles: BTreeMap<TraceProcessId, OwnedFd>,
    held_process: Option<TraceProcessId>,
    must_drain: bool,
    process_limit: TraceProcessLimit,
    tree_reconciliation_failed: bool,
    capture_limits: TraceCaptureLimits,
}

impl ActiveTrace {
    /// Returns the diagnostic process-tree root.
    #[must_use]
    pub const fn root(&self) -> TraceProcessId {
        self.session.process
    }

    /// Reports whether every known tracee has one terminal wait result.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.processes.is_empty() && !self.tree_reconciliation_failed
    }

    /// Collects both bounded streams after exact natural tree completion.
    pub fn finish(mut self) -> Result<CompletedTrace, TraceObservationError> {
        if self.session.deadline.expired() {
            self.must_drain = true;
            return Err(TraceObservationError::WaitTimedOut);
        }
        if !self.is_drained() {
            self.must_drain = true;
            return Err(TraceObservationError::DrainRequired);
        }
        let deadline = self.session.deadline;
        Ok(CompletedTrace {
            terminal: self.session.finish_terminal(deadline)?,
        })
    }

    /// Waits for the next complete event from the exact known process tree.
    #[cfg(target_os = "linux")]
    pub fn next_event(&mut self) -> Result<ActiveTraceEvent, TraceObservationError> {
        if self.must_drain {
            return Err(TraceObservationError::DrainRequired);
        }
        if self.processes.is_empty() {
            return Err(TraceObservationError::ProcessTreeDrained);
        }
        if self.session.deadline.expired() {
            self.must_drain = true;
            return Err(TraceObservationError::WaitTimedOut);
        }
        if let Some(process) = self.held_process.take() {
            self.resume_before_deadline(process)?;
        }

        loop {
            let processes = self.processes.keys().copied().collect::<Vec<_>>();
            for requested in processes {
                let observation = match crate::sys::trace_wait_event_nonblocking(requested.get()) {
                    Ok(Some(observation)) => observation,
                    Ok(None) => continue,
                    Err(_) => {
                        self.must_drain = true;
                        return Err(TraceObservationError::WaitFailed);
                    }
                };
                if self.session.deadline.expired() {
                    self.must_drain = true;
                    return Err(TraceObservationError::WaitTimedOut);
                }
                let handled = self.handle_wait_observation(requested, observation);
                if self.session.deadline.expired() {
                    self.must_drain = true;
                    return Err(TraceObservationError::WaitTimedOut);
                }
                match handled {
                    Ok(None) => continue,
                    Ok(Some(event)) => return Ok(event),
                    Err(error) => {
                        self.must_drain = true;
                        return Err(error);
                    }
                }
            }
            if self.session.deadline.expired() {
                self.must_drain = true;
                return Err(TraceObservationError::WaitTimedOut);
            }
            std::thread::sleep(TRACE_POLL_INTERVAL);
        }
    }

    /// Rejects active observation on an unsupported operating system.
    #[cfg(not(target_os = "linux"))]
    pub fn next_event(&mut self) -> Result<ActiveTraceEvent, TraceObservationError> {
        Err(TraceObservationError::UnsupportedOperatingSystem)
    }

    /// Signals every identity-stable process group and starts bounded cleanup.
    #[cfg(target_os = "linux")]
    pub fn begin_termination(mut self) -> Result<DrainingTrace, TraceObservationError> {
        let deadline = TraceDeadline::cleanup()?;
        self.held_process = None;
        self.must_drain = true;
        self.signal_all_process_groups()?;
        Ok(DrainingTrace {
            trace: self,
            deadline,
        })
    }

    /// Rejects trace termination on an unsupported operating system.
    #[cfg(not(target_os = "linux"))]
    pub fn begin_termination(self) -> Result<DrainingTrace, TraceObservationError> {
        Err(TraceObservationError::UnsupportedOperatingSystem)
    }

    /// Terminates every identity-stable process group and drains exact waits.
    pub fn terminate_and_drain(self) -> Result<TraceDrainReport, TraceObservationError> {
        self.begin_termination()?.finish()
    }

    #[cfg(target_os = "linux")]
    fn complete_drain(
        &mut self,
        observations: Vec<TraceDrainObservation>,
        deadline: TraceDeadline,
    ) -> Result<TraceDrainReport, TraceObservationError> {
        if self.tree_reconciliation_failed {
            return Err(TraceObservationError::TreeReconciliationFailed);
        }
        if deadline.expired() {
            return Err(TraceObservationError::DrainTimedOut);
        }
        Ok(TraceDrainReport {
            observations,
            terminal: self.session.finish_terminal(deadline)?,
        })
    }

    #[cfg(target_os = "linux")]
    fn handle_wait_observation(
        &mut self,
        requested: TraceProcessId,
        observation: crate::sys::TraceWaitObservation,
    ) -> Result<Option<ActiveTraceEvent>, TraceObservationError> {
        let reported = TraceProcessId::new(observation.process_id)
            .map_err(|_| TraceObservationError::ProcessIdentityInvalid)?;
        if reported != requested {
            return Err(TraceObservationError::ProcessIdentityChanged);
        }

        match observation.status {
            crate::sys::TraceWaitStatus::Stopped { signal, event }
                if signal == SIGNAL_TRAP && crate::sys::trace_event_is_exec(event) =>
            {
                let change = self.reconcile_exec_identity(requested, reported)?;
                let invocation =
                    self.processes
                        .get(&change.survivor)
                        .and_then(|state| match &state.pending {
                            Some(PendingTraceSyscall::Captured(invocation)) => {
                                Some(invocation.clone())
                            }
                            Some(PendingTraceSyscall::Ignored) | None => None,
                        });
                self.held_process = Some(change.survivor);
                Ok(Some(ActiveTraceEvent::ImageReplaced {
                    former_process: change.former,
                    process: change.survivor,
                    superseded_processes: change.superseded,
                    invocation,
                }))
            }
            crate::sys::TraceWaitStatus::Stopped { signal, event }
                if signal == SIGNAL_TRAP
                    && crate::sys::trace_process_creation_event(event).is_some() =>
            {
                self.tree_reconciliation_failed = true;
                let child = crate::sys::trace_event_process(reported.get())
                    .map_err(|_| TraceObservationError::EventMessageInvalid)
                    .and_then(|value| {
                        TraceProcessId::new(value)
                            .map_err(|_| TraceObservationError::ProcessIdentityInvalid)
                    })?;
                if self.processes.contains_key(&child) {
                    return Err(TraceObservationError::ProcessIdentityDuplicate);
                }
                let kind = match crate::sys::trace_process_creation_event(event) {
                    Some(crate::sys::TraceProcessCreationEvent::Clone) => {
                        TraceProcessCreationKind::Clone
                    }
                    Some(crate::sys::TraceProcessCreationEvent::Fork) => {
                        TraceProcessCreationKind::Fork
                    }
                    Some(crate::sys::TraceProcessCreationEvent::Vfork) => {
                        TraceProcessCreationKind::Vfork
                    }
                    None => return Err(TraceObservationError::EventMessageInvalid),
                };
                let capacity_exceeded = self.register_child(child)?;
                self.tree_reconciliation_failed = false;
                if capacity_exceeded {
                    self.must_drain = true;
                }
                self.held_process = Some(reported);
                Ok(Some(ActiveTraceEvent::ProcessCreated {
                    parent: reported,
                    child,
                    kind,
                }))
            }
            crate::sys::TraceWaitStatus::Stopped { signal, event }
                if signal == SIGNAL_SYSCALL && event == 0 =>
            {
                self.handle_syscall_stop(reported)
            }
            crate::sys::TraceWaitStatus::Stopped { signal, event }
                if signal == SIGNAL_STOP
                    && event == 0
                    && self
                        .processes
                        .get(&reported)
                        .is_some_and(|state| state.awaiting_initial_stop) =>
            {
                let state = self
                    .processes
                    .get_mut(&reported)
                    .ok_or(TraceObservationError::ProcessUnknown)?;
                state.awaiting_initial_stop = false;
                self.resume_before_deadline(reported)?;
                Ok(None)
            }
            crate::sys::TraceWaitStatus::Stopped { signal, event } => {
                self.must_drain = true;
                Ok(Some(ActiveTraceEvent::UnexpectedStop {
                    process: reported,
                    signal,
                    event,
                }))
            }
            crate::sys::TraceWaitStatus::Exited { code } => {
                self.record_terminal_process(reported)?;
                Ok(Some(ActiveTraceEvent::ProcessExited {
                    process: reported,
                    termination: TraceTermination::Exit(code),
                }))
            }
            crate::sys::TraceWaitStatus::Signaled { signal } => {
                self.record_terminal_process(reported)?;
                Ok(Some(ActiveTraceEvent::ProcessExited {
                    process: reported,
                    termination: TraceTermination::Signal(signal),
                }))
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn handle_syscall_stop(
        &mut self,
        process: TraceProcessId,
    ) -> Result<Option<ActiveTraceEvent>, TraceObservationError> {
        if self
            .processes
            .get(&process)
            .ok_or(TraceObservationError::ProcessUnknown)?
            .awaiting_initial_stop
        {
            return Err(TraceObservationError::InitialStopMissing);
        }
        match crate::sys::trace_syscall_stop(process.get())
            .map_err(|_| TraceObservationError::SyscallInformationInvalid)?
        {
            crate::sys::TraceSyscallStop::Entry {
                architecture,
                instruction_pointer,
                stack_pointer,
                number,
                arguments,
            } => {
                let state = self
                    .processes
                    .get(&process)
                    .ok_or(TraceObservationError::ProcessUnknown)?;
                if state.pending.is_some() {
                    return Err(TraceObservationError::SyscallOrderInvalid);
                }
                let registers = TraceSyscallRegisters {
                    architecture,
                    instruction_pointer,
                    stack_pointer,
                    number,
                    arguments,
                };
                let pending = capture_syscall_invocation(process, registers, self.capture_limits)?
                    .map_or(PendingTraceSyscall::Ignored, PendingTraceSyscall::Captured);
                self.processes
                    .get_mut(&process)
                    .ok_or(TraceObservationError::ProcessUnknown)?
                    .pending = Some(pending);
                self.resume_before_deadline(process)?;
                Ok(None)
            }
            crate::sys::TraceSyscallStop::Exit { result, is_error } => {
                let pending = self
                    .processes
                    .get_mut(&process)
                    .ok_or(TraceObservationError::ProcessUnknown)?
                    .pending
                    .take()
                    .ok_or(TraceObservationError::SyscallOrderInvalid)?;
                match pending {
                    PendingTraceSyscall::Captured(invocation) => {
                        self.held_process = Some(process);
                        Ok(Some(ActiveTraceEvent::SyscallCompleted {
                            process,
                            invocation,
                            result,
                            is_error,
                        }))
                    }
                    PendingTraceSyscall::Ignored => {
                        self.resume_before_deadline(process)?;
                        Ok(None)
                    }
                }
            }
            crate::sys::TraceSyscallStop::Seccomp | crate::sys::TraceSyscallStop::None => {
                Err(TraceObservationError::SyscallInformationInvalid)
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn register_child(&mut self, child: TraceProcessId) -> Result<bool, TraceObservationError> {
        if self.processes.len() >= self.process_limit.drain_capacity() {
            return Err(TraceObservationError::ProcessCapacityExceeded);
        }
        let capacity_exceeded = self.processes.len() >= self.process_limit.get() as usize;
        let thread_group = read_thread_group_id(child)?;
        if let std::collections::btree_map::Entry::Vacant(entry) =
            self.process_handles.entry(thread_group)
        {
            let handle = crate::sys::trace_open_process_handle(thread_group.get())
                .map_err(|_| TraceObservationError::ProcessHandleFailed)?;
            entry.insert(handle);
        }
        self.processes
            .insert(child, TraceeState::awaiting_stop(thread_group));
        Ok(capacity_exceeded)
    }

    #[cfg(target_os = "linux")]
    fn resume_before_deadline(
        &mut self,
        process: TraceProcessId,
    ) -> Result<(), TraceObservationError> {
        if self.session.deadline.expired() {
            self.must_drain = true;
            return Err(TraceObservationError::WaitTimedOut);
        }
        crate::sys::trace_syscall(process.get()).map_err(|_| {
            self.must_drain = true;
            TraceObservationError::ResumeFailed
        })
    }

    #[cfg(target_os = "linux")]
    fn reconcile_exec_identity(
        &mut self,
        requested: TraceProcessId,
        reported: TraceProcessId,
    ) -> Result<ExecIdentityChange, TraceObservationError> {
        let former = crate::sys::trace_event_process(reported.get())
            .map_err(|_| TraceObservationError::EventMessageInvalid)
            .and_then(|value| {
                TraceProcessId::new(value)
                    .map_err(|_| TraceObservationError::ProcessIdentityInvalid)
            })?;
        let change = reconcile_exec_processes(&mut self.processes, requested, reported, former)?;
        if let std::collections::btree_map::Entry::Vacant(entry) =
            self.process_handles.entry(reported)
        {
            let handle = crate::sys::trace_open_process_handle(reported.get())
                .map_err(|_| TraceObservationError::ProcessHandleFailed)?;
            entry.insert(handle);
        }
        self.remove_unused_process_handles();
        Ok(change)
    }

    #[cfg(target_os = "linux")]
    fn record_terminal_process(
        &mut self,
        process: TraceProcessId,
    ) -> Result<(), TraceObservationError> {
        if self.processes.remove(&process).is_none() {
            return Err(TraceObservationError::ProcessUnknown);
        }
        if process == self.session.process {
            self.session.record_root_reaped();
        }
        self.remove_unused_process_handles();
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn remove_unused_process_handles(&mut self) {
        self.process_handles.retain(|thread_group, _| {
            self.processes
                .values()
                .any(|state| state.thread_group == *thread_group)
        });
    }

    #[cfg(target_os = "linux")]
    fn handle_drain_observation(
        &mut self,
        requested: TraceProcessId,
        observation: crate::sys::TraceWaitObservation,
    ) -> Result<Option<TraceDrainObservation>, TraceObservationError> {
        let reported = TraceProcessId::new(observation.process_id)
            .map_err(|_| TraceObservationError::ProcessIdentityInvalid)?;
        if reported != requested {
            return Err(TraceObservationError::ProcessIdentityChanged);
        }
        match observation.status {
            crate::sys::TraceWaitStatus::Stopped { signal, event }
                if signal == SIGNAL_TRAP && crate::sys::trace_event_is_exec(event) =>
            {
                let change = self.reconcile_exec_identity(requested, reported)?;
                self.signal_process(change.survivor)?;
                return Ok(Some(TraceDrainObservation::ImageReplaced {
                    former_process: change.former,
                    process: change.survivor,
                    superseded_processes: change.superseded,
                }));
            }
            crate::sys::TraceWaitStatus::Stopped { signal, event }
                if signal == SIGNAL_TRAP
                    && crate::sys::trace_process_creation_event(event).is_some() =>
            {
                let child = crate::sys::trace_event_process(reported.get())
                    .map_err(|_| TraceObservationError::EventMessageInvalid)
                    .and_then(|value| {
                        TraceProcessId::new(value)
                            .map_err(|_| TraceObservationError::ProcessIdentityInvalid)
                    })?;
                if !self.processes.contains_key(&child) {
                    let _ = self.register_child(child)?;
                }
                self.signal_process(child)?;
                self.signal_process(reported)?;
                let kind = match crate::sys::trace_process_creation_event(event) {
                    Some(crate::sys::TraceProcessCreationEvent::Clone) => {
                        TraceProcessCreationKind::Clone
                    }
                    Some(crate::sys::TraceProcessCreationEvent::Fork) => {
                        TraceProcessCreationKind::Fork
                    }
                    Some(crate::sys::TraceProcessCreationEvent::Vfork) => {
                        TraceProcessCreationKind::Vfork
                    }
                    None => return Err(TraceObservationError::EventMessageInvalid),
                };
                return Ok(Some(TraceDrainObservation::ProcessCreated {
                    parent: reported,
                    child,
                    kind,
                }));
            }
            crate::sys::TraceWaitStatus::Stopped { .. } => {
                self.signal_process(reported)?;
            }
            crate::sys::TraceWaitStatus::Exited { .. }
            | crate::sys::TraceWaitStatus::Signaled { .. } => {
                let termination = match observation.status {
                    crate::sys::TraceWaitStatus::Exited { code } => TraceTermination::Exit(code),
                    crate::sys::TraceWaitStatus::Signaled { signal } => {
                        TraceTermination::Signal(signal)
                    }
                    crate::sys::TraceWaitStatus::Stopped { .. } => {
                        return Err(TraceObservationError::DrainFailed);
                    }
                };
                self.record_terminal_process(reported)?;
                return Ok(Some(TraceDrainObservation::ProcessExited {
                    process: reported,
                    termination,
                }));
            }
        }
        Ok(None)
    }

    #[cfg(target_os = "linux")]
    fn signal_process(&self, process: TraceProcessId) -> Result<(), TraceObservationError> {
        let thread_group = self
            .processes
            .get(&process)
            .map(|state| state.thread_group)
            .ok_or(TraceObservationError::ProcessUnknown)?;
        let handle = self
            .process_handles
            .get(&thread_group)
            .ok_or(TraceObservationError::ProcessHandleFailed)?;
        crate::sys::trace_kill_process_handle(handle.as_raw_fd())
            .map_err(|_| TraceObservationError::DrainFailed)
    }

    #[cfg(target_os = "linux")]
    fn signal_all_process_groups(&self) -> Result<(), TraceObservationError> {
        let mut failed = false;
        for handle in self.process_handles.values() {
            failed |= crate::sys::trace_kill_process_handle(handle.as_raw_fd()).is_err();
        }
        if failed {
            Err(TraceObservationError::DrainFailed)
        } else {
            Ok(())
        }
    }
}

/// Owns an already-signalled trace tree during bounded terminal cleanup.
#[derive(Debug)]
pub struct DrainingTrace {
    trace: ActiveTrace,
    deadline: TraceDeadline,
}

impl DrainingTrace {
    /// Drains exact waits before the cleanup deadline and captures terminal state.
    #[cfg(target_os = "linux")]
    pub fn finish(mut self) -> Result<TraceDrainReport, TraceObservationError> {
        let mut observations = Vec::new();
        while !self.trace.processes.is_empty() {
            if self.deadline.expired() {
                return Err(TraceObservationError::DrainTimedOut);
            }
            let mut observed = false;
            let processes = self.trace.processes.keys().copied().collect::<Vec<_>>();
            for requested in processes {
                if !self.trace.processes.contains_key(&requested) {
                    continue;
                }
                let observation = match crate::sys::trace_wait_event_nonblocking(requested.get()) {
                    Ok(Some(observation)) => observation,
                    Ok(None) => continue,
                    Err(_) => return Err(TraceObservationError::DrainFailed),
                };
                if self.deadline.expired() {
                    return Err(TraceObservationError::DrainTimedOut);
                }
                observed = true;
                if let Some(observation) = self
                    .trace
                    .handle_drain_observation(requested, observation)?
                {
                    observations.push(observation);
                }
                if self.deadline.expired() {
                    return Err(TraceObservationError::DrainTimedOut);
                }
            }
            if self.trace.processes.is_empty() {
                return self.trace.complete_drain(observations, self.deadline);
            }
            if self.deadline.expired() {
                return Err(TraceObservationError::DrainTimedOut);
            }
            if !observed {
                std::thread::sleep(TRACE_POLL_INTERVAL);
            }
        }
        self.trace.complete_drain(observations, self.deadline)
    }

    /// Rejects trace drain on an unsupported operating system.
    #[cfg(not(target_os = "linux"))]
    pub fn finish(self) -> Result<TraceDrainReport, TraceObservationError> {
        Err(TraceObservationError::UnsupportedOperatingSystem)
    }
}

impl Drop for ActiveTrace {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        let _ = self.signal_all_process_groups();
    }
}

#[cfg(target_os = "linux")]
fn read_thread_group_id(process: TraceProcessId) -> Result<TraceProcessId, TraceObservationError> {
    const MAX_STATUS_BYTES: usize = 65_536;

    let path = format!("/proc/{}/status", process.get());
    let bytes = std::fs::read(path).map_err(|_| TraceObservationError::ThreadGroupInvalid)?;
    if bytes.len() > MAX_STATUS_BYTES {
        return Err(TraceObservationError::ThreadGroupInvalid);
    }
    let status =
        std::str::from_utf8(&bytes).map_err(|_| TraceObservationError::ThreadGroupInvalid)?;
    parse_thread_group_id(status)
}

#[cfg(target_os = "linux")]
fn parse_thread_group_id(status: &str) -> Result<TraceProcessId, TraceObservationError> {
    let mut values = status
        .lines()
        .filter_map(|line| line.strip_prefix("Tgid:\t"));
    let value = values
        .next()
        .ok_or(TraceObservationError::ThreadGroupInvalid)?;
    if values.next().is_some() {
        return Err(TraceObservationError::ThreadGroupInvalid);
    }
    let value = value
        .parse::<u32>()
        .map_err(|_| TraceObservationError::ThreadGroupInvalid)?;
    TraceProcessId::new(value).map_err(|_| TraceObservationError::ThreadGroupInvalid)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TraceSyscallRegisters {
    architecture: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    number: u64,
    arguments: [u64; 6],
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TraceCaptureRequest {
    Path {
        class: TraceSyscallClass,
        path_address: u64,
        buffer_bytes: Option<u64>,
        directory_fd: Option<i32>,
        flags: Option<u64>,
        mask: Option<u64>,
        mode: Option<u64>,
    },
    Openat2 {
        directory_fd: i32,
        path_address: u64,
        how_address: u64,
        how_bytes: u64,
    },
    ProcessCreate {
        class: TraceSyscallClass,
        flags: Option<u64>,
    },
    Clone3 {
        arguments_address: u64,
        arguments_bytes: u64,
    },
    SocketAddress {
        class: TraceSyscallClass,
        descriptor: u32,
        address: u64,
        address_bytes: u64,
        address_optional: bool,
        payload_bytes: Option<u64>,
    },
    SocketCreate {
        domain: u32,
        protocol: u32,
        socket_type: u32,
    },
}

#[cfg(target_os = "linux")]
fn capture_syscall_invocation(
    process: TraceProcessId,
    registers: TraceSyscallRegisters,
    limits: TraceCaptureLimits,
) -> Result<Option<TraceSyscallInvocation>, TraceObservationError> {
    let Some(request) = decode_trace_syscall(registers)? else {
        return Ok(None);
    };
    let (class, operands) = match request {
        TraceCaptureRequest::Path {
            class,
            path_address,
            buffer_bytes,
            directory_fd,
            flags,
            mask,
            mode,
        } => {
            let path = read_tracee_string(process, path_address, limits)?;
            (
                class,
                TraceCapturedOperands::Path {
                    buffer_bytes,
                    directory_fd,
                    flags,
                    mask,
                    mode,
                    path,
                    resolve: None,
                },
            )
        }
        TraceCaptureRequest::Openat2 {
            directory_fd,
            path_address,
            how_address,
            how_bytes,
        } => {
            const OPEN_HOW_BYTES: u64 = 24;
            if how_bytes != OPEN_HOW_BYTES {
                return Err(TraceObservationError::SyscallFormUnsupported);
            }
            let path = read_tracee_string(process, path_address, limits)?;
            let mut how = [0_u8; OPEN_HOW_BYTES as usize];
            read_exact_tracee_memory(process, how_address, &mut how)?;
            (
                TraceSyscallClass::Openat2,
                TraceCapturedOperands::Path {
                    buffer_bytes: None,
                    directory_fd: Some(directory_fd),
                    flags: Some(read_little_endian_u64(&how, 0)?),
                    mask: None,
                    mode: Some(read_little_endian_u64(&how, 8)?),
                    path,
                    resolve: Some(read_little_endian_u64(&how, 16)?),
                },
            )
        }
        TraceCaptureRequest::ProcessCreate { class, flags } => {
            (class, TraceCapturedOperands::ProcessCreate { flags })
        }
        TraceCaptureRequest::Clone3 {
            arguments_address,
            arguments_bytes,
        } => {
            const CLONE3_MIN_BYTES: u64 = 8;
            const CLONE3_MAX_BYTES: u64 = 88;
            if !(CLONE3_MIN_BYTES..=CLONE3_MAX_BYTES).contains(&arguments_bytes)
                || arguments_bytes % 8 != 0
            {
                return Err(TraceObservationError::SyscallFormUnsupported);
            }
            let mut flags = [0_u8; 8];
            read_exact_tracee_memory(process, arguments_address, &mut flags)?;
            (
                TraceSyscallClass::Clone,
                TraceCapturedOperands::ProcessCreate {
                    flags: Some(u64::from_le_bytes(flags)),
                },
            )
        }
        TraceCaptureRequest::SocketAddress {
            class,
            descriptor,
            address,
            address_bytes,
            address_optional,
            payload_bytes,
        } => {
            let address =
                capture_socket_address(process, address, address_bytes, address_optional, limits)?;
            (
                class,
                TraceCapturedOperands::SocketAddress {
                    address,
                    descriptor,
                    payload_bytes,
                },
            )
        }
        TraceCaptureRequest::SocketCreate {
            domain,
            protocol,
            socket_type,
        } => (
            TraceSyscallClass::Socket,
            TraceCapturedOperands::SocketCreate {
                domain,
                protocol,
                socket_type,
            },
        ),
    };
    Ok(Some(TraceSyscallInvocation {
        architecture: registers.architecture,
        instruction_pointer: registers.instruction_pointer,
        stack_pointer: registers.stack_pointer,
        number: registers.number,
        arguments: registers.arguments,
        class,
        operands,
    }))
}

#[cfg(target_os = "linux")]
fn decode_trace_syscall(
    registers: TraceSyscallRegisters,
) -> Result<Option<TraceCaptureRequest>, TraceObservationError> {
    match registers.architecture {
        AUDIT_ARCH_X86_64 => decode_x86_64_syscall(registers.number, registers.arguments),
        AUDIT_ARCH_AARCH64 => decode_aarch64_syscall(registers.number, registers.arguments),
        _ => Err(TraceObservationError::ArchitectureUnsupported),
    }
}

#[cfg(target_os = "linux")]
fn decode_x86_64_syscall(
    number: u64,
    arguments: [u64; 6],
) -> Result<Option<TraceCaptureRequest>, TraceObservationError> {
    const X32_SYSCALL_BIT: u64 = 0x4000_0000;
    if number & X32_SYSCALL_BIT != 0 {
        return Err(TraceObservationError::SyscallFormUnsupported);
    }
    decode_supported_syscall(
        number,
        arguments,
        ArchitectureSyscalls {
            open: Some(2),
            socket: 41,
            connect: 42,
            sendto: 44,
            bind: 49,
            clone: 56,
            fork: Some(57),
            vfork: Some(58),
            execve: 59,
            creat: Some(85),
            readlink: Some(89),
            openat: 257,
            newfstatat: 262,
            readlinkat: 267,
            execveat: 322,
            statx: 332,
            clone3: 435,
            openat2: 437,
        },
    )
}

#[cfg(target_os = "linux")]
fn decode_aarch64_syscall(
    number: u64,
    arguments: [u64; 6],
) -> Result<Option<TraceCaptureRequest>, TraceObservationError> {
    decode_supported_syscall(
        number,
        arguments,
        ArchitectureSyscalls {
            open: None,
            socket: 198,
            connect: 203,
            sendto: 206,
            bind: 200,
            clone: 220,
            fork: None,
            vfork: None,
            execve: 221,
            creat: None,
            readlink: None,
            openat: 56,
            newfstatat: 79,
            readlinkat: 78,
            execveat: 281,
            statx: 291,
            clone3: 435,
            openat2: 437,
        },
    )
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct ArchitectureSyscalls {
    open: Option<u64>,
    socket: u64,
    connect: u64,
    sendto: u64,
    bind: u64,
    clone: u64,
    fork: Option<u64>,
    vfork: Option<u64>,
    execve: u64,
    creat: Option<u64>,
    readlink: Option<u64>,
    openat: u64,
    newfstatat: u64,
    readlinkat: u64,
    execveat: u64,
    statx: u64,
    clone3: u64,
    openat2: u64,
}

#[cfg(target_os = "linux")]
fn decode_supported_syscall(
    number: u64,
    arguments: [u64; 6],
    syscalls: ArchitectureSyscalls,
) -> Result<Option<TraceCaptureRequest>, TraceObservationError> {
    let request = if syscalls.open == Some(number) {
        TraceCaptureRequest::Path {
            class: TraceSyscallClass::Open,
            path_address: arguments[0],
            buffer_bytes: None,
            directory_fd: None,
            flags: Some(arguments[1]),
            mask: None,
            mode: Some(arguments[2]),
        }
    } else if number == syscalls.openat {
        TraceCaptureRequest::Path {
            class: TraceSyscallClass::Openat,
            path_address: arguments[1],
            buffer_bytes: None,
            directory_fd: Some(trace_i32_argument(arguments[0])?),
            flags: Some(arguments[2]),
            mask: None,
            mode: Some(arguments[3]),
        }
    } else if number == syscalls.openat2 {
        TraceCaptureRequest::Openat2 {
            directory_fd: trace_i32_argument(arguments[0])?,
            path_address: arguments[1],
            how_address: arguments[2],
            how_bytes: arguments[3],
        }
    } else if syscalls.creat == Some(number) {
        TraceCaptureRequest::Path {
            class: TraceSyscallClass::Creat,
            path_address: arguments[0],
            buffer_bytes: None,
            directory_fd: None,
            flags: None,
            mask: None,
            mode: Some(arguments[1]),
        }
    } else if number == syscalls.execve {
        TraceCaptureRequest::Path {
            class: TraceSyscallClass::Execve,
            path_address: arguments[0],
            buffer_bytes: None,
            directory_fd: None,
            flags: None,
            mask: None,
            mode: None,
        }
    } else if number == syscalls.execveat {
        TraceCaptureRequest::Path {
            class: TraceSyscallClass::Execveat,
            path_address: arguments[1],
            buffer_bytes: None,
            directory_fd: Some(trace_i32_argument(arguments[0])?),
            flags: Some(arguments[4]),
            mask: None,
            mode: None,
        }
    } else if number == syscalls.newfstatat {
        TraceCaptureRequest::Path {
            class: TraceSyscallClass::Newfstatat,
            path_address: arguments[1],
            buffer_bytes: None,
            directory_fd: Some(trace_i32_argument(arguments[0])?),
            flags: Some(arguments[3]),
            mask: None,
            mode: None,
        }
    } else if syscalls.readlink == Some(number) {
        TraceCaptureRequest::Path {
            class: TraceSyscallClass::Readlink,
            path_address: arguments[0],
            buffer_bytes: Some(arguments[2]),
            directory_fd: None,
            flags: None,
            mask: None,
            mode: None,
        }
    } else if number == syscalls.readlinkat {
        TraceCaptureRequest::Path {
            class: TraceSyscallClass::Readlinkat,
            path_address: arguments[1],
            buffer_bytes: Some(arguments[3]),
            directory_fd: Some(trace_i32_argument(arguments[0])?),
            flags: None,
            mask: None,
            mode: None,
        }
    } else if number == syscalls.statx {
        TraceCaptureRequest::Path {
            class: TraceSyscallClass::Statx,
            path_address: arguments[1],
            buffer_bytes: None,
            directory_fd: Some(trace_i32_argument(arguments[0])?),
            flags: Some(arguments[2]),
            mask: Some(arguments[3]),
            mode: None,
        }
    } else if number == syscalls.socket {
        TraceCaptureRequest::SocketCreate {
            domain: trace_u32_argument(arguments[0])?,
            protocol: trace_u32_argument(arguments[2])?,
            socket_type: trace_u32_argument(arguments[1])?,
        }
    } else if number == syscalls.connect || number == syscalls.bind {
        TraceCaptureRequest::SocketAddress {
            class: if number == syscalls.connect {
                TraceSyscallClass::Connect
            } else {
                TraceSyscallClass::Bind
            },
            descriptor: trace_u32_argument(arguments[0])?,
            address: arguments[1],
            address_bytes: arguments[2],
            address_optional: false,
            payload_bytes: None,
        }
    } else if number == syscalls.sendto {
        TraceCaptureRequest::SocketAddress {
            class: TraceSyscallClass::Sendto,
            descriptor: trace_u32_argument(arguments[0])?,
            address: arguments[4],
            address_bytes: arguments[5],
            address_optional: true,
            payload_bytes: Some(arguments[2]),
        }
    } else if number == syscalls.clone {
        TraceCaptureRequest::ProcessCreate {
            class: TraceSyscallClass::Clone,
            flags: Some(arguments[0]),
        }
    } else if syscalls.fork == Some(number) {
        TraceCaptureRequest::ProcessCreate {
            class: TraceSyscallClass::Fork,
            flags: None,
        }
    } else if syscalls.vfork == Some(number) {
        TraceCaptureRequest::ProcessCreate {
            class: TraceSyscallClass::Vfork,
            flags: None,
        }
    } else if number == syscalls.clone3 {
        TraceCaptureRequest::Clone3 {
            arguments_address: arguments[0],
            arguments_bytes: arguments[1],
        }
    } else {
        return Ok(None);
    };
    Ok(Some(request))
}

#[cfg(target_os = "linux")]
fn trace_i32_argument(value: u64) -> Result<i32, TraceObservationError> {
    let upper = value >> 32;
    if upper != 0 && upper != u64::from(u32::MAX) {
        return Err(TraceObservationError::SyscallFormUnsupported);
    }
    Ok(value as u32 as i32)
}

#[cfg(target_os = "linux")]
fn trace_u32_argument(value: u64) -> Result<u32, TraceObservationError> {
    let upper = value >> 32;
    if upper != 0 && upper != u64::from(u32::MAX) {
        return Err(TraceObservationError::SyscallFormUnsupported);
    }
    Ok(value as u32)
}

#[cfg(target_os = "linux")]
fn read_tracee_string(
    process: TraceProcessId,
    address: u64,
    limits: TraceCaptureLimits,
) -> Result<Vec<u8>, TraceObservationError> {
    let mut bytes = Vec::new();
    while bytes.len() < limits.tracee_string_bytes() {
        let remaining = limits.tracee_string_bytes() - bytes.len();
        let count = remaining.min(TRACE_MEMORY_CHUNK_BYTES);
        let mut chunk = vec![0_u8; count];
        let chunk_address = address
            .checked_add(bytes.len() as u64)
            .ok_or(TraceObservationError::TraceeMemoryReadFailed)?;
        read_exact_tracee_memory(process, chunk_address, &mut chunk)?;
        if let Some(terminator) = chunk.iter().position(|byte| *byte == 0) {
            bytes.extend_from_slice(&chunk[..terminator]);
            if bytes.len() > limits.path_bytes() {
                return Err(TraceObservationError::PathLimitExceeded);
            }
            return Ok(bytes);
        }
        bytes.extend_from_slice(&chunk);
        if bytes.len() > limits.path_bytes() {
            return Err(TraceObservationError::PathLimitExceeded);
        }
    }
    Err(TraceObservationError::TraceeStringLimitExceeded)
}

#[cfg(target_os = "linux")]
fn capture_socket_address(
    process: TraceProcessId,
    address: u64,
    address_bytes: u64,
    address_optional: bool,
    limits: TraceCaptureLimits,
) -> Result<Option<Vec<u8>>, TraceObservationError> {
    if address_optional && address == 0 && address_bytes == 0 {
        return Ok(None);
    }
    let address_bytes = usize::try_from(address_bytes)
        .map_err(|_| TraceObservationError::SocketAddressLimitExceeded)?;
    if address_bytes > limits.socket_address_bytes() {
        return Err(TraceObservationError::SocketAddressLimitExceeded);
    }
    if address == 0 && address_bytes != 0 {
        return Err(TraceObservationError::TraceeMemoryReadFailed);
    }
    let mut bytes = vec![0_u8; address_bytes];
    read_exact_tracee_memory(process, address, &mut bytes)?;
    Ok(Some(bytes))
}

#[cfg(target_os = "linux")]
fn read_exact_tracee_memory(
    process: TraceProcessId,
    address: u64,
    bytes: &mut [u8],
) -> Result<(), TraceObservationError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let remote = address
            .checked_add(offset as u64)
            .ok_or(TraceObservationError::TraceeMemoryReadFailed)?;
        let count =
            crate::sys::trace_read_process_memory(process.get(), remote, &mut bytes[offset..])
                .map_err(|_| TraceObservationError::TraceeMemoryReadFailed)?;
        if count == 0 {
            return Err(TraceObservationError::TraceeMemoryReadFailed);
        }
        offset = offset
            .checked_add(count)
            .ok_or(TraceObservationError::TraceeMemoryReadFailed)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_little_endian_u64(bytes: &[u8], start: usize) -> Result<u64, TraceObservationError> {
    let end = start
        .checked_add(8)
        .ok_or(TraceObservationError::SyscallFormUnsupported)?;
    let field = bytes
        .get(start..end)
        .ok_or(TraceObservationError::SyscallFormUnsupported)?;
    let field =
        <[u8; 8]>::try_from(field).map_err(|_| TraceObservationError::SyscallFormUnsupported)?;
    Ok(u64::from_le_bytes(field))
}

#[derive(Debug)]
struct TraceeState {
    thread_group: TraceProcessId,
    awaiting_initial_stop: bool,
    pending: Option<PendingTraceSyscall>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PendingTraceSyscall {
    Captured(TraceSyscallInvocation),
    Ignored,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Eq, PartialEq)]
struct ExecIdentityChange {
    former: TraceProcessId,
    survivor: TraceProcessId,
    superseded: Vec<TraceProcessId>,
}

impl TraceeState {
    const fn observing(thread_group: TraceProcessId) -> Self {
        Self {
            thread_group,
            awaiting_initial_stop: false,
            pending: None,
        }
    }

    const fn awaiting_stop(thread_group: TraceProcessId) -> Self {
        Self {
            thread_group,
            awaiting_initial_stop: true,
            pending: None,
        }
    }
}

#[cfg(target_os = "linux")]
fn reconcile_exec_processes(
    processes: &mut BTreeMap<TraceProcessId, TraceeState>,
    requested: TraceProcessId,
    reported: TraceProcessId,
    former: TraceProcessId,
) -> Result<ExecIdentityChange, TraceObservationError> {
    if reported != requested {
        return Err(TraceObservationError::ProcessIdentityChanged);
    }
    let survivor_thread_group = processes
        .get(&reported)
        .map(|state| state.thread_group)
        .ok_or(TraceObservationError::ProcessUnknown)?;
    let former_thread_group = processes
        .get(&former)
        .map(|state| state.thread_group)
        .ok_or(TraceObservationError::ProcessUnknown)?;
    if survivor_thread_group != reported || former_thread_group != reported {
        return Err(TraceObservationError::ProcessIdentityChanged);
    }

    let mut exec_state = processes
        .remove(&former)
        .ok_or(TraceObservationError::ProcessUnknown)?;
    let replaced_threads = processes
        .iter()
        .filter_map(|(process, state)| (state.thread_group == reported).then_some(*process))
        .collect::<Vec<_>>();
    for process in &replaced_threads {
        processes.remove(process);
    }
    exec_state.thread_group = reported;
    exec_state.awaiting_initial_stop = false;
    processes.insert(reported, exec_state);
    Ok(ExecIdentityChange {
        former,
        survivor: reported,
        superseded: replaced_threads,
    })
}

/// Contains one process-tree observation collected during exact drain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TraceDrainObservation {
    /// A pending creation event added a stopped child during drain.
    ProcessCreated {
        /// The stopped parent tracee.
        parent: TraceProcessId,
        /// The stopped child tracee.
        child: TraceProcessId,
        /// The process-creation event kind.
        kind: TraceProcessCreationKind,
    },
    /// A pending exec event changed the retained process identities.
    ImageReplaced {
        /// The pre-exec tracee identity.
        former_process: TraceProcessId,
        /// The post-exec tracee identity.
        process: TraceProcessId,
        /// Thread identities removed by the successful exec.
        superseded_processes: Vec<TraceProcessId>,
    },
    /// One exact terminal wait removed a retained tracee.
    ProcessExited {
        /// The terminated tracee identity.
        process: TraceProcessId,
        /// The exact terminal status class.
        termination: TraceTermination,
    },
}

/// Contains one bounded standard stream from a diagnostic trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceCapturedStream {
    bytes: Vec<u8>,
    capture: StreamCapture,
}

impl TraceCapturedStream {
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

/// Contains both bounded standard streams from a diagnostic trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceOutputCapture {
    stdout: TraceCapturedStream,
    stderr: TraceCapturedStream,
}

impl TraceOutputCapture {
    /// Returns the bounded standard-output capture.
    #[must_use]
    pub const fn stdout(&self) -> &TraceCapturedStream {
        &self.stdout
    }

    /// Returns the bounded standard-error capture.
    #[must_use]
    pub const fn stderr(&self) -> &TraceCapturedStream {
        &self.stderr
    }
}

/// Contains bounded output and resources after terminal diagnostic cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceTerminalCapture {
    resources: TerminalResources,
    output: TraceOutputCapture,
}

impl TraceTerminalCapture {
    /// Returns the complete terminal resource observation.
    #[must_use]
    pub const fn resources(&self) -> TerminalResources {
        self.resources
    }

    /// Returns both bounded standard streams.
    #[must_use]
    pub const fn output(&self) -> &TraceOutputCapture {
        &self.output
    }
}

/// Contains one naturally completed trace and its terminal capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedTrace {
    terminal: TraceTerminalCapture,
}

impl CompletedTrace {
    /// Returns the bounded output and complete resource observation.
    #[must_use]
    pub const fn terminal(&self) -> &TraceTerminalCapture {
        &self.terminal
    }

    /// Consumes the completed trace and returns its terminal capture.
    #[must_use]
    pub fn into_terminal(self) -> TraceTerminalCapture {
        self.terminal
    }
}

/// Contains every terminal observation from one successful exact drain.
#[derive(Debug, Eq, PartialEq)]
pub struct TraceDrainReport {
    observations: Vec<TraceDrainObservation>,
    terminal: TraceTerminalCapture,
}

impl TraceDrainReport {
    /// Returns the drain observations in collection order.
    #[must_use]
    pub fn observations(&self) -> &[TraceDrainObservation] {
        &self.observations
    }

    /// Consumes the report and returns its terminal capture.
    #[must_use]
    pub fn into_terminal(self) -> TraceTerminalCapture {
        self.terminal
    }
}

/// Identifies how one traced process created another tracee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceProcessCreationKind {
    /// The parent reported a `clone` event.
    Clone,
    /// The parent reported a `fork` event.
    Fork,
    /// The parent reported a `vfork` event.
    Vfork,
}

/// Identifies one architecture-qualified diagnostic system-call family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceSyscallClass {
    /// A `bind` operation.
    Bind,
    /// A `clone` or `clone3` operation.
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

/// Contains the bounded operands captured while a tracee was stopped at entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TraceCapturedOperands {
    /// Contains one path and its syscall-specific scalar operands.
    Path {
        /// The requested output buffer size when applicable.
        buffer_bytes: Option<u64>,
        /// The directory descriptor when applicable.
        directory_fd: Option<i32>,
        /// Open, lookup, or execution flags when applicable.
        flags: Option<u64>,
        /// The stat mask when applicable.
        mask: Option<u64>,
        /// Creation mode bits when applicable.
        mode: Option<u64>,
        /// Exact supplied path bytes before the terminating NUL.
        path: Vec<u8>,
        /// `openat2` resolution flags when applicable.
        resolve: Option<u64>,
    },
    /// Contains process-creation flags when the syscall supplies them directly.
    ProcessCreate {
        /// The supplied clone flags when available.
        flags: Option<u64>,
    },
    /// Contains one existing socket and an optional bounded address.
    SocketAddress {
        /// The supplied socket-address bytes, or no address for connected `sendto`.
        address: Option<Vec<u8>>,
        /// The socket descriptor argument.
        descriptor: u32,
        /// The attempted payload size without payload bytes.
        payload_bytes: Option<u64>,
    },
    /// Contains one socket-creation request.
    SocketCreate {
        /// The address-family number.
        domain: u32,
        /// The protocol number.
        protocol: u32,
        /// The socket-type number.
        socket_type: u32,
    },
}

/// Contains the architecture-qualified input registers and bounded operands for one system call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceSyscallInvocation {
    architecture: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    number: u64,
    arguments: [u64; 6],
    class: TraceSyscallClass,
    operands: TraceCapturedOperands,
}

impl TraceSyscallInvocation {
    /// Returns the Linux audit architecture value.
    #[must_use]
    pub const fn architecture(&self) -> u32 {
        self.architecture
    }

    /// Returns the instruction pointer at system-call entry.
    #[must_use]
    pub const fn instruction_pointer(&self) -> u64 {
        self.instruction_pointer
    }

    /// Returns the stack pointer at system-call entry.
    #[must_use]
    pub const fn stack_pointer(&self) -> u64 {
        self.stack_pointer
    }

    /// Returns the architecture-qualified system-call number.
    #[must_use]
    pub const fn number(&self) -> u64 {
        self.number
    }

    /// Returns the six supplied system-call argument words.
    #[must_use]
    pub const fn arguments(&self) -> [u64; 6] {
        self.arguments
    }

    /// Returns the closed diagnostic system-call class.
    #[must_use]
    pub const fn class(&self) -> TraceSyscallClass {
        self.class
    }

    /// Returns the bounded operands captured at the syscall-entry stop.
    #[must_use]
    pub const fn operands(&self) -> &TraceCapturedOperands {
        &self.operands
    }
}

/// Identifies one terminal status from an exact wait result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceTermination {
    /// The tracee exited with one status code.
    Exit(i32),
    /// The tracee terminated because of one signal.
    Signal(i32),
}

/// Contains one complete process-tree event from an active trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActiveTraceEvent {
    /// One system call reached entry and exit stops.
    SyscallCompleted {
        /// The tracee that made the system call.
        process: TraceProcessId,
        /// The architecture-qualified entry registers.
        invocation: TraceSyscallInvocation,
        /// The raw result word reported at exit.
        result: i64,
        /// Reports whether the result is a Linux error value.
        is_error: bool,
    },
    /// One ptrace process-creation event identified a new tracee.
    ProcessCreated {
        /// The stopped parent tracee.
        parent: TraceProcessId,
        /// The kernel-reported child tracee.
        child: TraceProcessId,
        /// The process-creation event kind.
        kind: TraceProcessCreationKind,
    },
    /// One tracee replaced its executable image.
    ImageReplaced {
        /// The pre-exec tracee identity.
        former_process: TraceProcessId,
        /// The post-exec tracee identity.
        process: TraceProcessId,
        /// Thread identities removed by the successful exec.
        superseded_processes: Vec<TraceProcessId>,
        /// The pending system-call entry when it was available.
        invocation: Option<TraceSyscallInvocation>,
    },
    /// One exact terminal wait result removed a tracee from the known tree.
    ProcessExited {
        /// The terminated tracee.
        process: TraceProcessId,
        /// The exact terminal status class.
        termination: TraceTermination,
    },
    /// One known tracee stopped outside the closed observer protocol.
    UnexpectedStop {
        /// The stopped tracee.
        process: TraceProcessId,
        /// The reported stop signal.
        signal: i32,
        /// The reported ptrace event value.
        event: u32,
    },
}

/// Identifies one fail-closed active-trace observation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceObservationError {
    /// Active trace observation is unavailable on this operating system.
    UnsupportedOperatingSystem,
    /// An active trace cannot continue until the process tree is drained.
    DrainRequired,
    /// The tree was already empty before another event was requested.
    ProcessTreeDrained,
    /// One process identity was outside the Linux positive PID range.
    ProcessIdentityInvalid,
    /// A wait result changed identity outside a validated exec transition.
    ProcessIdentityChanged,
    /// One new child reused a live process identity.
    ProcessIdentityDuplicate,
    /// A process-tree event could not be retained and reconciled exactly.
    TreeReconciliationFailed,
    /// The retained process set exceeded its closed drain capacity.
    ProcessCapacityExceeded,
    /// An event referred to a process outside the exact known tree.
    ProcessUnknown,
    /// A new child reached a syscall stop before its mandatory initial stop.
    InitialStopMissing,
    /// The exact wait operation failed.
    WaitFailed,
    /// No complete event arrived before the deadline.
    WaitTimedOut,
    /// A stopped tracee could not resume at the next syscall boundary.
    ResumeFailed,
    /// The kernel event message was unavailable or invalid.
    EventMessageInvalid,
    /// System-call information was unavailable or outside the closed format.
    SyscallInformationInvalid,
    /// The Linux audit architecture has no registered decoder.
    ArchitectureUnsupported,
    /// A registered system-call family used an unsupported ABI form.
    SyscallFormUnsupported,
    /// A stopped tracee operand could not be read completely.
    TraceeMemoryReadFailed,
    /// A tracee string had no terminator within its read bound.
    TraceeStringLimitExceeded,
    /// A retained path exceeded its independent byte bound.
    PathLimitExceeded,
    /// A socket address exceeded its independent byte bound.
    SocketAddressLimitExceeded,
    /// System-call entry and exit stops were not paired.
    SyscallOrderInvalid,
    /// A process identity handle could not be created.
    ProcessHandleFailed,
    /// A tracee thread-group identity was absent or invalid.
    ThreadGroupInvalid,
    /// The known process tree could not be drained.
    DrainFailed,
    /// The known process tree did not drain before the deadline.
    DrainTimedOut,
    /// One standard-stream drain failed or could not be joined.
    StreamReadFailed,
    /// The standard-stream drains did not finish before their terminal deadline.
    StreamDrainTimedOut,
    /// The exact cgroup could not drain and complete removal.
    ResourceCleanupFailed,
    /// The exact cgroup did not return complete version 2 observations.
    ResourceObservationIncomplete,
}

impl TraceObservationError {
    /// Returns the stable machine error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "diagnostic.trace.observation.os.unsupported",
            Self::DrainRequired => "diagnostic.trace.drain-required",
            Self::ProcessTreeDrained => "diagnostic.trace.process-tree-drained",
            Self::ProcessIdentityInvalid => "diagnostic.trace.process-identity.invalid",
            Self::ProcessIdentityChanged => "diagnostic.trace.process-identity.changed",
            Self::ProcessIdentityDuplicate => "diagnostic.trace.process-identity.duplicate",
            Self::TreeReconciliationFailed => "diagnostic.trace.tree-reconciliation.failed",
            Self::ProcessCapacityExceeded => "diagnostic.trace.process-capacity.exceeded",
            Self::ProcessUnknown => "diagnostic.trace.process.unknown",
            Self::InitialStopMissing => "diagnostic.trace.initial-stop.missing",
            Self::WaitFailed => "diagnostic.trace.event-wait.failed",
            Self::WaitTimedOut => "diagnostic.trace.event-wait.timed-out",
            Self::ResumeFailed => "diagnostic.trace.event-resume.failed",
            Self::EventMessageInvalid => "diagnostic.trace.event-message.invalid",
            Self::SyscallInformationInvalid => "diagnostic.trace.syscall-information.invalid",
            Self::ArchitectureUnsupported => "diagnostic.trace.architecture.unsupported",
            Self::SyscallFormUnsupported => "diagnostic.trace.syscall-form.unsupported",
            Self::TraceeMemoryReadFailed => "diagnostic.trace.tracee-memory.read-failed",
            Self::TraceeStringLimitExceeded => "diagnostic.trace.tracee-string.limit-exceeded",
            Self::PathLimitExceeded => "diagnostic.trace.path.limit-exceeded",
            Self::SocketAddressLimitExceeded => "diagnostic.trace.socket-address.limit-exceeded",
            Self::SyscallOrderInvalid => "diagnostic.trace.syscall-order.invalid",
            Self::ProcessHandleFailed => "diagnostic.trace.process-handle.failed",
            Self::ThreadGroupInvalid => "diagnostic.trace.thread-group.invalid",
            Self::DrainFailed => "diagnostic.trace.drain.failed",
            Self::DrainTimedOut => "diagnostic.trace.drain.timed-out",
            Self::StreamReadFailed => "diagnostic.trace.stream.read-failed",
            Self::StreamDrainTimedOut => "diagnostic.trace.stream-drain.timed-out",
            Self::ResourceCleanupFailed => "diagnostic.trace.resource-cleanup.failed",
            Self::ResourceObservationIncomplete => {
                "diagnostic.trace.resource-observation.incomplete"
            }
        }
    }
}

impl fmt::Display for TraceObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for TraceObservationError {}

fn map_acknowledgement_receive_error(error: LauncherError) -> TraceStartupError {
    match error {
        LauncherError::ChannelTimeout => TraceStartupError::AcknowledgementTimedOut,
        _ => TraceStartupError::AcknowledgementReceiveFailed,
    }
}

fn continue_trace(process: TraceProcessId) -> Result<(), TraceStartupError> {
    #[cfg(target_os = "linux")]
    {
        crate::sys::trace_continue(process.get()).map_err(|_| TraceStartupError::ResumeFailed)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = process;
        Err(TraceStartupError::UnsupportedOperatingSystem)
    }
}

fn stop_trace(process: TraceProcessId) -> Result<(), TraceStartupError> {
    #[cfg(target_os = "linux")]
    {
        crate::sys::trace_stop(process.get()).map_err(|_| TraceStartupError::StopFailed)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = process;
        Err(TraceStartupError::UnsupportedOperatingSystem)
    }
}

fn wait_for_exact_stop(
    session: &mut TraceSession,
    deadline: TraceDeadline,
    expected_signal: i32,
    expected_event: u32,
) -> Result<(), TraceStartupError> {
    #[cfg(target_os = "linux")]
    {
        let process = session.process;
        loop {
            if deadline.expired() {
                return Err(TraceStartupError::WaitTimedOut);
            }
            let observation = crate::sys::trace_wait_nonblocking(process.get())
                .map_err(|_| TraceStartupError::WaitFailed)?;
            if matches!(
                observation,
                Some(
                    crate::sys::TraceWaitStatus::Exited { .. }
                        | crate::sys::TraceWaitStatus::Signaled { .. }
                )
            ) {
                session.record_root_reaped();
            }
            if deadline.expired() {
                return Err(TraceStartupError::WaitTimedOut);
            }
            match observation {
                Some(crate::sys::TraceWaitStatus::Stopped { signal, event })
                    if signal == expected_signal && event == expected_event =>
                {
                    return Ok(());
                }
                Some(crate::sys::TraceWaitStatus::Stopped { .. }) => {
                    return Err(TraceStartupError::StopInvalid);
                }
                Some(crate::sys::TraceWaitStatus::Exited { code }) => {
                    let _ = code;
                    return Err(TraceStartupError::TraceeExited);
                }
                Some(crate::sys::TraceWaitStatus::Signaled { signal }) => {
                    let _ = signal;
                    return Err(TraceStartupError::TraceeExited);
                }
                None => std::thread::sleep(TRACE_POLL_INTERVAL),
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (session, deadline, expected_signal, expected_event);
        Err(TraceStartupError::UnsupportedOperatingSystem)
    }
}

/// Identifies one fail-closed diagnostic trace-start failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceStartupError {
    /// The host operating system is not Linux.
    UnsupportedOperatingSystem,
    /// A process identifier is outside the Linux positive PID range.
    ProcessIdInvalid,
    /// The retained process limit is zero or exceeds the diagnostic maximum.
    ProcessLimitInvalid,
    /// A tracee-operand capture limit is zero or exceeds its maximum.
    CaptureLimitInvalid,
    /// The absolute trace deadline is zero or cannot be represented.
    DeadlineInvalid,
    /// An inherited descriptor is standard, invalid, or duplicated.
    DescriptorSetInvalid,
    /// The prepared version 2 cgroup identity or resource controls did not match.
    CgroupIdentityMismatch,
    /// The prepared version 2 cgroup was already used or had nonzero observations.
    CgroupNotFresh,
    /// The stopped child could not be placed and read back in the exact cgroup.
    CgroupPlacementFailed,
    /// The launcher is not one exact executable launcher artifact.
    LauncherIdentityInvalid,
    /// The private launcher channel pair could not be created.
    ChannelCreationFailed,
    /// The prepared traced launcher could not be spawned.
    SpawnFailed,
    /// A configured standard stream was unavailable after spawn.
    StreamUnavailable,
    /// A standard-stream drain thread could not be started.
    StreamDrainStartFailed,
    /// A standard-stream pipe could not be made cancellable.
    StreamConfigurationFailed,
    /// The traced process status could not be read.
    WaitFailed,
    /// The traced process did not stop before the deadline.
    WaitTimedOut,
    /// The traced process exited before the required setup stop.
    TraceeExited,
    /// The traced process stopped with an unexpected signal or event.
    StopInvalid,
    /// The tracee could not be resumed without signal injection.
    ResumeFailed,
    /// The acknowledged launcher could not be stopped before release.
    StopFailed,
    /// The exact install request could not be sent on the retained channel.
    InstallSendFailed,
    /// The boundary acknowledgement did not arrive before the deadline.
    AcknowledgementTimedOut,
    /// The retained channel could not return a boundary acknowledgement.
    AcknowledgementReceiveFailed,
    /// The retained channel returned a different launcher message.
    AcknowledgementInvalid,
    /// The boundary acknowledgement identities did not match.
    BoundaryIdentityMismatch,
    /// The launcher reported a typed failure instead of an acknowledgement.
    LauncherReportedFailure,
    /// The exact diagnostic trace options could not be installed.
    OptionsInstallFailed,
    /// The identity-bound exec release could not be sent.
    ReleaseSendFailed,
    /// The root process identity handle could not be created.
    ProcessHandleFailed,
}

impl TraceStartupError {
    /// Returns the stable machine error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "diagnostic.trace.os.unsupported",
            Self::ProcessIdInvalid => "diagnostic.trace.process-id.invalid",
            Self::ProcessLimitInvalid => "diagnostic.trace.process-limit.invalid",
            Self::CaptureLimitInvalid => "diagnostic.trace.capture-limit.invalid",
            Self::DeadlineInvalid => "diagnostic.trace.deadline.invalid",
            Self::DescriptorSetInvalid => "diagnostic.trace.descriptor-set.invalid",
            Self::CgroupIdentityMismatch => "diagnostic.trace.cgroup-identity.mismatch",
            Self::CgroupNotFresh => "diagnostic.trace.cgroup.not-fresh",
            Self::CgroupPlacementFailed => "diagnostic.trace.cgroup-placement.failed",
            Self::LauncherIdentityInvalid => "diagnostic.trace.launcher-identity.invalid",
            Self::ChannelCreationFailed => "diagnostic.trace.channel.creation-failed",
            Self::SpawnFailed => "diagnostic.trace.spawn.failed",
            Self::StreamUnavailable => "diagnostic.trace.stream.unavailable",
            Self::StreamDrainStartFailed => "diagnostic.trace.stream-drain.start-failed",
            Self::StreamConfigurationFailed => "diagnostic.trace.stream.configuration-failed",
            Self::WaitFailed => "diagnostic.trace.wait.failed",
            Self::WaitTimedOut => "diagnostic.trace.wait.timed-out",
            Self::TraceeExited => "diagnostic.trace.tracee.exited",
            Self::StopInvalid => "diagnostic.trace.stop.invalid",
            Self::ResumeFailed => "diagnostic.trace.resume.failed",
            Self::StopFailed => "diagnostic.trace.stop.failed",
            Self::InstallSendFailed => "diagnostic.trace.install.send-failed",
            Self::AcknowledgementTimedOut => "diagnostic.trace.acknowledgement.timed-out",
            Self::AcknowledgementReceiveFailed => "diagnostic.trace.acknowledgement.receive-failed",
            Self::AcknowledgementInvalid => "diagnostic.trace.acknowledgement.invalid",
            Self::BoundaryIdentityMismatch => "diagnostic.trace.boundary-identity.mismatch",
            Self::LauncherReportedFailure => "diagnostic.trace.launcher.reported-failure",
            Self::OptionsInstallFailed => "diagnostic.trace.options.install-failed",
            Self::ReleaseSendFailed => "diagnostic.trace.release.send-failed",
            Self::ProcessHandleFailed => "diagnostic.trace.process-handle.failed",
        }
    }
}

impl fmt::Display for TraceStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for TraceStartupError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_ids_deadlines_and_error_codes_are_closed() {
        assert_eq!(
            TraceProcessId::new(0),
            Err(TraceStartupError::ProcessIdInvalid)
        );
        assert_eq!(
            TraceProcessId::new(i32::MAX as u32 + 1),
            Err(TraceStartupError::ProcessIdInvalid)
        );
        assert_eq!(
            TraceProcessLimit::new(0),
            Err(TraceStartupError::ProcessLimitInvalid)
        );
        assert_eq!(
            TraceProcessLimit::new(u64::from(MAX_TRACE_PROCESS_LIMIT) + 1),
            Err(TraceStartupError::ProcessLimitInvalid)
        );
        assert_eq!(
            TraceCaptureLimits::new(0, 1, 1),
            Err(TraceStartupError::CaptureLimitInvalid)
        );
        assert_eq!(
            TraceCaptureLimits::new(1, u64::from(MAX_TRACE_SOCKET_ADDRESS_BYTES) + 1, 1),
            Err(TraceStartupError::CaptureLimitInvalid)
        );
        assert!(matches!(
            TraceDeadline::after(Duration::ZERO),
            Err(TraceStartupError::DeadlineInvalid)
        ));
        let mut codes = [
            TraceStartupError::UnsupportedOperatingSystem,
            TraceStartupError::ProcessIdInvalid,
            TraceStartupError::ProcessLimitInvalid,
            TraceStartupError::CaptureLimitInvalid,
            TraceStartupError::DeadlineInvalid,
            TraceStartupError::DescriptorSetInvalid,
            TraceStartupError::CgroupIdentityMismatch,
            TraceStartupError::CgroupNotFresh,
            TraceStartupError::CgroupPlacementFailed,
            TraceStartupError::LauncherIdentityInvalid,
            TraceStartupError::ChannelCreationFailed,
            TraceStartupError::SpawnFailed,
            TraceStartupError::StreamUnavailable,
            TraceStartupError::StreamDrainStartFailed,
            TraceStartupError::StreamConfigurationFailed,
            TraceStartupError::WaitFailed,
            TraceStartupError::WaitTimedOut,
            TraceStartupError::TraceeExited,
            TraceStartupError::StopInvalid,
            TraceStartupError::ResumeFailed,
            TraceStartupError::StopFailed,
            TraceStartupError::InstallSendFailed,
            TraceStartupError::AcknowledgementTimedOut,
            TraceStartupError::AcknowledgementReceiveFailed,
            TraceStartupError::AcknowledgementInvalid,
            TraceStartupError::BoundaryIdentityMismatch,
            TraceStartupError::LauncherReportedFailure,
            TraceStartupError::OptionsInstallFailed,
            TraceStartupError::ReleaseSendFailed,
            TraceStartupError::ProcessHandleFailed,
        ]
        .map(TraceStartupError::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
    }

    #[test]
    fn observation_errors_have_unique_stable_codes() {
        let mut codes = [
            TraceObservationError::UnsupportedOperatingSystem,
            TraceObservationError::DrainRequired,
            TraceObservationError::ProcessTreeDrained,
            TraceObservationError::ProcessIdentityInvalid,
            TraceObservationError::ProcessIdentityChanged,
            TraceObservationError::ProcessIdentityDuplicate,
            TraceObservationError::TreeReconciliationFailed,
            TraceObservationError::ProcessCapacityExceeded,
            TraceObservationError::ProcessUnknown,
            TraceObservationError::InitialStopMissing,
            TraceObservationError::WaitFailed,
            TraceObservationError::WaitTimedOut,
            TraceObservationError::ResumeFailed,
            TraceObservationError::EventMessageInvalid,
            TraceObservationError::SyscallInformationInvalid,
            TraceObservationError::ArchitectureUnsupported,
            TraceObservationError::SyscallFormUnsupported,
            TraceObservationError::TraceeMemoryReadFailed,
            TraceObservationError::TraceeStringLimitExceeded,
            TraceObservationError::PathLimitExceeded,
            TraceObservationError::SocketAddressLimitExceeded,
            TraceObservationError::SyscallOrderInvalid,
            TraceObservationError::ProcessHandleFailed,
            TraceObservationError::ThreadGroupInvalid,
            TraceObservationError::DrainFailed,
            TraceObservationError::DrainTimedOut,
            TraceObservationError::StreamReadFailed,
            TraceObservationError::StreamDrainTimedOut,
            TraceObservationError::ResourceCleanupFailed,
            TraceObservationError::ResourceObservationIncomplete,
        ]
        .map(TraceObservationError::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
    }

    #[test]
    fn diagnostic_lifecycle_does_not_accept_refreshable_deadlines() {
        let _: fn(SpawnedTrace) -> Result<InitialExecStop, TraceStartupError> =
            SpawnedTrace::wait_for_initial_exec_stop;
        let _: fn(InitialExecStop) -> Result<LauncherPause, TraceStartupError> =
            InitialExecStop::continue_to_launcher_pause;
        let _: fn(LauncherPause) -> Result<BoundaryRunning, TraceStartupError> =
            LauncherPause::continue_for_boundary;
        let _: fn(BoundaryRunning) -> Result<AcknowledgedTraceStop, TraceStartupError> =
            BoundaryRunning::receive_acknowledgement_and_stop;
        let _: fn(AcknowledgedTraceStop) -> Result<TraceReady, TraceStartupError> =
            AcknowledgedTraceStop::install_options;
        let _: fn(
            TraceReady,
            TraceProcessLimit,
            TraceCaptureLimits,
        ) -> Result<ActiveTrace, TraceStartupError> = TraceReady::release;
        let _: fn(&mut ActiveTrace) -> Result<ActiveTraceEvent, TraceObservationError> =
            ActiveTrace::next_event;
        let _: fn(ActiveTrace) -> Result<DrainingTrace, TraceObservationError> =
            ActiveTrace::begin_termination;
        let _: fn(DrainingTrace) -> Result<TraceDrainReport, TraceObservationError> =
            DrainingTrace::finish;
        let _: fn(ActiveTrace) -> Result<TraceDrainReport, TraceObservationError> =
            ActiveTrace::terminate_and_drain;
    }

    #[test]
    fn diagnostic_stream_capture_drains_after_its_retained_prefix() {
        let cancellation = AtomicBool::new(false);
        let exact = capture_trace_stream(&b"abc"[..], OutputByteLimit::new(3), &cancellation)
            .expect("exact diagnostic stream capture");
        assert_eq!(exact.bytes(), b"abc");
        assert_eq!(exact.capture(), StreamCapture::Complete);

        let truncated =
            capture_trace_stream(&b"abcdef"[..], OutputByteLimit::new(3), &cancellation)
                .expect("truncated diagnostic stream capture");
        assert_eq!(truncated.bytes(), b"abc");
        assert_eq!(truncated.capture(), StreamCapture::Truncated);

        let zero = capture_trace_stream(&b"x"[..], OutputByteLimit::new(0), &cancellation)
            .expect("zero-limit diagnostic stream drain");
        assert!(zero.bytes().is_empty());
        assert_eq!(zero.capture(), StreamCapture::Truncated);

        cancellation.store(true, Ordering::Release);
        let cancelled =
            capture_trace_stream(&b"unread"[..], OutputByteLimit::new(6), &cancellation)
                .expect_err("cancelled diagnostic stream drain");
        assert_eq!(cancelled.kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn diagnostic_output_limits_keep_streams_independent() {
        let limits = TraceOutputLimits::new(OutputByteLimit::new(17), OutputByteLimit::new(29));
        assert_eq!(limits.stdout().get(), 17);
        assert_eq!(limits.stderr().get(), 29);
    }

    #[test]
    fn traced_child_numeric_cleanup_disarms_for_pidfd_and_raw_reap() {
        let mut state = TraceChildCleanupState::Live;
        assert!(state.requires_cleanup());
        state.record_identity_stable_handle();
        assert_eq!(state, TraceChildCleanupState::IdentityStableHandleOwned);
        assert!(!state.requires_cleanup());
        state.record_trace_wait_reap();
        assert_eq!(state, TraceChildCleanupState::ReapedByTraceWait);
        assert!(!state.requires_cleanup());
    }

    #[test]
    fn diagnostic_stream_completion_cancels_at_its_terminal_deadline() {
        struct PendingReader;

        impl io::Read for PendingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
        }

        let cancellation = Arc::new(AtomicBool::new(false));
        let stdout_cancellation = Arc::clone(&cancellation);
        let stderr_cancellation = Arc::clone(&cancellation);
        let stdout = std::thread::spawn(move || {
            capture_trace_stream(PendingReader, OutputByteLimit::new(1), &stdout_cancellation)
        });
        let stderr = std::thread::spawn(move || {
            capture_trace_stream(PendingReader, OutputByteLimit::new(1), &stderr_cancellation)
        });
        let mut readers = TraceStreamReaders {
            stdout: Some(stdout),
            stderr: Some(stderr),
            cancellation,
        };

        assert_eq!(
            readers.finish_before(Instant::now()),
            Err(TraceObservationError::StreamDrainTimedOut)
        );
        assert!(readers.stdout.is_none());
        assert!(readers.stderr.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn thread_group_parser_requires_one_exact_positive_field() {
        assert_eq!(
            parse_thread_group_id("Name:\ttarget\nTgid:\t42\nPid:\t43\n"),
            Ok(TraceProcessId::new(42).expect("positive process identity"))
        );
        for invalid in [
            "Name:\ttarget\nPid:\t43\n",
            "Tgid: 42\n",
            "Tgid:\t0\n",
            "Tgid:\t42\nTgid:\t42\n",
            "Tgid:\tnot-a-number\n",
        ] {
            assert_eq!(
                parse_thread_group_id(invalid),
                Err(TraceObservationError::ThreadGroupInvalid)
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn syscall_decoder_qualifies_numbers_by_architecture() {
        let x86_open = TraceSyscallRegisters {
            architecture: AUDIT_ARCH_X86_64,
            instruction_pointer: 1,
            stack_pointer: 2,
            number: 2,
            arguments: [0x1000, 0x12, 0o640, 0, 0, 0],
        };
        assert!(matches!(
            decode_trace_syscall(x86_open),
            Ok(Some(TraceCaptureRequest::Path {
                class: TraceSyscallClass::Open,
                path_address: 0x1000,
                flags: Some(0x12),
                mode: Some(0o640),
                ..
            }))
        ));

        let aarch64_openat = TraceSyscallRegisters {
            architecture: AUDIT_ARCH_AARCH64,
            instruction_pointer: 3,
            stack_pointer: 4,
            number: 56,
            arguments: [u64::MAX - 99, 0x2000, 0x34, 0o600, 0, 0],
        };
        assert!(matches!(
            decode_trace_syscall(aarch64_openat),
            Ok(Some(TraceCaptureRequest::Path {
                class: TraceSyscallClass::Openat,
                directory_fd: Some(-100),
                path_address: 0x2000,
                flags: Some(0x34),
                mode: Some(0o600),
                ..
            }))
        ));

        let aarch64_number_two = TraceSyscallRegisters {
            architecture: AUDIT_ARCH_AARCH64,
            instruction_pointer: 5,
            stack_pointer: 6,
            number: 2,
            arguments: [0; 6],
        };
        assert_eq!(decode_trace_syscall(aarch64_number_two), Ok(None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn syscall_decoder_rejects_unknown_architecture_and_x32_form() {
        let unknown = TraceSyscallRegisters {
            architecture: 0,
            instruction_pointer: 0,
            stack_pointer: 0,
            number: 2,
            arguments: [0; 6],
        };
        assert_eq!(
            decode_trace_syscall(unknown),
            Err(TraceObservationError::ArchitectureUnsupported)
        );

        let x32 = TraceSyscallRegisters {
            architecture: AUDIT_ARCH_X86_64,
            instruction_pointer: 0,
            stack_pointer: 0,
            number: 0x4000_0002,
            arguments: [0; 6],
        };
        assert_eq!(
            decode_trace_syscall(x32),
            Err(TraceObservationError::SyscallFormUnsupported)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nonleader_exec_preserves_pending_syscall_until_exit_pair() {
        let leader = TraceProcessId::new(41).expect("positive leader identity");
        let former = TraceProcessId::new(42).expect("positive former identity");
        let sibling = TraceProcessId::new(43).expect("positive sibling identity");
        let unrelated = TraceProcessId::new(51).expect("positive unrelated identity");
        let invocation = TraceSyscallInvocation {
            architecture: AUDIT_ARCH_X86_64,
            instruction_pointer: 0x1234,
            stack_pointer: 0x5678,
            number: 59,
            arguments: [1, 2, 3, 4, 5, 6],
            class: TraceSyscallClass::Execve,
            operands: TraceCapturedOperands::Path {
                buffer_bytes: None,
                directory_fd: None,
                flags: None,
                mask: None,
                mode: None,
                path: b"/bin/tool".to_vec(),
                resolve: None,
            },
        };
        let pending = PendingTraceSyscall::Captured(invocation.clone());
        let mut processes = BTreeMap::from([
            (leader, TraceeState::observing(leader)),
            (
                former,
                TraceeState {
                    thread_group: leader,
                    awaiting_initial_stop: false,
                    pending: Some(pending.clone()),
                },
            ),
            (sibling, TraceeState::observing(leader)),
            (unrelated, TraceeState::observing(unrelated)),
        ]);

        assert_eq!(
            reconcile_exec_processes(&mut processes, leader, leader, former),
            Ok(ExecIdentityChange {
                former,
                survivor: leader,
                superseded: vec![leader, sibling],
            })
        );
        assert_eq!(processes.len(), 2);
        assert!(!processes.contains_key(&former));
        assert!(!processes.contains_key(&sibling));
        assert_eq!(
            processes
                .get(&leader)
                .and_then(|state| state.pending.clone()),
            Some(pending.clone())
        );
        assert_eq!(
            processes
                .get_mut(&leader)
                .and_then(|state| state.pending.take()),
            Some(pending)
        );
        assert!(
            processes
                .get(&leader)
                .is_some_and(|state| state.pending.is_none())
        );
        assert!(processes.contains_key(&unrelated));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exec_identity_rejects_wrong_wait_owner_and_foreign_former_thread() {
        let leader = TraceProcessId::new(61).expect("positive leader identity");
        let former = TraceProcessId::new(62).expect("positive former identity");
        let foreign = TraceProcessId::new(71).expect("positive foreign identity");
        let mut processes = BTreeMap::from([
            (leader, TraceeState::observing(leader)),
            (former, TraceeState::observing(leader)),
            (foreign, TraceeState::observing(foreign)),
        ]);

        assert_eq!(
            reconcile_exec_processes(&mut processes, former, leader, former),
            Err(TraceObservationError::ProcessIdentityChanged)
        );
        assert_eq!(
            reconcile_exec_processes(&mut processes, leader, leader, foreign),
            Err(TraceObservationError::ProcessIdentityChanged)
        );
    }
}
