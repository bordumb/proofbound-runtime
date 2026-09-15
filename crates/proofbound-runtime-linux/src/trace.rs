//! Starts one diagnostic trace without adding authority to the child.

use core::fmt;
use std::num::NonZeroU32;
use std::os::fd::BorrowedFd;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use proofbound_runtime_core::ArtifactRole;

use crate::{
    Architecture, ExecRelease, InstallRequest, LauncherChannel, LauncherError, LauncherMessage,
    ResolvedFile,
};

const TRACE_POLL_INTERVAL: Duration = Duration::from_millis(1);
const SIGNAL_STOP: i32 = 19;
const SIGNAL_TRAP: i32 = 5;

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

/// Contains one absolute monotonic deadline for trace setup.
#[derive(Clone, Copy, Debug)]
pub struct TraceDeadline(Instant);

impl TraceDeadline {
    /// Creates a deadline after one nonzero duration.
    pub fn after(duration: Duration) -> Result<Self, TraceStartupError> {
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
}

/// Contains one command and its live inherited descriptors before spawn.
#[derive(Debug)]
pub struct PreparedTraceCommand<'descriptor> {
    command: Command,
    launcher: &'descriptor ResolvedFile,
    supervisor_channel: LauncherChannel,
    launcher_channel: LauncherChannel,
    request: InstallRequest,
    _descriptors: Vec<BorrowedFd<'descriptor>>,
}

impl PreparedTraceCommand<'_> {
    /// Spawns exactly one child whose first exec requests tracing.
    pub fn spawn(mut self) -> Result<SpawnedTrace, TraceStartupError> {
        self.launcher
            .revalidate_identity()
            .map_err(|_| TraceStartupError::LauncherIdentityInvalid)?;
        let child = self
            .command
            .spawn()
            .map_err(|_| TraceStartupError::SpawnFailed)?;
        let child = TraceChild(child);
        let process = TraceProcessId::new(child.0.id())?;
        drop(self.launcher_channel);
        Ok(SpawnedTrace {
            session: TraceSession {
                _child: child,
                process,
                channel: self.supervisor_channel,
                request: self.request,
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
        );
        Err(TraceStartupError::UnsupportedOperatingSystem)
    }
}

#[derive(Debug)]
struct TraceChild(Child);

impl Drop for TraceChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Debug)]
struct TraceSession {
    _child: TraceChild,
    process: TraceProcessId,
    channel: LauncherChannel,
    request: InstallRequest,
}

/// Owns the exact spawned child before its mandatory post-exec trace stop.
#[derive(Debug)]
pub struct SpawnedTrace {
    session: TraceSession,
}

impl SpawnedTrace {
    /// Waits for the exact post-exec trace stop of the spawned child.
    pub fn wait_for_initial_exec_stop(
        self,
        deadline: TraceDeadline,
    ) -> Result<InitialExecStop, TraceStartupError> {
        wait_for_exact_stop(self.session.process, deadline, SIGNAL_TRAP, 0)?;
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
    pub fn continue_to_launcher_pause(
        self,
        deadline: TraceDeadline,
    ) -> Result<LauncherPause, TraceStartupError> {
        continue_trace(self.session.process)?;
        wait_for_exact_stop(self.session.process, deadline, SIGNAL_STOP, 0)?;
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
        self,
        deadline: TraceDeadline,
    ) -> Result<AcknowledgedTraceStop, TraceStartupError> {
        if deadline.expired() {
            return Err(TraceStartupError::AcknowledgementTimedOut);
        }
        let response = self
            .session
            .channel
            .receive_timeout(deadline.0.saturating_duration_since(Instant::now()))
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
        stop_trace(self.session.process)?;
        wait_for_exact_stop(self.session.process, deadline, SIGNAL_STOP, 0)?;
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
        #[cfg(target_os = "linux")]
        {
            crate::sys::install_diagnostic_trace_options(self.session.process.get())
                .map_err(|_| TraceStartupError::OptionsInstallFailed)?;
            Ok(TraceReady {
                session: self.session,
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
}

impl TraceReady {
    /// Sends the bound exec release and starts syscall-stop observation.
    pub fn release(self) -> Result<ActiveTrace, TraceStartupError> {
        self.session
            .channel
            .send(&LauncherMessage::ExecRelease(ExecRelease::new(
                self.session.request.identity(),
            )))
            .map_err(|_| TraceStartupError::ReleaseSendFailed)?;
        #[cfg(target_os = "linux")]
        {
            crate::sys::trace_syscall(self.session.process.get())
                .map_err(|_| TraceStartupError::ResumeFailed)?;
            Ok(ActiveTrace {
                session: self.session,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(TraceStartupError::UnsupportedOperatingSystem)
        }
    }
}

/// Identifies an active diagnostic process-tree trace.
#[derive(Debug)]
pub struct ActiveTrace {
    session: TraceSession,
}

impl ActiveTrace {
    /// Returns the diagnostic process-tree root.
    #[must_use]
    pub const fn root(&self) -> TraceProcessId {
        self.session.process
    }
}

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
    process: TraceProcessId,
    deadline: TraceDeadline,
    expected_signal: i32,
    expected_event: u32,
) -> Result<(), TraceStartupError> {
    #[cfg(target_os = "linux")]
    {
        loop {
            match crate::sys::trace_wait_nonblocking(process.get())
                .map_err(|_| TraceStartupError::WaitFailed)?
            {
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
                None if deadline.expired() => return Err(TraceStartupError::WaitTimedOut),
                None => std::thread::sleep(TRACE_POLL_INTERVAL),
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (process, deadline, expected_signal, expected_event);
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
    /// The absolute trace deadline is zero or cannot be represented.
    DeadlineInvalid,
    /// An inherited descriptor is standard, invalid, or duplicated.
    DescriptorSetInvalid,
    /// The launcher is not one exact executable launcher artifact.
    LauncherIdentityInvalid,
    /// The private launcher channel pair could not be created.
    ChannelCreationFailed,
    /// The prepared traced launcher could not be spawned.
    SpawnFailed,
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
}

impl TraceStartupError {
    /// Returns the stable machine error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "diagnostic.trace.os.unsupported",
            Self::ProcessIdInvalid => "diagnostic.trace.process-id.invalid",
            Self::DeadlineInvalid => "diagnostic.trace.deadline.invalid",
            Self::DescriptorSetInvalid => "diagnostic.trace.descriptor-set.invalid",
            Self::LauncherIdentityInvalid => "diagnostic.trace.launcher-identity.invalid",
            Self::ChannelCreationFailed => "diagnostic.trace.channel.creation-failed",
            Self::SpawnFailed => "diagnostic.trace.spawn.failed",
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
        assert!(matches!(
            TraceDeadline::after(Duration::ZERO),
            Err(TraceStartupError::DeadlineInvalid)
        ));
        let mut codes = [
            TraceStartupError::UnsupportedOperatingSystem,
            TraceStartupError::ProcessIdInvalid,
            TraceStartupError::DeadlineInvalid,
            TraceStartupError::DescriptorSetInvalid,
            TraceStartupError::LauncherIdentityInvalid,
            TraceStartupError::ChannelCreationFailed,
            TraceStartupError::SpawnFailed,
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
        ]
        .map(TraceStartupError::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
    }
}
