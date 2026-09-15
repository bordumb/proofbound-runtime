//! Starts one diagnostic trace without adding authority to the child.

use core::fmt;
use std::num::NonZeroU32;
use std::os::fd::BorrowedFd;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use crate::{BoundaryInstalled, ExecRelease, LauncherChannel, LauncherIdentity, LauncherMessage};

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

    #[cfg(target_os = "linux")]
    fn expired(self) -> bool {
        Instant::now() >= self.0
    }
}

/// Contains one command and its live inherited descriptors before spawn.
#[derive(Debug)]
pub struct PreparedTraceCommand<'descriptor> {
    command: Command,
    _descriptors: Vec<BorrowedFd<'descriptor>>,
}

impl PreparedTraceCommand<'_> {
    /// Spawns exactly one child whose first exec requests tracing.
    pub fn spawn(mut self) -> Result<SpawnedTrace, TraceStartupError> {
        let child = self
            .command
            .spawn()
            .map_err(|_| TraceStartupError::SpawnFailed)?;
        let child = TraceChild(child);
        let process = TraceProcessId::new(child.0.id())?;
        Ok(SpawnedTrace { child, process })
    }
}

/// Prepares inherited descriptors and `PTRACE_TRACEME` for one child exec.
pub fn prepare_traced_launcher<'descriptor>(
    command: Command,
    inherited_descriptors: &[BorrowedFd<'descriptor>],
) -> Result<PreparedTraceCommand<'descriptor>, TraceStartupError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;

        let mut command = command;
        let mut descriptors = inherited_descriptors
            .iter()
            .map(|descriptor| descriptor.as_raw_fd())
            .collect::<Vec<_>>();
        descriptors.sort_unstable();
        if descriptors.iter().any(|descriptor| *descriptor < 3)
            || descriptors.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(TraceStartupError::DescriptorSetInvalid);
        }
        crate::sys::prepare_traced_exec(&mut command, descriptors);
        Ok(PreparedTraceCommand {
            command,
            _descriptors: inherited_descriptors.to_vec(),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (command, inherited_descriptors);
        Err(TraceStartupError::UnsupportedOperatingSystem)
    }
}

#[derive(Debug)]
struct TraceChild(Child);

impl TraceChild {
    fn child_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for TraceChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Owns the exact spawned child before its mandatory post-exec trace stop.
#[derive(Debug)]
pub struct SpawnedTrace {
    child: TraceChild,
    process: TraceProcessId,
}

impl SpawnedTrace {
    /// Waits for the exact post-exec trace stop of the spawned child.
    pub fn wait_for_initial_exec_stop(
        self,
        deadline: TraceDeadline,
    ) -> Result<InitialExecStop, TraceStartupError> {
        wait_for_exact_stop(self.process, deadline, SIGNAL_TRAP, 0)?;
        Ok(InitialExecStop {
            child: self.child,
            process: self.process,
        })
    }
}

/// Owns the exact child at the mandatory post-exec trace stop.
#[derive(Debug)]
pub struct InitialExecStop {
    child: TraceChild,
    process: TraceProcessId,
}

impl InitialExecStop {
    /// Resumes the trusted launcher until its declared self-stop.
    pub fn continue_to_launcher_pause(
        self,
        deadline: TraceDeadline,
    ) -> Result<LauncherPause, TraceStartupError> {
        continue_trace(self.process)?;
        wait_for_exact_stop(self.process, deadline, SIGNAL_STOP, 0)?;
        Ok(LauncherPause {
            child: self.child,
            process: self.process,
        })
    }
}

/// Owns the launcher at its pre-policy self-stop.
#[derive(Debug)]
pub struct LauncherPause {
    child: TraceChild,
    process: TraceProcessId,
}

impl LauncherPause {
    /// Returns the exact stopped launcher process identifier.
    #[must_use]
    pub const fn process(&self) -> TraceProcessId {
        self.process
    }

    /// Borrows the stopped launcher for stream and cgroup preparation.
    pub fn child_mut(&mut self) -> &mut Child {
        self.child.child_mut()
    }

    /// Resumes trusted launcher code for production-boundary installation.
    pub fn continue_for_boundary(self) -> Result<BoundaryRunning, TraceStartupError> {
        continue_trace(self.process)?;
        Ok(BoundaryRunning {
            child: self.child,
            process: self.process,
        })
    }
}

/// Owns a launcher that can install its production boundary but cannot exec.
#[derive(Debug)]
pub struct BoundaryRunning {
    child: TraceChild,
    process: TraceProcessId,
}

impl BoundaryRunning {
    /// Stops the acknowledged launcher at the pre-release trace point.
    pub fn stop_after_acknowledgement(
        self,
        acknowledgement: BoundaryInstalled,
        expected: LauncherIdentity,
        deadline: TraceDeadline,
    ) -> Result<AcknowledgedTraceStop, TraceStartupError> {
        if acknowledgement.identity() != expected {
            return Err(TraceStartupError::BoundaryIdentityMismatch);
        }
        stop_trace(self.process)?;
        wait_for_exact_stop(self.process, deadline, SIGNAL_STOP, 0)?;
        Ok(AcknowledgedTraceStop {
            child: self.child,
            process: self.process,
            identity: expected,
        })
    }
}

/// Owns an acknowledged launcher stopped before the supervisor release.
#[derive(Debug)]
pub struct AcknowledgedTraceStop {
    child: TraceChild,
    process: TraceProcessId,
    identity: LauncherIdentity,
}

impl AcknowledgedTraceStop {
    /// Installs the exact closed diagnostic process-tree trace options.
    pub fn install_options(self) -> Result<TraceReady, TraceStartupError> {
        #[cfg(target_os = "linux")]
        {
            crate::sys::install_diagnostic_trace_options(self.process.get())
                .map_err(|_| TraceStartupError::OptionsInstallFailed)?;
            Ok(TraceReady {
                child: self.child,
                process: self.process,
                identity: self.identity,
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
    child: TraceChild,
    process: TraceProcessId,
    identity: LauncherIdentity,
}

impl TraceReady {
    /// Sends the bound exec release and starts syscall-stop observation.
    pub fn release(self, channel: &LauncherChannel) -> Result<ActiveTrace, TraceStartupError> {
        channel
            .send(&LauncherMessage::ExecRelease(ExecRelease::new(
                self.identity,
            )))
            .map_err(|_| TraceStartupError::ReleaseSendFailed)?;
        #[cfg(target_os = "linux")]
        {
            crate::sys::trace_syscall(self.process.get())
                .map_err(|_| TraceStartupError::ResumeFailed)?;
            Ok(ActiveTrace {
                child: self.child,
                root: self.process,
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
    child: TraceChild,
    root: TraceProcessId,
}

impl ActiveTrace {
    /// Returns the diagnostic process-tree root.
    #[must_use]
    pub const fn root(&self) -> TraceProcessId {
        self.root
    }

    /// Borrows the exact traced child for the bounded event loop.
    pub fn child_mut(&mut self) -> &mut Child {
        self.child.child_mut()
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
    /// The boundary acknowledgement identities did not match.
    BoundaryIdentityMismatch,
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
            Self::SpawnFailed => "diagnostic.trace.spawn.failed",
            Self::WaitFailed => "diagnostic.trace.wait.failed",
            Self::WaitTimedOut => "diagnostic.trace.wait.timed-out",
            Self::TraceeExited => "diagnostic.trace.tracee.exited",
            Self::StopInvalid => "diagnostic.trace.stop.invalid",
            Self::ResumeFailed => "diagnostic.trace.resume.failed",
            Self::StopFailed => "diagnostic.trace.stop.failed",
            Self::BoundaryIdentityMismatch => "diagnostic.trace.boundary-identity.mismatch",
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
            TraceStartupError::SpawnFailed,
            TraceStartupError::WaitFailed,
            TraceStartupError::WaitTimedOut,
            TraceStartupError::TraceeExited,
            TraceStartupError::StopInvalid,
            TraceStartupError::ResumeFailed,
            TraceStartupError::StopFailed,
            TraceStartupError::BoundaryIdentityMismatch,
            TraceStartupError::OptionsInstallFailed,
            TraceStartupError::ReleaseSendFailed,
        ]
        .map(TraceStartupError::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
    }
}
