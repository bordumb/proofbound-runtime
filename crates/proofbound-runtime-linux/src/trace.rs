//! Starts one diagnostic trace without adding authority to the child.

use core::fmt;
use std::collections::BTreeMap;
use std::num::NonZeroU32;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::os::fd::{BorrowedFd, OwnedFd};
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
const SIGNAL_SYSCALL: i32 = SIGNAL_TRAP | 0x80;

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
    /// Returns the exact spawned process identifier.
    #[must_use]
    pub const fn process(&self) -> TraceProcessId {
        self.session.process
    }

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
            let options = crate::sys::install_diagnostic_trace_options(self.session.process.get())
                .map_err(|_| TraceStartupError::OptionsInstallFailed)?;
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
    pub fn release(self) -> Result<ActiveTrace, TraceStartupError> {
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
            crate::sys::trace_syscall(root.get()).map_err(|_| TraceStartupError::ResumeFailed)?;
            Ok(ActiveTrace {
                session: self.session,
                processes: BTreeMap::from([(root, TraceeState::observing(root))]),
                process_handles: BTreeMap::from([(root, process_handle)]),
                held_process: None,
                must_drain: false,
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
    processes: BTreeMap<TraceProcessId, TraceeState>,
    process_handles: BTreeMap<TraceProcessId, OwnedFd>,
    held_process: Option<TraceProcessId>,
    must_drain: bool,
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
        self.processes.is_empty()
    }

    /// Waits for the next complete event from the exact known process tree.
    #[cfg(target_os = "linux")]
    pub fn next_event(
        &mut self,
        deadline: TraceDeadline,
    ) -> Result<ActiveTraceEvent, TraceObservationError> {
        if self.must_drain {
            return Err(TraceObservationError::DrainRequired);
        }
        if self.processes.is_empty() {
            return Err(TraceObservationError::ProcessTreeDrained);
        }
        if let Some(process) = self.held_process.take() {
            if crate::sys::trace_syscall(process.get()).is_err() {
                self.must_drain = true;
                return Err(TraceObservationError::ResumeFailed);
            }
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
                match self.handle_wait_observation(requested, observation) {
                    Ok(WaitDecision::Continue) => continue,
                    Ok(WaitDecision::Event(event)) => return Ok(event),
                    Err(error) => {
                        self.must_drain = true;
                        return Err(error);
                    }
                }
            }
            if deadline.expired() {
                self.must_drain = true;
                return Err(TraceObservationError::WaitTimedOut);
            }
            std::thread::sleep(TRACE_POLL_INTERVAL);
        }
    }

    /// Terminates every identity-stable process group and drains exact waits.
    #[cfg(target_os = "linux")]
    pub fn terminate_and_drain(
        mut self,
        deadline: TraceDeadline,
    ) -> Result<(), TraceObservationError> {
        self.held_process = None;
        self.must_drain = true;
        self.signal_all_process_groups();
        while !self.processes.is_empty() {
            let mut observed = false;
            let processes = self.processes.keys().copied().collect::<Vec<_>>();
            for requested in processes {
                if !self.processes.contains_key(&requested) {
                    continue;
                }
                let observation = match crate::sys::trace_wait_event_nonblocking(requested.get()) {
                    Ok(Some(observation)) => observation,
                    Ok(None) => continue,
                    Err(_) => return Err(TraceObservationError::DrainFailed),
                };
                observed = true;
                self.handle_drain_observation(requested, observation)?;
            }
            if self.processes.is_empty() {
                return Ok(());
            }
            if deadline.expired() {
                return Err(TraceObservationError::DrainTimedOut);
            }
            if !observed {
                std::thread::sleep(TRACE_POLL_INTERVAL);
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn handle_wait_observation(
        &mut self,
        requested: TraceProcessId,
        observation: crate::sys::TraceWaitObservation,
    ) -> Result<WaitDecision, TraceObservationError> {
        let reported = TraceProcessId::new(observation.process_id)
            .map_err(|_| TraceObservationError::ProcessIdentityInvalid)?;
        if reported != requested {
            return Err(TraceObservationError::ProcessIdentityChanged);
        }

        match observation.status {
            crate::sys::TraceWaitStatus::Stopped { signal, event }
                if signal == SIGNAL_TRAP && crate::sys::trace_event_is_exec(event) =>
            {
                let process = self.reconcile_exec_identity(requested, reported)?;
                let invocation = self.processes.get(&process).and_then(|state| state.pending);
                self.held_process = Some(process);
                Ok(WaitDecision::Event(ActiveTraceEvent::ImageReplaced {
                    process,
                    invocation,
                }))
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
                self.register_child(child)?;
                self.held_process = Some(reported);
                Ok(WaitDecision::Event(ActiveTraceEvent::ProcessCreated {
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
                crate::sys::trace_syscall(reported.get())
                    .map_err(|_| TraceObservationError::ResumeFailed)?;
                Ok(WaitDecision::Continue)
            }
            crate::sys::TraceWaitStatus::Stopped { signal, event } => {
                self.must_drain = true;
                Ok(WaitDecision::Event(ActiveTraceEvent::UnexpectedStop {
                    process: reported,
                    signal,
                    event,
                }))
            }
            crate::sys::TraceWaitStatus::Exited { code } => {
                self.record_terminal_process(reported)?;
                Ok(WaitDecision::Event(ActiveTraceEvent::ProcessExited {
                    process: reported,
                    termination: TraceTermination::Exit(code),
                }))
            }
            crate::sys::TraceWaitStatus::Signaled { signal } => {
                self.record_terminal_process(reported)?;
                Ok(WaitDecision::Event(ActiveTraceEvent::ProcessExited {
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
    ) -> Result<WaitDecision, TraceObservationError> {
        let state = self
            .processes
            .get_mut(&process)
            .ok_or(TraceObservationError::ProcessUnknown)?;
        if state.awaiting_initial_stop {
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
                if state.pending.is_some() {
                    return Err(TraceObservationError::SyscallOrderInvalid);
                }
                state.pending = Some(TraceSyscallInvocation {
                    architecture,
                    instruction_pointer,
                    stack_pointer,
                    number,
                    arguments,
                });
                crate::sys::trace_syscall(process.get())
                    .map_err(|_| TraceObservationError::ResumeFailed)?;
                Ok(WaitDecision::Continue)
            }
            crate::sys::TraceSyscallStop::Exit { result, is_error } => {
                let invocation = state
                    .pending
                    .take()
                    .ok_or(TraceObservationError::SyscallOrderInvalid)?;
                self.held_process = Some(process);
                Ok(WaitDecision::Event(ActiveTraceEvent::SyscallCompleted {
                    process,
                    invocation,
                    result,
                    is_error,
                }))
            }
            crate::sys::TraceSyscallStop::Seccomp | crate::sys::TraceSyscallStop::None => {
                Err(TraceObservationError::SyscallInformationInvalid)
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn register_child(&mut self, child: TraceProcessId) -> Result<(), TraceObservationError> {
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
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn reconcile_exec_identity(
        &mut self,
        requested: TraceProcessId,
        reported: TraceProcessId,
    ) -> Result<TraceProcessId, TraceObservationError> {
        let former = crate::sys::trace_event_process(reported.get())
            .map_err(|_| TraceObservationError::EventMessageInvalid)
            .and_then(|value| {
                TraceProcessId::new(value)
                    .map_err(|_| TraceObservationError::ProcessIdentityInvalid)
            })?;
        let process = reconcile_exec_processes(&mut self.processes, requested, reported, former)?;
        if !self.process_handles.contains_key(&reported) {
            let handle = crate::sys::trace_open_process_handle(reported.get())
                .map_err(|_| TraceObservationError::ProcessHandleFailed)?;
            self.process_handles.insert(reported, handle);
        }
        self.remove_unused_process_handles();
        Ok(process)
    }

    #[cfg(target_os = "linux")]
    fn record_terminal_process(
        &mut self,
        process: TraceProcessId,
    ) -> Result<(), TraceObservationError> {
        if self.processes.remove(&process).is_none() {
            return Err(TraceObservationError::ProcessUnknown);
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
    ) -> Result<(), TraceObservationError> {
        let reported = TraceProcessId::new(observation.process_id)
            .map_err(|_| TraceObservationError::ProcessIdentityInvalid)?;
        if reported != requested {
            return Err(TraceObservationError::ProcessIdentityChanged);
        }
        match observation.status {
            crate::sys::TraceWaitStatus::Stopped { signal, event }
                if signal == SIGNAL_TRAP && crate::sys::trace_event_is_exec(event) =>
            {
                let process = self.reconcile_exec_identity(requested, reported)?;
                self.signal_process(process)?;
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
                    self.register_child(child)?;
                }
                self.signal_process(child)?;
                self.signal_process(reported)?;
            }
            crate::sys::TraceWaitStatus::Stopped { .. } => {
                self.signal_process(reported)?;
            }
            crate::sys::TraceWaitStatus::Exited { .. }
            | crate::sys::TraceWaitStatus::Signaled { .. } => {
                self.record_terminal_process(reported)?;
            }
        }
        Ok(())
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
    fn signal_all_process_groups(&self) {
        for handle in self.process_handles.values() {
            let _ = crate::sys::trace_kill_process_handle(handle.as_raw_fd());
        }
    }
}

impl Drop for ActiveTrace {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        self.signal_all_process_groups();
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

#[derive(Debug)]
struct TraceeState {
    thread_group: TraceProcessId,
    awaiting_initial_stop: bool,
    pending: Option<TraceSyscallInvocation>,
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
) -> Result<TraceProcessId, TraceObservationError> {
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
    for process in replaced_threads {
        processes.remove(&process);
    }
    exec_state.thread_group = reported;
    exec_state.awaiting_initial_stop = false;
    processes.insert(reported, exec_state);
    Ok(reported)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaitDecision {
    Continue,
    Event(ActiveTraceEvent),
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

/// Contains the architecture-qualified input registers for one system call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceSyscallInvocation {
    architecture: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    number: u64,
    arguments: [u64; 6],
}

impl TraceSyscallInvocation {
    /// Returns the Linux audit architecture value.
    #[must_use]
    pub const fn architecture(self) -> u32 {
        self.architecture
    }

    /// Returns the instruction pointer at system-call entry.
    #[must_use]
    pub const fn instruction_pointer(self) -> u64 {
        self.instruction_pointer
    }

    /// Returns the stack pointer at system-call entry.
    #[must_use]
    pub const fn stack_pointer(self) -> u64 {
        self.stack_pointer
    }

    /// Returns the architecture-qualified system-call number.
    #[must_use]
    pub const fn number(self) -> u64 {
        self.number
    }

    /// Returns the six supplied system-call argument words.
    #[must_use]
    pub const fn arguments(self) -> [u64; 6] {
        self.arguments
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
        /// The post-exec tracee identity.
        process: TraceProcessId,
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
}

impl TraceObservationError {
    /// Returns the stable machine error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DrainRequired => "diagnostic.trace.drain-required",
            Self::ProcessTreeDrained => "diagnostic.trace.process-tree-drained",
            Self::ProcessIdentityInvalid => "diagnostic.trace.process-identity.invalid",
            Self::ProcessIdentityChanged => "diagnostic.trace.process-identity.changed",
            Self::ProcessIdentityDuplicate => "diagnostic.trace.process-identity.duplicate",
            Self::ProcessUnknown => "diagnostic.trace.process.unknown",
            Self::InitialStopMissing => "diagnostic.trace.initial-stop.missing",
            Self::WaitFailed => "diagnostic.trace.event-wait.failed",
            Self::WaitTimedOut => "diagnostic.trace.event-wait.timed-out",
            Self::ResumeFailed => "diagnostic.trace.event-resume.failed",
            Self::EventMessageInvalid => "diagnostic.trace.event-message.invalid",
            Self::SyscallInformationInvalid => "diagnostic.trace.syscall-information.invalid",
            Self::SyscallOrderInvalid => "diagnostic.trace.syscall-order.invalid",
            Self::ProcessHandleFailed => "diagnostic.trace.process-handle.failed",
            Self::ThreadGroupInvalid => "diagnostic.trace.thread-group.invalid",
            Self::DrainFailed => "diagnostic.trace.drain.failed",
            Self::DrainTimedOut => "diagnostic.trace.drain.timed-out",
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
            TraceStartupError::ProcessHandleFailed,
        ]
        .map(TraceStartupError::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
    }

    #[test]
    fn observation_errors_have_unique_stable_codes() {
        let mut codes = [
            TraceObservationError::DrainRequired,
            TraceObservationError::ProcessTreeDrained,
            TraceObservationError::ProcessIdentityInvalid,
            TraceObservationError::ProcessIdentityChanged,
            TraceObservationError::ProcessIdentityDuplicate,
            TraceObservationError::ProcessUnknown,
            TraceObservationError::InitialStopMissing,
            TraceObservationError::WaitFailed,
            TraceObservationError::WaitTimedOut,
            TraceObservationError::ResumeFailed,
            TraceObservationError::EventMessageInvalid,
            TraceObservationError::SyscallInformationInvalid,
            TraceObservationError::SyscallOrderInvalid,
            TraceObservationError::ProcessHandleFailed,
            TraceObservationError::ThreadGroupInvalid,
            TraceObservationError::DrainFailed,
            TraceObservationError::DrainTimedOut,
        ]
        .map(TraceObservationError::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
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
    fn nonleader_exec_preserves_pending_syscall_until_exit_pair() {
        let leader = TraceProcessId::new(41).expect("positive leader identity");
        let former = TraceProcessId::new(42).expect("positive former identity");
        let sibling = TraceProcessId::new(43).expect("positive sibling identity");
        let unrelated = TraceProcessId::new(51).expect("positive unrelated identity");
        let invocation = TraceSyscallInvocation {
            architecture: 0xc000_003e,
            instruction_pointer: 0x1234,
            stack_pointer: 0x5678,
            number: 59,
            arguments: [1, 2, 3, 4, 5, 6],
        };
        let mut processes = BTreeMap::from([
            (leader, TraceeState::observing(leader)),
            (
                former,
                TraceeState {
                    thread_group: leader,
                    awaiting_initial_stop: false,
                    pending: Some(invocation),
                },
            ),
            (sibling, TraceeState::observing(leader)),
            (unrelated, TraceeState::observing(unrelated)),
        ]);

        assert_eq!(
            reconcile_exec_processes(&mut processes, leader, leader, former),
            Ok(leader)
        );
        assert_eq!(processes.len(), 2);
        assert!(!processes.contains_key(&former));
        assert!(!processes.contains_key(&sibling));
        assert_eq!(
            processes.get(&leader).and_then(|state| state.pending),
            Some(invocation)
        );
        assert_eq!(
            processes
                .get_mut(&leader)
                .and_then(|state| state.pending.take()),
            Some(invocation)
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
