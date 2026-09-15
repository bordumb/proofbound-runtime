//! Couples diagnostic trace setup to the pure observer protocol.

use core::fmt;
use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::os::fd::BorrowedFd;

use proofbound_runtime_core::ResourceLimits;
use proofbound_runtime_diagnose::artifact::ObservationBounds;
use proofbound_runtime_diagnose::observer::{
    DiagnosticProcessId, DiagnosticTraceOptions, ObserverDirective, ObserverProtocol,
    ObserverProtocolError, ProcessCreationKind,
};
use proofbound_runtime_linux::{
    AcknowledgedTraceStop, ActiveTrace, ActiveTraceEvent, Architecture, BoundaryRunning,
    DrainingTrace, FreshCgroup, InitialExecStop, InstallRequest, LauncherPause,
    PreparedTraceCommand, ResolvedFile, SpawnedTrace, TraceCaptureLimits, TraceDrainObservation,
    TraceObservationError, TraceProcessCreationKind, TraceProcessId, TraceProcessLimit, TraceReady,
    TraceStartupError, TraceTerminalCapture, prepare_traced_launcher,
};

/// Contains a validated observer request before child creation.
#[derive(Debug)]
pub struct PreparedObserver<'descriptor> {
    trace: PreparedTraceCommand<'descriptor>,
    bounds: ObservationBounds,
}

/// Prepares one trace and pure-protocol session from the same validated inputs.
pub fn prepare_observer<'descriptor>(
    launcher: &'descriptor ResolvedFile,
    request: InstallRequest,
    inherited_descriptors: &[BorrowedFd<'descriptor>],
    architecture: Architecture,
    landlock_abi: NonZeroU32,
    cgroup: FreshCgroup,
    limits: ResourceLimits,
    bounds: ObservationBounds,
) -> Result<PreparedObserver<'descriptor>, ObserverAdapterError> {
    let bounds = bounds
        .validate()
        .map_err(|_| ObserverAdapterError::BoundsInvalid)?;
    let trace = prepare_traced_launcher(
        launcher,
        request,
        inherited_descriptors,
        architecture,
        landlock_abi,
        cgroup,
        limits,
    )?;
    Ok(PreparedObserver { trace, bounds })
}

impl PreparedObserver<'_> {
    /// Spawns one child but does not yet record ptrace ownership.
    pub fn spawn(self) -> Result<SpawnedObserver, ObserverAdapterError> {
        Ok(SpawnedObserver {
            trace: self.trace.spawn()?,
            bounds: self.bounds,
        })
    }
}

/// Owns the spawned child before its exact initial trace stop.
#[derive(Debug)]
pub struct SpawnedObserver {
    trace: SpawnedTrace,
    bounds: ObservationBounds,
}

impl SpawnedObserver {
    /// Returns the exact spawned process identifier.
    #[must_use]
    pub const fn process(&self) -> TraceProcessId {
        self.trace.process()
    }

    /// Waits for ptrace ownership before it advances the pure protocol.
    pub fn wait_for_initial_exec_stop(self) -> Result<InitialObserver, ObserverAdapterError> {
        let process = self.trace.process();
        let trace = self.trace.wait_for_initial_exec_stop()?;
        let root = DiagnosticProcessId::new(process.get())?;
        let mut protocol = ObserverProtocol::new(root, self.bounds)?;
        protocol.attach_root()?;
        Ok(InitialObserver { trace, protocol })
    }
}

/// Owns one coupled session at the exact initial exec stop.
#[derive(Debug)]
pub struct InitialObserver {
    trace: InitialExecStop,
    protocol: ObserverProtocol,
}

impl InitialObserver {
    /// Continues trusted launcher code to its declared pause.
    pub fn continue_to_launcher_pause(
        self,
    ) -> Result<LauncherPausedObserver, ObserverAdapterError> {
        let trace = self.trace.continue_to_launcher_pause()?;
        Ok(LauncherPausedObserver {
            trace,
            protocol: self.protocol,
        })
    }
}

/// Owns one coupled session at the trusted launcher pause.
#[derive(Debug)]
pub struct LauncherPausedObserver {
    trace: LauncherPause,
    protocol: ObserverProtocol,
}

impl LauncherPausedObserver {
    /// Returns the exact stopped launcher process identifier.
    #[must_use]
    pub const fn process(&self) -> TraceProcessId {
        self.trace.process()
    }

    /// Starts production-boundary installation without releasing target code.
    pub fn continue_for_boundary(self) -> Result<BoundaryRunningObserver, ObserverAdapterError> {
        let trace = self.trace.continue_for_boundary()?;
        Ok(BoundaryRunningObserver {
            trace,
            protocol: self.protocol,
        })
    }
}

/// Owns one coupled session while the launcher installs its boundary.
#[derive(Debug)]
pub struct BoundaryRunningObserver {
    trace: BoundaryRunning,
    protocol: ObserverProtocol,
}

impl BoundaryRunningObserver {
    /// Records boundary readiness only after the exact acknowledgement stop.
    pub fn receive_acknowledgement_and_stop(
        self,
    ) -> Result<AcknowledgedObserver, ObserverAdapterError> {
        let trace = self.trace.receive_acknowledgement_and_stop()?;
        let mut protocol = self.protocol;
        protocol.record_boundary_ready()?;
        Ok(AcknowledgedObserver { trace, protocol })
    }
}

/// Owns one coupled session after the exact boundary acknowledgement.
#[derive(Debug)]
pub struct AcknowledgedObserver {
    trace: AcknowledgedTraceStop,
    protocol: ObserverProtocol,
}

impl AcknowledgedObserver {
    /// Records option readiness only after exact option installation.
    pub fn install_options(self) -> Result<ReadyObserver, ObserverAdapterError> {
        let trace = self.trace.install_options()?;
        let options = DiagnosticTraceOptions::from_bits(trace.options())?;
        let mut protocol = self.protocol;
        protocol.enable_trace_options(options)?;
        Ok(ReadyObserver { trace, protocol })
    }
}

/// Owns one coupled session with the exact trace options installed.
#[derive(Debug)]
pub struct ReadyObserver {
    trace: TraceReady,
    protocol: ObserverProtocol,
}

impl ReadyObserver {
    /// Authorizes release in the pure protocol before it releases target code.
    pub fn release(self) -> Result<ActiveObserver, ObserverAdapterError> {
        let process_limit = TraceProcessLimit::new(self.protocol.process_limit())?;
        let capture_limits = TraceCaptureLimits::new(
            self.protocol.path_byte_limit(),
            self.protocol.socket_address_byte_limit(),
            self.protocol.tracee_string_byte_limit(),
        )?;
        let mut protocol = self.protocol;
        protocol.release_target()?;
        let trace = self.trace.release(process_limit, capture_limits)?;
        Ok(ActiveObserver { trace, protocol })
    }
}

/// Owns one active trace coupled to its released pure protocol.
#[derive(Debug)]
pub struct ActiveObserver {
    trace: ActiveTrace,
    protocol: ObserverProtocol,
}

impl ActiveObserver {
    /// Returns the exact diagnostic process-tree root.
    #[must_use]
    pub const fn root(&self) -> TraceProcessId {
        self.trace.root()
    }

    /// Borrows the pure protocol for status inspection.
    #[must_use]
    pub const fn protocol(&self) -> &ObserverProtocol {
        &self.protocol
    }

    /// Consumes one exact trace event and advances the pure protocol.
    pub fn next_event(mut self) -> Result<ActiveObserverStep, ObserverAdapterError> {
        let event = match self.trace.next_event() {
            Ok(event) => event,
            Err(error) => {
                let directive = self.protocol.record_observer_failure()?;
                if directive != ObserverDirective::TerminateAndDrain {
                    return Err(ObserverAdapterError::Protocol(
                        ObserverProtocolError::TransitionInvalid,
                    ));
                }
                let trace = self.trace.begin_termination()?;
                return Ok(ActiveObserverStep::Drain {
                    observer: DrainingObserver {
                        trace,
                        protocol: self.protocol,
                        untracked_processes: BTreeSet::new(),
                    },
                    observation: ObserverObservation::Failure(error),
                });
            }
        };

        let mut untracked_processes = BTreeSet::new();
        let directive = match &event {
            ActiveTraceEvent::SyscallCompleted { process, .. } => {
                self.protocol.record_event(diagnostic_process(*process)?)?
            }
            ActiveTraceEvent::ProcessCreated {
                parent,
                child,
                kind,
            } => {
                let parent = diagnostic_process(*parent)?;
                let child = diagnostic_process(*child)?;
                let directive =
                    self.protocol
                        .discover_child(parent, child, process_creation_kind(*kind))?;
                if !self.protocol.tracks_process(child) {
                    untracked_processes.insert(child);
                }
                if directive == ObserverDirective::Continue {
                    self.protocol.record_event(parent)?
                } else {
                    directive
                }
            }
            ActiveTraceEvent::ImageReplaced {
                former_process,
                process,
                superseded_processes,
                ..
            } => {
                let former = diagnostic_process(*former_process)?;
                let survivor = diagnostic_process(*process)?;
                let superseded = superseded_processes
                    .iter()
                    .copied()
                    .map(diagnostic_process)
                    .collect::<Result<Vec<_>, _>>()?;
                let directive = self.protocol.record_exec(former, survivor, &superseded)?;
                if directive == ObserverDirective::Continue {
                    self.protocol.record_event(survivor)?
                } else {
                    directive
                }
            }
            ActiveTraceEvent::ProcessExited { process, .. } => self
                .protocol
                .record_process_exit(diagnostic_process(*process)?)?,
            ActiveTraceEvent::UnexpectedStop { process, .. } => self
                .protocol
                .record_unexpected_stop(diagnostic_process(*process)?)?,
        };

        if directive == ObserverDirective::TerminateAndDrain {
            let trace = self.trace.begin_termination()?;
            return Ok(ActiveObserverStep::Drain {
                observer: DrainingObserver {
                    trace,
                    protocol: self.protocol,
                    untracked_processes,
                },
                observation: ObserverObservation::Event(Box::new(event)),
            });
        }
        if directive != ObserverDirective::Continue {
            return Err(ObserverAdapterError::Protocol(
                ObserverProtocolError::TransitionInvalid,
            ));
        }
        if self.trace.is_drained() {
            let terminal = self.trace.finish()?.into_terminal();
            let publication = self.protocol.finish()?;
            return Ok(ActiveObserverStep::Complete {
                observer: CompletedObserver {
                    protocol: self.protocol,
                    publication,
                    terminal,
                },
                event,
            });
        }
        Ok(ActiveObserverStep::Continue {
            observer: self,
            event,
        })
    }
}

/// Identifies one coupled observation or effectful observer failure.
#[derive(Debug, Eq, PartialEq)]
pub enum ObserverObservation {
    /// One complete effectful trace event.
    Event(Box<ActiveTraceEvent>),
    /// One trace failure that forced termination and drain.
    Failure(TraceObservationError),
}

/// Selects the only legal state after one active observation step.
#[derive(Debug)]
pub enum ActiveObserverStep {
    /// Observation can continue with the returned stopped event already recorded.
    Continue {
        /// The coupled observer for the next consuming step.
        observer: ActiveObserver,
        /// The complete event recorded by the pure protocol.
        event: ActiveTraceEvent,
    },
    /// Observation must terminate and drain before any publication decision.
    Drain {
        /// The coupled observer that can only drain.
        observer: DrainingObserver,
        /// The event or failure that selected drain.
        observation: ObserverObservation,
    },
    /// Natural process-tree completion selected a publication decision.
    Complete {
        /// The terminal pure observer state.
        observer: CompletedObserver,
        /// The terminal event recorded by the pure protocol.
        event: ActiveTraceEvent,
    },
}

/// Owns one observer after a pure termination directive.
#[derive(Debug)]
pub struct DrainingObserver {
    trace: DrainingTrace,
    protocol: ObserverProtocol,
    untracked_processes: BTreeSet<DiagnosticProcessId>,
}

impl DrainingObserver {
    /// Terminates the exact trace tree and completes the pure drain protocol.
    pub fn finish(mut self) -> Result<CompletedObserver, ObserverAdapterError> {
        let report = self.trace.finish()?;
        for observation in report.observations() {
            match observation {
                TraceDrainObservation::ProcessCreated {
                    parent,
                    child,
                    kind,
                } => {
                    let parent = diagnostic_process(*parent)?;
                    let child = diagnostic_process(*child)?;
                    self.protocol
                        .discover_child(parent, child, process_creation_kind(*kind))?;
                    if !self.protocol.tracks_process(child) {
                        self.untracked_processes.insert(child);
                    }
                }
                TraceDrainObservation::ImageReplaced {
                    former_process,
                    process,
                    superseded_processes,
                } => {
                    let former = diagnostic_process(*former_process)?;
                    let survivor = diagnostic_process(*process)?;
                    let superseded = superseded_processes
                        .iter()
                        .copied()
                        .map(diagnostic_process)
                        .collect::<Result<Vec<_>, _>>()?;
                    self.protocol.record_exec(former, survivor, &superseded)?;
                }
                TraceDrainObservation::ProcessExited { process, .. } => {
                    let process = diagnostic_process(*process)?;
                    if self.untracked_processes.remove(&process) {
                        continue;
                    }
                    self.protocol.record_process_exit(process)?;
                }
            }
        }
        if !self.untracked_processes.is_empty() {
            return Err(ObserverAdapterError::Protocol(
                ObserverProtocolError::ProcessTreeChanged,
            ));
        }
        let terminal = report.into_terminal();
        self.protocol.confirm_tree_drained()?;
        let publication = self.protocol.finish()?;
        Ok(CompletedObserver {
            protocol: self.protocol,
            publication,
            terminal,
        })
    }
}

/// Contains one terminal diagnostic publication decision.
#[derive(Debug)]
pub struct CompletedObserver {
    protocol: ObserverProtocol,
    publication: ObserverDirective,
    terminal: TraceTerminalCapture,
}

impl CompletedObserver {
    /// Borrows the terminal pure protocol state.
    #[must_use]
    pub const fn protocol(&self) -> &ObserverProtocol {
        &self.protocol
    }

    /// Returns the pure complete or incomplete publication directive.
    #[must_use]
    pub const fn publication(&self) -> ObserverDirective {
        self.publication
    }

    /// Returns bounded output and resources from terminal trace cleanup.
    #[must_use]
    pub const fn terminal(&self) -> &TraceTerminalCapture {
        &self.terminal
    }
}

fn diagnostic_process(
    process: TraceProcessId,
) -> Result<DiagnosticProcessId, ObserverAdapterError> {
    DiagnosticProcessId::new(process.get()).map_err(ObserverAdapterError::Protocol)
}

const fn process_creation_kind(kind: TraceProcessCreationKind) -> ProcessCreationKind {
    match kind {
        TraceProcessCreationKind::Clone => ProcessCreationKind::Clone,
        TraceProcessCreationKind::Fork => ProcessCreationKind::Fork,
        TraceProcessCreationKind::Vfork => ProcessCreationKind::Vfork,
    }
}

/// Identifies one fail-closed adapter setup error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserverAdapterError {
    /// The declared observation bounds are invalid.
    BoundsInvalid,
    /// The Linux trace-startup operation failed.
    Trace(TraceStartupError),
    /// Active trace observation or drain failed.
    Observation(TraceObservationError),
    /// The pure observer protocol rejected a transition.
    Protocol(ObserverProtocolError),
}

impl ObserverAdapterError {
    /// Returns the stable machine error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BoundsInvalid => "diagnostic.observer-adapter.bounds-invalid",
            Self::Trace(error) => error.code(),
            Self::Observation(error) => error.code(),
            Self::Protocol(error) => error.code(),
        }
    }
}

impl From<TraceStartupError> for ObserverAdapterError {
    fn from(error: TraceStartupError) -> Self {
        Self::Trace(error)
    }
}

impl From<TraceObservationError> for ObserverAdapterError {
    fn from(error: TraceObservationError) -> Self {
        Self::Observation(error)
    }
}

impl From<ObserverProtocolError> for ObserverAdapterError {
    fn from(error: ObserverProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl fmt::Display for ObserverAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ObserverAdapterError {}
