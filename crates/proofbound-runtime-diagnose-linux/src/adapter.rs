//! Couples diagnostic trace setup to the pure observer protocol.

use core::fmt;
use std::num::NonZeroU32;
use std::os::fd::BorrowedFd;

use proofbound_runtime_diagnose::artifact::ObservationBounds;
use proofbound_runtime_diagnose::observer::{
    DiagnosticProcessId, DiagnosticTraceOptions, ObserverProtocol, ObserverProtocolError,
};
use proofbound_runtime_linux::{
    prepare_traced_launcher, AcknowledgedTraceStop, ActiveTrace, Architecture, BoundaryRunning,
    InitialExecStop, InstallRequest, LauncherPause, PreparedTraceCommand, ResolvedFile,
    SpawnedTrace, TraceDeadline, TraceProcessId, TraceReady, TraceStartupError,
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
    pub fn wait_for_initial_exec_stop(
        self,
        deadline: TraceDeadline,
    ) -> Result<InitialObserver, ObserverAdapterError> {
        let process = self.trace.process();
        let trace = self.trace.wait_for_initial_exec_stop(deadline)?;
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
        deadline: TraceDeadline,
    ) -> Result<LauncherPausedObserver, ObserverAdapterError> {
        let trace = self.trace.continue_to_launcher_pause(deadline)?;
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
        deadline: TraceDeadline,
    ) -> Result<AcknowledgedObserver, ObserverAdapterError> {
        let trace = self.trace.receive_acknowledgement_and_stop(deadline)?;
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
        let mut protocol = self.protocol;
        protocol.release_target()?;
        let trace = self.trace.release()?;
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
}

/// Identifies one fail-closed adapter setup error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserverAdapterError {
    /// The declared observation bounds are invalid.
    BoundsInvalid,
    /// The Linux trace-startup operation failed.
    Trace(TraceStartupError),
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
            Self::Protocol(error) => error.code(),
        }
    }
}

impl From<TraceStartupError> for ObserverAdapterError {
    fn from(error: TraceStartupError) -> Self {
        Self::Trace(error)
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
