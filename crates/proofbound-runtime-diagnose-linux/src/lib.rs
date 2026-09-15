#![deny(unsafe_code)]

//! Owns the separate effectful Linux diagnostic-observer path.

mod adapter;

pub use adapter::{
    AcknowledgedObserver, ActiveObserver, ActiveObserverStep, BoundaryRunningObserver,
    CompletedObserver, DrainingObserver, InitialObserver, LauncherPausedObserver,
    ObserverAdapterError, ObserverObservation, PreparedObserver, ReadyObserver, SpawnedObserver,
    prepare_observer,
};
pub use proofbound_runtime_linux::{
    ActiveTraceEvent, TraceCapturedOperands, TraceDeadline, TraceObservationError, TraceProcessId,
    TraceSyscallClass, TraceSyscallInvocation,
};
