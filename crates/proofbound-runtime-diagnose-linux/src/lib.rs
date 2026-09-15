#![deny(unsafe_code)]

//! Owns the separate effectful Linux diagnostic-observer path.

mod adapter;
mod mapping;

pub use adapter::{
    AcknowledgedObserver, ActiveObserver, ActiveObserverStep, BoundaryRunningObserver,
    CompletedObserver, DrainingObserver, InitialObserver, LauncherPausedObserver,
    ObserverAdapterError, ObserverObservation, PreparedObserver, ReadyObserver, SpawnedObserver,
    prepare_observer,
};
pub use mapping::{DiagnosticEventMapError, DiagnosticEventMapper};
pub use proofbound_runtime_linux::{
    ActiveTraceEvent, TraceCapturedOperands, TraceCapturedStream, TraceDeadline,
    TraceObservationError, TraceOutputCapture, TraceOutputLimits, TraceProcessId,
    TraceSyscallClass, TraceSyscallInvocation,
};

#[cfg(test)]
mod tests {
    use super::{
        ActiveObserver, ActiveObserverStep, ObserverAdapterError, ReadyObserver, TraceDeadline,
    };

    #[test]
    fn decoder_adapter_release_and_drain_paths_compile() {
        let _: fn(ReadyObserver) -> Result<ActiveObserver, ObserverAdapterError> =
            ReadyObserver::release;
        let _: fn(
            ActiveObserver,
            TraceDeadline,
        ) -> Result<ActiveObserverStep, ObserverAdapterError> = ActiveObserver::next_event;
    }
}
