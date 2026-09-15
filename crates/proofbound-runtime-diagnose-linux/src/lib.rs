#![deny(unsafe_code)]

//! Owns the separate effectful Linux diagnostic-observer path.

mod adapter;

pub use adapter::{
    prepare_observer, AcknowledgedObserver, ActiveObserver, BoundaryRunningObserver,
    InitialObserver, LauncherPausedObserver, ObserverAdapterError, PreparedObserver, ReadyObserver,
    SpawnedObserver,
};
pub use proofbound_runtime_linux::{TraceDeadline, TraceProcessId};
