#![deny(unsafe_code)]

//! Owns the separate effectful Linux diagnostic-observer path.

mod adapter;

pub use adapter::{
    AcknowledgedObserver, ActiveObserver, BoundaryRunningObserver, InitialObserver,
    LauncherPausedObserver, ObserverAdapterError, PreparedObserver, ReadyObserver, SpawnedObserver,
    prepare_observer,
};
pub use proofbound_runtime_linux::{TraceDeadline, TraceProcessId};
