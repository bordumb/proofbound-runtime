#![deny(unsafe_code)]

//! Owns the separate effectful Linux diagnostic-observer path.

pub use proofbound_runtime_linux::trace::{
    AcknowledgedTraceStop, ActiveTrace, BoundaryRunning, InitialExecStop, LauncherPause,
    PreparedTraceCommand, SpawnedTrace, TraceDeadline, TraceProcessId, TraceReady,
    TraceStartupError, prepare_traced_launcher,
};
