#![forbid(unsafe_code)]

//! Internal Runtime orchestration surface shared with operational benchmarks.
//!
//! This crate is not an embedding SDK. It keeps the benchmark on the exact
//! production orchestration source while the separately shipped `pbr` process
//! remains the supported product boundary.

#[allow(dead_code)]
mod plan;
pub mod run;
pub mod run_diagnostic;
