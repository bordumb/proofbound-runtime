#![forbid(unsafe_code)]

//! Constructs non-production diagnostic artifacts.
//!
//! This crate has no process, filesystem, clock, environment, or network
//! effects. The separate Linux diagnostic supervisor supplies bounded typed
//! observations. Production Runtime components do not depend on this crate.

pub mod artifact;
mod canonical;
pub mod draft;
pub mod producer;
