#![deny(unsafe_code)]

//! Owns the native Linux enforcement boundary.

pub mod cgroup;
pub mod output;
pub mod probe;
pub mod resolve;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod sys;

pub use cgroup::{CgroupError, FreshCgroup};
pub use output::{FreshOutputRoot, OutputEntry, OutputInventory, OutputRootError};
pub use probe::{
    Architecture, Capability, CapabilityReport, CgroupV2Capability, ProbeError, SeccompCapability,
    SupportedLinux, probe_capabilities,
};
pub use resolve::{
    ExecutableClosure, ResolutionError, ResolvedFile, RootedPathResolver, parse_elf_interpreter,
};
