#![deny(unsafe_code)]

//! Owns the native Linux enforcement boundary.

pub mod cgroup;
pub mod landlock;
pub mod output;
pub mod privilege;
pub mod probe;
pub mod resolve;
pub mod seccomp;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod sys;

pub use cgroup::{CgroupError, FreshCgroup};
pub use landlock::{
    LandlockAccess, LandlockBoundary, LandlockError, LandlockRule, install_landlock,
};
pub use output::{FreshOutputRoot, OutputEntry, OutputInventory, OutputRootError};
pub use privilege::{LockedPrivileges, PrivilegeError, lock_privileges};
pub use probe::{
    Architecture, Capability, CapabilityReport, CgroupV2Capability, ProbeError, SeccompCapability,
    SupportedLinux, probe_capabilities,
};
pub use resolve::{
    ExecutableClosure, ResolutionError, ResolvedFile, RootedPathResolver, parse_elf_interpreter,
};
pub use seccomp::{SeccompBoundary, SeccompError, install_deny_network};
