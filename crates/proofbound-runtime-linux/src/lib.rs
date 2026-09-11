#![deny(unsafe_code)]

//! Owns the native Linux enforcement boundary.

pub mod cgroup;
pub mod execution;
pub mod inventory;
pub mod landlock;
pub mod launcher;
pub mod output;
pub mod privilege;
pub mod probe;
pub mod resolve;
pub mod seccomp;
pub mod supervisor;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod sys;

pub use cgroup::{
    CgroupError, ConfiguredResources, FreshCgroup, MemoryEvents, ResourceObservation, SwapEvents,
    TerminalResources,
};
pub use execution::{ExecutionSetupError, fresh_execution_id};
pub use inventory::{ResolvedDirectory, ResolvedReadPath};
pub use landlock::{
    LandlockAccess, LandlockBoundary, LandlockError, LandlockRule, install_landlock,
};
pub use launcher::{
    AcknowledgedLauncher, BoundaryInstalled, ExecAuthorization, InstallRequest, InstalledLauncher,
    LauncherChannel, LauncherError, LauncherFailure, LauncherFilesystemRule, LauncherIdentity,
    LauncherMessage, LauncherStage, MAX_LAUNCHER_FRAME_BYTES, PreparedLauncher,
    decode_launcher_message, encode_launcher_message, pause_for_supervisor,
    receive_install_request, run_launcher, verify_launcher_response,
};
pub use output::{
    FreshOutputRoot, OutputEntry, OutputInventory, OutputRootError, OutputRootPreflight,
};
pub use privilege::{LockedPrivileges, PrivilegeError, lock_privileges};
pub use probe::{
    Architecture, Capability, CapabilityReport, CgroupV2Capability, ProbeError, SeccompCapability,
    SupportedLinux, probe_capabilities,
};
pub use resolve::{
    ExecutableClosure, ResolutionError, ResolvedFile, RootedPathResolver,
    identify_external_artifact, parse_elf_interpreter, revalidate_inherited_executable,
};
pub use seccomp::{
    SeccompBoundary, SeccompError, compile_deny_network_program, install_deny_network,
};
pub use supervisor::{
    CapturedStream, LauncherBootstrap, SupervisedExecution, SupervisorError, SupervisorTimings,
    parse_launcher_bootstrap, supervise_launcher,
};
