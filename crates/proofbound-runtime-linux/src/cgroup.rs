//! Owns fresh cgroup v2 creation, process limits, membership, and cleanup.

use core::fmt;
use std::path::{Path, PathBuf};

use proofbound_runtime_core::{CgroupIdentity, ExecutionId, ProcessLimit, ResourceLimits};

use crate::CgroupV2Capability;

#[cfg(target_os = "linux")]
const CONTROL_READ_LIMIT: u64 = 64 * 1024;
#[cfg(target_os = "linux")]
const CLEANUP_POLLS: usize = 5_000;

#[cfg(any(test, target_os = "linux"))]
fn installed_control_values(
    limits: ResourceLimits,
) -> Result<[(&'static str, String); 4], CgroupError> {
    let memory = limits
        .memory()
        .ok_or(CgroupError::ResourceProfileIncomplete)?;
    let swap = limits
        .swap()
        .ok_or(CgroupError::ResourceProfileIncomplete)?;
    Ok([
        ("pids.max", limits.processes().get().to_string()),
        ("memory.max", memory.get().to_string()),
        ("memory.swap.max", swap.get().to_string()),
        ("memory.oom.group", "1".to_owned()),
    ])
}

/// Owns one fresh cgroup v2 boundary for an execution attempt.
#[derive(Debug)]
pub struct FreshCgroup {
    path: PathBuf,
    identity: CgroupIdentity,
    process_limit: ProcessLimit,
    #[cfg(target_os = "linux")]
    removed: bool,
    #[cfg(target_os = "linux")]
    name: PathBuf,
    #[cfg(target_os = "linux")]
    parent: std::os::fd::OwnedFd,
    #[cfg(target_os = "linux")]
    descriptor: std::os::fd::OwnedFd,
}

impl FreshCgroup {
    /// Exclusively creates a child cgroup and installs the exact process limit.
    pub fn create(
        capability: &CgroupV2Capability,
        execution_id: ExecutionId,
        process_limit: ProcessLimit,
    ) -> Result<Self, CgroupError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd as _;

            if capability.mount_id() == 0
                || !capability.controllers().iter().any(|item| item == "pids")
            {
                return Err(CgroupError::CapabilityMismatch);
            }
            let parent = crate::sys::open_directory(capability.directory())
                .map_err(|_| CgroupError::ParentUnavailable)?;
            if directory_inode(&parent)? != capability.directory_inode() {
                return Err(CgroupError::CapabilityMismatch);
            }
            let enabled = read_word_set(&parent, "cgroup.subtree_control")?;
            if enabled.binary_search(&"pids".to_owned()).is_err() {
                return Err(CgroupError::ControllerUnavailable);
            }

            let name = cgroup_name(execution_id);
            crate::sys::create_directory_at(parent.as_raw_fd(), &name, 0o755)
                .map_err(map_creation_error)?;
            let descriptor = match crate::sys::openat2_directory(
                parent.as_raw_fd(),
                &name,
                crate::sys::RESOLVE_NO_MAGICLINKS | crate::sys::RESOLVE_NO_SYMLINKS,
            ) {
                Ok(descriptor) => descriptor,
                Err(_) => {
                    let _ = crate::sys::remove_directory_at(parent.as_raw_fd(), &name);
                    return Err(CgroupError::OpenFailed);
                }
            };

            let setup = (|| {
                let value = process_limit.get().to_string();
                write_control(&descriptor, "pids.max", value.as_bytes())?;
                let observed = read_control(&descriptor, "pids.max")?;
                if observed.trim() != value {
                    return Err(CgroupError::LimitMismatch);
                }
                if populated(&descriptor)? || !processes(&descriptor)?.is_empty() {
                    return Err(CgroupError::NotFresh);
                }
                Ok(())
            })();
            if let Err(error) = setup {
                drop(descriptor);
                let _ = crate::sys::remove_directory_at(parent.as_raw_fd(), &name);
                return Err(error);
            }

            let inode = directory_inode(&descriptor)?;
            let identity = CgroupIdentity::new(capability.mount_id(), inode);
            Ok(Self {
                path: capability.directory().join(&name),
                identity,
                process_limit,
                removed: false,
                name,
                parent,
                descriptor,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (capability, execution_id, process_limit);
            Err(CgroupError::UnsupportedOperatingSystem)
        }
    }

    /// Exclusively creates a child cgroup and installs all version 2 controls.
    pub fn create_v2(
        capability: &CgroupV2Capability,
        execution_id: ExecutionId,
        limits: ResourceLimits,
    ) -> Result<Self, CgroupError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd as _;

            if capability.mount_id() == 0
                || !["memory", "pids"]
                    .iter()
                    .all(|required| capability.controllers().iter().any(|item| item == required))
            {
                return Err(CgroupError::CapabilityMismatch);
            }
            let controls = installed_control_values(limits)?;
            let parent = crate::sys::open_directory(capability.directory())
                .map_err(|_| CgroupError::ParentUnavailable)?;
            if directory_inode(&parent)? != capability.directory_inode() {
                return Err(CgroupError::CapabilityMismatch);
            }
            let enabled = read_word_set(&parent, "cgroup.subtree_control")?;
            if !["memory", "pids"]
                .iter()
                .all(|required| enabled.binary_search(&(*required).to_owned()).is_ok())
            {
                return Err(CgroupError::ControllerUnavailable);
            }

            let name = cgroup_name(execution_id);
            crate::sys::create_directory_at(parent.as_raw_fd(), &name, 0o755)
                .map_err(map_creation_error)?;
            let descriptor = match crate::sys::openat2_directory(
                parent.as_raw_fd(),
                &name,
                crate::sys::RESOLVE_NO_MAGICLINKS | crate::sys::RESOLVE_NO_SYMLINKS,
            ) {
                Ok(descriptor) => descriptor,
                Err(_) => {
                    let _ = crate::sys::remove_directory_at(parent.as_raw_fd(), &name);
                    return Err(CgroupError::OpenFailed);
                }
            };

            let setup = (|| {
                for (name, value) in &controls {
                    write_control(&descriptor, name, value.as_bytes())?;
                    if read_control(&descriptor, name)?.trim() != value {
                        return Err(CgroupError::LimitMismatch);
                    }
                }
                if populated(&descriptor)? || !processes(&descriptor)?.is_empty() {
                    return Err(CgroupError::NotFresh);
                }
                Ok(())
            })();
            if let Err(error) = setup {
                drop(descriptor);
                let _ = crate::sys::remove_directory_at(parent.as_raw_fd(), &name);
                return Err(error);
            }

            let inode = directory_inode(&descriptor)?;
            let identity = CgroupIdentity::new(capability.mount_id(), inode);
            Ok(Self {
                path: capability.directory().join(&name),
                identity,
                process_limit: limits.processes(),
                removed: false,
                name,
                parent,
                descriptor,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (capability, execution_id, limits);
            Err(CgroupError::UnsupportedOperatingSystem)
        }
    }

    /// Returns the diagnostic cgroup filesystem path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the mount-and-inode identity bound into launcher messages.
    #[must_use]
    pub const fn identity(&self) -> CgroupIdentity {
        self.identity
    }

    /// Returns the exact installed `pids.max` value.
    #[must_use]
    pub const fn process_limit(&self) -> ProcessLimit {
        self.process_limit
    }

    /// Moves one paused launcher process into the cgroup and verifies membership.
    pub fn place_process(&self, process_id: u32) -> Result<(), CgroupError> {
        #[cfg(target_os = "linux")]
        {
            if process_id == 0 {
                return Err(CgroupError::ProcessIdInvalid);
            }
            write_control(
                &self.descriptor,
                "cgroup.procs",
                process_id.to_string().as_bytes(),
            )?;
            if self.contains_process(process_id)? {
                Ok(())
            } else {
                Err(CgroupError::MembershipMismatch)
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = process_id;
            Err(CgroupError::UnsupportedOperatingSystem)
        }
    }

    /// Reports whether the exact process identifier is currently a member.
    pub fn contains_process(&self, process_id: u32) -> Result<bool, CgroupError> {
        #[cfg(target_os = "linux")]
        {
            if process_id == 0 {
                return Err(CgroupError::ProcessIdInvalid);
            }
            Ok(processes(&self.descriptor)?
                .binary_search(&process_id)
                .is_ok())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = process_id;
            Err(CgroupError::UnsupportedOperatingSystem)
        }
    }

    /// Reports the kernel's `populated` state for the retained cgroup.
    pub fn is_populated(&self) -> Result<bool, CgroupError> {
        #[cfg(target_os = "linux")]
        {
            populated(&self.descriptor)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(CgroupError::UnsupportedOperatingSystem)
        }
    }

    /// Kills all remaining members, verifies drain, and removes the exact group.
    pub fn cleanup(self) -> Result<(), CgroupError> {
        #[cfg(target_os = "linux")]
        {
            let mut group = self;
            group.cleanup_in_place()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(CgroupError::UnsupportedOperatingSystem)
        }
    }

    #[cfg(target_os = "linux")]
    fn cleanup_in_place(&mut self) -> Result<(), CgroupError> {
        use std::os::fd::AsRawFd as _;

        if self.removed {
            return Ok(());
        }
        if populated(&self.descriptor)? {
            write_control(&self.descriptor, "cgroup.kill", b"1")?;
        }
        for _ in 0..CLEANUP_POLLS {
            if !populated(&self.descriptor)? && processes(&self.descriptor)?.is_empty() {
                crate::sys::remove_directory_at(self.parent.as_raw_fd(), &self.name)
                    .map_err(|_| CgroupError::RemovalFailed)?;
                self.removed = true;
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        Err(CgroupError::DrainFailed)
    }
}

impl Drop for FreshCgroup {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if !self.removed {
            let _ = self.cleanup_in_place();
        }
    }
}

/// Identifies one fail-closed cgroup lifecycle result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CgroupError {
    /// The host operating system is not Linux.
    UnsupportedOperatingSystem,
    /// The probed capability did not contain the required mount/controller.
    CapabilityMismatch,
    /// The execution limits omit the version 2 memory or swap bound.
    ResourceProfileIncomplete,
    /// The delegated parent could not be opened by descriptor.
    ParentUnavailable,
    /// The pids controller could not be enabled for child cgroups.
    ControllerUnavailable,
    /// A cgroup with the execution identity already existed.
    AlreadyExists,
    /// The fresh cgroup could not be created.
    CreationFailed,
    /// The fresh cgroup could not be reopened by descriptor.
    OpenFailed,
    /// A control file could not be read or written exactly.
    ControlUnavailable,
    /// The kernel did not retain the registered process limit.
    LimitMismatch,
    /// The new cgroup unexpectedly contained a process.
    NotFresh,
    /// A process identifier was zero.
    ProcessIdInvalid,
    /// The launcher was not observed in the cgroup after placement.
    MembershipMismatch,
    /// `cgroup.events` was malformed or omitted `populated`.
    EventsInvalid,
    /// The cgroup did not drain after `cgroup.kill`.
    DrainFailed,
    /// The empty cgroup could not be removed.
    RemovalFailed,
    /// Mount or inode identity could not be observed.
    IdentityUnavailable,
    /// The kernel cannot provide the required `openat2` guarantee.
    Openat2Unavailable,
}

impl CgroupError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "cgroup.os.unsupported",
            Self::CapabilityMismatch => "cgroup.capability.mismatch",
            Self::ResourceProfileIncomplete => "cgroup.resource-profile.incomplete",
            Self::ParentUnavailable => "cgroup.parent.unavailable",
            Self::ControllerUnavailable => "cgroup.controller.unavailable",
            Self::AlreadyExists => "cgroup.exists",
            Self::CreationFailed => "cgroup.creation-failed",
            Self::OpenFailed => "cgroup.open-failed",
            Self::ControlUnavailable => "cgroup.control.unavailable",
            Self::LimitMismatch => "cgroup.limit.mismatch",
            Self::NotFresh => "cgroup.not-fresh",
            Self::ProcessIdInvalid => "cgroup.process-id.invalid",
            Self::MembershipMismatch => "cgroup.membership.mismatch",
            Self::EventsInvalid => "cgroup.events.invalid",
            Self::DrainFailed => "cgroup.drain.failed",
            Self::RemovalFailed => "cgroup.removal.failed",
            Self::IdentityUnavailable => "cgroup.identity.unavailable",
            Self::Openat2Unavailable => "cgroup.openat2.unavailable",
        }
    }
}

impl fmt::Display for CgroupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CgroupError {}

#[cfg(any(test, target_os = "linux"))]
fn cgroup_name(execution_id: ExecutionId) -> PathBuf {
    use core::fmt::Write as _;

    let mut name = String::from("proofbound-runtime-");
    for byte in execution_id.as_bytes() {
        write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
    }
    PathBuf::from(name)
}

#[cfg(any(test, target_os = "linux"))]
fn parse_events(input: &str) -> Result<bool, CgroupError> {
    let mut populated = None;
    for line in input.lines() {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else {
            continue;
        };
        let value = fields.next().ok_or(CgroupError::EventsInvalid)?;
        if fields.next().is_some() {
            return Err(CgroupError::EventsInvalid);
        }
        if name == "populated" {
            if populated.is_some() {
                return Err(CgroupError::EventsInvalid);
            }
            populated = match value {
                "0" => Some(false),
                "1" => Some(true),
                _ => return Err(CgroupError::EventsInvalid),
            };
        }
    }
    populated.ok_or(CgroupError::EventsInvalid)
}

#[cfg(any(test, target_os = "linux"))]
fn parse_processes(input: &str) -> Result<Vec<u32>, CgroupError> {
    let mut values = input
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.parse::<u32>()
                .ok()
                .filter(|value| *value != 0)
                .ok_or(CgroupError::ControlUnavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    values.sort_unstable();
    values.dedup();
    Ok(values)
}

#[cfg(target_os = "linux")]
fn write_control(
    directory: &std::os::fd::OwnedFd,
    name: &str,
    value: &[u8],
) -> Result<(), CgroupError> {
    use std::fs::File;
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;

    let descriptor = crate::sys::openat2_write(
        directory.as_raw_fd(),
        Path::new(name),
        crate::sys::RESOLVE_NO_MAGICLINKS | crate::sys::RESOLVE_NO_SYMLINKS,
    )
    .map_err(map_control_open_error)?;
    let mut file = File::from(descriptor);
    file.write_all(value)
        .map_err(|_| CgroupError::ControlUnavailable)
}

#[cfg(target_os = "linux")]
fn read_control(directory: &std::os::fd::OwnedFd, name: &str) -> Result<String, CgroupError> {
    use std::fs::File;
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;

    let descriptor = crate::sys::openat2_file(
        directory.as_raw_fd(),
        Path::new(name),
        crate::sys::RESOLVE_NO_MAGICLINKS | crate::sys::RESOLVE_NO_SYMLINKS,
    )
    .map_err(map_control_open_error)?;
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take(CONTROL_READ_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CgroupError::ControlUnavailable)?;
    if bytes.len() as u64 > CONTROL_READ_LIMIT {
        return Err(CgroupError::ControlUnavailable);
    }
    String::from_utf8(bytes).map_err(|_| CgroupError::ControlUnavailable)
}

#[cfg(target_os = "linux")]
fn read_word_set(directory: &std::os::fd::OwnedFd, name: &str) -> Result<Vec<String>, CgroupError> {
    let mut values = read_control(directory, name)?
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    Ok(values)
}

#[cfg(target_os = "linux")]
fn processes(directory: &std::os::fd::OwnedFd) -> Result<Vec<u32>, CgroupError> {
    parse_processes(&read_control(directory, "cgroup.procs")?)
}

#[cfg(target_os = "linux")]
fn populated(directory: &std::os::fd::OwnedFd) -> Result<bool, CgroupError> {
    parse_events(&read_control(directory, "cgroup.events")?)
}

#[cfg(target_os = "linux")]
fn directory_inode(directory: &std::os::fd::OwnedFd) -> Result<u64, CgroupError> {
    use std::fs::File;
    use std::os::unix::fs::MetadataExt as _;

    File::from(
        directory
            .try_clone()
            .map_err(|_| CgroupError::IdentityUnavailable)?,
    )
    .metadata()
    .map(|metadata| metadata.ino())
    .map_err(|_| CgroupError::IdentityUnavailable)
}

#[cfg(target_os = "linux")]
fn map_creation_error(error: std::io::Error) -> CgroupError {
    if error.raw_os_error() == Some(libc::EEXIST) {
        CgroupError::AlreadyExists
    } else {
        CgroupError::CreationFailed
    }
}

#[cfg(target_os = "linux")]
fn map_control_open_error(error: std::io::Error) -> CgroupError {
    if error.raw_os_error() == Some(libc::ENOSYS) {
        CgroupError::Openat2Unavailable
    } else {
        CgroupError::ControlUnavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofbound_runtime_core::{
        MemoryByteLimit, OutputByteLimit, ResourceLimits, SwapByteLimit, WallTimeLimit,
    };

    const ATTACK_CATALOG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/attacks/cgroup/lifecycle-v1.toml"
    ));

    fn execution_id() -> ExecutionId {
        ExecutionId::from_bytes([0, 1, 2, 3, 4, 5, 0x46, 7, 0x88, 9, 10, 11, 12, 13, 14, 15])
            .expect("fixture is a version 4 UUID")
    }

    #[test]
    fn cgroup_name_is_a_single_stable_component() {
        assert_eq!(
            cgroup_name(execution_id()),
            Path::new("proofbound-runtime-000102030405460788090a0b0c0d0e0f")
        );
    }

    #[test]
    fn version_two_controls_are_complete_and_canonical() {
        let limits = ResourceLimits::new_v2(
            ProcessLimit::new(2).expect("valid process limit"),
            WallTimeLimit::from_milliseconds(1_000).expect("valid wall limit"),
            OutputByteLimit::new(1_024),
            OutputByteLimit::new(2_048),
            MemoryByteLimit::new(65_536).expect("valid memory limit"),
            SwapByteLimit::new(0).expect("valid swap limit"),
        );
        assert_eq!(
            installed_control_values(limits).expect("v2 controls are complete"),
            [
                ("pids.max", "2".to_owned()),
                ("memory.max", "65536".to_owned()),
                ("memory.swap.max", "0".to_owned()),
                ("memory.oom.group", "1".to_owned()),
            ]
        );
        let legacy = ResourceLimits::new(
            ProcessLimit::new(2).expect("valid process limit"),
            WallTimeLimit::from_milliseconds(1_000).expect("valid wall limit"),
            OutputByteLimit::new(1_024),
            OutputByteLimit::new(2_048),
        );
        assert_eq!(
            installed_control_values(legacy),
            Err(CgroupError::ResourceProfileIncomplete)
        );
    }

    #[test]
    fn version_two_observations_are_strict_monotonic_and_derive_events() {
        let initial = parse_resource_snapshot(
            "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n",
            "max 0\nfail 0\n",
            "0\n",
            "0\n",
        )
        .expect("canonical zero snapshot");
        assert!(initial.is_zero());

        let terminal = parse_resource_snapshot(
            "low 0\nhigh 2\nmax 3\noom 1\noom_kill 1\noom_group_kill 0\n",
            "max 4\nfail 5\n",
            "65536\n",
            "32768\n",
        )
        .expect("canonical terminal snapshot");
        let observed = terminal
            .checked_delta(initial)
            .expect("monotonic counters");
        assert_eq!(observed.memory_peak_bytes(), 65_536);
        assert_eq!(observed.swap_peak_bytes(), 32_768);
        assert_eq!(observed.memory_events().high(), 2);
        assert_eq!(observed.memory_events().max(), 3);
        assert_eq!(observed.memory_events().oom(), 1);
        assert_eq!(observed.memory_events().oom_kill(), 1);
        assert_eq!(observed.swap_events().max(), 4);
        assert_eq!(observed.swap_events().fail(), 5);
        assert!(observed.limit_events().contains(LimitEvent::MemoryHigh));
        assert!(observed.limit_events().contains(LimitEvent::MemoryMax));
        assert!(observed.limit_events().contains(LimitEvent::MemoryOom));
        assert!(observed.limit_events().contains(LimitEvent::MemoryOomKill));
        assert!(observed.limit_events().contains(LimitEvent::SwapMax));
        assert!(observed.limit_events().contains(LimitEvent::SwapFail));

        assert_eq!(
            initial.checked_delta(terminal),
            Err(CgroupError::ObservationRegression)
        );
        assert_eq!(
            parse_resource_snapshot(
                "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
                "max 0\nfail 0\n",
                "0\n",
                "0\n",
            ),
            Err(CgroupError::ObservationInvalid)
        );
    }

    #[test]
    fn parses_kernel_events_and_process_sets_strictly() {
        assert_eq!(parse_events("populated 0\nfrozen 0\n"), Ok(false));
        assert_eq!(parse_events("populated 1\n"), Ok(true));
        assert_eq!(parse_events("frozen 0\n"), Err(CgroupError::EventsInvalid));
        assert_eq!(
            parse_events("populated 0\npopulated 1\n"),
            Err(CgroupError::EventsInvalid)
        );
        assert_eq!(parse_processes("42\n7\n42\n"), Ok(vec![7, 42]));
        assert_eq!(parse_processes("0\n"), Err(CgroupError::ControlUnavailable));
    }

    #[test]
    fn frozen_cgroup_attack_catalog_is_closed() {
        let expected_ids = [
            "preexisting-cgroup",
            "missing-pids-controller",
            "pids-limit-substitution",
            "launcher-membership-omission",
            "launcher-membership-substitution",
            "populated-cleanup",
        ];
        assert!(ATTACK_CATALOG.starts_with("schema = \"proofbound-runtime-cgroup-attacks/1\""));
        assert_eq!(
            ATTACK_CATALOG.matches("[[attack]]").count(),
            expected_ids.len()
        );
        for id in expected_ids {
            assert!(ATTACK_CATALOG.contains(&format!("id = \"{id}\"")));
        }
    }

    #[test]
    fn error_codes_are_unique_and_stable() {
        let errors = [
            CgroupError::UnsupportedOperatingSystem,
            CgroupError::CapabilityMismatch,
            CgroupError::ResourceProfileIncomplete,
            CgroupError::ParentUnavailable,
            CgroupError::ControllerUnavailable,
            CgroupError::AlreadyExists,
            CgroupError::CreationFailed,
            CgroupError::OpenFailed,
            CgroupError::ControlUnavailable,
            CgroupError::LimitMismatch,
            CgroupError::NotFresh,
            CgroupError::ProcessIdInvalid,
            CgroupError::MembershipMismatch,
            CgroupError::EventsInvalid,
            CgroupError::DrainFailed,
            CgroupError::RemovalFailed,
            CgroupError::IdentityUnavailable,
            CgroupError::Openat2Unavailable,
        ];
        let mut codes = errors.map(CgroupError::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn supported_probe_can_create_limit_and_remove_empty_group() {
        let Some(root) = std::env::var_os("PROOFBOUND_CGROUP_ROOT") else {
            return;
        };
        let Ok(supported) = crate::probe_capabilities(Path::new(&root)).require_supported() else {
            return;
        };
        let limit = ProcessLimit::new(1).expect("nonzero process limit");
        let group = FreshCgroup::create(supported.cgroup_v2(), execution_id(), limit)
            .expect("positive capability must support lifecycle");
        assert_eq!(group.process_limit(), limit);
        assert!(!group.is_populated().expect("read populated state"));
        group.cleanup().expect("remove empty test cgroup");
    }
}
