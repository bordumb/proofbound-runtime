//! Owns fresh cgroup v2 creation, process limits, membership, and cleanup.

use core::fmt;
use std::path::{Path, PathBuf};

use proofbound_runtime_core::{
    CgroupIdentity, ExecutionId, LimitEvent, LimitEvents, MemoryByteLimit, ProcessLimit,
    ResourceLimits, SwapByteLimit,
};

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

/// Contains the checked terminal deltas from `memory.events.local`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryEvents {
    low: u64,
    high: u64,
    max: u64,
    oom: u64,
    oom_kill: u64,
    oom_group_kill: u64,
}

impl MemoryEvents {
    /// Returns the `low` counter delta.
    #[must_use]
    pub const fn low(self) -> u64 {
        self.low
    }
    /// Returns the `high` counter delta.
    #[must_use]
    pub const fn high(self) -> u64 {
        self.high
    }
    /// Returns the `max` counter delta.
    #[must_use]
    pub const fn max(self) -> u64 {
        self.max
    }
    /// Returns the `oom` counter delta.
    #[must_use]
    pub const fn oom(self) -> u64 {
        self.oom
    }
    /// Returns the `oom_kill` counter delta.
    #[must_use]
    pub const fn oom_kill(self) -> u64 {
        self.oom_kill
    }
    /// Returns the `oom_group_kill` counter delta.
    #[must_use]
    pub const fn oom_group_kill(self) -> u64 {
        self.oom_group_kill
    }

    #[cfg(any(test, target_os = "linux"))]
    fn checked_sub(self, initial: Self) -> Option<Self> {
        Some(Self {
            low: self.low.checked_sub(initial.low)?,
            high: self.high.checked_sub(initial.high)?,
            max: self.max.checked_sub(initial.max)?,
            oom: self.oom.checked_sub(initial.oom)?,
            oom_kill: self.oom_kill.checked_sub(initial.oom_kill)?,
            oom_group_kill: self.oom_group_kill.checked_sub(initial.oom_group_kill)?,
        })
    }

    #[cfg(any(test, target_os = "linux"))]
    const fn is_zero(self) -> bool {
        self.low == 0
            && self.high == 0
            && self.max == 0
            && self.oom == 0
            && self.oom_kill == 0
            && self.oom_group_kill == 0
    }
}

/// Contains the checked terminal deltas from `memory.swap.events`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SwapEvents {
    max: u64,
    fail: u64,
}

impl SwapEvents {
    /// Returns the `max` counter delta.
    #[must_use]
    pub const fn max(self) -> u64 {
        self.max
    }
    /// Returns the `fail` counter delta.
    #[must_use]
    pub const fn fail(self) -> u64 {
        self.fail
    }

    #[cfg(any(test, target_os = "linux"))]
    fn checked_sub(self, initial: Self) -> Option<Self> {
        Some(Self {
            max: self.max.checked_sub(initial.max)?,
            fail: self.fail.checked_sub(initial.fail)?,
        })
    }

    #[cfg(any(test, target_os = "linux"))]
    const fn is_zero(self) -> bool {
        self.max == 0 && self.fail == 0
    }
}

/// Contains terminal version 2 observations from one exact fresh cgroup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalResources {
    configured: ConfiguredResources,
    memory_peak_bytes: u64,
    swap_peak_bytes: u64,
    memory_events: MemoryEvents,
    swap_events: SwapEvents,
}

impl TerminalResources {
    /// Returns the exact values read back after installing the cgroup controls.
    #[must_use]
    pub const fn configured(self) -> ConfiguredResources {
        self.configured
    }
    /// Returns the terminal `memory.peak` value.
    #[must_use]
    pub const fn memory_peak_bytes(self) -> u64 {
        self.memory_peak_bytes
    }
    /// Returns the terminal `memory.swap.peak` value.
    #[must_use]
    pub const fn swap_peak_bytes(self) -> u64 {
        self.swap_peak_bytes
    }
    /// Returns checked memory-event deltas.
    #[must_use]
    pub const fn memory_events(self) -> MemoryEvents {
        self.memory_events
    }
    /// Returns checked swap-event deltas.
    #[must_use]
    pub const fn swap_events(self) -> SwapEvents {
        self.swap_events
    }

    /// Derives the canonical limit-event set from nonzero counters only.
    #[must_use]
    pub fn limit_events(self) -> LimitEvents {
        let mut events = Vec::new();
        for (present, event) in [
            (self.memory_events.high != 0, LimitEvent::MemoryHigh),
            (self.memory_events.max != 0, LimitEvent::MemoryMax),
            (self.memory_events.oom != 0, LimitEvent::MemoryOom),
            (self.memory_events.oom_kill != 0, LimitEvent::MemoryOomKill),
            (
                self.memory_events.oom_group_kill != 0,
                LimitEvent::MemoryOomGroupKill,
            ),
            (self.swap_events.max != 0, LimitEvent::SwapMax),
            (self.swap_events.fail != 0, LimitEvent::SwapFail),
        ] {
            if present {
                events.push(event);
            }
        }
        LimitEvents::new(&events)
    }
}

/// Contains the exact version 2 control values read back from one fresh cgroup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfiguredResources {
    processes: ProcessLimit,
    memory: MemoryByteLimit,
    swap: SwapByteLimit,
    memory_oom_group: u64,
}

impl ConfiguredResources {
    /// Returns the read-back `pids.max` value.
    #[must_use]
    pub const fn processes(self) -> ProcessLimit {
        self.processes
    }

    /// Returns the read-back `memory.max` value.
    #[must_use]
    pub const fn memory(self) -> MemoryByteLimit {
        self.memory
    }

    /// Returns the read-back `memory.swap.max` value.
    #[must_use]
    pub const fn swap(self) -> SwapByteLimit {
        self.swap
    }

    /// Returns the read-back `memory.oom.group` value.
    #[must_use]
    pub const fn memory_oom_group(self) -> u64 {
        self.memory_oom_group
    }
}

/// Reports whether terminal cgroup observations completed after exact cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceObservation {
    /// Legacy process-only execution has no version 2 resource observation.
    Legacy,
    /// Every version 2 terminal counter and peak was read and checked.
    Complete(TerminalResources),
    /// Configured readbacks are retained, but terminal observation failed.
    Incomplete(ConfiguredResources),
}

impl ResourceObservation {
    /// Returns complete terminal resources, if observation succeeded.
    #[must_use]
    pub const fn complete(self) -> Option<TerminalResources> {
        match self {
            Self::Complete(resources) => Some(resources),
            Self::Legacy | Self::Incomplete(_) => None,
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
fn retain_resource_observation(
    configured: ConfiguredResources,
    observation: Result<TerminalResources, CgroupError>,
) -> ResourceObservation {
    match observation {
        Ok(terminal) => ResourceObservation::Complete(terminal),
        Err(_) => ResourceObservation::Incomplete(configured),
    }
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResourceSnapshot {
    memory_peak_bytes: u64,
    swap_peak_bytes: u64,
    memory_events: MemoryEvents,
    swap_events: SwapEvents,
}

#[cfg(any(test, target_os = "linux"))]
impl ResourceSnapshot {
    const fn is_zero(self) -> bool {
        self.memory_peak_bytes == 0
            && self.swap_peak_bytes == 0
            && self.memory_events.is_zero()
            && self.swap_events.is_zero()
    }

    fn checked_delta(
        self,
        initial: Self,
        configured: ConfiguredResources,
    ) -> Result<TerminalResources, CgroupError> {
        if self.memory_peak_bytes < initial.memory_peak_bytes
            || self.swap_peak_bytes < initial.swap_peak_bytes
        {
            return Err(CgroupError::ObservationRegression);
        }
        Ok(TerminalResources {
            configured,
            memory_peak_bytes: self.memory_peak_bytes,
            swap_peak_bytes: self.swap_peak_bytes,
            memory_events: self
                .memory_events
                .checked_sub(initial.memory_events)
                .ok_or(CgroupError::ObservationRegression)?,
            swap_events: self
                .swap_events
                .checked_sub(initial.swap_events)
                .ok_or(CgroupError::ObservationRegression)?,
        })
    }
}

#[cfg(any(test, target_os = "linux"))]
fn configured_resources_from_readbacks(
    values: [&str; 4],
) -> Result<ConfiguredResources, CgroupError> {
    let processes = parse_canonical_u64(values[0])
        .ok()
        .and_then(|value| u32::try_from(value).ok())
        .and_then(|value| ProcessLimit::new(value).ok())
        .ok_or(CgroupError::LimitMismatch)?;
    let memory = parse_canonical_u64(values[1])
        .ok()
        .and_then(|value| MemoryByteLimit::new(value).ok())
        .ok_or(CgroupError::LimitMismatch)?;
    let swap = parse_canonical_u64(values[2])
        .ok()
        .and_then(|value| SwapByteLimit::new(value).ok())
        .ok_or(CgroupError::LimitMismatch)?;
    let memory_oom_group = parse_canonical_u64(values[3])?;
    if memory_oom_group != 1 {
        return Err(CgroupError::LimitMismatch);
    }
    Ok(ConfiguredResources {
        processes,
        memory,
        swap,
        memory_oom_group,
    })
}

#[cfg(any(test, target_os = "linux"))]
fn parse_resource_snapshot(
    memory_events: &str,
    swap_events: &str,
    memory_peak: &str,
    swap_peak: &str,
) -> Result<ResourceSnapshot, CgroupError> {
    let memory = parse_named_counters(
        memory_events,
        ["low", "high", "max", "oom", "oom_kill", "oom_group_kill"],
        [],
    )?;
    let swap = parse_named_counters(swap_events, ["max", "fail"], ["high"])?;
    Ok(ResourceSnapshot {
        memory_peak_bytes: parse_u64_line(memory_peak)?,
        swap_peak_bytes: parse_u64_line(swap_peak)?,
        memory_events: MemoryEvents {
            low: memory[0],
            high: memory[1],
            max: memory[2],
            oom: memory[3],
            oom_kill: memory[4],
            oom_group_kill: memory[5],
        },
        swap_events: SwapEvents {
            max: swap[0],
            fail: swap[1],
        },
    })
}

#[cfg(any(test, target_os = "linux"))]
fn parse_named_counters<const N: usize, const I: usize>(
    input: &str,
    names: [&str; N],
    ignored_names: [&str; I],
) -> Result<[u64; N], CgroupError> {
    let mut values = [None; N];
    let mut ignored = [false; I];
    for line in input.lines() {
        let mut fields = line.split_whitespace();
        let name = fields.next().ok_or(CgroupError::ObservationInvalid)?;
        let value = fields.next().ok_or(CgroupError::ObservationInvalid)?;
        if fields.next().is_some() {
            return Err(CgroupError::ObservationInvalid);
        }
        if let Some(index) = names.iter().position(|required| *required == name) {
            if values[index].is_some() {
                return Err(CgroupError::ObservationInvalid);
            }
            values[index] = Some(parse_canonical_u64(value)?);
        } else if let Some(index) = ignored_names.iter().position(|ignored| *ignored == name) {
            if ignored[index] {
                return Err(CgroupError::ObservationInvalid);
            }
            parse_canonical_u64(value)?;
            ignored[index] = true;
        } else {
            return Err(CgroupError::ObservationInvalid);
        }
    }
    if values.iter().any(Option::is_none) {
        return Err(CgroupError::ObservationInvalid);
    }
    Ok(values.map(|value| value.expect("all counters were checked")))
}

#[cfg(any(test, target_os = "linux"))]
fn parse_u64_line(input: &str) -> Result<u64, CgroupError> {
    let value = input.strip_suffix('\n').unwrap_or(input);
    if value.contains('\n') || value.contains('\r') {
        return Err(CgroupError::ObservationInvalid);
    }
    parse_canonical_u64(value)
}

#[cfg(any(test, target_os = "linux"))]
fn parse_canonical_u64(value: &str) -> Result<u64, CgroupError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(CgroupError::ObservationInvalid);
    }
    value.parse().map_err(|_| CgroupError::ObservationInvalid)
}

/// Owns one fresh cgroup v2 boundary for an execution attempt.
#[derive(Debug)]
pub struct FreshCgroup {
    path: PathBuf,
    identity: CgroupIdentity,
    process_limit: ProcessLimit,
    #[cfg(target_os = "linux")]
    configured_resources: Option<ConfiguredResources>,
    #[cfg(target_os = "linux")]
    initial_resources: Option<ResourceSnapshot>,
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
                configured_resources: None,
                initial_resources: None,
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
                let mut readbacks = Vec::with_capacity(controls.len());
                for (name, value) in &controls {
                    write_control(&descriptor, name, value.as_bytes())?;
                    let observed = read_control(&descriptor, name)?;
                    let observed = observed.trim();
                    if observed != value {
                        return Err(CgroupError::LimitMismatch);
                    }
                    readbacks.push(observed.to_owned());
                }
                let configured = configured_resources_from_readbacks([
                    &readbacks[0],
                    &readbacks[1],
                    &readbacks[2],
                    &readbacks[3],
                ])?;
                let initial = read_resource_snapshot(&descriptor)?;
                if !initial.is_zero() {
                    return Err(CgroupError::ObservationNonzero);
                }
                if populated(&descriptor)? || !processes(&descriptor)?.is_empty() {
                    return Err(CgroupError::NotFresh);
                }
                Ok((initial, configured))
            })();
            let (initial_resources, configured_resources) = match setup {
                Ok(values) => values,
                Err(error) => {
                    drop(descriptor);
                    let _ = crate::sys::remove_directory_at(parent.as_raw_fd(), &name);
                    return Err(error);
                }
            };

            let inode = directory_inode(&descriptor)?;
            let identity = CgroupIdentity::new(capability.mount_id(), inode);
            Ok(Self {
                path: capability.directory().join(&name),
                identity,
                process_limit: limits.processes(),
                configured_resources: Some(configured_resources),
                initial_resources: Some(initial_resources),
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

    /// Drains the exact group, captures version 2 observations, then removes it.
    pub fn finish(self) -> Result<ResourceObservation, CgroupError> {
        #[cfg(target_os = "linux")]
        {
            let mut group = self;
            group.drain_in_place()?;
            let observation = match (group.initial_resources, group.configured_resources) {
                (Some(initial), Some(configured)) => retain_resource_observation(
                    configured,
                    read_resource_snapshot(&group.descriptor)
                        .and_then(|terminal| terminal.checked_delta(initial, configured)),
                ),
                (None, None) => ResourceObservation::Legacy,
                _ => return Err(CgroupError::ObservationInvalid),
            };
            group.remove_in_place()?;
            Ok(observation)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(CgroupError::UnsupportedOperatingSystem)
        }
    }

    #[cfg(target_os = "linux")]
    fn cleanup_in_place(&mut self) -> Result<(), CgroupError> {
        self.drain_in_place()?;
        self.remove_in_place()
    }

    #[cfg(target_os = "linux")]
    fn drain_in_place(&mut self) -> Result<(), CgroupError> {
        if self.removed {
            return Ok(());
        }
        if populated(&self.descriptor)? {
            write_control(&self.descriptor, "cgroup.kill", b"1")?;
        }
        for _ in 0..CLEANUP_POLLS {
            if !populated(&self.descriptor)? && processes(&self.descriptor)?.is_empty() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        Err(CgroupError::DrainFailed)
    }

    #[cfg(target_os = "linux")]
    fn remove_in_place(&mut self) -> Result<(), CgroupError> {
        use std::os::fd::AsRawFd as _;

        if self.removed {
            return Ok(());
        }
        crate::sys::remove_directory_at(self.parent.as_raw_fd(), &self.name)
            .map_err(|_| CgroupError::RemovalFailed)?;
        self.removed = true;
        Ok(())
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
    /// A required resource observation was absent, malformed, or overflowing.
    ObservationInvalid,
    /// A fresh cgroup reported a nonzero initial resource observation.
    ObservationNonzero,
    /// A terminal resource counter or peak regressed.
    ObservationRegression,
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
            Self::ObservationInvalid => "cgroup.observation.invalid",
            Self::ObservationNonzero => "cgroup.observation.nonzero-initial",
            Self::ObservationRegression => "cgroup.observation.regression",
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
fn read_resource_snapshot(
    directory: &std::os::fd::OwnedFd,
) -> Result<ResourceSnapshot, CgroupError> {
    parse_resource_snapshot(
        &read_control(directory, "memory.events.local")?,
        &read_control(directory, "memory.swap.events")?,
        &read_control(directory, "memory.peak")?,
        &read_control(directory, "memory.swap.peak")?,
    )
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
        let configured = configured_resources_from_readbacks(["2", "65536", "0", "1"])
            .expect("canonical configured readbacks");
        let observed = terminal
            .checked_delta(initial, configured)
            .expect("monotonic counters");
        assert_eq!(observed.configured(), configured);
        assert_eq!(observed.configured().processes().get(), 2);
        assert_eq!(observed.configured().memory().get(), 65_536);
        assert_eq!(observed.configured().swap().get(), 0);
        assert_eq!(observed.configured().memory_oom_group(), 1);
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
            retain_resource_observation(configured, Err(CgroupError::ObservationInvalid)),
            ResourceObservation::Incomplete(configured)
        );

        assert_eq!(
            initial.checked_delta(terminal, configured),
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
    fn swap_observation_accepts_the_kernel_high_counter_without_claiming_it() {
        let snapshot = parse_resource_snapshot(
            "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n",
            "high 7\nmax 2\nfail 3\n",
            "0\n",
            "0\n",
        )
        .expect("the excluded swap-high counter is present on supported kernels");

        assert_eq!(snapshot.swap_events.max, 2);
        assert_eq!(snapshot.swap_events.fail, 3);
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
            CgroupError::ObservationInvalid,
            CgroupError::ObservationNonzero,
            CgroupError::ObservationRegression,
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
