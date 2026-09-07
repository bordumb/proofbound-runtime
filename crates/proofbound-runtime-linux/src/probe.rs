//! Reports native Linux boundary capabilities without installing a boundary.

use core::fmt;
use core::num::NonZeroU32;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
const MIN_LANDLOCK_ABI: u32 = 3;
#[cfg(target_os = "linux")]
const MAX_REVIEWED_LANDLOCK_ABI: u32 = 11;

/// Identifies one supported native Linux architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Architecture {
    /// The x86-64 architecture.
    X86_64,
    /// The 64-bit Arm architecture.
    Aarch64,
}

impl Architecture {
    /// Returns the stable receipt wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

/// Reports one independently probed capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Capability<T> {
    /// The capability was observed with its exact value.
    Available(T),
    /// The capability could not satisfy the supported profile.
    Unavailable(ProbeError),
}

impl<T> Capability<T> {
    /// Reports whether the capability is available.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    fn into_result(self) -> Result<T, ProbeError> {
        match self {
            Self::Available(value) => Ok(value),
            Self::Unavailable(error) => Err(error),
        }
    }
}

/// Contains the seccomp features required by the version 1 profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeccompCapability {
    available_actions: Vec<String>,
}

impl SeccompCapability {
    /// Returns every kernel-reported action in canonical order.
    #[must_use]
    pub fn available_actions(&self) -> &[String] {
        &self.available_actions
    }
}

/// Contains one usable delegated cgroup v2 root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CgroupV2Capability {
    directory: PathBuf,
    mount_id: u64,
    directory_inode: u64,
    controllers: Vec<String>,
}

impl CgroupV2Capability {
    /// Returns the empty delegated cgroup v2 root.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Returns the kernel mount identifier for the unified hierarchy.
    #[must_use]
    pub const fn mount_id(&self) -> u64 {
        self.mount_id
    }

    /// Returns the inode identity of the delegated root at probe time.
    #[must_use]
    pub const fn directory_inode(&self) -> u64 {
        self.directory_inode
    }

    /// Returns available controllers in canonical order.
    #[must_use]
    pub fn controllers(&self) -> &[String] {
        &self.controllers
    }
}

/// Contains each capability result, including failures on unsupported hosts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityReport {
    /// Native Linux operating-system support.
    pub operating_system: Capability<()>,
    /// Supported machine architecture.
    pub architecture: Capability<Architecture>,
    /// Exact Linux kernel release.
    pub kernel_release: Capability<String>,
    /// Nonzero Landlock ABI reported by the kernel.
    pub landlock_abi: Capability<NonZeroU32>,
    /// `PR_GET_NO_NEW_PRIVS` support.
    pub no_new_privileges: Capability<()>,
    /// Required seccomp filter actions.
    pub seccomp: Capability<SeccompCapability>,
    /// Delegated cgroup v2 directory and required controllers.
    pub cgroup_v2: Capability<CgroupV2Capability>,
}

impl CapabilityReport {
    /// Requires every capability and returns the supported host identity.
    pub fn require_supported(self) -> Result<SupportedLinux, ProbeError> {
        self.operating_system.into_result()?;
        Ok(SupportedLinux {
            architecture: self.architecture.into_result()?,
            kernel_release: self.kernel_release.into_result()?,
            landlock_abi: self.landlock_abi.into_result()?,
            seccomp: self.seccomp.into_result()?,
            cgroup_v2: self.cgroup_v2.into_result()?,
            no_new_privileges: self.no_new_privileges.into_result()?,
        })
    }
}

/// Contains the complete observed identity of one supported Linux host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportedLinux {
    architecture: Architecture,
    kernel_release: String,
    landlock_abi: NonZeroU32,
    seccomp: SeccompCapability,
    cgroup_v2: CgroupV2Capability,
    no_new_privileges: (),
}

impl SupportedLinux {
    /// Returns the supported architecture.
    #[must_use]
    pub const fn architecture(&self) -> Architecture {
        self.architecture
    }

    /// Returns the exact Linux kernel release.
    #[must_use]
    pub fn kernel_release(&self) -> &str {
        &self.kernel_release
    }

    /// Returns the nonzero Landlock ABI.
    #[must_use]
    pub const fn landlock_abi(&self) -> NonZeroU32 {
        self.landlock_abi
    }

    /// Returns the supported seccomp capability.
    #[must_use]
    pub const fn seccomp(&self) -> &SeccompCapability {
        &self.seccomp
    }

    /// Returns the delegated cgroup v2 capability.
    #[must_use]
    pub const fn cgroup_v2(&self) -> &CgroupV2Capability {
        &self.cgroup_v2
    }

    /// Reports support for installing `no_new_privs`.
    #[must_use]
    pub const fn supports_no_new_privileges(&self) -> bool {
        let () = self.no_new_privileges;
        true
    }
}

/// Identifies one fail-closed native capability result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeError {
    /// The host operating system is not Linux.
    UnsupportedOperatingSystem,
    /// The Linux machine architecture is outside the version 1 set.
    UnsupportedArchitecture,
    /// The exact kernel release could not be read.
    KernelReleaseUnavailable,
    /// The kernel did not report a nonzero Landlock ABI.
    LandlockUnavailable,
    /// The kernel Landlock ABI is outside the reviewed version 1 range.
    LandlockAbiUnsupported,
    /// The kernel did not support querying `no_new_privs`.
    NoNewPrivilegesUnavailable,
    /// The kernel did not expose seccomp filter actions.
    SeccompUnavailable,
    /// A seccomp action required by the version 1 profile is absent.
    SeccompActionMissing,
    /// A unified cgroup v2 mount or configured delegation root could not be resolved.
    CgroupV2Unavailable,
    /// The configured root is not an empty delegated parent of the supervisor.
    CgroupV2DelegationUnavailable,
    /// The pids controller required by version 1 is unavailable.
    CgroupV2ControllerMissing,
}

impl ProbeError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "platform.os.unsupported",
            Self::UnsupportedArchitecture => "platform.architecture.unsupported",
            Self::KernelReleaseUnavailable => "platform.kernel-release.unavailable",
            Self::LandlockUnavailable => "platform.landlock.unavailable",
            Self::LandlockAbiUnsupported => "platform.landlock.abi-unsupported",
            Self::NoNewPrivilegesUnavailable => "platform.no-new-privileges.unavailable",
            Self::SeccompUnavailable => "platform.seccomp.unavailable",
            Self::SeccompActionMissing => "platform.seccomp.action-missing",
            Self::CgroupV2Unavailable => "platform.cgroup-v2.unavailable",
            Self::CgroupV2DelegationUnavailable => "platform.cgroup-v2.delegation-unavailable",
            Self::CgroupV2ControllerMissing => "platform.cgroup-v2.controller-missing",
        }
    }
}

impl fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProbeError {}

/// Probes every version 1 platform capability without installing a boundary.
///
/// `cgroup_root` must name an already-prepared delegated cgroup v2 inner node.
/// The supervisor must run in a strict descendant leaf, the root must contain no
/// direct processes, and the `pids` controller must already be enabled for its
/// children. The probe never mutates the host cgroup hierarchy.
#[must_use]
pub fn probe_capabilities(cgroup_root: &Path) -> CapabilityReport {
    probe_platform(cgroup_root)
}

#[cfg(not(target_os = "linux"))]
fn probe_platform(_cgroup_root: &Path) -> CapabilityReport {
    const UNSUPPORTED: Capability<()> =
        Capability::Unavailable(ProbeError::UnsupportedOperatingSystem);
    CapabilityReport {
        operating_system: UNSUPPORTED,
        architecture: Capability::Unavailable(ProbeError::UnsupportedOperatingSystem),
        kernel_release: Capability::Unavailable(ProbeError::UnsupportedOperatingSystem),
        landlock_abi: Capability::Unavailable(ProbeError::UnsupportedOperatingSystem),
        no_new_privileges: UNSUPPORTED,
        seccomp: Capability::Unavailable(ProbeError::UnsupportedOperatingSystem),
        cgroup_v2: Capability::Unavailable(ProbeError::UnsupportedOperatingSystem),
    }
}

#[cfg(target_os = "linux")]
fn probe_platform(cgroup_root: &Path) -> CapabilityReport {
    CapabilityReport {
        operating_system: Capability::Available(()),
        architecture: probe_architecture(),
        kernel_release: read_nonempty(
            "/proc/sys/kernel/osrelease",
            ProbeError::KernelReleaseUnavailable,
        ),
        landlock_abi: probe_landlock(),
        no_new_privileges: probe_no_new_privileges(),
        seccomp: probe_seccomp(),
        cgroup_v2: probe_cgroup_v2(cgroup_root),
    }
}

#[cfg(target_os = "linux")]
fn probe_architecture() -> Capability<Architecture> {
    #[cfg(target_arch = "x86_64")]
    return Capability::Available(Architecture::X86_64);
    #[cfg(target_arch = "aarch64")]
    return Capability::Available(Architecture::Aarch64);
    #[allow(unreachable_code)]
    Capability::Unavailable(ProbeError::UnsupportedArchitecture)
}

#[cfg(target_os = "linux")]
fn probe_landlock() -> Capability<NonZeroU32> {
    match crate::sys::landlock_abi().ok().and_then(NonZeroU32::new) {
        Some(abi) if (MIN_LANDLOCK_ABI..=MAX_REVIEWED_LANDLOCK_ABI).contains(&abi.get()) => {
            Capability::Available(abi)
        }
        Some(_) => Capability::Unavailable(ProbeError::LandlockAbiUnsupported),
        None => Capability::Unavailable(ProbeError::LandlockUnavailable),
    }
}

#[cfg(target_os = "linux")]
fn probe_no_new_privileges() -> Capability<()> {
    match crate::sys::no_new_privileges_supported() {
        Ok(true) => Capability::Available(()),
        Ok(false) | Err(_) => Capability::Unavailable(ProbeError::NoNewPrivilegesUnavailable),
    }
}

#[cfg(target_os = "linux")]
fn probe_seccomp() -> Capability<SeccompCapability> {
    if crate::sys::seccomp_mode().is_err() {
        return Capability::Unavailable(ProbeError::SeccompUnavailable);
    }
    let Capability::Available(actions) = read_set("/proc/sys/kernel/seccomp/actions_avail") else {
        return Capability::Unavailable(ProbeError::SeccompUnavailable);
    };
    if !["allow", "errno", "kill_process"].iter().all(|required| {
        actions
            .binary_search_by(|item| item.as_str().cmp(required))
            .is_ok()
    }) {
        return Capability::Unavailable(ProbeError::SeccompActionMissing);
    }
    Capability::Available(SeccompCapability {
        available_actions: actions,
    })
}

#[cfg(target_os = "linux")]
fn probe_cgroup_v2(configured_root: &Path) -> Capability<CgroupV2Capability> {
    use std::os::unix::fs::MetadataExt as _;

    let Some((mount_id, mount)) = cgroup_v2_mount() else {
        return Capability::Unavailable(ProbeError::CgroupV2Unavailable);
    };
    let Ok(mount) = std::fs::canonicalize(mount) else {
        return Capability::Unavailable(ProbeError::CgroupV2Unavailable);
    };
    let Ok(directory) = std::fs::canonicalize(configured_root) else {
        return Capability::Unavailable(ProbeError::CgroupV2Unavailable);
    };
    if directory == mount || !directory.starts_with(&mount) {
        return Capability::Unavailable(ProbeError::CgroupV2DelegationUnavailable);
    }
    let Some(relative) = current_cgroup() else {
        return Capability::Unavailable(ProbeError::CgroupV2Unavailable);
    };
    let Ok(current) = std::fs::canonicalize(mount.join(relative.trim_start_matches('/'))) else {
        return Capability::Unavailable(ProbeError::CgroupV2Unavailable);
    };
    let Ok(supervisor_relative) = current.strip_prefix(&directory) else {
        return Capability::Unavailable(ProbeError::CgroupV2DelegationUnavailable);
    };
    if supervisor_relative.as_os_str().is_empty()
        || !matches!(
            std::fs::read_to_string(directory.join("cgroup.procs")),
            Ok(value) if value.trim().is_empty()
        )
        || !matches!(
            std::fs::read_to_string(directory.join("cgroup.type")),
            Ok(value) if value.trim() == "domain"
        )
    {
        return Capability::Unavailable(ProbeError::CgroupV2DelegationUnavailable);
    }
    let Capability::Available(controllers) = read_set(directory.join("cgroup.controllers")) else {
        return Capability::Unavailable(ProbeError::CgroupV2Unavailable);
    };
    if controllers
        .binary_search_by(|item| item.as_str().cmp("pids"))
        .is_err()
    {
        return Capability::Unavailable(ProbeError::CgroupV2ControllerMissing);
    }
    let Capability::Available(enabled) = read_set(directory.join("cgroup.subtree_control")) else {
        return Capability::Unavailable(ProbeError::CgroupV2DelegationUnavailable);
    };
    if enabled
        .binary_search_by(|item| item.as_str().cmp("pids"))
        .is_err()
    {
        return Capability::Unavailable(ProbeError::CgroupV2DelegationUnavailable);
    }
    if !crate::sys::path_is_writable(&directory)
        || std::fs::OpenOptions::new()
            .write(true)
            .open(directory.join("cgroup.subtree_control"))
            .is_err()
        || std::fs::OpenOptions::new()
            .write(true)
            .open(directory.join("cgroup.procs"))
            .is_err()
    {
        return Capability::Unavailable(ProbeError::CgroupV2DelegationUnavailable);
    }
    let Ok(metadata) = std::fs::metadata(&directory) else {
        return Capability::Unavailable(ProbeError::CgroupV2Unavailable);
    };
    Capability::Available(CgroupV2Capability {
        directory,
        mount_id,
        directory_inode: metadata.ino(),
        controllers,
    })
}

#[cfg(target_os = "linux")]
fn cgroup_v2_mount() -> Option<(u64, PathBuf)> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    parse_cgroup_v2_mount(&mountinfo)
}

#[cfg(any(test, target_os = "linux"))]
fn parse_cgroup_v2_mount(mountinfo: &str) -> Option<(u64, PathBuf)> {
    mountinfo.lines().find_map(|line| {
        let (mount, filesystem) = line.split_once(" - ")?;
        if filesystem.split_whitespace().next()? != "cgroup2" {
            return None;
        }
        let mut fields = mount.split_whitespace();
        let mount_id = fields.next()?.parse().ok()?;
        let path = fields.nth(3).map(decode_mount_path)?;
        Some((mount_id, path))
    })
}

#[cfg(target_os = "linux")]
fn current_cgroup() -> Option<String> {
    std::fs::read_to_string("/proc/self/cgroup")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
}

#[cfg(any(test, target_os = "linux"))]
fn decode_mount_path(value: &str) -> PathBuf {
    PathBuf::from(
        value
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\"),
    )
}

#[cfg(target_os = "linux")]
fn read_nonempty(path: impl AsRef<Path>, error: ProbeError) -> Capability<String> {
    match std::fs::read_to_string(path) {
        Ok(value) if !value.trim().is_empty() => Capability::Available(value.trim().to_owned()),
        Ok(_) | Err(_) => Capability::Unavailable(error),
    }
}

#[cfg(target_os = "linux")]
fn read_set(path: impl AsRef<Path>) -> Capability<Vec<String>> {
    match std::fs::read_to_string(path) {
        Ok(value) => {
            let mut values: Vec<_> = value.split_whitespace().map(str::to_owned).collect();
            values.sort();
            values.dedup();
            Capability::Available(values)
        }
        Err(_) => Capability::Unavailable(ProbeError::CgroupV2Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_hosts_never_produce_supported_linux() {
        let report = probe_capabilities(Path::new("/unsupported"));
        assert_eq!(
            report.clone().require_supported(),
            Err(ProbeError::UnsupportedOperatingSystem)
        );
        assert!(!report.operating_system.is_available());
        assert!(!report.landlock_abi.is_available());
        assert!(!report.seccomp.is_available());
        assert!(!report.cgroup_v2.is_available());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn supported_result_contains_every_required_capability() {
        let Some(root) = std::env::var_os("PROOFBOUND_CGROUP_ROOT") else {
            return;
        };
        let report = probe_capabilities(Path::new(&root));
        if let Ok(supported) = report.require_supported() {
            assert!(!supported.kernel_release().is_empty());
            assert!(supported.landlock_abi().get() > 0);
            assert!(supported.supports_no_new_privileges());
            assert!(
                supported
                    .seccomp()
                    .available_actions()
                    .iter()
                    .any(|action| action == "errno")
            );
            assert!(
                supported
                    .cgroup_v2()
                    .controllers()
                    .iter()
                    .any(|controller| controller == "pids")
            );
        }
    }

    #[test]
    fn probe_errors_have_distinct_stable_codes() {
        let errors = [
            ProbeError::UnsupportedOperatingSystem,
            ProbeError::UnsupportedArchitecture,
            ProbeError::KernelReleaseUnavailable,
            ProbeError::LandlockUnavailable,
            ProbeError::LandlockAbiUnsupported,
            ProbeError::NoNewPrivilegesUnavailable,
            ProbeError::SeccompUnavailable,
            ProbeError::SeccompActionMissing,
            ProbeError::CgroupV2Unavailable,
            ProbeError::CgroupV2DelegationUnavailable,
            ProbeError::CgroupV2ControllerMissing,
        ];
        let mut codes: Vec<_> = errors.into_iter().map(ProbeError::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), errors.len());
    }

    #[test]
    fn parses_exact_cgroup_v2_mount_identity() {
        let mountinfo = concat!(
            "22 1 0:20 / /proc rw - proc proc rw\n",
            "37 1 0:42 / /sys/fs/cgroup\\040delegated rw - cgroup2 cgroup rw\n",
        );
        assert_eq!(
            parse_cgroup_v2_mount(mountinfo),
            Some((37, PathBuf::from("/sys/fs/cgroup delegated")))
        );
    }
}
