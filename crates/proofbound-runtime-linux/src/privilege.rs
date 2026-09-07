//! Removes active Linux capabilities and irreversibly installs `no_new_privs`.

use core::fmt;

/// Witnesses that privilege removal was installed and read back successfully.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockedPrivileges {
    user_id: u32,
    group_id: u32,
}

impl LockedPrivileges {
    /// Returns the unchanged unprivileged user identity.
    #[must_use]
    pub const fn user_id(self) -> u32 {
        self.user_id
    }

    /// Returns the unchanged unprivileged group identity.
    #[must_use]
    pub const fn group_id(self) -> u32 {
        self.group_id
    }
}

/// Clears active capability authority and installs `no_new_privs`.
///
/// This operation is intentionally irreversible and belongs in the launcher
/// child after process creation, never in the long-lived supervisor.
pub fn lock_privileges() -> Result<LockedPrivileges, PrivilegeError> {
    #[cfg(target_os = "linux")]
    {
        let initial = inspect_privileges()?;
        let identity = require_unprivileged_identity(initial)?;
        crate::sys::clear_ambient_capabilities().map_err(|_| PrivilegeError::AmbientClearFailed)?;
        crate::sys::clear_capability_sets().map_err(|_| PrivilegeError::CapabilityDropFailed)?;
        crate::sys::set_no_new_privileges()
            .map_err(|_| PrivilegeError::NoNewPrivilegesInstallFailed)?;

        let locked = inspect_privileges()?;
        validate_locked(identity, locked)?;
        Ok(identity)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(PrivilegeError::UnsupportedOperatingSystem)
    }
}

/// Identifies one fail-closed privilege-lock result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivilegeError {
    /// The host operating system is not Linux.
    UnsupportedOperatingSystem,
    /// User, group, capability, or ambient state could not be inspected.
    InspectionUnavailable,
    /// The launcher had root user or group identity.
    RootIdentity,
    /// Real, effective, and saved identities were not identical.
    IdentityMismatch,
    /// An identity changed while privileges were being locked.
    IdentityDrift,
    /// Ambient capabilities could not be cleared.
    AmbientClearFailed,
    /// Effective, permitted, and inheritable capability sets could not be zeroed.
    CapabilityDropFailed,
    /// Capability state was nonzero after the drop.
    CapabilityVerificationFailed,
    /// `PR_SET_NO_NEW_PRIVS` failed.
    NoNewPrivilegesInstallFailed,
    /// `PR_GET_NO_NEW_PRIVS` did not confirm the lock.
    NoNewPrivilegesVerificationFailed,
}

impl PrivilegeError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "privilege.os.unsupported",
            Self::InspectionUnavailable => "privilege.inspection.unavailable",
            Self::RootIdentity => "privilege.identity.root",
            Self::IdentityMismatch => "privilege.identity.mismatch",
            Self::IdentityDrift => "privilege.identity.drift",
            Self::AmbientClearFailed => "privilege.ambient.clear-failed",
            Self::CapabilityDropFailed => "privilege.capability.drop-failed",
            Self::CapabilityVerificationFailed => "privilege.capability.verification-failed",
            Self::NoNewPrivilegesInstallFailed => "privilege.no-new-privileges.install-failed",
            Self::NoNewPrivilegesVerificationFailed => {
                "privilege.no-new-privileges.verification-failed"
            }
        }
    }
}

impl fmt::Display for PrivilegeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PrivilegeError {}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Copy)]
struct IdentitySnapshot {
    real_uid: u32,
    effective_uid: u32,
    saved_uid: u32,
    real_gid: u32,
    effective_gid: u32,
    saved_gid: u32,
    capabilities: CapabilitySnapshot,
    ambient_any: bool,
    no_new_privileges: bool,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Copy, Default)]
struct CapabilitySnapshot {
    effective: u64,
    permitted: u64,
    inheritable: u64,
}

#[cfg(target_os = "linux")]
fn inspect_privileges() -> Result<IdentitySnapshot, PrivilegeError> {
    let (real_uid, effective_uid, saved_uid, real_gid, effective_gid, saved_gid) =
        crate::sys::process_ids().map_err(|_| PrivilegeError::InspectionUnavailable)?;
    let capabilities =
        crate::sys::capability_sets().map_err(|_| PrivilegeError::InspectionUnavailable)?;
    let last_capability = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|value| *value < 64)
        .ok_or(PrivilegeError::InspectionUnavailable)?;
    let mut ambient_any = false;
    for capability in 0..=last_capability {
        ambient_any |= crate::sys::ambient_capability_is_set(capability)
            .map_err(|_| PrivilegeError::InspectionUnavailable)?;
    }
    let no_new_privileges = crate::sys::no_new_privileges_enabled()
        .map_err(|_| PrivilegeError::InspectionUnavailable)?;
    Ok(IdentitySnapshot {
        real_uid,
        effective_uid,
        saved_uid,
        real_gid,
        effective_gid,
        saved_gid,
        capabilities: CapabilitySnapshot {
            effective: capabilities.effective,
            permitted: capabilities.permitted,
            inheritable: capabilities.inheritable,
        },
        ambient_any,
        no_new_privileges,
    })
}

#[cfg(any(test, target_os = "linux"))]
fn require_unprivileged_identity(
    snapshot: IdentitySnapshot,
) -> Result<LockedPrivileges, PrivilegeError> {
    if snapshot.real_uid == 0
        || snapshot.effective_uid == 0
        || snapshot.saved_uid == 0
        || snapshot.real_gid == 0
        || snapshot.effective_gid == 0
        || snapshot.saved_gid == 0
    {
        return Err(PrivilegeError::RootIdentity);
    }
    if snapshot.real_uid != snapshot.effective_uid
        || snapshot.real_uid != snapshot.saved_uid
        || snapshot.real_gid != snapshot.effective_gid
        || snapshot.real_gid != snapshot.saved_gid
    {
        return Err(PrivilegeError::IdentityMismatch);
    }
    Ok(LockedPrivileges {
        user_id: snapshot.real_uid,
        group_id: snapshot.real_gid,
    })
}

#[cfg(any(test, target_os = "linux"))]
fn validate_locked(
    identity: LockedPrivileges,
    snapshot: IdentitySnapshot,
) -> Result<(), PrivilegeError> {
    if snapshot.real_uid != identity.user_id
        || snapshot.effective_uid != identity.user_id
        || snapshot.saved_uid != identity.user_id
        || snapshot.real_gid != identity.group_id
        || snapshot.effective_gid != identity.group_id
        || snapshot.saved_gid != identity.group_id
    {
        return Err(PrivilegeError::IdentityDrift);
    }
    if snapshot.capabilities.effective != 0
        || snapshot.capabilities.permitted != 0
        || snapshot.capabilities.inheritable != 0
        || snapshot.ambient_any
    {
        return Err(PrivilegeError::CapabilityVerificationFailed);
    }
    if !snapshot.no_new_privileges {
        return Err(PrivilegeError::NoNewPrivilegesVerificationFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTACK_CATALOG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/attacks/privilege/lock-v1.toml"
    ));

    fn snapshot() -> IdentitySnapshot {
        IdentitySnapshot {
            real_uid: 1000,
            effective_uid: 1000,
            saved_uid: 1000,
            real_gid: 1000,
            effective_gid: 1000,
            saved_gid: 1000,
            capabilities: CapabilitySnapshot::default(),
            ambient_any: false,
            no_new_privileges: false,
        }
    }

    #[test]
    fn accepts_only_equal_nonroot_identity() {
        assert_eq!(
            require_unprivileged_identity(snapshot()),
            Ok(LockedPrivileges {
                user_id: 1000,
                group_id: 1000
            })
        );
        let mut root = snapshot();
        root.saved_uid = 0;
        assert_eq!(
            require_unprivileged_identity(root),
            Err(PrivilegeError::RootIdentity)
        );
        let mut mismatch = snapshot();
        mismatch.effective_gid = 1001;
        assert_eq!(
            require_unprivileged_identity(mismatch),
            Err(PrivilegeError::IdentityMismatch)
        );
    }

    #[test]
    fn locked_state_requires_zero_capabilities_and_no_new_privileges() {
        let identity = LockedPrivileges {
            user_id: 1000,
            group_id: 1000,
        };
        let mut locked = snapshot();
        locked.no_new_privileges = true;
        assert_eq!(validate_locked(identity, locked), Ok(()));

        locked.capabilities.permitted = 1;
        assert_eq!(
            validate_locked(identity, locked),
            Err(PrivilegeError::CapabilityVerificationFailed)
        );
        locked.capabilities.permitted = 0;
        locked.no_new_privileges = false;
        assert_eq!(
            validate_locked(identity, locked),
            Err(PrivilegeError::NoNewPrivilegesVerificationFailed)
        );
    }

    #[test]
    fn frozen_privilege_attack_catalog_is_closed() {
        let expected_ids = [
            "root-launcher",
            "saved-id-mismatch",
            "ambient-capability-retained",
            "permitted-capability-retained",
            "no-new-privileges-omitted",
            "no-new-privileges-forged",
        ];
        assert!(ATTACK_CATALOG.starts_with("schema = \"proofbound-runtime-privilege-attacks/1\""));
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
            PrivilegeError::UnsupportedOperatingSystem,
            PrivilegeError::InspectionUnavailable,
            PrivilegeError::RootIdentity,
            PrivilegeError::IdentityMismatch,
            PrivilegeError::IdentityDrift,
            PrivilegeError::AmbientClearFailed,
            PrivilegeError::CapabilityDropFailed,
            PrivilegeError::CapabilityVerificationFailed,
            PrivilegeError::NoNewPrivilegesInstallFailed,
            PrivilegeError::NoNewPrivilegesVerificationFailed,
        ];
        let mut codes = errors.map(PrivilegeError::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_lock_is_never_positive_evidence() {
        assert_eq!(
            lock_privileges(),
            Err(PrivilegeError::UnsupportedOperatingSystem)
        );
    }
}
