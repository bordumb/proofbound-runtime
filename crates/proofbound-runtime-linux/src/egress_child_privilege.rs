//! Drops the new user namespace's bounding and active capabilities.

use crate::LockedPrivileges;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressChildPrivilegeError {
    CapabilityInventory,
    BoundingSet,
    PrivilegeLock,
}

pub fn lock_egress_child_privileges() -> Result<LockedPrivileges, EgressChildPrivilegeError> {
    let last_capability = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(|_| EgressChildPrivilegeError::CapabilityInventory)?
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|value| *value < 64)
        .ok_or(EgressChildPrivilegeError::CapabilityInventory)?;
    crate::sys::drop_capability_bounding_set(last_capability)
        .map_err(|_| EgressChildPrivilegeError::BoundingSet)?;
    crate::lock_privileges().map_err(|_| EgressChildPrivilegeError::PrivilegeLock)
}
