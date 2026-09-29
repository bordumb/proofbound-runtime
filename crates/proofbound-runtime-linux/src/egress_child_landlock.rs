//! Landlock filesystem, network, and scope rules for the egress child.

use core::num::NonZeroU32;
use std::os::fd::AsRawFd as _;

use crate::landlock::{
    ACCESS_RESOLVE_UNIX, allowed_access, descriptor_is_directory, handled_access,
};
use crate::{LandlockAccess, LandlockRule, LockedPrivileges};

const NET_BIND_TCP: u64 = 1 << 0;
const NET_CONNECT_TCP: u64 = 1 << 1;
const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;
const PROXY_PORT: u16 = 3128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressChildLandlockError {
    Abi,
    Rule,
    Restrict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressChildLandlock {
    pub abi: u32,
    pub handled_filesystem: u64,
    pub handled_network: u64,
    pub scoped: u64,
    pub path_rule_count: usize,
    pub proxy_port: u16,
}

pub fn install_egress_child_landlock(
    abi: NonZeroU32,
    _locked: &LockedPrivileges,
    rules: &[LandlockRule<'_>],
) -> Result<EgressChildLandlock, EgressChildLandlockError> {
    if !(9..=11).contains(&abi.get()) || rules.is_empty() {
        return Err(EgressChildLandlockError::Abi);
    }
    let observed_abi = crate::sys::landlock_abi().map_err(|_| EgressChildLandlockError::Abi)?;
    if observed_abi != abi.get() {
        return Err(EgressChildLandlockError::Abi);
    }
    let handled_filesystem = handled_access(abi);
    let handled_network = NET_BIND_TCP | NET_CONNECT_TCP;
    let scoped = SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL;
    let ruleset =
        crate::sys::create_egress_landlock_ruleset(handled_filesystem, handled_network, scoped)
            .map_err(|_| EgressChildLandlockError::Rule)?;
    for rule in rules {
        let directory = descriptor_is_directory(rule.descriptor())
            .map_err(|_| EgressChildLandlockError::Rule)?;
        let mut access =
            allowed_access(rule.access(), directory).map_err(|_| EgressChildLandlockError::Rule)?;
        if directory && rule.access() == LandlockAccess::Write {
            access |= ACCESS_RESOLVE_UNIX;
        }
        crate::sys::add_landlock_path_rule(
            ruleset.as_raw_fd(),
            rule.descriptor().as_raw_fd(),
            access,
        )
        .map_err(|_| EgressChildLandlockError::Rule)?;
    }
    crate::sys::add_landlock_net_port_rule(ruleset.as_raw_fd(), PROXY_PORT, NET_CONNECT_TCP)
        .map_err(|_| EgressChildLandlockError::Rule)?;
    crate::sys::restrict_with_landlock(ruleset.as_raw_fd())
        .map_err(|_| EgressChildLandlockError::Restrict)?;
    Ok(EgressChildLandlock {
        abi: abi.get(),
        handled_filesystem,
        handled_network,
        scoped,
        path_rule_count: rules.len(),
        proxy_port: PROXY_PORT,
    })
}
