//! Irreversible proxy boundary installed before readiness is reported.

use std::fs::File;
use std::os::fd::{AsRawFd as _, BorrowedFd};

use proofbound_runtime_core::Sha256Digest;
use sha2::{Digest as _, Sha256};

use crate::{Architecture, egress_seccomp};

const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_HANDLED_ABI_9: u64 = (1 << 17) - 1;
const NET_BIND_TCP: u64 = 1 << 0;
const NET_CONNECT_TCP: u64 = 1 << 1;
const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyConfinementError {
    LandlockAbi,
    ReadDescriptor,
    Landlock,
    Dumpability,
    Privileges,
    Seccomp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyConfinement {
    pub landlock_abi: u32,
    pub handled_filesystem: u64,
    pub handled_network: u64,
    pub scoped: u64,
    pub filter_sha256: Sha256Digest,
}

/// Applies filesystem, network-port and process-domain Landlock restrictions,
/// then the closed socket and process seccomp filter. Every referenced runtime
/// object must already be opened and identified by the supervisor.
pub fn install_proxy_confinement(
    architecture: Architecture,
    read_only: &[BorrowedFd<'_>],
    declared_connect_ports: &[u16],
) -> Result<ProxyConfinement, ProxyConfinementError> {
    if read_only.is_empty()
        || declared_connect_ports.is_empty()
        || declared_connect_ports.contains(&0)
    {
        return Err(ProxyConfinementError::ReadDescriptor);
    }
    let abi = crate::sys::landlock_abi().map_err(|_| ProxyConfinementError::LandlockAbi)?;
    if !(9..=11).contains(&abi) {
        return Err(ProxyConfinementError::LandlockAbi);
    }
    let mut ports = declared_connect_ports.to_vec();
    ports.sort_unstable();
    ports.dedup();
    crate::sys::disable_dumpability().map_err(|_| ProxyConfinementError::Dumpability)?;
    crate::lock_privileges().map_err(|_| ProxyConfinementError::Privileges)?;
    let handled_network = NET_BIND_TCP | NET_CONNECT_TCP;
    let scoped = SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL;
    let ruleset =
        crate::sys::create_egress_landlock_ruleset(FS_HANDLED_ABI_9, handled_network, scoped)
            .map_err(|_| ProxyConfinementError::Landlock)?;
    for descriptor in read_only {
        let file = File::from(
            descriptor
                .try_clone_to_owned()
                .map_err(|_| ProxyConfinementError::ReadDescriptor)?,
        );
        let metadata = file
            .metadata()
            .map_err(|_| ProxyConfinementError::ReadDescriptor)?;
        let allowed = if metadata.is_dir() {
            FS_READ_FILE | FS_READ_DIR
        } else if metadata.is_file() {
            FS_READ_FILE
        } else {
            return Err(ProxyConfinementError::ReadDescriptor);
        };
        crate::sys::add_landlock_path_rule(ruleset.as_raw_fd(), descriptor.as_raw_fd(), allowed)
            .map_err(|_| ProxyConfinementError::Landlock)?;
    }
    for port in ports {
        crate::sys::add_landlock_net_port_rule(ruleset.as_raw_fd(), port, NET_CONNECT_TCP)
            .map_err(|_| ProxyConfinementError::Landlock)?;
    }
    crate::sys::restrict_with_landlock(ruleset.as_raw_fd())
        .map_err(|_| ProxyConfinementError::Landlock)?;
    let filter = egress_seccomp::install_proxy_seccomp(architecture)
        .map_err(|_| ProxyConfinementError::Seccomp)?;
    Ok(ProxyConfinement {
        landlock_abi: abi,
        handled_filesystem: FS_HANDLED_ABI_9,
        handled_network,
        scoped,
        filter_sha256: Sha256Digest::from_bytes(Sha256::digest(filter).into()),
    })
}
