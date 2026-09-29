//! Separate paused-launcher entry for the declared-egress child boundary.

use core::num::NonZeroU32;
use std::os::fd::{AsFd as _, AsRawFd as _};

use proofbound_runtime_core::Sha256Digest;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::egress_child_landlock::install_egress_child_landlock;
use crate::egress_child_privilege::lock_egress_child_privileges;
use crate::egress_child_seccomp::{compile_child_seccomp, install_child_seccomp};
use crate::egress_namespace::{
    EgressNamespaceReport, create_egress_namespace, send_namespace_ready,
};
use crate::{
    Architecture, LandlockRule, LauncherChannel, LauncherError, LauncherIdentity, LauncherMessage,
    pause_for_supervisor, receive_install_request, sys,
};

const PROXY_READY_SCHEMA: &str = "proofbound-runtime-egress-proxy-ready/1";
const BOUNDARY_SCHEMA: &str = "proofbound-runtime-egress-boundary-installed/1";
const MAX_PACKET: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProxyReady {
    generation: u64,
    binding: Sha256Digest,
}

fn receive_proxy_ready(
    channel: i32,
    identity: LauncherIdentity,
    namespace: &EgressNamespaceReport,
) -> Result<ProxyReady, LauncherError> {
    let mut buffer = vec![0_u8; MAX_PACKET + 1];
    let length =
        sys::receive_packet(channel, &mut buffer).map_err(|_| LauncherError::ChannelReadFailed)?;
    if length == 0 || length > MAX_PACKET {
        return Err(LauncherError::Malformed);
    }
    let value: Value =
        serde_json::from_slice(&buffer[..length]).map_err(|_| LauncherError::Malformed)?;
    let object = value.as_object().ok_or(LauncherError::Malformed)?;
    if object.len() != 9
        || object.get("schema").and_then(Value::as_str) != Some(PROXY_READY_SCHEMA)
        || object.get("execution_id").and_then(Value::as_str)
            != Some(hex(identity.execution_id().as_bytes()).as_str())
        || object.get("policy_sha256").and_then(Value::as_str)
            != Some(identity.policy_id().to_hex().as_str())
        || object.get("cgroup_mount_id").and_then(Value::as_u64)
            != Some(identity.cgroup_id().mount_id())
        || object.get("cgroup_inode").and_then(Value::as_u64) != Some(identity.cgroup_id().inode())
        || object.get("child_netns_device").and_then(Value::as_u64)
            != Some(namespace.network_namespace.device)
        || object.get("child_netns_inode").and_then(Value::as_u64)
            != Some(namespace.network_namespace.inode)
    {
        return Err(LauncherError::PolicyIdentityMismatch);
    }
    let generation = object
        .get("generation")
        .and_then(Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or(LauncherError::Malformed)?;
    let binding = object
        .get("readiness_binding")
        .and_then(Value::as_str)
        .and_then(|value| Sha256Digest::parse_hex(value).ok())
        .ok_or(LauncherError::Malformed)?;
    Ok(ProxyReady {
        generation,
        binding,
    })
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

fn installed_packet(
    identity: LauncherIdentity,
    namespace: &EgressNamespaceReport,
    proxy: ProxyReady,
    landlock: crate::egress_child_landlock::EgressChildLandlock,
    filter: &[u8],
) -> Vec<u8> {
    let routes = namespace
        .routes
        .iter()
        .map(|route| {
            json!({"family": route.family, "destination": route.destination,
                "prefix_length": route.prefix_length, "interface": route.interface})
        })
        .collect::<Vec<_>>();
    let filter_digest = Sha256Digest::from_bytes(Sha256::digest(filter).into());
    serde_json::to_vec(&json!({
        "schema": BOUNDARY_SCHEMA,
        "execution_id": hex(identity.execution_id().as_bytes()),
        "policy_sha256": identity.policy_id().to_hex(),
        "cgroup_mount_id": identity.cgroup_id().mount_id(),
        "cgroup_inode": identity.cgroup_id().inode(),
        "user_namespace": {"device": namespace.user_namespace.device, "inode": namespace.user_namespace.inode},
        "network_namespace": {"device": namespace.network_namespace.device, "inode": namespace.network_namespace.inode},
        "uid_map": {"inside": namespace.uid_map.inside, "outside": namespace.uid_map.outside, "length": namespace.uid_map.length},
        "gid_map": {"inside": namespace.gid_map.inside, "outside": namespace.gid_map.outside, "length": namespace.gid_map.length},
        "interfaces": namespace.interfaces,
        "routes": routes,
        "listener": {"address": [127, 0, 0, 1], "port": 3128, "backlog": 128},
        "proxy_generation": proxy.generation,
        "proxy_readiness_binding": proxy.binding.to_hex(),
        "landlock_abi": landlock.abi,
        "landlock_handled_filesystem": landlock.handled_filesystem,
        "landlock_handled_network": landlock.handled_network,
        "landlock_scoped": landlock.scoped,
        "child_filter_sha256": filter_digest.to_hex(),
    }))
    .expect("fixed JSON fields are serializable")
}

/// Runs the egress launcher. The supervisor must validate the transferred
/// listener and proxy readiness before sending `proxy-ready`.
pub fn run_egress_launcher(
    channel: &LauncherChannel,
    identity: LauncherIdentity,
    architecture: Architecture,
    landlock_abi: NonZeroU32,
) -> Result<(), LauncherError> {
    pause_for_supervisor()?;
    let prepared = receive_install_request(channel, identity)?;
    let request = prepared.request();
    let expected_filter = compile_child_seccomp(architecture)
        .map_err(|_| LauncherError::SeccompInstallationFailed)?;
    if request.seccomp_program() != expected_filter {
        return Err(LauncherError::SeccompProgramMismatch);
    }
    crate::revalidate_inherited_executable(request.executable_fd(), request.executable_id())
        .map_err(|_| LauncherError::ExecutableIdentityMismatch)?;
    let arguments = request
        .arguments()
        .iter()
        .map(|argument| std::ffi::CString::new(argument.as_str()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| LauncherError::Malformed)?;
    let environment = request
        .environment()
        .iter()
        .map(|(key, value)| std::ffi::CString::new(format!("{key}={value}")))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| LauncherError::Malformed)?;
    let channel_fd = channel.as_fd().as_raw_fd();
    let ready =
        create_egress_namespace().map_err(|_| LauncherError::PrivilegeInstallationFailed)?;
    let namespace = EgressNamespaceReport {
        user_namespace: ready.user_namespace,
        network_namespace: ready.network_namespace,
        uid_map: ready.uid_map,
        gid_map: ready.gid_map,
        interfaces: ready.interfaces.clone(),
        routes: ready.routes.clone(),
    };
    send_namespace_ready(channel_fd, ready).map_err(|_| LauncherError::ChannelWriteFailed)?;
    let proxy = receive_proxy_ready(channel_fd, identity, &namespace)?;

    for descriptor in core::iter::once(request.executable_fd())
        .chain(core::iter::once(request.working_directory_fd()))
        .chain(request.filesystem().iter().map(|rule| rule.descriptor()))
    {
        sys::set_descriptor_close_on_exec(descriptor as i32)
            .map_err(|_| LauncherError::FileDescriptorInvalid)?;
    }
    let retained = core::iter::once(request.executable_fd() as i32)
        .chain(core::iter::once(request.working_directory_fd() as i32))
        .chain(
            request
                .filesystem()
                .iter()
                .map(|rule| rule.descriptor() as i32),
        )
        .chain(core::iter::once(channel_fd))
        .collect::<Vec<_>>();
    sys::close_descriptors_except(&retained).map_err(|_| LauncherError::FileDescriptorInvalid)?;
    let privileges =
        lock_egress_child_privileges().map_err(|_| LauncherError::PrivilegeInstallationFailed)?;
    let duplicated = request
        .filesystem()
        .iter()
        .map(|rule| {
            Ok((
                sys::duplicate_descriptor(rule.descriptor() as i32)
                    .map_err(|_| LauncherError::FileDescriptorInvalid)?,
                rule.access().to_vec(),
            ))
        })
        .collect::<Result<Vec<_>, LauncherError>>()?;
    let mut rules = Vec::new();
    for (descriptor, access) in &duplicated {
        for access in access {
            rules.push(LandlockRule::new(descriptor.as_fd(), *access));
        }
    }
    let landlock = install_egress_child_landlock(landlock_abi, &privileges, &rules)
        .map_err(|_| LauncherError::LandlockInstallationFailed)?;
    drop(rules);
    drop(duplicated);
    let installed_filter = install_child_seccomp(architecture)
        .map_err(|_| LauncherError::SeccompInstallationFailed)?;
    if installed_filter != expected_filter {
        return Err(LauncherError::SeccompProgramMismatch);
    }
    let acknowledgement =
        installed_packet(identity, &namespace, proxy, landlock, &installed_filter);
    sys::send_packet(channel_fd, &acknowledgement)
        .map_err(|_| LauncherError::ChannelWriteFailed)?;
    let LauncherMessage::ExecRelease(release) = channel.receive()? else {
        return Err(LauncherError::UnexpectedMessage);
    };
    if release.identity() != identity {
        return Err(LauncherError::ExecutionIdentityMismatch);
    }
    crate::revalidate_inherited_executable(request.executable_fd(), request.executable_id())
        .map_err(|_| LauncherError::ExecutableIdentityMismatch)?;
    sys::change_directory(request.working_directory_fd() as i32)
        .map_err(|_| LauncherError::WorkingDirectoryFailed)?;
    sys::execveat(request.executable_fd() as i32, &arguments, &environment)
        .map_err(|_| LauncherError::ExecFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress_namespace::{IdentityMap, NamespaceIdentity};
    use proofbound_runtime_core::{CgroupIdentity, ExecutionId};

    #[test]
    fn proxy_ready_must_bind_current_child_namespace() {
        let (sender, receiver) = sys::private_socket_pair().unwrap();
        let execution =
            ExecutionId::from_bytes([1, 1, 1, 1, 1, 1, 0x41, 1, 0x81, 1, 1, 1, 1, 1, 1, 1])
                .unwrap();
        let identity = LauncherIdentity::new(
            execution,
            Sha256Digest::from_bytes([2; 32]),
            CgroupIdentity::new(3, 4),
        );
        let namespace = EgressNamespaceReport {
            user_namespace: NamespaceIdentity {
                device: 5,
                inode: 6,
            },
            network_namespace: NamespaceIdentity {
                device: 7,
                inode: 8,
            },
            uid_map: IdentityMap {
                inside: 1000,
                outside: 1000,
                length: 1,
            },
            gid_map: IdentityMap {
                inside: 1000,
                outside: 1000,
                length: 1,
            },
            interfaces: vec!["lo".to_owned()],
            routes: Vec::new(),
        };
        let mut packet = json!({
            "schema": PROXY_READY_SCHEMA,
            "execution_id": hex(execution.as_bytes()),
            "policy_sha256": identity.policy_id().to_hex(),
            "cgroup_mount_id": 3,
            "cgroup_inode": 4,
            "child_netns_device": 7,
            "child_netns_inode": 9,
            "generation": 1,
            "readiness_binding": Sha256Digest::from_bytes([10; 32]).to_hex(),
        });
        let send = |packet: &Value| {
            sys::send_packet(sender.as_raw_fd(), &serde_json::to_vec(packet).unwrap()).unwrap();
        };
        send(&packet);
        assert_eq!(
            receive_proxy_ready(receiver.as_raw_fd(), identity, &namespace),
            Err(LauncherError::PolicyIdentityMismatch)
        );
        packet["child_netns_inode"] = json!(8);
        send(&packet);
        assert_eq!(
            receive_proxy_ready(receiver.as_raw_fd(), identity, &namespace)
                .unwrap()
                .generation,
            1
        );
    }
}
