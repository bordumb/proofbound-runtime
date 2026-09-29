//! Fresh user and loopback-only network namespace for an egress child.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use serde_json::{Value, json};

use crate::sys;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressNamespaceError {
    Identity,
    NamespaceCreate,
    IdentityMap,
    Loopback,
    InterfaceInventory,
    RouteInventory,
    Listener,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityMap {
    pub inside: u32,
    pub outside: u32,
    pub length: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteObservation {
    pub family: &'static str,
    pub destination: Vec<u8>,
    pub prefix_length: u8,
    pub interface: String,
}

#[derive(Debug)]
pub struct EgressNamespaceReady {
    pub user_namespace: NamespaceIdentity,
    pub network_namespace: NamespaceIdentity,
    pub uid_map: IdentityMap,
    pub gid_map: IdentityMap,
    pub interfaces: Vec<String>,
    pub routes: Vec<RouteObservation>,
    pub listener: TcpListener,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressNamespaceReport {
    pub user_namespace: NamespaceIdentity,
    pub network_namespace: NamespaceIdentity,
    pub uid_map: IdentityMap,
    pub gid_map: IdentityMap,
    pub interfaces: Vec<String>,
    pub routes: Vec<RouteObservation>,
}

pub fn send_namespace_ready(
    channel: i32,
    ready: EgressNamespaceReady,
) -> Result<(), EgressNamespaceError> {
    let routes = ready
        .routes
        .iter()
        .map(|route| {
            json!({
                "family": route.family,
                "destination": route.destination,
                "prefix_length": route.prefix_length,
                "interface": route.interface,
            })
        })
        .collect::<Vec<_>>();
    let message = json!({
        "schema": "proofbound-runtime-egress-namespace-ready/1",
        "user_namespace": {"device": ready.user_namespace.device, "inode": ready.user_namespace.inode},
        "network_namespace": {"device": ready.network_namespace.device, "inode": ready.network_namespace.inode},
        "uid_map": {"inside": ready.uid_map.inside, "outside": ready.uid_map.outside, "length": 1},
        "gid_map": {"inside": ready.gid_map.inside, "outside": ready.gid_map.outside, "length": 1},
        "interfaces": ready.interfaces,
        "routes": routes,
        "listener": {"address": [127, 0, 0, 1], "port": 3128, "backlog": 128},
    });
    let bytes = serde_json::to_vec(&message).map_err(|_| EgressNamespaceError::Listener)?;
    if bytes.len() > 65_536 {
        return Err(EgressNamespaceError::Listener);
    }
    sys::send_packet_with_descriptor(channel, &bytes, ready.listener.as_raw_fd())
        .map_err(|_| EgressNamespaceError::Listener)
}

/// Validates a transferred listener against the launcher's kernel namespace
/// identity and the supervisor's separate namespace.
pub fn receive_namespace_ready(
    channel: i32,
    launcher_pid: u32,
) -> Result<(EgressNamespaceReport, TcpListener), EgressNamespaceError> {
    let mut bytes = vec![0_u8; 65_537];
    let (length, descriptor) = sys::receive_packet_with_descriptor(channel, &mut bytes)
        .map_err(|_| EgressNamespaceError::Listener)?;
    if length > 65_536 || length == 0 {
        return Err(EgressNamespaceError::Listener);
    }
    let value: Value =
        serde_json::from_slice(&bytes[..length]).map_err(|_| EgressNamespaceError::Listener)?;
    let map = value.as_object().ok_or(EgressNamespaceError::Listener)?;
    if map.len() != 8
        || map.get("schema").and_then(Value::as_str)
            != Some("proofbound-runtime-egress-namespace-ready/1")
    {
        return Err(EgressNamespaceError::Listener);
    }
    let identity = |field: &str| -> Result<NamespaceIdentity, EgressNamespaceError> {
        let value = map
            .get(field)
            .and_then(Value::as_object)
            .ok_or(EgressNamespaceError::Identity)?;
        if value.len() != 2 {
            return Err(EgressNamespaceError::Identity);
        }
        Ok(NamespaceIdentity {
            device: value
                .get("device")
                .and_then(Value::as_u64)
                .ok_or(EgressNamespaceError::Identity)?,
            inode: value
                .get("inode")
                .and_then(Value::as_u64)
                .ok_or(EgressNamespaceError::Identity)?,
        })
    };
    let mapping = |field: &str| -> Result<IdentityMap, EgressNamespaceError> {
        let value = map
            .get(field)
            .and_then(Value::as_object)
            .ok_or(EgressNamespaceError::IdentityMap)?;
        if value.len() != 3 {
            return Err(EgressNamespaceError::IdentityMap);
        }
        let part = |name: &str| -> Result<u32, EgressNamespaceError> {
            value
                .get(name)
                .and_then(Value::as_u64)
                .and_then(|item| u32::try_from(item).ok())
                .ok_or(EgressNamespaceError::IdentityMap)
        };
        Ok(IdentityMap {
            inside: part("inside")?,
            outside: part("outside")?,
            length: part("length")?,
        })
    };
    let user_namespace = identity("user_namespace")?;
    let network_namespace = identity("network_namespace")?;
    let uid_map = mapping("uid_map")?;
    let gid_map = mapping("gid_map")?;
    if uid_map.inside == 0
        || gid_map.inside == 0
        || uid_map.inside != uid_map.outside
        || gid_map.inside != gid_map.outside
        || uid_map.length != 1
        || gid_map.length != 1
    {
        return Err(EgressNamespaceError::IdentityMap);
    }
    let interfaces = map
        .get("interfaces")
        .and_then(Value::as_array)
        .ok_or(EgressNamespaceError::InterfaceInventory)?;
    if interfaces.as_slice() != [Value::String("lo".to_owned())] {
        return Err(EgressNamespaceError::InterfaceInventory);
    }
    let routes = map
        .get("routes")
        .and_then(Value::as_array)
        .ok_or(EgressNamespaceError::RouteInventory)?;
    let routes = routes
        .iter()
        .map(|route| {
            let route = route
                .as_object()
                .ok_or(EgressNamespaceError::RouteInventory)?;
            if route.len() != 4 {
                return Err(EgressNamespaceError::RouteInventory);
            }
            let family = route
                .get("family")
                .and_then(Value::as_str)
                .ok_or(EgressNamespaceError::RouteInventory)?;
            let destination = route
                .get("destination")
                .and_then(Value::as_array)
                .ok_or(EgressNamespaceError::RouteInventory)?
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .and_then(|byte| u8::try_from(byte).ok())
                        .ok_or(EgressNamespaceError::RouteInventory)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let prefix_length = route
                .get("prefix_length")
                .and_then(Value::as_u64)
                .and_then(|value| u8::try_from(value).ok())
                .ok_or(EgressNamespaceError::RouteInventory)?;
            let interface = route
                .get("interface")
                .and_then(Value::as_str)
                .ok_or(EgressNamespaceError::RouteInventory)?;
            let valid = match family {
                "ipv4" => {
                    destination.len() == 4
                        && destination[0] == 127
                        && (8..=32).contains(&prefix_length)
                }
                "ipv6" => {
                    destination.as_slice() == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                        && prefix_length == 128
                }
                _ => false,
            };
            if !valid || interface != "lo" {
                return Err(EgressNamespaceError::RouteInventory);
            }
            Ok(RouteObservation {
                family: if family == "ipv4" { "ipv4" } else { "ipv6" },
                destination,
                prefix_length,
                interface: "lo".to_owned(),
            })
        })
        .collect::<Result<Vec<_>, EgressNamespaceError>>()?;
    let listener_record = map
        .get("listener")
        .and_then(Value::as_object)
        .ok_or(EgressNamespaceError::Listener)?;
    if listener_record.len() != 3
        || listener_record.get("address") != Some(&json!([127, 0, 0, 1]))
        || listener_record.get("port") != Some(&json!(3128))
        || listener_record.get("backlog") != Some(&json!(128))
    {
        return Err(EgressNamespaceError::Listener);
    }
    let (supervisor_user, supervisor_network) = current_namespaces()?;
    if user_namespace == supervisor_user || network_namespace == supervisor_network {
        return Err(EgressNamespaceError::Identity);
    }
    let launcher_user = fs::metadata(format!("/proc/{launcher_pid}/ns/user"))
        .map_err(|_| EgressNamespaceError::Identity)?;
    let launcher_network = fs::metadata(format!("/proc/{launcher_pid}/ns/net"))
        .map_err(|_| EgressNamespaceError::Identity)?;
    if (launcher_user.dev(), launcher_user.ino()) != (user_namespace.device, user_namespace.inode)
        || (launcher_network.dev(), launcher_network.ino())
            != (network_namespace.device, network_namespace.inode)
    {
        return Err(EgressNamespaceError::Identity);
    }
    if fs::read_to_string(format!("/proc/{launcher_pid}/setgroups"))
        .map_err(|_| EgressNamespaceError::IdentityMap)?
        .trim()
        != "deny"
        || process_identity_map(launcher_pid, "uid_map")? != uid_map
        || process_identity_map(launcher_pid, "gid_map")? != gid_map
    {
        return Err(EgressNamespaceError::IdentityMap);
    }
    let device_inventory = fs::read_to_string(format!("/proc/{launcher_pid}/net/dev"))
        .map_err(|_| EgressNamespaceError::InterfaceInventory)?;
    if interface_names_from_net_dev(&device_inventory)? != ["lo"] {
        return Err(EgressNamespaceError::InterfaceInventory);
    }
    let route_inventory = process_routes(launcher_pid)?;
    if route_inventory != routes {
        return Err(EgressNamespaceError::RouteInventory);
    }
    let listener = TcpListener::from(descriptor);
    if sys::socket_type(listener.as_raw_fd()).map_err(|_| EgressNamespaceError::Listener)?
        != libc::SOCK_STREAM
        || !sys::socket_accepting(listener.as_raw_fd())
            .map_err(|_| EgressNamespaceError::Listener)?
        || listener
            .local_addr()
            .map_err(|_| EgressNamespaceError::Listener)?
            != SocketAddr::from((Ipv4Addr::LOCALHOST, 3128))
    {
        return Err(EgressNamespaceError::Listener);
    }
    let socket_namespace = sys::socket_network_namespace(listener.as_raw_fd())
        .map_err(|_| EgressNamespaceError::Listener)?;
    let socket_metadata = fs::metadata(format!("/proc/self/fd/{}", socket_namespace.as_raw_fd()))
        .map_err(|_| EgressNamespaceError::Listener)?;
    if (socket_metadata.dev(), socket_metadata.ino())
        != (network_namespace.device, network_namespace.inode)
    {
        return Err(EgressNamespaceError::Listener);
    }
    Ok((
        EgressNamespaceReport {
            user_namespace,
            network_namespace,
            uid_map,
            gid_map,
            interfaces: vec!["lo".to_owned()],
            routes,
        },
        listener,
    ))
}

fn process_identity_map(pid: u32, name: &str) -> Result<IdentityMap, EgressNamespaceError> {
    let source = fs::read_to_string(format!("/proc/{pid}/{name}"))
        .map_err(|_| EgressNamespaceError::IdentityMap)?;
    let fields = source.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 3 {
        return Err(EgressNamespaceError::IdentityMap);
    }
    Ok(IdentityMap {
        inside: fields[0]
            .parse()
            .map_err(|_| EgressNamespaceError::IdentityMap)?,
        outside: fields[1]
            .parse()
            .map_err(|_| EgressNamespaceError::IdentityMap)?,
        length: fields[2]
            .parse()
            .map_err(|_| EgressNamespaceError::IdentityMap)?,
    })
}

fn interface_names_from_net_dev(source: &str) -> Result<Vec<String>, EgressNamespaceError> {
    let mut lines = source.lines();
    if !lines.next().is_some_and(|line| line.contains("Inter-|"))
        || !lines.next().is_some_and(|line| line.contains("face |"))
    {
        return Err(EgressNamespaceError::InterfaceInventory);
    }
    let mut names = lines
        .map(|line| {
            line.split_once(':')
                .map(|(name, _)| name.trim().to_owned())
                .ok_or(EgressNamespaceError::InterfaceInventory)
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort_unstable();
    Ok(names)
}

fn process_routes(pid: u32) -> Result<Vec<RouteObservation>, EgressNamespaceError> {
    let mut routes = ipv4_routes(
        &fs::read_to_string(format!("/proc/{pid}/net/route"))
            .map_err(|_| EgressNamespaceError::RouteInventory)?,
    )?;
    routes.extend(ipv6_routes(
        &fs::read_to_string(format!("/proc/{pid}/net/ipv6_route"))
            .map_err(|_| EgressNamespaceError::RouteInventory)?,
    )?);
    routes.sort_unstable_by(|left, right| {
        (left.family, &left.destination, left.prefix_length).cmp(&(
            right.family,
            &right.destination,
            right.prefix_length,
        ))
    });
    Ok(routes)
}

fn namespace_identity(path: &str) -> Result<NamespaceIdentity, EgressNamespaceError> {
    let metadata = fs::metadata(path).map_err(|_| EgressNamespaceError::Identity)?;
    Ok(NamespaceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

pub fn current_namespaces() -> Result<(NamespaceIdentity, NamespaceIdentity), EgressNamespaceError>
{
    Ok((
        namespace_identity("/proc/self/ns/user")?,
        namespace_identity("/proc/self/ns/net")?,
    ))
}

fn identity_maps(uid: u32, gid: u32) -> Result<(IdentityMap, IdentityMap), EgressNamespaceError> {
    if uid == 0 || gid == 0 {
        return Err(EgressNamespaceError::Identity);
    }
    fs::write("/proc/self/setgroups", "deny\n").map_err(|_| EgressNamespaceError::IdentityMap)?;
    fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n"))
        .map_err(|_| EgressNamespaceError::IdentityMap)?;
    fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n"))
        .map_err(|_| EgressNamespaceError::IdentityMap)?;
    let map = |path: &str, expected: u32| -> Result<IdentityMap, EgressNamespaceError> {
        let bytes = fs::read_to_string(path).map_err(|_| EgressNamespaceError::IdentityMap)?;
        let mut fields = bytes.split_whitespace();
        let parse = |field: Option<&str>| {
            field
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or(EgressNamespaceError::IdentityMap)
        };
        let observed = IdentityMap {
            inside: parse(fields.next())?,
            outside: parse(fields.next())?,
            length: parse(fields.next())?,
        };
        if fields.next().is_some()
            || observed
                != (IdentityMap {
                    inside: expected,
                    outside: expected,
                    length: 1,
                })
        {
            return Err(EgressNamespaceError::IdentityMap);
        }
        Ok(observed)
    };
    Ok((
        map("/proc/self/uid_map", uid)?,
        map("/proc/self/gid_map", gid)?,
    ))
}

fn interfaces() -> Result<Vec<String>, EgressNamespaceError> {
    // The proc view is keyed to this process's network namespace. A sysfs
    // mount inherited across unshare can still expose the parent inventory.
    let names = interface_names_from_net_dev(
        &fs::read_to_string("/proc/net/dev")
            .map_err(|_| EgressNamespaceError::InterfaceInventory)?,
    )?;
    if names != ["lo"] {
        return Err(EgressNamespaceError::InterfaceInventory);
    }
    Ok(names)
}

fn decode_ipv4_route(value: &str) -> Result<[u8; 4], EgressNamespaceError> {
    if value.len() != 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EgressNamespaceError::RouteInventory);
    }
    let number =
        u32::from_str_radix(value, 16).map_err(|_| EgressNamespaceError::RouteInventory)?;
    Ok(number.to_le_bytes())
}

fn ipv4_routes(source: &str) -> Result<Vec<RouteObservation>, EgressNamespaceError> {
    let mut lines = source.lines();
    if !lines
        .next()
        .is_some_and(|header| header.starts_with("Iface\tDestination\tGateway"))
    {
        return Err(EgressNamespaceError::RouteInventory);
    }
    let mut routes = Vec::new();
    for line in lines {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 8 || parts[0] != "lo" {
            return Err(EgressNamespaceError::RouteInventory);
        }
        let destination = decode_ipv4_route(parts[1])?;
        let gateway = decode_ipv4_route(parts[2])?;
        let mask = decode_ipv4_route(parts[7])?;
        let prefix = u32::from_be_bytes(mask).leading_ones() as u8;
        if destination[0] != 127
            || gateway != [0; 4]
            || prefix < 8
            || u32::from_be_bytes(mask).trailing_zeros() != 32 - u32::from(prefix)
        {
            return Err(EgressNamespaceError::RouteInventory);
        }
        routes.push(RouteObservation {
            family: "ipv4",
            destination: destination.to_vec(),
            prefix_length: prefix,
            interface: "lo".to_owned(),
        });
    }
    Ok(routes)
}

fn ipv6_routes(source: &str) -> Result<Vec<RouteObservation>, EgressNamespaceError> {
    let mut routes = Vec::new();
    for line in source.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 10 || parts[9] != "lo" || parts[0].len() != 32 {
            return Err(EgressNamespaceError::RouteInventory);
        }
        let mut destination = [0_u8; 16];
        for (index, byte) in destination.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&parts[0][index * 2..index * 2 + 2], 16)
                .map_err(|_| EgressNamespaceError::RouteInventory)?;
        }
        let prefix =
            u8::from_str_radix(parts[1], 16).map_err(|_| EgressNamespaceError::RouteInventory)?;
        let flags =
            u32::from_str_radix(parts[8], 16).map_err(|_| EgressNamespaceError::RouteInventory)?;
        if destination == [0; 16] && prefix == 0 && flags & 0x200 != 0 {
            // Linux emits unreachable ::/0 entries on `lo`; they provide no
            // routed path and do not belong in the positive route inventory.
            continue;
        }
        // The fixed namespace may contain only the ::1 host route.
        if destination != [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
            || prefix != 128
            || flags & 0x200 != 0
            || parts[4] != "00000000000000000000000000000000"
        {
            return Err(EgressNamespaceError::RouteInventory);
        }
        routes.push(RouteObservation {
            family: "ipv6",
            destination: destination.to_vec(),
            prefix_length: prefix,
            interface: "lo".to_owned(),
        });
    }
    Ok(routes)
}

fn routes() -> Result<Vec<RouteObservation>, EgressNamespaceError> {
    let mut routes = ipv4_routes(
        &fs::read_to_string("/proc/net/route").map_err(|_| EgressNamespaceError::RouteInventory)?,
    )?;
    routes.extend(ipv6_routes(
        &fs::read_to_string("/proc/net/ipv6_route")
            .map_err(|_| EgressNamespaceError::RouteInventory)?,
    )?);
    routes.sort_unstable_by(|left, right| {
        (left.family, &left.destination, left.prefix_length).cmp(&(
            right.family,
            &right.destination,
            right.prefix_length,
        ))
    });
    Ok(routes)
}

/// Runs only in the paused launcher, before privilege and file boundaries.
pub fn create_egress_namespace() -> Result<EgressNamespaceReady, EgressNamespaceError> {
    let (real_uid, effective_uid, saved_uid, real_gid, effective_gid, saved_gid) =
        sys::process_ids().map_err(|_| EgressNamespaceError::Identity)?;
    if real_uid == 0
        || real_gid == 0
        || real_uid != effective_uid
        || real_uid != saved_uid
        || real_gid != effective_gid
        || real_gid != saved_gid
    {
        return Err(EgressNamespaceError::Identity);
    }
    let (previous_user, previous_network) = current_namespaces()?;
    sys::unshare_egress_namespaces().map_err(|_| EgressNamespaceError::NamespaceCreate)?;
    let (uid_map, gid_map) = identity_maps(real_uid, real_gid)?;
    sys::bring_loopback_up().map_err(|_| EgressNamespaceError::Loopback)?;
    let interfaces = interfaces()?;
    let routes = routes()?;
    let (user_namespace, network_namespace) = current_namespaces()?;
    if user_namespace == previous_user || network_namespace == previous_network {
        return Err(EgressNamespaceError::NamespaceCreate);
    }
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 3128)))
        .map_err(|_| EgressNamespaceError::Listener)?;
    sys::set_listener_backlog(listener.as_raw_fd(), 128)
        .map_err(|_| EgressNamespaceError::Listener)?;
    if listener
        .local_addr()
        .map_err(|_| EgressNamespaceError::Listener)?
        != SocketAddr::from((Ipv4Addr::LOCALHOST, 3128))
    {
        return Err(EgressNamespaceError::Listener);
    }
    let socket_namespace = sys::socket_network_namespace(listener.as_raw_fd())
        .map_err(|_| EgressNamespaceError::Listener)?;
    let metadata = fs::metadata(Path::new(&format!(
        "/proc/self/fd/{}",
        socket_namespace.as_raw_fd()
    )))
    .map_err(|_| EgressNamespaceError::Listener)?;
    if (metadata.dev(), metadata.ino()) != (network_namespace.device, network_namespace.inode) {
        return Err(EgressNamespaceError::Listener);
    }
    Ok(EgressNamespaceReady {
        user_namespace,
        network_namespace,
        uid_map,
        gid_map,
        interfaces,
        routes,
        listener,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_parsers_reject_non_loopback_paths() {
        let header =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n";
        assert!(ipv4_routes(header).unwrap().is_empty());
        assert!(
            ipv4_routes(&format!(
                "{header}eth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
            ))
            .is_err()
        );
        assert!(ipv6_routes("00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 eth0\n").is_err());
        let local = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 80200001 lo\n";
        assert_eq!(ipv6_routes(local).unwrap().len(), 1);
    }

    #[test]
    fn supervisor_inventory_rejects_a_second_interface() {
        let header = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n";
        assert_eq!(
            interface_names_from_net_dev(&format!(
                "{header}    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
            ))
            .unwrap(),
            ["lo"]
        );
        assert_ne!(
            interface_names_from_net_dev(&format!("{header}    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n  eth0: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")).unwrap(),
            ["lo"]
        );
    }

    #[test]
    fn listener_descriptor_moves_in_one_private_packet() {
        let (sender, receiver) = sys::private_socket_pair().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let expected = listener.local_addr().unwrap();
        sys::send_packet_with_descriptor(
            sender.as_raw_fd(),
            b"namespace-ready",
            listener.as_raw_fd(),
        )
        .unwrap();
        drop(listener);
        let mut packet = [0_u8; 64];
        let (count, moved) =
            sys::receive_packet_with_descriptor(receiver.as_raw_fd(), &mut packet).unwrap();
        assert_eq!(&packet[..count], b"namespace-ready");
        assert_eq!(TcpListener::from(moved).local_addr().unwrap(), expected);
    }

    #[test]
    fn socket_namespace_identity_matches_current_network_namespace() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let namespace = match sys::socket_network_namespace(listener.as_raw_fd()) {
            Ok(namespace) => namespace,
            // Restricted containers lack CAP_NET_ADMIN in their current
            // network namespace. Production readiness rejects this state.
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => return,
            Err(error) => panic!("SIOCGSKNS failed unexpectedly: {error}"),
        };
        let socket = fs::metadata(format!("/proc/self/fd/{}", namespace.as_raw_fd())).unwrap();
        let current = namespace_identity("/proc/self/ns/net").unwrap();
        assert_eq!(
            (socket.dev(), socket.ino()),
            (current.device, current.inode)
        );
    }
}
