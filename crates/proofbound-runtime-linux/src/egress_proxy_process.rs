//! Descriptor-only entry point for the separately identified egress proxy.

use std::fs::File;
use std::io::Read as _;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::path::Path;
use std::time::Duration;

use proofbound_runtime_core::{ExecutionId, Sha256Digest, parse_egress_execution_plan};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::egress_confinement::install_proxy_confinement;
use crate::egress_proxy::{EgressProxyEngine, ProxyReportEvent, encode_proxy_report};
use crate::{Architecture, sys};

const MAX_POLICY_BYTES: u64 = 16 * 1024 * 1024;
const DRAIN_PACKET: &[u8] = b"PBR-EGRESS-DRAIN/1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyProcessError {
    Bootstrap,
    Descriptor,
    Policy,
    Identity,
    Confinement,
    Report,
    Engine,
    Protocol,
}

impl ProxyProcessError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Bootstrap => "egress.proxy.bootstrap.invalid",
            Self::Descriptor => "egress.proxy.descriptor.invalid",
            Self::Policy => "egress.proxy.policy.invalid",
            Self::Identity => "egress.proxy.identity.invalid",
            Self::Confinement => "egress.proxy.confinement.failed",
            Self::Report => "egress.proxy.report.failed",
            Self::Engine => "egress.proxy.engine.failed",
            Self::Protocol => "egress.proxy.protocol.invalid",
        }
    }
}

/// Exact command-line bootstrap; the inherited descriptor set is closed by
/// the supervisor before exec and closed again here before policy parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyBootstrap {
    pub plan_fd: u32,
    pub listener_fd: u32,
    pub report_fd: u32,
    pub execution_id: ExecutionId,
    pub policy_sha256: Sha256Digest,
    pub generation: u64,
    pub plan_sha256: Sha256Digest,
    pub proxy_sha256: Sha256Digest,
    pub closure_sha256: Sha256Digest,
    pub resolver_sha256: Sha256Digest,
    pub child_netns_device: u64,
    pub child_netns_inode: u64,
}

pub fn parse_proxy_bootstrap(arguments: &[String]) -> Result<ProxyBootstrap, ProxyProcessError> {
    const NAMES: [&str; 13] = [
        "--egress-proxy-protocol",
        "--plan-fd",
        "--listener-fd",
        "--report-fd",
        "--execution-id",
        "--policy-sha256",
        "--generation",
        "--plan-sha256",
        "--proxy-sha256",
        "--runtime-closure-sha256",
        "--resolver-configuration-sha256",
        "--child-netns-device",
        "--child-netns-inode",
    ];
    if arguments.len() != NAMES.len() * 2
        || NAMES
            .iter()
            .enumerate()
            .any(|(index, name)| arguments[index * 2] != *name)
        || arguments[1] != "1"
    {
        return Err(ProxyProcessError::Bootstrap);
    }
    let descriptor = |index: usize| -> Result<u32, ProxyProcessError> {
        arguments[index]
            .parse::<u32>()
            .ok()
            .filter(|value| (3..=i32::MAX as u32).contains(value))
            .ok_or(ProxyProcessError::Bootstrap)
    };
    let number = |index: usize| -> Result<u64, ProxyProcessError> {
        arguments[index]
            .parse::<u64>()
            .map_err(|_| ProxyProcessError::Bootstrap)
    };
    let digest = |index: usize| -> Result<Sha256Digest, ProxyProcessError> {
        Sha256Digest::parse_hex(&arguments[index]).map_err(|_| ProxyProcessError::Bootstrap)
    };
    let plan_fd = descriptor(3)?;
    let listener_fd = descriptor(5)?;
    let report_fd = descriptor(7)?;
    if plan_fd == listener_fd || plan_fd == report_fd || listener_fd == report_fd {
        return Err(ProxyProcessError::Bootstrap);
    }
    let execution = decode_hex::<16>(&arguments[9])?;
    Ok(ProxyBootstrap {
        plan_fd,
        listener_fd,
        report_fd,
        execution_id: ExecutionId::from_bytes(execution)
            .map_err(|_| ProxyProcessError::Bootstrap)?,
        policy_sha256: digest(11)?,
        generation: number(13)?,
        plan_sha256: digest(15)?,
        proxy_sha256: digest(17)?,
        closure_sha256: digest(19)?,
        resolver_sha256: digest(21)?,
        child_netns_device: number(23)?,
        child_netns_inode: number(25)?,
    })
}

fn decode_hex<const N: usize>(input: &str) -> Result<[u8; N], ProxyProcessError> {
    if input.len() != N * 2 || !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ProxyProcessError::Bootstrap);
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16)
            .map_err(|_| ProxyProcessError::Bootstrap)?;
    }
    Ok(output)
}

fn take(descriptor: u32) -> Result<OwnedFd, ProxyProcessError> {
    let descriptor = i32::try_from(descriptor).map_err(|_| ProxyProcessError::Descriptor)?;
    sys::take_inherited_descriptor(descriptor).map_err(|_| ProxyProcessError::Descriptor)
}

fn read_policy(descriptor: OwnedFd) -> Result<Vec<u8>, ProxyProcessError> {
    let mut bytes = Vec::new();
    let file = File::from(descriptor);
    if !file
        .metadata()
        .map_err(|_| ProxyProcessError::Policy)?
        .is_file()
    {
        return Err(ProxyProcessError::Policy);
    }
    file.take(MAX_POLICY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProxyProcessError::Policy)?;
    if bytes.len() > MAX_POLICY_BYTES as usize {
        return Err(ProxyProcessError::Policy);
    }
    Ok(bytes)
}

fn own_executable_digest() -> Result<Sha256Digest, ProxyProcessError> {
    let mut executable = File::open("/proc/self/exe").map_err(|_| ProxyProcessError::Identity)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let length = executable
            .read(&mut buffer)
            .map_err(|_| ProxyProcessError::Identity)?;
        if length == 0 {
            break;
        }
        hasher.update(&buffer[..length]);
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn open_read_path(path: &Path) -> Result<File, ProxyProcessError> {
    let relative = path
        .strip_prefix("/")
        .map_err(|_| ProxyProcessError::Policy)?;
    let root = sys::open_directory(Path::new("/")).map_err(|_| ProxyProcessError::Policy)?;
    let flags = sys::RESOLVE_BENEATH | sys::RESOLVE_NO_SYMLINKS | sys::RESOLVE_NO_MAGICLINKS;
    let descriptor = sys::openat2_file(root.as_raw_fd(), relative, flags)
        .or_else(|_| sys::openat2_directory(root.as_raw_fd(), relative, flags))
        .map_err(|_| ProxyProcessError::Policy)?;
    Ok(File::from(descriptor))
}

fn send_json(report_fd: i32, value: serde_json::Value) -> Result<(), ProxyProcessError> {
    let bytes = serde_json::to_vec(&value).map_err(|_| ProxyProcessError::Report)?;
    if bytes.len() > crate::egress_proxy::MAX_PROXY_REPORT_BYTES {
        return Err(ProxyProcessError::Report);
    }
    sys::send_packet(report_fd, &bytes).map_err(|_| ProxyProcessError::Report)
}

fn send_events(report_fd: i32, events: Vec<ProxyReportEvent>) -> Result<(), ProxyProcessError> {
    for event in events {
        let bytes = encode_proxy_report(&event).map_err(|_| ProxyProcessError::Report)?;
        sys::send_packet(report_fd, &bytes).map_err(|_| ProxyProcessError::Report)?;
    }
    Ok(())
}

/// Runs only with the exact inherited listener, report channel, and policy
/// descriptor. No readiness packet is sent until both kernel filters install.
pub fn run_proxy_process(bootstrap: ProxyBootstrap) -> Result<(), ProxyProcessError> {
    let report = take(bootstrap.report_fd)?;
    let plan = take(bootstrap.plan_fd)?;
    let listener = take(bootstrap.listener_fd)?;
    sys::close_descriptors_except(&[plan.as_raw_fd(), listener.as_raw_fd(), report.as_raw_fd()])
        .map_err(|_| ProxyProcessError::Descriptor)?;
    if sys::socket_type(report.as_raw_fd()).map_err(|_| ProxyProcessError::Descriptor)?
        != libc::SOCK_SEQPACKET
        || sys::socket_type(listener.as_raw_fd()).map_err(|_| ProxyProcessError::Descriptor)?
            != libc::SOCK_STREAM
        || !sys::socket_accepting(listener.as_raw_fd())
            .map_err(|_| ProxyProcessError::Descriptor)?
    {
        return Err(ProxyProcessError::Descriptor);
    }
    sys::set_nonblocking(report.as_raw_fd()).map_err(|_| ProxyProcessError::Descriptor)?;
    let listener = TcpListener::from(listener);
    if listener
        .local_addr()
        .map_err(|_| ProxyProcessError::Descriptor)?
        != SocketAddr::from((Ipv4Addr::LOCALHOST, 3128))
    {
        return Err(ProxyProcessError::Descriptor);
    }
    let plan_bytes = read_policy(plan)?;
    if Sha256Digest::from_bytes(Sha256::digest(&plan_bytes).into()) != bootstrap.plan_sha256
        || own_executable_digest()? != bootstrap.proxy_sha256
    {
        return Err(ProxyProcessError::Identity);
    }
    let plan = parse_egress_execution_plan(&plan_bytes).map_err(|_| ProxyProcessError::Policy)?;
    let authority = plan.egress();
    let mut read_paths = authority
        .proxy_runtime_read()
        .iter()
        .map(|path| path.as_str().to_owned())
        .collect::<Vec<_>>();
    read_paths.push(authority.resolver().configuration().as_str().to_owned());
    read_paths.sort_unstable();
    read_paths.dedup();
    let files = read_paths
        .iter()
        .map(|path| open_read_path(Path::new(path)))
        .collect::<Result<Vec<_>, _>>()?;
    let borrowed = files.iter().map(|file| file.as_fd()).collect::<Vec<_>>();
    let mut ports = authority
        .endpoints()
        .iter()
        .map(|endpoint| endpoint.port.get())
        .collect::<Vec<_>>();
    ports.push(authority.resolver().endpoint().port().get());
    let architecture = if cfg!(target_arch = "x86_64") {
        Architecture::X86_64
    } else if cfg!(target_arch = "aarch64") {
        Architecture::Aarch64
    } else {
        return Err(ProxyProcessError::Confinement);
    };
    let confinement = install_proxy_confinement(architecture, &borrowed, &ports)
        .map_err(|_| ProxyProcessError::Confinement)?;
    drop(borrowed);
    drop(files);
    let mut engine = EgressProxyEngine::new(authority.clone(), listener)
        .map_err(|_| ProxyProcessError::Engine)?;
    engine
        .mark_ready_and_serving()
        .map_err(|_| ProxyProcessError::Engine)?;
    let binding = readiness_binding(bootstrap, confinement.filter_sha256);
    send_json(
        report.as_raw_fd(),
        json!({
            "kind": "ready",
            "execution_id": hex_bytes(bootstrap.execution_id.as_bytes()),
            "policy_sha256": bootstrap.policy_sha256.to_hex(),
            "generation": bootstrap.generation,
            "plan_sha256": bootstrap.plan_sha256.to_hex(),
            "proxy_sha256": bootstrap.proxy_sha256.to_hex(),
            "runtime_closure_sha256": bootstrap.closure_sha256.to_hex(),
            "resolver_configuration_sha256": bootstrap.resolver_sha256.to_hex(),
            "child_netns_device": bootstrap.child_netns_device,
            "child_netns_inode": bootstrap.child_netns_inode,
            "landlock_abi": confinement.landlock_abi,
            "landlock_handled_filesystem": confinement.handled_filesystem,
            "landlock_handled_network": confinement.handled_network,
            "landlock_scoped": confinement.scoped,
            "proxy_filter_sha256": confinement.filter_sha256.to_hex(),
            "readiness_binding": binding.to_hex(),
        }),
    )?;
    loop {
        engine
            .step(Duration::from_millis(25))
            .map_err(|_| ProxyProcessError::Engine)?;
        send_events(report.as_raw_fd(), engine.take_reports())?;
        if sys::wait_readable(report.as_raw_fd(), Duration::ZERO)
            .map_err(|_| ProxyProcessError::Protocol)?
        {
            let mut request = [0_u8; 64];
            let length = sys::receive_packet(report.as_raw_fd(), &mut request)
                .map_err(|_| ProxyProcessError::Protocol)?;
            if &request[..length] != DRAIN_PACKET {
                return Err(ProxyProcessError::Protocol);
            }
            let (_, _, events) = engine.drain().map_err(|_| ProxyProcessError::Engine)?;
            send_events(report.as_raw_fd(), events)?;
            return Ok(());
        }
    }
}

fn readiness_binding(bootstrap: ProxyBootstrap, filter: Sha256Digest) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"PBR-EGRESS-READY/1");
    hasher.update(bootstrap.execution_id.as_bytes());
    hasher.update(bootstrap.policy_sha256.as_bytes());
    hasher.update(bootstrap.generation.to_be_bytes());
    hasher.update(bootstrap.plan_sha256.as_bytes());
    hasher.update(bootstrap.proxy_sha256.as_bytes());
    hasher.update(bootstrap.closure_sha256.as_bytes());
    hasher.update(bootstrap.resolver_sha256.as_bytes());
    hasher.update(bootstrap.child_netns_device.to_be_bytes());
    hasher.update(bootstrap.child_netns_inode.to_be_bytes());
    hasher.update(filter.as_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_rejects_extra_arguments_and_duplicate_descriptors() {
        let names = [
            "--egress-proxy-protocol",
            "--plan-fd",
            "--listener-fd",
            "--report-fd",
            "--execution-id",
            "--policy-sha256",
            "--generation",
            "--plan-sha256",
            "--proxy-sha256",
            "--runtime-closure-sha256",
            "--resolver-configuration-sha256",
            "--child-netns-device",
            "--child-netns-inode",
        ];
        let values = [
            "1",
            "3",
            "4",
            "5",
            "01010101010141018101010101010101",
            "00".repeat(32).leak(),
            "1",
            "00".repeat(32).leak(),
            "00".repeat(32).leak(),
            "00".repeat(32).leak(),
            "00".repeat(32).leak(),
            "11",
            "12",
        ];
        let mut arguments = names
            .iter()
            .zip(values)
            .flat_map(|(name, value)| [(*name).to_owned(), value.to_owned()])
            .collect::<Vec<_>>();
        assert!(parse_proxy_bootstrap(&arguments).is_ok());
        arguments[5] = "3".to_owned();
        assert_eq!(
            parse_proxy_bootstrap(&arguments),
            Err(ProxyProcessError::Bootstrap)
        );
        arguments[5] = "4".to_owned();
        arguments.push("unexpected".to_owned());
        assert_eq!(
            parse_proxy_bootstrap(&arguments),
            Err(ProxyProcessError::Bootstrap)
        );
    }
}
