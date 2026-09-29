//! Supervisor-side checks for the separately confined egress proxy.

use core::num::NonZeroU32;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use proofbound_runtime_core::{ExecutionId, ExecutionOutcome, ResourceLimits, Sha256Digest};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::egress_namespace::EgressNamespaceReport;
use crate::egress_proxy_process::ProxyBootstrap;
use crate::egress_receipt::EgressReportCollector;
use crate::{
    Architecture, ExecRelease, FreshCgroup, InstallRequest, LauncherChannel, LauncherIdentity,
    LauncherMessage, ResourceObservation, sys,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressSupervisorError {
    ReadyInvalid,
    ReadyBindingMismatch,
    DescriptorInvalid,
    SpawnFailed,
    PauseNotObserved,
    CgroupPlacementFailed,
    ResumeFailed,
    ReportFailed,
    DrainFailed,
    CleanupFailed,
    BoundaryInvalid,
    ChildFailed,
}

impl EgressSupervisorError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ReadyInvalid => "network.egress.proxy.ready-invalid",
            Self::ReadyBindingMismatch => "launcher.ack.network.egress.binding-mismatch",
            Self::DescriptorInvalid => "network.egress.proxy.descriptor-invalid",
            Self::SpawnFailed => "network.egress.proxy.spawn-failed",
            Self::PauseNotObserved => "network.egress.proxy.pause-not-observed",
            Self::CgroupPlacementFailed => "network.egress.proxy.cgroup-placement-failed",
            Self::ResumeFailed => "network.egress.proxy.resume-failed",
            Self::ReportFailed => "network.egress.proxy.report-invalid",
            Self::DrainFailed => "network.egress.proxy.drain-failed",
            Self::CleanupFailed => "network.egress.proxy.cleanup-failed",
            Self::BoundaryInvalid => "launcher.ack.network.egress.invalid",
            Self::ChildFailed => "network.egress.child.failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressProxyReady {
    pub generation: u64,
    pub binding: Sha256Digest,
    pub filter_sha256: Sha256Digest,
    pub landlock_abi: u32,
    pub handled_filesystem: u64,
    pub handled_network: u64,
    pub scoped: u64,
}

/// Retained identities and groups for one exact version 3 native launch.
pub struct EgressSupervisorInputs<'a> {
    pub launcher_program: &'a Path,
    pub request: InstallRequest,
    pub child_cgroup: FreshCgroup,
    pub proxy_cgroup: FreshCgroup,
    pub limits: ResourceLimits,
    pub child_descriptors: &'a [BorrowedFd<'a>],
    pub plan: BorrowedFd<'a>,
    pub proxy: BorrowedFd<'a>,
    pub plan_sha256: Sha256Digest,
    pub proxy_sha256: Sha256Digest,
    pub closure_sha256: Sha256Digest,
    pub resolver_sha256: Sha256Digest,
    pub architecture: Architecture,
    pub landlock_abi: NonZeroU32,
}

pub struct EgressSupervisedExecution {
    pub boundary: Value,
    pub namespace: EgressNamespaceReport,
    pub proxy_ready: EgressProxyReady,
    pub outcome: ExecutionOutcome,
    pub stdout: crate::CapturedStream,
    pub stderr: crate::CapturedStream,
    pub child_resources: ResourceObservation,
    pub proxy_resources: ResourceObservation,
    pub reports: EgressReportCollector,
    pub elapsed: Duration,
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Installs the child namespace and proxy sibling before releasing the
/// identified child executable. Any failed handshake produces no receipt.
pub fn supervise_egress_launcher(
    inputs: EgressSupervisorInputs<'_>,
) -> Result<EgressSupervisedExecution, EgressSupervisorError> {
    let start = Instant::now();
    crate::supervisor::validate_descriptor_set(&inputs.request, inputs.child_descriptors)
        .map_err(|_| EgressSupervisorError::DescriptorInvalid)?;
    if inputs.request.identity().cgroup_id() != inputs.child_cgroup.identity() {
        return Err(EgressSupervisorError::DescriptorInvalid);
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(
            inputs.limits.wall_time().milliseconds(),
        ))
        .ok_or(EgressSupervisorError::ChildFailed)?;
    let (supervisor_channel, launcher_channel) =
        LauncherChannel::pair().map_err(|_| EgressSupervisorError::DescriptorInvalid)?;
    let mut arguments = crate::supervisor::bootstrap_arguments(
        launcher_channel.as_fd().as_raw_fd(),
        inputs.request.identity(),
        inputs.architecture,
        inputs.landlock_abi,
    );
    arguments[0] = "__proofbound_egress_launcher_v1".to_owned();
    let mut command = Command::new(inputs.launcher_program);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut inherited = inputs
        .child_descriptors
        .iter()
        .map(BorrowedFd::as_raw_fd)
        .collect::<Vec<_>>();
    inherited.push(launcher_channel.as_fd().as_raw_fd());
    sys::inherit_descriptors_for_exec(&mut command, inherited);
    let mut child = ChildGuard(
        command
            .spawn()
            .map_err(|_| EgressSupervisorError::SpawnFailed)?,
    );
    drop(launcher_channel);
    let stdout = child
        .0
        .stdout
        .take()
        .ok_or(EgressSupervisorError::SpawnFailed)?;
    let stderr = child
        .0
        .stderr
        .take()
        .ok_or(EgressSupervisorError::SpawnFailed)?;
    let stdout_reader = crate::supervisor::spawn_capture(stdout, inputs.limits.stdout())
        .map_err(|_| EgressSupervisorError::ChildFailed)?;
    let stderr_reader = crate::supervisor::spawn_capture(stderr, inputs.limits.stderr())
        .map_err(|_| EgressSupervisorError::ChildFailed)?;
    crate::supervisor::wait_for_pause(child.0.id(), deadline)
        .map_err(|_| EgressSupervisorError::PauseNotObserved)?;
    inputs
        .child_cgroup
        .place_process(child.0.id())
        .map_err(|_| EgressSupervisorError::CgroupPlacementFailed)?;
    sys::continue_process(child.0.id()).map_err(|_| EgressSupervisorError::ResumeFailed)?;
    supervisor_channel
        .send(&LauncherMessage::Install(inputs.request.clone()))
        .map_err(|_| EgressSupervisorError::ReportFailed)?;
    if !sys::wait_readable(
        supervisor_channel.as_fd().as_raw_fd(),
        deadline.saturating_duration_since(Instant::now()),
    )
    .map_err(|_| EgressSupervisorError::ChildFailed)?
    {
        return Err(EgressSupervisorError::ChildFailed);
    }
    let (namespace, listener) = crate::egress_namespace::receive_namespace_ready(
        supervisor_channel.as_fd().as_raw_fd(),
        child.0.id(),
    )
    .map_err(|_| EgressSupervisorError::BoundaryInvalid)?;
    let mut proxy = start_proxy(
        inputs.proxy,
        inputs.plan,
        listener.as_fd(),
        inputs.proxy_cgroup,
        inputs.request.identity().execution_id(),
        inputs.request.identity().policy_id(),
        1,
        inputs.plan_sha256,
        inputs.proxy_sha256,
        inputs.closure_sha256,
        inputs.resolver_sha256,
        namespace.network_namespace.device,
        namespace.network_namespace.inode,
        inputs.architecture,
        deadline,
    )?;
    drop(listener);
    let ready = proxy.ready();
    if ready.landlock_abi != inputs.landlock_abi.get() {
        return Err(EgressSupervisorError::ReadyInvalid);
    }
    send_proxy_ready(
        &supervisor_channel,
        inputs.request.identity(),
        &namespace,
        ready,
    )?;
    if !sys::wait_readable(
        supervisor_channel.as_fd().as_raw_fd(),
        deadline.saturating_duration_since(Instant::now()),
    )
    .map_err(|_| EgressSupervisorError::BoundaryInvalid)?
    {
        return Err(EgressSupervisorError::BoundaryInvalid);
    }
    let mut packet = [0_u8; 65_537];
    let size = sys::receive_packet(supervisor_channel.as_fd().as_raw_fd(), &mut packet)
        .map_err(|_| EgressSupervisorError::BoundaryInvalid)?;
    let boundary = validate_boundary_installed(
        &packet[..size],
        inputs.request.identity(),
        &namespace,
        ready,
        inputs.landlock_abi,
        inputs.architecture,
    )?;
    supervisor_channel
        .send(&LauncherMessage::ExecRelease(ExecRelease::new(
            inputs.request.identity(),
        )))
        .map_err(|_| EgressSupervisorError::ChildFailed)?;
    let outcome = monitor_egress_child(&mut child.0, &mut proxy, deadline)?;
    let child_resources = inputs
        .child_cgroup
        .finish()
        .map_err(|_| EgressSupervisorError::CleanupFailed)?;
    let (reports, proxy_resources) = proxy.drain()?;
    let stdout = crate::supervisor::join_capture(stdout_reader)
        .map_err(|_| EgressSupervisorError::ChildFailed)?;
    let stderr = crate::supervisor::join_capture(stderr_reader)
        .map_err(|_| EgressSupervisorError::ChildFailed)?;
    Ok(EgressSupervisedExecution {
        boundary,
        namespace,
        proxy_ready: ready,
        outcome,
        stdout,
        stderr,
        child_resources,
        proxy_resources,
        reports,
        elapsed: start.elapsed(),
    })
}

fn monitor_egress_child(
    child: &mut Child,
    proxy: &mut EgressProxySession,
    deadline: Instant,
) -> Result<ExecutionOutcome, EgressSupervisorError> {
    use std::os::unix::process::ExitStatusExt as _;

    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| EgressSupervisorError::ChildFailed)?
        {
            return Ok(crate::supervisor::classify_process_result(
                status.code(),
                status.signal().and_then(|value| u32::try_from(value).ok()),
                false,
                false,
            ));
        }
        if !proxy.is_healthy()? {
            let _ = child.kill();
            return Err(EgressSupervisorError::ReportFailed);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Ok(ExecutionOutcome::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Sends only the validated readiness binding to the waiting launcher.
pub fn send_proxy_ready(
    channel: &LauncherChannel,
    identity: LauncherIdentity,
    namespace: &EgressNamespaceReport,
    ready: EgressProxyReady,
) -> Result<(), EgressSupervisorError> {
    let packet = serde_json::to_vec(&json!({
        "schema": "proofbound-runtime-egress-proxy-ready/1",
        "execution_id": hex(identity.execution_id().as_bytes()),
        "policy_sha256": identity.policy_id().to_hex(),
        "cgroup_mount_id": identity.cgroup_id().mount_id(),
        "cgroup_inode": identity.cgroup_id().inode(),
        "child_netns_device": namespace.network_namespace.device,
        "child_netns_inode": namespace.network_namespace.inode,
        "generation": ready.generation,
        "readiness_binding": ready.binding.to_hex(),
    }))
    .map_err(|_| EgressSupervisorError::ReadyInvalid)?;
    sys::send_packet(channel.as_fd().as_raw_fd(), &packet)
        .map_err(|_| EgressSupervisorError::ReportFailed)
}

/// Checks the full launcher's installed-boundary acknowledgement against
/// independent namespace, proxy, cgroup, and compiled-filter observations.
pub fn validate_boundary_installed(
    packet: &[u8],
    identity: LauncherIdentity,
    namespace: &EgressNamespaceReport,
    ready: EgressProxyReady,
    landlock_abi: NonZeroU32,
    architecture: Architecture,
) -> Result<Value, EgressSupervisorError> {
    if packet.is_empty() || packet.len() > 65_536 || !(9..=11).contains(&landlock_abi.get()) {
        return Err(EgressSupervisorError::BoundaryInvalid);
    }
    let observed: Value =
        serde_json::from_slice(packet).map_err(|_| EgressSupervisorError::BoundaryInvalid)?;
    let filter = crate::egress_child_seccomp::compile_child_seccomp(architecture)
        .map_err(|_| EgressSupervisorError::BoundaryInvalid)?;
    let filter_sha256 = Sha256Digest::from_bytes(Sha256::digest(filter).into());
    let routes = namespace
        .routes
        .iter()
        .map(|route| {
            json!({"family": route.family, "destination": route.destination,
                "prefix_length": route.prefix_length, "interface": route.interface})
        })
        .collect::<Vec<_>>();
    let expected = json!({
        "schema": "proofbound-runtime-egress-boundary-installed/1",
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
        "proxy_generation": ready.generation,
        "proxy_readiness_binding": ready.binding.to_hex(),
        "landlock_abi": landlock_abi.get(),
        "landlock_handled_filesystem": (1_u64 << 17) - 1,
        "landlock_handled_network": 3,
        "landlock_scoped": 3,
        "child_filter_sha256": filter_sha256.to_hex(),
    });
    if observed != expected {
        return Err(EgressSupervisorError::BoundaryInvalid);
    }
    Ok(observed)
}

/// A separately confined proxy started from an already identified descriptor.
/// The retained group and process are killed if any later setup stage fails.
pub struct EgressProxySession {
    child: Child,
    cgroup: Option<FreshCgroup>,
    report: OwnedFd,
    reader: Option<std::thread::JoinHandle<Result<EgressReportCollector, EgressSupervisorError>>>,
    draining: Arc<AtomicBool>,
    ready: EgressProxyReady,
}

impl EgressProxySession {
    pub const fn ready(&self) -> EgressProxyReady {
        self.ready
    }

    fn is_healthy(&mut self) -> Result<bool, EgressSupervisorError> {
        if self
            .reader
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
        {
            return Ok(false);
        }
        Ok(self
            .child
            .try_wait()
            .map_err(|_| EgressSupervisorError::ReportFailed)?
            .is_none())
    }

    /// Drains after the child process tree has terminated. The caller must
    /// separately retain and bind the returned proxy cgroup observation.
    pub fn drain(
        mut self,
    ) -> Result<(EgressReportCollector, crate::ResourceObservation), EgressSupervisorError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        self.draining.store(true, Ordering::Release);
        sys::send_packet(self.report.as_raw_fd(), b"PBR-EGRESS-DRAIN/1")
            .map_err(|_| EgressSupervisorError::DrainFailed)?;
        let collector = self
            .reader
            .take()
            .ok_or(EgressSupervisorError::ReportFailed)?
            .join()
            .map_err(|_| EgressSupervisorError::ReportFailed)??;
        let status = wait_proxy_exit_before(&mut self.child, deadline)?;
        if !status.success() {
            return Err(EgressSupervisorError::CleanupFailed);
        }
        let resources = self
            .cgroup
            .take()
            .ok_or(EgressSupervisorError::CleanupFailed)?
            .finish()
            .map_err(|_| EgressSupervisorError::CleanupFailed)?;
        Ok((collector, resources))
    }
}

fn wait_proxy_exit_before(
    child: &mut Child,
    deadline: Instant,
) -> Result<std::process::ExitStatus, EgressSupervisorError> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| EgressSupervisorError::CleanupFailed)?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(EgressSupervisorError::DrainFailed);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

impl Drop for EgressProxySession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts the proxy paused, places it in its own fresh group, and validates
/// the first private report before the launcher may install its boundary.
#[allow(clippy::too_many_arguments)]
pub fn start_proxy(
    proxy: BorrowedFd<'_>,
    plan: BorrowedFd<'_>,
    listener: BorrowedFd<'_>,
    cgroup: FreshCgroup,
    execution_id: ExecutionId,
    policy_sha256: Sha256Digest,
    generation: u64,
    plan_sha256: Sha256Digest,
    proxy_sha256: Sha256Digest,
    closure_sha256: Sha256Digest,
    resolver_sha256: Sha256Digest,
    child_netns_device: u64,
    child_netns_inode: u64,
    architecture: Architecture,
    deadline: Instant,
) -> Result<EgressProxySession, EgressSupervisorError> {
    let (supervisor_report, proxy_report) =
        sys::private_socket_pair().map_err(|_| EgressSupervisorError::DescriptorInvalid)?;
    let bootstrap = ProxyBootstrap {
        plan_fd: u32::try_from(plan.as_raw_fd())
            .map_err(|_| EgressSupervisorError::DescriptorInvalid)?,
        listener_fd: u32::try_from(listener.as_raw_fd())
            .map_err(|_| EgressSupervisorError::DescriptorInvalid)?,
        report_fd: u32::try_from(proxy_report.as_raw_fd())
            .map_err(|_| EgressSupervisorError::DescriptorInvalid)?,
        execution_id,
        policy_sha256,
        generation,
        plan_sha256,
        proxy_sha256,
        closure_sha256,
        resolver_sha256,
        child_netns_device,
        child_netns_inode,
    };
    if generation == 0
        || [
            proxy.as_raw_fd(),
            plan.as_raw_fd(),
            listener.as_raw_fd(),
            proxy_report.as_raw_fd(),
        ]
        .iter()
        .any(|descriptor| *descriptor < 3)
    {
        return Err(EgressSupervisorError::DescriptorInvalid);
    }
    let filter = crate::egress_seccomp::compile_proxy_seccomp(architecture)
        .map_err(|_| EgressSupervisorError::ReadyInvalid)?;
    let expected_filter = Sha256Digest::from_bytes(Sha256::digest(filter).into());
    let mut command = Command::new(Path::new(&format!("/proc/self/fd/{}", proxy.as_raw_fd())));
    command
        .args(bootstrap.arguments())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    sys::inherit_only_descriptors_for_exec(
        &mut command,
        vec![
            plan.as_raw_fd(),
            listener.as_raw_fd(),
            proxy_report.as_raw_fd(),
        ],
        vec![proxy.as_raw_fd()],
    )
    .map_err(|_| EgressSupervisorError::DescriptorInvalid)?;
    let mut child = command
        .spawn()
        .map_err(|_| EgressSupervisorError::SpawnFailed)?;
    drop(proxy_report);
    let setup = (|| {
        while !sys::process_is_stopped(child.id())
            .map_err(|_| EgressSupervisorError::PauseNotObserved)?
        {
            if Instant::now() >= deadline {
                return Err(EgressSupervisorError::PauseNotObserved);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        cgroup
            .place_process(child.id())
            .map_err(|_| EgressSupervisorError::CgroupPlacementFailed)?;
        sys::continue_process(child.id()).map_err(|_| EgressSupervisorError::ResumeFailed)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero()
            || !sys::wait_readable(supervisor_report.as_raw_fd(), remaining)
                .map_err(|_| EgressSupervisorError::ReportFailed)?
        {
            return Err(EgressSupervisorError::ReportFailed);
        }
        let mut packet = [0_u8; 32_769];
        let size = sys::receive_packet(supervisor_report.as_raw_fd(), &mut packet)
            .map_err(|_| EgressSupervisorError::ReportFailed)?;
        if size == 0 || size > 32_768 {
            return Err(EgressSupervisorError::ReportFailed);
        }
        let ready = validate_proxy_ready(&packet[..size], bootstrap, expected_filter)?;
        let mut collector = EgressReportCollector::new();
        collector
            .ingest(&packet[..size])
            .map_err(|_| EgressSupervisorError::ReportFailed)?;
        Ok((ready, collector))
    })();
    match setup {
        Ok((ready, collector)) => {
            let reader_setup = (|| {
                let reader_report = supervisor_report
                    .try_clone()
                    .map_err(|_| EgressSupervisorError::DescriptorInvalid)?;
                let draining = Arc::new(AtomicBool::new(false));
                let reader_draining = Arc::clone(&draining);
                let reader = std::thread::Builder::new()
                    .name("proofbound-egress-report".to_owned())
                    .spawn(move || collect_reports(reader_report, collector, reader_draining))
                    .map_err(|_| EgressSupervisorError::ReportFailed)?;
                Ok((reader, draining))
            })();
            match reader_setup {
                Ok((reader, draining)) => Ok(EgressProxySession {
                    child,
                    cgroup: Some(cgroup),
                    report: supervisor_report,
                    reader: Some(reader),
                    draining,
                    ready,
                }),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    Err(error)
                }
            }
        }
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(error)
        }
    }
}

fn collect_reports(
    report: OwnedFd,
    collector: EgressReportCollector,
    draining: Arc<AtomicBool>,
) -> Result<EgressReportCollector, EgressSupervisorError> {
    collect_reports_before(report, collector, draining, Duration::from_secs(5))
}

fn collect_reports_before(
    report: OwnedFd,
    mut collector: EgressReportCollector,
    draining: Arc<AtomicBool>,
    drain_timeout: Duration,
) -> Result<EgressReportCollector, EgressSupervisorError> {
    let mut drain_deadline = None;
    loop {
        if draining.load(Ordering::Acquire) && drain_deadline.is_none() {
            drain_deadline = Instant::now().checked_add(drain_timeout);
        }
        if drain_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(EgressSupervisorError::DrainFailed);
        }
        if !sys::wait_readable(report.as_raw_fd(), Duration::from_millis(100))
            .map_err(|_| EgressSupervisorError::ReportFailed)?
        {
            continue;
        }
        let mut packet = [0_u8; 32_769];
        let size = sys::receive_packet(report.as_raw_fd(), &mut packet)
            .map_err(|_| EgressSupervisorError::ReportFailed)?;
        if size == 0 || size > 32_768 {
            return Err(EgressSupervisorError::ReportFailed);
        }
        let final_packet = serde_json::from_slice::<Value>(&packet[..size])
            .ok()
            .and_then(|value| value.get("kind").and_then(Value::as_str).map(str::to_owned))
            .as_deref()
            == Some("final");
        collector
            .ingest(&packet[..size])
            .map_err(|_| EgressSupervisorError::ReportFailed)?;
        if final_packet {
            if !draining.load(Ordering::Acquire) {
                return Err(EgressSupervisorError::ReportFailed);
            }
            return Ok(collector);
        }
    }
}

/// Checks the complete proxy readiness packet against independently selected
/// bootstrap facts and the expected compiled proxy filter.
pub fn validate_proxy_ready(
    packet: &[u8],
    bootstrap: ProxyBootstrap,
    expected_filter: Sha256Digest,
) -> Result<EgressProxyReady, EgressSupervisorError> {
    const FIELDS: [&str; 16] = [
        "kind",
        "execution_id",
        "policy_sha256",
        "generation",
        "plan_sha256",
        "proxy_sha256",
        "runtime_closure_sha256",
        "resolver_configuration_sha256",
        "child_netns_device",
        "child_netns_inode",
        "landlock_abi",
        "landlock_handled_filesystem",
        "landlock_handled_network",
        "landlock_scoped",
        "proxy_filter_sha256",
        "readiness_binding",
    ];
    if packet.is_empty() || packet.len() > 32_768 {
        return Err(EgressSupervisorError::ReadyInvalid);
    }
    let value: Value =
        serde_json::from_slice(packet).map_err(|_| EgressSupervisorError::ReadyInvalid)?;
    let fields = value
        .as_object()
        .ok_or(EgressSupervisorError::ReadyInvalid)?;
    if fields.len() != FIELDS.len() || fields.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err(EgressSupervisorError::ReadyInvalid);
    }
    let text = |name: &str| -> Result<&str, EgressSupervisorError> {
        value
            .get(name)
            .and_then(Value::as_str)
            .ok_or(EgressSupervisorError::ReadyInvalid)
    };
    let number = |name: &str| -> Result<u64, EgressSupervisorError> {
        value
            .get(name)
            .and_then(Value::as_u64)
            .ok_or(EgressSupervisorError::ReadyInvalid)
    };
    let digest = |name: &str| -> Result<Sha256Digest, EgressSupervisorError> {
        Sha256Digest::parse_hex(text(name)?).map_err(|_| EgressSupervisorError::ReadyInvalid)
    };
    if text("kind")? != "ready"
        || text("execution_id")? != hex(bootstrap.execution_id.as_bytes())
        || digest("policy_sha256")? != bootstrap.policy_sha256
        || number("generation")? != bootstrap.generation
        || bootstrap.generation == 0
        || digest("plan_sha256")? != bootstrap.plan_sha256
        || digest("proxy_sha256")? != bootstrap.proxy_sha256
        || digest("runtime_closure_sha256")? != bootstrap.closure_sha256
        || digest("resolver_configuration_sha256")? != bootstrap.resolver_sha256
        || number("child_netns_device")? != bootstrap.child_netns_device
        || number("child_netns_inode")? != bootstrap.child_netns_inode
    {
        return Err(EgressSupervisorError::ReadyInvalid);
    }
    let landlock_abi =
        u32::try_from(number("landlock_abi")?).map_err(|_| EgressSupervisorError::ReadyInvalid)?;
    let handled_filesystem = number("landlock_handled_filesystem")?;
    let handled_network = number("landlock_handled_network")?;
    let scoped = number("landlock_scoped")?;
    let filter_sha256 = digest("proxy_filter_sha256")?;
    if !(9..=11).contains(&landlock_abi)
        || handled_filesystem != (1_u64 << 17) - 1
        || handled_network != 3
        || scoped != 3
        || filter_sha256 != expected_filter
    {
        return Err(EgressSupervisorError::ReadyInvalid);
    }
    let binding = digest("readiness_binding")?;
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
    hasher.update(filter_sha256.as_bytes());
    if binding != Sha256Digest::from_bytes(hasher.finalize().into()) {
        return Err(EgressSupervisorError::ReadyBindingMismatch);
    }
    Ok(EgressProxyReady {
        generation: bootstrap.generation,
        binding,
        filter_sha256,
        landlock_abi,
        handled_filesystem,
        handled_network,
        scoped,
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

#[cfg(test)]
mod tests {
    use super::*;
    use proofbound_runtime_core::ExecutionId;
    use serde_json::json;

    fn fixture() -> (ProxyBootstrap, Sha256Digest, Value) {
        let bootstrap = ProxyBootstrap {
            plan_fd: 3,
            listener_fd: 4,
            report_fd: 5,
            execution_id: ExecutionId::from_bytes([
                1, 1, 1, 1, 1, 1, 0x41, 1, 0x81, 1, 1, 1, 1, 1, 1, 1,
            ])
            .unwrap(),
            policy_sha256: Sha256Digest::from_bytes([2; 32]),
            generation: 1,
            plan_sha256: Sha256Digest::from_bytes([3; 32]),
            proxy_sha256: Sha256Digest::from_bytes([4; 32]),
            closure_sha256: Sha256Digest::from_bytes([5; 32]),
            resolver_sha256: Sha256Digest::from_bytes([6; 32]),
            child_netns_device: 7,
            child_netns_inode: 8,
        };
        let filter = Sha256Digest::from_bytes([9; 32]);
        let binding = crate::egress_proxy_process::readiness_binding(bootstrap, filter);
        let packet = json!({
            "kind": "ready",
            "execution_id": hex(bootstrap.execution_id.as_bytes()),
            "policy_sha256": bootstrap.policy_sha256.to_hex(),
            "generation": bootstrap.generation,
            "plan_sha256": bootstrap.plan_sha256.to_hex(),
            "proxy_sha256": bootstrap.proxy_sha256.to_hex(),
            "runtime_closure_sha256": bootstrap.closure_sha256.to_hex(),
            "resolver_configuration_sha256": bootstrap.resolver_sha256.to_hex(),
            "child_netns_device": bootstrap.child_netns_device,
            "child_netns_inode": bootstrap.child_netns_inode,
            "landlock_abi": 9,
            "landlock_handled_filesystem": (1_u64 << 17) - 1,
            "landlock_handled_network": 3,
            "landlock_scoped": 3,
            "proxy_filter_sha256": filter.to_hex(),
            "readiness_binding": binding.to_hex(),
        });
        (bootstrap, filter, packet)
    }

    #[test]
    fn ready_packet_binds_independently_selected_identities() {
        let (bootstrap, filter, mut packet) = fixture();
        let bytes = serde_json::to_vec(&packet).unwrap();
        let ready = validate_proxy_ready(&bytes, bootstrap, filter).unwrap();
        assert_eq!(ready.generation, 1);
        assert_eq!(ready.landlock_abi, 9);

        packet["proxy_sha256"] = json!(Sha256Digest::from_bytes([7; 32]).to_hex());
        assert_eq!(
            validate_proxy_ready(&serde_json::to_vec(&packet).unwrap(), bootstrap, filter),
            Err(EgressSupervisorError::ReadyInvalid)
        );
        let (_, _, mut packet) = fixture();
        packet["readiness_binding"] = json!(Sha256Digest::from_bytes([7; 32]).to_hex());
        assert_eq!(
            validate_proxy_ready(&serde_json::to_vec(&packet).unwrap(), bootstrap, filter),
            Err(EgressSupervisorError::ReadyBindingMismatch)
        );
        let (_, _, mut packet) = fixture();
        packet["unexpected"] = json!(true);
        assert_eq!(
            validate_proxy_ready(&serde_json::to_vec(&packet).unwrap(), bootstrap, filter),
            Err(EgressSupervisorError::ReadyInvalid)
        );
    }

    #[test]
    fn final_before_drain_and_lost_reports_fail_closed() {
        let (_, _, ready) = fixture();
        let mut collector = EgressReportCollector::new();
        collector
            .ingest(&serde_json::to_vec(&ready).unwrap())
            .unwrap();
        let final_report = json!({
            "kind": "final", "event_sequence": 0, "connections": 0,
            "active": 0, "resolutions": 0, "dns_messages": 0,
            "client_to_remote_bytes": 0, "remote_to_client_bytes": 0,
            "rejections": 0, "rejection_reason_counts": [0,0,0,0,0,0,0,0,0,0],
            "limit_events": [], "phases": ["created", "ready", "serving", "draining", "closed"],
        });
        let (reader, writer) = sys::private_socket_pair().unwrap();
        sys::send_packet(
            writer.as_raw_fd(),
            &serde_json::to_vec(&final_report).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            collect_reports_before(
                reader,
                collector,
                Arc::new(AtomicBool::new(false)),
                Duration::from_millis(20)
            ),
            Err(EgressSupervisorError::ReportFailed)
        ));

        let (_, _, ready) = fixture();
        let mut collector = EgressReportCollector::new();
        collector
            .ingest(&serde_json::to_vec(&ready).unwrap())
            .unwrap();
        let (reader, writer) = sys::private_socket_pair().unwrap();
        drop(writer);
        assert!(matches!(
            collect_reports_before(
                reader,
                collector,
                Arc::new(AtomicBool::new(true)),
                Duration::from_millis(20)
            ),
            Err(EgressSupervisorError::ReportFailed)
        ));

        let (_, _, ready) = fixture();
        let mut collector = EgressReportCollector::new();
        collector
            .ingest(&serde_json::to_vec(&ready).unwrap())
            .unwrap();
        let (reader, _writer) = sys::private_socket_pair().unwrap();
        assert!(matches!(
            collect_reports_before(
                reader,
                collector,
                Arc::new(AtomicBool::new(true)),
                Duration::from_millis(20)
            ),
            Err(EgressSupervisorError::DrainFailed)
        ));
    }

    #[test]
    fn proxy_exit_must_precede_drain_deadline() {
        let mut exited = Command::new("/bin/true").spawn().unwrap();
        assert!(
            wait_proxy_exit_before(&mut exited, Instant::now() + Duration::from_secs(1))
                .unwrap()
                .success()
        );
        let mut stuck = Command::new("/bin/sleep").arg("2").spawn().unwrap();
        assert_eq!(
            wait_proxy_exit_before(&mut stuck, Instant::now() + Duration::from_millis(20)),
            Err(EgressSupervisorError::DrainFailed)
        );
        stuck.kill().unwrap();
        stuck.wait().unwrap();
    }
}
