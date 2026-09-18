//! Runs one identified connector as a separately supervised process.

use core::fmt;
use core::num::NonZeroU64;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use proofbound_runtime_core::{
    ArtifactRole, ExecutionId, FileMode, ServiceExecutionPlan, Sha256Digest,
    parse_service_execution_plan,
};
use sha2::{Digest as _, Sha256};

use crate::{Architecture, ResolutionError, ResolvedFile, parse_elf_interpreter};

const CONNECTOR_PROTOCOL: &str = "1";
const CONNECTOR_BOOTSTRAP_ARGUMENTS: usize = 28;
const MAX_CONNECTOR_REPORT_BYTES: usize = 256;
const MAX_CONNECTOR_EXECUTABLE_BYTES: u64 = 268_435_456;
const MAX_PLAN_BYTES: u64 = 1_048_576;
const MAX_TRUST_ROOT_BYTES: u64 = 16_777_216;
const REPORT_MAGIC: &[u8; 8] = b"PBRCP001";
const READY_REPORT: u8 = 1;
const TERMINAL_REPORT: u8 = 2;
const FAILURE_REPORT: u8 = 3;

/// Identifies one service-support artifact without extending legacy receipt roles.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ServiceArtifactRole {
    /// Contains the exact connector executable.
    ConnectorExecutable,
    /// Contains one connector runtime file.
    ConnectorRuntimeLibrary,
    /// Contains the declared resolver configuration.
    ResolverConfiguration,
    /// Contains the caller-selected TLS trust roots.
    TrustRootSet,
}

/// Contains one nonzero connector-process generation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConnectorProcessGeneration(NonZeroU64);

impl ConnectorProcessGeneration {
    /// Validates one process generation.
    pub const fn new(value: u64) -> Result<Self, ConnectorProcessError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(ConnectorProcessError::BindingInvalid),
        }
    }

    /// Returns the nonzero generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Contains one nonzero private service-channel identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ServiceChannelId([u8; 16]);

impl ServiceChannelId {
    /// Rejects the reserved all-zero channel identity.
    pub fn new(value: [u8; 16]) -> Result<Self, ConnectorProcessError> {
        if value == [0; 16] {
            Err(ConnectorProcessError::BindingInvalid)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the exact channel-identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl ServiceArtifactRole {
    /// Returns the stable service-session role name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectorExecutable => "connector-executable",
            Self::ConnectorRuntimeLibrary => "connector-runtime-library",
            Self::ResolverConfiguration => "resolver-configuration",
            Self::TrustRootSet => "trust-root-set",
        }
    }
}

/// Contains the identity of one service-support artifact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ServiceArtifactIdentity {
    role: ServiceArtifactRole,
    digest: Sha256Digest,
    size: u64,
    mode: FileMode,
}

impl ServiceArtifactIdentity {
    /// Returns the service-support role.
    #[must_use]
    pub const fn role(&self) -> ServiceArtifactRole {
        self.role
    }

    /// Returns the complete-file SHA-256 digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the file size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns the Unix mode bits.
    #[must_use]
    pub const fn mode(&self) -> FileMode {
        self.mode
    }
}

/// Owns one retained service-support file descriptor and its measured identity.
#[derive(Debug)]
pub struct ResolvedServiceArtifact {
    requested_path: PathBuf,
    resolved_target: PathBuf,
    identity: ServiceArtifactIdentity,
    #[cfg(target_os = "linux")]
    descriptor: std::os::fd::OwnedFd,
}

impl ResolvedServiceArtifact {
    /// Opens one canonical absolute regular file without following magic links.
    pub fn open(path: &Path, role: ServiceArtifactRole) -> Result<Self, ConnectorProcessError> {
        require_canonical_absolute_path(path)?;
        #[cfg(target_os = "linux")]
        {
            let descriptor =
                crate::sys::openat2_file(libc::AT_FDCWD, path, crate::sys::RESOLVE_NO_MAGICLINKS)
                    .map_err(|_| ConnectorProcessError::ArtifactUnavailable)?;
            let resolved_target = crate::resolve::descriptor_target(&descriptor)
                .map_err(|_| ConnectorProcessError::ArtifactIdentity)?;
            let identity = identify_service_descriptor(&descriptor, role)?;
            if role == ServiceArtifactRole::ConnectorExecutable
                && identity.mode().get() & 0o111 == 0
            {
                return Err(ConnectorProcessError::ConnectorNotExecutable);
            }
            Ok(Self {
                requested_path: path.to_path_buf(),
                resolved_target,
                identity,
                descriptor,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = role;
            Err(ConnectorProcessError::UnsupportedOperatingSystem)
        }
    }

    /// Returns the exact requested path.
    #[must_use]
    pub fn requested_path(&self) -> &Path {
        &self.requested_path
    }

    /// Returns the target observed through the retained descriptor.
    #[must_use]
    pub fn resolved_target(&self) -> &Path {
        &self.resolved_target
    }

    /// Returns the complete measured identity.
    #[must_use]
    pub const fn identity(&self) -> &ServiceArtifactIdentity {
        &self.identity
    }

    /// Recomputes the identity immediately before use.
    pub fn revalidate_identity(&self) -> Result<(), ConnectorProcessError> {
        #[cfg(target_os = "linux")]
        {
            let observed = identify_service_descriptor(&self.descriptor, self.identity.role())?;
            if observed == self.identity {
                Ok(())
            } else {
                Err(ConnectorProcessError::ArtifactIdentityDrift)
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(ConnectorProcessError::UnsupportedOperatingSystem)
        }
    }

    /// Reads the retained file and revalidates its identity.
    pub fn read_bytes(&self, maximum: u64) -> Result<Vec<u8>, ConnectorProcessError> {
        if self.identity.size() > maximum {
            return Err(ConnectorProcessError::ArtifactTooLarge);
        }
        #[cfg(target_os = "linux")]
        {
            use std::fs::File;
            use std::os::unix::fs::FileExt as _;

            let file = File::from(
                self.descriptor
                    .try_clone()
                    .map_err(|_| ConnectorProcessError::ArtifactIdentity)?,
            );
            let length = usize::try_from(self.identity.size())
                .map_err(|_| ConnectorProcessError::ArtifactTooLarge)?;
            let mut bytes = vec![0_u8; length];
            file.read_exact_at(&mut bytes, 0)
                .map_err(|_| ConnectorProcessError::ArtifactIdentity)?;
            self.revalidate_identity()?;
            Ok(bytes)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(ConnectorProcessError::UnsupportedOperatingSystem)
        }
    }

    #[cfg(target_os = "linux")]
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.descriptor.as_fd()
    }
}

/// Contains the closed inherited-descriptor bootstrap for the connector binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorBootstrap {
    plan_descriptor: u32,
    trust_root_descriptor: u32,
    channel_descriptor: u32,
    control_descriptor: u32,
    execution_id: ExecutionId,
    policy_digest: Sha256Digest,
    process_generation: ConnectorProcessGeneration,
    channel_id: ServiceChannelId,
    plan_digest: Sha256Digest,
    trust_root_digest: Sha256Digest,
    connector_digest: Sha256Digest,
    runtime_closure_digest: Sha256Digest,
    resolver_configuration_digest: Sha256Digest,
}

impl ConnectorBootstrap {
    /// Returns the inherited plan descriptor.
    #[must_use]
    pub const fn plan_descriptor(self) -> u32 {
        self.plan_descriptor
    }

    /// Returns the inherited trust-root descriptor.
    #[must_use]
    pub const fn trust_root_descriptor(self) -> u32 {
        self.trust_root_descriptor
    }

    /// Returns the inherited private data-channel descriptor.
    #[must_use]
    pub const fn channel_descriptor(self) -> u32 {
        self.channel_descriptor
    }

    /// Returns the inherited private control-channel descriptor.
    #[must_use]
    pub const fn control_descriptor(self) -> u32 {
        self.control_descriptor
    }
}

/// Parses the exact connector bootstrap vocabulary.
pub fn parse_connector_bootstrap(
    arguments: &[String],
) -> Result<ConnectorBootstrap, ConnectorProcessError> {
    if arguments.len() != CONNECTOR_BOOTSTRAP_ARGUMENTS {
        return Err(ConnectorProcessError::BootstrapInvalid);
    }
    let expected = [
        "--connector-protocol",
        "--plan-fd",
        "--trust-root-fd",
        "--channel-fd",
        "--control-fd",
        "--execution-id",
        "--policy-sha256",
        "--process-generation",
        "--channel-id",
        "--plan-sha256",
        "--trust-root-sha256",
        "--connector-sha256",
        "--runtime-closure-sha256",
        "--resolver-configuration-sha256",
    ];
    for (index, name) in expected.into_iter().enumerate() {
        if arguments[index * 2] != name {
            return Err(ConnectorProcessError::BootstrapInvalid);
        }
    }
    if arguments[1] != CONNECTOR_PROTOCOL {
        return Err(ConnectorProcessError::BootstrapInvalid);
    }
    let parse_descriptor = |value: &str| {
        value
            .parse::<u32>()
            .ok()
            .filter(|descriptor| *descriptor >= 3 && *descriptor <= i32::MAX as u32)
            .ok_or(ConnectorProcessError::BootstrapInvalid)
    };
    let execution_bytes = parse_hex_array::<16>(&arguments[11])?;
    let execution_id = ExecutionId::from_bytes(execution_bytes)
        .map_err(|_| ConnectorProcessError::BootstrapInvalid)?;
    let process_generation = ConnectorProcessGeneration::new(
        arguments[15]
            .parse::<u64>()
            .map_err(|_| ConnectorProcessError::BootstrapInvalid)?,
    )
    .map_err(|_| ConnectorProcessError::BootstrapInvalid)?;
    let bootstrap = ConnectorBootstrap {
        plan_descriptor: parse_descriptor(&arguments[3])?,
        trust_root_descriptor: parse_descriptor(&arguments[5])?,
        channel_descriptor: parse_descriptor(&arguments[7])?,
        control_descriptor: parse_descriptor(&arguments[9])?,
        execution_id,
        policy_digest: parse_digest(&arguments[13])?,
        process_generation,
        channel_id: ServiceChannelId::new(parse_hex_array(&arguments[17])?)
            .map_err(|_| ConnectorProcessError::BootstrapInvalid)?,
        plan_digest: parse_digest(&arguments[19])?,
        trust_root_digest: parse_digest(&arguments[21])?,
        connector_digest: parse_digest(&arguments[23])?,
        runtime_closure_digest: parse_digest(&arguments[25])?,
        resolver_configuration_digest: parse_digest(&arguments[27])?,
    };
    let mut descriptors = [
        bootstrap.plan_descriptor,
        bootstrap.trust_root_descriptor,
        bootstrap.channel_descriptor,
        bootstrap.control_descriptor,
    ];
    descriptors.sort_unstable();
    if descriptors.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ConnectorProcessError::BootstrapInvalid);
    }
    Ok(bootstrap)
}

/// Identifies the process stage that reported a terminal failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorFailureStage {
    /// The inherited bootstrap or artifact bytes were invalid.
    Bootstrap,
    /// Service-name resolution failed.
    Resolution,
    /// Endpoint connection or TLS authentication failed.
    Authentication,
    /// The private channel or authenticated proxy failed.
    Channel,
}

/// Contains one closed connector-process failure report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorFailure {
    stage: ConnectorFailureStage,
    code: u8,
}

impl ConnectorFailure {
    /// Returns the failed process stage.
    #[must_use]
    pub const fn stage(self) -> ConnectorFailureStage {
        self.stage
    }

    /// Returns the stable stage-local failure code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self.code
    }
}

/// Contains the authenticated facts received before any child release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorReady {
    execution_id: ExecutionId,
    policy_digest: Sha256Digest,
    process_generation: ConnectorProcessGeneration,
    channel_id: ServiceChannelId,
    setup_binding_digest: Sha256Digest,
    dns_observation_digest: Sha256Digest,
    selected_endpoint: SocketAddr,
    tls_version: proofbound_runtime_connector::TlsVersion,
    tls_implementation_digest: Sha256Digest,
    certificate_chain_digest: Sha256Digest,
    handshake_bytes: u64,
    authenticated_ns: u64,
}

impl ConnectorReady {
    /// Returns the execution identifier echoed by the connector.
    #[must_use]
    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }

    /// Returns the policy digest echoed by the connector.
    #[must_use]
    pub const fn policy_digest(self) -> Sha256Digest {
        self.policy_digest
    }

    /// Returns the nonzero supervisor generation.
    #[must_use]
    pub const fn process_generation(self) -> ConnectorProcessGeneration {
        self.process_generation
    }

    /// Returns the private channel identifier.
    #[must_use]
    pub const fn channel_id(self) -> ServiceChannelId {
        self.channel_id
    }

    /// Returns the complete bootstrap-artifact binding digest.
    #[must_use]
    pub const fn setup_binding_digest(self) -> Sha256Digest {
        self.setup_binding_digest
    }

    /// Returns the canonical DNS-observation digest.
    #[must_use]
    pub const fn dns_observation_digest(self) -> Sha256Digest {
        self.dns_observation_digest
    }

    /// Returns the one selected service endpoint.
    #[must_use]
    pub const fn selected_endpoint(self) -> SocketAddr {
        self.selected_endpoint
    }

    /// Returns the negotiated TLS protocol version.
    #[must_use]
    pub const fn tls_version(self) -> proofbound_runtime_connector::TlsVersion {
        self.tls_version
    }

    /// Returns the TLS implementation digest.
    #[must_use]
    pub const fn tls_implementation_digest(self) -> Sha256Digest {
        self.tls_implementation_digest
    }

    /// Returns the authenticated peer-chain digest.
    #[must_use]
    pub const fn certificate_chain_digest(self) -> Sha256Digest {
        self.certificate_chain_digest
    }

    /// Returns the observed TLS handshake byte count.
    #[must_use]
    pub const fn handshake_bytes(self) -> u64 {
        self.handshake_bytes
    }

    /// Returns the connector-relative authentication time.
    #[must_use]
    pub const fn authenticated_ns(self) -> u64 {
        self.authenticated_ns
    }
}

/// Contains the bounded terminal traffic observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorTerminal {
    child_to_service_bytes: u64,
    service_to_child_bytes: u64,
    active_ns: u64,
    closed_ns: u64,
}

impl ConnectorTerminal {
    /// Returns accepted child-to-service plaintext bytes.
    #[must_use]
    pub const fn child_to_service_bytes(self) -> u64 {
        self.child_to_service_bytes
    }

    /// Returns delivered service-to-child plaintext bytes.
    #[must_use]
    pub const fn service_to_child_bytes(self) -> u64 {
        self.service_to_child_bytes
    }

    /// Returns the connector-relative active time.
    #[must_use]
    pub const fn active_ns(self) -> u64 {
        self.active_ns
    }

    /// Returns the connector-relative close time.
    #[must_use]
    pub const fn closed_ns(self) -> u64 {
        self.closed_ns
    }
}

/// Owns an identified connector launch before process creation.
pub struct PreparedConnectorProcess<'a> {
    connector: &'a ResolvedServiceArtifact,
    plan_source: &'a ResolvedFile,
    trust_root: &'a ResolvedServiceArtifact,
    resolver_configuration: &'a ResolvedServiceArtifact,
    runtime_closure: &'a [ResolvedServiceArtifact],
    plan: ServiceExecutionPlan,
    execution_id: ExecutionId,
    policy_digest: Sha256Digest,
    process_generation: ConnectorProcessGeneration,
    channel_id: ServiceChannelId,
    runtime_closure_digest: Sha256Digest,
    setup_deadline: Instant,
}

/// Validates all connector artifacts and prepares one exact process launch.
#[allow(clippy::too_many_arguments)]
pub fn prepare_connector_process<'a>(
    connector: &'a ResolvedServiceArtifact,
    plan_source: &'a ResolvedFile,
    trust_root: &'a ResolvedServiceArtifact,
    resolver_configuration: &'a ResolvedServiceArtifact,
    runtime_closure: &'a [ResolvedServiceArtifact],
    execution_id: ExecutionId,
    policy_digest: Sha256Digest,
    process_generation: ConnectorProcessGeneration,
    channel_id: ServiceChannelId,
    architecture: Architecture,
) -> Result<PreparedConnectorProcess<'a>, ConnectorProcessError> {
    require_service_role(connector, ServiceArtifactRole::ConnectorExecutable)?;
    require_service_role(trust_root, ServiceArtifactRole::TrustRootSet)?;
    require_service_role(
        resolver_configuration,
        ServiceArtifactRole::ResolverConfiguration,
    )?;
    if runtime_closure
        .iter()
        .any(|artifact| artifact.identity().role() != ServiceArtifactRole::ConnectorRuntimeLibrary)
    {
        return Err(ConnectorProcessError::ArtifactRole);
    }
    if plan_source.identity().role() != ArtifactRole::ExecutionPlan {
        return Err(ConnectorProcessError::ArtifactRole);
    }
    if trust_root.identity().size() > MAX_TRUST_ROOT_BYTES {
        return Err(ConnectorProcessError::ArtifactTooLarge);
    }
    plan_source.revalidate_identity().map_err(map_resolution)?;
    if plan_source.identity().size() > MAX_PLAN_BYTES {
        return Err(ConnectorProcessError::ArtifactTooLarge);
    }
    let plan_bytes = plan_source.read_bytes().map_err(map_resolution)?;
    let plan = parse_service_execution_plan(&plan_bytes)
        .map_err(|_| ConnectorProcessError::PlanInvalid)?;
    let setup_deadline = Instant::now()
        .checked_add(Duration::from_millis(
            plan.service_session().limits().setup_time_ms(),
        ))
        .ok_or(ConnectorProcessError::Timeout)?;
    connector.revalidate_identity()?;
    require_before_deadline(setup_deadline)?;
    trust_root.revalidate_identity()?;
    require_before_deadline(setup_deadline)?;
    resolver_configuration.revalidate_identity()?;
    require_before_deadline(setup_deadline)?;
    for artifact in runtime_closure {
        artifact.revalidate_identity()?;
        require_before_deadline(setup_deadline)?;
    }
    let connector_bytes = connector.read_bytes(MAX_CONNECTOR_EXECUTABLE_BYTES)?;
    require_before_deadline(setup_deadline)?;
    let interpreter = parse_elf_interpreter(&connector_bytes, architecture)
        .map_err(|_| ConnectorProcessError::ConnectorExecutableInvalid)?;
    require_before_deadline(setup_deadline)?;
    if let Some(interpreter) = interpreter {
        let loader = runtime_closure
            .iter()
            .find(|artifact| artifact.requested_path() == interpreter.as_path())
            .ok_or(ConnectorProcessError::ConnectorLoaderMissing)?;
        if loader.identity().mode().get() & 0o111 == 0 {
            return Err(ConnectorProcessError::ConnectorNotExecutable);
        }
    }
    validate_declared_artifacts(
        &plan,
        connector,
        trust_root,
        resolver_configuration,
        runtime_closure,
    )?;
    require_before_deadline(setup_deadline)?;
    let runtime_closure_digest = digest_runtime_closure(runtime_closure);
    require_before_deadline(setup_deadline)?;
    Ok(PreparedConnectorProcess {
        connector,
        plan_source,
        trust_root,
        resolver_configuration,
        runtime_closure,
        plan,
        execution_id,
        policy_digest,
        process_generation,
        channel_id,
        runtime_closure_digest,
        setup_deadline,
    })
}

impl PreparedConnectorProcess<'_> {
    /// Spawns the retained connector and waits for authenticated readiness.
    pub fn spawn(self) -> Result<ReadyConnectorProcess, ConnectorProcessError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::{AsFd as _, AsRawFd as _};
            use std::os::unix::net::UnixStream;
            use std::process::{Command, Stdio};

            let setup_deadline = self.setup_deadline;
            let reaper = connector_reaper_sender()?;
            require_before_deadline(setup_deadline)?;
            self.connector.revalidate_identity()?;
            require_before_deadline(setup_deadline)?;
            self.plan_source
                .revalidate_identity()
                .map_err(map_resolution)?;
            require_before_deadline(setup_deadline)?;
            self.trust_root.revalidate_identity()?;
            require_before_deadline(setup_deadline)?;
            self.resolver_configuration.revalidate_identity()?;
            require_before_deadline(setup_deadline)?;
            for artifact in self.runtime_closure {
                artifact.revalidate_identity()?;
                require_before_deadline(setup_deadline)?;
            }
            let (supervisor_control, connector_control) =
                crate::sys::private_socket_pair().map_err(|_| ConnectorProcessError::Channel)?;
            let (child_channel, connector_channel) =
                crate::sys::private_stream_pair().map_err(|_| ConnectorProcessError::Channel)?;
            let connector_fd = self.connector.as_fd().as_raw_fd();
            let plan_fd = self.plan_source.as_fd().as_raw_fd();
            let trust_fd = self.trust_root.as_fd().as_raw_fd();
            let channel_fd = connector_channel.as_fd().as_raw_fd();
            let control_fd = connector_control.as_fd().as_raw_fd();
            let bootstrap = ConnectorBootstrap {
                plan_descriptor: u32::try_from(plan_fd)
                    .map_err(|_| ConnectorProcessError::BootstrapInvalid)?,
                trust_root_descriptor: u32::try_from(trust_fd)
                    .map_err(|_| ConnectorProcessError::BootstrapInvalid)?,
                channel_descriptor: u32::try_from(channel_fd)
                    .map_err(|_| ConnectorProcessError::BootstrapInvalid)?,
                control_descriptor: u32::try_from(control_fd)
                    .map_err(|_| ConnectorProcessError::BootstrapInvalid)?,
                execution_id: self.execution_id,
                policy_digest: self.policy_digest,
                process_generation: self.process_generation,
                channel_id: self.channel_id,
                plan_digest: self.plan_source.identity().digest(),
                trust_root_digest: self.trust_root.identity().digest(),
                connector_digest: self.connector.identity().digest(),
                runtime_closure_digest: self.runtime_closure_digest,
                resolver_configuration_digest: self.resolver_configuration.identity().digest(),
            };
            let mut command = Command::new(format!("/proc/self/fd/{connector_fd}"));
            command
                .args(bootstrap_arguments(bootstrap))
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            crate::sys::inherit_only_descriptors_for_exec(
                &mut command,
                vec![plan_fd, trust_fd, channel_fd, control_fd],
                vec![connector_fd],
            )
            .map_err(|_| ConnectorProcessError::BootstrapInvalid)?;
            require_before_deadline(setup_deadline)?;
            let child = command.spawn().map_err(|_| ConnectorProcessError::Spawn)?;
            drop(connector_control);
            drop(connector_channel);
            let mut process = ConnectorProcessGuard {
                child: Some(child),
                control: Some(supervisor_control),
                reaper,
            };
            let packet = process.receive_before(setup_deadline)?;
            match decode_report(&packet)? {
                ConnectorReport::Ready(ready) => {
                    let ready = *ready;
                    require_ready_binding(
                        ready,
                        self.execution_id,
                        self.policy_digest,
                        self.process_generation,
                        self.channel_id,
                        setup_binding_digest(
                            self.execution_id,
                            self.policy_digest,
                            self.process_generation,
                            self.channel_id,
                            self.plan_source.identity().digest(),
                            self.trust_root.identity().digest(),
                            self.connector.identity().digest(),
                            self.runtime_closure_digest,
                            self.resolver_configuration.identity().digest(),
                        ),
                    )?;
                    require_before_deadline(setup_deadline)?;
                    // SAFETY: the descriptor is uniquely owned by `child_channel`
                    // and UnixStream takes that ownership exactly once.
                    let channel = UnixStream::from(child_channel);
                    let terminal_deadline = Instant::now()
                        .checked_add(Duration::from_millis(
                            self.plan.service_session().limits().session_time_ms(),
                        ))
                        .ok_or(ConnectorProcessError::Timeout)?;
                    Ok(ReadyConnectorProcess {
                        process,
                        channel: Some(channel),
                        ready,
                        terminal_deadline,
                        child_to_service_limit: self
                            .plan
                            .service_session()
                            .limits()
                            .child_to_service_bytes(),
                        service_to_child_limit: self
                            .plan
                            .service_session()
                            .limits()
                            .service_to_child_bytes(),
                    })
                }
                ConnectorReport::Failure(failure) => {
                    if failure.stage() == ConnectorFailureStage::Channel {
                        return Err(ConnectorProcessError::Protocol);
                    }
                    process.reap_before(false, setup_deadline)?;
                    Err(ConnectorProcessError::ConnectorFailed(failure))
                }
                ConnectorReport::Terminal(_) => Err(ConnectorProcessError::Protocol),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            Err(ConnectorProcessError::UnsupportedOperatingSystem)
        }
    }
}

/// Owns one authenticated connector before child-channel transfer.
pub struct ReadyConnectorProcess {
    #[cfg(target_os = "linux")]
    process: ConnectorProcessGuard,
    #[cfg(target_os = "linux")]
    channel: Option<std::os::unix::net::UnixStream>,
    ready: ConnectorReady,
    terminal_deadline: Instant,
    child_to_service_limit: u64,
    service_to_child_limit: u64,
}

impl ReadyConnectorProcess {
    /// Returns the authenticated readiness observation.
    #[must_use]
    pub const fn ready(&self) -> ConnectorReady {
        self.ready
    }

    /// Transfers the only child-side stream endpoint for later launcher release.
    #[cfg(target_os = "linux")]
    pub fn take_child_channel(
        &mut self,
    ) -> Result<std::os::unix::net::UnixStream, ConnectorProcessError> {
        self.channel
            .take()
            .ok_or(ConnectorProcessError::ChannelAlreadyTransferred)
    }

    /// Waits for the bounded terminal report and reaps the connector.
    pub fn finish(mut self) -> Result<ConnectorTerminal, ConnectorProcessError> {
        #[cfg(target_os = "linux")]
        {
            self.channel.take();
            require_before_deadline(self.terminal_deadline)?;
            let packet = self.process.receive_before(self.terminal_deadline)?;
            match decode_report(&packet)? {
                ConnectorReport::Terminal(terminal) => {
                    self.process.reap_before(true, self.terminal_deadline)?;
                    validate_terminal(
                        terminal,
                        self.ready,
                        self.child_to_service_limit,
                        self.service_to_child_limit,
                    )?;
                    require_before_deadline(self.terminal_deadline)?;
                    Ok(terminal)
                }
                ConnectorReport::Failure(failure) => {
                    if failure.stage() != ConnectorFailureStage::Channel {
                        return Err(ConnectorProcessError::Protocol);
                    }
                    self.process.reap_before(false, self.terminal_deadline)?;
                    Err(ConnectorProcessError::ConnectorFailed(failure))
                }
                ConnectorReport::Ready(_) => Err(ConnectorProcessError::Protocol),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(ConnectorProcessError::UnsupportedOperatingSystem)
        }
    }
}

#[cfg(target_os = "linux")]
struct ConnectorProcessGuard {
    child: Option<std::process::Child>,
    control: Option<std::os::fd::OwnedFd>,
    reaper: std::sync::mpsc::Sender<std::process::Child>,
}

#[cfg(target_os = "linux")]
impl ConnectorProcessGuard {
    fn receive_before(&self, deadline: Instant) -> Result<Vec<u8>, ConnectorProcessError> {
        use std::os::fd::AsRawFd as _;

        let timeout = remaining_before(deadline)?;
        let descriptor = self
            .control
            .as_ref()
            .ok_or(ConnectorProcessError::Protocol)?
            .as_raw_fd();
        if !crate::sys::wait_readable(descriptor, timeout)
            .map_err(|_| ConnectorProcessError::Protocol)?
        {
            return Err(ConnectorProcessError::Timeout);
        }
        let mut buffer = [0_u8; MAX_CONNECTOR_REPORT_BYTES + 1];
        let length = crate::sys::receive_packet(descriptor, &mut buffer)
            .map_err(|_| ConnectorProcessError::Protocol)?;
        require_before_deadline(deadline)?;
        if length == 0 || length > MAX_CONNECTOR_REPORT_BYTES {
            return Err(ConnectorProcessError::Protocol);
        }
        Ok(buffer[..length].to_vec())
    }

    fn reap_before(
        &mut self,
        expected_success: bool,
        deadline: Instant,
    ) -> Result<(), ConnectorProcessError> {
        loop {
            require_before_deadline(deadline)?;
            let status = self
                .child
                .as_mut()
                .ok_or(ConnectorProcessError::Wait)?
                .try_wait()
                .map_err(|_| ConnectorProcessError::Wait)?;
            require_before_deadline(deadline)?;
            if let Some(status) = status {
                self.child.take();
                self.control.take();
                return if status.success() == expected_success {
                    Ok(())
                } else {
                    Err(ConnectorProcessError::Exit)
                };
            }
            let remaining = remaining_before(deadline)?;
            std::thread::sleep(remaining.min(Duration::from_millis(1)));
        }
    }

    fn terminate_without_blocking(&mut self) {
        self.control.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            if self.reaper.send(child).is_err() {
                std::process::abort();
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ConnectorProcessGuard {
    fn drop(&mut self) {
        self.terminate_without_blocking();
    }
}

fn remaining_before(deadline: Instant) -> Result<Duration, ConnectorProcessError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(ConnectorProcessError::Timeout)
}

fn require_before_deadline(deadline: Instant) -> Result<(), ConnectorProcessError> {
    remaining_before(deadline).map(|_| ())
}

#[cfg(target_os = "linux")]
type ConnectorReaperSender = std::sync::mpsc::Sender<std::process::Child>;

#[cfg(target_os = "linux")]
fn connector_reaper_sender() -> Result<ConnectorReaperSender, ConnectorProcessError> {
    use std::sync::OnceLock;
    use std::sync::mpsc;

    static REAPER: OnceLock<Option<ConnectorReaperSender>> = OnceLock::new();
    REAPER
        .get_or_init(|| {
            let (sender, receiver) = mpsc::channel::<std::process::Child>();
            std::thread::Builder::new()
                .name("pbr-connector-reaper".to_owned())
                .spawn(move || {
                    while let Ok(mut child) = receiver.recv() {
                        let _ = child.wait();
                    }
                })
                .ok()
                .map(|_| sender)
        })
        .clone()
        .ok_or(ConnectorProcessError::ReaperUnavailable)
}

/// Runs the connector engine from inherited descriptors.
pub fn run_connector_process(bootstrap: ConnectorBootstrap) -> Result<(), ConnectorProcessError> {
    #[cfg(target_os = "linux")]
    {
        use std::fs::File;
        use std::os::fd::AsRawFd as _;
        use std::os::unix::net::UnixStream;

        let control_fd = take_inherited(bootstrap.control_descriptor)?;
        let inherited = (|| {
            Ok::<_, ConnectorProcessError>((
                take_inherited(bootstrap.plan_descriptor)?,
                take_inherited(bootstrap.trust_root_descriptor)?,
                take_inherited(bootstrap.channel_descriptor)?,
            ))
        })();
        let (plan_fd, trust_fd, channel_fd) = match inherited {
            Ok(descriptors) => descriptors,
            Err(error) => {
                send_failure(control_fd.as_raw_fd(), ConnectorFailureStage::Bootstrap, 1)?;
                return Err(error);
            }
        };
        let plan_bytes = match read_inherited_file(File::from(plan_fd), MAX_PLAN_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => {
                send_failure(control_fd.as_raw_fd(), ConnectorFailureStage::Bootstrap, 2)?;
                return Err(error);
            }
        };
        let trust_root_bytes = match read_inherited_file(File::from(trust_fd), MAX_TRUST_ROOT_BYTES)
        {
            Ok(bytes) => bytes,
            Err(error) => {
                send_failure(control_fd.as_raw_fd(), ConnectorFailureStage::Bootstrap, 3)?;
                return Err(error);
            }
        };
        if digest_bytes(&plan_bytes) != bootstrap.plan_digest
            || digest_bytes(&trust_root_bytes) != bootstrap.trust_root_digest
        {
            send_failure(control_fd.as_raw_fd(), ConnectorFailureStage::Bootstrap, 4)?;
            return Err(ConnectorProcessError::ArtifactIdentityDrift);
        }
        let plan = match parse_service_execution_plan(&plan_bytes) {
            Ok(plan) => plan,
            Err(_) => {
                send_failure(control_fd.as_raw_fd(), ConnectorFailureStage::Bootstrap, 5)?;
                return Err(ConnectorProcessError::PlanInvalid);
            }
        };
        let resolution = match proofbound_runtime_connector::resolve_service(plan.service_session())
        {
            Ok(resolution) => resolution,
            Err(error) => {
                send_failure(
                    control_fd.as_raw_fd(),
                    ConnectorFailureStage::Resolution,
                    dns_error_code(error),
                )?;
                return Err(ConnectorProcessError::Engine);
            }
        };
        let dns_observation_digest = digest_dns_observation(&resolution);
        let session = match proofbound_runtime_connector::authenticate_service(
            &resolution,
            &trust_root_bytes,
        ) {
            Ok(session) => session,
            Err(error) => {
                send_failure(
                    control_fd.as_raw_fd(),
                    ConnectorFailureStage::Authentication,
                    tls_error_code(error.kind()),
                )?;
                return Err(ConnectorProcessError::Engine);
            }
        };
        let ready = ready_observation(
            bootstrap,
            dns_observation_digest,
            plan.service_session().port(),
            &session,
        );
        crate::sys::send_packet(control_fd.as_raw_fd(), &encode_ready(ready))
            .map_err(|_| ConnectorProcessError::Protocol)?;
        // SAFETY: the descriptor is uniquely owned by `channel_fd` and
        // UnixStream takes that ownership exactly once.
        let channel = UnixStream::from(channel_fd);
        let traffic =
            match proofbound_runtime_connector::proxy_authenticated_channel(session, channel) {
                Ok(traffic) => traffic,
                Err(error) => {
                    send_failure(
                        control_fd.as_raw_fd(),
                        ConnectorFailureStage::Channel,
                        channel_error_code(error),
                    )?;
                    return Err(ConnectorProcessError::Engine);
                }
            };
        let terminal = ConnectorTerminal {
            child_to_service_bytes: traffic.child_to_service_bytes(),
            service_to_child_bytes: traffic.service_to_child_bytes(),
            active_ns: traffic.active_ns(),
            closed_ns: traffic.closed_ns(),
        };
        crate::sys::send_packet(control_fd.as_raw_fd(), &encode_terminal(terminal))
            .map_err(|_| ConnectorProcessError::Protocol)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = bootstrap;
        Err(ConnectorProcessError::UnsupportedOperatingSystem)
    }
}

/// Identifies one fail-closed connector-process error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorProcessError {
    /// The host is not Linux.
    UnsupportedOperatingSystem,
    /// A service-support path was not canonical and absolute.
    ArtifactPath,
    /// A service-support file could not be opened.
    ArtifactUnavailable,
    /// A service-support artifact had the wrong role.
    ArtifactRole,
    /// A service-support file could not be identified.
    ArtifactIdentity,
    /// A retained service-support identity changed before use.
    ArtifactIdentityDrift,
    /// An input artifact exceeded its closed byte bound.
    ArtifactTooLarge,
    /// The connector executable had no execute permission bit.
    ConnectorNotExecutable,
    /// The connector executable was not a supported ELF image.
    ConnectorExecutableInvalid,
    /// A dynamic connector's `PT_INTERP` pathname was not registered.
    ConnectorLoaderMissing,
    /// The service execution plan was invalid.
    PlanInvalid,
    /// A declared path or identity binding did not match.
    BindingInvalid,
    /// The connector bootstrap vocabulary was invalid.
    BootstrapInvalid,
    /// A private connector channel could not be created.
    Channel,
    /// The connector reaper could not be established before process creation.
    ReaperUnavailable,
    /// The retained connector process could not be spawned.
    Spawn,
    /// The connector did not report before its declared deadline.
    Timeout,
    /// A connector control packet was absent, malformed, or out of order.
    Protocol,
    /// The connector reported one typed terminal failure.
    ConnectorFailed(ConnectorFailure),
    /// The connector engine failed after reporting its typed reason.
    Engine,
    /// The child-side channel was already transferred.
    ChannelAlreadyTransferred,
    /// The connector process could not be waited for.
    Wait,
    /// The connector exited unsuccessfully after a terminal report.
    Exit,
}

impl ConnectorProcessError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "network.connector.os.unsupported",
            Self::ArtifactPath => "network.connector.artifact.path-invalid",
            Self::ArtifactUnavailable => "network.connector.artifact.unavailable",
            Self::ArtifactRole => "network.connector.artifact.role-invalid",
            Self::ArtifactIdentity => "network.connector.artifact.identity-unavailable",
            Self::ArtifactIdentityDrift => "network.connector.artifact.identity-drift",
            Self::ArtifactTooLarge => "network.connector.artifact.too-large",
            Self::ConnectorNotExecutable => "network.connector.executable.mode-missing",
            Self::ConnectorExecutableInvalid => "network.connector.executable.invalid",
            Self::ConnectorLoaderMissing => "network.connector.loader.missing",
            Self::PlanInvalid => "network.connector.plan.invalid",
            Self::BindingInvalid => "network.connector.binding.invalid",
            Self::BootstrapInvalid => "network.connector.bootstrap.invalid",
            Self::Channel => "network.connector.channel.failed",
            Self::ReaperUnavailable => "network.connector.reaper.unavailable",
            Self::Spawn => "network.connector.spawn.failed",
            Self::Timeout => "network.connector.timeout",
            Self::Protocol => "network.connector.protocol.invalid",
            Self::ConnectorFailed(_) => "network.connector.reported-failure",
            Self::Engine => "network.connector.engine.failed",
            Self::ChannelAlreadyTransferred => "network.connector.channel.already-transferred",
            Self::Wait => "network.connector.wait.failed",
            Self::Exit => "network.connector.exit.failed",
        }
    }
}

impl fmt::Display for ConnectorProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ConnectorProcessError {}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ConnectorReport {
    Ready(Box<ConnectorReady>),
    Terminal(ConnectorTerminal),
    Failure(ConnectorFailure),
}

#[cfg(target_os = "linux")]
fn identify_service_descriptor(
    descriptor: &std::os::fd::OwnedFd,
    role: ServiceArtifactRole,
) -> Result<ServiceArtifactIdentity, ConnectorProcessError> {
    let measured = crate::resolve::identify_descriptor(descriptor, ArtifactRole::RuntimeLibrary)
        .map_err(map_resolution)?;
    Ok(ServiceArtifactIdentity {
        role,
        digest: measured.digest(),
        size: measured.size(),
        mode: measured.mode(),
    })
}

fn require_canonical_absolute_path(path: &Path) -> Result<(), ConnectorProcessError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        Err(ConnectorProcessError::ArtifactPath)
    } else {
        Ok(())
    }
}

fn require_service_role(
    artifact: &ResolvedServiceArtifact,
    expected: ServiceArtifactRole,
) -> Result<(), ConnectorProcessError> {
    if artifact.identity().role() == expected {
        Ok(())
    } else {
        Err(ConnectorProcessError::ArtifactRole)
    }
}

fn validate_declared_artifacts(
    plan: &ServiceExecutionPlan,
    connector: &ResolvedServiceArtifact,
    trust_root: &ResolvedServiceArtifact,
    resolver_configuration: &ResolvedServiceArtifact,
    runtime_closure: &[ResolvedServiceArtifact],
) -> Result<(), ConnectorProcessError> {
    let session = plan.service_session();
    if connector.requested_path() != Path::new(session.connector_executable().as_str())
        || trust_root.requested_path() != Path::new(session.tls().trust_root_set().as_str())
        || resolver_configuration.requested_path()
            != Path::new(session.resolution().configuration().as_str())
        || runtime_closure.len() != session.connector_runtime_read().len()
        || runtime_closure
            .iter()
            .zip(session.connector_runtime_read())
            .any(|(artifact, declared)| artifact.requested_path() != Path::new(declared.as_str()))
    {
        return Err(ConnectorProcessError::BindingInvalid);
    }
    Ok(())
}

fn digest_runtime_closure(runtime_closure: &[ResolvedServiceArtifact]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"proofbound-runtime-connector-closure/1\0");
    for artifact in runtime_closure {
        let identity = artifact.identity();
        hasher.update(identity.role().as_str().as_bytes());
        hasher.update([0]);
        hasher.update(identity.digest().as_bytes());
        hasher.update(identity.size().to_be_bytes());
        hasher.update(identity.mode().get().to_be_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn bootstrap_arguments(bootstrap: ConnectorBootstrap) -> Vec<String> {
    vec![
        "--connector-protocol".to_owned(),
        CONNECTOR_PROTOCOL.to_owned(),
        "--plan-fd".to_owned(),
        bootstrap.plan_descriptor.to_string(),
        "--trust-root-fd".to_owned(),
        bootstrap.trust_root_descriptor.to_string(),
        "--channel-fd".to_owned(),
        bootstrap.channel_descriptor.to_string(),
        "--control-fd".to_owned(),
        bootstrap.control_descriptor.to_string(),
        "--execution-id".to_owned(),
        hex(bootstrap.execution_id.as_bytes()),
        "--policy-sha256".to_owned(),
        bootstrap.policy_digest.to_hex(),
        "--process-generation".to_owned(),
        bootstrap.process_generation.get().to_string(),
        "--channel-id".to_owned(),
        hex(bootstrap.channel_id.as_bytes()),
        "--plan-sha256".to_owned(),
        bootstrap.plan_digest.to_hex(),
        "--trust-root-sha256".to_owned(),
        bootstrap.trust_root_digest.to_hex(),
        "--connector-sha256".to_owned(),
        bootstrap.connector_digest.to_hex(),
        "--runtime-closure-sha256".to_owned(),
        bootstrap.runtime_closure_digest.to_hex(),
        "--resolver-configuration-sha256".to_owned(),
        bootstrap.resolver_configuration_digest.to_hex(),
    ]
}

#[cfg(target_os = "linux")]
fn take_inherited(descriptor: u32) -> Result<std::os::fd::OwnedFd, ConnectorProcessError> {
    let descriptor =
        i32::try_from(descriptor).map_err(|_| ConnectorProcessError::BootstrapInvalid)?;
    crate::sys::take_inherited_descriptor(descriptor)
        .map_err(|_| ConnectorProcessError::BootstrapInvalid)
}

#[cfg(target_os = "linux")]
fn read_inherited_file(
    file: std::fs::File,
    maximum: u64,
) -> Result<Vec<u8>, ConnectorProcessError> {
    use std::io::Read as _;

    let maximum = usize::try_from(maximum).map_err(|_| ConnectorProcessError::ArtifactTooLarge)?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ConnectorProcessError::ArtifactIdentity)?;
    if bytes.len() > maximum {
        Err(ConnectorProcessError::ArtifactTooLarge)
    } else {
        Ok(bytes)
    }
}

fn ready_observation(
    bootstrap: ConnectorBootstrap,
    dns_observation_digest: Sha256Digest,
    port: proofbound_runtime_core::TcpPort,
    session: &proofbound_runtime_connector::AuthenticatedTlsSession,
) -> ConnectorReady {
    let tls = session.observation();
    ConnectorReady {
        execution_id: bootstrap.execution_id,
        policy_digest: bootstrap.policy_digest,
        process_generation: bootstrap.process_generation,
        channel_id: bootstrap.channel_id,
        setup_binding_digest: setup_binding_digest(
            bootstrap.execution_id,
            bootstrap.policy_digest,
            bootstrap.process_generation,
            bootstrap.channel_id,
            bootstrap.plan_digest,
            bootstrap.trust_root_digest,
            bootstrap.connector_digest,
            bootstrap.runtime_closure_digest,
            bootstrap.resolver_configuration_digest,
        ),
        dns_observation_digest,
        selected_endpoint: session.selected_answer().endpoint(port),
        tls_version: tls.version(),
        tls_implementation_digest: tls.implementation_identity(),
        certificate_chain_digest: tls.certificate_chain_identity(),
        handshake_bytes: tls.handshake_bytes(),
        authenticated_ns: tls.authenticated_ns(),
    }
}

fn encode_endpoint(endpoint: std::net::SocketAddr) -> [u8; 19] {
    let mut bytes = [0_u8; 19];
    match endpoint.ip() {
        std::net::IpAddr::V4(address) => {
            bytes[0] = 4;
            bytes[1..5].copy_from_slice(&address.octets());
        }
        std::net::IpAddr::V6(address) => {
            bytes[0] = 6;
            bytes[1..17].copy_from_slice(&address.octets());
        }
    }
    bytes[17..19].copy_from_slice(&endpoint.port().to_be_bytes());
    bytes
}

fn digest_dns_observation(
    resolution: &proofbound_runtime_connector::DnsResolution,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"proofbound-runtime-dns-observation/1\0");
    for message in resolution.messages() {
        hasher.update(message.identity().as_bytes());
        hasher.update(message.size().to_be_bytes());
        hasher.update(message.observed_ns().to_be_bytes());
    }
    for link in resolution.cname_chain() {
        append_text(&mut hasher, link.owner().as_str());
        append_text(&mut hasher, link.target().as_str());
        hasher.update(link.message_identity().as_bytes());
        hasher.update(link.ttl_seconds().to_be_bytes());
        hasher.update(link.expires_ns().to_be_bytes());
    }
    for answer in resolution.answers() {
        append_text(&mut hasher, answer.name().as_str());
        hasher.update(encode_endpoint(answer.endpoint(resolution.port())));
        hasher.update(answer.message_identity().as_bytes());
        hasher.update(answer.ttl_seconds().to_be_bytes());
        hasher.update(answer.record_expires_ns().to_be_bytes());
        hasher.update(answer.effective_expires_ns().to_be_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn append_text(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn encode_ready(ready: ConnectorReady) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(245);
    bytes.extend_from_slice(REPORT_MAGIC);
    bytes.push(READY_REPORT);
    bytes.extend_from_slice(ready.execution_id.as_bytes());
    bytes.extend_from_slice(ready.policy_digest.as_bytes());
    bytes.extend_from_slice(&ready.process_generation.get().to_be_bytes());
    bytes.extend_from_slice(ready.channel_id.as_bytes());
    bytes.extend_from_slice(ready.setup_binding_digest.as_bytes());
    bytes.extend_from_slice(ready.dns_observation_digest.as_bytes());
    bytes.extend_from_slice(&encode_endpoint(ready.selected_endpoint));
    bytes.push(match ready.tls_version {
        proofbound_runtime_connector::TlsVersion::Tls12 => 12,
        proofbound_runtime_connector::TlsVersion::Tls13 => 13,
    });
    bytes.extend_from_slice(ready.tls_implementation_digest.as_bytes());
    bytes.extend_from_slice(ready.certificate_chain_digest.as_bytes());
    bytes.extend_from_slice(&ready.handshake_bytes.to_be_bytes());
    bytes.extend_from_slice(&ready.authenticated_ns.to_be_bytes());
    bytes
}

fn encode_terminal(terminal: ConnectorTerminal) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(41);
    bytes.extend_from_slice(REPORT_MAGIC);
    bytes.push(TERMINAL_REPORT);
    bytes.extend_from_slice(&terminal.child_to_service_bytes.to_be_bytes());
    bytes.extend_from_slice(&terminal.service_to_child_bytes.to_be_bytes());
    bytes.extend_from_slice(&terminal.active_ns.to_be_bytes());
    bytes.extend_from_slice(&terminal.closed_ns.to_be_bytes());
    bytes
}

fn encode_failure(failure: ConnectorFailure) -> [u8; 11] {
    let mut bytes = [0_u8; 11];
    bytes[..8].copy_from_slice(REPORT_MAGIC);
    bytes[8] = FAILURE_REPORT;
    bytes[9] = match failure.stage {
        ConnectorFailureStage::Bootstrap => 1,
        ConnectorFailureStage::Resolution => 2,
        ConnectorFailureStage::Authentication => 3,
        ConnectorFailureStage::Channel => 4,
    };
    bytes[10] = failure.code;
    bytes
}

fn decode_report(bytes: &[u8]) -> Result<ConnectorReport, ConnectorProcessError> {
    if bytes.get(..8) != Some(REPORT_MAGIC) {
        return Err(ConnectorProcessError::Protocol);
    }
    match bytes.get(8).copied() {
        Some(READY_REPORT) if bytes.len() == 245 => {
            let execution_id = ExecutionId::from_bytes(array_at(bytes, 9)?)
                .map_err(|_| ConnectorProcessError::Protocol)?;
            Ok(ConnectorReport::Ready(Box::new(ConnectorReady {
                execution_id,
                policy_digest: Sha256Digest::from_bytes(array_at(bytes, 25)?),
                process_generation: ConnectorProcessGeneration::new(u64::from_be_bytes(array_at(
                    bytes, 57,
                )?))
                .map_err(|_| ConnectorProcessError::Protocol)?,
                channel_id: ServiceChannelId::new(array_at(bytes, 65)?)
                    .map_err(|_| ConnectorProcessError::Protocol)?,
                setup_binding_digest: Sha256Digest::from_bytes(array_at(bytes, 81)?),
                dns_observation_digest: Sha256Digest::from_bytes(array_at(bytes, 113)?),
                selected_endpoint: decode_endpoint(array_at(bytes, 145)?)?,
                tls_version: match bytes[164] {
                    12 => proofbound_runtime_connector::TlsVersion::Tls12,
                    13 => proofbound_runtime_connector::TlsVersion::Tls13,
                    _ => return Err(ConnectorProcessError::Protocol),
                },
                tls_implementation_digest: Sha256Digest::from_bytes(array_at(bytes, 165)?),
                certificate_chain_digest: Sha256Digest::from_bytes(array_at(bytes, 197)?),
                handshake_bytes: u64::from_be_bytes(array_at(bytes, 229)?),
                authenticated_ns: u64::from_be_bytes(array_at(bytes, 237)?),
            })))
        }
        Some(TERMINAL_REPORT) if bytes.len() == 41 => {
            Ok(ConnectorReport::Terminal(ConnectorTerminal {
                child_to_service_bytes: u64::from_be_bytes(array_at(bytes, 9)?),
                service_to_child_bytes: u64::from_be_bytes(array_at(bytes, 17)?),
                active_ns: u64::from_be_bytes(array_at(bytes, 25)?),
                closed_ns: u64::from_be_bytes(array_at(bytes, 33)?),
            }))
        }
        Some(FAILURE_REPORT) if bytes.len() == 11 => {
            let stage = match bytes[9] {
                1 => ConnectorFailureStage::Bootstrap,
                2 => ConnectorFailureStage::Resolution,
                3 => ConnectorFailureStage::Authentication,
                4 => ConnectorFailureStage::Channel,
                _ => return Err(ConnectorProcessError::Protocol),
            };
            if !valid_failure_code(stage, bytes[10]) {
                return Err(ConnectorProcessError::Protocol);
            }
            Ok(ConnectorReport::Failure(ConnectorFailure {
                stage,
                code: bytes[10],
            }))
        }
        _ => Err(ConnectorProcessError::Protocol),
    }
}

fn valid_failure_code(stage: ConnectorFailureStage, code: u8) -> bool {
    match stage {
        ConnectorFailureStage::Bootstrap => (1..=5).contains(&code),
        ConnectorFailureStage::Resolution => (1..=12).contains(&code),
        ConnectorFailureStage::Authentication => (1..=19).contains(&code),
        ConnectorFailureStage::Channel => (1..=4).contains(&code) || (33..=51).contains(&code),
    }
}

fn require_ready_binding(
    ready: ConnectorReady,
    execution_id: ExecutionId,
    policy_digest: Sha256Digest,
    process_generation: ConnectorProcessGeneration,
    channel_id: ServiceChannelId,
    expected_setup_binding: Sha256Digest,
) -> Result<(), ConnectorProcessError> {
    if ready.execution_id != execution_id
        || ready.policy_digest != policy_digest
        || ready.process_generation != process_generation
        || ready.channel_id != channel_id
        || ready.setup_binding_digest != expected_setup_binding
        || ready.selected_endpoint.port() == 0
    {
        Err(ConnectorProcessError::BindingInvalid)
    } else {
        Ok(())
    }
}

fn decode_endpoint(bytes: [u8; 19]) -> Result<SocketAddr, ConnectorProcessError> {
    let port = u16::from_be_bytes([bytes[17], bytes[18]]);
    if port == 0 {
        return Err(ConnectorProcessError::Protocol);
    }
    let address = match bytes[0] {
        4 if bytes[5..17] == [0; 12] => {
            IpAddr::V4(Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]))
        }
        6 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&bytes[1..17]).map_err(|_| ConnectorProcessError::Protocol)?,
        )),
        _ => return Err(ConnectorProcessError::Protocol),
    };
    Ok(SocketAddr::new(address, port))
}

fn validate_terminal(
    terminal: ConnectorTerminal,
    ready: ConnectorReady,
    child_to_service_limit: u64,
    service_to_child_limit: u64,
) -> Result<(), ConnectorProcessError> {
    if terminal.child_to_service_bytes > child_to_service_limit
        || terminal.service_to_child_bytes > service_to_child_limit
        || terminal.active_ns != ready.authenticated_ns
        || terminal.closed_ns < terminal.active_ns
    {
        Err(ConnectorProcessError::BindingInvalid)
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn setup_binding_digest(
    execution_id: ExecutionId,
    policy_digest: Sha256Digest,
    process_generation: ConnectorProcessGeneration,
    channel_id: ServiceChannelId,
    plan_digest: Sha256Digest,
    trust_root_digest: Sha256Digest,
    connector_digest: Sha256Digest,
    runtime_closure_digest: Sha256Digest,
    resolver_configuration_digest: Sha256Digest,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"proofbound-runtime-connector-setup/1\0");
    hasher.update(execution_id.as_bytes());
    hasher.update(policy_digest.as_bytes());
    hasher.update(process_generation.get().to_be_bytes());
    hasher.update(channel_id.as_bytes());
    hasher.update(plan_digest.as_bytes());
    hasher.update(trust_root_digest.as_bytes());
    hasher.update(connector_digest.as_bytes());
    hasher.update(runtime_closure_digest.as_bytes());
    hasher.update(resolver_configuration_digest.as_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn send_failure(
    descriptor: i32,
    stage: ConnectorFailureStage,
    code: u8,
) -> Result<(), ConnectorProcessError> {
    crate::sys::send_packet(
        descriptor,
        &encode_failure(ConnectorFailure { stage, code }),
    )
    .map_err(|_| ConnectorProcessError::Protocol)
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn parse_digest(value: &str) -> Result<Sha256Digest, ConnectorProcessError> {
    Sha256Digest::parse_hex(value).map_err(|_| ConnectorProcessError::BootstrapInvalid)
}

fn parse_hex_array<const N: usize>(value: &str) -> Result<[u8; N], ConnectorProcessError> {
    let input = value.as_bytes();
    if input.len() != N * 2 {
        return Err(ConnectorProcessError::BootstrapInvalid);
    }
    let mut bytes = [0_u8; N];
    for (index, output) in bytes.iter_mut().enumerate() {
        *output =
            (lower_hex_nibble(input[index * 2])? << 4) | lower_hex_nibble(input[index * 2 + 1])?;
    }
    Ok(bytes)
}

fn lower_hex_nibble(value: u8) -> Result<u8, ConnectorProcessError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ConnectorProcessError::BootstrapInvalid),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ConnectorProcessError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(ConnectorProcessError::Protocol)
}

fn map_resolution(error: ResolutionError) -> ConnectorProcessError {
    match error {
        ResolutionError::UnsupportedOperatingSystem => {
            ConnectorProcessError::UnsupportedOperatingSystem
        }
        ResolutionError::IdentityDrift => ConnectorProcessError::ArtifactIdentityDrift,
        ResolutionError::ForbiddenFileKind
        | ResolutionError::IdentityUnavailable
        | ResolutionError::IdentityMismatch => ConnectorProcessError::ArtifactIdentity,
        _ => ConnectorProcessError::ArtifactUnavailable,
    }
}

fn dns_error_code(error: proofbound_runtime_connector::DnsError) -> u8 {
    use proofbound_runtime_connector::DnsError;
    match error {
        DnsError::RandomUnavailable => 1,
        DnsError::ResolverUnavailable => 2,
        DnsError::RequestFailed => 3,
        DnsError::ResponseFailed => 4,
        DnsError::ResponseTooLarge => 5,
        DnsError::MessageLimit => 6,
        DnsError::Deadline => 7,
        DnsError::MalformedResponse => 8,
        DnsError::ResolverFailure => 9,
        DnsError::InvalidCnameChain => 10,
        DnsError::InvalidAnswerSet => 11,
        DnsError::ExpiredAnswer => 12,
    }
}

fn tls_error_code(error: proofbound_runtime_connector::TlsError) -> u8 {
    use proofbound_runtime_connector::TlsError;
    match error {
        TlsError::EndpointUnavailable => 1,
        TlsError::EndpointAttemptLimit => 2,
        TlsError::EndpointAttemptDeadline => 3,
        TlsError::SetupDeadline => 4,
        TlsError::AnswerExpired => 5,
        TlsError::TrustRootSetInvalid => 6,
        TlsError::ServiceNameInvalid => 7,
        TlsError::ServiceNameMismatch => 8,
        TlsError::Configuration => 9,
        TlsError::Authentication => 10,
        TlsError::Resumption => 11,
        TlsError::Version => 12,
        TlsError::HandshakeLimit => 13,
        TlsError::CertificateChainMissing => 14,
        TlsError::SessionDeadline => 15,
        TlsError::ChildToServiceLimit => 16,
        TlsError::ServiceToChildLimit => 17,
        TlsError::SessionIo => 18,
        TlsError::PrematureClose => 19,
    }
}

fn channel_error_code(error: proofbound_runtime_connector::ChannelError) -> u8 {
    match error {
        proofbound_runtime_connector::ChannelError::UnsupportedOperatingSystem => 1,
        proofbound_runtime_connector::ChannelError::Configuration => 2,
        proofbound_runtime_connector::ChannelError::ChildRead => 3,
        proofbound_runtime_connector::ChannelError::ChildWrite => 4,
        proofbound_runtime_connector::ChannelError::Tls(error) => {
            32_u8.saturating_add(tls_error_code(error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execution_id() -> ExecutionId {
        ExecutionId::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
        .expect("fixture identifier is valid")
    }

    fn generation(value: u64) -> ConnectorProcessGeneration {
        ConnectorProcessGeneration::new(value).expect("fixture generation is nonzero")
    }

    fn channel_id(byte: u8) -> ServiceChannelId {
        ServiceChannelId::new([byte; 16]).expect("fixture channel identity is nonzero")
    }

    #[test]
    fn bootstrap_is_closed_and_descriptor_set_is_unique() {
        let arguments = bootstrap_arguments(ConnectorBootstrap {
            plan_descriptor: 3,
            trust_root_descriptor: 4,
            channel_descriptor: 5,
            control_descriptor: 6,
            execution_id: execution_id(),
            policy_digest: Sha256Digest::from_bytes([1; 32]),
            process_generation: generation(7),
            channel_id: channel_id(2),
            plan_digest: Sha256Digest::from_bytes([3; 32]),
            trust_root_digest: Sha256Digest::from_bytes([4; 32]),
            connector_digest: Sha256Digest::from_bytes([5; 32]),
            runtime_closure_digest: Sha256Digest::from_bytes([6; 32]),
            resolver_configuration_digest: Sha256Digest::from_bytes([7; 32]),
        });
        assert!(parse_connector_bootstrap(&arguments).is_ok());
        let mut duplicate = arguments.clone();
        duplicate[5] = "3".to_owned();
        assert_eq!(
            parse_connector_bootstrap(&duplicate),
            Err(ConnectorProcessError::BootstrapInvalid)
        );
        let mut unknown = arguments;
        unknown[0] = "--unknown".to_owned();
        assert_eq!(
            parse_connector_bootstrap(&unknown),
            Err(ConnectorProcessError::BootstrapInvalid)
        );
    }

    #[test]
    fn report_decoder_rejects_mutation_and_out_of_order_shapes() {
        let ready = ConnectorReady {
            execution_id: execution_id(),
            policy_digest: Sha256Digest::from_bytes([1; 32]),
            process_generation: generation(1),
            channel_id: channel_id(2),
            setup_binding_digest: Sha256Digest::from_bytes([8; 32]),
            dns_observation_digest: Sha256Digest::from_bytes([3; 32]),
            selected_endpoint: "192.0.2.10:443".parse().expect("valid endpoint"),
            tls_version: proofbound_runtime_connector::TlsVersion::Tls13,
            tls_implementation_digest: Sha256Digest::from_bytes([4; 32]),
            certificate_chain_digest: Sha256Digest::from_bytes([5; 32]),
            handshake_bytes: 8_192,
            authenticated_ns: 4_000,
        };
        let encoded = encode_ready(ready);
        assert_eq!(
            decode_report(&encoded),
            Ok(ConnectorReport::Ready(Box::new(ready)))
        );
        for index in [0, 8, 57, 164] {
            let mut mutated = encoded.clone();
            mutated[index] ^= 1;
            assert_ne!(
                decode_report(&mutated),
                Ok(ConnectorReport::Ready(Box::new(ready)))
            );
        }
        let mut noncanonical_endpoint = encoded.clone();
        noncanonical_endpoint[150] = 1;
        assert_eq!(
            decode_report(&noncanonical_endpoint),
            Err(ConnectorProcessError::Protocol)
        );
        let mut zero_port = encoded;
        zero_port[162] = 0;
        zero_port[163] = 0;
        assert_eq!(
            decode_report(&zero_port),
            Err(ConnectorProcessError::Protocol)
        );
        assert_eq!(
            decode_report(&encode_terminal(ConnectorTerminal {
                child_to_service_bytes: 1,
                service_to_child_bytes: 2,
                active_ns: 3,
                closed_ns: 4,
            })),
            Ok(ConnectorReport::Terminal(ConnectorTerminal {
                child_to_service_bytes: 1,
                service_to_child_bytes: 2,
                active_ns: 3,
                closed_ns: 4,
            }))
        );
    }

    #[test]
    fn ready_binding_rejects_each_identity_substitution() {
        let ready = ConnectorReady {
            execution_id: execution_id(),
            policy_digest: Sha256Digest::from_bytes([1; 32]),
            process_generation: generation(3),
            channel_id: channel_id(2),
            setup_binding_digest: Sha256Digest::from_bytes([8; 32]),
            dns_observation_digest: Sha256Digest::from_bytes([3; 32]),
            selected_endpoint: "[2001:db8::10]:443".parse().expect("valid endpoint"),
            tls_version: proofbound_runtime_connector::TlsVersion::Tls13,
            tls_implementation_digest: Sha256Digest::from_bytes([4; 32]),
            certificate_chain_digest: Sha256Digest::from_bytes([5; 32]),
            handshake_bytes: 8,
            authenticated_ns: 9,
        };
        assert!(
            require_ready_binding(
                ready,
                execution_id(),
                Sha256Digest::from_bytes([1; 32]),
                generation(3),
                channel_id(2),
                Sha256Digest::from_bytes([8; 32]),
            )
            .is_ok()
        );
        assert_eq!(
            require_ready_binding(
                ready,
                execution_id(),
                Sha256Digest::from_bytes([9; 32]),
                generation(3),
                channel_id(2),
                Sha256Digest::from_bytes([8; 32]),
            ),
            Err(ConnectorProcessError::BindingInvalid)
        );
        assert_eq!(
            require_ready_binding(
                ready,
                execution_id(),
                Sha256Digest::from_bytes([1; 32]),
                generation(4),
                channel_id(2),
                Sha256Digest::from_bytes([8; 32]),
            ),
            Err(ConnectorProcessError::BindingInvalid)
        );
        assert_eq!(
            require_ready_binding(
                ready,
                execution_id(),
                Sha256Digest::from_bytes([1; 32]),
                generation(3),
                channel_id(8),
                Sha256Digest::from_bytes([8; 32]),
            ),
            Err(ConnectorProcessError::BindingInvalid)
        );
        assert_eq!(
            require_ready_binding(
                ready,
                execution_id(),
                Sha256Digest::from_bytes([1; 32]),
                generation(3),
                channel_id(2),
                Sha256Digest::from_bytes([9; 32]),
            ),
            Err(ConnectorProcessError::BindingInvalid)
        );
    }

    #[test]
    fn terminal_report_must_match_ready_time_and_directional_limits() {
        let ready = ConnectorReady {
            execution_id: execution_id(),
            policy_digest: Sha256Digest::from_bytes([1; 32]),
            process_generation: generation(3),
            channel_id: channel_id(2),
            setup_binding_digest: Sha256Digest::from_bytes([8; 32]),
            dns_observation_digest: Sha256Digest::from_bytes([3; 32]),
            selected_endpoint: "192.0.2.10:443".parse().expect("valid endpoint"),
            tls_version: proofbound_runtime_connector::TlsVersion::Tls13,
            tls_implementation_digest: Sha256Digest::from_bytes([4; 32]),
            certificate_chain_digest: Sha256Digest::from_bytes([5; 32]),
            handshake_bytes: 8,
            authenticated_ns: 9,
        };
        let terminal = ConnectorTerminal {
            child_to_service_bytes: 10,
            service_to_child_bytes: 20,
            active_ns: 9,
            closed_ns: 30,
        };
        assert!(validate_terminal(terminal, ready, 10, 20).is_ok());
        for invalid in [
            ConnectorTerminal {
                child_to_service_bytes: 11,
                ..terminal
            },
            ConnectorTerminal {
                service_to_child_bytes: 21,
                ..terminal
            },
            ConnectorTerminal {
                active_ns: 8,
                ..terminal
            },
            ConnectorTerminal {
                closed_ns: 7,
                ..terminal
            },
        ] {
            assert_eq!(
                validate_terminal(invalid, ready, 10, 20),
                Err(ConnectorProcessError::BindingInvalid)
            );
        }
    }
}
