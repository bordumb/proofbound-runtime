#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use proofbound_runtime_core::{
    Architecture as ReceiptArchitecture, ArtifactIdentity, ArtifactRole, BoundaryRecord,
    EnvironmentName, ExecutionObservations, ExecutionOutcome, ExecutionPlan, ExecutionReceipt,
    ExecutionReceiptParts, FileAccess, FileMode, PathRole, PlatformIdentity,
    REQUIRED_RUNTIME_ASSUMPTIONS, ReceiptCommand, ReceiptPlan, ReceiptPolicy, ReceiptStreams,
    ResourceLimits, RuntimeIdentity, Sha256Digest, TrustedComputingBaseEntry,
    TrustedComputingBaseRole, compile_policy, normalize_authority, parse_execution_plan,
};
use proofbound_runtime_linux::{
    Architecture, CgroupError, ExecutionSetupError, FreshCgroup, FreshOutputRoot, InstallRequest,
    LandlockAccess, LauncherError, LauncherFilesystemRule, LauncherIdentity, OutputRootError,
    ProbeError, ResolutionError, ResolvedReadPath, RootedPathResolver, SupervisorError,
    compile_deny_network_program, fresh_execution_id, identify_external_artifact,
    probe_capabilities, supervise_launcher,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const INVALID_INPUT: u8 = 2;
const UNSUPPORTED_BOUNDARY: u8 = 3;
const IDENTITY_DRIFT: u8 = 4;
const LAUNCHER_FAILURE: u8 = 5;
const RECEIPT_FAILURE: u8 = 6;
const RUN_RESULT_SCHEMA: &str = "proofbound-runtime-run-result/1";
const NORMALIZED_PLAN_MODE: u16 = 0;
const POLICY_MODE: u16 = 0;
const STREAM_MODE: u16 = 0;
const ARGUMENT_DOMAIN: &[u8] = b"proofbound-runtime-arguments/1\n";
const POLICY_DOMAIN: &[u8] = b"proofbound-runtime-installed-policy/1\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RunError {
    exit_code: u8,
    code: &'static str,
}

impl RunError {
    pub(crate) const fn exit_code(self) -> u8 {
        self.exit_code
    }

    pub(crate) const fn code(self) -> &'static str {
        self.code
    }

    const fn invalid(code: &'static str) -> Self {
        Self {
            exit_code: INVALID_INPUT,
            code,
        }
    }

    const fn unsupported(code: &'static str) -> Self {
        Self {
            exit_code: UNSUPPORTED_BOUNDARY,
            code,
        }
    }

    const fn identity(code: &'static str) -> Self {
        Self {
            exit_code: IDENTITY_DRIFT,
            code,
        }
    }

    const fn launcher(code: &'static str) -> Self {
        Self {
            exit_code: LAUNCHER_FAILURE,
            code,
        }
    }

    const fn receipt(code: &'static str) -> Self {
        Self {
            exit_code: RECEIPT_FAILURE,
            code,
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn execute(
    _plan_path: &Path,
    _receipt_path: &Path,
    _cgroup_root: &Path,
) -> Result<Value, RunError> {
    Err(RunError::unsupported("execution.os.unsupported"))
}

#[cfg(target_os = "linux")]
pub(crate) fn execute(
    plan_path: &Path,
    receipt_path: &Path,
    cgroup_root: &Path,
) -> Result<Value, RunError> {
    use std::os::fd::AsRawFd as _;

    let receipt_path = prepare_receipt_path(receipt_path)?;
    let canonical_plan =
        fs::canonicalize(plan_path).map_err(|_| RunError::invalid("plan.input.read-failed"))?;
    let plan_source = identify_external_artifact(&canonical_plan, ArtifactRole::ExecutionPlan)
        .map_err(map_resolution)?;
    let plan_bytes = plan_source.read_bytes().map_err(map_resolution)?;
    let plan_text = core::str::from_utf8(&plan_bytes)
        .map_err(|_| RunError::invalid("plan.input.utf8-invalid"))?;
    let plan = parse_execution_plan(plan_text).map_err(|error| RunError::invalid(error.code()))?;
    let normalized = normalize_authority(plan.authority().clone())
        .map_err(|error| RunError::invalid(error.code()))?;
    let compiled = compile_policy(normalized.clone());
    let plan_root = canonical_plan
        .parent()
        .ok_or_else(|| RunError::invalid("plan.input.parent-unavailable"))?;
    let resolver = RootedPathResolver::open(plan_root).map_err(map_resolution)?;

    let supported = probe_capabilities(cgroup_root)
        .require_supported()
        .map_err(map_probe)?;
    let output_authority = compiled
        .filesystem()
        .rules()
        .iter()
        .find(|rule| rule.access() == FileAccess::Write && rule.role() == PathRole::OutputRoot)
        .ok_or_else(|| RunError::invalid("plan.authority.output-root.count"))?;
    let output_root =
        FreshOutputRoot::create(&resolver, output_authority.path()).map_err(map_output)?;
    if receipt_path.starts_with(output_root.resolved_target()) {
        return Err(RunError::invalid("receipt.path.child-writable"));
    }
    let working_directory = resolver
        .resolve_working_directory(plan.command().working_directory())
        .map_err(map_resolution)?;
    let executable = resolver
        .discover_executable(plan.command().executable(), supported.architecture())
        .map_err(map_resolution)?;
    let readable = resolve_read_authority(&resolver, &compiled)?;

    let current_executable = fs::canonicalize(
        std::env::current_exe().map_err(|_| RunError::identity("runtime.path.unavailable"))?,
    )
    .map_err(|_| RunError::identity("runtime.path.unavailable"))?;
    let launcher_path = current_executable
        .parent()
        .ok_or_else(|| RunError::identity("launcher.path.unavailable"))?
        .join("pbr-native-launcher");
    let launcher_path = fs::canonicalize(launcher_path)
        .map_err(|_| RunError::identity("launcher.path.unavailable"))?;
    let runtime_artifact =
        identify_external_artifact(&current_executable, ArtifactRole::RuntimeBinary)
            .map_err(map_resolution)?;
    let launcher_artifact =
        identify_external_artifact(&launcher_path, ArtifactRole::LauncherBinary)
            .map_err(map_resolution)?;

    let environment = collect_environment(compiled.environment())?;
    let arguments = execution_arguments(&plan);
    let argument_identity = arguments_identity(&arguments);
    let seccomp = compile_deny_network_program(compiled.network(), supported.architecture())
        .map_err(|error| RunError::launcher(error.code()))?;
    let normalized_bytes = serde_json::to_vec(
        &crate::plan::checked_plan_json(&plan).map_err(|error| RunError::invalid(error.code()))?,
    )
    .map_err(|_| RunError::receipt("receipt.normalized-plan.encoding-failed"))?;
    let normalized_identity = bytes_identity(
        ArtifactRole::NormalizedPlan,
        &normalized_bytes,
        NORMALIZED_PLAN_MODE,
    )?;
    let policy_identity = installed_policy_identity(
        &normalized_identity,
        &seccomp,
        &executable,
        &readable,
        &output_root,
        compiled.cgroup().limits(),
    )?;

    let execution_id = fresh_execution_id().map_err(map_execution_setup)?;
    let limits = compiled.cgroup().limits();
    let cgroup = FreshCgroup::create(supported.cgroup_v2(), execution_id, limits.processes())
        .map_err(map_cgroup)?;
    let cgroup_identity = cgroup.identity();
    let launcher_identity =
        LauncherIdentity::new(execution_id, policy_identity.digest(), cgroup_identity);

    let executable_fd = executable.executable().as_fd().as_raw_fd();
    let working_directory_fd = working_directory.as_fd().as_raw_fd();
    let mut rules = vec![launcher_rule(
        executable_fd,
        vec![LandlockAccess::Read, LandlockAccess::Execute],
    )?];
    if let Some(loader) = executable.loader() {
        rules.push(launcher_rule(
            loader.as_fd().as_raw_fd(),
            vec![LandlockAccess::Read, LandlockAccess::Execute],
        )?);
    }
    for path in &readable {
        rules.push(launcher_rule(
            path.as_fd().as_raw_fd(),
            vec![LandlockAccess::Read],
        )?);
    }
    rules.push(launcher_rule(
        output_root.as_fd().as_raw_fd(),
        vec![LandlockAccess::Write],
    )?);
    let descriptor_upper_bound = rules
        .iter()
        .map(LauncherFilesystemRule::descriptor)
        .chain([
            descriptor(executable_fd)?,
            descriptor(working_directory_fd)?,
        ])
        .max()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| RunError::launcher("launcher.file-descriptor.invalid"))?;
    let request = InstallRequest::new(
        launcher_identity,
        executable.executable().identity().clone(),
        descriptor(executable_fd)?,
        descriptor(working_directory_fd)?,
        arguments,
        environment,
        rules,
        seccomp,
        descriptor_upper_bound,
    )
    .map_err(map_launcher)?;

    plan_source.revalidate_identity().map_err(map_resolution)?;
    runtime_artifact
        .revalidate_identity()
        .map_err(map_resolution)?;
    launcher_artifact
        .revalidate_identity()
        .map_err(map_resolution)?;
    executable.revalidate_identities().map_err(map_resolution)?;
    working_directory
        .revalidate_identity()
        .map_err(map_resolution)?;
    for path in &readable {
        path.revalidate_identity().map_err(map_resolution)?;
    }
    output_root.revalidate_empty().map_err(map_output)?;

    let mut inherited = vec![executable.executable().as_fd(), working_directory.as_fd()];
    if let Some(loader) = executable.loader() {
        inherited.push(loader.as_fd());
    }
    for path in &readable {
        inherited.push(path.as_fd());
    }
    inherited.push(output_root.as_fd());
    let execution = supervise_launcher(
        &launcher_path,
        request,
        cgroup,
        limits,
        &inherited,
        supported.architecture(),
        supported.landlock_abi(),
    )
    .map_err(map_supervisor)?;

    let outputs = output_root.inventory().map_err(map_output)?;
    outputs.revalidate_identities().map_err(map_output)?;
    let receipt = build_receipt(ReceiptInputs {
        plan: &plan,
        plan_source: plan_source.identity().clone(),
        normalized_identity,
        policy_identity,
        supported: &supported,
        runtime_identity: runtime_artifact.identity().clone(),
        launcher_identity: launcher_artifact.identity().clone(),
        executable: &executable,
        working_directory: working_directory.identity().clone(),
        readable: &readable,
        output_root: output_root.identity().clone(),
        cgroup_identity,
        execution_id,
        argument_identity,
        execution: &execution,
        outputs: outputs.receipt_identities(),
    })?;
    let receipt_bytes = receipt
        .canonical_bytes()
        .map_err(|error| RunError::receipt(error.code()))?;
    let commitment = format!("sha256:{}", hex_digest(&receipt_bytes));
    persist_receipt(&receipt_path, execution_id.as_bytes(), &receipt_bytes)?;

    Ok(json!({
        "schema": RUN_RESULT_SCHEMA,
        "receipt": receipt_path.to_str()
            .ok_or_else(|| RunError::invalid("receipt.path.utf8-invalid"))?,
        "commitment": commitment,
        "outcome": outcome_json(execution.outcome()),
    }))
}

#[cfg(target_os = "linux")]
fn resolve_read_authority(
    resolver: &RootedPathResolver,
    compiled: &proofbound_runtime_core::CompiledPolicy,
) -> Result<Vec<ResolvedReadPath>, RunError> {
    compiled
        .filesystem()
        .rules()
        .iter()
        .filter(|rule| rule.access() == FileAccess::Read)
        .map(|rule| {
            let role = match rule.role() {
                PathRole::ProjectInput => ArtifactRole::ProjectInput,
                PathRole::RuntimeLibrary => ArtifactRole::RuntimeLibrary,
                _ => return Err(RunError::invalid("plan.authority.read.role-invalid")),
            };
            resolver
                .resolve_read_path(rule.path(), role)
                .map_err(map_resolution)
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn collect_environment(names: &[EnvironmentName]) -> Result<BTreeMap<String, String>, RunError> {
    let mut environment = BTreeMap::new();
    for name in names {
        let Some(value) = std::env::var_os(name.as_str()) else {
            continue;
        };
        let value = value
            .into_string()
            .map_err(|_| RunError::invalid("plan.environment.value.utf8-invalid"))?;
        environment.insert(name.as_str().to_owned(), value);
    }
    Ok(environment)
}

fn execution_arguments(plan: &ExecutionPlan) -> Vec<String> {
    core::iter::once(plan.command().executable().as_str().to_owned())
        .chain(
            plan.command()
                .arguments()
                .iter()
                .map(|argument| argument.as_str().to_owned()),
        )
        .collect()
}

fn arguments_identity(arguments: &[String]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(ARGUMENT_DOMAIN);
    for argument in arguments {
        hasher.update(
            u64::try_from(argument.len())
                .expect("a string length fits u64")
                .to_be_bytes(),
        );
        hasher.update(argument.as_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn bytes_identity(
    role: ArtifactRole,
    bytes: &[u8],
    mode: u16,
) -> Result<ArtifactIdentity, RunError> {
    let mode = FileMode::new(mode).map_err(|error| RunError::receipt(error.code()))?;
    Ok(ArtifactIdentity::new(
        role,
        Sha256Digest::from_bytes(Sha256::digest(bytes).into()),
        u64::try_from(bytes.len())
            .map_err(|_| RunError::receipt("receipt.artifact.size-invalid"))?,
        mode,
    ))
}

#[cfg(target_os = "linux")]
fn installed_policy_identity(
    normalized: &ArtifactIdentity,
    seccomp: &[u8],
    executable: &proofbound_runtime_linux::ExecutableClosure,
    readable: &[ResolvedReadPath],
    output_root: &FreshOutputRoot,
    limits: ResourceLimits,
) -> Result<ArtifactIdentity, RunError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(POLICY_DOMAIN);
    encode_artifact(&mut bytes, normalized)?;
    encode_artifact(&mut bytes, executable.executable().identity())?;
    if let Some(loader) = executable.loader() {
        encode_artifact(&mut bytes, loader.identity())?;
    }
    for path in readable {
        encode_artifact(&mut bytes, path.identity())?;
    }
    encode_artifact(&mut bytes, output_root.identity())?;
    bytes.extend_from_slice(&limits.processes().get().to_be_bytes());
    bytes.extend_from_slice(&limits.wall_time().milliseconds().to_be_bytes());
    bytes.extend_from_slice(&limits.stdout().get().to_be_bytes());
    bytes.extend_from_slice(&limits.stderr().get().to_be_bytes());
    bytes.extend_from_slice(
        &u64::try_from(seccomp.len())
            .map_err(|_| RunError::receipt("receipt.policy.size-invalid"))?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(seccomp);
    bytes_identity(ArtifactRole::CompiledPolicy, &bytes, POLICY_MODE)
}

fn encode_artifact(output: &mut Vec<u8>, identity: &ArtifactIdentity) -> Result<(), RunError> {
    let role = identity.role().as_str().as_bytes();
    output.extend_from_slice(
        &u64::try_from(role.len())
            .map_err(|_| RunError::receipt("receipt.artifact.role-size-invalid"))?
            .to_be_bytes(),
    );
    output.extend_from_slice(role);
    output.extend_from_slice(identity.digest().as_bytes());
    output.extend_from_slice(&identity.size().to_be_bytes());
    output.extend_from_slice(&identity.mode().get().to_be_bytes());
    Ok(())
}

#[cfg(target_os = "linux")]
struct ReceiptInputs<'a> {
    plan: &'a ExecutionPlan,
    plan_source: ArtifactIdentity,
    normalized_identity: ArtifactIdentity,
    policy_identity: ArtifactIdentity,
    supported: &'a proofbound_runtime_linux::SupportedLinux,
    runtime_identity: ArtifactIdentity,
    launcher_identity: ArtifactIdentity,
    executable: &'a proofbound_runtime_linux::ExecutableClosure,
    working_directory: ArtifactIdentity,
    readable: &'a [ResolvedReadPath],
    output_root: ArtifactIdentity,
    cgroup_identity: proofbound_runtime_core::CgroupIdentity,
    execution_id: proofbound_runtime_core::ExecutionId,
    argument_identity: Sha256Digest,
    execution: &'a proofbound_runtime_linux::SupervisedExecution,
    outputs: Vec<ArtifactIdentity>,
}

#[cfg(target_os = "linux")]
fn build_receipt(input: ReceiptInputs<'_>) -> Result<ExecutionReceipt, RunError> {
    let elapsed = u64::try_from(input.execution.elapsed().as_nanos())
        .map_err(|_| RunError::receipt("receipt.observation.range"))?;
    let stdout = bytes_identity(
        ArtifactRole::StandardOutput,
        input.execution.stdout().bytes(),
        STREAM_MODE,
    )?;
    let stderr = bytes_identity(
        ArtifactRole::StandardError,
        input.execution.stderr().bytes(),
        STREAM_MODE,
    )?;
    let trusted_computing_base = trusted_computing_base(&input)?;
    let receipt = ExecutionReceipt::new(ExecutionReceiptParts {
        execution_id: input.execution_id,
        plan: ReceiptPlan::new(
            input.plan.id().clone(),
            input.plan_source,
            input.normalized_identity,
        )
        .map_err(|error| RunError::receipt(error.code()))?,
        policy: ReceiptPolicy::new(input.policy_identity.clone())
            .map_err(|error| RunError::receipt(error.code()))?,
        platform: PlatformIdentity::new(
            receipt_architecture(input.supported.architecture()),
            input.supported.kernel_release(),
            input.supported.landlock_abi().get(),
            input.supported.seccomp().available_actions().to_vec(),
            input.supported.cgroup_v2().controllers().to_vec(),
        )
        .map_err(|error| RunError::receipt(error.code()))?,
        runtime: RuntimeIdentity::new(
            input.runtime_identity.clone(),
            input.launcher_identity.clone(),
        )
        .map_err(|error| RunError::receipt(error.code()))?,
        command: ReceiptCommand::new(
            input.executable.executable().identity().clone(),
            input
                .executable
                .loader()
                .map(|loader| loader.identity().clone()),
            input.working_directory,
            input.argument_identity,
        )
        .map_err(|error| RunError::receipt(error.code()))?,
        inputs: canonical_input_identities(input.readable),
        environment: input.plan.authority().environment().to_vec(),
        output_root: input.output_root,
        boundary: BoundaryRecord::new(
            input.execution.boundary(),
            input.execution_id,
            input.policy_identity.digest(),
            input.cgroup_identity,
        ),
        observations: ExecutionObservations::new(0, elapsed)
            .map_err(|error| RunError::receipt(error.code()))?,
        streams: ReceiptStreams::new(
            stdout,
            input.execution.stdout().capture(),
            stderr,
            input.execution.stderr().capture(),
        )
        .map_err(|error| RunError::receipt(error.code()))?,
        outcome: input.execution.outcome(),
        outputs: input.outputs,
        producer: input.runtime_identity,
        assumptions: REQUIRED_RUNTIME_ASSUMPTIONS
            .into_iter()
            .map(str::to_owned)
            .collect(),
        trusted_computing_base,
    })
    .map_err(|error| RunError::receipt(error.code()))?;
    Ok(receipt)
}

#[cfg(target_os = "linux")]
fn canonical_input_identities(readable: &[ResolvedReadPath]) -> Vec<ArtifactIdentity> {
    let mut identities = readable
        .iter()
        .map(|path| path.identity().clone())
        .collect::<Vec<_>>();
    identities.sort();
    identities.dedup();
    identities
}

#[cfg(target_os = "linux")]
fn trusted_computing_base(
    input: &ReceiptInputs<'_>,
) -> Result<Vec<TrustedComputingBaseEntry>, RunError> {
    let mut entries = vec![
        tcb(
            TrustedComputingBaseRole::HostHardwareFirmware,
            "local-host:unattested",
        )?,
        tcb(
            TrustedComputingBaseRole::LinuxKernel,
            input.supported.kernel_release(),
        )?,
        tcb(
            TrustedComputingBaseRole::Landlock,
            format!("abi:{}", input.supported.landlock_abi()),
        )?,
        tcb(
            TrustedComputingBaseRole::Seccomp,
            input.supported.seccomp().available_actions().join(","),
        )?,
        tcb(
            TrustedComputingBaseRole::CgroupV2,
            format!(
                "mount:{}:inode:{}",
                input.cgroup_identity.mount_id(),
                input.cgroup_identity.inode()
            ),
        )?,
        tcb(TrustedComputingBaseRole::NoNewPrivileges, "linux-prctl")?,
        tcb(
            TrustedComputingBaseRole::Filesystem,
            "local-filesystem:unattested",
        )?,
        tcb(
            TrustedComputingBaseRole::RuntimeBinary,
            input.runtime_identity.digest().to_hex(),
        )?,
        tcb(
            TrustedComputingBaseRole::LauncherBinary,
            input.launcher_identity.digest().to_hex(),
        )?,
        tcb(
            TrustedComputingBaseRole::RustToolchain,
            "PBR-TOOLCHAIN-AX-003",
        )?,
        tcb(TrustedComputingBaseRole::CryptographicDigest, "sha2-0.11.0")?,
        tcb(
            TrustedComputingBaseRole::RuntimeExecutable,
            input.executable.executable().identity().digest().to_hex(),
        )?,
    ];
    if let Some(loader) = input.executable.loader() {
        entries.push(tcb(
            TrustedComputingBaseRole::RuntimeLoaderExecutable,
            loader.identity().digest().to_hex(),
        )?);
    }
    let runtime_libraries = input
        .readable
        .iter()
        .filter(|path| path.identity().role() == ArtifactRole::RuntimeLibrary)
        .map(|path| path.identity().digest().to_hex())
        .collect::<Vec<_>>();
    if !runtime_libraries.is_empty() {
        entries.push(tcb(
            TrustedComputingBaseRole::RuntimeLibrary,
            runtime_libraries.join(","),
        )?);
    }
    Ok(entries)
}

fn tcb(
    role: TrustedComputingBaseRole,
    identity: impl Into<String>,
) -> Result<TrustedComputingBaseEntry, RunError> {
    TrustedComputingBaseEntry::new(role, identity).map_err(|error| RunError::receipt(error.code()))
}

const fn receipt_architecture(architecture: Architecture) -> ReceiptArchitecture {
    match architecture {
        Architecture::X86_64 => ReceiptArchitecture::X86_64,
        Architecture::Aarch64 => ReceiptArchitecture::Aarch64,
    }
}

#[cfg(target_os = "linux")]
fn launcher_rule(
    descriptor_value: i32,
    access: Vec<LandlockAccess>,
) -> Result<LauncherFilesystemRule, RunError> {
    LauncherFilesystemRule::new(descriptor(descriptor_value)?, access).map_err(map_launcher)
}

#[cfg(target_os = "linux")]
fn descriptor(value: i32) -> Result<u32, RunError> {
    u32::try_from(value).map_err(|_| RunError::launcher("launcher.file-descriptor.invalid"))
}

fn prepare_receipt_path(path: &Path) -> Result<PathBuf, RunError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| RunError::invalid("receipt.path.parent-unavailable"))?
            .join(path)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| RunError::invalid("receipt.path.parent-unavailable"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|_| RunError::invalid("receipt.path.parent-unavailable"))?;
    let leaf = absolute
        .file_name()
        .ok_or_else(|| RunError::invalid("receipt.path.invalid"))?;
    let target = parent.join(leaf);
    match fs::symlink_metadata(&target) {
        Ok(_) => Err(RunError::invalid("receipt.path.exists")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(target),
        Err(_) => Err(RunError::invalid("receipt.path.unavailable")),
    }
}

fn persist_receipt(target: &Path, execution_id: &[u8; 16], bytes: &[u8]) -> Result<(), RunError> {
    let parent = target
        .parent()
        .ok_or_else(|| RunError::receipt("receipt.output.parent-unavailable"))?;
    let temporary = parent.join(format!(".pbr-receipt-{}.tmp", encode_hex(execution_id)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut guard = TemporaryReceipt {
        path: temporary.clone(),
    };
    let mut file = options
        .open(&temporary)
        .map_err(|_| RunError::receipt("receipt.output.create-failed"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| RunError::receipt("receipt.output.write-failed"))?;
    fs::hard_link(&temporary, target)
        .map_err(|_| RunError::receipt("receipt.output.publish-failed"))?;
    fs::remove_file(&temporary).map_err(|_| RunError::receipt("receipt.output.cleanup-failed"))?;
    guard.path.clear();
    Ok(())
}

struct TemporaryReceipt {
    path: PathBuf,
}

impl Drop for TemporaryReceipt {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn outcome_json(outcome: ExecutionOutcome) -> Value {
    match outcome {
        ExecutionOutcome::Exited { code } => json!({"kind": "exited", "code": code}),
        ExecutionOutcome::Signaled { signal } => {
            json!({"kind": "signaled", "signal": signal.get()})
        }
        ExecutionOutcome::TimedOut => json!({"kind": "timed-out"}),
        ExecutionOutcome::Denied => json!({"kind": "denied"}),
        ExecutionOutcome::LauncherFailed => json!({"kind": "launcher-failed"}),
        ExecutionOutcome::Incomplete => json!({"kind": "incomplete"}),
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

const fn map_probe(error: ProbeError) -> RunError {
    RunError::unsupported(error.code())
}

const fn map_execution_setup(error: ExecutionSetupError) -> RunError {
    match error {
        ExecutionSetupError::UnsupportedOperatingSystem => RunError::unsupported(error.code()),
        ExecutionSetupError::RandomUnavailable => RunError::launcher(error.code()),
    }
}

const fn map_resolution(error: ResolutionError) -> RunError {
    match error {
        ResolutionError::UnsupportedOperatingSystem | ResolutionError::Openat2Unavailable => {
            RunError::unsupported(error.code())
        }
        ResolutionError::IdentityMismatch | ResolutionError::IdentityDrift => {
            RunError::identity(error.code())
        }
        _ => RunError::invalid(error.code()),
    }
}

const fn map_output(error: OutputRootError) -> RunError {
    match error {
        OutputRootError::UnsupportedOperatingSystem | OutputRootError::Openat2Unavailable => {
            RunError::unsupported(error.code())
        }
        OutputRootError::IdentityDrift => RunError::identity(error.code()),
        _ => RunError::invalid(error.code()),
    }
}

const fn map_cgroup(error: CgroupError) -> RunError {
    match error {
        CgroupError::UnsupportedOperatingSystem => RunError::unsupported(error.code()),
        CgroupError::CapabilityMismatch => RunError::identity(error.code()),
        _ => RunError::launcher(error.code()),
    }
}

const fn map_launcher(error: LauncherError) -> RunError {
    RunError::launcher(error.code())
}

const fn map_supervisor(error: SupervisorError) -> RunError {
    match error {
        SupervisorError::UnsupportedOperatingSystem => RunError::unsupported(error.code()),
        _ => RunError::launcher(error.code()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTACK_CATALOG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/attacks/run/orchestration-v1.toml"
    ));

    #[test]
    fn orchestration_attack_catalog_is_closed() {
        let expected = [
            "command-override",
            "unsupported-boundary",
            "plan-root-escape",
            "environment-amplification",
            "executable-drift",
            "launcher-substitution",
            "output-root-substitution",
            "outcome-substitution",
            "receipt-preexists",
        ];
        assert!(ATTACK_CATALOG.starts_with("schema = \"proofbound-runtime-run-attacks/1\""));
        assert_eq!(ATTACK_CATALOG.matches("[[case]]").count(), expected.len());
        for id in expected {
            assert!(ATTACK_CATALOG.contains(&format!("id = \"{id}\"")));
        }
    }

    #[test]
    fn argument_identity_is_framed_and_ordered() {
        let first = arguments_identity(&["ab".to_owned(), "c".to_owned()]);
        let second = arguments_identity(&["a".to_owned(), "bc".to_owned()]);
        let reversed = arguments_identity(&["c".to_owned(), "ab".to_owned()]);
        assert_ne!(first, second);
        assert_ne!(first, reversed);
    }

    #[test]
    fn receipt_publication_never_replaces_an_existing_file() {
        let root = std::env::temp_dir().join(format!(
            "proofbound-runtime-receipt-publication-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create receipt fixture root");
        let target = root.join("receipt.json");
        fs::write(&target, b"existing").expect("write existing receipt");
        let error = persist_receipt(&target, &[7; 16], b"replacement")
            .expect_err("existing receipt must not be replaced");
        assert_eq!(error.code(), "receipt.output.publish-failed");
        assert_eq!(
            fs::read(&target).expect("existing receipt reads"),
            b"existing"
        );
        fs::remove_dir_all(root).expect("remove receipt fixture root");
    }

    #[test]
    fn receipt_publication_exposes_complete_exact_bytes() {
        let root = std::env::temp_dir().join(format!(
            "proofbound-runtime-receipt-success-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create receipt fixture root");
        let target = root.join("receipt.json");
        persist_receipt(&target, &[8; 16], b"canonical").expect("publish receipt");
        assert_eq!(fs::read(&target).expect("receipt reads"), b"canonical");
        fs::remove_dir_all(root).expect("remove receipt fixture root");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_hosts_cannot_execute() {
        let error = execute(
            Path::new("plan.toml"),
            Path::new("receipt.json"),
            Path::new("/unsupported"),
        )
        .expect_err("non-Linux host must not run");
        assert_eq!(error.exit_code(), UNSUPPORTED_BOUNDARY);
        assert_eq!(error.code(), "execution.os.unsupported");
    }
}
