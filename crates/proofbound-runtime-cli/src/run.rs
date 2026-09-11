#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use proofbound_runtime_core::{
    Architecture as ReceiptArchitecture, ArtifactIdentity, ArtifactRole, BoundaryRecord,
    EnvironmentName, ExecutionObservations, ExecutionOutcome, ExecutionPlan, ExecutionReceipt,
    ExecutionReceiptParts, FileAccess, FileMode, PathRole, PlatformIdentity,
    REQUIRED_RUNTIME_ASSUMPTIONS, ReceiptCommand, ReceiptError, ReceiptPlan, ReceiptPolicy,
    ReceiptStreams, ResourceLimits, RuntimeIdentity, Sha256Digest, TrustedComputingBaseEntry,
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

use crate::run_diagnostic::{RunError, RunPhase, RunRule};

const RUN_RESULT_SCHEMA: &str = "proofbound-runtime-run-result/1";
const NORMALIZED_PLAN_MODE: u16 = 0;
const POLICY_MODE: u16 = 0;
const STREAM_MODE: u16 = 0;
const ARGUMENT_DOMAIN: &[u8] = b"proofbound-runtime-arguments/1\n";
const POLICY_DOMAIN: &[u8] = b"proofbound-runtime-installed-policy/1\n";

/// Closed operational timing domain for one successful native run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum RunBenchmarkPhase {
    /// Receipt target preparation, strict plan parsing, and normalization.
    PlanValidationAndNormalization = 0,
    /// Capability probing and rooted output/working-directory preparation.
    HostAndPathPreflight = 1,
    /// Executable, runtime closure, policy, and identity inventory.
    ExecutableClosureInventory = 2,
    /// Fresh cgroup creation and configured-limit readback.
    CgroupCreationAndReadback = 3,
    /// Launcher creation through observation of its stopped state.
    StoppedLauncherCreation = 4,
    /// Cgroup placement and launcher boundary installation acknowledgement.
    BoundaryInstallation = 5,
    /// Child release through terminal child status.
    ChildExecution = 6,
    /// Exact process-tree drain and cgroup cleanup.
    ProcessTreeCleanup = 7,
    /// Joining the already-running bounded stream drains.
    StreamCollection = 8,
    /// Output inventory and identity revalidation.
    OutputInventory = 9,
    /// Receipt construction, canonical encoding, and no-replace publication.
    ReceiptConstructionAndPublication = 10,
    /// JSON projection of the completed run result.
    RunResultProjection = 11,
}

impl RunBenchmarkPhase {
    /// All phases in their production dependency order.
    pub const ALL: [Self; 12] = [
        Self::PlanValidationAndNormalization,
        Self::HostAndPathPreflight,
        Self::ExecutableClosureInventory,
        Self::CgroupCreationAndReadback,
        Self::StoppedLauncherCreation,
        Self::BoundaryInstallation,
        Self::ChildExecution,
        Self::ProcessTreeCleanup,
        Self::StreamCollection,
        Self::OutputInventory,
        Self::ReceiptConstructionAndPublication,
        Self::RunResultProjection,
    ];

    /// Returns the stable operational subject name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlanValidationAndNormalization => "plan-validation-and-normalization-v1",
            Self::HostAndPathPreflight => "host-and-path-preflight-v1",
            Self::ExecutableClosureInventory => "executable-closure-inventory-v1",
            Self::CgroupCreationAndReadback => "cgroup-creation-and-readback-v1",
            Self::StoppedLauncherCreation => "stopped-launcher-creation-v1",
            Self::BoundaryInstallation => "boundary-installation-v1",
            Self::ChildExecution => "child-execution-v1",
            Self::ProcessTreeCleanup => "process-tree-cleanup-v1",
            Self::StreamCollection => "stream-collection-v1",
            Self::OutputInventory => "output-inventory-v1",
            Self::ReceiptConstructionAndPublication => "receipt-construction-and-publication-v1",
            Self::RunResultProjection => "run-result-projection-v1",
        }
    }
}

/// Non-overlapping monotonic intervals for the closed native run phases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunTimings {
    intervals: [std::time::Duration; RunBenchmarkPhase::ALL.len()],
}

impl RunTimings {
    /// Constructs one complete interval set in the closed phase order.
    #[must_use]
    pub const fn from_intervals(
        intervals: [std::time::Duration; RunBenchmarkPhase::ALL.len()],
    ) -> Self {
        Self { intervals }
    }

    /// Returns every interval in the closed phase order.
    #[must_use]
    pub const fn intervals(&self) -> &[std::time::Duration; RunBenchmarkPhase::ALL.len()] {
        &self.intervals
    }

    /// Returns the interval for one closed phase.
    #[must_use]
    pub const fn phase(&self, phase: RunBenchmarkPhase) -> std::time::Duration {
        self.intervals[phase as usize]
    }

    /// Returns the sum of all non-overlapping intervals.
    #[must_use]
    pub fn total(&self) -> std::time::Duration {
        self.intervals.iter().copied().fold(
            std::time::Duration::ZERO,
            std::time::Duration::saturating_add,
        )
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn execute(
    _plan_path: &Path,
    _receipt_path: &Path,
    _cgroup_root: &Path,
) -> Result<Value, RunError> {
    Err(RunError::unsupported(
        RunPhase::HostCapabilities,
        RunRule::HostSupported,
        "execution.os.unsupported",
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn execute(
    plan_path: &Path,
    receipt_path: &Path,
    cgroup_root: &Path,
) -> Result<Value, RunError> {
    use std::os::fd::AsRawFd as _;

    let receipt_path = prepare_receipt_path(receipt_path)?;
    let canonical_plan = fs::canonicalize(plan_path).map_err(|_| {
        RunError::invalid(
            RunPhase::PlanInput,
            RunRule::PlanSourceReadable,
            "plan.input.read-failed",
        )
    })?;
    let plan_source = identify_external_artifact(&canonical_plan, ArtifactRole::ExecutionPlan)
        .map_err(|error| map_resolution(RunPhase::PlanInput, RunRule::PlanSourceReadable, error))?;
    let plan_bytes = plan_source
        .read_bytes()
        .map_err(|error| map_resolution(RunPhase::PlanInput, RunRule::PlanSourceReadable, error))?;
    let plan_text = core::str::from_utf8(&plan_bytes).map_err(|_| {
        RunError::invalid(
            RunPhase::PlanInput,
            RunRule::PlanSourceReadable,
            "plan.input.utf8-invalid",
        )
    })?;
    let plan = parse_execution_plan(plan_text).map_err(|error| {
        RunError::invalid(RunPhase::PlanValidation, RunRule::PlanValid, error.code())
    })?;
    let normalized = normalize_authority(plan.authority().clone()).map_err(|error| {
        RunError::invalid(
            RunPhase::AuthorityNormalization,
            RunRule::AuthorityNormalized,
            error.code(),
        )
    })?;
    let compiled = compile_policy(normalized.clone());
    let plan_root = canonical_plan.parent().ok_or_else(|| {
        RunError::invalid(
            RunPhase::PlanRoot,
            RunRule::PlanRootConfined,
            "plan.input.parent-unavailable",
        )
    })?;
    let resolver = RootedPathResolver::open(plan_root)
        .map_err(|error| map_resolution(RunPhase::PlanRoot, RunRule::PlanRootConfined, error))?;

    let supported = probe_capabilities(cgroup_root)
        .require_supported()
        .map_err(map_probe)?;
    let output_authority = compiled
        .filesystem()
        .rules()
        .iter()
        .find(|rule| rule.access() == FileAccess::Write && rule.role() == PathRole::OutputRoot)
        .ok_or_else(|| {
            RunError::invalid(
                RunPhase::PlanValidation,
                RunRule::PlanValid,
                "plan.authority.output-root.count",
            )
        })?;
    let output_root = FreshOutputRoot::create(&resolver, output_authority.path())
        .map_err(|error| map_output(RunPhase::OutputRoot, RunRule::OutputRootFresh, error))?;
    if receipt_path.starts_with(output_root.resolved_target()) {
        return Err(RunError::invalid(
            RunPhase::ReceiptTarget,
            RunRule::ReceiptTargetValid,
            "receipt.path.child-writable",
        ));
    }
    let working_directory = resolver
        .resolve_working_directory(plan.command().working_directory())
        .map_err(|error| {
            map_resolution(
                RunPhase::WorkingDirectory,
                RunRule::WorkingDirectoryResolved,
                error,
            )
        })?;
    let executable = resolver
        .discover_executable(plan.command().executable(), supported.architecture())
        .map_err(|error| {
            map_resolution(
                RunPhase::ExecutableClosure,
                RunRule::ExecutableClosureResolved,
                error,
            )
        })?;
    let readable = resolve_read_authority(&resolver, &compiled)?;

    let current_executable = fs::canonicalize(std::env::current_exe().map_err(|_| {
        RunError::identity(
            RunPhase::RuntimeIdentity,
            RunRule::RuntimeIdentityObserved,
            "runtime.path.unavailable",
        )
    })?)
    .map_err(|_| {
        RunError::identity(
            RunPhase::RuntimeIdentity,
            RunRule::RuntimeIdentityObserved,
            "runtime.path.unavailable",
        )
    })?;
    let launcher_path = current_executable
        .parent()
        .ok_or_else(|| {
            RunError::identity(
                RunPhase::LauncherIdentity,
                RunRule::LauncherIdentityObserved,
                "launcher.path.unavailable",
            )
        })?
        .join("pbr-native-launcher");
    let launcher_path = fs::canonicalize(launcher_path).map_err(|_| {
        RunError::identity(
            RunPhase::LauncherIdentity,
            RunRule::LauncherIdentityObserved,
            "launcher.path.unavailable",
        )
    })?;
    let runtime_artifact =
        identify_external_artifact(&current_executable, ArtifactRole::RuntimeBinary).map_err(
            |error| {
                map_resolution(
                    RunPhase::RuntimeIdentity,
                    RunRule::RuntimeIdentityObserved,
                    error,
                )
            },
        )?;
    let launcher_artifact =
        identify_external_artifact(&launcher_path, ArtifactRole::LauncherBinary).map_err(
            |error| {
                map_resolution(
                    RunPhase::LauncherIdentity,
                    RunRule::LauncherIdentityObserved,
                    error,
                )
            },
        )?;

    let receipt_environment = compiled.environment().to_vec();
    let environment = collect_environment(&receipt_environment)?;
    let arguments = execution_arguments(&plan);
    let argument_identity = arguments_identity(&arguments);
    let seccomp = compile_deny_network_program(compiled.network(), supported.architecture())
        .map_err(|error| {
            RunError::launcher(
                RunPhase::PolicyCompilation,
                RunRule::PolicyIdentityConstructed,
                error.code(),
            )
        })?;
    let normalized_bytes =
        serde_json::to_vec(&crate::plan::checked_plan_json(&plan).map_err(|error| {
            RunError::invalid(
                RunPhase::PolicyCompilation,
                RunRule::PolicyIdentityConstructed,
                error.code(),
            )
        })?)
        .map_err(|_| {
            RunError::receipt(
                RunPhase::PolicyCompilation,
                RunRule::PolicyIdentityConstructed,
                "receipt.normalized-plan.encoding-failed",
            )
        })?;
    let normalized_identity = bytes_identity(
        ArtifactRole::NormalizedPlan,
        &normalized_bytes,
        NORMALIZED_PLAN_MODE,
        RunPhase::PolicyCompilation,
        RunRule::PolicyIdentityConstructed,
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
        .ok_or_else(|| {
            RunError::launcher(
                RunPhase::LauncherRequest,
                RunRule::LauncherRequestConstructed,
                "launcher.file-descriptor.invalid",
            )
        })?;
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
    .map_err(map_launcher_request)?;

    plan_source.revalidate_identity().map_err(|error| {
        map_resolution(
            RunPhase::IdentityRevalidation,
            RunRule::ArtifactIdentitiesStable,
            error,
        )
    })?;
    runtime_artifact.revalidate_identity().map_err(|error| {
        map_resolution(
            RunPhase::IdentityRevalidation,
            RunRule::ArtifactIdentitiesStable,
            error,
        )
    })?;
    launcher_artifact.revalidate_identity().map_err(|error| {
        map_resolution(
            RunPhase::IdentityRevalidation,
            RunRule::ArtifactIdentitiesStable,
            error,
        )
    })?;
    executable.revalidate_identities().map_err(|error| {
        map_resolution(
            RunPhase::IdentityRevalidation,
            RunRule::ArtifactIdentitiesStable,
            error,
        )
    })?;
    working_directory.revalidate_identity().map_err(|error| {
        map_resolution(
            RunPhase::IdentityRevalidation,
            RunRule::ArtifactIdentitiesStable,
            error,
        )
    })?;
    for path in &readable {
        path.revalidate_identity().map_err(|error| {
            map_resolution(
                RunPhase::IdentityRevalidation,
                RunRule::ArtifactIdentitiesStable,
                error,
            )
        })?;
    }
    output_root.revalidate_empty().map_err(|error| {
        map_output(
            RunPhase::IdentityRevalidation,
            RunRule::ArtifactIdentitiesStable,
            error,
        )
    })?;

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

    let outputs = output_root.inventory().map_err(|error| {
        map_output(
            RunPhase::OutputInventory,
            RunRule::OutputInventoryStable,
            error,
        )
    })?;
    outputs.revalidate_identities().map_err(|error| {
        map_output(
            RunPhase::OutputInventory,
            RunRule::OutputInventoryStable,
            error,
        )
    })?;
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
        environment: receipt_environment,
        execution: &execution,
        outputs: outputs.receipt_identities(),
    })?;
    let receipt_bytes = receipt.canonical_bytes().map_err(|error| {
        RunError::receipt(
            RunPhase::ReceiptConstruction,
            RunRule::ReceiptConstructed,
            error.code(),
        )
    })?;
    let commitment = format!("sha256:{}", hex_digest(&receipt_bytes));
    persist_receipt(&receipt_path, execution_id.as_bytes(), &receipt_bytes)?;

    run_result_json(
        &receipt_path,
        execution_id,
        &commitment,
        execution.outcome(),
    )
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
                _ => {
                    return Err(RunError::invalid(
                        RunPhase::ReadAuthority,
                        RunRule::ReadAuthorityResolved,
                        "plan.authority.read.role-invalid",
                    ));
                }
            };
            resolver
                .resolve_read_path(rule.path(), role)
                .map_err(|error| {
                    map_resolution(
                        RunPhase::ReadAuthority,
                        RunRule::ReadAuthorityResolved,
                        error,
                    )
                })
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
        let value = value.into_string().map_err(|_| {
            RunError::invalid(
                RunPhase::Environment,
                RunRule::EnvironmentRepresentable,
                "plan.environment.value.utf8-invalid",
            )
        })?;
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
    phase: RunPhase,
    rule: RunRule,
) -> Result<ArtifactIdentity, RunError> {
    let mode = FileMode::new(mode).map_err(|error| RunError::receipt(phase, rule, error.code()))?;
    Ok(ArtifactIdentity::new(
        role,
        Sha256Digest::from_bytes(Sha256::digest(bytes).into()),
        u64::try_from(bytes.len())
            .map_err(|_| RunError::receipt(phase, rule, "receipt.artifact.size-invalid"))?,
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
            .map_err(|_| {
                RunError::receipt(
                    RunPhase::PolicyCompilation,
                    RunRule::PolicyIdentityConstructed,
                    "receipt.policy.size-invalid",
                )
            })?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(seccomp);
    bytes_identity(
        ArtifactRole::CompiledPolicy,
        &bytes,
        POLICY_MODE,
        RunPhase::PolicyCompilation,
        RunRule::PolicyIdentityConstructed,
    )
}

fn encode_artifact(output: &mut Vec<u8>, identity: &ArtifactIdentity) -> Result<(), RunError> {
    let role = identity.role().as_str().as_bytes();
    output.extend_from_slice(
        &u64::try_from(role.len())
            .map_err(|_| {
                RunError::receipt(
                    RunPhase::PolicyCompilation,
                    RunRule::PolicyIdentityConstructed,
                    "receipt.artifact.role-size-invalid",
                )
            })?
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
    environment: Vec<EnvironmentName>,
    execution: &'a proofbound_runtime_linux::SupervisedExecution,
    outputs: Vec<ArtifactIdentity>,
}

#[cfg(target_os = "linux")]
fn build_receipt(input: ReceiptInputs<'_>) -> Result<ExecutionReceipt, RunError> {
    let elapsed = u64::try_from(input.execution.elapsed().as_nanos()).map_err(|_| {
        RunError::receipt(
            RunPhase::ReceiptConstruction,
            RunRule::ReceiptConstructed,
            "receipt.observation.range",
        )
    })?;
    let stdout = bytes_identity(
        ArtifactRole::StandardOutput,
        input.execution.stdout().bytes(),
        STREAM_MODE,
        RunPhase::ReceiptConstruction,
        RunRule::ReceiptConstructed,
    )?;
    let stderr = bytes_identity(
        ArtifactRole::StandardError,
        input.execution.stderr().bytes(),
        STREAM_MODE,
        RunPhase::ReceiptConstruction,
        RunRule::ReceiptConstructed,
    )?;
    let trusted_computing_base = trusted_computing_base(&input)?;
    let receipt = proofbound_runtime_core::construct_execution_receipt(ExecutionReceiptParts {
        execution_id: input.execution_id,
        plan: ReceiptPlan::new(
            input.plan.id().clone(),
            input.plan_source,
            input.normalized_identity,
        )
        .map_err(map_receipt_construction)?,
        policy: ReceiptPolicy::new(input.policy_identity.clone())
            .map_err(map_receipt_construction)?,
        platform: PlatformIdentity::new(
            receipt_architecture(input.supported.architecture()),
            input.supported.kernel_release(),
            input.supported.landlock_abi().get(),
            input.supported.seccomp().available_actions().to_vec(),
            input.supported.cgroup_v2().controllers().to_vec(),
        )
        .map_err(map_receipt_construction)?,
        runtime: RuntimeIdentity::new(
            input.runtime_identity.clone(),
            input.launcher_identity.clone(),
        )
        .map_err(map_receipt_construction)?,
        command: ReceiptCommand::new(
            input.executable.executable().identity().clone(),
            input
                .executable
                .loader()
                .map(|loader| loader.identity().clone()),
            input.working_directory,
            input.argument_identity,
        )
        .map_err(map_receipt_construction)?,
        inputs: canonical_input_identities(input.readable),
        environment: input.environment,
        output_root: input.output_root,
        boundary: BoundaryRecord::new(
            input.execution.boundary(),
            input.execution_id,
            input.policy_identity.digest(),
            input.cgroup_identity,
        ),
        observations: ExecutionObservations::new(0, elapsed).map_err(map_receipt_construction)?,
        streams: ReceiptStreams::new(
            stdout,
            input.execution.stdout().capture(),
            stderr,
            input.execution.stderr().capture(),
        )
        .map_err(map_receipt_construction)?,
        outcome: input.execution.outcome(),
        outputs: input.outputs,
        producer: input.runtime_identity,
        assumptions: REQUIRED_RUNTIME_ASSUMPTIONS
            .into_iter()
            .map(str::to_owned)
            .collect(),
        trusted_computing_base,
    })
    .map_err(map_receipt_construction)?;
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
    TrustedComputingBaseEntry::new(role, identity).map_err(map_receipt_construction)
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
    LauncherFilesystemRule::new(descriptor(descriptor_value)?, access).map_err(map_launcher_request)
}

#[cfg(target_os = "linux")]
fn descriptor(value: i32) -> Result<u32, RunError> {
    u32::try_from(value).map_err(|_| {
        RunError::launcher(
            RunPhase::LauncherRequest,
            RunRule::LauncherRequestConstructed,
            "launcher.file-descriptor.invalid",
        )
    })
}

pub(crate) fn prepare_receipt_path(path: &Path) -> Result<PathBuf, RunError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| {
                RunError::invalid(
                    RunPhase::ReceiptTarget,
                    RunRule::ReceiptTargetValid,
                    "receipt.path.parent-unavailable",
                )
            })?
            .join(path)
    };
    let parent = absolute.parent().ok_or_else(|| {
        RunError::invalid(
            RunPhase::ReceiptTarget,
            RunRule::ReceiptTargetValid,
            "receipt.path.parent-unavailable",
        )
    })?;
    let parent = fs::canonicalize(parent).map_err(|_| {
        RunError::invalid(
            RunPhase::ReceiptTarget,
            RunRule::ReceiptTargetValid,
            "receipt.path.parent-unavailable",
        )
    })?;
    let leaf = absolute.file_name().ok_or_else(|| {
        RunError::invalid(
            RunPhase::ReceiptTarget,
            RunRule::ReceiptTargetValid,
            "receipt.path.invalid",
        )
    })?;
    let target = parent.join(leaf);
    match fs::symlink_metadata(&target) {
        Ok(_) => Err(RunError::invalid(
            RunPhase::ReceiptTarget,
            RunRule::ReceiptTargetValid,
            "receipt.path.exists",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(target),
        Err(_) => Err(RunError::invalid(
            RunPhase::ReceiptTarget,
            RunRule::ReceiptTargetValid,
            "receipt.path.unavailable",
        )),
    }
}

fn persist_receipt(target: &Path, execution_id: &[u8; 16], bytes: &[u8]) -> Result<(), RunError> {
    let parent = target.parent().ok_or_else(|| {
        RunError::receipt(
            RunPhase::ReceiptPublication,
            RunRule::ReceiptPublished,
            "receipt.output.parent-unavailable",
        )
    })?;
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
    let mut file = options.open(&temporary).map_err(|_| {
        RunError::receipt(
            RunPhase::ReceiptPublication,
            RunRule::ReceiptPublished,
            "receipt.output.create-failed",
        )
    })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| {
            RunError::receipt(
                RunPhase::ReceiptPublication,
                RunRule::ReceiptPublished,
                "receipt.output.write-failed",
            )
        })?;
    fs::hard_link(&temporary, target).map_err(|_| {
        RunError::receipt(
            RunPhase::ReceiptPublication,
            RunRule::ReceiptPublished,
            "receipt.output.publish-failed",
        )
    })?;
    fs::remove_file(&temporary).map_err(|_| {
        RunError::receipt(
            RunPhase::ReceiptPublication,
            RunRule::ReceiptPublished,
            "receipt.output.cleanup-failed",
        )
    })?;
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

fn run_result_json(
    receipt_path: &Path,
    execution_id: proofbound_runtime_core::ExecutionId,
    commitment: &str,
    outcome: ExecutionOutcome,
) -> Result<Value, RunError> {
    Ok(json!({
        "schema": RUN_RESULT_SCHEMA,
        "execution_id": execution_id.to_text(),
        "receipt": receipt_path.to_str()
            .ok_or_else(|| RunError::invalid(
                RunPhase::ResultProjection,
                RunRule::RunResultRepresentable,
                "receipt.path.utf8-invalid",
            ))?,
        "commitment": commitment,
        "outcome": outcome_json(outcome),
    }))
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
    RunError::unsupported(
        RunPhase::HostCapabilities,
        RunRule::HostSupported,
        error.code(),
    )
}

const fn map_execution_setup(error: ExecutionSetupError) -> RunError {
    match error {
        ExecutionSetupError::UnsupportedOperatingSystem => RunError::unsupported(
            RunPhase::ExecutionIdentity,
            RunRule::ExecutionIdentityCreated,
            error.code(),
        ),
        ExecutionSetupError::RandomUnavailable => RunError::launcher(
            RunPhase::ExecutionIdentity,
            RunRule::ExecutionIdentityCreated,
            error.code(),
        ),
    }
}

const fn map_resolution(phase: RunPhase, rule: RunRule, error: ResolutionError) -> RunError {
    match error {
        ResolutionError::UnsupportedOperatingSystem | ResolutionError::Openat2Unavailable => {
            RunError::unsupported(phase, rule, error.code())
        }
        ResolutionError::IdentityMismatch | ResolutionError::IdentityDrift => {
            RunError::identity(phase, rule, error.code())
        }
        _ => RunError::invalid(phase, rule, error.code()),
    }
}

const fn map_output(phase: RunPhase, rule: RunRule, error: OutputRootError) -> RunError {
    match error {
        OutputRootError::UnsupportedOperatingSystem | OutputRootError::Openat2Unavailable => {
            RunError::unsupported(phase, rule, error.code())
        }
        OutputRootError::IdentityDrift => RunError::identity(phase, rule, error.code()),
        _ => RunError::invalid(phase, rule, error.code()),
    }
}

const fn map_cgroup(error: CgroupError) -> RunError {
    match error {
        CgroupError::UnsupportedOperatingSystem => RunError::unsupported(
            RunPhase::Cgroup,
            RunRule::CgroupBoundaryPrepared,
            error.code(),
        ),
        CgroupError::CapabilityMismatch => RunError::identity(
            RunPhase::Cgroup,
            RunRule::CgroupBoundaryPrepared,
            error.code(),
        ),
        _ => RunError::launcher(
            RunPhase::Cgroup,
            RunRule::CgroupBoundaryPrepared,
            error.code(),
        ),
    }
}

const fn map_launcher_request(error: LauncherError) -> RunError {
    RunError::launcher(
        RunPhase::LauncherRequest,
        RunRule::LauncherRequestConstructed,
        error.code(),
    )
}

const fn map_supervisor(error: SupervisorError) -> RunError {
    match error {
        SupervisorError::UnsupportedOperatingSystem => RunError::unsupported(
            RunPhase::LauncherProtocol,
            RunRule::LauncherBoundaryComplete,
            error.code(),
        ),
        _ => RunError::launcher(
            RunPhase::LauncherProtocol,
            RunRule::LauncherBoundaryComplete,
            error.code(),
        ),
    }
}

fn map_receipt_construction(error: ReceiptError) -> RunError {
    RunError::receipt(
        RunPhase::ReceiptConstruction,
        RunRule::ReceiptConstructed,
        error.code(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTACK_CATALOG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/attacks/run/orchestration-v1.toml"
    ));
    const DIAGNOSTIC_ATTACK_CATALOG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/attacks/run/diagnostics-v1.toml"
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
            "execution-id-replay",
        ];
        assert!(ATTACK_CATALOG.starts_with("schema = \"proofbound-runtime-run-attacks/1\""));
        assert_eq!(ATTACK_CATALOG.matches("[[case]]").count(), expected.len());
        for id in expected {
            assert!(ATTACK_CATALOG.contains(&format!("id = \"{id}\"")));
        }
    }

    #[test]
    fn diagnostic_attack_catalog_is_closed() {
        let expected = [
            (
                "capability-unavailable",
                3,
                "host-capabilities",
                "host-supported",
                "platform.cgroup-v2.controller-missing",
            ),
            (
                "resolution-failure",
                2,
                "executable-closure",
                "executable-closure-resolved",
                "resolve.elf.malformed",
            ),
            (
                "identity-drift",
                4,
                "identity-revalidation",
                "artifact-identities-stable",
                "resolve.identity.drift",
            ),
            (
                "output-root-failure",
                2,
                "output-root",
                "output-root-fresh",
                "output.root.exists",
            ),
            (
                "launcher-protocol-failure",
                5,
                "launcher-protocol",
                "launcher-boundary-complete",
                "supervisor.protocol.failed",
            ),
            (
                "cgroup-failure",
                5,
                "cgroup",
                "cgroup-boundary-prepared",
                "cgroup.limit.mismatch",
            ),
            (
                "receipt-construction-failure",
                6,
                "receipt-construction",
                "receipt-constructed",
                "receipt.observation.range",
            ),
            (
                "receipt-publication-failure",
                6,
                "receipt-publication",
                "receipt-published",
                "receipt.output.publish-failed",
            ),
            (
                "result-projection-failure",
                2,
                "result-projection",
                "run-result-representable",
                "receipt.path.utf8-invalid",
            ),
        ];
        assert!(
            DIAGNOSTIC_ATTACK_CATALOG
                .starts_with("schema = \"proofbound-runtime-run-diagnostic-attacks/1\"")
        );
        assert_eq!(
            DIAGNOSTIC_ATTACK_CATALOG.matches("[[case]]").count(),
            expected.len()
        );
        for (id, exit, phase, rule, code) in expected {
            assert!(DIAGNOSTIC_ATTACK_CATALOG.contains(&format!("id = \"{id}\"")));
            assert!(DIAGNOSTIC_ATTACK_CATALOG.contains(&format!("expected_exit = {exit}")));
            assert!(DIAGNOSTIC_ATTACK_CATALOG.contains(&format!("expected_phase = \"{phase}\"")));
            assert!(DIAGNOSTIC_ATTACK_CATALOG.contains(&format!("expected_rule = \"{rule}\"")));
            assert!(DIAGNOSTIC_ATTACK_CATALOG.contains(&format!("expected_code = \"{code}\"")));
        }
    }

    #[test]
    fn diagnostic_mappings_match_the_frozen_boundary() {
        let cases = [
            (
                map_probe(ProbeError::CgroupV2ControllerMissing),
                3,
                RunPhase::HostCapabilities,
                RunRule::HostSupported,
                "platform.cgroup-v2.controller-missing",
            ),
            (
                map_resolution(
                    RunPhase::ExecutableClosure,
                    RunRule::ExecutableClosureResolved,
                    ResolutionError::ElfMalformed,
                ),
                2,
                RunPhase::ExecutableClosure,
                RunRule::ExecutableClosureResolved,
                "resolve.elf.malformed",
            ),
            (
                map_resolution(
                    RunPhase::IdentityRevalidation,
                    RunRule::ArtifactIdentitiesStable,
                    ResolutionError::IdentityDrift,
                ),
                4,
                RunPhase::IdentityRevalidation,
                RunRule::ArtifactIdentitiesStable,
                "resolve.identity.drift",
            ),
            (
                map_output(
                    RunPhase::OutputRoot,
                    RunRule::OutputRootFresh,
                    OutputRootError::AlreadyExists,
                ),
                2,
                RunPhase::OutputRoot,
                RunRule::OutputRootFresh,
                "output.root.exists",
            ),
            (
                map_supervisor(SupervisorError::ProtocolFailed),
                5,
                RunPhase::LauncherProtocol,
                RunRule::LauncherBoundaryComplete,
                "supervisor.protocol.failed",
            ),
            (
                map_cgroup(CgroupError::LimitMismatch),
                5,
                RunPhase::Cgroup,
                RunRule::CgroupBoundaryPrepared,
                "cgroup.limit.mismatch",
            ),
            (
                RunError::receipt(
                    RunPhase::ReceiptConstruction,
                    RunRule::ReceiptConstructed,
                    "receipt.observation.range",
                ),
                6,
                RunPhase::ReceiptConstruction,
                RunRule::ReceiptConstructed,
                "receipt.observation.range",
            ),
            (
                RunError::receipt(
                    RunPhase::ReceiptPublication,
                    RunRule::ReceiptPublished,
                    "receipt.output.publish-failed",
                ),
                6,
                RunPhase::ReceiptPublication,
                RunRule::ReceiptPublished,
                "receipt.output.publish-failed",
            ),
            (
                RunError::invalid(
                    RunPhase::ResultProjection,
                    RunRule::RunResultRepresentable,
                    "receipt.path.utf8-invalid",
                ),
                2,
                RunPhase::ResultProjection,
                RunRule::RunResultRepresentable,
                "receipt.path.utf8-invalid",
            ),
        ];

        for (error, exit, phase, rule, code) in cases {
            assert_eq!(error.exit_code(), exit);
            assert_eq!(error.phase(), phase);
            assert_eq!(error.rule(), rule);
            assert_eq!(error.code(), code);
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
    fn run_timings_preserve_the_closed_production_phase_order() {
        let intervals = core::array::from_fn(|index| {
            std::time::Duration::from_nanos(u64::try_from(index + 1).expect("index fits u64"))
        });
        let timings = RunTimings::from_intervals(intervals);

        assert_eq!(timings.intervals(), &intervals);
        assert_eq!(
            timings.phase(RunBenchmarkPhase::PlanValidationAndNormalization),
            std::time::Duration::from_nanos(1)
        );
        assert_eq!(
            timings.phase(RunBenchmarkPhase::RunResultProjection),
            std::time::Duration::from_nanos(12)
        );
        assert_eq!(timings.total(), std::time::Duration::from_nanos(78));
    }

    #[test]
    fn run_result_transports_execution_identity_outside_receipt() {
        let execution_id = proofbound_runtime_core::ExecutionId::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
        .expect("fixture execution ID is version 4");
        let result = run_result_json(
            Path::new("receipt.json"),
            execution_id,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ExecutionOutcome::Exited { code: 0 },
        )
        .expect("run result is representable");
        assert_eq!(
            result,
            json!({
                "commitment": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "execution_id": "00112233-4455-4677-8899-aabbccddeeff",
                "outcome": {"kind": "exited", "code": 0},
                "receipt": "receipt.json",
                "schema": "proofbound-runtime-run-result/1",
            })
        );
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
        assert_eq!(error.exit_code(), 3);
        assert_eq!(error.code(), "execution.os.unsupported");
    }
}
