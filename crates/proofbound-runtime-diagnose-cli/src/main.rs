#![forbid(unsafe_code)]

//! Runs one bounded diagnostic execution and publishes non-reusable artifacts.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use proofbound_runtime_core::{
    Architecture as ReceiptArchitecture, ArtifactIdentity, ArtifactRole, DiagnosticCompletion,
    DraftProvenance, EnvironmentName, FileAccess, FileMode, NetworkMode, PathRole, ResourceLimits,
    Sha256Digest, compile_policy, normalize_authority, parse_execution_plan_for_execution,
};
use proofbound_runtime_diagnose::artifact::{
    DiagnosticArtifactIdentity, DiagnosticArtifactRole, DiagnosticGap, DiagnosticPlatform,
    DiagnosticReceiptParts, DiagnosticTcbEntry, DiagnosticTcbRole, ObservationBounds,
};
use proofbound_runtime_diagnose::draft::{
    ContentIdentity, DraftInput, IdentifiedClosureEntry, IdentifiedClosureRole, PlanDraftInputs,
};
use proofbound_runtime_diagnose::observer::ObserverDirective;
use proofbound_runtime_diagnose::producer::build_diagnostic_artifacts;
use proofbound_runtime_diagnose_linux::{
    ActiveObserverStep, ActiveTraceEvent, DiagnosticEventMapper, TraceCandidateObservation,
    prepare_observer,
};
use proofbound_runtime_linux::{
    Architecture, FreshCgroup, FreshOutputRoot, InstallRequest, LandlockAccess,
    LauncherFilesystemRule, LauncherIdentity, ResolvedReadPath, RootedPathResolver,
    compile_deny_network_program, fresh_execution_id, identify_external_artifact,
    probe_capabilities,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};

const INVALID_INPUT: u8 = 2;
const UNSUPPORTED_BOUNDARY: u8 = 3;
const EXECUTION_FAILED: u8 = 5;
const OUTPUT_FAILED: u8 = 6;
const NORMALIZED_PLAN_MODE: u16 = 0;
const POLICY_MODE: u16 = 0;
const POLICY_DOMAIN: &[u8] = b"proofbound-runtime-installed-policy/1\n";
const DIAGNOSTIC_ASSUMPTIONS: [&str; 7] = [
    "PBR-DIAGNOSTIC-CANDIDATE-AX-027",
    "PBR-DIAGNOSTIC-COMMAND-AX-029",
    "PBR-DIAGNOSTIC-DECODE-AX-017",
    "PBR-DIAGNOSTIC-LIFECYCLE-AX-023",
    "PBR-DIAGNOSTIC-OBJECT-AX-025",
    "PBR-DIAGNOSTIC-STREAM-AX-022",
    "PBR-DIAGNOSTIC-TRACE-AX-016",
];

fn main() -> ExitCode {
    let arguments = env::args_os().collect::<Vec<_>>();
    if arguments.len() == 2 && arguments[1] == OsStr::new("--version") {
        println!(concat!("pbr-diagnose ", env!("CARGO_PKG_VERSION")));
        return ExitCode::SUCCESS;
    }
    if arguments.len() == 2
        && (arguments[1] == OsStr::new("--help") || arguments[1] == OsStr::new("-h"))
    {
        println!(
            "usage: pbr-diagnose --plan SEED_PLAN --receipt ABSENT_RECEIPT --draft ABSENT_DRAFT --cgroup-root DELEGATED_CGROUP_ROOT [--static-scaffold DECLARED_PROJECT_INPUT]"
        );
        return ExitCode::SUCCESS;
    }
    let mut stderr = io::stderr().lock();
    let code = match parse_args(arguments).and_then(execute) {
        Ok(report) => {
            let mut stdout = io::stdout().lock();
            if serde_json::to_writer(&mut stdout, &report)
                .and_then(|()| writeln!(stdout).map_err(serde_json::Error::io))
                .is_ok()
            {
                0
            } else {
                let _ = writeln!(stderr, "diagnostic.output.write-failed");
                OUTPUT_FAILED
            }
        }
        Err(error) => {
            let _ = writeln!(stderr, "{}", error.code);
            error.exit_code
        }
    };
    ExitCode::from(code)
}

#[derive(Debug, Eq, PartialEq)]
struct CommandInput {
    plan: PathBuf,
    receipt: PathBuf,
    draft: PathBuf,
    cgroup_root: PathBuf,
    static_scaffold: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DiagnoseError {
    exit_code: u8,
    code: &'static str,
}

impl DiagnoseError {
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

    const fn execution(code: &'static str) -> Self {
        Self {
            exit_code: EXECUTION_FAILED,
            code,
        }
    }

    const fn output(code: &'static str) -> Self {
        Self {
            exit_code: OUTPUT_FAILED,
            code,
        }
    }
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<CommandInput, DiagnoseError> {
    let mut args = args.into_iter();
    let _program = args.next();
    let mut plan = None;
    let mut receipt = None;
    let mut draft = None;
    let mut cgroup_root = None;
    let mut static_scaffold = None;
    while let Some(option) = args.next() {
        let argument = args
            .next()
            .ok_or_else(|| DiagnoseError::invalid("diagnostic.cli.usage-invalid"))?;
        if option == OsStr::new("--plan") && plan.is_none() {
            plan = Some(argument);
        } else if option == OsStr::new("--receipt") && receipt.is_none() {
            receipt = Some(argument);
        } else if option == OsStr::new("--draft") && draft.is_none() {
            draft = Some(argument);
        } else if option == OsStr::new("--cgroup-root") && cgroup_root.is_none() {
            cgroup_root = Some(argument);
        } else if option == OsStr::new("--static-scaffold") && static_scaffold.is_none() {
            static_scaffold = Some(argument);
        } else {
            return Err(DiagnoseError::invalid("diagnostic.cli.usage-invalid"));
        }
    }
    Ok(CommandInput {
        plan: plan
            .ok_or_else(|| DiagnoseError::invalid("diagnostic.cli.usage-invalid"))?
            .into(),
        receipt: receipt
            .ok_or_else(|| DiagnoseError::invalid("diagnostic.cli.usage-invalid"))?
            .into(),
        draft: draft
            .ok_or_else(|| DiagnoseError::invalid("diagnostic.cli.usage-invalid"))?
            .into(),
        cgroup_root: cgroup_root
            .ok_or_else(|| DiagnoseError::invalid("diagnostic.cli.usage-invalid"))?
            .into(),
        static_scaffold: static_scaffold.map(PathBuf::from),
    })
}

#[cfg(not(target_os = "linux"))]
fn execute(_input: CommandInput) -> Result<serde_json::Value, DiagnoseError> {
    Err(DiagnoseError::unsupported("diagnostic.os.unsupported"))
}

#[cfg(target_os = "linux")]
fn execute(input: CommandInput) -> Result<serde_json::Value, DiagnoseError> {
    let receipt_target = prepare_absent_target(&input.receipt, "diagnostic.receipt")?;
    let draft_target = prepare_absent_target(&input.draft, "diagnostic.draft")?;
    if receipt_target == draft_target {
        return Err(DiagnoseError::invalid(
            "diagnostic.output.targets-identical",
        ));
    }

    let canonical_plan = fs::canonicalize(&input.plan)
        .map_err(|_| DiagnoseError::invalid("diagnostic.plan.read-failed"))?;
    let plan_source = identify_external_artifact(&canonical_plan, ArtifactRole::ExecutionPlan)
        .map_err(|error| DiagnoseError::invalid(error.code()))?;
    let plan_bytes = plan_source
        .read_bytes()
        .map_err(|error| DiagnoseError::invalid(error.code()))?;
    let plan = parse_execution_plan_for_execution(&plan_bytes)
        .map_err(|error| DiagnoseError::invalid(error.code()))?;
    let normalized = normalize_authority(plan.authority().clone())
        .map_err(|error| DiagnoseError::invalid(error.code()))?;
    let compiled = compile_policy(normalized);
    let plan_root = canonical_plan
        .parent()
        .ok_or_else(|| DiagnoseError::invalid("diagnostic.plan.parent-unavailable"))?;
    let resolver = RootedPathResolver::open(plan_root)
        .map_err(|error| DiagnoseError::invalid(error.code()))?;
    let supported = probe_capabilities(&input.cgroup_root)
        .require_supported()
        .map_err(|error| DiagnoseError::unsupported(error.code()))?;

    let output_authority = compiled
        .filesystem()
        .rules()
        .iter()
        .find(|rule| rule.access() == FileAccess::Write && rule.role() == PathRole::OutputRoot)
        .ok_or_else(|| DiagnoseError::invalid("plan.authority.output-root.count"))?;
    let output_root = FreshOutputRoot::create(&resolver, output_authority.path())
        .map_err(|error| DiagnoseError::invalid(error.code()))?;
    if receipt_target.starts_with(output_root.resolved_target())
        || draft_target.starts_with(output_root.resolved_target())
    {
        return Err(DiagnoseError::invalid("diagnostic.output.child-writable"));
    }
    let working_directory = resolver
        .resolve_working_directory(plan.command().working_directory())
        .map_err(|error| DiagnoseError::invalid(error.code()))?;
    let executable = resolver
        .discover_executable(plan.command().executable(), supported.architecture())
        .map_err(|error| DiagnoseError::invalid(error.code()))?;
    let readable = resolve_read_authority(&resolver, &compiled)?;
    let static_scaffold = load_static_scaffold(
        input.static_scaffold.as_deref(),
        &readable,
        &executable,
        supported.architecture(),
    )?;

    let observer_path = fs::canonicalize(
        env::current_exe()
            .map_err(|_| DiagnoseError::execution("diagnostic.observer.path-unavailable"))?,
    )
    .map_err(|_| DiagnoseError::execution("diagnostic.observer.path-unavailable"))?;
    let binary_root = observer_path
        .parent()
        .ok_or_else(|| DiagnoseError::execution("diagnostic.binary-root.unavailable"))?;
    let runtime_path = fs::canonicalize(binary_root.join("pbr"))
        .map_err(|_| DiagnoseError::execution("diagnostic.runtime.path-unavailable"))?;
    let launcher_path = fs::canonicalize(binary_root.join("pbr-native-launcher"))
        .map_err(|_| DiagnoseError::execution("diagnostic.launcher.path-unavailable"))?;
    let observer_artifact = identify_external_artifact(&observer_path, ArtifactRole::RuntimeBinary)
        .map_err(|error| DiagnoseError::execution(error.code()))?;
    let runtime_artifact = identify_external_artifact(&runtime_path, ArtifactRole::RuntimeBinary)
        .map_err(|error| DiagnoseError::execution(error.code()))?;
    let launcher_artifact =
        identify_external_artifact(&launcher_path, ArtifactRole::LauncherBinary)
            .map_err(|error| DiagnoseError::execution(error.code()))?;

    let environment_names = compiled.environment().to_vec();
    let environment = collect_environment(&environment_names)?;
    let arguments = execution_arguments(&plan);
    let seccomp = compile_deny_network_program(compiled.network(), supported.architecture())
        .map_err(|error| DiagnoseError::execution(error.code()))?;
    let normalized_bytes = serde_json::to_vec(&checked_plan_json(&plan)?)
        .map_err(|_| DiagnoseError::invalid("diagnostic.plan.encoding-invalid"))?;
    let normalized_identity = bytes_identity(
        ArtifactRole::NormalizedPlan,
        &normalized_bytes,
        NORMALIZED_PLAN_MODE,
    )?;
    let limits = compiled.cgroup().limits();
    let policy_identity = installed_policy_identity(
        &normalized_identity,
        &seccomp,
        &executable,
        &readable,
        &output_root,
        limits,
    )?;

    let execution_id =
        fresh_execution_id().map_err(|error| DiagnoseError::execution(error.code()))?;
    let cgroup = FreshCgroup::create_v2(supported.cgroup_v2(), execution_id, limits)
        .map_err(|error| DiagnoseError::execution(error.code()))?;
    let launcher_identity =
        LauncherIdentity::new(execution_id, policy_identity.digest(), cgroup.identity());

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
        .ok_or_else(|| DiagnoseError::execution("launcher.file-descriptor.invalid"))?;
    let request = InstallRequest::new(
        launcher_identity,
        executable.executable().identity().clone(),
        descriptor(executable_fd)?,
        descriptor(working_directory_fd)?,
        arguments.clone(),
        environment,
        rules,
        seccomp,
        descriptor_upper_bound,
    )
    .map_err(|error| DiagnoseError::execution(error.code()))?;

    plan_source
        .revalidate_identity()
        .map_err(|error| DiagnoseError::execution(error.code()))?;
    observer_artifact
        .revalidate_identity()
        .map_err(|error| DiagnoseError::execution(error.code()))?;
    runtime_artifact
        .revalidate_identity()
        .map_err(|error| DiagnoseError::execution(error.code()))?;
    launcher_artifact
        .revalidate_identity()
        .map_err(|error| DiagnoseError::execution(error.code()))?;
    executable
        .revalidate_identities()
        .map_err(|error| DiagnoseError::execution(error.code()))?;
    working_directory
        .revalidate_identity()
        .map_err(|error| DiagnoseError::execution(error.code()))?;
    for path in &readable {
        path.revalidate_identity()
            .map_err(|error| DiagnoseError::execution(error.code()))?;
    }
    output_root
        .revalidate_empty()
        .map_err(|error| DiagnoseError::execution(error.code()))?;

    let mut inherited = vec![executable.executable().as_fd(), working_directory.as_fd()];
    if let Some(loader) = executable.loader() {
        inherited.push(loader.as_fd());
    }
    for path in &readable {
        inherited.push(path.as_fd());
    }
    inherited.push(output_root.as_fd());

    let bounds = default_observation_bounds();
    let mut observer = prepare_observer(
        &launcher_artifact,
        request,
        &inherited,
        supported.architecture(),
        supported.landlock_abi(),
        cgroup,
        limits,
        bounds,
    )
    .map_err(|error| DiagnoseError::execution(error.code()))?
    .spawn()
    .map_err(|error| DiagnoseError::execution(error.code()))?
    .wait_for_initial_exec_stop()
    .map_err(|error| DiagnoseError::execution(error.code()))?
    .continue_to_launcher_pause()
    .map_err(|error| DiagnoseError::execution(error.code()))?
    .continue_for_boundary()
    .map_err(|error| DiagnoseError::execution(error.code()))?
    .receive_acknowledgement_and_stop()
    .map_err(|error| DiagnoseError::execution(error.code()))?
    .install_options()
    .map_err(|error| DiagnoseError::execution(error.code()))?
    .release()
    .map_err(|error| DiagnoseError::execution(error.code()))?;

    let mut mapper = DiagnosticEventMapper::new();
    let mut events = Vec::new();
    let mut resolution_gaps = BTreeSet::new();
    let mut observer_error_codes = BTreeSet::new();
    let completed = loop {
        match observer
            .next_event()
            .map_err(|error| DiagnoseError::execution(error.code()))?
        {
            ActiveObserverStep::Continue {
                observer: next,
                event,
            } => {
                retain_resolution_gap(&event, &mut resolution_gaps);
                if let Some(event) = mapper
                    .map(&event)
                    .map_err(|error| DiagnoseError::execution(error.code()))?
                {
                    events.push(event);
                }
                observer = *next;
            }
            ActiveObserverStep::Drain {
                observer: draining,
                observation,
            } => {
                match observation {
                    proofbound_runtime_diagnose_linux::ObserverObservation::Event(event) => {
                        retain_resolution_gap(&event, &mut resolution_gaps);
                        if let Some(event) = mapper
                            .map(&event)
                            .map_err(|error| DiagnoseError::execution(error.code()))?
                        {
                            events.push(event);
                        }
                    }
                    proofbound_runtime_diagnose_linux::ObserverObservation::Failure(error) => {
                        observer_error_codes.insert(error.code());
                    }
                }
                break draining
                    .finish()
                    .map_err(|error| DiagnoseError::execution(error.code()))?;
            }
            ActiveObserverStep::Complete {
                observer: completed,
                event,
            } => {
                retain_resolution_gap(&event, &mut resolution_gaps);
                if let Some(event) = mapper
                    .map(&event)
                    .map_err(|error| DiagnoseError::execution(error.code()))?
                {
                    events.push(event);
                }
                break completed;
            }
        }
    };

    let publication = completed.publication();
    if !matches!(
        publication,
        ObserverDirective::PublishComplete | ObserverDirective::PublishIncomplete
    ) {
        return Err(DiagnoseError::execution("diagnostic.publication.invalid"));
    }
    let gaps = completed
        .protocol()
        .gaps()
        .chain(resolution_gaps)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let completion = match (publication, gaps.is_empty()) {
        (ObserverDirective::PublishComplete, true) => DiagnosticCompletion::Complete,
        (ObserverDirective::PublishComplete | ObserverDirective::PublishIncomplete, false) => {
            DiagnosticCompletion::Incomplete
        }
        _ => return Err(DiagnoseError::execution("diagnostic.publication.invalid")),
    };
    let receipt_parts = DiagnosticReceiptParts {
        execution_id,
        seed_plan: diagnostic_identity(
            plan_source.identity(),
            DiagnosticArtifactRole::ExecutionPlan,
        )?,
        target: diagnostic_identity(
            executable.executable().identity(),
            DiagnosticArtifactRole::RuntimeExecutable,
        )?,
        runtime: diagnostic_identity(
            runtime_artifact.identity(),
            DiagnosticArtifactRole::RuntimeBinary,
        )?,
        launcher: diagnostic_identity(
            launcher_artifact.identity(),
            DiagnosticArtifactRole::LauncherBinary,
        )?,
        observer: diagnostic_identity(
            observer_artifact.identity(),
            DiagnosticArtifactRole::DiagnosticObserver,
        )?,
        platform: DiagnosticPlatform::new(
            receipt_architecture(supported.architecture()),
            supported.kernel_release(),
            supported.landlock_abi().get(),
        )
        .map_err(|error| DiagnoseError::output(error.code()))?,
        arguments,
        environment_names: environment_names
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect(),
        bounds,
        events,
        completion,
        gaps,
        trusted_computing_base: diagnostic_tcb(
            &supported,
            runtime_artifact.identity(),
            launcher_artifact.identity(),
            observer_artifact.identity(),
        )?,
        assumptions: DIAGNOSTIC_ASSUMPTIONS
            .iter()
            .map(|assumption| (*assumption).to_owned())
            .collect(),
    };
    let artifacts = build_diagnostic_artifacts(
        receipt_parts,
        PlanDraftInputs {
            static_scaffold: static_scaffold.as_ref().map(|value| value.digest),
            inputs: draft_inputs(&readable)?,
            identified_closure: static_scaffold
                .map(|value| value.identified_closure)
                .unwrap_or_default(),
            ..PlanDraftInputs::default()
        },
    )
    .map_err(|_| DiagnoseError::output("diagnostic.artifact.construction-failed"))?;
    publish_pair(
        &receipt_target,
        artifacts.receipt().as_bytes(),
        &draft_target,
        artifacts.draft().as_bytes(),
        execution_id.as_bytes(),
    )?;

    Ok(json!({
        "completion": completion.as_str(),
        "draft": draft_target,
        "observer_error_codes": observer_error_codes,
        "receipt": receipt_target,
        "receipt_sha256": format!("sha256:{}", artifacts.receipt().commitment().to_hex()),
        "schema": "proofbound-runtime-diagnose-result/1",
    }))
}

fn default_observation_bounds() -> ObservationBounds {
    ObservationBounds {
        event_count: 100_000,
        event_count_per_process: 10_000,
        output_bytes: 16 * 1024 * 1024,
        path_bytes: 4096,
        process_count: 256,
        socket_address_bytes: 256,
        symlink_hops: 40,
        tracee_string_bytes: 4096,
    }
}

fn retain_resolution_gap(event: &ActiveTraceEvent, gaps: &mut BTreeSet<DiagnosticGap>) {
    let ActiveTraceEvent::SyscallCompleted {
        candidate: Some(candidate),
        ..
    } = event
    else {
        return;
    };
    match candidate {
        TraceCandidateObservation::IdentityDrift => {
            gaps.insert(DiagnosticGap::IdentityDrift);
        }
        TraceCandidateObservation::SymlinkLimit => {
            gaps.insert(DiagnosticGap::SymlinkLimit);
        }
        TraceCandidateObservation::Stable(_) => {}
    }
}

fn checked_plan_json(
    plan: &proofbound_runtime_core::ExecutionPlan,
) -> Result<serde_json::Value, DiagnoseError> {
    let normalized = normalize_authority(plan.authority().clone())
        .map_err(|error| DiagnoseError::invalid(error.code()))?;
    let limits = normalized.limits();
    let mut limit_projection = json!({
        "wall_time_ms": limits.wall_time().milliseconds(),
        "stdout_bytes": limits.stdout().get(),
        "stderr_bytes": limits.stderr().get(),
        "processes": limits.processes().get(),
    });
    if let (Some(memory), Some(swap)) = (limits.memory(), limits.swap()) {
        let object = limit_projection
            .as_object_mut()
            .expect("limit projection is an object");
        object.insert("memory_bytes".to_owned(), json!(memory.get().to_string()));
        object.insert("swap_bytes".to_owned(), json!(swap.get().to_string()));
    }
    Ok(json!({
        "schema": if limits.is_version_two() {
            "proofbound-runtime-plan-check/2"
        } else {
            "proofbound-runtime-plan-check/1"
        },
        "id": plan.id().as_str(),
        "command": {
            "executable": plan.command().executable().as_str(),
            "arguments": plan.command().arguments().iter()
                .map(|argument| argument.as_str())
                .collect::<Vec<_>>(),
            "working_directory": plan.command().working_directory().as_str(),
        },
        "authority": {
            "network": match normalized.network() {
                NetworkMode::Deny => "deny",
            },
            "environment": normalized.environment().iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>(),
            "paths": normalized.paths().iter().map(|entry| json!({
                "path": entry.path().as_str(),
                "access": match entry.access() {
                    FileAccess::Read => "read",
                    FileAccess::Write => "write",
                    FileAccess::Execute => "execute",
                },
                "role": match entry.role() {
                    PathRole::ProjectInput => "project-input",
                    PathRole::OutputRoot => "output-root",
                    PathRole::RuntimeExecutable => "runtime-executable",
                    PathRole::RuntimeLoaderExecutable => "runtime-loader-executable",
                    PathRole::RuntimeLibrary => "runtime-library",
                },
            })).collect::<Vec<_>>(),
            "limits": limit_projection,
        },
    }))
}

fn resolve_read_authority(
    resolver: &RootedPathResolver,
    compiled: &proofbound_runtime_core::CompiledPolicy,
) -> Result<Vec<ResolvedReadPath>, DiagnoseError> {
    compiled
        .filesystem()
        .rules()
        .iter()
        .filter(|rule| rule.access() == FileAccess::Read)
        .map(|rule| {
            let role = match rule.role() {
                PathRole::ProjectInput => ArtifactRole::ProjectInput,
                PathRole::RuntimeLibrary => ArtifactRole::RuntimeLibrary,
                _ => return Err(DiagnoseError::invalid("plan.authority.read.role-invalid")),
            };
            resolver
                .resolve_read_path(rule.path(), role)
                .map_err(|error| DiagnoseError::invalid(error.code()))
        })
        .collect()
}

fn collect_environment(
    names: &[EnvironmentName],
) -> Result<BTreeMap<String, String>, DiagnoseError> {
    let mut environment = BTreeMap::new();
    for name in names {
        let Some(value) = env::var_os(name.as_str()) else {
            continue;
        };
        let value = value
            .into_string()
            .map_err(|_| DiagnoseError::invalid("plan.environment.value.utf8-invalid"))?;
        environment.insert(name.as_str().to_owned(), value);
    }
    Ok(environment)
}

fn execution_arguments(plan: &proofbound_runtime_core::ExecutionPlan) -> Vec<String> {
    core::iter::once(plan.command().executable().as_str().to_owned())
        .chain(
            plan.command()
                .arguments()
                .iter()
                .map(|argument| argument.as_str().to_owned()),
        )
        .collect()
}

fn descriptor(value: i32) -> Result<u32, DiagnoseError> {
    u32::try_from(value).map_err(|_| DiagnoseError::execution("launcher.file-descriptor.invalid"))
}

fn launcher_rule(
    descriptor_value: i32,
    access: Vec<LandlockAccess>,
) -> Result<LauncherFilesystemRule, DiagnoseError> {
    LauncherFilesystemRule::new(descriptor(descriptor_value)?, access)
        .map_err(|error| DiagnoseError::execution(error.code()))
}

fn bytes_identity(
    role: ArtifactRole,
    bytes: &[u8],
    mode: u16,
) -> Result<ArtifactIdentity, DiagnoseError> {
    let mode = FileMode::new(mode).map_err(|error| DiagnoseError::output(error.code()))?;
    Ok(ArtifactIdentity::new(
        role,
        Sha256Digest::from_bytes(Sha256::digest(bytes).into()),
        u64::try_from(bytes.len())
            .map_err(|_| DiagnoseError::output("diagnostic.artifact.size-invalid"))?,
        mode,
    ))
}

fn installed_policy_identity(
    normalized: &ArtifactIdentity,
    seccomp: &[u8],
    executable: &proofbound_runtime_linux::ExecutableClosure,
    readable: &[ResolvedReadPath],
    output_root: &FreshOutputRoot,
    limits: ResourceLimits,
) -> Result<ArtifactIdentity, DiagnoseError> {
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
            .map_err(|_| DiagnoseError::output("diagnostic.policy.size-invalid"))?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(seccomp);
    bytes_identity(ArtifactRole::CompiledPolicy, &bytes, POLICY_MODE)
}

fn encode_artifact(output: &mut Vec<u8>, identity: &ArtifactIdentity) -> Result<(), DiagnoseError> {
    let role = identity.role().as_str().as_bytes();
    output.extend_from_slice(
        &u64::try_from(role.len())
            .map_err(|_| DiagnoseError::output("diagnostic.artifact.role-size-invalid"))?
            .to_be_bytes(),
    );
    output.extend_from_slice(role);
    output.extend_from_slice(identity.digest().as_bytes());
    output.extend_from_slice(&identity.size().to_be_bytes());
    output.extend_from_slice(&identity.mode().get().to_be_bytes());
    Ok(())
}

fn diagnostic_identity(
    identity: &ArtifactIdentity,
    role: DiagnosticArtifactRole,
) -> Result<DiagnosticArtifactIdentity, DiagnoseError> {
    DiagnosticArtifactIdentity::new(role, identity.digest(), identity.size(), identity.mode())
        .map_err(|error| DiagnoseError::output(error.code()))
}

const MAX_STATIC_SCAFFOLD_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
struct StaticScaffoldInput {
    digest: Sha256Digest,
    identified_closure: Vec<IdentifiedClosureEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticScaffoldReport {
    schema: String,
    safe_policy: bool,
    host_profile: StaticHostProfile,
    executable: StaticArtifact,
    interpreter: Option<StaticArtifact>,
    resolution_inputs: Vec<StaticArtifact>,
    dependencies: Vec<StaticDependency>,
    suggested_runtime_roots: Vec<StaticRuntimeRoot>,
    open_items: Vec<StaticOpenItem>,
}

#[derive(Deserialize)]
enum StaticHostProfile {
    #[serde(rename = "linux-glibc-x86-64-v1")]
    LinuxGlibcX86_64V1,
    #[serde(rename = "linux-glibc-aarch64-v1")]
    LinuxGlibcAarch64V1,
    #[serde(rename = "linux-musl-x86-64-v1")]
    LinuxMuslX86_64V1,
    #[serde(rename = "linux-musl-aarch64-v1")]
    LinuxMuslAarch64V1,
}

impl StaticHostProfile {
    const fn supports(&self, architecture: Architecture) -> bool {
        matches!(
            (self, architecture),
            (
                Self::LinuxGlibcX86_64V1 | Self::LinuxMuslX86_64V1,
                Architecture::X86_64
            ) | (
                Self::LinuxGlibcAarch64V1 | Self::LinuxMuslAarch64V1,
                Architecture::Aarch64
            )
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticArtifact {
    mode: String,
    requested: String,
    resolved: String,
    sha256: String,
    size_bytes: u64,
    symlink_chain: Vec<StaticSymlinkHop>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticSymlinkHop {
    path: String,
    target: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticDependency {
    candidates: Vec<StaticSearchCandidate>,
    declared_by: String,
    search_rule: StaticSearchRule,
    selected: StaticArtifact,
    soname: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticSearchCandidate {
    path: String,
    search_rule: StaticSearchRule,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum StaticSearchRule {
    ElfRpath,
    ElfRunpath,
    GlibcLoaderCacheExact,
    InheritedRpath,
    MuslPathFile,
    ProfileDefault,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticRuntimeRoot {
    path: String,
    provenance: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticOpenItem {
    code: StaticOpenItemCode,
    detail: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum StaticOpenItemCode {
    ChooseEnvironment,
    ChooseLimits,
    ChooseNetworkMode,
    ChooseWriteRoots,
    ConfigurationUnresolved,
    DynamicLoadsUnresolved,
    LoaderDataUnavailable,
    RelativeSearchPath,
    SearchPathConflict,
    UnsupportedDynamicToken,
}

fn load_static_scaffold(
    requested: Option<&Path>,
    readable: &[ResolvedReadPath],
    target: &proofbound_runtime_linux::ExecutableClosure,
    architecture: Architecture,
) -> Result<Option<StaticScaffoldInput>, DiagnoseError> {
    let Some(requested) = requested else {
        return Ok(None);
    };
    if requested.as_os_str().is_empty() || requested.is_absolute() {
        return Err(DiagnoseError::invalid(
            "diagnostic.static-scaffold.path-invalid",
        ));
    }
    let mut matches = readable
        .iter()
        .filter(|candidate| candidate.requested_path() == requested);
    let selected = matches
        .next()
        .ok_or_else(|| DiagnoseError::invalid("diagnostic.static-scaffold.not-declared"))?;
    if matches.next().is_some() || selected.identity().role() != ArtifactRole::ProjectInput {
        return Err(DiagnoseError::invalid(
            "diagnostic.static-scaffold.not-declared",
        ));
    }
    let ResolvedReadPath::File(file) = selected else {
        return Err(DiagnoseError::invalid(
            "diagnostic.static-scaffold.file-required",
        ));
    };
    if file.identity().size() > MAX_STATIC_SCAFFOLD_BYTES {
        return Err(DiagnoseError::invalid(
            "diagnostic.static-scaffold.size-invalid",
        ));
    }
    let bytes = file
        .read_bytes()
        .map_err(|_| DiagnoseError::invalid("diagnostic.static-scaffold.identity-drift"))?;
    let report: StaticScaffoldReport = serde_json::from_slice(&bytes)
        .map_err(|_| DiagnoseError::invalid("diagnostic.static-scaffold.schema-invalid"))?;
    validate_static_scaffold(&report, target, readable, architecture)?;

    let mut identified_closure = Vec::with_capacity(2 + report.dependencies.len());
    identified_closure.push(closure_entry(
        IdentifiedClosureRole::Executable,
        &report.executable,
        DraftProvenance::StaticExecutableClosure,
    )?);
    if let Some(interpreter) = &report.interpreter {
        identified_closure.push(closure_entry(
            IdentifiedClosureRole::Interpreter,
            interpreter,
            DraftProvenance::PlatformRequiredClosure,
        )?);
    }
    for dependency in &report.dependencies {
        identified_closure.push(closure_entry(
            IdentifiedClosureRole::RuntimeLibrary,
            &dependency.selected,
            DraftProvenance::PlatformRequiredClosure,
        )?);
    }
    Ok(Some(StaticScaffoldInput {
        digest: file.identity().digest(),
        identified_closure,
    }))
}

fn closure_entry(
    role: IdentifiedClosureRole,
    artifact: &StaticArtifact,
    provenance: DraftProvenance,
) -> Result<IdentifiedClosureEntry, DiagnoseError> {
    IdentifiedClosureEntry::new(
        role,
        artifact.resolved.clone(),
        ContentIdentity::new(
            parse_static_digest(&artifact.sha256).ok_or_else(|| {
                DiagnoseError::invalid("diagnostic.static-scaffold.schema-invalid")
            })?,
            artifact.size_bytes,
        ),
        parse_static_mode(&artifact.mode)
            .ok_or_else(|| DiagnoseError::invalid("diagnostic.static-scaffold.schema-invalid"))?,
        provenance,
    )
    .map_err(|_| DiagnoseError::invalid("diagnostic.static-scaffold.schema-invalid"))
}

fn validate_static_scaffold(
    report: &StaticScaffoldReport,
    target: &proofbound_runtime_linux::ExecutableClosure,
    readable: &[ResolvedReadPath],
    architecture: Architecture,
) -> Result<(), DiagnoseError> {
    if report.schema != "proofbound-runtime-plan-scaffold/1" || report.safe_policy {
        return Err(DiagnoseError::invalid(
            "diagnostic.static-scaffold.schema-invalid",
        ));
    }
    if !report.host_profile.supports(architecture) {
        return Err(DiagnoseError::invalid(
            "diagnostic.static-scaffold.profile-mismatch",
        ));
    }
    validate_static_artifact(&report.executable)?;
    if !static_artifact_matches_file(&report.executable, target.executable()) {
        return Err(DiagnoseError::invalid(
            "diagnostic.static-scaffold.target-mismatch",
        ));
    }
    if report.resolution_inputs.len() > 257
        || report.dependencies.len() > 256
        || report.suggested_runtime_roots.len() > 257
        || report.open_items.len() > 65_536
    {
        return Err(DiagnoseError::invalid(
            "diagnostic.static-scaffold.schema-invalid",
        ));
    }
    for artifact in report.resolution_inputs.iter() {
        validate_static_artifact(artifact)?;
    }
    match (&report.interpreter, target.loader()) {
        (Some(interpreter), Some(loader)) => {
            validate_static_artifact(interpreter)?;
            if !static_artifact_matches_file(interpreter, loader) {
                return Err(DiagnoseError::invalid(
                    "diagnostic.static-scaffold.target-mismatch",
                ));
            }
        }
        (None, None) => {}
        _ => {
            return Err(DiagnoseError::invalid(
                "diagnostic.static-scaffold.target-mismatch",
            ));
        }
    }
    for dependency in &report.dependencies {
        validate_static_dependency(dependency)?;
        if !readable.iter().any(|path| {
            matches!(path, ResolvedReadPath::File(_))
                && path.identity().role() == ArtifactRole::RuntimeLibrary
                && static_artifact_matches_resolved(&dependency.selected, path)
        }) {
            return Err(DiagnoseError::invalid(
                "diagnostic.static-scaffold.dependency-not-declared",
            ));
        }
    }
    for root in &report.suggested_runtime_roots {
        if !Path::new(&root.path).is_absolute()
            || root.path.len() > 1_048_576
            || root.provenance.is_empty()
            || root.provenance.len() > 257
            || root
                .provenance
                .iter()
                .any(|value| value.is_empty() || value.len() > 1_048_576)
        {
            return Err(DiagnoseError::invalid(
                "diagnostic.static-scaffold.schema-invalid",
            ));
        }
    }
    for item in &report.open_items {
        let _ = &item.code;
        if item.detail.is_empty() || item.detail.len() > 1_048_576 {
            return Err(DiagnoseError::invalid(
                "diagnostic.static-scaffold.schema-invalid",
            ));
        }
    }
    Ok(())
}

fn validate_static_dependency(dependency: &StaticDependency) -> Result<(), DiagnoseError> {
    if dependency.candidates.is_empty()
        || dependency.candidates.len() > 256
        || dependency.soname.is_empty()
        || dependency.soname.contains('/')
        || !Path::new(&dependency.declared_by).is_absolute()
    {
        return Err(DiagnoseError::invalid(
            "diagnostic.static-scaffold.schema-invalid",
        ));
    }
    let _ = &dependency.search_rule;
    validate_static_artifact(&dependency.selected)?;
    for candidate in &dependency.candidates {
        let _ = &candidate.search_rule;
        if !Path::new(&candidate.path).is_absolute() || candidate.path.len() > 1_048_576 {
            return Err(DiagnoseError::invalid(
                "diagnostic.static-scaffold.schema-invalid",
            ));
        }
    }
    Ok(())
}

fn validate_static_artifact(artifact: &StaticArtifact) -> Result<(), DiagnoseError> {
    if artifact.requested.is_empty()
        || artifact.requested.len() > 1_048_576
        || !Path::new(&artifact.resolved).is_absolute()
        || artifact.resolved.len() > 1_048_576
        || artifact.size_bytes > 64 * 1024 * 1024
        || parse_static_mode(&artifact.mode).is_none()
        || parse_static_digest(&artifact.sha256).is_none()
        || artifact.symlink_chain.len() > 40
        || artifact.symlink_chain.iter().any(|hop| {
            hop.path.is_empty()
                || hop.target.is_empty()
                || hop.path.len() > 1_048_576
                || hop.target.len() > 1_048_576
        })
    {
        return Err(DiagnoseError::invalid(
            "diagnostic.static-scaffold.schema-invalid",
        ));
    }
    Ok(())
}

fn static_artifact_matches(artifact: &StaticArtifact, identity: &ArtifactIdentity) -> bool {
    parse_static_digest(&artifact.sha256) == Some(identity.digest())
        && artifact.size_bytes == identity.size()
        && parse_static_mode(&artifact.mode) == Some(identity.mode().get())
}

fn static_artifact_matches_file(
    artifact: &StaticArtifact,
    file: &proofbound_runtime_linux::ResolvedFile,
) -> bool {
    static_artifact_matches(artifact, file.identity())
        && Path::new(&artifact.resolved) == file.resolved_target()
}

fn static_artifact_matches_resolved(artifact: &StaticArtifact, file: &ResolvedReadPath) -> bool {
    static_artifact_matches(artifact, file.identity())
        && Path::new(&artifact.resolved) == file.resolved_target()
}

fn parse_static_digest(value: &str) -> Option<Sha256Digest> {
    value
        .strip_prefix("sha256:")
        .and_then(|hex| Sha256Digest::parse_hex(hex).ok())
}

fn parse_static_mode(value: &str) -> Option<u16> {
    if value.len() != 4 || !value.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return None;
    }
    u16::from_str_radix(value, 8).ok()
}

fn draft_inputs(readable: &[ResolvedReadPath]) -> Result<Vec<DraftInput>, DiagnoseError> {
    readable
        .iter()
        .filter(|path| path.identity().role() == ArtifactRole::ProjectInput)
        .map(|path| {
            DraftInput::new(
                path.resolved_target()
                    .to_str()
                    .ok_or_else(|| DiagnoseError::output("diagnostic.input.path-invalid"))?
                    .to_owned(),
                ContentIdentity::new(path.identity().digest(), path.identity().size()),
                path.identity().mode().get(),
            )
            .map_err(|error| DiagnoseError::output(error.code()))
        })
        .collect()
}

fn diagnostic_tcb(
    supported: &proofbound_runtime_linux::SupportedLinux,
    runtime: &ArtifactIdentity,
    launcher: &ArtifactIdentity,
    observer: &ArtifactIdentity,
) -> Result<Vec<DiagnosticTcbEntry>, DiagnoseError> {
    let entries = [
        (
            DiagnosticTcbRole::DiagnosticObserver,
            observer.digest().to_hex(),
        ),
        (
            DiagnosticTcbRole::Filesystem,
            "local-filesystem:unattested".to_owned(),
        ),
        (
            DiagnosticTcbRole::Hardware,
            "local-host:unattested".to_owned(),
        ),
        (
            DiagnosticTcbRole::LinuxKernel,
            supported.kernel_release().to_owned(),
        ),
        (
            DiagnosticTcbRole::RuntimeLauncher,
            launcher.digest().to_hex(),
        ),
        (
            DiagnosticTcbRole::RuntimeSupervisor,
            format!(
                "{}:{}",
                runtime.digest().to_hex(),
                observer.digest().to_hex()
            ),
        ),
    ];
    entries
        .into_iter()
        .map(|(role, identity)| {
            DiagnosticTcbEntry::new(role, identity)
                .map_err(|error| DiagnoseError::output(error.code()))
        })
        .collect()
}

const fn receipt_architecture(architecture: Architecture) -> ReceiptArchitecture {
    match architecture {
        Architecture::X86_64 => ReceiptArchitecture::X86_64,
        Architecture::Aarch64 => ReceiptArchitecture::Aarch64,
    }
}

fn prepare_absent_target(path: &Path, prefix: &'static str) -> Result<PathBuf, DiagnoseError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|_| DiagnoseError::invalid("diagnostic.output.parent-unavailable"))?
            .join(path)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| DiagnoseError::invalid("diagnostic.output.parent-unavailable"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|_| DiagnoseError::invalid("diagnostic.output.parent-unavailable"))?;
    let leaf = absolute
        .file_name()
        .ok_or_else(|| DiagnoseError::invalid("diagnostic.output.path-invalid"))?;
    let target = parent.join(leaf);
    match fs::symlink_metadata(&target) {
        Ok(_) => Err(DiagnoseError::invalid(if prefix == "diagnostic.receipt" {
            "diagnostic.receipt.exists"
        } else {
            "diagnostic.draft.exists"
        })),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(target),
        Err(_) => Err(DiagnoseError::invalid("diagnostic.output.unavailable")),
    }
}

fn publish_pair(
    receipt_target: &Path,
    receipt: &[u8],
    draft_target: &Path,
    draft: &[u8],
    execution_id: &[u8; 16],
) -> Result<(), DiagnoseError> {
    let suffix = encode_hex(execution_id);
    let receipt_temp = stage_output(receipt_target, receipt, &format!("receipt-{suffix}"))?;
    let draft_temp = match stage_output(draft_target, draft, &format!("draft-{suffix}")) {
        Ok(path) => path,
        Err(error) => {
            let _ = fs::remove_file(&receipt_temp);
            return Err(error);
        }
    };
    if fs::hard_link(&draft_temp, draft_target).is_err() {
        let _ = fs::remove_file(&receipt_temp);
        let _ = fs::remove_file(&draft_temp);
        return Err(DiagnoseError::output("diagnostic.draft.publish-failed"));
    }
    if fs::hard_link(&receipt_temp, receipt_target).is_err() {
        let _ = fs::remove_file(draft_target);
        let _ = fs::remove_file(&receipt_temp);
        let _ = fs::remove_file(&draft_temp);
        return Err(DiagnoseError::output("diagnostic.receipt.publish-failed"));
    }
    fs::remove_file(&receipt_temp)
        .and_then(|()| fs::remove_file(&draft_temp))
        .map_err(|_| DiagnoseError::output("diagnostic.output.cleanup-failed"))?;
    sync_parent(receipt_target)?;
    if receipt_target.parent() != draft_target.parent() {
        sync_parent(draft_target)?;
    }
    Ok(())
}

fn stage_output(target: &Path, bytes: &[u8], suffix: &str) -> Result<PathBuf, DiagnoseError> {
    let parent = target
        .parent()
        .ok_or_else(|| DiagnoseError::output("diagnostic.output.parent-unavailable"))?;
    let temporary = parent.join(format!(".pbr-diagnose-{suffix}.tmp"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| DiagnoseError::output("diagnostic.output.create-failed"))?;
    if file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        let _ = fs::remove_file(&temporary);
        return Err(DiagnoseError::output("diagnostic.output.write-failed"));
    }
    Ok(temporary)
}

fn sync_parent(target: &Path) -> Result<(), DiagnoseError> {
    let parent = target
        .parent()
        .ok_or_else(|| DiagnoseError::output("diagnostic.output.parent-unavailable"))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| DiagnoseError::output("diagnostic.output.sync-failed"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_requires_each_exact_output_and_cgroup_argument_once() {
        let parsed = parse_args([
            OsString::from("pbr-diagnose"),
            OsString::from("--plan"),
            OsString::from("seed.cbor"),
            OsString::from("--receipt"),
            OsString::from("receipt.json"),
            OsString::from("--draft"),
            OsString::from("draft.json"),
            OsString::from("--cgroup-root"),
            OsString::from("/sys/fs/cgroup/delegated"),
            OsString::from("--static-scaffold"),
            OsString::from("plan-scaffold.json"),
        ])
        .expect("complete diagnostic command");
        assert_eq!(parsed.plan, PathBuf::from("seed.cbor"));
        assert_eq!(parsed.receipt, PathBuf::from("receipt.json"));
        assert_eq!(parsed.draft, PathBuf::from("draft.json"));
        assert_eq!(
            parsed.static_scaffold,
            Some(PathBuf::from("plan-scaffold.json"))
        );

        for invalid in [
            vec!["pbr-diagnose", "--plan", "seed.cbor"],
            vec![
                "pbr-diagnose",
                "--plan",
                "seed.cbor",
                "--plan",
                "other.cbor",
                "--receipt",
                "receipt.json",
                "--draft",
                "draft.json",
                "--cgroup-root",
                "/sys/fs/cgroup/delegated",
            ],
        ] {
            assert_eq!(
                parse_args(invalid.into_iter().map(OsString::from)),
                Err(DiagnoseError::invalid("diagnostic.cli.usage-invalid"))
            );
        }
    }

    #[test]
    fn diagnostic_bounds_are_closed_and_nonzero() {
        assert_eq!(
            default_observation_bounds().validate(),
            Ok(default_observation_bounds())
        );
    }

    #[test]
    fn diagnostic_assumption_set_is_closed() {
        assert_eq!(
            DIAGNOSTIC_ASSUMPTIONS,
            [
                "PBR-DIAGNOSTIC-CANDIDATE-AX-027",
                "PBR-DIAGNOSTIC-COMMAND-AX-029",
                "PBR-DIAGNOSTIC-DECODE-AX-017",
                "PBR-DIAGNOSTIC-LIFECYCLE-AX-023",
                "PBR-DIAGNOSTIC-OBJECT-AX-025",
                "PBR-DIAGNOSTIC-STREAM-AX-022",
                "PBR-DIAGNOSTIC-TRACE-AX-016",
            ]
        );
    }
}
