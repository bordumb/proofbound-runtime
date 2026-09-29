//! Native declared-egress orchestration for the version 3 execution path.

use super::*;
use proofbound_runtime_core::{
    AddressScope, AuthorityPath, EgressAuthority, EgressDestination, EgressExecutionPlan,
    MemoryByteLimit, OutputByteLimit, ProcessLimit, ReceiptNetworkV3, ResolverAddress, RunResultV3,
    SniBinding, SwapByteLimit,
};
use proofbound_runtime_linux::egress_supervisor::{
    EgressSupervisedExecution, EgressSupervisorInputs, supervise_egress_launcher,
};
use proofbound_runtime_linux::{ResolvedFile, egress_child_seccomp};
use serde_json::json;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;

fn authority_json(authority: &EgressAuthority) -> Value {
    let endpoints = authority
        .endpoints()
        .iter()
        .map(|endpoint| {
            let destination = match &endpoint.destination {
                EgressDestination::DnsName { name, scope } => json!({
                    "kind": "dns-name", "name": name.as_str(),
                    "address_scope": match scope {
                        AddressScope::Global => "global",
                        AddressScope::GlobalOrPrivate => "global-or-private",
                    },
                }),
                EgressDestination::Ipv4(bytes) => json!({"kind": "ipv4", "bytes": bytes}),
                EgressDestination::Ipv6(bytes) => json!({"kind": "ipv6", "bytes": bytes}),
            };
            let tls_sni = match &endpoint.tls_sni {
                SniBinding::NotInspected => json!("not-inspected"),
                SniBinding::Required(name) => json!({"mode": "required", "name": name.as_str()}),
            };
            json!({"destination": destination, "port": endpoint.port.get(),
                "protocol": "tcp", "tls_sni": tls_sni})
        })
        .collect::<Vec<_>>();
    let resolver = authority.resolver();
    let address = match resolver.endpoint().address() {
        ResolverAddress::Ipv4(bytes) => json!({"family": "ipv4", "bytes": bytes}),
        ResolverAddress::Ipv6(bytes) => json!({"family": "ipv6", "bytes": bytes}),
    };
    let limits = authority.limits();
    json!({
        "endpoints": endpoints,
        "resolver": {
            "address": address,
            "port": resolver.endpoint().port().get(),
            "configuration": resolver.configuration().as_str(),
            "maximum_cname_depth": resolver.maximum_cname_depth(),
            "maximum_answer_count": resolver.maximum_answer_count(),
            "maximum_response_bytes": resolver.maximum_response_bytes(),
            "resolution_deadline_ms": resolver.resolution_deadline_ms(),
            "attempt_deadline_ms": resolver.attempt_deadline_ms(),
            "address_order": "ipv4-then-ipv6-lexicographic",
        },
        "limits": {
            "connections": limits.connections,
            "concurrent_connections": limits.concurrent_connections,
            "attempts_per_connection": limits.attempts_per_connection,
            "resolutions": limits.resolutions,
            "dns_messages": limits.dns_messages,
            "client_to_remote_bytes": limits.client_to_remote_bytes,
            "remote_to_client_bytes": limits.remote_to_client_bytes,
            "connection_idle_ms": limits.connection_idle_ms,
        },
        "proxy_executable": authority.proxy_executable().as_str(),
        "proxy_runtime_read": authority.proxy_runtime_read().iter().map(|path| path.as_str()).collect::<Vec<_>>(),
        "proxy_environment": authority.proxy_environment().iter().map(|name| name.as_str()).collect::<Vec<_>>(),
    })
}

fn artifact_json(artifact: &ArtifactIdentity) -> Value {
    json!({"sha256": artifact.digest().to_hex(), "size": artifact.size(),
        "mode": artifact.mode().get()})
}

fn observed_boundary(execution: &EgressSupervisedExecution) -> Result<Value, RunError> {
    let supervisor_net = fs::metadata("/proc/self/ns/net").map_err(|_| {
        RunError::receipt(
            RunPhase::ReceiptConstruction,
            RunRule::ReceiptConstructed,
            "receipt.network.egress.namespace-unavailable",
        )
    })?;
    let namespace = &execution.namespace;
    let routes = namespace
        .routes
        .iter()
        .map(|route| {
            json!({
                "family": route.family,
                "destination": {"family": route.family, "bytes": route.destination},
                "prefix_length": route.prefix_length,
                "interface": route.interface,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "user_namespace": {"device": namespace.user_namespace.device, "inode": namespace.user_namespace.inode},
        "child_network_namespace": {"device": namespace.network_namespace.device, "inode": namespace.network_namespace.inode},
        "supervisor_network_namespace": {"device": supervisor_net.dev(), "inode": supervisor_net.ino()},
        "uid_map": {"inside": namespace.uid_map.inside, "outside": namespace.uid_map.outside, "length": namespace.uid_map.length},
        "gid_map": {"inside": namespace.gid_map.inside, "outside": namespace.gid_map.outside, "length": namespace.gid_map.length},
        "interfaces": namespace.interfaces,
        "routes": routes,
        "listener": {"address": [127, 0, 0, 1], "port": 3128, "backlog": 128},
        "landlock_abi": execution.boundary["landlock_abi"],
        "landlock_handled_network": ["tcp-bind", "tcp-connect"],
        "child_filter_sha256": execution.boundary["child_filter_sha256"],
        "proxy_filter_sha256": execution.proxy_ready.filter_sha256.to_hex(),
    }))
}

fn egress_error(code: &'static str) -> RunError {
    RunError::launcher(
        RunPhase::LauncherProtocol,
        RunRule::LauncherBoundaryComplete,
        code,
    )
}

pub(super) fn execute_egress_prepared(
    receipt_path: PathBuf,
    canonical_plan: PathBuf,
    plan_source: ResolvedFile,
    plan_bytes: Vec<u8>,
    plan: EgressExecutionPlan,
    cgroup_root: &Path,
    runtime_executable: &Path,
) -> Result<ObservedRun, RunError> {
    let start = std::time::Instant::now();
    let base = plan.base();
    let authority = plan.egress();
    let normalized = normalize_authority(base.authority().clone()).map_err(|error| {
        RunError::invalid(
            RunPhase::AuthorityNormalization,
            RunRule::AuthorityNormalized,
            error.code(),
        )
    })?;
    let compiled = compile_policy(normalized.clone());
    if !proofbound_runtime_core::compile_egress_policy(authority)
        .is_no_more_permissive_than(authority)
    {
        return Err(RunError::invalid(
            RunPhase::PolicyCompilation,
            RunRule::PolicyIdentityConstructed,
            "policy.network.egress.authority-expanded",
        ));
    }
    let plan_root = canonical_plan.parent().ok_or_else(|| {
        RunError::invalid(
            RunPhase::PlanRoot,
            RunRule::PlanRootConfined,
            "plan.input.parent-unavailable",
        )
    })?;
    let resolver = RootedPathResolver::open(plan_root)
        .map_err(|error| map_resolution(RunPhase::PlanRoot, RunRule::PlanRootConfined, error))?;
    let normalization_elapsed = start.elapsed();

    let phase = std::time::Instant::now();
    let supported = probe_capabilities(cgroup_root)
        .require_supported()
        .map_err(map_probe)?;
    if !(9..=11).contains(&supported.landlock_abi().get()) {
        return Err(RunError::unsupported(
            RunPhase::HostCapabilities,
            RunRule::HostSupported,
            "host.landlock.abi-below-egress",
        ));
    }
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
        .resolve_working_directory(base.command().working_directory())
        .map_err(|error| {
            map_resolution(
                RunPhase::WorkingDirectory,
                RunRule::WorkingDirectoryResolved,
                error,
            )
        })?;
    let preflight_elapsed = phase.elapsed();

    let phase = std::time::Instant::now();
    let execute_paths = compiled
        .filesystem()
        .rules()
        .iter()
        .filter(|rule| rule.access() == FileAccess::Execute)
        .map(|rule| rule.path().clone())
        .collect::<Vec<_>>();
    let executable_set = resolver
        .discover_executable_set(
            &execute_paths,
            base.command().executable(),
            output_root.resolved_target(),
            supported.architecture(),
        )
        .map_err(|error| {
            RunError::identity(
                RunPhase::ExecutableClosure,
                RunRule::ExecutableClosureResolved,
                error.code(),
            )
        })?;
    let executable = resolver
        .discover_executable(base.command().executable(), supported.architecture())
        .map_err(|error| {
            map_resolution(
                RunPhase::ExecutableClosure,
                RunRule::ExecutableClosureResolved,
                error,
            )
        })?;
    if executable_set.command().file().identity() != executable.executable().identity() {
        return Err(RunError::identity(
            RunPhase::ExecutableClosure,
            RunRule::ExecutableClosureResolved,
            "resolve.executable.identity-drift",
        ));
    }
    let readable = resolve_read_authority(&resolver, &compiled)?;
    let proxy_path =
        AuthorityPath::new(authority.proxy_executable().as_str().to_owned()).map_err(|error| {
            RunError::invalid(RunPhase::PlanValidation, RunRule::PlanValid, error.code())
        })?;
    let proxy = resolver
        .resolve_external_file(&proxy_path, ArtifactRole::RuntimeExecutable)
        .map_err(|error| {
            map_resolution(
                RunPhase::RuntimeIdentity,
                RunRule::RuntimeIdentityObserved,
                error,
            )
        })?;
    let proxy_closure = authority
        .proxy_runtime_read()
        .iter()
        .map(|path| {
            let path = AuthorityPath::new(path.as_str().to_owned()).map_err(|error| {
                RunError::invalid(RunPhase::PlanValidation, RunRule::PlanValid, error.code())
            })?;
            resolver
                .resolve_read_path(&path, ArtifactRole::RuntimeLibrary)
                .map_err(|error| {
                    map_resolution(
                        RunPhase::ReadAuthority,
                        RunRule::ReadAuthorityResolved,
                        error,
                    )
                })
        })
        .collect::<Result<Vec<_>, RunError>>()?;
    let resolver_path =
        AuthorityPath::new(authority.resolver().configuration().as_str().to_owned()).map_err(
            |error| RunError::invalid(RunPhase::PlanValidation, RunRule::PlanValid, error.code()),
        )?;
    let resolver_configuration = resolver
        .resolve_read_path(&resolver_path, ArtifactRole::RuntimeLibrary)
        .map_err(|error| {
            map_resolution(
                RunPhase::ReadAuthority,
                RunRule::ReadAuthorityResolved,
                error,
            )
        })?;

    let runtime_path = fs::canonicalize(runtime_executable).map_err(|_| {
        RunError::identity(
            RunPhase::RuntimeIdentity,
            RunRule::RuntimeIdentityObserved,
            "runtime.path.unavailable",
        )
    })?;
    let bundle_root = runtime_path.parent().ok_or_else(|| {
        RunError::identity(
            RunPhase::RuntimeIdentity,
            RunRule::RuntimeIdentityObserved,
            "runtime.path.unavailable",
        )
    })?;
    let launcher_path =
        fs::canonicalize(bundle_root.join("pbr-native-launcher")).map_err(|_| {
            RunError::identity(
                RunPhase::LauncherIdentity,
                RunRule::LauncherIdentityObserved,
                "launcher.path.unavailable",
            )
        })?;
    let bundle_proxy = fs::canonicalize(bundle_root.join("pbr-egress-proxy")).map_err(|_| {
        RunError::identity(
            RunPhase::RuntimeIdentity,
            RunRule::RuntimeIdentityObserved,
            "network.egress.proxy.path-unavailable",
        )
    })?;
    if proxy.resolved_target() != bundle_proxy {
        return Err(RunError::identity(
            RunPhase::RuntimeIdentity,
            RunRule::RuntimeIdentityObserved,
            "network.egress.proxy.bundle-mismatch",
        ));
    }
    let runtime_artifact = identify_external_artifact(&runtime_path, ArtifactRole::RuntimeBinary)
        .map_err(|error| {
        map_resolution(
            RunPhase::RuntimeIdentity,
            RunRule::RuntimeIdentityObserved,
            error,
        )
    })?;
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
    let mut environment = collect_environment(&receipt_environment)?;
    for variable in authority.proxy_environment() {
        environment.insert(
            variable.as_str().to_owned(),
            "http://127.0.0.1:3128".to_owned(),
        );
    }
    let arguments = execution_arguments(base);
    let argument_identity = arguments_identity(&arguments);
    let seccomp =
        egress_child_seccomp::compile_child_seccomp(supported.architecture()).map_err(|error| {
            RunError::launcher(
                RunPhase::PolicyCompilation,
                RunRule::PolicyIdentityConstructed,
                error.code(),
            )
        })?;
    let mut normalized_json = crate::plan::checked_plan_json(base).map_err(|error| {
        RunError::invalid(
            RunPhase::PolicyCompilation,
            RunRule::PolicyIdentityConstructed,
            error.code(),
        )
    })?;
    normalized_json["schema"] = json!("proofbound-runtime-plan-check/3");
    let mut network_json = authority_json(authority);
    network_json["mode"] = json!("declared-egress");
    normalized_json["authority"]["network"] = network_json;
    let normalized_bytes = serde_json::to_vec(&normalized_json).map_err(|_| {
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
    let base_policy = installed_policy_identity(
        &normalized_identity,
        &seccomp,
        &executable,
        &readable,
        &output_root,
        compiled.cgroup().limits(),
    )?;
    let mut hasher = Sha256::new();
    hasher.update(b"PBR-EGRESS-POLICY/1");
    hasher.update(base_policy.digest().as_bytes());
    hasher.update(proxy.identity().digest().as_bytes());
    for member in &proxy_closure {
        hasher.update(member.identity().digest().as_bytes());
    }
    hasher.update(resolver_configuration.identity().digest().as_bytes());
    let proxy_filter =
        proofbound_runtime_linux::egress_seccomp::compile_proxy_seccomp(supported.architecture())
            .map_err(|error| {
            RunError::launcher(
                RunPhase::PolicyCompilation,
                RunRule::PolicyIdentityConstructed,
                error.code(),
            )
        })?;
    hasher.update(Sha256::digest(&proxy_filter));
    let policy_bytes = hasher.finalize().to_vec();
    let policy_identity = bytes_identity(
        ArtifactRole::CompiledPolicy,
        &policy_bytes,
        POLICY_MODE,
        RunPhase::PolicyCompilation,
        RunRule::PolicyIdentityConstructed,
    )?;
    let inventory_elapsed = phase.elapsed();

    let phase = std::time::Instant::now();
    let execution_id = fresh_execution_id().map_err(map_execution_setup)?;
    let limits = compiled.cgroup().limits();
    let child_cgroup =
        FreshCgroup::create_v2(supported.cgroup_v2(), execution_id, limits).map_err(map_cgroup)?;
    let cgroup_identity = child_cgroup.identity();
    let proxy_memory =
        16 * 1024 * 1024 + u64::from(authority.limits().concurrent_connections) * 256 * 1024;
    let proxy_limits = ResourceLimits::new_v2(
        ProcessLimit::new(1).expect("one is valid"),
        limits.wall_time(),
        OutputByteLimit::new(0),
        OutputByteLimit::new(0),
        MemoryByteLimit::new(proxy_memory).expect("proxy memory is quantized"),
        SwapByteLimit::new(0).expect("zero swap is valid"),
    );
    let proxy_cgroup = FreshCgroup::create_v2(
        supported.cgroup_v2(),
        fresh_execution_id().map_err(map_execution_setup)?,
        proxy_limits,
    )
    .map_err(map_cgroup)?;
    let identity = LauncherIdentity::new(execution_id, policy_identity.digest(), cgroup_identity);
    let cgroups_elapsed = phase.elapsed();

    let phase = std::time::Instant::now();
    let executable_fd = executable_set.command().file().as_fd().as_raw_fd();
    let working_fd = working_directory.as_fd().as_raw_fd();
    let mut rules = Vec::new();
    let mut inherited = vec![
        executable_set.command().file().as_fd(),
        working_directory.as_fd(),
    ];
    for member in executable_set.members() {
        rules.push(launcher_rule(
            member.file().as_fd().as_raw_fd(),
            vec![LandlockAccess::Read, LandlockAccess::Execute],
        )?);
        inherited.push(member.file().as_fd());
        if let Some(loader) = member.loader() {
            rules.push(launcher_rule(
                loader.as_fd().as_raw_fd(),
                vec![LandlockAccess::Read, LandlockAccess::Execute],
            )?);
            inherited.push(loader.as_fd());
        }
    }
    for path in &readable {
        rules.push(launcher_rule(
            path.as_fd().as_raw_fd(),
            vec![LandlockAccess::Read],
        )?);
        inherited.push(path.as_fd());
    }
    rules.push(launcher_rule(
        output_root.as_fd().as_raw_fd(),
        vec![LandlockAccess::Write],
    )?);
    inherited.push(output_root.as_fd());
    inherited.sort_by_key(std::os::fd::BorrowedFd::as_raw_fd);
    inherited.dedup_by_key(|fd| fd.as_raw_fd());
    let descriptor_upper_bound = rules
        .iter()
        .map(LauncherFilesystemRule::descriptor)
        .chain([descriptor(executable_fd)?, descriptor(working_fd)?])
        .max()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| egress_error("launcher.file-descriptor.invalid"))?;
    let request = InstallRequest::new(
        identity,
        executable_set.command().file().identity().clone(),
        descriptor(executable_fd)?,
        descriptor(working_fd)?,
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
    executable_set.revalidate_identities().map_err(|error| {
        RunError::identity(
            RunPhase::IdentityRevalidation,
            RunRule::ArtifactIdentitiesStable,
            error.code(),
        )
    })?;
    proxy.revalidate_identity().map_err(|error| {
        map_resolution(
            RunPhase::IdentityRevalidation,
            RunRule::ArtifactIdentitiesStable,
            error,
        )
    })?;
    resolver_configuration
        .revalidate_identity()
        .map_err(|error| {
            map_resolution(
                RunPhase::IdentityRevalidation,
                RunRule::ArtifactIdentitiesStable,
                error,
            )
        })?;
    for member in &proxy_closure {
        member.revalidate_identity().map_err(|error| {
            map_resolution(
                RunPhase::IdentityRevalidation,
                RunRule::ArtifactIdentitiesStable,
                error,
            )
        })?;
    }
    working_directory.revalidate_identity().map_err(|error| {
        map_resolution(
            RunPhase::IdentityRevalidation,
            RunRule::ArtifactIdentitiesStable,
            error,
        )
    })?;
    output_root.revalidate_empty().map_err(|error| {
        map_output(
            RunPhase::IdentityRevalidation,
            RunRule::ArtifactIdentitiesStable,
            error,
        )
    })?;
    let request_elapsed = phase.elapsed();

    let mut closure_hasher = Sha256::new();
    closure_hasher.update(b"PBR-EGRESS-PROXY-CLOSURE/1");
    for member in &proxy_closure {
        closure_hasher.update(member.identity().digest().as_bytes());
    }
    let closure_sha256 = Sha256Digest::from_bytes(closure_hasher.finalize().into());
    let mut execution = supervise_egress_launcher(EgressSupervisorInputs {
        launcher_program: &launcher_path,
        request,
        child_cgroup,
        proxy_cgroup,
        limits,
        child_descriptors: &inherited,
        plan: plan_source.as_fd(),
        proxy: proxy.as_fd(),
        plan_sha256: Sha256Digest::from_bytes(Sha256::digest(&plan_bytes).into()),
        proxy_sha256: proxy.identity().digest(),
        closure_sha256,
        resolver_sha256: resolver_configuration.identity().digest(),
        architecture: supported.architecture(),
        landlock_abi: supported.landlock_abi(),
    })
    .map_err(|error| egress_error(error.code()))?;

    let phase = std::time::Instant::now();
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
    let output_elapsed = phase.elapsed();

    let phase = std::time::Instant::now();
    let flags = execution.reports.flags();
    let boundary = observed_boundary(&execution)?;
    let artifacts = json!({
        "executable": artifact_json(proxy.identity()),
        "runtime_closure": proxy_closure.iter().map(|member| artifact_json(member.identity())).collect::<Vec<_>>(),
        "resolver_configuration": artifact_json(resolver_configuration.identity()),
    });
    let observation = std::mem::take(&mut execution.reports)
        .finish(
            authority_json(authority),
            policy_identity.digest(),
            boundary,
            artifacts,
            json!({"listener_closed": true, "proxy_cgroup_removed": true, "proxy_reaped": true}),
        )
        .map_err(|error| {
            RunError::receipt(
                RunPhase::ReceiptConstruction,
                RunRule::ReceiptConstructed,
                error.code(),
            )
        })?;
    let receipt = build_receipt(ReceiptInputs {
        plan: base,
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
        egress: Some(EgressReceiptArtifacts {
            proxy: proxy.identity().clone(),
            closure: proxy_closure
                .iter()
                .map(|member| member.identity().clone())
                .collect(),
            resolver: resolver_configuration.identity().clone(),
        }),
    })?;
    let receipt_bytes = receipt
        .canonical_v3_bytes(&ReceiptNetworkV3::DeclaredEgress {
            observation_cbor: observation,
            flags,
        })
        .map_err(|error| {
            RunError::receipt(
                RunPhase::ReceiptConstruction,
                RunRule::ReceiptConstructed,
                error.code(),
            )
        })?;
    let commitment = Sha256Digest::from_bytes(Sha256::digest(&receipt_bytes).into());
    persist_receipt(&receipt_path, execution_id.as_bytes(), &receipt_bytes)?;
    let receipt_elapsed = phase.elapsed();
    let result = RunResultV3::new(&receipt_path, execution_id, commitment, execution.outcome)
        .map_err(|_| {
            RunError::invalid(
                RunPhase::ResultProjection,
                RunRule::RunResultRepresentable,
                "receipt.path.utf8-invalid",
            )
        })?;
    Ok(ObservedRun {
        report: result.json_projection(),
        timings: RunTimings::from_intervals([
            normalization_elapsed,
            preflight_elapsed,
            inventory_elapsed,
            cgroups_elapsed,
            request_elapsed,
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            execution.elapsed,
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            output_elapsed,
            receipt_elapsed,
            std::time::Duration::ZERO,
        ]),
    })
}
