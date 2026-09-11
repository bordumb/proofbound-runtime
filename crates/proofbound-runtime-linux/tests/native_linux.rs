const ATTACK_CATALOG: &str = include_str!("../../../tests/attacks/native-linux/boundary-v1.toml");
const MEMORY_ATTACK_CATALOG: &str =
    include_str!("../../../tests/attacks/native-linux/memory-v2.toml");
const NATIVE_FIXTURE_SOURCE: &str = include_str!("fixtures/native-boundary-probe.c");

#[test]
fn native_boundary_catalog_is_closed() {
    let expected = [
        "boundary-positive",
        "filesystem-read-allowed",
        "filesystem-read-denied",
        "network-denied",
        "process-limit-denied",
        "undeclared-descriptor",
        "stdout-over-limit",
        "wall-time-over-limit",
        "lingering-descendant",
    ];
    assert!(
        ATTACK_CATALOG.starts_with("schema = \"proofbound-runtime-native-boundary-attacks/1\"")
    );
    assert_eq!(ATTACK_CATALOG.matches("[[case]]").count(), expected.len());
    for id in expected {
        assert!(ATTACK_CATALOG.contains(&format!("id = \"{id}\"")));
    }
}

#[test]
fn native_memory_catalog_is_closed() {
    let expected = [
        "anonymous-over-limit-single-process",
        "anonymous-over-limit-max-process-tree",
        "anonymous-memory-accounted",
        "mapped-file-memory-accounted",
        "page-cache-memory-accounted",
        "shared-memory-accounted",
        "socket-memory-accounted",
        "zero-swap-enforced",
        "swap-limit-reached",
        "host-without-swap",
        "pre-release-allocation-blocked",
        "sibling-cgroup-immune",
        "supervisor-cgroup-immune",
        "memory-pressure-timeout-cleanup",
        "memory-pressure-launcher-failure-cleanup",
        "memory-pressure-supervisor-failure-cleanup",
        "oom-cleanup-exact",
        "receipt-resource-mutations-rejected",
    ];
    assert!(
        MEMORY_ATTACK_CATALOG
            .starts_with("schema = \"proofbound-runtime-native-memory-attacks/2\"")
    );
    assert_eq!(
        MEMORY_ATTACK_CATALOG.matches("[[case]]").count(),
        expected.len()
    );
    for id in expected {
        assert!(MEMORY_ATTACK_CATALOG.contains(&format!("id = \"{id}\"")));
    }
}

#[test]
fn native_memory_workload_modes_are_closed() {
    let expected = [
        "memory-anonymous",
        "memory-over-limit",
        "memory-process-tree-over-limit",
        "memory-mapped-file",
        "memory-page-cache",
        "memory-shared",
        "memory-socket",
        "memory-baseline",
        "memory-pressure-timeout",
        "memory-pressure-stopped",
        "memory-pre-main",
    ];
    for mode in expected {
        assert_eq!(
            NATIVE_FIXTURE_SOURCE
                .matches(&format!("strcmp(argv[1], \"{mode}\")"))
                .count(),
            1,
            "fixture mode {mode} must have one implementation"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::os::fd::{AsFd as _, AsRawFd as _};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU8, Ordering};

    use proofbound_runtime_core::{
        ArtifactIdentity, ArtifactRole, AuthorityPath, BoundaryInstallation, ExecutionId,
        ExecutionOutcome, LimitEvent, MemoryByteLimit, OutputByteLimit, ProcessLimit,
        ResourceLimits, Sha256Digest, StreamCapture, SwapByteLimit, WallTimeLimit,
    };
    use proofbound_runtime_linux::{
        ExecutableClosure, FreshCgroup, InstallRequest, LandlockAccess, LauncherFilesystemRule,
        LauncherIdentity, ResolvedFile, RootedPathResolver, SupervisorError, SupportedLinux,
        compile_deny_network_program, probe_capabilities, supervise_launcher,
    };
    use sha2::{Digest as _, Sha256};

    static CASE_NUMBER: AtomicU8 = AtomicU8::new(1);

    struct FixtureDirectory(PathBuf);

    struct PreparedCase {
        executable: ExecutableClosure,
        working_directory: File,
        readable: Option<ResolvedFile>,
        request: InstallRequest,
    }

    impl Drop for FixtureDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn production_launcher_enforces_native_boundary_corpus() {
        let required = std::env::var_os("PROOFBOUND_NATIVE_REQUIRED").is_some();
        let (Some(cgroup_root), Some(fixture)) = (
            std::env::var_os("PROOFBOUND_CGROUP_ROOT"),
            std::env::var_os("PROOFBOUND_NATIVE_FIXTURE"),
        ) else {
            assert!(!required, "native corpus configuration is required");
            return;
        };
        let supported = probe_capabilities(Path::new(&cgroup_root))
            .require_supported()
            .expect("identified native host must satisfy the complete capability profile");
        let fixture = PathBuf::from(fixture);
        let workspace = create_fixture_directory();
        std::fs::write(workspace.0.join("allowed.txt"), b"proofbound\n")
            .expect("write allowed fixture");
        std::fs::write(workspace.0.join("denied.txt"), b"secret\n").expect("write denied fixture");

        let positive = run_case(
            &supported,
            &fixture,
            &workspace.0,
            "positive",
            &[],
            None,
            1,
            1024,
            2000,
        );
        assert_eq!(positive.boundary(), BoundaryInstallation::Installed);
        assert_outcome(&positive, ExecutionOutcome::Exited { code: 0 });
        assert_eq!(positive.stdout().bytes(), b"boundary-installed\n");

        let allowed = run_case(
            &supported,
            &fixture,
            &workspace.0,
            "read-allowed",
            &["allowed.txt"],
            Some("allowed.txt"),
            1,
            1024,
            2000,
        );
        assert_outcome(&allowed, ExecutionOutcome::Exited { code: 0 });

        let denied = run_case(
            &supported,
            &fixture,
            &workspace.0,
            "read-denied",
            &["denied.txt"],
            None,
            1,
            1024,
            2000,
        );
        assert_outcome(&denied, ExecutionOutcome::Exited { code: 0 });
        assert_eq!(denied.stdout().bytes(), b"filesystem-denied\n");

        let network = run_case(
            &supported,
            &fixture,
            &workspace.0,
            "network-denied",
            &[],
            None,
            1,
            1024,
            2000,
        );
        assert_outcome(&network, ExecutionOutcome::Exited { code: 0 });
        assert_eq!(network.stdout().bytes(), b"network-denied\n");

        let processes = run_case(
            &supported,
            &fixture,
            &workspace.0,
            "fork-denied",
            &[],
            None,
            1,
            1024,
            2000,
        );
        assert_outcome(&processes, ExecutionOutcome::Exited { code: 0 });
        assert_eq!(processes.stdout().bytes(), b"process-denied\n");

        let leak = File::open(workspace.0.join("denied.txt")).expect("open leak fixture");
        let leak_fd = leak.as_raw_fd();
        // SAFETY: `leak_fd` is a live descriptor owned by `leak`; this only
        // clears its close-on-exec bit to model an inherited ambient capability.
        assert_eq!(unsafe { libc::fcntl(leak_fd, libc::F_SETFD, 0) }, 0);
        let fd_closed = run_case(
            &supported,
            &fixture,
            &workspace.0,
            "fd-closed",
            &[&leak_fd.to_string()],
            None,
            1,
            1024,
            2000,
        );
        assert_outcome(&fd_closed, ExecutionOutcome::Exited { code: 0 });
        drop(leak);

        let output = run_case(
            &supported,
            &fixture,
            &workspace.0,
            "output-over-limit",
            &[],
            None,
            1,
            64,
            2000,
        );
        assert_outcome(&output, ExecutionOutcome::Exited { code: 0 });
        assert_eq!(output.stdout().capture(), StreamCapture::Truncated);
        assert_eq!(output.stdout().bytes().len(), 64);

        let timeout = run_case(
            &supported,
            &fixture,
            &workspace.0,
            "timeout",
            &[],
            None,
            1,
            1024,
            50,
        );
        assert_outcome(&timeout, ExecutionOutcome::TimedOut);

        let lingering = run_case(
            &supported,
            &fixture,
            &workspace.0,
            "lingering-descendant",
            &[],
            None,
            2,
            1024,
            2000,
        );
        assert_outcome(&lingering, ExecutionOutcome::Exited { code: 0 });
    }

    #[test]
    fn production_launcher_enforces_native_memory_corpus() {
        let required = std::env::var_os("PROOFBOUND_NATIVE_REQUIRED").is_some();
        let (Some(cgroup_root), Some(fixture)) = (
            std::env::var_os("PROOFBOUND_CGROUP_ROOT"),
            std::env::var_os("PROOFBOUND_NATIVE_FIXTURE"),
        ) else {
            assert!(!required, "native corpus configuration is required");
            return;
        };
        let supported = probe_capabilities(Path::new(&cgroup_root))
            .require_supported()
            .expect("identified native host must satisfy the complete capability profile");
        let fixture = PathBuf::from(fixture);
        let workspace = create_fixture_directory();
        let memory_file = workspace.0.join("memory.bin");
        File::create(&memory_file).expect("create memory-accounting fixture");

        let anonymous = run_v2_case(
            &supported,
            &fixture,
            &workspace.0,
            "memory-anonymous",
            &["16777216"],
            None,
            1,
            128 * 1024 * 1024,
            0,
            5_000,
        );
        assert_eq!(anonymous.boundary(), BoundaryInstallation::Installed);
        assert_outcome(&anonymous, ExecutionOutcome::Exited { code: 0 });
        assert_eq!(anonymous.stdout().bytes(), b"anonymous-accounted\n");
        assert_accounted_without_limit_event(&anonymous);

        let pre_main = run_v2_case(
            &supported,
            &fixture,
            &workspace.0,
            "memory-pre-main",
            &[],
            None,
            1,
            128 * 1024 * 1024,
            0,
            5_000,
        );
        assert_eq!(pre_main.boundary(), BoundaryInstallation::Installed);
        assert_outcome(&pre_main, ExecutionOutcome::Exited { code: 0 });
        assert_eq!(
            pre_main.stdout().bytes(),
            b"pre-main-allocation-accounted\n"
        );
        assert_accounted_without_limit_event(&pre_main);

        let mapped = run_v2_case(
            &supported,
            &fixture,
            &workspace.0,
            "memory-mapped-file",
            &["memory.bin", "16777216"],
            Some("memory.bin"),
            1,
            128 * 1024 * 1024,
            0,
            5_000,
        );
        assert_outcome(&mapped, ExecutionOutcome::Exited { code: 0 });
        assert_eq!(mapped.stdout().bytes(), b"mapped-file-accounted\n");
        assert_accounted_without_limit_event(&mapped);

        let page_cache = run_v2_case(
            &supported,
            &fixture,
            &workspace.0,
            "memory-page-cache",
            &["memory.bin", "16777216"],
            Some("memory.bin"),
            1,
            128 * 1024 * 1024,
            0,
            5_000,
        );
        assert_outcome(&page_cache, ExecutionOutcome::Exited { code: 0 });
        assert_eq!(page_cache.stdout().bytes(), b"page-cache-accounted\n");
        assert_accounted_without_limit_event(&page_cache);

        let shared = run_v2_case(
            &supported,
            &fixture,
            &workspace.0,
            "memory-shared",
            &["16777216"],
            None,
            1,
            128 * 1024 * 1024,
            0,
            5_000,
        );
        assert_outcome(&shared, ExecutionOutcome::Exited { code: 0 });
        assert_eq!(shared.stdout().bytes(), b"shared-memory-accounted\n");
        assert_accounted_without_limit_event(&shared);

        let single_oom = run_v2_case(
            &supported,
            &fixture,
            &workspace.0,
            "memory-over-limit",
            &["8388608"],
            None,
            1,
            64 * 1024 * 1024,
            0,
            10_000,
        );
        assert_eq!(single_oom.boundary(), BoundaryInstallation::Installed);
        assert_memory_denial(&single_oom);

        let mut sibling = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn supervisor-cgroup sibling");
        let process_tree_oom = run_v2_case(
            &supported,
            &fixture,
            &workspace.0,
            "memory-process-tree-over-limit",
            &["4194304", "3"],
            None,
            4,
            64 * 1024 * 1024,
            0,
            10_000,
        );
        assert_memory_denial(&process_tree_oom);
        assert!(
            sibling.try_wait().expect("inspect sibling").is_none(),
            "workload OOM selection must not kill a supervisor-cgroup sibling"
        );
        sibling.kill().expect("stop sibling");
        sibling.wait().expect("reap sibling");

        let timeout = run_v2_case(
            &supported,
            &fixture,
            &workspace.0,
            "memory-pressure-timeout",
            &["16777216"],
            None,
            1,
            128 * 1024 * 1024,
            0,
            50,
        );
        assert_outcome(&timeout, ExecutionOutcome::TimedOut);
        assert!(
            timeout
                .resources()
                .expect("v2 timeout observations")
                .memory_peak_bytes()
                > 0
        );
    }

    #[test]
    fn native_cgroup_accounts_socket_memory_outside_denied_network_profile() {
        let required = std::env::var_os("PROOFBOUND_NATIVE_REQUIRED").is_some();
        let (Some(cgroup_root), Some(fixture)) = (
            std::env::var_os("PROOFBOUND_CGROUP_ROOT"),
            std::env::var_os("PROOFBOUND_NATIVE_FIXTURE"),
        ) else {
            assert!(!required, "native corpus configuration is required");
            return;
        };
        let supported = probe_capabilities(Path::new(&cgroup_root))
            .require_supported()
            .expect("identified native host must satisfy the complete capability profile");
        let fixture = PathBuf::from(fixture);

        let baseline = run_raw_cgroup_case(&supported, &fixture, "memory-baseline");
        let socket = run_raw_cgroup_case(&supported, &fixture, "memory-socket");
        assert!(
            socket.memory_peak_bytes() >= baseline.memory_peak_bytes().saturating_add(64 * 1024),
            "socket peak {socket:#?} must exceed baseline {baseline:#?}"
        );
        assert!(socket.limit_events().is_empty(), "{socket:#?}");
    }

    #[test]
    fn production_launcher_enforces_native_swap_presence_matrix() {
        let required = std::env::var_os("PROOFBOUND_NATIVE_REQUIRED").is_some();
        let Ok(swap_mode) = std::env::var("PROOFBOUND_NATIVE_SWAP_MODE") else {
            assert!(!required, "native swap mode is required");
            return;
        };
        let (Some(cgroup_root), Some(fixture)) = (
            std::env::var_os("PROOFBOUND_CGROUP_ROOT"),
            std::env::var_os("PROOFBOUND_NATIVE_FIXTURE"),
        ) else {
            assert!(!required, "native corpus configuration is required");
            return;
        };
        let supported = probe_capabilities(Path::new(&cgroup_root))
            .require_supported()
            .expect("identified native host must satisfy the complete capability profile");
        let fixture = PathBuf::from(fixture);
        let workspace = create_fixture_directory();
        let swap_devices = std::fs::read_to_string("/proc/swaps")
            .expect("kernel swap inventory is readable")
            .lines()
            .skip(1)
            .count();

        match swap_mode.as_str() {
            "absent" => {
                assert_eq!(swap_devices, 0, "absent phase must have no host swap");
                let execution = run_v2_case(
                    &supported,
                    &fixture,
                    &workspace.0,
                    "memory-anonymous",
                    &["16777216"],
                    None,
                    1,
                    128 * 1024 * 1024,
                    0,
                    5_000,
                );
                assert_outcome(&execution, ExecutionOutcome::Exited { code: 0 });
                let resources = execution.resources().expect("absent-swap observations");
                assert_eq!(resources.swap_peak_bytes(), 0, "{execution:#?}");
                assert_eq!(resources.swap_events().max(), 0, "{execution:#?}");
                assert_eq!(resources.swap_events().fail(), 0, "{execution:#?}");
            }
            "present" => {
                assert!(
                    swap_devices > 0,
                    "present phase must have a host swap device"
                );
                let execution = run_v2_case(
                    &supported,
                    &fixture,
                    &workspace.0,
                    "memory-over-limit",
                    &["8388608"],
                    None,
                    1,
                    64 * 1024 * 1024,
                    16 * 1024 * 1024,
                    15_000,
                );
                let resources = execution.resources().expect("present-swap observations");
                assert!(resources.swap_peak_bytes() > 0, "{execution:#?}");
                assert!(
                    resources.swap_peak_bytes() <= 16 * 1024 * 1024,
                    "{execution:#?}"
                );
                assert!(
                    resources.swap_events().max() > 0 || resources.swap_events().fail() > 0,
                    "{execution:#?}"
                );
                assert!(
                    resources.limit_events().contains(LimitEvent::SwapMax)
                        || resources.limit_events().contains(LimitEvent::SwapFail),
                    "{execution:#?}"
                );
            }
            other => panic!("unknown native swap mode: {other}"),
        }
    }

    #[test]
    fn native_failure_paths_remove_cgroup_under_memory_pressure() {
        let required = std::env::var_os("PROOFBOUND_NATIVE_REQUIRED").is_some();
        let (Some(cgroup_root), Some(fixture)) = (
            std::env::var_os("PROOFBOUND_CGROUP_ROOT"),
            std::env::var_os("PROOFBOUND_NATIVE_FIXTURE"),
        ) else {
            assert!(!required, "native corpus configuration is required");
            return;
        };
        let supported = probe_capabilities(Path::new(&cgroup_root))
            .require_supported()
            .expect("identified native host must satisfy the complete capability profile");
        let fixture = PathBuf::from(fixture);
        let workspace = create_fixture_directory();

        run_failure_under_pressure(&supported, &fixture, &workspace.0, false);
        run_failure_under_pressure(&supported, &fixture, &workspace.0, true);
    }

    #[test]
    fn discovers_and_retains_the_native_shell_executable_closure() {
        let architecture = if cfg!(target_arch = "x86_64") {
            proofbound_runtime_linux::Architecture::X86_64
        } else {
            proofbound_runtime_linux::Architecture::Aarch64
        };
        let resolver =
            RootedPathResolver::open(Path::new("/")).expect("native root descriptor is available");
        let executable = AuthorityPath::new("/bin/sh").expect("shell path is valid");
        let closure = resolver
            .discover_executable(&executable, architecture)
            .expect("native shell closure resolves");

        assert_eq!(
            closure.executable().identity().role(),
            ArtifactRole::RuntimeExecutable
        );
        assert_eq!(
            closure
                .loader()
                .expect("native shell is dynamic")
                .identity()
                .role(),
            ArtifactRole::RuntimeLoaderExecutable
        );
        closure
            .revalidate_identities()
            .expect("retained executable closure is unchanged");
    }

    #[test]
    fn read_directory_inventory_detects_drift_and_symlinks() {
        use std::os::unix::fs::symlink;

        let workspace = create_fixture_directory();
        std::fs::create_dir(workspace.0.join("inputs")).expect("create input directory");
        std::fs::write(workspace.0.join("inputs/data.txt"), b"first\n")
            .expect("write input fixture");
        let resolver = RootedPathResolver::open(&workspace.0).expect("open fixture root");
        let inputs = AuthorityPath::new("inputs").expect("input path is valid");
        let resolved = resolver
            .resolve_read_path(&inputs, ArtifactRole::ProjectInput)
            .expect("read directory resolves");
        assert_eq!(resolved.identity().role(), ArtifactRole::ProjectInput);
        resolved
            .revalidate_identity()
            .expect("unchanged input inventory revalidates");

        std::fs::write(workspace.0.join("inputs/data.txt"), b"second\n")
            .expect("mutate input fixture");
        assert_eq!(
            resolved.revalidate_identity(),
            Err(proofbound_runtime_linux::ResolutionError::IdentityDrift)
        );
        symlink("data.txt", workspace.0.join("inputs/link")).expect("create input symlink");
        let link = AuthorityPath::new("inputs/link").expect("link path is valid");
        assert!(matches!(
            resolver.resolve_read_path(&link, ArtifactRole::ProjectInput),
            Err(proofbound_runtime_linux::ResolutionError::SymlinkInvalid)
        ));
        assert_eq!(
            resolved.revalidate_identity(),
            Err(proofbound_runtime_linux::ResolutionError::SymlinkInvalid)
        );
    }

    #[test]
    fn runtime_artifacts_and_execution_ids_are_exact() {
        let current = std::fs::canonicalize(std::env::current_exe().expect("current executable"))
            .expect("canonical current executable");
        let artifact = proofbound_runtime_linux::identify_external_artifact(
            &current,
            ArtifactRole::RuntimeBinary,
        )
        .expect("runtime artifact resolves");
        assert_eq!(
            artifact.read_bytes().expect("retained bytes read"),
            std::fs::read(&current).expect("current executable reads")
        );
        let first = proofbound_runtime_linux::fresh_execution_id().expect("first execution ID");
        let second = proofbound_runtime_linux::fresh_execution_id().expect("second execution ID");
        assert_ne!(first, second);
    }

    fn assert_outcome(
        execution: &proofbound_runtime_linux::SupervisedExecution,
        expected: ExecutionOutcome,
    ) {
        assert_eq!(execution.outcome(), expected, "{execution:#?}");
    }

    fn assert_accounted_without_limit_event(
        execution: &proofbound_runtime_linux::SupervisedExecution,
    ) {
        let resources = execution.resources().expect("v2 resource observations");
        assert!(
            resources.memory_peak_bytes() >= 1024 * 1024,
            "{execution:#?}"
        );
        assert!(resources.limit_events().is_empty(), "{execution:#?}");
        assert_eq!(resources.swap_peak_bytes(), 0, "{execution:#?}");
    }

    fn assert_memory_denial(execution: &proofbound_runtime_linux::SupervisedExecution) {
        let resources = execution.resources().expect("v2 resource observations");
        assert!(
            resources.limit_events().contains(LimitEvent::MemoryMax),
            "{execution:#?}"
        );
        assert!(
            resources.memory_events().oom_kill() > 0
                || execution.stdout().bytes() == b"allocation-denied\n",
            "{execution:#?}"
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn run_case(
        supported: &SupportedLinux,
        fixture: &Path,
        workspace: &Path,
        case: &str,
        case_arguments: &[&str],
        readable_file: Option<&str>,
        process_limit: u32,
        stdout_limit: u64,
        wall_time_ms: u64,
    ) -> proofbound_runtime_linux::SupervisedExecution {
        let limits = ResourceLimits::new(
            ProcessLimit::new(process_limit).expect("nonzero process limit"),
            WallTimeLimit::from_milliseconds(wall_time_ms).expect("nonzero wall time"),
            OutputByteLimit::new(stdout_limit),
            OutputByteLimit::new(1024),
        );
        run_case_with_limits(
            supported,
            fixture,
            workspace,
            case,
            case_arguments,
            readable_file,
            limits,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn run_v2_case(
        supported: &SupportedLinux,
        fixture: &Path,
        workspace: &Path,
        case: &str,
        case_arguments: &[&str],
        readable_file: Option<&str>,
        process_limit: u32,
        memory_bytes: u64,
        swap_bytes: u64,
        wall_time_ms: u64,
    ) -> proofbound_runtime_linux::SupervisedExecution {
        let limits = ResourceLimits::new_v2(
            ProcessLimit::new(process_limit).expect("nonzero process limit"),
            WallTimeLimit::from_milliseconds(wall_time_ms).expect("nonzero wall time"),
            OutputByteLimit::new(1024),
            OutputByteLimit::new(1024),
            MemoryByteLimit::new(memory_bytes).expect("valid memory limit"),
            SwapByteLimit::new(swap_bytes).expect("valid swap limit"),
        );
        run_case_with_limits(
            supported,
            fixture,
            workspace,
            case,
            case_arguments,
            readable_file,
            limits,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn run_case_with_limits(
        supported: &SupportedLinux,
        fixture: &Path,
        workspace: &Path,
        case: &str,
        case_arguments: &[&str],
        readable_file: Option<&str>,
        limits: ResourceLimits,
    ) -> proofbound_runtime_linux::SupervisedExecution {
        let execution_id = execution_id();
        let cgroup = if limits.memory().is_some() {
            FreshCgroup::create_v2(supported.cgroup_v2(), execution_id, limits)
        } else {
            FreshCgroup::create(supported.cgroup_v2(), execution_id, limits.processes())
        }
        .expect("create fresh execution cgroup");
        let cgroup_path = cgroup.path().to_owned();
        let PreparedCase {
            executable,
            working_directory,
            readable,
            request,
        } = prepare_case(
            supported,
            fixture,
            workspace,
            case,
            case_arguments,
            readable_file,
            execution_id,
            cgroup.identity(),
            false,
        );
        let mut inherited = vec![executable.executable().as_fd(), working_directory.as_fd()];
        if let Some(readable) = &readable {
            inherited.push(readable.as_fd());
        }
        let execution = supervise_launcher(
            Path::new(env!("CARGO_BIN_EXE_pbr-native-launcher")),
            request,
            cgroup,
            limits,
            &inherited,
            supported.architecture(),
            supported.landlock_abi(),
        )
        .expect("supervise native launcher");
        assert!(
            !cgroup_path.exists(),
            "terminal execution must remove its exact fresh cgroup"
        );
        execution
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_case(
        supported: &SupportedLinux,
        fixture: &Path,
        workspace: &Path,
        case: &str,
        case_arguments: &[&str],
        readable_file: Option<&str>,
        execution_id: ExecutionId,
        cgroup_identity: proofbound_runtime_core::CgroupIdentity,
        corrupt_executable_identity: bool,
    ) -> PreparedCase {
        let resolver = RootedPathResolver::open(workspace).expect("open fixture root");
        let fixture_authority = AuthorityPath::new(
            fixture
                .to_str()
                .expect("fixture path must be UTF-8")
                .to_owned(),
        )
        .expect("fixture authority path");
        let observed = resolver
            .resolve_external_file(&fixture_authority, ArtifactRole::RuntimeExecutable)
            .expect("identify static fixture");
        let observed_executable = observed.identity().clone();
        drop(observed);
        let executable = resolver
            .resolve_executable(
                &fixture_authority,
                &observed_executable,
                None,
                supported.architecture(),
            )
            .expect("resolve static fixture closure");
        assert!(
            executable.loader().is_none(),
            "native fixture must be static"
        );
        let working_directory = File::open(workspace).expect("open working directory");
        let readable = readable_file.map(|path| {
            let resolved = resolver
                .resolve_rooted_file(
                    &AuthorityPath::new(path.to_owned()).expect("readable authority path"),
                    ArtifactRole::ProjectInput,
                )
                .expect("resolve readable fixture");
            let access = if matches!(case, "memory-mapped-file" | "memory-page-cache") {
                vec![LandlockAccess::Read, LandlockAccess::Write]
            } else {
                vec![LandlockAccess::Read]
            };
            (resolved, access)
        });

        let expected_executable = if corrupt_executable_identity {
            ArtifactIdentity::new(
                observed_executable.role(),
                Sha256Digest::from_bytes([0xff; 32]),
                observed_executable.size(),
                observed_executable.mode(),
            )
        } else {
            observed_executable
        };
        let seccomp = compile_deny_network_program(
            proofbound_runtime_core::SeccompPolicy::DenyNetworkV1,
            supported.architecture(),
        )
        .expect("compile native seccomp policy");
        let mut hasher = Sha256::new();
        hasher.update(case.as_bytes());
        hasher.update(&seccomp);
        let policy_id = Sha256Digest::from_bytes(hasher.finalize().into());
        let identity = LauncherIdentity::new(execution_id, policy_id, cgroup_identity);

        let executable_fd = executable.executable().as_fd().as_raw_fd();
        let working_directory_fd = working_directory.as_raw_fd();
        let mut rules = vec![
            LauncherFilesystemRule::new(
                u32::try_from(executable_fd).expect("positive executable descriptor"),
                vec![LandlockAccess::Read, LandlockAccess::Execute],
            )
            .expect("executable rule"),
        ];
        if let Some((readable, access)) = &readable {
            rules.push(
                LauncherFilesystemRule::new(
                    u32::try_from(readable.as_fd().as_raw_fd())
                        .expect("positive readable descriptor"),
                    access.clone(),
                )
                .expect("read rule"),
            );
        }
        let mut arguments = vec!["native-boundary-probe".to_owned(), case.to_owned()];
        arguments.extend(case_arguments.iter().map(|value| (*value).to_owned()));
        let declared_upper_bound = rules
            .iter()
            .map(LauncherFilesystemRule::descriptor)
            .chain([
                u32::try_from(executable_fd).expect("positive executable descriptor"),
                u32::try_from(working_directory_fd).expect("positive directory descriptor"),
            ])
            .max()
            .and_then(|descriptor| descriptor.checked_add(1))
            .expect("descriptor upper bound");
        let environment = if case == "memory-pre-main" {
            BTreeMap::from([("PROOFBOUND_PRE_MAIN_ALLOCATION".to_owned(), "1".to_owned())])
        } else {
            BTreeMap::new()
        };
        let request = InstallRequest::new(
            identity,
            expected_executable,
            u32::try_from(executable_fd).expect("positive executable descriptor"),
            u32::try_from(working_directory_fd).expect("positive directory descriptor"),
            arguments,
            environment,
            rules,
            seccomp,
            declared_upper_bound,
        )
        .expect("construct install request");

        PreparedCase {
            executable,
            working_directory,
            readable: readable.map(|(resolved, _)| resolved),
            request,
        }
    }

    fn run_failure_under_pressure(
        supported: &SupportedLinux,
        fixture: &Path,
        workspace: &Path,
        supervisor_failure: bool,
    ) {
        let limits = ResourceLimits::new_v2(
            ProcessLimit::new(2).expect("pressure helper and launcher"),
            WallTimeLimit::from_milliseconds(5_000).expect("bounded failure case"),
            OutputByteLimit::new(1024),
            OutputByteLimit::new(1024),
            MemoryByteLimit::new(128 * 1024 * 1024).expect("valid memory limit"),
            SwapByteLimit::new(0).expect("zero swap limit"),
        );
        let execution_id = execution_id();
        let cgroup = FreshCgroup::create_v2(supported.cgroup_v2(), execution_id, limits)
            .expect("create failure-path cgroup");
        let cgroup_path = cgroup.path().to_owned();
        let marker = workspace.join(if supervisor_failure {
            "supervisor-pressure-ready"
        } else {
            "launcher-pressure-ready"
        });
        let mut pressure = start_pressure(&cgroup, fixture, &marker);
        let PreparedCase {
            executable,
            working_directory,
            readable,
            request,
        } = prepare_case(
            supported,
            fixture,
            workspace,
            "positive",
            &[],
            None,
            execution_id,
            cgroup.identity(),
            !supervisor_failure,
        );
        assert!(readable.is_none());
        let mut inherited = vec![executable.executable().as_fd(), working_directory.as_fd()];
        if supervisor_failure {
            inherited.pop();
        }
        let result = supervise_launcher(
            Path::new(env!("CARGO_BIN_EXE_pbr-native-launcher")),
            request,
            cgroup,
            limits,
            &inherited,
            supported.architecture(),
            supported.landlock_abi(),
        );
        let removed = !cgroup_path.exists();
        if pressure
            .try_wait()
            .expect("inspect pressure helper")
            .is_none()
        {
            pressure.kill().expect("stop residual pressure helper");
        }
        pressure.wait().expect("reap pressure helper");
        assert!(removed, "failure path must remove the exact cgroup");

        if supervisor_failure {
            assert_eq!(result, Err(SupervisorError::DescriptorSetInvalid));
        } else {
            let execution = result.expect("launcher failure remains an observed execution");
            assert_eq!(execution.boundary(), BoundaryInstallation::Incomplete);
            assert_outcome(&execution, ExecutionOutcome::LauncherFailed);
            assert!(execution.launcher_failure().is_some(), "{execution:#?}");
            assert!(
                execution
                    .resources()
                    .expect("launcher-failure resource observations")
                    .memory_peak_bytes()
                    >= 1024 * 1024,
                "{execution:#?}"
            );
        }
    }

    fn start_pressure(cgroup: &FreshCgroup, fixture: &Path, marker: &Path) -> std::process::Child {
        let mut child = std::process::Command::new(fixture)
            .args([
                "memory-pressure-stopped",
                "16777216",
                marker.to_str().expect("pressure marker path is UTF-8"),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn stopped pressure helper");
        wait_until_stopped(child.id());
        cgroup
            .place_process(child.id())
            .expect("move pressure helper into exact cgroup");
        let process_id = i32::try_from(child.id()).expect("Linux process IDs fit i32");
        // SAFETY: `process_id` names the live stopped child owned above.
        assert_eq!(unsafe { libc::kill(process_id, libc::SIGCONT) }, 0);
        for _ in 0..5_000 {
            if std::fs::read(marker).is_ok_and(|bytes| bytes == b"ready\n") {
                return child;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        child.kill().expect("stop unresponsive pressure helper");
        child.wait().expect("reap unresponsive pressure helper");
        panic!("pressure helper did not confirm allocation");
    }

    fn run_raw_cgroup_case(
        supported: &SupportedLinux,
        fixture: &Path,
        case: &str,
    ) -> proofbound_runtime_linux::TerminalResources {
        let limits = ResourceLimits::new_v2(
            ProcessLimit::new(1).expect("one raw fixture process"),
            WallTimeLimit::from_milliseconds(5_000).expect("bounded raw fixture"),
            OutputByteLimit::new(1024),
            OutputByteLimit::new(1024),
            MemoryByteLimit::new(128 * 1024 * 1024).expect("valid memory limit"),
            SwapByteLimit::new(0).expect("zero swap limit"),
        );
        let cgroup = FreshCgroup::create_v2(supported.cgroup_v2(), execution_id(), limits)
            .expect("create raw accounting cgroup");
        let cgroup_path = cgroup.path().to_owned();
        let child = std::process::Command::new(fixture)
            .arg(case)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn stopped raw accounting fixture");
        wait_until_stopped(child.id());
        cgroup
            .place_process(child.id())
            .expect("move stopped fixture into exact cgroup");
        assert!(
            cgroup
                .contains_process(child.id())
                .expect("read exact cgroup membership")
        );
        // SAFETY: `child.id()` is the live stopped child owned above, and
        // SIGCONT cannot access the parent's memory.
        let process_id = i32::try_from(child.id()).expect("Linux process IDs fit i32");
        assert_eq!(unsafe { libc::kill(process_id, libc::SIGCONT) }, 0);
        let output = child
            .wait_with_output()
            .expect("collect raw accounting fixture");
        assert!(output.status.success(), "{case}: {output:#?}");
        if case == "memory-socket" {
            assert_eq!(output.stdout, b"socket-memory-accounted\n");
        }
        let resources = cgroup
            .finish()
            .expect("drain and remove raw accounting cgroup")
            .expect("v2 raw accounting observation");
        assert!(!cgroup_path.exists(), "exact raw cgroup must be removed");
        resources
    }

    fn wait_until_stopped(process_id: u32) {
        let status_path = PathBuf::from(format!("/proc/{process_id}/status"));
        for _ in 0..5_000 {
            let status = std::fs::read_to_string(&status_path)
                .expect("stopped raw fixture remains observable");
            if status.lines().any(|line| line.starts_with("State:\tT")) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        panic!("raw accounting fixture did not stop before cgroup placement");
    }

    fn execution_id() -> ExecutionId {
        let marker = CASE_NUMBER.fetch_add(1, Ordering::Relaxed);
        let mut bytes = [0_u8; 16];
        bytes[..4].copy_from_slice(&std::process::id().to_be_bytes());
        bytes[6] = 0x40;
        bytes[8] = 0x80;
        bytes[15] = marker;
        ExecutionId::from_bytes(bytes).expect("valid deterministic version 4 execution ID")
    }

    fn create_fixture_directory() -> FixtureDirectory {
        let path =
            std::env::temp_dir().join(format!("proofbound-runtime-native-{}", std::process::id()));
        std::fs::create_dir(&path).expect("create unique native fixture directory");
        FixtureDirectory(path)
    }
}
