const ATTACK_CATALOG: &str = include_str!("../../../tests/attacks/native-linux/boundary-v1.toml");
const MEMORY_ATTACK_CATALOG: &str =
    include_str!("../../../tests/attacks/native-linux/memory-v2.toml");

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
    assert!(MEMORY_ATTACK_CATALOG.starts_with(
        "schema = \"proofbound-runtime-native-memory-attacks/2\""
    ));
    assert_eq!(
        MEMORY_ATTACK_CATALOG.matches("[[case]]").count(),
        expected.len()
    );
    for id in expected {
        assert!(MEMORY_ATTACK_CATALOG.contains(&format!("id = \"{id}\"")));
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
        ArtifactRole, AuthorityPath, BoundaryInstallation, ExecutionId, ExecutionOutcome,
        OutputByteLimit, ProcessLimit, ResourceLimits, Sha256Digest, StreamCapture, WallTimeLimit,
    };
    use proofbound_runtime_linux::{
        FreshCgroup, InstallRequest, LandlockAccess, LauncherFilesystemRule, LauncherIdentity,
        RootedPathResolver, SupportedLinux, compile_deny_network_program, probe_capabilities,
        supervise_launcher,
    };
    use sha2::{Digest as _, Sha256};

    static CASE_NUMBER: AtomicU8 = AtomicU8::new(1);

    struct FixtureDirectory(PathBuf);

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
        let expected_executable = observed.identity().clone();
        drop(observed);
        let executable = resolver
            .resolve_executable(
                &fixture_authority,
                &expected_executable,
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
            resolver
                .resolve_rooted_file(
                    &AuthorityPath::new(path.to_owned()).expect("readable authority path"),
                    ArtifactRole::ProjectInput,
                )
                .expect("resolve readable fixture")
        });

        let execution_id = execution_id();
        let limits = ResourceLimits::new(
            ProcessLimit::new(process_limit).expect("nonzero process limit"),
            WallTimeLimit::from_milliseconds(wall_time_ms).expect("nonzero wall time"),
            OutputByteLimit::new(stdout_limit),
            OutputByteLimit::new(1024),
        );
        let cgroup = FreshCgroup::create(supported.cgroup_v2(), execution_id, limits.processes())
            .expect("create fresh execution cgroup");
        let seccomp = compile_deny_network_program(
            proofbound_runtime_core::SeccompPolicy::DenyNetworkV1,
            supported.architecture(),
        )
        .expect("compile native seccomp policy");
        let mut hasher = Sha256::new();
        hasher.update(case.as_bytes());
        hasher.update(&seccomp);
        let policy_id = Sha256Digest::from_bytes(hasher.finalize().into());
        let identity = LauncherIdentity::new(execution_id, policy_id, cgroup.identity());

        let executable_fd = executable.executable().as_fd().as_raw_fd();
        let working_directory_fd = working_directory.as_raw_fd();
        let mut rules = vec![
            LauncherFilesystemRule::new(
                u32::try_from(executable_fd).expect("positive executable descriptor"),
                vec![LandlockAccess::Read, LandlockAccess::Execute],
            )
            .expect("executable rule"),
        ];
        if let Some(readable) = &readable {
            rules.push(
                LauncherFilesystemRule::new(
                    u32::try_from(readable.as_fd().as_raw_fd())
                        .expect("positive readable descriptor"),
                    vec![LandlockAccess::Read],
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
        let request = InstallRequest::new(
            identity,
            expected_executable,
            u32::try_from(executable_fd).expect("positive executable descriptor"),
            u32::try_from(working_directory_fd).expect("positive directory descriptor"),
            arguments,
            BTreeMap::new(),
            rules,
            seccomp,
            declared_upper_bound,
        )
        .expect("construct install request");

        let mut inherited = vec![executable.executable().as_fd(), working_directory.as_fd()];
        if let Some(readable) = &readable {
            inherited.push(readable.as_fd());
        }
        supervise_launcher(
            Path::new(env!("CARGO_BIN_EXE_pbr-native-launcher")),
            request,
            cgroup,
            limits,
            &inherited,
            supported.architecture(),
            supported.landlock_abi(),
        )
        .expect("supervise native launcher")
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
