#![forbid(unsafe_code)]

use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use proofbound_runtime_bench::{
    BenchmarkError, MeasurementConfig, PureBenchmarkResult, SourceRevision, ToolchainIdentity,
    benchmark_core_v1,
};
#[cfg(target_os = "linux")]
use proofbound_runtime_bench::{
    NativeBenchmarkResult, NativeHostIdentity, NativeRunArtifacts, NativeRuntimeIdentity,
    NativeWorkloadIdentity, summarize_native_runs,
};
#[cfg(target_os = "linux")]
use proofbound_runtime_cli::run::{ObservedRun, execute_observed};
use proofbound_runtime_core::Sha256Digest;
use sha2::{Digest, Sha256};

const BUILD_PROFILE: &str = env!("PBR_BENCH_BUILD_PROFILE");
const WARMUP_COUNT: usize = 100;
const SAMPLE_COUNT: usize = 1_000;
const TARGET_SAMPLE_NS: u64 = 10_000_000;
#[cfg(target_os = "linux")]
const NATIVE_WARMUP_COUNT: usize = 10;
#[cfg(target_os = "linux")]
const NATIVE_SAMPLE_COUNT: usize = 100;

#[derive(Debug, Eq, PartialEq)]
enum Arguments {
    Pure {
        source_commit: String,
    },
    Native {
        source_commit: String,
        result_root: PathBuf,
        cgroup_root: PathBuf,
        runtime_bin_directory: PathBuf,
        plan: PathBuf,
        workload_executable: PathBuf,
        expected_output: PathBuf,
        runner_image: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CliError {
    Usage,
    Command,
    Output,
    Benchmark(BenchmarkError),
}

impl CliError {
    const fn code(self) -> &'static str {
        match self {
            Self::Usage => "benchmark.arguments.invalid",
            Self::Command => "benchmark.provenance.command-failed",
            Self::Output => "benchmark.output.failed",
            Self::Benchmark(error) => match error {
                BenchmarkError::EmptySeries => "benchmark.series.empty",
                BenchmarkError::InvalidBatchCount => "benchmark.batch.invalid",
                BenchmarkError::InvalidTarget => "benchmark.target.invalid",
                BenchmarkError::BatchOverflow => "benchmark.batch.overflow",
                BenchmarkError::InvalidWarmupCount => "benchmark.warmup.invalid",
                BenchmarkError::ClockRegression => "benchmark.clock.regression",
                BenchmarkError::PreparationCountMismatch => "benchmark.preparation.count-mismatch",
                BenchmarkError::InvalidSourceCommit => "benchmark.source-commit.invalid",
                BenchmarkError::InvalidDigest => "benchmark.digest.invalid",
                BenchmarkError::SubjectDomainMismatch => "benchmark.subject-domain.mismatch",
                BenchmarkError::Encoding => "benchmark.result.encoding-failed",
                BenchmarkError::SubjectFailed => "benchmark.subject.failed",
                BenchmarkError::SourceMismatch => "benchmark.source-commit.mismatch",
                BenchmarkError::DirtyTree => "benchmark.tree.dirty",
                BenchmarkError::InvalidToolchain => "benchmark.toolchain.invalid",
                BenchmarkError::InvalidBuildProfile => "benchmark.build-profile.invalid",
                BenchmarkError::ConfigurationMismatch => "benchmark.configuration.mismatch",
                BenchmarkError::DurationOverflow => "benchmark.duration.overflow",
                BenchmarkError::UnsupportedHost => "benchmark.native.os-unsupported",
                BenchmarkError::InvalidNativeInput => "benchmark.native.input-invalid",
                BenchmarkError::NativeExecutionFailed => "benchmark.native.execution-failed",
                BenchmarkError::NativeArtifactFailed => "benchmark.native.artifact-failed",
            },
        }
    }
}

impl From<BenchmarkError> for CliError {
    fn from(error: BenchmarkError) -> Self {
        Self::Benchmark(error)
    }
}

fn main() -> ExitCode {
    match run(std::env::args(), &mut io::stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error.code());
            ExitCode::from(2)
        }
    }
}

fn run(
    arguments: impl IntoIterator<Item = String>,
    output: &mut impl Write,
) -> Result<(), CliError> {
    match parse_arguments(arguments)? {
        Arguments::Pure { source_commit } => run_pure(&source_commit, output),
        Arguments::Native {
            source_commit,
            result_root,
            cgroup_root,
            runtime_bin_directory,
            plan,
            workload_executable,
            expected_output,
            runner_image,
        } => run_native(
            &source_commit,
            &result_root,
            &cgroup_root,
            &runtime_bin_directory,
            &plan,
            &workload_executable,
            &expected_output,
            runner_image,
            output,
        ),
    }
}

fn run_pure(source_commit: &str, output: &mut impl Write) -> Result<(), CliError> {
    if BUILD_PROFILE != "release" {
        return Err(BenchmarkError::InvalidBuildProfile.into());
    }
    let (source, toolchain, executable_sha256) = observe_common(source_commit)?;
    let config = MeasurementConfig::new(WARMUP_COUNT, SAMPLE_COUNT, TARGET_SAMPLE_NS)?;
    let subjects = benchmark_core_v1(config)?;
    let result = PureBenchmarkResult::new(
        source,
        executable_sha256,
        toolchain,
        BUILD_PROFILE,
        std::env::consts::ARCH.to_owned(),
        config,
        subjects,
    )?;
    write_result(output, &result.to_json()?)
}

fn observe_common(
    source_commit: &str,
) -> Result<(SourceRevision, ToolchainIdentity, String), CliError> {
    let observed_commit = command_text("git", ["rev-parse", "--verify", "HEAD^{commit}"])?;
    let porcelain_status =
        command_text("git", ["status", "--porcelain=v1", "--untracked-files=all"])?;
    let source = SourceRevision::new(
        source_commit,
        observed_commit.trim_end_matches(['\r', '\n']),
        &porcelain_status,
    )?;
    let rustc_verbose = command_text("rustc", ["--version", "--verbose"])?;
    let toolchain = ToolchainIdentity::parse(&rustc_verbose)?;
    let executable = std::env::current_exe().map_err(|_| CliError::Command)?;
    let executable_sha256 = sha256_path(&executable, BenchmarkError::InvalidNativeInput)?;
    Ok((source, toolchain, executable_sha256))
}

fn write_result(output: &mut impl Write, result: &[u8]) -> Result<(), CliError> {
    output
        .write_all(result)
        .and_then(|()| output.write_all(b"\n"))
        .map_err(|_| CliError::Output)
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn run_native(
    _source_commit: &str,
    _result_root: &Path,
    _cgroup_root: &Path,
    _runtime_bin_directory: &Path,
    _plan: &Path,
    _workload_executable: &Path,
    _expected_output: &Path,
    _runner_image: String,
    _output: &mut impl Write,
) -> Result<(), CliError> {
    Err(BenchmarkError::UnsupportedHost.into())
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn run_native(
    source_commit: &str,
    result_root: &Path,
    cgroup_root: &Path,
    runtime_bin_directory: &Path,
    plan: &Path,
    workload_executable: &Path,
    expected_output: &Path,
    runner_image: String,
    output: &mut impl Write,
) -> Result<(), CliError> {
    if BUILD_PROFILE != "release" {
        return Err(BenchmarkError::InvalidBuildProfile.into());
    }
    let (source, toolchain, executable_sha256) = observe_common(source_commit)?;
    let repository_root = canonical_existing(Path::new(
        command_text("git", ["rev-parse", "--show-toplevel"])?.trim(),
    ))?;
    let result_root = canonical_existing(result_root)?;
    if result_root.starts_with(&repository_root) {
        return Err(BenchmarkError::InvalidNativeInput.into());
    }
    let cgroup_root = canonical_existing(cgroup_root)?;
    let runtime_bin_directory = canonical_existing(runtime_bin_directory)?;
    let plan = canonical_existing(plan)?;
    let workload_executable = canonical_existing(workload_executable)?;
    let expected_output = canonical_existing(expected_output)?;
    let plan_parent = plan.parent().ok_or(BenchmarkError::InvalidNativeInput)?;
    let output_root = plan_parent.join("output");
    let workload_output = output_root.join("hello.txt");
    let runs_root = result_root.join("runs");
    if output_root.exists() || runs_root.exists() {
        return Err(BenchmarkError::InvalidNativeInput.into());
    }
    std::fs::create_dir(&runs_root).map_err(|_| BenchmarkError::NativeArtifactFailed)?;

    let pbr = runtime_bin_directory.join("pbr");
    let launcher = runtime_bin_directory.join("pbr-native-launcher");
    let verifier = runtime_bin_directory.join("pbr-verify");
    let runtime = NativeRuntimeIdentity::new(
        sha256_path(&pbr, BenchmarkError::InvalidNativeInput)?,
        sha256_path(&launcher, BenchmarkError::InvalidNativeInput)?,
        sha256_path(&verifier, BenchmarkError::InvalidNativeInput)?,
    )?;
    let expected_output_bytes =
        std::fs::read(&expected_output).map_err(|_| BenchmarkError::InvalidNativeInput)?;
    let workload = NativeWorkloadIdentity::new(
        "hello-static-v1",
        sha256_path(&plan, BenchmarkError::InvalidNativeInput)?,
        sha256_path(&workload_executable, BenchmarkError::InvalidNativeInput)?,
        sha256_path(&expected_output, BenchmarkError::InvalidNativeInput)?,
    )?;

    let warmup_receipt = plan_parent.join("warmup-receipt.json");
    if warmup_receipt.exists() {
        return Err(BenchmarkError::InvalidNativeInput.into());
    }
    for _ in 0..NATIVE_WARMUP_COUNT {
        let observed = execute_observed(&plan, &warmup_receipt, &cgroup_root, &pbr)
            .map_err(|_| BenchmarkError::NativeExecutionFailed)?;
        validate_native_run(
            &observed,
            &warmup_receipt,
            &workload_output,
            &expected_output_bytes,
        )?;
        cleanup_native_run(&warmup_receipt, &workload_output, &output_root, true)?;
    }

    let mut timings = Vec::with_capacity(NATIVE_SAMPLE_COUNT);
    let mut artifacts = Vec::with_capacity(NATIVE_SAMPLE_COUNT);
    for index in 0..NATIVE_SAMPLE_COUNT {
        let run_root = runs_root.join(format!("{index:03}"));
        std::fs::create_dir(&run_root).map_err(|_| BenchmarkError::NativeArtifactFailed)?;
        let receipt = run_root.join("receipt.json");
        let observed = execute_observed(&plan, &receipt, &cgroup_root, &pbr)
            .map_err(|_| BenchmarkError::NativeExecutionFailed)?;
        let receipt_sha256 = validate_native_run(
            &observed,
            &receipt,
            &workload_output,
            &expected_output_bytes,
        )?;
        let run_result = run_root.join("run-result.json");
        let run_result_bytes =
            serde_json::to_vec(observed.report()).map_err(|_| BenchmarkError::Encoding)?;
        write_new(&run_result, &run_result_bytes)?;
        let retained_output = run_root.join("hello.txt");
        std::fs::copy(&workload_output, &retained_output)
            .map_err(|_| BenchmarkError::NativeArtifactFailed)?;
        let run_result_sha256 = sha256_path(&run_result, BenchmarkError::NativeArtifactFailed)?;
        let output_sha256 = sha256_path(&retained_output, BenchmarkError::NativeArtifactFailed)?;
        cleanup_native_run(&receipt, &workload_output, &output_root, false)?;
        timings.push(*observed.timings());
        artifacts.push(NativeRunArtifacts::new(
            receipt_sha256,
            run_result_sha256,
            output_sha256,
        )?);
    }

    let host = observe_native_host(runner_image, &cgroup_root)?;
    let measurements = summarize_native_runs(&timings)?;
    let result = NativeBenchmarkResult::new(
        source,
        executable_sha256,
        toolchain,
        BUILD_PROFILE,
        std::env::consts::ARCH.to_owned(),
        host,
        runtime,
        workload,
        measurements,
        artifacts,
    )?;
    write_result(output, &result.to_json()?)
}

#[cfg(target_os = "linux")]
fn validate_native_run(
    observed: &ObservedRun,
    receipt: &Path,
    workload_output: &Path,
    expected_output: &[u8],
) -> Result<String, CliError> {
    let receipt_sha256 = sha256_path(receipt, BenchmarkError::NativeArtifactFailed)?;
    validate_run_projection(observed.report(), receipt, &receipt_sha256)?;
    let entries = std::fs::read_dir(
        workload_output
            .parent()
            .ok_or(BenchmarkError::NativeArtifactFailed)?,
    )
    .map_err(|_| BenchmarkError::NativeArtifactFailed)?
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| BenchmarkError::NativeArtifactFailed)?;
    if entries.len() != 1 || entries[0].path() != workload_output {
        return Err(BenchmarkError::NativeArtifactFailed.into());
    }
    let output =
        std::fs::read(workload_output).map_err(|_| BenchmarkError::NativeArtifactFailed)?;
    if output != expected_output {
        return Err(BenchmarkError::NativeArtifactFailed.into());
    }
    Ok(receipt_sha256)
}

fn validate_run_projection(
    projection: &serde_json::Value,
    receipt: &Path,
    receipt_sha256: &str,
) -> Result<(), BenchmarkError> {
    let report = projection
        .as_object()
        .ok_or(BenchmarkError::NativeArtifactFailed)?;
    if report.len() != 5
        || report.get("schema").and_then(serde_json::Value::as_str)
            != Some("proofbound-runtime-run-result/1")
        || report.get("commitment").and_then(serde_json::Value::as_str)
            != Some(format!("sha256:{receipt_sha256}").as_str())
        || report.get("receipt").and_then(serde_json::Value::as_str)
            != Some(receipt.to_string_lossy().as_ref())
        || report
            .get("execution_id")
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        || report.get("outcome") != Some(&serde_json::json!({"kind": "exited", "code": 0}))
    {
        return Err(BenchmarkError::NativeArtifactFailed);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_native_run(
    receipt: &Path,
    workload_output: &Path,
    output_root: &Path,
    remove_receipt: bool,
) -> Result<(), CliError> {
    if remove_receipt {
        std::fs::remove_file(receipt).map_err(|_| BenchmarkError::NativeArtifactFailed)?;
    }
    std::fs::remove_file(workload_output).map_err(|_| BenchmarkError::NativeArtifactFailed)?;
    std::fs::remove_dir(output_root).map_err(|_| BenchmarkError::NativeArtifactFailed)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn observe_native_host(
    runner_image: String,
    cgroup_root: &Path,
) -> Result<NativeHostIdentity, CliError> {
    if !cgroup_root.join("cgroup.controllers").is_file() {
        return Err(BenchmarkError::InvalidNativeInput.into());
    }
    let lscpu = command_text("lscpu", std::iter::empty::<&str>())?;
    let cpu_model = lscpu
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name.trim() == "Model name").then(|| value.trim().to_owned())
        })
        .filter(|value| !value.is_empty())
        .ok_or(BenchmarkError::InvalidNativeInput)?;
    let cpu_count = command_text("getconf", ["_NPROCESSORS_ONLN"])?
        .trim()
        .parse::<u64>()
        .map_err(|_| BenchmarkError::InvalidNativeInput)?;
    let memory_bytes = parse_kib_field(
        &std::fs::read_to_string("/proc/meminfo")
            .map_err(|_| BenchmarkError::InvalidNativeInput)?,
        "MemTotal:",
    )?
    .checked_mul(1024)
    .ok_or(BenchmarkError::InvalidNativeInput)?;
    let kernel_release = command_text("uname", ["-r"])?
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    let mut enabled_controllers =
        std::fs::read_to_string(cgroup_root.join("cgroup.subtree_control"))
            .map_err(|_| BenchmarkError::InvalidNativeInput)?
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
    enabled_controllers.sort();
    let maximum_resident_set_bytes = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| parse_kib_field(&status, "VmHWM:").ok())
        .and_then(|value| value.checked_mul(1024));
    Ok(NativeHostIdentity::new(
        runner_image,
        cpu_model,
        cpu_count,
        memory_bytes,
        kernel_release,
        2,
        enabled_controllers,
        maximum_resident_set_bytes,
    )?)
}

#[cfg(target_os = "linux")]
fn parse_kib_field(contents: &str, field: &str) -> Result<u64, BenchmarkError> {
    let mut matches = contents.lines().filter_map(|line| {
        let value = line.strip_prefix(field)?.trim();
        let value = value.strip_suffix("kB")?.trim();
        value.parse::<u64>().ok()
    });
    let value = matches.next().ok_or(BenchmarkError::InvalidNativeInput)?;
    if matches.next().is_some() {
        return Err(BenchmarkError::InvalidNativeInput);
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn canonical_existing(path: &Path) -> Result<PathBuf, CliError> {
    path.canonicalize()
        .map_err(|_| BenchmarkError::InvalidNativeInput.into())
}

#[cfg(target_os = "linux")]
fn write_new(path: &Path, contents: &[u8]) -> Result<(), CliError> {
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| BenchmarkError::NativeArtifactFailed)?;
    target
        .write_all(contents)
        .map_err(|_| BenchmarkError::NativeArtifactFailed.into())
}

fn sha256_path(path: &Path, error: BenchmarkError) -> Result<String, CliError> {
    let bytes = std::fs::read(path).map_err(|_| error)?;
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    Ok(Sha256Digest::from_bytes(digest).to_hex())
}

fn command_text<I, S>(program: &str, arguments: I) -> Result<String, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let completed = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|_| CliError::Command)?;
    if !completed.status.success() || !completed.stderr.is_empty() {
        return Err(CliError::Command);
    }
    String::from_utf8(completed.stdout).map_err(|_| CliError::Command)
}

fn parse_arguments(arguments: impl IntoIterator<Item = String>) -> Result<Arguments, CliError> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next().ok_or(CliError::Usage)?;
    match arguments.next().as_deref() {
        Some("pure") => {
            let source_commit = exact_value(&mut arguments, "--source-commit")?;
            if arguments.next().is_some() || !is_source_commit(&source_commit) {
                return Err(CliError::Usage);
            }
            Ok(Arguments::Pure { source_commit })
        }
        Some("native") => {
            let source_commit = exact_value(&mut arguments, "--source-commit")?;
            let result_root = PathBuf::from(exact_value(&mut arguments, "--result-root")?);
            let cgroup_root = PathBuf::from(exact_value(&mut arguments, "--cgroup-root")?);
            let runtime_bin_directory =
                PathBuf::from(exact_value(&mut arguments, "--runtime-bin-directory")?);
            let plan = PathBuf::from(exact_value(&mut arguments, "--plan")?);
            let workload_executable =
                PathBuf::from(exact_value(&mut arguments, "--workload-executable")?);
            let expected_output = PathBuf::from(exact_value(&mut arguments, "--expected-output")?);
            let runner_image = exact_value(&mut arguments, "--runner-image")?;
            if arguments.next().is_some()
                || !is_source_commit(&source_commit)
                || [
                    &result_root,
                    &cgroup_root,
                    &runtime_bin_directory,
                    &plan,
                    &workload_executable,
                    &expected_output,
                ]
                .into_iter()
                .any(|path| !path.is_absolute())
                || runner_image.is_empty()
                || runner_image.len() > 512
            {
                return Err(CliError::Usage);
            }
            Ok(Arguments::Native {
                source_commit,
                result_root,
                cgroup_root,
                runtime_bin_directory,
                plan,
                workload_executable,
                expected_output,
                runner_image,
            })
        }
        _ => Err(CliError::Usage),
    }
}

fn exact_value(
    arguments: &mut impl Iterator<Item = String>,
    expected_flag: &str,
) -> Result<String, CliError> {
    if arguments.next().as_deref() != Some(expected_flag) {
        return Err(CliError::Usage);
    }
    arguments.next().ok_or(CliError::Usage)
}

fn is_source_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "linux"))]
    use super::run;
    use super::{Arguments, BenchmarkError, CliError, parse_arguments, validate_run_projection};

    #[test]
    fn arguments_accept_one_exact_pure_source() {
        let revision = "a".repeat(40);
        assert_eq!(
            parse_arguments([
                "pbr-bench".to_owned(),
                "pure".to_owned(),
                "--source-commit".to_owned(),
                revision.clone(),
            ]),
            Ok(Arguments::Pure {
                source_commit: revision,
            })
        );
    }

    #[test]
    fn arguments_accept_the_closed_native_input_set() {
        let revision = "a".repeat(40);
        assert_eq!(
            parse_arguments([
                "pbr-bench".to_owned(),
                "native".to_owned(),
                "--source-commit".to_owned(),
                revision.clone(),
                "--workload-id".to_owned(),
                "hello-dynamic-v1".to_owned(),
                "--result-root".to_owned(),
                "/results".to_owned(),
                "--cgroup-root".to_owned(),
                "/sys/fs/cgroup/delegated".to_owned(),
                "--runtime-bin-directory".to_owned(),
                "/runtime".to_owned(),
                "--plan".to_owned(),
                "/work/plan.toml".to_owned(),
                "--workload-executable".to_owned(),
                "/work/hello-static".to_owned(),
                "--expected-output".to_owned(),
                "/work/expected-output.txt".to_owned(),
                "--runner-image".to_owned(),
                "ubuntu-24.04".to_owned(),
            ]),
            Ok(Arguments::Native {
                source_commit: revision,
                workload_id: "hello-dynamic-v1".to_owned(),
                result_root: "/results".into(),
                cgroup_root: "/sys/fs/cgroup/delegated".into(),
                runtime_bin_directory: "/runtime".into(),
                plan: "/work/plan.toml".into(),
                workload_executable: "/work/hello-static".into(),
                expected_output: "/work/expected-output.txt".into(),
                runner_image: "ubuntu-24.04".to_owned(),
            })
        );
    }

    #[test]
    fn arguments_reject_missing_extra_and_noncanonical_sources() {
        for arguments in [
            vec!["pbr-bench"],
            vec!["pbr-bench", "native", "--source-commit", "a"],
            vec![
                "pbr-bench",
                "native",
                "--source-commit",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--workload-id",
                "hello-unregistered-v1",
                "--result-root",
                "/results",
                "--cgroup-root",
                "/cgroup",
                "--runtime-bin-directory",
                "/runtime",
                "--plan",
                "/plan",
                "--workload-executable",
                "/workload",
                "--expected-output",
                "/expected",
                "--runner-image",
                "ubuntu-24.04",
            ],
            vec![
                "pbr-bench",
                "native",
                "--source-commit",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--result-root",
                "relative",
                "--cgroup-root",
                "/cgroup",
                "--runtime-bin-directory",
                "/runtime",
                "--plan",
                "/plan",
                "--workload-executable",
                "/workload",
                "--expected-output",
                "/expected",
                "--runner-image",
                "ubuntu-24.04",
            ],
            vec!["pbr-bench", "pure", "--source-commit", "a"],
            vec![
                "pbr-bench",
                "pure",
                "--source-commit",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "extra",
            ],
        ] {
            assert_eq!(
                parse_arguments(arguments.into_iter().map(str::to_owned)),
                Err(CliError::Usage)
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn native_command_remains_fail_closed_off_linux() {
        let revision = "a".repeat(40);
        let error = run(
            [
                "pbr-bench".to_owned(),
                "native".to_owned(),
                "--source-commit".to_owned(),
                revision,
                "--workload-id".to_owned(),
                "hello-static-v1".to_owned(),
                "--result-root".to_owned(),
                "/results".to_owned(),
                "--cgroup-root".to_owned(),
                "/sys/fs/cgroup/delegated".to_owned(),
                "--runtime-bin-directory".to_owned(),
                "/runtime".to_owned(),
                "--plan".to_owned(),
                "/work/plan.toml".to_owned(),
                "--workload-executable".to_owned(),
                "/work/hello-static".to_owned(),
                "--expected-output".to_owned(),
                "/work/expected-output.txt".to_owned(),
                "--runner-image".to_owned(),
                "ubuntu-24.04".to_owned(),
            ],
            &mut Vec::new(),
        )
        .expect_err("native benchmarking cannot run on an unsupported host");

        assert_eq!(error, CliError::Benchmark(BenchmarkError::UnsupportedHost));
    }

    #[test]
    fn native_validator_accepts_only_the_real_run_projection() {
        let receipt = std::path::Path::new("/results/runs/000/receipt.json");
        let digest = "a".repeat(64);
        let projection = serde_json::json!({
            "commitment": format!("sha256:{digest}"),
            "execution_id": "00112233-4455-4677-8899-aabbccddeeff",
            "outcome": {"kind": "exited", "code": 0},
            "receipt": receipt,
            "schema": "proofbound-runtime-run-result/1",
        });
        assert_eq!(
            validate_run_projection(&projection, receipt, &digest),
            Ok(())
        );

        let mut missing_receipt = projection.clone();
        missing_receipt
            .as_object_mut()
            .expect("fixture is an object")
            .remove("receipt");
        assert_eq!(
            validate_run_projection(&missing_receipt, receipt, &digest),
            Err(BenchmarkError::NativeArtifactFailed)
        );
    }
}
