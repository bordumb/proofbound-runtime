#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use proofbound_runtime_bench::{
    BenchmarkError, MeasurementConfig, PureBenchmarkResult, SourceRevision, ToolchainIdentity,
    benchmark_core_v1,
};
use proofbound_runtime_core::Sha256Digest;
use sha2::{Digest, Sha256};

const BUILD_PROFILE: &str = env!("PBR_BENCH_BUILD_PROFILE");
const WARMUP_COUNT: usize = 100;
const SAMPLE_COUNT: usize = 1_000;
const TARGET_SAMPLE_NS: u64 = 10_000_000;

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
    let arguments = match parse_arguments(arguments)? {
        Arguments::Pure { source_commit } => source_commit,
        Arguments::Native { .. } => return Err(CliError::Usage),
    };
    if BUILD_PROFILE != "release" {
        return Err(BenchmarkError::InvalidBuildProfile.into());
    }

    let observed_commit = command_text("git", ["rev-parse", "--verify", "HEAD^{commit}"])?;
    let porcelain_status =
        command_text("git", ["status", "--porcelain=v1", "--untracked-files=all"])?;
    let source = SourceRevision::new(
        &arguments,
        observed_commit.trim_end_matches(['\r', '\n']),
        &porcelain_status,
    )?;
    let rustc_verbose = command_text("rustc", ["--version", "--verbose"])?;
    let toolchain = ToolchainIdentity::parse(&rustc_verbose)?;
    let executable = std::env::current_exe().map_err(|_| CliError::Command)?;
    let executable_bytes = std::fs::read(executable).map_err(|_| CliError::Command)?;
    let executable_digest: [u8; 32] = Sha256::digest(executable_bytes).into();
    let executable_sha256 = Sha256Digest::from_bytes(executable_digest).to_hex();
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
    output
        .write_all(&result.to_json()?)
        .and_then(|()| output.write_all(b"\n"))
        .map_err(|_| CliError::Output)
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
    use super::{Arguments, BenchmarkError, CliError, parse_arguments, run};

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
}
