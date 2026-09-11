#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::io::{self, Write};
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
struct Arguments {
    source_commit: String,
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
    let arguments = parse_arguments(arguments)?;
    if BUILD_PROFILE != "release" {
        return Err(BenchmarkError::InvalidBuildProfile.into());
    }

    let observed_commit = command_text("git", ["rev-parse", "--verify", "HEAD^{commit}"])?;
    let porcelain_status =
        command_text("git", ["status", "--porcelain=v1", "--untracked-files=all"])?;
    let source = SourceRevision::new(
        &arguments.source_commit,
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
    if arguments.next().as_deref() != Some("pure")
        || arguments.next().as_deref() != Some("--source-commit")
    {
        return Err(CliError::Usage);
    }
    let source_commit = arguments.next().ok_or(CliError::Usage)?;
    if arguments.next().is_some()
        || source_commit.len() != 40
        || !source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CliError::Usage);
    }
    Ok(Arguments { source_commit })
}

#[cfg(test)]
mod tests {
    use super::{Arguments, CliError, parse_arguments};

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
            Ok(Arguments {
                source_commit: revision,
            })
        );
    }

    #[test]
    fn arguments_reject_missing_extra_and_noncanonical_sources() {
        for arguments in [
            vec!["pbr-bench"],
            vec!["pbr-bench", "native", "--source-commit", "a"],
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
}
