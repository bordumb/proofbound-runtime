#![forbid(unsafe_code)]

//! Produces operational Runtime performance metadata outside the assurance
//! evidence boundary.

use core::fmt;
use std::time::Instant;

use proofbound_runtime_core::{
    Architecture, ArtifactIdentity, ArtifactRole, BoundaryInstallation, BoundaryRecord,
    CgroupIdentity, EnvironmentName, ExecutionId, ExecutionObservations, ExecutionOutcome,
    ExecutionReceiptParts, FileMode, PlanId, PlatformIdentity, ReceiptCommand, ReceiptPlan,
    ReceiptPolicy, ReceiptStreams, RuntimeIdentity, Sha256Digest, StreamCapture,
    TrustedComputingBaseEntry, TrustedComputingBaseRole, compile_policy,
    construct_execution_receipt, normalize_authority, parse_execution_plan,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// One closed benchmark-harness failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkError {
    /// A measured series contained no samples.
    EmptySeries,
    /// Batch calibration started from zero invocations.
    InvalidBatchCount,
    /// Batch calibration selected a zero-duration target.
    InvalidTarget,
    /// The next calibrated batch cannot fit in the platform counter.
    BatchOverflow,
    /// A measurement selected zero warm-up iterations.
    InvalidWarmupCount,
    /// The supplied monotonic clock moved backwards.
    ClockRegression,
    /// An input-preparation step returned the wrong number of inputs.
    PreparationCountMismatch,
    /// A source revision is not one canonical full Git object identity.
    InvalidSourceCommit,
    /// A retained SHA-256 identity is not canonical lowercase hexadecimal.
    InvalidDigest,
    /// The pure result does not contain each closed subject exactly once.
    SubjectDomainMismatch,
    /// Operational JSON serialization failed.
    Encoding,
    /// A prevalidated production subject could not be evaluated.
    SubjectFailed,
    /// The observed repository head differs from the requested source.
    SourceMismatch,
    /// The repository contained tracked or untracked changes.
    DirtyTree,
    /// Rust compiler verbose output omitted or duplicated a required identity.
    InvalidToolchain,
    /// The benchmark binary was not built with the frozen release profile.
    InvalidBuildProfile,
    /// Retained samples disagree with the declared measurement protocol.
    ConfigurationMismatch,
}

impl fmt::Display for BenchmarkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptySeries => "benchmark.series.empty",
            Self::InvalidBatchCount => "benchmark.batch.invalid",
            Self::InvalidTarget => "benchmark.target.invalid",
            Self::BatchOverflow => "benchmark.batch.overflow",
            Self::InvalidWarmupCount => "benchmark.warmup.invalid",
            Self::ClockRegression => "benchmark.clock.regression",
            Self::PreparationCountMismatch => "benchmark.preparation.count-mismatch",
            Self::InvalidSourceCommit => "benchmark.source-commit.invalid",
            Self::InvalidDigest => "benchmark.digest.invalid",
            Self::SubjectDomainMismatch => "benchmark.subject-domain.mismatch",
            Self::Encoding => "benchmark.result.encoding-failed",
            Self::SubjectFailed => "benchmark.subject.failed",
            Self::SourceMismatch => "benchmark.source-commit.mismatch",
            Self::DirtyTree => "benchmark.tree.dirty",
            Self::InvalidToolchain => "benchmark.toolchain.invalid",
            Self::InvalidBuildProfile => "benchmark.build-profile.invalid",
            Self::ConfigurationMismatch => "benchmark.configuration.mismatch",
        })
    }
}

impl std::error::Error for BenchmarkError {}

/// Exact sorted samples and their frozen integer summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Summary {
    /// Raw elapsed nanoseconds in ascending order.
    pub samples_ns: Vec<u64>,
    /// Number of raw samples.
    pub count: usize,
    /// Smallest observed duration.
    pub minimum_ns: u64,
    /// Integer midpoint median.
    pub median_ns: u64,
    /// Nearest-rank 95th percentile.
    pub p95_ns: u64,
    /// Largest observed duration.
    pub maximum_ns: u64,
}

/// Frozen controls for one measured operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct MeasurementConfig {
    warmup_count: usize,
    sample_count: usize,
    target_sample_ns: u64,
}

impl MeasurementConfig {
    /// Validates one nonempty measurement configuration.
    pub const fn new(
        warmup_count: usize,
        sample_count: usize,
        target_sample_ns: u64,
    ) -> Result<Self, BenchmarkError> {
        if warmup_count == 0 {
            return Err(BenchmarkError::InvalidWarmupCount);
        }
        if sample_count == 0 {
            return Err(BenchmarkError::EmptySeries);
        }
        if target_sample_ns == 0 {
            return Err(BenchmarkError::InvalidTarget);
        }
        Ok(Self {
            warmup_count,
            sample_count,
            target_sample_ns,
        })
    }
}

/// One calibrated benchmark measurement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Measurement {
    /// Number of operation invocations in each measured sample.
    pub batch_count: usize,
    /// Per-invocation elapsed-time observations.
    pub summary: Summary,
}

/// Closed version 1 pure-operation benchmark domain.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PureSubject {
    /// Strict version 1 plan parsing and typed validation.
    #[serde(rename = "plan-parse-v1")]
    PlanParseV1,
    /// Version 1 authority normalization.
    #[serde(rename = "authority-normalization-v1")]
    AuthorityNormalizationV1,
    /// Version 1 policy compilation.
    #[serde(rename = "policy-compilation-v1")]
    PolicyCompilationV1,
    /// Version 1 typed execution-receipt construction.
    #[serde(rename = "receipt-construction-v1")]
    ReceiptConstructionV1,
    /// Version 1 canonical JSON receipt encoding.
    #[serde(rename = "receipt-canonical-encoding-v1")]
    ReceiptCanonicalEncodingV1,
}

const PURE_SUBJECT_DOMAIN: [PureSubject; 5] = [
    PureSubject::PlanParseV1,
    PureSubject::AuthorityNormalizationV1,
    PureSubject::PolicyCompilationV1,
    PureSubject::ReceiptConstructionV1,
    PureSubject::ReceiptCanonicalEncodingV1,
];

/// One pure subject, exact fixture identity, and calibrated measurement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PureSubjectResult {
    subject: PureSubject,
    fixture_sha256: String,
    measurement: Measurement,
}

impl PureSubjectResult {
    /// Validates one pure benchmark subject result.
    pub fn new(
        subject: PureSubject,
        fixture_sha256: String,
        measurement: Measurement,
    ) -> Result<Self, BenchmarkError> {
        if !is_lower_hex_exact(&fixture_sha256, 64) {
            return Err(BenchmarkError::InvalidDigest);
        }
        Ok(Self {
            subject,
            fixture_sha256,
            measurement,
        })
    }

    /// Returns the closed subject identifier.
    #[must_use]
    pub const fn subject(&self) -> PureSubject {
        self.subject
    }

    /// Returns the exact input-fixture identity.
    #[must_use]
    pub fn fixture_sha256(&self) -> &str {
        &self.fixture_sha256
    }

    /// Returns the calibrated measurement.
    #[must_use]
    pub const fn measurement(&self) -> &Measurement {
        &self.measurement
    }
}

/// One complete operational result for the closed pure benchmark domain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PureBenchmarkResult {
    schema: &'static str,
    kind: &'static str,
    complete: bool,
    source: SourceRevision,
    benchmark_executable_sha256: String,
    toolchain: ToolchainIdentity,
    build_profile: &'static str,
    architecture: String,
    protocol: MeasurementConfig,
    subjects: Vec<PureSubjectResult>,
}

impl PureBenchmarkResult {
    /// Validates and canonicalizes one complete pure result.
    pub fn new(
        source: SourceRevision,
        benchmark_executable_sha256: String,
        toolchain: ToolchainIdentity,
        build_profile: &'static str,
        architecture: String,
        protocol: MeasurementConfig,
        mut subjects: Vec<PureSubjectResult>,
    ) -> Result<Self, BenchmarkError> {
        if !is_lower_hex_exact(&benchmark_executable_sha256, 64) {
            return Err(BenchmarkError::InvalidDigest);
        }
        if build_profile != "release" {
            return Err(BenchmarkError::InvalidBuildProfile);
        }
        subjects.sort_by_key(PureSubjectResult::subject);
        if subjects.len() != PURE_SUBJECT_DOMAIN.len()
            || !subjects
                .iter()
                .map(PureSubjectResult::subject)
                .eq(PURE_SUBJECT_DOMAIN)
        {
            return Err(BenchmarkError::SubjectDomainMismatch);
        }
        if subjects.iter().any(|subject| {
            subject.measurement.batch_count == 0
                || subject.measurement.summary.count != protocol.sample_count
                || subject.measurement.summary.samples_ns.len() != protocol.sample_count
        }) {
            return Err(BenchmarkError::ConfigurationMismatch);
        }
        Ok(Self {
            schema: "proofbound-runtime-performance-result/1",
            kind: "pure",
            complete: true,
            source,
            benchmark_executable_sha256,
            toolchain,
            build_profile,
            architecture,
            protocol,
            subjects,
        })
    }

    /// Returns pure subjects in their canonical domain order.
    #[must_use]
    pub fn subjects(&self) -> &[PureSubjectResult] {
        &self.subjects
    }

    /// Encodes stable compact operational JSON.
    pub fn to_json(&self) -> Result<Vec<u8>, BenchmarkError> {
        serde_json::to_vec(self).map_err(|_| BenchmarkError::Encoding)
    }
}

/// One exact clean repository source observed before measurement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceRevision {
    commit: String,
    tree_state: &'static str,
}

impl SourceRevision {
    /// Validates an expected source against the observed repository state.
    pub fn new(
        expected_commit: &str,
        observed_commit: &str,
        porcelain_status: &str,
    ) -> Result<Self, BenchmarkError> {
        if !is_lower_hex_exact(expected_commit, 40) || !is_lower_hex_exact(observed_commit, 40) {
            return Err(BenchmarkError::InvalidSourceCommit);
        }
        if expected_commit != observed_commit {
            return Err(BenchmarkError::SourceMismatch);
        }
        if !porcelain_status.is_empty() {
            return Err(BenchmarkError::DirtyTree);
        }
        Ok(Self {
            commit: expected_commit.to_owned(),
            tree_state: "clean",
        })
    }

    /// Returns the exact full source commit.
    #[must_use]
    pub fn commit(&self) -> &str {
        &self.commit
    }

    /// Returns the observed closed tree state.
    #[must_use]
    pub const fn tree_state(&self) -> &'static str {
        self.tree_state
    }
}

/// Required fields from one exact `rustc --version --verbose` observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ToolchainIdentity {
    release: String,
    target: String,
}

impl ToolchainIdentity {
    /// Parses exactly one nonempty `release` and `host` field.
    pub fn parse(verbose: &str) -> Result<Self, BenchmarkError> {
        let release = unique_verbose_field(verbose, "release: ")?;
        let target = unique_verbose_field(verbose, "host: ")?;
        Ok(Self { release, target })
    }

    /// Returns the exact Rust release string.
    #[must_use]
    pub fn release(&self) -> &str {
        &self.release
    }

    /// Returns the compiler host target.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }
}

fn unique_verbose_field(verbose: &str, prefix: &str) -> Result<String, BenchmarkError> {
    let mut values = verbose.lines().filter_map(|line| line.strip_prefix(prefix));
    let value = values.next().filter(|value| !value.is_empty());
    if value.is_none() || values.next().is_some() {
        return Err(BenchmarkError::InvalidToolchain);
    }
    Ok(value.expect("nonempty unique value was checked").to_owned())
}

fn is_lower_hex_exact(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Measures a reusable-input operation with a monotonic clock.
pub fn measure<T, Operation>(
    config: MeasurementConfig,
    operation: Operation,
) -> Result<Measurement, BenchmarkError>
where
    Operation: FnMut() -> T,
{
    let origin = Instant::now();
    measure_with_clock(config, operation, || elapsed_ns(origin))
}

/// Measures a consuming operation without timing input preparation.
pub fn measure_prepared<Input, Output, Prepare, Operation>(
    config: MeasurementConfig,
    prepare: Prepare,
    operation: Operation,
) -> Result<Measurement, BenchmarkError>
where
    Prepare: FnMut(usize) -> Vec<Input>,
    Operation: FnMut(Input) -> Output,
{
    let origin = Instant::now();
    measure_prepared_with_clock(config, prepare, operation, || elapsed_ns(origin))
}

fn elapsed_ns(origin: Instant) -> u64 {
    u64::try_from(origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Measures the closed first set of existing version 1 pure operations.
pub fn benchmark_core_v1(
    config: MeasurementConfig,
) -> Result<Vec<PureSubjectResult>, BenchmarkError> {
    const PLAN_FIXTURE: &str =
        include_str!("../../../tests/conformance/plan/positive/minimal-v1.toml");
    const RECEIPT_FIXTURE: &[u8] =
        include_bytes!("../../../experiments/performance/fixtures/reusable-receipt-v1.json");

    let plan = parse_execution_plan(PLAN_FIXTURE).map_err(|_| BenchmarkError::SubjectFailed)?;
    let normalized =
        normalize_authority(plan.authority().clone()).map_err(|_| BenchmarkError::SubjectFailed)?;
    let fixture_digest: [u8; 32] = Sha256::digest(PLAN_FIXTURE.as_bytes()).into();
    let fixture_sha256 = Sha256Digest::from_bytes(fixture_digest).to_hex();
    let receipt_parts = receipt_parts_v1()?;
    let receipt = construct_execution_receipt(receipt_parts.clone())
        .map_err(|_| BenchmarkError::SubjectFailed)?;
    let receipt_bytes = receipt
        .canonical_bytes()
        .map_err(|_| BenchmarkError::SubjectFailed)?;
    if RECEIPT_FIXTURE.strip_suffix(b"\n") != Some(receipt_bytes.as_slice()) {
        return Err(BenchmarkError::SubjectFailed);
    }
    let receipt_fixture_digest: [u8; 32] = Sha256::digest(RECEIPT_FIXTURE).into();
    let receipt_fixture_sha256 = Sha256Digest::from_bytes(receipt_fixture_digest).to_hex();

    let plan_parse = measure(config, || {
        parse_execution_plan(std::hint::black_box(PLAN_FIXTURE))
            .expect("prevalidated plan fixture remains valid")
    })?;
    let authority_normalization = measure_prepared(
        config,
        |count| vec![plan.authority().clone(); count],
        |authority| {
            normalize_authority(authority).expect("prevalidated authority fixture remains valid")
        },
    )?;
    let policy_compilation = measure_prepared(
        config,
        |count| vec![normalized.clone(); count],
        compile_policy,
    )?;
    let receipt_construction = measure_prepared(
        config,
        |count| vec![receipt_parts.clone(); count],
        |parts| {
            construct_execution_receipt(parts)
                .expect("prevalidated receipt parts remain constructible")
        },
    )?;
    let receipt_encoding = measure_prepared(
        config,
        |count| vec![receipt.clone(); count],
        |receipt| {
            receipt
                .canonical_bytes()
                .expect("prevalidated receipt remains encodable")
        },
    )?;

    [
        (PureSubject::PlanParseV1, fixture_sha256.clone(), plan_parse),
        (
            PureSubject::AuthorityNormalizationV1,
            fixture_sha256.clone(),
            authority_normalization,
        ),
        (
            PureSubject::PolicyCompilationV1,
            fixture_sha256,
            policy_compilation,
        ),
        (
            PureSubject::ReceiptConstructionV1,
            receipt_fixture_sha256.clone(),
            receipt_construction,
        ),
        (
            PureSubject::ReceiptCanonicalEncodingV1,
            receipt_fixture_sha256,
            receipt_encoding,
        ),
    ]
    .into_iter()
    .map(|(subject, fixture, measurement)| PureSubjectResult::new(subject, fixture, measurement))
    .collect()
}

fn artifact_v1(role: ArtifactRole, marker: u8) -> Result<ArtifactIdentity, BenchmarkError> {
    let mode = FileMode::new(0o640).map_err(|_| BenchmarkError::SubjectFailed)?;
    Ok(ArtifactIdentity::new(
        role,
        Sha256Digest::from_bytes([marker; 32]),
        u64::from(marker),
        mode,
    ))
}

fn receipt_parts_v1() -> Result<ExecutionReceiptParts, BenchmarkError> {
    let execution_id = ExecutionId::from_bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ])
    .map_err(|_| BenchmarkError::SubjectFailed)?;
    let runtime = artifact_v1(ArtifactRole::RuntimeBinary, 4)?;
    let policy = artifact_v1(ArtifactRole::CompiledPolicy, 3)?;
    let trusted_computing_base = [
        TrustedComputingBaseRole::HostHardwareFirmware,
        TrustedComputingBaseRole::LinuxKernel,
        TrustedComputingBaseRole::Landlock,
        TrustedComputingBaseRole::Seccomp,
        TrustedComputingBaseRole::CgroupV2,
        TrustedComputingBaseRole::NoNewPrivileges,
        TrustedComputingBaseRole::Filesystem,
        TrustedComputingBaseRole::RuntimeBinary,
        TrustedComputingBaseRole::LauncherBinary,
        TrustedComputingBaseRole::RustToolchain,
        TrustedComputingBaseRole::CryptographicDigest,
        TrustedComputingBaseRole::RuntimeExecutable,
        TrustedComputingBaseRole::RuntimeLoaderExecutable,
        TrustedComputingBaseRole::RuntimeLibrary,
    ]
    .into_iter()
    .map(|role| {
        TrustedComputingBaseEntry::new(role, format!("{}:benchmark-fixture", role.as_str()))
            .map_err(|_| BenchmarkError::SubjectFailed)
    })
    .collect::<Result<Vec<_>, _>>()?;

    Ok(ExecutionReceiptParts {
        execution_id,
        plan: ReceiptPlan::new(
            PlanId::new("benchmark.plan").map_err(|_| BenchmarkError::SubjectFailed)?,
            artifact_v1(ArtifactRole::ExecutionPlan, 1)?,
            artifact_v1(ArtifactRole::NormalizedPlan, 2)?,
        )
        .map_err(|_| BenchmarkError::SubjectFailed)?,
        policy: ReceiptPolicy::new(policy.clone()).map_err(|_| BenchmarkError::SubjectFailed)?,
        platform: PlatformIdentity::new(
            Architecture::X86_64,
            "6.12.0-benchmark",
            6,
            vec!["log".to_owned(), "tsync".to_owned()],
            vec!["memory".to_owned(), "pids".to_owned()],
        )
        .map_err(|_| BenchmarkError::SubjectFailed)?,
        runtime: RuntimeIdentity::new(
            runtime.clone(),
            artifact_v1(ArtifactRole::LauncherBinary, 5)?,
        )
        .map_err(|_| BenchmarkError::SubjectFailed)?,
        command: ReceiptCommand::new(
            artifact_v1(ArtifactRole::RuntimeExecutable, 6)?,
            Some(artifact_v1(ArtifactRole::RuntimeLoaderExecutable, 7)?),
            artifact_v1(ArtifactRole::WorkingDirectory, 8)?,
            Sha256Digest::from_bytes([9; 32]),
        )
        .map_err(|_| BenchmarkError::SubjectFailed)?,
        inputs: vec![
            artifact_v1(ArtifactRole::RuntimeLibrary, 10)?,
            artifact_v1(ArtifactRole::ProjectInput, 11)?,
        ],
        environment: vec![
            EnvironmentName::new("LANG").map_err(|_| BenchmarkError::SubjectFailed)?,
            EnvironmentName::new("PATH").map_err(|_| BenchmarkError::SubjectFailed)?,
        ],
        output_root: artifact_v1(ArtifactRole::OutputRoot, 12)?,
        boundary: BoundaryRecord::new(
            BoundaryInstallation::Installed,
            execution_id,
            policy.digest(),
            CgroupIdentity::new(13, 14),
        ),
        observations: ExecutionObservations::new(15, 16)
            .map_err(|_| BenchmarkError::SubjectFailed)?,
        streams: ReceiptStreams::new(
            artifact_v1(ArtifactRole::StandardOutput, 17)?,
            StreamCapture::Complete,
            artifact_v1(ArtifactRole::StandardError, 18)?,
            StreamCapture::Complete,
        )
        .map_err(|_| BenchmarkError::SubjectFailed)?,
        outcome: ExecutionOutcome::Exited { code: 0 },
        outputs: vec![artifact_v1(ArtifactRole::OutputArtifact, 19)?],
        producer: runtime,
        assumptions: proofbound_runtime_core::REQUIRED_RUNTIME_ASSUMPTIONS
            .into_iter()
            .rev()
            .map(str::to_owned)
            .collect(),
        trusted_computing_base,
    })
}

/// Sorts and summarizes one nonempty elapsed-time series.
pub fn summarize(mut samples_ns: Vec<u64>) -> Result<Summary, BenchmarkError> {
    if samples_ns.is_empty() {
        return Err(BenchmarkError::EmptySeries);
    }
    samples_ns.sort_unstable();
    let count = samples_ns.len();
    let median_ns = if count.is_multiple_of(2) {
        let lower = samples_ns[count / 2 - 1];
        let upper = samples_ns[count / 2];
        lower + (upper - lower) / 2
    } else {
        samples_ns[count / 2]
    };
    // ceil(0.95 * count) equals count - floor(count / 20).
    let p95_index = count - count / 20 - 1;

    Ok(Summary {
        minimum_ns: samples_ns[0],
        median_ns,
        p95_ns: samples_ns[p95_index],
        maximum_ns: samples_ns[count - 1],
        samples_ns,
        count,
    })
}

/// Derives the next deterministic batch count from one calibration sample.
///
/// `Ok(None)` means the current batch reached the target. A zero elapsed value
/// grows the batch by exactly ten so timer resolution cannot create division
/// by zero or an unbounded inferred factor.
pub fn next_batch_count(
    current: usize,
    elapsed_ns: u64,
    target_ns: u64,
) -> Result<Option<usize>, BenchmarkError> {
    if current == 0 {
        return Err(BenchmarkError::InvalidBatchCount);
    }
    if target_ns == 0 {
        return Err(BenchmarkError::InvalidTarget);
    }
    if elapsed_ns >= target_ns {
        return Ok(None);
    }

    let factor = if elapsed_ns == 0 {
        10
    } else {
        usize::try_from(target_ns.div_ceil(elapsed_ns))
            .map_err(|_| BenchmarkError::BatchOverflow)?
    };
    current
        .checked_mul(factor)
        .map(Some)
        .ok_or(BenchmarkError::BatchOverflow)
}

/// Measures an operation against a caller-supplied monotonic nanosecond clock.
///
/// Supplying the clock keeps the loop exactly testable. Production callers
/// adapt `Instant` to this boundary.
pub fn measure_with_clock<T, Operation, Clock>(
    config: MeasurementConfig,
    mut operation: Operation,
    mut clock: Clock,
) -> Result<Measurement, BenchmarkError>
where
    Operation: FnMut() -> T,
    Clock: FnMut() -> u64,
{
    for _ in 0..config.warmup_count {
        std::hint::black_box(operation());
    }

    let mut batch_count = 1;
    loop {
        let elapsed_ns = time_batch(batch_count, &mut operation, &mut clock)?;
        match next_batch_count(batch_count, elapsed_ns, config.target_sample_ns)? {
            Some(next) => batch_count = next,
            None => break,
        }
    }

    let divisor = u64::try_from(batch_count).map_err(|_| BenchmarkError::BatchOverflow)?;
    let mut samples_ns = Vec::with_capacity(config.sample_count);
    for _ in 0..config.sample_count {
        let elapsed_ns = time_batch(batch_count, &mut operation, &mut clock)?;
        samples_ns.push(elapsed_ns / divisor);
    }

    Ok(Measurement {
        batch_count,
        summary: summarize(samples_ns)?,
    })
}

fn time_batch<T, Operation, Clock>(
    batch_count: usize,
    operation: &mut Operation,
    clock: &mut Clock,
) -> Result<u64, BenchmarkError>
where
    Operation: FnMut() -> T,
    Clock: FnMut() -> u64,
{
    let started_ns = clock();
    for _ in 0..batch_count {
        std::hint::black_box(operation());
    }
    clock()
        .checked_sub(started_ns)
        .ok_or(BenchmarkError::ClockRegression)
}

/// Measures a consuming operation while excluding input construction.
pub fn measure_prepared_with_clock<Input, Output, Prepare, Operation, Clock>(
    config: MeasurementConfig,
    mut prepare: Prepare,
    mut operation: Operation,
    mut clock: Clock,
) -> Result<Measurement, BenchmarkError>
where
    Prepare: FnMut(usize) -> Vec<Input>,
    Operation: FnMut(Input) -> Output,
    Clock: FnMut() -> u64,
{
    run_prepared_batch(
        config.warmup_count,
        &mut prepare,
        &mut operation,
        None::<&mut Clock>,
    )?;

    let mut batch_count = 1;
    loop {
        let elapsed_ns =
            run_prepared_batch(batch_count, &mut prepare, &mut operation, Some(&mut clock))?
                .expect("a supplied clock produces elapsed time");
        match next_batch_count(batch_count, elapsed_ns, config.target_sample_ns)? {
            Some(next) => batch_count = next,
            None => break,
        }
    }

    let divisor = u64::try_from(batch_count).map_err(|_| BenchmarkError::BatchOverflow)?;
    let mut samples_ns = Vec::with_capacity(config.sample_count);
    for _ in 0..config.sample_count {
        let elapsed_ns =
            run_prepared_batch(batch_count, &mut prepare, &mut operation, Some(&mut clock))?
                .expect("a supplied clock produces elapsed time");
        samples_ns.push(elapsed_ns / divisor);
    }

    Ok(Measurement {
        batch_count,
        summary: summarize(samples_ns)?,
    })
}

fn run_prepared_batch<Input, Output, Prepare, Operation, Clock>(
    count: usize,
    prepare: &mut Prepare,
    operation: &mut Operation,
    mut clock: Option<&mut Clock>,
) -> Result<Option<u64>, BenchmarkError>
where
    Prepare: FnMut(usize) -> Vec<Input>,
    Operation: FnMut(Input) -> Output,
    Clock: FnMut() -> u64,
{
    let inputs = prepare(count);
    if inputs.len() != count {
        return Err(BenchmarkError::PreparationCountMismatch);
    }
    let started_ns = clock.as_mut().map(|clock| clock());
    for input in inputs {
        std::hint::black_box(operation(input));
    }
    match started_ns {
        Some(started_ns) => clock.expect("clock is present when a start was recorded")()
            .checked_sub(started_ns)
            .map(Some)
            .ok_or(BenchmarkError::ClockRegression),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::{
        BenchmarkError, Measurement, MeasurementConfig, PureBenchmarkResult, PureSubject,
        PureSubjectResult, SourceRevision, Summary, ToolchainIdentity, benchmark_core_v1,
        measure_prepared_with_clock, measure_with_clock, next_batch_count, summarize,
    };

    #[test]
    fn summary_uses_frozen_integer_statistics() {
        assert_eq!(
            summarize(vec![4, 1, 3, 2]),
            Ok(Summary {
                samples_ns: vec![1, 2, 3, 4],
                count: 4,
                minimum_ns: 1,
                median_ns: 2,
                p95_ns: 4,
                maximum_ns: 4,
            })
        );
    }

    #[test]
    fn odd_median_and_nearest_rank_p95_are_exact() {
        let samples = (1..=100).rev().collect();
        let summary = summarize(samples).expect("nonempty samples summarize");
        assert_eq!(summary.median_ns, 50);
        assert_eq!(summary.p95_ns, 95);
        assert_eq!(summary.samples_ns, (1..=100).collect::<Vec<_>>());
    }

    #[test]
    fn midpoint_does_not_overflow() {
        let summary = summarize(vec![u64::MAX, u64::MAX - 2]).expect("large samples summarize");
        assert_eq!(summary.median_ns, u64::MAX - 1);
    }

    #[test]
    fn empty_series_fails_closed() {
        assert_eq!(summarize(Vec::new()), Err(BenchmarkError::EmptySeries));
    }

    #[test]
    fn calibration_uses_exact_ceiling_ratio() {
        assert_eq!(next_batch_count(3, 2, 11), Ok(Some(18)));
        assert_eq!(next_batch_count(18, 11, 11), Ok(None));
    }

    #[test]
    fn zero_elapsed_calibration_grows_by_ten() {
        assert_eq!(next_batch_count(7, 0, 10), Ok(Some(70)));
    }

    #[test]
    fn invalid_or_overflowing_calibration_fails_closed() {
        assert_eq!(
            next_batch_count(0, 1, 10),
            Err(BenchmarkError::InvalidBatchCount)
        );
        assert_eq!(
            next_batch_count(1, 1, 0),
            Err(BenchmarkError::InvalidTarget)
        );
        assert_eq!(
            next_batch_count(usize::MAX, 0, 1),
            Err(BenchmarkError::BatchOverflow)
        );
    }

    #[test]
    fn measurement_excludes_warmup_and_calibration_from_samples() {
        let config = MeasurementConfig::new(2, 3, 10).expect("config is valid");
        let clock_values = [0, 2, 10, 20, 30, 45, 50, 70, 75, 100];
        let clock_index = Cell::new(0);
        let operation_count = Cell::new(0);
        let measured = measure_with_clock(
            config,
            || operation_count.set(operation_count.get() + 1),
            || {
                let index = clock_index.get();
                clock_index.set(index + 1);
                clock_values[index]
            },
        )
        .expect("fixed clock series measures");

        assert_eq!(
            measured,
            Measurement {
                batch_count: 5,
                summary: Summary {
                    samples_ns: vec![3, 4, 5],
                    count: 3,
                    minimum_ns: 3,
                    median_ns: 4,
                    p95_ns: 5,
                    maximum_ns: 5,
                },
            }
        );
        assert_eq!(operation_count.get(), 23);
        assert_eq!(clock_index.get(), clock_values.len());
    }

    #[test]
    fn measurement_rejects_invalid_configuration_and_clock_regression() {
        assert_eq!(
            MeasurementConfig::new(0, 1, 1),
            Err(BenchmarkError::InvalidWarmupCount)
        );
        assert_eq!(
            MeasurementConfig::new(1, 0, 1),
            Err(BenchmarkError::EmptySeries)
        );
        let config = MeasurementConfig::new(1, 1, 1).expect("config is valid");
        let clock_values = [2, 1];
        let clock_index = Cell::new(0);
        assert_eq!(
            measure_with_clock(
                config,
                || (),
                || {
                    let index = clock_index.get();
                    clock_index.set(index + 1);
                    clock_values[index]
                },
            ),
            Err(BenchmarkError::ClockRegression)
        );
    }

    #[test]
    fn prepared_measurement_excludes_input_construction() {
        let config = MeasurementConfig::new(1, 2, 10).expect("config is valid");
        let clock_values = [0, 10, 20, 23, 30, 35];
        let clock_index = Cell::new(0);
        let prepared_batches = Cell::new(Vec::new());
        let measured = measure_prepared_with_clock(
            config,
            |count| {
                let mut batches = prepared_batches.take();
                batches.push(count);
                prepared_batches.set(batches);
                vec![7_u8; count]
            },
            |value| u16::from(value) + 1,
            || {
                let index = clock_index.get();
                clock_index.set(index + 1);
                clock_values[index]
            },
        )
        .expect("prepared series measures");

        assert_eq!(measured.batch_count, 1);
        assert_eq!(measured.summary.samples_ns, vec![3, 5]);
        assert_eq!(prepared_batches.take(), vec![1, 1, 1, 1]);
    }

    #[test]
    fn prepared_measurement_rejects_incomplete_batch() {
        let config = MeasurementConfig::new(1, 1, 10).expect("config is valid");
        assert_eq!(
            measure_prepared_with_clock(config, |_| Vec::<u8>::new(), |_| (), || 0),
            Err(BenchmarkError::PreparationCountMismatch)
        );
    }

    fn fixed_measurement(marker: u64) -> Measurement {
        Measurement {
            batch_count: 2,
            summary: Summary {
                samples_ns: vec![marker, marker + 1],
                count: 2,
                minimum_ns: marker,
                median_ns: marker,
                p95_ns: marker + 1,
                maximum_ns: marker + 1,
            },
        }
    }

    fn fixed_subject(subject: PureSubject, marker: char) -> PureSubjectResult {
        PureSubjectResult::new(
            subject,
            marker.to_string().repeat(64),
            fixed_measurement(u64::from(u32::from(marker))),
        )
        .expect("fixture subject is valid")
    }

    #[test]
    fn pure_result_closes_and_sorts_the_subject_domain() {
        let revision = "a".repeat(40);
        let source = SourceRevision::new(&revision, &revision, "").expect("source is valid");
        let toolchain =
            ToolchainIdentity::parse("host: x86_64-unknown-linux-gnu\nrelease: 1.93.0\n")
                .expect("toolchain is valid");
        let result = PureBenchmarkResult::new(
            source,
            "b".repeat(64),
            toolchain,
            "release",
            "x86_64".to_owned(),
            MeasurementConfig::new(1, 2, 1).expect("config is valid"),
            vec![
                fixed_subject(PureSubject::PolicyCompilationV1, '3'),
                fixed_subject(PureSubject::PlanParseV1, '1'),
                fixed_subject(PureSubject::ReceiptCanonicalEncodingV1, '5'),
                fixed_subject(PureSubject::AuthorityNormalizationV1, '2'),
                fixed_subject(PureSubject::ReceiptConstructionV1, '4'),
            ],
        )
        .expect("complete result is valid");

        assert_eq!(
            result
                .subjects()
                .iter()
                .map(PureSubjectResult::subject)
                .collect::<Vec<_>>(),
            vec![
                PureSubject::PlanParseV1,
                PureSubject::AuthorityNormalizationV1,
                PureSubject::PolicyCompilationV1,
                PureSubject::ReceiptConstructionV1,
                PureSubject::ReceiptCanonicalEncodingV1,
            ]
        );
        let first = result.to_json().expect("result encodes");
        let second = result.to_json().expect("result re-encodes");
        assert_eq!(first, second);
        let value: serde_json::Value = serde_json::from_slice(&first).expect("result is JSON");
        assert_eq!(value["schema"], "proofbound-runtime-performance-result/1");
        assert_eq!(value["kind"], "pure");
        assert_eq!(value["complete"], true);
        assert_eq!(value["source"]["commit"], "a".repeat(40));
        assert_eq!(value["source"]["tree_state"], "clean");
        assert_eq!(value["toolchain"]["release"], "1.93.0");
        assert_eq!(value["toolchain"]["target"], "x86_64-unknown-linux-gnu");
        assert_eq!(value["build_profile"], "release");
        assert_eq!(value["protocol"]["warmup_count"], 1);
        assert_eq!(value["protocol"]["sample_count"], 2);
        assert_eq!(value["protocol"]["target_sample_ns"], 1);
        assert_eq!(value["subjects"][0]["subject"], "plan-parse-v1");
    }

    #[test]
    fn pure_result_rejects_missing_duplicate_and_invalid_identities() {
        let subject = fixed_subject(PureSubject::PlanParseV1, '1');
        let revision = "a".repeat(40);
        let source = SourceRevision::new(&revision, &revision, "").expect("source is valid");
        let toolchain =
            ToolchainIdentity::parse("host: x86_64-unknown-linux-gnu\nrelease: 1.93.0\n")
                .expect("toolchain is valid");
        let make = |source: SourceRevision,
                    executable: String,
                    profile: &'static str,
                    config: MeasurementConfig,
                    subjects: Vec<PureSubjectResult>| {
            PureBenchmarkResult::new(
                source,
                executable,
                toolchain.clone(),
                profile,
                "x86_64".to_owned(),
                config,
                subjects,
            )
        };
        let mismatched_source =
            SourceRevision::new(&"c".repeat(40), &"c".repeat(40), "").expect("source is valid");
        assert_eq!(
            make(
                mismatched_source,
                "B".repeat(64),
                "release",
                MeasurementConfig::new(1, 2, 1).expect("config is valid"),
                Vec::new(),
            ),
            Err(BenchmarkError::InvalidDigest)
        );
        assert_eq!(
            make(
                source.clone(),
                "b".repeat(64),
                "debug",
                MeasurementConfig::new(1, 2, 1).expect("config is valid"),
                Vec::new(),
            ),
            Err(BenchmarkError::InvalidBuildProfile)
        );
        assert_eq!(
            make(
                source.clone(),
                "b".repeat(64),
                "release",
                MeasurementConfig::new(1, 2, 1).expect("config is valid"),
                vec![subject.clone()],
            ),
            Err(BenchmarkError::SubjectDomainMismatch)
        );
        assert_eq!(
            make(
                source,
                "b".repeat(64),
                "release",
                MeasurementConfig::new(1, 2, 1).expect("config is valid"),
                vec![subject.clone(), subject],
            ),
            Err(BenchmarkError::SubjectDomainMismatch)
        );
        let complete_subjects = vec![
            fixed_subject(PureSubject::PlanParseV1, '1'),
            fixed_subject(PureSubject::AuthorityNormalizationV1, '2'),
            fixed_subject(PureSubject::PolicyCompilationV1, '3'),
            fixed_subject(PureSubject::ReceiptConstructionV1, '4'),
            fixed_subject(PureSubject::ReceiptCanonicalEncodingV1, '5'),
        ];
        assert_eq!(
            make(
                SourceRevision::new(&revision, &revision, "").expect("source is valid"),
                "b".repeat(64),
                "release",
                MeasurementConfig::new(1, 3, 1).expect("config is valid"),
                complete_subjects,
            ),
            Err(BenchmarkError::ConfigurationMismatch)
        );
    }

    #[test]
    fn core_benchmark_uses_the_exact_closed_version_one_subjects() {
        let config = MeasurementConfig::new(1, 2, 1).expect("config is valid");
        let subjects = benchmark_core_v1(config).expect("core subjects measure");

        assert_eq!(
            subjects
                .iter()
                .map(|subject| {
                    serde_json::to_value(subject.subject())
                        .expect("subject serializes")
                        .as_str()
                        .expect("subject serializes as text")
                        .to_owned()
                })
                .collect::<Vec<_>>(),
            vec![
                "plan-parse-v1",
                "authority-normalization-v1",
                "policy-compilation-v1",
                "receipt-construction-v1",
                "receipt-canonical-encoding-v1",
            ]
        );
        assert!(subjects[..3].iter().all(|subject| {
            subject.fixture_sha256()
                == "80194be084f9749fe47bc5feb1ac737d8e793b67230b0590abc2d2948881aa4a"
        }));
        assert_eq!(subjects[3].fixture_sha256(), subjects[4].fixture_sha256());
        assert_eq!(
            subjects[3].fixture_sha256(),
            "783e5cb442aa12eadccdccc2082ea3a389f55732092a5597c904fb4faba936de"
        );
        assert_ne!(subjects[3].fixture_sha256(), subjects[0].fixture_sha256());
        assert!(subjects.iter().all(|subject| {
            subject.measurement().summary.count == 2 && subject.measurement().batch_count >= 1
        }));
    }

    #[test]
    fn receipt_fixture_matches_the_checked_in_typed_constants() {
        let receipt = super::construct_execution_receipt(
            super::receipt_parts_v1().expect("receipt parts are valid"),
        )
        .expect("receipt constructs");
        let bytes = receipt.canonical_bytes().expect("receipt encodes");
        let fixture =
            include_bytes!("../../../experiments/performance/fixtures/reusable-receipt-v1.json");
        assert_eq!(fixture.strip_suffix(b"\n"), Some(bytes.as_slice()));
    }

    #[test]
    fn source_revision_requires_exact_clean_head() {
        let revision = "a".repeat(40);
        let source =
            SourceRevision::new(&revision, &revision, "").expect("exact clean head is valid");
        assert_eq!(source.commit(), revision);
        assert_eq!(source.tree_state(), "clean");
        assert_eq!(
            SourceRevision::new(&revision, &"b".repeat(40), ""),
            Err(BenchmarkError::SourceMismatch)
        );
        assert_eq!(
            SourceRevision::new(&revision, &revision, " M src/lib.rs\n"),
            Err(BenchmarkError::DirtyTree)
        );
    }

    #[test]
    fn toolchain_identity_parses_closed_rustc_verbose_output() {
        let identity = ToolchainIdentity::parse(
            "rustc 1.93.0 (fixture 2026-01-01)\n\
             binary: rustc\n\
             commit-hash: fixture\n\
             commit-date: 2026-01-01\n\
             host: x86_64-unknown-linux-gnu\n\
             release: 1.93.0\n\
             LLVM version: 20.1.0\n",
        )
        .expect("complete rustc identity parses");
        assert_eq!(identity.release(), "1.93.0");
        assert_eq!(identity.target(), "x86_64-unknown-linux-gnu");
        assert_eq!(
            ToolchainIdentity::parse("rustc 1.93.0\n"),
            Err(BenchmarkError::InvalidToolchain)
        );
        assert_eq!(
            ToolchainIdentity::parse("host: a\nhost: b\nrelease: 1\n"),
            Err(BenchmarkError::InvalidToolchain)
        );
    }
}
