#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as FmtWrite;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Output};

use proofbound_runtime_accept::{
    AcceptanceDecision, DecisionInput, DecodedPolicy, EvaluationInputs, RejectionReason,
    decode_policy, evaluate, project_decision, reject_unverified,
};
use proofbound_runtime_compose::{
    ArtifactBytes, CompositionError, CompositionInputs, compose, decode_release_acceptance_facts,
};
use proofbound_runtime_verify::{ReceiptCommitment, decode_receipt, verify_receipt};
use serde_json::json;
use sha2::{Digest, Sha256};

const SUCCESS: u8 = 0;
const INVALID_INPUT: u8 = 2;
const REJECTED: u8 = 7;
const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RELEASE_MEMBER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_VERIFIER_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RELEASE_FILES: usize = 4_096;
const RELEASE_DIRECTORY_DOMAIN: &[u8] = b"proofbound-release-directory/1\0";
const HELP: &str = "usage: pbr-accept --policy <policy.cbor> --expected-policy-identity sha256:<digest> --release <directory> --proofbound-verifier <path> --proofbound-observation-inputs <path> --runtime-bundle <directory> --execution-receipt <path> --execution-commitment sha256:<digest> --expected-execution-id <uuid> --output <absent-path>\n       pbr-accept inspect <acceptance-decision.cbor>";

fn main() -> ExitCode {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    ExitCode::from(run(env::args_os().collect(), &mut stdout, &mut stderr))
}

#[derive(Debug)]
struct CliError {
    code: &'static str,
}

impl CliError {
    const fn new(code: &'static str) -> Self {
        Self { code }
    }
}

struct Args {
    policy: PathBuf,
    expected_policy_identity: String,
    release: PathBuf,
    proofbound_verifier: PathBuf,
    proofbound_observation_inputs: PathBuf,
    runtime_bundle: PathBuf,
    execution_receipt: PathBuf,
    execution_commitment: String,
    expected_execution_id: String,
    output: PathBuf,
}

enum Outcome {
    Text(String),
    Decision { summary: String, accepted: bool },
}

fn run(args: Vec<OsString>, stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    match run_inner(args) {
        Ok(Outcome::Text(text)) => write_success(stdout, &text),
        Ok(Outcome::Decision { summary, accepted }) => {
            if writeln!(stdout, "{summary}").is_err() {
                INVALID_INPUT
            } else if accepted {
                SUCCESS
            } else {
                REJECTED
            }
        }
        Err(error) => {
            let _ignored = writeln!(stderr, "pbr-accept: {}", error.code);
            INVALID_INPUT
        }
    }
}

fn run_inner(args: Vec<OsString>) -> Result<Outcome, CliError> {
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h")) {
        return Ok(Outcome::Text(HELP.to_owned()));
    }
    if args.len() == 2 && args[1] == "--version" {
        return Ok(Outcome::Text(format!(
            "pbr-accept {}",
            env!("CARGO_PKG_VERSION")
        )));
    }
    if args.len() == 3 && args[1] == "inspect" {
        let bytes = read_regular(Path::new(&args[2]))?;
        let projection =
            project_decision(&bytes).map_err(|_| CliError::new("acceptance.decision.invalid"))?;
        return serde_json::to_string(&projection)
            .map(Outcome::Text)
            .map_err(|_| CliError::new("acceptance.output.write-failed"));
    }

    let args = parse_args(&args)?;
    require_directory(&args.release)?;
    require_directory(&args.runtime_bundle)?;
    require_bundle_inventory(&args.runtime_bundle)?;
    require_absent(&args.output)?;

    let policy_bytes = read_regular(&args.policy)?;
    let policy = decode_policy(&policy_bytes, &args.expected_policy_identity)
        .map_err(|error| map_accept_error(error.code()))?;
    let release_envelope = read_regular(&args.release.join("release.json"))?;
    let compiled_release = read_regular(&args.release.join("compiled-receipt.json"))?;
    let release_tcb = read_regular(&args.release.join("tcb-ledger.json"))?;
    let proofbound_verifier = read_executable(&args.proofbound_verifier)?;
    let proofbound_verifier_sha256 = sha256_text(&proofbound_verifier);
    let proofbound_release_sha256 = release_directory_digest(&args.release)?;
    let proofbound_observation_inputs = read_regular(&args.proofbound_observation_inputs)?;
    let runtime_manifest = read_regular(&args.runtime_bundle.join("RELEASE-MANIFEST.json"))?;
    let runtime = read_executable(&args.runtime_bundle.join("pbr"))?;
    let launcher = read_executable(&args.runtime_bundle.join("pbr-native-launcher"))?;
    let execution_verifier_path = args.runtime_bundle.join("pbr-verify");
    let execution_verifier = read_executable(&execution_verifier_path)?;
    let composer = read_executable(&args.runtime_bundle.join("pbr-compose"))?;
    let acceptor_path =
        env::current_exe().map_err(|_| CliError::new("acceptance.input.read-failed"))?;
    let acceptor = read_executable(&acceptor_path)?;
    let execution_receipt = read_regular(&args.execution_receipt)?;

    let release_verification = run_verifier(
        &args.proofbound_verifier,
        &[
            OsStr::new("--release"),
            args.release.as_os_str(),
            OsStr::new("--observation-inputs"),
            args.proofbound_observation_inputs.as_os_str(),
            OsStr::new("--json"),
        ],
    )?;
    let execution_verification = run_verifier(
        &execution_verifier_path,
        &[
            OsStr::new("--expected-commitment"),
            OsStr::new(&args.execution_commitment),
            args.execution_receipt.as_os_str(),
        ],
    )?;

    let raw = RawInputs {
        policy: &policy_bytes,
        release_envelope: &release_envelope,
        compiled_release: &compiled_release,
        release_verification: &release_verification.stdout,
        release_verifier: &proofbound_verifier,
        release_observation_inputs: &proofbound_observation_inputs,
        release_tcb_ledger: &release_tcb,
        runtime_manifest: &runtime_manifest,
        runtime: &runtime,
        launcher: &launcher,
        execution_verifier: &execution_verifier,
        composer: &composer,
        acceptor: &acceptor,
        execution_receipt: &execution_receipt,
        execution_verification: &execution_verification.stdout,
    };

    let decision = if !release_verification.valid {
        reject(
            &policy,
            &raw,
            &args,
            RejectionReason::ReleaseVerificationFailed,
        )?
    } else if !execution_verification.valid {
        reject(
            &policy,
            &raw,
            &args,
            RejectionReason::ExecutionVerificationFailed,
        )?
    } else {
        let composition_inputs = composition_inputs(&raw, &args);
        match compose(&composition_inputs) {
            Ok(composed) => match verified_decision(
                &policy,
                &raw,
                &args,
                &composed,
                &proofbound_release_sha256,
                &proofbound_verifier_sha256,
            ) {
                Ok(decision) => decision,
                Err(()) => reject(
                    &policy,
                    &raw,
                    &args,
                    RejectionReason::InputVerificationFailed,
                )?,
            },
            Err(error) => reject(&policy, &raw, &args, composition_rejection(error))?,
        }
    };

    publish_no_replace(&args.output, decision.bytes())?;
    let summary = json!({
        "decision_id": decision.identity(),
        "output": args.output,
        "reasons": decision.reasons().iter().map(|reason| reason.as_str()).collect::<Vec<_>>(),
        "schema": "proofbound-runtime-accept-result/1",
        "status": if decision.accepted() { "accepted" } else { "rejected" },
    })
    .to_string();
    Ok(Outcome::Decision {
        summary,
        accepted: decision.accepted(),
    })
}

struct RawInputs<'a> {
    policy: &'a [u8],
    release_envelope: &'a [u8],
    compiled_release: &'a [u8],
    release_verification: &'a [u8],
    release_verifier: &'a [u8],
    release_observation_inputs: &'a [u8],
    release_tcb_ledger: &'a [u8],
    runtime_manifest: &'a [u8],
    runtime: &'a [u8],
    launcher: &'a [u8],
    execution_verifier: &'a [u8],
    composer: &'a [u8],
    acceptor: &'a [u8],
    execution_receipt: &'a [u8],
    execution_verification: &'a [u8],
}

impl RawInputs<'_> {
    fn decision_inputs(&self) -> Vec<DecisionInput> {
        vec![
            DecisionInput::new("acceptance-policy", self.policy),
            DecisionInput::new("release-envelope", self.release_envelope),
            DecisionInput::new("compiled-release", self.compiled_release),
            DecisionInput::new("release-verification", self.release_verification),
            DecisionInput::new("release-verifier", self.release_verifier),
            DecisionInput::new(
                "release-observation-inputs",
                self.release_observation_inputs,
            ),
            DecisionInput::new("release-tcb-ledger", self.release_tcb_ledger),
            DecisionInput::new("runtime-manifest", self.runtime_manifest),
            DecisionInput::new("runtime", self.runtime),
            DecisionInput::new("launcher", self.launcher),
            DecisionInput::new("execution-verifier", self.execution_verifier),
            DecisionInput::new("composer", self.composer),
            DecisionInput::new("acceptor", self.acceptor),
            DecisionInput::new("execution-receipt", self.execution_receipt),
            DecisionInput::new("execution-verification", self.execution_verification),
        ]
    }
}

fn composition_inputs<'a>(raw: &'a RawInputs<'a>, args: &'a Args) -> CompositionInputs<'a> {
    CompositionInputs {
        release_envelope: named("release.json", raw.release_envelope),
        compiled_release: named("compiled-receipt.json", raw.compiled_release),
        release_verification: named("proofbound-verification.json", raw.release_verification),
        release_verifier: named("proofbound-verify", raw.release_verifier),
        release_observation_inputs: named(
            "proofbound-observation-inputs.json",
            raw.release_observation_inputs,
        ),
        release_tcb_ledger: named("tcb-ledger.json", raw.release_tcb_ledger),
        runtime_manifest: named("RELEASE-MANIFEST.json", raw.runtime_manifest),
        runtime: named("pbr", raw.runtime),
        launcher: named("pbr-native-launcher", raw.launcher),
        execution_verifier: named("pbr-verify", raw.execution_verifier),
        composer: named("pbr-compose", raw.composer),
        execution_receipt: named("execution-receipt.cbor", raw.execution_receipt),
        execution_verification: named("execution-verification.json", raw.execution_verification),
        expected_execution_commitment: &args.execution_commitment,
        expected_execution_id: &args.expected_execution_id,
    }
}

fn verified_decision(
    policy: &DecodedPolicy,
    raw: &RawInputs<'_>,
    args: &Args,
    composed: &[u8],
    proofbound_release_sha256: &str,
    proofbound_verifier_sha256: &str,
) -> Result<AcceptanceDecision, ()> {
    let commitment = ReceiptCommitment::parse(&args.execution_commitment).map_err(|_| ())?;
    verify_receipt(raw.execution_receipt, commitment).map_err(|_| ())?;
    let execution = decode_receipt(raw.execution_receipt)
        .map_err(|_| ())?
        .acceptance_facts()
        .ok_or(())?;
    let release = decode_release_acceptance_facts(composed).map_err(|_| ())?;
    evaluate(
        policy,
        EvaluationInputs {
            execution: &execution,
            release: &release,
            expected_execution_commitment: &args.execution_commitment,
            expected_execution_id: &args.expected_execution_id,
            composition_id: &release.composition_id,
            proofbound_release_sha256,
            proofbound_verifier_sha256,
            artifacts: raw.decision_inputs(),
        },
    )
    .map_err(|_| ())
}

fn reject(
    policy: &DecodedPolicy,
    raw: &RawInputs<'_>,
    args: &Args,
    reason: RejectionReason,
) -> Result<AcceptanceDecision, CliError> {
    reject_unverified(
        policy,
        &args.execution_commitment,
        &args.expected_execution_id,
        raw.decision_inputs(),
        reason,
    )
    .map_err(|error| map_accept_error(error.code()))
}

fn composition_rejection(error: CompositionError) -> RejectionReason {
    match error {
        CompositionError::ExecutionReplayed => RejectionReason::ExecutionReplay,
        CompositionError::AssumptionOmitted => RejectionReason::InputVerificationFailed,
        _ => RejectionReason::CompositionMissing,
    }
}

fn parse_args(args: &[OsString]) -> Result<Args, CliError> {
    if args.len() != 21
        || args[1] != "--policy"
        || args[3] != "--expected-policy-identity"
        || args[5] != "--release"
        || args[7] != "--proofbound-verifier"
        || args[9] != "--proofbound-observation-inputs"
        || args[11] != "--runtime-bundle"
        || args[13] != "--execution-receipt"
        || args[15] != "--execution-commitment"
        || args[17] != "--expected-execution-id"
        || args[19] != "--output"
    {
        return Err(CliError::new("cli.usage.invalid"));
    }
    let text = |index: usize| {
        args[index]
            .to_str()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| CliError::new("cli.usage.invalid"))
    };
    Ok(Args {
        policy: PathBuf::from(&args[2]),
        expected_policy_identity: text(4)?,
        release: PathBuf::from(&args[6]),
        proofbound_verifier: PathBuf::from(&args[8]),
        proofbound_observation_inputs: PathBuf::from(&args[10]),
        runtime_bundle: PathBuf::from(&args[12]),
        execution_receipt: PathBuf::from(&args[14]),
        execution_commitment: text(16)?,
        expected_execution_id: text(18)?,
        output: PathBuf::from(&args[20]),
    })
}

struct VerifierRun {
    stdout: Vec<u8>,
    valid: bool,
}

fn run_verifier(path: &Path, args: &[&OsStr]) -> Result<VerifierRun, CliError> {
    let output = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .map_err(|_| CliError::new("acceptance.verifier.start-failed"))?;
    validate_process_output(output)
}

fn validate_process_output(output: Output) -> Result<VerifierRun, CliError> {
    if output.stdout.len() > MAX_VERIFIER_OUTPUT_BYTES
        || output.stderr.len() > MAX_VERIFIER_OUTPUT_BYTES
    {
        return Err(CliError::new("acceptance.verifier.output-too-large"));
    }
    let valid = output.status.success()
        && output.stderr.is_empty()
        && !output.stdout.is_empty()
        && std::str::from_utf8(&output.stdout).is_ok();
    Ok(VerifierRun {
        stdout: output.stdout,
        valid,
    })
}

fn require_directory(path: &Path) -> Result<(), CliError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| CliError::new("acceptance.input.read-failed"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::new("acceptance.input.type-invalid"));
    }
    Ok(())
}

fn require_bundle_inventory(path: &Path) -> Result<(), CliError> {
    let actual = fs::read_dir(path)
        .map_err(|_| CliError::new("acceptance.input.read-failed"))?
        .map(|entry| {
            entry
                .map_err(|_| CliError::new("acceptance.input.read-failed"))
                .and_then(|entry| {
                    entry
                        .file_name()
                        .into_string()
                        .map_err(|_| CliError::new("acceptance.bundle.role-mismatch"))
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = [
        "RELEASE-MANIFEST.json",
        "pbr",
        "pbr-compose",
        "pbr-native-launcher",
        "pbr-verify",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if actual != expected {
        return Err(CliError::new("acceptance.bundle.role-mismatch"));
    }
    Ok(())
}

fn read_regular(path: &Path) -> Result<Vec<u8>, CliError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| CliError::new("acceptance.input.read-failed"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_INPUT_BYTES
    {
        return Err(CliError::new("acceptance.input.type-invalid"));
    }
    fs::read(path).map_err(|_| CliError::new("acceptance.input.read-failed"))
}

fn read_executable(path: &Path) -> Result<Vec<u8>, CliError> {
    let bytes = read_regular(path)?;
    let metadata = fs::metadata(path).map_err(|_| CliError::new("acceptance.input.read-failed"))?;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(CliError::new("acceptance.input.not-executable"));
    }
    Ok(bytes)
}

fn sha256_text(bytes: &[u8]) -> String {
    digest_text(&Sha256::digest(bytes))
}

fn digest_text(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(71);
    text.push_str("sha256:");
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("writing to a String cannot fail");
    }
    text
}

fn release_directory_digest(root: &Path) -> Result<String, CliError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in
            fs::read_dir(&directory).map_err(|_| CliError::new("acceptance.input.read-failed"))?
        {
            let entry = entry.map_err(|_| CliError::new("acceptance.input.read-failed"))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| CliError::new("acceptance.input.read-failed"))?;
            if metadata.file_type().is_symlink() {
                return Err(CliError::new("acceptance.input.type-invalid"));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() && metadata.len() <= MAX_RELEASE_MEMBER_BYTES {
                let relative = path
                    .strip_prefix(root)
                    .ok()
                    .and_then(Path::to_str)
                    .ok_or_else(|| CliError::new("acceptance.input.type-invalid"))?
                    .to_owned();
                files.push((
                    relative,
                    fs::read(path).map_err(|_| CliError::new("acceptance.input.read-failed"))?,
                ));
                if files.len() > MAX_RELEASE_FILES {
                    return Err(CliError::new("acceptance.input.type-invalid"));
                }
            } else {
                return Err(CliError::new("acceptance.input.type-invalid"));
            }
        }
    }
    files.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let mut digest = Sha256::new();
    digest.update(RELEASE_DIRECTORY_DOMAIN);
    for (path, bytes) in files {
        digest.update(
            u64::try_from(path.len())
                .map_err(|_| CliError::new("acceptance.input.type-invalid"))?
                .to_be_bytes(),
        );
        digest.update(path.as_bytes());
        digest.update(
            u64::try_from(bytes.len())
                .map_err(|_| CliError::new("acceptance.input.type-invalid"))?
                .to_be_bytes(),
        );
        digest.update(Sha256::digest(bytes));
    }
    Ok(digest_text(&digest.finalize()))
}

fn require_absent(path: &Path) -> Result<(), CliError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(CliError::new("acceptance.output.exists")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CliError::new("acceptance.output.write-failed")),
    }
}

fn publish_no_replace(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    require_absent(path)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| CliError::new("acceptance.output.write-failed"))?;
    let mut temporary = None;
    for attempt in 0..100_u8 {
        let candidate = parent.join(format!(
            ".{name}.pbr-accept.{}.{attempt}",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(CliError::new("acceptance.output.write-failed")),
        }
    }
    let (temporary_path, mut file) =
        temporary.ok_or_else(|| CliError::new("acceptance.output.write-failed"))?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|_| CliError::new("acceptance.output.write-failed"))?;
        file.sync_all()
            .map_err(|_| CliError::new("acceptance.output.write-failed"))?;
        drop(file);
        fs::hard_link(&temporary_path, path).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CliError::new("acceptance.output.exists")
            } else {
                CliError::new("acceptance.output.write-failed")
            }
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| CliError::new("acceptance.output.write-failed"))?;
        Ok(())
    })();
    let _ignored = fs::remove_file(&temporary_path);
    result
}

fn named<'a>(name: &'a str, bytes: &'a [u8]) -> ArtifactBytes<'a> {
    ArtifactBytes { name, bytes }
}

fn map_accept_error(code: &str) -> CliError {
    match code {
        "acceptance.policy.malformed-cbor" => CliError::new("acceptance.policy.malformed-cbor"),
        "acceptance.policy.invalid" => CliError::new("acceptance.policy.invalid"),
        "acceptance.identity.invalid" => CliError::new("acceptance.identity.invalid"),
        _ => CliError::new("acceptance.decision.invalid"),
    }
}

fn write_success(output: &mut impl Write, text: &str) -> u8 {
    if writeln!(output, "{text}").is_ok() {
        SUCCESS
    } else {
        INVALID_INPUT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn closed_usage_help_and_version_are_stable() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run(arguments(&["pbr-accept"]), &mut stdout, &mut stderr),
            INVALID_INPUT
        );
        assert_eq!(stderr, b"pbr-accept: cli.usage.invalid\n");
        for option in ["--help", "--version"] {
            stdout.clear();
            stderr.clear();
            assert_eq!(
                run(arguments(&["pbr-accept", option]), &mut stdout, &mut stderr),
                SUCCESS
            );
            assert!(!stdout.is_empty());
            assert!(stderr.is_empty());
        }
    }

    #[test]
    fn inspect_projects_the_canonical_golden_decision() {
        let path =
            std::env::temp_dir().join(format!("pbr-accept-golden-{}.cbor", std::process::id()));
        let bytes = bytes_from_hex(include_str!(
            "../../../schemas/vectors/v2/acceptance-decision.cbor.hex"
        ));
        fs::write(&path, bytes).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run(
                vec![
                    OsString::from("pbr-accept"),
                    OsString::from("inspect"),
                    path.clone().into_os_string(),
                ],
                &mut stdout,
                &mut stderr,
            ),
            SUCCESS
        );
        let _ignored = fs::remove_file(path);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&stdout).unwrap()["status"],
            "accepted"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn composition_failures_derive_distinct_rejection_reasons() {
        assert_eq!(
            composition_rejection(CompositionError::ExecutionReplayed),
            RejectionReason::ExecutionReplay
        );
        assert_eq!(
            composition_rejection(CompositionError::AssumptionOmitted),
            RejectionReason::InputVerificationFailed
        );
        assert_eq!(
            composition_rejection(CompositionError::ReleaseSubstituted),
            RejectionReason::CompositionMissing
        );
    }

    #[test]
    fn release_directory_identity_binds_relative_paths_and_contents() {
        let root = std::env::temp_dir().join(format!(
            "pbr-accept-release-identity-{}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("release.json"), b"release").unwrap();
        let first = release_directory_digest(&root).unwrap();
        assert_eq!(
            first,
            "sha256:5819a8862375bd1e15d67503a8a79c2cf9c97c6bdf509fc2953f9a35af3c0562"
        );
        fs::write(root.join("release.json"), b"substituted").unwrap();
        assert_ne!(first, release_directory_digest(&root).unwrap());
        fs::create_dir(root.join("nested")).unwrap();
        fs::write(root.join("nested/release.json"), b"release").unwrap();
        assert_ne!(first, release_directory_digest(&root).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    fn bytes_from_hex(text: &str) -> Vec<u8> {
        text.trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("bad hex"),
        }
    }
}
