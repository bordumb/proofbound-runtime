#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Output};

use proofbound_runtime_compose::{ArtifactBytes, CompositionInputs, compose};
use serde_json::json;

const SUCCESS: u8 = 0;
const INVALID_INPUT: u8 = 2;
const VERIFICATION_FAILED: u8 = 7;
const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_VERIFIER_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const HELP: &str = "usage: pbr-compose --release <directory> --proofbound-verifier <path> --proofbound-observation-inputs <path> --runtime-bundle <directory> --execution-receipt <path> --execution-commitment sha256:<digest> --expected-execution-id <uuid> --output <absent-path>";

fn main() -> ExitCode {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    ExitCode::from(run(env::args_os().collect(), &mut stdout, &mut stderr))
}

#[derive(Debug)]
struct CliError {
    exit_code: u8,
    code: String,
}

impl CliError {
    fn invalid(code: &str) -> Self {
        Self {
            exit_code: INVALID_INPUT,
            code: code.to_owned(),
        }
    }

    fn verification(code: &str) -> Self {
        Self {
            exit_code: VERIFICATION_FAILED,
            code: code.to_owned(),
        }
    }
}

struct Args {
    release: PathBuf,
    proofbound_verifier: PathBuf,
    proofbound_observation_inputs: PathBuf,
    runtime_bundle: PathBuf,
    execution_receipt: PathBuf,
    execution_commitment: String,
    expected_execution_id: String,
    output: PathBuf,
}

fn run(args: Vec<OsString>, stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    match run_inner(args) {
        Ok(Some(summary)) => write_success(stdout, &summary),
        Ok(None) => write_success(stdout, HELP),
        Err(error) => fail(stderr, error),
    }
}

fn run_inner(args: Vec<OsString>) -> Result<Option<String>, CliError> {
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h")) {
        return Ok(None);
    }
    if args.len() == 2 && args[1] == "--version" {
        return Ok(Some(format!("pbr-compose {}", env!("CARGO_PKG_VERSION"))));
    }
    let args = parse_args(&args)?;
    require_directory(&args.release)?;
    require_directory(&args.runtime_bundle)?;
    require_bundle_inventory(&args.runtime_bundle)?;
    require_absent(&args.output)?;

    let release_envelope = read_regular(&args.release.join("release.json"))?;
    let compiled_release = read_regular(&args.release.join("compiled-receipt.json"))?;
    let release_tcb = read_regular(&args.release.join("tcb-ledger.json"))?;
    let proofbound_verifier = read_executable(&args.proofbound_verifier)?;
    let proofbound_observation_inputs = read_regular(&args.proofbound_observation_inputs)?;
    let proofbound_verification = run_proofbound_verifier(
        &args.proofbound_verifier,
        &args.release,
        &args.proofbound_observation_inputs,
    )?;

    let runtime_manifest = read_regular(&args.runtime_bundle.join("RELEASE-MANIFEST.json"))?;
    let runtime = read_executable(&args.runtime_bundle.join("pbr"))?;
    let launcher = read_executable(&args.runtime_bundle.join("pbr-native-launcher"))?;
    let execution_verifier_path = args.runtime_bundle.join("pbr-verify");
    let execution_verifier = read_executable(&execution_verifier_path)?;
    let composer = read_executable(&args.runtime_bundle.join("pbr-compose"))?;
    let running_composer =
        env::current_exe().map_err(|_| CliError::invalid("composition.input.read-failed"))?;
    if read_executable(&running_composer)? != composer {
        return Err(CliError::verification("composition.bundle.substituted"));
    }
    let execution_receipt = read_regular(&args.execution_receipt)?;
    let execution_verification = run_execution_verifier(
        &execution_verifier_path,
        &args.execution_commitment,
        &args.execution_receipt,
    )?;

    let inputs = CompositionInputs {
        release_envelope: named("release.json", &release_envelope),
        compiled_release: named("compiled-receipt.json", &compiled_release),
        release_verification: named("proofbound-verification.json", &proofbound_verification),
        release_verifier: named("proofbound-verify", &proofbound_verifier),
        release_observation_inputs: named(
            "proofbound-observation-inputs.json",
            &proofbound_observation_inputs,
        ),
        release_tcb_ledger: named("tcb-ledger.json", &release_tcb),
        runtime_manifest: named("RELEASE-MANIFEST.json", &runtime_manifest),
        runtime: named("pbr", &runtime),
        launcher: named("pbr-native-launcher", &launcher),
        execution_verifier: named("pbr-verify", &execution_verifier),
        composer: named("pbr-compose", &composer),
        execution_receipt: named("execution-receipt.json", &execution_receipt),
        execution_verification: named("execution-verification.json", &execution_verification),
        expected_execution_commitment: &args.execution_commitment,
        expected_execution_id: &args.expected_execution_id,
    };
    let composed = compose(&inputs).map_err(|error| CliError::verification(error.code()))?;
    publish_no_replace(&args.output, &composed)?;
    let value: serde_json::Value = serde_json::from_slice(&composed)
        .map_err(|_| CliError::verification("composition.schema.invalid"))?;
    let composition_id = value
        .get("composition_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CliError::verification("composition.schema.invalid"))?;
    let summary = serde_json::to_string(&json!({
        "composition_id": composition_id,
        "output": args.output,
        "schema": "proofbound-runtime-compose-result/1"
    }))
    .map_err(|_| CliError::invalid("composition.output.write-failed"))?;
    Ok(Some(summary))
}

fn parse_args(args: &[OsString]) -> Result<Args, CliError> {
    if args.len() != 17
        || args[1] != "--release"
        || args[3] != "--proofbound-verifier"
        || args[5] != "--proofbound-observation-inputs"
        || args[7] != "--runtime-bundle"
        || args[9] != "--execution-receipt"
        || args[11] != "--execution-commitment"
        || args[13] != "--expected-execution-id"
        || args[15] != "--output"
    {
        return Err(CliError::invalid("cli.usage.invalid"));
    }
    let text = |index: usize| {
        args[index]
            .to_str()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| CliError::invalid("cli.usage.invalid"))
    };
    Ok(Args {
        release: PathBuf::from(&args[2]),
        proofbound_verifier: PathBuf::from(&args[4]),
        proofbound_observation_inputs: PathBuf::from(&args[6]),
        runtime_bundle: PathBuf::from(&args[8]),
        execution_receipt: PathBuf::from(&args[10]),
        execution_commitment: text(12)?,
        expected_execution_id: text(14)?,
        output: PathBuf::from(&args[16]),
    })
}

fn require_directory(path: &Path) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| CliError::invalid("composition.input.read-failed"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::invalid("composition.input.type-invalid"));
    }
    Ok(())
}

fn require_bundle_inventory(path: &Path) -> Result<(), CliError> {
    let mut actual = BTreeSet::new();
    let entries =
        fs::read_dir(path).map_err(|_| CliError::invalid("composition.input.read-failed"))?;
    for entry in entries {
        let entry = entry.map_err(|_| CliError::invalid("composition.input.read-failed"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CliError::invalid("composition.bundle.role-mismatch"))?;
        actual.insert(name);
    }
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
        return Err(CliError::verification("composition.bundle.role-mismatch"));
    }
    Ok(())
}

fn require_absent(path: &Path) -> Result<(), CliError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(CliError::invalid("composition.output.exists")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CliError::invalid("composition.output.write-failed")),
    }
}

fn read_regular(path: &Path) -> Result<Vec<u8>, CliError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| CliError::invalid("composition.input.read-failed"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_INPUT_BYTES
    {
        return Err(CliError::invalid("composition.input.type-invalid"));
    }
    fs::read(path).map_err(|_| CliError::invalid("composition.input.read-failed"))
}

fn read_executable(path: &Path) -> Result<Vec<u8>, CliError> {
    let bytes = read_regular(path)?;
    let metadata =
        fs::metadata(path).map_err(|_| CliError::invalid("composition.input.read-failed"))?;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(CliError::invalid("composition.input.not-executable"));
    }
    Ok(bytes)
}

fn run_proofbound_verifier(
    path: &Path,
    release: &Path,
    observation_inputs: &Path,
) -> Result<Vec<u8>, CliError> {
    let output = Command::new(path)
        .arg("--release")
        .arg(release)
        .arg("--observation-inputs")
        .arg(observation_inputs)
        .arg("--json")
        .env_clear()
        .output()
        .map_err(|_| CliError::verification("composition.release.verification-failed"))?;
    validate_process_output(output, "composition.release.verification-failed", false)
}

fn run_execution_verifier(
    path: &Path,
    commitment: &str,
    receipt: &Path,
) -> Result<Vec<u8>, CliError> {
    let output = Command::new(path)
        .arg("--expected-commitment")
        .arg(commitment)
        .arg(receipt)
        .env_clear()
        .output()
        .map_err(|_| CliError::verification("composition.execution.verification-failed"))?;
    validate_process_output(output, "composition.execution.verification-failed", true)
}

fn validate_process_output(
    output: Output,
    fallback: &str,
    propagate_pbr_error: bool,
) -> Result<Vec<u8>, CliError> {
    if output.stdout.len() > MAX_VERIFIER_OUTPUT_BYTES
        || output.stderr.len() > MAX_VERIFIER_OUTPUT_BYTES
    {
        return Err(CliError::verification(fallback));
    }
    if !output.status.success() {
        if propagate_pbr_error && let Some(code) = exact_pbr_error(&output.stderr) {
            return Err(CliError::verification(code));
        }
        return Err(CliError::verification(fallback));
    }
    if !output.stderr.is_empty()
        || output.stdout.is_empty()
        || std::str::from_utf8(&output.stdout).is_err()
    {
        return Err(CliError::verification(fallback));
    }
    Ok(output.stdout)
}

fn exact_pbr_error(stderr: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(stderr).ok()?;
    let code = text.strip_prefix("pbr-verify: ")?.strip_suffix('\n')?;
    if code.is_empty()
        || code.bytes().any(|byte| {
            !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-')
        })
    {
        return None;
    }
    Some(code)
}

fn publish_no_replace(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    require_absent(path)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| CliError::invalid("composition.output.write-failed"))?;
    let mut temporary = None;
    for attempt in 0..100_u8 {
        let candidate = parent.join(format!(
            ".{file_name}.pbr-compose.{}.{attempt}",
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
            Err(_) => return Err(CliError::invalid("composition.output.write-failed")),
        }
    }
    let (temporary_path, mut file) =
        temporary.ok_or_else(|| CliError::invalid("composition.output.write-failed"))?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|_| CliError::invalid("composition.output.write-failed"))?;
        file.sync_all()
            .map_err(|_| CliError::invalid("composition.output.write-failed"))?;
        drop(file);
        fs::hard_link(&temporary_path, path).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CliError::invalid("composition.output.exists")
            } else {
                CliError::invalid("composition.output.write-failed")
            }
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| CliError::invalid("composition.output.write-failed"))?;
        Ok(())
    })();
    let _ignored = fs::remove_file(&temporary_path);
    result
}

fn named<'a>(name: &'a str, bytes: &'a [u8]) -> ArtifactBytes<'a> {
    ArtifactBytes { name, bytes }
}

fn write_success(output: &mut impl Write, text: &str) -> u8 {
    if writeln!(output, "{text}").is_ok() {
        SUCCESS
    } else {
        INVALID_INPUT
    }
}

fn fail(stderr: &mut impl Write, error: CliError) -> u8 {
    let _ignored = writeln!(stderr, "pbr-compose: {}", error.code);
    error.exit_code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn closed_usage_and_version_are_stable() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run(arguments(&["pbr-compose"]), &mut stdout, &mut stderr),
            2
        );
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"pbr-compose: cli.usage.invalid\n");

        for option in ["--help", "--version"] {
            stdout.clear();
            stderr.clear();
            assert_eq!(
                run(
                    arguments(&["pbr-compose", option]),
                    &mut stdout,
                    &mut stderr
                ),
                0
            );
            assert!(!stdout.is_empty());
            assert!(stderr.is_empty());
            if option == "--help" {
                assert!(
                    String::from_utf8_lossy(&stdout).contains("--proofbound-observation-inputs")
                );
            }
        }
    }

    #[test]
    fn verifier_error_propagation_is_closed() {
        assert_eq!(
            exact_pbr_error(b"pbr-verify: receipt.canonical.non-canonical\n"),
            Some("receipt.canonical.non-canonical")
        );
        assert_eq!(exact_pbr_error(b"other: failure\n"), None);
        assert_eq!(exact_pbr_error(b"pbr-verify: BAD\n"), None);
        assert_eq!(
            exact_pbr_error(b"pbr-verify: receipt.bad\ntrailing\n"),
            None
        );
    }

    #[test]
    fn proofbound_verifier_receives_exact_observation_inputs() {
        let directory = std::env::temp_dir().join(format!(
            "proofbound-runtime-compose-verifier-test-{}",
            std::process::id()
        ));
        let _ignored = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).expect("test directory is created");
        let verifier = directory.join("proofbound-verify");
        let release = directory.join("release");
        let observation_inputs = directory.join("observations.json");
        fs::create_dir(&release).unwrap();
        fs::write(&observation_inputs, b"{}").unwrap();
        fs::write(
            &verifier,
            format!(
                "#!/bin/sh\nset -eu\ntest \"$1\" = --release\ntest \"$2\" = '{}'\ntest \"$3\" = --observation-inputs\ntest \"$4\" = '{}'\ntest \"$5\" = --json\nprintf '{{}}'\n",
                release.display(),
                observation_inputs.display()
            ),
        )
        .unwrap();
        let mut permissions = fs::metadata(&verifier).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&verifier, permissions).unwrap();

        assert_eq!(
            run_proofbound_verifier(&verifier, &release, &observation_inputs).unwrap(),
            b"{}"
        );
        let substituted = directory.join("substituted.json");
        let error = run_proofbound_verifier(&verifier, &release, &substituted).unwrap_err();
        assert_eq!(error.code, "composition.release.verification-failed");
        fs::remove_dir_all(directory).expect("test directory is removed");
    }

    #[test]
    fn publication_never_replaces_an_existing_path() {
        let directory = std::env::temp_dir().join(format!(
            "proofbound-runtime-compose-test-{}",
            std::process::id()
        ));
        let _ignored = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).expect("test directory is created");
        let output = directory.join("receipt.json");
        fs::write(&output, b"existing").expect("fixture is written");
        let error = publish_no_replace(&output, b"replacement").unwrap_err();
        assert_eq!(error.code, "composition.output.exists");
        assert_eq!(fs::read(&output).unwrap(), b"existing");
        fs::remove_dir_all(directory).expect("test directory is removed");
    }
}
