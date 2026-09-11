#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("compose crate has a repository root")
        .to_path_buf()
}

fn release_paths() -> (String, PathBuf, PathBuf) {
    assert_eq!(std::env::consts::OS, "linux");
    let expected = std::env::var("PROOFBOUND_EXPECTED_ARCH")
        .expect("release observation requires PROOFBOUND_EXPECTED_ARCH");
    assert!(matches!(expected.as_str(), "aarch64" | "x86_64"));
    let output = Command::new("uname")
        .arg("-m")
        .output()
        .expect("uname executes");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)
            .expect("uname is UTF-8")
            .trim(),
        expected
    );

    let root = repository_root();
    (
        expected.clone(),
        root.join("dist/release-observation").join(&expected),
        root.join("dist/native-evidence").join(expected),
    )
}

fn read_json(path: &Path) -> Value {
    let metadata = fs::symlink_metadata(path).expect("observation input exists");
    assert!(!metadata.file_type().is_symlink());
    assert!(metadata.is_file());
    serde_json::from_slice(&fs::read(path).expect("observation input is readable"))
        .expect("observation input is valid JSON")
}

fn inspect_execution_receipt(bundle: &Path, evidence: &Path) -> Value {
    let output = Command::new(bundle.join("pbr"))
        .arg("inspect")
        .arg(evidence.join("execution-receipt.cbor"))
        .output()
        .expect("release runtime inspects the execution receipt");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).expect("receipt projection is JSON")
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn assert_manifest_artifact(bundle: &Path, name: &str) -> (String, u64) {
    let manifest = read_json(&bundle.join("RELEASE-MANIFEST.json"));
    assert_eq!(manifest["schema"], "proofbound-runtime-release-manifest/1");
    let artifact = manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts are an array")
        .iter()
        .find(|artifact| artifact["name"] == name)
        .expect("manifest contains the observed artifact");
    let expected_digest = artifact["sha256"]
        .as_str()
        .expect("manifest digest is a string")
        .to_owned();
    let expected_size = artifact["size"]
        .as_u64()
        .expect("manifest size is an integer");

    let path = bundle.join(name);
    let metadata = fs::symlink_metadata(&path).expect("release artifact exists");
    assert!(!metadata.file_type().is_symlink());
    assert!(metadata.is_file());
    assert_ne!(metadata.permissions().mode() & 0o111, 0);
    let bytes = fs::read(path).expect("release artifact is readable");
    assert_eq!(bytes.len() as u64, expected_size);
    assert_eq!(digest(&bytes), expected_digest);
    (expected_digest, expected_size)
}

fn assert_receipt_artifact(value: &Value, expected_role: &str, digest: &str, size: u64) {
    assert_eq!(value["role"], expected_role);
    assert_eq!(value["sha256"], digest);
    assert_eq!(
        value["size"]
            .as_str()
            .expect("receipt artifact size is a string")
            .parse::<u64>()
            .expect("receipt artifact size is decimal"),
        size
    );
}

fn assert_version(binary: &Path, name: &str) {
    let output = Command::new(binary)
        .arg("--version")
        .output()
        .expect("release artifact executes");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let version =
        fs::read_to_string(repository_root().join("VERSION")).expect("VERSION is readable");
    assert_eq!(
        String::from_utf8(output.stdout).expect("version output is UTF-8"),
        format!("{name} {}\n", version.trim())
    );
}

fn assert_native_resource_context(
    evidence: &Path,
    architecture: &str,
    runtime_digest: &str,
    runtime_size: u64,
) {
    let context = read_json(&evidence.join("native-context.json"));
    assert_eq!(context["schema"], "proofbound-runtime-native-context/1");
    assert_eq!(context["architecture"], architecture);
    assert_eq!(
        context["source_revision"],
        std::env::var("PBR_RELEASE_REVISION")
            .expect("release observation requires the exact source revision")
    );
    let controllers = context["cgroup_v2"]["controllers"]
        .as_array()
        .expect("native cgroup controller inventory is an array");
    for required in ["memory", "pids"] {
        assert!(controllers.iter().any(|controller| controller == required));
    }
    let runtime = context["artifacts"]
        .as_array()
        .expect("native artifact inventory is an array")
        .iter()
        .find(|artifact| artifact["role"] == "runtime")
        .expect("native context identifies the Runtime artifact");
    assert_eq!(runtime["name"], "pbr");
    assert_eq!(runtime["sha256"], runtime_digest);
    assert_eq!(runtime["size"], runtime_size);
}

fn assert_native_run_diagnostics(evidence: &Path, architecture: &str) {
    let diagnostics = read_json(&evidence.join("native-run-diagnostics.json"));
    assert_eq!(
        diagnostics["schema"],
        "proofbound-runtime-native-run-diagnostics/1"
    );
    assert_eq!(diagnostics["architecture"], architecture);
    assert_eq!(
        diagnostics["source_revision"],
        std::env::var("PBR_RELEASE_REVISION")
            .expect("release observation requires the exact source revision")
    );
    assert_eq!(
        diagnostics["cases"],
        serde_json::json!([
            "receipt-target-preexists",
            "plan-input-missing",
            "host-capability-unavailable",
            "output-root-preexists",
            "executable-resolution-failure",
        ])
    );
}

fn assert_version_two_resources(receipt: &Value) {
    assert_eq!(receipt["schema"], "proofbound-runtime-execution-receipt/2");
    let resources = &receipt["resources"];
    assert_eq!(resources["configured"]["pids.max"], 1);
    assert_eq!(resources["configured"]["memory.max"], "268435456");
    assert_eq!(resources["configured"]["memory.swap.max"], "0");
    assert_eq!(resources["configured"]["memory.oom.group"], 1);
    assert_eq!(resources["limit_events"], serde_json::json!([]));
    assert!(
        resources["terminal"]["memory_peak_bytes"]
            .as_str()
            .expect("memory peak is an exact decimal string")
            .parse::<u64>()
            .expect("memory peak fits u64")
            > 0
    );
    assert_eq!(resources["terminal"]["swap_peak_bytes"], "0");
    for group in ["memory_events", "swap_events"] {
        for counter in resources["terminal"][group]
            .as_object()
            .expect("resource event group is an object")
            .values()
        {
            counter
                .as_str()
                .expect("resource event is an exact decimal string")
                .parse::<u64>()
                .expect("resource event fits u64");
        }
    }
}

#[test]
fn observes_runtime_release() {
    let (architecture, bundle, evidence) = release_paths();
    let (digest, size) = assert_manifest_artifact(&bundle, "pbr");
    let receipt = inspect_execution_receipt(&bundle, &evidence);
    assert_eq!(receipt["platform"]["architecture"], architecture);
    assert_version_two_resources(&receipt);
    assert_native_resource_context(&evidence, &architecture, &digest, size);
    assert_native_run_diagnostics(&evidence, &architecture);
    assert_receipt_artifact(
        &receipt["runtime"]["runtime"],
        "runtime-binary",
        &digest,
        size,
    );
    assert_receipt_artifact(&receipt["producer"], "runtime-binary", &digest, size);
    assert_version(&bundle.join("pbr"), "pbr");
}

#[test]
fn observes_launcher_release() {
    let (architecture, bundle, evidence) = release_paths();
    let (digest, size) = assert_manifest_artifact(&bundle, "pbr-native-launcher");
    let receipt = inspect_execution_receipt(&bundle, &evidence);
    assert_eq!(receipt["platform"]["architecture"], architecture);
    assert_receipt_artifact(
        &receipt["runtime"]["launcher"],
        "launcher-binary",
        &digest,
        size,
    );
}

#[test]
fn observes_verifier_release() {
    let (_architecture, bundle, evidence) = release_paths();
    assert_manifest_artifact(&bundle, "pbr-verify");
    let commitment = fs::read_to_string(evidence.join("receipt-commitment.txt"))
        .expect("receipt commitment is readable");
    let output = Command::new(bundle.join("pbr-verify"))
        .arg("--expected-commitment")
        .arg(commitment.trim())
        .arg(evidence.join("execution-receipt.cbor"))
        .output()
        .expect("release verifier executes");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).expect("verifier output is JSON"),
        read_json(&evidence.join("verification.json"))
    );
    assert_version(&bundle.join("pbr-verify"), "pbr-verify");
}

#[test]
fn observes_composer_release() {
    let (_architecture, bundle, _evidence) = release_paths();
    assert_manifest_artifact(&bundle, "pbr-compose");
    assert_version(&bundle.join("pbr-compose"), "pbr-compose");
}
