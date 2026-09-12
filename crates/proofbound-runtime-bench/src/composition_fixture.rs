use proofbound_runtime_compose::{ArtifactBytes, CompositionInputs};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const EXECUTION_ID: &str = "00112233-4455-4677-8899-aabbccddeeff";

pub(crate) struct CompositionFixture {
    release_envelope: Vec<u8>,
    compiled_release: Vec<u8>,
    release_verification: Vec<u8>,
    release_verifier: Vec<u8>,
    release_observation_inputs: Vec<u8>,
    release_tcb_ledger: Vec<u8>,
    runtime_manifest: Vec<u8>,
    runtime: Vec<u8>,
    launcher: Vec<u8>,
    execution_verifier: Vec<u8>,
    composer: Vec<u8>,
    execution_receipt: Vec<u8>,
    execution_verification: Vec<u8>,
    commitment: String,
}

impl CompositionFixture {
    pub(crate) fn new() -> Self {
        let runtime = b"exact-pbr".to_vec();
        let launcher = b"exact-launcher".to_vec();
        let execution_verifier = b"exact-pbr-verify".to_vec();
        let composer = b"exact-pbr-compose".to_vec();
        let runtime_digest = digest_hex(&runtime);
        let launcher_digest = digest_hex(&launcher);
        let verifier_digest = digest_hex(&execution_verifier);
        let composer_digest = digest_hex(&composer);
        let artifact_observation = json!({
            "artifact": {
                "logical_name": "dist/release-observation/x86_64/pbr",
                "sha256": digest_text(&runtime),
                "size_bytes": runtime.len()
            },
            "dependencies": [digest_text(b"runtime evidence")],
            "evidence": digest_text(b"observation evidence"),
            "identity": digest_text(b"observation relation"),
            "platform": {"architecture": "x86_64", "operating_system": "linux"},
            "procedure": {
                "logical_name": "crates/proofbound-runtime-compose/tests/release_observation.rs",
                "sha256": digest_text(b"observation procedure"),
                "size_bytes": 21
            },
            "semantic_kind": "example-test",
            "subject_role": "runtime-release",
            "toolchain_closure": {
                "kind": "toolchain",
                "sha256": digest_text(b"toolchain closure")
            }
        });
        let claim = json!({
            "artifact_observations": [artifact_observation],
            "assumption": "ASSUMED",
            "assumptions": ["PBR-TOOLCHAIN-AX-003"],
            "claim_id": "PBR-TEST-001",
            "formal": "TESTED",
            "linkage": "MODEL_ONLY",
            "policy_admitted": true,
            "public_statement": "The frozen fixture remains bounded.",
            "undischarged_premises": []
        });
        let compiled_release = canonical_json(json!({
            "assumptions": [],
            "claims": [],
            "closures": [],
            "evidence": [{
                "record": {
                    "artifact_binding": {
                        "artifact": {
                            "logical_name": "dist/release-observation/x86_64/pbr",
                            "sha256": digest_text(&runtime),
                            "size_bytes": runtime.len()
                        },
                        "theorem_evidence": digest_text(b"theorem evidence")
                    },
                    "claim_ids": ["PBR-TEST-001"],
                    "evidence_context": "release-linux-x86-64",
                    "kind": "artifact-soundness",
                    "outcome": "passed",
                    "schema": "proofbound-evidence/5"
                },
                "sha256": digest_text(b"artifact evidence")
            }],
            "evidence_context": "release-linux-x86-64",
            "graph": {},
            "graph_sha256": digest_text(b"graph"),
            "policies": [],
            "premises": [],
            "project": "proofbound-runtime",
            "project_revision": "0123456789abcdef0123456789abcdef01234567",
            "project_tier": 3,
            "reported_statuses": [claim.clone()],
            "schema": "proofbound-compiled-release/6",
            "sealed_files": [],
            "tree_state": "clean"
        }));
        let payload_digest = domain_digest_text("proofbound-compiled-release/6", &compiled_release);
        let release_envelope = canonical_json(json!({
            "payload": "compiled-receipt.json",
            "payload_sha256": payload_digest,
            "schema": "proofbound-release-envelope/6"
        }));
        let release_verification = canonical_json(json!({
            "claims": [claim],
            "evidence_context": "release-linux-x86-64",
            "not_proved_out_of_scope": {
                "assumptions": ["PBR-TEST-001: PBR-TOOLCHAIN-AX-003"],
                "exclusions": [],
                "open_obligations": ["PBR-TEST-001: exact release linkage"],
                "undischarged_premises": []
            },
            "payload_sha256": payload_digest,
            "project": "proofbound-runtime",
            "project_revision": "0123456789abcdef0123456789abcdef01234567",
            "publication_blocked": false,
            "schema": "proofbound-verification-report/3",
            "trust_boundary": "Exact observation bytes were supplied externally.",
            "verdict": "bytes-observed"
        }));
        let release_observation_inputs = canonical_json(json!({
            "observations": [{
                "artifact_path": "dist/release-observation/x86_64/pbr",
                "claim_id": "PBR-TEST-001",
                "platform": {"architecture": "x86_64", "operating_system": "linux"},
                "procedure_path": "crates/proofbound-runtime-compose/tests/release_observation.rs",
                "subject_role": "runtime-release"
            }],
            "schema": "proofbound-observation-inputs/1"
        }));
        let release_tcb_ledger = canonical_json(json!({
            "components": [{
                "identity_sha256": digest_text(b"proofbound-verifier"),
                "name": "proofbound-verify",
                "version": "0.0.1"
            }],
            "schema": "proofbound-tcb-ledger/1"
        }));
        let runtime_manifest = canonical_json(json!({
            "architecture": "x86_64",
            "artifacts": [
                {"name": "pbr", "sha256": runtime_digest, "size": runtime.len()},
                {"name": "pbr-native-launcher", "sha256": launcher_digest, "size": launcher.len()},
                {"name": "pbr-verify", "sha256": verifier_digest, "size": execution_verifier.len()},
                {"name": "pbr-compose", "sha256": composer_digest, "size": composer.len()}
            ],
            "schema": "proofbound-runtime-release-manifest/1",
            "target": "x86_64-unknown-linux-gnu",
            "toolchain": "rustc fixture",
            "version": "0.1.0"
        }));
        let wire_artifact = |role: &str, digest: &str, size: usize| json!({"mode": 493, "role": role, "sha256": digest, "size": size.to_string()});
        let execution_receipt = canonical_json(json!({
            "assumptions": ["PBR-HOST-AX-002", "PBR-LINUX-AX-001", "PBR-TOOLCHAIN-AX-003"],
            "boundary": {},
            "command": {},
            "eligibility": {"reasons": [], "status": "reusable"},
            "environment": [],
            "execution_id": EXECUTION_ID,
            "inputs": [],
            "observations": {},
            "outcome": {},
            "output_root": {},
            "outputs": [],
            "plan": {},
            "platform": {},
            "policy": {},
            "producer": wire_artifact("runtime-binary", &runtime_digest, runtime.len()),
            "product_version": "0.1.0",
            "runtime": {
                "launcher": wire_artifact("launcher-binary", &launcher_digest, launcher.len()),
                "runtime": wire_artifact("runtime-binary", &runtime_digest, runtime.len())
            },
            "schema": "proofbound-runtime-receipt/1",
            "streams": {},
            "trusted_computing_base": [
                {"identity": runtime_digest, "role": "runtime-binary"},
                {"identity": launcher_digest, "role": "launcher-binary"},
                {"identity": "PBR-TOOLCHAIN-AX-003", "role": "rust-toolchain"}
            ]
        }));
        let commitment = digest_text(&execution_receipt);
        let execution_verification = canonical_json(json!({
            "eligibility": {"reasons": [], "status": "reusable"},
            "receipt_commitment": commitment,
            "valid": true
        }));
        Self {
            release_envelope,
            compiled_release,
            release_verification,
            release_verifier: b"proofbound-verifier".to_vec(),
            release_observation_inputs,
            release_tcb_ledger,
            runtime_manifest,
            runtime,
            launcher,
            execution_verifier,
            composer,
            execution_receipt,
            execution_verification,
            commitment,
        }
    }

    pub(crate) fn inputs(&self) -> CompositionInputs<'_> {
        CompositionInputs {
            release_envelope: named("release.json", &self.release_envelope),
            compiled_release: named("compiled-receipt.json", &self.compiled_release),
            release_verification: named("proofbound-verification.json", &self.release_verification),
            release_verifier: named("proofbound-verify", &self.release_verifier),
            release_observation_inputs: named(
                "proofbound-observation-inputs.json",
                &self.release_observation_inputs,
            ),
            release_tcb_ledger: named("tcb-ledger.json", &self.release_tcb_ledger),
            runtime_manifest: named("RELEASE-MANIFEST.json", &self.runtime_manifest),
            runtime: named("pbr", &self.runtime),
            launcher: named("pbr-native-launcher", &self.launcher),
            execution_verifier: named("pbr-verify", &self.execution_verifier),
            composer: named("pbr-compose", &self.composer),
            execution_receipt: named("execution-receipt.json", &self.execution_receipt),
            execution_verification: named(
                "execution-verification.json",
                &self.execution_verification,
            ),
            expected_execution_commitment: &self.commitment,
            expected_execution_id: EXECUTION_ID,
        }
    }
}

fn named<'a>(name: &'a str, bytes: &'a [u8]) -> ArtifactBytes<'a> {
    ArtifactBytes { name, bytes }
}

fn canonical_json(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).expect("typed composition fixture JSON encodes")
}

fn digest_text(bytes: &[u8]) -> String {
    format!("sha256:{}", digest_hex(bytes))
}

fn domain_digest_text(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    format!("sha256:{}", hex_digest(&hasher.finalize()))
}

fn digest_hex(bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(bytes))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
