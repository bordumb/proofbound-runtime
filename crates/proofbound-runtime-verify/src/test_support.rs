//! Shared complete receipt fixture for independent verifier unit tests.

pub(crate) fn artifact(role: &str, marker: &str) -> serde_json::Value {
    serde_json::json!({
        "role": role,
        "sha256": marker.repeat(64),
        "size": "1",
        "mode": 416
    })
}

pub(crate) fn receipt() -> serde_json::Value {
    let execution_id = "00112233-4455-4677-8899-aabbccddeeff";
    let policy_sha256 = "3".repeat(64);
    serde_json::json!({
        "schema": "proofbound-runtime-receipt/1",
        "product_version": "0.0.0",
        "execution_id": execution_id,
        "plan": {
            "id": "fixture.plan",
            "source": artifact("execution-plan", "1"),
            "normalized": artifact("normalized-plan", "2")
        },
        "policy": {
            "identity": artifact("compiled-policy", "3"),
            "model_version": "proofbound-runtime-linux-policy/1"
        },
        "platform": {
            "operating_system": "linux",
            "architecture": "x86_64",
            "kernel_release": "6.12.0",
            "landlock_abi": 6,
            "seccomp_features": ["tsync"],
            "cgroup_controllers": ["pids"]
        },
        "runtime": {
            "runtime": artifact("runtime-binary", "4"),
            "launcher": artifact("launcher-binary", "5")
        },
        "command": {
            "executable": artifact("runtime-executable", "6"),
            "loader": artifact("runtime-loader-executable", "7"),
            "working_directory": artifact("working-directory", "8"),
            "arguments_sha256": "9".repeat(64)
        },
        "inputs": [
            artifact("runtime-library", "7"),
            artifact("project-input", "a")
        ],
        "environment": ["PATH"],
        "output_root": artifact("output-root", "b"),
        "boundary": {
            "state": "installed",
            "execution_id": execution_id,
            "policy_sha256": policy_sha256,
            "cgroup": {"mount_id": "1", "inode": "2"}
        },
        "observations": {
            "clock": "linux-monotonic",
            "started_ns": "3",
            "finished_ns": "4"
        },
        "streams": {
            "stdout": {"artifact": artifact("standard-output", "c"), "capture": "complete"},
            "stderr": {"artifact": artifact("standard-error", "d"), "capture": "complete"}
        },
        "outcome": {"kind": "exited", "code": 0},
        "outputs": [artifact("output-artifact", "e")],
        "eligibility": {"status": "reusable", "reasons": []},
        "producer": artifact("runtime-binary", "4"),
        "assumptions": ["PBR-HOST-AX-002", "PBR-LINUX-AX-001", "PBR-TOOLCHAIN-AX-003"],
        "trusted_computing_base": [
            {"role": "host-hardware-firmware", "identity": "fixture:host"},
            {"role": "linux-kernel", "identity": "linux:6.12.0"},
            {"role": "landlock", "identity": "abi:6"},
            {"role": "seccomp", "identity": "feature:tsync"},
            {"role": "cgroup-v2", "identity": "controller:pids"},
            {"role": "no-new-privileges", "identity": "linux:prctl"},
            {"role": "filesystem", "identity": "fixture:filesystem"},
            {"role": "runtime-binary", "identity": "sha256:runtime"},
            {"role": "launcher-binary", "identity": "sha256:launcher"},
            {"role": "rust-toolchain", "identity": "rustc:fixture"},
            {"role": "cryptographic-digest", "identity": "sha256:fixture"},
            {"role": "runtime-executable", "identity": "sha256:executable"},
            {"role": "runtime-loader-executable", "identity": "sha256:loader"},
            {"role": "runtime-library", "identity": "sha256:library"}
        ]
    })
}

pub(crate) fn bytes(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("fixture JSON encodes")
}
