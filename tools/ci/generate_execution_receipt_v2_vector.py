#!/usr/bin/env python3
"""Regenerate the semantically valid execution-receipt v2 golden vector."""

import hashlib
import json
from pathlib import Path

from deterministic_cbor import json_projection
from encode_plan_v2 import encode


ROOT = Path(__file__).resolve().parents[2] / "schemas/vectors/v2"
EXECUTION_ID = bytes.fromhex("00112233445546778899aabbccddeeff")


def digest(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def artifact(role: str, value: bytes, mode: int = 0o755) -> dict[str, object]:
    return {
        "mode": mode,
        "role": role,
        "sha256": digest(value),
        "size": len(value),
    }


def receipt() -> dict[str, object]:
    runtime = artifact("runtime-binary", b"exact-pbr")
    launcher = artifact("launcher-binary", b"exact-launcher")
    executable = artifact("runtime-executable", b"golden executable")
    policy = artifact("compiled-policy", b"golden policy")
    return {
        "assumptions": [
            "PBR-HOST-AX-002",
            "PBR-LINUX-AX-001",
            "PBR-TOOLCHAIN-AX-003",
        ],
        "boundary": {
            "cgroup": {"inode": 12, "mount_id": 34},
            "execution_id": EXECUTION_ID,
            "policy_sha256": policy["sha256"],
            "state": "installed",
        },
        "command": {
            "arguments_sha256": digest(b"golden arguments"),
            "executable": executable,
            "loader": None,
            "working_directory": artifact("working-directory", b"golden cwd"),
        },
        "eligibility": {"reasons": [], "status": "reusable"},
        "environment": [],
        "execution_id": EXECUTION_ID,
        "inputs": [],
        "observations": {
            "clock": "linux-monotonic",
            "finished_ns": 200,
            "started_ns": 100,
        },
        "outcome": {"code": 0, "kind": "exited"},
        "output_root": artifact("output-root", b"golden output", 0o700),
        "outputs": [],
        "plan": {
            "id": "golden-v2",
            "limits": {
                "memory_bytes": 65_536,
                "processes": 2,
                "stderr_bytes": 2_048,
                "stdout_bytes": 1_024,
                "swap_bytes": 0,
                "wall_time_ms": 1_000,
            },
            "normalized": artifact("normalized-plan", b"golden normalized plan"),
            "source": artifact("execution-plan", b"golden source plan"),
        },
        "platform": {
            "architecture": "x86_64",
            "cgroup_controllers": ["memory", "pids"],
            "kernel_release": "6.8.0",
            "landlock_abi": 4,
            "operating_system": "linux",
            "seccomp_features": ["deny-network-v1"],
        },
        "policy": {
            "identity": policy,
            "model_version": "proofbound-runtime-linux-policy/2",
        },
        "producer": runtime,
        "product_version": "0.2.0",
        "resources": {
            "configured": {
                "memory.max": 65_536,
                "memory.oom.group": 1,
                "memory.swap.max": 0,
                "pids.max": 2,
            },
            "limit_events": [],
            "terminal": {
                "memory_events": {
                    "high": 0,
                    "low": 0,
                    "max": 0,
                    "oom": 0,
                    "oom_group_kill": 0,
                    "oom_kill": 0,
                },
                "memory_peak_bytes": 32_768,
                "swap_events": {"fail": 0, "max": 0},
                "swap_peak_bytes": 0,
            },
        },
        "runtime": {"launcher": launcher, "runtime": runtime},
        "schema": "proofbound-runtime-execution-receipt/2",
        "streams": {
            "stderr": {
                "artifact": artifact("standard-error", b"golden stderr", 0o600),
                "capture": "complete",
            },
            "stdout": {
                "artifact": artifact("standard-output", b"golden stdout", 0o600),
                "capture": "complete",
            },
        },
        "trusted_computing_base": [
            {"identity": "golden-host", "role": "host-hardware-firmware"},
            {"identity": "golden-linux", "role": "linux-kernel"},
            {"identity": "golden-landlock", "role": "landlock"},
            {"identity": "golden-seccomp", "role": "seccomp"},
            {"identity": "golden-cgroup", "role": "cgroup-v2"},
            {"identity": "golden-nnp", "role": "no-new-privileges"},
            {"identity": "golden-filesystem", "role": "filesystem"},
            {"identity": runtime["sha256"].hex(), "role": "runtime-binary"},
            {"identity": launcher["sha256"].hex(), "role": "launcher-binary"},
            {"identity": "golden-rust", "role": "rust-toolchain"},
            {"identity": "sha256", "role": "cryptographic-digest"},
            {"identity": executable["sha256"].hex(), "role": "runtime-executable"},
        ],
    }


def main() -> None:
    value = receipt()
    encoded = encode(value)
    (ROOT / "execution-receipt.cbor.hex").write_text(encoded.hex() + "\n")
    (ROOT / "execution-receipt.projection.json").write_text(
        json.dumps(json_projection(value), sort_keys=True, separators=(",", ":")) + "\n"
    )


if __name__ == "__main__":
    main()
