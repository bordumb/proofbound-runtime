#!/usr/bin/env python3
"""Generate proposed service-session success and failure receipt fragments."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from deterministic_cbor import json_projection
from encode_plan_v2 import encode
from generate_service_observation_v1_vector import observation


ASSUMPTIONS = [
    "PBR-DNS-AX-004",
    "PBR-HOST-AX-002",
    "PBR-LINUX-AX-001",
    "PBR-TLS-AX-005",
    "PBR-TOOLCHAIN-AX-003",
]
TCB = [
    {"role": "connector-executable", "identity_sha256": bytes([0x21]) * 32},
    {"role": "dns-resolver", "identity_sha256": bytes([0x31]) * 32},
    {"role": "host-hardware-firmware", "identity_sha256": bytes([0x41]) * 32},
    {"role": "linux-kernel", "identity_sha256": bytes([0x51]) * 32},
    {"role": "tls-implementation", "identity_sha256": bytes([0x61]) * 32},
    {"role": "tls-trust-roots", "identity_sha256": bytes([0x52]) * 32},
]


def digest_vector(directory: Path, name: str) -> bytes:
    payload = bytes.fromhex((directory / f"{name}.cbor.hex").read_text(encoding="ascii").strip())
    return hashlib.sha256(payload).digest()


def common(directory: Path) -> dict:
    return {
        "schema": "proofbound-runtime-service-session-receipt/1",
        "service": {"name": "api.anthropic.com", "port": 443},
        "execution_id": bytes(range(16)),
        "plan_sha256": bytes([0x81]) * 32,
        "policy_sha256": bytes([0x71]) * 32,
        "install_request_sha256": digest_vector(directory, "service-launcher-install"),
        "assumptions": ASSUMPTIONS,
        "trusted_computing_base": TCB,
    }


def success(directory: Path) -> dict:
    value = common(directory)
    observation_bytes = encode(observation())
    value.update(
        {
            "eligibility": {"status": "reusable", "reasons": []},
            "result": {
                "kind": "success",
                "installed_sha256": digest_vector(directory, "service-launcher-installed"),
                "release_sha256": digest_vector(directory, "service-launcher-release"),
                "observation_cbor": observation_bytes,
                "observation_sha256": hashlib.sha256(observation_bytes).digest(),
                "child_outcome": {"kind": "exited", "code": 0},
            },
        }
    )
    return value


def failure(directory: Path) -> dict:
    value = common(directory)
    value.update(
        {
            "eligibility": {
                "status": "non-reusable",
                "reasons": ["network.tls-authentication-failed"],
            },
            "result": {
                "kind": "failed",
                "phase": "authenticating",
                "reason": "tls-authentication-failed",
                "observed_ns": 3_500,
                "boundary_state": "not-installed",
                "installed_sha256": None,
                "release_sha256": None,
                "observation_sha256": None,
                "cleanup": {
                    "child": "not-started",
                    "channel": "closed",
                    "cgroup": "empty-removed",
                    "connector": "reaped",
                    "namespace": "destroyed",
                },
            },
        }
    )
    return value


def write(directory: Path, name: str, value: dict) -> None:
    (directory / f"{name}.cbor.hex").write_text(encode(value).hex() + "\n", encoding="ascii")
    (directory / f"{name}.projection.json").write_text(
        json.dumps(json_projection(value), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    arguments = parser.parse_args()
    write(arguments.directory, "service-session-receipt-success", success(arguments.directory))
    write(arguments.directory, "service-session-receipt-failure", failure(arguments.directory))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
