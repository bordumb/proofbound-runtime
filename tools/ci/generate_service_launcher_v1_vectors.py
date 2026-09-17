#!/usr/bin/env python3
"""Generate the proposed service-session launcher protocol vectors."""

import argparse
import hashlib
import json
from pathlib import Path

from deterministic_cbor import json_projection
from encode_plan_v2 import encode


def artifact(role: str, byte: int, size: int, mode: int) -> dict:
    return {"role": role, "sha256": bytes([byte]) * 32, "size": size, "mode": mode}


def messages() -> dict[str, dict]:
    execution_id = bytes([0x11]) * 16
    policy = bytes([0x21]) * 32
    cgroup = {"mount_id": 42, "inode": 73}
    seccomp_program = bytes([0x81]) * 64
    service = {
        "service": {"name": "api.anthropic.com", "port": 443},
        "connector": {
            "executable": artifact("connector-executable", 0x31, 65_536, 0o555),
            "runtime_closure_sha256": bytes([0x32]) * 32,
            "process_generation": 1,
        },
        "dns_observation_sha256": bytes([0x41]) * 32,
        "selected_endpoint": {"family": "ipv4", "address": bytes([192, 0, 2, 10]), "port": 443},
        "tls_observation_sha256": bytes([0x42]) * 32,
        "channel": {
            "protocol": "unix-stream-v1",
            "connector_endpoint_id": bytes([0x51]) * 16,
            "child_endpoint_id": bytes([0x52]) * 16,
            "child_descriptor": 9,
            "role": "service-session-channel",
        },
        "limits": {
            "setup_time_ms": 10_000,
            "session_time_ms": 30_000,
            "child_to_service_bytes": 1_048_576,
            "service_to_child_bytes": 1_048_576,
            "dns_messages": 4,
            "endpoint_attempts": 4,
            "tls_handshake_bytes": 262_144,
        },
        "child_filter_sha256": hashlib.sha256(seccomp_program).digest(),
        "credential_source": None,
    }
    request = {
        "schema": "proofbound-runtime-service-launcher-install/1",
        "execution_id": execution_id,
        "policy_sha256": policy,
        "cgroup": cgroup,
        "executable": artifact("runtime-executable", 0x71, 131_072, 0o555),
        "executable_fd": 7,
        "working_directory_fd": 8,
        "arguments": ["bin/client", "request.json"],
        "environment": {"LANG": "C.UTF-8"},
        "filesystem": [
            {"fd": 7, "access": ["read", "execute"]},
            {"fd": 10, "access": ["read"]},
            {"fd": 11, "access": ["write"]},
        ],
        "seccomp_program": seccomp_program,
        "close_file_descriptors_from": 12,
        "service": service,
    }
    install_request_sha256 = hashlib.sha256(encode(request)).digest()
    installed = {
        "schema": "proofbound-runtime-service-launcher-boundary-installed/1",
        "state": "installed",
        "execution_id": execution_id,
        "policy_sha256": policy,
        "cgroup": cgroup,
        "install_request_sha256": install_request_sha256,
        "service": service,
    }
    released = {
        "schema": "proofbound-runtime-service-launcher-exec-release/1",
        "state": "released",
        "execution_id": execution_id,
        "policy_sha256": policy,
        "cgroup": cgroup,
        "install_request_sha256": install_request_sha256,
        "service_binding_sha256": hashlib.sha256(encode(service)).digest(),
        "credential_state": "not-declared",
    }
    return {"install": request, "installed": installed, "release": released}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    for name, value in messages().items():
        (args.directory / f"service-launcher-{name}.cbor.hex").write_text(
            encode(value).hex() + "\n", encoding="ascii"
        )
        (args.directory / f"service-launcher-{name}.projection.json").write_text(
            json.dumps(json_projection(value), sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
