#!/usr/bin/env python3
"""Generate the proposed service-session launcher protocol vectors."""

import argparse
import hashlib
import json
from pathlib import Path

from deterministic_cbor import json_projection
from encode_plan_v2 import encode
from generate_service_observation_v1_vector import observation


def artifact(role: str, byte: int, size: int, mode: int) -> dict:
    return {"role": role, "sha256": bytes([byte]) * 32, "size": size, "mode": mode}


def messages() -> dict[str, dict]:
    session = observation()
    execution_id = session["execution_id"]
    policy = session["policy_sha256"]
    cgroup = {"mount_id": 42, "inode": 73}
    seccomp_program = bytes([0x81]) * 64
    service = {
        "service": session["service"],
        "connector": {
            "executable": session["connector"]["executable"],
            "runtime_closure_sha256": session["connector"]["runtime_closure_sha256"],
            "process_generation": session["connector"]["process_generation"],
        },
        "dns_observation_sha256": hashlib.sha256(encode(session["dns"])).digest(),
        "selected_endpoint": session["dns"]["selected_endpoint"],
        "tls_observation_sha256": hashlib.sha256(encode(session["tls"])).digest(),
        "channel": {
            "protocol": "unix-stream-v1",
            "connector_endpoint_id": bytes([0x51]) * 16,
            "child_endpoint_id": session["channel"]["channel_id"],
            "child_descriptor": session["channel"]["child_descriptor"],
            "role": "service-session-channel",
        },
        "limits": session["limits"],
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
