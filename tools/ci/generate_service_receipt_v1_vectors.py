#!/usr/bin/env python3
"""Generate proposed service-session success and failure receipt fragments."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from deterministic_cbor import decode_strict, json_projection
from encode_plan_v2 import encode
from generate_service_observation_v1_vector import observation


ASSUMPTIONS = [
    "PBR-DNS-AX-004",
    "PBR-TLS-AX-005",
]


def digest_vector(directory: Path, name: str) -> bytes:
    payload = vector_bytes(directory, name)
    return hashlib.sha256(payload).digest()


def vector_bytes(directory: Path, name: str) -> bytes:
    return bytes.fromhex((directory / f"{name}.cbor.hex").read_text(encoding="ascii").strip())


def install_request(directory: Path) -> dict:
    return decode_strict(vector_bytes(directory, "service-launcher-install"))


def trusted_computing_base() -> list[dict]:
    session = observation()
    return [
        {"role": "connector-executable", "identity_sha256": session["connector"]["executable"]["sha256"]},
        {"role": "connector-runtime-closure", "identity_sha256": session["connector"]["runtime_closure_sha256"]},
        {"role": "tls-implementation", "identity_sha256": session["tls"]["implementation_sha256"]},
        {"role": "tls-trust-roots", "identity_sha256": session["tls"]["trust_root_set"]["sha256"]},
    ]


def common(directory: Path, *, retain_install_request: bool) -> dict:
    request = install_request(directory)
    return {
        "schema": "proofbound-runtime-service-session-receipt/1",
        "service": request["service"]["service"],
        "execution_id": request["execution_id"],
        "plan_sha256": bytes([0x81]) * 32,
        "policy_sha256": request["policy_sha256"],
        "install_request_sha256": (
            digest_vector(directory, "service-launcher-install")
            if retain_install_request
            else None
        ),
        "assumptions": ASSUMPTIONS,
        "trusted_computing_base": trusted_computing_base(),
    }


def success(directory: Path) -> dict:
    value = common(directory, retain_install_request=True)
    request = install_request(directory)
    session = observation()
    session["execution_id"] = request["execution_id"]
    session["policy_sha256"] = request["policy_sha256"]
    session["service"] = request["service"]["service"]
    session["limits"] = request["service"]["limits"]
    session["dns"]["selected_endpoint"] = request["service"]["selected_endpoint"]
    session["channel"]["child_descriptor"] = request["service"]["channel"]["child_descriptor"]
    session["channel"]["channel_id"] = request["service"]["channel"]["child_endpoint_id"]
    session["connector"]["executable"] = request["service"]["connector"]["executable"]
    session["connector"]["process_generation"] = request["service"]["connector"]["process_generation"]
    session["credential_source"] = request["service"]["credential_source"]
    observation_bytes = encode(session)
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
    value = common(directory, retain_install_request=False)
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
                "clock": "linux-monotonic",
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
