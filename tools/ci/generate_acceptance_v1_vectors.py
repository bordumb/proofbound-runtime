#!/usr/bin/env python3
"""Regenerate the deterministic-CBOR acceptance policy and decision vectors."""

import hashlib
import json
from pathlib import Path

from deterministic_cbor import json_projection
from encode_plan_v2 import encode


ROOT = Path(__file__).resolve().parents[2] / "schemas/vectors/v2"
POLICY_SCHEMA = "proofbound-runtime-acceptance-policy/1"
DECISION_SCHEMA = "proofbound-runtime-acceptance-decision/1"


def digest(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def identity(domain: str, value: bytes) -> bytes:
    return digest(domain.encode("ascii") + b"\0" + value)


def policy() -> dict[str, object]:
    return {
        "execution": {
            "eligibility": "reusable",
            "executable": {
                "mode": 0o755,
                "sha256": digest(b"golden executable"),
                "size": len(b"golden executable"),
            },
            "freshness": {"mode": "not-required"},
            "plan_id": "golden-v2",
            "platform": {"architecture": "x86_64", "operating_system": "linux"},
            "policy_model_version": "proofbound-runtime-linux-policy/2",
            "policy_sha256": digest(b"golden policy"),
            "receipt_schema": "proofbound-runtime-execution-receipt/2",
            "resources": {
                "memory.max": 65_536,
                "memory.oom.group": 1,
                "memory.swap.max": 0,
                "pids.max": 2,
            },
            "runtime_version": "0.2.0",
        },
        "reject_if_present": {
            "assumptions": ["PBR-UNREVIEWED-AX-999"],
            "exclusions": ["network-enabled-execution"],
            "open_obligations": ["unreviewed-native-context"],
            "tcb_roles": ["unregistered-wrapper"],
        },
        "release": {
            "claims": [
                {
                    "assumption": "ASSUMED",
                    "claim_id": "PBR-AUTH-001",
                    "formal": "PROVED",
                    "linkage": "ARTIFACT_BOUND",
                    "policy_admitted": True,
                },
                {
                    "assumption": "ASSUMED",
                    "claim_id": "PBR-RESOURCE-010",
                    "formal": "TESTED",
                    "linkage": "ARTIFACT_BOUND",
                    "policy_admitted": True,
                },
            ],
            "evidence_context": "release-linux-x86-64-runtime",
            "payload_sha256": digest(b"golden release payload"),
            "project": "proofbound-runtime",
            "project_revision": bytes.fromhex("11" * 20),
        },
        "schema": POLICY_SCHEMA,
    }


def artifact(role: str, contents: bytes) -> dict[str, object]:
    return {"role": role, "sha256": digest(contents), "size": len(contents)}


def decision(policy_bytes: bytes) -> dict[str, object]:
    result = {
        "composition_id": digest(b"golden composition"),
        "decision_id": b"",
        "execution_commitment": digest(b"golden execution receipt"),
        "execution_id": bytes.fromhex("00112233445546778899aabbccddeeff"),
        "inputs": [
            artifact("acceptance-policy", policy_bytes),
            artifact("release-envelope", b"release envelope"),
            artifact("compiled-release", b"compiled release"),
            artifact("release-verification", b"release verification"),
            artifact("release-verifier", b"release verifier"),
            artifact("release-observation-inputs", b"observation inputs"),
            artifact("release-tcb-ledger", b"release tcb"),
            artifact("runtime-manifest", b"runtime manifest"),
            artifact("runtime", b"runtime"),
            artifact("launcher", b"launcher"),
            artifact("execution-verifier", b"execution verifier"),
            artifact("composer", b"composer"),
            artifact("acceptor", b"acceptor"),
            artifact("execution-receipt", b"golden execution receipt"),
            artifact("execution-verification", b"execution verification"),
        ],
        "policy_identity": identity(POLICY_SCHEMA, policy_bytes),
        "reasons": [],
        "schema": DECISION_SCHEMA,
        "status": "accepted",
    }
    body = dict(result)
    del body["decision_id"]
    result["decision_id"] = identity(DECISION_SCHEMA, encode(body))
    return result


def write(name: str, value: dict[str, object]) -> bytes:
    encoded = encode(value)
    (ROOT / f"{name}.cbor.hex").write_text(encoded.hex() + "\n", encoding="ascii")
    (ROOT / f"{name}.projection.json").write_text(
        json.dumps(json_projection(value), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return encoded


def main() -> None:
    policy_bytes = write("acceptance-policy", policy())
    write("acceptance-decision", decision(policy_bytes))


if __name__ == "__main__":
    main()
