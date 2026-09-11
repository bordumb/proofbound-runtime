#!/usr/bin/env python3
"""Compile one reviewable JSON policy source to deterministic CBOR."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from tools.ci.encode_plan_v2 import encode


SCHEMA = "proofbound-runtime-acceptance-policy/1"
DOMAIN = SCHEMA.encode("ascii") + b"\0"
DIGEST_FIELDS = {"sha256", "policy_sha256", "payload_sha256"}
EXPECTED_KEYS = {
    (): {"schema", "execution", "release", "reject_if_present"},
    ("execution",): {
        "receipt_schema", "runtime_version", "platform", "plan_id",
        "executable", "policy_sha256", "policy_model_version", "resources",
        "eligibility", "freshness",
    },
    ("execution", "platform"): {"operating_system", "architecture"},
    ("execution", "executable"): {"sha256", "size", "mode"},
    ("execution", "resources"): {
        "pids.max", "memory.max", "memory.swap.max", "memory.oom.group",
    },
    ("execution", "freshness"): {"mode"},
    ("release",): {
        "project", "project_revision", "payload_sha256", "evidence_context", "claims",
    },
    ("release", "claims", "*"): {
        "claim_id", "formal", "linkage", "assumption", "policy_admitted",
    },
    ("reject_if_present",): {
        "assumptions", "exclusions", "open_obligations", "tcb_roles",
    },
}


class PolicyError(Exception):
    """One invalid reviewable policy source."""


def parse_hex(value: Any, size: int, label: str, prefix: bool) -> bytes:
    if not isinstance(value, str):
        raise PolicyError(f"{label} must be text")
    encoded = value.removeprefix("sha256:") if prefix else value
    if len(encoded) != size * 2 or any(c not in "0123456789abcdef" for c in encoded):
        raise PolicyError(f"{label} must contain {size} lowercase hexadecimal bytes")
    return bytes.fromhex(encoded)


def close(value: Any, path: tuple[str, ...] = ()) -> Any:
    if isinstance(value, dict):
        lookup = tuple("*" if part.isdigit() else part for part in path)
        expected = EXPECTED_KEYS.get(lookup)
        if expected is not None and set(value) != expected:
            raise PolicyError(f"{'.'.join(path) or 'policy'} has unexpected fields")
        result = {}
        for key, item in value.items():
            if key in DIGEST_FIELDS:
                result[key] = parse_hex(item, 32, ".".join(path + (key,)), True)
            elif key == "project_revision":
                result[key] = parse_hex(item, 20, ".".join(path + (key,)), False)
            else:
                result[key] = close(item, path + (key,))
        return result
    if isinstance(value, list):
        return [close(item, path + (str(index),)) for index, item in enumerate(value)]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise PolicyError(f"{'.'.join(path)} contains an unsupported value")


def compile_policy(source: Path, output: Path) -> dict[str, str]:
    if output.exists() or output.is_symlink():
        raise PolicyError(f"output already exists: {output}")
    try:
        value = json.loads(source.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PolicyError(f"policy source is invalid JSON: {error}") from error
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise PolicyError("policy source schema is unsupported")
    encoded = encode(close(value))
    with output.open("xb") as destination:
        destination.write(encoded)
    return {
        "output": str(output),
        "policy_identity": "sha256:" + hashlib.sha256(DOMAIN + encoded).hexdigest(),
        "schema": "proofbound-runtime-policy-compile-result/1",
        "source_sha256": "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest(),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--source", required=True, type=Path)
    result.add_argument("--output", required=True, type=Path)
    return result


def main() -> int:
    try:
        print(json.dumps(compile_policy(**vars(parser().parse_args())), sort_keys=True, separators=(",", ":")))
    except PolicyError as error:
        raise SystemExit(f"compile-policy: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
