#!/usr/bin/env python3
"""Generate the proposed service-session compiled-policy golden vector."""

import argparse
import json
from pathlib import Path

from deterministic_cbor import decode_strict, json_projection
from encode_plan_v2 import encode


ACCESS_RANK = {"read": 0, "write": 1, "execute": 2}
ROLE_RANK = {
    "project-input": 0,
    "output-root": 1,
    "runtime-executable": 2,
    "runtime-loader-executable": 3,
    "runtime-library": 4,
}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--plan", required=True, type=Path)
    result.add_argument("--output", required=True, type=Path)
    result.add_argument("--projection", required=True, type=Path)
    return result


def filesystem_rules(authority: dict) -> list[dict]:
    entries = []
    for field, access, role in (
        ("read", "read", "project-input"),
        ("runtime_read", "read", "runtime-library"),
        ("write", "write", "output-root"),
        ("execute", "execute", "runtime-executable"),
    ):
        entries.extend(
            {"path": path, "access": access, "role": role} for path in authority[field]
        )
    unique = {
        (entry["path"], entry["access"], entry["role"]): entry for entry in entries
    }
    return sorted(
        unique.values(),
        key=lambda entry: (
            entry["path"].encode("utf-8"),
            ACCESS_RANK[entry["access"]],
            ROLE_RANK[entry["role"]],
        ),
    )


def main() -> int:
    args = parser().parse_args()
    plan = decode_strict(bytes.fromhex(args.plan.read_text(encoding="ascii")))
    if plan.get("schema") != "proofbound-runtime-plan/2":
        raise SystemExit("input is not a version 2 execution plan")
    authority = plan["authority"]
    network = authority["network"]
    if (
        not isinstance(network, dict)
        or network.get("mode") != "authenticated-service-session"
    ):
        raise SystemExit("input does not contain a service session")
    compiled_network = dict(network)
    compiled_network["mode"] = "authenticated-service-session-v1"
    compiled_network.setdefault("credential_source", None)
    limits = plan["limits"]
    policy = {
        "schema": "proofbound-runtime-linux-policy/2",
        "cgroup": {
            "pids.max": limits["processes"],
            "memory.max": limits["memory_bytes"],
            "memory.oom.group": 1,
            "memory.swap.max": limits["swap_bytes"],
            "stderr_bytes": limits["stderr_bytes"],
            "stdout_bytes": limits["stdout_bytes"],
            "wall_time_ms": limits["wall_time_ms"],
        },
        "network": compiled_network,
        "filesystem": filesystem_rules(authority),
        "environment": sorted(
            set(authority["environment"]), key=lambda item: item.encode("utf-8")
        ),
        "no_new_privileges": True,
    }
    encoded = encode(policy)
    args.output.write_text(encoded.hex() + "\n", encoding="ascii")
    args.projection.write_text(
        json.dumps(json_projection(policy), sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
