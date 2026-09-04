#!/usr/bin/env python3
"""Check authority vectors with an independent reference interpretation."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "proofbound-runtime-authority-vector/1"
ACCESS = {"read": 0, "write": 1, "execute": 2}
ROLES = {
    "project-input": 0,
    "output-root": 1,
    "runtime-executable": 2,
    "runtime-loader-executable": 3,
    "runtime-library": 4,
}


class VectorError(Exception):
    """Contains one stable conformance rejection code."""


def reject(code: str) -> None:
    """Reject a vector with one stable code."""

    raise VectorError(code)


def normalize(vector: dict[str, Any]) -> dict[str, Any]:
    """Interpret and normalize one authority vector independently."""

    if vector.get("schema") != SCHEMA:
        reject("authority.vector.schema")
    authority = vector["input"]
    if authority.get("network") != "deny":
        reject("authority.network.unsupported")

    unique_paths: dict[tuple[str, int, int], dict[str, str]] = {}
    for item in authority["paths"]:
        path = item["path"]
        if not path:
            reject("authority.path.empty")
        if "\0" in path:
            reject("authority.path.null")
        access = item["access"]
        role = item["role"]
        if access not in ACCESS:
            reject("authority.access.unsupported")
        if role not in ROLES:
            reject("authority.path_role.unsupported")
        unique_paths[(path, ACCESS[access], ROLES[role])] = item

    environment = set()
    for name in authority["environment"]:
        if not name:
            reject("authority.environment.empty")
        if "\0" in name:
            reject("authority.environment.null")
        if "=" in name:
            reject("authority.environment.equals")
        environment.add(name)

    limits = authority["limits"]
    if limits["processes"] == 0:
        reject("authority.limit.processes.zero")
    if limits["wall_time_ms"] == 0:
        reject("authority.limit.wall_time.zero")

    return {
        "paths": [unique_paths[key] for key in sorted(unique_paths)],
        "environment": sorted(environment),
        "limits": limits,
        "network": "deny",
    }


def vector_paths(root: Path) -> list[Path]:
    """Return all authority vector paths in stable order."""

    return sorted((root / "tests" / "conformance").glob("*/*.json"))


def main() -> int:
    """Check all vectors and report exact failures."""

    root = Path(__file__).resolve().parents[2]
    failures: list[str] = []
    for path in vector_paths(root):
        vector = json.loads(path.read_text(encoding="utf-8"))
        try:
            result = normalize(vector)
        except (KeyError, TypeError, ValueError):
            result = "authority.vector.type"
        except VectorError as error:
            result = str(error)

        expected = vector.get("expected", vector.get("expected_error"))
        if result != expected:
            failures.append(f"{path.relative_to(root)}: expected {expected!r}, got {result!r}")

    for failure in failures:
        print(f"authority conformance failed: {failure}", file=sys.stderr)
    if not failures:
        print(f"authority conformance: {len(vector_paths(root))} vectors passed")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
