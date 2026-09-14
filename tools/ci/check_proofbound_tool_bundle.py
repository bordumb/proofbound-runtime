#!/usr/bin/env python3
"""Replay the exact Proofbound tool-bundle consumer checks."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


INVENTORY = [
    "tool-bundle-pin-closed-canonical-form",
    "tool-bundle-hosted-release-identity",
    "tool-bundle-hosted-release-immutability",
    "tool-bundle-tag-target-identity",
    "tool-bundle-exact-asset-inventory",
    "tool-bundle-complete-manifest-domain",
    "tool-bundle-embedded-detached-manifest-link",
    "tool-bundle-publication-manifest-linkage",
    "tool-bundle-checksum-order-and-identity",
    "tool-bundle-verify-before-execute",
    "tool-bundle-ci-dogfood",
]


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    commands = (
        [sys.executable, "tools/ci/install_proofbound_tool_bundle.py", "--check"],
        [
            sys.executable,
            "-m",
            "unittest",
            "tools.ci.test_install_proofbound_tool_bundle",
            "tools.ci.test_required_workflow",
        ],
    )
    for command in commands:
        completed = subprocess.run(
            command,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            sys.stderr.buffer.write(completed.stdout)
            sys.stderr.buffer.write(completed.stderr)
            return 2
    report = {
        "accepted": True,
        "inventory": INVENTORY,
        "schema": "proofbound-independent-check-result/1",
    }
    sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
