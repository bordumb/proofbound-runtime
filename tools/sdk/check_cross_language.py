#!/usr/bin/env python3
"""Replay the dependency-free Python and TypeScript SDK evidence surfaces."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


INVENTORY = [
    "python-sdk-contract",
    "sdk-package-reproduction",
    "typescript-sdk-contract",
]


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    commands = [
        [
            sys.executable,
            "-m",
            "unittest",
            "tools.ci.test_sdk_contract",
            "tools.ci.test_sdk_packages",
        ],
        [sys.executable, "-m", "unittest", "discover", "-s", "sdk/python/tests"],
        [
            "node",
            "--experimental-strip-types",
            "--test",
            "sdk/typescript/tests/test.mjs",
        ],
    ]
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
