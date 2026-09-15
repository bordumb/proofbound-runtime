#!/usr/bin/env python3
"""Replay the independent RT-8 Linux trace-startup contract."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


INVENTORY = [
    "diagnostic-trace-startup-fail-closed-surface",
    "diagnostic-trace-startup-feature-isolation",
    "diagnostic-trace-startup-raw-call-confinement",
    "diagnostic-trace-startup-release-order",
]


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "unittest",
            "tools.ci.test_diagnostic_trace_startup",
        ],
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
    sys.stdout.write(
        json.dumps(
            {
                "accepted": True,
                "inventory": INVENTORY,
                "schema": "proofbound-independent-check-result/1",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
