#!/usr/bin/env python3
"""Replay the independent RT-8 observer-adapter contract."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


INVENTORY = [
    "diagnostic-observer-adapter-bound-inputs",
    "diagnostic-observer-adapter-drain-coupling",
    "diagnostic-observer-adapter-event-coupling",
    "diagnostic-observer-adapter-mutation-witnesses",
    "diagnostic-observer-adapter-process-capacity",
    "diagnostic-observer-adapter-production-separation",
    "diagnostic-observer-adapter-state-continuity",
    "diagnostic-observer-adapter-transition-order",
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
            "tools.ci.test_diagnostic_observer_adapter",
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
