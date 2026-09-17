#!/usr/bin/env python3
"""Replay the proposed service-session observation contract checks."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


INVENTORY = [
    "service-observation-canonical-vector",
    "service-observation-closed-schema",
    "service-observation-complete-success-lifecycle",
    "service-observation-connector-runtime-closure-binding",
    "service-observation-endpoint-and-tls-binding",
    "service-observation-tls-implementation-binding",
    "service-observation-bounded-counters",
    "service-observation-complete-cleanup",
    "service-observation-secret-and-payload-exclusion",
    "service-observation-causal-mutation-rejection",
]


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-m", "unittest", "tools.ci.test_service_observation_contract"],
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
