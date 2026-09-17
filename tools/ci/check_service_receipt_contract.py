#!/usr/bin/env python3
"""Replay the proposed service-session receipt and failure contract."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


INVENTORY = [
    "service-receipt-canonical-success-and-failure",
    "service-receipt-closed-schema",
    "service-receipt-exact-execution-plan-policy-and-service-binding",
    "service-receipt-exact-launcher-transcript-binding",
    "service-receipt-success-observation-binding",
    "service-receipt-success-reuse-gate",
    "service-receipt-typed-failure-phase-and-reason",
    "service-receipt-failure-non-reuse-gate",
    "service-receipt-boundary-release-and-cleanup-consistency",
    "service-receipt-assumption-and-tcb-closure",
    "service-receipt-secret-and-content-exclusion",
    "service-receipt-causal-mutation-rejection",
]


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-m", "unittest", "tools.ci.test_service_receipt_contract"],
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
