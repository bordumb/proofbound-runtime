#!/usr/bin/env python3
"""Replay the proposed service-session launcher protocol contract."""

import json
import os
from pathlib import Path
import subprocess
import sys


INVENTORY = [
    "service-launcher-canonical-handshake",
    "service-launcher-execution-policy-cgroup-binding",
    "service-launcher-connector-observation-binding",
    "service-launcher-channel-descriptor-binding",
    "service-launcher-child-filter-binding",
    "service-launcher-release-binding",
    "service-launcher-secret-and-content-exclusion",
    "service-launcher-causal-mutation-rejection",
]


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-m", "unittest", "tools.ci.test_service_launcher_contract"],
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
    sys.stdout.write(json.dumps({"accepted": True, "inventory": INVENTORY, "schema": "proofbound-independent-check-result/1"}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
