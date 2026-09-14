#!/usr/bin/env python3
"""Replay the public verifier package evidence surface."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


INVENTORY = [
    "verifier-package-preflight-attacks",
    "verifier-package-archive-source-identity",
    "verifier-package-deterministic-manifest",
    "verifier-package-independent-manifest-verification",
    "verifier-package-reproduction",
    "verifier-package-consumer",
    "verifier-package-release-retention",
    "verifier-package-aggregate-provenance",
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
            "tools.ci.test_verifier_package",
            "tools.ci.test_release_provenance",
            "tools.ci.test_release_workflow.ReleaseWorkflowTests.test_verifier_package_is_preflighted_reproduced_and_dogfooded",
            "tools.ci.test_release_workflow.ReleaseWorkflowTests.test_release_provenance_joins_and_verifies_every_release_artifact",
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
    report = {
        "accepted": True,
        "inventory": INVENTORY,
        "schema": "proofbound-independent-check-result/1",
    }
    sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
