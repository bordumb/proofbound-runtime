#!/usr/bin/env python3
"""Replay the current-integration producer and verifier contract checks."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


INVENTORY = [
    "current-integration-closed-deterministic-cbor",
    "current-integration-independent-verification",
    "current-integration-complete-registry-observation-dependency",
    "current-integration-exact-package-identities",
    "current-integration-exact-runtime-artifact-identities",
    "current-integration-exact-runtime-executable-identities",
    "current-integration-exact-schema-profiles",
    "current-integration-closed-sdk-error-vocabularies",
    "current-integration-exact-linux-platform-profiles",
    "current-integration-exact-proofbound-tool-and-schema-identities",
    "current-integration-optional-tuples-fail-closed",
    "current-integration-human-trust-limit",
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
            "tools.ci.test_current_integration",
            (
                "tools.ci.test_release_workflow.ReleaseWorkflowTests."
                "test_current_integration_requires_complete_anonymous_observation"
            ),
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
