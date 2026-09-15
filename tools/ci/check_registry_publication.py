#!/usr/bin/env python3
"""Replay the selected registry-publication contract checks."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


INVENTORY = [
    "registry-publication-explicit-opt-in",
    "registry-publication-exact-mainline-source",
    "registry-publication-protected-environment",
    "registry-publication-ordered-package-set",
    "registry-publication-credential-separation",
    "registry-publication-upload-input-reproduction",
    "registry-publication-npm-bootstrap-gate",
    "registry-publication-anonymous-retrieval",
    "registry-publication-exact-byte-comparison",
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
            "tools.ci.test_registry_packages",
            (
                "tools.ci.test_release_workflow.ReleaseWorkflowTests."
                "test_registry_publication_is_explicit_protected_and_ordered"
            ),
            (
                "tools.ci.test_release_workflow.ReleaseWorkflowTests."
                "test_preflight_rejects_non_sha_and_non_mainline_revisions"
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
