#!/usr/bin/env python3
"""Record the exact host and executable identity for one native corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path


ARCHITECTURES = ("aarch64", "x86_64")
RUNTIME_BINARIES = (
    ("runtime", "pbr"),
    ("launcher", "pbr-native-launcher"),
    ("verifier", "pbr-verify"),
)


def read_tokens(path: Path) -> list[str]:
    """Read one kernel token set into a stable order."""

    return sorted(set(path.read_text(encoding="utf-8").split()))


def artifact_identity(path: Path, role: str) -> dict[str, object]:
    """Describe the exact regular, non-symlink artifact bytes."""

    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"native artifact is not a regular non-symlink file: {path}")
    data = path.read_bytes()
    return {
        "mode": stat.S_IMODE(metadata.st_mode),
        "name": path.name,
        "role": role,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def source_revision(repository_root: Path) -> str:
    """Read and validate the exact checked-out source revision."""

    revision = subprocess.run(
        ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise ValueError("source revision is not a lowercase SHA-1 object name")
    return revision


def build_context(
    repository_root: Path,
    architecture: str,
    cgroup_root: Path,
    fixture: Path,
    runtime_bin_directory: Path,
) -> dict[str, object]:
    """Build the closed native execution-context record."""

    if architecture not in ARCHITECTURES:
        raise ValueError(f"unsupported native architecture: {architecture}")
    cgroup_metadata = cgroup_root.stat()
    artifacts = [artifact_identity(fixture, "native-boundary-fixture")]
    artifacts.extend(
        artifact_identity(runtime_bin_directory / name, role)
        for role, name in RUNTIME_BINARIES
    )
    uname = os.uname()
    return {
        "architecture": architecture,
        "artifacts": artifacts,
        "cgroup_v2": {
            "controllers": read_tokens(cgroup_root / "cgroup.controllers"),
            "device": cgroup_metadata.st_dev,
            "inode": cgroup_metadata.st_ino,
            "path": str(cgroup_root),
            "subtree_control": read_tokens(cgroup_root / "cgroup.subtree_control"),
        },
        "kernel": {
            "machine": uname.machine,
            "release": uname.release,
            "system": uname.sysname,
            "version": uname.version,
        },
        "schema": "proofbound-runtime-native-context/1",
        "source_revision": source_revision(repository_root),
    }


def write_context(output: Path, context: dict[str, object]) -> None:
    """Create one canonical context record without replacing prior evidence."""

    encoded = json.dumps(context, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(encoded)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--cgroup-root", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--runtime-bin-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repository_root = Path(__file__).resolve().parents[2]
    try:
        context = build_context(
            repository_root,
            args.architecture,
            args.cgroup_root,
            args.fixture,
            args.runtime_bin_directory,
        )
        write_context(args.output, context)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"native context generation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
