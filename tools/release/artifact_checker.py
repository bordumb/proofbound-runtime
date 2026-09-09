#!/usr/bin/env python3
"""Emit the closed canonical identity report for one Runtime release executable."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path


MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
ELF_HEADER_BYTES = 64
ARCHITECTURES = {
    "aarch64": 183,
    "x86_64": 62,
}


def canonical_logical_name(value: str) -> str:
    """Validate one repository-relative artifact name without normalizing it."""

    path = Path(value)
    if (
        not value
        or len(value) > 4096
        or path.is_absolute()
        or "\\" in value
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("artifact logical name is not canonical repository-relative text")
    return value


def expected_machine(logical_name: str) -> int:
    """Derive the exact ELF machine from the reviewed release path."""

    matches = [
        machine
        for architecture, machine in ARCHITECTURES.items()
        if f"/{architecture}/" in f"/{logical_name}"
    ]
    if len(matches) != 1 or not logical_name.endswith("/pbr"):
        raise ValueError("artifact path does not select one supported pbr architecture")
    return matches[0]


def read_regular_artifact(path: Path) -> tuple[bytes, os.stat_result]:
    """Read one bounded non-symlink file without a path-replacement window."""

    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("artifact is not a regular non-symlink file")
    if before.st_size < ELF_HEADER_BYTES or before.st_size > MAX_ARTIFACT_BYTES:
        raise ValueError("artifact byte size is outside the registered bound")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("artifact path changed while it was opened")
        chunks: list[bytes] = []
        remaining = MAX_ARTIFACT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(payload) != opened.st_size or len(payload) > MAX_ARTIFACT_BYTES:
        raise ValueError("artifact changed size or exceeded its byte bound while read")
    return payload, opened


def validate_elf(payload: bytes, metadata: os.stat_result, machine: int) -> None:
    """Reject a non-executable or architecture-substituted ELF artifact."""

    if metadata.st_mode & 0o111 == 0:
        raise ValueError("artifact has no executable permission bit")
    if payload[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("artifact is not a little-endian ELF64 version 1 executable")
    elf_type = int.from_bytes(payload[16:18], "little")
    actual_machine = int.from_bytes(payload[18:20], "little")
    elf_version = int.from_bytes(payload[20:24], "little")
    if elf_type not in {2, 3} or actual_machine != machine or elf_version != 1:
        raise ValueError("artifact ELF type, machine, or version does not match its release path")


def artifact_report(logical_name: str) -> dict[str, object]:
    """Inspect bytes and return the checker-owned identity facts only."""

    logical_name = canonical_logical_name(logical_name)
    payload, metadata = read_regular_artifact(Path(logical_name))
    validate_elf(payload, metadata, expected_machine(logical_name))
    return {
        "accepted": True,
        "artifact_logical_name": logical_name,
        "artifact_sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "inventory": [logical_name],
        "schema": "proofbound-artifact-check-result/1",
    }


def minimal_elf(machine: int) -> bytes:
    """Create a structural fixture for the checker self-test, not a release artifact."""

    header = bytearray(ELF_HEADER_BYTES)
    header[:7] = b"\x7fELF\x02\x01\x01"
    header[16:18] = (3).to_bytes(2, "little")
    header[18:20] = machine.to_bytes(2, "little")
    header[20:24] = (1).to_bytes(4, "little")
    return bytes(header) + b"proofbound-runtime-checker-self-test"


def self_check() -> None:
    """Exercise positive identity reports and fail-closed substitutions."""

    with tempfile.TemporaryDirectory(prefix="pbr-artifact-checker-") as directory:
        root = Path(directory)
        previous = Path.cwd()
        try:
            os.chdir(root)
            for architecture, machine in ARCHITECTURES.items():
                logical_name = f"dist/release-observation/{architecture}/pbr"
                path = Path(logical_name)
                path.parent.mkdir(parents=True)
                payload = minimal_elf(machine)
                path.write_bytes(payload)
                path.chmod(0o755)
                report = artifact_report(logical_name)
                assert report["artifact_logical_name"] == logical_name
                assert report["artifact_sha256"] == (
                    "sha256:" + hashlib.sha256(payload).hexdigest()
                )
                assert report["inventory"] == [logical_name]

            aarch64 = Path("dist/release-observation/aarch64/pbr")
            aarch64.write_bytes(minimal_elf(ARCHITECTURES["x86_64"]))
            aarch64.chmod(0o755)
            try:
                artifact_report(aarch64.as_posix())
            except ValueError:
                pass
            else:
                raise AssertionError("architecture substitution was accepted")

            target = Path("dist/release-observation/x86_64/pbr")
            target.chmod(0o644)
            try:
                artifact_report(target.as_posix())
            except ValueError:
                pass
            else:
                raise AssertionError("non-executable artifact was accepted")

            target.unlink()
            target.symlink_to(aarch64.resolve())
            try:
                artifact_report(target.as_posix())
            except ValueError:
                pass
            else:
                raise AssertionError("symlink artifact was accepted")
        finally:
            os.chdir(previous)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", nargs="?")
    parser.add_argument("--self-check", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.self_check:
            if arguments.artifact is not None:
                parser.error("--self-check does not accept an artifact")
            self_check()
            return 0
        if arguments.artifact is None:
            parser.error("artifact is required")
        encoded = json.dumps(
            artifact_report(arguments.artifact), sort_keys=True, separators=(",", ":")
        ).encode()
        sys.stdout.buffer.write(encoded)
        return 0
    except (AssertionError, OSError, ValueError) as error:
        print(f"release artifact check failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
