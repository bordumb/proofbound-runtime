#!/usr/bin/env python3
"""Publish one closed, no-replace result for the Landlock port control."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path


MAX_INPUT_BYTES = 1024 * 1024
SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}")
CASES = (
    ("allowed-service", True),
    ("same-port-service-substitution", True),
    ("other-port-denied", False),
    ("wrong-certificate-denied", False),
)


class RecordError(Exception):
    """A result input or publication boundary is invalid."""


def regular_bytes(path: Path) -> bytes:
    """Read one bounded regular file without following a symlink."""

    try:
        metadata = path.lstat()
    except OSError as error:
        raise RecordError(f"input unavailable: {path.name}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_INPUT_BYTES:
        raise RecordError(f"input is not one bounded regular file: {path.name}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RecordError(f"input could not be opened: {path.name}") from error
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise RecordError(f"input identity changed: {path.name}")
        data = bytearray()
        while len(data) <= MAX_INPUT_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_INPUT_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_INPUT_BYTES:
            raise RecordError(f"input exceeded byte limit: {path.name}")
        closed = os.fstat(descriptor)
        if (closed.st_dev, closed.st_ino, closed.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise RecordError(f"input identity changed: {path.name}")
        return bytes(data)
    finally:
        os.close(descriptor)


def sha256(data: bytes) -> str:
    """Return one lowercase SHA-256 digest."""

    return hashlib.sha256(data).hexdigest()


def identity(name: str, data: bytes, mode: int) -> dict[str, object]:
    """Return one closed file identity."""

    return {
        "mode": format(stat.S_IMODE(mode), "04o"),
        "name": name,
        "sha256": sha256(data),
        "size": len(data),
    }


def canonical_json(value: object) -> bytes:
    """Return canonical experiment JSON bytes."""

    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def write_new(path: Path, data: bytes, mode: int = 0o644) -> None:
    """Write one new file and never replace an existing path."""

    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise RecordError(f"short write: {path.name}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def bounded_text(value: str, field: str) -> str:
    """Validate one single-line metadata value."""

    if not value or len(value.encode()) > 1024 or "\n" in value or "\r" in value:
        raise RecordError(f"invalid metadata: {field}")
    return value


def parse_exit(value: str, field: str) -> int:
    """Parse one process exit status."""

    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise RecordError(f"invalid exit status: {field}") from error
    if not 0 <= parsed <= 255:
        raise RecordError(f"invalid exit status: {field}")
    return parsed


def confined_file(root: Path, relative: str) -> Path:
    """Return one child path without traversal or symlinked components."""

    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise RecordError(f"invalid relative input: {relative}")
    path = root / candidate
    try:
        path.relative_to(root)
    except ValueError as error:
        raise RecordError(f"input escaped root: {relative}") from error
    current = root
    for part in candidate.parts:
        current /= part
        try:
            if current.is_symlink():
                raise RecordError(f"input traverses a symlink: {relative}")
        except OSError as error:
            raise RecordError(f"input path cannot be inspected: {relative}") from error
    return path


def record(arguments: argparse.Namespace) -> Path:
    """Validate exact inputs and publish one immutable result directory."""

    output = Path(arguments.output)
    source_root = Path(arguments.source_root)
    work_root = Path(arguments.work_root)
    if not output.is_absolute() or not source_root.is_absolute() or not work_root.is_absolute():
        raise RecordError("output and input roots must be absolute")
    if not SOURCE_COMMIT.fullmatch(arguments.source_commit):
        raise RecordError("source commit must be one lowercase SHA-1 identity")
    if arguments.architecture not in {"x86_64", "aarch64"}:
        raise RecordError("unsupported architecture")
    try:
        landlock_abi = int(arguments.landlock_abi, 10)
    except ValueError as error:
        raise RecordError("invalid Landlock ABI") from error
    if not 4 <= landlock_abi <= 65535:
        raise RecordError("invalid Landlock ABI")

    metadata = {
        "architecture": arguments.architecture,
        "compiler": bounded_text(arguments.compiler, "compiler"),
        "curl": bounded_text(arguments.curl, "curl"),
        "kernel_release": bounded_text(arguments.kernel_release, "kernel_release"),
        "openssl": bounded_text(arguments.openssl, "openssl"),
        "python": bounded_text(arguments.python, "python"),
    }
    exit_values = {
        case: parse_exit(getattr(arguments, case.replace("-", "_")), case)
        for case, _ in CASES
    }

    plan_path = confined_file(source_root, "experiments/network_authority/port-control.toml")
    source_path = confined_file(
        source_root, "experiments/network_authority/landlock_port_control.c"
    )
    wrapper_path = confined_file(work_root, "landlock-port-control")
    allowed_certificate_path = confined_file(work_root, "allowed-certificate.pem")
    denied_certificate_path = confined_file(work_root, "denied-certificate.pem")
    input_paths = [
        plan_path,
        source_path,
        wrapper_path,
        allowed_certificate_path,
        denied_certificate_path,
    ]
    for case, _ in CASES:
        input_paths.extend(
            [
                confined_file(work_root, f"stdout/{case}.log"),
                confined_file(work_root, f"stderr/{case}.log"),
            ]
        )
    inputs = {path: regular_bytes(path) for path in input_paths}

    parent = output.parent
    if not parent.is_dir() or output.exists() or output.is_symlink():
        raise RecordError("output must be one absent child of an existing directory")
    os.mkdir(output, 0o755)
    os.mkdir(output / "stdout", 0o755)
    os.mkdir(output / "stderr", 0o755)

    write_new(output / "plan.toml", inputs[plan_path])
    attack_entries = []
    for case, expects_zero in CASES:
        observed = exit_values[case]
        matched = (observed == 0) == expects_zero
        attack_entries.append(
            {
                "case": case,
                "expected_exit": "zero" if expects_zero else "nonzero",
                "matched_expected": matched,
                "observed_exit": observed,
            }
        )
        write_new(
            output / "stdout" / f"{case}.log",
            inputs[work_root / "stdout" / f"{case}.log"],
        )
        write_new(
            output / "stderr" / f"{case}.log",
            inputs[work_root / "stderr" / f"{case}.log"],
        )

    all_expected = all(entry["matched_expected"] for entry in attack_entries)
    attack_result = {
        "cases": attack_entries,
        "complete": True,
        "schema": "proofbound-runtime-network-experiment-attacks/1",
    }
    fixture_manifest = {
        "certificates": [
            identity(
                "allowed-certificate.pem",
                inputs[allowed_certificate_path],
                allowed_certificate_path.lstat().st_mode,
            ),
            identity(
                "denied-certificate.pem",
                inputs[denied_certificate_path],
                denied_certificate_path.lstat().st_mode,
            ),
        ],
        "network": "disposable-loopback-namespace",
        "schema": "proofbound-runtime-network-experiment-fixture/1",
    }
    kernel_manifest = {
        "architecture": metadata["architecture"],
        "kernel_release": metadata["kernel_release"],
        "landlock_abi": landlock_abi,
        "schema": "proofbound-runtime-network-experiment-kernel/1",
    }
    tool_manifest = {
        "compiler": metadata["compiler"],
        "curl": metadata["curl"],
        "openssl": metadata["openssl"],
        "python": metadata["python"],
        "schema": "proofbound-runtime-network-experiment-tools/1",
    }
    artifact_manifest = {
        "artifacts": [
            identity(
                "landlock-port-control",
                inputs[wrapper_path],
                wrapper_path.lstat().st_mode,
            ),
            identity(
                "landlock_port_control.c",
                inputs[source_path],
                source_path.lstat().st_mode,
            ),
        ],
        "schema": "proofbound-runtime-network-experiment-artifacts/1",
    }

    manifests = {
        "attack-results.json": canonical_json(attack_result),
        "fixture-manifest.json": canonical_json(fixture_manifest),
        "kernel-manifest.json": canonical_json(kernel_manifest),
        "tool-manifest.json": canonical_json(tool_manifest),
        "artifact-manifest.json": canonical_json(artifact_manifest),
    }
    for name, data in manifests.items():
        write_new(output / name, data)

    published_inputs = dict(manifests)
    published_inputs["plan.toml"] = inputs[plan_path]
    for case, _ in CASES:
        published_inputs[f"stdout/{case}.log"] = inputs[
            work_root / "stdout" / f"{case}.log"
        ]
        published_inputs[f"stderr/{case}.log"] = inputs[
            work_root / "stderr" / f"{case}.log"
        ]
    result = {
        "complete": True,
        "conclusion": (
            "port-only-landlock-cannot-select-service"
            if all_expected
            else "unexpected-control-result"
        ),
        "experiment": "network-authority/1",
        "inputs": [
            {"name": name, "sha256": sha256(data), "size": len(data)}
            for name, data in sorted(published_inputs.items())
        ],
        "mechanism": "landlock-port-control",
        "schema": "proofbound-runtime-network-experiment-result/1",
        "source_commit": arguments.source_commit,
    }
    write_new(output / "RESULT.json", canonical_json(result))
    return output


def parser() -> argparse.ArgumentParser:
    """Build the closed command-line parser."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--output", required=True)
    result.add_argument("--source-root", required=True)
    result.add_argument("--work-root", required=True)
    result.add_argument("--source-commit", required=True)
    result.add_argument("--architecture", required=True)
    result.add_argument("--kernel-release", required=True)
    result.add_argument("--landlock-abi", required=True)
    result.add_argument("--compiler", required=True)
    result.add_argument("--curl", required=True)
    result.add_argument("--openssl", required=True)
    result.add_argument("--python", required=True)
    for case, _ in CASES:
        result.add_argument(f"--{case}", required=True)
    return result


def main() -> int:
    """Publish one result or fail with a bounded diagnostic."""

    try:
        record(parser().parse_args())
    except (OSError, RecordError) as error:
        print(f"network experiment record failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
