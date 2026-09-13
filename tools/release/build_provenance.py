#!/usr/bin/env python3
"""Build the closed deterministic-CBOR identity of all release assets."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


SCHEMA = "proofbound-runtime-release-provenance/2"
MAX_ARTIFACTS = 100_000
MAX_NAME_BYTES = 4_096
MAX_U64 = (1 << 64) - 1
NAMESPACE = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")


def encode_argument(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    for additional, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (width * 8):
            return bytes([(major << 5) | additional]) + value.to_bytes(width, "big")
    raise ValueError("CBOR integer exceeds u64")


def encode(value: Any) -> bytes:
    if isinstance(value, bytes):
        return encode_argument(2, len(value)) + value
    if isinstance(value, str):
        payload = value.encode("utf-8")
        return encode_argument(3, len(payload)) + payload
    if type(value) is int and 0 <= value <= MAX_U64:
        return encode_argument(0, value)
    if isinstance(value, list):
        return encode_argument(4, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        entries = sorted((encode(key), encode(item)) for key, item in value.items())
        return encode_argument(5, len(entries)) + b"".join(
            key + item for key, item in entries
        )
    raise ValueError(f"unsupported CBOR value: {type(value).__name__}")


def parse_roots(specifications: list[str]) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    for specification in specifications:
        namespace, separator, raw_path = specification.partition("=")
        if not separator or not NAMESPACE.fullmatch(namespace):
            raise ValueError(f"invalid artifact root: {specification}")
        if namespace in roots:
            raise ValueError(f"duplicate artifact namespace: {namespace}")
        path = Path(raw_path)
        if path.is_symlink() or not path.is_dir():
            raise ValueError(f"artifact root is not a real directory: {path}")
        roots[namespace] = path.resolve(strict=True)
    if not roots:
        raise ValueError("at least one artifact root is required")
    return roots


def digest(path: Path) -> tuple[bytes, int]:
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            hasher.update(block)
            size += len(block)
            if size > MAX_U64:
                raise ValueError(f"artifact is too large: {path}")
    return hasher.digest(), size


def inventory(roots: dict[str, Path]) -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = []
    for namespace, root in roots.items():
        for path in root.rglob("*"):
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"artifact is not a regular file: {path}")
            relative = path.relative_to(root).as_posix()
            logical_name = f"{namespace}/{relative}"
            if not (0 < len(logical_name.encode("utf-8")) <= MAX_NAME_BYTES):
                raise ValueError(f"artifact logical name is outside bounds: {logical_name}")
            sha256, size = digest(path)
            artifacts.append(
                {
                    "logical_name": logical_name,
                    "sha256": sha256,
                    "size_bytes": size,
                }
            )
            if len(artifacts) > MAX_ARTIFACTS:
                raise ValueError("release artifact count exceeds the bound")
    artifacts.sort(key=lambda item: str(item["logical_name"]).encode("utf-8"))
    if not artifacts:
        raise ValueError("release artifact inventory is empty")
    return artifacts


def write_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--artifact-root", action="append", required=True)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        if not REVISION.fullmatch(arguments.revision):
            raise ValueError("revision must be one lowercase 40-character Git object id")
        roots = parse_roots(arguments.artifact_root)
        output = arguments.output.resolve()
        if any(output.is_relative_to(root) for root in roots.values()):
            raise ValueError("provenance output must be outside every artifact root")
        value = {
            "schema": SCHEMA,
            "source_revision": bytes.fromhex(arguments.revision),
            "artifacts": inventory(roots),
        }
        write_exclusive(output, encode(value))
    except (OSError, ValueError) as error:
        print(f"release provenance build failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
