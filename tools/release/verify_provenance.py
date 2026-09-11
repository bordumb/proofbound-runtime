#!/usr/bin/env python3
"""Independently verify a release-provenance object and its closed assets."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
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


class CborError(ValueError):
    """The input is not one complete deterministic-CBOR item."""


@dataclass
class _Decoder:
    data: bytes
    max_depth: int
    max_items: int
    offset: int = 0
    items: int = 0

    def take(self, length: int) -> bytes:
        end = self.offset + length
        if length < 0 or end > len(self.data):
            raise CborError("truncated item")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        if additional == 24:
            value = self.take(1)[0]
            if value < 24:
                raise CborError("non-shortest argument")
            return value
        widths = {25: 2, 26: 4, 27: 8}
        width = widths.get(additional)
        if width is None:
            raise CborError(
                "indefinite length" if additional == 31 else "reserved argument"
            )
        value = int.from_bytes(self.take(width), "big")
        if value < {2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[width]:
            raise CborError("non-shortest argument")
        return value

    def item(self, depth: int = 0) -> Any:
        if depth > self.max_depth:
            raise CborError("nesting limit exceeded")
        self.items += 1
        if self.items > self.max_items or self.offset >= len(self.data):
            raise CborError("item bound exceeded or item missing")
        initial = self.take(1)[0]
        major = initial >> 5
        additional = initial & 31
        if major == 7:
            if additional == 20:
                return False
            if additional == 21:
                return True
            if additional == 22:
                return None
            raise CborError("unadmitted simple or floating-point value")
        argument = self.argument(additional)
        if major == 0:
            return argument
        if major == 1:
            return -1 - argument
        if major == 2:
            return self.take(argument)
        if major == 3:
            try:
                return self.take(argument).decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise CborError("invalid UTF-8 text") from error
        if major == 4:
            return [self.item(depth + 1) for _ in range(argument)]
        if major == 5:
            result: dict[str, Any] = {}
            previous: bytes | None = None
            for _ in range(argument):
                start = self.offset
                key = self.item(depth + 1)
                encoded_key = self.data[start:self.offset]
                if not isinstance(key, str):
                    raise CborError("map key is not text")
                if previous is not None and encoded_key <= previous:
                    raise CborError("map keys are duplicated or out of order")
                previous = encoded_key
                result[key] = self.item(depth + 1)
            return result
        if major == 6:
            raise CborError("tag is not admitted")
        raise CborError("unknown major type")


def decode_strict(data: bytes, max_bytes: int, max_depth: int, max_items: int) -> Any:
    if not data or len(data) > max_bytes:
        raise CborError("input size is outside bounds")
    decoder = _Decoder(data, max_depth, max_items)
    value = decoder.item()
    if decoder.offset != len(data):
        raise CborError("trailing bytes")
    return value


def json_projection(value: Any) -> Any:
    if isinstance(value, bytes):
        return f"hex:{value.hex()}"
    if isinstance(value, list):
        return [json_projection(item) for item in value]
    if isinstance(value, dict):
        return {key: json_projection(item) for key, item in value.items()}
    if type(value) is int:
        return str(value)
    return value


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


def file_identity(path: Path) -> tuple[bytes, int]:
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            hasher.update(block)
            size += len(block)
            if size > MAX_U64:
                raise ValueError(f"artifact is too large: {path}")
    return hasher.digest(), size


def filesystem_inventory(roots: dict[str, Path]) -> dict[str, tuple[bytes, int]]:
    result: dict[str, tuple[bytes, int]] = {}
    for namespace, root in roots.items():
        for path in root.rglob("*"):
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"artifact is not a regular file: {path}")
            logical_name = f"{namespace}/{path.relative_to(root).as_posix()}"
            if logical_name in result:
                raise ValueError(f"duplicate artifact logical name: {logical_name}")
            result[logical_name] = file_identity(path)
            if len(result) > MAX_ARTIFACTS:
                raise ValueError("release artifact count exceeds the bound")
    if not result:
        raise ValueError("release artifact inventory is empty")
    return result


def require_exact_keys(value: object, expected: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} fields are not the closed schema")
    return value


def verify(value: object, expected_revision: str, roots: dict[str, Path]) -> None:
    root = require_exact_keys(
        value, {"schema", "source_revision", "artifacts"}, "provenance"
    )
    if root["schema"] != SCHEMA:
        raise ValueError("provenance schema is unsupported")
    if root["source_revision"] != bytes.fromhex(expected_revision):
        raise ValueError("provenance source revision does not match")
    artifacts = root["artifacts"]
    if not isinstance(artifacts, list) or not (1 <= len(artifacts) <= MAX_ARTIFACTS):
        raise ValueError("provenance artifact count is outside bounds")

    expected = filesystem_inventory(roots)
    observed: set[str] = set()
    previous_name: bytes | None = None
    for index, raw_artifact in enumerate(artifacts):
        artifact = require_exact_keys(
            raw_artifact,
            {"logical_name", "sha256", "size_bytes"},
            f"artifact {index}",
        )
        name = artifact["logical_name"]
        if not isinstance(name, str):
            raise ValueError(f"artifact {index} logical name is not text")
        encoded_name = name.encode("utf-8")
        if not (0 < len(encoded_name) <= MAX_NAME_BYTES):
            raise ValueError(f"artifact {index} logical name is outside bounds")
        if previous_name is not None and encoded_name <= previous_name:
            raise ValueError("artifact logical names are duplicated or out of order")
        previous_name = encoded_name
        namespace, separator, relative = name.partition("/")
        if (
            not separator
            or namespace not in roots
            or not relative
            or relative.startswith("/")
            or "\\" in relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))
        ):
            raise ValueError(f"artifact {index} logical name is unsafe")
        sha256 = artifact["sha256"]
        size = artifact["size_bytes"]
        if not isinstance(sha256, bytes) or len(sha256) != 32:
            raise ValueError(f"artifact {index} SHA-256 is invalid")
        if type(size) is not int or not (0 <= size <= MAX_U64):
            raise ValueError(f"artifact {index} size is invalid")
        actual = expected.get(name)
        if actual is None or actual != (sha256, size):
            raise ValueError(f"artifact {index} identity does not match: {name}")
        observed.add(name)
    if observed != set(expected):
        raise ValueError("provenance does not close the artifact inventory")


def write_projection(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        json_projection(value), sort_keys=True, separators=(",", ":")
    ).encode() + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--artifact-root", action="append", required=True)
    parser.add_argument("--projection", type=Path)
    arguments = parser.parse_args()
    try:
        if not REVISION.fullmatch(arguments.expected_revision):
            raise ValueError("expected revision must be lowercase 40-character hex")
        roots = parse_roots(arguments.artifact_root)
        value = decode_strict(
            arguments.provenance.read_bytes(),
            max_bytes=64 * 1024 * 1024,
            max_depth=8,
            max_items=400_010,
        )
        verify(value, arguments.expected_revision, roots)
        if arguments.projection is not None:
            projection = arguments.projection.resolve()
            if any(projection.is_relative_to(root) for root in roots.values()):
                raise ValueError("projection output must be outside every artifact root")
            write_projection(projection, value)
    except (CborError, OSError, ValueError) as error:
        print(f"release provenance verification failed: {error}", file=sys.stderr)
        return 1
    print("release provenance verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
