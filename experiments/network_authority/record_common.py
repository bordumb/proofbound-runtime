"""Closed, no-replace primitives shared by network experiment recorders."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path


MAX_INPUT_BYTES = 1024 * 1024
SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}")


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
    """Publish complete bytes atomically and never replace an existing path."""

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise RecordError(f"short write: {path.name}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


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
