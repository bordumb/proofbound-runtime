#!/usr/bin/env python3
"""Install one exact Proofbound Runtime release archive without replacement."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

REPOSITORY = "https://github.com/bordumb/proofbound-runtime"
RESULT_SCHEMA = "proofbound-runtime-install-result/1"
MANIFEST_SCHEMA = "proofbound-runtime-release-manifest/1"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MEMBERS = (
    "RELEASE-MANIFEST.json",
    "pbr",
    "pbr-native-launcher",
    "pbr-verify",
    "pbr-compose",
)
BINARIES = MEMBERS[1:]


@dataclass(frozen=True)
class Release:
    target: str
    archive_sha256: str


RELEASES = {
    ("0.1.0", "x86_64"): Release(
        target="x86_64-unknown-linux-gnu",
        archive_sha256="e0bf91c787d67be9c96f76992b661c3fa905707491e51310673302bf88776040",
    ),
    ("0.1.0", "aarch64"): Release(
        target="aarch64-unknown-linux-gnu",
        archive_sha256="a30e3b83eaa56a2a97b111a551d75c63261e0247ac65c30c51e787f49db6138f",
    ),
}

ARCHITECTURE_ALIASES = {
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "amd64": "x86_64",
    "x86_64": "x86_64",
}


class InstallError(Exception):
    """Reports one fail-closed release installation error."""


def archive_name(version: str, release: Release) -> str:
    return f"proofbound-runtime-v{version}-{release.target}.tar.gz"


def select_release(version: str, architecture: str | None) -> tuple[str, Release]:
    observed = architecture or platform.machine()
    normalized = ARCHITECTURE_ALIASES.get(observed.lower())
    if normalized is None:
        raise InstallError(f"unsupported architecture: {observed}")
    release = RELEASES.get((version, normalized))
    if release is None:
        raise InstallError(
            f"unsupported release: version={version} architecture={normalized}"
        )
    return normalized, release


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_archive_digest(path: Path, expected: str) -> str:
    actual = digest_file(path)
    if actual != expected:
        raise InstallError(
            f"archive digest mismatch: expected sha256:{expected}, actual sha256:{actual}"
        )
    return actual


def copy_bounded(source: BinaryIO, destination: BinaryIO) -> None:
    total = 0
    while chunk := source.read(1024 * 1024):
        total += len(chunk)
        if total > MAX_ARCHIVE_BYTES:
            raise InstallError(
                f"release archive exceeds {MAX_ARCHIVE_BYTES} downloaded bytes"
            )
        destination.write(chunk)


def download_archive(url: str, destination: Path) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "proofbound-runtime-release-installer/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > MAX_ARCHIVE_BYTES:
                raise InstallError(
                    f"release archive declares more than {MAX_ARCHIVE_BYTES} bytes"
                )
            with destination.open("xb") as output:
                copy_bounded(response, output)
    except InstallError:
        raise
    except (OSError, ValueError) as error:
        raise InstallError(f"release download failed: {error}") from error


def read_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    if not member.isfile():
        raise InstallError(f"archive member is not a regular file: {member.name}")
    if member.size > MAX_MEMBER_BYTES:
        raise InstallError(
            f"archive member exceeds {MAX_MEMBER_BYTES} bytes: {member.name}"
        )
    source = archive.extractfile(member)
    if source is None:
        raise InstallError(f"archive member cannot be read: {member.name}")
    data = source.read(MAX_MEMBER_BYTES + 1)
    if len(data) != member.size:
        raise InstallError(f"archive member size changed while reading: {member.name}")
    return data


def require_closed_object(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise InstallError(f"{label} must contain exactly {sorted(fields)}")
    return value


def inspect_archive(
    path: Path, version: str, architecture: str, release: Release
) -> dict[str, bytes]:
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            entries = archive.getmembers()
            names = [entry.name for entry in entries]
            if names != list(MEMBERS):
                raise InstallError(
                    f"archive inventory mismatch: expected {list(MEMBERS)}, actual {names}"
                )
            files = {entry.name: read_member(archive, entry) for entry in entries}
    except InstallError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise InstallError(f"release archive is invalid: {error}") from error

    try:
        decoded = json.loads(files["RELEASE-MANIFEST.json"])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InstallError(f"release manifest is invalid JSON: {error}") from error
    manifest = require_closed_object(
        decoded,
        {"architecture", "artifacts", "schema", "target", "toolchain", "version"},
        "release manifest",
    )
    expected_header = {
        "schema": MANIFEST_SCHEMA,
        "version": version,
        "architecture": architecture,
        "target": release.target,
    }
    for field, expected in expected_header.items():
        if manifest[field] != expected:
            raise InstallError(
                f"release manifest {field} mismatch: expected {expected!r}, "
                f"actual {manifest[field]!r}"
            )
    if not isinstance(manifest["toolchain"], str) or not manifest["toolchain"]:
        raise InstallError("release manifest toolchain must be non-empty text")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(BINARIES):
        raise InstallError("release manifest artifact inventory has the wrong size")
    for expected_name, raw_artifact in zip(BINARIES, artifacts, strict=True):
        artifact = require_closed_object(
            raw_artifact, {"name", "sha256", "size"}, "release artifact"
        )
        if artifact["name"] != expected_name:
            raise InstallError(
                f"release artifact order mismatch: expected {expected_name}, "
                f"actual {artifact['name']!r}"
            )
        data = files[expected_name]
        actual_digest = hashlib.sha256(data).hexdigest()
        if artifact["sha256"] != actual_digest or artifact["size"] != len(data):
            raise InstallError(f"release artifact identity mismatch: {expected_name}")
    return files


def install_files(files: dict[str, bytes], destination: Path) -> None:
    if not destination.is_absolute():
        raise InstallError("destination must be an absolute path")
    parent = destination.parent
    if not parent.is_dir():
        raise InstallError(f"destination parent is not a directory: {parent}")
    try:
        destination.mkdir(mode=0o755)
    except FileExistsError as error:
        raise InstallError(f"destination already exists: {destination}") from error
    except OSError as error:
        raise InstallError(f"destination cannot be created: {error}") from error

    try:
        for name in MEMBERS:
            output = destination / name
            with output.open("xb") as handle:
                handle.write(files[name])
                handle.flush()
                os.fsync(handle.fileno())
            output.chmod(0o755 if name in BINARIES else 0o644)
    except (KeyError, OSError) as error:
        shutil.rmtree(destination, ignore_errors=True)
        raise InstallError(f"installation did not complete: {error}") from error


def parse_args(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version", required=True, help="exact version without a v prefix"
    )
    parser.add_argument(
        "--architecture",
        choices=sorted({value for value in ARCHITECTURE_ALIASES.values()}),
        help="release architecture; defaults to the current machine",
    )
    parser.add_argument(
        "--destination",
        required=True,
        type=Path,
        help="absolute path that must not exist",
    )
    parser.add_argument(
        "--archive",
        type=Path,
        help="verify this local archive instead of downloading it",
    )
    return parser.parse_args(arguments)


def run(arguments: list[str]) -> dict[str, object]:
    options = parse_args(arguments)
    architecture, release = select_release(options.version, options.architecture)
    name = archive_name(options.version, release)

    with tempfile.TemporaryDirectory(prefix="proofbound-runtime-install.") as temporary:
        if options.archive is None:
            archive = Path(temporary) / name
            download_archive(
                f"{REPOSITORY}/releases/download/v{options.version}/{name}", archive
            )
        else:
            archive = options.archive
            if not archive.is_file():
                raise InstallError(f"archive is not a regular file: {archive}")
        archive_digest = verify_archive_digest(archive, release.archive_sha256)
        files = inspect_archive(archive, options.version, architecture, release)
        install_files(files, options.destination)

    return {
        "architecture": architecture,
        "archive_sha256": archive_digest,
        "destination": str(options.destination),
        "schema": RESULT_SCHEMA,
        "version": options.version,
    }


def main() -> int:
    try:
        result = run(sys.argv[1:])
    except InstallError as error:
        print(f"installation failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
