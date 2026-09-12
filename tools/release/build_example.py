#!/usr/bin/env python3
"""Build the deterministic source bundle for the maintained Runtime example."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import tempfile
from pathlib import Path

MANIFEST_SCHEMA = "proofbound-runtime-example-manifest/1"
RESULT_SCHEMA = "proofbound-runtime-example-bundle-result/1"
SOURCE_DATE_EPOCH = 946684800
SOURCE_FILES = ("README.md", "hello.c", "run-example.sh", "encode-plan-v2.py")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class BundleError(Exception):
    """Reports one fail-closed example packaging error."""


def file_identity(data: bytes) -> dict[str, object]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def load_sources(repository: Path) -> tuple[str, dict[str, bytes]]:
    try:
        version = (repository / "VERSION").read_text(encoding="utf-8").strip()
    except OSError as error:
        raise BundleError(f"version cannot be read: {error}") from error
    if VERSION_PATTERN.fullmatch(version) is None:
        raise BundleError(f"version is not an exact semantic version: {version!r}")
    source_root = repository / "examples" / "hello-static"
    source_paths = {
        "README.md": source_root / "README.md",
        "hello.c": source_root / "hello.c",
        "run-example.sh": source_root / "run-example.sh",
        "encode-plan-v2.py": repository / "tools" / "ci" / "encode_plan_v2.py",
    }
    files: dict[str, bytes] = {}
    for name in SOURCE_FILES:
        path = source_paths[name]
        try:
            data = path.read_bytes()
        except OSError as error:
            raise BundleError(
                f"example source cannot be read: {path}: {error}"
            ) from error
        if not data or len(data) > 1024 * 1024:
            raise BundleError(f"example source has an invalid size: {path}")
        files[name] = data
    return version, files


def bundle_bytes(version: str, sources: dict[str, bytes]) -> bytes:
    if tuple(sources) != SOURCE_FILES:
        raise BundleError("example source inventory is not closed or ordered")
    manifest = {
        "files": [
            {"name": name, **file_identity(sources[name])} for name in SOURCE_FILES
        ],
        "schema": MANIFEST_SCHEMA,
        "version": version,
    }
    files = {
        "EXAMPLE-MANIFEST.json": (
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        ),
        **sources,
    }
    prefix = f"proofbound-runtime-example-v{version}"
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", filename="", mtime=0) as zipped:
        with tarfile.open(
            fileobj=zipped, mode="w", format=tarfile.GNU_FORMAT
        ) as archive:
            for name, data in files.items():
                entry = tarfile.TarInfo(f"{prefix}/{name}")
                entry.size = len(data)
                entry.mode = (
                    0o755 if name in {"run-example.sh", "encode-plan-v2.py"} else 0o644
                )
                entry.mtime = SOURCE_DATE_EPOCH
                entry.uid = 0
                entry.gid = 0
                entry.uname = ""
                entry.gname = ""
                archive.addfile(entry, io.BytesIO(data))
    return compressed.getvalue()


def publish_bundle(
    output_directory: Path, version: str, data: bytes
) -> tuple[Path, str]:
    if not output_directory.is_dir():
        raise BundleError(f"output directory is not a directory: {output_directory}")
    name = f"proofbound-runtime-example-v{version}.tar.gz"
    target = output_directory / name
    checksum = output_directory / f"{name}.sha256"
    if target.exists() or checksum.exists():
        raise BundleError("example bundle or checksum already exists")
    digest = hashlib.sha256(data).hexdigest()
    with tempfile.TemporaryDirectory(
        prefix=".proofbound-example.", dir=output_directory
    ) as temporary:
        temporary_root = Path(temporary)
        temporary_bundle = temporary_root / name
        temporary_checksum = temporary_root / f"{name}.sha256"
        temporary_bundle.write_bytes(data)
        temporary_checksum.write_text(f"{digest}  {name}\n", encoding="utf-8")
        target_published = False
        checksum_published = False
        try:
            os.link(temporary_bundle, target)
            target_published = True
            os.link(temporary_checksum, checksum)
            checksum_published = True
        except OSError as error:
            if target_published:
                target.unlink(missing_ok=True)
            if checksum_published:
                checksum.unlink(missing_ok=True)
            raise BundleError(f"example bundle publication failed: {error}") from error
    return target, digest


def parse_args(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-directory",
        required=True,
        type=Path,
        help="existing directory in which bundle and checksum must not exist",
    )
    return parser.parse_args(arguments)


def run(arguments: list[str], repository: Path | None = None) -> dict[str, object]:
    options = parse_args(arguments)
    root = repository or Path(__file__).resolve().parents[2]
    version, sources = load_sources(root)
    target, digest = publish_bundle(
        options.output_directory.resolve(), version, bundle_bytes(version, sources)
    )
    return {
        "archive": str(target),
        "archive_sha256": digest,
        "schema": RESULT_SCHEMA,
        "version": version,
    }


def main() -> int:
    try:
        result = run(sys.argv[1:])
    except BundleError as error:
        print(f"example bundle failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
