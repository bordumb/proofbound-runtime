#!/usr/bin/env python3
"""Build the dependency-free Proofbound Runtime SDK wheel reproducibly."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
from pathlib import Path
import time
import zipfile


VERSION = "0.2.0"
ARTIFACT = f"proofbound_runtime_sdk-{VERSION}-py3-none-any.whl"
DIST_INFO = f"proofbound_runtime_sdk-{VERSION}.dist-info"
SOURCE_DATE_EPOCH = 315_532_800


def _metadata() -> bytes:
    return (
        "Metadata-Version: 2.1\n"
        "Name: proofbound-runtime-sdk\n"
        f"Version: {VERSION}\n"
        "Summary: Plan construction and run-result decoding for Proofbound Runtime\n"
        "License: MIT\n"
        "Requires-Python: >=3.10\n"
        "Project-URL: Repository, https://github.com/bordumb/proofbound-runtime\n"
        "\n"
    ).encode()


def _wheel_metadata() -> bytes:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: proofbound-runtime-sdk-wheel/1\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
        "\n"
    ).encode()


def _digest(data: bytes) -> str:
    value = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + value.decode("ascii")


def _record(entries: list[tuple[str, bytes]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    for name, data in entries:
        writer.writerow((name, _digest(data), len(data)))
    writer.writerow((f"{DIST_INFO}/RECORD", "", ""))
    return stream.getvalue().encode()


def _zip_info(name: str, epoch: int) -> zipfile.ZipInfo:
    moment = time.gmtime(max(epoch, SOURCE_DATE_EPOCH))
    info = zipfile.ZipInfo(name, moment[:6])
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def build(repository: Path, output_directory: Path, epoch: int) -> Path:
    package = repository / "sdk/python/proofbound_runtime/__init__.py"
    entries = [
        ("proofbound_runtime/__init__.py", package.read_bytes()),
        (f"{DIST_INFO}/METADATA", _metadata()),
        (f"{DIST_INFO}/WHEEL", _wheel_metadata()),
        (f"{DIST_INFO}/top_level.txt", b"proofbound_runtime\n"),
    ]
    entries.append((f"{DIST_INFO}/RECORD", _record(entries)))
    output_directory.mkdir(parents=True, exist_ok=True)
    artifact = output_directory / ARTIFACT
    with artifact.open("xb") as destination:
        with zipfile.ZipFile(destination, "w", strict_timestamps=True) as archive:
            for name, data in entries:
                archive.writestr(_zip_info(name, epoch), data, compresslevel=9)
    return artifact


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=int, default=SOURCE_DATE_EPOCH)
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    artifact = build(repository, arguments.output.resolve(), arguments.source_date_epoch)
    print(artifact)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
