#!/usr/bin/env python3
"""Build the dependency-free TypeScript SDK npm tarball reproducibly."""

from __future__ import annotations

import argparse
import gzip
import io
import os
from pathlib import Path
import tarfile


VERSION = "0.2.0"
ARTIFACT = f"proofbound-runtime-sdk-{VERSION}.tgz"
SOURCE_DATE_EPOCH = 315_532_800
MEMBERS = (
    ("package/README.md", "sdk/typescript/README.md"),
    ("package/package.json", "sdk/typescript/package.json"),
    ("package/src/index.d.ts", "sdk/typescript/src/index.d.ts"),
    ("package/src/index.ts", "sdk/typescript/src/index.ts"),
)


def build(repository: Path, output_directory: Path, epoch: int) -> Path:
    output_directory.mkdir(parents=True, exist_ok=True)
    artifact = output_directory / ARTIFACT
    descriptor = os.open(artifact, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as destination:
        with gzip.GzipFile(filename="", mode="wb", fileobj=destination, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for archive_name, source_name in MEMBERS:
                    data = (repository / source_name).read_bytes()
                    member = tarfile.TarInfo(archive_name)
                    member.size = len(data)
                    member.mode = 0o644
                    member.uid = 0
                    member.gid = 0
                    member.uname = ""
                    member.gname = ""
                    member.mtime = epoch
                    archive.addfile(member, io.BytesIO(data))
    return artifact


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-date-epoch", type=int, default=SOURCE_DATE_EPOCH)
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    artifact = build(repository, arguments.output.resolve(), arguments.source_date_epoch)
    print(artifact)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
