#!/usr/bin/env python3
"""Build and byte-compare the three Proofbound Runtime SDK packages."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


RUST_NAME = "proofbound-runtime-sdk-{version}.crate"
PYTHON_NAME = "proofbound_runtime_sdk-{version}-py3-none-any.whl"
NPM_NAME = "proofbound-runtime-sdk-{version}.tgz"
SDK_SOURCE_FILES = (
    "Cargo.lock",
    "Cargo.toml",
    "VERSION",
    "crates/proofbound-runtime-sdk/Cargo.toml",
    "crates/proofbound-runtime-sdk/src/lib.rs",
    "sdk/python/README.md",
    "sdk/python/proofbound_runtime/__init__.py",
    "sdk/python/pyproject.toml",
    "sdk/typescript/README.md",
    "sdk/typescript/package.json",
    "sdk/typescript/src/index.d.ts",
    "sdk/typescript/src/index.ts",
    "tools/release/build_sdks.py",
    "tools/sdk/build_npm_package.py",
    "tools/sdk/build_python_wheel.py",
)


def run(arguments: list[str], *, cwd: Path) -> None:
    subprocess.run(
        arguments,
        cwd=cwd,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )


def build_once(repository: Path, work: Path, version: str) -> dict[str, bytes]:
    rust_target = work / "rust"
    python_output = work / "python"
    npm_output = work / "npm"
    python_output.mkdir()
    npm_output.mkdir()

    run(
        [
            "cargo",
            "package",
            "--locked",
            "--allow-dirty",
            "--no-verify",
            "-p",
            "proofbound-runtime-sdk",
            "--target-dir",
            str(rust_target),
        ],
        cwd=repository,
    )
    run(
        [
            sys.executable,
            "tools/sdk/build_python_wheel.py",
            "--output",
            str(python_output),
        ],
        cwd=repository,
    )
    run(
        [
            sys.executable,
            "tools/sdk/build_npm_package.py",
            "--output",
            str(npm_output),
        ],
        cwd=repository,
    )

    paths = {
        RUST_NAME.format(version=version): (
            rust_target / "package" / RUST_NAME.format(version=version)
        ),
        NPM_NAME.format(version=version): npm_output / NPM_NAME.format(version=version),
        PYTHON_NAME.format(version=version): (
            python_output / PYTHON_NAME.format(version=version)
        ),
    }
    return {name: path.read_bytes() for name, path in sorted(paths.items())}


def write_exclusive(path: Path, data: bytes, mode: int = 0o644) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(data)


def source_revision(repository: Path) -> str:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )
    if revision.returncode == 0:
        value = revision.stdout.strip()
        if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
            raise ValueError(f"invalid Git source revision: {value!r}")
        return value

    digest = hashlib.sha256(b"proofbound-runtime-sdk-source-tree/1\0")
    for relative_name in SDK_SOURCE_FILES:
        relative = relative_name.encode("utf-8")
        content = (repository / relative_name).read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"tree-sha256:{digest.hexdigest()}"


def build(repository: Path, output: Path) -> None:
    version = (repository / "VERSION").read_text(encoding="ascii").strip()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError(f"SDK output directory is not empty: {output}")
    target = repository / "target"
    target.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sdk-release.", dir=target) as first_root:
        with tempfile.TemporaryDirectory(prefix="sdk-release.", dir=target) as second_root:
            first = build_once(repository, Path(first_root), version)
            second = build_once(repository, Path(second_root), version)
    if first != second:
        mismatches = sorted(name for name in first if first[name] != second.get(name))
        raise ValueError(f"SDK package reproduction mismatch: {mismatches}")

    artifacts = []
    sums = []
    for name, data in first.items():
        digest = hashlib.sha256(data).hexdigest()
        write_exclusive(output / name, data)
        artifacts.append({"name": name, "sha256": digest, "size": len(data)})
        sums.append(f"{digest}  {name}\n")
    manifest = {
        "artifacts": artifacts,
        "schema": "proofbound-runtime-sdk-manifest/1",
        "source_revision": source_revision(repository),
        "version": version,
    }
    write_exclusive(
        output / "SDK-MANIFEST.json",
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n",
    )
    write_exclusive(output / "SHA256SUMS", "".join(sums).encode("ascii"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    try:
        build(repository, arguments.output.resolve())
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"SDK release build failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
