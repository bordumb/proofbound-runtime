#!/usr/bin/env python3
"""Check the SDK package inventories and reproducible wheel bytes."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
WHEEL = "proofbound_runtime_sdk-0.2.0-py3-none-any.whl"
DIST_INFO = "proofbound_runtime_sdk-0.2.0.dist-info"


class SdkPackageTests(unittest.TestCase):
    def test_release_sdk_bundle_is_reproducible_and_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(
                [
                    "python3",
                    "tools/release/build_sdks.py",
                    "--output",
                    directory,
                ],
                cwd=ROOT,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            output = Path(directory)
            expected = [
                "SDK-MANIFEST.json",
                "SHA256SUMS",
                "proofbound-runtime-sdk-0.2.0.crate",
                "proofbound-runtime-sdk-0.2.0.tgz",
                "proofbound_runtime_sdk-0.2.0-py3-none-any.whl",
            ]
            self.assertEqual(sorted(path.name for path in output.iterdir()), expected)
            manifest = json.loads((output / "SDK-MANIFEST.json").read_bytes())
            self.assertEqual(manifest["schema"], "proofbound-runtime-sdk-manifest/1")
            self.assertEqual(manifest["version"], "0.2.0")
            self.assertEqual(
                [artifact["name"] for artifact in manifest["artifacts"]],
                expected[2:],
            )
            sums = (output / "SHA256SUMS").read_text(encoding="ascii").splitlines()
            self.assertEqual([line.split("  ", 1)[1] for line in sums], expected[2:])

    def test_rust_sdk_is_independently_packageable(self) -> None:
        manifest = (
            ROOT / "crates/proofbound-runtime-sdk/Cargo.toml"
        ).read_text(encoding="utf-8")

        self.assertIn("publish = true", manifest)
        self.assertNotIn("proofbound-runtime-core", manifest)
        result = subprocess.run(
            [
                "cargo",
                "package",
                "--locked",
                "--allow-dirty",
                "--no-verify",
                "--list",
                "-p",
                "proofbound-runtime-sdk",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.stdout.splitlines(),
            [
                ".cargo_vcs_info.json",
                "Cargo.lock",
                "Cargo.toml",
                "Cargo.toml.orig",
                "src/lib.rs",
            ],
        )

    def test_python_wheel_is_reproducible_and_closed(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            artifacts = []
            for directory in (first, second):
                subprocess.run(
                    [
                        "python3",
                        "tools/sdk/build_python_wheel.py",
                        "--output",
                        directory,
                    ],
                    cwd=ROOT,
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
                artifacts.append((Path(directory) / WHEEL).read_bytes())
            self.assertEqual(artifacts[0], artifacts[1])

            with zipfile.ZipFile(io.BytesIO(artifacts[0])) as archive:
                expected = [
                    "proofbound_runtime/__init__.py",
                    f"{DIST_INFO}/METADATA",
                    f"{DIST_INFO}/WHEEL",
                    f"{DIST_INFO}/top_level.txt",
                    f"{DIST_INFO}/RECORD",
                ]
                self.assertEqual(archive.namelist(), expected)
                metadata = archive.read(f"{DIST_INFO}/METADATA")
                self.assertIn(b"Name: proofbound-runtime-sdk\n", metadata)
                self.assertIn(b"Version: 0.2.0\n", metadata)
                rows = list(
                    csv.reader(
                        io.StringIO(archive.read(f"{DIST_INFO}/RECORD").decode())
                    )
                )
                self.assertEqual([row[0] for row in rows], expected)
                for name, digest, size in rows[:-1]:
                    content = archive.read(name)
                    actual = base64.urlsafe_b64encode(
                        hashlib.sha256(content).digest()
                    ).rstrip(b"=").decode()
                    self.assertEqual(digest, "sha256=" + actual)
                    self.assertEqual(size, str(len(content)))
                self.assertEqual(rows[-1][1:], ["", ""])

    def test_typescript_package_inventory_is_closed(self) -> None:
        result = subprocess.run(
            ["npm", "pack", "--dry-run", "--json"],
            cwd=ROOT / "sdk/typescript",
            check=True,
            capture_output=True,
            text=True,
        )
        package = json.loads(result.stdout)[0]
        self.assertEqual(package["filename"], "proofbound-runtime-sdk-0.2.0.tgz")
        self.assertEqual(
            [entry["path"] for entry in package["files"]],
            ["README.md", "package.json", "src/index.d.ts", "src/index.ts"],
        )

    def test_typescript_tarball_is_reproducible_and_closed(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            artifacts = []
            for directory in (first, second):
                subprocess.run(
                    [
                        "python3",
                        "tools/sdk/build_npm_package.py",
                        "--output",
                        directory,
                    ],
                    cwd=ROOT,
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
                artifact = Path(directory) / "proofbound-runtime-sdk-0.2.0.tgz"
                artifacts.append(artifact.read_bytes())
                with tarfile.open(artifact, "r:gz") as archive:
                    self.assertEqual(
                        archive.getnames(),
                        [
                            "package/README.md",
                            "package/package.json",
                            "package/src/index.d.ts",
                            "package/src/index.ts",
                        ],
                    )
                    self.assertTrue(all(member.isfile() for member in archive))
            self.assertEqual(artifacts[0], artifacts[1])


if __name__ == "__main__":
    unittest.main()
