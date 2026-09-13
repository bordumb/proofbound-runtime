#!/usr/bin/env python3
"""Check the public verifier package preflight and retained package bytes."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from tools.release import build_verifier_package as package


ROOT = Path(__file__).resolve().parents[2]
ATTACKS = ROOT / "tests/attacks/distribution/verifier-package-v1.toml"


class VerifierPackagePreflightTests(unittest.TestCase):
    def fixture(self, directory: str) -> Path:
        root = Path(directory)
        shutil.copy2(ROOT / "Cargo.toml", root / "Cargo.toml")
        shutil.copy2(ROOT / "VERSION", root / "VERSION")
        crate = root / package.CRATE
        crate.parent.mkdir(parents=True)
        shutil.copytree(ROOT / package.CRATE, crate)
        schemas = root / "schemas"
        schemas.mkdir()
        for name in (
            "verifier-package-manifest-v1.schema.json",
            "verifier-package-preflight-v1.schema.json",
        ):
            shutil.copy2(ROOT / "schemas" / name, schemas / name)
        return root

    def assert_failure(
        self,
        root: Path,
        expected: package.FailureCode,
    ) -> None:
        with self.assertRaises(package.PackageError) as raised:
            package.preflight(root)
        self.assertEqual(raised.exception.code, expected.value)

    def test_selected_verifier_manifest_passes_the_closed_preflight(self) -> None:
        self.assertEqual(package.preflight(ROOT), "0.2.0")

    def test_machine_manifests_have_closed_registered_schemas(self) -> None:
        expected = {
            "verifier-package-manifest-v1.schema.json": (
                package.PACKAGE_MANIFEST_SCHEMA,
                {"additionalProperties": False},
            ),
            "verifier-package-preflight-v1.schema.json": (
                package.PREFLIGHT_SCHEMA,
                {"additionalProperties": False},
            ),
        }
        for name, (schema_identity, closed) in expected.items():
            with self.subTest(schema=name):
                schema = json.loads((ROOT / "schemas" / name).read_bytes())
                self.assertEqual(
                    schema["properties"]["schema"]["const"],
                    schema_identity,
                )
                self.assertEqual(
                    {"additionalProperties": schema["additionalProperties"]},
                    closed,
                )

    def test_attack_catalog_is_closed(self) -> None:
        source = ATTACKS.read_text(encoding="utf-8")
        observed = [
            line.split('"', 2)[1]
            for line in source.splitlines()
            if line.startswith("id = ")
        ]
        self.assertEqual(
            observed,
            [
                "publication-disabled",
                "metadata-omission",
                "workspace-dependency",
                "path-dependency",
                "source-file-injection",
                "version-substitution",
                "source-revision-substitution",
                "archive-file-injection",
                "archive-source-substitution",
                "reproduction-drift",
                "unreviewed-registry-publication",
            ],
        )

    def test_first_slice_has_no_registry_publication_route(self) -> None:
        builder = (ROOT / "tools/release/build_verifier_package.py").read_text(
            encoding="utf-8"
        )
        sources = [
            (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"),
            builder,
        ]
        for source in sources:
            self.assertNotIn("cargo publish", source)
            self.assertNotIn("npm publish", source)
            self.assertNotIn("twine upload", source)
        self.assertGreaterEqual(builder.count('"--offline"'), 2)

    def test_publication_inheritance_or_denial_is_rejected(self) -> None:
        for replacement in ("publish.workspace = true", "publish = false"):
            with self.subTest(replacement=replacement):
                with tempfile.TemporaryDirectory() as directory:
                    root = self.fixture(directory)
                    manifest = root / package.CRATE / "Cargo.toml"
                    source = manifest.read_text(encoding="utf-8")
                    manifest.write_text(
                        source.replace('publish = ["crates-io"]', replacement),
                        encoding="utf-8",
                    )
                    self.assert_failure(
                        root,
                        package.FailureCode.PUBLICATION_DISABLED,
                    )

    def test_missing_public_metadata_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            manifest = root / package.CRATE / "Cargo.toml"
            source = manifest.read_text(encoding="utf-8")
            manifest.write_text(
                source.replace("description = ", "unregistered-description = "),
                encoding="utf-8",
            )
            self.assert_failure(root, package.FailureCode.MANIFEST_METADATA)

    def test_runtime_workspace_dependency_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            manifest = root / package.CRATE / "Cargo.toml"
            source = manifest.read_text(encoding="utf-8")
            manifest.write_text(
                source.replace(
                    "[dependencies]\n",
                    "[dependencies]\nproofbound-runtime-core.workspace = true\n",
                ),
                encoding="utf-8",
            )
            self.assert_failure(root, package.FailureCode.WORKSPACE_DEPENDENCY)

    def test_aliased_runtime_workspace_dependency_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            workspace = root / "Cargo.toml"
            workspace_source = workspace.read_text(encoding="utf-8")
            workspace.write_text(
                workspace_source.replace(
                    "[workspace.dependencies]\n",
                    "[workspace.dependencies]\n"
                    'verifier-helper = { package = "proofbound-runtime-core", '
                    'path = "crates/proofbound-runtime-core" }\n',
                ),
                encoding="utf-8",
            )
            manifest = root / package.CRATE / "Cargo.toml"
            manifest_source = manifest.read_text(encoding="utf-8")
            manifest.write_text(
                manifest_source.replace(
                    "[dependencies]\n",
                    "[dependencies]\nverifier-helper.workspace = true\n",
                ),
                encoding="utf-8",
            )
            self.assert_failure(root, package.FailureCode.WORKSPACE_DEPENDENCY)

    def test_local_path_dependency_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            manifest = root / package.CRATE / "Cargo.toml"
            source = manifest.read_text(encoding="utf-8")
            manifest.write_text(
                source.replace(
                    "[dependencies]\n",
                    '[dependencies]\nhelper = { path = "../helper", version = "1" }\n',
                ),
                encoding="utf-8",
            )
            self.assert_failure(root, package.FailureCode.PATH_DEPENDENCY)

    def test_undeclared_source_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            injected = root / package.CRATE / "src/injected.rs"
            injected.write_text("pub fn injected() {}\n", encoding="utf-8")
            self.assert_failure(root, package.FailureCode.SOURCE_INVENTORY)

    def test_workspace_and_product_version_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / "VERSION").write_text("0.2.1\n", encoding="ascii")
            self.assert_failure(root, package.FailureCode.VERSION_MISMATCH)

    def test_source_revision_substitution_is_rejected_before_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / "Cargo.lock").write_bytes((ROOT / "Cargo.lock").read_bytes())
            (root / "tools/release").mkdir(parents=True)
            shutil.copy2(
                ROOT / "tools/release/build_verifier_package.py",
                root / "tools/release/build_verifier_package.py",
            )
            with self.assertRaises(package.PackageError) as raised:
                package.build(root, root / "output", "0" * 40)
            self.assertEqual(
                raised.exception.code,
                package.FailureCode.SOURCE_REVISION.value,
            )

    def test_archive_file_injection_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "attacked.crate"
            content = b"injected"
            info = tarfile.TarInfo(
                "proofbound-runtime-verify-0.2.0/src/injected.rs"
            )
            info.size = len(content)
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.addfile(info, io.BytesIO(content))
            with self.assertRaises(package.PackageError) as raised:
                package._validate_archive(root, archive_path)
            self.assertEqual(
                raised.exception.code,
                package.FailureCode.PACKAGE_INVENTORY.value,
            )

    def test_archive_source_substitution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            archive_path = (
                root / "proofbound-runtime-verify-0.2.0.crate"
            )
            archive_root = archive_path.name.removesuffix(".crate")
            with tarfile.open(archive_path, "w:gz") as archive:
                for relative in package._expected_archive_inventory(root):
                    content = b""
                    if relative in package.PACKAGE_PAYLOAD_FILES:
                        content = (root / package.CRATE / relative).read_bytes()
                    if relative == "src/lib.rs":
                        content += b"\n// substituted package bytes\n"
                    info = tarfile.TarInfo(f"{archive_root}/{relative}")
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
            with self.assertRaises(package.PackageError) as raised:
                package._validate_archive(root, archive_path)
            self.assertEqual(
                raised.exception.code,
                package.FailureCode.PACKAGE_PAYLOAD.value,
            )

    def test_reproduction_drift_is_rejected_before_dogfood(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / "Cargo.lock").write_bytes((ROOT / "Cargo.lock").read_bytes())
            (root / "tools/release").mkdir(parents=True)
            shutil.copy2(
                ROOT / "tools/release/build_verifier_package.py",
                root / "tools/release/build_verifier_package.py",
            )
            output = root / "output"
            with mock.patch.object(
                package,
                "_build_once",
                side_effect=[b"first", b"second"],
            ):
                with self.assertRaises(package.PackageError) as raised:
                    package.build(root, output)
            self.assertEqual(
                raised.exception.code,
                package.FailureCode.REPRODUCTION.value,
            )


class VerifierPackageArtifactTests(unittest.TestCase):
    def test_release_package_is_reproducible_closed_and_consumable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(
                [
                    sys.executable,
                    "tools/release/build_verifier_package.py",
                    "--output",
                    directory,
                ],
                cwd=ROOT,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            output = Path(directory)
            archive_name = "proofbound-runtime-verify-0.2.0.crate"
            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                [
                    "SHA256SUMS",
                    "VERIFIER-PACKAGE-MANIFEST.json",
                    archive_name,
                ],
            )
            archive = output / archive_name
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            manifest = json.loads(
                (output / "VERIFIER-PACKAGE-MANIFEST.json").read_bytes()
            )
            self.assertEqual(
                set(manifest),
                {
                    "artifacts",
                    "binary",
                    "package",
                    "schema",
                    "source_revision",
                    "supported_receipt_schemas",
                    "version",
                },
            )
            self.assertEqual(manifest["schema"], package.PACKAGE_MANIFEST_SCHEMA)
            self.assertEqual(manifest["package"], package.PACKAGE_NAME)
            self.assertEqual(manifest["binary"], package.PACKAGE_BINARY)
            self.assertEqual(manifest["version"], "0.2.0")
            self.assertEqual(
                manifest["supported_receipt_schemas"],
                package.SUPPORTED_RECEIPT_SCHEMAS,
            )
            self.assertEqual(
                manifest["artifacts"],
                [
                    {
                        "name": archive_name,
                        "sha256": digest,
                        "size": archive.stat().st_size,
                    }
                ],
            )
            self.assertRegex(
                manifest["source_revision"],
                r"^(?:[0-9a-f]{40}|tree-sha256:[0-9a-f]{64})$",
            )
            self.assertEqual(
                (output / "SHA256SUMS").read_text(encoding="ascii"),
                f"{digest}  {archive_name}\n",
            )
            package._validate_archive(ROOT, archive)


if __name__ == "__main__":
    unittest.main()
