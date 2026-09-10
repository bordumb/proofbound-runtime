from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.release.build_example import (
    MANIFEST_SCHEMA,
    SOURCE_DATE_EPOCH,
    SOURCE_FILES,
    BundleError,
    bundle_bytes,
    publish_bundle,
)

VERSION = "9.8.7"


def sources() -> dict[str, bytes]:
    return {name: f"fixture for {name}\n".encode() for name in SOURCE_FILES}


class BuildExampleTests(unittest.TestCase):
    def test_bundle_is_deterministic_closed_and_self_describing(self) -> None:
        first = bundle_bytes(VERSION, sources())
        second = bundle_bytes(VERSION, sources())
        self.assertEqual(first, second)

        prefix = f"proofbound-runtime-example-v{VERSION}"
        with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as archive:
            members = archive.getmembers()
            self.assertEqual(
                [member.name for member in members],
                [
                    f"{prefix}/EXAMPLE-MANIFEST.json",
                    *(f"{prefix}/{name}" for name in SOURCE_FILES),
                ],
            )
            for member in members:
                self.assertTrue(member.isfile())
                self.assertEqual(member.mtime, SOURCE_DATE_EPOCH)
                self.assertEqual(member.uid, 0)
                self.assertEqual(member.gid, 0)
                expected_mode = (
                    0o755 if member.name.endswith("/run-example.sh") else 0o644
                )
                self.assertEqual(member.mode, expected_mode)
            manifest_member = archive.extractfile(members[0])
            self.assertIsNotNone(manifest_member)
            manifest = json.loads(manifest_member.read())

        expected_sources = sources()
        self.assertEqual(set(manifest), {"files", "schema", "version"})
        self.assertEqual(manifest["schema"], MANIFEST_SCHEMA)
        self.assertEqual(manifest["version"], VERSION)
        self.assertEqual(
            manifest["files"],
            [
                {
                    "name": name,
                    "sha256": hashlib.sha256(expected_sources[name]).hexdigest(),
                    "size": len(expected_sources[name]),
                }
                for name in SOURCE_FILES
            ],
        )

    def test_source_inventory_is_exact_and_ordered(self) -> None:
        missing = sources()
        missing.pop("hello.c")
        with self.assertRaisesRegex(BundleError, "inventory"):
            bundle_bytes(VERSION, missing)

        reordered = {name: sources()[name] for name in reversed(SOURCE_FILES)}
        with self.assertRaisesRegex(BundleError, "inventory"):
            bundle_bytes(VERSION, reordered)

    def test_publication_writes_matching_checksum_without_replacement(self) -> None:
        data = bundle_bytes(VERSION, sources())
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            target, digest = publish_bundle(output, VERSION, data)
            checksum = target.with_name(f"{target.name}.sha256")

            self.assertEqual(target.read_bytes(), data)
            self.assertEqual(digest, hashlib.sha256(data).hexdigest())
            self.assertEqual(checksum.read_text(), f"{digest}  {target.name}\n")
            with self.assertRaisesRegex(BundleError, "already exists"):
                publish_bundle(output, VERSION, data)

    def test_publication_requires_an_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            with self.assertRaisesRegex(BundleError, "not a directory"):
                publish_bundle(missing, VERSION, b"bundle")

    def test_publication_race_preserves_a_foreign_checksum(self) -> None:
        data = bundle_bytes(VERSION, sources())
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            name = f"proofbound-runtime-example-v{VERSION}.tar.gz"
            target = output / name
            checksum = output / f"{name}.sha256"
            real_link = __import__("os").link
            calls = 0

            def racing_link(source: Path, destination: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    real_link(source, destination)
                    return
                checksum.write_text("foreign checksum\n", encoding="utf-8")
                raise FileExistsError("simulated publication race")

            with mock.patch(
                "tools.release.build_example.os.link", side_effect=racing_link
            ):
                with self.assertRaisesRegex(BundleError, "publication failed"):
                    publish_bundle(output, VERSION, data)

            self.assertFalse(target.exists())
            self.assertEqual(checksum.read_text(), "foreign checksum\n")


if __name__ == "__main__":
    unittest.main()
