from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from tools.install_release import (
    BINARIES,
    MANIFEST_SCHEMA,
    MEMBERS,
    InstallError,
    Release,
    inspect_archive,
    install_files,
    verify_archive_digest,
)

VERSION = "9.8.7"
ARCHITECTURE = "x86_64"
RELEASE = Release(target="x86_64-unknown-linux-gnu", archive_sha256="unused")


def bundle_files() -> dict[str, bytes]:
    files = {name: f"test bytes for {name}\n".encode() for name in BINARIES}
    manifest = {
        "architecture": ARCHITECTURE,
        "artifacts": [
            {
                "name": name,
                "sha256": hashlib.sha256(files[name]).hexdigest(),
                "size": len(files[name]),
            }
            for name in BINARIES
        ],
        "schema": MANIFEST_SCHEMA,
        "target": RELEASE.target,
        "toolchain": "rustc test",
        "version": VERSION,
    }
    return {
        "RELEASE-MANIFEST.json": (
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        ),
        **files,
    }


def write_archive(
    path: Path,
    files: dict[str, bytes],
    *,
    names: tuple[str, ...] = MEMBERS,
    symlink: str | None = None,
) -> None:
    with tarfile.open(path, mode="w:gz") as archive:
        for name in names:
            data = files.get(name, b"unexpected\n")
            entry = tarfile.TarInfo(name)
            if name == symlink:
                entry.type = tarfile.SYMTYPE
                entry.linkname = "pbr"
                entry.size = 0
                archive.addfile(entry)
            else:
                entry.mode = 0o644 if name == "RELEASE-MANIFEST.json" else 0o755
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))


class InstallReleaseTests(unittest.TestCase):
    def test_valid_archive_is_inspected_and_installed_without_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "release.tar.gz"
            expected = bundle_files()
            write_archive(archive, expected)

            files = inspect_archive(archive, VERSION, ARCHITECTURE, RELEASE)
            destination = root / "installed"
            install_files(files, destination)

            self.assertEqual(set(files), set(MEMBERS))
            for name in MEMBERS:
                self.assertEqual((destination / name).read_bytes(), expected[name])
            self.assertEqual((destination / "pbr").stat().st_mode & 0o777, 0o755)
            self.assertEqual(
                (destination / "RELEASE-MANIFEST.json").stat().st_mode & 0o777,
                0o644,
            )
            with self.assertRaisesRegex(InstallError, "destination already exists"):
                install_files(files, destination)

    def test_archive_digest_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "release.tar.gz"
            archive.write_bytes(b"not the expected archive")
            with self.assertRaisesRegex(InstallError, "archive digest mismatch"):
                verify_archive_digest(archive, "0" * 64)

    def test_extra_or_reordered_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "release.tar.gz"
            files = bundle_files()
            write_archive(archive, files, names=(*MEMBERS, "extra"))
            with self.assertRaisesRegex(InstallError, "archive inventory mismatch"):
                inspect_archive(archive, VERSION, ARCHITECTURE, RELEASE)

    def test_link_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "release.tar.gz"
            write_archive(archive, bundle_files(), symlink="pbr")
            with self.assertRaisesRegex(InstallError, "not a regular file"):
                inspect_archive(archive, VERSION, ARCHITECTURE, RELEASE)

    def test_artifact_identity_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "release.tar.gz"
            files = bundle_files()
            files["pbr"] = b"substituted bytes\n"
            write_archive(archive, files)
            with self.assertRaisesRegex(
                InstallError, "artifact identity mismatch: pbr"
            ):
                inspect_archive(archive, VERSION, ARCHITECTURE, RELEASE)

    def test_partial_installation_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "installed"
            files = bundle_files()
            del files["pbr-compose"]
            with self.assertRaisesRegex(InstallError, "installation did not complete"):
                install_files(files, destination)
            self.assertFalse(destination.exists())

    @unittest.skipIf(os.name == "nt", "mode assertion requires POSIX")
    def test_relative_destination_is_rejected(self) -> None:
        with self.assertRaisesRegex(InstallError, "absolute path"):
            install_files(bundle_files(), Path("relative"))


if __name__ == "__main__":
    unittest.main()
