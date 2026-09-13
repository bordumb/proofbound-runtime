#!/usr/bin/env python3
"""Falsify the aggregate release-provenance producer and verifier boundary."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.ci.deterministic_cbor import decode_strict


ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "tools/release/build_provenance.py"
VERIFIER = ROOT / "tools/release/verify_provenance.py"
REVISION = "00112233445566778899aabbccddeeff00112233"


class ReleaseProvenanceTests(unittest.TestCase):
    def test_producer_and_independent_verifier_close_the_asset_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdk = root / "sdk"
            native = root / "x86_64"
            sdk.mkdir()
            (native / "runtime").mkdir(parents=True)
            (sdk / "package.crate").write_bytes(b"crate")
            (native / "runtime/bundle.tar.gz").write_bytes(b"runtime")
            provenance = root / "release-provenance.cbor"
            projection = root / "release-provenance.projection.json"
            roots = [f"sdk={sdk}", f"x86_64={native}"]

            subprocess.run(
                [
                    sys.executable,
                    str(BUILDER),
                    "--revision",
                    REVISION,
                    "--artifact-root",
                    roots[1],
                    "--artifact-root",
                    roots[0],
                    "--output",
                    str(provenance),
                ],
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    str(VERIFIER),
                    "--provenance",
                    str(provenance),
                    "--expected-revision",
                    REVISION,
                    "--artifact-root",
                    roots[0],
                    "--artifact-root",
                    roots[1],
                    "--projection",
                    str(projection),
                ],
                check=True,
            )

            decoded = decode_strict(provenance.read_bytes())
            self.assertEqual(decoded["schema"], "proofbound-runtime-release-provenance/2")
            self.assertEqual(decoded["source_revision"], bytes.fromhex(REVISION))
            self.assertEqual(
                [artifact["logical_name"] for artifact in decoded["artifacts"]],
                ["sdk/package.crate", "x86_64/runtime/bundle.tar.gz"],
            )
            self.assertEqual(
                decoded["artifacts"][0],
                {
                    "logical_name": "sdk/package.crate",
                    "sha256": hashlib.sha256(b"crate").digest(),
                    "size_bytes": 5,
                },
            )
            self.assertEqual(
                json.loads(projection.read_bytes())["source_revision"],
                f"hex:{REVISION}",
            )

            (sdk / "package.crate").write_bytes(b"substituted")
            rejected = subprocess.run(
                [
                    sys.executable,
                    str(VERIFIER),
                    "--provenance",
                    str(provenance),
                    "--expected-revision",
                    REVISION,
                    "--artifact-root",
                    roots[0],
                    "--artifact-root",
                    roots[1],
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("release provenance verification failed", rejected.stderr)

    def test_verifier_does_not_import_the_producer_codec(self) -> None:
        verifier = VERIFIER.read_text(encoding="utf-8")
        self.assertNotIn("build_provenance", verifier)
        self.assertIn("class _Decoder:", verifier)
        self.assertIn("def decode_strict(", verifier)


if __name__ == "__main__":
    unittest.main()
