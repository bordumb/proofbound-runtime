import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.release.verify_registry_packages import RegistryError, observe


REVISION = "12" * 20
VERSION = "0.2.0"


class RegistryPackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sdk = self.root / "sdk"
        self.verifier = self.root / "verifier"
        self.sdk.mkdir()
        self.verifier.mkdir()
        self.bytes = {
            f"proofbound-runtime-sdk-{VERSION}.crate": b"rust sdk",
            f"proofbound-runtime-sdk-{VERSION}.tgz": b"npm sdk",
            f"proofbound_runtime_sdk-{VERSION}-py3-none-any.whl": b"python sdk",
            f"proofbound-runtime-verify-{VERSION}.crate": b"verifier",
        }
        for name, data in self.bytes.items():
            directory = self.verifier if "verify" in name else self.sdk
            (directory / name).write_bytes(data)
        sdk_artifacts = [
            {
                "name": name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
            for name, data in sorted(self.bytes.items())
            if "verify" not in name
        ]
        (self.sdk / "SDK-MANIFEST.json").write_text(
            json.dumps(
                {
                    "artifacts": sdk_artifacts,
                    "schema": "proofbound-runtime-sdk-manifest/1",
                    "source_revision": REVISION,
                    "version": VERSION,
                }
            )
        )
        verifier_name = f"proofbound-runtime-verify-{VERSION}.crate"
        verifier_bytes = self.bytes[verifier_name]
        (self.verifier / "VERIFIER-PACKAGE-MANIFEST.projection.json").write_text(
            json.dumps(
                {
                    "artifacts": [
                        {
                            "name": verifier_name,
                            "sha256": f"hex:{hashlib.sha256(verifier_bytes).hexdigest()}",
                            "size": str(len(verifier_bytes)),
                        }
                    ],
                    "schema": "proofbound-runtime-verifier-package-manifest/1",
                    "source_revision": REVISION,
                    "version": VERSION,
                }
            )
        )

    def tearDown(self):
        self.temporary.cleanup()

    def registry(self):
        wheel = f"proofbound_runtime_sdk-{VERSION}-py3-none-any.whl"
        npm = f"proofbound-runtime-sdk-{VERSION}.tgz"
        mapping = {
            f"https://pypi.org/pypi/proofbound-runtime-sdk/{VERSION}/json": json.dumps(
                {
                    "urls": [
                        {
                            "filename": wheel,
                            "url": f"https://files.pythonhosted.org/packages/{wheel}",
                        }
                    ]
                }
            ).encode(),
            f"https://registry.npmjs.org/%40proofbound%2Fruntime-sdk/{VERSION}": json.dumps(
                {
                    "dist": {
                        "tarball": (
                            "https://registry.npmjs.org/@proofbound/runtime-sdk/-/"
                            f"{npm}"
                        )
                    }
                }
            ).encode(),
            (
                "https://static.crates.io/crates/proofbound-runtime-verify/"
                f"proofbound-runtime-verify-{VERSION}.crate"
            ): self.bytes[f"proofbound-runtime-verify-{VERSION}.crate"],
            (
                "https://static.crates.io/crates/proofbound-runtime-sdk/"
                f"proofbound-runtime-sdk-{VERSION}.crate"
            ): self.bytes[f"proofbound-runtime-sdk-{VERSION}.crate"],
            f"https://files.pythonhosted.org/packages/{wheel}": self.bytes[wheel],
            (
                "https://registry.npmjs.org/@proofbound/runtime-sdk/-/"
                f"{npm}"
            ): self.bytes[npm],
        }

        def fetch(url, maximum):
            data = mapping[url]
            if len(data) > maximum:
                raise RegistryError("test response exceeds the byte bound")
            return data

        return fetch

    def test_all_four_registry_artifacts_must_match_approved_bytes(self):
        result = observe(
            sdk_directory=self.sdk,
            verifier_directory=self.verifier,
            expected_revision=REVISION,
            fetch=self.registry(),
        )
        self.assertEqual(result["schema"], "proofbound-runtime-registry-observations/1")
        self.assertEqual(result["source_revision"], REVISION)
        self.assertEqual(len(result["observations"]), 4)
        self.assertEqual(
            [(item["ecosystem"], item["package"]) for item in result["observations"]],
            [
                ("crates.io", "proofbound-runtime-sdk"),
                ("npm", "@proofbound/runtime-sdk"),
                ("pypi", "proofbound-runtime-sdk"),
                ("crates.io", "proofbound-runtime-verify"),
            ],
        )

    def test_registry_substitution_fails_closed(self):
        clean = self.registry()

        def substituted(url, maximum):
            data = clean(url, maximum)
            if "static.crates.io/crates/proofbound-runtime-verify" in url:
                return b"substitute"
            return data

        with self.assertRaisesRegex(RegistryError, "registry bytes differ"):
            observe(
                sdk_directory=self.sdk,
                verifier_directory=self.verifier,
                expected_revision=REVISION,
                fetch=substituted,
            )

    def test_manifest_revision_and_registry_hosts_are_closed(self):
        sdk_manifest = self.sdk / "SDK-MANIFEST.json"
        value = json.loads(sdk_manifest.read_bytes())
        value["source_revision"] = "34" * 20
        sdk_manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(RegistryError, "source revision"):
            observe(
                sdk_directory=self.sdk,
                verifier_directory=self.verifier,
                expected_revision=REVISION,
                fetch=self.registry(),
            )


if __name__ == "__main__":
    unittest.main()
