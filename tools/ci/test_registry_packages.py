import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.release.verify_registry_packages import RegistryError, fetch_url, observe


REVISION = "12" * 20
VERSION = "0.2.0"
ROOT = Path(__file__).resolve().parents[2]


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
                    "binary": "pbr-verify",
                    "package": "proofbound-runtime-verify",
                    "schema": "proofbound-runtime-verifier-package-manifest/1",
                    "source_revision": REVISION,
                    "supported_receipt_schemas": [
                        "proofbound-runtime-receipt/1",
                        "proofbound-runtime-execution-receipt/2",
                    ],
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

    def test_registry_metadata_with_duplicate_members_fails_closed(self):
        clean = self.registry()

        def duplicate_metadata(url, maximum):
            if url.startswith("https://pypi.org/"):
                return b'{"urls":[],"urls":[]}'
            return clean(url, maximum)

        with self.assertRaisesRegex(RegistryError, "duplicate JSON member"):
            observe(
                sdk_directory=self.sdk,
                verifier_directory=self.verifier,
                expected_revision=REVISION,
                fetch=duplicate_metadata,
            )

    def test_registry_redirect_cannot_change_the_admitted_host(self):
        opened = []

        class RedirectingOpener:
            def __init__(self, handler):
                self.handler = handler

            def open(self, request, timeout):
                opened.append(request.full_url)
                redirected = "https://substitute.example/package"
                self.handler.redirect_request(
                    request,
                    None,
                    302,
                    "Found",
                    {},
                    redirected,
                )
                opened.append(redirected)
                raise AssertionError("the rejected redirect target was opened")

        with patch(
            "tools.release.verify_registry_packages.build_opener",
            side_effect=lambda handler: RedirectingOpener(handler),
        ):
            with self.assertRaisesRegex(RegistryError, "redirects are not admitted"):
                fetch_url("https://registry.example/package", 64)
        self.assertEqual(opened, ["https://registry.example/package"])

    def test_initial_registry_endpoint_rejects_port_credentials_and_fragment(self):
        for rejected in (
            "https://registry.example:444/package",
            "https://user@registry.example/package",
            "https://registry.example/package#substitute",
        ):
            with self.subTest(rejected=rejected):
                with patch(
                    "tools.release.verify_registry_packages.build_opener"
                ) as opener:
                    with self.assertRaisesRegex(RegistryError, "admitted HTTPS endpoint"):
                        fetch_url(rejected, 64)
                    opener.assert_not_called()

    def test_registry_metadata_cannot_select_port_or_credentials(self):
        clean = self.registry()

        for rejected in (
            "https://files.pythonhosted.org:444/package.whl",
            "https://user@files.pythonhosted.org/package.whl",
        ):
            with self.subTest(rejected=rejected):

                def substituted_metadata(url, maximum):
                    data = clean(url, maximum)
                    if url.startswith("https://pypi.org/"):
                        value = json.loads(data)
                        value["urls"][0]["url"] = rejected
                        return json.dumps(value).encode()
                    return data

                with self.assertRaisesRegex(RegistryError, "outside the admitted host"):
                    observe(
                        sdk_directory=self.sdk,
                        verifier_directory=self.verifier,
                        expected_revision=REVISION,
                        fetch=substituted_metadata,
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

    def test_sdk_manifest_members_and_version_are_closed(self):
        manifest_path = self.sdk / "SDK-MANIFEST.json"
        original = json.loads(manifest_path.read_bytes())

        cases = {}
        unknown_root = json.loads(json.dumps(original))
        unknown_root["unknown"] = True
        cases["SDK manifest members"] = unknown_root
        unknown_artifact = json.loads(json.dumps(original))
        unknown_artifact["artifacts"][0]["unknown"] = True
        cases["SDK artifact members"] = unknown_artifact
        invalid_version = json.loads(json.dumps(original))
        invalid_version["version"] = "../../other"
        cases["invalid SDK version"] = invalid_version

        for expected, value in cases.items():
            with self.subTest(expected=expected):
                manifest_path.write_text(json.dumps(value))
                with self.assertRaisesRegex(RegistryError, expected):
                    observe(
                        sdk_directory=self.sdk,
                        verifier_directory=self.verifier,
                        expected_revision=REVISION,
                        fetch=self.registry(),
                    )
        manifest_path.write_text(json.dumps(original))

    def test_verifier_manifest_members_are_closed(self):
        manifest_path = (
            self.verifier / "VERIFIER-PACKAGE-MANIFEST.projection.json"
        )
        original = json.loads(manifest_path.read_bytes())

        cases = {}
        unknown_root = json.loads(json.dumps(original))
        unknown_root["unknown"] = True
        cases["verifier manifest members"] = unknown_root
        unknown_artifact = json.loads(json.dumps(original))
        unknown_artifact["artifacts"][0]["unknown"] = True
        cases["verifier artifact members"] = unknown_artifact

        for expected, value in cases.items():
            with self.subTest(expected=expected):
                manifest_path.write_text(json.dumps(value))
                with self.assertRaisesRegex(RegistryError, expected):
                    observe(
                        sdk_directory=self.sdk,
                        verifier_directory=self.verifier,
                        expected_revision=REVISION,
                        fetch=self.registry(),
                    )
        manifest_path.write_text(json.dumps(original))

    def test_observation_schema_is_closed_and_matches_the_producer(self):
        schema = json.loads(
            (ROOT / "schemas/registry-observations-v1.schema.json").read_bytes()
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["properties"]["schema"]["const"],
            "proofbound-runtime-registry-observations/1",
        )
        self.assertEqual(schema["properties"]["observations"]["minItems"], 4)
        self.assertEqual(schema["properties"]["observations"]["maxItems"], 4)


if __name__ == "__main__":
    unittest.main()
