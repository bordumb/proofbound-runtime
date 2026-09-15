from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest

from tools.release.build_current_integration import encode
from tools.release.verify_current_integration import decode_strict


ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "tools/release/build_current_integration.py"
VERIFIER = ROOT / "tools/release/verify_current_integration.py"
SCHEMA = ROOT / "schemas/current-integration-v1.cddl"
REVISION = "00112233445566778899aabbccddeeff00112233"
PROOFBOUND_REVISION = "112233445566778899aabbccddeeff0011223344"
VERSION = "0.2.0"
TARGETS = {
    "aarch64": "aarch64-unknown-linux-gnu",
    "x86_64": "x86_64-unknown-linux-gnu",
}
RUNTIME_EXECUTABLES = ("pbr", "pbr-native-launcher", "pbr-verify", "pbr-compose")


def write_tar(path: Path, members: dict[str, bytes]) -> None:
    with tarfile.open(path, mode="w:gz") as archive:
        for name, data in members.items():
            entry = tarfile.TarInfo(name)
            entry.mode = 0o644 if name == "RELEASE-MANIFEST.json" else 0o755
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))


def write_runtime_bundle(path: Path, architecture: str, target: str) -> None:
    files = {name: f"{architecture} {name}\n".encode() for name in RUNTIME_EXECUTABLES}
    manifest = (
        json.dumps(
            {
                "architecture": architecture,
                "artifacts": [
                    {
                        "name": name,
                        "sha256": hashlib.sha256(files[name]).hexdigest(),
                        "size": len(files[name]),
                    }
                    for name in RUNTIME_EXECUTABLES
                ],
                "schema": "proofbound-runtime-release-manifest/1",
                "target": target,
                "toolchain": "rustc test",
                "version": VERSION,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    write_tar(path, {"RELEASE-MANIFEST.json": manifest, **files})


class CurrentIntegrationFixture:
    def __init__(self, root: Path):
        self.root = root
        self.registry = root / "registry-observations.json"
        self.pin = root / "proofbound-pin.json"
        self.record = root / "current-integration.cbor"
        self.projection = root / "current-integration.projection.json"
        self.rendering = root / "CURRENT-INTEGRATION.md"
        self.runtime_arguments: list[str] = []
        for architecture, target in TARGETS.items():
            for role, name in (
                (
                    "runtime-bundle",
                    f"proofbound-runtime-v{VERSION}-{target}.tar.gz",
                ),
                ("acceptor", f"pbr-accept-v{VERSION}-{target}"),
            ):
                path = root / architecture / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if role == "runtime-bundle":
                    write_runtime_bundle(path, architecture, target)
                else:
                    path.write_bytes(f"{architecture} {role}\n".encode())
                self.runtime_arguments.extend(
                    ["--runtime-artifact", f"{architecture}:{role}={path}"]
                )

        observations = []
        packages = (
            (
                "crates.io",
                "proofbound-runtime-sdk",
                "proofbound-runtime-sdk-0.2.0.crate",
            ),
            ("npm", "@proofbound/runtime-sdk", "proofbound-runtime-sdk-0.2.0.tgz"),
            (
                "pypi",
                "proofbound-runtime-sdk",
                "proofbound_runtime_sdk-0.2.0-py3-none-any.whl",
            ),
            (
                "crates.io",
                "proofbound-runtime-verify",
                "proofbound-runtime-verify-0.2.0.crate",
            ),
        )
        for ecosystem, package, artifact in packages:
            payload = f"{ecosystem} {package}\n".encode()
            host = {
                "crates.io": "static.crates.io",
                "npm": "registry.npmjs.org",
                "pypi": "files.pythonhosted.org",
            }[ecosystem]
            observations.append(
                {
                    "artifact": artifact,
                    "ecosystem": ecosystem,
                    "package": package,
                    "sha256": f"hex:{hashlib.sha256(payload).hexdigest()}",
                    "size_bytes": len(payload),
                    "url": f"https://{host}/packages/{artifact}",
                }
            )
        self.registry.write_text(
            json.dumps(
                {
                    "observations": observations,
                    "schema": "proofbound-runtime-registry-observations/1",
                    "source_revision": REVISION,
                    "version": VERSION,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )

        asset_names = (
            ("SHA256SUMS", "checksums"),
            ("TOOL-BUNDLE-PUBLICATION.json", "publication-manifest"),
            ("install-proofbound-tools.py", "installer"),
            (
                f"proofbound-tools-{PROOFBOUND_REVISION}-linux-aarch64.manifest.json",
                "bundle-manifest",
            ),
            (
                f"proofbound-tools-{PROOFBOUND_REVISION}-linux-aarch64.tar.gz",
                "archive",
            ),
            (
                f"proofbound-tools-{PROOFBOUND_REVISION}-linux-x86_64.manifest.json",
                "bundle-manifest",
            ),
            (
                f"proofbound-tools-{PROOFBOUND_REVISION}-linux-x86_64.tar.gz",
                "archive",
            ),
        )
        assets = []
        for index, (name, role) in enumerate(asset_names, start=1):
            assets.append(
                {
                    "name": name,
                    "role": role,
                    "sha256": f"sha256:{index:064x}",
                    "size_bytes": index,
                }
            )
        self.pin.write_text(
            json.dumps(
                {
                    "assets": assets,
                    "bundle_workflow_run_id": 102,
                    "producer_repository": "bordumb/proof-bound",
                    "release_id": 103,
                    "release_tag": f"proofbound-tools-{PROOFBOUND_REVISION}",
                    "schema": "proofbound-runtime-proofbound-tool-pin/1",
                    "source_revision": PROOFBOUND_REVISION,
                    "verification_run_id": 101,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )

    def builder_command(self) -> list[str]:
        return [
            sys.executable,
            str(BUILDER),
            "--revision",
            REVISION,
            "--registry-observations",
            str(self.registry),
            *self.runtime_arguments,
            "--proofbound-pin",
            str(self.pin),
            "--output",
            str(self.record),
        ]

    def verifier_command(self) -> list[str]:
        return [
            sys.executable,
            str(VERIFIER),
            "--record",
            str(self.record),
            "--expected-revision",
            REVISION,
            "--registry-observations",
            str(self.registry),
            *self.runtime_arguments,
            "--proofbound-pin",
            str(self.pin),
            "--projection",
            str(self.projection),
            "--rendering",
            str(self.rendering),
        ]


class CurrentIntegrationTests(unittest.TestCase):
    def test_complete_observed_tuple_builds_verifies_and_renders(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CurrentIntegrationFixture(Path(directory))
            subprocess.run(fixture.builder_command(), check=True)
            subprocess.run(fixture.verifier_command(), check=True)

            value = decode_strict(fixture.record.read_bytes())
            self.assertEqual(
                value["schema"], "proofbound-runtime-current-integration/1"
            )
            self.assertEqual(
                value["runtime"]["source_revision"], bytes.fromhex(REVISION)
            )
            self.assertEqual(len(value["runtime"]["artifacts"]), 4)
            self.assertEqual(len(value["runtime"]["executables"]), 8)
            self.assertEqual(
                [item["name"] for item in value["runtime"]["executables"]],
                [*RUNTIME_EXECUTABLES, *RUNTIME_EXECUTABLES],
            )
            self.assertEqual(len(value["packages"]), 4)
            self.assertEqual(value["optional_integrations"], [])
            self.assertEqual(
                value["proofbound"]["source_revision"],
                bytes.fromhex(PROOFBOUND_REVISION),
            )
            projection = json.loads(fixture.projection.read_bytes())
            self.assertEqual(
                projection["runtime"]["source_revision"], f"hex:{REVISION}"
            )
            rendering = fixture.rendering.read_text()
            self.assertIn("An identity that is", rendering)
            self.assertIn("does not authenticate", rendering)
            self.assertIn("No Auths, Capsec, guest, service", rendering)

    def test_artifact_substitution_after_construction_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CurrentIntegrationFixture(Path(directory))
            subprocess.run(fixture.builder_command(), check=True)
            artifact = Path(fixture.runtime_arguments[1].split("=", 1)[1])
            artifact.write_bytes(b"substituted\n")

            rejected = subprocess.run(
                fixture.verifier_command(), capture_output=True, text=True
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("current-integration verification failed", rejected.stderr)
            self.assertFalse(fixture.projection.exists())
            self.assertFalse(fixture.rendering.exists())

    def test_symlinked_runtime_artifact_is_not_admitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CurrentIntegrationFixture(Path(directory))
            subprocess.run(fixture.builder_command(), check=True)
            artifact = Path(fixture.runtime_arguments[1].split("=", 1)[1])
            link = fixture.root / "linked" / artifact.name
            link.parent.mkdir()
            link.symlink_to(artifact)
            fixture.runtime_arguments[1] = (
                fixture.runtime_arguments[1].split("=", 1)[0] + f"={link}"
            )

            for command in (fixture.builder_command(), fixture.verifier_command()):
                with self.subTest(command=Path(command[1]).name):
                    rejected = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn("cannot read Runtime artifact", rejected.stderr)
            self.assertFalse(fixture.projection.exists())
            self.assertFalse(fixture.rendering.exists())

    def test_cddl_text_bounds_are_enforced_by_both_implementations(self) -> None:
        mutations = (
            (
                "version",
                lambda value: value.__setitem__("version", f"1.{'1' * 63}.1"),
                "exceeds the byte bound",
            ),
            (
                "source-url",
                lambda value: value["observations"][0].__setitem__(
                    "url", "https://static.crates.io/" + "a" * 4096
                ),
                "exceeds the byte bound",
            ),
        )
        for label, mutate, message in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = CurrentIntegrationFixture(Path(directory))
                subprocess.run(fixture.builder_command(), check=True)
                registry = json.loads(fixture.registry.read_bytes())
                mutate(registry)
                fixture.registry.write_text(json.dumps(registry))
                for command in (
                    fixture.builder_command(),
                    fixture.verifier_command(),
                ):
                    rejected = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn(message, rejected.stderr)
                self.assertFalse(fixture.projection.exists())
                self.assertFalse(fixture.rendering.exists())

        schema = SCHEMA.read_text(encoding="utf-8")
        self.assertIn('"product_label": text .size (1..64)', schema)
        self.assertIn('"version": text .size (1..64)', schema)
        self.assertIn('"source_url": text .size (1..4096)', schema)
        self.assertIn("positive-u64 = 1..18446744073709551615", schema)

    def test_oversized_json_is_rejected_by_both_bounded_readers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CurrentIntegrationFixture(Path(directory))
            subprocess.run(fixture.builder_command(), check=True)
            fixture.registry.write_bytes(b"{" + b" " * 1_048_576)

            for command in (fixture.builder_command(), fixture.verifier_command()):
                with self.subTest(command=Path(command[1]).name):
                    rejected = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn("exceeds the read bound", rejected.stderr)
            self.assertFalse(fixture.projection.exists())
            self.assertFalse(fixture.rendering.exists())

    def test_archive_member_overflow_is_streamed_and_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CurrentIntegrationFixture(Path(directory))
            subprocess.run(fixture.builder_command(), check=True)
            archive_path = Path(fixture.runtime_arguments[1].split("=", 1)[1])
            with tarfile.open(archive_path, mode="r:gz") as archive:
                members = {
                    entry.name: archive.extractfile(entry).read()
                    for entry in archive.getmembers()
                }
            members["unregistered"] = b"overflow sentinel\n"
            write_tar(archive_path, members)

            for command in (fixture.builder_command(), fixture.verifier_command()):
                with self.subTest(command=Path(command[1]).name):
                    rejected = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn("member inventory mismatch", rejected.stderr)
            self.assertFalse(fixture.projection.exists())
            self.assertFalse(fixture.rendering.exists())

    def test_symlinked_record_is_not_admitted_by_the_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CurrentIntegrationFixture(Path(directory))
            subprocess.run(fixture.builder_command(), check=True)
            link = fixture.root / "linked-record.cbor"
            link.symlink_to(fixture.record)
            fixture.record = link

            rejected = subprocess.run(
                fixture.verifier_command(), capture_output=True, text=True
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("cannot read input", rejected.stderr)
            self.assertFalse(fixture.projection.exists())
            self.assertFalse(fixture.rendering.exists())

    def test_runtime_executable_substitution_cannot_enter_the_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CurrentIntegrationFixture(Path(directory))
            archive_path = Path(fixture.runtime_arguments[1].split("=", 1)[1])
            with tarfile.open(archive_path, mode="r:gz") as archive:
                members = {
                    entry.name: archive.extractfile(entry).read()
                    for entry in archive.getmembers()
                }
            members["pbr-verify"] = b"substituted verifier\n"
            write_tar(archive_path, members)

            rejected = subprocess.run(
                fixture.builder_command(), capture_output=True, text=True
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("executable identity mismatch", rejected.stderr)
            self.assertFalse(fixture.record.exists())

    def test_incomplete_registry_observation_cannot_build_a_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CurrentIntegrationFixture(Path(directory))
            registry = json.loads(fixture.registry.read_bytes())
            registry["observations"].pop()
            fixture.registry.write_text(json.dumps(registry))

            rejected = subprocess.run(
                fixture.builder_command(), capture_output=True, text=True
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("inventory is incomplete", rejected.stderr)
            self.assertFalse(fixture.record.exists())

    def test_registry_host_and_proofbound_role_are_not_copied_on_trust(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CurrentIntegrationFixture(Path(directory))
            registry = json.loads(fixture.registry.read_bytes())
            registry["observations"][0]["url"] = "https://substitute.example/pkg"
            fixture.registry.write_text(json.dumps(registry))
            rejected = subprocess.run(
                fixture.builder_command(), capture_output=True, text=True
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("outside the admitted host", rejected.stderr)

        with tempfile.TemporaryDirectory() as directory:
            fixture = CurrentIntegrationFixture(Path(directory))
            pin = json.loads(fixture.pin.read_bytes())
            pin["assets"][0]["role"] = "archive"
            fixture.pin.write_text(json.dumps(pin))
            rejected = subprocess.run(
                fixture.builder_command(), capture_output=True, text=True
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("identity or role mismatch", rejected.stderr)

    def test_unknown_record_member_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CurrentIntegrationFixture(Path(directory))
            subprocess.run(fixture.builder_command(), check=True)
            value = decode_strict(fixture.record.read_bytes())
            value["unknown"] = "substitute"
            fixture.record.write_bytes(encode(value))

            rejected = subprocess.run(
                fixture.verifier_command(), capture_output=True, text=True
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("closed schema", rejected.stderr)

    def test_noncanonical_cbor_fails_before_semantic_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CurrentIntegrationFixture(Path(directory))
            fixture.record.write_bytes(b"\xa2\x61b\x00\x61a\x00")

            rejected = subprocess.run(
                fixture.verifier_command(), capture_output=True, text=True
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("map keys are duplicated or out of order", rejected.stderr)

    def test_error_vocabularies_match_all_three_sdk_sources(self) -> None:
        sources = {
            "rust": ROOT / "crates/proofbound-runtime-sdk/src/lib.rs",
            "python": ROOT / "sdk/python/proofbound_runtime/__init__.py",
            "node": ROOT / "sdk/typescript/src/index.ts",
        }
        from tools.release.verify_current_integration import EXPECTED_CODES

        for language, path in sources.items():
            with self.subTest(language=language):
                codes = sorted(
                    set(re.findall(r'"(sdk\.[a-z0-9.-]+)"', path.read_text()))
                )
                self.assertEqual(codes, EXPECTED_CODES[language])

    def test_language_minimums_match_package_metadata(self) -> None:
        from tools.release.verify_current_integration import MINIMUMS

        cargo = (ROOT / "Cargo.toml").read_text()
        python = (ROOT / "sdk/python/pyproject.toml").read_text()
        node = json.loads((ROOT / "sdk/typescript/package.json").read_bytes())
        self.assertIn(f'rust-version = "{MINIMUMS["rust"]}"', cargo)
        self.assertIn(f'requires-python = ">={MINIMUMS["python"]}"', python)
        self.assertEqual(node["engines"]["node"], f">={MINIMUMS['node']}")

    def test_schema_profiles_match_current_source_constants(self) -> None:
        sources = {
            "plan": (ROOT / "crates/proofbound-runtime-core/src/plan.rs").read_text(),
            "sdk": (ROOT / "crates/proofbound-runtime-sdk/src/lib.rs").read_text(),
            "receipt": (
                ROOT / "crates/proofbound-runtime-core/src/receipt.rs"
            ).read_text(),
            "verifier": (
                ROOT / "crates/proofbound-runtime-verify/src/decode_v2.rs"
            ).read_text()
            + (ROOT / "crates/proofbound-runtime-verify/src/decode.rs").read_text(),
            "compose": (
                ROOT / "crates/proofbound-runtime-compose/src/lib.rs"
            ).read_text(),
            "accept": (
                ROOT / "crates/proofbound-runtime-accept/src/lib.rs"
            ).read_text(),
            "result": (
                ROOT / "crates/proofbound-runtime-core/src/run_result.rs"
            ).read_text(),
        }

        def schema_constants(source: str) -> dict[str, str]:
            return dict(
                re.findall(
                    r"(?m)^(?:pub )?const ([A-Z0-9_]*SCHEMA(?:_V[0-9]+)?):[^=]+="
                    r' "([^"]+)";',
                    source,
                )
            )

        selected = {
            "plan": {
                key: value
                for key, value in schema_constants(sources["plan"]).items()
                if key.startswith("PLAN_SCHEMA")
            },
            "sdk": schema_constants(sources["sdk"]),
            "receipt": {
                key: value
                for key, value in schema_constants(sources["receipt"]).items()
                if key.startswith("EXECUTION_RECEIPT")
            },
            "verifier": schema_constants(sources["verifier"]),
            "compose": {
                key: value
                for key, value in schema_constants(sources["compose"]).items()
                if key.startswith(
                    (
                        "COMPOSITION_SCHEMA",
                        "RELEASE_ENVELOPE_SCHEMA",
                        "RELEASE_REPORT_SCHEMA",
                        "COMPILED_RELEASE_SCHEMA",
                        "EXECUTION_RECEIPT_SCHEMA",
                    )
                )
            },
            "accept": {
                key: value
                for key, value in schema_constants(sources["accept"]).items()
                if key in {"POLICY_SCHEMA", "DECISION_SCHEMA"}
            },
            "result": schema_constants(sources["result"]),
        }
        expected = {
            "plan": {
                "PLAN_SCHEMA": "proofbound-runtime-plan/1",
                "PLAN_SCHEMA_V2": "proofbound-runtime-plan/2",
            },
            "sdk": {
                "PLAN_SCHEMA": "proofbound-runtime-plan/2",
                "RESULT_SCHEMA": "proofbound-runtime-run-result/2",
            },
            "receipt": {
                "EXECUTION_RECEIPT_SCHEMA": "proofbound-runtime-receipt/1",
                "EXECUTION_RECEIPT_V2_SCHEMA": (
                    "proofbound-runtime-execution-receipt/2"
                ),
            },
            "verifier": {
                "RECEIPT_SCHEMA": "proofbound-runtime-receipt/1",
                "SCHEMA": "proofbound-runtime-execution-receipt/2",
            },
            "compose": {
                "COMPILED_RELEASE_SCHEMA": "proofbound-compiled-release/7",
                "COMPOSITION_SCHEMA": "proofbound-runtime-composed-receipt/1",
                "COMPOSITION_SCHEMA_V2": "proofbound-runtime-composed-receipt/2",
                "EXECUTION_RECEIPT_SCHEMA": "proofbound-runtime-receipt/1",
                "EXECUTION_RECEIPT_SCHEMA_V2": (
                    "proofbound-runtime-execution-receipt/2"
                ),
                "RELEASE_ENVELOPE_SCHEMA": "proofbound-release-envelope/7",
                "RELEASE_REPORT_SCHEMA": "proofbound-verification-report/3",
            },
            "accept": {
                "DECISION_SCHEMA": "proofbound-runtime-acceptance-decision/2",
                "POLICY_SCHEMA": "proofbound-runtime-acceptance-policy/1",
            },
            "result": {"SCHEMA": "proofbound-runtime-run-result/2"},
        }
        self.assertEqual(selected, expected)

    def test_verifier_owns_its_decoder_and_semantic_tables(self) -> None:
        verifier = VERIFIER.read_text(encoding="utf-8")
        self.assertNotIn("build_current_integration", verifier)
        self.assertIn("class Decoder:", verifier)
        self.assertIn("EXPECTED_SCHEMAS =", verifier)
        self.assertIn("EXPECTED_CODES =", verifier)


if __name__ == "__main__":
    unittest.main()
