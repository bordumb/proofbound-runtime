import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from tools.ci import install_proofbound_tool_bundle as installer


REVISION = "1" * 40


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def archive_with_manifest(platform: str, manifest: bytes) -> bytes:
    output = io.BytesIO()
    root = f"proofbound-tools-{REVISION}-{platform}"
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo(f"{root}/{installer.EMBEDDED_MANIFEST_NAME}")
        member.size = len(manifest)
        archive.addfile(member, io.BytesIO(manifest))
    return output.getvalue()


def fixture() -> tuple[dict[str, object], dict[str, bytes]]:
    payloads: dict[str, bytes] = {}
    roles = installer._required_assets(REVISION)
    for name in roles:
        payloads[name] = f"payload:{name}\n".encode()
    binary = b"binary"
    for platform in installer.PLATFORMS:
        manifest_name = f"proofbound-tools-{REVISION}-{platform}.manifest.json"
        artifacts = []
        for path in installer.BUNDLE_PAYLOAD_PATHS:
            data = binary if path.startswith("bin/") else f"payload:{path}\n".encode()
            artifacts.append(
                {
                    "executable": path.startswith("bin/"),
                    "path": path,
                    "sha256": f"sha256:{hashlib.sha256(data).hexdigest()}",
                    "size_bytes": len(data),
                }
            )
        payloads[manifest_name] = canonical(
            {
                "artifacts": artifacts,
                "platform": platform,
                "product_label": "0.1.0",
                "rust_toolchain": "1.94.0",
                "schema": installer.BUNDLE_SCHEMA,
                "source_revision": REVISION,
                "verification_run_id": 101,
            }
        )
        archive_name = f"proofbound-tools-{REVISION}-{platform}.tar.gz"
        payloads[archive_name] = archive_with_manifest(
            platform, payloads[manifest_name]
        )
    publication = {
        "assets": [],
        "bundle_workflow_run_id": 202,
        "producer_repository": installer.PRODUCER_REPOSITORY,
        "release_tag": f"proofbound-tools-{REVISION}",
        "schema": installer.PUBLICATION_SCHEMA,
        "source_revision": REVISION,
        "verification_run_id": 101,
    }
    publication_names = set(roles) - {
        installer.CHECKSUMS_NAME,
        installer.PUBLICATION_NAME,
    }
    for name in sorted(publication_names):
        data = payloads[name]
        publication["assets"].append(
            {
                "name": name,
                "role": roles[name],
                "sha256": f"sha256:{hashlib.sha256(data).hexdigest()}",
                "size_bytes": len(data),
            }
        )
    payloads[installer.PUBLICATION_NAME] = canonical(publication)
    payloads[installer.CHECKSUMS_NAME] = "".join(
        f"{hashlib.sha256(payloads[name]).hexdigest()}  {name}\n"
        for name in sorted(set(roles) - {installer.CHECKSUMS_NAME})
    ).encode()
    assets = [
        {
            "name": name,
            "role": roles[name],
            "sha256": f"sha256:{hashlib.sha256(payloads[name]).hexdigest()}",
            "size_bytes": len(payloads[name]),
        }
        for name in sorted(roles)
    ]
    pin: dict[str, object] = {
        "assets": assets,
        "bundle_workflow_run_id": 202,
        "producer_repository": installer.PRODUCER_REPOSITORY,
        "release_id": 303,
        "release_tag": f"proofbound-tools-{REVISION}",
        "schema": installer.PIN_SCHEMA,
        "source_revision": REVISION,
        "verification_run_id": 101,
    }
    return pin, payloads


def release(pin: dict[str, object]) -> dict[str, object]:
    return {
        "assets": [
            {
                "digest": item["sha256"],
                "name": item["name"],
                "size": item["size_bytes"],
                "state": "uploaded",
            }
            for item in pin["assets"]
        ],
        "draft": False,
        "id": pin["release_id"],
        "immutable": True,
        "prerelease": False,
        "tag_name": pin["release_tag"],
        "target_commitish": pin["source_revision"],
    }


def tag_reference(revision: str = REVISION, kind: str = "commit") -> bytes:
    return canonical(
        {
            "object": {"sha": revision, "type": kind},
            "ref": f"refs/tags/proofbound-tools-{REVISION}",
        }
    )


def annotated_tag(tag_digest: str, revision: str = REVISION) -> bytes:
    return canonical({"object": {"sha": revision, "type": "commit"}, "sha": tag_digest})


class PinTests(unittest.TestCase):
    def test_api_credential_is_scoped_to_github_metadata(self) -> None:
        with mock.patch.dict(
            installer.os.environ, {"GITHUB_TOKEN": "fixture-credential"}
        ):
            api_headers = installer._request_headers(
                "https://api.github.com/repos/bordumb/proof-bound/releases/1"
            )
            asset_headers = installer._request_headers(
                "https://github.com/bordumb/proof-bound/releases/download/tag/asset"
            )
        self.assertEqual(api_headers["Authorization"], "Bearer fixture-credential")
        self.assertNotIn("Authorization", asset_headers)

    def test_api_credential_rejects_header_injection(self) -> None:
        with mock.patch.dict(
            installer.os.environ, {"GITHUB_TOKEN": "fixture\ncredential"}
        ):
            with self.assertRaisesRegex(installer.ToolBundleError, "malformed"):
                installer._request_headers(
                    "https://api.github.com/repos/example/release"
                )

    def test_api_credential_rejects_noncanonical_origin(self) -> None:
        with mock.patch.dict(
            installer.os.environ, {"GITHUB_TOKEN": "fixture-credential"}
        ):
            for url in (
                "http://api.github.com/repos/example/release",
                "https://api.github.com:443/repos/example/release",
            ):
                with self.subTest(url=url):
                    with self.assertRaisesRegex(
                        installer.ToolBundleError, "origin is invalid"
                    ):
                        installer._request_headers(url)

    def test_api_credential_rejects_every_redirect(self) -> None:
        request = installer.Request(
            "https://api.github.com/repos/example/release",
            headers={"Authorization": "Bearer fixture-credential"},
        )
        handler = installer._CredentialRedirectHandler()
        for target in (
            "https://api.github.com/repos/example/other-release",
            "https://example.invalid/capture",
            "http://api.github.com/repos/example/release",
        ):
            with self.subTest(target=target):
                with self.assertRaisesRegex(
                    installer.ToolBundleError, "request redirected"
                ):
                    handler.redirect_request(
                        request,
                        None,
                        302,
                        "Found",
                        {},
                        target,
                    )

    def test_canonical_pin_and_upstream_records_are_closed(self) -> None:
        pin, payloads = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pin.json"
            path.write_bytes(canonical(pin))
            self.assertEqual(installer.load_pin(path), pin)
        installer.validate_release(release(pin), pin)
        installer.validate_publication(
            json.loads(payloads[installer.PUBLICATION_NAME]), pin
        )
        installer._parse_checksums(payloads[installer.CHECKSUMS_NAME], pin)

    def test_pin_rejects_unknown_duplicate_and_noncanonical_data(self) -> None:
        pin, _ = fixture()
        attacked = dict(pin)
        attacked["unknown"] = True
        with self.assertRaisesRegex(installer.ToolBundleError, "fields are not exact"):
            installer.validate_pin(attacked)
        duplicate = b'{"schema":"a","schema":"b"}\n'
        with self.assertRaisesRegex(installer.ToolBundleError, "duplicate JSON key"):
            installer._decode_json(duplicate, "fixture")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pin.json"
            path.write_text(json.dumps(pin, indent=2), encoding="utf-8")
            with self.assertRaisesRegex(installer.ToolBundleError, "not canonical"):
                installer.load_pin(path)

    def test_pin_rejects_asset_identity_and_inventory_attacks(self) -> None:
        pin, _ = fixture()
        for attack in ("digest", "role", "order", "missing"):
            with self.subTest(attack=attack):
                attacked = json.loads(json.dumps(pin))
                if attack == "digest":
                    attacked["assets"][0]["sha256"] = "sha256:" + "0" * 63
                elif attack == "role":
                    attacked["assets"][0]["role"] = "archive"
                elif attack == "order":
                    attacked["assets"][0], attacked["assets"][1] = (
                        attacked["assets"][1],
                        attacked["assets"][0],
                    )
                else:
                    attacked["assets"].pop()
                with self.assertRaises(installer.ToolBundleError):
                    installer.validate_pin(attacked)

    def test_release_rejects_mutability_and_asset_substitution(self) -> None:
        pin, _ = fixture()
        for attack in ("mutable", "target", "asset"):
            with self.subTest(attack=attack):
                attacked = release(pin)
                if attack == "mutable":
                    attacked["immutable"] = False
                elif attack == "target":
                    attacked["target_commitish"] = "2" * 40
                else:
                    attacked["assets"][0]["digest"] = "sha256:" + "0" * 64
                with self.assertRaises(installer.ToolBundleError):
                    installer.validate_release(attacked, pin)

    def test_tag_resolution_accepts_exact_lightweight_and_annotated_tags(self) -> None:
        pin, _ = fixture()
        tag_digest = "2" * 40

        def lightweight(_url: str, _limit: int) -> bytes:
            return tag_reference()

        installer.validate_tag_target(pin, lightweight)

        def annotated(url: str, _limit: int) -> bytes:
            return (
                tag_reference(tag_digest, "tag")
                if "/ref/tags/" in url
                else annotated_tag(tag_digest)
            )

        installer.validate_tag_target(pin, annotated)

    def test_tag_resolution_rejects_a_different_commit(self) -> None:
        pin, _ = fixture()
        with self.assertRaisesRegex(installer.ToolBundleError, "target differs"):
            installer.validate_tag_target(
                pin, lambda _url, _limit: tag_reference("3" * 40)
            )

    def test_bundle_manifest_rejects_platform_and_binary_inventory_substitution(
        self,
    ) -> None:
        pin, payloads = fixture()
        name = f"proofbound-tools-{REVISION}-linux-x86_64.manifest.json"
        manifest = json.loads(payloads[name])
        records = installer.validate_bundle_manifest(manifest, pin, "linux-x86_64")
        self.assertEqual(tuple(records), installer.BINARY_NAMES)
        for attack in ("platform", "binary", "toolchain", "payload", "mode"):
            with self.subTest(attack=attack):
                attacked = json.loads(json.dumps(manifest))
                if attack == "platform":
                    attacked["platform"] = "linux-aarch64"
                elif attack == "binary":
                    binary = next(
                        item
                        for item in attacked["artifacts"]
                        if item["path"].startswith("bin/")
                    )
                    binary["path"] = "bin/substitute"
                elif attack == "toolchain":
                    attacked["rust_toolchain"] = "nightly"
                elif attack == "payload":
                    attacked["artifacts"].pop(0)
                else:
                    attacked["artifacts"][0]["executable"] = True
                with self.assertRaises(installer.ToolBundleError):
                    installer.validate_bundle_manifest(attacked, pin, "linux-x86_64")

    def test_detached_manifest_requires_canonical_carrier_and_archive_equality(
        self,
    ) -> None:
        pin, payloads = fixture()
        manifest_name = f"proofbound-tools-{REVISION}-linux-x86_64.manifest.json"
        archive_name = f"proofbound-tools-{REVISION}-linux-x86_64.tar.gz"
        manifest = payloads[manifest_name]
        installer.validate_detached_manifest(manifest, pin, "linux-x86_64")
        installer.validate_embedded_manifest(
            payloads[archive_name], manifest, pin, "linux-x86_64"
        )
        with self.assertRaisesRegex(installer.ToolBundleError, "not canonical"):
            installer.validate_detached_manifest(manifest + b" ", pin, "linux-x86_64")
        changed = json.loads(manifest)
        changed["source_revision"] = "4" * 40
        with self.assertRaisesRegex(installer.ToolBundleError, "manifests differ"):
            installer.validate_embedded_manifest(
                payloads[archive_name],
                canonical(changed),
                pin,
                "linux-x86_64",
            )

    def test_checksums_reject_reordering_and_unpinned_names(self) -> None:
        pin, payloads = fixture()
        lines = payloads[installer.CHECKSUMS_NAME].decode("ascii").splitlines()
        with self.assertRaisesRegex(installer.ToolBundleError, "ordered"):
            installer._parse_checksums(
                ("\n".join(reversed(lines)) + "\n").encode(), pin
            )
        with self.assertRaisesRegex(installer.ToolBundleError, "differ from the pin"):
            installer._parse_checksums(
                payloads[installer.CHECKSUMS_NAME]
                + ("0" * 64 + "  zzz-extra\n").encode(),
                pin,
            )

    def test_install_checks_every_identity_before_running_installer(self) -> None:
        pin, payloads = fixture()
        hosted = canonical(release(pin))

        def fetch(url: str, _limit: int) -> bytes:
            if "/releases/303" in url:
                return hosted
            if "/git/ref/tags/" in url:
                return tag_reference()
            return payloads[url.rsplit("/", 1)[1]]

        def fake_run(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess:
            self.assertEqual(
                kwargs["env"], {"PATH": installer.os.environ.get("PATH", "")}
            )
            self.assertEqual(Path(kwargs["cwd"]), Path(command[1]).parent)
            destination = Path(command[command.index("--destination") + 1])
            destination.mkdir()
            for name in installer.BINARY_NAMES:
                executable = destination / name
                executable.write_bytes(b"binary")
                executable.chmod(0o755)
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "bin"
            with mock.patch.object(
                installer.subprocess, "run", side_effect=fake_run
            ) as run:
                installer.install(pin, "linux-x86_64", destination, fetch)
            self.assertEqual(run.call_count, 1)

    def test_install_rejects_each_changed_download_before_execution(self) -> None:
        pin, payloads = fixture()
        hosted = canonical(release(pin))

        selected_names = {
            installer.CHECKSUMS_NAME,
            installer.INSTALLER_NAME,
            installer.PUBLICATION_NAME,
            f"proofbound-tools-{REVISION}-linux-x86_64.tar.gz",
            f"proofbound-tools-{REVISION}-linux-x86_64.manifest.json",
        }
        for changed_name in selected_names:
            with self.subTest(changed_name=changed_name):

                def fetch(url: str, _limit: int) -> bytes:
                    if "/releases/303" in url:
                        return hosted
                    if "/git/ref/tags/" in url:
                        return tag_reference()
                    name = url.rsplit("/", 1)[1]
                    data = payloads[name]
                    return data + b"changed" if name == changed_name else data

                with tempfile.TemporaryDirectory() as temporary:
                    with mock.patch.object(installer.subprocess, "run") as run:
                        with self.assertRaisesRegex(
                            installer.ToolBundleError,
                            "downloaded asset identity differs",
                        ):
                            installer.install(
                                pin,
                                "linux-x86_64",
                                Path(temporary) / "bin",
                                fetch,
                            )
                    run.assert_not_called()

    def test_install_rejects_changed_installed_executable(self) -> None:
        pin, payloads = fixture()
        hosted = canonical(release(pin))

        def fetch(url: str, _limit: int) -> bytes:
            if "/releases/303" in url:
                return hosted
            if "/git/ref/tags/" in url:
                return tag_reference()
            return payloads[url.rsplit("/", 1)[1]]

        def fake_run(
            command: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess:
            destination = Path(command[command.index("--destination") + 1])
            destination.mkdir()
            for name in installer.BINARY_NAMES:
                executable = destination / name
                executable.write_bytes(
                    b"changed" if name == "proofbound" else b"binary"
                )
                executable.chmod(0o755)
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(installer.subprocess, "run", side_effect=fake_run):
                with self.assertRaisesRegex(
                    installer.ToolBundleError,
                    "installed Proofbound executable identity differs",
                ):
                    installer.install(
                        pin,
                        "linux-x86_64",
                        Path(temporary) / "bin",
                        fetch,
                    )


if __name__ == "__main__":
    unittest.main()
