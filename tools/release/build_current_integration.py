#!/usr/bin/env python3
"""Build one closed current-integration record after registry observation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tarfile
from typing import Any
from urllib.parse import urlparse


SCHEMA = "proofbound-runtime-current-integration/1"
REGISTRY_SCHEMA = "proofbound-runtime-registry-observations/1"
PROOFBOUND_PIN_SCHEMA = "proofbound-runtime-proofbound-tool-pin/1"
REVISION = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
HEX_DIGEST = re.compile(r"(?:hex:|sha256:)[0-9a-f]{64}\Z")
MAX_INPUT_BYTES = 1_048_576
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_RUNTIME_MEMBER_BYTES = 16 * 1024 * 1024
MAX_U64 = (1 << 64) - 1

RUNTIME_TARGETS = {
    "aarch64": "aarch64-unknown-linux-gnu",
    "x86_64": "x86_64-unknown-linux-gnu",
}
RUNTIME_ROLES = ("runtime-bundle", "acceptor")
RUNTIME_MEMBERS = (
    "RELEASE-MANIFEST.json",
    "pbr",
    "pbr-native-launcher",
    "pbr-verify",
    "pbr-compose",
)
RUNTIME_EXECUTABLES = RUNTIME_MEMBERS[1:]
RUNTIME_ORDER = tuple(
    (architecture, role)
    for architecture in ("aarch64", "x86_64")
    for role in RUNTIME_ROLES
)
PACKAGE_ORDER = (
    ("crates.io", "proofbound-runtime-sdk"),
    ("npm", "@proofbound/runtime-sdk"),
    ("pypi", "proofbound-runtime-sdk"),
    ("crates.io", "proofbound-runtime-verify"),
)
SCHEMA_PROFILES = [
    {
        "accepted": ["proofbound-runtime-plan/1", "proofbound-runtime-plan/2"],
        "emitted": ["proofbound-runtime-plan/2"],
        "surface": "execution-plan",
    },
    {
        "accepted": [
            "proofbound-runtime-receipt/1",
            "proofbound-runtime-execution-receipt/2",
        ],
        "emitted": ["proofbound-runtime-execution-receipt/2"],
        "surface": "execution-receipt",
    },
    {
        "accepted": [
            "proofbound-runtime-composed-receipt/1",
            "proofbound-runtime-composed-receipt/2",
        ],
        "emitted": ["proofbound-runtime-composed-receipt/2"],
        "surface": "composed-receipt",
    },
    {
        "accepted": ["proofbound-runtime-acceptance-policy/1"],
        "emitted": [],
        "surface": "acceptance-policy",
    },
    {
        "accepted": ["proofbound-runtime-acceptance-decision/2"],
        "emitted": ["proofbound-runtime-acceptance-decision/2"],
        "surface": "acceptance-decision",
    },
    {
        "accepted": ["proofbound-runtime-run-result/2"],
        "emitted": ["proofbound-runtime-run-result/2"],
        "surface": "machine-run-result",
    },
]
SDK_CODES = {
    "rust": [
        "sdk.plan.cbor-bound",
        "sdk.plan.duplicate",
        "sdk.plan.field-invalid",
        "sdk.plan.id-invalid",
        "sdk.plan.limit-invalid",
        "sdk.plan.limit-not-quantized",
        "sdk.plan.runtime-read-not-absolute",
        "sdk.plan.shape-invalid",
        "sdk.result.field-invalid",
        "sdk.result.malformed-json",
        "sdk.result.schema-unsupported",
        "sdk.result.unknown-field",
    ],
    "python": [
        "sdk.plan.cbor-bound",
        "sdk.plan.duplicate",
        "sdk.plan.field-invalid",
        "sdk.plan.id-invalid",
        "sdk.plan.limit-invalid",
        "sdk.plan.limit-not-quantized",
        "sdk.plan.runtime-read-not-absolute",
        "sdk.plan.shape-invalid",
        "sdk.process.bound-invalid",
        "sdk.process.environment-invalid",
        "sdk.process.failed",
        "sdk.process.output-bound",
        "sdk.process.path-not-absolute",
        "sdk.process.start-failed",
        "sdk.result.field-invalid",
        "sdk.result.malformed-json",
        "sdk.result.not-one-line",
        "sdk.result.schema-unsupported",
        "sdk.result.unknown-field",
    ],
    "node": [
        "sdk.plan.cbor-bound",
        "sdk.plan.duplicate",
        "sdk.plan.field-invalid",
        "sdk.plan.id-invalid",
        "sdk.plan.limit-invalid",
        "sdk.plan.limit-not-quantized",
        "sdk.plan.runtime-read-not-absolute",
        "sdk.plan.shape-invalid",
        "sdk.plan.unknown-field",
        "sdk.process.bound-invalid",
        "sdk.process.environment-invalid",
        "sdk.process.failed",
        "sdk.process.output-bound",
        "sdk.process.path-not-absolute",
        "sdk.process.start-failed",
        "sdk.result.field-invalid",
        "sdk.result.malformed-json",
        "sdk.result.not-one-line",
        "sdk.result.schema-unsupported",
        "sdk.result.unknown-field",
    ],
}
LANGUAGE_MINIMUMS = {"rust": "1.93", "python": "3.10", "node": "22.6"}
PROOFBOUND_RECEIPT_SCHEMAS = [
    "proofbound-release-envelope/7",
    "proofbound-verification-report/3",
    "proofbound-compiled-release/7",
]


class IntegrationError(ValueError):
    """One current-integration construction error."""


def encode_argument(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    for additional, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (width * 8):
            return bytes([(major << 5) | additional]) + value.to_bytes(width, "big")
    raise IntegrationError("CBOR integer exceeds u64")


def encode(value: Any) -> bytes:
    """Encode the admitted value subset as deterministic CBOR."""

    if isinstance(value, bytes):
        return encode_argument(2, len(value)) + value
    if isinstance(value, str):
        payload = value.encode("utf-8")
        return encode_argument(3, len(payload)) + payload
    if type(value) is int and 0 <= value <= MAX_U64:
        return encode_argument(0, value)
    if isinstance(value, list):
        return encode_argument(4, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        entries = sorted((encode(key), encode(item)) for key, item in value.items())
        return encode_argument(5, len(entries)) + b"".join(
            key + item for key, item in entries
        )
    raise IntegrationError(f"unsupported CBOR value: {type(value).__name__}")


def closed_json_data(data: bytes, label: str) -> dict[str, object]:
    def object_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise IntegrationError(f"duplicate JSON member in {label}: {key}")
            result[key] = value
        return result

    if len(data) > MAX_INPUT_BYTES:
        raise IntegrationError(f"input exceeds the read bound: {label}")
    try:
        value = json.loads(data, object_pairs_hook=object_hook)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IntegrationError(f"invalid JSON input: {label}") from error
    if not isinstance(value, dict):
        raise IntegrationError(f"JSON input is not an object: {label}")
    return value


def closed_json(path: Path) -> dict[str, object]:
    """Read one bounded JSON object and reject duplicate members."""

    if path.is_symlink() or not path.is_file():
        raise IntegrationError(f"input is not a regular file: {path}")
    return closed_json_data(path.read_bytes(), str(path))


def exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise IntegrationError(f"{label} fields are not the closed schema")


def text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IntegrationError(f"invalid {label}")
    return value


def natural(value: object, label: str) -> int:
    if type(value) is not int or value <= 0 or value > MAX_U64:
        raise IntegrationError(f"invalid {label}")
    return value


def admitted_source_url(value: object, ecosystem: str) -> str:
    url = text(value, "registry artifact URL")
    parsed = urlparse(url)
    expected_host = {
        "crates.io": "static.crates.io",
        "npm": "registry.npmjs.org",
        "pypi": "files.pythonhosted.org",
    }[ecosystem]
    try:
        port = parsed.port
    except ValueError as error:
        raise IntegrationError("registry artifact URL has an invalid port") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected_host
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.fragment
    ):
        raise IntegrationError("registry artifact URL is outside the admitted host")
    return url


def digest_file(path: Path) -> tuple[bytes, int]:
    if path.is_symlink() or not path.is_file():
        raise IntegrationError(f"artifact is not a regular file: {path}")
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            size += len(block)
            if size > MAX_ARTIFACT_BYTES:
                raise IntegrationError(f"artifact exceeds the byte bound: {path}")
            hasher.update(block)
    if size == 0:
        raise IntegrationError(f"artifact is empty: {path}")
    return hasher.digest(), size


def inspect_runtime_bundle(
    path: Path, architecture: str, target: str, version: str
) -> list[dict[str, object]]:
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            entries = archive.getmembers()
            if [entry.name for entry in entries] != list(RUNTIME_MEMBERS):
                raise IntegrationError("Runtime bundle member inventory mismatch")
            files: dict[str, bytes] = {}
            for entry in entries:
                if not entry.isfile() or not (0 < entry.size <= MAX_RUNTIME_MEMBER_BYTES):
                    raise IntegrationError(
                        f"Runtime bundle member is not an admitted regular file: {entry.name}"
                    )
                source = archive.extractfile(entry)
                if source is None:
                    raise IntegrationError(
                        f"Runtime bundle member cannot be read: {entry.name}"
                    )
                data = source.read(MAX_RUNTIME_MEMBER_BYTES + 1)
                if len(data) != entry.size:
                    raise IntegrationError(
                        f"Runtime bundle member size changed: {entry.name}"
                    )
                files[entry.name] = data
    except IntegrationError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise IntegrationError("Runtime bundle is not a valid archive") from error

    manifest = closed_json_data(
        files["RELEASE-MANIFEST.json"], f"{path}:RELEASE-MANIFEST.json"
    )
    exact_keys(
        manifest,
        {"architecture", "artifacts", "schema", "target", "toolchain", "version"},
        "Runtime release manifest",
    )
    expected_header = {
        "architecture": architecture,
        "schema": "proofbound-runtime-release-manifest/1",
        "target": target,
        "version": version,
    }
    for field, expected in expected_header.items():
        if manifest[field] != expected:
            raise IntegrationError(f"Runtime release manifest {field} mismatch")
    text(manifest["toolchain"], "Runtime release toolchain")
    raw_artifacts = manifest["artifacts"]
    if not isinstance(raw_artifacts, list) or len(raw_artifacts) != 4:
        raise IntegrationError("Runtime release executable inventory mismatch")
    executables = []
    for index, raw in enumerate(raw_artifacts):
        if not isinstance(raw, dict):
            raise IntegrationError("Runtime release executable is not an object")
        exact_keys(raw, {"name", "sha256", "size"}, "Runtime release executable")
        name = text(raw["name"], "Runtime release executable name")
        if name != RUNTIME_EXECUTABLES[index]:
            raise IntegrationError("Runtime release executable order mismatch")
        digest = text(raw["sha256"], "Runtime release executable digest")
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise IntegrationError("Runtime release executable digest is invalid")
        size = natural(raw["size"], "Runtime release executable size")
        data = files[name]
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise IntegrationError("Runtime release executable identity mismatch")
        executables.append(
            {
                "architecture": architecture,
                "name": name,
                "operating_system": "linux",
                "sha256": bytes.fromhex(digest),
                "size_bytes": size,
                "target": target,
            }
        )
    return executables


def parse_runtime_artifacts(
    specifications: list[str], version: str
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    paths: dict[tuple[str, str], Path] = {}
    for specification in specifications:
        identity, separator, raw_path = specification.partition("=")
        architecture, role_separator, role = identity.partition(":")
        if not separator or not role_separator:
            raise IntegrationError(f"invalid Runtime artifact argument: {specification}")
        key = (architecture, role)
        if key not in RUNTIME_ORDER:
            raise IntegrationError(f"unsupported Runtime artifact role: {identity}")
        if key in paths:
            raise IntegrationError(f"duplicate Runtime artifact role: {identity}")
        paths[key] = Path(raw_path)
    if set(paths) != set(RUNTIME_ORDER):
        raise IntegrationError("Runtime artifact inventory is incomplete")

    result = []
    executables = []
    for architecture, role in RUNTIME_ORDER:
        target = RUNTIME_TARGETS[architecture]
        expected_name = (
            f"proofbound-runtime-v{version}-{target}.tar.gz"
            if role == "runtime-bundle"
            else f"pbr-accept-v{version}-{target}"
        )
        path = paths[(architecture, role)]
        if path.name != expected_name:
            raise IntegrationError(
                f"Runtime {architecture} {role} artifact name mismatch"
            )
        digest, size = digest_file(path)
        result.append(
            {
                "architecture": architecture,
                "artifact": expected_name,
                "operating_system": "linux",
                "role": role,
                "sha256": digest,
                "size_bytes": size,
                "target": target,
            }
        )
        if role == "runtime-bundle":
            observed = inspect_runtime_bundle(path, architecture, target, version)
            if digest_file(path) != (digest, size):
                raise IntegrationError("Runtime bundle changed during inspection")
            executables.extend(observed)
    return result, executables


def registry_packages(path: Path, revision: str) -> tuple[str, list[dict[str, object]]]:
    value = closed_json(path)
    exact_keys(
        value,
        {"observations", "schema", "source_revision", "version"},
        "registry observation",
    )
    if value["schema"] != REGISTRY_SCHEMA:
        raise IntegrationError("registry observation schema is unsupported")
    if value["source_revision"] != revision:
        raise IntegrationError("registry observation source revision mismatch")
    version = text(value["version"], "registry package version")
    if VERSION.fullmatch(version) is None:
        raise IntegrationError("registry package version is invalid")
    observations = value["observations"]
    if not isinstance(observations, list) or len(observations) != len(PACKAGE_ORDER):
        raise IntegrationError("registry package inventory is incomplete")
    result: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    expected_artifacts = (
        f"proofbound-runtime-sdk-{version}.crate",
        f"proofbound-runtime-sdk-{version}.tgz",
        f"proofbound_runtime_sdk-{version}-py3-none-any.whl",
        f"proofbound-runtime-verify-{version}.crate",
    )
    for index, raw in enumerate(observations):
        if not isinstance(raw, dict):
            raise IntegrationError(f"registry package {index} is not an object")
        exact_keys(
            raw,
            {"artifact", "ecosystem", "package", "sha256", "size_bytes", "url"},
            f"registry package {index}",
        )
        ecosystem = text(raw["ecosystem"], "registry ecosystem")
        package = text(raw["package"], "registry package")
        if (ecosystem, package) != PACKAGE_ORDER[index]:
            raise IntegrationError("registry package order or identity mismatch")
        if (ecosystem, package) in seen:
            raise IntegrationError("registry package identity is duplicated")
        seen.add((ecosystem, package))
        artifact = text(raw["artifact"], "registry artifact")
        if Path(artifact).name != artifact or artifact != expected_artifacts[index]:
            raise IntegrationError("registry artifact name mismatch")
        sha256 = text(raw["sha256"], "registry artifact digest")
        if not sha256.startswith("hex:") or HEX_DIGEST.fullmatch(sha256) is None:
            raise IntegrationError("registry artifact digest is invalid")
        result.append(
            {
                "artifact": artifact,
                "ecosystem": ecosystem,
                "package": package,
                "sha256": bytes.fromhex(sha256.removeprefix("hex:")),
                "size_bytes": natural(raw["size_bytes"], "registry artifact size"),
                "source_url": admitted_source_url(raw["url"], ecosystem),
                "version": version,
            }
        )
    return version, result


def proofbound_identity(path: Path) -> dict[str, object]:
    value = closed_json(path)
    exact_keys(
        value,
        {
            "assets",
            "bundle_workflow_run_id",
            "producer_repository",
            "release_id",
            "release_tag",
            "schema",
            "source_revision",
            "verification_run_id",
        },
        "Proofbound tool pin",
    )
    if value["schema"] != PROOFBOUND_PIN_SCHEMA:
        raise IntegrationError("Proofbound tool pin schema is unsupported")
    source_revision = text(value["source_revision"], "Proofbound source revision")
    if REVISION.fullmatch(source_revision) is None:
        raise IntegrationError("Proofbound source revision is invalid")
    if value["producer_repository"] != "bordumb/proof-bound":
        raise IntegrationError("Proofbound producer repository mismatch")
    expected_tag = f"proofbound-tools-{source_revision}"
    if value["release_tag"] != expected_tag:
        raise IntegrationError("Proofbound release tag mismatch")
    raw_assets = value["assets"]
    if not isinstance(raw_assets, list) or len(raw_assets) != 7:
        raise IntegrationError("Proofbound tool asset inventory is incomplete")
    assets: list[dict[str, object]] = []
    previous: bytes | None = None
    expected_assets = (
        ("SHA256SUMS", "checksums"),
        ("TOOL-BUNDLE-PUBLICATION.json", "publication-manifest"),
        ("install-proofbound-tools.py", "installer"),
        (
            f"proofbound-tools-{source_revision}-linux-aarch64.manifest.json",
            "bundle-manifest",
        ),
        (
            f"proofbound-tools-{source_revision}-linux-aarch64.tar.gz",
            "archive",
        ),
        (
            f"proofbound-tools-{source_revision}-linux-x86_64.manifest.json",
            "bundle-manifest",
        ),
        (
            f"proofbound-tools-{source_revision}-linux-x86_64.tar.gz",
            "archive",
        ),
    )
    for index, raw in enumerate(raw_assets):
        if not isinstance(raw, dict):
            raise IntegrationError(f"Proofbound tool asset {index} is not an object")
        exact_keys(raw, {"name", "role", "sha256", "size_bytes"}, "Proofbound asset")
        name = text(raw["name"], "Proofbound asset name")
        encoded_name = name.encode("utf-8")
        if Path(name).name != name or not (1 <= len(encoded_name) <= 256):
            raise IntegrationError("Proofbound asset name is invalid")
        if previous is not None and encoded_name <= previous:
            raise IntegrationError("Proofbound assets are duplicated or out of order")
        previous = encoded_name
        role = text(raw["role"], "Proofbound asset role")
        if (name, role) != expected_assets[index]:
            raise IntegrationError("Proofbound asset identity or role mismatch")
        digest = text(raw["sha256"], "Proofbound asset digest")
        if not digest.startswith("sha256:") or HEX_DIGEST.fullmatch(digest) is None:
            raise IntegrationError("Proofbound asset digest is invalid")
        assets.append(
            {
                "name": name,
                "role": role,
                "sha256": bytes.fromhex(digest.removeprefix("sha256:")),
                "size_bytes": natural(raw["size_bytes"], "Proofbound asset size"),
            }
        )
        if assets[-1]["size_bytes"] > 536_870_912:
            raise IntegrationError("Proofbound asset size exceeds the pin bound")
    return {
        "assets": assets,
        "bundle_workflow_run_id": natural(
            value["bundle_workflow_run_id"], "Proofbound bundle workflow run ID"
        ),
        "producer_repository": "bordumb/proof-bound",
        "receipt_schemas": PROOFBOUND_RECEIPT_SCHEMAS,
        "release_id": natural(value["release_id"], "Proofbound release ID"),
        "release_tag": expected_tag,
        "source_revision": bytes.fromhex(source_revision),
        "verification_run_id": natural(
            value["verification_run_id"], "Proofbound verification run ID"
        ),
    }


def build(
    *,
    revision: str,
    registry_observations: Path,
    runtime_artifacts: list[str],
    proofbound_pin: Path,
) -> dict[str, object]:
    if REVISION.fullmatch(revision) is None:
        raise IntegrationError("source revision must be one lowercase Git object ID")
    version, packages = registry_packages(registry_observations, revision)
    runtime_artifact_values, runtime_executables = parse_runtime_artifacts(
        runtime_artifacts, version
    )
    return {
        "language_profiles": [
            {
                "error_codes": SDK_CODES[language],
                "language": language,
                "minimum_version": LANGUAGE_MINIMUMS[language],
            }
            for language in ("rust", "python", "node")
        ],
        "optional_integrations": [],
        "packages": packages,
        "platform_profiles": [
            {
                "architecture": architecture,
                "operating_system": "linux",
                "target": RUNTIME_TARGETS[architecture],
            }
            for architecture in ("aarch64", "x86_64")
        ],
        "proofbound": proofbound_identity(proofbound_pin),
        "runtime": {
            "artifacts": runtime_artifact_values,
            "executables": runtime_executables,
            "product_label": version,
            "source_revision": bytes.fromhex(revision),
        },
        "schema": SCHEMA,
        "schema_profiles": SCHEMA_PROFILES,
    }


def write_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--registry-observations", required=True, type=Path)
    parser.add_argument("--runtime-artifact", action="append", required=True)
    parser.add_argument("--proofbound-pin", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        value = build(
            revision=arguments.revision,
            registry_observations=arguments.registry_observations,
            runtime_artifacts=arguments.runtime_artifact,
            proofbound_pin=arguments.proofbound_pin,
        )
        write_exclusive(arguments.output.resolve(), encode(value))
    except (OSError, IntegrationError) as error:
        print(f"current-integration build failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
