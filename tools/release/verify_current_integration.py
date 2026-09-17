#!/usr/bin/env python3
"""Independently verify and render one current-integration record."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
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
MAX_CBOR_BYTES = 1_048_576
MAX_CBOR_ITEMS = 4_096
MAX_CBOR_DEPTH = 16
MAX_U64 = (1 << 64) - 1

RUNTIME_TARGETS = {
    "aarch64": "aarch64-unknown-linux-gnu",
    "x86_64": "x86_64-unknown-linux-gnu",
}
RUNTIME_MEMBERS = (
    "RELEASE-MANIFEST.json",
    "pbr",
    "pbr-native-launcher",
    "pbr-verify",
    "pbr-compose",
    "pbr-diagnose",
)
RUNTIME_EXECUTABLES = RUNTIME_MEMBERS[1:]
RUNTIME_ORDER = tuple(
    (architecture, role)
    for architecture in ("aarch64", "x86_64")
    for role in ("runtime-bundle", "acceptor")
)
PACKAGE_ORDER = (
    ("crates.io", "proofbound-runtime-sdk"),
    ("npm", "@proofbound/runtime-sdk"),
    ("pypi", "proofbound-runtime-sdk"),
    ("crates.io", "proofbound-runtime-verify"),
)
EXPECTED_SCHEMAS = [
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
EXPECTED_CODES = {
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
MINIMUMS = {"rust": "1.93", "python": "3.10", "node": "22.6"}
PROOFBOUND_SCHEMAS = [
    "proofbound-release-envelope/7",
    "proofbound-verification-report/3",
    "proofbound-compiled-release/7",
]


class VerificationError(ValueError):
    """One current-integration verification error."""


class CborError(VerificationError):
    """The input is not one complete deterministic-CBOR item."""


@dataclass
class Decoder:
    data: bytes
    offset: int = 0
    item_count: int = 0

    def take(self, length: int) -> bytes:
        end = self.offset + length
        if length < 0 or end > len(self.data):
            raise CborError("truncated CBOR item")
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        if additional == 24:
            value = self.take(1)[0]
            if value < 24:
                raise CborError("non-shortest CBOR argument")
            return value
        widths = {25: 2, 26: 4, 27: 8}
        width = widths.get(additional)
        if width is None:
            label = "indefinite length" if additional == 31 else "reserved argument"
            raise CborError(f"{label} is not admitted")
        value = int.from_bytes(self.take(width), "big")
        if value < {2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[width]:
            raise CborError("non-shortest CBOR argument")
        return value

    def item(self, depth: int = 0) -> Any:
        if depth > MAX_CBOR_DEPTH:
            raise CborError("CBOR nesting exceeds the bound")
        self.item_count += 1
        if self.item_count > MAX_CBOR_ITEMS or self.offset >= len(self.data):
            raise CborError("CBOR item count exceeds the bound or an item is missing")
        initial = self.take(1)[0]
        major = initial >> 5
        additional = initial & 31
        if major == 7:
            if additional == 20:
                return False
            if additional == 21:
                return True
            if additional == 22:
                return None
            raise CborError("CBOR floating-point or simple value is not admitted")
        argument = self.argument(additional)
        if major == 0:
            return argument
        if major == 2:
            return self.take(argument)
        if major == 3:
            try:
                return self.take(argument).decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise CborError("CBOR text is not UTF-8") from error
        if major == 4:
            return [self.item(depth + 1) for _ in range(argument)]
        if major == 5:
            result: dict[str, Any] = {}
            previous_key: bytes | None = None
            for _ in range(argument):
                key_start = self.offset
                key = self.item(depth + 1)
                encoded_key = self.data[key_start : self.offset]
                if not isinstance(key, str):
                    raise CborError("CBOR map key is not text")
                if previous_key is not None and encoded_key <= previous_key:
                    raise CborError("CBOR map keys are duplicated or out of order")
                previous_key = encoded_key
                result[key] = self.item(depth + 1)
            return result
        if major == 1:
            raise CborError("negative CBOR integer is not admitted")
        if major == 6:
            raise CborError("CBOR tag is not admitted")
        raise CborError("unsupported CBOR major type")


def decode_strict(data: bytes) -> object:
    if not data or len(data) > MAX_CBOR_BYTES:
        raise CborError("CBOR input size is outside the bound")
    decoder = Decoder(data)
    value = decoder.item()
    if decoder.offset != len(data):
        raise CborError("CBOR input has trailing bytes")
    return value


def closed_json_data(data: bytes, label: str) -> dict[str, object]:
    def object_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"duplicate JSON member in {label}: {key}")
            result[key] = value
        return result

    if len(data) > MAX_INPUT_BYTES:
        raise VerificationError(f"input exceeds the read bound: {label}")
    try:
        value = json.loads(data, object_pairs_hook=object_hook)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid JSON input: {label}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"JSON input is not an object: {label}")
    return value


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise VerificationError(
            "host cannot open integration inputs without following links"
        )
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise VerificationError(f"input is not a regular file: {path}")
            if before.st_size > maximum:
                raise VerificationError(f"input exceeds the read bound: {label}")
            data = source.read(maximum + 1)
            after = os.fstat(source.fileno())
    except VerificationError:
        raise
    except OSError as error:
        raise VerificationError(f"cannot read input: {path}") from error
    if len(data) > maximum:
        raise VerificationError(f"input exceeds the read bound: {label}")
    if (before.st_dev, before.st_ino, before.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ) or after.st_size != len(data):
        raise VerificationError(f"input changed while read: {label}")
    return data


def closed_json(path: Path) -> dict[str, object]:
    return closed_json_data(read_regular(path, MAX_INPUT_BYTES, str(path)), str(path))


def exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise VerificationError(f"{label} fields are not the closed schema")
    return value


def text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerificationError(f"invalid {label}")
    return value


def bounded_text(value: object, maximum: int, label: str) -> str:
    result = text(value, label)
    if len(result.encode("utf-8")) > maximum:
        raise VerificationError(f"{label} exceeds the byte bound")
    return result


def natural(value: object, label: str) -> int:
    if type(value) is not int or value <= 0 or value > MAX_U64:
        raise VerificationError(f"invalid {label}")
    return value


def admitted_source_url(value: object, ecosystem: str) -> str:
    url = bounded_text(value, 4096, "registry artifact URL")
    parsed = urlparse(url)
    expected_host = {
        "crates.io": "static.crates.io",
        "npm": "registry.npmjs.org",
        "pypi": "files.pythonhosted.org",
    }[ecosystem]
    try:
        port = parsed.port
    except ValueError as error:
        raise VerificationError("registry artifact URL has an invalid port") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected_host
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.fragment
    ):
        raise VerificationError("registry artifact URL is outside the admitted host")
    return url


def file_identity(path: Path) -> tuple[bytes, int]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise VerificationError(
            "host cannot open Runtime artifacts without following links"
        )
    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise VerificationError(f"artifact is not a regular file: {path}")
            if not (0 < before.st_size <= MAX_ARTIFACT_BYTES):
                raise VerificationError(f"artifact exceeds the byte bound: {path}")
            while block := source.read(1024 * 1024):
                size += len(block)
                if size > MAX_ARTIFACT_BYTES:
                    raise VerificationError(f"artifact exceeds the byte bound: {path}")
                digest.update(block)
            after = os.fstat(source.fileno())
    except VerificationError:
        raise
    except OSError as error:
        raise VerificationError(f"cannot read Runtime artifact: {path}") from error
    if size == 0:
        raise VerificationError(f"artifact is empty: {path}")
    if (before.st_dev, before.st_ino, before.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ) or after.st_size != size:
        raise VerificationError(f"artifact changed while read: {path}")
    return digest.digest(), size


def inspect_runtime_bundle(
    path: Path, architecture: str, target: str, version: str
) -> list[dict[str, object]]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise VerificationError(
            "host cannot inspect Runtime bundles without following links"
        )
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
        )
        with os.fdopen(descriptor, "rb") as compressed:
            before = os.fstat(compressed.fileno())
            if not stat.S_ISREG(before.st_mode) or not (
                0 < before.st_size <= MAX_ARTIFACT_BYTES
            ):
                raise VerificationError(
                    "Runtime bundle is not an admitted regular file"
                )
            files: dict[str, bytes] = {}
            with tarfile.open(fileobj=compressed, mode="r|gz") as archive:
                count = 0
                for entry in archive:
                    if count >= len(RUNTIME_MEMBERS):
                        raise VerificationError(
                            "Runtime bundle member inventory mismatch"
                        )
                    expected_name = RUNTIME_MEMBERS[count]
                    if (
                        entry.name != expected_name
                        or not entry.isfile()
                        or not (0 < entry.size <= MAX_RUNTIME_MEMBER_BYTES)
                    ):
                        raise VerificationError(
                            "Runtime bundle member inventory or type mismatch"
                        )
                    source = archive.extractfile(entry)
                    if source is None:
                        raise VerificationError(
                            f"Runtime bundle member cannot be read: {entry.name}"
                        )
                    data = source.read(MAX_RUNTIME_MEMBER_BYTES + 1)
                    if len(data) != entry.size:
                        raise VerificationError(
                            f"Runtime bundle member size changed: {entry.name}"
                        )
                    files[entry.name] = data
                    count += 1
                if count != len(RUNTIME_MEMBERS):
                    raise VerificationError("Runtime bundle member inventory mismatch")
            after = os.fstat(compressed.fileno())
            if (before.st_dev, before.st_ino, before.st_size) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
            ):
                raise VerificationError("Runtime bundle changed during inspection")
    except VerificationError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise VerificationError("Runtime bundle is not a valid archive") from error

    manifest = exact_keys(
        closed_json_data(
            files["RELEASE-MANIFEST.json"], f"{path}:RELEASE-MANIFEST.json"
        ),
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
            raise VerificationError(f"Runtime release manifest {field} mismatch")
    text(manifest["toolchain"], "Runtime release toolchain")
    raw_artifacts = manifest["artifacts"]
    if not isinstance(raw_artifacts, list) or len(raw_artifacts) != len(RUNTIME_EXECUTABLES):
        raise VerificationError("Runtime release executable inventory mismatch")
    executables = []
    for index, raw in enumerate(raw_artifacts):
        item = exact_keys(
            raw,
            {"name", "sha256", "size"},
            f"Runtime release executable {index}",
        )
        name = text(item["name"], "Runtime release executable name")
        if name != RUNTIME_EXECUTABLES[index]:
            raise VerificationError("Runtime release executable order mismatch")
        digest = text(item["sha256"], "Runtime release executable digest")
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise VerificationError("Runtime release executable digest is invalid")
        size = natural(item["size"], "Runtime release executable size")
        data = files[name]
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise VerificationError("Runtime release executable identity mismatch")
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


def expected_runtime(
    specifications: list[str], version: str
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    paths: dict[tuple[str, str], Path] = {}
    for specification in specifications:
        identity, separator, raw_path = specification.partition("=")
        architecture, role_separator, role = identity.partition(":")
        if not separator or not role_separator:
            raise VerificationError(
                f"invalid Runtime artifact argument: {specification}"
            )
        key = (architecture, role)
        if key not in RUNTIME_ORDER or key in paths:
            raise VerificationError(
                f"invalid or duplicate Runtime artifact: {identity}"
            )
        paths[key] = Path(raw_path)
    if set(paths) != set(RUNTIME_ORDER):
        raise VerificationError("Runtime artifact inventory is incomplete")

    artifacts = []
    executables = []
    for architecture, role in RUNTIME_ORDER:
        target = RUNTIME_TARGETS[architecture]
        name = (
            f"proofbound-runtime-v{version}-{target}.tar.gz"
            if role == "runtime-bundle"
            else f"pbr-accept-v{version}-{target}"
        )
        path = paths[(architecture, role)]
        if path.name != name:
            raise VerificationError(f"Runtime {architecture} {role} name mismatch")
        digest, size = file_identity(path)
        artifacts.append(
            {
                "architecture": architecture,
                "artifact": name,
                "operating_system": "linux",
                "role": role,
                "sha256": digest,
                "size_bytes": size,
                "target": target,
            }
        )
        if role == "runtime-bundle":
            observed = inspect_runtime_bundle(path, architecture, target, version)
            if file_identity(path) != (digest, size):
                raise VerificationError("Runtime bundle changed during inspection")
            executables.extend(observed)
    return artifacts, executables


def expected_packages(path: Path, revision: str) -> tuple[str, list[dict[str, object]]]:
    value = exact_keys(
        closed_json(path),
        {"observations", "schema", "source_revision", "version"},
        "registry observation",
    )
    if value["schema"] != REGISTRY_SCHEMA or value["source_revision"] != revision:
        raise VerificationError("registry observation identity mismatch")
    version = bounded_text(value["version"], 64, "package version")
    if VERSION.fullmatch(version) is None:
        raise VerificationError("package version is invalid")
    observations = value["observations"]
    if not isinstance(observations, list) or len(observations) != 4:
        raise VerificationError("registry package inventory is incomplete")
    packages = []
    expected_artifacts = (
        f"proofbound-runtime-sdk-{version}.crate",
        f"proofbound-runtime-sdk-{version}.tgz",
        f"proofbound_runtime_sdk-{version}-py3-none-any.whl",
        f"proofbound-runtime-verify-{version}.crate",
    )
    for index, raw in enumerate(observations):
        item = exact_keys(
            raw,
            {"artifact", "ecosystem", "package", "sha256", "size_bytes", "url"},
            f"registry package {index}",
        )
        identity = (
            text(item["ecosystem"], "registry ecosystem"),
            text(item["package"], "registry package"),
        )
        if identity != PACKAGE_ORDER[index]:
            raise VerificationError("registry package order or identity mismatch")
        artifact = text(item["artifact"], "registry artifact")
        digest = text(item["sha256"], "registry digest")
        if Path(artifact).name != artifact or artifact != expected_artifacts[index]:
            raise VerificationError("registry artifact name mismatch")
        if not digest.startswith("hex:") or HEX_DIGEST.fullmatch(digest) is None:
            raise VerificationError("registry artifact digest is invalid")
        packages.append(
            {
                "artifact": artifact,
                "ecosystem": identity[0],
                "package": identity[1],
                "sha256": bytes.fromhex(digest.removeprefix("hex:")),
                "size_bytes": natural(item["size_bytes"], "registry artifact size"),
                "source_url": admitted_source_url(item["url"], identity[0]),
                "version": version,
            }
        )
    return version, packages


def expected_proofbound(path: Path) -> dict[str, object]:
    value = exact_keys(
        closed_json(path),
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
        raise VerificationError("Proofbound tool pin schema is unsupported")
    source_revision = text(value["source_revision"], "Proofbound source revision")
    if REVISION.fullmatch(source_revision) is None:
        raise VerificationError("Proofbound source revision is invalid")
    if value["producer_repository"] != "bordumb/proof-bound":
        raise VerificationError("Proofbound repository identity mismatch")
    release_tag = f"proofbound-tools-{source_revision}"
    if value["release_tag"] != release_tag:
        raise VerificationError("Proofbound release tag mismatch")
    raw_assets = value["assets"]
    if not isinstance(raw_assets, list) or len(raw_assets) != 7:
        raise VerificationError("Proofbound asset inventory is incomplete")
    assets = []
    previous_name: bytes | None = None
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
        item = exact_keys(
            raw,
            {"name", "role", "sha256", "size_bytes"},
            f"Proofbound asset {index}",
        )
        name = text(item["name"], "Proofbound asset name")
        encoded_name = name.encode("utf-8")
        if Path(name).name != name or not (1 <= len(encoded_name) <= 256):
            raise VerificationError("Proofbound asset name is invalid")
        if previous_name is not None and encoded_name <= previous_name:
            raise VerificationError("Proofbound asset order or identity mismatch")
        previous_name = encoded_name
        role = text(item["role"], "Proofbound asset role")
        if (name, role) != expected_assets[index]:
            raise VerificationError("Proofbound asset identity or role mismatch")
        digest = text(item["sha256"], "Proofbound asset digest")
        if not digest.startswith("sha256:") or HEX_DIGEST.fullmatch(digest) is None:
            raise VerificationError("Proofbound asset digest is invalid")
        assets.append(
            {
                "name": name,
                "role": role,
                "sha256": bytes.fromhex(digest.removeprefix("sha256:")),
                "size_bytes": natural(item["size_bytes"], "Proofbound asset size"),
            }
        )
        if assets[-1]["size_bytes"] > 536_870_912:
            raise VerificationError("Proofbound asset size exceeds the pin bound")
    return {
        "assets": assets,
        "bundle_workflow_run_id": natural(
            value["bundle_workflow_run_id"], "Proofbound bundle workflow run ID"
        ),
        "producer_repository": "bordumb/proof-bound",
        "receipt_schemas": PROOFBOUND_SCHEMAS,
        "release_id": natural(value["release_id"], "Proofbound release ID"),
        "release_tag": release_tag,
        "source_revision": bytes.fromhex(source_revision),
        "verification_run_id": natural(
            value["verification_run_id"], "Proofbound verification run ID"
        ),
    }


def expected_record(
    *,
    revision: str,
    registry_observations: Path,
    runtime_artifacts: list[str],
    proofbound_pin: Path,
) -> dict[str, object]:
    if REVISION.fullmatch(revision) is None:
        raise VerificationError("expected revision is not one lowercase Git object ID")
    version, packages = expected_packages(registry_observations, revision)
    runtime_artifact_values, runtime_executables = expected_runtime(
        runtime_artifacts, version
    )
    return {
        "language_profiles": [
            {
                "error_codes": EXPECTED_CODES[language],
                "language": language,
                "minimum_version": MINIMUMS[language],
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
        "proofbound": expected_proofbound(proofbound_pin),
        "runtime": {
            "artifacts": runtime_artifact_values,
            "executables": runtime_executables,
            "product_label": version,
            "source_revision": bytes.fromhex(revision),
        },
        "schema": SCHEMA,
        "schema_profiles": EXPECTED_SCHEMAS,
    }


def validate_shape(value: object) -> dict[str, object]:
    root = exact_keys(
        value,
        {
            "language_profiles",
            "optional_integrations",
            "packages",
            "platform_profiles",
            "proofbound",
            "runtime",
            "schema",
            "schema_profiles",
        },
        "current-integration record",
    )
    if root["schema"] != SCHEMA:
        raise VerificationError("current-integration schema is unsupported")
    return root


def project(value: object) -> object:
    if isinstance(value, bytes):
        return f"hex:{value.hex()}"
    if isinstance(value, list):
        return [project(item) for item in value]
    if isinstance(value, dict):
        return {key: project(item) for key, item in value.items()}
    return value


def markdown(value: dict[str, object]) -> str:
    runtime = value["runtime"]
    proofbound = value["proofbound"]
    assert isinstance(runtime, dict)
    assert isinstance(proofbound, dict)
    revision = runtime["source_revision"]
    proofbound_revision = proofbound["source_revision"]
    assert isinstance(revision, bytes)
    assert isinstance(proofbound_revision, bytes)
    lines = [
        "# Proofbound Runtime current integration",
        "",
        f"- Runtime source: `{revision.hex()}`",
        f"- Product label: `{runtime['product_label']}`",
        f"- Proofbound source: `{proofbound_revision.hex()}`",
        f"- Proofbound release: `{proofbound['release_tag']}`",
        "",
        "This document names one exact supported prelaunch tuple. An identity that is",
        "absent from this document is unsupported. Digests name exact bytes; this record",
        "does not authenticate Runtime, Proofbound, GitHub, or a package publisher.",
        "",
        "## Runtime artifacts",
        "",
        "| Platform | Role | Artifact | SHA-256 | Size |",
        "| --- | --- | --- | --- | ---: |",
    ]
    artifacts = runtime["artifacts"]
    assert isinstance(artifacts, list)
    for artifact in artifacts:
        assert isinstance(artifact, dict)
        digest = artifact["sha256"]
        assert isinstance(digest, bytes)
        lines.append(
            f"| linux/{artifact['architecture']} | {artifact['role']} | "
            f"`{artifact['artifact']}` | `{digest.hex()}` | {artifact['size_bytes']} |"
        )
    lines.extend(
        [
            "",
            "## Registry packages",
            "",
            "| Ecosystem | Package | Artifact | SHA-256 | Size |",
            "| --- | --- | --- | --- | ---: |",
        ]
    )
    packages = value["packages"]
    assert isinstance(packages, list)
    for package in packages:
        assert isinstance(package, dict)
        digest = package["sha256"]
        assert isinstance(digest, bytes)
        lines.append(
            f"| {package['ecosystem']} | `{package['package']}` | "
            f"`{package['artifact']}` | `{digest.hex()}` | {package['size_bytes']} |"
        )
    lines.extend(
        [
            "",
            "## Runtime bundle executables",
            "",
            "| Platform | Executable | SHA-256 | Size |",
            "| --- | --- | --- | ---: |",
        ]
    )
    executables = runtime["executables"]
    assert isinstance(executables, list)
    for executable in executables:
        assert isinstance(executable, dict)
        digest = executable["sha256"]
        assert isinstance(digest, bytes)
        lines.append(
            f"| linux/{executable['architecture']} | `{executable['name']}` | "
            f"`{digest.hex()}` | {executable['size_bytes']} |"
        )
    lines.extend(["", "## Wire schemas", ""])
    schemas = value["schema_profiles"]
    assert isinstance(schemas, list)
    for profile in schemas:
        assert isinstance(profile, dict)
        emitted = ", ".join(f"`{item}`" for item in profile["emitted"]) or "none"
        accepted = ", ".join(f"`{item}`" for item in profile["accepted"])
        lines.append(f"- {profile['surface']}: emits {emitted}; accepts {accepted}.")
    lines.extend(["", "## Language profiles and closed SDK errors", ""])
    languages = value["language_profiles"]
    assert isinstance(languages, list)
    for language in languages:
        assert isinstance(language, dict)
        codes = ", ".join(f"`{code}`" for code in language["error_codes"])
        lines.append(
            f"- {language['language']} >= {language['minimum_version']}: {codes}."
        )
    lines.extend(
        [
            "",
            "## Optional integrations",
            "",
            "None. No Auths, Capsec, guest, service, or other optional profile is part of",
            "this Runtime-only tuple.",
            "",
        ]
    )
    return "\n".join(lines)


def write_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--registry-observations", required=True, type=Path)
    parser.add_argument("--runtime-artifact", action="append", required=True)
    parser.add_argument("--proofbound-pin", required=True, type=Path)
    parser.add_argument("--projection", type=Path)
    parser.add_argument("--rendering", type=Path)
    arguments = parser.parse_args()
    try:
        record_path = arguments.record
        actual = validate_shape(
            decode_strict(
                read_regular(record_path, MAX_CBOR_BYTES, "current-integration record")
            )
        )
        expected = expected_record(
            revision=arguments.expected_revision,
            registry_observations=arguments.registry_observations,
            runtime_artifacts=arguments.runtime_artifact,
            proofbound_pin=arguments.proofbound_pin,
        )
        if actual != expected:
            raise VerificationError("record differs from the exact integration inputs")
        if arguments.projection is not None:
            encoded = json.dumps(
                project(actual), sort_keys=True, separators=(",", ":")
            ).encode()
            write_exclusive(arguments.projection.resolve(), encoded + b"\n")
        if arguments.rendering is not None:
            write_exclusive(arguments.rendering.resolve(), markdown(actual).encode())
    except (OSError, VerificationError) as error:
        print(f"current-integration verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
