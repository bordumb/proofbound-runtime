#!/usr/bin/env python3
"""Independently verify one retained Runtime verifier-package manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from tools.ci.deterministic_cbor import CborError, decode_strict


PACKAGE = "proofbound-runtime-verify"
BINARY = "pbr-verify"
SCHEMA = "proofbound-runtime-verifier-package-manifest/1"
SUPPORTED_RECEIPT_SCHEMAS = [
    "proofbound-runtime-receipt/1",
    "proofbound-runtime-execution-receipt/2",
]
MANIFEST_KEYS = {
    "artifacts",
    "binary",
    "package",
    "schema",
    "source_revision",
    "supported_receipt_schemas",
    "version",
}
ARTIFACT_KEYS = {"name", "sha256", "size"}
GIT_REVISION = re.compile(r"[0-9a-f]{40}")
TREE_REVISION = re.compile(r"tree-sha256:[0-9a-f]{64}")
PACKAGE_LABEL = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
)
EXPECTED_CDDL = r"""verifier-package-manifest = {
  "schema": "proofbound-runtime-verifier-package-manifest/1",
  "source_revision": git-revision / tree-revision,
  "package": "proofbound-runtime-verify",
  "binary": "pbr-verify",
  "version": package-label,
  "supported_receipt_schemas": [
    "proofbound-runtime-receipt/1",
    "proofbound-runtime-execution-receipt/2",
  ],
  "artifacts": [verifier-package-artifact],
}

git-revision = (text .size 40) .regexp "[0-9a-f]{40}"
tree-revision = (text .size 76) .regexp "tree-sha256:[0-9a-f]{64}"
package-label = (text .size (5..64)) .regexp "[0-9]+\\.[0-9]+\\.[0-9]+[-+0-9A-Za-z.]*"

verifier-package-artifact = {
  "name": (text .size (38..101)) .regexp "proofbound-runtime-verify-[0-9A-Za-z.+-]+\\.crate",
  "sha256": bytes .size 32,
  "size": 1..18446744073709551615,
}
"""


class ManifestError(ValueError):
    """The manifest or its retained artifact violates the closed contract."""


def validate_cddl(content: str) -> None:
    """Require the reviewed CDDL contract used by this independent verifier."""

    if content != EXPECTED_CDDL:
        raise ManifestError("the CDDL differs from the independently checked contract")


def _closed_map(value: object, keys: set[str], name: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ManifestError(f"{name} does not have the exact registered fields")
    if any(not isinstance(key, str) for key in value):
        raise ManifestError(f"{name} contains a non-text key")
    return value


def validate_manifest(
    value: object,
    *,
    expected_source_revision: str,
    expected_version: str,
    archive_name: str,
    archive_bytes: bytes,
) -> None:
    """Validate exact manifest semantics and the retained archive identity."""

    manifest = _closed_map(value, MANIFEST_KEYS, "manifest")
    if manifest["schema"] != SCHEMA:
        raise ManifestError("the manifest schema is not the selected schema")
    if manifest["package"] != PACKAGE or manifest["binary"] != BINARY:
        raise ManifestError("the package or binary identity is not selected")
    source_revision = manifest["source_revision"]
    if not isinstance(source_revision, str) or not (
        GIT_REVISION.fullmatch(source_revision)
        or TREE_REVISION.fullmatch(source_revision)
    ):
        raise ManifestError("the source revision is not an exact admitted identity")
    if source_revision != expected_source_revision:
        raise ManifestError("the source revision differs from the selected revision")
    version = manifest["version"]
    if not isinstance(version, str) or PACKAGE_LABEL.fullmatch(version) is None:
        raise ManifestError("the package label is not an admitted Cargo label")
    if version != expected_version:
        raise ManifestError("the package label differs from the selected label")
    if manifest["supported_receipt_schemas"] != SUPPORTED_RECEIPT_SCHEMAS:
        raise ManifestError(
            "the receipt schema inventory is not the selected inventory"
        )
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise ManifestError("the artifact inventory is not a singleton")
    artifact = _closed_map(artifacts[0], ARTIFACT_KEYS, "artifact")
    expected_name = f"{PACKAGE}-{expected_version}.crate"
    if archive_name != expected_name or artifact["name"] != expected_name:
        raise ManifestError(
            "the archive name is not derived from the selected package label"
        )
    digest = artifact["sha256"]
    size = artifact["size"]
    if not isinstance(digest, bytes) or len(digest) != 32:
        raise ManifestError("the archive digest is not one SHA-256 value")
    if type(size) is not int or not 1 <= size < 1 << 64:
        raise ManifestError("the archive size is outside the admitted u64 range")
    if size != len(archive_bytes):
        raise ManifestError("the archive size differs from the retained bytes")
    if digest != hashlib.sha256(archive_bytes).digest():
        raise ManifestError("the archive digest differs from the retained bytes")


def verify(
    manifest_path: Path,
    archive_path: Path,
    cddl_path: Path,
    expected_source_revision: str,
    expected_version: str,
) -> None:
    """Decode and validate one canonical manifest and retained archive."""

    try:
        validate_cddl(cddl_path.read_text(encoding="utf-8"))
        manifest_bytes = manifest_path.read_bytes()
        archive_bytes = archive_path.read_bytes()
        value = decode_strict(
            manifest_bytes,
            max_bytes=64 * 1024,
            max_depth=8,
            max_items=64,
        )
    except (OSError, UnicodeError, CborError) as error:
        raise ManifestError(str(error)) from error
    validate_manifest(
        value,
        expected_source_revision=expected_source_revision,
        expected_version=expected_version,
        archive_name=archive_path.name,
        archive_bytes=archive_bytes,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--cddl", type=Path, required=True)
    parser.add_argument("--expected-source-revision", required=True)
    parser.add_argument("--expected-version", required=True)
    arguments = parser.parse_args()
    try:
        verify(
            arguments.manifest,
            arguments.archive,
            arguments.cddl,
            arguments.expected_source_revision,
            arguments.expected_version,
        )
    except ManifestError as error:
        print(
            f"verifier package manifest verification failed: {error}", file=sys.stderr
        )
        return 1
    print(
        json.dumps(
            {
                "accepted": True,
                "schema": "proofbound-runtime-verifier-package-manifest-check/1",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
