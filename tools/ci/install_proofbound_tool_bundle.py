#!/usr/bin/env python3
"""Install one exact public Proofbound tool bundle."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Callable
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


PIN_SCHEMA = "proofbound-runtime-proofbound-tool-pin/1"
PUBLICATION_SCHEMA = "proofbound-tool-bundle-publication-manifest/1"
BUNDLE_SCHEMA = "proofbound-tool-bundle-manifest/1"
PRODUCER_REPOSITORY = "bordumb/proof-bound"
PUBLICATION_NAME = "TOOL-BUNDLE-PUBLICATION.json"
CHECKSUMS_NAME = "SHA256SUMS"
INSTALLER_NAME = "install-proofbound-tools.py"
PLATFORMS = ("linux-aarch64", "linux-x86_64")
BINARY_NAMES = (
    "proofbound",
    "proofbound-adapter-aeneas",
    "proofbound-adapter-kani",
    "proofbound-adapter-lean",
    "proofbound-adapter-node",
    "proofbound-adapter-test",
    "proofbound-verify",
)
DOCUMENT_PATHS = (
    "LICENSE",
    "README.md",
    "docs/guides/release-verification.md",
)
SCHEMA_PATHS = (
    "schemas/README.md",
    "schemas/adapter-observation.schema.json",
    "schemas/adapter-protocol.schema.json",
    "schemas/assumption.schema.json",
    "schemas/checker-result.schema.json",
    "schemas/claim.schema.json",
    "schemas/closure.schema.json",
    "schemas/demo-registry.schema.json",
    "schemas/error.schema.json",
    "schemas/evidence-unit.schema.json",
    "schemas/evidence.schema.json",
    "schemas/graph.schema.json",
    "schemas/lean-expr-v1.cddl",
    "schemas/model-check-unit.schema.json",
    "schemas/mutation-registry.schema.json",
    "schemas/observation-inputs.schema.json",
    "schemas/policy.schema.json",
    "schemas/project.schema.json",
    "schemas/receipt.schema.json",
    "schemas/report.schema.json",
    "schemas/review.schema.json",
    "schemas/tcb.schema.json",
    "schemas/tool-bundle-manifest.schema.json",
    "schemas/tool-bundle-publication-manifest.schema.json",
    "schemas/translation-toolchain-lock.schema.json",
    "schemas/translation-unit.schema.json",
)
BUNDLE_PAYLOAD_PATHS = tuple(
    sorted(
        (
            *(f"bin/{name}" for name in BINARY_NAMES),
            *DOCUMENT_PATHS,
            *SCHEMA_PATHS,
        )
    )
)
REVISION = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}")
PAYLOAD_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,4095}")
TOOL_LABEL = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
MAX_PIN_BYTES = 128 * 1024
MAX_RELEASE_RECORD_BYTES = 8 * 1024 * 1024
MAX_ASSET_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_ARTIFACTS = 4096
MAX_TAG_DEPTH = 8
EMBEDDED_MANIFEST_NAME = "TOOL-BUNDLE-MANIFEST.json"
DEFAULT_PIN = (
    Path(__file__).resolve().parents[2]
    / "proofbound"
    / "toolchains"
    / "proofbound-tool-bundle-pin.json"
)


class ToolBundleError(ValueError):
    """One fail-closed tool-bundle installation error."""


def _duplicate_guard(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ToolBundleError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _decode_json(data: bytes, description: str) -> object:
    try:
        return json.loads(data, object_pairs_hook=_duplicate_guard)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ToolBundleError(f"cannot parse {description}: {error}") from error


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _read_regular(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ToolBundleError(f"not a regular file: {path}")
            data = source.read(limit + 1)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise ToolBundleError(f"cannot read {path}: {error}") from error
    if len(data) > limit:
        raise ToolBundleError(f"file is too large: {path}")
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or after.st_size != len(data)
    ):
        raise ToolBundleError(f"file changed while read: {path}")
    return data


def _required_assets(revision: str) -> dict[str, str]:
    assets = {
        CHECKSUMS_NAME: "checksums",
        INSTALLER_NAME: "installer",
        PUBLICATION_NAME: "publication-manifest",
    }
    for platform in PLATFORMS:
        assets[f"proofbound-tools-{revision}-{platform}.tar.gz"] = "archive"
        assets[f"proofbound-tools-{revision}-{platform}.manifest.json"] = (
            "bundle-manifest"
        )
    return assets


def _asset_records(
    value: object, expected: dict[str, str], description: str
) -> dict[str, dict[str, object]]:
    if not isinstance(value, list) or len(value) != len(expected):
        raise ToolBundleError(f"{description} asset inventory is not exact")
    result: dict[str, dict[str, object]] = {}
    previous = ""
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "name",
            "role",
            "sha256",
            "size_bytes",
        }:
            raise ToolBundleError(f"{description} asset record is malformed")
        name = item["name"]
        role = item["role"]
        digest = item["sha256"]
        size = item["size_bytes"]
        if not isinstance(name, str) or ASSET_NAME.fullmatch(name) is None:
            raise ToolBundleError(f"{description} asset name is invalid")
        if name <= previous or name not in expected or role != expected[name]:
            raise ToolBundleError(f"{description} asset set or role differs")
        if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
            raise ToolBundleError(f"{description} asset digest is invalid: {name}")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 < size <= MAX_ASSET_BYTES
        ):
            raise ToolBundleError(f"{description} asset size is invalid: {name}")
        result[name] = item
        previous = name
    if set(result) != set(expected):
        raise ToolBundleError(f"{description} asset inventory differs")
    return result


def validate_pin(value: object) -> dict[str, object]:
    """Validate and return one exact Runtime-owned Proofbound bundle pin."""

    if not isinstance(value, dict) or set(value) != {
        "assets",
        "bundle_workflow_run_id",
        "producer_repository",
        "release_id",
        "release_tag",
        "schema",
        "source_revision",
        "verification_run_id",
    }:
        raise ToolBundleError("tool-bundle pin fields are not exact")
    if value["schema"] != PIN_SCHEMA:
        raise ToolBundleError("tool-bundle pin schema is unsupported")
    if value["producer_repository"] != PRODUCER_REPOSITORY:
        raise ToolBundleError("tool-bundle producer repository differs")
    revision = value["source_revision"]
    if not isinstance(revision, str) or REVISION.fullmatch(revision) is None:
        raise ToolBundleError("tool-bundle source revision is invalid")
    if value["release_tag"] != f"proofbound-tools-{revision}":
        raise ToolBundleError("tool-bundle release tag differs")
    for key in ("verification_run_id", "bundle_workflow_run_id", "release_id"):
        item = value[key]
        if not isinstance(item, int) or isinstance(item, bool) or item < 1:
            raise ToolBundleError(f"tool-bundle {key} is invalid")
    _asset_records(value["assets"], _required_assets(revision), "pin")
    return value


def load_pin(path: Path = DEFAULT_PIN) -> dict[str, object]:
    """Read one canonical exact-identity pin from a regular file."""

    data = _read_regular(path, MAX_PIN_BYTES)
    pin = validate_pin(_decode_json(data, "tool-bundle pin"))
    if _canonical_json(pin) != data:
        raise ToolBundleError("tool-bundle pin is not canonical JSON")
    return pin


def validate_release(value: object, pin: dict[str, object]) -> None:
    """Require a public immutable release that equals the reviewed pin."""

    if not isinstance(value, dict):
        raise ToolBundleError("hosted release record is not an object")
    required = {
        "assets",
        "draft",
        "id",
        "immutable",
        "prerelease",
        "tag_name",
        "target_commitish",
    }
    if not required.issubset(value):
        raise ToolBundleError("hosted release record omits required fields")
    if (
        not isinstance(value["id"], int)
        or isinstance(value["id"], bool)
        or value["id"] != pin["release_id"]
        or value["tag_name"] != pin["release_tag"]
        or value["target_commitish"] != pin["source_revision"]
        or value["draft"] is not False
        or value["prerelease"] is not False
        or value["immutable"] is not True
    ):
        raise ToolBundleError("hosted release identity or state differs")
    pin_assets = {item["name"]: item for item in pin["assets"]}
    hosted_assets = value["assets"]
    if not isinstance(hosted_assets, list) or len(hosted_assets) != len(pin_assets):
        raise ToolBundleError("hosted release asset inventory differs")
    observed: dict[str, tuple[object, object]] = {}
    for item in hosted_assets:
        if not isinstance(item, dict):
            raise ToolBundleError("hosted release asset record is malformed")
        name = item.get("name")
        if (
            not isinstance(name, str)
            or name in observed
            or item.get("state") != "uploaded"
            or not isinstance(item.get("digest"), str)
            or not isinstance(item.get("size"), int)
            or isinstance(item.get("size"), bool)
        ):
            raise ToolBundleError("hosted release asset record is invalid")
        observed[name] = (item.get("digest"), item.get("size"))
    expected = {
        name: (item["sha256"], item["size_bytes"]) for name, item in pin_assets.items()
    }
    if observed != expected:
        raise ToolBundleError("hosted release asset identities differ")


def _git_object(value: object, description: str) -> tuple[str, str]:
    if not isinstance(value, dict) or not isinstance(value.get("object"), dict):
        raise ToolBundleError(f"{description} omits its Git object")
    item = value["object"]
    kind = item.get("type")
    digest = item.get("sha")
    if (
        kind not in {"commit", "tag"}
        or not isinstance(digest, str)
        or REVISION.fullmatch(digest) is None
    ):
        raise ToolBundleError(f"{description} Git object is invalid")
    return kind, digest


def validate_tag_target(
    pin: dict[str, object], fetch: Callable[[str, int], bytes]
) -> None:
    """Resolve the hosted tag and require the exact pinned source commit."""

    repository = str(pin["producer_repository"])
    tag = str(pin["release_tag"])
    root = f"https://api.github.com/repos/{repository}/git"
    record = _decode_json(
        fetch(f"{root}/ref/tags/{quote(tag, safe='')}", MAX_RELEASE_RECORD_BYTES),
        "release tag reference",
    )
    if not isinstance(record, dict) or record.get("ref") != f"refs/tags/{tag}":
        raise ToolBundleError("release tag reference identity differs")
    kind, digest = _git_object(record, "release tag reference")
    seen: set[str] = set()
    for _ in range(MAX_TAG_DEPTH):
        if kind == "commit":
            if digest != pin["source_revision"]:
                raise ToolBundleError("release tag target differs from the pin")
            return
        if digest in seen:
            raise ToolBundleError("release tag chain contains a cycle")
        seen.add(digest)
        requested = digest
        record = _decode_json(
            fetch(f"{root}/tags/{requested}", MAX_RELEASE_RECORD_BYTES),
            "annotated release tag",
        )
        if not isinstance(record, dict) or record.get("sha") != requested:
            raise ToolBundleError("annotated release tag identity differs")
        kind, digest = _git_object(record, "annotated release tag")
    raise ToolBundleError("release tag chain is too deep")


def validate_publication(value: object, pin: dict[str, object]) -> None:
    """Require the upstream publication manifest to equal the pin subset."""

    if not isinstance(value, dict) or set(value) != {
        "assets",
        "bundle_workflow_run_id",
        "producer_repository",
        "release_tag",
        "schema",
        "source_revision",
        "verification_run_id",
    }:
        raise ToolBundleError("publication manifest fields are not exact")
    for field in (
        "bundle_workflow_run_id",
        "producer_repository",
        "release_tag",
        "source_revision",
        "verification_run_id",
    ):
        if value[field] != pin[field]:
            raise ToolBundleError(f"publication manifest {field} differs")
    if value["schema"] != PUBLICATION_SCHEMA:
        raise ToolBundleError("publication manifest schema is unsupported")
    revision = str(pin["source_revision"])
    expected = _required_assets(revision)
    del expected[CHECKSUMS_NAME]
    del expected[PUBLICATION_NAME]
    publication_assets = _asset_records(value["assets"], expected, "publication")
    pin_assets = {item["name"]: item for item in pin["assets"]}
    if any(publication_assets[name] != pin_assets[name] for name in expected):
        raise ToolBundleError("publication asset identities differ from the pin")


def validate_bundle_manifest(
    value: object, pin: dict[str, object], platform: str
) -> dict[str, dict[str, object]]:
    """Validate the selected detached manifest and return its binary records."""

    if not isinstance(value, dict) or set(value) != {
        "artifacts",
        "platform",
        "product_label",
        "rust_toolchain",
        "schema",
        "source_revision",
        "verification_run_id",
    }:
        raise ToolBundleError("bundle manifest fields are not exact")
    if (
        value["schema"] != BUNDLE_SCHEMA
        or value["source_revision"] != pin["source_revision"]
        or value["verification_run_id"] != pin["verification_run_id"]
        or value["platform"] != platform
    ):
        raise ToolBundleError("bundle manifest identity differs")
    if (
        not isinstance(value["product_label"], str)
        or TOOL_LABEL.fullmatch(value["product_label"]) is None
        or not isinstance(value["rust_toolchain"], str)
        or TOOL_LABEL.fullmatch(value["rust_toolchain"]) is None
    ):
        raise ToolBundleError("bundle manifest metadata is malformed")
    artifacts = value["artifacts"]
    if (
        not isinstance(artifacts, list)
        or not 0 < len(artifacts) <= MAX_BUNDLE_ARTIFACTS
    ):
        raise ToolBundleError("bundle manifest artifact inventory is malformed")
    binaries: dict[str, dict[str, object]] = {}
    paths: list[str] = []
    previous = ""
    for record in artifacts:
        if not isinstance(record, dict) or set(record) != {
            "executable",
            "path",
            "sha256",
            "size_bytes",
        }:
            raise ToolBundleError("bundle manifest artifact record is malformed")
        path = record["path"]
        digest = record["sha256"]
        size = record["size_bytes"]
        executable = record["executable"]
        if (
            not isinstance(path, str)
            or PAYLOAD_PATH.fullmatch(path) is None
            or path <= previous
            or "\\" in path
            or path.startswith("/")
            or any(component in {"", ".", ".."} for component in path.split("/"))
        ):
            raise ToolBundleError("bundle manifest artifact paths are not a safe set")
        if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
            raise ToolBundleError(f"bundle manifest artifact digest is invalid: {path}")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= MAX_ASSET_BYTES
            or not isinstance(executable, bool)
        ):
            raise ToolBundleError(
                f"bundle manifest artifact metadata is invalid: {path}"
            )
        if executable is not path.startswith("bin/"):
            raise ToolBundleError(f"bundle manifest artifact mode differs: {path}")
        if path.startswith("bin/"):
            name = path.removeprefix("bin/")
            if name not in BINARY_NAMES:
                raise ToolBundleError("bundle manifest binary inventory differs")
            binaries[name] = record
        paths.append(path)
        previous = path
    if tuple(paths) != BUNDLE_PAYLOAD_PATHS or tuple(binaries) != BINARY_NAMES:
        raise ToolBundleError("bundle manifest payload inventory differs")
    return binaries


def validate_detached_manifest(
    data: bytes, pin: dict[str, object], platform: str
) -> dict[str, dict[str, object]]:
    """Require canonical bytes in the complete current manifest domain."""

    value = _decode_json(data, "bundle manifest")
    if _canonical_json(value) != data:
        raise ToolBundleError("bundle manifest is not canonical JSON")
    return validate_bundle_manifest(value, pin, platform)


def validate_embedded_manifest(
    archive_bytes: bytes,
    detached_manifest_bytes: bytes,
    pin: dict[str, object],
    platform: str,
) -> None:
    """Require the archive's embedded manifest to equal the detached bytes."""

    revision = str(pin["source_revision"])
    expected = f"proofbound-tools-{revision}-{platform}/{EMBEDDED_MANIFEST_NAME}"
    embedded: bytes | None = None
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r|gz") as archive:
            for index, member in enumerate(archive, start=1):
                if index > MAX_BUNDLE_ARTIFACTS + 1:
                    raise ToolBundleError(
                        "bundle archive member inventory is too large"
                    )
                if member.name != expected:
                    continue
                if (
                    embedded is not None
                    or not member.isfile()
                    or not 0 < member.size <= MAX_PIN_BYTES
                ):
                    raise ToolBundleError("embedded bundle manifest is invalid")
                source = archive.extractfile(member)
                if source is None:
                    raise ToolBundleError("embedded bundle manifest cannot be read")
                embedded = source.read(MAX_PIN_BYTES + 1)
                if len(embedded) != member.size:
                    raise ToolBundleError("embedded bundle manifest size differs")
    except (EOFError, OSError, tarfile.TarError) as error:
        raise ToolBundleError(f"cannot inspect bundle archive: {error}") from error
    if embedded is None:
        raise ToolBundleError("bundle archive omits its embedded manifest")
    if embedded != detached_manifest_bytes:
        raise ToolBundleError("embedded and detached bundle manifests differ")


def _parse_checksums(data: bytes, pin: dict[str, object]) -> None:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ToolBundleError("published checksums are not ASCII") from error
    expected = {
        item["name"]: str(item["sha256"]).removeprefix("sha256:")
        for item in pin["assets"]
        if item["name"] != CHECKSUMS_NAME
    }
    observed: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(
            r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,255})", line
        )
        if match is None or match.group(2) in observed:
            raise ToolBundleError("published checksums are not a canonical unique set")
        observed[match.group(2)] = match.group(1)
    if list(observed) != sorted(observed):
        raise ToolBundleError("published checksums are not ordered by asset name")
    if text != "".join(f"{digest}  {name}\n" for name, digest in observed.items()):
        raise ToolBundleError("published checksums are not canonical")
    if observed != expected:
        raise ToolBundleError("published checksums differ from the pin")


def _request_headers(url: str) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "proofbound-runtime-ci",
    }
    token = os.environ.get("GITHUB_TOKEN")
    parsed = urlsplit(url)
    if token and parsed.hostname == "api.github.com":
        if parsed.scheme != "https" or parsed.netloc != "api.github.com":
            raise ToolBundleError("GitHub API credential origin is invalid")
        if token != token.strip() or any(character in token for character in "\0\n\r"):
            raise ToolBundleError("GitHub API credential is malformed")
        headers["Authorization"] = f"Bearer {token}"
    return headers


class _CredentialRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self, request, file_pointer, code, message, headers, new_url
    ):
        if request.has_header("Authorization"):
            raise ToolBundleError("credential-bearing GitHub API request redirected")
        return super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )


def _fetch(url: str, limit: int) -> bytes:
    request = Request(
        url,
        headers=_request_headers(url),
    )
    try:
        with build_opener(_CredentialRedirectHandler()).open(
            request, timeout=30
        ) as response:
            if urlsplit(str(response.geturl())).scheme != "https":
                raise ToolBundleError("download redirected outside HTTPS")
            data = response.read(limit + 1)
    except OSError as error:
        raise ToolBundleError(f"cannot download {url}: {error}") from error
    if len(data) > limit:
        raise ToolBundleError(f"download is too large: {url}")
    return data


def _checked_asset(
    name: str,
    pin_assets: dict[str, dict[str, object]],
    fetch: Callable[[str, int], bytes],
    public_root: str,
) -> bytes:
    record = pin_assets[name]
    data = fetch(f"{public_root}/{quote(name)}", int(record["size_bytes"]) + 1)
    observed = f"sha256:{hashlib.sha256(data).hexdigest()}"
    if len(data) != record["size_bytes"] or observed != record["sha256"]:
        raise ToolBundleError(f"downloaded asset identity differs: {name}")
    return data


def install(
    pin: dict[str, object],
    platform: str,
    destination: Path,
    fetch: Callable[[str, int], bytes] = _fetch,
) -> None:
    """Download, verify, and install one pinned public platform bundle."""

    pin = validate_pin(pin)
    if platform not in PLATFORMS:
        raise ToolBundleError("requested Proofbound tool platform is unsupported")
    repository = str(pin["producer_repository"])
    release_id = int(pin["release_id"])
    release_url = f"https://api.github.com/repos/{repository}/releases/{release_id}"
    release = _decode_json(
        fetch(release_url, MAX_RELEASE_RECORD_BYTES), "release record"
    )
    validate_release(release, pin)
    validate_tag_target(pin, fetch)
    tag = str(pin["release_tag"])
    public_root = f"https://github.com/{repository}/releases/download/{tag}"
    pin_assets = {item["name"]: item for item in pin["assets"]}
    checksums = _checked_asset(CHECKSUMS_NAME, pin_assets, fetch, public_root)
    _parse_checksums(checksums, pin)
    publication_bytes = _checked_asset(PUBLICATION_NAME, pin_assets, fetch, public_root)
    publication = _decode_json(publication_bytes, "publication manifest")
    validate_publication(publication, pin)
    revision = str(pin["source_revision"])
    archive_name = f"proofbound-tools-{revision}-{platform}.tar.gz"
    manifest_name = f"proofbound-tools-{revision}-{platform}.manifest.json"
    archive_bytes = _checked_asset(archive_name, pin_assets, fetch, public_root)
    manifest_bytes = _checked_asset(manifest_name, pin_assets, fetch, public_root)
    binary_records = validate_detached_manifest(manifest_bytes, pin, platform)
    validate_embedded_manifest(archive_bytes, manifest_bytes, pin, platform)
    installer_bytes = _checked_asset(INSTALLER_NAME, pin_assets, fetch, public_root)
    with tempfile.TemporaryDirectory(prefix="proofbound-tools.") as temporary:
        root = Path(temporary)
        archive = root / archive_name
        installer = root / INSTALLER_NAME
        archive.write_bytes(archive_bytes)
        installer.write_bytes(installer_bytes)
        completed = subprocess.run(
            [
                sys.executable,
                str(installer),
                "--archive",
                str(archive),
                "--sha256",
                str(pin_assets[archive_name]["sha256"]),
                "--destination",
                str(destination),
            ],
            check=False,
            cwd=root,
            env={"PATH": os.environ.get("PATH", "")},
        )
    if completed.returncode != 0:
        raise ToolBundleError("the pinned Proofbound installer rejected the bundle")
    if destination.is_symlink() or not destination.is_dir():
        raise ToolBundleError("the Proofbound installation destination is invalid")
    if tuple(sorted(path.name for path in destination.iterdir())) != BINARY_NAMES:
        raise ToolBundleError("the installed Proofbound executable inventory differs")
    for path in destination.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ToolBundleError(
                "an installed Proofbound executable is not a regular file"
            )
        mode = path.stat().st_mode
        if mode & stat.S_IXUSR == 0:
            raise ToolBundleError(
                "an installed Proofbound executable is not executable"
            )
        data = _read_regular(path, MAX_ASSET_BYTES)
        record = binary_records[path.name]
        digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
        if len(data) != record["size_bytes"] or digest != record["sha256"]:
            raise ToolBundleError(
                f"installed Proofbound executable identity differs: {path.name}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pin", type=Path, default=DEFAULT_PIN)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--platform", choices=PLATFORMS)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    try:
        pin = load_pin(args.pin.absolute())
        if not args.check:
            if args.platform is None or args.destination is None:
                raise ToolBundleError("installation needs --platform and --destination")
            install(pin, args.platform, args.destination.absolute())
    except (OSError, ToolBundleError) as error:
        print(f"Proofbound tool bundle rejected: {error}", file=sys.stderr)
        return 1
    print(
        "Proofbound tool bundle pin verified"
        if args.check
        else "Proofbound tools installed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
