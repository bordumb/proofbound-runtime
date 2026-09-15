#!/usr/bin/env python3
"""Retrieve selected registry packages and compare their exact approved bytes."""

from __future__ import annotations

import argparse
from collections.abc import Callable
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote, urlparse
from urllib.request import build_opener, HTTPRedirectHandler, Request


SCHEMA = "proofbound-runtime-registry-observations/1"
REVISION = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z"
)
MAX_METADATA_BYTES = 1_048_576
USER_AGENT = "proofbound-runtime-registry-observer/1"


class RegistryError(ValueError):
    """One fail-closed registry observation error."""


def canonical_json(value: object) -> bytes:
    """Encode one duplicate-free canonical JSON value."""

    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def closed_json(data: bytes, label: str) -> dict[str, object]:
    """Decode one bounded JSON object and reject duplicate member names."""

    def closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise RegistryError(f"duplicate JSON member in {label}: {key}")
            value[key] = item
        return value

    if len(data) > MAX_METADATA_BYTES:
        raise RegistryError(f"metadata exceeds the read bound: {label}")
    try:
        value = json.loads(data, object_pairs_hook=closed_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RegistryError(f"invalid JSON metadata: {label}") from error
    if not isinstance(value, dict):
        raise RegistryError(f"metadata is not an object: {label}")
    return value


def load_json(path: Path) -> dict[str, object]:
    """Read one bounded JSON object and reject duplicate member names."""

    return closed_json(path.read_bytes(), str(path))


def admitted_https_url(url: str, host: str) -> bool:
    """Accept one credential-free HTTPS URL on the default port and exact host."""

    parsed = urlparse(url)
    try:
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname == host
        and parsed.username is None
        and parsed.password is None
        and port in (None, 443)
        and not parsed.fragment
    )


class RejectRedirects(HTTPRedirectHandler):
    """Reject every redirect before the client can issue the next request."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        del request, file_pointer, code, message, headers, new_url
        raise RegistryError("registry redirects are not admitted")


def fetch_url(url: str, maximum: int) -> bytes:
    """Read one HTTPS resource with a strict byte bound."""

    if maximum < 0:
        raise RegistryError("invalid download bound")
    requested_url = urlparse(url)
    if (
        requested_url.hostname is None
        or not admitted_https_url(url, requested_url.hostname)
    ):
        raise RegistryError("registry URL is outside the admitted HTTPS endpoint")
    request = Request(url, headers={"User-Agent": USER_AGENT})
    opener = build_opener(RejectRedirects())
    with opener.open(request, timeout=30) as response:  # noqa: S310 - URL is closed above.
        final = response.geturl()
        if final != url:
            raise RegistryError("registry response URL differs from the admitted endpoint")
        data = response.read(maximum + 1)
    if len(data) > maximum:
        raise RegistryError("registry response exceeds the byte bound")
    return data


def exact_file(directory: Path, name: str, digest: str, size: int) -> bytes:
    """Read one approved regular file and validate its registered identity."""

    if Path(name).name != name:
        raise RegistryError(f"approved artifact name is not one file name: {name}")
    path = directory / name
    if path.is_symlink() or not path.is_file():
        raise RegistryError(f"approved artifact is not a regular file: {name}")
    data = path.read_bytes()
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise RegistryError(f"approved artifact identity mismatch: {name}")
    return data


def text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise RegistryError(f"invalid {field}")
    return value


def natural(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise RegistryError(f"invalid {field}")
    return value


def exact_keys(value: dict[str, object], expected: set[str], field: str) -> None:
    if set(value) != expected:
        raise RegistryError(f"invalid {field} members")


def sdk_artifacts(
    directory: Path, expected_revision: str
) -> tuple[str, dict[str, tuple[str, int, bytes]]]:
    manifest = load_json(directory / "SDK-MANIFEST.json")
    exact_keys(
        manifest,
        {"artifacts", "schema", "source_revision", "version"},
        "SDK manifest",
    )
    if manifest.get("schema") != "proofbound-runtime-sdk-manifest/1":
        raise RegistryError("SDK manifest schema mismatch")
    if manifest.get("source_revision") != expected_revision:
        raise RegistryError("SDK source revision mismatch")
    version = text(manifest.get("version"), "SDK version")
    if VERSION.fullmatch(version) is None:
        raise RegistryError("invalid SDK version")
    entries = manifest.get("artifacts")
    if not isinstance(entries, list) or len(entries) != 3:
        raise RegistryError("SDK artifact inventory mismatch")
    expected = {
        f"proofbound-runtime-sdk-{version}.crate",
        f"proofbound-runtime-sdk-{version}.tgz",
        f"proofbound_runtime_sdk-{version}-py3-none-any.whl",
    }
    artifacts: dict[str, tuple[str, int, bytes]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise RegistryError("invalid SDK artifact")
        exact_keys(entry, {"name", "sha256", "size"}, "SDK artifact")
        name = text(entry.get("name"), "SDK artifact name")
        if name not in expected:
            raise RegistryError("SDK artifact name is outside the selected set")
        digest = text(entry.get("sha256"), "SDK artifact digest")
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise RegistryError("invalid SDK artifact digest")
        size = natural(entry.get("size"), "SDK artifact size")
        if name in artifacts:
            raise RegistryError("duplicate SDK artifact")
        artifacts[name] = (digest, size, exact_file(directory, name, digest, size))
    if set(artifacts) != expected:
        raise RegistryError("SDK artifact names do not match the selected set")
    return version, artifacts


def verifier_artifact(
    directory: Path, expected_revision: str, version: str
) -> tuple[str, str, int, bytes]:
    manifest = load_json(directory / "VERIFIER-PACKAGE-MANIFEST.projection.json")
    exact_keys(
        manifest,
        {
            "artifacts",
            "binary",
            "package",
            "schema",
            "source_revision",
            "supported_receipt_schemas",
            "version",
        },
        "verifier manifest",
    )
    if manifest.get("schema") != "proofbound-runtime-verifier-package-manifest/1":
        raise RegistryError("verifier manifest schema mismatch")
    if manifest.get("source_revision") != expected_revision:
        raise RegistryError("verifier source revision mismatch")
    if manifest.get("version") != version:
        raise RegistryError("verifier version mismatch")
    if manifest.get("binary") != "pbr-verify":
        raise RegistryError("verifier binary mismatch")
    if manifest.get("package") != "proofbound-runtime-verify":
        raise RegistryError("verifier package mismatch")
    if manifest.get("supported_receipt_schemas") != [
        "proofbound-runtime-receipt/1",
        "proofbound-runtime-execution-receipt/2",
    ]:
        raise RegistryError("verifier receipt schema inventory mismatch")
    entries = manifest.get("artifacts")
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        raise RegistryError("verifier artifact inventory mismatch")
    entry = entries[0]
    exact_keys(entry, {"name", "sha256", "size"}, "verifier artifact")
    name = text(entry.get("name"), "verifier artifact name")
    expected_name = f"proofbound-runtime-verify-{version}.crate"
    if name != expected_name:
        raise RegistryError("verifier artifact name mismatch")
    digest_text = text(entry.get("sha256"), "verifier artifact digest")
    if re.fullmatch(r"hex:[0-9a-f]{64}", digest_text) is None:
        raise RegistryError("invalid verifier artifact digest")
    digest = digest_text.removeprefix("hex:")
    size_text = text(entry.get("size"), "verifier artifact size")
    if not size_text.isascii() or not size_text.isdecimal():
        raise RegistryError("invalid verifier artifact size")
    size = int(size_text)
    if size <= 0:
        raise RegistryError("invalid verifier artifact size")
    return name, digest, size, exact_file(directory, name, digest, size)


def metadata(fetch: Callable[[str, int], bytes], url: str) -> dict[str, object]:
    return closed_json(fetch(url, MAX_METADATA_BYTES), url)


def observe(
    *,
    sdk_directory: Path,
    verifier_directory: Path,
    expected_revision: str,
    fetch: Callable[[str, int], bytes] = fetch_url,
) -> dict[str, object]:
    """Compare all selected registry artifacts with their approved bytes."""

    if REVISION.fullmatch(expected_revision) is None:
        raise RegistryError("expected revision is not a lowercase Git object id")
    version, sdk = sdk_artifacts(sdk_directory, expected_revision)
    verifier = verifier_artifact(verifier_directory, expected_revision, version)
    approved = {
        "proofbound-runtime-verify": verifier,
        "proofbound-runtime-sdk": (
            f"proofbound-runtime-sdk-{version}.crate",
            *sdk[f"proofbound-runtime-sdk-{version}.crate"],
        ),
        "proofbound-runtime-sdk-pypi": (
            f"proofbound_runtime_sdk-{version}-py3-none-any.whl",
            *sdk[f"proofbound_runtime_sdk-{version}-py3-none-any.whl"],
        ),
        "proofbound-runtime-sdk-npm": (
            f"proofbound-runtime-sdk-{version}.tgz",
            *sdk[f"proofbound-runtime-sdk-{version}.tgz"],
        ),
    }

    urls: dict[str, str] = {
        "proofbound-runtime-verify": (
            f"https://static.crates.io/crates/proofbound-runtime-verify/"
            f"proofbound-runtime-verify-{version}.crate"
        ),
        "proofbound-runtime-sdk": (
            f"https://static.crates.io/crates/proofbound-runtime-sdk/"
            f"proofbound-runtime-sdk-{version}.crate"
        ),
    }

    pypi_url = f"https://pypi.org/pypi/proofbound-runtime-sdk/{version}/json"
    pypi = metadata(fetch, pypi_url)
    pypi_files = pypi.get("urls")
    wheel_name = approved["proofbound-runtime-sdk-pypi"][0]
    if not isinstance(pypi_files, list):
        raise RegistryError("PyPI release inventory is invalid")
    matching = [
        item
        for item in pypi_files
        if isinstance(item, dict) and item.get("filename") == wheel_name
    ]
    if len(matching) != 1:
        raise RegistryError("PyPI wheel is absent or ambiguous")
    wheel_url = text(matching[0].get("url"), "PyPI wheel URL")
    if not admitted_https_url(wheel_url, "files.pythonhosted.org"):
        raise RegistryError("PyPI wheel URL is outside the admitted host")
    urls["proofbound-runtime-sdk-pypi"] = wheel_url

    npm_name = "@proofbound/runtime-sdk"
    npm_url = f"https://registry.npmjs.org/{quote(npm_name, safe='')}/{version}"
    npm = metadata(fetch, npm_url)
    distribution = npm.get("dist")
    if not isinstance(distribution, dict):
        raise RegistryError("npm distribution metadata is invalid")
    tarball_url = text(distribution.get("tarball"), "npm tarball URL")
    if not admitted_https_url(tarball_url, "registry.npmjs.org"):
        raise RegistryError("npm tarball URL is outside the admitted host")
    urls["proofbound-runtime-sdk-npm"] = tarball_url

    observations = []
    ecosystems = {
        "proofbound-runtime-verify": ("crates.io", "proofbound-runtime-verify"),
        "proofbound-runtime-sdk": ("crates.io", "proofbound-runtime-sdk"),
        "proofbound-runtime-sdk-pypi": ("pypi", "proofbound-runtime-sdk"),
        "proofbound-runtime-sdk-npm": ("npm", npm_name),
    }
    for key in sorted(approved):
        name, digest, size, expected = approved[key]
        observed = fetch(urls[key], size)
        if observed != expected:
            raise RegistryError(f"registry bytes differ from approved artifact: {key}")
        ecosystem, package = ecosystems[key]
        observations.append(
            {
                "artifact": name,
                "ecosystem": ecosystem,
                "package": package,
                "sha256": f"hex:{digest}",
                "size_bytes": size,
                "url": urls[key],
            }
        )
    return {
        "observations": observations,
        "schema": SCHEMA,
        "source_revision": expected_revision,
        "version": version,
    }


def write_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-directory", required=True, type=Path)
    parser.add_argument("--verifier-directory", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        value = observe(
            sdk_directory=arguments.sdk_directory.resolve(),
            verifier_directory=arguments.verifier_directory.resolve(),
            expected_revision=arguments.expected_revision,
        )
        write_exclusive(arguments.output.resolve(), canonical_json(value) + b"\n")
    except (OSError, RegistryError) as error:
        print(f"registry observation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
