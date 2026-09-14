#!/usr/bin/env python3
"""Preflight, reproduce, and dogfood the public verifier crate package."""

from __future__ import annotations

import argparse
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib


PACKAGE_NAME = "proofbound-runtime-verify"
PACKAGE_DESCRIPTION = (
    "Independent execution-receipt verification for Proofbound Runtime"
)
PACKAGE_BINARY = "pbr-verify"
PACKAGE_MANIFEST_SCHEMA = "proofbound-runtime-verifier-package-manifest/1"
PACKAGE_MANIFEST_CDDL = "schemas/verifier-package-manifest-v1.cddl"
PREFLIGHT_SCHEMA = "proofbound-runtime-package-preflight/1"
SUPPORTED_RECEIPT_SCHEMAS = [
    "proofbound-runtime-receipt/1",
    "proofbound-runtime-execution-receipt/2",
]
CRATE = Path("crates/proofbound-runtime-verify")
CRATE_REPOSITORY_FILES = (
    "Cargo.toml",
    "README.md",
    "src/attack_tests.rs",
    "src/canonical.rs",
    "src/cbor.rs",
    "src/commitment.rs",
    "src/decode.rs",
    "src/decode_v2.rs",
    "src/derive.rs",
    "src/error.rs",
    "src/identity.rs",
    "src/lib.rs",
    "src/main.rs",
    "src/test_support.rs",
    "tests/receipt_vectors.rs",
)
PACKAGE_PAYLOAD_FILES = (
    "README.md",
    "src/attack_tests.rs",
    "src/canonical.rs",
    "src/cbor.rs",
    "src/commitment.rs",
    "src/decode.rs",
    "src/decode_v2.rs",
    "src/derive.rs",
    "src/error.rs",
    "src/identity.rs",
    "src/lib.rs",
    "src/main.rs",
    "src/test_support.rs",
)
SOURCE_REVISION_FILES = (
    "Cargo.lock",
    "Cargo.toml",
    "VERSION",
    *(str(CRATE / name) for name in CRATE_REPOSITORY_FILES),
    PACKAGE_MANIFEST_CDDL,
    "schemas/verifier-package-preflight-v1.schema.json",
    "tools/release/build_verifier_package.py",
)


class FailureCode(str, Enum):
    """Stable verifier-package preflight and production failure codes."""

    MANIFEST_METADATA = "package.manifest.metadata-invalid"
    PUBLICATION_DISABLED = "package.manifest.publication-disabled"
    WORKSPACE_DEPENDENCY = "package.manifest.workspace-dependency"
    PATH_DEPENDENCY = "package.manifest.path-dependency"
    DEPENDENCY_SOURCE = "package.manifest.dependency-source"
    SOURCE_INVENTORY = "package.source.inventory-mismatch"
    SOURCE_REVISION = "package.source.revision-mismatch"
    VERSION_MISMATCH = "package.version.mismatch"
    PACKAGE_INVENTORY = "package.archive.inventory-mismatch"
    PACKAGE_PAYLOAD = "package.archive.payload-mismatch"
    REPRODUCTION = "package.archive.reproduction-mismatch"
    CONSUMER = "package.consumer.failed"
    OUTPUT_NOT_EMPTY = "package.output.not-empty"
    COMMAND = "package.command.failed"
    IO = "package.io.failed"


class PackageError(ValueError):
    """One verifier-package failure with a stable machine code."""

    def __init__(self, code: FailureCode, detail: str):
        super().__init__(detail)
        self.code = code.value


def _table(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PackageError(FailureCode.MANIFEST_METADATA, f"missing or invalid {name}")
    return value


def _load_toml(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as source:
            return _table(tomllib.load(source), str(path))
    except tomllib.TOMLDecodeError as error:
        raise PackageError(FailureCode.MANIFEST_METADATA, str(error)) from error
    except OSError as error:
        raise PackageError(FailureCode.IO, str(error)) from error


DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")

EXPECTED_MANIFEST_KEYS = {
    "package",
    "bin",
    "dependencies",
    "dev-dependencies",
}
EXPECTED_PACKAGE = {
    "name": PACKAGE_NAME,
    "description": PACKAGE_DESCRIPTION,
    "version": {"workspace": True},
    "edition": {"workspace": True},
    "license": {"workspace": True},
    "repository": {"workspace": True},
    "rust-version": {"workspace": True},
    "publish": ["crates-io"],
    "readme": "README.md",
    "include": ["README.md", "src/*.rs"],
}
EXPECTED_BINARIES = [{"name": PACKAGE_BINARY, "path": "src/main.rs"}]
EXPECTED_DEPENDENCIES = {
    "serde": {"workspace": True},
    "serde_json": {"workspace": True},
    "sha2": {"workspace": True},
}
EXPECTED_DEV_DEPENDENCIES = {"toml": {"workspace": True}}


def _dependency_tables(
    manifest: dict[str, object],
) -> list[tuple[str, dict[str, object]]]:
    result: list[tuple[str, dict[str, object]]] = []
    for name in DEPENDENCY_TABLES:
        if name in manifest:
            result.append((name, _table(manifest[name], f"[{name}]")))
    targets = manifest.get("target", {})
    if not isinstance(targets, dict):
        raise PackageError(FailureCode.MANIFEST_METADATA, "invalid [target]")
    for target, target_value in targets.items():
        target_table = _table(target_value, f"[target.{target}]")
        for name in DEPENDENCY_TABLES:
            if name in target_table:
                result.append(
                    (
                        f"target.{target}.{name}",
                        _table(target_table[name], f"[target.{target}.{name}]"),
                    )
                )
    return result


def _dependency_specification(
    dependency: str,
    value: object,
    workspace_dependencies: dict[str, object],
) -> tuple[str, dict[str, object]]:
    if isinstance(value, str):
        return dependency, {}
    specification = _table(value, f"dependency {dependency}")
    if specification.get("workspace") is True:
        if dependency not in workspace_dependencies:
            raise PackageError(
                FailureCode.MANIFEST_METADATA,
                f"workspace dependency {dependency} is not registered",
            )
        workspace_value = workspace_dependencies[dependency]
        if isinstance(workspace_value, str):
            return dependency, {}
        workspace_specification = _table(
            workspace_value,
            f"workspace dependency {dependency}",
        )
        return (
            str(workspace_specification.get("package", dependency)),
            workspace_specification,
        )
    return str(specification.get("package", dependency)), specification


def _validate_dependencies(
    manifest: dict[str, object],
    workspace: dict[str, object],
) -> None:
    workspace_table = _table(workspace.get("workspace"), "[workspace]")
    workspace_dependencies = _table(
        workspace_table.get("dependencies", {}),
        "[workspace.dependencies]",
    )
    for source_name, source in (("package", manifest), ("workspace", workspace)):
        for replacement in ("patch", "replace"):
            if replacement in source and source[replacement]:
                raise PackageError(
                    FailureCode.DEPENDENCY_SOURCE,
                    f"{source_name} [{replacement}] dependency substitution "
                    "is not admitted",
                )
    for section, dependencies in _dependency_tables(manifest):
        for dependency, value in dependencies.items():
            actual_name, specification = _dependency_specification(
                dependency,
                value,
                workspace_dependencies,
            )
            if actual_name.startswith("proofbound-runtime-"):
                raise PackageError(
                    FailureCode.WORKSPACE_DEPENDENCY,
                    f"internal dependency in [{section}]",
                )
            if "path" in specification:
                raise PackageError(
                    FailureCode.PATH_DEPENDENCY,
                    f"path dependency in [{section}]",
                )
            if "git" in specification or "registry" in specification:
                raise PackageError(
                    FailureCode.DEPENDENCY_SOURCE,
                    f"non-crates.io dependency source in [{section}]",
                )


def _validate_manifest_surface(manifest: dict[str, object]) -> None:
    if set(manifest) != EXPECTED_MANIFEST_KEYS:
        raise PackageError(
            FailureCode.MANIFEST_METADATA,
            "the verifier manifest contains an unregistered top-level surface",
        )
    if manifest.get("package") != EXPECTED_PACKAGE:
        raise PackageError(
            FailureCode.MANIFEST_METADATA,
            "the verifier package table differs from the closed contract",
        )
    if manifest.get("bin") != EXPECTED_BINARIES:
        raise PackageError(
            FailureCode.MANIFEST_METADATA,
            "the verifier binary targets differ from the closed contract",
        )
    if manifest.get("dependencies") != EXPECTED_DEPENDENCIES:
        raise PackageError(
            FailureCode.MANIFEST_METADATA,
            "the verifier dependencies differ from the closed contract",
        )
    if manifest.get("dev-dependencies") != EXPECTED_DEV_DEPENDENCIES:
        raise PackageError(
            FailureCode.MANIFEST_METADATA,
            "the verifier development dependencies differ from the closed contract",
        )


def _actual_crate_files(crate: Path) -> tuple[str, ...]:
    actual: list[str] = []
    for path in crate.rglob("*"):
        if path.is_symlink():
            raise PackageError(
                FailureCode.SOURCE_INVENTORY,
                f"symlink is not admitted: {path.relative_to(crate)}",
            )
        if path.is_file():
            actual.append(path.relative_to(crate).as_posix())
    return tuple(sorted(actual))


def preflight(repository: Path) -> str:
    """Validate the closed public verifier package and return its version."""

    manifest_path = repository / CRATE / "Cargo.toml"
    workspace_path = repository / "Cargo.toml"
    try:
        version_file = (repository / "VERSION").read_text(encoding="ascii").strip()
    except OSError as error:
        raise PackageError(FailureCode.IO, str(error)) from error
    manifest = _load_toml(manifest_path)
    workspace = _load_toml(workspace_path)

    package = _table(manifest.get("package"), "[package]")
    if package.get("publish") != ["crates-io"]:
        raise PackageError(
            FailureCode.PUBLICATION_DISABLED,
            "the verifier package is not restricted to crates.io publication",
        )

    workspace_table = _table(workspace.get("workspace"), "[workspace]")
    workspace_package = _table(
        workspace_table.get("package"),
        "[workspace.package]",
    )
    workspace_version = workspace_package.get("version")
    if workspace_version != version_file:
        raise PackageError(
            FailureCode.VERSION_MISMATCH,
            "VERSION and workspace.package.version differ",
        )

    _validate_dependencies(manifest, workspace)
    _validate_manifest_surface(manifest)
    actual = _actual_crate_files(repository / CRATE)
    expected = tuple(sorted(CRATE_REPOSITORY_FILES))
    if actual != expected:
        raise PackageError(
            FailureCode.SOURCE_INVENTORY,
            f"expected {expected!r}, observed {actual!r}",
        )
    return version_file


def _run(
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str] | None = None,
) -> None:
    try:
        subprocess.run(
            arguments,
            cwd=cwd,
            env=environment,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise PackageError(FailureCode.COMMAND, arguments[0]) from error


def _archive_name(version: str) -> str:
    return f"{PACKAGE_NAME}-{version}.crate"


def _expected_archive_inventory(repository: Path) -> list[str]:
    expected = ["Cargo.lock", "Cargo.toml", "Cargo.toml.orig", *PACKAGE_PAYLOAD_FILES]
    if (repository / ".git").exists():
        expected.insert(0, ".cargo_vcs_info.json")
    return expected


def _archive_member_bytes(
    archive: tarfile.TarFile,
    archive_root: str,
    relative: str,
) -> bytes:
    member = archive.extractfile(f"{archive_root}/{relative}")
    if member is None:
        raise PackageError(
            FailureCode.PACKAGE_INVENTORY,
            f"package member has no bytes: {relative}",
        )
    return member.read()


def _git_head(repository: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise PackageError(FailureCode.IO, str(error)) from error
    revision = result.stdout.strip()
    if result.returncode != 0 or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise PackageError(
            FailureCode.PACKAGE_PAYLOAD,
            "cannot identify the package Git revision",
        )
    return revision


def _git_dirty(repository: Path) -> bool:
    try:
        result = subprocess.run(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--",
                CRATE.as_posix(),
            ],
            cwd=repository,
            check=False,
            capture_output=True,
        )
    except OSError as error:
        raise PackageError(FailureCode.IO, str(error)) from error
    if result.returncode != 0:
        raise PackageError(
            FailureCode.PACKAGE_PAYLOAD,
            "cannot identify the package Git state",
        )
    return bool(result.stdout)


def _validate_vcs_info(repository: Path, content: bytes) -> None:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PackageError(
            FailureCode.PACKAGE_PAYLOAD,
            "the package VCS information is invalid",
        ) from error
    expected = {
        "git": {
            "sha1": _git_head(repository),
            "dirty": _git_dirty(repository),
        },
        "path_in_vcs": CRATE.as_posix(),
    }
    if value != expected:
        raise PackageError(
            FailureCode.PACKAGE_PAYLOAD,
            "the package VCS information differs from the selected source",
        )


def _validate_archive(repository: Path, archive_path: Path) -> None:
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            expected_root = archive_path.name.removesuffix(".crate")
            observed: list[str] = []
            for member in members:
                root, separator, relative = member.name.partition("/")
                if not separator or root != expected_root or not member.isfile():
                    raise PackageError(
                        FailureCode.PACKAGE_INVENTORY,
                        f"non-file or invalid package member: {member.name}",
                    )
                observed.append(relative)
            expected = _expected_archive_inventory(repository)
            if observed != expected:
                raise PackageError(
                    FailureCode.PACKAGE_INVENTORY,
                    f"expected {expected!r}, observed {observed!r}",
                )
            retained_sources = {
                "Cargo.toml.orig": repository / CRATE / "Cargo.toml",
                **{
                    relative: repository / CRATE / relative
                    for relative in PACKAGE_PAYLOAD_FILES
                },
            }
            for relative, source_path in retained_sources.items():
                try:
                    source = source_path.read_bytes()
                except OSError as error:
                    raise PackageError(FailureCode.IO, str(error)) from error
                if _archive_member_bytes(archive, expected_root, relative) != source:
                    raise PackageError(
                        FailureCode.PACKAGE_PAYLOAD,
                        f"package member differs from source: {relative}",
                    )
            if ".cargo_vcs_info.json" in expected:
                _validate_vcs_info(
                    repository,
                    _archive_member_bytes(
                        archive,
                        expected_root,
                        ".cargo_vcs_info.json",
                    ),
                )
    except (OSError, tarfile.TarError) as error:
        raise PackageError(FailureCode.PACKAGE_INVENTORY, str(error)) from error


def _build_once(repository: Path, work: Path, version: str) -> bytes:
    target = work / "target"
    _run(
        [
            "cargo",
            "package",
            "--locked",
            "--offline",
            "--allow-dirty",
            "--no-verify",
            "-p",
            PACKAGE_NAME,
            "--target-dir",
            str(target),
        ],
        cwd=repository,
    )
    archive = target / "package" / _archive_name(version)
    _validate_archive(repository, archive)
    try:
        return archive.read_bytes()
    except OSError as error:
        raise PackageError(FailureCode.IO, str(error)) from error


def _extract_for_consumer(archive_path: Path, destination: Path) -> Path:
    try:
        archive = tarfile.open(archive_path, "r:gz")
    except (OSError, tarfile.TarError) as error:
        raise PackageError(FailureCode.PACKAGE_INVENTORY, str(error)) from error
    with archive:
        members = archive.getmembers()
        roots = {member.name.partition("/")[0] for member in members}
        if len(roots) != 1:
            raise PackageError(
                FailureCode.PACKAGE_INVENTORY,
                "archive root is not unique",
            )
        root = roots.pop()
        for member in members:
            _, separator, relative = member.name.partition("/")
            if (
                not separator
                or not relative
                or relative.startswith("/")
                or "\\" in relative
                or any(part in {"", ".", ".."} for part in relative.split("/"))
                or not member.isfile()
            ):
                raise PackageError(
                    FailureCode.PACKAGE_INVENTORY,
                    f"unsafe package member: {member.name}",
                )
            source = archive.extractfile(member)
            if source is None:
                raise PackageError(
                    FailureCode.PACKAGE_INVENTORY,
                    f"package member has no bytes: {member.name}",
                )
            target = destination / root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(descriptor, "wb") as output:
                output.write(source.read())
    return destination / root


def _dogfood(archive_path: Path, work: Path, version: str) -> None:
    source = _extract_for_consumer(archive_path, work / "consumer-source")
    installation = work / "consumer-install"
    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = str(work / "consumer-target")
    _run(
        [
            "cargo",
            "install",
            "--locked",
            "--offline",
            "--path",
            str(source),
            "--root",
            str(installation),
        ],
        cwd=work,
        environment=environment,
    )
    binary = installation / "bin" / PACKAGE_BINARY
    try:
        completed = subprocess.run(
            [str(binary), "--version"],
            cwd=work,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise PackageError(FailureCode.CONSUMER, str(error)) from error
    if (
        completed.returncode != 0
        or completed.stdout != f"{PACKAGE_BINARY} {version}\n"
        or completed.stderr
    ):
        raise PackageError(
            FailureCode.CONSUMER,
            "the installed verifier did not report the selected version",
        )


def _write_exclusive(path: Path, data: bytes) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(data)
    except OSError as error:
        raise PackageError(FailureCode.IO, str(error)) from error


def _encode_cbor_argument(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    for additional, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (width * 8):
            return bytes([(major << 5) | additional]) + value.to_bytes(width, "big")
    raise PackageError(
        FailureCode.PACKAGE_PAYLOAD,
        "a verifier package manifest integer exceeds u64",
    )


def _encode_cbor(value: object) -> bytes:
    if isinstance(value, bytes):
        return _encode_cbor_argument(2, len(value)) + value
    if isinstance(value, str):
        payload = value.encode("utf-8")
        return _encode_cbor_argument(3, len(payload)) + payload
    if type(value) is int and 0 <= value < 1 << 64:
        return _encode_cbor_argument(0, value)
    if isinstance(value, list):
        return _encode_cbor_argument(4, len(value)) + b"".join(
            _encode_cbor(item) for item in value
        )
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise PackageError(
                FailureCode.PACKAGE_PAYLOAD,
                "a verifier package manifest map key is not text",
            )
        entries = sorted(
            (_encode_cbor(key), _encode_cbor(item)) for key, item in value.items()
        )
        return _encode_cbor_argument(5, len(entries)) + b"".join(
            key + item for key, item in entries
        )
    raise PackageError(
        FailureCode.PACKAGE_PAYLOAD,
        f"unsupported verifier package manifest value: {type(value).__name__}",
    )


def _manifest_projection(value: dict[str, object]) -> dict[str, object]:
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise PackageError(
            FailureCode.PACKAGE_PAYLOAD,
            "the verifier package manifest artifact inventory is invalid",
        )
    artifact = artifacts[0]
    if not isinstance(artifact, dict):
        raise PackageError(
            FailureCode.PACKAGE_PAYLOAD,
            "the verifier package manifest artifact entry is invalid",
        )
    digest = artifact["sha256"]
    size = artifact["size"]
    if not isinstance(digest, bytes) or type(size) is not int:
        raise PackageError(
            FailureCode.PACKAGE_PAYLOAD,
            "the verifier package manifest identity is invalid",
        )
    return {
        **value,
        "artifacts": [
            {
                **artifact,
                "sha256": f"hex:{digest.hex()}",
                "size": str(size),
            }
        ],
    }


def _tree_revision(repository: Path) -> str:
    digest = hashlib.sha256(b"proofbound-runtime-verifier-package-source-tree/1\0")
    try:
        for relative_name in SOURCE_REVISION_FILES:
            relative = relative_name.encode("utf-8")
            content = (repository / relative_name).read_bytes()
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
    except OSError as error:
        raise PackageError(FailureCode.IO, str(error)) from error
    return f"tree-sha256:{digest.hexdigest()}"


def source_revision(repository: Path) -> str:
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return _tree_revision(repository)
    if revision.returncode != 0:
        return _tree_revision(repository)
    value = revision.stdout.strip()
    try:
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", *SOURCE_REVISION_FILES],
            cwd=repository,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        unchanged = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--", *SOURCE_REVISION_FILES],
            cwd=repository,
            check=False,
        )
    except OSError:
        return _tree_revision(repository)
    if (
        re.fullmatch(r"[0-9a-f]{40}", value)
        and tracked.returncode == 0
        and unchanged.returncode == 0
    ):
        return value
    return _tree_revision(repository)


def build(
    repository: Path,
    output: Path,
    expected_revision: str | None = None,
) -> None:
    """Build, compare, dogfood, and retain one verifier crate package."""

    version = preflight(repository)
    revision = source_revision(repository)
    if expected_revision is not None and revision != expected_revision:
        raise PackageError(
            FailureCode.SOURCE_REVISION,
            "the package source does not match the selected release revision",
        )
    try:
        output.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise PackageError(FailureCode.IO, str(error)) from error
    if any(output.iterdir()):
        raise PackageError(FailureCode.OUTPUT_NOT_EMPTY, str(output))
    target = repository / "target"
    try:
        target.mkdir(exist_ok=True)
    except OSError as error:
        raise PackageError(FailureCode.IO, str(error)) from error
    with tempfile.TemporaryDirectory(prefix="verifier-package.", dir=target) as first:
        with tempfile.TemporaryDirectory(
            prefix="verifier-package.", dir=target
        ) as second:
            first_bytes = _build_once(repository, Path(first), version)
            second_bytes = _build_once(repository, Path(second), version)
    if first_bytes != second_bytes:
        raise PackageError(
            FailureCode.REPRODUCTION,
            _archive_name(version),
        )
    if not first_bytes:
        raise PackageError(
            FailureCode.PACKAGE_PAYLOAD,
            "the verifier package archive is empty",
        )

    archive_name = _archive_name(version)
    archive_path = output / archive_name
    _write_exclusive(archive_path, first_bytes)
    with tempfile.TemporaryDirectory(
        prefix="proofbound-runtime-verifier-consumer."
    ) as consumer:
        _dogfood(archive_path, Path(consumer), version)

    digest = hashlib.sha256(first_bytes).digest()
    manifest = {
        "artifacts": [
            {"name": archive_name, "sha256": digest, "size": len(first_bytes)}
        ],
        "binary": PACKAGE_BINARY,
        "package": PACKAGE_NAME,
        "schema": PACKAGE_MANIFEST_SCHEMA,
        "source_revision": revision,
        "supported_receipt_schemas": SUPPORTED_RECEIPT_SCHEMAS,
        "version": version,
    }
    _write_exclusive(
        output / "VERIFIER-PACKAGE-MANIFEST.cbor",
        _encode_cbor(manifest),
    )
    _write_exclusive(
        output / "VERIFIER-PACKAGE-MANIFEST.projection.json",
        json.dumps(
            _manifest_projection(manifest),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n",
    )
    _write_exclusive(
        output / "SHA256SUMS",
        f"{digest.hex()}  {archive_name}\n".encode("ascii"),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--check", action="store_true")
    selection.add_argument("--output", type=Path)
    parser.add_argument("--expected-revision")
    arguments = parser.parse_args()
    if arguments.check and arguments.expected_revision is not None:
        parser.error("--expected-revision requires --output")
    repository = Path(__file__).resolve().parents[2]
    try:
        version = preflight(repository)
        if arguments.check:
            result = {
                "accepted": True,
                "package": PACKAGE_NAME,
                "schema": PREFLIGHT_SCHEMA,
                "version": version,
            }
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        else:
            assert arguments.output is not None
            build(
                repository,
                arguments.output.resolve(),
                arguments.expected_revision,
            )
    except PackageError as error:
        print(
            f"verifier package build failed: {error.code}: {error}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
