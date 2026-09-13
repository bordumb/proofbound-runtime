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


PACKAGE_NAME = "proofbound-runtime-verify"
PACKAGE_DESCRIPTION = (
    "Independent execution-receipt verification for Proofbound Runtime"
)
PACKAGE_BINARY = "pbr-verify"
PACKAGE_MANIFEST_SCHEMA = "proofbound-runtime-verifier-package-manifest/1"
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
    "schemas/verifier-package-manifest-v1.schema.json",
    "schemas/verifier-package-preflight-v1.schema.json",
    "tools/release/build_verifier_package.py",
)


class FailureCode(str, Enum):
    """Stable verifier-package preflight and production failure codes."""

    MANIFEST_METADATA = "package.manifest.metadata-invalid"
    PUBLICATION_DISABLED = "package.manifest.publication-disabled"
    WORKSPACE_DEPENDENCY = "package.manifest.workspace-dependency"
    PATH_DEPENDENCY = "package.manifest.path-dependency"
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


def _section(source: str, name: str) -> list[str]:
    header = f"[{name}]"
    lines = source.splitlines()
    try:
        start = lines.index(header) + 1
    except ValueError as error:
        raise PackageError(FailureCode.MANIFEST_METADATA, f"missing {header}") from error
    result: list[str] = []
    for line in lines[start:]:
        if line.strip().startswith("["):
            break
        result.append(line)
    return result


def _assignment(lines: list[str], key: str) -> str:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=\s*(?P<value>[^#]+?)\s*$")
    values = [match.group("value") for line in lines if (match := pattern.match(line))]
    if len(values) != 1:
        raise PackageError(
            FailureCode.MANIFEST_METADATA,
            f"expected one {key} assignment",
        )
    return values[0]


def _dependency_sections(source: str) -> list[tuple[str, list[str]]]:
    sections: list[tuple[str, list[str]]] = []
    current_name = ""
    current_lines: list[str] = []
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            if current_name:
                sections.append((current_name, current_lines))
            current_name = line[1:-1]
            current_lines = []
        elif current_name:
            current_lines.append(raw_line)
    if current_name:
        sections.append((current_name, current_lines))
    return [
        (name, lines)
        for name, lines in sections
        if name in {"dependencies", "dev-dependencies", "build-dependencies"}
        or name.startswith(("dependencies.", "dev-dependencies.", "build-dependencies."))
        or ".dependencies" in name
        or ".dev-dependencies" in name
        or ".build-dependencies" in name
    ]


def _dependency_name(section: str, line: str) -> str | None:
    for marker in ("dependencies.", "dev-dependencies.", "build-dependencies."):
        if marker in section:
            return section.split(marker, 1)[1].strip('"\'')
    content = line.split("#", 1)[0].strip()
    if not content or "=" not in content:
        return None
    name = content.split("=", 1)[0].strip().strip('"\'')
    return name.removesuffix(".workspace")


def _workspace_dependencies(workspace: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for section, lines in _dependency_sections(workspace):
        if section == "workspace.dependencies":
            for line in lines:
                content = line.split("#", 1)[0].strip()
                if not content or "=" not in content:
                    continue
                key, value = (part.strip() for part in content.split("=", 1))
                result[key.strip('"\'')] = value
        elif section.startswith("workspace.dependencies."):
            dependency = section.split("workspace.dependencies.", 1)[1]
            result[dependency.strip('"\'')] = " ".join(
                line.split("#", 1)[0].strip() for line in lines
            )
    return result


def _validate_dependencies(manifest: str, workspace: str) -> None:
    workspace_dependencies = _workspace_dependencies(workspace)
    for section, lines in _dependency_sections(manifest):
        for line in lines:
            content = line.split("#", 1)[0].strip()
            if not content:
                continue
            dependency = _dependency_name(section, line)
            workspace_value = workspace_dependencies.get(dependency or "", "")
            combined = f"{content} {workspace_value}"
            if (dependency or "").startswith("proofbound-runtime-") or re.search(
                r"[\"']proofbound-runtime-[a-z0-9-]+[\"']", combined
            ):
                raise PackageError(
                    FailureCode.WORKSPACE_DEPENDENCY,
                    f"internal dependency in [{section}]",
                )
            if re.search(r"\bpath\s*=", combined):
                raise PackageError(
                    FailureCode.PATH_DEPENDENCY,
                    f"path dependency in [{section}]",
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
        manifest = manifest_path.read_text(encoding="utf-8")
        workspace = workspace_path.read_text(encoding="utf-8")
        version_file = (repository / "VERSION").read_text(encoding="ascii").strip()
    except OSError as error:
        raise PackageError(FailureCode.IO, str(error)) from error

    package = _section(manifest, "package")
    required = {
        "name": f'"{PACKAGE_NAME}"',
        "description": f'"{PACKAGE_DESCRIPTION}"',
        "version.workspace": "true",
        "edition.workspace": "true",
        "license.workspace": "true",
        "repository.workspace": "true",
        "rust-version.workspace": "true",
        "readme": '"README.md"',
        "include": '["README.md", "src/*.rs"]',
    }
    for key, expected in required.items():
        if _assignment(package, key) != expected:
            raise PackageError(
                FailureCode.MANIFEST_METADATA,
                f"{key} does not match the public package contract",
            )
    try:
        publication = _assignment(package, "publish")
    except PackageError as error:
        raise PackageError(
            FailureCode.PUBLICATION_DISABLED,
            "the verifier package does not declare the approved registry",
        ) from error
    if publication != '["crates-io"]':
        raise PackageError(
            FailureCode.PUBLICATION_DISABLED,
            "the verifier package is not restricted to crates.io publication",
        )

    workspace_package = _section(workspace, "workspace.package")
    workspace_version = _assignment(workspace_package, "version").strip('"')
    if workspace_version != version_file:
        raise PackageError(
            FailureCode.VERSION_MISMATCH,
            "VERSION and workspace.package.version differ",
        )

    _validate_dependencies(manifest, workspace)
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
            for relative in PACKAGE_PAYLOAD_FILES:
                member = archive.extractfile(f"{expected_root}/{relative}")
                if member is None:
                    raise PackageError(
                        FailureCode.PACKAGE_INVENTORY,
                        f"package member has no bytes: {relative}",
                    )
                try:
                    source = (repository / CRATE / relative).read_bytes()
                except OSError as error:
                    raise PackageError(FailureCode.IO, str(error)) from error
                if member.read() != source:
                    raise PackageError(
                        FailureCode.PACKAGE_PAYLOAD,
                        f"package member differs from source: {relative}",
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
    if completed.returncode != 0 or completed.stdout != f"{PACKAGE_BINARY} {version}\n" or completed.stderr:
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
        with tempfile.TemporaryDirectory(prefix="verifier-package.", dir=target) as second:
            first_bytes = _build_once(repository, Path(first), version)
            second_bytes = _build_once(repository, Path(second), version)
    if first_bytes != second_bytes:
        raise PackageError(
            FailureCode.REPRODUCTION,
            _archive_name(version),
        )

    archive_name = _archive_name(version)
    archive_path = output / archive_name
    _write_exclusive(archive_path, first_bytes)
    with tempfile.TemporaryDirectory(
        prefix="proofbound-runtime-verifier-consumer."
    ) as consumer:
        _dogfood(archive_path, Path(consumer), version)

    digest = hashlib.sha256(first_bytes).hexdigest()
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
        output / "VERIFIER-PACKAGE-MANIFEST.json",
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n",
    )
    _write_exclusive(
        output / "SHA256SUMS",
        f"{digest}  {archive_name}\n".encode("ascii"),
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
