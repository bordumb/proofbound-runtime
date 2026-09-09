#!/usr/bin/env python3
"""Create the closed external byte-input manifest for a native release."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path


ARCHITECTURES = ("aarch64", "x86_64")
OBSERVATIONS = (
    ("PBR-COMPOSE-008", "composer-release", "pbr-compose"),
    ("PBR-RUN-007", "runtime-release", "pbr"),
    ("PBR-SEQUENCE-003", "launcher-release", "pbr-native-launcher"),
    ("PBR-VERIFY-006", "verifier-release", "pbr-verify"),
)
PROCEDURE = Path("crates/proofbound-runtime-compose/tests/release_observation.rs")


def relative_path(source: Path, base: Path) -> str:
    """Return a portable path from the manifest directory to one input."""

    return Path(os.path.relpath(source, base)).as_posix()


def build_manifest(root: Path, output: Path, architecture: str) -> dict[str, object]:
    """Build one closed manifest without reading or writing its inputs."""

    if architecture not in ARCHITECTURES:
        raise ValueError(f"unsupported release architecture: {architecture}")
    base = output.parent
    bundle = root / "dist/release-observation" / architecture
    procedure = relative_path(root / PROCEDURE, base)
    observations = [
        {
            "artifact_path": relative_path(bundle / artifact, base),
            "claim_id": claim,
            "platform": {
                "architecture": architecture,
                "operating_system": "linux",
            },
            "procedure_path": procedure,
            "subject_role": role,
        }
        for claim, role, artifact in OBSERVATIONS
    ]
    return {
        "observations": observations,
        "schema": "proofbound-observation-inputs/1",
    }


def require_regular(path: Path) -> None:
    """Reject a missing, non-regular, or symlink observation input."""

    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"observation input is not a regular non-symlink file: {path}")


def write_manifest(root: Path, output: Path, architecture: str) -> None:
    """Validate all named inputs and create one canonical manifest without replacement."""

    manifest = build_manifest(root, output, architecture)
    require_regular(root / PROCEDURE)
    for _, _, artifact in OBSERVATIONS:
        require_regular(root / "dist/release-observation" / architecture / artifact)
    parent = output.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError(f"manifest parent is not a regular directory: {parent}")
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(encoded)


def self_check(root: Path) -> list[str]:
    """Return any closed-shape or substitution-regression errors."""

    errors: list[str] = []
    for architecture in ARCHITECTURES:
        output = root / "dist/native-evidence" / architecture / "inputs.json"
        manifest = build_manifest(root, output, architecture)
        observations = manifest["observations"]
        if not isinstance(observations, list) or len(observations) != len(OBSERVATIONS):
            errors.append(f"{architecture}: observation inventory is incomplete")
            continue
        actual = [
            (item["claim_id"], item["subject_role"])
            for item in observations
            if isinstance(item, dict)
        ]
        expected = [(claim, role) for claim, role, _ in OBSERVATIONS]
        if actual != expected:
            errors.append(f"{architecture}: observation roles or claims were substituted")
        if any(
            item["platform"]
            != {"architecture": architecture, "operating_system": "linux"}
            for item in observations
        ):
            errors.append(f"{architecture}: observation platform was substituted")
        expected_artifacts = [
            f"../../release-observation/{architecture}/{artifact}"
            for _, _, artifact in OBSERVATIONS
        ]
        if [item["artifact_path"] for item in observations] != expected_artifacts:
            errors.append(f"{architecture}: artifact paths escaped the release bundle")
        if any(
            item["procedure_path"]
            != "../../../crates/proofbound-runtime-compose/tests/release_observation.rs"
            for item in observations
        ):
            errors.append(f"{architecture}: procedure path was substituted")
        if any(Path(item["artifact_path"]).is_absolute() for item in observations):
            errors.append(f"{architecture}: artifact path must be manifest-relative")
        if any(Path(item["procedure_path"]).is_absolute() for item in observations):
            errors.append(f"{architecture}: procedure path must be manifest-relative")
    try:
        build_manifest(root, root / "dist/invalid.json", "riscv64")
        errors.append("unsupported architecture was accepted")
    except ValueError:
        pass
    return errors


def main() -> int:
    """Validate the generator or create one native observation manifest."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--architecture")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    if args.check:
        if args.architecture is not None or args.output is not None:
            parser.error("--check cannot be combined with generation arguments")
        errors = self_check(root)
        for error in errors:
            print(f"observation input check failed: {error}", file=sys.stderr)
        return int(bool(errors))
    if args.architecture is None or args.output is None:
        parser.error("--architecture and --output are required")
    try:
        if ".." in args.output.parts:
            raise ValueError("output path must not contain a parent traversal")
        output = args.output if args.output.is_absolute() else root / args.output
        output.relative_to(root)
        write_manifest(root, output, args.architecture)
    except (OSError, ValueError) as error:
        print(f"observation input generation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
