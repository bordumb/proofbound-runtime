#!/usr/bin/env python3
"""Validate the canonical product, Cargo workspace, and Lake package version."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


VERSION_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
)
WORKSPACE_PACKAGE = re.compile(r"(?ms)^\[workspace\.package]\s*(.*?)(?=^\[|\Z)")
TOML_VERSION = re.compile(r'(?m)^version\s*=\s*"([^"]+)"\s*$')


def validate(root: Path) -> list[str]:
    """Return all detected version errors."""

    errors: list[str] = []
    raw_version = (root / "VERSION").read_text(encoding="utf-8")
    if raw_version != raw_version.strip() + "\n":
        errors.append("VERSION must contain one value followed by one newline")
    version = raw_version.strip()
    if VERSION_PATTERN.fullmatch(version) is None:
        errors.append("VERSION must contain a canonical X.Y.Z value")

    cargo = (root / "Cargo.toml").read_text(encoding="utf-8")
    workspace = WORKSPACE_PACKAGE.search(cargo)
    version_match = TOML_VERSION.search(workspace.group(1)) if workspace else None
    cargo_version = version_match.group(1) if version_match else None
    if cargo_version != version:
        errors.append(
            f"Cargo.toml workspace version {cargo_version!r} does not match {version!r}"
        )

    lake = (root / "lakefile.toml").read_text(encoding="utf-8")
    lake_match = TOML_VERSION.search(lake)
    lake_version = lake_match.group(1) if lake_match else None
    if lake_version != version:
        errors.append(
            f"lakefile.toml package version {lake_version!r} does not match {version!r}"
        )
    return errors


def main() -> int:
    """Run the version check."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate version data")
    parser.add_argument("--root", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.check:
        parser.error("--check is required")

    root = (args.root or Path(__file__).resolve().parents[2]).resolve()
    try:
        errors = validate(root)
    except (OSError, ValueError) as error:
        errors = [str(error)]
    for error in errors:
        print(f"version check failed: {error}", file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
