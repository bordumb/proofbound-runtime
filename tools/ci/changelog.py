#!/usr/bin/env python3
"""Validate changelog structure and product version coverage."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import date
from pathlib import Path


VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
RELEASE_HEADING = re.compile(r"(?m)^## \[([^]]+)] - ([0-9]{4}-[0-9]{2}-[0-9]{2})$")


def staged_paths(root: Path) -> set[str]:
    """Return paths staged for addition, copy, modification, or rename."""

    completed = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return set(completed.stdout.splitlines())


def validate(root: Path, staged: bool) -> list[str]:
    """Return all detected changelog errors."""

    errors: list[str] = []
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")

    if VERSION_PATTERN.fullmatch(version) is None:
        errors.append("VERSION is not a canonical X.Y.Z value")
    if not changelog.startswith("# Changelog\n"):
        errors.append("CHANGELOG.md must start with '# Changelog'")
    if changelog.count("## [Unreleased]") != 1:
        errors.append("CHANGELOG.md must contain one Unreleased heading")

    releases: dict[str, str] = {}
    for released_version, released_at in RELEASE_HEADING.findall(changelog):
        if released_version in releases:
            errors.append(f"CHANGELOG.md repeats release {released_version}")
        releases[released_version] = released_at
        try:
            date.fromisoformat(released_at)
        except ValueError:
            errors.append(f"CHANGELOG.md has invalid date {released_at!r}")

    if version not in releases:
        errors.append(f"CHANGELOG.md needs a release entry for {version}")

    unreleased = changelog.find("## [Unreleased]")
    current = changelog.find(f"## [{version}] - ")
    if unreleased < 0 or current < 0 or unreleased > current:
        errors.append("the Unreleased section must precede the current release")

    if staged:
        changed = staged_paths(root)
        if "VERSION" in changed and "CHANGELOG.md" not in changed:
            errors.append("a staged VERSION change must also stage CHANGELOG.md")
    return errors


def main() -> int:
    """Run the changelog check."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true", help="check staged co-change policy")
    parser.add_argument("--root", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = (args.root or Path(__file__).resolve().parents[2]).resolve()
    try:
        errors = validate(root, args.staged)
    except (OSError, subprocess.CalledProcessError) as error:
        errors = [str(error)]
    for error in errors:
        print(f"changelog check failed: {error}", file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
