#!/usr/bin/env python3
"""Reject repository state that is not ready for release promotion."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import date
from pathlib import Path


VERSION_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
)
RELEASE_HEADING = re.compile(r"(?m)^## \[([^]]+)] - ([0-9]{4}-[0-9]{2}-[0-9]{2})$")


def version_key(value: str) -> tuple[int, int, int]:
    if VERSION_PATTERN.fullmatch(value) is None:
        raise ValueError(f"invalid semantic version {value!r}")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def normalize_tags(raw_tags: list[str]) -> list[str]:
    normalized: list[str] = []
    for raw_tag in raw_tags:
        tag = raw_tag.removeprefix("v")
        if VERSION_PATTERN.fullmatch(tag):
            normalized.append(tag)
    return normalized


def validate(root: Path, existing_tags: list[str]) -> list[str]:
    errors: list[str] = []
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    try:
        current_key = version_key(version)
    except ValueError as error:
        return [str(error)]

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
        errors.append(f"CHANGELOG.md needs a dated release entry for {version}")

    unreleased_heading = "## [Unreleased]"
    current_heading = f"## [{version}] - "
    unreleased_start = changelog.find(unreleased_heading)
    current_start = changelog.find(current_heading)
    if unreleased_start < 0:
        errors.append("CHANGELOG.md needs one Unreleased heading")
    elif current_start < 0 or current_start < unreleased_start:
        errors.append("the current release entry must follow Unreleased")
    else:
        unreleased_body = changelog[
            unreleased_start + len(unreleased_heading) : current_start
        ]
        if unreleased_body.strip():
            errors.append("the Unreleased section must be empty before promotion")

    normalized_tags = normalize_tags(existing_tags)
    if version in normalized_tags:
        errors.append(f"release tag v{version} already exists")
    previous = max(normalized_tags, key=version_key) if normalized_tags else None
    if previous is not None and current_key <= version_key(previous):
        errors.append(f"release version {version} must be newer than v{previous}")

    expected_unreleased = (
        "[Unreleased]: "
        f"https://github.com/bordumb/proofbound-runtime/compare/v{version}...HEAD"
    )
    if expected_unreleased not in changelog.splitlines():
        errors.append("the Unreleased comparison link must start at the promoted version")
    if previous is not None:
        expected_release = (
            f"[{version}]: https://github.com/bordumb/proofbound-runtime/compare/"
            f"v{previous}...v{version}"
        )
        if expected_release not in changelog.splitlines():
            errors.append("the current release comparison link is missing or stale")
    return errors


def repository_tags(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "tag", "--list"],
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.splitlines()


def main() -> int:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("--root", type=Path, default=Path(__file__).parents[2])
    argument_parser.add_argument(
        "--existing-tags",
        help="comma-separated test override; production reads repository tags",
    )
    args = argument_parser.parse_args()
    root = args.root.resolve()
    try:
        tags = (
            args.existing_tags.split(",") if args.existing_tags is not None else repository_tags(root)
        )
        errors = validate(root, tags)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        errors = [str(error)]
    for error in errors:
        print(f"release state invalid: {error}", file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
