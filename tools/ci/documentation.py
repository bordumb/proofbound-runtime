#!/usr/bin/env python3
"""Validate repository text and local Markdown references."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote


TEXT_SUFFIXES = {".json", ".md", ".py", ".rs", ".sh", ".toml", ".yaml", ".yml"}
SKIPPED_PARTS = {".git", ".lake", ".proofbound", "target"}
LOCAL_LINK = re.compile(r"\[[^]]*]\(([^)]+)\)")
FEEDBACK_FILE = re.compile(r"pbf-([0-9]{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.md")


def text_files(root: Path) -> list[Path]:
    """Return repository text files in stable order."""

    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or SKIPPED_PARTS.intersection(path.parts):
            continue
        if path.suffix in TEXT_SUFFIXES or path.name in {
            ".editorconfig",
            ".gitignore",
            "LICENSE",
            "VERSION",
            "justfile",
        }:
            files.append(path)
    return sorted(files)


def local_link_errors(path: Path, text: str) -> list[str]:
    """Return missing local-link errors for one Markdown file."""

    errors: list[str] = []
    for raw_target in LOCAL_LINK.findall(text):
        target = raw_target.strip().strip("<>")
        if target.startswith(("#", "http://", "https://", "mailto:")):
            continue
        relative = unquote(target.split("#", 1)[0])
        if not relative:
            continue
        resolved = (path.parent / relative).resolve()
        if not resolved.exists():
            errors.append(f"{path}: local Markdown target does not exist: {target}")
    return errors


def feedback_errors(root: Path) -> list[str]:
    """Return feedback identity and index errors."""

    directory = root / "docs" / "proofbound-feedback"
    index = (directory / "README.md").read_text(encoding="utf-8")
    seen: set[str] = set()
    errors: list[str] = []
    for path in sorted(directory.glob("pbf-*.md")):
        match = FEEDBACK_FILE.fullmatch(path.name)
        if match is None:
            errors.append(f"{path}: invalid feedback filename")
            continue
        identity = f"PBF-{match.group(1)}"
        if identity in seen:
            errors.append(f"{path}: duplicate feedback identity {identity}")
        seen.add(identity)
        first_line = path.read_text(encoding="utf-8").splitlines()[0]
        if not first_line.startswith(f"# {identity}:"):
            errors.append(f"{path}: heading does not match {identity}")
        if f"({path.name})" not in index:
            errors.append(f"{path}: feedback index does not link to this file")
    return errors


def validate(root: Path) -> list[str]:
    """Return all detected documentation errors."""

    errors: list[str] = []
    for path in text_files(root):
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError) as error:
            errors.append(f"{path}: {error}")
            continue
        if b"\r" in raw:
            errors.append(f"{path}: carriage return is not permitted")
        if raw and not raw.endswith(b"\n"):
            errors.append(f"{path}: final newline is missing")
        for number, line in enumerate(text.splitlines(), start=1):
            if line.rstrip(" \t") != line:
                errors.append(f"{path}:{number}: trailing whitespace")
        if path.suffix == ".md":
            if sum(line.startswith("```") for line in text.splitlines()) % 2:
                errors.append(f"{path}: fenced code block is not closed")
            errors.extend(local_link_errors(path, text))
    errors.extend(feedback_errors(root))
    return errors


def main() -> int:
    """Run the documentation check."""

    root = Path(__file__).resolve().parents[2]
    errors = validate(root)
    for error in errors:
        print(f"documentation check failed: {error}", file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
