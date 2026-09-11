#!/usr/bin/env python3
"""Discover the exact dynamic-library files for the frozen native workload."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


class DiscoveryFailure(Exception):
    """The host inspection did not identify one closed dynamic library set."""


def canonical_file(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise DiscoveryFailure
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise DiscoveryFailure from error
    if not resolved.is_file():
        raise DiscoveryFailure
    return resolved


def parse_interpreter(output: str) -> Path:
    matches = re.findall(r"\[Requesting program interpreter: (/[^\]\n]+)\]", output)
    if len(matches) != 1:
        raise DiscoveryFailure
    return canonical_file(matches[0])


def parse_libraries(output: str, interpreter: Path) -> list[Path]:
    libraries: set[Path] = set()
    for line in output.splitlines():
        stripped = line.strip()
        if "=> not found" in stripped:
            raise DiscoveryFailure
        candidate: str | None = None
        if "=>" in stripped:
            right = stripped.split("=>", 1)[1].strip().split()
            if right:
                candidate = right[0]
        else:
            first = stripped.split(maxsplit=1)
            if first and first[0].startswith("/"):
                candidate = first[0]
        if candidate is None or not candidate.startswith("/"):
            continue
        resolved = canonical_file(candidate)
        if resolved != interpreter:
            libraries.add(resolved)
    if not libraries:
        raise DiscoveryFailure
    return sorted(libraries, key=lambda path: str(path))


def inspect(executable: Path) -> list[Path]:
    try:
        readelf = subprocess.run(
            ["readelf", "-l", "--", str(executable)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        ldd = subprocess.run(
            ["ldd", str(executable)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DiscoveryFailure from error
    if readelf.returncode != 0 or readelf.stderr or ldd.returncode != 0 or ldd.stderr:
        raise DiscoveryFailure
    return parse_libraries(ldd.stdout, parse_interpreter(readelf.stdout))


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    options = parser.parse_args(arguments)
    try:
        libraries = inspect(options.executable.resolve(strict=True))
    except (OSError, DiscoveryFailure):
        print("benchmark.native.dynamic-closure-invalid", file=sys.stderr)
        return 1
    print(json.dumps([str(path) for path in libraries], separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
