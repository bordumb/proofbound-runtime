#!/usr/bin/env python3
"""Run CI commands while emitting non-evidentiary timing metadata."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path


SCHEMA = "proofbound-runtime-ci-timing/1"
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_ROOT = (REPOSITORY_ROOT / ".proofbound").resolve()


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser()
    subparsers = argument_parser.add_subparsers(dest="command_name", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--output", required=True, type=Path)
    run_parser.add_argument("--stage", required=True)
    run_parser.add_argument("--kind", required=True, choices=("stage", "unit"))
    run_parser.add_argument("--name", required=True)
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    return argument_parser


def validate_identifier(label: str, value: str) -> None:
    if not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} must match {IDENTIFIER.pattern}")


def validate_output(output: Path) -> None:
    resolved = output.resolve()
    if resolved == EVIDENCE_ROOT or EVIDENCE_ROOT in resolved.parents:
        raise ValueError("CI timing metadata must not be written under .proofbound")


def revision() -> str:
    github_sha = os.environ.get("GITHUB_SHA")
    if github_sha:
        return github_sha
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPOSITORY_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def append_record(output: Path, record: dict[str, object]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    descriptor = os.open(output, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, line.encode("utf-8"))
    finally:
        os.close(descriptor)


def run_command(args: argparse.Namespace) -> int:
    validate_identifier("stage", args.stage)
    validate_identifier("name", args.name)
    validate_output(args.output)
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        raise ValueError("a command is required after --")

    started = time.monotonic_ns()
    try:
        completed = subprocess.run(command, check=False)
        return_code = completed.returncode
    except FileNotFoundError:
        return_code = 127
    duration_ms = max(0, (time.monotonic_ns() - started) // 1_000_000)
    portable_return_code = return_code if return_code >= 0 else 128 + abs(return_code)
    append_record(
        args.output,
        {
            "duration_ms": duration_ms,
            "exit_code": portable_return_code,
            "job": os.environ.get("GITHUB_JOB"),
            "kind": args.kind,
            "name": args.name,
            "outcome": "success" if return_code == 0 else "failure",
            "revision": revision(),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "runner_arch": os.environ.get("RUNNER_ARCH"),
            "schema": SCHEMA,
            "stage": args.stage,
        },
    )
    return portable_return_code


def main() -> int:
    try:
        args = parser().parse_args()
        if args.command_name == "run":
            return run_command(args)
    except ValueError as error:
        print(f"timing metadata error: {error}", file=sys.stderr)
        return 2
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
