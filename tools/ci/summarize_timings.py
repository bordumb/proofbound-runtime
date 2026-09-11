#!/usr/bin/env python3
"""Summarize retained non-evidentiary CI timing records for humans."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


SCHEMA = "proofbound-runtime-ci-timing/1"
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
RECORD_KEYS = frozenset(
    {
        "duration_ms",
        "exit_code",
        "job",
        "kind",
        "name",
        "outcome",
        "revision",
        "run_attempt",
        "run_id",
        "runner_arch",
        "schema",
        "stage",
    }
)


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="timing JSONL files or directories containing them",
    )
    return argument_parser


def closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def timing_files(inputs: list[Path]) -> list[Path]:
    files: set[Path] = set()
    for supplied in inputs:
        path = supplied.resolve()
        if path.is_file():
            files.add(path)
        elif path.is_dir():
            files.update(candidate.resolve() for candidate in path.rglob("*.jsonl"))
        else:
            raise ValueError(f"timing input does not exist: {supplied}")
    if not files:
        raise ValueError("no timing JSONL files found")
    return sorted(files)


def require_string(record: dict[str, object], key: str) -> str:
    value = record[key]
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a nonempty string")
    return value


def validate_record(record: object) -> dict[str, object]:
    if not isinstance(record, dict):
        raise ValueError("timing record must be one JSON object")
    keys = frozenset(record)
    if keys != RECORD_KEYS:
        missing = sorted(RECORD_KEYS - keys)
        unknown = sorted(keys - RECORD_KEYS)
        raise ValueError(f"timing record keys differ: missing={missing}, unknown={unknown}")
    if record["schema"] != SCHEMA:
        raise ValueError("timing record schema is unsupported")

    duration = record["duration_ms"]
    exit_code = record["exit_code"]
    if type(duration) is not int or duration < 0:
        raise ValueError("duration_ms must be a nonnegative integer")
    if type(exit_code) is not int or not 0 <= exit_code <= 255:
        raise ValueError("exit_code must be an integer from 0 through 255")

    kind = require_string(record, "kind")
    stage = require_string(record, "stage")
    name = require_string(record, "name")
    if kind not in ("stage", "unit"):
        raise ValueError("kind must be stage or unit")
    for label, value in (("stage", stage), ("name", name)):
        if IDENTIFIER.fullmatch(value) is None:
            raise ValueError(f"{label} must match {IDENTIFIER.pattern}")

    outcome = require_string(record, "outcome")
    expected_outcome = "success" if exit_code == 0 else "failure"
    if outcome != expected_outcome:
        raise ValueError("outcome does not match exit_code")
    revision = require_string(record, "revision")
    if REVISION.fullmatch(revision) is None:
        raise ValueError("revision must be an exact lowercase 40-character commit")
    for key in ("job", "run_attempt", "run_id", "runner_arch"):
        require_string(record, key)
    return record


def read_records(inputs: list[Path]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    identities: set[tuple[object, ...]] = set()
    for path in timing_files(inputs):
        lines = path.read_text(encoding="utf-8").splitlines()
        if not lines:
            raise ValueError(f"timing file is empty: {path}")
        for line_number, line in enumerate(lines, 1):
            if not line:
                raise ValueError(f"blank timing record at {path}:{line_number}")
            try:
                decoded = json.loads(line, object_pairs_hook=closed_object)
                record = validate_record(decoded)
            except (json.JSONDecodeError, ValueError) as error:
                raise ValueError(f"invalid timing record at {path}:{line_number}: {error}") from error
            identity = (
                record["run_id"],
                record["run_attempt"],
                record["job"],
                record["kind"],
                record["stage"],
                record["name"],
                record["revision"],
            )
            if identity in identities:
                raise ValueError(f"duplicate timing record at {path}:{line_number}")
            identities.add(identity)
            records.append(record)
    return records


def median(values: list[int]) -> int:
    midpoint = len(values) // 2
    if len(values) % 2:
        return values[midpoint]
    return (values[midpoint - 1] + values[midpoint]) // 2


def nearest_rank_p95(values: list[int]) -> int:
    return values[((95 * len(values) + 99) // 100) - 1]


def render(records: list[dict[str, object]]) -> str:
    groups: dict[tuple[str, str, str], list[dict[str, object]]] = defaultdict(list)
    for record in records:
        key = (str(record["kind"]), str(record["stage"]), str(record["name"]))
        groups[key].append(record)

    lines = ["kind\tstage\tname\tsamples\tsuccesses\tfailures\tmedian_ms\tp95_ms"]
    for key in sorted(groups):
        group = groups[key]
        successes = sorted(
            int(record["duration_ms"])
            for record in group
            if record["outcome"] == "success"
        )
        failures = len(group) - len(successes)
        summary = (
            (str(median(successes)), str(nearest_rank_p95(successes)))
            if successes
            else ("-", "-")
        )
        lines.append(
            "\t".join(
                (*key, str(len(group)), str(len(successes)), str(failures), *summary)
            )
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    try:
        args = parser().parse_args()
        sys.stdout.write(render(read_records(args.inputs)))
    except (OSError, ValueError) as error:
        print(f"timing summary error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
