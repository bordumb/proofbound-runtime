#!/usr/bin/env python3
"""Publish one immutable experiment 0001F mechanism result."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.record_common import (
    SOURCE_COMMIT,
    RecordError,
    bounded_text,
    canonical_json,
    confined_file,
    identity,
    regular_bytes,
    sha256,
    write_new,
)
from experiments.network_authority.run_routing_direct_case import (
    RoutingOrchestrationError,
    read_document,
)
from experiments.network_authority.routing_cell import RoutingCellError, classify
from experiments.network_authority.routing_transport_case import (
    MECHANISMS,
    RoutingCase,
    load_routing_matrix,
)


MAX_EVIDENCE_FILES = 512
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
REQUIRED_ARTIFACTS = {
    "landlock-port": {
        "allowed-certificate.pem",
        "denied-certificate.pem",
        "routing-child-control",
        "routing-landlock-control",
    },
    "cgroup-endpoint": {
        "allowed-certificate.pem",
        "denied-certificate.pem",
        "routing-child-control",
        "routing-endpoint-control",
    },
    "explicit-broker": {
        "allowed-certificate.pem",
        "broker-child-control",
        "denied-certificate.pem",
    },
    "preconnected-channel": {
        "allowed-certificate.pem",
        "denied-certificate.pem",
        "preconnected-child-control",
    },
}
SOURCE_SUBJECTS = {
    "landlock-port": (
        "experiments/network_authority/routing_landlock_control.c",
        "experiments/network_authority/routing_child_control.c",
        "experiments/network_authority/routing_transport_client.py",
        "experiments/network_authority/run_routing_direct_case.py",
    ),
    "cgroup-endpoint": (
        "experiments/network_authority/routing_endpoint_control.c",
        "experiments/network_authority/routing_child_control.c",
        "experiments/network_authority/routing_transport_client.py",
        "experiments/network_authority/run_routing_direct_case.py",
    ),
    "explicit-broker": (
        "experiments/network_authority/broker_child_control.c",
        "experiments/network_authority/routing_mediator.py",
        "experiments/network_authority/routing_mediated_client.py",
        "experiments/network_authority/run_routing_broker_case.py",
    ),
    "preconnected-channel": (
        "experiments/network_authority/preconnected_child_control.c",
        "experiments/network_authority/routing_mediator.py",
        "experiments/network_authority/routing_mediated_client.py",
        "experiments/network_authority/run_routing_preconnected_case.py",
    ),
}
COMMON_SUBJECTS = (
    "docs/experiments/0001f-routing-transport-slice.md",
    "experiments/network_authority/decision-matrix.toml",
    "experiments/network_authority/routing_cell.py",
    "experiments/network_authority/routing_transport_case.py",
)


def evidence_inventory(root: Path, cases: tuple[RoutingCase, ...], mechanism: str):
    """Read one bounded, symlink-free, exact-root evidence tree."""

    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise RecordError("evidence root is invalid")
    root_names = {path.name for path in root.iterdir()}
    if root_names != {"artifacts", "cases"}:
        raise RecordError("evidence root inventory is not exact")
    artifacts = root / "artifacts"
    case_root = root / "cases"
    if (
        artifacts.is_symlink()
        or case_root.is_symlink()
        or not artifacts.is_dir()
        or not case_root.is_dir()
    ):
        raise RecordError("evidence root children are invalid")
    artifact_names = {path.name for path in artifacts.iterdir()}
    if artifact_names != REQUIRED_ARTIFACTS[mechanism]:
        raise RecordError("compiled artifact inventory is not exact")
    for name in artifact_names:
        path = artifacts / name
        mode = path.lstat().st_mode
        if name.endswith("-control") and mode & 0o111 == 0:
            raise RecordError("compiled control is not executable")
    case_names = {path.name for path in case_root.iterdir()}
    if case_names != {case.identifier for case in cases}:
        raise RecordError("routing case directory inventory is not exact")

    result: dict[str, tuple[bytes, int]] = {}
    total = 0
    pending = [artifacts, case_root]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir(), key=lambda item: item.name):
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise RecordError(f"evidence path is a symlink: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise RecordError(f"evidence path is not regular: {relative}")
            data = regular_bytes(path)
            total += len(data)
            result[relative] = (data, metadata.st_mode)
            if len(result) > MAX_EVIDENCE_FILES or total > MAX_EVIDENCE_BYTES:
                raise RecordError("routing evidence inventory exceeds its bound")
    return result


def cell_document(
    case: RoutingCase,
    mechanism: str,
    raw_path: Path,
) -> dict[str, object]:
    """Derive one cell, retaining invalid raw input as a harness failure."""

    expected = case.expectation(mechanism)
    try:
        raw = read_document(raw_path)
        observed = classify(raw, case, mechanism)
        observed_document: dict[str, object] = {
            "outcome": observed.outcome,
            "stage": observed.stage,
        }
        matched = (
            observed.outcome == expected.outcome and observed.stage == expected.stage
        )
        failure = None
    except (OSError, RecordError, RoutingCellError, RoutingOrchestrationError) as error:
        raw = None
        observed_document = {"outcome": "harness-failure", "stage": None}
        matched = False
        failure = type(error).__name__
    return {
        "case": case.identifier,
        "expectation": {"outcome": expected.outcome, "stage": expected.stage},
        "failure": failure,
        "matched": matched,
        "mechanism": mechanism,
        "observed": observed_document,
        "raw": raw,
        "schema": "proofbound-runtime-routing-cell/1",
    }


def make_directory(path: Path) -> None:
    """Create one result directory component with fixed permissions."""

    os.mkdir(path, 0o755)


def record(arguments: argparse.Namespace) -> Path:
    """Validate all inputs and publish one no-replace mechanism result."""

    output = Path(arguments.output)
    source_root = Path(arguments.source_root)
    evidence_root = Path(arguments.evidence_root)
    if (
        not output.is_absolute()
        or not source_root.is_absolute()
        or not evidence_root.is_absolute()
        or not source_root.is_dir()
        or source_root.is_symlink()
    ):
        raise RecordError("routing result roots must be absolute")
    if not SOURCE_COMMIT.fullmatch(arguments.source_commit):
        raise RecordError("source commit must be one lowercase SHA-1 identity")
    if arguments.mechanism not in MECHANISMS:
        raise RecordError("routing result mechanism is invalid")
    if arguments.architecture not in {"x86_64", "aarch64"}:
        raise RecordError("routing result architecture is invalid")
    metadata = {
        "architecture": arguments.architecture,
        "compiler": bounded_text(arguments.compiler, "compiler"),
        "kernel_release": bounded_text(arguments.kernel_release, "kernel_release"),
        "openssl": bounded_text(arguments.openssl, "openssl"),
        "python": bounded_text(arguments.python, "python"),
    }
    matrix_path = source_root / "experiments/network_authority/decision-matrix.toml"
    matrix = load_routing_matrix(matrix_path)
    evidence = evidence_inventory(evidence_root, matrix.cases, arguments.mechanism)
    subjects: dict[str, tuple[bytes, int]] = {}
    for relative in (*COMMON_SUBJECTS, *SOURCE_SUBJECTS[arguments.mechanism]):
        path = confined_file(source_root, relative)
        subjects[relative] = (regular_bytes(path), path.lstat().st_mode)

    cells = [
        cell_document(
            case,
            arguments.mechanism,
            evidence_root / f"cases/{case.identifier}/raw-cell.json",
        )
        for case in matrix.cases
    ]
    complete = len(cells) == 16 and all(cell["matched"] for cell in cells)

    if not output.parent.is_dir() or output.exists() or output.is_symlink():
        raise RecordError("routing output must be absent below an existing directory")
    make_directory(output)
    make_directory(output / "cells")
    make_directory(output / "evidence")
    make_directory(output / "source")
    published: dict[str, bytes] = {}

    matrix_bytes = subjects["experiments/network_authority/decision-matrix.toml"][0]
    write_new(output / "decision-matrix.toml", matrix_bytes)
    published["decision-matrix.toml"] = matrix_bytes
    for cell in cells:
        relative = f"cells/{cell['case']}/CELL.json"
        directory = output / f"cells/{cell['case']}"
        make_directory(directory)
        data = canonical_json(cell)
        write_new(output / relative, data)
        published[relative] = data

    for relative, (data, _mode) in sorted(evidence.items()):
        target = output / "evidence" / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        write_new(target, data)
        published[f"evidence/{relative}"] = data

    source_entries = []
    for index, (relative, (data, mode)) in enumerate(sorted(subjects.items())):
        name = f"{index:02d}-{Path(relative).name}"
        write_new(output / "source" / name, data, stat.S_IMODE(mode))
        published[f"source/{name}"] = data
        source_entries.append(
            {"path": relative, **identity(name, data, mode)}
        )
    source_manifest = {
        "decision_matrix_sha256": matrix.source_sha256,
        "files": source_entries,
        "schema": "proofbound-runtime-routing-source-manifest/1",
        "source_commit": arguments.source_commit,
    }
    evidence_manifest = {
        "files": [
            {
                "mode": format(stat.S_IMODE(mode), "04o"),
                "name": relative,
                "sha256": sha256(data),
                "size": len(data),
            }
            for relative, (data, mode) in sorted(evidence.items())
        ],
        "schema": "proofbound-runtime-routing-evidence-manifest/1",
    }
    tool_manifest = {
        **metadata,
        "schema": "proofbound-runtime-routing-tool-manifest/1",
    }
    for name, value in (
        ("source-manifest.json", source_manifest),
        ("evidence-manifest.json", evidence_manifest),
        ("tool-manifest.json", tool_manifest),
    ):
        data = canonical_json(value)
        write_new(output / name, data)
        published[name] = data

    result = {
        "case_count": len(cells),
        "complete": complete,
        "conclusion": (
            "routing-transport-slice-matched"
            if complete
            else "routing-transport-slice-mismatch"
        ),
        "decision_matrix_sha256": matrix.source_sha256,
        "inputs": [
            {"name": name, "sha256": sha256(data), "size": len(data)}
            for name, data in sorted(published.items())
        ],
        "matched_case_count": sum(bool(cell["matched"]) for cell in cells),
        "mechanism": arguments.mechanism,
        "schema": "proofbound-runtime-routing-result/1",
        "source_commit": arguments.source_commit,
    }
    write_new(output / "RESULT.json", canonical_json(result))
    return output


def parser() -> argparse.ArgumentParser:
    """Build the closed routing result recorder interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    for name in (
        "output",
        "source-root",
        "evidence-root",
        "source-commit",
        "mechanism",
        "architecture",
        "kernel-release",
        "compiler",
        "openssl",
        "python",
    ):
        result.add_argument(f"--{name}", required=True)
    return result


def main() -> int:
    """Publish one result or fail with a bounded diagnostic."""

    try:
        record(parser().parse_args())
        return 0
    except (OSError, RecordError) as error:
        print(f"routing transport record failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
