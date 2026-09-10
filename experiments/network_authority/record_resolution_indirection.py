#!/usr/bin/env python3
"""Publish one immutable experiment 0001G mechanism result."""

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
from experiments.network_authority.resolution_cell import ResolutionCellError, classify
from experiments.network_authority.resolution_indirection_case import (
    ResolutionCase,
    case_plan,
    load_resolution_matrix,
)
from experiments.network_authority.run_resolution_direct_case import (
    ResolutionDirectError,
    read_document,
)
from experiments.network_authority.routing_transport_case import MECHANISMS


MAX_EVIDENCE_FILES = 2048
MAX_EVIDENCE_BYTES = 128 * 1024 * 1024
COMMON_ARTIFACTS = {
    "allowed-certificate.pem",
    "registered-resolver.json",
    "staged",
    "substitute-resolver.json",
}
REQUIRED_ARTIFACTS = {
    "landlock-port": COMMON_ARTIFACTS | {"routing-child-control", "routing-landlock-control"},
    "cgroup-endpoint": COMMON_ARTIFACTS | {"routing-child-control", "routing-endpoint-control"},
    "explicit-broker": COMMON_ARTIFACTS | {"broker-child-control"},
    "preconnected-channel": COMMON_ARTIFACTS | {"preconnected-child-control"},
}
STAGED_NETWORK_FILES = {
    "__init__.py",
    "decision_http_fixture.py",
    "decision_proxy_fixture.py",
    "explicit_broker.py",
    "record_common.py",
    "resolution_indirection_client.py",
    "resolution_network_client.py",
    "scripted_dns.py",
}
COMMON_SUBJECTS = (
    "docs/experiments/0001g-resolution-indirection-slice.md",
    "experiments/network_authority/decision-matrix.toml",
    "experiments/network_authority/record_common.py",
    "experiments/network_authority/record_resolution_indirection.py",
    "experiments/network_authority/resolution_broker.py",
    "experiments/network_authority/resolution_cell.py",
    "experiments/network_authority/resolution_indirection_case.py",
    "experiments/network_authority/resolution_indirection_client.py",
    "experiments/network_authority/resolution_network_client.py",
    "experiments/network_authority/scripted_dns.py",
    "experiments/network_authority/decision_http_fixture.py",
    "experiments/network_authority/decision_proxy_fixture.py",
    "experiments/network_authority/run_resolution_direct_case.py",
    "experiments/network_authority/run_resolution_broker_case.py",
    "experiments/network_authority/run_resolution_preconnected_case.py",
)
SOURCE_SUBJECTS = {
    "landlock-port": (
        "experiments/network_authority/routing_landlock_control.c",
        "experiments/network_authority/routing_child_control.c",
    ),
    "cgroup-endpoint": (
        "experiments/network_authority/routing_endpoint_control.c",
        "experiments/network_authority/routing_child_control.c",
    ),
    "explicit-broker": (
        "experiments/network_authority/broker_child_control.c",
        "experiments/network_authority/explicit_broker.py",
    ),
    "preconnected-channel": (
        "experiments/network_authority/preconnected_child_control.c",
        "experiments/network_authority/run_routing_preconnected_case.py",
        "experiments/network_authority/routing_mediator.py",
    ),
}


def evidence_inventory(
    root: Path, cases: tuple[ResolutionCase, ...], mechanism: str
) -> dict[str, tuple[bytes, int]]:
    """Read one bounded, symlink-free, exact-root evidence tree."""

    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise RecordError("resolution evidence root is invalid")
    if {path.name for path in root.iterdir()} != {"artifacts", "cases"}:
        raise RecordError("resolution evidence root inventory is not exact")
    artifacts = root / "artifacts"
    case_root = root / "cases"
    if artifacts.is_symlink() or case_root.is_symlink() or not artifacts.is_dir() or not case_root.is_dir():
        raise RecordError("resolution evidence root children are invalid")
    artifact_names = {path.name for path in artifacts.iterdir()}
    if artifact_names != REQUIRED_ARTIFACTS[mechanism]:
        raise RecordError("resolution compiled artifact inventory is not exact")
    for name in artifact_names:
        path = artifacts / name
        if name.endswith("-control") and path.lstat().st_mode & 0o111 == 0:
            raise RecordError("resolution compiled control is not executable")
    staged_root = artifacts / "staged"
    staged_experiments = staged_root / "experiments"
    staged_network = staged_experiments / "network_authority"
    if (
        staged_root.is_symlink()
        or staged_experiments.is_symlink()
        or staged_network.is_symlink()
        or not staged_network.is_dir()
        or {path.name for path in staged_experiments.iterdir()} != {"__init__.py", "network_authority"}
        or {path.name for path in staged_network.iterdir()} != STAGED_NETWORK_FILES
    ):
        raise RecordError("resolution staged client inventory is not exact")
    if {path.name for path in case_root.iterdir()} != {case.identifier for case in cases}:
        raise RecordError("resolution case directory inventory is not exact")

    result: dict[str, tuple[bytes, int]] = {}
    total = 0
    pending = [artifacts, case_root]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir(), key=lambda item: item.name):
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise RecordError(f"resolution evidence path is a symlink: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise RecordError(f"resolution evidence path is not regular: {relative}")
            data = regular_bytes(path)
            total += len(data)
            result[relative] = (data, metadata.st_mode)
            if len(result) > MAX_EVIDENCE_FILES or total > MAX_EVIDENCE_BYTES:
                raise RecordError("resolution evidence inventory exceeds its bound")
    return result


def cell_document(
    case: ResolutionCase,
    mechanism: str,
    raw_path: Path,
    plan_path: Path,
    matrix_sha256: str,
    registered_resolver_sha256: str,
    substitute_resolver_sha256: str,
) -> dict[str, object]:
    """Derive one cell, retaining invalid raw input as a harness failure."""

    expected = case.expectation(mechanism)
    try:
        plan = read_document(plan_path)
        expected_plan = case_plan(
            case,
            mechanism,
            matrix_sha256,
            registered_resolver_sha256,
            substitute_resolver_sha256,
        )
        if plan != expected_plan:
            raise ResolutionDirectError("prelaunch resolution case plan changed")
        raw = read_document(raw_path)
        observed = classify(raw, case, mechanism)
        observed_document: dict[str, object] = {"outcome": observed.outcome, "stage": observed.stage}
        matched = observed.outcome == expected.outcome and observed.stage == expected.stage
        failure = None
    except (OSError, RecordError, ResolutionCellError, ResolutionDirectError) as error:
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
        "schema": "proofbound-runtime-resolution-cell/1",
    }


def _make_directory(path: Path) -> None:
    os.mkdir(path, 0o755)


def record(arguments: argparse.Namespace) -> Path:
    """Validate all inputs and publish one no-replace resolution result."""

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
        raise RecordError("resolution result roots must be absolute")
    if not SOURCE_COMMIT.fullmatch(arguments.source_commit):
        raise RecordError("resolution source commit is invalid")
    if arguments.mechanism not in MECHANISMS:
        raise RecordError("resolution result mechanism is invalid")
    if arguments.architecture not in {"x86_64", "aarch64"}:
        raise RecordError("resolution result architecture is invalid")
    metadata = {
        "architecture": arguments.architecture,
        "compiler": bounded_text(arguments.compiler, "compiler"),
        "kernel_release": bounded_text(arguments.kernel_release, "kernel_release"),
        "openssl": bounded_text(arguments.openssl, "openssl"),
        "python": bounded_text(arguments.python, "python"),
    }
    matrix = load_resolution_matrix(source_root / "experiments/network_authority/decision-matrix.toml")
    evidence = evidence_inventory(evidence_root, matrix.cases, arguments.mechanism)
    registered_bytes = evidence["artifacts/registered-resolver.json"][0]
    substitute_bytes = evidence["artifacts/substitute-resolver.json"][0]
    registered_digest = sha256(registered_bytes)
    substitute_digest = sha256(substitute_bytes)
    if registered_digest == substitute_digest:
        raise RecordError("resolution configuration identities are not distinct")
    subjects: dict[str, tuple[bytes, int]] = {}
    for relative in (*COMMON_SUBJECTS, *SOURCE_SUBJECTS[arguments.mechanism]):
        path = confined_file(source_root, relative)
        subjects[relative] = (regular_bytes(path), path.lstat().st_mode)
    cells = [
        cell_document(
            case,
            arguments.mechanism,
            evidence_root / f"cases/{case.identifier}/raw-cell.json",
            evidence_root / f"cases/{case.identifier}/case-plan.json",
            matrix.source_sha256,
            registered_digest,
            substitute_digest,
        )
        for case in matrix.cases
    ]
    complete = len(cells) == 18 and all(bool(cell["matched"]) for cell in cells)
    if not output.parent.is_dir() or output.exists() or output.is_symlink():
        raise RecordError("resolution output must be absent below an existing directory")
    _make_directory(output)
    _make_directory(output / "cells")
    _make_directory(output / "evidence")
    _make_directory(output / "source")
    published: dict[str, bytes] = {}
    matrix_bytes = subjects["experiments/network_authority/decision-matrix.toml"][0]
    write_new(output / "decision-matrix.toml", matrix_bytes)
    published["decision-matrix.toml"] = matrix_bytes
    for cell in cells:
        relative = f"cells/{cell['case']}/CELL.json"
        directory = output / f"cells/{cell['case']}"
        _make_directory(directory)
        data = canonical_json(cell)
        write_new(output / relative, data)
        published[relative] = data
    for relative, (data, mode) in sorted(evidence.items()):
        target = output / "evidence" / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        write_new(target, data, stat.S_IMODE(mode))
        published[f"evidence/{relative}"] = data
    source_entries = []
    for index, (relative, (data, mode)) in enumerate(sorted(subjects.items())):
        name = f"{index:02d}-{Path(relative).name}"
        write_new(output / "source" / name, data, stat.S_IMODE(mode))
        published[f"source/{name}"] = data
        source_entries.append({"path": relative, **identity(name, data, mode)})
    manifests = {
        "source-manifest.json": {
            "decision_matrix_sha256": matrix.source_sha256,
            "files": source_entries,
            "schema": "proofbound-runtime-resolution-source-manifest/1",
            "source_commit": arguments.source_commit,
        },
        "evidence-manifest.json": {
            "files": [
                {
                    "mode": format(stat.S_IMODE(mode), "04o"),
                    "name": relative,
                    "sha256": sha256(data),
                    "size": len(data),
                }
                for relative, (data, mode) in sorted(evidence.items())
            ],
            "schema": "proofbound-runtime-resolution-evidence-manifest/1",
        },
        "tool-manifest.json": {
            **metadata,
            "schema": "proofbound-runtime-resolution-tool-manifest/1",
        },
    }
    for name, value in manifests.items():
        data = canonical_json(value)
        write_new(output / name, data)
        published[name] = data
    result = {
        "case_count": len(cells),
        "complete": complete,
        "conclusion": (
            "resolution-indirection-slice-matched"
            if complete
            else "resolution-indirection-slice-mismatch"
        ),
        "decision_matrix_sha256": matrix.source_sha256,
        "inputs": [
            {"name": name, "sha256": sha256(data), "size": len(data)}
            for name, data in sorted(published.items())
        ],
        "matched_case_count": sum(bool(cell["matched"]) for cell in cells),
        "mechanism": arguments.mechanism,
        "schema": "proofbound-runtime-resolution-result/1",
        "source_commit": arguments.source_commit,
    }
    write_new(output / "RESULT.json", canonical_json(result))
    return output


def parser() -> argparse.ArgumentParser:
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
    try:
        record(parser().parse_args())
        return 0
    except (OSError, RecordError) as error:
        print(f"resolution indirection record failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
