#!/usr/bin/env python3
"""Publish one immutable experiment 0001H mechanism result."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.bypass_cell import BypassCellError, derive
from experiments.network_authority.bypass_lifecycle_case import (
    BypassCase, BypassLifecycleError, case_plan, load_bypass_matrix,
)
from experiments.network_authority.record_common import (
    SOURCE_COMMIT, RecordError, bounded_text, canonical_json, confined_file,
    identity, regular_bytes, sha256, write_new,
)
from experiments.network_authority.routing_transport_case import MECHANISMS


MAX_EVIDENCE_FILES = 2048
MAX_EVIDENCE_BYTES = 128 * 1024 * 1024
SUBJECT_NAMES = {"certificate", "channel", "client", "executable", "native-policy", "resolver", "trust-root"}
STAGED_FILES = {
    "__init__.py", "bypass_cell.py", "bypass_lifecycle_case.py",
    "bypass_lifecycle_evidence.py", "bypass_syscall_probe.py",
    "connection_reuse_channel.py", "connection_reuse_client.py",
    "connection_reuse_fixture.py", "explicit_broker.py", "record_common.py",
    "run_bypass_lifecycle_case.py", "run_bypass_syscall_case.py",
    "run_connection_reuse_case.py",
}
COMMON_ARTIFACTS = {
    "broker-child-control", "preconnected-child-control", "process-limit-control",
    "routing-child-control", "staged", "stopped-release-control", "subjects",
}
REQUIRED_ARTIFACTS = {
    "landlock-port": COMMON_ARTIFACTS | {"routing-landlock-control"},
    "cgroup-endpoint": COMMON_ARTIFACTS | {"routing-endpoint-control"},
    "explicit-broker": COMMON_ARTIFACTS,
    "preconnected-channel": COMMON_ARTIFACTS,
}
COMMON_SUBJECTS = (
    "docs/experiments/0001h-bypass-lifecycle-slice.md",
    "experiments/network_authority/bypass_cell.py",
    "experiments/network_authority/bypass_lifecycle_case.py",
    "experiments/network_authority/bypass_lifecycle_evidence.py",
    "experiments/network_authority/bypass_syscall_probe.py",
    "experiments/network_authority/connection_reuse_channel.py",
    "experiments/network_authority/connection_reuse_client.py",
    "experiments/network_authority/connection_reuse_fixture.py",
    "experiments/network_authority/decision-matrix.toml",
    "experiments/network_authority/process_limit_control.c",
    "experiments/network_authority/record_bypass_lifecycle.py",
    "experiments/network_authority/record_common.py",
    "experiments/network_authority/run_bypass_lifecycle_case.py",
    "experiments/network_authority/run_bypass_syscall_case.py",
    "experiments/network_authority/run_connection_reuse_case.py",
    "experiments/network_authority/stopped_release_control.c",
)
CONTROL_SOURCES = {
    "landlock-port": "experiments/network_authority/routing_landlock_control.c",
    "cgroup-endpoint": "experiments/network_authority/routing_endpoint_control.c",
}
COMMON_CONTROL_SOURCES = (
    "experiments/network_authority/broker_child_control.c",
    "experiments/network_authority/preconnected_child_control.c",
    "experiments/network_authority/routing_child_control.c",
)


def document(path: Path) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value = {}
        for name, item in pairs:
            if name in value:
                raise RecordError("bypass JSON contains duplicate names")
            value[name] = item
        return value
    try:
        value = json.loads(regular_bytes(path), object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecordError("bypass JSON input is invalid") from error
    if not isinstance(value, dict):
        raise RecordError("bypass JSON input is not an object")
    return value


def evidence_inventory(root: Path, cases: tuple[BypassCase, ...], mechanism: str) -> dict[str, tuple[bytes, int]]:
    if not root.is_absolute() or not root.is_dir() or root.is_symlink() or {path.name for path in root.iterdir()} != {"artifacts", "cases"}:
        raise RecordError("bypass evidence root is invalid")
    artifacts, case_root = root / "artifacts", root / "cases"
    if {path.name for path in artifacts.iterdir()} != REQUIRED_ARTIFACTS[mechanism] or {path.name for path in case_root.iterdir()} != {case.identifier for case in cases}:
        raise RecordError("bypass artifact or case inventory is not exact")
    if {path.name for path in (artifacts / "subjects").iterdir()} != SUBJECT_NAMES:
        raise RecordError("bypass subject inventory is not exact")
    staged = artifacts / "staged/experiments/network_authority"
    if {path.name for path in staged.iterdir()} != STAGED_FILES or {path.name for path in staged.parent.iterdir()} != {"__init__.py", "network_authority"}:
        raise RecordError("bypass staged inventory is not exact")
    result = {}
    total = 0
    pending = [artifacts, case_root]
    while pending:
        directory = pending.pop()
        if directory.is_symlink() or not directory.is_dir():
            raise RecordError("bypass evidence directory is invalid")
        for path in sorted(directory.iterdir()):
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise RecordError("bypass evidence contains a symlink")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                data = regular_bytes(path)
                result[relative] = (data, metadata.st_mode)
                total += len(data)
            else:
                raise RecordError("bypass evidence contains a special file")
            if len(result) > MAX_EVIDENCE_FILES or total > MAX_EVIDENCE_BYTES:
                raise RecordError("bypass evidence exceeds its bound")
    for name in REQUIRED_ARTIFACTS[mechanism] - {"staged", "subjects"}:
        if (artifacts / name).lstat().st_mode & 0o111 == 0:
            raise RecordError("bypass native control is not executable")
    return result


def expected_identities(evidence: dict[str, tuple[bytes, int]], case: str, mechanism: str) -> dict[str, str]:
    def digest(name: str) -> str:
        return sha256(evidence[name][0])
    if case == "inherited-connected-internet-socket" or case.startswith("mediator-") or "substitution" in case or case in {"cleanup-and-namespace-teardown-failure", "existing-result-replacement"}:
        return {name: digest(f"artifacts/subjects/{name}") for name in sorted(SUBJECT_NAMES)}
    if case == "connection-reuse-beyond-count":
        result = {
            "broker-child": digest("artifacts/broker-child-control"),
            "client": digest("artifacts/staged/experiments/network_authority/connection_reuse_client.py"),
            "preconnected-child": digest("artifacts/preconnected-child-control"),
            "routing-child": digest("artifacts/routing-child-control"),
        }
        if mechanism in {"landlock-port", "cgroup-endpoint"}:
            control = "routing-landlock-control" if mechanism == "landlock-port" else "routing-endpoint-control"
            result["fixture"] = digest("artifacts/staged/experiments/network_authority/connection_reuse_fixture.py")
            result["mechanism-control"] = digest(f"artifacts/{control}")
        return result
    result = {
        "child-control": digest(f"artifacts/{'routing-child-control' if mechanism in {'landlock-port', 'cgroup-endpoint'} else 'broker-child-control' if mechanism == 'explicit-broker' else 'preconnected-child-control'}"),
        "client": digest("artifacts/staged/experiments/network_authority/bypass_syscall_probe.py"),
        "process-limit-control": digest("artifacts/process-limit-control"),
    }
    if mechanism in {"landlock-port", "cgroup-endpoint"}:
        result["mechanism-control"] = digest(f"artifacts/{'routing-landlock-control' if mechanism == 'landlock-port' else 'routing-endpoint-control'}")
    if case == "concurrent-install-and-connect":
        result["stopped-release-control"] = digest("artifacts/stopped-release-control")
    return result


def cell_document(case: BypassCase, mechanism: str, evidence: dict[str, tuple[bytes, int]], root: Path, matrix_sha256: str) -> dict[str, object]:
    expected = case.expectation(mechanism)
    try:
        plan = document(root / f"cases/{case.identifier}/case-plan.json")
        if plan != case_plan(case, mechanism, matrix_sha256, expected_identities(evidence, case.identifier, mechanism)):
            raise BypassLifecycleError("prelaunch bypass plan changed")
        raw = document(root / f"cases/{case.identifier}/raw-cell.json")
        observed = derive(raw, case, mechanism)
        observed_value = {"outcome": observed.outcome, "stage": observed.stage}
        matched = observed_value == {"outcome": expected.outcome, "stage": expected.stage}
        failure = None
    except (BypassCellError, BypassLifecycleError, OSError, RecordError) as error:
        raw = None
        observed_value = {"outcome": "harness-failure", "stage": None}
        matched = False
        failure = type(error).__name__
    return {"case": case.identifier, "expectation": {"outcome": expected.outcome, "stage": expected.stage}, "failure": failure, "matched": matched, "mechanism": mechanism, "observed": observed_value, "raw": raw, "schema": "proofbound-runtime-bypass-cell/1"}


def record(arguments: argparse.Namespace) -> Path:
    output, source_root, evidence_root = map(Path, (arguments.output, arguments.source_root, arguments.evidence_root))
    if not all(path.is_absolute() for path in (output, source_root, evidence_root)) or not source_root.is_dir() or source_root.is_symlink():
        raise RecordError("bypass result roots must be absolute")
    if not SOURCE_COMMIT.fullmatch(arguments.source_commit) or arguments.mechanism not in MECHANISMS or arguments.architecture not in {"x86_64", "aarch64"}:
        raise RecordError("bypass result identity is invalid")
    matrix = load_bypass_matrix(source_root / "experiments/network_authority/decision-matrix.toml")
    evidence = evidence_inventory(evidence_root, matrix.cases, arguments.mechanism)
    subjects = {}
    source_paths = [*COMMON_SUBJECTS, *COMMON_CONTROL_SOURCES]
    if arguments.mechanism in CONTROL_SOURCES:
        source_paths.append(CONTROL_SOURCES[arguments.mechanism])
    for relative in source_paths:
        path = confined_file(source_root, relative)
        subjects[relative] = (regular_bytes(path), path.lstat().st_mode)
    cells = [cell_document(case, arguments.mechanism, evidence, evidence_root, matrix.source_sha256) for case in matrix.cases]
    complete = len(cells) == 18 and all(cell["matched"] is True for cell in cells)
    if not output.parent.is_dir() or output.exists() or output.is_symlink():
        raise RecordError("bypass output must be absent below an existing directory")
    for directory in (output, output / "cells", output / "evidence", output / "source"):
        os.mkdir(directory, 0o755)
    published = {}
    matrix_bytes = subjects["experiments/network_authority/decision-matrix.toml"][0]
    write_new(output / "decision-matrix.toml", matrix_bytes); published["decision-matrix.toml"] = matrix_bytes
    for cell in cells:
        directory = output / f"cells/{cell['case']}"; os.mkdir(directory, 0o755)
        data = canonical_json(cell); write_new(directory / "CELL.json", data); published[f"cells/{cell['case']}/CELL.json"] = data
    for relative, (data, mode) in sorted(evidence.items()):
        target = output / "evidence" / relative; target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        write_new(target, data, stat.S_IMODE(mode)); published[f"evidence/{relative}"] = data
    source_entries = []
    for index, (relative, (data, mode)) in enumerate(sorted(subjects.items())):
        name = f"{index:02d}-{Path(relative).name}"; write_new(output / "source" / name, data, stat.S_IMODE(mode)); published[f"source/{name}"] = data
        source_entries.append({"path": relative, **identity(name, data, mode)})
    manifests = {
        "source-manifest.json": {"decision_matrix_sha256": matrix.source_sha256, "files": source_entries, "schema": "proofbound-runtime-bypass-source-manifest/1", "source_commit": arguments.source_commit},
        "evidence-manifest.json": {"files": [{"mode": format(stat.S_IMODE(mode), "04o"), "name": name, "sha256": sha256(data), "size": len(data)} for name, (data, mode) in sorted(evidence.items())], "schema": "proofbound-runtime-bypass-evidence-manifest/1"},
        "tool-manifest.json": {"architecture": arguments.architecture, "compiler": bounded_text(arguments.compiler, "compiler"), "kernel_release": bounded_text(arguments.kernel_release, "kernel_release"), "python": bounded_text(arguments.python, "python"), "schema": "proofbound-runtime-bypass-tool-manifest/1"},
    }
    for name, value in manifests.items():
        data = canonical_json(value); write_new(output / name, data); published[name] = data
    result = {"case_count": len(cells), "complete": complete, "conclusion": "bypass-lifecycle-slice-matched" if complete else "bypass-lifecycle-slice-mismatch", "decision_matrix_sha256": matrix.source_sha256, "inputs": [{"name": name, "sha256": sha256(data), "size": len(data)} for name, data in sorted(published.items())], "matched_case_count": sum(cell["matched"] is True for cell in cells), "mechanism": arguments.mechanism, "schema": "proofbound-runtime-bypass-result/1", "source_commit": arguments.source_commit}
    write_new(output / "RESULT.json", canonical_json(result))
    return output


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    for name in ("output", "source-root", "evidence-root", "source-commit", "mechanism", "architecture", "kernel-release", "compiler", "python"):
        result.add_argument(f"--{name}", required=True)
    return result


def main() -> int:
    try:
        record(parser().parse_args()); return 0
    except (OSError, RecordError) as error:
        print(f"bypass lifecycle record failed: {error}", file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())
