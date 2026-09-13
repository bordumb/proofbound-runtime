#!/usr/bin/env python3
"""Publish one immutable incomplete experiment 0001I result."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.measurement_domain import (
    ARCHITECTURES,
    MECHANISMS,
    MeasurementDomainError,
    load_measurement_domain,
)
from experiments.network_authority.record_common import (
    SOURCE_COMMIT,
    RecordError,
    bounded_text,
    canonical_json,
    regular_bytes,
    sha256,
    write_new,
)
from experiments.network_authority.routing_transport_case import (
    RoutingCaseError,
    load_routing_matrix,
)


def record_failure(arguments: argparse.Namespace) -> Path:
    """Retain a bounded native failure without promoting it to a measurement."""

    output = Path(arguments.output)
    source_root = Path(arguments.source_root)
    stdout_path = Path(arguments.stdout)
    stderr_path = Path(arguments.stderr)
    if (
        not all(
            path.is_absolute()
            for path in (output, source_root, stdout_path, stderr_path)
        )
        or output.exists()
        or output.is_symlink()
        or not output.parent.is_dir()
        or not source_root.is_dir()
        or source_root.is_symlink()
        or arguments.mechanism not in MECHANISMS
        or arguments.architecture not in ARCHITECTURES
        or not SOURCE_COMMIT.fullmatch(arguments.source_commit)
        or type(arguments.exit_status) is not int
        or not 1 <= arguments.exit_status <= 255
    ):
        raise RecordError("incomplete measurement identity is invalid")
    domain_path = source_root / "experiments/network_authority/measurement-domain.toml"
    matrix_path = source_root / "experiments/network_authority/decision-matrix.toml"
    domain = load_measurement_domain(domain_path)
    matrix = load_routing_matrix(matrix_path)
    domain.profile(arguments.mechanism)
    stdout = regular_bytes(stdout_path)
    stderr = regular_bytes(stderr_path)
    domain_bytes = regular_bytes(domain_path)
    matrix_bytes = regular_bytes(matrix_path)
    tool = canonical_json({
        "architecture": arguments.architecture,
        "compiler": bounded_text(arguments.compiler, "compiler"),
        "kernel_release": bounded_text(arguments.kernel_release, "kernel release"),
        "python": bounded_text(arguments.python, "python"),
        "schema": "proofbound-runtime-network-measurement-tool-manifest/1",
    })

    os.mkdir(output, 0o755)
    os.mkdir(output / "diagnostic", 0o755)
    os.mkdir(output / "source", 0o755)
    published = {
        "diagnostic/stderr.txt": (stderr, 0o644),
        "diagnostic/stdout.txt": (stdout, 0o644),
        "source/decision-matrix.toml": (matrix_bytes, 0o644),
        "source/measurement-domain.toml": (domain_bytes, 0o644),
        "tool-manifest.json": (tool, 0o644),
    }
    for name, (data, mode) in sorted(published.items()):
        write_new(output / name, data, stat.S_IMODE(mode))
    result = {
        "architecture": arguments.architecture,
        "complete": False,
        "conclusion": "network-measurement-incomplete",
        "decision_matrix_sha256": matrix.source_sha256,
        "exit_status": arguments.exit_status,
        "inputs": [
            {"name": name, "sha256": sha256(data), "size": len(data)}
            for name, (data, _mode) in sorted(published.items())
        ],
        "measurement_domain_sha256": domain.source_sha256,
        "mechanism": arguments.mechanism,
        "schema": "proofbound-runtime-network-measurement-result/1",
        "source_commit": arguments.source_commit,
        "stage": "native-measurement",
    }
    write_new(output / "RESULT.json", canonical_json(result))
    return output


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    for name in (
        "output", "source-root", "stdout", "stderr", "source-commit",
        "mechanism", "architecture", "kernel-release", "compiler", "python",
    ):
        result.add_argument(f"--{name}", required=True)
    result.add_argument("--exit-status", required=True, type=int)
    return result


def main() -> int:
    try:
        record_failure(parser().parse_args())
        return 0
    except (
        MeasurementDomainError,
        RecordError,
        RoutingCaseError,
        OSError,
        ValueError,
    ) as error:
        print(f"incomplete network measurement record failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
