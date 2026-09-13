#!/usr/bin/env python3
"""Publish one closed result for the explicit per-execution broker control."""

from __future__ import annotations

import argparse
import os
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
    parse_exit,
    regular_bytes,
    sha256,
    write_new,
)


CASES = (
    ("allowed-request", True),
    ("target-substitution", False),
    ("direct-tcp-denied", False),
    ("direct-udp-denied", False),
    ("wrong-certificate-denied", False),
    ("zero-frame-denied", False),
    ("oversized-frame-denied", False),
    ("truncated-frame-denied", False),
    ("duplicate-key-denied", False),
    ("invalid-utf8-denied", False),
    ("noncanonical-frame-denied", False),
    ("fork-direct-tcp-denied", False),
    ("broker-crash-denied", False),
    ("foreign-descriptor-denied", False),
)
SOURCE_FILES = (
    "__init__.py",
    "explicit_broker.py",
    "record_common.py",
    "broker_case_client.py",
    "run_broker_case.py",
    "broker_child_control.c",
)


def parse_boundary(data: bytes, architecture: str) -> dict[str, object]:
    """Decode one exact wrapper observation record."""

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RecordError("boundary observation is not UTF-8") from error
    fields: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if not separator or not name or not value or name in fields:
            raise RecordError("boundary observation grammar is invalid")
        fields[name] = value
    expected = {
        "architecture",
        "instruction_count",
        "no_new_privs",
        "retained_fd",
        "socket_family",
        "socket_type",
    }
    if set(fields) != expected:
        raise RecordError("boundary observation fields are not exact")
    if (
        fields["architecture"] != architecture
        or fields["no_new_privs"] != "true"
        or fields["socket_family"] != "unix"
        or fields["socket_type"] != "stream"
    ):
        raise RecordError("boundary observation value is invalid")
    try:
        instruction_count = int(fields["instruction_count"], 10)
        retained_fd = int(fields["retained_fd"], 10)
    except ValueError as error:
        raise RecordError("boundary numeric observation is invalid") from error
    if instruction_count <= 0 or retained_fd < 3:
        raise RecordError("boundary numeric observation is outside its domain")
    return {
        "architecture": architecture,
        "instruction_count": instruction_count,
        "no_new_privs": True,
        "retained_fd": retained_fd,
        "socket_family": "unix",
        "socket_type": "stream",
    }


def record(arguments: argparse.Namespace) -> Path:
    """Validate exact inputs and publish one immutable broker result."""

    output = Path(arguments.output)
    source_root = Path(arguments.source_root)
    work_root = Path(arguments.work_root)
    if not output.is_absolute() or not source_root.is_absolute() or not work_root.is_absolute():
        raise RecordError("output and input roots must be absolute")
    if not SOURCE_COMMIT.fullmatch(arguments.source_commit):
        raise RecordError("source commit must be one lowercase SHA-1 identity")
    if arguments.architecture not in {"x86_64", "aarch64"}:
        raise RecordError("unsupported architecture")
    if arguments.cleanup_observed not in {"true", "false"}:
        raise RecordError("cleanup observation must be true or false")
    metadata = {
        "architecture": arguments.architecture,
        "compiler": bounded_text(arguments.compiler, "compiler"),
        "kernel_release": bounded_text(arguments.kernel_release, "kernel_release"),
        "openssl": bounded_text(arguments.openssl, "openssl"),
        "python": bounded_text(arguments.python, "python"),
    }
    exit_values = {
        case: parse_exit(getattr(arguments, case.replace("-", "_")), case)
        for case, _ in CASES
    }

    experiment_root = "experiments/network_authority"
    plan_path = confined_file(source_root, f"{experiment_root}/broker-control.toml")
    source_paths = [
        confined_file(source_root, f"{experiment_root}/{name}") for name in SOURCE_FILES
    ]
    wrapper_path = confined_file(work_root, "broker-child-control")
    allowed_certificate_path = confined_file(work_root, "allowed-certificate.pem")
    denied_certificate_path = confined_file(work_root, "denied-certificate.pem")
    input_paths = [
        plan_path,
        *source_paths,
        wrapper_path,
        allowed_certificate_path,
        denied_certificate_path,
    ]
    for case, _ in CASES:
        input_paths.extend(
            [
                confined_file(work_root, f"state/{case}/seccomp-program.bin"),
                confined_file(work_root, f"state/{case}/boundary-observations.txt"),
                confined_file(work_root, f"stdout/{case}.log"),
                confined_file(work_root, f"stderr/{case}.log"),
                confined_file(work_root, f"broker-stdout/{case}.log"),
                confined_file(work_root, f"broker-stderr/{case}.log"),
            ]
        )
    for service in ("allowed", "denied"):
        input_paths.extend(
            [
                confined_file(work_root, f"fixture-stdout/{service}.log"),
                confined_file(work_root, f"fixture-stderr/{service}.log"),
            ]
        )
    inputs = {path: regular_bytes(path) for path in input_paths}

    boundaries = []
    program_digests = set()
    for case, _ in CASES:
        program_path = work_root / f"state/{case}/seccomp-program.bin"
        observation_path = work_root / f"state/{case}/boundary-observations.txt"
        program_identity = identity(
            "seccomp-program.bin", inputs[program_path], program_path.lstat().st_mode
        )
        program_digests.add(program_identity["sha256"])
        boundaries.append(
            {
                "case": case,
                "observations": parse_boundary(
                    inputs[observation_path], arguments.architecture
                ),
                "seccomp_program": program_identity,
            }
        )
    if len(program_digests) != 1:
        raise RecordError("broker cases did not install one exact seccomp program")

    if not output.parent.is_dir() or output.exists() or output.is_symlink():
        raise RecordError("output must be one absent child of an existing directory")
    os.mkdir(output, 0o755)
    for directory in (
        "stdout",
        "stderr",
        "stdout/broker",
        "stderr/broker",
        "stdout/fixture",
        "stderr/fixture",
    ):
        os.mkdir(output / directory, 0o755)
    write_new(output / "plan.toml", inputs[plan_path])

    attack_entries = []
    published_inputs: dict[str, bytes] = {"plan.toml": inputs[plan_path]}
    for case, expects_zero in CASES:
        observed = exit_values[case]
        attack_entries.append(
            {
                "case": case,
                "expected_exit": "zero" if expects_zero else "nonzero",
                "matched_expected": (observed == 0) == expects_zero,
                "observed_exit": observed,
            }
        )
        mappings = (
            (f"stdout/{case}.log", work_root / f"stdout/{case}.log"),
            (f"stderr/{case}.log", work_root / f"stderr/{case}.log"),
            (f"stdout/broker/{case}.log", work_root / f"broker-stdout/{case}.log"),
            (f"stderr/broker/{case}.log", work_root / f"broker-stderr/{case}.log"),
        )
        for relative, source in mappings:
            write_new(output / relative, inputs[source])
            published_inputs[relative] = inputs[source]
    for service in ("allowed", "denied"):
        for stream in ("stdout", "stderr"):
            relative = f"{stream}/fixture/{service}.log"
            source = work_root / f"fixture-{stream}/{service}.log"
            write_new(output / relative, inputs[source])
            published_inputs[relative] = inputs[source]

    attack_result = {
        "cases": attack_entries,
        "complete": True,
        "schema": "proofbound-runtime-network-experiment-attacks/1",
    }
    broker_manifest = {
        "channel": {"maximum_frame_bytes": 4096, "type": "unix-stream"},
        "operation": {"maximum_payload_bytes": 1024, "name": "echo"},
        "service": {
            "endpoint": "127.0.0.1:443",
            "name": "allowed.test",
            "transport": "tls",
        },
        "schema": "proofbound-runtime-network-experiment-broker/1",
    }
    boundary_manifest = {
        "cases": boundaries,
        "cleanup_observed": arguments.cleanup_observed == "true",
        "schema": "proofbound-runtime-network-experiment-child-boundary/1",
    }
    fixture_manifest = {
        "certificates": [
            identity(
                "allowed-certificate.pem",
                inputs[allowed_certificate_path],
                allowed_certificate_path.lstat().st_mode,
            ),
            identity(
                "denied-certificate.pem",
                inputs[denied_certificate_path],
                denied_certificate_path.lstat().st_mode,
            ),
        ],
        "network": "disposable-loopback-namespace",
        "schema": "proofbound-runtime-network-experiment-fixture/1",
    }
    kernel_manifest = {
        "architecture": metadata["architecture"],
        "kernel_release": metadata["kernel_release"],
        "schema": "proofbound-runtime-network-experiment-kernel/1",
    }
    tool_manifest = {
        "compiler": metadata["compiler"],
        "openssl": metadata["openssl"],
        "python": metadata["python"],
        "schema": "proofbound-runtime-network-experiment-tools/1",
    }
    artifact_manifest = {
        "artifacts": [
            identity(
                "broker-child-control", inputs[wrapper_path], wrapper_path.lstat().st_mode
            ),
            *[
                identity(path.name, inputs[path], path.lstat().st_mode)
                for path in source_paths
            ],
        ],
        "schema": "proofbound-runtime-network-experiment-artifacts/1",
    }
    manifests = {
        "artifact-manifest.json": canonical_json(artifact_manifest),
        "attack-results.json": canonical_json(attack_result),
        "boundary-manifest.json": canonical_json(boundary_manifest),
        "broker-manifest.json": canonical_json(broker_manifest),
        "fixture-manifest.json": canonical_json(fixture_manifest),
        "kernel-manifest.json": canonical_json(kernel_manifest),
        "tool-manifest.json": canonical_json(tool_manifest),
    }
    for name, data in manifests.items():
        write_new(output / name, data)
        published_inputs[name] = data

    all_expected = all(entry["matched_expected"] for entry in attack_entries)
    complete = all_expected and arguments.cleanup_observed == "true"
    result = {
        "complete": complete,
        "conclusion": (
            "explicit-broker-binds-fixed-service-control"
            if complete
            else "unexpected-control-result"
        ),
        "experiment": "network-authority/1",
        "inputs": [
            {"name": name, "sha256": sha256(data), "size": len(data)}
            for name, data in sorted(published_inputs.items())
        ],
        "mechanism": "explicit-per-execution-broker-control",
        "schema": "proofbound-runtime-network-experiment-result/1",
        "source_commit": arguments.source_commit,
    }
    write_new(output / "RESULT.json", canonical_json(result))
    return output


def parser() -> argparse.ArgumentParser:
    """Build the closed recorder interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    for name in (
        "output",
        "source-root",
        "work-root",
        "source-commit",
        "architecture",
        "kernel-release",
        "compiler",
        "openssl",
        "python",
        "cleanup-observed",
    ):
        result.add_argument(f"--{name}", required=True)
    for case, _ in CASES:
        result.add_argument(f"--{case}", required=True)
    return result


def main() -> int:
    """Publish one result or fail with a bounded diagnostic."""

    try:
        record(parser().parse_args())
    except (OSError, RecordError) as error:
        print(f"network experiment record failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
