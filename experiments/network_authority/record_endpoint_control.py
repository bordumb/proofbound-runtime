#!/usr/bin/env python3
"""Publish one closed, no-replace result for the cgroup-BPF endpoint control."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

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
    ("allowed-endpoint", True),
    ("same-port-endpoint-substitution", False),
    ("other-port-denied", False),
    ("wrong-certificate-denied", False),
)
DIGEST = frozenset("0123456789abcdef")


def positive_integer(value: str, field: str) -> int:
    """Parse one strictly positive decimal observation."""

    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise RecordError(f"invalid positive integer: {field}") from error
    if parsed <= 0:
        raise RecordError(f"invalid positive integer: {field}")
    return parsed


def digest(value: str, field: str) -> str:
    """Validate one lowercase SHA-256 observation."""

    if len(value) != 64 or any(character not in DIGEST for character in value):
        raise RecordError(f"invalid SHA-256 digest: {field}")
    return value


def record(arguments: argparse.Namespace) -> Path:
    """Validate exact inputs and publish one immutable endpoint result."""

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
        "curl": bounded_text(arguments.curl, "curl"),
        "kernel_release": bounded_text(arguments.kernel_release, "kernel_release"),
        "openssl": bounded_text(arguments.openssl, "openssl"),
        "python": bounded_text(arguments.python, "python"),
    }
    observations = {
        "btf_sha256": digest(arguments.btf_sha256, "btf_sha256"),
        "btf_size": positive_integer(arguments.btf_size, "btf_size"),
        "cgroup_id": positive_integer(arguments.cgroup_id, "cgroup_id"),
        "connect4_program_id": positive_integer(
            arguments.connect4_program_id, "connect4_program_id"
        ),
        "connect6_program_id": positive_integer(
            arguments.connect6_program_id, "connect6_program_id"
        ),
    }
    exit_values = {
        case: parse_exit(getattr(arguments, case.replace("-", "_")), case)
        for case, _ in CASES
    }

    plan_path = confined_file(
        source_root, "experiments/network_authority/endpoint-control.toml"
    )
    source_path = confined_file(
        source_root, "experiments/network_authority/cgroup_endpoint_control.c"
    )
    loader_path = confined_file(work_root, "cgroup-endpoint-control")
    connect4_path = confined_file(work_root, "connect4-program.bin")
    connect6_path = confined_file(work_root, "connect6-program.bin")
    connect4_log_path = confined_file(work_root, "connect4-verifier.log")
    connect6_log_path = confined_file(work_root, "connect6-verifier.log")
    allowed_certificate_path = confined_file(work_root, "allowed-certificate.pem")
    denied_certificate_path = confined_file(work_root, "denied-certificate.pem")
    input_paths = [
        plan_path,
        source_path,
        loader_path,
        connect4_path,
        connect6_path,
        connect4_log_path,
        connect6_log_path,
        allowed_certificate_path,
        denied_certificate_path,
    ]
    for case, _ in CASES:
        input_paths.extend(
            [
                confined_file(work_root, f"stdout/{case}.log"),
                confined_file(work_root, f"stderr/{case}.log"),
            ]
        )
    inputs = {path: regular_bytes(path) for path in input_paths}

    if not output.parent.is_dir() or output.exists() or output.is_symlink():
        raise RecordError("output must be one absent child of an existing directory")
    os.mkdir(output, 0o755)
    os.mkdir(output / "stdout", 0o755)
    os.mkdir(output / "stderr", 0o755)
    write_new(output / "plan.toml", inputs[plan_path])

    attack_entries = []
    for case, expects_zero in CASES:
        observed = exit_values[case]
        matched = (observed == 0) == expects_zero
        attack_entries.append(
            {
                "case": case,
                "expected_exit": "zero" if expects_zero else "nonzero",
                "matched_expected": matched,
                "observed_exit": observed,
            }
        )
        for stream in ("stdout", "stderr"):
            relative = f"{stream}/{case}.log"
            write_new(output / relative, inputs[work_root / relative])

    attack_result = {
        "cases": attack_entries,
        "complete": True,
        "schema": "proofbound-runtime-network-experiment-attacks/1",
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
        "btf": {
            "name": "/sys/kernel/btf/vmlinux",
            "sha256": observations["btf_sha256"],
            "size": observations["btf_size"],
        },
        "cgroup_filesystem": "cgroup2",
        "kernel_release": metadata["kernel_release"],
        "schema": "proofbound-runtime-network-experiment-kernel/1",
    }
    tool_manifest = {
        "compiler": metadata["compiler"],
        "curl": metadata["curl"],
        "openssl": metadata["openssl"],
        "python": metadata["python"],
        "schema": "proofbound-runtime-network-experiment-tools/1",
    }
    artifact_manifest = {
        "artifacts": [
            identity(
                "cgroup-endpoint-control", inputs[loader_path], loader_path.lstat().st_mode
            ),
            identity(
                "cgroup_endpoint_control.c", inputs[source_path], source_path.lstat().st_mode
            ),
        ],
        "schema": "proofbound-runtime-network-experiment-artifacts/1",
    }
    bpf_manifest = {
        "allowed_endpoint": {"ipv4": "127.0.0.1", "port": 443, "transport": "tcp"},
        "cgroup_id": observations["cgroup_id"],
        "cleanup_observed": arguments.cleanup_observed == "true",
        "programs": [
            {
                "attach_type": "BPF_CGROUP_INET4_CONNECT",
                "instructions": identity(
                    "connect4-program.bin",
                    inputs[connect4_path],
                    connect4_path.lstat().st_mode,
                ),
                "program_id": observations["connect4_program_id"],
                "verifier_log": identity(
                    "connect4-verifier.log",
                    inputs[connect4_log_path],
                    connect4_log_path.lstat().st_mode,
                ),
            },
            {
                "attach_type": "BPF_CGROUP_INET6_CONNECT",
                "instructions": identity(
                    "connect6-program.bin",
                    inputs[connect6_path],
                    connect6_path.lstat().st_mode,
                ),
                "program_id": observations["connect6_program_id"],
                "verifier_log": identity(
                    "connect6-verifier.log",
                    inputs[connect6_log_path],
                    connect6_log_path.lstat().st_mode,
                ),
            },
        ],
        "schema": "proofbound-runtime-network-experiment-bpf/1",
    }
    manifests = {
        "artifact-manifest.json": canonical_json(artifact_manifest),
        "attack-results.json": canonical_json(attack_result),
        "bpf-manifest.json": canonical_json(bpf_manifest),
        "fixture-manifest.json": canonical_json(fixture_manifest),
        "kernel-manifest.json": canonical_json(kernel_manifest),
        "tool-manifest.json": canonical_json(tool_manifest),
    }
    for name, data in manifests.items():
        write_new(output / name, data)

    published_inputs = dict(manifests)
    published_inputs["plan.toml"] = inputs[plan_path]
    for case, _ in CASES:
        for stream in ("stdout", "stderr"):
            relative = f"{stream}/{case}.log"
            published_inputs[relative] = inputs[work_root / relative]
    all_expected = all(entry["matched_expected"] for entry in attack_entries)
    complete = all_expected and arguments.cleanup_observed == "true"
    result = {
        "complete": complete,
        "conclusion": (
            "endpoint-control-selects-routing-tuple-only"
            if complete
            else "unexpected-control-result"
        ),
        "experiment": "network-authority/1",
        "inputs": [
            {"name": name, "sha256": sha256(data), "size": len(data)}
            for name, data in sorted(published_inputs.items())
        ],
        "mechanism": "cgroup-bpf-endpoint-control",
        "schema": "proofbound-runtime-network-experiment-result/1",
        "source_commit": arguments.source_commit,
    }
    write_new(output / "RESULT.json", canonical_json(result))
    return output


def parser() -> argparse.ArgumentParser:
    """Build the closed command-line parser."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    for name in (
        "output",
        "source-root",
        "work-root",
        "source-commit",
        "architecture",
        "kernel-release",
        "btf-sha256",
        "btf-size",
        "compiler",
        "curl",
        "openssl",
        "python",
        "cgroup-id",
        "connect4-program-id",
        "connect6-program-id",
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
