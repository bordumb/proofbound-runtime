#!/usr/bin/env python3
"""Publish one immutable experiment 0001I measurement result."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.measurement_domain import (
    ARCHITECTURES,
    INVENTORY_CATEGORIES,
    MECHANISMS,
    MeasurementDomainError,
    load_measurement_domain,
)
from experiments.network_authority.measurement_observation import (
    MeasurementObservationError,
    inventory_observation,
    summarize_samples,
)
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
from experiments.network_authority.routing_cell import RoutingCellError, classify
from experiments.network_authority.routing_transport_case import load_routing_matrix
from experiments.network_authority.run_network_measurement import tree_summary


MAX_EVIDENCE_FILES = 8192
MAX_EVIDENCE_BYTES = 256 * 1024 * 1024
RAW_FIELDS = {
    "decision_matrix_sha256",
    "lifecycle",
    "measurement_domain_sha256",
    "mechanism",
    "mediator_resources",
    "platform",
    "request_observations",
    "request_summary",
    "residual_authority",
    "schema",
    "setup_observations",
    "setup_summary",
    "source_commit",
}
ARTIFACTS = {
    "landlock-port": {
        "certificate", "routing-child-control", "routing-landlock-control",
        "trust-root",
    },
    "cgroup-endpoint": {
        "certificate", "routing-child-control", "routing-endpoint-control",
        "trust-root",
    },
    "explicit-broker": {"broker-child-control", "certificate", "trust-root"},
    "preconnected-channel": {
        "certificate", "preconnected-child-control", "trust-root",
    },
}
HTTP_REQUEST_SHA256 = "74d2d0d91b73d482d44bc44c9efce9fb374bd424634b224f8f5ad7955307c804"
HTTP_RESPONSE_SHA256 = "171b2e654c262c92a4325908047e52e6dc22b739fb8339a0f8c0f5321d1140ee"
BINARIES = {
    "landlock-port": ("routing-child-control", "routing-landlock-control"),
    "cgroup-endpoint": ("routing-child-control", "routing-endpoint-control"),
    "explicit-broker": ("broker-child-control",),
    "preconnected-channel": ("preconnected-child-control",),
}
COMMON_SOURCES = (
    "docs/experiments/0001e-decision-matrix-execution.md",
    "docs/experiments/0001i-network-measurement-slice.md",
    "experiments/network_authority/decision-matrix.toml",
    "experiments/network_authority/decision_http_fixture.py",
    "experiments/network_authority/explicit_broker.py",
    "experiments/network_authority/measurement-domain.toml",
    "experiments/network_authority/measurement_domain.py",
    "experiments/network_authority/measurement_observation.py",
    "experiments/network_authority/record_common.py",
    "experiments/network_authority/record_network_measurement.py",
    "experiments/network_authority/record_network_measurement_failure.py",
    "experiments/network_authority/routing_cell.py",
    "experiments/network_authority/routing_mediated_client.py",
    "experiments/network_authority/routing_mediator.py",
    "experiments/network_authority/routing_transport_case.py",
    "experiments/network_authority/routing_transport_client.py",
    "experiments/network_authority/run_network_measurement.py",
    "experiments/network_authority/run_network_measurement.sh",
    "experiments/network_authority/run_routing_broker_case.py",
    "experiments/network_authority/run_routing_direct_case.py",
    "experiments/network_authority/run_routing_preconnected_case.py",
    "experiments/network_authority/verify_network_measurement.py",
)
CONTROL_SOURCES = {
    "landlock-port": (
        "experiments/network_authority/routing_child_control.c",
        "experiments/network_authority/routing_landlock_control.c",
    ),
    "cgroup-endpoint": (
        "experiments/network_authority/routing_child_control.c",
        "experiments/network_authority/routing_endpoint_control.c",
    ),
    "explicit-broker": (
        "experiments/network_authority/broker_child_control.c",
    ),
    "preconnected-channel": (
        "experiments/network_authority/preconnected_child_control.c",
    ),
}


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON names."""

    result = {}
    for key, value in pairs:
        if key in result:
            raise RecordError("measurement JSON contains duplicate names")
        result[key] = value
    return result


def document(path: Path) -> dict[str, object]:
    """Read one bounded JSON object."""

    try:
        value = json.loads(regular_bytes(path), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecordError("measurement JSON input is invalid") from error
    if not isinstance(value, dict):
        raise RecordError("measurement JSON input is not an object")
    return value


def file_inventory(root: Path) -> dict[str, tuple[bytes, int]]:
    """Read one closed, bounded, symlink-free evidence tree."""

    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise RecordError("measurement evidence root is invalid")
    result = {}
    total = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise RecordError("measurement evidence contains a symlink")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                data = regular_bytes(path)
                result[relative] = (data, metadata.st_mode)
                total += len(data)
            else:
                raise RecordError("measurement evidence contains a special file")
            if len(result) > MAX_EVIDENCE_FILES or total > MAX_EVIDENCE_BYTES:
                raise RecordError("measurement evidence exceeds its bound")
    return result


def validate_state(value: object, iteration: int, expected_exit: int) -> None:
    """Validate one raw cold-setup observation."""

    if not isinstance(value, dict) or set(value) != {
        "cleanup", "duration_ns", "exit", "iteration", "state"
    }:
        raise RecordError("setup observation is not closed")
    state = value["state"]
    if (
        value["cleanup"] is not True
        or type(value["duration_ns"]) is not int
        or value["duration_ns"] <= 0
        or value["exit"] != expected_exit
        or value["iteration"] != iteration
        or not isinstance(state, dict)
        or set(state) != {"file_count", "files", "sha256", "total_bytes"}
    ):
        raise RecordError("setup observation is invalid")
    files = state["files"]
    if not isinstance(files, list) or not files:
        raise RecordError("setup state file inventory is invalid")
    previous = None
    total = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {
            "name", "sha256", "size_bytes"
        }:
            raise RecordError("setup state file identity is not closed")
        name = item["name"]
        digest = item["sha256"]
        size = item["size_bytes"]
        if (
            not isinstance(name, str)
            or not name
            or Path(name).is_absolute()
            or ".." in Path(name).parts
            or previous is not None
            and name <= previous
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or type(size) is not int
            or size < 0
        ):
            raise RecordError("setup state file identity is invalid")
        previous = name
        total += size
    if (
        type(state["file_count"]) is not int
        or state["file_count"] != len(files)
        or type(state["total_bytes"]) is not int
        or state["total_bytes"] != total
        or not isinstance(state["sha256"], str)
        or state["sha256"] != sha256(canonical_json(files))
    ):
        raise RecordError("setup state summary is inconsistent")


def validate_lifecycle(value: object) -> None:
    """Validate the all-pass 1,000-iteration lifecycle bit set."""

    if not isinstance(value, dict) or set(value) != {
        "bit_order", "bits_hex", "first_failure", "iteration_count", "passed_count"
    }:
        raise RecordError("lifecycle observation is not closed")
    try:
        bits = bytes.fromhex(value["bits_hex"])
    except (TypeError, ValueError) as error:
        raise RecordError("lifecycle bits are invalid") from error
    if (
        value["bit_order"] != "least-significant-bit-first"
        or len(bits) != 125
        or bits != b"\xff" * 125
        or value["first_failure"] is not None
        or value["iteration_count"] != 1000
        or value["passed_count"] != 1000
    ):
        raise RecordError("lifecycle observation is incomplete")


def validate_requests(
    observation_root: Path,
    raw: dict[str, object],
    mechanism: str,
    exact_case: object,
) -> None:
    """Reclassify all retained exact-request raw cells."""

    values = raw["request_observations"]
    if not isinstance(values, list) or len(values) != 100:
        raise RecordError("request observation inventory is invalid")
    request_root = observation_root / "requests"
    if {path.name for path in request_root.iterdir()} != {
        f"{index:03d}" for index in range(100)
    }:
        raise RecordError("request evidence inventory is not exact")
    for index, value in enumerate(values):
        if not isinstance(value, dict) or set(value) != {
            "duration_ns", "iteration", "raw_cell_sha256"
        }:
            raise RecordError("request observation is not closed")
        case_root = request_root / f"{index:03d}"
        raw_path = case_root / "raw-cell.json"
        if (
            value["iteration"] != index
            or type(value["duration_ns"]) is not int
            or value["duration_ns"] <= 0
            or value["raw_cell_sha256"] != sha256(regular_bytes(raw_path))
        ):
            raise RecordError("request observation identity is invalid")
        cell = document(raw_path)
        observed = classify(cell, exact_case, mechanism)  # type: ignore[arg-type]
        if observed.outcome != "allowed" or observed.stage != "application-protocol":
            raise RecordError("request cell did not produce the exact workload")
        fixture = document(case_root / "fixture-observation.json")
        if fixture != {
            "event": "exact-response",
            "peer_ip": "127.0.0.1",
            "request_sha256": HTTP_REQUEST_SHA256,
            "response_sha256": HTTP_RESPONSE_SHA256,
            "schema": "proofbound-runtime-decision-http-observation/1",
            "sni": "allowed.test",
            "tls_version": "TLSv1.3",
        }:
            raise RecordError("request fixture observation is invalid")


def validate_raw(
    raw: dict[str, object],
    observation_root: Path,
    mechanism: str,
    source_commit: str,
    domain: object,
    matrix: object,
) -> None:
    """Validate one complete raw measurement before publication."""

    profile = domain.profile(mechanism)  # type: ignore[attr-defined]
    exact = [
        case for case in matrix.cases  # type: ignore[attr-defined]
        if case.identifier == "exact-service-ipv4"
    ]
    if (
        set(raw) != RAW_FIELDS
        or raw["schema"] != "proofbound-runtime-network-raw-measurement/1"
        or raw["mechanism"] != mechanism
        or raw["source_commit"] != source_commit
        or raw["measurement_domain_sha256"] != domain.source_sha256  # type: ignore[attr-defined]
        or raw["decision_matrix_sha256"] != matrix.source_sha256  # type: ignore[attr-defined]
        or len(exact) != 1
        or raw["residual_authority"] != list(profile.expected_residual_authority)
    ):
        raise RecordError("raw measurement identity is invalid")
    setup = raw["setup_observations"]
    if not isinstance(setup, list) or len(setup) != 100:
        raise RecordError("setup observation inventory is invalid")
    setup_exit = 4 if mechanism == "explicit-broker" else 0
    for index, value in enumerate(setup):
        validate_state(value, index, setup_exit)
    if raw["setup_summary"] != summarize_samples(
        (item["duration_ns"] for item in setup), 100
    ):
        raise RecordError("setup sample summary changed")
    validate_requests(observation_root, raw, mechanism, exact[0])
    request_values = raw["request_observations"]
    if raw["request_summary"] != summarize_samples(
        (item["duration_ns"] for item in request_values), 100
    ):
        raise RecordError("request sample summary changed")
    validate_lifecycle(raw["lifecycle"])
    resources = raw["mediator_resources"]
    if not isinstance(resources, dict) or set(resources) != {
        "maximum_process_count", "maximum_resident_set_bytes"
    }:
        raise RecordError("mediator resource observation is not closed")
    if profile.mediator_metrics:
        if (
            resources["maximum_process_count"] != 1
            or type(resources["maximum_resident_set_bytes"]) is not int
            or resources["maximum_resident_set_bytes"] <= 0
        ):
            raise RecordError("mediator resource observation is invalid")
    elif resources != {
        "maximum_process_count": None,
        "maximum_resident_set_bytes": None,
    }:
        raise RecordError("direct mechanism contains mediator metrics")
    platform_value = raw["platform"]
    platform_fields = {
        "architecture", "bpf_features", "cgroup_v2_controllers",
        "effective_capabilities", "kernel_release", "landlock_abi",
        "monotonic_clock", "namespace_operations", "python", "schema",
        "tls_implementation",
    }
    if not isinstance(platform_value, dict) or set(platform_value) != platform_fields:
        raise RecordError("measurement platform observation is not closed")
    controllers = platform_value["cgroup_v2_controllers"]
    for field in ("kernel_release", "python", "tls_implementation"):
        if not isinstance(platform_value[field], str):
            raise RecordError("measurement platform text is invalid")
        bounded_text(platform_value[field], field)
    if (
        platform_value["schema"]
        != "proofbound-runtime-network-measurement-platform/1"
        or platform_value["architecture"] not in ARCHITECTURES
        or platform_value["monotonic_clock"]
        not in {"CLOCK_MONOTONIC_RAW", "CLOCK_MONOTONIC"}
        or platform_value["namespace_operations"] != ["mount", "network"]
        or not isinstance(platform_value["effective_capabilities"], str)
        or not re.fullmatch(
            r"[0-9a-f]{16}", platform_value["effective_capabilities"]
        )
        or not isinstance(controllers, list)
        or not controllers
        or any(not isinstance(item, str) or not item for item in controllers)
        or controllers != sorted(set(controllers))
        or platform_value["bpf_features"]
        != (
            list(profile.required_mechanism_features)
            if mechanism == "cgroup-endpoint"
            else []
        )
    ):
        raise RecordError("measurement platform observation is invalid")
    if mechanism == "landlock-port":
        if (
            type(platform_value["landlock_abi"]) is not int
            or platform_value["landlock_abi"] < 4
        ):
            raise RecordError("Landlock ABI observation is invalid")
    elif platform_value["landlock_abi"] is not None:
        raise RecordError("unselected Landlock ABI observation is present")
    reference = tree_summary(observation_root / "reference-setup-state")
    if reference != setup[0]["state"]:
        raise RecordError("reference setup state identity changed")
    namespace = document(observation_root / "namespace-cleanup.json")
    if (
        set(namespace)
        != {
            "mount_namespace_handle_absent",
            "namespace_process_pid",
            "namespace_process_reaped",
            "network_namespace_handle_absent",
            "schema",
        }
        or namespace["schema"]
        != "proofbound-runtime-network-measurement-namespace-cleanup/1"
        or namespace["mount_namespace_handle_absent"] is not True
        or namespace["network_namespace_handle_absent"] is not True
        or namespace["namespace_process_reaped"] is not True
        or type(namespace["namespace_process_pid"]) is not int
        or namespace["namespace_process_pid"] <= 0
    ):
        raise RecordError("measurement namespace cleanup is incomplete")


def inventory_members(
    mechanism: str,
    artifacts: Path,
    observation_root: Path,
    sources: dict[str, tuple[bytes, int]],
    nonzero_categories: tuple[str, ...],
) -> tuple[dict[str, object], dict[str, bytes]]:
    """Derive every trusted-object category and generated canonical object."""

    generated = {}

    def member(role: str, data: bytes) -> dict[str, object]:
        return {"role": role, "sha256": sha256(data), "size_bytes": len(data)}

    values: dict[str, list[dict[str, object]]] = {
        category: [] for category in INVENTORY_CATEGORIES
    }
    for name in BINARIES[mechanism]:
        values["trusted-binaries"].append(
            member(name, regular_bytes(artifacts / name))
        )
    for path, (data, _mode) in sorted(sources.items()):
        values["source-configuration"].append(member(path, data))
    for role in ("certificate", "trust-root"):
        values["certificates"].append(member(role, regular_bytes(artifacts / role)))
    reference = observation_root / "reference-setup-state"
    if mechanism == "landlock-port":
        data = regular_bytes(reference / "ruleset-configuration.txt")
        values["landlock-rules"].append(member("connect-tcp-port-443", data))
    if mechanism == "cgroup-endpoint":
        for family in ("connect4", "connect6"):
            program = regular_bytes(reference / f"{family}-program.bin")
            values["bpf-programs"].append(member(family, program))
            map_value = canonical_json(
                {
                    "key_sha256": sha256(
                        regular_bytes(reference / f"{family}-map-key.bin")
                    ),
                    "schema": "proofbound-runtime-network-bpf-map-configuration/1",
                    "value_sha256": sha256(regular_bytes(reference / "map-value.bin")),
                }
            )
            name = f"bpf-map-{family}.json"
            generated[name] = map_value
            values["bpf-maps"].append(member(f"{family}-endpoint-map", map_value))
    channels = {
        "explicit-broker": ("framed-operation-channel", "framed"),
        "preconnected-channel": ("transparent-session-channel", "transparent"),
    }
    if mechanism in channels:
        role, mode = channels[mechanism]
        channel = canonical_json(
            {
                "family": "AF_UNIX",
                "mode": mode,
                "schema": "proofbound-runtime-network-channel-configuration/1",
                "type": "SOCK_STREAM",
            }
        )
        generated["control-channel.json"] = channel
        values["control-channels"].append(member(role, channel))
    inventory = inventory_observation(values, nonzero_categories)
    return inventory, generated


def record(arguments: argparse.Namespace) -> Path:
    """Publish one immutable measurement result and all exact inputs."""

    output = Path(arguments.output)
    source_root = Path(arguments.source_root)
    evidence_root = Path(arguments.evidence_root)
    if (
        not all(path.is_absolute() for path in (output, source_root, evidence_root))
        or not source_root.is_dir()
        or source_root.is_symlink()
        or arguments.mechanism not in MECHANISMS
        or arguments.architecture not in ARCHITECTURES
        or not SOURCE_COMMIT.fullmatch(arguments.source_commit)
    ):
        raise RecordError("measurement result identity is invalid")
    if (
        not evidence_root.is_dir()
        or evidence_root.is_symlink()
        or {path.name for path in evidence_root.iterdir()} != {"artifacts", "observation"}
    ):
        raise RecordError("measurement evidence layout is invalid")
    artifacts = evidence_root / "artifacts"
    observation_root = evidence_root / "observation"
    if {path.name for path in artifacts.iterdir()} != ARTIFACTS[arguments.mechanism]:
        raise RecordError("measurement artifact inventory is not exact")
    for name in BINARIES[arguments.mechanism]:
        if artifacts.joinpath(name).lstat().st_mode & 0o111 == 0:
            raise RecordError("measurement control is not executable")
    domain = load_measurement_domain(source_root / "experiments/network_authority/measurement-domain.toml")
    matrix = load_routing_matrix(source_root / "experiments/network_authority/decision-matrix.toml")
    raw = document(observation_root / "RAW.json")
    validate_raw(raw, observation_root, arguments.mechanism, arguments.source_commit, domain, matrix)
    platform_value = raw["platform"]
    if (
        platform_value["architecture"] != arguments.architecture
        or platform_value["kernel_release"] != arguments.kernel_release
        or not arguments.python.endswith(str(platform_value["python"]))
    ):
        raise RecordError("measurement tool and platform identities disagree")
    evidence = file_inventory(evidence_root)
    source_paths = (*COMMON_SOURCES, *CONTROL_SOURCES[arguments.mechanism])
    sources = {}
    for relative in source_paths:
        path = confined_file(source_root, relative)
        sources[relative] = (regular_bytes(path), path.lstat().st_mode)
    inventory, generated = inventory_members(
        arguments.mechanism,
        artifacts,
        observation_root,
        sources,
        domain.profile(arguments.mechanism).nonzero_inventory_categories,
    )
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise RecordError("measurement output must be absent")
    for directory in (output, output / "evidence", output / "source", output / "inventory"):
        os.mkdir(directory, 0o755)
    published = {}
    for relative, (data, mode) in sorted(evidence.items()):
        target = output / "evidence" / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        write_new(target, data, stat.S_IMODE(mode))
        published[f"evidence/{relative}"] = data
    source_entries = []
    for index, (relative, (data, mode)) in enumerate(sorted(sources.items())):
        name = f"{index:02d}-{Path(relative).name}"
        write_new(output / "source" / name, data, stat.S_IMODE(mode))
        published[f"source/{name}"] = data
        source_entries.append({"path": relative, **identity(name, data, mode)})
    for name, data in sorted(generated.items()):
        write_new(output / "inventory" / name, data)
        published[f"inventory/{name}"] = data
    manifests = {
        "evidence-manifest.json": {
            "files": [
                {
                    "mode": format(stat.S_IMODE(mode), "04o"),
                    "name": name,
                    "sha256": sha256(data),
                    "size": len(data),
                }
                for name, (data, mode) in sorted(evidence.items())
            ],
            "schema": "proofbound-runtime-network-measurement-evidence-manifest/1",
        },
        "inventory.json": {
            "categories": inventory,
            "schema": "proofbound-runtime-network-measurement-inventory/1",
        },
        "source-manifest.json": {
            "decision_matrix_sha256": matrix.source_sha256,
            "files": source_entries,
            "measurement_domain_sha256": domain.source_sha256,
            "schema": "proofbound-runtime-network-measurement-source-manifest/1",
            "source_commit": arguments.source_commit,
        },
        "tool-manifest.json": {
            "architecture": arguments.architecture,
            "compiler": bounded_text(arguments.compiler, "compiler"),
            "kernel_release": bounded_text(arguments.kernel_release, "kernel release"),
            "python": bounded_text(arguments.python, "python"),
            "schema": "proofbound-runtime-network-measurement-tool-manifest/1",
        },
    }
    for name, value in manifests.items():
        data = canonical_json(value)
        write_new(output / name, data)
        published[name] = data
    result = {
        "architecture": arguments.architecture,
        "complete": True,
        "conclusion": "network-measurement-complete",
        "decision_matrix_sha256": matrix.source_sha256,
        "inputs": [
            {"name": name, "sha256": sha256(data), "size": len(data)}
            for name, data in sorted(published.items())
        ],
        "measurement_domain_sha256": domain.source_sha256,
        "mechanism": arguments.mechanism,
        "raw_measurement_sha256": sha256(regular_bytes(observation_root / "RAW.json")),
        "request_summary": raw["request_summary"],
        "residual_authority": raw["residual_authority"],
        "schema": "proofbound-runtime-network-measurement-result/1",
        "setup_summary": raw["setup_summary"],
        "source_commit": arguments.source_commit,
    }
    write_new(output / "RESULT.json", canonical_json(result))
    return output


def parser() -> argparse.ArgumentParser:
    """Build the closed measurement recorder interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    for name in (
        "output", "source-root", "evidence-root", "source-commit", "mechanism",
        "architecture", "kernel-release", "compiler", "python",
    ):
        result.add_argument(f"--{name}", required=True)
    return result


def main() -> int:
    """Record one result or report a bounded publication error."""

    try:
        record(parser().parse_args())
        return 0
    except (
        MeasurementDomainError,
        MeasurementObservationError,
        RecordError,
        RoutingCellError,
        OSError,
        ValueError,
    ) as error:
        print(f"network measurement record failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
