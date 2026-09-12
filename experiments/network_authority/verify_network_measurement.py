#!/usr/bin/env python3
"""Independent verifier for experiment 0001I measurement results."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

try:
    import tomllib as toml
except ModuleNotFoundError:
    import tomli as toml  # type: ignore[no-redef]


MAX_FILES = 10000
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
COMMIT = re.compile(r"[0-9a-f]{40}")
ARCHITECTURES = ("x86_64", "aarch64")
MECHANISMS = (
    "landlock-port", "cgroup-endpoint", "explicit-broker",
    "preconnected-channel",
)
CATEGORIES = (
    "trusted-binaries", "source-configuration", "certificates",
    "bpf-programs", "bpf-maps", "landlock-rules", "control-channels",
)
SYSTEM_OBSERVATIONS = (
    "effective-capabilities", "namespace-operations", "cgroup-v2-controllers",
    "landlock-abi", "bpf-features", "tls-implementation", "monotonic-clock",
)
RESIDUAL_AUTHORITIES = (
    "direct-tcp-to-any-address-on-allowed-port",
    "direct-tcp-to-selected-endpoint", "child-controlled-resolution",
    "child-controlled-tls", "arbitrary-application-bytes",
    "registered-operation-via-mediator",
    "arbitrary-application-bytes-on-authenticated-session",
)
LIFECYCLE_FAILURE_CODES = (
    "create-failed", "failure-injection-failed", "request-released",
    "cleanup-failed", "resource-survived", "observation-invalid",
)
DOMAIN_FIELDS = {
    "schema", "architectures", "mechanisms", "duration_unit", "sample_order",
    "setup_sample_count", "request_sample_count", "median_algorithm",
    "p95_algorithm", "lifecycle_iteration_count", "lifecycle_bit_order",
    "maximum_seconds", "inventory_categories", "system_observations",
    "residual_authorities", "lifecycle_failure_codes", "request", "profiles",
}
PROFILE_FIELDS = {
    "id", "setup_subject", "request_subject", "mediator_metrics",
    "nonzero_inventory_categories", "required_harness_features",
    "required_mechanism_features", "expected_residual_authority",
}
NONZERO = {
    "landlock-port": (
        "trusted-binaries", "source-configuration", "certificates",
        "landlock-rules",
    ),
    "cgroup-endpoint": (
        "trusted-binaries", "source-configuration", "certificates",
        "bpf-programs", "bpf-maps",
    ),
    "explicit-broker": (
        "trusted-binaries", "source-configuration", "certificates",
        "control-channels",
    ),
    "preconnected-channel": (
        "trusted-binaries", "source-configuration", "certificates",
        "control-channels",
    ),
}
RESIDUAL = {
    "landlock-port": [
        "direct-tcp-to-any-address-on-allowed-port",
        "child-controlled-resolution", "child-controlled-tls",
        "arbitrary-application-bytes",
    ],
    "cgroup-endpoint": [
        "direct-tcp-to-selected-endpoint", "child-controlled-tls",
        "arbitrary-application-bytes",
    ],
    "explicit-broker": ["registered-operation-via-mediator"],
    "preconnected-channel": [
        "arbitrary-application-bytes-on-authenticated-session"
    ],
}
PROFILE_RULES = {
    "landlock-port": {
        "mediator_metrics": False,
        "nonzero_inventory_categories": list(NONZERO["landlock-port"]),
        "required_harness_features": [
            "root", "network-namespace", "mount-namespace",
        ],
        "required_mechanism_features": [
            "landlock-abi-4", "landlock-access-net-connect-tcp",
        ],
        "expected_residual_authority": RESIDUAL["landlock-port"],
    },
    "cgroup-endpoint": {
        "mediator_metrics": False,
        "nonzero_inventory_categories": list(NONZERO["cgroup-endpoint"]),
        "required_harness_features": [
            "root", "network-namespace", "mount-namespace", "cgroup-v2",
        ],
        "required_mechanism_features": [
            "bpf-cgroup-inet4-connect", "bpf-cgroup-inet6-connect",
        ],
        "expected_residual_authority": RESIDUAL["cgroup-endpoint"],
    },
    "explicit-broker": {
        "mediator_metrics": True,
        "nonzero_inventory_categories": list(NONZERO["explicit-broker"]),
        "required_harness_features": [
            "root", "network-namespace", "mount-namespace",
        ],
        "required_mechanism_features": [
            "seccomp-deny-child-network", "broker-owned-python-tls",
        ],
        "expected_residual_authority": RESIDUAL["explicit-broker"],
    },
    "preconnected-channel": {
        "mediator_metrics": True,
        "nonzero_inventory_categories": list(NONZERO["preconnected-channel"]),
        "required_harness_features": [
            "root", "network-namespace", "mount-namespace",
        ],
        "required_mechanism_features": [
            "seccomp-deny-child-network", "connector-owned-python-tls",
        ],
        "expected_residual_authority": RESIDUAL["preconnected-channel"],
    },
}
BINARIES = {
    "landlock-port": ("routing-child-control", "routing-landlock-control"),
    "cgroup-endpoint": ("routing-child-control", "routing-endpoint-control"),
    "explicit-broker": ("broker-child-control",),
    "preconnected-channel": ("preconnected-child-control",),
}
ARTIFACTS = {
    mechanism: {"certificate", "trust-root", *binaries}
    for mechanism, binaries in BINARIES.items()
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
HTTP_REQUEST_SHA256 = "74d2d0d91b73d482d44bc44c9efce9fb374bd424634b224f8f5ad7955307c804"
HTTP_RESPONSE_SHA256 = "171b2e654c262c92a4325908047e52e6dc22b739fb8339a0f8c0f5321d1140ee"
BROKER_RESPONSE_SHA256 = "2f2fa0a0407cb1936a31718aa5805bf358151ac3a097d1219383ef33977b5585"
RAW_FIELDS = {
    "decision_matrix_sha256", "lifecycle", "measurement_domain_sha256",
    "mechanism", "mediator_resources", "platform", "request_observations",
    "request_summary", "residual_authority", "schema", "setup_observations",
    "setup_summary", "source_commit",
}


class VerificationError(Exception):
    """A measurement result is incomplete, inconsistent, or replaceable."""


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("JSON contains a duplicate name")
        result[key] = value
    return result


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def bounded_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value.encode()) <= 1024
        and "\n" not in value
        and "\r" not in value
    )


def regular_bytes(path: Path) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_BYTES:
        raise VerificationError("result input is not bounded and regular")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev, metadata.st_ino, metadata.st_size,
        ):
            raise VerificationError("result input identity changed")
        data = bytearray()
        while len(data) <= MAX_FILE_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_FILE_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != metadata.st_size or len(data) > MAX_FILE_BYTES:
            raise VerificationError("result input size changed")
        closed = os.fstat(descriptor)
        if (closed.st_dev, closed.st_ino, closed.st_size) != (
            metadata.st_dev, metadata.st_ino, metadata.st_size,
        ):
            raise VerificationError("result input identity changed")
        return bytes(data)
    finally:
        os.close(descriptor)


def document_bytes(data: bytes) -> dict[str, object]:
    try:
        value = json.loads(data, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("JSON input is invalid") from error
    if not isinstance(value, dict) or canonical_json(value) != data:
        raise VerificationError("JSON input is not one canonical object")
    return value


def document(files: dict[str, bytes], name: str) -> dict[str, object]:
    if name not in files:
        raise VerificationError(f"result input is absent: {name}")
    return document_bytes(files[name])


def result_files(root: Path) -> dict[str, bytes]:
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise VerificationError("result root is invalid")
    result = {}
    total = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise VerificationError("result contains a symlink")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                result[relative] = regular_bytes(path)
                total += len(result[relative])
            else:
                raise VerificationError("result contains a special file")
            if len(result) > MAX_FILES or total > MAX_TOTAL_BYTES:
                raise VerificationError("result file inventory exceeds its bound")
    return result


def manifest_entries(value: object, fields: set[str]) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise VerificationError("manifest inventory is invalid")
    result = []
    for item in value:
        if not isinstance(item, dict) or set(item) != fields:
            raise VerificationError("manifest entry is not closed")
        result.append(item)
    return result


def parse_domain(data: bytes, mechanism: str) -> dict[str, object]:
    try:
        value = toml.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, toml.TOMLDecodeError) as error:
        raise VerificationError("measurement domain is invalid") from error
    if (
        not isinstance(value, dict)
        or set(value) != DOMAIN_FIELDS
        or value.get("schema")
        != "proofbound-runtime-network-measurement-domain/1"
    ):
        raise VerificationError("measurement domain schema is invalid")
    exact = {
        "architectures": list(ARCHITECTURES),
        "mechanisms": list(MECHANISMS),
        "duration_unit": "nanoseconds",
        "sample_order": "ascending",
        "setup_sample_count": 100,
        "request_sample_count": 100,
        "median_algorithm": "midpoint-floor",
        "p95_algorithm": "nearest-rank",
        "lifecycle_iteration_count": 1000,
        "lifecycle_bit_order": "least-significant-bit-first",
        "maximum_seconds": 600,
        "inventory_categories": list(CATEGORIES),
        "system_observations": list(SYSTEM_OBSERVATIONS),
        "residual_authorities": list(RESIDUAL_AUTHORITIES),
        "lifecycle_failure_codes": list(LIFECYCLE_FAILURE_CODES),
    }
    if any(
        type(value.get(field)) is not type(expected)
        or value.get(field) != expected
        for field, expected in exact.items()
    ):
        raise VerificationError("measurement domain constants changed")
    request = value.get("request")
    if not isinstance(request, dict) or type(request.get("port")) is not int or request != {
        "service_name": "allowed.test", "address": "127.0.0.1", "port": 443,
        "transport": "tcp", "application_protocol": "https", "method": "GET",
        "path": "/v1/echo", "response_body": "0123456789abcdef0123456789abcdef",
    }:
        raise VerificationError("measurement workload changed")
    profiles = value.get("profiles")
    if not isinstance(profiles, list) or len(profiles) != len(MECHANISMS):
        raise VerificationError("measurement profile inventory changed")
    for index, profile in enumerate(profiles):
        identifier = MECHANISMS[index]
        if (
            not isinstance(profile, dict)
            or set(profile) != PROFILE_FIELDS
            or profile["id"] != identifier
            or not all(
                isinstance(profile[field], str) and profile[field]
                for field in ("setup_subject", "request_subject")
            )
            or any(
                profile[field] != expected
                for field, expected in PROFILE_RULES[identifier].items()
            )
        ):
            raise VerificationError("measurement mechanism profile changed")
    return value


def parse_exact_case(data: bytes, mechanism: str, matrix_sha256: str) -> None:
    if sha256(data) != matrix_sha256:
        raise VerificationError("decision matrix identity changed")
    try:
        value = toml.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, toml.TOMLDecodeError) as error:
        raise VerificationError("decision matrix is invalid") from error
    cases = value.get("cases") if isinstance(value, dict) else None
    matches = [
        item for item in cases or []
        if isinstance(item, dict) and item.get("id") == "exact-service-ipv4"
    ]
    expected = f"{mechanism}=allowed@application-protocol"
    expectations = matches[0].get("expectations") if len(matches) == 1 else None
    if (
        len(matches) != 1
        or not isinstance(expectations, list)
        or expected not in expectations
    ):
        raise VerificationError("exact request expectation changed")


def summarize(values: list[int]) -> dict[str, object]:
    if len(values) != 100 or any(type(value) is not int or value <= 0 for value in values):
        raise VerificationError("measurement sample inventory is invalid")
    ordered = sorted(values)
    return {
        "count": 100,
        "median_ns": (ordered[49] + ordered[50]) // 2,
        "p95_ns": ordered[94],
        "samples_ns": ordered,
    }


def state_summary(files: dict[str, bytes], prefix: str) -> dict[str, object]:
    selected = []
    for name, data in sorted(files.items()):
        if name.startswith(prefix):
            relative = name[len(prefix):]
            if not relative:
                continue
            selected.append({"name": relative, "sha256": sha256(data), "size_bytes": len(data)})
    if not selected:
        raise VerificationError("reference setup state is empty")
    return {
        "file_count": len(selected),
        "files": selected,
        "sha256": sha256(canonical_json(selected)),
        "total_bytes": sum(item["size_bytes"] for item in selected),
    }


def validate_state(value: object) -> None:
    """Validate one self-consistent, ordered setup-state summary."""

    if not isinstance(value, dict) or set(value) != {
        "file_count", "files", "sha256", "total_bytes"
    }:
        raise VerificationError("setup state is not closed")
    entries = value["files"]
    if not isinstance(entries, list) or not entries:
        raise VerificationError("setup state inventory is invalid")
    previous = None
    total = 0
    for item in entries:
        if not isinstance(item, dict) or set(item) != {
            "name", "sha256", "size_bytes"
        }:
            raise VerificationError("setup state file identity is not closed")
        name = item["name"]
        item_digest = item["sha256"]
        size = item["size_bytes"]
        if (
            not isinstance(name, str)
            or not name
            or Path(name).is_absolute()
            or ".." in Path(name).parts
            or previous is not None
            and name <= previous
            or not digest(item_digest)
            or type(size) is not int
            or size < 0
        ):
            raise VerificationError("setup state file identity is invalid")
        previous = name
        total += size
    if value != {
        "file_count": len(entries),
        "files": entries,
        "sha256": sha256(canonical_json(entries)),
        "total_bytes": total,
    }:
        raise VerificationError("setup state summary is inconsistent")


def validate_fixture(value: dict[str, object]) -> None:
    if value != {
        "event": "exact-response",
        "peer_ip": "127.0.0.1",
        "request_sha256": HTTP_REQUEST_SHA256,
        "response_sha256": HTTP_RESPONSE_SHA256,
        "schema": "proofbound-runtime-decision-http-observation/1",
        "sni": "allowed.test",
        "tls_version": "TLSv1.3",
    }:
        raise VerificationError("exact fixture observation changed")


def validate_raw_cell(value: dict[str, object], mechanism: str) -> None:
    fields = {
        "case", "cleanup", "client", "client_exit", "client_started",
        "fixture_complete", "fixture_contact", "mechanism", "mediator",
        "plan_rejection", "schema",
    }
    if (
        set(value) != fields
        or value["schema"] != "proofbound-runtime-routing-raw-cell/1"
        or value["case"] != "exact-service-ipv4"
        or value["mechanism"] != mechanism
        or value["cleanup"] is not True
        or value["client_started"] is not True
        or value["client_exit"] != 0
        or value["fixture_complete"] is not True
        or value["fixture_contact"] is not True
        or value["plan_rejection"] is not None
    ):
        raise VerificationError("exact request raw cell is invalid")
    client = value["client"]
    if not isinstance(client, dict):
        raise VerificationError("exact request client observation is absent")
    common = {
        "action": "tls-request-ipv4", "case": "exact-service-ipv4",
        "errno": None, "phase": "application-protocol",
        "schema": "proofbound-runtime-routing-client-observation/1",
    }
    if mechanism in {"landlock-port", "cgroup-endpoint"}:
        expected_client = {
            **common, "event": "exact-response",
            "response_sha256": HTTP_RESPONSE_SHA256, "tls_version": "TLSv1.3",
        }
        if value["mediator"] is not None:
            raise VerificationError("direct result contains a mediator")
    else:
        expected_client = {
            **common, "event": "mediated-response",
            "response_sha256": BROKER_RESPONSE_SHA256
            if mechanism == "explicit-broker" else HTTP_RESPONSE_SHA256,
        }
        if value["mediator"] != {
            "detail": "authenticated-exact-response", "event": "exact-response",
            "schema": "proofbound-runtime-routing-mediator-observation/1",
            "stage": "application-protocol",
        }:
            raise VerificationError("mediator observation changed")
    if client != expected_client:
        raise VerificationError("exact request client observation changed")


def validate_raw_measurement(
    files: dict[str, bytes], raw: dict[str, object], mechanism: str,
    source_commit: str, domain_sha256: str, matrix_sha256: str,
) -> None:
    if (
        set(raw) != RAW_FIELDS
        or raw["schema"] != "proofbound-runtime-network-raw-measurement/1"
        or raw["mechanism"] != mechanism
        or raw["source_commit"] != source_commit
        or raw["measurement_domain_sha256"] != domain_sha256
        or raw["decision_matrix_sha256"] != matrix_sha256
        or raw["residual_authority"] != RESIDUAL[mechanism]
    ):
        raise VerificationError("raw measurement identity changed")
    setup = raw["setup_observations"]
    if not isinstance(setup, list) or len(setup) != 100:
        raise VerificationError("setup observation inventory changed")
    setup_exit = 4 if mechanism == "explicit-broker" else 0
    durations = []
    for index, item in enumerate(setup):
        if (
            not isinstance(item, dict)
            or set(item) != {"cleanup", "duration_ns", "exit", "iteration", "state"}
            or item["cleanup"] is not True
            or item["exit"] != setup_exit
            or item["iteration"] != index
            or type(item["duration_ns"]) is not int
            or item["duration_ns"] <= 0
        ):
            raise VerificationError("setup observation changed")
        validate_state(item["state"])
        durations.append(item["duration_ns"])
    if raw["setup_summary"] != summarize(durations):
        raise VerificationError("setup aggregate changed")
    reference = state_summary(files, "evidence/observation/reference-setup-state/")
    if setup[0]["state"] != reference:
        raise VerificationError("reference setup state changed")
    namespace = document(files, "evidence/observation/namespace-cleanup.json")
    if (
        set(namespace)
        != {
            "mount_namespace_handle_absent", "namespace_process_pid",
            "namespace_process_reaped", "network_namespace_handle_absent",
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
        raise VerificationError("namespace cleanup observation is incomplete")
    requests = raw["request_observations"]
    if not isinstance(requests, list) or len(requests) != 100:
        raise VerificationError("request observation inventory changed")
    request_durations = []
    for index, item in enumerate(requests):
        if not isinstance(item, dict) or set(item) != {
            "duration_ns", "iteration", "raw_cell_sha256"
        }:
            raise VerificationError("request observation is not closed")
        prefix = f"evidence/observation/requests/{index:03d}/"
        raw_name = prefix + "raw-cell.json"
        if (
            item["iteration"] != index
            or type(item["duration_ns"]) is not int
            or item["duration_ns"] <= 0
            or item["raw_cell_sha256"] != sha256(files.get(raw_name, b""))
        ):
            raise VerificationError("request observation identity changed")
        validate_raw_cell(document(files, raw_name), mechanism)
        validate_fixture(document(files, prefix + "fixture-observation.json"))
        request_durations.append(item["duration_ns"])
    if raw["request_summary"] != summarize(request_durations):
        raise VerificationError("request aggregate changed")
    lifecycle = raw["lifecycle"]
    if lifecycle != {
        "bit_order": "least-significant-bit-first", "bits_hex": "ff" * 125,
        "first_failure": None, "iteration_count": 1000, "passed_count": 1000,
    }:
        raise VerificationError("lifecycle observation is incomplete")
    resources = raw["mediator_resources"]
    if mechanism in {"explicit-broker", "preconnected-channel"}:
        if (
            not isinstance(resources, dict)
            or resources.get("maximum_process_count") != 1
            or type(resources.get("maximum_resident_set_bytes")) is not int
            or resources["maximum_resident_set_bytes"] <= 0
        ):
            raise VerificationError("mediator resource observation is invalid")
    elif resources != {
        "maximum_process_count": None, "maximum_resident_set_bytes": None,
    }:
        raise VerificationError("direct mechanism contains mediator resources")
    platform_value = raw["platform"]
    if not isinstance(platform_value, dict) or set(platform_value) != {
        "architecture", "bpf_features", "cgroup_v2_controllers",
        "effective_capabilities", "kernel_release", "landlock_abi",
        "monotonic_clock", "namespace_operations", "python", "schema",
        "tls_implementation",
    }:
        raise VerificationError("platform observation is not closed")
    if (
        platform_value["schema"]
        != "proofbound-runtime-network-measurement-platform/1"
        or platform_value["architecture"] not in ARCHITECTURES
        or platform_value["namespace_operations"] != ["mount", "network"]
        or platform_value["monotonic_clock"] not in {"CLOCK_MONOTONIC_RAW", "CLOCK_MONOTONIC"}
        or not isinstance(platform_value["effective_capabilities"], str)
        or not re.fullmatch(r"[0-9a-f]{16}", platform_value["effective_capabilities"])
        or not isinstance(platform_value["cgroup_v2_controllers"], list)
        or not platform_value["cgroup_v2_controllers"]
        or any(
            not isinstance(item, str) or not item
            for item in platform_value["cgroup_v2_controllers"]
        )
        or platform_value["cgroup_v2_controllers"] != sorted(set(platform_value["cgroup_v2_controllers"]))
        or not all(
            bounded_text(platform_value[field])
            for field in ("kernel_release", "python", "tls_implementation")
        )
    ):
        raise VerificationError("platform observation is invalid")
    if mechanism == "landlock-port":
        if type(platform_value["landlock_abi"]) is not int or platform_value["landlock_abi"] < 4:
            raise VerificationError("Landlock ABI observation is invalid")
    elif platform_value["landlock_abi"] is not None:
        raise VerificationError("unselected Landlock ABI is present")
    expected_bpf = ["bpf-cgroup-inet4-connect", "bpf-cgroup-inet6-connect"] if mechanism == "cgroup-endpoint" else []
    if platform_value["bpf_features"] != expected_bpf:
        raise VerificationError("BPF feature observation changed")


def source_inputs(files: dict[str, bytes], mechanism: str, source_commit: str) -> tuple[bytes, bytes, dict[str, bytes]]:
    manifest = document(files, "source-manifest.json")
    if set(manifest) != {
        "decision_matrix_sha256", "files", "measurement_domain_sha256",
        "schema", "source_commit",
    } or manifest["schema"] != "proofbound-runtime-network-measurement-source-manifest/1" or manifest["source_commit"] != source_commit:
        raise VerificationError("source manifest is invalid")
    expected_paths = tuple(sorted((*COMMON_SOURCES, *CONTROL_SOURCES[mechanism])))
    entries = manifest_entries(
        manifest["files"], {"mode", "name", "path", "sha256", "size"}
    )
    if tuple(item["path"] for item in entries) != expected_paths:
        raise VerificationError("source path inventory changed")
    expected_names = tuple(
        f"{index:02d}-{Path(path).name}"
        for index, path in enumerate(expected_paths)
    )
    if tuple(item["name"] for item in entries) != expected_names:
        raise VerificationError("source publication inventory changed")
    actual_names = tuple(sorted(
        name[len("source/"):] for name in files if name.startswith("source/")
    ))
    if actual_names != tuple(sorted(expected_names)):
        raise VerificationError("source result inventory changed")
    by_path = {}
    for item in entries:
        name = "source/" + str(item["name"])
        data = files.get(name)
        if (
            data is None or item["sha256"] != sha256(data)
            or item["size"] != len(data) or not digest(item["sha256"])
            or not re.fullmatch(r"[0-7]{4}", str(item["mode"]))
        ):
            raise VerificationError("source identity changed")
        by_path[str(item["path"])] = data
    domain = by_path["experiments/network_authority/measurement-domain.toml"]
    matrix = by_path["experiments/network_authority/decision-matrix.toml"]
    if manifest["measurement_domain_sha256"] != sha256(domain) or manifest["decision_matrix_sha256"] != sha256(matrix):
        raise VerificationError("source domain identity changed")
    return domain, matrix, by_path


def evidence_inputs(files: dict[str, bytes], mechanism: str) -> None:
    manifest = document(files, "evidence-manifest.json")
    if set(manifest) != {"files", "schema"} or manifest["schema"] != "proofbound-runtime-network-measurement-evidence-manifest/1":
        raise VerificationError("evidence manifest is invalid")
    entries = manifest_entries(manifest["files"], {"mode", "name", "sha256", "size"})
    actual = sorted(name[len("evidence/"):] for name in files if name.startswith("evidence/"))
    if [item["name"] for item in entries] != actual:
        raise VerificationError("evidence inventory changed")
    artifact_names = {
        name.removeprefix("artifacts/")
        for name in actual if name.startswith("artifacts/")
    }
    if artifact_names != ARTIFACTS[mechanism] or any(
        not name.startswith(("artifacts/", "observation/")) for name in actual
    ):
        raise VerificationError("evidence layout changed")
    for item in entries:
        data = files["evidence/" + str(item["name"])]
        if item["sha256"] != sha256(data) or item["size"] != len(data) or not re.fullmatch(r"[0-7]{4}", str(item["mode"])):
            raise VerificationError("evidence identity changed")


def validate_inventory(files: dict[str, bytes], mechanism: str, sources: dict[str, bytes]) -> None:
    value = document(files, "inventory.json")
    if set(value) != {"categories", "schema"} or value["schema"] != "proofbound-runtime-network-measurement-inventory/1":
        raise VerificationError("measurement inventory is invalid")
    categories = value["categories"]
    if not isinstance(categories, dict) or set(categories) != set(CATEGORIES):
        raise VerificationError("inventory categories changed")
    expected_roles = {
        "trusted-binaries": {
            name: files[f"evidence/artifacts/{name}"] for name in BINARIES[mechanism]
        },
        "source-configuration": sources,
        "certificates": {
            role: files[f"evidence/artifacts/{role}"] for role in ("certificate", "trust-root")
        },
        "bpf-programs": {}, "bpf-maps": {}, "landlock-rules": {},
        "control-channels": {},
    }
    reference = "evidence/observation/reference-setup-state/"
    if mechanism == "landlock-port":
        expected_roles["landlock-rules"] = {
            "connect-tcp-port-443": files[reference + "ruleset-configuration.txt"]
        }
    if mechanism == "cgroup-endpoint":
        expected_roles["bpf-programs"] = {
            family: files[reference + f"{family}-program.bin"]
            for family in ("connect4", "connect6")
        }
        expected_roles["bpf-maps"] = {
            f"{family}-endpoint-map": files[f"inventory/bpf-map-{family}.json"]
            for family in ("connect4", "connect6")
        }
        for family in ("connect4", "connect6"):
            expected = canonical_json({
                "key_sha256": sha256(files[reference + f"{family}-map-key.bin"]),
                "schema": "proofbound-runtime-network-bpf-map-configuration/1",
                "value_sha256": sha256(files[reference + "map-value.bin"]),
            })
            if files[f"inventory/bpf-map-{family}.json"] != expected:
                raise VerificationError("BPF map configuration changed")
    if mechanism in {"explicit-broker", "preconnected-channel"}:
        mode = "framed" if mechanism == "explicit-broker" else "transparent"
        role = "framed-operation-channel" if mechanism == "explicit-broker" else "transparent-session-channel"
        expected = canonical_json({
            "family": "AF_UNIX", "mode": mode,
            "schema": "proofbound-runtime-network-channel-configuration/1",
            "type": "SOCK_STREAM",
        })
        if files.get("inventory/control-channel.json") != expected:
            raise VerificationError("channel configuration changed")
        expected_roles["control-channels"] = {role: expected}
    for category in CATEGORIES:
        observed = categories[category]
        roles = expected_roles[category]
        if not isinstance(observed, dict) or set(observed) != {"count", "members", "total_bytes"}:
            raise VerificationError("inventory category is not closed")
        members = observed["members"]
        expected_members = [
            {"role": role, "sha256": sha256(data), "size_bytes": len(data)}
            for role, data in sorted(roles.items())
        ]
        if observed != {
            "count": len(expected_members), "members": expected_members,
            "total_bytes": sum(item["size_bytes"] for item in expected_members),
        } or bool(expected_members) != (category in NONZERO[mechanism]):
            raise VerificationError("inventory category identity changed")


def verify_incomplete(
    files: dict[str, bytes], result: dict[str, object]
) -> dict[str, object]:
    """Verify a retained native failure without treating it as a measurement."""

    fields = {
        "architecture", "complete", "conclusion", "decision_matrix_sha256",
        "exit_status", "inputs", "measurement_domain_sha256", "mechanism",
        "schema", "source_commit", "stage",
    }
    mechanism = result.get("mechanism")
    architecture = result.get("architecture")
    source_commit = result.get("source_commit")
    if (
        set(result) != fields
        or result["schema"] != "proofbound-runtime-network-measurement-result/1"
        or result["complete"] is not False
        or result["conclusion"] != "network-measurement-incomplete"
        or result["stage"] != "native-measurement"
        or mechanism not in MECHANISMS
        or architecture not in ARCHITECTURES
        or not isinstance(source_commit, str)
        or not COMMIT.fullmatch(source_commit)
        or type(result["exit_status"]) is not int
        or not 1 <= result["exit_status"] <= 255
    ):
        raise VerificationError("incomplete measurement identity is invalid")
    expected_names = [
        "diagnostic/stderr.txt", "diagnostic/stdout.txt",
        "source/decision-matrix.toml", "source/measurement-domain.toml",
        "tool-manifest.json",
    ]
    if sorted(name for name in files if name != "RESULT.json") != expected_names:
        raise VerificationError("incomplete measurement inventory changed")
    inputs = manifest_entries(result["inputs"], {"name", "sha256", "size"})
    if [item["name"] for item in inputs] != expected_names:
        raise VerificationError("incomplete result input inventory changed")
    for item in inputs:
        data = files[str(item["name"])]
        if (
            item["sha256"] != sha256(data)
            or item["size"] != len(data)
            or not digest(item["sha256"])
        ):
            raise VerificationError("incomplete result input identity changed")
    domain = files["source/measurement-domain.toml"]
    matrix = files["source/decision-matrix.toml"]
    if (
        result["measurement_domain_sha256"] != sha256(domain)
        or result["decision_matrix_sha256"] != sha256(matrix)
    ):
        raise VerificationError("incomplete result domain identity changed")
    parse_domain(domain, mechanism)
    parse_exact_case(matrix, mechanism, sha256(matrix))
    tool = document(files, "tool-manifest.json")
    if (
        set(tool) != {"architecture", "compiler", "kernel_release", "python", "schema"}
        or tool["schema"] != "proofbound-runtime-network-measurement-tool-manifest/1"
        or tool["architecture"] != architecture
        or not all(
            bounded_text(tool[field])
            for field in ("compiler", "kernel_release", "python")
        )
    ):
        raise VerificationError("incomplete measurement tool identity is invalid")
    return result


def verify(root: Path) -> dict[str, object]:
    files = result_files(root)
    result = document(files, "RESULT.json")
    if result.get("complete") is False:
        return verify_incomplete(files, result)
    fields = {
        "architecture", "complete", "conclusion", "decision_matrix_sha256",
        "inputs", "measurement_domain_sha256", "mechanism",
        "raw_measurement_sha256", "request_summary", "residual_authority",
        "schema", "setup_summary", "source_commit",
    }
    mechanism = result.get("mechanism")
    architecture = result.get("architecture")
    source_commit = result.get("source_commit")
    if (
        set(result) != fields
        or result["schema"] != "proofbound-runtime-network-measurement-result/1"
        or result["complete"] is not True
        or result["conclusion"] != "network-measurement-complete"
        or mechanism not in MECHANISMS
        or architecture not in ARCHITECTURES
        or not isinstance(source_commit, str)
        or not COMMIT.fullmatch(source_commit)
    ):
        raise VerificationError("measurement result identity is invalid")
    expected_names = sorted(name for name in files if name != "RESULT.json")
    inputs = manifest_entries(result["inputs"], {"name", "sha256", "size"})
    if [item["name"] for item in inputs] != expected_names:
        raise VerificationError("result input inventory changed")
    for item in inputs:
        data = files[str(item["name"])]
        if item["sha256"] != sha256(data) or item["size"] != len(data):
            raise VerificationError("result input identity changed")
    domain, matrix, sources = source_inputs(files, mechanism, source_commit)
    if result["measurement_domain_sha256"] != sha256(domain) or result["decision_matrix_sha256"] != sha256(matrix):
        raise VerificationError("result domain identity changed")
    parse_domain(domain, mechanism)
    parse_exact_case(matrix, mechanism, sha256(matrix))
    evidence_inputs(files, mechanism)
    raw_bytes = files.get("evidence/observation/RAW.json")
    if raw_bytes is None or result["raw_measurement_sha256"] != sha256(raw_bytes):
        raise VerificationError("raw measurement identity changed")
    raw = document_bytes(raw_bytes)
    validate_raw_measurement(
        files, raw, mechanism, source_commit, sha256(domain), sha256(matrix)
    )
    if result["setup_summary"] != raw["setup_summary"] or result["request_summary"] != raw["request_summary"] or result["residual_authority"] != raw["residual_authority"]:
        raise VerificationError("result summary changed")
    tool = document(files, "tool-manifest.json")
    platform_value = raw["platform"]
    if (
        set(tool) != {"architecture", "compiler", "kernel_release", "python", "schema"}
        or tool["schema"] != "proofbound-runtime-network-measurement-tool-manifest/1"
        or tool["architecture"] != architecture
        or platform_value["architecture"] != architecture
        or tool["kernel_release"] != platform_value["kernel_release"]
        or not all(
            bounded_text(tool[field])
            for field in ("compiler", "kernel_release", "python")
        )
        or not tool["python"].endswith(platform_value["python"])
    ):
        raise VerificationError("tool and platform observations disagree")
    try:
        validate_inventory(files, mechanism, sources)
    except KeyError as error:
        raise VerificationError("inventory input is absent") from error
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("result", type=Path)
    return result


def main() -> int:
    try:
        result = verify(parser().parse_args().result)
        print(canonical_json({
            "architecture": result["architecture"], "complete": result["complete"],
            "mechanism": result["mechanism"],
            "result_sha256": sha256(canonical_json(result)),
            "schema": "proofbound-runtime-network-measurement-verification/1",
            "verified": True,
        }).decode(), end="")
        return 0
    except (OSError, VerificationError, ValueError) as error:
        print(f"network measurement verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
