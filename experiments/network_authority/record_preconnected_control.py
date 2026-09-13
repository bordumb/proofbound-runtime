#!/usr/bin/env python3
"""Publish one closed result for the preconnected authenticated channel."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.preconnected_channel import MAX_DIRECTION_BYTES
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
    ("allowed-request", True, True, True),
    ("undeclared-path-exposure", True, True, True),
    ("connect-shape-exposure", True, True, True),
    ("direct-tcp-denied", False, True, False),
    ("direct-udp-denied", False, True, False),
    ("fork-direct-tcp-denied", False, True, False),
    ("alternate-endpoint-denied-certificate", False, False, False),
    ("alternate-endpoint-allowed-certificate", False, False, False),
    ("wrong-certificate-denied", False, False, False),
    ("plaintext-endpoint-denied", False, False, False),
    ("connector-crash-denied", False, True, False),
    ("wrong-cookie-denied", False, False, False),
    ("non-unix-descriptor-denied", False, False, False),
    ("foreign-descriptor-denied", False, True, False),
)
PRELAUNCH_CASES = {
    "alternate-endpoint-denied-certificate",
    "alternate-endpoint-allowed-certificate",
    "wrong-certificate-denied",
    "plaintext-endpoint-denied",
}
FIXTURE_OBSERVATIONS = {
    "allowed-request": b"allowed-request\n",
    "undeclared-path-exposure": b"undeclared-path-observed\n",
    "connect-shape-exposure": b"connect-shape-observed\n",
    "plaintext-endpoint-denied": b"plaintext-contact-observed\n",
}
SOURCE_FILES = (
    "__init__.py",
    "record_common.py",
    "preconnected_channel.py",
    "preconnected_case_client.py",
    "run_preconnected_case.py",
    "preconnected_child_control.c",
    "record_preconnected_control.py",
)


def exact_json(data: bytes, label: str) -> dict[str, object]:
    """Decode one canonical JSON object."""

    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecordError(f"{label} is not JSON") from error
    if not isinstance(value, dict) or canonical_json(value) != data:
        raise RecordError(f"{label} is not one canonical object")
    return value


def exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    """Reject an open or incomplete observation object."""

    if set(value) != expected:
        raise RecordError(f"{label} fields are not exact")


def positive_int(value: object, label: str) -> int:
    """Require one positive integer that is not a Boolean."""

    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RecordError(f"{label} is not a positive integer")
    return value


def parse_case_observation(
    data: bytes,
    case: str,
    expects_boundary: bool,
    expects_relay: bool,
    allowed_certificate_sha256: str,
) -> dict[str, object]:
    """Validate one closed orchestration observation."""

    value = exact_json(data, f"{case} observation")
    exact_keys(
        value,
        {
            "case",
            "child_started",
            "connector_authenticated",
            "connector_observation",
            "fixture_exit",
            "fixture_reaped",
            "local_channel",
            "orchestration_outcome",
            "relay_observation",
            "schema",
        },
        f"{case} observation",
    )
    expected_authenticated = case not in PRELAUNCH_CASES
    if (
        value["schema"]
        != "proofbound-runtime-network-experiment-preconnected-case/1"
        or value["case"] != case
        or value["child_started"] is not expects_boundary
        or value["connector_authenticated"] is not expected_authenticated
        or value["fixture_reaped"] is not True
        or value["orchestration_outcome"]
        != ("expected-prelaunch-failure" if case in PRELAUNCH_CASES else "child-complete")
    ):
        raise RecordError(f"{case} observation value is invalid")
    fixture_exit = value["fixture_exit"]
    if isinstance(fixture_exit, bool) or not isinstance(fixture_exit, int):
        raise RecordError(f"{case} fixture exit is invalid")

    local = value["local_channel"]
    if not isinstance(local, dict):
        raise RecordError(f"{case} local channel is absent")
    exact_keys(
        local,
        {"child_cookie", "child_peer", "parent_cookie", "parent_peer", "type"},
        f"{case} local channel",
    )
    child_cookie = positive_int(local["child_cookie"], f"{case} child cookie")
    parent_cookie = positive_int(local["parent_cookie"], f"{case} parent cookie")
    if child_cookie == parent_cookie or local["type"] != "unix-stream":
        raise RecordError(f"{case} local channel identity is invalid")
    for side in ("child_peer", "parent_peer"):
        peer = local[side]
        if not isinstance(peer, dict):
            raise RecordError(f"{case} peer credentials are absent")
        exact_keys(peer, {"gid", "pid", "uid"}, f"{case} {side}")
        positive_int(peer["pid"], f"{case} peer pid")
        for field in ("uid", "gid"):
            item = peer[field]
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                raise RecordError(f"{case} peer identity is invalid")
    if local["child_peer"] != local["parent_peer"]:
        raise RecordError(f"{case} socket pair peer credentials drifted")

    connector = value["connector_observation"]
    if expected_authenticated:
        if not isinstance(connector, dict):
            raise RecordError(f"{case} connector observation is absent")
        exact_keys(
            connector,
            {
                "cipher",
                "local_ip",
                "local_port",
                "peer_certificate_sha256",
                "peer_ip",
                "peer_port",
                "service_name",
                "tls_version",
            },
            f"{case} connector observation",
        )
        digest = connector["peer_certificate_sha256"]
        if (
            connector["peer_ip"] != "127.0.0.1"
            or connector["peer_port"] != 443
            or connector["service_name"] != "allowed.test"
            or connector["tls_version"] != "TLSv1.3"
            or digest != allowed_certificate_sha256
            or connector["local_ip"] != "127.0.0.1"
            or not isinstance(connector["cipher"], str)
        ):
            raise RecordError(f"{case} authenticated session is invalid")
        positive_int(connector["local_port"], f"{case} local port")
        bounded_text(connector["cipher"], f"{case} cipher")
    elif connector is not None:
        raise RecordError(f"{case} recorded an unexpected authenticated session")

    relay = value["relay_observation"]
    if expects_relay:
        if not isinstance(relay, dict):
            raise RecordError(f"{case} relay observation is absent")
        exact_keys(
            relay,
            {
                "child_to_service_bytes",
                "service_to_child_bytes",
                "tls_shutdown_observed",
            },
            f"{case} relay observation",
        )
        for field in ("child_to_service_bytes", "service_to_child_bytes"):
            size = positive_int(relay[field], f"{case} {field}")
            if size > MAX_DIRECTION_BYTES:
                raise RecordError(f"{case} relay exceeded its byte bound")
        if relay["tls_shutdown_observed"] is not True:
            raise RecordError(f"{case} TLS shutdown was not observed")
    elif relay is not None:
        raise RecordError(f"{case} recorded an unexpected completed relay")
    return value


def parse_boundary(
    data: bytes, architecture: str, case_observation: dict[str, object]
) -> dict[str, object]:
    """Decode and bind one exact native wrapper observation."""

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
        "channel_cookie",
        "instruction_count",
        "no_new_privs",
        "peer_gid",
        "peer_pid",
        "peer_uid",
        "retained_fd",
        "socket_family",
        "socket_type",
    }
    if set(fields) != expected:
        raise RecordError("boundary observation fields are not exact")
    local = case_observation["local_channel"]
    assert isinstance(local, dict)
    peer = local["child_peer"]
    assert isinstance(peer, dict)
    try:
        numeric = {
            name: int(fields[name], 10)
            for name in (
                "channel_cookie",
                "instruction_count",
                "peer_gid",
                "peer_pid",
                "peer_uid",
                "retained_fd",
            )
        }
    except ValueError as error:
        raise RecordError("boundary numeric observation is invalid") from error
    if (
        fields["architecture"] != architecture
        or fields["no_new_privs"] != "true"
        or fields["socket_family"] != "unix"
        or fields["socket_type"] != "stream"
        or numeric["channel_cookie"] != local["child_cookie"]
        or numeric["peer_pid"] != peer["pid"]
        or numeric["peer_uid"] != peer["uid"]
        or numeric["peer_gid"] != peer["gid"]
        or numeric["instruction_count"] <= 0
        or numeric["retained_fd"] < 3
    ):
        raise RecordError("boundary observation value is invalid")
    return {
        "architecture": architecture,
        **numeric,
        "no_new_privs": True,
        "socket_family": "unix",
        "socket_type": "stream",
    }


def record(arguments: argparse.Namespace) -> Path:
    """Validate exact inputs and publish one immutable control result."""

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
        for case, _, _, _ in CASES
    }

    experiment_root = "experiments/network_authority"
    plan_path = confined_file(source_root, f"{experiment_root}/preconnected-control.toml")
    source_paths = [
        confined_file(source_root, f"{experiment_root}/{name}") for name in SOURCE_FILES
    ]
    wrapper_path = confined_file(work_root, "preconnected-child-control")
    allowed_certificate_path = confined_file(work_root, "allowed-certificate.pem")
    denied_certificate_path = confined_file(work_root, "denied-certificate.pem")
    input_paths = [
        plan_path,
        *source_paths,
        wrapper_path,
        allowed_certificate_path,
        denied_certificate_path,
    ]
    for case, _, expects_boundary, _ in CASES:
        input_paths.extend(
            [
                confined_file(work_root, f"state/{case}/case-observations.json"),
                confined_file(work_root, f"state/{case}/fixture.ready"),
                confined_file(work_root, f"stdout/{case}.log"),
                confined_file(work_root, f"stderr/{case}.log"),
                confined_file(work_root, f"fixture-stdout/{case}.log"),
                confined_file(work_root, f"fixture-stderr/{case}.log"),
            ]
        )
        if expects_boundary:
            input_paths.extend(
                [
                    confined_file(work_root, f"state/{case}/boundary/seccomp-program.bin"),
                    confined_file(
                        work_root,
                        f"state/{case}/boundary/boundary-observations.txt",
                    ),
                    confined_file(work_root, f"home/{case}.started"),
                ]
            )
        if case in FIXTURE_OBSERVATIONS:
            input_paths.append(
                confined_file(work_root, f"state/{case}/fixture-observation.txt")
            )
    inputs = {path: regular_bytes(path) for path in input_paths}
    try:
        allowed_pem = inputs[allowed_certificate_path].decode("ascii")
        allowed_der = ssl.PEM_cert_to_DER_cert(allowed_pem)
    except (UnicodeDecodeError, ValueError) as error:
        raise RecordError("allowed certificate is not one PEM certificate") from error
    allowed_certificate_sha256 = hashlib.sha256(allowed_der).hexdigest()

    case_observations: dict[str, dict[str, object]] = {}
    boundaries = []
    program_digests = set()
    for case, _, expects_boundary, expects_relay in CASES:
        state = work_root / "state" / case
        observation_path = state / "case-observations.json"
        case_observation = parse_case_observation(
            inputs[observation_path],
            case,
            expects_boundary,
            expects_relay,
            allowed_certificate_sha256,
        )
        case_observations[case] = case_observation
        expected_state = {"case-observations.json", "fixture.ready"}
        if expects_boundary:
            expected_state.add("boundary")
            if inputs[work_root / "home" / f"{case}.started"] != b"started\n":
                raise RecordError(f"{case} client-start marker is invalid")
        if case in FIXTURE_OBSERVATIONS:
            expected_state.add("fixture-observation.txt")
            if inputs[state / "fixture-observation.txt"] != FIXTURE_OBSERVATIONS[case]:
                raise RecordError(f"{case} fixture observation is invalid")
        if {path.name for path in state.iterdir()} != expected_state:
            raise RecordError(f"{case} state inventory is not exact")
        if expects_boundary:
            boundary_root = state / "boundary"
            if {path.name for path in boundary_root.iterdir()} != {
                "boundary-observations.txt",
                "seccomp-program.bin",
            }:
                raise RecordError(f"{case} boundary inventory is not exact")
            program_path = boundary_root / "seccomp-program.bin"
            program_identity = identity(
                "seccomp-program.bin", inputs[program_path], program_path.lstat().st_mode
            )
            program_digests.add(program_identity["sha256"])
            boundaries.append(
                {
                    "case": case,
                    "observations": parse_boundary(
                        inputs[boundary_root / "boundary-observations.txt"],
                        arguments.architecture,
                        case_observation,
                    ),
                    "seccomp_program": program_identity,
                }
            )
    if len(program_digests) != 1:
        raise RecordError("preconnected cases did not install one seccomp program")
    expected_markers = {f"{case}.started" for case, _, boundary, _ in CASES if boundary}
    if {path.name for path in (work_root / "home").iterdir()} != expected_markers:
        raise RecordError("client-start marker inventory is not exact")

    if not output.parent.is_dir() or output.exists() or output.is_symlink():
        raise RecordError("output must be one absent child of an existing directory")
    os.mkdir(output, 0o755)
    for directory in (
        "observations",
        "observations/fixture",
        "stdout",
        "stderr",
        "stdout/fixture",
        "stderr/fixture",
    ):
        os.mkdir(output / directory, 0o755)
    write_new(output / "plan.toml", inputs[plan_path])
    published_inputs: dict[str, bytes] = {"plan.toml": inputs[plan_path]}
    attack_entries = []
    for case, expects_zero, _, _ in CASES:
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
            (f"observations/{case}.json", work_root / f"state/{case}/case-observations.json"),
            (f"stdout/{case}.log", work_root / f"stdout/{case}.log"),
            (f"stderr/{case}.log", work_root / f"stderr/{case}.log"),
            (f"stdout/fixture/{case}.log", work_root / f"fixture-stdout/{case}.log"),
            (f"stderr/fixture/{case}.log", work_root / f"fixture-stderr/{case}.log"),
        )
        for relative, source in mappings:
            write_new(output / relative, inputs[source])
            published_inputs[relative] = inputs[source]
        if case in FIXTURE_OBSERVATIONS:
            relative = f"observations/fixture/{case}.txt"
            source = work_root / f"state/{case}/fixture-observation.txt"
            write_new(output / relative, inputs[source])
            published_inputs[relative] = inputs[source]

    attack_result = {
        "cases": attack_entries,
        "complete": True,
        "expected_authority_exposures": [
            "undeclared-path-exposure",
            "connect-shape-exposure",
        ],
        "schema": "proofbound-runtime-network-experiment-attacks/1",
    }
    boundary_manifest = {
        "cases": boundaries,
        "cleanup_observed": arguments.cleanup_observed == "true",
        "schema": "proofbound-runtime-network-experiment-child-boundary/1",
    }
    channel_manifest = {
        "application_protocol": "transparent",
        "channel": {
            "maximum_child_to_service_bytes": MAX_DIRECTION_BYTES,
            "maximum_service_to_child_bytes": MAX_DIRECTION_BYTES,
            "type": "unix-stream",
        },
        "reconnect_count": 0,
        "service": {
            "endpoint": "127.0.0.1:443",
            "name": "allowed.test",
            "transport": "tls-1.3",
        },
        "session_count": 1,
        "schema": "proofbound-runtime-network-experiment-preconnected-channel/1",
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
    artifact_manifest = {
        "artifacts": [
            identity(
                "preconnected-child-control",
                inputs[wrapper_path],
                wrapper_path.lstat().st_mode,
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
        "channel-manifest.json": canonical_json(channel_manifest),
        "fixture-manifest.json": canonical_json(fixture_manifest),
        "kernel-manifest.json": canonical_json(
            {
                "architecture": metadata["architecture"],
                "kernel_release": metadata["kernel_release"],
                "schema": "proofbound-runtime-network-experiment-kernel/1",
            }
        ),
        "tool-manifest.json": canonical_json(
            {
                "compiler": metadata["compiler"],
                "openssl": metadata["openssl"],
                "python": metadata["python"],
                "schema": "proofbound-runtime-network-experiment-tools/1",
            }
        ),
    }
    for name, data in manifests.items():
        write_new(output / name, data)
        published_inputs[name] = data

    complete = (
        all(entry["matched_expected"] for entry in attack_entries)
        and arguments.cleanup_observed == "true"
    )
    result = {
        "complete": complete,
        "conclusion": (
            "preconnected-channel-binds-one-authenticated-session-control"
            if complete
            else "unexpected-control-result"
        ),
        "experiment": "network-authority/1",
        "inputs": [
            {"name": name, "sha256": sha256(data), "size": len(data)}
            for name, data in sorted(published_inputs.items())
        ],
        "mechanism": "preconnected-authenticated-channel-control",
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
    for case, _, _, _ in CASES:
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
