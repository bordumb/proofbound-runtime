#!/usr/bin/env python3
"""Run one experiment 0001F case through routing mechanism A or B."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.record_common import (
    RecordError,
    canonical_json,
    regular_bytes,
    write_new,
)
from experiments.network_authority.routing_cell import raw_cell
from experiments.network_authority.routing_transport_case import (
    RoutingCase,
    load_routing_matrix,
    plan_rejection,
)


DIRECT_MECHANISMS = {"landlock-port", "cgroup-endpoint"}
NO_FIXTURE_CASES = {"tcp-bind-listen", "udp-bind"}
MAX_DOCUMENT_BYTES = 16384


class RoutingOrchestrationError(Exception):
    """One direct routing case could not produce closed raw evidence."""


@dataclass(frozen=True)
class FixturePlan:
    module: str
    address: str
    port: int
    script: str
    certificate_role: str | None


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON names instead of accepting their last value."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RoutingOrchestrationError("routing document has duplicate names")
        result[key] = value
    return result


def fixture_plan(case_id: str) -> FixturePlan | None:
    """Return the expectation-independent target for one executable case."""

    tls = {
        "exact-service-ipv4": ("127.0.0.1", "allowed"),
        "exact-service-ipv6": ("fd00::1", "allowed"),
        "undeclared-service-ipv4-443": ("127.0.0.2", "denied"),
        "undeclared-service-ipv6-443": ("fd00::2", "denied"),
        "literal-allowed-address": ("127.0.0.1", "allowed"),
        "literal-undeclared-address": ("127.0.0.2", "denied"),
        "allowed-endpoint-wrong-certificate": ("127.0.0.1", "denied"),
        "alternate-endpoint-allowed-certificate": ("127.0.0.2", "allowed"),
        "ipv4-mapped-ipv6": ("127.0.0.1", "allowed"),
    }
    if case_id in tls:
        address, role = tls[case_id]
        return FixturePlan(
            "experiments.network_authority.decision_http_fixture",
            address,
            443,
            "exact",
            role,
        )
    sockets = {
        "direct-tcp-other-port": "tcp-connect",
        "direct-udp-dns-shaped": "udp-dns",
        "direct-udp-quic-shaped": "udp-quic",
    }
    if case_id in sockets:
        return FixturePlan(
            "experiments.network_authority.decision_socket_fixture",
            "127.0.0.1",
            8443,
            sockets[case_id],
            None,
        )
    if case_id in NO_FIXTURE_CASES or plan_rejection(case_id) is not None:
        return None
    raise RoutingOrchestrationError("routing case has no fixture plan")


def read_document(path: Path) -> dict[str, object]:
    """Read one small closed JSON object from an immutable regular file."""

    try:
        data = regular_bytes(path)
        if not data or len(data) > MAX_DOCUMENT_BYTES:
            raise RoutingOrchestrationError("routing document size is invalid")
        value = json.loads(data, object_pairs_hook=unique_object)
    except (RecordError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RoutingOrchestrationError("routing document is invalid") from error
    if not isinstance(value, dict):
        raise RoutingOrchestrationError("routing document is not an object")
    return value


def fixture_command(
    plan: FixturePlan,
    arguments: argparse.Namespace,
    case_root: Path,
) -> list[str]:
    """Build one exact fixture command without consulting expectations."""

    ready = case_root / "fixture-ready.json"
    observation = case_root / "fixture-observation.json"
    command = [
        sys.executable,
        "-m",
        plan.module,
        "--script",
        plan.script,
        "--bind-ip",
        plan.address,
        "--port",
        str(plan.port),
        "--ready-file",
        str(ready),
    ]
    if plan.certificate_role is not None:
        certificate = getattr(arguments, f"{plan.certificate_role}_certificate")
        private_key = getattr(arguments, f"{plan.certificate_role}_private_key")
        command.extend(
            [
                "--certificate",
                str(certificate),
                "--private-key",
                str(private_key),
                "--contact-file",
                str(case_root / "fixture-contact.json"),
            ]
        )
    command.extend(["--observation-file", str(observation)])
    return command


def client_command(
    case: RoutingCase,
    arguments: argparse.Namespace,
    case_root: Path,
) -> list[str]:
    """Build the exact staged-client command for a direct mechanism."""

    child_output = case_root / "child-output"
    return [
        sys.executable,
        str(arguments.client),
        "--case",
        case.identifier,
        "--allowed-ipv4",
        "127.0.0.1",
        "--allowed-ipv6",
        "fd00::1",
        "--denied-ipv4",
        "127.0.0.2",
        "--denied-ipv6",
        "fd00::2",
        "--service-port",
        "443",
        "--other-port",
        "8443",
        "--allowed-ca",
        str(arguments.allowed_certificate),
        "--started-file",
        str(child_output / "started.txt"),
        "--observation",
        str(child_output / "observation.json"),
    ]


def boundary_command(
    case: RoutingCase,
    arguments: argparse.Namespace,
    case_root: Path,
) -> list[str]:
    """Compose mechanism A or B with the common scalar child boundary."""

    child = [
        str(arguments.child_control),
        str(case_root / "child-boundary"),
        "--",
        *client_command(case, arguments, case_root),
    ]
    if arguments.mechanism == "landlock-port":
        return [
            str(arguments.mechanism_control),
            "443",
            str(case_root / "mechanism-state"),
            "--",
            *child,
        ]
    if arguments.mechanism == "cgroup-endpoint":
        if arguments.cgroup_directory is None:
            raise RoutingOrchestrationError("cgroup endpoint case lacks a cgroup")
        return [
            str(arguments.mechanism_control),
            str(arguments.cgroup_directory),
            "127.0.0.1",
            "fd00::1",
            "443",
            str(case_root / "mechanism-state"),
            "--",
            *child,
        ]
    raise RoutingOrchestrationError("direct routing mechanism is unknown")


def wait_ready(path: Path, process: subprocess.Popen[bytes]) -> None:
    """Wait within five seconds for a fixture readiness document."""

    for _ in range(100):
        if path.is_file():
            return
        if process.poll() is not None:
            break
        time.sleep(0.05)
    raise RoutingOrchestrationError("routing fixture did not become ready")


def validate_ready(value: dict[str, object], plan: FixturePlan) -> None:
    """Require a ready document to retain the frozen target exactly."""

    expected_family = "ipv6" if ":" in plan.address else "ipv4"
    common = {
        "address": plan.address,
        "family": expected_family,
        "port": plan.port,
    }
    if plan.certificate_role is None:
        expected = {
            **common,
            "schema": "proofbound-runtime-decision-socket-ready/1",
            "script": plan.script,
        }
    else:
        expected = {
            **common,
            "schema": "proofbound-runtime-decision-http-ready/1",
        }
    if value != expected:
        raise RoutingOrchestrationError("fixture readiness identity changed")


def reap_fixture(process: subprocess.Popen[bytes], contacted: bool) -> bool:
    """Reap one fixture, terminating only an uncontacted listener."""

    if process.poll() is None:
        if contacted:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                return False
        else:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
                return False
    return process.poll() is not None


def observed_raw(
    case: RoutingCase,
    mechanism: str,
    case_root: Path,
    client_exit: int,
    cleanup: bool,
) -> dict[str, object]:
    """Project process and file markers into the closed raw-cell schema."""

    started_path = case_root / "child-output/started.txt"
    observation_path = case_root / "child-output/observation.json"
    started = started_path.is_file()
    if started and regular_bytes(started_path) != b"started\n":
        raise RoutingOrchestrationError("child start marker is invalid")
    client = read_document(observation_path) if observation_path.is_file() else None
    raw = raw_cell(
        case,
        mechanism,
        cleanup=cleanup,
        client=client,
        client_started=started,
        fixture_contact=(case_root / "fixture-contact.json").is_file(),
        fixture_complete=(case_root / "fixture-observation.json").is_file(),
    )
    raw["client_exit"] = client_exit if started else None
    return raw


def run(arguments: argparse.Namespace) -> dict[str, object]:
    """Run one direct case and return raw evidence without comparing expectations."""

    if arguments.mechanism not in DIRECT_MECHANISMS:
        raise RoutingOrchestrationError("direct routing mechanism is invalid")
    if os.geteuid() != 0:
        raise RoutingOrchestrationError("direct routing orchestration requires root")
    matrix = load_routing_matrix(arguments.matrix)
    matches = [case for case in matrix.cases if case.identifier == arguments.case]
    if len(matches) != 1:
        raise RoutingOrchestrationError("routing case identity is not unique")
    case = matches[0]
    arguments.case_root.mkdir(mode=0o755)
    rejection = plan_rejection(case.identifier)
    if rejection is not None:
        raw = raw_cell(case, arguments.mechanism, plan_rejection=rejection)
        write_new(arguments.raw_output, canonical_json(raw))
        return raw

    child_output = arguments.case_root / "child-output"
    child_output.mkdir(mode=0o700)
    os.chown(child_output, 65534, 65534)
    plan = fixture_plan(case.identifier)
    fixture: subprocess.Popen[bytes] | None = None
    fixture_stdout = (arguments.case_root / "fixture.stdout").open("xb")
    fixture_stderr = (arguments.case_root / "fixture.stderr").open("xb")
    child_stdout = (arguments.case_root / "child.stdout").open("xb")
    child_stderr = (arguments.case_root / "child.stderr").open("xb")
    cleanup = True
    client_exit = 125
    try:
        if plan is not None:
            fixture = subprocess.Popen(
                fixture_command(plan, arguments, arguments.case_root),
                cwd=arguments.repository_root,
                env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0"},
                stdin=subprocess.DEVNULL,
                stdout=fixture_stdout,
                stderr=fixture_stderr,
            )
            ready_path = arguments.case_root / "fixture-ready.json"
            wait_ready(ready_path, fixture)
            validate_ready(read_document(ready_path), plan)
        try:
            completed = subprocess.run(
                boundary_command(case, arguments, arguments.case_root),
                cwd=arguments.repository_root,
                env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0"},
                stdin=subprocess.DEVNULL,
                stdout=child_stdout,
                stderr=child_stderr,
                check=False,
                timeout=case.maximum_seconds,
            )
            client_exit = completed.returncode if 0 <= completed.returncode <= 255 else 125
        except subprocess.TimeoutExpired:
            client_exit = 124
        if fixture is not None:
            cleanup = reap_fixture(
                fixture, (arguments.case_root / "fixture-contact.json").is_file()
            )
        if arguments.mechanism == "cgroup-endpoint":
            try:
                arguments.cgroup_directory.rmdir()
            except OSError:
                cleanup = False
        raw = observed_raw(
            case, arguments.mechanism, arguments.case_root, client_exit, cleanup
        )
        write_new(arguments.raw_output, canonical_json(raw))
        return raw
    finally:
        if fixture is not None and fixture.poll() is None:
            fixture.kill()
            fixture.wait(timeout=2)
        fixture_stdout.close()
        fixture_stderr.close()
        child_stdout.close()
        child_stderr.close()


def parser() -> argparse.ArgumentParser:
    """Build the closed direct one-case orchestration interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--case", required=True)
    result.add_argument("--mechanism", choices=sorted(DIRECT_MECHANISMS), required=True)
    result.add_argument("--repository-root", type=Path, required=True)
    result.add_argument("--matrix", type=Path, required=True)
    result.add_argument("--case-root", type=Path, required=True)
    result.add_argument("--raw-output", type=Path, required=True)
    result.add_argument("--mechanism-control", type=Path, required=True)
    result.add_argument("--child-control", type=Path, required=True)
    result.add_argument("--client", type=Path, required=True)
    result.add_argument("--allowed-certificate", type=Path, required=True)
    result.add_argument("--allowed-private-key", type=Path, required=True)
    result.add_argument("--denied-certificate", type=Path, required=True)
    result.add_argument("--denied-private-key", type=Path, required=True)
    result.add_argument("--cgroup-directory", type=Path)
    return result


def main() -> int:
    """Run one routing case or fail as a harness error."""

    try:
        arguments = parser().parse_args()
        absolute_paths = (
            arguments.repository_root,
            arguments.matrix,
            arguments.case_root,
            arguments.raw_output,
            arguments.mechanism_control,
            arguments.child_control,
            arguments.client,
            arguments.allowed_certificate,
            arguments.allowed_private_key,
            arguments.denied_certificate,
            arguments.denied_private_key,
        )
        if any(not path.is_absolute() for path in absolute_paths) or (
            arguments.cgroup_directory is not None
            and not arguments.cgroup_directory.is_absolute()
        ):
            raise RoutingOrchestrationError("routing orchestration paths are not absolute")
        run(arguments)
        return 0
    except (
        OSError,
        RecordError,
        RoutingOrchestrationError,
        subprocess.SubprocessError,
        ValueError,
    ) as error:
        print(f"routing direct case orchestration failed: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
