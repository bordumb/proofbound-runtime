#!/usr/bin/env python3
"""Run one experiment 0001F case through the explicit operation broker."""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.record_common import (
    RecordError,
    canonical_json,
    regular_bytes,
    write_new,
)
from experiments.network_authority.run_routing_direct_case import (
    FixturePlan,
    RoutingOrchestrationError,
    fixture_command,
    read_document,
    reap_fixture,
    validate_ready,
    wait_ready,
)
from experiments.network_authority.routing_cell import raw_cell
from experiments.network_authority.routing_transport_case import (
    RoutingCase,
    case_plan,
    load_routing_matrix,
    plan_rejection,
)


TARGET_REJECTION_CASES = {
    "undeclared-service-ipv4-443",
    "undeclared-service-ipv6-443",
    "literal-allowed-address",
    "literal-undeclared-address",
}
DIRECT_CASES = {
    "direct-tcp-other-port",
    "direct-udp-dns-shaped",
    "direct-udp-quic-shaped",
    "tcp-bind-listen",
    "udp-bind",
}


def broker_fixture_plan(case_id: str) -> FixturePlan | None:
    """Return the exact remote or attack fixture for mechanism C."""

    tls = {
        "exact-service-ipv4": ("127.0.0.1", "allowed"),
        "exact-service-ipv6": ("fd00::1", "allowed"),
        "allowed-endpoint-wrong-certificate": ("127.0.0.1", "denied"),
        "alternate-endpoint-allowed-certificate": ("127.0.0.2", "allowed"),
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
    if (
        case_id in TARGET_REJECTION_CASES
        or case_id in {"tcp-bind-listen", "udp-bind", "ipv4-mapped-ipv6"}
        or plan_rejection(case_id) is not None
    ):
        return None
    raise RoutingOrchestrationError("broker case has no fixture plan")


def broker_endpoints(case_id: str) -> tuple[str, str]:
    """Return exact dial and expected addresses for one broker exchange."""

    if case_id == "exact-service-ipv6":
        return "fd00::1", "fd00::1"
    if case_id == "alternate-endpoint-allowed-certificate":
        return "127.0.0.2", "127.0.0.1"
    if case_id in TARGET_REJECTION_CASES or case_id in {
        "exact-service-ipv4",
        "allowed-endpoint-wrong-certificate",
    }:
        return "127.0.0.1", "127.0.0.1"
    raise RoutingOrchestrationError("case does not invoke the broker")


def invokes_broker(case_id: str) -> bool:
    """Report whether the case sends one explicit operation."""

    return case_id in TARGET_REJECTION_CASES or case_id in {
        "exact-service-ipv4",
        "exact-service-ipv6",
        "allowed-endpoint-wrong-certificate",
        "alternate-endpoint-allowed-certificate",
    }


def child_command(
    case: RoutingCase,
    arguments: argparse.Namespace,
    case_root: Path,
    descriptor: int,
) -> list[str]:
    """Compose the strong broker child boundary with the staged client."""

    output = case_root / "child-output"
    return [
        str(arguments.child_control),
        str(descriptor),
        str(case_root / "child-boundary"),
        "--",
        sys.executable,
        str(arguments.client),
        "--case",
        case.identifier,
        "--fd",
        str(descriptor),
        "--channel-mode",
        "explicit-broker",
        "--started-file",
        str(output / "started.txt"),
        "--observation",
        str(output / "observation.json"),
    ]


def broker_command(
    case: RoutingCase,
    arguments: argparse.Namespace,
    case_root: Path,
    descriptor: int,
) -> list[str]:
    """Build the exact trusted broker process command."""

    dial, expected = broker_endpoints(case.identifier)
    return [
        sys.executable,
        "-m",
        "experiments.network_authority.routing_mediator",
        "--fd",
        str(descriptor),
        "--dial-address",
        dial,
        "--expected-address",
        expected,
        "--port",
        "443",
        "--ca-certificate",
        str(arguments.allowed_certificate),
        "--marker",
        str(case_root / "mediator.json"),
        "--session-observation",
        str(case_root / "session-observation.json"),
    ]


def observed_raw(
    case: RoutingCase,
    case_root: Path,
    client_exit: int,
    cleanup: bool,
) -> dict[str, object]:
    """Project broker process markers into one closed raw cell."""

    started_path = case_root / "child-output/started.txt"
    observation_path = case_root / "child-output/observation.json"
    started = started_path.is_file()
    if started and regular_bytes(started_path) != b"started\n":
        raise RoutingOrchestrationError("broker child start marker is invalid")
    return raw_cell(
        case,
        "explicit-broker",
        cleanup=cleanup,
        client=read_document(observation_path) if observation_path.is_file() else None,
        client_started=started,
        fixture_contact=(case_root / "fixture-contact.json").is_file(),
        fixture_complete=(case_root / "fixture-observation.json").is_file(),
        mediator=read_document(case_root / "mediator.json")
        if (case_root / "mediator.json").is_file()
        else None,
    ) | {"client_exit": client_exit if started else None}


def run(arguments: argparse.Namespace) -> dict[str, object]:
    """Run one broker case without comparing its registered expectation."""

    if os.geteuid() != 0:
        raise RoutingOrchestrationError("broker routing orchestration requires root")
    matrix = load_routing_matrix(arguments.matrix)
    matches = [case for case in matrix.cases if case.identifier == arguments.case]
    if len(matches) != 1:
        raise RoutingOrchestrationError("broker routing case is not unique")
    case = matches[0]
    arguments.case_root.mkdir(mode=0o755)
    write_new(
        arguments.case_root / "case-plan.json",
        canonical_json(case_plan(case, "explicit-broker", matrix.source_sha256)),
    )
    rejection = plan_rejection(case.identifier)
    if case.identifier == "ipv4-mapped-ipv6":
        rejection = "interface-cannot-represent-address"
    if rejection is not None:
        raw = raw_cell(case, "explicit-broker", plan_rejection=rejection)
        write_new(arguments.raw_output, canonical_json(raw))
        return raw

    output = arguments.case_root / "child-output"
    output.mkdir(mode=0o700)
    os.chown(output, 65534, 65534)
    plan = broker_fixture_plan(case.identifier)
    fixture: subprocess.Popen[bytes] | None = None
    broker: subprocess.Popen[bytes] | None = None
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    fixture_stdout = (arguments.case_root / "fixture.stdout").open("xb")
    fixture_stderr = (arguments.case_root / "fixture.stderr").open("xb")
    broker_stdout = (arguments.case_root / "mediator.stdout").open("xb")
    broker_stderr = (arguments.case_root / "mediator.stderr").open("xb")
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
        if invokes_broker(case.identifier):
            broker = subprocess.Popen(
                broker_command(case, arguments, arguments.case_root, parent.fileno()),
                cwd=arguments.repository_root,
                env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0"},
                pass_fds=(parent.fileno(),),
                stdin=subprocess.DEVNULL,
                stdout=broker_stdout,
                stderr=broker_stderr,
            )
        parent.close()
        try:
            completed = subprocess.run(
                child_command(case, arguments, arguments.case_root, child.fileno()),
                cwd=arguments.repository_root,
                env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0"},
                pass_fds=(child.fileno(),),
                stdin=subprocess.DEVNULL,
                stdout=child_stdout,
                stderr=child_stderr,
                check=False,
                timeout=case.maximum_seconds,
            )
            client_exit = completed.returncode if 0 <= completed.returncode <= 255 else 125
        except subprocess.TimeoutExpired:
            client_exit = 124
        child.close()
        if broker is not None:
            try:
                broker.wait(timeout=2)
            except subprocess.TimeoutExpired:
                cleanup = False
        if fixture is not None:
            cleanup = reap_fixture(
                fixture, (arguments.case_root / "fixture-contact.json").is_file()
            ) and cleanup
        raw = observed_raw(case, arguments.case_root, client_exit, cleanup)
        write_new(arguments.raw_output, canonical_json(raw))
        return raw
    finally:
        parent.close()
        child.close()
        for process in (broker, fixture):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=2)
        for stream in (
            fixture_stdout,
            fixture_stderr,
            broker_stdout,
            broker_stderr,
            child_stdout,
            child_stderr,
        ):
            stream.close()


def parser() -> argparse.ArgumentParser:
    """Build the closed broker one-case orchestration interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--case", required=True)
    result.add_argument("--repository-root", type=Path, required=True)
    result.add_argument("--matrix", type=Path, required=True)
    result.add_argument("--case-root", type=Path, required=True)
    result.add_argument("--raw-output", type=Path, required=True)
    result.add_argument("--child-control", type=Path, required=True)
    result.add_argument("--client", type=Path, required=True)
    result.add_argument("--allowed-certificate", type=Path, required=True)
    result.add_argument("--allowed-private-key", type=Path, required=True)
    result.add_argument("--denied-certificate", type=Path, required=True)
    result.add_argument("--denied-private-key", type=Path, required=True)
    return result


def main() -> int:
    """Run one broker case or fail as a harness error."""

    arguments = parser().parse_args()
    try:
        paths = tuple(value for value in vars(arguments).values() if isinstance(value, Path))
        if any(not path.is_absolute() for path in paths):
            raise RoutingOrchestrationError("broker orchestration paths are not absolute")
        run(arguments)
        return 0
    except (
        OSError,
        RecordError,
        RoutingOrchestrationError,
        subprocess.SubprocessError,
        ValueError,
    ) as error:
        print(f"routing broker case orchestration failed: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
