#!/usr/bin/env python3
"""Run one experiment 0001F case through a preconnected authenticated channel."""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import struct
import subprocess
import sys
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
from experiments.network_authority.routing_mediator import (
    MediatorError,
    MediatorRejection,
    marker,
    open_authenticated,
    relay_transparent,
)
from experiments.network_authority.routing_transport_case import (
    RoutingCase,
    case_plan,
    load_routing_matrix,
    plan_rejection,
)


DIRECT_CASES = {
    "direct-tcp-other-port",
    "direct-udp-dns-shaped",
    "direct-udp-quic-shaped",
    "tcp-bind-listen",
    "udp-bind",
}
SO_COOKIE = 57
SO_PEERCRED = 17
PRELAUNCH_DETAILS = {
    "undeclared-service-ipv4-443": "connector-endpoint-mismatch",
    "undeclared-service-ipv6-443": "connector-endpoint-mismatch",
    "literal-allowed-address": "connector-endpoint-mismatch",
    "literal-undeclared-address": "connector-endpoint-mismatch",
    "allowed-endpoint-wrong-certificate": "certificate-rejected",
    "alternate-endpoint-allowed-certificate": "connector-endpoint-mismatch",
    "ipv4-mapped-ipv6": "connector-endpoint-mismatch",
}


@dataclass
class StartedFixture:
    process: subprocess.Popen[bytes]
    stdout: object
    stderr: object
    root: Path

    def close_streams(self) -> None:
        self.stdout.close()  # type: ignore[attr-defined]
        self.stderr.close()  # type: ignore[attr-defined]


def socket_cookie(channel: socket.socket) -> int:
    """Read one nonzero Linux socket identity cookie."""

    raw = channel.getsockopt(socket.SOL_SOCKET, SO_COOKIE, 8)
    if len(raw) != 8:
        raise RoutingOrchestrationError("local channel cookie is incomplete")
    result = struct.unpack("=Q", raw)[0]
    if result == 0:
        raise RoutingOrchestrationError("local channel cookie is invalid")
    return result


def peer_credentials(channel: socket.socket) -> dict[str, int]:
    """Read one exact Linux Unix-peer credential tuple."""

    raw = channel.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, 12)
    if len(raw) != 12:
        raise RoutingOrchestrationError("local peer credentials are incomplete")
    pid, uid, gid = struct.unpack("=3i", raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise RoutingOrchestrationError("local peer credentials are invalid")
    return {"gid": gid, "pid": pid, "uid": uid}


def primary_fixture_plan(case_id: str) -> FixturePlan | None:
    """Return the case-visible fixture, excluding the connector service."""

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
        case_id in PRELAUNCH_DETAILS
        or case_id in {"tcp-bind-listen", "udp-bind"}
        or plan_rejection(case_id) is not None
    ):
        return None
    raise RoutingOrchestrationError("preconnected case has no primary fixture plan")


def connector_plan(case_id: str) -> FixturePlan | None:
    """Return the TLS fixture used to establish the connector-owned session."""

    if case_id in DIRECT_CASES:
        return FixturePlan(
            "experiments.network_authority.decision_http_fixture",
            "127.0.0.1",
            443,
            "exact",
            "allowed",
        )
    if case_id in {
        "exact-service-ipv4",
        "exact-service-ipv6",
        "allowed-endpoint-wrong-certificate",
        "alternate-endpoint-allowed-certificate",
    }:
        return primary_fixture_plan(case_id)
    return None


def connector_endpoints(case_id: str) -> tuple[str, str]:
    """Return the exact dial and expected tuple before child release."""

    if case_id == "exact-service-ipv6":
        return "fd00::1", "fd00::1"
    if case_id == "alternate-endpoint-allowed-certificate":
        return "127.0.0.2", "127.0.0.1"
    if case_id in DIRECT_CASES or case_id in {
        "exact-service-ipv4",
        "allowed-endpoint-wrong-certificate",
    }:
        return "127.0.0.1", "127.0.0.1"
    raise RoutingOrchestrationError("case does not establish a connector session")


def start_fixture(
    plan: FixturePlan,
    arguments: argparse.Namespace,
    root: Path,
) -> StartedFixture:
    """Start and validate one exact bounded fixture."""

    root.mkdir(mode=0o755, exist_ok=root == arguments.case_root)
    stdout = (root / "fixture.stdout").open("xb")
    stderr = (root / "fixture.stderr").open("xb")
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            fixture_command(plan, arguments, root),
            cwd=arguments.repository_root,
            env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0"},
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
        )
        ready = root / "fixture-ready.json"
        wait_ready(ready, process)
        validate_ready(read_document(ready), plan)
        return StartedFixture(process, stdout, stderr, root)
    except BaseException:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        stdout.close()
        stderr.close()
        raise


def child_command(
    case: RoutingCase,
    arguments: argparse.Namespace,
    case_root: Path,
    descriptor: int,
    cookie: int,
    peer: dict[str, int],
) -> list[str]:
    """Bind the staged client to one exact authenticated local channel."""

    output = case_root / "child-output"
    return [
        str(arguments.child_control),
        str(descriptor),
        str(cookie),
        str(peer["pid"]),
        str(peer["uid"]),
        str(peer["gid"]),
        str(case_root / "child-boundary"),
        "--",
        sys.executable,
        str(arguments.client),
        "--case",
        case.identifier,
        "--fd",
        str(descriptor),
        "--channel-mode",
        "preconnected-channel",
        "--started-file",
        str(output / "started.txt"),
        "--observation",
        str(output / "observation.json"),
    ]


def observed_raw(
    case: RoutingCase,
    case_root: Path,
    client_exit: int | None,
    cleanup: bool,
) -> dict[str, object]:
    """Project only case-visible fixture and mediator markers into raw evidence."""

    started_path = case_root / "child-output/started.txt"
    observation_path = case_root / "child-output/observation.json"
    started = started_path.is_file()
    if started and regular_bytes(started_path) != b"started\n":
        raise RoutingOrchestrationError("preconnected child start marker is invalid")
    raw = raw_cell(
        case,
        "preconnected-channel",
        cleanup=cleanup,
        client=read_document(observation_path) if observation_path.is_file() else None,
        client_started=started,
        fixture_contact=(case_root / "fixture-contact.json").is_file(),
        fixture_complete=(case_root / "fixture-observation.json").is_file(),
        mediator=read_document(case_root / "mediator.json")
        if (case_root / "mediator.json").is_file()
        else None,
    )
    raw["client_exit"] = client_exit if started else None
    return raw


def publish_prelaunch(case: RoutingCase, case_root: Path, detail: str) -> dict[str, object]:
    """Publish one trusted rejection before any child exists."""

    mediator = marker("rejected", "prelaunch", detail)
    write_new(case_root / "mediator.json", canonical_json(mediator))
    return raw_cell(
        case,
        "preconnected-channel",
        fixture_contact=(case_root / "fixture-contact.json").is_file(),
        fixture_complete=(case_root / "fixture-observation.json").is_file(),
        mediator=mediator,
    )


def run(arguments: argparse.Namespace) -> dict[str, object]:
    """Run one preconnected case without comparing its expectation."""

    if os.geteuid() != 0:
        raise RoutingOrchestrationError("preconnected orchestration requires root")
    matrix = load_routing_matrix(arguments.matrix)
    matches = [case for case in matrix.cases if case.identifier == arguments.case]
    if len(matches) != 1:
        raise RoutingOrchestrationError("preconnected routing case is not unique")
    case = matches[0]
    arguments.case_root.mkdir(mode=0o755)
    write_new(
        arguments.case_root / "case-plan.json",
        canonical_json(
            case_plan(case, "preconnected-channel", matrix.source_sha256)
        ),
    )
    rejection = plan_rejection(case.identifier)
    if rejection is not None:
        raw = raw_cell(case, "preconnected-channel", plan_rejection=rejection)
        write_new(arguments.raw_output, canonical_json(raw))
        return raw

    primary: StartedFixture | None = None
    connector: StartedFixture | None = None
    protected: ssl.SSLSocket | None = None
    parent: socket.socket | None = None
    child_channel: socket.socket | None = None
    child: subprocess.Popen[bytes] | None = None
    child_stdout = None
    child_stderr = None
    cleanup = True
    client_exit: int | None = None
    try:
        plan = primary_fixture_plan(case.identifier)
        if plan is not None:
            primary = start_fixture(plan, arguments, arguments.case_root)

        if case.identifier in PRELAUNCH_DETAILS:
            detail = PRELAUNCH_DETAILS[case.identifier]
            connector_spec = connector_plan(case.identifier)
            if connector_spec is not None:
                if primary is None:
                    raise RoutingOrchestrationError("prelaunch connector fixture is absent")
                dial, expected = connector_endpoints(case.identifier)
                try:
                    protected, _session = open_authenticated(
                        dial, expected, 443, arguments.allowed_certificate
                    )
                except MediatorRejection as observed:
                    if observed.detail != detail:
                        raise RoutingOrchestrationError(
                            "prelaunch rejection detail changed"
                        ) from observed
                else:
                    protected.close()
                    protected = None
                    raise RoutingOrchestrationError("substitution passed connector checks")
            raw = publish_prelaunch(case, arguments.case_root, detail)
            if primary is not None:
                cleanup = reap_fixture(
                    primary.process,
                    (arguments.case_root / "fixture-contact.json").is_file(),
                )
            raw["cleanup"] = cleanup
            write_new(arguments.raw_output, canonical_json(raw))
            return raw

        connector_root = arguments.case_root
        if case.identifier in DIRECT_CASES:
            connector_root = arguments.case_root / "connector"
            connector_spec = connector_plan(case.identifier)
            if connector_spec is None:
                raise RoutingOrchestrationError("direct case lacks connector fixture")
            connector = start_fixture(connector_spec, arguments, connector_root)
        elif primary is not None:
            connector = primary
        else:
            raise RoutingOrchestrationError("released child lacks connector fixture")

        dial, expected = connector_endpoints(case.identifier)
        protected, session = open_authenticated(
            dial, expected, 443, arguments.allowed_certificate
        )
        write_new(
            connector_root / "session-observation.json", canonical_json(session)
        )
        parent, child_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        child_cookie = socket_cookie(child_channel)
        child_peer = peer_credentials(child_channel)
        output = arguments.case_root / "child-output"
        output.mkdir(mode=0o700)
        os.chown(output, 65534, 65534)
        child_stdout = (arguments.case_root / "child.stdout").open("xb")
        child_stderr = (arguments.case_root / "child.stderr").open("xb")
        child = subprocess.Popen(
            child_command(
                case,
                arguments,
                arguments.case_root,
                child_channel.fileno(),
                child_cookie,
                child_peer,
            ),
            cwd=arguments.repository_root,
            env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0"},
            pass_fds=(child_channel.fileno(),),
            stdin=subprocess.DEVNULL,
            stdout=child_stdout,
            stderr=child_stderr,
        )
        child_channel.close()
        child_channel = None

        if case.identifier in {"exact-service-ipv4", "exact-service-ipv6"}:
            relay_transparent(parent, protected)
            protected = None
            mediator = marker(
                "exact-response",
                "application-protocol",
                "authenticated-exact-response",
            )
            write_new(arguments.case_root / "mediator.json", canonical_json(mediator))
        else:
            protected.close()
            protected = None
        parent.close()
        parent = None
        try:
            client_exit = child.wait(timeout=case.maximum_seconds)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)
            client_exit = 124
        if client_exit is None or not 0 <= client_exit <= 255:
            client_exit = 125

        if primary is not None and primary is not connector:
            cleanup = reap_fixture(
                primary.process,
                (arguments.case_root / "fixture-contact.json").is_file(),
            ) and cleanup
        if connector is not None:
            connector_contact = (connector.root / "fixture-contact.json").is_file()
            cleanup = reap_fixture(connector.process, connector_contact) and cleanup
        raw = observed_raw(case, arguments.case_root, client_exit, cleanup)
        write_new(arguments.raw_output, canonical_json(raw))
        return raw
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=2)
        for channel in (parent, child_channel, protected):
            if channel is not None:
                channel.close()
        fixtures = []
        for item in (primary, connector):
            if item is not None and all(item is not seen for seen in fixtures):
                fixtures.append(item)
        for item in fixtures:
            if item.process.poll() is None:
                item.process.kill()
                item.process.wait(timeout=2)
            item.close_streams()
        if child_stdout is not None:
            child_stdout.close()
        if child_stderr is not None:
            child_stderr.close()


def parser() -> argparse.ArgumentParser:
    """Build the closed preconnected one-case orchestration interface."""

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
    """Run one preconnected case or fail as a harness error."""

    arguments = parser().parse_args()
    try:
        paths = tuple(value for value in vars(arguments).values() if isinstance(value, Path))
        if any(not path.is_absolute() for path in paths):
            raise RoutingOrchestrationError(
                "preconnected orchestration paths are not absolute"
            )
        run(arguments)
        return 0
    except (
        MediatorError,
        OSError,
        RecordError,
        RoutingOrchestrationError,
        subprocess.SubprocessError,
        ValueError,
    ) as error:
        print(f"routing preconnected case orchestration failed: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
