#!/usr/bin/env python3
"""Run one experiment 0001G case through a preconnected TLS channel."""

from __future__ import annotations

import argparse
import hashlib
import os
import socket
import ssl
import subprocess
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.decision_http_fixture import script_exchange
from experiments.network_authority.decision_proxy_fixture import (
    DENIED_SENTINEL,
    HTTP_CONNECT_REQUEST,
    HTTP_CONNECT_RESPONSE,
    PROBE,
    SOCKS_CONNECT_REQUEST,
    SOCKS_CONNECT_RESPONSE,
    SOCKS_GREETING,
    SOCKS_METHOD,
)
from experiments.network_authority.record_common import (
    RecordError,
    canonical_json,
    regular_bytes,
    write_new,
)
from experiments.network_authority.resolution_cell import raw_cell
from experiments.network_authority.resolution_indirection_case import (
    DNS_PLANS,
    ResolutionCase,
    case_plan,
    load_resolution_matrix,
    parameters_for,
)
from experiments.network_authority.resolution_network_client import SCHEMA as CLIENT_SCHEMA
from experiments.network_authority.routing_mediator import open_authenticated, read_exact
from experiments.network_authority.run_resolution_direct_case import (
    StartedFixture,
    _fixture_counts,
    read_document,
    resolve_group,
    start_http,
    start_proxy,
    stop_fixture,
)
from experiments.network_authority.run_routing_preconnected_case import (
    peer_credentials,
    socket_cookie,
)


class ResolutionPreconnectedError(Exception):
    """One preconnected case could not produce closed raw evidence."""


def _environment() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0"}


def child_command(
    arguments: argparse.Namespace,
    invocation: Path,
    descriptor: int,
    cookie: int,
    peer: dict[str, int],
    action: str,
) -> list[str]:
    output = invocation / "child-output"
    return [
        str(arguments.child_control),
        str(descriptor),
        str(cookie),
        str(peer["pid"]),
        str(peer["uid"]),
        str(peer["gid"]),
        str(invocation / "child-boundary"),
        "--",
        sys.executable,
        str(arguments.client),
        "--action",
        action,
        "--address",
        "127.0.0.1",
        "--port",
        "443",
        "--ca-certificate",
        str(arguments.allowed_certificate),
        "--fd",
        str(descriptor),
        "--started-file",
        str(output / "started.txt"),
        "--observation",
        str(output / "observation.json"),
    ]


def _relay_http(
    local: socket.socket, protected: ssl.SSLSocket, script: str
) -> None:
    request, response, _event = script_exchange(script)
    if read_exact(local, len(request)) != request or local.recv(1) != b"":
        raise ResolutionPreconnectedError("transparent HTTP request is not exact")
    protected.sendall(request)
    remote_response = read_exact(protected, len(response))
    if remote_response != response:
        raise ResolutionPreconnectedError("transparent HTTP response is not exact")
    raw = protected.unwrap()
    raw.close()
    local.sendall(response)
    local.shutdown(socket.SHUT_WR)


def _relay_proxy(
    local: socket.socket, protected: ssl.SSLSocket, protocol: str
) -> None:
    if protocol == "http-connect":
        if read_exact(local, len(HTTP_CONNECT_REQUEST)) != HTTP_CONNECT_REQUEST:
            raise ResolutionPreconnectedError("transparent CONNECT request changed")
        protected.sendall(HTTP_CONNECT_REQUEST)
        response = read_exact(protected, len(HTTP_CONNECT_RESPONSE))
        if response != HTTP_CONNECT_RESPONSE:
            raise ResolutionPreconnectedError("transparent CONNECT response changed")
        local.sendall(response)
    elif protocol == "socks5":
        if read_exact(local, len(SOCKS_GREETING)) != SOCKS_GREETING:
            raise ResolutionPreconnectedError("transparent SOCKS greeting changed")
        protected.sendall(SOCKS_GREETING)
        method = read_exact(protected, len(SOCKS_METHOD))
        if method != SOCKS_METHOD:
            raise ResolutionPreconnectedError("transparent SOCKS method changed")
        local.sendall(method)
        if read_exact(local, len(SOCKS_CONNECT_REQUEST)) != SOCKS_CONNECT_REQUEST:
            raise ResolutionPreconnectedError("transparent SOCKS request changed")
        protected.sendall(SOCKS_CONNECT_REQUEST)
        response = read_exact(protected, len(SOCKS_CONNECT_RESPONSE))
        if response != SOCKS_CONNECT_RESPONSE:
            raise ResolutionPreconnectedError("transparent SOCKS response changed")
        local.sendall(response)
    else:
        raise ResolutionPreconnectedError("transparent proxy protocol is unknown")
    if read_exact(local, len(PROBE)) != PROBE:
        raise ResolutionPreconnectedError("transparent proxy probe changed")
    protected.sendall(PROBE)
    sentinel = read_exact(protected, len(DENIED_SENTINEL))
    if sentinel != DENIED_SENTINEL:
        raise ResolutionPreconnectedError("transparent proxy sentinel changed")
    local.sendall(sentinel)
    if read_exact(local, 1) != b"\x00" or local.recv(1) != b"":
        raise ResolutionPreconnectedError("transparent proxy close marker changed")
    protected.sendall(b"\x00")
    raw = protected.unwrap()
    raw.close()
    local.shutdown(socket.SHUT_WR)


def run_channel_exchange(
    arguments: argparse.Namespace,
    case: ResolutionCase,
    case_root: Path,
    ordinal: int,
    address: str,
    action: str,
    relay_kind: str,
) -> list[str]:
    """Authenticate one session, bind one local channel, and release one child."""

    invocation = case_root / f"invocation-{ordinal:02d}"
    invocation.mkdir(mode=0o755)
    protected, session = open_authenticated(address, address, 443, arguments.allowed_certificate)
    write_new(invocation / "session-observation.json", canonical_json(session))
    parent, child_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    cookie = socket_cookie(child_channel)
    peer = peer_credentials(child_channel)
    output = invocation / "child-output"
    output.mkdir(mode=0o700)
    os.chown(output, 65534, 65534)
    stdout = (invocation / "child.stdout").open("xb")
    stderr = (invocation / "child.stderr").open("xb")
    child: subprocess.Popen[bytes] | None = None
    try:
        child = subprocess.Popen(
            child_command(
                arguments,
                invocation,
                child_channel.fileno(),
                cookie,
                peer,
                action,
            ),
            cwd=arguments.repository_root,
            env=_environment(),
            pass_fds=(child_channel.fileno(),),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
        )
        child_channel.close()
        if relay_kind in {"exact", "redirect-host", "redirect-cleartext", "redirect-port"}:
            _relay_http(parent, protected, relay_kind)
        elif relay_kind in {"http-connect", "socks5"}:
            _relay_proxy(parent, protected, relay_kind)
        else:
            raise ResolutionPreconnectedError("channel relay kind is unknown")
        protected = None  # type: ignore[assignment]
        parent.close()
        try:
            child_exit = child.wait(timeout=case.maximum_seconds)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)
            raise ResolutionPreconnectedError("preconnected child exceeded its deadline")
    finally:
        child_channel.close()
        parent.close()
        if protected is not None:
            protected.close()
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=2)
        stdout.close()
        stderr.close()
    if child_exit != 0 or regular_bytes(output / "started.txt") != b"started\n":
        raise ResolutionPreconnectedError("preconnected child did not complete")
    observation = read_document(output / "observation.json")
    if (
        set(observation) != {"action", "events", "schema", "transcript_sha256"}
        or observation["action"] != action
        or observation["schema"] != CLIENT_SCHEMA
        or not isinstance(observation["events"], list)
        or hashlib.sha256("\n".join(observation["events"]).encode()).hexdigest()
        != observation["transcript_sha256"]
    ):
        raise ResolutionPreconnectedError("preconnected client observation changed")
    return list(observation["events"])


def _service_exchange(
    arguments: argparse.Namespace,
    case: ResolutionCase,
    case_root: Path,
    fixtures: list[StartedFixture],
    ordinal: int,
    address: str,
) -> list[str]:
    fixture = start_http(arguments, case_root / f"service-{ordinal:02d}", address, 443, "exact")
    fixtures.append(fixture)
    events = run_channel_exchange(
        arguments,
        case,
        case_root,
        ordinal,
        address,
        "channel-exact",
        "exact",
    )
    if not stop_fixture(fixture):
        raise ResolutionPreconnectedError("preconnected service fixture cleanup failed")
    return events


def run(arguments: argparse.Namespace) -> dict[str, object]:
    """Execute one preconnected case without reading its expectation."""

    if os.geteuid() != 0:
        raise ResolutionPreconnectedError("preconnected resolution orchestration requires root")
    matrix = load_resolution_matrix(arguments.matrix)
    matches = [item for item in matrix.cases if item.identifier == arguments.case]
    if len(matches) != 1:
        raise ResolutionPreconnectedError("preconnected resolution case is not unique")
    case = matches[0]
    registered_digest = hashlib.sha256(regular_bytes(arguments.registered_resolver)).hexdigest()
    substitute_digest = hashlib.sha256(regular_bytes(arguments.substitute_resolver)).hexdigest()
    arguments.case_root.mkdir(mode=0o755)
    write_new(
        arguments.case_root / "case-plan.json",
        canonical_json(
            case_plan(
                case,
                "preconnected-channel",
                matrix.source_sha256,
                registered_digest,
                substitute_digest,
            )
        ),
    )
    if case.identifier.startswith("ambient-"):
        raw = raw_cell(case, "preconnected-channel", plan_rejection="ambient-environment-present")
        write_new(arguments.raw_output, canonical_json(raw))
        return raw
    if case.identifier == "resolver-configuration-substitution":
        raw = raw_cell(case, "preconnected-channel", prelaunch_rejection="resolver-config-digest-mismatch")
        write_new(arguments.raw_output, canonical_json(raw))
        return raw

    resolver_events: list[dict[str, object]] = []
    network_events: list[str] = []
    fixtures: list[StartedFixture] = []
    client_started = False
    cleanup = True
    try:
        if case.identifier in DNS_PLANS:
            specifications = parameters_for(case.identifier)["queries"]
            if not isinstance(specifications, list):
                raise ResolutionPreconnectedError("connector DNS plan is invalid")
            groups: list[tuple[str, list[dict[str, object]]]] = []
            for specification in specifications:
                if not isinstance(specification, dict):
                    raise ResolutionPreconnectedError("connector DNS query is invalid")
                script = str(specification["script"])
                if groups and groups[-1][0] == script:
                    groups[-1][1].append(specification)
                else:
                    groups.append((script, [specification]))
            for ordinal, (script, queries) in enumerate(groups):
                resolver_events.extend(
                    resolve_group(arguments, arguments.case_root, ordinal, script, queries, True)
                )
            resolved_events = [item for item in resolver_events if item["event"] == "resolved"]
            if case.identifier == "stable-a-and-aaaa" and len(resolved_events) == 2:
                for ordinal, fact in enumerate(resolved_events):
                    network_events.extend(
                        _service_exchange(arguments, case, arguments.case_root, fixtures, ordinal, str(fact["address"]))
                    )
                client_started = True
            elif case.identifier in {"cname-to-declared-service", "resolver-truncated-tcp-fallback"} and len(resolved_events) == 1:
                network_events.extend(
                    _service_exchange(arguments, case, arguments.case_root, fixtures, 0, str(resolved_events[0]["address"]))
                )
                client_started = True
            elif case.identifier == "ttl-rebind-to-undeclared" and resolved_events:
                network_events.extend(
                    _service_exchange(arguments, case, arguments.case_root, fixtures, 0, str(resolved_events[0]["address"]))
                )
                client_started = True
        elif case.identifier.startswith("redirect-"):
            script = {
                "redirect-undeclared-host": "redirect-host",
                "redirect-cleartext": "redirect-cleartext",
                "redirect-other-port": "redirect-port",
            }[case.identifier]
            fixture = start_http(arguments, arguments.case_root / "service-00", "127.0.0.1", 443, script)
            fixtures.append(fixture)
            network_events.extend(
                run_channel_exchange(
                    arguments,
                    case,
                    arguments.case_root,
                    0,
                    "127.0.0.1",
                    f"channel-{script}",
                    script,
                )
            )
            client_started = True
            cleanup = stop_fixture(fixture)
        else:
            protocol = "http-connect" if case.identifier == "http-connect-target-confusion" else "socks5"
            fixture = start_proxy(arguments, arguments.case_root / "proxy-00", "127.0.0.1", protocol)
            fixtures.append(fixture)
            action = "channel-proxy-http" if protocol == "http-connect" else "channel-proxy-socks"
            network_events.extend(
                run_channel_exchange(
                    arguments,
                    case,
                    arguments.case_root,
                    0,
                    "127.0.0.1",
                    action,
                    protocol,
                )
            )
            client_started = True
            cleanup = stop_fixture(fixture)
        service_contacts, service_completions, proxy_contacts, proxy_completions = _fixture_counts(fixtures)
        if case.identifier == "stable-a-and-aaaa" and network_events == [
            "declared-response",
            "declared-response",
        ]:
            network_events = ["declared-response"]
        raw = raw_cell(
            case,
            "preconnected-channel",
            cleanup=cleanup,
            client_started=client_started,
            dns_query_count=sum(len(item["transports"]) for item in resolver_events),
            network_events=network_events,
            proxy_complete_count=proxy_completions,
            proxy_contact_count=proxy_contacts,
            resolver_events=resolver_events,
            service_complete_count=service_completions,
            service_contact_count=service_contacts,
        )
        write_new(arguments.raw_output, canonical_json(raw))
        return raw
    finally:
        for fixture in fixtures:
            if fixture.process.poll() is None:
                fixture.process.kill()
                fixture.process.wait(timeout=2)


def parser() -> argparse.ArgumentParser:
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
    result.add_argument("--registered-resolver", type=Path, required=True)
    result.add_argument("--substitute-resolver", type=Path, required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if (
            not arguments.repository_root.is_absolute()
            or not arguments.matrix.is_absolute()
            or not arguments.case_root.is_absolute()
            or not arguments.raw_output.is_absolute()
            or arguments.raw_output.parent != arguments.case_root
        ):
            raise ResolutionPreconnectedError("preconnected resolution paths are invalid")
        run(arguments)
        return 0
    except (OSError, RecordError, ResolutionPreconnectedError, ValueError) as error:
        print(f"preconnected resolution case failed: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
