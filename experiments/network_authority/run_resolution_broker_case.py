#!/usr/bin/env python3
"""Run one experiment 0001G case through the explicit operation broker."""

from __future__ import annotations

import argparse
import hashlib
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
from experiments.network_authority.resolution_broker import SCHEMA as BROKER_SCHEMA
from experiments.network_authority.resolution_cell import raw_cell
from experiments.network_authority.resolution_indirection_case import (
    DNS_PLANS,
    ResolutionCase,
    case_plan,
    load_resolution_matrix,
    parameters_for,
)
from experiments.network_authority.resolution_network_client import SCHEMA as CLIENT_SCHEMA
from experiments.network_authority.run_resolution_direct_case import (
    ResolutionDirectError,
    StartedFixture,
    _fixture_counts,
    read_document,
    resolve_group,
    resolve_rebind_sequence,
    start_http,
    stop_fixture,
)


class ResolutionBrokerOrchestrationError(Exception):
    """One broker case could not produce closed raw evidence."""


def _environment() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0"}


def child_command(
    arguments: argparse.Namespace,
    invocation: Path,
    descriptor: int,
    action: str,
) -> list[str]:
    output = invocation / "child-output"
    return [
        str(arguments.child_control),
        str(descriptor),
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


def broker_command(
    arguments: argparse.Namespace,
    invocation: Path,
    descriptor: int,
    mode: str,
    redirect_script: str | None,
    address: str,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "experiments.network_authority.resolution_broker",
        "--fd",
        str(descriptor),
        "--mode",
        mode,
        "--address",
        address,
        "--port",
        "443",
        "--ca-certificate",
        str(arguments.allowed_certificate),
        "--marker",
        str(invocation / "broker-observation.json"),
        "--session-observation",
        str(invocation / "session-observation.json"),
    ]
    if redirect_script is not None:
        command.extend(["--redirect-script", redirect_script])
    return command


def run_broker_exchange(
    arguments: argparse.Namespace,
    case: ResolutionCase,
    case_root: Path,
    ordinal: int,
    mode: str,
    action: str,
    address: str = "127.0.0.1",
    redirect_script: str | None = None,
) -> list[str]:
    """Run one isolated child/broker exchange and validate both records."""

    invocation = case_root / f"invocation-{ordinal:02d}"
    invocation.mkdir(mode=0o755)
    output = invocation / "child-output"
    output.mkdir(mode=0o700)
    os.chown(output, 65534, 65534)
    broker_channel, child_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    broker_stdout = (invocation / "broker.stdout").open("xb")
    broker_stderr = (invocation / "broker.stderr").open("xb")
    child_stdout = (invocation / "child.stdout").open("xb")
    child_stderr = (invocation / "child.stderr").open("xb")
    broker: subprocess.Popen[bytes] | None = None
    child: subprocess.Popen[bytes] | None = None
    try:
        broker = subprocess.Popen(
            broker_command(
                arguments,
                invocation,
                broker_channel.fileno(),
                mode,
                redirect_script,
                address,
            ),
            cwd=arguments.repository_root,
            env=_environment(),
            pass_fds=(broker_channel.fileno(),),
            stdin=subprocess.DEVNULL,
            stdout=broker_stdout,
            stderr=broker_stderr,
        )
        child = subprocess.Popen(
            child_command(arguments, invocation, child_channel.fileno(), action),
            cwd=arguments.repository_root,
            env=_environment(),
            pass_fds=(child_channel.fileno(),),
            stdin=subprocess.DEVNULL,
            stdout=child_stdout,
            stderr=child_stderr,
        )
        broker_channel.close()
        child_channel.close()
        try:
            child_exit = child.wait(timeout=case.maximum_seconds)
            broker_exit = broker.wait(timeout=2)
        except subprocess.TimeoutExpired:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=2)
            if broker.poll() is None:
                broker.kill()
                broker.wait(timeout=2)
            raise ResolutionBrokerOrchestrationError("broker exchange exceeded its deadline")
    finally:
        broker_channel.close()
        child_channel.close()
        broker_stdout.close()
        broker_stderr.close()
        child_stdout.close()
        child_stderr.close()
    if child_exit != 0 or broker_exit != 0:
        raise ResolutionBrokerOrchestrationError("broker or child did not complete")
    if regular_bytes(output / "started.txt") != b"started\n":
        raise ResolutionBrokerOrchestrationError("broker child start marker is invalid")
    client = read_document(output / "observation.json")
    marker = read_document(invocation / "broker-observation.json")
    expected_marker = {
        "exact": {"code": None, "event": "exact-response", "schema": BROKER_SCHEMA},
        "redirect-reject": {"code": "redirect-rejected", "event": "rejected", "schema": BROKER_SCHEMA},
        "proxy-reject": {"code": "proxy-target-rejected", "event": "rejected", "schema": BROKER_SCHEMA},
    }[mode]
    if marker != expected_marker:
        raise ResolutionBrokerOrchestrationError("broker observation identity changed")
    if (
        set(client) != {"action", "events", "schema", "transcript_sha256"}
        or client["action"] != action
        or client["schema"] != CLIENT_SCHEMA
        or not isinstance(client["events"], list)
        or hashlib.sha256("\n".join(client["events"]).encode()).hexdigest()
        != client["transcript_sha256"]
    ):
        raise ResolutionBrokerOrchestrationError("broker client observation changed")
    return list(client["events"])


def _service_exchange(
    arguments: argparse.Namespace,
    case: ResolutionCase,
    case_root: Path,
    fixtures: list[StartedFixture],
    ordinal: int,
    address: str,
) -> list[str]:
    fixture = start_http(
        arguments,
        case_root / f"service-{ordinal:02d}",
        address,
        443,
        "exact",
    )
    fixtures.append(fixture)
    events = run_broker_exchange(
        arguments, case, case_root, ordinal, "exact", "broker-exact", address
    )
    if not stop_fixture(fixture):
        raise ResolutionBrokerOrchestrationError("broker service fixture cleanup failed")
    return events


def run(arguments: argparse.Namespace) -> dict[str, object]:
    """Execute one broker case without reading its registered expectation."""

    if os.geteuid() != 0:
        raise ResolutionBrokerOrchestrationError("broker resolution orchestration requires root")
    matrix = load_resolution_matrix(arguments.matrix)
    matches = [item for item in matrix.cases if item.identifier == arguments.case]
    if len(matches) != 1:
        raise ResolutionBrokerOrchestrationError("broker resolution case is not unique")
    case = matches[0]
    registered_digest = hashlib.sha256(regular_bytes(arguments.registered_resolver)).hexdigest()
    substitute_digest = hashlib.sha256(regular_bytes(arguments.substitute_resolver)).hexdigest()
    arguments.case_root.mkdir(mode=0o755)
    write_new(
        arguments.case_root / "case-plan.json",
        canonical_json(
            case_plan(
                case,
                "explicit-broker",
                matrix.source_sha256,
                registered_digest,
                substitute_digest,
            )
        ),
    )
    if case.identifier.startswith("ambient-"):
        raw = raw_cell(case, "explicit-broker", plan_rejection="ambient-environment-present")
        write_new(arguments.raw_output, canonical_json(raw))
        return raw
    if case.identifier == "resolver-configuration-substitution":
        raw = raw_cell(case, "explicit-broker", prelaunch_rejection="resolver-config-digest-mismatch")
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
                raise ResolutionBrokerOrchestrationError("broker DNS plan is invalid")
            if case.identifier == "ttl-rebind-to-undeclared":
                resolver_events, first_events = resolve_rebind_sequence(
                    arguments,
                    arguments.case_root,
                    specifications,
                    True,
                    lambda fact: _service_exchange(
                        arguments,
                        case,
                        arguments.case_root,
                        fixtures,
                        0,
                        str(fact["address"]),
                    ),
                )
                network_events.extend(first_events)
                client_started = True
            groups: list[tuple[str, list[dict[str, object]]]] = []
            for specification in specifications:
                if not isinstance(specification, dict):
                    raise ResolutionBrokerOrchestrationError("broker DNS query is invalid")
                script = str(specification["script"])
                if groups and groups[-1][0] == script:
                    groups[-1][1].append(specification)
                else:
                    groups.append((script, [specification]))
            if case.identifier != "ttl-rebind-to-undeclared":
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
        elif case.identifier.startswith("redirect-"):
            script = {
                "redirect-undeclared-host": "redirect-host",
                "redirect-cleartext": "redirect-cleartext",
                "redirect-other-port": "redirect-port",
            }[case.identifier]
            fixture = start_http(arguments, arguments.case_root / "service-00", "127.0.0.1", 443, script)
            fixtures.append(fixture)
            network_events.extend(
                run_broker_exchange(
                    arguments,
                    case,
                    arguments.case_root,
                    0,
                    "redirect-reject",
                    "broker-redirect-rejected",
                    "127.0.0.1",
                    script,
                )
            )
            client_started = True
            cleanup = stop_fixture(fixture)
        else:
            network_events.extend(
                run_broker_exchange(
                    arguments,
                    case,
                    arguments.case_root,
                    0,
                    "proxy-reject",
                    "broker-proxy-rejected",
                )
            )
            client_started = True
        service_contacts, service_completions, proxy_contacts, proxy_completions = _fixture_counts(fixtures)
        if case.identifier == "stable-a-and-aaaa" and network_events == [
            "declared-response",
            "declared-response",
        ]:
            network_events = ["declared-response"]
        raw = raw_cell(
            case,
            "explicit-broker",
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
            raise ResolutionBrokerOrchestrationError("broker resolution paths are invalid")
        run(arguments)
        return 0
    except (
        OSError,
        RecordError,
        ResolutionBrokerOrchestrationError,
        ResolutionDirectError,
        ValueError,
    ) as error:
        print(f"broker resolution case failed: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
