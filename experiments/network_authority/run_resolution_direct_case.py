#!/usr/bin/env python3
"""Run one experiment 0001G case through mechanism A or B."""

from __future__ import annotations

import argparse
import hashlib
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
from experiments.network_authority.resolution_cell import raw_cell, rejected, resolved
from experiments.network_authority.resolution_indirection_case import (
    DNS_PLANS,
    ResolutionCase,
    case_plan,
    load_resolution_matrix,
    parameters_for,
)
from experiments.network_authority.resolution_indirection_client import resolve_once
from experiments.network_authority.resolution_network_client import SCHEMA as CLIENT_SCHEMA


DIRECT_MECHANISMS = {"landlock-port", "cgroup-endpoint"}
MAX_DOCUMENT_BYTES = 65536


class ResolutionDirectError(Exception):
    """One direct resolution case could not produce closed raw evidence."""


@dataclass(frozen=True)
class StartedFixture:
    root: Path
    process: subprocess.Popen[bytes]
    kind: str


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ResolutionDirectError("resolution document has duplicate names")
        result[key] = value
    return result


def read_document(path: Path) -> dict[str, object]:
    try:
        data = regular_bytes(path)
        if not data or len(data) > MAX_DOCUMENT_BYTES:
            raise ResolutionDirectError("resolution document size is invalid")
        value = json.loads(data, object_pairs_hook=unique_object)
    except (RecordError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ResolutionDirectError("resolution document is invalid") from error
    if not isinstance(value, dict):
        raise ResolutionDirectError("resolution document is not an object")
    return value


def _environment() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0"}


def _wait_ready(path: Path, process: subprocess.Popen[bytes]) -> dict[str, object]:
    for _ in range(100):
        if path.is_file():
            return read_document(path)
        if process.poll() is not None:
            break
        time.sleep(0.05)
    raise ResolutionDirectError("resolution fixture did not become ready")


def _start(
    command: list[str], root: Path, kind: str, repository_root: Path
) -> StartedFixture:
    root.mkdir(mode=0o755)
    stdout = (root / "fixture.stdout").open("xb")
    stderr = (root / "fixture.stderr").open("xb")
    try:
        process = subprocess.Popen(
            command,
            cwd=repository_root,
            env=_environment(),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
        )
    finally:
        stdout.close()
        stderr.close()
    return StartedFixture(root, process, kind)


def start_dns(
    arguments: argparse.Namespace,
    root: Path,
    script: str,
    maximum_queries: int,
) -> tuple[StartedFixture, int]:
    ready = root / "ready.json"
    fixture = _start(
        [
            sys.executable,
            "-m",
            "experiments.network_authority.scripted_dns",
            "--bind-ip",
            "127.0.0.1",
            "--port",
            "0",
            "--script",
            script,
            "--maximum-queries",
            str(maximum_queries),
            "--ready-file",
            str(ready),
            "--transcript-file",
            str(root / "transcript.json"),
        ],
        root,
        "dns",
        arguments.repository_root,
    )
    document = _wait_ready(ready, fixture.process)
    if (
        set(document) != {"address", "port", "schema"}
        or document["address"] != "127.0.0.1"
        or document["schema"] != "proofbound-runtime-scripted-dns-ready/1"
        or type(document["port"]) is not int
    ):
        raise ResolutionDirectError("DNS readiness identity changed")
    return fixture, int(document["port"])


def start_http(
    arguments: argparse.Namespace,
    root: Path,
    address: str,
    port: int,
    script: str,
) -> StartedFixture:
    ready = root / "ready.json"
    fixture = _start(
        [
            sys.executable,
            "-m",
            "experiments.network_authority.decision_http_fixture",
            "--bind-ip",
            address,
            "--port",
            str(port),
            "--script",
            script,
            "--certificate",
            str(arguments.allowed_certificate),
            "--private-key",
            str(arguments.allowed_private_key),
            "--ready-file",
            str(ready),
            "--contact-file",
            str(root / "contact.json"),
            "--observation-file",
            str(root / "observation.json"),
        ],
        root,
        "service",
        arguments.repository_root,
    )
    document = _wait_ready(ready, fixture.process)
    family = "ipv6" if ":" in address else "ipv4"
    if document != {
        "address": address,
        "family": family,
        "port": port,
        "schema": "proofbound-runtime-decision-http-ready/1",
    }:
        raise ResolutionDirectError("HTTP readiness identity changed")
    return fixture


def start_proxy(
    arguments: argparse.Namespace,
    root: Path,
    address: str,
    protocol: str,
) -> StartedFixture:
    ready = root / "ready.json"
    fixture = _start(
        [
            sys.executable,
            "-m",
            "experiments.network_authority.decision_proxy_fixture",
            "--bind-ip",
            address,
            "--port",
            "443",
            "--script",
            protocol,
            "--certificate",
            str(arguments.allowed_certificate),
            "--private-key",
            str(arguments.allowed_private_key),
            "--ready-file",
            str(ready),
            "--contact-file",
            str(root / "contact.json"),
            "--observation-file",
            str(root / "observation.json"),
        ],
        root,
        "proxy",
        arguments.repository_root,
    )
    document = _wait_ready(ready, fixture.process)
    if document != {
        "address": address,
        "family": "ipv4",
        "port": 443,
        "schema": "proofbound-runtime-decision-proxy-ready/1",
    }:
        raise ResolutionDirectError("proxy readiness identity changed")
    return fixture


def stop_fixture(fixture: StartedFixture) -> bool:
    contacted = (fixture.root / "contact.json").is_file()
    if fixture.kind == "dns":
        contacted = True
    if fixture.process.poll() is None:
        if contacted:
            try:
                fixture.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                return False
        else:
            fixture.process.send_signal(signal.SIGTERM)
            try:
                fixture.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                fixture.process.kill()
                fixture.process.wait(timeout=2)
                return False
    return fixture.process.poll() is not None


def boundary_command(
    arguments: argparse.Namespace,
    invocation_root: Path,
    action: str,
    address: str,
    port: int,
) -> list[str]:
    output = invocation_root / "child-output"
    child = [
        str(arguments.child_control),
        str(invocation_root / "child-boundary"),
        "--",
        sys.executable,
        str(arguments.client),
        "--action",
        action,
        "--address",
        address,
        "--port",
        str(port),
        "--ca-certificate",
        str(arguments.allowed_certificate),
        "--started-file",
        str(output / "started.txt"),
        "--observation",
        str(output / "observation.json"),
    ]
    if arguments.mechanism == "landlock-port":
        return [
            str(arguments.mechanism_control),
            "443",
            str(invocation_root / "mechanism-state"),
            "--",
            *child,
        ]
    if arguments.mechanism == "cgroup-endpoint" and arguments.cgroup_directory is not None:
        return [
            str(arguments.mechanism_control),
            str(arguments.cgroup_directory),
            "127.0.0.1",
            "fd00::1",
            "443",
            str(invocation_root / "mechanism-state"),
            "--",
            *child,
        ]
    raise ResolutionDirectError("direct boundary configuration is incomplete")


def run_network(
    arguments: argparse.Namespace,
    case: ResolutionCase,
    case_root: Path,
    ordinal: int,
    action: str,
    address: str,
    port: int,
) -> list[str]:
    invocation = case_root / f"invocation-{ordinal:02d}"
    invocation.mkdir(mode=0o755)
    output = invocation / "child-output"
    output.mkdir(mode=0o700)
    os.chown(output, 65534, 65534)
    stdout = (invocation / "child.stdout").open("xb")
    stderr = (invocation / "child.stderr").open("xb")
    try:
        try:
            completed = subprocess.run(
                boundary_command(arguments, invocation, action, address, port),
                cwd=arguments.repository_root,
                env=_environment(),
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                check=False,
                timeout=case.maximum_seconds,
            )
            exit_code = completed.returncode
        except subprocess.TimeoutExpired:
            exit_code = 124
    finally:
        stdout.close()
        stderr.close()
    started = output / "started.txt"
    observation_path = output / "observation.json"
    if (
        exit_code != 0
        or not started.is_file()
        or regular_bytes(started) != b"started\n"
        or not observation_path.is_file()
    ):
        raise ResolutionDirectError("boundary client did not publish a complete observation")
    observation = read_document(observation_path)
    if (
        set(observation) != {"action", "events", "schema", "transcript_sha256"}
        or observation["action"] != action
        or observation["schema"] != CLIENT_SCHEMA
        or not isinstance(observation["events"], list)
        or hashlib.sha256("\n".join(observation["events"]).encode()).hexdigest()
        != observation["transcript_sha256"]
    ):
        raise ResolutionDirectError("boundary client observation identity changed")
    return list(observation["events"])


def resolution_fact(observation: dict[str, object]) -> dict[str, object]:
    responses = observation.get("responses")
    if not isinstance(responses, list):
        raise ResolutionDirectError("resolver response inventory is absent")
    transports = [item.get("transport") for item in responses if isinstance(item, dict)]
    if not transports and observation.get("reason") == "timeout":
        transports = ["udp"]
    if observation.get("event") == "resolved":
        return resolved(
            str(observation.get("address")),
            str(observation.get("terminal_name")),
            *transports,
        )
    if observation.get("event") == "resolver-rejected" and isinstance(observation.get("reason"), str):
        return rejected(str(observation["reason"]), *transports)
    raise ResolutionDirectError("resolver observation cannot produce one fact")


def resolve_group(
    arguments: argparse.Namespace,
    case_root: Path,
    group_ordinal: int,
    script: str,
    query_specs: list[dict[str, object]],
    require_declared: bool,
) -> list[dict[str, object]]:
    maximum_queries = len(query_specs) + (1 if script == "truncated-fallback" else 0)
    fixture, port = start_dns(arguments, case_root / f"dns-{group_ordinal:02d}", script, maximum_queries)
    facts: list[dict[str, object]] = []
    try:
        for index, query in enumerate(query_specs):
            if script == "rebind" and index > 0:
                time.sleep(1)
            observation = resolve_once(
                "127.0.0.1",
                port,
                str(query["name"]),
                int(query["question_type"]),
                int(query["identifier"]),
                allow_cname=script.startswith("cname-"),
                require_declared=require_declared,
                allow_tcp_fallback=script == "truncated-fallback",
                timeout_seconds=0.25 if script == "timeout" else 1.0,
            )
            write_new(
                fixture.root / f"resolution-{index:02d}.json",
                canonical_json(observation),
            )
            facts.append(resolution_fact(observation))
        if not stop_fixture(fixture):
            raise ResolutionDirectError("DNS fixture cleanup failed")
    finally:
        if fixture.process.poll() is None:
            fixture.process.kill()
            fixture.process.wait(timeout=2)
    return facts


def _fixture_counts(fixtures: list[StartedFixture]) -> tuple[int, int, int, int]:
    service = [item for item in fixtures if item.kind == "service"]
    proxies = [item for item in fixtures if item.kind == "proxy"]
    return (
        sum((item.root / "contact.json").is_file() for item in service),
        sum((item.root / "observation.json").is_file() for item in service),
        sum((item.root / "contact.json").is_file() for item in proxies),
        sum((item.root / "observation.json").is_file() for item in proxies),
    )


def _service_action(
    arguments: argparse.Namespace,
    case: ResolutionCase,
    case_root: Path,
    fixtures: list[StartedFixture],
    ordinal: int,
    action: str,
    address: str,
    port: int,
    script: str,
) -> list[str]:
    fixture = start_http(arguments, case_root / f"service-{ordinal:02d}", address, port, script)
    fixtures.append(fixture)
    events = run_network(arguments, case, case_root, ordinal, action, address, port)
    if not stop_fixture(fixture):
        raise ResolutionDirectError("service fixture cleanup failed")
    return events


def run(arguments: argparse.Namespace) -> dict[str, object]:
    """Execute one direct case without consulting its expected outcome."""

    if arguments.mechanism not in DIRECT_MECHANISMS or os.geteuid() != 0:
        raise ResolutionDirectError("direct resolution orchestration requires a root mechanism")
    matrix = load_resolution_matrix(arguments.matrix)
    matches = [item for item in matrix.cases if item.identifier == arguments.case]
    if len(matches) != 1:
        raise ResolutionDirectError("resolution case identity is not unique")
    case = matches[0]
    registered = regular_bytes(arguments.registered_resolver)
    substitute = regular_bytes(arguments.substitute_resolver)
    registered_digest = hashlib.sha256(registered).hexdigest()
    substitute_digest = hashlib.sha256(substitute).hexdigest()
    arguments.case_root.mkdir(mode=0o755)
    write_new(
        arguments.case_root / "case-plan.json",
        canonical_json(
            case_plan(
                case,
                arguments.mechanism,
                matrix.source_sha256,
                registered_digest,
                substitute_digest,
            )
        ),
    )
    if case.identifier == "resolver-configuration-substitution" and arguments.mechanism == "cgroup-endpoint":
        raw = raw_cell(case, arguments.mechanism, prelaunch_rejection="resolver-config-digest-mismatch")
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
                raise ResolutionDirectError("DNS query plan is invalid")
            groups: list[tuple[str, list[dict[str, object]]]] = []
            for specification in specifications:
                if not isinstance(specification, dict):
                    raise ResolutionDirectError("DNS query specification is invalid")
                script = str(specification["script"])
                if groups and groups[-1][0] == script:
                    groups[-1][1].append(specification)
                else:
                    groups.append((script, [specification]))
            require_declared = case.identifier not in {
                "ttl-rebind-to-undeclared",
                "cname-to-undeclared-service",
                "resolver-configuration-substitution",
            }
            for ordinal, (script, queries) in enumerate(groups):
                resolver_events.extend(
                    resolve_group(arguments, arguments.case_root, ordinal, script, queries, require_declared)
                )
            if all(item["event"] == "resolved" for item in resolver_events):
                if case.identifier == "stable-a-and-aaaa":
                    for ordinal, fact in enumerate(resolver_events):
                        network_events.extend(
                            _service_action(
                                arguments, case, arguments.case_root, fixtures, ordinal,
                                "exact", str(fact["address"]), 443, "exact",
                            )
                        )
                        client_started = True
                elif case.identifier in {"cname-to-declared-service", "resolver-truncated-tcp-fallback"}:
                    network_events.extend(
                        _service_action(
                            arguments, case, arguments.case_root, fixtures, 0,
                            "exact", str(resolver_events[0]["address"]), 443, "exact",
                        )
                    )
                    client_started = True
                elif case.identifier in {
                    "cname-to-undeclared-service",
                    "resolver-configuration-substitution",
                }:
                    network_events.extend(
                        _service_action(
                            arguments, case, arguments.case_root, fixtures, 0,
                            "raw-contact", str(resolver_events[-1]["address"]), 443, "exact",
                        )
                    )
                    client_started = True
                elif case.identifier == "ttl-rebind-to-undeclared":
                    network_events.extend(
                        _service_action(
                            arguments, case, arguments.case_root, fixtures, 0,
                            "exact", str(resolver_events[0]["address"]), 443, "exact",
                        )
                    )
                    network_events.extend(
                        _service_action(
                            arguments, case, arguments.case_root, fixtures, 1,
                            "raw-contact", str(resolver_events[1]["address"]), 443, "exact",
                        )
                    )
                    client_started = True
        elif case.identifier.startswith("redirect-"):
            primary = start_http(
                arguments,
                arguments.case_root / "service-00",
                "127.0.0.1",
                443,
                {
                    "redirect-undeclared-host": "redirect-host",
                    "redirect-cleartext": "redirect-cleartext",
                    "redirect-other-port": "redirect-port",
                }[case.identifier],
            )
            follow_address, follow_port = {
                "redirect-undeclared-host": ("127.0.0.2", 443),
                "redirect-cleartext": ("127.0.0.1", 80),
                "redirect-other-port": ("127.0.0.1", 8443),
            }[case.identifier]
            follow = start_http(
                arguments,
                arguments.case_root / "service-01",
                follow_address,
                follow_port,
                "exact",
            )
            fixtures.extend([primary, follow])
            network_events.extend(
                run_network(
                    arguments,
                    case,
                    arguments.case_root,
                    0,
                    {
                        "redirect-undeclared-host": "redirect-host",
                        "redirect-cleartext": "redirect-cleartext",
                        "redirect-other-port": "redirect-port",
                    }[case.identifier],
                    "127.0.0.1",
                    443,
                )
            )
            client_started = True
            cleanup = stop_fixture(primary) and stop_fixture(follow)
        else:
            protocol = "http-connect" if case.identifier != "socks-target-confusion" else "socks5"
            ambient = case.identifier.startswith("ambient-")
            address = "127.0.0.2" if ambient else "127.0.0.1"
            fixture = start_proxy(arguments, arguments.case_root / "proxy-00", address, protocol)
            fixtures.append(fixture)
            action = "proxy-socks" if protocol == "socks5" else "proxy-http"
            network_events.extend(
                run_network(arguments, case, arguments.case_root, 0, action, address, 443)
            )
            if ambient and network_events == ["proxy-target-reached"]:
                network_events = ["ambient-proxy-contact"]
            client_started = True
            cleanup = stop_fixture(fixture)
        if arguments.mechanism == "cgroup-endpoint" and arguments.cgroup_directory is not None:
            try:
                arguments.cgroup_directory.rmdir()
            except OSError:
                cleanup = False
        service_contacts, service_completions, proxy_contacts, proxy_completions = _fixture_counts(fixtures)
        raw = raw_cell(
            case,
            arguments.mechanism,
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
    result.add_argument("--registered-resolver", type=Path, required=True)
    result.add_argument("--substitute-resolver", type=Path, required=True)
    result.add_argument("--cgroup-directory", type=Path)
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
            raise ResolutionDirectError("direct resolution paths are invalid")
        run(arguments)
        return 0
    except (OSError, RecordError, ResolutionDirectError, ValueError) as error:
        print(f"direct resolution case failed: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
