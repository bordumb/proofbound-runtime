#!/usr/bin/env python3
"""Run one preconnected-channel case through its native child boundary."""

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import time
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.preconnected_case_client import CASES
from experiments.network_authority.preconnected_channel import (
    ConnectorError,
    authenticated_session,
    relay_session,
)
from experiments.network_authority.record_common import canonical_json, write_new


SO_COOKIE = 57
SO_PEERCRED = 17
PRELAUNCH_FAILURES = {
    "alternate-endpoint-denied-certificate",
    "alternate-endpoint-allowed-certificate",
    "wrong-certificate-denied",
    "plaintext-endpoint-denied",
}
POSITIVE_CASES = {
    "allowed-request",
    "undeclared-path-exposure",
    "connect-shape-exposure",
}


def socket_cookie(channel: socket.socket) -> int:
    """Read one Linux socket identity cookie."""

    raw = channel.getsockopt(socket.SOL_SOCKET, SO_COOKIE, 8)
    if len(raw) != 8:
        raise ConnectorError("socket cookie observation is incomplete")
    result = struct.unpack("=Q", raw)[0]
    if result == 0:
        raise ConnectorError("socket cookie observation is invalid")
    return result


def peer_credentials(channel: socket.socket) -> dict[str, int]:
    """Read one Linux Unix-peer credential observation."""

    raw = channel.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, 12)
    if len(raw) != 12:
        raise ConnectorError("peer credential observation is incomplete")
    pid, uid, gid = struct.unpack("=3i", raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise ConnectorError("peer credential observation is invalid")
    return {"gid": gid, "pid": pid, "uid": uid}


def wait_ready(path: Path, fixture: subprocess.Popen[bytes]) -> None:
    """Wait within a fixed deadline for one new fixture readiness file."""

    for _ in range(100):
        if path.is_file():
            return
        if fixture.poll() is not None:
            break
        time.sleep(0.05)
    raise ConnectorError("preconnected fixture did not become ready")


def fixture_configuration(arguments: argparse.Namespace) -> tuple[str, Path, Path, bool]:
    """Return the frozen fixture address, certificate, key, and plaintext mode."""

    if arguments.case == "alternate-endpoint-denied-certificate":
        return (
            arguments.alternate_endpoint_ip,
            arguments.denied_certificate,
            arguments.denied_private_key,
            False,
        )
    if arguments.case == "alternate-endpoint-allowed-certificate":
        return (
            arguments.alternate_endpoint_ip,
            arguments.allowed_certificate,
            arguments.allowed_private_key,
            False,
        )
    if arguments.case == "wrong-certificate-denied":
        return (
            arguments.allowed_endpoint_ip,
            arguments.denied_certificate,
            arguments.denied_private_key,
            False,
        )
    return (
        arguments.allowed_endpoint_ip,
        arguments.allowed_certificate,
        arguments.allowed_private_key,
        arguments.case == "plaintext-endpoint-denied",
    )


def run(arguments: argparse.Namespace) -> int:
    """Run one exact case and retain orchestration observations."""

    arguments.state_directory.mkdir(mode=0o755)
    ready_file = arguments.state_directory / "fixture.ready"
    fixture_observation = arguments.state_directory / "fixture-observation.txt"
    bind_ip, certificate, private_key, plaintext = fixture_configuration(arguments)
    fixture_command = [
        sys.executable,
        "-m",
        "experiments.network_authority.preconnected_channel",
        "--bind-ip",
        bind_ip,
        "--port",
        str(arguments.endpoint_port),
        "--certificate",
        str(certificate),
        "--private-key",
        str(private_key),
        "--ready-file",
        str(ready_file),
        "--observation-file",
        str(fixture_observation),
    ]
    if plaintext:
        fixture_command.append("--plaintext")

    fixture_stdout = arguments.fixture_stdout.open("xb")
    fixture_stderr = arguments.fixture_stderr.open("xb")
    fixture = subprocess.Popen(
        fixture_command,
        cwd=arguments.repository_root,
        stdin=subprocess.DEVNULL,
        stdout=fixture_stdout,
        stderr=fixture_stderr,
    )
    parent_channel: socket.socket | None = None
    child_channel: socket.socket | None = None
    protected: ssl.SSLSocket | None = None
    child: subprocess.Popen[bytes] | None = None
    pipe_read: int | None = None
    pipe_write: int | None = None
    foreign_descriptor: int | None = None
    case_result = 0
    observation: dict[str, object] = {
        "case": arguments.case,
        "child_started": False,
        "connector_authenticated": False,
        "connector_observation": None,
        "fixture_reaped": False,
        "local_channel": None,
        "orchestration_outcome": "incomplete",
        "relay_observation": None,
        "schema": "proofbound-runtime-network-experiment-preconnected-case/1",
    }
    try:
        wait_ready(ready_file, fixture)
        parent_channel, child_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        parent_cookie = socket_cookie(parent_channel)
        child_cookie = socket_cookie(child_channel)
        child_peer = peer_credentials(child_channel)
        parent_peer = peer_credentials(parent_channel)
        observation["local_channel"] = {
            "child_cookie": child_cookie,
            "child_peer": child_peer,
            "parent_cookie": parent_cookie,
            "parent_peer": parent_peer,
            "type": "unix-stream",
        }

        try:
            protected, connector_observation = authenticated_session(
                bind_ip,
                arguments.allowed_endpoint_ip,
                arguments.endpoint_port,
                "allowed.test",
                arguments.allowed_certificate,
            )
        except (ConnectorError, OSError, ssl.SSLError, ValueError):
            expected = arguments.case in PRELAUNCH_FAILURES
            observation["orchestration_outcome"] = (
                "expected-prelaunch-failure"
                if expected
                else "unexpected-authentication-failure"
            )
            case_result = 7 if expected else 0
        else:
            observation["connector_authenticated"] = True
            observation["connector_observation"] = connector_observation
            if arguments.case in PRELAUNCH_FAILURES:
                observation["orchestration_outcome"] = "unexpected-prelaunch-success"
                case_result = 0
            else:
                retained_descriptor = child_channel.fileno()
                passed_descriptors = [retained_descriptor]
                expected_cookie = child_cookie
                if arguments.case == "wrong-cookie-denied":
                    expected_cookie += 1
                if arguments.case == "non-unix-descriptor-denied":
                    pipe_read, pipe_write = os.pipe()
                    retained_descriptor = pipe_read
                    passed_descriptors = [pipe_read]
                if arguments.case == "foreign-descriptor-denied":
                    foreign_descriptor = os.open("/dev/null", os.O_RDONLY)
                    passed_descriptors.append(foreign_descriptor)

                command = [
                    str(arguments.wrapper),
                    str(retained_descriptor),
                    str(expected_cookie),
                    str(child_peer["pid"]),
                    str(child_peer["uid"]),
                    str(child_peer["gid"]),
                    str(arguments.state_directory / "boundary"),
                    "--",
                    sys.executable,
                    str(arguments.client),
                    "--case",
                    arguments.case,
                    "--fd",
                    str(retained_descriptor),
                    "--started-file",
                    str(arguments.client_started_file),
                ]
                if foreign_descriptor is not None:
                    command.extend(["--foreign-fd", str(foreign_descriptor)])
                child = subprocess.Popen(
                    command,
                    pass_fds=tuple(passed_descriptors),
                    stdin=subprocess.DEVNULL,
                )
                child_channel.close()
                child_channel = None

                relay_observation: dict[str, object] | None = None
                if arguments.case == "connector-crash-denied":
                    parent_channel.close()
                    parent_channel = None
                    protected.close()
                    protected = None
                else:
                    try:
                        relay_observation = relay_session(parent_channel, protected)
                        protected = None
                    except (ConnectorError, OSError, ssl.SSLError):
                        if arguments.case in POSITIVE_CASES:
                            case_result = 7
                    finally:
                        parent_channel.close()
                        parent_channel = None
                observation["relay_observation"] = relay_observation
                try:
                    observed = child.wait(timeout=6)
                    case_result = observed if 0 <= observed <= 255 else 0
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
                    case_result = 0
                observation["child_started"] = arguments.client_started_file.is_file()
                observation["orchestration_outcome"] = "child-complete"

        try:
            fixture_exit = fixture.wait(timeout=5)
        except subprocess.TimeoutExpired:
            fixture.kill()
            fixture.wait(timeout=2)
            fixture_exit = 124
        observation["fixture_exit"] = fixture_exit
        observation["fixture_reaped"] = fixture.poll() is not None
        if arguments.case in POSITIVE_CASES and fixture_exit != 0:
            case_result = 7
        return case_result
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=2)
        for channel in (parent_channel, child_channel, protected):
            if channel is not None:
                channel.close()
        for descriptor in (pipe_read, pipe_write, foreign_descriptor):
            if descriptor is not None:
                os.close(descriptor)
        if fixture.poll() is None:
            fixture.kill()
            fixture.wait(timeout=2)
        observation["fixture_reaped"] = fixture.poll() is not None
        write_new(
            arguments.state_directory / "case-observations.json",
            canonical_json(observation),
        )
        fixture_stdout.close()
        fixture_stderr.close()


def parser() -> argparse.ArgumentParser:
    """Build the closed one-case interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--case", choices=CASES, required=True)
    result.add_argument("--repository-root", type=Path, required=True)
    result.add_argument("--wrapper", type=Path, required=True)
    result.add_argument("--client", type=Path, required=True)
    result.add_argument("--state-directory", type=Path, required=True)
    result.add_argument("--client-started-file", type=Path, required=True)
    result.add_argument("--fixture-stdout", type=Path, required=True)
    result.add_argument("--fixture-stderr", type=Path, required=True)
    result.add_argument("--allowed-endpoint-ip", required=True)
    result.add_argument("--alternate-endpoint-ip", required=True)
    result.add_argument("--endpoint-port", type=int, required=True)
    result.add_argument("--allowed-certificate", type=Path, required=True)
    result.add_argument("--allowed-private-key", type=Path, required=True)
    result.add_argument("--denied-certificate", type=Path, required=True)
    result.add_argument("--denied-private-key", type=Path, required=True)
    return result


def main() -> int:
    """Run one case or return bypass-like zero on orchestration ambiguity."""

    try:
        return run(parser().parse_args())
    except (OSError, ValueError, ConnectorError, subprocess.SubprocessError) as error:
        print(f"preconnected case orchestration failed: {error}", file=sys.stderr)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
