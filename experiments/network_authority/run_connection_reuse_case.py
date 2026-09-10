#!/usr/bin/env python3
"""Run the experiment 0001H connection-count case through one mechanism."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import struct
import sys
import threading
import time
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.bypass_cell import raw_cell
from experiments.network_authority.bypass_lifecycle_case import case_plan, load_bypass_matrix
from experiments.network_authority.connection_reuse_channel import broker_server, channel_server
from experiments.network_authority.connection_reuse_client import SCHEMA
from experiments.network_authority.record_common import canonical_json, regular_bytes, write_new


SO_COOKIE = 57
SO_PEERCRED = 17


class ReuseOrchestrationError(Exception):
    """The connection-count case did not produce closed evidence."""


def socket_cookie(channel: socket.socket) -> int:
    raw = channel.getsockopt(socket.SOL_SOCKET, SO_COOKIE, 8)
    if len(raw) != 8 or (value := struct.unpack("=Q", raw)[0]) == 0:
        raise ReuseOrchestrationError("reuse socket cookie is invalid")
    return value


def peer_credentials(channel: socket.socket) -> dict[str, int]:
    raw = channel.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, 12)
    if len(raw) != 12:
        raise ReuseOrchestrationError("reuse peer credentials are incomplete")
    pid, uid, gid = struct.unpack("=3i", raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise ReuseOrchestrationError("reuse peer credentials are invalid")
    return {"gid": gid, "pid": pid, "uid": uid}


def document(path: Path) -> dict[str, object]:
    try:
        value = json.loads(regular_bytes(path))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReuseOrchestrationError("reuse document is invalid") from error
    if not isinstance(value, dict):
        raise ReuseOrchestrationError("reuse document is not an object")
    return value


def wait_ready(path: Path, process: subprocess.Popen[bytes]) -> dict[str, object]:
    for _ in range(100):
        if path.is_file():
            return document(path)
        if process.poll() is not None:
            break
        time.sleep(0.05)
    raise ReuseOrchestrationError("reuse fixture did not become ready")


def child_command(arguments: argparse.Namespace, output: Path, child: socket.socket | None) -> list[str]:
    action = {"landlock-port": "direct", "cgroup-endpoint": "direct", "explicit-broker": "broker", "preconnected-channel": "channel"}[arguments.mechanism]
    client = [sys.executable, str(arguments.client), "--action", action, "--started-file", str(output / "started.txt"), "--observation", str(output / "observation.json")]
    if action == "direct":
        client.extend(["--address", "127.0.0.1", "--port", "443"])
        wrapped = [str(arguments.routing_child_control), str(arguments.case_root / "child-boundary"), "--", *client]
        if arguments.mechanism == "landlock-port":
            return [str(arguments.mechanism_control), "443", str(arguments.case_root / "mechanism"), "--", *wrapped]
        if arguments.cgroup_directory is None:
            raise ReuseOrchestrationError("reuse cgroup directory is absent")
        return [str(arguments.mechanism_control), str(arguments.cgroup_directory), "127.0.0.1", "fd00::1", "443", str(arguments.case_root / "mechanism"), "--", *wrapped]
    if child is None:
        raise ReuseOrchestrationError("reuse channel is absent")
    descriptor = child.fileno()
    client.extend(["--fd", str(descriptor)])
    if action == "broker":
        return [str(arguments.broker_child_control), str(descriptor), str(arguments.case_root / "child-boundary"), "--", *client]
    peer = peer_credentials(child)
    return [str(arguments.preconnected_child_control), str(descriptor), str(socket_cookie(child)), str(peer["pid"]), str(peer["uid"]), str(peer["gid"]), str(arguments.case_root / "child-boundary"), "--", *client]


def run(arguments: argparse.Namespace) -> dict[str, object]:
    if os.geteuid() != 0:
        raise ReuseOrchestrationError("connection reuse orchestration requires root")
    matrix = load_bypass_matrix(arguments.matrix)
    case = next((item for item in matrix.cases if item.identifier == "connection-reuse-beyond-count"), None)
    if case is None:
        raise ReuseOrchestrationError("connection reuse case is absent")
    controls = {"client": arguments.client, "routing-child": arguments.routing_child_control, "broker-child": arguments.broker_child_control, "preconnected-child": arguments.preconnected_child_control}
    if arguments.mechanism in {"landlock-port", "cgroup-endpoint"}:
        controls["mechanism-control"] = arguments.mechanism_control
        controls["fixture"] = arguments.fixture
    identities = {name: hashlib.sha256(regular_bytes(path)).hexdigest() for name, path in controls.items()}
    arguments.case_root.mkdir(mode=0o755)
    write_new(arguments.case_root / "case-plan.json", canonical_json(case_plan(case, arguments.mechanism, matrix.source_sha256, identities)))
    output = arguments.case_root / "child-output"
    output.mkdir(mode=0o700)
    os.chown(output, 65534, 65534)
    parent: socket.socket | None = None
    child: socket.socket | None = None
    server_events: list[list[str]] = []
    server_errors: list[BaseException] = []
    server_thread: threading.Thread | None = None
    fixture: subprocess.Popen[bytes] | None = None
    if arguments.mechanism in {"landlock-port", "cgroup-endpoint"}:
        fixture = subprocess.Popen([sys.executable, str(arguments.fixture), "--address", "127.0.0.1", "--port", "443", "--ready-file", str(arguments.case_root / "fixture-ready.json"), "--observation-file", str(arguments.case_root / "fixture-observation.json")], cwd=arguments.repository_root, env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0"}, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ready = wait_ready(arguments.case_root / "fixture-ready.json", fixture)
        if ready.get("port") != 443:
            raise ReuseOrchestrationError("reuse fixture endpoint changed")
    else:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        server = broker_server if arguments.mechanism == "explicit-broker" else channel_server

        def target() -> None:
            try:
                server_events.append(server(parent.detach()))
            except BaseException as error:
                server_errors.append(error)

        server_thread = threading.Thread(target=target)
        server_thread.start()
    command = child_command(arguments, output, child)
    passed = () if child is None else (child.fileno(),)
    try:
        completed = subprocess.run(command, pass_fds=passed, cwd=arguments.repository_root, env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0"}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=case.maximum_seconds, check=False)
    finally:
        if child is not None:
            child.close()
        if server_thread is not None:
            server_thread.join(timeout=2)
        if fixture is not None:
            fixture.wait(timeout=2)
    write_new(arguments.case_root / "child.stdout", completed.stdout)
    write_new(arguments.case_root / "child.stderr", completed.stderr)
    if completed.returncode != 0 or server_errors or (server_thread is not None and server_thread.is_alive()) or (fixture is not None and fixture.returncode != 0):
        raise ReuseOrchestrationError("reuse participants did not complete")
    observation = document(output / "observation.json")
    if set(observation) != {"action", "events", "schema", "transcript_sha256"} or observation["schema"] != SCHEMA or not isinstance(observation["events"], list):
        raise ReuseOrchestrationError("reuse client observation changed")
    events = list(observation["events"])
    if server_events and server_events != [events]:
        raise ReuseOrchestrationError("reuse peers disagree")
    raw = raw_cell(case, arguments.mechanism, connection_count=2 if arguments.mechanism in {"landlock-port", "cgroup-endpoint"} else 1, events=events)
    write_new(arguments.raw_output, canonical_json(raw))
    return raw


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    for name in ("repository-root", "matrix", "case-root", "raw-output", "client", "fixture", "routing-child-control", "broker-child-control", "preconnected-child-control"):
        result.add_argument(f"--{name}", type=Path, required=True)
    result.add_argument("--mechanism", required=True)
    result.add_argument("--mechanism-control", type=Path)
    result.add_argument("--cgroup-directory", type=Path)
    return result


def main() -> int:
    try:
        run(parser().parse_args())
        return 0
    except (OSError, ReuseOrchestrationError, subprocess.TimeoutExpired, ValueError) as error:
        print(f"connection reuse case failed: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
