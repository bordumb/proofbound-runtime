#!/usr/bin/env python3
"""Run one experiment 0001H syscall/process bypass case."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.bypass_cell import raw_cell
from experiments.network_authority.bypass_lifecycle_case import case_plan, load_bypass_matrix
from experiments.network_authority.bypass_syscall_probe import ACTIONS, SCHEMA
from experiments.network_authority.record_common import canonical_json, regular_bytes, write_new


SO_COOKIE = 57
SO_PEERCRED = 17


class BypassSyscallOrchestrationError(Exception):
    """One native bypass case failed to publish exact syscall evidence."""


def socket_cookie(channel: socket.socket) -> int:
    raw = channel.getsockopt(socket.SOL_SOCKET, SO_COOKIE, 8)
    if len(raw) != 8 or (value := struct.unpack("=Q", raw)[0]) == 0:
        raise BypassSyscallOrchestrationError("socket cookie is invalid")
    return value


def peer_credentials(channel: socket.socket) -> dict[str, int]:
    raw = channel.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, 12)
    if len(raw) != 12:
        raise BypassSyscallOrchestrationError("peer credentials are incomplete")
    pid, uid, gid = struct.unpack("=3i", raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise BypassSyscallOrchestrationError("peer credentials are invalid")
    return {"gid": gid, "pid": pid, "uid": uid}


def read_document(path: Path) -> dict[str, object]:
    try:
        value = json.loads(regular_bytes(path))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BypassSyscallOrchestrationError("syscall observation is invalid") from error
    if not isinstance(value, dict):
        raise BypassSyscallOrchestrationError("syscall observation is not an object")
    return value


def subject_identities(arguments: argparse.Namespace) -> dict[str, str]:
    paths = {
        "client": arguments.client,
        "process-limit-control": arguments.process_limit_control,
        "child-control": {
            "landlock-port": arguments.routing_child_control,
            "cgroup-endpoint": arguments.routing_child_control,
            "explicit-broker": arguments.broker_child_control,
            "preconnected-channel": arguments.preconnected_child_control,
        }[arguments.mechanism],
    }
    if arguments.mechanism in {"landlock-port", "cgroup-endpoint"}:
        paths["mechanism-control"] = arguments.mechanism_control
    if arguments.case == "concurrent-install-and-connect":
        paths["stopped-release-control"] = arguments.stopped_release_control
    return {name: hashlib.sha256(regular_bytes(path)).hexdigest() for name, path in paths.items()}


def child_command(
    arguments: argparse.Namespace,
    state: Path,
    output: Path,
    retained: socket.socket | None,
) -> list[str]:
    action = arguments.case
    probe = [
        sys.executable, str(arguments.client), "--action", action,
        "--started-file", str(output / "started.txt"),
        "--observation", str(output / "observation.json"),
    ]
    if action == "concurrent-install-and-connect":
        probe.extend(["--address", "127.0.0.2", "--port", "8443"])
    if action == "fork-exec-at-process-limit":
        probe = [str(arguments.process_limit_control), "--", *probe]
    if action == "concurrent-install-and-connect":
        probe = [
            str(arguments.stopped_release_control),
            str(state / "release-sequence"),
            "--",
            *probe,
        ]
    if arguments.mechanism in {"landlock-port", "cgroup-endpoint"}:
        child = [str(arguments.routing_child_control), str(state / "child-boundary"), "--", *probe]
        if arguments.mechanism == "landlock-port":
            return [str(arguments.mechanism_control), "443", str(state / "mechanism"), "--", *child]
        if arguments.cgroup_directory is None:
            raise BypassSyscallOrchestrationError("cgroup attack lacks its exact directory")
        return [
            str(arguments.mechanism_control), str(arguments.cgroup_directory),
            "127.0.0.1", "fd00::1", "443", str(state / "mechanism"), "--", *child,
        ]
    if retained is None:
        raise BypassSyscallOrchestrationError("mediated child lacks its retained channel")
    descriptor = retained.fileno()
    if arguments.mechanism == "explicit-broker":
        return [str(arguments.broker_child_control), str(descriptor), str(state / "child-boundary"), "--", *probe]
    peer = peer_credentials(retained)
    return [
        str(arguments.preconnected_child_control), str(descriptor),
        str(socket_cookie(retained)), str(peer["pid"]), str(peer["uid"]),
        str(peer["gid"]), str(state / "child-boundary"), "--", *probe,
    ]


def run(arguments: argparse.Namespace) -> dict[str, object]:
    if os.geteuid() != 0 or arguments.case not in ACTIONS:
        raise BypassSyscallOrchestrationError("native bypass orchestration requires root and one syscall case")
    matrix = load_bypass_matrix(arguments.matrix)
    matches = [case for case in matrix.cases if case.identifier == arguments.case]
    if len(matches) != 1:
        raise BypassSyscallOrchestrationError("native bypass case is not unique")
    case = matches[0]
    arguments.case_root.mkdir(mode=0o755)
    write_new(arguments.case_root / "case-plan.json", canonical_json(case_plan(case, arguments.mechanism, matrix.source_sha256, arguments.source_commit, subject_identities(arguments))))
    output = arguments.case_root / "child-output"
    output.mkdir(mode=0o700)
    os.chown(output, 65534, 65534)
    if case.identifier == "concurrent-install-and-connect":
        sequence = arguments.case_root / "release-sequence"
        sequence.mkdir(mode=0o700)
        os.chown(sequence, 65534, 65534)
    parent: socket.socket | None = None
    child: socket.socket | None = None
    passed: tuple[int, ...] = ()
    if arguments.mechanism in {"explicit-broker", "preconnected-channel"}:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        passed = (child.fileno(),)
    command = child_command(arguments, arguments.case_root, output, child)
    try:
        completed = subprocess.run(
            command, pass_fds=passed, cwd=arguments.repository_root,
            env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=case.maximum_seconds, check=False,
        )
        write_new(arguments.case_root / "child.stdout", completed.stdout)
        write_new(arguments.case_root / "child.stderr", completed.stderr)
    finally:
        if child is not None:
            child.close()
        if parent is not None:
            parent.close()
    if completed.returncode != 0 or regular_bytes(output / "started.txt") != b"started\n":
        raise BypassSyscallOrchestrationError("native bypass child did not complete")
    observation = read_document(output / "observation.json")
    if set(observation) != {"action", "attempts", "schema"} or observation["action"] != case.identifier or observation["schema"] != SCHEMA or not isinstance(observation["attempts"], list):
        raise BypassSyscallOrchestrationError("native bypass observation changed")
    if case.identifier == "concurrent-install-and-connect":
        attempts = observation["attempts"]
        if (
            attempts
            != [
                {
                    "errno": 1,
                    "result": "error",
                    "syscall": "connect-after-acknowledgement",
                }
            ]
            or regular_bytes(arguments.case_root / "release-sequence/child-stopped.txt")
            != b"child-stopped\n"
            or regular_bytes(
                arguments.case_root / "release-sequence/boundary-acknowledged.txt"
            )
            != b"boundary-acknowledged\n"
        ):
            raise BypassSyscallOrchestrationError("stopped release evidence changed")
        raw = raw_cell(
            case,
            arguments.mechanism,
            events=[
                "child-stopped",
                "boundary-acknowledged",
                "child-released",
                "connect-denied",
            ],
        )
    else:
        raw = raw_cell(case, arguments.mechanism, syscall_attempts=observation["attempts"])
    write_new(arguments.raw_output, canonical_json(raw))
    return raw


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    for name in ("matrix", "case-root", "raw-output", "repository-root", "client", "process-limit-control", "stopped-release-control", "routing-child-control", "broker-child-control", "preconnected-child-control"):
        result.add_argument(f"--{name}", type=Path, required=True)
    result.add_argument("--case", choices=ACTIONS, required=True)
    result.add_argument("--mechanism", required=True)
    result.add_argument("--source-commit", required=True)
    result.add_argument("--mechanism-control", type=Path)
    result.add_argument("--cgroup-directory", type=Path)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        run(arguments)
        return 0
    except (BypassSyscallOrchestrationError, OSError, subprocess.TimeoutExpired, ValueError) as error:
        print(f"native bypass case failed: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
