#!/usr/bin/env python3
"""Raw syscall observer for experiment 0001H bypass cases."""

from __future__ import annotations

import argparse
import ctypes
import os
import socket
import sys
from collections.abc import Callable
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.record_common import canonical_json, write_new


SCHEMA = "proofbound-runtime-bypass-syscall-observation/1"
ACTIONS = (
    "pathname-unix-socket",
    "abstract-unix-socket",
    "inherited-connected-internet-socket",
    "io-uring-socket-create-connect",
    "io-uring-descriptor-send",
    "raw-and-packet-sockets",
)


class BypassProbeError(Exception):
    """A syscall probe could not publish a closed observation."""


def observe(name: str, operation: Callable[[], object]) -> dict[str, object]:
    """Invoke one operation and retain success or the exact native errno."""

    try:
        value = operation()
    except OSError as error:
        return {"errno": error.errno, "result": "error", "syscall": name}
    if isinstance(value, socket.socket):
        value.close()
    return {"errno": None, "result": "success", "syscall": name}


def io_uring_setup() -> int:
    """Issue the real io_uring_setup syscall with a deliberately null params pointer."""

    library = ctypes.CDLL(None, use_errno=True)
    result = library.syscall(425, 2, ctypes.c_void_p())
    if result < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    os.close(result)
    return result


def execute(action: str, inherited_fd: int | None) -> list[dict[str, object]]:
    """Run the exact syscall inventory for one bypass action."""

    if action not in ACTIONS:
        raise BypassProbeError("bypass syscall action is unknown")
    if action == "pathname-unix-socket":
        return [observe("socket(AF_UNIX,SOCK_STREAM)", lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))]
    if action == "abstract-unix-socket":
        return [observe("socket(AF_UNIX,SOCK_STREAM)-abstract", lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))]
    if action == "inherited-connected-internet-socket":
        if inherited_fd is None or inherited_fd < 3:
            raise BypassProbeError("inherited descriptor is absent")
        return [observe("fstat(inherited-inet)", lambda: os.fstat(inherited_fd))]
    if action.startswith("io-uring-"):
        return [observe("io_uring_setup", io_uring_setup)]
    packet = getattr(socket, "AF_PACKET", 17)
    return [
        observe("socket(AF_INET,SOCK_RAW)", lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)),
        observe("socket(AF_PACKET,SOCK_DGRAM)", lambda: socket.socket(packet, socket.SOCK_DGRAM, 0)),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--action", choices=ACTIONS, required=True)
    parser.add_argument("--inherited-fd", type=int)
    parser.add_argument("--started-file", type=Path, required=True)
    parser.add_argument("--observation", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        if (
            not arguments.started_file.is_absolute()
            or not arguments.observation.is_absolute()
            or arguments.started_file == arguments.observation
        ):
            raise BypassProbeError("bypass probe output paths are invalid")
        write_new(arguments.started_file, b"started\n")
        attempts = execute(arguments.action, arguments.inherited_fd)
        write_new(
            arguments.observation,
            canonical_json({"action": arguments.action, "attempts": attempts, "schema": SCHEMA}),
        )
        return 0
    except (BypassProbeError, OSError, ValueError) as error:
        print(f"bypass syscall probe failed: {error}", file=sys.stderr)
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
