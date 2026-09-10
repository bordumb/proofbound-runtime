#!/usr/bin/env python3
"""Unprivileged adversarial client for the explicit broker control."""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
import socket
import struct
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.explicit_broker import (
    MAX_FRAME_BYTES,
    ProtocolError,
    wire_json,
)


CASES = (
    "allowed-request",
    "target-substitution",
    "direct-tcp-denied",
    "direct-udp-denied",
    "wrong-certificate-denied",
    "zero-frame-denied",
    "oversized-frame-denied",
    "truncated-frame-denied",
    "duplicate-key-denied",
    "invalid-utf8-denied",
    "noncanonical-frame-denied",
    "fork-direct-tcp-denied",
    "broker-crash-denied",
    "foreign-descriptor-denied",
)
ERROR_RESPONSE = wire_json({"code": "request-failed", "status": "error"})


def write_all(descriptor: int, data: bytes) -> None:
    """Write exact bytes through ordinary write(2)."""

    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise ProtocolError("short channel write")
        view = view[written:]


def read_exact(descriptor: int, size: int) -> bytes:
    """Read exact bytes through ordinary read(2)."""

    result = bytearray()
    while len(result) < size:
        chunk = os.read(descriptor, size - len(result))
        if not chunk:
            raise ProtocolError("channel response is truncated")
        result.extend(chunk)
    return bytes(result)


def shutdown_write(descriptor: int) -> None:
    """Close the retained channel write direction without socket send calls."""

    library = ctypes.CDLL(None, use_errno=True)
    if library.shutdown(descriptor, socket.SHUT_WR) != 0:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value))


def exchange(descriptor: int, framed_request: bytes) -> bytes:
    """Send one raw frame, delimit it, and read one exact response frame."""

    write_all(descriptor, framed_request)
    shutdown_write(descriptor)
    size = struct.unpack(">I", read_exact(descriptor, 4))[0]
    if size == 0 or size > MAX_FRAME_BYTES:
        raise ProtocolError("response frame length is invalid")
    response = read_exact(descriptor, size)
    if os.read(descriptor, 1) != b"":
        raise ProtocolError("response has trailing bytes")
    return response


def frame(payload: bytes) -> bytes:
    """Frame raw bytes without interpreting them."""

    return struct.pack(">I", len(payload)) + payload


def rejection_result(response: bytes) -> int:
    """Return attack-denied only for the exact closed error."""

    return 7 if response == ERROR_RESPONSE else 0


def direct_socket_result(socket_type: int) -> int:
    """Return attack-denied only when socket creation receives EPERM."""

    try:
        created = socket.socket(socket.AF_INET, socket_type)
    except OSError as error:
        return 7 if error.errno == errno.EPERM else 0
    created.close()
    return 0


def fork_direct_tcp_result() -> int:
    """Require a descendant to retain the direct-socket denial."""

    child = os.fork()
    if child == 0:
        os._exit(direct_socket_result(socket.SOCK_STREAM))
    _, child_status = os.waitpid(child, 0)
    if os.WIFEXITED(child_status):
        return os.WEXITSTATUS(child_status)
    return 0


def request_for_case(case: str) -> bytes:
    """Return the exact raw request for a broker-facing case."""

    if case in {"allowed-request", "wrong-certificate-denied", "broker-crash-denied"}:
        return frame(wire_json({"operation": "echo", "payload": "bounded payload"}))
    if case == "target-substitution":
        return frame(
            b'{"operation":"echo","payload":"bounded payload","target":"denied.test"}'
        )
    if case == "zero-frame-denied":
        return struct.pack(">I", 0)
    if case == "oversized-frame-denied":
        return struct.pack(">I", MAX_FRAME_BYTES + 1)
    if case == "truncated-frame-denied":
        return struct.pack(">I", 2) + b"x"
    if case == "duplicate-key-denied":
        return frame(b'{"operation":"echo","operation":"echo","payload":"x"}')
    if case == "invalid-utf8-denied":
        return frame(b"\xff")
    if case == "noncanonical-frame-denied":
        return frame(b'{"operation": "echo", "payload": "x"}')
    raise ProtocolError("case has no broker request")


def run(case: str, descriptor: int, foreign_descriptor: int | None) -> int:
    """Run one closed adversarial case."""

    if case == "direct-tcp-denied":
        return direct_socket_result(socket.SOCK_STREAM)
    if case == "direct-udp-denied":
        return direct_socket_result(socket.SOCK_DGRAM)
    if case == "fork-direct-tcp-denied":
        return fork_direct_tcp_result()
    if case == "foreign-descriptor-denied":
        if foreign_descriptor is None:
            return 0
        try:
            os.fstat(foreign_descriptor)
        except OSError as error:
            return 7 if error.errno == errno.EBADF else 0
        return 0

    try:
        response = exchange(descriptor, request_for_case(case))
    except (OSError, ProtocolError):
        return 7 if case == "broker-crash-denied" else 0
    if case == "allowed-request":
        expected = wire_json({"payload": "bounded payload", "status": "ok"})
        return 0 if response == expected else 7
    return rejection_result(response)


def parser() -> argparse.ArgumentParser:
    """Build the closed case-client interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--case", choices=CASES, required=True)
    result.add_argument("--fd", type=int, required=True)
    result.add_argument("--foreign-fd", type=int)
    return result


def main() -> int:
    """Run one case with bounded diagnostics."""

    arguments = parser().parse_args()
    try:
        return run(arguments.case, arguments.fd, arguments.foreign_fd)
    except (OSError, ProtocolError, ValueError) as error:
        print(f"broker case client failed: {error}", file=sys.stderr)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
