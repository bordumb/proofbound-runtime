#!/usr/bin/env python3
"""Unprivileged adversarial client for experiment 0001D."""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
import socket
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.preconnected_channel import (
    ALLOWED_REQUEST,
    ALLOWED_RESPONSE,
    CONNECT_REQUEST,
    CONNECT_RESPONSE,
    MAX_DIRECTION_BYTES,
    UNDECLARED_PATH_REQUEST,
    UNDECLARED_PATH_RESPONSE,
    ConnectorError,
)


CASES = (
    "allowed-request",
    "undeclared-path-exposure",
    "connect-shape-exposure",
    "direct-tcp-denied",
    "direct-udp-denied",
    "fork-direct-tcp-denied",
    "alternate-endpoint-denied-certificate",
    "alternate-endpoint-allowed-certificate",
    "wrong-certificate-denied",
    "plaintext-endpoint-denied",
    "connector-crash-denied",
    "wrong-cookie-denied",
    "non-unix-descriptor-denied",
    "foreign-descriptor-denied",
)


def write_all(descriptor: int, data: bytes) -> None:
    """Write exact bytes through ordinary write(2)."""

    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise ConnectorError("short channel write")
        view = view[written:]


def shutdown_write(descriptor: int) -> None:
    """Half-close the retained channel without socket send operations."""

    library = ctypes.CDLL(None, use_errno=True)
    if library.shutdown(descriptor, socket.SHUT_WR) != 0:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value))


def exchange(descriptor: int, request: bytes) -> bytes:
    """Exchange one bounded request and response on the retained stream."""

    write_all(descriptor, request)
    shutdown_write(descriptor)
    response = bytearray()
    while True:
        chunk = os.read(descriptor, min(1024, MAX_DIRECTION_BYTES + 1 - len(response)))
        if not chunk:
            break
        response.extend(chunk)
        if len(response) > MAX_DIRECTION_BYTES:
            raise ConnectorError("channel response exceeded its byte bound")
    if not response:
        raise ConnectorError("channel response was empty")
    return bytes(response)


def direct_socket_result(socket_type: int) -> int:
    """Return denial only when socket creation receives EPERM."""

    try:
        created = socket.socket(socket.AF_INET, socket_type)
    except OSError as error:
        return 7 if error.errno == errno.EPERM else 0
    created.close()
    return 0


def fork_direct_tcp_result() -> int:
    """Require a descendant to retain direct-socket denial."""

    child = os.fork()
    if child == 0:
        os._exit(direct_socket_result(socket.SOCK_STREAM))
    _, child_status = os.waitpid(child, 0)
    if os.WIFEXITED(child_status):
        return os.WEXITSTATUS(child_status)
    return 0


def request_case_result(descriptor: int, request: bytes, response: bytes) -> int:
    """Require the exact response that proves the registered observation."""

    try:
        observed = exchange(descriptor, request)
    except (ConnectorError, OSError):
        return 7
    return 0 if observed == response else 7


def run(case: str, descriptor: int, foreign_descriptor: int | None) -> int:
    """Run one child-visible case without interpreting orchestration state."""

    if case == "allowed-request":
        return request_case_result(descriptor, ALLOWED_REQUEST, ALLOWED_RESPONSE)
    if case == "undeclared-path-exposure":
        return request_case_result(
            descriptor, UNDECLARED_PATH_REQUEST, UNDECLARED_PATH_RESPONSE
        )
    if case == "connect-shape-exposure":
        return request_case_result(descriptor, CONNECT_REQUEST, CONNECT_RESPONSE)
    if case == "direct-tcp-denied":
        return direct_socket_result(socket.SOCK_STREAM)
    if case == "direct-udp-denied":
        return direct_socket_result(socket.SOCK_DGRAM)
    if case == "fork-direct-tcp-denied":
        return fork_direct_tcp_result()
    if case == "connector-crash-denied":
        try:
            exchange(descriptor, ALLOWED_REQUEST)
        except (ConnectorError, OSError):
            return 7
        return 0
    if case == "foreign-descriptor-denied":
        if foreign_descriptor is None:
            return 0
        try:
            os.fstat(foreign_descriptor)
        except OSError as error:
            return 7 if error.errno == errno.EBADF else 0
        return 0
    raise ConnectorError("case must fail before client execution")


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
    except (ConnectorError, OSError, ValueError) as error:
        print(f"preconnected case client failed: {error}", file=sys.stderr)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
