#!/usr/bin/env python3
"""Native syscall probes for the experiment 0001F A/B child boundary."""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
import socket
from collections.abc import Callable


CASES = (
    "identity-locked",
    "ipv4-stream-created",
    "ipv6-stream-created",
    "udp-denied",
    "unix-denied",
    "socketpair-denied",
    "tcp-bind-denied",
    "io-uring-denied",
    "foreign-descriptor-closed",
)


def denied(call: Callable[[], object]) -> int:
    """Require one Python socket operation to receive exact EPERM."""

    try:
        call()
    except OSError as error:
        return 0 if error.errno == errno.EPERM else 7
    return 7


def socket_created(family: int) -> int:
    """Require one Internet stream socket to remain available."""

    try:
        created = socket.socket(family, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    except OSError:
        return 7
    created.close()
    return 0


def identity_locked() -> int:
    """Require dropped uid/gid and the installed no-new-privileges bit."""

    status = {}
    with open("/proc/self/status", encoding="ascii") as source:
        for line in source:
            key, separator, value = line.partition(":")
            if separator:
                status[key] = value.strip()
    locked = (
        os.getuid() == 65534
        and os.getgid() == 65534
        and status.get("NoNewPrivs") == "1"
    )
    return 0 if locked else 7


def tcp_bind_denied() -> int:
    """Require stream creation to succeed and bind to receive EPERM."""

    try:
        created = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return 7
    try:
        return denied(lambda: created.bind(("127.0.0.1", 0)))
    finally:
        created.close()


def io_uring_denied() -> int:
    """Require io_uring_setup(2) to receive exact EPERM."""

    library = ctypes.CDLL(None, use_errno=True)
    result = library.syscall(425, 1, ctypes.c_void_p())
    if result != -1:
        if result >= 0:
            os.close(result)
        return 7
    return 0 if ctypes.get_errno() == errno.EPERM else 7


def foreign_descriptor_closed(descriptor: int | None) -> int:
    """Require the wrapper to close one deliberately inherited descriptor."""

    if descriptor is None:
        return 7
    try:
        os.fstat(descriptor)
    except OSError as error:
        return 0 if error.errno == errno.EBADF else 7
    return 7


def run(case: str, foreign_descriptor: int | None) -> int:
    """Execute one exact boundary probe."""

    if case == "identity-locked":
        return identity_locked()
    if case == "ipv4-stream-created":
        return socket_created(socket.AF_INET)
    if case == "ipv6-stream-created":
        return socket_created(socket.AF_INET6)
    if case == "udp-denied":
        return denied(lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    if case == "unix-denied":
        return denied(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
    if case == "socketpair-denied":
        return denied(socket.socketpair)
    if case == "tcp-bind-denied":
        return tcp_bind_denied()
    if case == "io-uring-denied":
        return io_uring_denied()
    if case == "foreign-descriptor-closed":
        return foreign_descriptor_closed(foreign_descriptor)
    raise ValueError("routing boundary probe case is unknown")


def parser() -> argparse.ArgumentParser:
    """Build the closed probe interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--case", choices=CASES, required=True)
    result.add_argument("--foreign-fd", type=int)
    return result


def main() -> int:
    """Run one probe with no ambiguous exception success."""

    arguments = parser().parse_args()
    try:
        return run(arguments.case, arguments.foreign_fd)
    except (OSError, ValueError):
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
