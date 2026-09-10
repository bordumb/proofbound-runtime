#!/usr/bin/env python3
"""Child-side dual-stack endpoint probes for experiment 0001F."""

from __future__ import annotations

import argparse
import errno
import socket


def connect_result(family: int, address: str, port: int, allowed: bool) -> int:
    """Require one connect to succeed or receive exact EPERM."""

    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        try:
            connection.connect((address, port))
        except OSError as error:
            return 0 if not allowed and error.errno == errno.EPERM else 7
    return 0 if allowed else 7


def run(port: int) -> int:
    """Exercise allowed and denied dual-stack routing tuples."""

    if not 1 <= port < 65535:
        return 7
    probes = (
        (socket.AF_INET, "127.0.0.1", port, True),
        (socket.AF_INET6, "::1", port, True),
        (socket.AF_INET, "127.0.0.2", port, False),
        (socket.AF_INET, "127.0.0.1", port + 1, False),
        (socket.AF_INET6, "::ffff:127.0.0.1", port, False),
    )
    return 0 if all(connect_result(*probe) == 0 for probe in probes) else 7


def parser() -> argparse.ArgumentParser:
    """Build the closed probe interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--port", type=int, required=True)
    return result


def main() -> int:
    """Run the exact endpoint probe corpus."""

    arguments = parser().parse_args()
    try:
        return run(arguments.port)
    except (OSError, ValueError):
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
