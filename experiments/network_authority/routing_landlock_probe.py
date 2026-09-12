#!/usr/bin/env python3
"""Child-side port-selection probes for experiment 0001F mechanism A."""

from __future__ import annotations

import argparse
import errno
import socket


def connect(address: str, port: int, expected_errno: int | None) -> bool:
    """Require one connect success or one exact error."""

    try:
        with socket.create_connection((address, port), timeout=2):
            return expected_errno is None
    except OSError as error:
        return expected_errno is not None and error.errno == expected_errno


def run(allowed_port: int, denied_port: int) -> int:
    """Prove that the allowed port is reachable and another port is not."""

    if (
        not 1 <= allowed_port <= 65535
        or not 1 <= denied_port <= 65535
        or allowed_port == denied_port
    ):
        return 7
    outcomes = (
        connect("127.0.0.1", allowed_port, None),
        connect("127.0.0.1", denied_port, errno.EACCES),
    )
    return 0 if all(outcomes) else 7


def parser() -> argparse.ArgumentParser:
    """Build the closed probe interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--allowed-port", type=int, required=True)
    result.add_argument("--denied-port", type=int, required=True)
    return result


def main() -> int:
    """Run the exact Landlock port probe."""

    arguments = parser().parse_args()
    return run(arguments.allowed_port, arguments.denied_port)


if __name__ == "__main__":
    raise SystemExit(main())
