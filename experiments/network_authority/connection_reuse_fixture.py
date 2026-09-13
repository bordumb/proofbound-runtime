#!/usr/bin/env python3
"""Exact two-connection target and scalar client for experiment 0001H."""

from __future__ import annotations

import argparse
import hashlib
import os
import socket
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.record_common import canonical_json, write_new


PROBE = b"proofbound-reuse-probe\n"
SENTINEL = b"proofbound-reuse-sentinel\n"
SCHEMA = "proofbound-runtime-connection-reuse-observation/1"


class ReuseFixtureError(Exception):
    """The connection-reuse transcript was incomplete or ambiguous."""


def _write(descriptor: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        count = os.write(descriptor, remaining)
        if count <= 0:
            raise ReuseFixtureError("scalar write was short")
        remaining = remaining[count:]


def _read(descriptor: int, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = os.read(descriptor, size - len(result))
        if not chunk:
            raise ReuseFixtureError("scalar read was truncated")
        result.extend(chunk)
    return bytes(result)


def exchange(channel: socket.socket) -> None:
    if _read(channel.fileno(), len(PROBE)) != PROBE or os.read(channel.fileno(), 1) != b"":
        raise ReuseFixtureError("reuse probe changed")
    _write(channel.fileno(), SENTINEL)


def serve(address: str, port: int, ready: Path, observation: Path) -> None:
    if address not in {"127.0.0.1", "fd00::1"} or not 0 <= port <= 65535:
        raise ReuseFixtureError("reuse endpoint is outside the frozen topology")
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((address, port))
        listener.listen(2)
        listener.settimeout(8)
        write_new(
            ready,
            canonical_json({"address": address, "port": listener.getsockname()[1], "schema": "proofbound-runtime-connection-reuse-ready/1"}),
        )
        for _ordinal in range(2):
            channel, _peer = listener.accept()
            with channel:
                exchange(channel)
    write_new(
        observation,
        canonical_json({"connection_count": 2, "probe_sha256": hashlib.sha256(PROBE).hexdigest(), "schema": SCHEMA, "sentinel_sha256": hashlib.sha256(SENTINEL).hexdigest()}),
    )


def direct_reuse(address: str, port: int) -> list[str]:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    events = []
    for ordinal in range(2):
        with socket.socket(family, socket.SOCK_STREAM) as channel:
            channel.connect((address, port))
            _write(channel.fileno(), PROBE)
            channel.shutdown(socket.SHUT_WR)
            if _read(channel.fileno(), len(SENTINEL)) != SENTINEL or os.read(channel.fileno(), 1) != b"":
                raise ReuseFixtureError("reuse sentinel changed")
        events.append("registered-exchange" if ordinal == 0 else "excess-exchange")
    return events


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--address", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--observation-file", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        serve(arguments.address, arguments.port, arguments.ready_file, arguments.observation_file)
        return 0
    except (OSError, ReuseFixtureError, ValueError) as error:
        print(f"connection reuse fixture failed: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
