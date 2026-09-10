#!/usr/bin/env python3
"""Boundary client for experiment 0001H connection reuse."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.connection_reuse_channel import broker_client, channel_client
from experiments.network_authority.connection_reuse_fixture import ReuseFixtureError, direct_reuse
from experiments.network_authority.record_common import canonical_json, write_new


ACTIONS = ("direct", "broker", "channel")
SCHEMA = "proofbound-runtime-connection-reuse-client/1"


def execute(action: str, address: str | None, port: int | None, descriptor: int | None) -> list[str]:
    if action == "direct" and address in {"127.0.0.1", "fd00::1"} and port == 443 and descriptor is None:
        return direct_reuse(address, port)
    if action == "broker" and descriptor is not None and address is None and port is None:
        return broker_client(descriptor)
    if action == "channel" and descriptor is not None and address is None and port is None:
        return channel_client(descriptor)
    raise ValueError("connection reuse client arguments are not exact")


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--action", choices=ACTIONS, required=True)
    parser.add_argument("--address")
    parser.add_argument("--port", type=int)
    parser.add_argument("--fd", type=int)
    parser.add_argument("--started-file", type=Path, required=True)
    parser.add_argument("--observation", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        write_new(arguments.started_file, b"started\n")
        events = execute(arguments.action, arguments.address, arguments.port, arguments.fd)
        write_new(arguments.observation, canonical_json({"action": arguments.action, "events": events, "schema": SCHEMA, "transcript_sha256": hashlib.sha256("\n".join(events).encode()).hexdigest()}))
        return 0
    except (OSError, ReuseFixtureError, ValueError) as error:
        print(f"connection reuse client failed: {error}", file=sys.stderr)
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
