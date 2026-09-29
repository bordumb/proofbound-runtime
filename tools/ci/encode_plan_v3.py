#!/usr/bin/env python3
"""Encode a native declared-egress corpus plan as deterministic CBOR."""

import argparse
import json
from pathlib import Path
from typing import Any

if __package__:
    from .encode_plan_v2 import encode
else:
    from encode_plan_v2 import encode


DECIMAL_FIELDS = {
    "memory.max",
    "memory.swap.max",
    "memory_bytes",
    "swap_bytes",
    "stdout_bytes",
    "stderr_bytes",
    "maximum_response_bytes",
}


def wire_value(value: Any, field: str = "") -> Any:
    if isinstance(value, str) and value.startswith("hex:"):
        return bytes.fromhex(value[4:])
    if isinstance(value, str) and field in DECIMAL_FIELDS:
        return int(value)
    if isinstance(value, list):
        return [wire_value(item) for item in value]
    if isinstance(value, dict):
        return {key: wire_value(item, key) for key, item in value.items()}
    return value


def byte_string(value: object, label: str) -> bytes:
    if not isinstance(value, list) or not all(
        isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255
        for item in value
    ):
        raise ValueError(f"{label} must be an octet array")
    return bytes(value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--projection", type=Path)
    parser.add_argument("--network-file", type=Path)
    parser.add_argument("--id")
    parser.add_argument("--executable")
    parser.add_argument("--argument", action="append", default=[])
    parser.add_argument("--working-directory")
    parser.add_argument("--read", action="append", default=[])
    parser.add_argument("--runtime-read", action="append", default=[])
    parser.add_argument("--write", action="append", default=[])
    parser.add_argument("--execute", action="append", default=[])
    parser.add_argument("--environment", action="append", default=[])
    parser.add_argument("--processes", type=int)
    parser.add_argument("--wall-time-ms", type=int)
    parser.add_argument("--stdout-bytes", type=int)
    parser.add_argument("--stderr-bytes", type=int)
    parser.add_argument("--memory-bytes", type=int)
    parser.add_argument("--swap-bytes", type=int)
    args = parser.parse_args()
    if args.projection is not None:
        plan = wire_value(json.loads(args.projection.read_text(encoding="utf-8")))
        if plan.get("schema") != "proofbound-runtime-plan/3":
            raise SystemExit("projection must name plan version 3")
        with args.output.open("xb") as destination:
            destination.write(encode(plan))
        return 0
    if any(value is None for value in (
        args.network_file, args.id, args.executable, args.working_directory,
        args.processes, args.wall_time_ms, args.stdout_bytes, args.stderr_bytes,
        args.memory_bytes, args.swap_bytes,
    )):
        raise SystemExit("native plan arguments are incomplete")
    network = json.loads(args.network_file.read_text(encoding="utf-8"))
    if not isinstance(network, dict) or network.get("mode") != "declared-egress":
        raise SystemExit("network file must declare the egress mode")
    try:
        network["resolver"]["address"]["bytes"] = byte_string(
            network["resolver"]["address"]["bytes"], "resolver address"
        )
        for endpoint in network["endpoints"]:
            destination = endpoint["destination"]
            if destination["kind"] in {"ipv4", "ipv6"}:
                destination["bytes"] = byte_string(
                    destination["bytes"], "endpoint address"
                )
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit(f"invalid network file: {error}") from error
    if len(args.write) != 1 or not args.execute:
        raise SystemExit("v3 plan requires one write root and an executable set")
    if args.executable not in args.execute:
        raise SystemExit("command must be in the executable set")
    plan = {
        "schema": "proofbound-runtime-plan/3",
        "id": args.id,
        "command": {
            "executable": args.executable,
            "arguments": args.argument,
            "working_directory": args.working_directory,
        },
        "authority": {
            "read": args.read,
            "runtime_read": args.runtime_read,
            "write": args.write,
            "execute": sorted(set(args.execute)),
            "environment": args.environment,
            "network": network,
        },
        "limits": {
            "processes": args.processes,
            "wall_time_ms": args.wall_time_ms,
            "stdout_bytes": args.stdout_bytes,
            "stderr_bytes": args.stderr_bytes,
            "memory_bytes": args.memory_bytes,
            "swap_bytes": args.swap_bytes,
        },
    }
    with args.output.open("xb") as destination:
        destination.write(encode(plan))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
