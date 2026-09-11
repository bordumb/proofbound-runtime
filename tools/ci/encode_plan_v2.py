#!/usr/bin/env python3
"""Encode one closed Proofbound Runtime v2 plan as deterministic CBOR."""

import argparse
import json
from pathlib import Path
from typing import Any


QUANTUM = 65_536
MAX_RESOURCE = 1_099_511_627_776


def encode_argument(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    for additional, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (width * 8):
            return bytes([(major << 5) | additional]) + value.to_bytes(width, "big")
    raise ValueError("CBOR integer exceeds u64")


def encode(value: Any) -> bytes:
    if isinstance(value, str):
        payload = value.encode("utf-8")
        return encode_argument(3, len(payload)) + payload
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return encode_argument(0, value)
    if isinstance(value, list):
        return encode_argument(4, len(value)) + b"".join(map(encode, value))
    if isinstance(value, dict):
        entries = sorted((encode(key), encode(item)) for key, item in value.items())
        return encode_argument(5, len(entries)) + b"".join(
            key + item for key, item in entries
        )
    raise ValueError(f"unsupported CBOR value: {type(value).__name__}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--output", required=True, type=Path)
    result.add_argument("--id", required=True)
    result.add_argument("--executable", required=True)
    result.add_argument("--argument", action="append", default=[])
    result.add_argument("--working-directory", required=True)
    result.add_argument("--read", action="append", default=[])
    result.add_argument("--runtime-read", action="append", default=[])
    result.add_argument("--runtime-read-json")
    result.add_argument("--write", action="append", required=True)
    result.add_argument("--execute", action="append", required=True)
    result.add_argument("--environment", action="append", default=[])
    result.add_argument("--processes", required=True, type=int)
    result.add_argument("--wall-time-ms", required=True, type=int)
    result.add_argument("--stdout-bytes", required=True, type=int)
    result.add_argument("--stderr-bytes", required=True, type=int)
    result.add_argument("--memory-bytes", required=True, type=int)
    result.add_argument("--swap-bytes", required=True, type=int)
    return result


def main() -> int:
    args = parser().parse_args()
    if len(args.write) != 1 or len(args.execute) != 1:
        raise SystemExit("v2 plan requires exactly one write and execute path")
    if args.processes <= 0 or args.wall_time_ms <= 0:
        raise SystemExit("processes and wall time must be positive")
    if min(args.stdout_bytes, args.stderr_bytes, args.swap_bytes) < 0:
        raise SystemExit("byte limits cannot be negative")
    if not (QUANTUM <= args.memory_bytes <= MAX_RESOURCE):
        raise SystemExit("memory limit is outside the v2 range")
    if args.memory_bytes % QUANTUM or args.swap_bytes % QUANTUM:
        raise SystemExit("memory and swap limits must use the 64 KiB quantum")
    if args.swap_bytes > MAX_RESOURCE:
        raise SystemExit("swap limit is outside the v2 range")

    runtime_read = args.runtime_read
    if args.runtime_read_json is not None:
        decoded = json.loads(args.runtime_read_json)
        if not isinstance(decoded, list) or not all(isinstance(item, str) for item in decoded):
            raise SystemExit("runtime-read JSON must be an array of strings")
        runtime_read.extend(decoded)
    plan = {
        "id": args.id,
        "schema": "proofbound-runtime-plan/2",
        "limits": {
            "processes": args.processes,
            "swap_bytes": args.swap_bytes,
            "stderr_bytes": args.stderr_bytes,
            "stdout_bytes": args.stdout_bytes,
            "memory_bytes": args.memory_bytes,
            "wall_time_ms": args.wall_time_ms,
        },
        "command": {
            "arguments": args.argument,
            "executable": args.executable,
            "working_directory": args.working_directory,
        },
        "authority": {
            "read": args.read,
            "write": args.write,
            "execute": args.execute,
            "network": "deny",
            "environment": args.environment,
            "runtime_read": runtime_read,
        },
    }
    with args.output.open("xb") as destination:
        destination.write(encode(plan))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
