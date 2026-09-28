#!/usr/bin/env python3
"""Reproduce one deterministic CBOR version 3 plan from its JSON projection."""

import argparse
import json
from pathlib import Path
from typing import Any

from tools.ci.encode_plan_v2 import encode


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--projection", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    plan = wire_value(json.loads(args.projection.read_text(encoding="utf-8")))
    if plan.get("schema") != "proofbound-runtime-plan/3":
        raise SystemExit("projection must name plan version 3")
    with args.output.open("xb") as destination:
        destination.write(encode(plan))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
