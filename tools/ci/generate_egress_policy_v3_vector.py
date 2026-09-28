#!/usr/bin/env python3
"""Reproduce the proposed egress compiled-policy vector from the plan."""

import json
from pathlib import Path

from tools.ci.encode_plan_v2 import encode
from tools.ci.encode_plan_v3 import wire_value


ROOT = Path(__file__).resolve().parents[2]
VECTORS_V2 = ROOT / "schemas/vectors/v2"
VECTORS_V3 = ROOT / "schemas/vectors/v3"


def main() -> int:
    base = json.loads((VECTORS_V2 / "compiled-policy.projection.json").read_text())
    plan = json.loads(
        (VECTORS_V3 / "execution-plan-egress.projection.json").read_text()
    )
    base.update(
        {
            "schema": "proofbound-runtime-linux-policy/3",
            "child_network": "egress-namespace-v1",
            "egress": plan["authority"]["network"],
            "listener": {
                "address": "hex:7f000001",
                "port": 3128,
                "backlog": 128,
            },
            "child_filter": "hex:" + "11" * 32,
            "proxy_filter": "hex:" + "22" * 32,
            "child_landlock_network": {
                "handled": ["tcp-bind", "tcp-connect"],
                "connect_ports": [3128],
                "bind_ports": [],
            },
            "child_landlock_scope": {
                "abstract_unix_socket": True,
                "signal": True,
            },
            "proxy_landlock_network": {
                "handled": ["tcp-bind", "tcp-connect"],
                "connect_ports": [53, 443],
                "bind_ports": [],
            },
            "address_classes": "address-class-table-v1",
        }
    )
    (VECTORS_V3 / "compiled-policy-egress.projection.json").write_text(
        json.dumps(base, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    (VECTORS_V3 / "compiled-policy-egress.cbor.hex").write_text(
        encode(wire_value(base)).hex() + "\n", encoding="ascii"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
