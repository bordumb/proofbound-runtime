#!/usr/bin/env python3
"""Reproduce proposed v3 deny-mode vectors from frozen v2 wire fixtures."""

import json
from pathlib import Path

from tools.ci.deterministic_cbor import decode_strict, json_projection
from tools.ci.encode_plan_v2 import encode


ROOT = Path(__file__).resolve().parents[2] / "schemas/vectors"


def main() -> int:
    for name, version in [
        ("run-result", 3),
        ("execution-receipt", 3),
        ("composed-receipt", 3),
        ("acceptance-policy", 2),
        ("acceptance-decision", 3),
    ]:
        source = bytes.fromhex((ROOT / "v2" / f"{name}.cbor.hex").read_text())
        value = decode_strict(source)
        value["schema"] = f"proofbound-runtime-{name}/{version}"
        if name == "execution-receipt":
            value["network"] = {"mode": "deny"}
            value["policy"]["model_version"] = "proofbound-runtime-linux-policy/3"
        elif name == "composed-receipt":
            value["execution"]["network"] = {"mode": "deny"}
            value["runtime_bundle"]["artifacts"].append(
                {"name": "pbr-egress-proxy", "size": 17, "sha256": bytes([17]) * 32}
            )
        elif name == "acceptance-policy":
            value["execution"]["network"] = "deny"
            value["execution"]["receipt_schema"] = (
                "proofbound-runtime-execution-receipt/3"
            )
            value["execution"]["policy_model_version"] = (
                "proofbound-runtime-linux-policy/3"
            )
        target = ROOT / "v3" / name
        target.with_suffix(".cbor.hex").write_text(encode(value).hex() + "\n")
        target.with_suffix(".projection.json").write_text(
            json.dumps(json_projection(value), sort_keys=True, separators=(",", ":"))
            + "\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
