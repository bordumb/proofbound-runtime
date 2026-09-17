#!/usr/bin/env python3
"""Generate the proposed authenticated-service-session observation vector."""

import argparse
import json
from pathlib import Path

from deterministic_cbor import json_projection
from encode_plan_v2 import encode


def artifact(role: str, byte: int, size: int, mode: int) -> dict:
    return {
        "role": role,
        "size": size,
        "mode": mode,
        "sha256": bytes([byte]) * 32,
    }


def observation() -> dict:
    endpoint_1 = {"family": "ipv4", "address": bytes([192, 0, 2, 10]), "port": 443}
    endpoint_2 = {"family": "ipv6", "address": bytes.fromhex("20010db8000000000000000000000010"), "port": 443}
    phases = [
        ("created", "begin-resolution", "resolving", 1_000),
        ("resolving", "resolution-complete", "connecting", 2_000),
        ("connecting", "endpoint-connected", "authenticating", 3_000),
        ("authenticating", "tls-authenticated", "ready", 4_000),
        ("ready", "child-released", "active", 5_000),
        ("active", "begin-close", "closing", 8_000),
        ("closing", "close-complete", "closed", 9_000),
    ]
    return {
        "schema": "proofbound-runtime-service-session-observation/1",
        "service": {"name": "api.anthropic.com", "port": 443},
        "limits": {
            "setup_time_ms": 10_000,
            "session_time_ms": 30_000,
            "child_to_service_bytes": 1_048_576,
            "service_to_child_bytes": 1_048_576,
            "dns_messages": 4,
            "endpoint_attempts": 4,
            "tls_handshake_bytes": 262_144,
        },
        "dns": {
            "resolver": {"family": "ipv4", "address": bytes([1, 1, 1, 1]), "port": 53},
            "configuration": artifact("resolver-configuration", 0x31, 128, 0o444),
            "maximum_cname_depth": 8,
            "maximum_answer_count": 16,
            "maximum_response_bytes": 65_536,
            "resolution_deadline_ms": 5_000,
            "attempt_deadline_ms": 1_000,
            "address_order": "ipv4-then-ipv6-lexicographic",
            "messages": [{"sha256": bytes([0x41]) * 32, "size": 96, "observed_ns": 1_500}],
            "cname_chain": ["api.anthropic.com"],
            "answers": [
                {"name": "api.anthropic.com", "endpoint": endpoint_1, "message_sha256": bytes([0x41]) * 32, "ttl_seconds": 60, "expires_ns": 60_000_001_500},
                {"name": "api.anthropic.com", "endpoint": endpoint_2, "message_sha256": bytes([0x41]) * 32, "ttl_seconds": 60, "expires_ns": 60_000_001_500},
            ],
            "attempts": [
                {"ordinal": 1, "endpoint": endpoint_1, "result": "connected", "started_ns": 2_100, "finished_ns": 3_000}
            ],
            "selected_endpoint": endpoint_1,
        },
        "tls": {
            "version": "tls-1.3",
            "service_name_verification": "dns-san-exact-match",
            "certificate_chain_sha256": bytes([0x51]) * 32,
            "trust_root_set": artifact("trust-root-set", 0x52, 214_949, 0o444),
            "revocation": "not-checked-recorded-assumption",
            "session_resumption": "not-used",
            "early_data": "not-used",
            "handshake_bytes": 8_192,
            "authenticated_ns": 4_000,
        },
        "channel": {
            "protocol": "unix-stream-v1",
            "child_descriptor": 9,
            "channel_id": bytes([0x61]) * 16,
            "descriptor_state": "registered-only",
        },
        "traffic": {
            "child_to_service_bytes": 512,
            "service_to_child_bytes": 1_024,
            "active_ns": 5_000,
            "closed_ns": 9_000,
        },
        "cleanup": {
            "connector": "reaped",
            "channel": "closed",
            "child": "reaped",
            "cgroup": "empty-removed",
            "namespace": "destroyed",
        },
        "lifecycle": [
            {"from": source, "event": event, "to": target, "observed_ns": observed_ns}
            for source, event, target, observed_ns in phases
        ],
        "execution_id": bytes(range(16)),
        "policy_sha256": bytes([0x71]) * 32,
        "connector": {
            "executable": artifact("connector-executable", 0x21, 65_536, 0o555),
            "runtime_closure": [artifact("connector-runtime-library", 0x22, 131_072, 0o444)],
            "process_generation": 1,
        },
        "credential_source": {
            "id": "anthropic-test",
            "service": "api.anthropic.com",
            "environment": "API_KEY",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--projection", required=True, type=Path)
    args = parser.parse_args()
    value = observation()
    args.output.write_text(encode(value).hex() + "\n", encoding="ascii")
    args.projection.write_text(
        json.dumps(json_projection(value), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
