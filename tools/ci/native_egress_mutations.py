#!/usr/bin/env python3
"""Mutate native release receipts and require independent semantic rejection."""

from __future__ import annotations

import argparse
import copy
import hashlib
from pathlib import Path
import subprocess

from deterministic_cbor import decode_strict
from encode_plan_v2 import encode


def observation(receipt: dict) -> dict:
    return receipt["network"]["observation"]


def change_connection_count(receipt: dict) -> None:
    counters = observation(receipt)["counters"]
    counters["connections"] += 1


def change_sequence(receipt: dict) -> None:
    connection = observation(receipt)["connections"][0]
    connection["close_sequence"] = connection["open_sequence"]


def change_attempt_selection(receipt: dict) -> None:
    observation(receipt)["connections"][0]["selected_attempt"] = 999


def change_byte_count(receipt: dict) -> None:
    observation(receipt)["connections"][0]["client_to_remote_bytes"] += 1


def change_limit_event(receipt: dict) -> None:
    observation(receipt)["limit_events"].append("egress-limit-connections")


def change_proxy_phase(receipt: dict) -> None:
    observation(receipt)["proxy"]["phases"].remove("ready")


def change_cleanup(receipt: dict) -> None:
    observation(receipt)["cleanup"]["listener_closed"] = False


def change_listener(receipt: dict) -> None:
    observation(receipt)["boundary"]["listener"]["port"] = 3130


def change_namespace(receipt: dict) -> None:
    boundary = observation(receipt)["boundary"]
    boundary["child_network_namespace"] = copy.deepcopy(
        boundary["supervisor_network_namespace"]
    )


def change_proxy_identity(receipt: dict) -> None:
    identity = observation(receipt)["proxy"]["executable"]
    digest = bytearray(identity["sha256"])
    digest[0] ^= 1
    identity["sha256"] = bytes(digest)


def change_resolution_index(receipt: dict) -> None:
    observation(receipt)["connections"][0]["resolution_index"] = 999


def change_endpoint_index(receipt: dict) -> None:
    observation(receipt)["connections"][0]["endpoint_index"] = 999


def change_answer_index(receipt: dict) -> None:
    observation(receipt)["connections"][0]["attempts"][0]["answer_index"] = 999


def change_resolution_outcome(receipt: dict) -> None:
    observation(receipt)["resolutions"][0]["outcome"] = "failed"


def change_sni_relation(receipt: dict) -> None:
    observation(receipt)["connections"][0]["sni_result"] = "denied-mismatch"


def change_rejection_count(receipt: dict) -> None:
    observation(receipt)["counters"]["rejections"] += 1


MUTATIONS = (
    ("proxy-literal", "connection-counter", change_connection_count),
    ("proxy-literal", "sequence-order", change_sequence),
    ("proxy-literal", "attempt-selection", change_attempt_selection),
    ("proxy-literal", "connection-bytes", change_byte_count),
    ("proxy-literal", "limit-event-derivation", change_limit_event),
    ("proxy-literal", "proxy-phases", change_proxy_phase),
    ("proxy-literal", "cleanup-eligibility", change_cleanup),
    ("proxy-literal", "listener-binding", change_listener),
    ("proxy-literal", "namespace-isolation", change_namespace),
    ("proxy-literal", "proxy-executable-identity", change_proxy_identity),
    ("proxy-literal", "endpoint-reference", change_endpoint_index),
    ("proxy-named", "resolution-reference", change_resolution_index),
    ("proxy-named", "answer-reference", change_answer_index),
    ("proxy-named", "resolution-outcome", change_resolution_outcome),
    ("proxy-sni-matched", "sni-attempt-relation", change_sni_relation),
    ("proxy-undeclared-name", "rejection-counter", change_rejection_count),
)

EXPECTED_CODES = {
    "endpoint-reference": "verify.network.egress.endpoint-unknown",
    "answer-reference": "verify.network.egress.answer-unknown",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    arguments = parser.parse_args()

    original = {}
    for case, _, _ in MUTATIONS:
        if case not in original:
            path = arguments.directory / f"{case}-receipt.cbor"
            original[case] = decode_strict(path.read_bytes())
    for case, name, mutate in MUTATIONS:
        receipt = copy.deepcopy(original[case])
        mutate(receipt)
        encoded = encode(receipt)
        assert decode_strict(encoded) == receipt, name
        output = arguments.directory / f"mutation-{name}.cbor"
        output.write_bytes(encoded)
        commitment = "sha256:" + hashlib.sha256(encoded).hexdigest()
        result = subprocess.run(
            [str(arguments.verifier), "--expected-commitment", commitment, str(output)],
            capture_output=True,
            text=True,
            check=False,
        )
        semantic_codes = (
            "pbr-verify: verify.network.egress.",
            "pbr-verify: receipt.eligibility.",
            "pbr-verify: receipt.tcb.",
        )
        if result.returncode != 7 or not result.stderr.startswith(semantic_codes):
            raise AssertionError((name, result.returncode, result.stdout, result.stderr))
        if "commitment" in result.stderr:
            raise AssertionError((name, "commitment check hid the semantic mutation"))
        if name in EXPECTED_CODES and EXPECTED_CODES[name] not in result.stderr:
            raise AssertionError((name, "wrong verifier relation", result.stderr))
        print(f"native receipt mutation rejected: {name}: {result.stderr.strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
