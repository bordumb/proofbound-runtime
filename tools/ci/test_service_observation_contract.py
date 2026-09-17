import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.ci.deterministic_cbor import decode_strict, json_projection
from tools.ci.service_observation_contract import ContractError, validate_observation


ROOT = Path(__file__).resolve().parents[2]
VECTOR = ROOT / "schemas/vectors/v2/service-session-observation.cbor.hex"
PROJECTION = ROOT / "schemas/vectors/v2/service-session-observation.projection.json"


def move_dns_message_before_resolution(value: dict) -> None:
    value["dns"]["messages"][0]["observed_ns"] = 900


def overlap_endpoint_attempts(value: dict) -> None:
    first = value["dns"]["attempts"][0]
    first["result"] = "failed"
    first["finished_ns"] = 2_700
    second_endpoint = copy.deepcopy(value["dns"]["answers"][1]["endpoint"])
    value["dns"]["attempts"].append(
        {
            "ordinal": 2,
            "endpoint": second_endpoint,
            "result": "connected",
            "started_ns": 2_600,
            "finished_ns": 3_000,
        }
    )
    value["dns"]["selected_endpoint"] = second_endpoint


def attempt_expired_endpoint(value: dict) -> None:
    answer = value["dns"]["answers"][0]
    answer["ttl_seconds"] = 1
    answer["record_expires_ns"] = 1_000_001_300
    answer["effective_expires_ns"] = 1_000_001_300
    attempt = value["dns"]["attempts"][0]
    attempt["started_ns"] = 1_000_001_500
    attempt["finished_ns"] = 1_000_001_600
    for index, observed_ns in enumerate(
        [1_000, 2_000, 1_000_001_600, 1_000_001_700, 1_000_001_800, 1_000_001_900, 1_000_002_000]
    ):
        value["lifecycle"][index]["observed_ns"] = observed_ns
    value["tls"]["authenticated_ns"] = 1_000_001_700
    value["traffic"]["active_ns"] = 1_000_001_800
    value["traffic"]["closed_ns"] = 1_000_002_000


def substitute_runtime_closure(value: dict) -> None:
    value["connector"]["runtime_closure"][0]["sha256"] = bytes(32)


class ServiceObservationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = decode_strict(bytes.fromhex(VECTOR.read_text(encoding="ascii")))

    def test_canonical_vector_is_complete_and_valid(self) -> None:
        validate_observation(self.value)
        self.assertEqual(
            json_projection(self.value),
            json.loads(PROJECTION.read_text(encoding="utf-8")),
        )

    def test_generator_reproduces_exact_vector(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "observation.hex"
            projection = Path(directory) / "observation.json"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/ci/generate_service_observation_v1_vector.py"),
                    "--output",
                    str(output),
                    "--projection",
                    str(projection),
                ],
                cwd=ROOT,
                check=True,
            )
            self.assertEqual(output.read_bytes(), VECTOR.read_bytes())
            self.assertEqual(projection.read_bytes(), PROJECTION.read_bytes())

    def test_schema_is_closed_and_forbids_payload_content(self) -> None:
        schema = (ROOT / "schemas/service-session-observation-v1.cddl").read_text(encoding="utf-8")
        self.assertIn("service-session-observation-v1 = {", schema)
        self.assertNotIn('"credential_value":', schema)
        self.assertNotIn('"request_bytes":', schema)
        self.assertNotIn('"response_bytes":', schema)

    def test_direct_answer_without_cname_chain_is_valid(self) -> None:
        self.value["dns"]["cname_chain"] = []
        for answer in self.value["dns"]["answers"]:
            answer["name"] = "api.anthropic.com"
            answer["effective_expires_ns"] = answer["record_expires_ns"]
        validate_observation(self.value)

    def test_registered_mutations_fail_for_their_causal_reason(self) -> None:
        mutations = {
            "unknown-field": lambda value: value.update({"ambient_network": True}),
            "oversized-dns-message-limit": lambda value: value["limits"].__setitem__("dns_messages", 65_536),
            "insufficient-dns-message-limit": lambda value: value["limits"].__setitem__("dns_messages", 1),
            "attempt-limit-exceeds-answers": lambda value: value["limits"].__setitem__("endpoint_attempts", 17),
            "resolution-deadline-exceeds-setup": lambda value: value["dns"].__setitem__("resolution_deadline_ms", 10_001),
            "dns-message-before-resolution": move_dns_message_before_resolution,
            "unrecorded-endpoint": lambda value: value["dns"].__setitem__(
                "selected_endpoint", {"family": "ipv4", "address": bytes([203, 0, 113, 9]), "port": 443}
            ),
            "attempt-order": lambda value: value["dns"]["attempts"][0].__setitem__("ordinal", 2),
            "attempt-before-resolution": lambda value: value["dns"]["attempts"][0].__setitem__("started_ns", 1_900),
            "overlapping-attempts": overlap_endpoint_attempts,
            "endpoint-event-mismatch": lambda value: value["lifecycle"][2].__setitem__("observed_ns", 3_001),
            "ttl-expiry-mismatch": lambda value: value["dns"]["answers"][0].__setitem__("record_expires_ns", 4_000),
            "cname-expiry-mismatch": lambda value: value["dns"]["cname_chain"][0].__setitem__("expires_ns", 4_000),
            "cname-message-substitution": lambda value: value["dns"]["cname_chain"][0].__setitem__("message_sha256", bytes([0x99]) * 32),
            "cname-owner-substitution": lambda value: value["dns"]["cname_chain"][0].__setitem__("owner", "other.example.com"),
            "effective-expiry-omits-cname": lambda value: value["dns"]["answers"][0].__setitem__("effective_expires_ns", value["dns"]["answers"][0]["record_expires_ns"]),
            "attempt-expired-endpoint": attempt_expired_endpoint,
            "tls-name-mismatch": lambda value: value["tls"].__setitem__("service_name_verification", "mismatch"),
            "tls-implementation-width": lambda value: value["tls"].__setitem__("implementation_sha256", bytes(31)),
            "tls-resumption": lambda value: value["tls"].__setitem__("session_resumption", "used"),
            "connector-runtime-closure-substitution": substitute_runtime_closure,
            "excess-traffic": lambda value: value["traffic"].__setitem__("child_to_service_bytes", 2_000_000),
            "skipped-lifecycle": lambda value: value["lifecycle"].pop(2),
            "incomplete-cleanup": lambda value: value["cleanup"].__setitem__("connector", "running"),
            "cross-service-credential": lambda value: value["credential_source"].__setitem__("service", "example.com"),
            "uppercase-credential-id": lambda value: value["credential_source"].__setitem__("id", "Anthropic"),
            "underscore-credential-id": lambda value: value["credential_source"].__setitem__("id", "anthropic_test"),
            "nul-credential-id": lambda value: value["credential_source"].__setitem__("id", "anthropic\0test"),
            "non-ascii-credential-id": lambda value: value["credential_source"].__setitem__("id", "anthropic-é"),
            "retained-secret": lambda value: value["credential_source"].update({"credential_value": "canary"}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(self.value)
                mutate(candidate)
                with self.assertRaises(ContractError):
                    validate_observation(candidate)


if __name__ == "__main__":
    unittest.main()
