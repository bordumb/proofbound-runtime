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

    def test_registered_mutations_fail_for_their_causal_reason(self) -> None:
        mutations = {
            "unknown-field": lambda value: value.update({"ambient_network": True}),
            "unrecorded-endpoint": lambda value: value["dns"].__setitem__(
                "selected_endpoint", {"family": "ipv4", "address": bytes([203, 0, 113, 9]), "port": 443}
            ),
            "attempt-order": lambda value: value["dns"]["attempts"][0].__setitem__("ordinal", 2),
            "expired-answer": lambda value: value["dns"]["answers"][0].__setitem__("expires_ns", 4_000),
            "tls-name-mismatch": lambda value: value["tls"].__setitem__("service_name_verification", "mismatch"),
            "tls-resumption": lambda value: value["tls"].__setitem__("session_resumption", "used"),
            "excess-traffic": lambda value: value["traffic"].__setitem__("child_to_service_bytes", 2_000_000),
            "skipped-lifecycle": lambda value: value["lifecycle"].pop(2),
            "incomplete-cleanup": lambda value: value["cleanup"].__setitem__("connector", "running"),
            "cross-service-credential": lambda value: value["credential_source"].__setitem__("service", "example.com"),
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
