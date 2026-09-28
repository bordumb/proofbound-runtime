"""Independent deterministic-CBOR check for the proposed v3 egress plan."""

import json
import unittest
from pathlib import Path

from tools.ci.deterministic_cbor import decode_strict, json_projection
from tools.ci.encode_plan_v2 import encode
from tools.ci.encode_plan_v3 import wire_value


ROOT = Path(__file__).resolve().parents[2] / "schemas/vectors/v3"
SCHEMAS = ROOT.parents[1]


class EgressV3VectorTests(unittest.TestCase):
    def test_every_proposed_wire_object_has_a_closed_schema_root(self) -> None:
        for name, version in [
            ("execution-plan", 3),
            ("compiled-policy", 3),
            ("run-result", 3),
            ("execution-receipt", 3),
            ("egress-observation", 1),
            ("composed-receipt", 3),
            ("acceptance-policy", 2),
            ("acceptance-decision", 3),
            ("current-integration", 2),
        ]:
            with self.subTest(name=name):
                schema = (SCHEMAS / f"{name}-v{version}.cddl").read_text()
                self.assertIn(f"{name}-v{version} = {{", schema)
                identity = {
                    "execution-plan": "proofbound-runtime-plan/3",
                    "compiled-policy": "proofbound-runtime-linux-policy/3",
                }.get(name, f"proofbound-runtime-{name}/{version}")
                self.assertIn(f'"{identity}"', schema)

    def test_other_versioned_vectors_are_closed_deterministic_cbor(self) -> None:
        for name, version in [
            ("run-result", 3),
            ("execution-receipt", 3),
            ("composed-receipt", 3),
            ("acceptance-policy", 2),
            ("acceptance-decision", 3),
        ]:
            with self.subTest(name=name):
                golden = bytes.fromhex(
                    (ROOT / f"{name}.cbor.hex").read_text(encoding="ascii")
                )
                decoded = decode_strict(golden)
                projection = json.loads(
                    (ROOT / f"{name}.projection.json").read_text(encoding="utf-8")
                )
                self.assertEqual(decoded["schema"], f"proofbound-runtime-{name}/{version}")
                self.assertEqual(json_projection(decoded), projection)
                self.assertEqual(encode(decoded), golden)

    def test_plan_vector_matches_projection_and_canonical_cbor(self) -> None:
        projection = json.loads(
            (ROOT / "execution-plan-egress.projection.json").read_text(encoding="utf-8")
        )
        golden = bytes.fromhex(
            (ROOT / "execution-plan-egress.cbor.hex").read_text(encoding="ascii")
        )
        decoded = decode_strict(golden)
        self.assertEqual(decoded, wire_value(projection))
        self.assertEqual(json_projection(decoded), projection)
        self.assertEqual(encode(decoded), golden)
        self.assertEqual(projection["schema"], "proofbound-runtime-plan/3")
        self.assertEqual(
            projection["authority"]["network"]["mode"], "declared-egress"
        )

    def test_policy_vector_binds_egress_authority_and_network_roles(self) -> None:
        plan = decode_strict(
            bytes.fromhex(
                (ROOT / "execution-plan-egress.cbor.hex").read_text(encoding="ascii")
            )
        )
        golden = bytes.fromhex(
            (ROOT / "compiled-policy-egress.cbor.hex").read_text(encoding="ascii")
        )
        policy = decode_strict(golden)
        projection = json.loads(
            (ROOT / "compiled-policy-egress.projection.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(policy, wire_value(projection))
        self.assertEqual(json_projection(policy), projection)
        self.assertEqual(encode(policy), golden)
        self.assertEqual(policy["egress"], plan["authority"]["network"])
        self.assertEqual(policy["network"], "deny-network-v1")
        self.assertEqual(policy["child_network"], "egress-namespace-v1")
        self.assertEqual(policy["listener"], {"address": b"\x7f\0\0\x01", "port": 3128, "backlog": 128})
        self.assertEqual(policy["proxy_landlock_network"]["connect_ports"], [53, 443])


if __name__ == "__main__":
    unittest.main()
