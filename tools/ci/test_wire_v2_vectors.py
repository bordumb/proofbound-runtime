import json
import unittest
from pathlib import Path

from tools.ci.deterministic_cbor import CborError, decode_strict, json_projection


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = REPOSITORY_ROOT / "schemas"
VECTOR_ROOT = SCHEMA_ROOT / "vectors/v2"
IDENTITIES = {
    "execution-plan": "proofbound-runtime-plan/2",
    "compiled-policy": "proofbound-runtime-linux-policy/2",
    "run-result": "proofbound-runtime-run-result/2",
    "execution-receipt": "proofbound-runtime-execution-receipt/2",
    "composed-receipt": "proofbound-runtime-composed-receipt/2",
}


class WireV2GoldenVectorTests(unittest.TestCase):
    def test_vectors_are_strict_deterministic_cbor_with_expected_projection(self) -> None:
        for name, identity in IDENTITIES.items():
            with self.subTest(name=name):
                encoded = bytes.fromhex(
                    (VECTOR_ROOT / f"{name}.cbor.hex").read_text(encoding="ascii")
                )
                decoded = decode_strict(encoded)
                self.assertEqual(decoded["schema"], identity)
                expected = json.loads(
                    (VECTOR_ROOT / f"{name}.projection.json").read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(json_projection(decoded), expected)

    def test_decoder_rejects_every_forbidden_encoding_class(self) -> None:
        attacks = {
            "non-shortest integer": bytes.fromhex("1817"),
            "indefinite array": bytes.fromhex("9fff"),
            "integer map key": bytes.fromhex("a10000"),
            "out-of-order keys": bytes.fromhex("a2616200616100"),
            "duplicate key": bytes.fromhex("a2616100616101"),
            "trailing item": bytes.fromhex("0000"),
            "tag": bytes.fromhex("c000"),
            "floating point": bytes.fromhex("f90000"),
        }
        for name, encoded in attacks.items():
            with self.subTest(name=name):
                with self.assertRaises(CborError):
                    decode_strict(encoded)

    def test_cddl_roots_and_text_key_policy_are_explicit(self) -> None:
        for name in IDENTITIES:
            with self.subTest(name=name):
                cddl = (SCHEMA_ROOT / f"{name}-v2.cddl").read_text(encoding="utf-8")
                self.assertIn(f"{name}-v2 = {{", cddl)
                self.assertNotRegex(cddl, r"(?m)^\s*[0-9]+\s*:")


if __name__ == "__main__":
    unittest.main()
