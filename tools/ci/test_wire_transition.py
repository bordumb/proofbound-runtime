import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ADR = REPOSITORY_ROOT / "docs/adr/0003-deterministic-cbor-wire-objects.md"
MEMORY_SPEC = REPOSITORY_ROOT / "docs/specs/0007_memory_and_swap_profile.md"
SCHEMA_ROOT = REPOSITORY_ROOT / "schemas"
SOURCE_ROOT = REPOSITORY_ROOT / "crates"
VERSION_TWO_IDENTITIES = (
    "proofbound-runtime-plan/2",
    "proofbound-runtime-linux-policy/2",
    "proofbound-runtime-execution-receipt/2",
    "proofbound-runtime-run-result/2",
    "proofbound-runtime-composed-receipt/2",
)


class WireTransitionTests(unittest.TestCase):
    def test_open_map_key_gate_blocks_version_two_wire_implementation(self) -> None:
        adr = ADR.read_text(encoding="utf-8")

        self.assertIn("The deterministic-CBOR decision is accepted.", adr)
        self.assertRegex(adr, r"The map-key representation is\s+not yet selected\.")
        self.assertIn("No implementation may infer this choice", adr)
        self.assertEqual(sorted(SCHEMA_ROOT.glob("*v2*.cddl")), [])
        rust_sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(SOURCE_ROOT.glob("**/*.rs"))
        )
        for identity in VERSION_TWO_IDENTITIES:
            with self.subTest(identity=identity):
                self.assertNotIn(identity, rust_sources)

    def test_memory_receipt_uses_cbor_integers_not_json_workarounds(self) -> None:
        specification = MEMORY_SPEC.read_text(encoding="utf-8")
        normalized = " ".join(specification.split())

        self.assertIn(
            "Each byte count and counter is encoded as an unsigned integer in the "
            "version 2 committed CBOR bytes.",
            normalized,
        )
        self.assertNotIn("so the JSON wire can represent", specification)
        self.assertIn(
            "the projection is not a wire object and is never a\nverification input",
            specification,
        )


if __name__ == "__main__":
    unittest.main()
