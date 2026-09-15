import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DIAGNOSTIC_SCHEMA = ROOT / "schemas/diagnostic-receipt-v1.schema.json"
DRAFT_SCHEMA = ROOT / "schemas/plan-draft-v1.schema.json"
DIAGNOSTIC_VECTOR = ROOT / "schemas/vectors/diagnostic/diagnostic-receipt.json"
DRAFT_VECTOR = ROOT / "schemas/vectors/diagnostic/plan-draft.json"


class DiagnosticDraftingContractTests(unittest.TestCase):
    def test_vectors_are_duplicate_free_canonical_json_with_closed_non_claim_flags(self):
        for path in [DIAGNOSTIC_VECTOR, DRAFT_VECTOR]:
            raw = path.read_bytes().removesuffix(b"\n")
            value = json.loads(raw, object_pairs_hook=self._closed_object)
            canonical = json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
            self.assertEqual(raw, canonical, path)
            self.assertFalse(value["safe_policy"])

        receipt = json.loads(DIAGNOSTIC_VECTOR.read_bytes())
        self.assertEqual(receipt["execution_profile"], "diagnostic")
        self.assertFalse(receipt["reusable"])
        self.assertIn(receipt["completion"], {"complete", "incomplete"})
        self.assertEqual(receipt["mechanism"], "linux-ptrace-syscall-v1")

    def test_schemas_are_closed_and_fix_every_security_discriminant(self):
        diagnostic = json.loads(DIAGNOSTIC_SCHEMA.read_bytes())
        draft = json.loads(DRAFT_SCHEMA.read_bytes())
        for schema in [diagnostic, draft]:
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(schema["properties"]["safe_policy"], {"const": False})

        self.assertEqual(
            diagnostic["properties"]["schema"]["const"],
            "proofbound-runtime-diagnostic-receipt/1",
        )
        self.assertEqual(
            diagnostic["properties"]["execution_profile"]["const"], "diagnostic"
        )
        self.assertEqual(diagnostic["properties"]["reusable"], {"const": False})
        self.assertEqual(
            diagnostic["properties"]["mechanism"]["const"],
            "linux-ptrace-syscall-v1",
        )
        self.assertEqual(
            draft["properties"]["schema"]["const"],
            "proofbound-runtime-plan-draft/1",
        )
        self.assertEqual(
            set(draft["$defs"]["provenance"]["enum"]),
            {
                "capsec-source-observation",
                "diagnostic-runtime-observation",
                "human-authored",
                "platform-required-closure",
                "static-executable-closure",
            },
        )

    def test_production_entry_points_have_no_diagnostic_observer_dependency(self):
        cli_manifest = (ROOT / "crates/proofbound-runtime-cli/Cargo.toml").read_text()
        linux_manifest = (ROOT / "crates/proofbound-runtime-linux/Cargo.toml").read_text()
        launcher = (
            ROOT
            / "crates/proofbound-runtime-linux/src/bin/pbr-native-launcher.rs"
        ).read_text()
        for text in [cli_manifest, linux_manifest, launcher]:
            self.assertNotIn("proofbound-runtime-diagnose", text)
            self.assertNotIn("linux-ptrace-syscall-v1", text)

    def test_each_production_consumer_has_the_required_non_reuse_reason(self):
        verifier = (ROOT / "crates/proofbound-runtime-verify/src/error.rs").read_text()
        composer = (ROOT / "crates/proofbound-runtime-compose/src/main.rs").read_text()
        acceptor = (ROOT / "crates/proofbound-runtime-accept/src/main.rs").read_text()
        acceptance = (ROOT / "crates/proofbound-runtime-accept/src/lib.rs").read_text()
        self.assertIn("profile.diagnostic.not-reusable", verifier)
        self.assertIn("profile.diagnostic.not-reusable", composer)
        self.assertIn("profile.diagnostic.not-reusable", acceptor)
        self.assertIn("diagnostic-profile-not-reusable", acceptance)

    @staticmethod
    def _closed_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON member: {key}")
            value[key] = item
        return value


if __name__ == "__main__":
    unittest.main()
