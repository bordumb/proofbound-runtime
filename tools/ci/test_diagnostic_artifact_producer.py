import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RECEIPT_VECTOR = ROOT / "schemas/vectors/diagnostic/diagnostic-receipt.json"
DRAFT_VECTOR = ROOT / "schemas/vectors/diagnostic/plan-draft.json"
DIAGNOSE_MANIFEST = ROOT / "crates/proofbound-runtime-diagnose/Cargo.toml"
ARTIFACT_SOURCE = ROOT / "crates/proofbound-runtime-diagnose/src/artifact.rs"
DRAFT_SOURCE = ROOT / "crates/proofbound-runtime-diagnose/src/draft.rs"
DIAGNOSTIC_SCHEMA = ROOT / "schemas/diagnostic-receipt-v1.schema.json"
PRODUCTION_MANIFESTS = [
    ROOT / "crates/proofbound-runtime-cli/Cargo.toml",
    ROOT / "crates/proofbound-runtime-linux/Cargo.toml",
]


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class DiagnosticArtifactProducerContractTests(unittest.TestCase):
    def setUp(self):
        self.receipt_bytes = RECEIPT_VECTOR.read_bytes().removesuffix(b"\n")
        self.draft_bytes = DRAFT_VECTOR.read_bytes().removesuffix(b"\n")
        self.receipt = json.loads(self.receipt_bytes)
        self.draft = json.loads(self.draft_bytes)
        self.artifact_source = ARTIFACT_SOURCE.read_text()
        self.draft_source = DRAFT_SOURCE.read_text()

    def test_canonical_vectors_bind_one_exact_non_reusable_projection(self):
        self.assertEqual(self.receipt_bytes, canonical_json(self.receipt))
        self.assertEqual(self.draft_bytes, canonical_json(self.draft))
        self.assertFalse(self.receipt["safe_policy"])
        self.assertFalse(self.receipt["reusable"])
        self.assertFalse(self.draft["safe_policy"])
        self.assertEqual(
            self.draft["diagnostic_receipt_commitment"],
            "sha256:" + hashlib.sha256(self.receipt_bytes).hexdigest(),
        )
        self.assertEqual(
            self.draft["seed_plan"], self.receipt["seed_plan"]["sha256"]
        )
        self.assertEqual(
            len(self.receipt["events"]), self.receipt["bounds"]["event_count"]
        )
        self.assertIn("event-limit", self.receipt["gaps"])
        for field in ["arguments", "environment_names", "gaps"]:
            self.assertEqual(self.draft[field], self.receipt[field])

    def test_draft_keeps_network_gaps_and_human_authority_open(self):
        codes = {item["code"] for item in self.draft["open_items"]}
        self.assertEqual(
            codes,
            {
                "capsec-missing",
                "choose-environment",
                "choose-limits",
                "choose-network-mode",
                "choose-write-roots",
                "diagnostic-gap",
                "network-attempt",
                "observation-unresolved",
            },
        )
        network_events = [
            event
            for event in self.receipt["events"]
            if event["class"] in {"bind", "connect", "sendto", "socket"}
        ]
        self.assertTrue(network_events)
        self.assertIn("network-attempt", codes)
        self.assertNotIn("network", self.draft)
        self.assertNotIn("write", self.draft)
        self.assertNotIn("limits", self.draft)
        self.assertEqual(
            self.draft["breadth"]["denials"],
            sum(event["error"] is not None for event in self.receipt["events"]),
        )
        self.assertEqual(
            self.draft["breadth"]["unresolved_events"],
            sum(
                event["resolution"] in {"redacted", "unresolved"}
                for event in self.receipt["events"]
            ),
        )
        self.assertEqual(
            self.draft["candidates"],
            [
                {
                    "kind": "read",
                    "path": "/workspace/config",
                    "provenance": ["diagnostic-runtime-observation"],
                }
            ],
        )

    def test_diagnostic_producer_is_absent_from_production_dependencies(self):
        diagnose = DIAGNOSE_MANIFEST.read_text()
        self.assertIn("proofbound-runtime-core.workspace = true", diagnose)
        self.assertNotIn("proofbound-runtime-cli", diagnose)
        self.assertNotIn("proofbound-runtime-linux", diagnose)
        for path in PRODUCTION_MANIFESTS:
            manifest = path.read_text()
            self.assertNotIn("proofbound-runtime-diagnose", manifest, path)

    def test_redaction_paths_bounds_and_capsec_are_closed_in_source(self):
        schema = json.loads(DIAGNOSTIC_SCHEMA.read_text())
        path_operands = schema["$defs"]["pathOperands"]
        self.assertIn("symlink_hops", path_operands["required"])
        self.assertEqual(
            path_operands["properties"]["symlink_hops"]["maximum"], 40
        )
        redacted_rule = next(
            rule
            for rule in schema["$defs"]["event"]["allOf"]
            if rule.get("if", {}).get("properties", {}).get("resolution")
            == {"const": "redacted"}
        )
        redacted_operands = redacted_rule["then"]["properties"]["operands"][
            "oneOf"
        ]
        self.assertIn(
            {"properties": {"path": {"type": "null"}}},
            redacted_operands[0]["allOf"],
        )
        self.assertIn(
            {"properties": {"address": {"type": "null"}}},
            redacted_operands[2]["allOf"],
        )
        for guard in [
            "retains_redacted_target",
            "is_normalized_absolute_path",
            "SymlinkBoundExceeded",
            "event_limit_reached",
            "per_process_limit_reached",
            "process_limit_reached",
        ]:
            self.assertIn(guard, self.artifact_source)
        for guard in [
            "observation.report != profile.report",
            "DraftPathScope",
            "is_system_path",
            "receipt.output_bound()",
            "OutputBoundExceeded",
        ]:
            self.assertIn(guard, self.draft_source)


if __name__ == "__main__":
    unittest.main()
