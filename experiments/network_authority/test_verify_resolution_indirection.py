"""Independent-verifier mutation tests for experiment 0001G results."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.record_common import canonical_json
from experiments.network_authority.record_resolution_indirection import record
from experiments.network_authority.test_record_resolution_indirection import ResolutionRecorderTests
from experiments.network_authority.verify_resolution_indirection import VerificationError, verify


class ResolutionVerifierTests(unittest.TestCase):
    def result(self, root: Path) -> Path:
        helper = ResolutionRecorderTests()
        evidence = helper.fixture(root)
        return record(helper.arguments(root, evidence, "result"))

    def test_complete_record_verifies_independently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.result(Path(temporary))
            verified = verify(result)
            self.assertTrue(verified["complete"])
            self.assertEqual(verified["matched_case_count"], 18)
            self.assertEqual(verified["mechanism"], "landlock-port")

    def test_outer_digest_inventory_and_unlisted_file_mutations_fail(self) -> None:
        for mutation in ("digest", "missing", "unlisted"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                result = self.result(Path(temporary))
                result_document = json.loads((result / "RESULT.json").read_bytes())
                if mutation == "digest":
                    result_document["inputs"][0]["sha256"] = "0" * 64
                    (result / "RESULT.json").write_bytes(canonical_json(result_document))
                elif mutation == "missing":
                    (result / result_document["inputs"][0]["name"]).unlink()
                else:
                    (result / "unlisted").write_bytes(b"attack\n")
                with self.assertRaises(VerificationError):
                    verify(result)

    def test_cell_raw_and_plan_substitution_fail_even_with_rehashed_outer_input(self) -> None:
        for relative, mutation in (
            (
                "cells/stable-a-and-aaaa/CELL.json",
                lambda value: value["raw"].__setitem__("service_contact_count", 1),
            ),
            (
                "evidence/cases/stable-a-and-aaaa/case-plan.json",
                lambda value: value.__setitem__("registered_environment", {"HTTP_PROXY": "attack"}),
            ),
            (
                "cells/cname-to-undeclared-service/CELL.json",
                lambda value: value["raw"]["resolver_events"][0].__setitem__(
                    "terminal_name", "allowed.test"
                ),
            ),
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                result = self.result(Path(temporary))
                path = result / relative
                value = json.loads(path.read_bytes())
                mutation(value)
                data = canonical_json(value)
                path.write_bytes(data)
                result_document = json.loads((result / "RESULT.json").read_bytes())
                entry = next(item for item in result_document["inputs"] if item["name"] == relative)
                entry["size"] = len(data)
                entry["sha256"] = __import__("hashlib").sha256(data).hexdigest()
                (result / "RESULT.json").write_bytes(canonical_json(result_document))
                with self.assertRaises(VerificationError):
                    verify(result)

    def test_plan_parameters_fail_after_all_containing_manifests_are_rehashed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.result(Path(temporary))
            relative = "evidence/cases/stable-a-and-aaaa/case-plan.json"
            path = result / relative
            plan = json.loads(path.read_bytes())
            plan["parameters"]["queries"][0]["identifier"] = 999
            plan_data = canonical_json(plan)
            path.write_bytes(plan_data)

            evidence_path = result / "evidence-manifest.json"
            evidence = json.loads(evidence_path.read_bytes())
            evidence_entry = next(
                item
                for item in evidence["files"]
                if item["name"] == "cases/stable-a-and-aaaa/case-plan.json"
            )
            evidence_entry["size"] = len(plan_data)
            evidence_entry["sha256"] = hashlib.sha256(plan_data).hexdigest()
            evidence_data = canonical_json(evidence)
            evidence_path.write_bytes(evidence_data)

            outer = json.loads((result / "RESULT.json").read_bytes())
            for name, data in ((relative, plan_data), ("evidence-manifest.json", evidence_data)):
                entry = next(item for item in outer["inputs"] if item["name"] == name)
                entry["size"] = len(data)
                entry["sha256"] = hashlib.sha256(data).hexdigest()
            (result / "RESULT.json").write_bytes(canonical_json(outer))

            with self.assertRaisesRegex(VerificationError, "prelaunch case plan changed"):
                verify(result)


if __name__ == "__main__":
    unittest.main()
