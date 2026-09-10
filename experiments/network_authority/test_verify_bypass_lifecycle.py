"""Independent-verifier mutation tests for experiment 0001H results."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.record_bypass_lifecycle import record
from experiments.network_authority.record_common import canonical_json
from experiments.network_authority.test_record_bypass_lifecycle import BypassRecorderTests
from experiments.network_authority.verify_bypass_lifecycle import VerificationError, verify


class BypassVerifierTests(unittest.TestCase):
    def result(self, root: Path) -> Path:
        helper = BypassRecorderTests()
        evidence = helper.evidence(root)
        return record(helper.arguments(root, evidence))

    @staticmethod
    def rehash(result: Path, relative: str, data: bytes) -> None:
        outer = json.loads((result / "RESULT.json").read_bytes())
        entry = next(item for item in outer["inputs"] if item["name"] == relative)
        entry["size"] = len(data)
        entry["sha256"] = hashlib.sha256(data).hexdigest()
        (result / "RESULT.json").write_bytes(canonical_json(outer))

    def test_complete_record_verifies_independently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            verified = verify(self.result(Path(temporary)))
        self.assertTrue(verified["complete"])
        self.assertEqual(verified["matched_case_count"], 18)

    def test_outer_digest_missing_and_unlisted_mutations_fail(self) -> None:
        for mutation in ("digest", "missing", "unlisted"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                result = self.result(Path(temporary))
                outer = json.loads((result / "RESULT.json").read_bytes())
                if mutation == "digest":
                    outer["inputs"][0]["sha256"] = "0" * 64
                    (result / "RESULT.json").write_bytes(canonical_json(outer))
                elif mutation == "missing":
                    (result / outer["inputs"][0]["name"]).unlink()
                else:
                    (result / "unlisted").write_bytes(b"attack\n")
                with self.assertRaises(VerificationError):
                    verify(result)

    def test_raw_semantics_fail_after_outer_digest_is_rehashed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.result(Path(temporary))
            relative = "cells/pathname-unix-socket/CELL.json"
            path = result / relative
            cell = json.loads(path.read_bytes())
            cell["raw"]["syscall_attempts"][0]["errno"] = 0
            data = canonical_json(cell)
            path.write_bytes(data)
            self.rehash(result, relative, data)
            with self.assertRaises(VerificationError):
                verify(result)

    def test_plan_fails_after_evidence_and_outer_manifests_are_rehashed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.result(Path(temporary))
            relative = "evidence/cases/certificate-and-channel-substitution/case-plan.json"
            path = result / relative
            plan = json.loads(path.read_bytes())
            plan["parameters"]["mutated_subject"] = "channel"
            data = canonical_json(plan)
            path.write_bytes(data)
            evidence_path = result / "evidence-manifest.json"
            evidence = json.loads(evidence_path.read_bytes())
            entry = next(item for item in evidence["files"] if item["name"] == relative.removeprefix("evidence/"))
            entry["size"] = len(data)
            entry["sha256"] = hashlib.sha256(data).hexdigest()
            evidence_data = canonical_json(evidence)
            evidence_path.write_bytes(evidence_data)
            outer = json.loads((result / "RESULT.json").read_bytes())
            for name, contents in ((relative, data), ("evidence-manifest.json", evidence_data)):
                outer_entry = next(item for item in outer["inputs"] if item["name"] == name)
                outer_entry["size"] = len(contents)
                outer_entry["sha256"] = hashlib.sha256(contents).hexdigest()
            (result / "RESULT.json").write_bytes(canonical_json(outer))
            with self.assertRaisesRegex(VerificationError, "prelaunch bypass plan changed"):
                verify(result)


if __name__ == "__main__":
    unittest.main()
