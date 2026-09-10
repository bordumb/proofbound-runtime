"""Mutation and publication tests for the experiment 0001H recorder."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.bypass_lifecycle_case import case_plan, load_bypass_matrix
from experiments.network_authority.record_bypass_lifecycle import (
    REQUIRED_ARTIFACTS, STAGED_FILES, SUBJECT_NAMES, expected_identities, record,
)
from experiments.network_authority.record_common import RecordError, canonical_json
from experiments.network_authority.test_bypass_cell import observed


ROOT = Path(__file__).resolve().parents[2]
MATRIX = load_bypass_matrix(ROOT / "experiments/network_authority/decision-matrix.toml")


class BypassRecorderTests(unittest.TestCase):
    def evidence(self, root: Path, mechanism: str = "landlock-port") -> Path:
        evidence = root / "evidence"; artifacts = evidence / "artifacts"; cases = evidence / "cases"
        artifacts.mkdir(parents=True); cases.mkdir()
        for name in REQUIRED_ARTIFACTS[mechanism] - {"staged", "subjects"}:
            path = artifacts / name; path.write_bytes((name + "\n").encode()); path.chmod(0o755)
        subjects = artifacts / "subjects"; subjects.mkdir()
        for name in SUBJECT_NAMES:
            (subjects / name).write_bytes((name + "\n").encode())
        staged = artifacts / "staged/experiments/network_authority"; staged.mkdir(parents=True)
        (staged.parent / "__init__.py").write_bytes(b"")
        for name in STAGED_FILES:
            (staged / name).write_bytes((name + "\n").encode())
        inventory = {}
        for path in artifacts.rglob("*"):
            if path.is_file():
                inventory[path.relative_to(evidence).as_posix()] = (path.read_bytes(), path.stat().st_mode)
        for case in MATRIX.cases:
            case_root = cases / case.identifier; case_root.mkdir()
            plan = case_plan(case, mechanism, MATRIX.source_sha256, expected_identities(inventory, case.identifier, mechanism))
            (case_root / "case-plan.json").write_bytes(canonical_json(plan))
            (case_root / "raw-cell.json").write_bytes(canonical_json(observed(case, mechanism)))
            (case_root / "trace.txt").write_bytes(b"bounded trace\n")
        return evidence

    def arguments(self, root: Path, evidence: Path, mechanism: str = "landlock-port") -> argparse.Namespace:
        return argparse.Namespace(output=str(root / "result"), source_root=str(ROOT), evidence_root=str(evidence), source_commit="a" * 40, mechanism=mechanism, architecture="x86_64", kernel_release="test-kernel", compiler="test-cc", python="test-python")

    def test_complete_record_publishes_eighteen_matched_cells(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); result = record(self.arguments(root, self.evidence(root)))
            summary = json.loads((result / "RESULT.json").read_bytes())
            self.assertTrue(summary["complete"]); self.assertEqual(summary["matched_case_count"], 18)

    def test_raw_mutation_is_retained_as_harness_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); evidence = self.evidence(root)
            path = evidence / "cases/pathname-unix-socket/raw-cell.json"; raw = json.loads(path.read_bytes()); raw["cleanup"] = False; path.write_bytes(canonical_json(raw))
            result = record(self.arguments(root, evidence)); summary = json.loads((result / "RESULT.json").read_bytes())
            self.assertFalse(summary["complete"]); self.assertEqual(summary["matched_case_count"], 17)

    def test_symlink_and_existing_output_fail_before_replacement(self) -> None:
        for mutation in ("symlink", "existing"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); evidence = self.evidence(root); arguments = self.arguments(root, evidence)
                if mutation == "symlink":
                    path = evidence / "cases/pathname-unix-socket/trace.txt"; path.unlink(); os.symlink("raw-cell.json", path)
                else:
                    (root / "result").mkdir(); (root / "result/sentinel").write_bytes(b"keep\n")
                with self.assertRaises(RecordError):
                    record(arguments)


if __name__ == "__main__":
    unittest.main()
