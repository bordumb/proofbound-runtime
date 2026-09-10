"""Falsifiers for experiment 0001H lifecycle orchestration."""

from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from experiments.network_authority.run_bypass_lifecycle_case import SUBJECTS, run


ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "experiments/network_authority/decision-matrix.toml"


class BypassLifecycleOrchestrationTests(unittest.TestCase):
    def arguments(self, root: Path, case: str, mechanism: str = "explicit-broker") -> argparse.Namespace:
        subjects = root / "subjects"
        subjects.mkdir()
        for name in SUBJECTS:
            (subjects / name).write_bytes((name + "\n").encode())
        return argparse.Namespace(
            case=case, mechanism=mechanism, repository_root=ROOT, matrix=MATRIX,
            case_root=root / "case", raw_output=root / "case/raw-cell.json",
            subject_root=subjects, foreign_fd=None,
        )

    def test_non_mediator_mechanism_rejects_crash_case_at_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch("os.geteuid", return_value=0):
            raw = run(self.arguments(Path(temporary), "mediator-crash-during-exchange", "landlock-port"))
        self.assertEqual(raw["plan_rejection"], "mechanism-has-no-mediator")

    def test_substitution_is_real_and_rejected_prelaunch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch("os.geteuid", return_value=0):
            arguments = self.arguments(Path(temporary), "certificate-and-channel-substitution")
            raw = run(arguments)
            self.assertEqual((arguments.case_root / "mutated-subject").read_bytes(), b"proofbound-substitute-subject\n")
            self.assertTrue((arguments.case_root / "lifecycle-evidence.json").is_file())
        self.assertEqual(raw["prelaunch_rejection"], "certificate-channel-identity-mismatch")

    def test_existing_result_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch("os.geteuid", return_value=0):
            arguments = self.arguments(Path(temporary), "existing-result-replacement")
            raw = run(arguments)
            self.assertEqual((arguments.case_root / "existing-result").read_bytes(), b"existing-result\n")
        self.assertTrue(raw["publication_preserved"])

    def test_cleanup_injection_terminates_its_real_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch("os.geteuid", return_value=0):
            raw = run(self.arguments(Path(temporary), "cleanup-and-namespace-teardown-failure"))
        self.assertEqual(raw["survivor_count"], 0)
        self.assertEqual(raw["events"], ["teardown-failure-injected", "failure-retained"])


if __name__ == "__main__":
    unittest.main()
