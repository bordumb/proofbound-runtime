"""Falsifiers for experiment 0001H lifecycle evidence primitives."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.bypass_lifecycle_evidence import (
    LifecycleEvidenceError,
    cleanup_evidence,
    crash_evidence,
    no_replace_evidence,
    restart_evidence,
    substitution_evidence,
)


class BypassLifecycleEvidenceTests(unittest.TestCase):
    def test_real_crash_before_and_during_retain_signal_and_identity(self) -> None:
        for phase in ("before-release", "during-exchange"):
            with self.subTest(phase=phase):
                value = crash_evidence(phase)
                self.assertEqual(value["event"], f"mediator-crashed-{phase}")
                self.assertGreater(value["identity"]["pid"], 0)
                self.assertEqual(value["termination"]["status"], "signaled")
        with self.assertRaises(LifecycleEvidenceError):
            crash_evidence("unknown")

    def test_restart_retains_distinct_process_generations(self) -> None:
        value = restart_evidence()
        self.assertNotEqual(value["first"]["pid"], value["second"]["pid"])
        self.assertEqual(value["event"], "mediator-identity-mismatch")

    def test_single_subject_substitution_retains_both_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            subject = Path(temporary) / "subject"
            subject.write_bytes(b"registered\n")
            value = substitution_evidence(subject, b"substitute\n")
            self.assertNotEqual(value["before_sha256"], value["after_sha256"])
            self.assertEqual(value["mutation_count"], 1)

    def test_cleanup_has_no_surviving_process(self) -> None:
        self.assertEqual(cleanup_evidence()["survivor_count"], 0)

    def test_publication_replacement_preserves_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "result"
            value = no_replace_evidence(path)
            self.assertEqual(value["event"], "replacement-rejected")
            self.assertEqual(path.read_bytes(), b"existing-result\n")


if __name__ == "__main__":
    unittest.main()
