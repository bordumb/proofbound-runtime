"""Static closure tests for the experiment 0001H namespace runner."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

from experiments.network_authority.record_bypass_lifecycle import (
    REQUIRED_ARTIFACTS, STAGED_FILES, SUBJECT_NAMES,
)
from experiments.network_authority.routing_transport_case import MECHANISMS


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "experiments/network_authority/run_bypass_lifecycle.sh"
WORKFLOW = ROOT / ".github/workflows/network-authority-experiment.yml"


class BypassLifecycleRunnerTests(unittest.TestCase):
    def test_shell_grammar_is_valid(self) -> None:
        completed = subprocess.run(["bash", "-n", str(RUNNER)], check=False, capture_output=True)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    def test_runner_materializes_exact_artifact_domains(self) -> None:
        self.assertEqual(set(REQUIRED_ARTIFACTS), set(MECHANISMS))
        self.assertEqual(len(STAGED_FILES), 13)
        self.assertEqual(len(SUBJECT_NAMES), 7)
        source = RUNNER.read_text()
        for name in STAGED_FILES | SUBJECT_NAMES:
            with self.subTest(name=name):
                self.assertIn(name, source)

    def test_runner_requires_clean_exact_native_subject(self) -> None:
        source = RUNNER.read_text()
        for required in (
            "status --porcelain", "rev-parse --verify 'HEAD^{commit}'",
            "unshare --net --mount-proc", "ip address add fd00::1/128 dev lo nodad",
            "ip address add fd00::2/128 dev lo nodad", "cmp --silent",
            "[[ ${#bypass_cases[@]} -ne 18 ]]", "--source-commit \"$source_commit\"",
            "experiments.network_authority.verify_bypass_lifecycle",
            "bypass-lifecycle-slice-matched",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        self.assertNotIn("--force", source)

    def test_workflow_runs_every_mechanism_on_both_architectures(self) -> None:
        workflow = WORKFLOW.read_text()
        _prefix, marker, job = workflow.partition("  bypass-lifecycle-slice:\n")
        self.assertTrue(marker)
        job, marker, _suffix = job.partition("\n  landlock-port-control:\n")
        self.assertTrue(marker)
        for mechanism in MECHANISMS:
            with self.subTest(mechanism=mechanism):
                self.assertEqual(job.count(f"          - mechanism: {mechanism}\n"), 2)
        self.assertEqual(job.count("            architecture: x86_64\n"), 4)
        self.assertEqual(job.count("            architecture: aarch64\n"), 4)
        self.assertIn("runs-on: ${{ matrix.runner }}", job)
        self.assertIn("if: always()", job)
        self.assertIn("run_bypass_lifecycle.sh", job)
        self.assertIn("actions/upload-artifact@v4", job)


if __name__ == "__main__":
    unittest.main()
