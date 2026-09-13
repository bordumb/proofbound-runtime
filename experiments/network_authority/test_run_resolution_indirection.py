"""Static closure tests for the experiment 0001G namespace runner."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

from experiments.network_authority.record_resolution_indirection import (
    REQUIRED_ARTIFACTS,
    STAGED_NETWORK_FILES,
)
from experiments.network_authority.routing_transport_case import MECHANISMS


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RUNNER = REPOSITORY_ROOT / "experiments/network_authority/run_resolution_indirection.sh"
WORKFLOW = REPOSITORY_ROOT / ".github/workflows/network-authority-experiment.yml"


class ResolutionIndirectionRunnerTests(unittest.TestCase):
    def test_shell_grammar_is_valid(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    def test_every_mechanism_has_exact_artifact_and_staged_source_sets(self) -> None:
        self.assertEqual(set(REQUIRED_ARTIFACTS), set(MECHANISMS))
        self.assertEqual(len(STAGED_NETWORK_FILES), 8)
        for mechanism in MECHANISMS:
            with self.subTest(mechanism=mechanism):
                self.assertIn("staged", REQUIRED_ARTIFACTS[mechanism])
        for name in (
            "__init__.py",
            "record_common.py",
            "resolution_indirection_client.py",
            "resolution_network_client.py",
        ):
            self.assertIn(name, STAGED_NETWORK_FILES)

    def test_runner_requires_clean_subject_namespace_and_no_replace_result(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for required in (
            "status --porcelain",
            "rev-parse --verify 'HEAD^{commit}'",
            "unshare --net --mount-proc",
            "ip address add fd00::1/128 dev lo nodad",
            "ip address add fd00::2/128 dev lo nodad",
            "cmp --silent",
            "[[ ${#resolution_cases[@]} -ne 18 ]]",
            "experiments.network_authority.verify_resolution_indirection",
            "resolution-indirection-slice-matched",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        self.assertNotIn("--force", source)

    def test_workflow_runs_every_mechanism_on_both_architectures(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        _prefix, marker, job = workflow.partition("  resolution-indirection-slice:\n")
        self.assertTrue(marker)
        job, marker, _suffix = job.partition("\n  bypass-lifecycle-slice:\n")
        self.assertTrue(marker)
        for mechanism in MECHANISMS:
            with self.subTest(mechanism=mechanism):
                self.assertEqual(job.count(f"          - mechanism: {mechanism}\n"), 2)
        self.assertEqual(job.count("            architecture: x86_64\n"), 4)
        self.assertEqual(job.count("            architecture: aarch64\n"), 4)
        self.assertIn("runs-on: ${{ matrix.runner }}", job)
        self.assertIn("if: always()", job)
        self.assertIn("run_resolution_indirection.sh", job)
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
            " # v7.0.1",
            job,
        )


if __name__ == "__main__":
    unittest.main()
