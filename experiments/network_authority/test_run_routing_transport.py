"""Static closure tests for the experiment 0001F namespace runner."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

from experiments.network_authority.record_routing_transport import (
    REQUIRED_ARTIFACTS,
    STAGED_NETWORK_FILES,
)
from experiments.network_authority.routing_transport_case import MECHANISMS


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RUNNER = REPOSITORY_ROOT / "experiments/network_authority/run_routing_transport.sh"


class RoutingTransportRunnerTests(unittest.TestCase):
    def test_shell_grammar_is_valid(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    def test_every_mechanism_has_closed_artifact_and_staged_source_sets(self) -> None:
        self.assertEqual(set(REQUIRED_ARTIFACTS), set(MECHANISMS))
        self.assertEqual(set(STAGED_NETWORK_FILES), set(MECHANISMS))
        for mechanism in MECHANISMS:
            with self.subTest(mechanism=mechanism):
                self.assertIn("staged", REQUIRED_ARTIFACTS[mechanism])
                self.assertIn("__init__.py", STAGED_NETWORK_FILES[mechanism])
                self.assertIn("record_common.py", STAGED_NETWORK_FILES[mechanism])

    def test_runner_requires_clean_subject_namespace_and_no_replace_result(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for required in (
            "status --porcelain",
            "rev-parse --verify 'HEAD^{commit}'",
            "unshare --net --mount-proc",
            "ip address add fd00::1/128 dev lo nodad",
            "ip address add fd00::2/128 dev lo nodad",
            "cmp --silent",
            '[[ ${#routing_cases[@]} -ne 16 ]]',
            "routing-transport-slice-matched",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        self.assertNotIn("--force", source)


if __name__ == "__main__":
    unittest.main()
