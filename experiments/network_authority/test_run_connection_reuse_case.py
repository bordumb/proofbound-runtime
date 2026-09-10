"""Command-shape tests for experiment 0001H reuse orchestration."""

from __future__ import annotations

import argparse
import unittest
from pathlib import Path

from experiments.network_authority.run_connection_reuse_case import ReuseOrchestrationError, child_command


class ConnectionReuseOrchestrationTests(unittest.TestCase):
    def arguments(self, mechanism: str) -> argparse.Namespace:
        return argparse.Namespace(mechanism=mechanism, client=Path("/client"), routing_child_control=Path("/routing"), broker_child_control=Path("/broker"), preconnected_child_control=Path("/channel"), mechanism_control=Path("/mechanism"), cgroup_directory=Path("/cgroup"), case_root=Path("/case"))

    def test_direct_candidate_wraps_common_child_and_two_connection_client(self) -> None:
        command = child_command(self.arguments("landlock-port"), Path("/output"), None)
        self.assertLess(command.index("/mechanism"), command.index("/routing"))
        self.assertIn("direct", command)
        self.assertIn("443", command)

    def test_broker_requires_and_retains_exact_channel(self) -> None:
        with self.assertRaises(ReuseOrchestrationError):
            child_command(self.arguments("explicit-broker"), Path("/output"), None)


if __name__ == "__main__":
    unittest.main()
