"""Command and fail-closed tests for native experiment 0001H orchestration."""

from __future__ import annotations

import argparse
import unittest
from pathlib import Path

from experiments.network_authority.run_bypass_syscall_case import (
    BypassSyscallOrchestrationError,
    child_command,
)


class BypassSyscallOrchestrationTests(unittest.TestCase):
    def arguments(self, mechanism: str) -> argparse.Namespace:
        values = dict(
            case="raw-and-packet-sockets", mechanism=mechanism,
            client=Path("/client"), process_limit_control=Path("/limit"),
            routing_child_control=Path("/routing-child"),
            broker_child_control=Path("/broker-child"),
            preconnected_child_control=Path("/channel-child"),
            mechanism_control=Path("/mechanism"), cgroup_directory=Path("/cgroup"),
        )
        return argparse.Namespace(**values)

    def test_direct_commands_preserve_candidate_before_child_and_probe(self) -> None:
        for mechanism in ("landlock-port", "cgroup-endpoint"):
            command = child_command(self.arguments(mechanism), Path("/state"), Path("/output"), None)
            self.assertEqual(command[0], "/mechanism")
            self.assertLess(command.index("/routing-child"), command.index("/client"))

    def test_broker_requires_retained_channel(self) -> None:
        with self.assertRaises(BypassSyscallOrchestrationError):
            child_command(self.arguments("explicit-broker"), Path("/state"), Path("/output"), None)

    def test_fork_case_inserts_process_limit_inside_child_boundary(self) -> None:
        arguments = self.arguments("landlock-port")
        arguments.case = "fork-exec-at-process-limit"
        command = child_command(arguments, Path("/state"), Path("/output"), None)
        self.assertLess(command.index("/routing-child"), command.index("/limit"))
        self.assertLess(command.index("/limit"), command.index("/client"))


if __name__ == "__main__":
    unittest.main()
