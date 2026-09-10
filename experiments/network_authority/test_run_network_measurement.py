"""Falsifiers for the experiment 0001I native measurement runner."""

from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.run_network_measurement import (
    MAX_STATE_FILES,
    MeasurementRunError,
    broker_setup_command,
    clock_identity,
    direct_command,
    request_command,
    tree_summary,
)


def arguments(root: Path, mechanism: str) -> argparse.Namespace:
    return argparse.Namespace(
        mechanism=mechanism,
        source_root=root,
        matrix=root / "decision-matrix.toml",
        landlock_control=root / "landlock",
        endpoint_control=root / "endpoint",
        routing_child_control=root / "routing-child",
        broker_child_control=root / "broker-child",
        preconnected_child_control=root / "preconnected-child",
        client=root / "client.py",
        allowed_certificate=root / "allowed.pem",
        allowed_private_key=root / "allowed.key",
        denied_certificate=root / "denied.pem",
        denied_private_key=root / "denied.key",
    )


class NetworkMeasurementRunnerTests(unittest.TestCase):
    def test_shell_records_only_after_namespace_process_reap(self) -> None:
        script = (
            Path(__file__).resolve().parent / "run_network_measurement.sh"
        ).read_text(encoding="utf-8")
        wait_index = script.index('wait "$namespace_pid"')
        cleanup_index = script.index("namespace-cleanup.json")
        record_index = script.index("record_network_measurement \\\n")
        self.assertLess(wait_index, cleanup_index)
        self.assertLess(cleanup_index, record_index)
        self.assertNotIn("exec unshare", script)
        self.assertEqual(script.count("status --porcelain"), 2)
        post_run_identity = script.index("source changed during observation")
        self.assertLess(wait_index, post_run_identity)
        self.assertLess(post_run_identity, record_index)
        incomplete_index = script.index("record_network_measurement_failure")
        failure_exit_index = script.index('exit "$inside_exit"')
        self.assertLess(wait_index, incomplete_index)
        self.assertLess(incomplete_index, failure_exit_index)

    def test_clock_is_one_registered_monotonic_source(self) -> None:
        _clock, name = clock_identity()
        self.assertIn(name, {"CLOCK_MONOTONIC_RAW", "CLOCK_MONOTONIC"})

    def test_direct_setup_commands_install_before_exec(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            landlock = direct_command(
                arguments(root, "landlock-port"), root / "state", None, False
            )
            endpoint = direct_command(
                arguments(root, "cgroup-endpoint"),
                root / "state",
                root / "cgroup",
                True,
            )
            self.assertEqual(landlock[-2:], ["--", "/bin/true"])
            self.assertEqual(
                endpoint[-2:],
                ["--", "/proofbound-measurement-intentionally-absent"],
            )
            self.assertEqual(endpoint[1], str(root / "cgroup"))

    def test_request_commands_reuse_the_exact_functional_runners(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            modules = {}
            for mechanism in (
                "landlock-port", "cgroup-endpoint", "explicit-broker",
                "preconnected-channel",
            ):
                command = request_command(
                    arguments(root, mechanism),
                    root / mechanism,
                    root / "cgroup" if mechanism == "cgroup-endpoint" else None,
                )
                modules[mechanism] = command[command.index("-m") + 1]
                self.assertEqual(command[command.index("--case") + 1], "exact-service-ipv4")
            self.assertEqual(
                modules,
                {
                    "landlock-port": "experiments.network_authority.run_routing_direct_case",
                    "cgroup-endpoint": "experiments.network_authority.run_routing_direct_case",
                    "explicit-broker": "experiments.network_authority.run_routing_broker_case",
                    "preconnected-channel": "experiments.network_authority.run_routing_preconnected_case",
                },
            )

    def test_broker_setup_requires_the_real_ready_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = broker_setup_command(arguments(root, "explicit-broker"), 8, root)
            self.assertEqual(
                command[command.index("--ready") + 1], str(root / "ready.json")
            )
            self.assertEqual(command[command.index("--fd") + 1], "8")

    def test_state_identity_is_closed_bounded_and_symlink_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "b").write_bytes(b"two")
            (root / "a").write_bytes(b"one")
            summary = tree_summary(root)
            self.assertEqual([item["name"] for item in summary["files"]], ["a", "b"])
            self.assertEqual(summary["file_count"], 2)
            self.assertEqual(summary["total_bytes"], 6)
            (root / "link").symlink_to(root / "a")
            with self.assertRaises(MeasurementRunError):
                tree_summary(root)

    def test_state_file_bound_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(MAX_STATE_FILES + 1):
                (root / str(index)).write_bytes(b"x")
            with self.assertRaises(MeasurementRunError):
                tree_summary(root)


if __name__ == "__main__":
    unittest.main()
