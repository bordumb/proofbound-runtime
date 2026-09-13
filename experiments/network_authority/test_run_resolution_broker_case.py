"""Falsifiers for resolution broker one-case orchestration."""

from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from experiments.network_authority.record_common import canonical_json
from experiments.network_authority.run_resolution_broker_case import (
    broker_command,
    child_command,
    run,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATRIX = REPOSITORY_ROOT / "experiments/network_authority/decision-matrix.toml"


class ResolutionBrokerCaseTests(unittest.TestCase):
    def arguments(self, root: Path, case: str) -> argparse.Namespace:
        registered = root / "registered.json"
        substitute = root / "substitute.json"
        registered.write_bytes(canonical_json({"resolver": "registered"}))
        substitute.write_bytes(canonical_json({"resolver": "substitute"}))
        return argparse.Namespace(
            case=case,
            repository_root=REPOSITORY_ROOT,
            matrix=MATRIX,
            case_root=root / "case",
            raw_output=root / "case/raw-cell.json",
            child_control=root / "child-control",
            client=root / "client.py",
            allowed_certificate=root / "certificate.pem",
            allowed_private_key=root / "private-key.pem",
            registered_resolver=registered,
            substitute_resolver=substitute,
        )

    def test_commands_preserve_closed_mode_action_and_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            arguments = self.arguments(root, "redirect-undeclared-host")
            invocation = root / "invoke"
            child = child_command(arguments, invocation, 7, "broker-redirect-rejected")
            broker = broker_command(arguments, invocation, 8, "redirect-reject", "redirect-host", "127.0.0.1")
            self.assertEqual(child[1:4], ["7", str(invocation / "child-boundary"), "--"])
            self.assertIn("broker-redirect-rejected", child)
            self.assertIn("redirect-reject", broker)
            self.assertEqual(broker[-2:], ["--redirect-script", "redirect-host"])

    def test_ambient_proxy_rejects_at_plan_without_process_or_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            arguments = self.arguments(Path(temporary), "ambient-http-proxy")
            with mock.patch("os.geteuid", return_value=0), mock.patch(
                "experiments.network_authority.run_resolution_broker_case.subprocess.Popen"
            ) as started:
                raw = run(arguments)
            started.assert_not_called()
            self.assertEqual(raw["plan_rejection"], "ambient-environment-present")
            self.assertFalse(raw["client_started"])

    def test_resolver_substitution_rejects_prelaunch_without_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            arguments = self.arguments(Path(temporary), "resolver-configuration-substitution")
            with mock.patch("os.geteuid", return_value=0), mock.patch(
                "experiments.network_authority.run_resolution_broker_case.subprocess.Popen"
            ) as started:
                raw = run(arguments)
            started.assert_not_called()
            self.assertEqual(raw["prelaunch_rejection"], "resolver-config-digest-mismatch")


if __name__ == "__main__":
    unittest.main()
