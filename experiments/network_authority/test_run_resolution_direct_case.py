"""Falsifiers for direct resolution one-case orchestration."""

from __future__ import annotations

import argparse
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from experiments.network_authority.record_common import canonical_json
from experiments.network_authority.run_resolution_direct_case import (
    ResolutionDirectError,
    boundary_command,
    resolution_fact,
    run,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATRIX = REPOSITORY_ROOT / "experiments/network_authority/decision-matrix.toml"


class ResolutionDirectCaseTests(unittest.TestCase):
    def arguments(self, root: Path, mechanism: str = "landlock-port") -> argparse.Namespace:
        registered = root / "registered.json"
        substitute = root / "substitute.json"
        registered.write_bytes(canonical_json({"resolver": "registered"}))
        substitute.write_bytes(canonical_json({"resolver": "substitute"}))
        return argparse.Namespace(
            case="resolver-configuration-substitution",
            mechanism=mechanism,
            repository_root=REPOSITORY_ROOT,
            matrix=MATRIX,
            case_root=root / "case",
            raw_output=root / "case/raw-cell.json",
            mechanism_control=root / "mechanism-control",
            child_control=root / "child-control",
            client=root / "client.py",
            allowed_certificate=root / "certificate.pem",
            allowed_private_key=root / "private-key.pem",
            registered_resolver=registered,
            substitute_resolver=substitute,
            cgroup_directory=root / "cgroup" if mechanism == "cgroup-endpoint" else None,
        )

    def test_boundary_command_preserves_candidate_before_common_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            landlock = self.arguments(root)
            command = boundary_command(landlock, root / "invoke", "raw-contact", "127.0.0.2", 443)
            self.assertEqual(command[0], str(landlock.mechanism_control))
            self.assertEqual(command[1], "443")
            self.assertIn(str(landlock.child_control), command)
            endpoint = self.arguments(root, "cgroup-endpoint")
            command = boundary_command(endpoint, root / "invoke", "exact", "127.0.0.1", 443)
            self.assertEqual(command[1], str(endpoint.cgroup_directory))
            self.assertEqual(command[2:5], ["127.0.0.1", "fd00::1", "443"])

    def test_resolution_fact_retains_transport_and_terminal_identity(self) -> None:
        response = b"response"
        observation = {
            "address": "127.0.0.2",
            "event": "resolved",
            "responses": [{"transport": "udp", "response_sha256": hashlib.sha256(response).hexdigest()}],
            "terminal_name": "allowed.test",
        }
        self.assertEqual(
            resolution_fact(observation),
            {
                "address": "127.0.0.2",
                "event": "resolved",
                "reason": None,
                "schema": "proofbound-runtime-resolution-fact/1",
                "terminal_name": "allowed.test",
                "transports": ["udp"],
            },
        )
        timeout = resolution_fact({"event": "resolver-rejected", "reason": "timeout", "responses": []})
        self.assertEqual(timeout["transports"], ["udp"])

    def test_endpoint_configuration_substitution_rejects_before_any_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            arguments = self.arguments(root, "cgroup-endpoint")
            with mock.patch("os.geteuid", return_value=0), mock.patch(
                "experiments.network_authority.run_resolution_direct_case.subprocess.Popen"
            ) as started:
                raw = run(arguments)
            started.assert_not_called()
            self.assertEqual(raw["prelaunch_rejection"], "resolver-config-digest-mismatch")
            self.assertFalse(raw["client_started"])
            self.assertTrue(arguments.raw_output.is_file())
            plan = (arguments.case_root / "case-plan.json").read_bytes()
            self.assertIn(hashlib.sha256(arguments.registered_resolver.read_bytes()).hexdigest().encode(), plan)

    def test_missing_cgroup_and_open_resolver_fact_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            arguments = self.arguments(root, "cgroup-endpoint")
            arguments.cgroup_directory = None
            with self.assertRaises(ResolutionDirectError):
                boundary_command(arguments, root / "invoke", "exact", "127.0.0.1", 443)
            with self.assertRaises(ResolutionDirectError):
                resolution_fact({"event": "open", "responses": []})


if __name__ == "__main__":
    unittest.main()
