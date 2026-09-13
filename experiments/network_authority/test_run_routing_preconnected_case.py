"""Falsifiers for experiment 0001F preconnected-channel orchestration."""

from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.run_routing_preconnected_case import (
    DIRECT_CASES,
    PRELAUNCH_DETAILS,
    child_command,
    connector_endpoints,
    connector_plan,
    primary_fixture_plan,
)
from experiments.network_authority.routing_transport_case import load_routing_matrix


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATRIX = load_routing_matrix(
    REPOSITORY_ROOT / "experiments/network_authority/decision-matrix.toml"
)


class RoutingPreconnectedCaseTests(unittest.TestCase):
    def case(self, identifier: str):
        return next(case for case in MATRIX.cases if case.identifier == identifier)

    def test_every_case_has_a_closed_primary_fixture_decision(self) -> None:
        plans = {case.identifier: primary_fixture_plan(case.identifier) for case in MATRIX.cases}
        self.assertEqual(len(plans), 16)
        self.assertEqual(plans["exact-service-ipv6"].address, "fd00::1")
        self.assertEqual(
            plans["allowed-endpoint-wrong-certificate"].certificate_role,
            "denied",
        )
        for case_id in set(PRELAUNCH_DETAILS) - {
            "allowed-endpoint-wrong-certificate",
            "alternate-endpoint-allowed-certificate",
        }:
            self.assertIsNone(plans[case_id])

    def test_direct_attacks_get_a_separate_authenticated_connector(self) -> None:
        for case_id in DIRECT_CASES:
            with self.subTest(case=case_id):
                plan = connector_plan(case_id)
                self.assertEqual(plan.address, "127.0.0.1")
                self.assertEqual(plan.certificate_role, "allowed")
                self.assertEqual(connector_endpoints(case_id), ("127.0.0.1", "127.0.0.1"))

    def test_substitution_rejections_are_before_child_release(self) -> None:
        self.assertEqual(len(PRELAUNCH_DETAILS), 7)
        self.assertEqual(
            PRELAUNCH_DETAILS["allowed-endpoint-wrong-certificate"],
            "certificate-rejected",
        )
        self.assertEqual(
            connector_endpoints("alternate-endpoint-allowed-certificate"),
            ("127.0.0.2", "127.0.0.1"),
        )

    def test_child_command_pins_channel_cookie_and_peer_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            arguments = argparse.Namespace(
                child_control=root / "preconnected-child-control",
                client=root / "routing-mediated-client.py",
            )
            command = child_command(
                self.case("exact-service-ipv4"),
                arguments,
                root,
                9,
                12345,
                {"pid": 77, "uid": 0, "gid": 0},
            )
            self.assertEqual(command[1:7], ["9", "12345", "77", "0", "0", str(root / "child-boundary")])
            self.assertEqual(
                command[command.index("--channel-mode") + 1],
                "preconnected-channel",
            )


if __name__ == "__main__":
    unittest.main()
