"""Falsifiers for experiment 0001F explicit-broker orchestration."""

from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.run_routing_broker_case import (
    TARGET_REJECTION_CASES,
    broker_command,
    broker_endpoints,
    broker_fixture_plan,
    child_command,
    invokes_broker,
)
from experiments.network_authority.routing_transport_case import load_routing_matrix


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATRIX = load_routing_matrix(
    REPOSITORY_ROOT / "experiments/network_authority/decision-matrix.toml"
)


def arguments(root: Path) -> argparse.Namespace:
    return argparse.Namespace(
        child_control=root / "broker-child-control",
        client=root / "routing-mediated-client.py",
        allowed_certificate=root / "allowed-certificate.pem",
        allowed_private_key=root / "allowed-key.pem",
        denied_certificate=root / "denied-certificate.pem",
        denied_private_key=root / "denied-key.pem",
    )


class RoutingBrokerCaseTests(unittest.TestCase):
    def case(self, identifier: str):
        return next(case for case in MATRIX.cases if case.identifier == identifier)

    def test_target_schema_attacks_have_no_remote_fixture(self) -> None:
        for identifier in TARGET_REJECTION_CASES:
            with self.subTest(case=identifier):
                self.assertTrue(invokes_broker(identifier))
                self.assertIsNone(broker_fixture_plan(identifier))
                self.assertEqual(broker_endpoints(identifier), ("127.0.0.1", "127.0.0.1"))

    def test_endpoint_and_certificate_substitutions_are_distinct(self) -> None:
        wrong_certificate = broker_fixture_plan("allowed-endpoint-wrong-certificate")
        endpoint = broker_fixture_plan("alternate-endpoint-allowed-certificate")
        self.assertEqual(wrong_certificate.address, "127.0.0.1")
        self.assertEqual(wrong_certificate.certificate_role, "denied")
        self.assertEqual(endpoint.address, "127.0.0.2")
        self.assertEqual(endpoint.certificate_role, "allowed")
        self.assertEqual(
            broker_endpoints("alternate-endpoint-allowed-certificate"),
            ("127.0.0.2", "127.0.0.1"),
        )

    def test_all_cases_have_an_explicit_or_absent_fixture(self) -> None:
        plans = {case.identifier: broker_fixture_plan(case.identifier) for case in MATRIX.cases}
        self.assertEqual(len(plans), 16)
        self.assertEqual(plans["exact-service-ipv6"].address, "fd00::1")
        self.assertIsNone(plans["ipv4-mapped-ipv6"])
        self.assertIsNone(plans["alternate-address-text"])

    def test_child_and_broker_commands_share_only_the_registered_channel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = self.case("exact-service-ipv6")
            child = child_command(case, arguments(root), root, 9)
            broker = broker_command(case, arguments(root), root, 8)
            self.assertEqual(child[1], "9")
            self.assertNotIn("preconnected-channel", child)
            self.assertEqual(child[child.index("--channel-mode") + 1], "explicit-broker")
            self.assertEqual(broker[broker.index("--dial-address") + 1], "fd00::1")
            self.assertEqual(broker[broker.index("--expected-address") + 1], "fd00::1")


if __name__ == "__main__":
    unittest.main()
