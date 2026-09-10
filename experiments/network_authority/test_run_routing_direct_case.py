"""Falsifiers for experiment 0001F direct one-case orchestration."""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.record_common import canonical_json
from experiments.network_authority.run_routing_direct_case import (
    RoutingOrchestrationError,
    boundary_command,
    fixture_command,
    fixture_plan,
    observed_raw,
    read_document,
    validate_ready,
)
from experiments.network_authority.routing_transport_case import load_routing_matrix


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATRIX = load_routing_matrix(
    REPOSITORY_ROOT / "experiments/network_authority/decision-matrix.toml"
)


def arguments(root: Path, mechanism: str) -> argparse.Namespace:
    return argparse.Namespace(
        mechanism=mechanism,
        mechanism_control=root / "mechanism",
        child_control=root / "boundary",
        client=root / "client.py",
        cgroup_directory=root / "cgroup" if mechanism == "cgroup-endpoint" else None,
        allowed_certificate=root / "allowed-certificate.pem",
        allowed_private_key=root / "allowed-key.pem",
        denied_certificate=root / "denied-certificate.pem",
        denied_private_key=root / "denied-key.pem",
    )


class RoutingDirectCaseTests(unittest.TestCase):
    def case(self, identifier: str):
        return next(case for case in MATRIX.cases if case.identifier == identifier)

    def test_every_case_has_one_frozen_fixture_or_explicit_absence(self) -> None:
        observed = {case.identifier: fixture_plan(case.identifier) for case in MATRIX.cases}
        self.assertEqual(len(observed), 16)
        self.assertEqual(observed["exact-service-ipv4"].address, "127.0.0.1")
        self.assertEqual(observed["exact-service-ipv6"].address, "fd00::1")
        self.assertEqual(
            observed["allowed-endpoint-wrong-certificate"].certificate_role,
            "denied",
        )
        self.assertEqual(
            observed["alternate-endpoint-allowed-certificate"].certificate_role,
            "allowed",
        )
        self.assertEqual(observed["direct-udp-dns-shaped"].script, "udp-dns")
        self.assertEqual(observed["direct-udp-quic-shaped"].script, "udp-quic")
        for identifier in (
            "tcp-bind-listen",
            "udp-bind",
            "non-scoped-ipv6-scope-id",
            "alternate-address-text",
        ):
            self.assertIsNone(observed[identifier])

    def test_fixture_readiness_must_match_the_planned_target_exactly(self) -> None:
        plan = fixture_plan("exact-service-ipv4")
        self.assertIsNotNone(plan)
        valid = {
            "address": "127.0.0.1",
            "family": "ipv4",
            "port": 443,
            "schema": "proofbound-runtime-decision-http-ready/1",
        }
        validate_ready(valid, plan)
        for key, value in (("port", 8443), ("address", "127.0.0.2")):
            mutated = dict(valid)
            mutated[key] = value
            with self.subTest(key=key), self.assertRaises(RoutingOrchestrationError):
                validate_ready(mutated, plan)

    def test_mechanism_commands_compose_before_the_same_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = self.case("exact-service-ipv4")
            commands = {
                mechanism: boundary_command(case, arguments(root, mechanism), root)
                for mechanism in ("landlock-port", "cgroup-endpoint")
            }
            landlock = commands["landlock-port"]
            endpoint = commands["cgroup-endpoint"]
            self.assertEqual(landlock[:2], [str(root / "mechanism"), "443"])
            self.assertEqual(endpoint[1:6], [str(root / "cgroup"), "127.0.0.1", "fd00::1", "443", str(root / "mechanism-state")])
            landlock_child = landlock[landlock.index("--") + 1 :]
            endpoint_child = endpoint[endpoint.index("--") + 1 :]
            self.assertEqual(landlock_child, endpoint_child)

    def test_fixture_command_contains_no_case_expectation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = fixture_plan("allowed-endpoint-wrong-certificate")
            self.assertIsNotNone(plan)
            command = fixture_command(plan, arguments(root, "landlock-port"), root)
            joined = " ".join(command)
            self.assertIn(str(root / "denied-certificate.pem"), command)
            self.assertNotIn("denied@tls", joined)
            self.assertNotIn("expect", joined)

    def test_raw_projection_requires_exact_start_marker(self) -> None:
        case = self.case("exact-service-ipv4")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "child-output"
            output.mkdir()
            (output / "started.txt").write_bytes(b"started\n")
            client = {
                "action": case.action,
                "case": case.identifier,
                "errno": None,
                "event": "exact-response",
                "phase": "application-protocol",
                "response_sha256": "a" * 64,
                "schema": "proofbound-runtime-routing-client-observation/1",
                "tls_version": "TLSv1.3",
            }
            (output / "observation.json").write_bytes(canonical_json(client))
            raw = observed_raw(case, "landlock-port", root, 0, True)
            self.assertTrue(raw["client_started"])
            self.assertEqual(raw["client"], client)
            (output / "started.txt").write_bytes(b"late\n")
            with self.assertRaises(RoutingOrchestrationError):
                observed_raw(case, "landlock-port", root, 0, True)

    def test_duplicate_json_names_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_bytes(b'{"event":"first","event":"second"}\n')
            with self.assertRaises(RoutingOrchestrationError):
                read_document(path)


if __name__ == "__main__":
    unittest.main()
