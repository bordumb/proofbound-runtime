"""Falsifiers for the experiment 0001F routing case domain."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.routing_transport_case import (
    MECHANISMS,
    ROUTING_CASE_IDS,
    RoutingCaseError,
    load_routing_matrix,
    parse_expectation,
    plan_rejection,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATRIX = REPOSITORY_ROOT / "experiments/network_authority/decision-matrix.toml"


class RoutingTransportCaseTests(unittest.TestCase):
    def test_repository_routing_projection_is_exact(self) -> None:
        matrix = load_routing_matrix(MATRIX)
        self.assertEqual(tuple(item.identifier for item in matrix.cases), ROUTING_CASE_IDS)
        self.assertEqual(len(matrix.source_sha256), 64)
        for case in matrix.cases:
            self.assertEqual(tuple(item.mechanism for item in case.expectations), MECHANISMS)
            for mechanism in MECHANISMS:
                self.assertEqual(case.expectation(mechanism).mechanism, mechanism)

    def mutate(self, before: bytes, after: bytes) -> Path:
        self.assertIn(before, MATRIX.read_bytes())
        temporary = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        temporary.write(MATRIX.read_bytes().replace(before, after, 1))
        temporary.close()
        return Path(temporary.name)

    def test_unknown_root_case_and_fixture_fail_closed(self) -> None:
        paths = (
            self.mutate(b'schema = "', b'unknown = true\nschema = "'),
            self.mutate(b'id = "exact-service-ipv4"', b'id = "unknown-case"'),
            self.mutate(
                b'fixture = "dual-stack-tls"', b'fixture = "socket-bypass"'
            ),
        )
        for path in paths:
            with self.subTest(path=path), self.assertRaises(RoutingCaseError):
                load_routing_matrix(path)

    def test_missing_reordered_and_duplicate_expectations_fail_closed(self) -> None:
        complete = (
            b'expectations = ["landlock-port=allowed@application-protocol", '
            b'"cgroup-endpoint=allowed@application-protocol", '
            b'"explicit-broker=allowed@application-protocol", '
            b'"preconnected-channel=allowed@application-protocol"]'
        )
        mutations = (
            complete.replace(
                b', "preconnected-channel=allowed@application-protocol"', b''
            ),
            complete.replace(
                b'"landlock-port=allowed@application-protocol", '
                b'"cgroup-endpoint=allowed@application-protocol"',
                b'"cgroup-endpoint=allowed@application-protocol", '
                b'"landlock-port=allowed@application-protocol"',
            ),
            complete.replace(
                b'"preconnected-channel=allowed@application-protocol"',
                b'"landlock-port=allowed@application-protocol"',
            ),
        )
        for mutation in mutations:
            path = self.mutate(complete, mutation)
            with self.subTest(path=path), self.assertRaises(RoutingCaseError):
                load_routing_matrix(path)

    def test_expectation_grammar_and_vocabulary_are_closed(self) -> None:
        for raw in (
            "landlock-port=success@routing",
            "unknown=denied@routing",
            "landlock-port=denied@magic",
            "landlock-port=denied@routing@tls",
            None,
        ):
            with self.subTest(raw=raw), self.assertRaises(RoutingCaseError):
                parse_expectation(raw)

    def test_frozen_address_attacks_have_exact_plan_rejections(self) -> None:
        self.assertEqual(
            plan_rejection("non-scoped-ipv6-scope-id"), "scope-id-not-allowed"
        )
        self.assertEqual(
            plan_rejection("alternate-address-text"), "address-text-not-canonical"
        )
        self.assertIsNone(plan_rejection("exact-service-ipv4"))
        with self.assertRaises(RoutingCaseError):
            plan_rejection("unknown-case")


if __name__ == "__main__":
    unittest.main()
