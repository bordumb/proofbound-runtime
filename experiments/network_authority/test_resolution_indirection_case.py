"""Completeness and mutation tests for the experiment 0001G case domain."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.resolution_indirection_case import (
    AMBIENT_VARIABLES,
    DNS_PLANS,
    RESOLUTION_CASE_IDS,
    ResolutionCaseError,
    case_plan,
    load_resolution_matrix,
    parameters_for,
)
from experiments.network_authority.routing_transport_case import MECHANISMS


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATRIX = REPOSITORY_ROOT / "experiments/network_authority/decision-matrix.toml"


class ResolutionIndirectionCaseTests(unittest.TestCase):
    def test_repository_projection_is_exact_and_complete(self) -> None:
        matrix = load_resolution_matrix(MATRIX)
        self.assertEqual(tuple(item.identifier for item in matrix.cases), RESOLUTION_CASE_IDS)
        self.assertEqual(len(matrix.cases), 18)
        self.assertEqual(len(DNS_PLANS), 10)
        self.assertEqual(len(AMBIENT_VARIABLES), 3)
        for case in matrix.cases:
            self.assertEqual(tuple(item.mechanism for item in case.expectations), MECHANISMS)
            self.assertTrue(parameters_for(case.identifier))

    def test_case_plan_freezes_expectation_queries_and_substitution_identities(self) -> None:
        matrix = load_resolution_matrix(MATRIX)
        case = next(item for item in matrix.cases if item.identifier == "ttl-rebind-to-undeclared")
        plan = case_plan(case, "cgroup-endpoint", matrix.source_sha256, "a" * 64, "b" * 64)
        self.assertEqual(plan["expectation"], {"outcome": "denied", "stage": "routing"})
        self.assertEqual(plan["parameters"]["minimum_ttl_wait_ns"], 1_000_000_000)
        self.assertEqual(len(plan["parameters"]["queries"]), 2)
        self.assertEqual(plan["registered_environment"], {})
        self.assertEqual(plan["schema"], "proofbound-runtime-resolution-case-plan/1")
        with self.assertRaises(ResolutionCaseError):
            case_plan(case, "cgroup-endpoint", matrix.source_sha256, "a" * 64, "a" * 64)

    def test_ambient_and_indirection_parameters_are_closed(self) -> None:
        self.assertEqual(
            parameters_for("ambient-http-proxy"),
            {
                "ambient_environment": {"HTTP_PROXY": "https://127.0.0.2:443"},
                "proxy_protocol": "http-connect",
            },
        )
        self.assertEqual(parameters_for("redirect-other-port"), {"redirect_script": "redirect-port"})
        self.assertEqual(parameters_for("socks-target-confusion"), {"proxy_protocol": "socks5"})
        with self.assertRaises(ResolutionCaseError):
            parameters_for("unknown")

    def mutate(self, before: bytes, after: bytes) -> Path:
        self.assertIn(before, MATRIX.read_bytes())
        temporary = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        temporary.write(MATRIX.read_bytes().replace(before, after, 1))
        temporary.close()
        return Path(temporary.name)

    def test_unknown_case_fixture_and_expectation_order_fail_closed(self) -> None:
        first_case = b'id = "stable-a-and-aaaa"'
        first_fixture = (
            b'id = "stable-a-and-aaaa"\n'
            b'slice = "resolution-indirection"\n'
            b'parent_rows = ["exact-service"]\n'
            b'fixture = "scripted-dns"'
        )
        complete = (
            b'expectations = ["landlock-port=allowed@application-protocol", '
            b'"cgroup-endpoint=allowed@application-protocol", '
            b'"explicit-broker=allowed@application-protocol", '
            b'"preconnected-channel=allowed@application-protocol"]'
        )
        paths = (
            self.mutate(first_case, b'id = "unknown-resolution-case"'),
            self.mutate(
                first_fixture,
                first_fixture.replace(b'fixture = "scripted-dns"', b'fixture = "proxy-service"'),
            ),
            self.mutate(
                first_fixture + b'\nattempted_authority = "resolver-policy"\nauthority_exposure = false\nmaximum_seconds = 10\n' + complete,
                first_fixture + b'\nattempted_authority = "resolver-policy"\nauthority_exposure = false\nmaximum_seconds = 10\n' + complete.replace(
                    b'"landlock-port=allowed@application-protocol", "cgroup-endpoint=allowed@application-protocol"',
                    b'"cgroup-endpoint=allowed@application-protocol", "landlock-port=allowed@application-protocol"',
                ),
            ),
        )
        for path in paths:
            with self.subTest(path=path), self.assertRaises(ResolutionCaseError):
                load_resolution_matrix(path)


if __name__ == "__main__":
    unittest.main()
