"""Completeness and mutation tests for experiment 0001H's case domain."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.bypass_lifecycle_case import (
    BYPASS_CASE_IDS,
    BypassLifecycleError,
    case_plan,
    load_bypass_matrix,
    parameters_for,
)
from experiments.network_authority.routing_transport_case import MECHANISMS


ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "experiments/network_authority/decision-matrix.toml"


class BypassLifecycleCaseTests(unittest.TestCase):
    def test_repository_projection_is_exact(self) -> None:
        matrix = load_bypass_matrix(MATRIX)
        self.assertEqual(tuple(item.identifier for item in matrix.cases), BYPASS_CASE_IDS)
        self.assertEqual(len(matrix.cases), 18)
        for case in matrix.cases:
            self.assertEqual(tuple(item.mechanism for item in case.expectations), MECHANISMS)
            self.assertTrue(parameters_for(case.identifier))

    def test_plan_freezes_parameters_expectation_and_sorted_identities(self) -> None:
        matrix = load_bypass_matrix(MATRIX)
        case = next(item for item in matrix.cases if item.identifier == "connection-reuse-beyond-count")
        plan = case_plan(case, "explicit-broker", matrix.source_sha256, {"z": "b" * 64, "a": "a" * 64})
        self.assertEqual(plan["expectation"], {"outcome": "denied", "stage": "application-protocol"})
        self.assertEqual(plan["parameters"], {"registered_connections": 1, "attempted_connections": 2})
        self.assertEqual(list(plan["subject_identities"]), ["a", "z"])

    def test_parameter_vocabulary_is_closed(self) -> None:
        self.assertEqual(parameters_for("concurrent-install-and-connect")["child_state"], "stopped")
        self.assertEqual(parameters_for("existing-result-replacement")["publication"], "no-replace")
        with self.assertRaises(BypassLifecycleError):
            parameters_for("unknown")

    def test_unknown_case_and_fixture_fail_closed(self) -> None:
        source = MATRIX.read_bytes()
        for before, after in (
            (b'id = "pathname-unix-socket"', b'id = "unknown-bypass"'),
            (
                b'id = "pathname-unix-socket"\nslice = "bypass-lifecycle"\nparent_rows = ["unix-sockets"]\nfixture = "socket-bypass"',
                b'id = "pathname-unix-socket"\nslice = "bypass-lifecycle"\nparent_rows = ["unix-sockets"]\nfixture = "publication"',
            ),
        ):
            with self.subTest(after=after), tempfile.NamedTemporaryFile(delete=False) as temporary:
                path = Path(temporary.name)
                self.addCleanup(path.unlink, missing_ok=True)
                temporary.write(source.replace(before, after, 1))
            with self.assertRaises(BypassLifecycleError):
                load_bypass_matrix(path)

    def test_invalid_identity_and_mechanism_fail_closed(self) -> None:
        matrix = load_bypass_matrix(MATRIX)
        for mechanism, identities in (("unknown", {"a": "a" * 64}), ("landlock-port", {"a": "not-a-digest"})):
            with self.subTest(mechanism=mechanism), self.assertRaises(BypassLifecycleError):
                case_plan(matrix.cases[0], mechanism, matrix.source_sha256, identities)


if __name__ == "__main__":
    unittest.main()
