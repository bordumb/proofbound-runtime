"""Falsifiers for the experiment 0001E deterministic comparison domain."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.comparison_domain import (
    ARCHITECTURES,
    CLASSIFICATIONS,
    MECHANISMS,
    SLICES,
    ComparisonDomainError,
    load_comparison_domain,
)
from experiments.network_authority.measurement_domain import load_measurement_domain


ROOT = Path(__file__).resolve().parents[2]
DOMAIN = ROOT / "experiments/network_authority/comparison-domain.toml"
MEASUREMENT_DOMAIN = ROOT / "experiments/network_authority/measurement-domain.toml"


class ComparisonDomainTests(unittest.TestCase):
    def mutate(self, before: bytes, after: bytes) -> Path:
        source = DOMAIN.read_bytes()
        self.assertIn(before, source)
        temporary = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        temporary.write(source.replace(before, after, 1))
        temporary.close()
        return Path(temporary.name)

    def test_repository_domain_is_closed_and_covers_measurement_profiles(self) -> None:
        domain = load_comparison_domain(DOMAIN)
        measurement = load_measurement_domain(MEASUREMENT_DOMAIN)
        self.assertEqual(tuple(item.identifier for item in domain.slice_contracts), SLICES)
        self.assertEqual(ARCHITECTURES, ("x86_64", "aarch64"))
        self.assertEqual(len(MECHANISMS), 4)
        self.assertEqual(len(CLASSIFICATIONS), 4)
        for mechanism in MECHANISMS:
            residual = measurement.profile(mechanism).expected_residual_authority
            classification = domain.classify(residual)
            if mechanism in {"landlock-port", "cgroup-endpoint"}:
                self.assertEqual(classification, "ineligible-service-identity")
            else:
                self.assertTrue(classification.startswith("eligible-for-adr-review-with-"))

    def test_unknown_or_partial_residual_authority_fails_closed(self) -> None:
        domain = load_comparison_domain(DOMAIN)
        for residual in (
            (),
            ("arbitrary-application-bytes",),
            ("unknown",),
            ("registered-operation-via-mediator", "arbitrary-application-bytes"),
        ):
            with self.subTest(residual=residual), self.assertRaises(ComparisonDomainError):
                domain.classify(residual)

    def test_slice_schema_count_and_order_are_frozen(self) -> None:
        mutations = (
            (b'functional_case_count = 16', b'functional_case_count = 15'),
            (
                b'result_schema = "proofbound-runtime-resolution-result/1"',
                b'result_schema = "proofbound-runtime-resolution-result/2"',
            ),
            (b'id = "routing-transport"', b'id = "resolution-indirection"'),
        )
        for before, after in mutations:
            with self.subTest(before=before), self.assertRaises(ComparisonDomainError):
                load_comparison_domain(self.mutate(before, after))

    def test_classification_and_authority_changes_fail_closed(self) -> None:
        mutations = (
            (
                b'classification = "ineligible-service-identity"',
                b'classification = "eligible-for-adr-review-with-service-session-authority"',
            ),
            (
                b'residual_authority = ["registered-operation-via-mediator"]',
                b'residual_authority = ["arbitrary-application-bytes"]',
            ),
            (
                b'"incomplete-experiment"]',
                b'"incomplete-experiment", "selected"]',
            ),
        )
        for before, after in mutations:
            with self.subTest(before=before), self.assertRaises(ComparisonDomainError):
                load_comparison_domain(self.mutate(before, after))

    def test_path_must_be_absolute_regular_and_not_symlinked(self) -> None:
        with self.assertRaises(ComparisonDomainError):
            load_comparison_domain(Path("comparison-domain.toml"))
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "domain.toml"
            link.symlink_to(DOMAIN)
            with self.assertRaises(ComparisonDomainError):
                load_comparison_domain(link)


if __name__ == "__main__":
    unittest.main()
