"""Falsifiers for deterministic comparison of verified network results."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from itertools import product
from pathlib import Path

from experiments.network_authority.compare_network_results import (
    ComparisonError,
    VerifiedSlice,
    canonical_json,
    compare_verified_results,
    publish_new,
)
from experiments.network_authority.comparison_domain import (
    ARCHITECTURES,
    MECHANISMS,
    SLICES,
    load_comparison_domain,
)
from experiments.network_authority.measurement_domain import load_measurement_domain


ROOT = Path(__file__).resolve().parents[2]
DOMAIN = load_comparison_domain(
    ROOT / "experiments/network_authority/comparison-domain.toml"
)
MEASUREMENT = load_measurement_domain(
    ROOT / "experiments/network_authority/measurement-domain.toml"
)


def complete_inputs() -> list[VerifiedSlice]:
    result = []
    for slice_name, mechanism, architecture in product(SLICES, MECHANISMS, ARCHITECTURES):
        contract = DOMAIN.slice(slice_name)
        measurement = slice_name == "measurement"
        profile = MEASUREMENT.profile(mechanism)
        result.append(
            VerifiedSlice(
                slice=slice_name,
                mechanism=mechanism,
                architecture=architecture,
                source_commit=(SLICES.index(slice_name) + 1) * "1" + (39 * "0"),
                result_schema=contract.result_schema,
                verification_schema=contract.verification_schema,
                result_sha256=(len(result) + 1).to_bytes(32, "big").hex(),
                decision_matrix_sha256="a" * 64,
                measurement_domain_sha256=(
                    MEASUREMENT.source_sha256 if measurement else None
                ),
                complete=True,
                conclusion=contract.complete_conclusion,
                residual_authority=(
                    profile.expected_residual_authority if measurement else None
                ),
                setup_summary=(
                    {"count": 100, "median_ns": 10, "p95_ns": 20}
                    if measurement
                    else None
                ),
                request_summary=(
                    {"count": 100, "median_ns": 30, "p95_ns": 40}
                    if measurement
                    else None
                ),
            )
        )
    return result


class CompareNetworkResultsTests(unittest.TestCase):
    def test_complete_inventory_has_only_review_eligibility_and_no_selection(self) -> None:
        result = compare_verified_results(DOMAIN, MEASUREMENT, complete_inputs())
        self.assertTrue(result["complete"])
        self.assertEqual(result["conclusion"], "network-candidates-ready-for-adr-review")
        self.assertIsNone(result["production_selection"])
        classifications = {
            item["mechanism"]: item["classification"] for item in result["mechanisms"]
        }
        self.assertEqual(classifications["landlock-port"], "ineligible-service-identity")
        self.assertEqual(classifications["cgroup-endpoint"], "ineligible-service-identity")
        self.assertEqual(
            classifications["explicit-broker"],
            "eligible-for-adr-review-with-explicit-operation-authority",
        )
        self.assertEqual(
            classifications["preconnected-channel"],
            "eligible-for-adr-review-with-service-session-authority",
        )
        self.assertEqual(len(result["inputs"]), 32)
        self.assertEqual(canonical_json(result), canonical_json(result))

    def test_missing_duplicate_and_cross_architecture_substitution_fail_closed(self) -> None:
        original = complete_inputs()
        variants = (
            original[:-1],
            original + [original[0]],
            original[:-1] + [replace(original[-1], architecture="x86_64")],
        )
        for values in variants:
            with self.subTest(count=len(values)), self.assertRaises(ComparisonError):
                compare_verified_results(DOMAIN, MEASUREMENT, values)

    def test_mixed_matrix_source_and_measurement_domain_fail_closed(self) -> None:
        original = complete_inputs()
        mutations = (
            replace(original[0], decision_matrix_sha256="b" * 64),
            replace(original[0], source_commit="f" * 40),
            replace(original[-1], measurement_domain_sha256="c" * 64),
        )
        for mutation in mutations:
            values = original.copy()
            values[0 if mutation.slice != "measurement" else -1] = mutation
            with self.subTest(mutation=mutation), self.assertRaises(ComparisonError):
                compare_verified_results(DOMAIN, MEASUREMENT, values)

    def test_residual_authority_drift_fails_instead_of_broadening_eligibility(self) -> None:
        values = complete_inputs()
        index = next(
            i
            for i, item in enumerate(values)
            if item.slice == "measurement"
            and item.mechanism == "explicit-broker"
            and item.architecture == "aarch64"
        )
        values[index] = replace(
            values[index], residual_authority=("arbitrary-application-bytes",)
        )
        with self.assertRaisesRegex(ComparisonError, "residual authority"):
            compare_verified_results(DOMAIN, MEASUREMENT, values)

    def test_verified_incomplete_measurement_cannot_be_eligible(self) -> None:
        values = complete_inputs()
        for index, item in enumerate(values):
            if item.slice == "measurement" and item.mechanism == "explicit-broker":
                values[index] = replace(
                    item,
                    complete=False,
                    conclusion="network-measurement-incomplete",
                    residual_authority=None,
                    setup_summary=None,
                    request_summary=None,
                )
        result = compare_verified_results(DOMAIN, MEASUREMENT, values)
        self.assertFalse(result["complete"])
        broker = next(
            item for item in result["mechanisms"] if item["mechanism"] == "explicit-broker"
        )
        self.assertEqual(broker["classification"], "incomplete-experiment")
        self.assertIsNone(broker["residual_authority"])

    def test_publication_is_no_replace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / "comparison.json"
            publish_new(output, b"first\n")
            with self.assertRaises(FileExistsError):
                publish_new(output, b"second\n")
            self.assertEqual(output.read_bytes(), b"first\n")


if __name__ == "__main__":
    unittest.main()
