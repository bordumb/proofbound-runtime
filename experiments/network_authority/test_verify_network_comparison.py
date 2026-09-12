"""Falsifiers for independent network comparison verification."""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from itertools import product
from pathlib import Path

from experiments.network_authority.verify_network_comparison import (
    ARCHITECTURES,
    AUTHORITY_RULES,
    MECHANISMS,
    SLICES,
    SLICE_CONTRACTS,
    SliceFact,
    VerificationError,
    canonical_json,
    derive_expected,
    document,
    measurement_profiles,
    verify_comparison_domain,
)


ROOT = Path(__file__).resolve().parents[2]
COMPARISON_DOMAIN = ROOT / "experiments/network_authority/comparison-domain.toml"
MEASUREMENT_DOMAIN = ROOT / "experiments/network_authority/measurement-domain.toml"


def complete_facts() -> list[SliceFact]:
    _, profiles = measurement_profiles(MEASUREMENT_DOMAIN)
    facts = []
    for slice_name, mechanism, architecture in product(SLICES, MECHANISMS, ARCHITECTURES):
        contract = SLICE_CONTRACTS[slice_name]
        measurement = slice_name == "measurement"
        facts.append(
            SliceFact(
                slice=slice_name,
                mechanism=mechanism,
                architecture=architecture,
                source_commit=str(SLICES.index(slice_name) + 1) * 40,
                result_schema=contract[0],
                verification_schema=contract[1],
                result_sha256=(len(facts) + 1).to_bytes(32, "big").hex(),
                decision_matrix_sha256="a" * 64,
                measurement_domain_sha256=(
                    hashlib_sha256(MEASUREMENT_DOMAIN.read_bytes()) if measurement else None
                ),
                complete=True,
                residual_authority=profiles[mechanism] if measurement else None,
                setup={"count": 100, "median_ns": 10, "p95_ns": 20} if measurement else None,
                request={"count": 100, "median_ns": 30, "p95_ns": 40} if measurement else None,
            )
        )
    return facts


def hashlib_sha256(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()


class VerifyNetworkComparisonTests(unittest.TestCase):
    def expected(self, facts: list[SliceFact] | None = None) -> dict[str, object]:
        measurement_sha256, profiles = measurement_profiles(MEASUREMENT_DOMAIN)
        return derive_expected(
            complete_facts() if facts is None else facts,
            verify_comparison_domain(COMPARISON_DOMAIN),
            measurement_sha256,
            profiles,
        )

    def test_independent_derivation_matches_the_closed_result_shape(self) -> None:
        expected = self.expected()
        self.assertTrue(expected["complete"])
        self.assertIsNone(expected["production_selection"])
        self.assertEqual(len(expected["inputs"]), 32)
        observed = {
            item["mechanism"]: item["classification"] for item in expected["mechanisms"]
        }
        for authority, classification in AUTHORITY_RULES.items():
            mechanism = next(
                item["mechanism"]
                for item in expected["mechanisms"]
                if tuple(item["residual_authority"]) == authority
            )
            self.assertEqual(observed[mechanism], classification)

    def test_missing_duplicate_mixed_source_and_authority_drift_fail_closed(self) -> None:
        original = complete_facts()
        variants = [original[:-1], original + [original[0]]]
        mixed_source = original.copy()
        mixed_source[0] = replace(mixed_source[0], source_commit="f" * 40)
        variants.append(mixed_source)
        drift = original.copy()
        index = next(
            i
            for i, item in enumerate(drift)
            if item.slice == "measurement" and item.mechanism == "explicit-broker"
        )
        drift[index] = replace(drift[index], residual_authority=("arbitrary-application-bytes",))
        variants.append(drift)
        for facts in variants:
            with self.subTest(count=len(facts)), self.assertRaises(VerificationError):
                self.expected(facts)

    def test_document_rejects_noncanonical_duplicate_and_unknown_projection(self) -> None:
        expected = self.expected()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "comparison.json"
            path.write_bytes(canonical_json(expected))
            decoded, raw = document(path)
            self.assertEqual(decoded, expected)
            self.assertEqual(raw, canonical_json(expected))
            for invalid in (
                json.dumps(expected, indent=2).encode(),
                b'{"schema":"a","schema":"b"}\n',
            ):
                path.write_bytes(invalid)
                with self.assertRaises(VerificationError):
                    document(path)

    def test_domain_verifier_rejects_rule_mutation(self) -> None:
        source = COMPARISON_DOMAIN.read_bytes()
        mutated = source.replace(
            b'classification = "ineligible-service-identity"',
            b'classification = "eligible-for-adr-review-with-service-session-authority"',
            1,
        )
        with tempfile.NamedTemporaryFile() as temporary:
            path = Path(temporary.name).resolve()
            path.write_bytes(mutated)
            with self.assertRaises(VerificationError):
                verify_comparison_domain(path)


if __name__ == "__main__":
    unittest.main()
