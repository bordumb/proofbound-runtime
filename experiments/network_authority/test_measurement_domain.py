"""Falsifiers for the experiment 0001I measurement domain."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.measurement_domain import (
    ARCHITECTURES,
    INVENTORY_CATEGORIES,
    MECHANISMS,
    MeasurementDomainError,
    load_measurement_domain,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DOMAIN = REPOSITORY_ROOT / "experiments/network_authority/measurement-domain.toml"


class MeasurementDomainTests(unittest.TestCase):
    def mutate(self, before: bytes, after: bytes) -> Path:
        source = DOMAIN.read_bytes()
        self.assertIn(before, source)
        temporary = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        temporary.write(source.replace(before, after, 1))
        temporary.close()
        return Path(temporary.name)

    def test_repository_domain_is_exact(self) -> None:
        domain = load_measurement_domain(DOMAIN)
        self.assertEqual(len(domain.source_sha256), 64)
        self.assertEqual(tuple(item.identifier for item in domain.profiles), MECHANISMS)
        self.assertEqual(ARCHITECTURES, ("x86_64", "aarch64"))
        for mechanism in MECHANISMS:
            profile = domain.profile(mechanism)
            self.assertTrue(profile.nonzero_inventory_categories)
            self.assertTrue(
                set(profile.nonzero_inventory_categories).issubset(
                    INVENTORY_CATEGORIES
                )
            )
            self.assertTrue(profile.expected_residual_authority)
        self.assertIn(
            "bpf-maps",
            domain.profile("cgroup-endpoint").nonzero_inventory_categories,
        )

    def test_counts_aggregation_and_bit_order_are_frozen(self) -> None:
        mutations = (
            (b"setup_sample_count = 100", b"setup_sample_count = 99"),
            (b"request_sample_count = 100", b"request_sample_count = 101"),
            (b"median_algorithm = \"midpoint-floor\"", b"median_algorithm = \"lower\""),
            (b"p95_algorithm = \"nearest-rank\"", b"p95_algorithm = \"linear\""),
            (b"lifecycle_iteration_count = 1000", b"lifecycle_iteration_count = 999"),
            (
                b"lifecycle_bit_order = \"least-significant-bit-first\"",
                b"lifecycle_bit_order = \"most-significant-bit-first\"",
            ),
        )
        for before, after in mutations:
            with self.subTest(before=before), self.assertRaises(MeasurementDomainError):
                load_measurement_domain(self.mutate(before, after))

    def test_missing_reordered_and_duplicate_profiles_fail_closed(self) -> None:
        marker = b'[[profiles]]\nid = "landlock-port"'
        for replacement in (
            b'[[profiles]]\nid = "unknown"',
            b'[[profiles]]\nid = "cgroup-endpoint"',
            b'unknown = true\n[[profiles]]\nid = "landlock-port"',
        ):
            with self.subTest(replacement=replacement), self.assertRaises(
                MeasurementDomainError
            ):
                load_measurement_domain(self.mutate(marker, replacement))

    def test_inventory_features_and_residual_authority_are_closed(self) -> None:
        mutations = (
            (b'"control-channels"]', b'"control-channels", "unknown"]'),
            (b'"monotonic-clock"]', b'"unknown"]'),
            (
                b'expected_residual_authority = ["registered-operation-via-mediator"]',
                b'expected_residual_authority = ["arbitrary-application-bytes"]',
            ),
        )
        for before, after in mutations:
            with self.subTest(before=before), self.assertRaises(MeasurementDomainError):
                load_measurement_domain(self.mutate(before, after))

    def test_path_must_be_absolute_regular_and_not_symlinked(self) -> None:
        with self.assertRaises(MeasurementDomainError):
            load_measurement_domain(Path("measurement-domain.toml"))
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "domain.toml"
            link.symlink_to(DOMAIN)
            with self.assertRaises(MeasurementDomainError):
                load_measurement_domain(link)


if __name__ == "__main__":
    unittest.main()
