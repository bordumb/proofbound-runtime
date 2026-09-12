"""Tests for deterministic experiment 0001I observation primitives."""

from __future__ import annotations

import unittest

from experiments.network_authority.measurement_domain import INVENTORY_CATEGORIES
from experiments.network_authority.measurement_observation import (
    MeasurementObservationError,
    inventory_observation,
    lifecycle_observation,
    summarize_samples,
)


DIGEST = "0" * 64


class MeasurementObservationTests(unittest.TestCase):
    def test_even_samples_use_midpoint_floor_and_nearest_rank_p95(self) -> None:
        samples = list(range(100, 0, -1))
        self.assertEqual(
            summarize_samples(samples, 100),
            {
                "count": 100,
                "median_ns": 50,
                "p95_ns": 95,
                "samples_ns": list(range(1, 101)),
            },
        )

    def test_odd_samples_use_middle_value(self) -> None:
        result = summarize_samples([9, 1, 5], 3)
        self.assertEqual(result["median_ns"], 5)
        self.assertEqual(result["p95_ns"], 9)

    def test_invalid_samples_fail_closed(self) -> None:
        for samples, count in (([1], 2), ([0], 1), ([True], 1), ([600_000_000_001], 1)):
            with self.subTest(samples=samples), self.assertRaises(
                MeasurementObservationError
            ):
                summarize_samples(samples, count)

    def test_lifecycle_bits_are_least_significant_first(self) -> None:
        outcomes = [None, "cleanup-failed", None, None, None, None, None, None, None]
        self.assertEqual(
            lifecycle_observation(outcomes, 9),
            {
                "bit_order": "least-significant-bit-first",
                "bits_hex": "fd01",
                "first_failure": {"code": "cleanup-failed", "iteration": 1},
                "iteration_count": 9,
                "passed_count": 8,
            },
        )

    def test_lifecycle_inventory_and_code_are_closed(self) -> None:
        for outcomes, count in (([None], 2), (["unknown"], 1)):
            with self.subTest(outcomes=outcomes), self.assertRaises(
                MeasurementObservationError
            ):
                lifecycle_observation(outcomes, count)

    def test_inventory_totals_are_derived_from_sorted_members(self) -> None:
        inventories = {category: [] for category in INVENTORY_CATEGORIES}
        inventories["trusted-binaries"] = [
            {"role": "z-control", "sha256": DIGEST, "size_bytes": 4},
            {"role": "a-child", "sha256": "1" * 64, "size_bytes": 3},
        ]
        result = inventory_observation(inventories, ["trusted-binaries"])
        self.assertEqual(result["trusted-binaries"]["count"], 2)
        self.assertEqual(result["trusted-binaries"]["total_bytes"], 7)
        self.assertEqual(
            [item["role"] for item in result["trusted-binaries"]["members"]],
            ["a-child", "z-control"],
        )
        self.assertEqual(result["bpf-maps"]["count"], 0)

    def test_inventory_rejects_presence_drift_and_duplicate_roles(self) -> None:
        empty = {category: [] for category in INVENTORY_CATEGORIES}
        with self.assertRaises(MeasurementObservationError):
            inventory_observation(empty, ["trusted-binaries"])
        duplicate = {category: [] for category in INVENTORY_CATEGORIES}
        member = {"role": "same", "sha256": DIGEST, "size_bytes": 1}
        duplicate["trusted-binaries"] = [member]
        duplicate["certificates"] = [member]
        with self.assertRaises(MeasurementObservationError):
            inventory_observation(
                duplicate, ["trusted-binaries", "certificates"]
            )


if __name__ == "__main__":
    unittest.main()
