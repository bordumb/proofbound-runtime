#!/usr/bin/env python3
"""Deterministic observation primitives for experiment 0001I."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from experiments.network_authority.measurement_domain import (
    INVENTORY_CATEGORIES,
    LIFECYCLE_FAILURE_CODES,
)


MAX_SAMPLE_NS = 600 * 1_000_000_000


class MeasurementObservationError(Exception):
    """A raw measurement cannot form one closed observation."""


def summarize_samples(samples: Iterable[int], expected_count: int) -> dict[str, object]:
    """Sort exact nanosecond samples and derive frozen integer aggregates."""

    if type(expected_count) is not int or expected_count <= 0:
        raise MeasurementObservationError("sample count bound is invalid")
    values = list(samples)
    if len(values) != expected_count or any(
        type(value) is not int or not 0 < value <= MAX_SAMPLE_NS for value in values
    ):
        raise MeasurementObservationError("sample inventory is invalid")
    values.sort()
    middle = expected_count // 2
    median = (
        values[middle]
        if expected_count % 2 == 1
        else (values[middle - 1] + values[middle]) // 2
    )
    rank = (95 * expected_count + 99) // 100
    return {
        "count": expected_count,
        "median_ns": median,
        "p95_ns": values[rank - 1],
        "samples_ns": values,
    }


def lifecycle_observation(
    outcomes: Sequence[str | None], expected_count: int
) -> dict[str, object]:
    """Encode ordered lifecycle outcomes as one least-significant-first bit set."""

    if type(expected_count) is not int or expected_count <= 0:
        raise MeasurementObservationError("lifecycle count bound is invalid")
    if len(outcomes) != expected_count:
        raise MeasurementObservationError("lifecycle outcome count is invalid")
    bits = bytearray((expected_count + 7) // 8)
    first_failure = None
    passed = 0
    for index, outcome in enumerate(outcomes):
        if outcome is None:
            bits[index // 8] |= 1 << (index % 8)
            passed += 1
            continue
        if outcome not in LIFECYCLE_FAILURE_CODES:
            raise MeasurementObservationError("lifecycle failure code is unknown")
        if first_failure is None:
            first_failure = {"code": outcome, "iteration": index}
    unused = len(bits) * 8 - expected_count
    if unused and bits[-1] & (((1 << unused) - 1) << (8 - unused)):
        raise MeasurementObservationError("lifecycle padding bits are not zero")
    return {
        "bit_order": "least-significant-bit-first",
        "bits_hex": bytes(bits).hex(),
        "first_failure": first_failure,
        "iteration_count": expected_count,
        "passed_count": passed,
    }


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def inventory_observation(
    inventories: Mapping[str, Sequence[Mapping[str, object]]],
    nonzero_categories: Sequence[str],
) -> dict[str, object]:
    """Validate inventory members and derive exact category counts and sizes."""

    if tuple(inventories) != INVENTORY_CATEGORIES:
        raise MeasurementObservationError("inventory category order is not exact")
    if not nonzero_categories or any(
        category not in INVENTORY_CATEGORIES for category in nonzero_categories
    ) or len(set(nonzero_categories)) != len(nonzero_categories):
        raise MeasurementObservationError("nonzero inventory selection is invalid")
    result = {}
    all_roles: set[str] = set()
    for category in INVENTORY_CATEGORIES:
        members = inventories[category]
        if not isinstance(members, Sequence):
            raise MeasurementObservationError("inventory members are invalid")
        normalized = []
        for member in members:
            if not isinstance(member, Mapping) or set(member) != {
                "role", "sha256", "size_bytes"
            }:
                raise MeasurementObservationError("inventory member is not closed")
            role, digest, size = (
                member["role"], member["sha256"], member["size_bytes"]
            )
            if (
                not isinstance(role, str)
                or not role
                or len(role.encode()) > 128
                or role in all_roles
                or not _digest(digest)
                or type(size) is not int
                or size < 0
            ):
                raise MeasurementObservationError("inventory member identity is invalid")
            all_roles.add(role)
            normalized.append(
                {"role": role, "sha256": digest, "size_bytes": size}
            )
        normalized.sort(key=lambda item: item["role"])
        if bool(normalized) != (category in nonzero_categories):
            raise MeasurementObservationError("inventory category presence changed")
        result[category] = {
            "count": len(normalized),
            "members": normalized,
            "total_bytes": sum(item["size_bytes"] for item in normalized),
        }
    return result
