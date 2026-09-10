#!/usr/bin/env python3
"""Deterministically compare independently verified experiment 0001 results."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from itertools import product
from pathlib import Path
from typing import Callable

from experiments.network_authority import verify_bypass_lifecycle
from experiments.network_authority import verify_network_measurement
from experiments.network_authority import verify_resolution_indirection
from experiments.network_authority import verify_routing_transport
from experiments.network_authority.comparison_domain import (
    ARCHITECTURES,
    MECHANISMS,
    SLICES,
    ComparisonDomain,
    ComparisonDomainError,
    load_comparison_domain,
)
from experiments.network_authority.measurement_domain import (
    MeasurementDomain,
    MeasurementDomainError,
    load_measurement_domain,
)


MAX_JSON_BYTES = 1024 * 1024
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
OUTPUT_SCHEMA = "proofbound-runtime-network-comparison/1"
VERIFIERS: dict[str, Callable[[Path], dict[str, object]]] = {
    "routing-transport": verify_routing_transport.verify,
    "resolution-indirection": verify_resolution_indirection.verify,
    "bypass-lifecycle": verify_bypass_lifecycle.verify,
    "measurement": verify_network_measurement.verify,
}


class ComparisonError(Exception):
    """The result set cannot support the deterministic comparison."""


@dataclass(frozen=True)
class VerifiedSlice:
    """Facts retained after an independent slice verifier accepts one result."""

    slice: str
    mechanism: str
    architecture: str
    source_commit: str
    result_schema: str
    verification_schema: str
    result_sha256: str
    decision_matrix_sha256: str
    measurement_domain_sha256: str | None
    complete: bool
    conclusion: str
    residual_authority: tuple[str, ...] | None
    setup_summary: dict[str, object] | None
    request_summary: dict[str, object] | None


def canonical_json(value: object) -> bytes:
    """Return the experiment's canonical JSON encoding with one final newline."""

    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ComparisonError("comparison JSON contains a duplicate name")
        result[key] = value
    return result


def _regular_bytes(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ComparisonError(f"comparison input is unavailable: {path.name}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_JSON_BYTES:
        raise ComparisonError(f"comparison input is not bounded and regular: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise ComparisonError("comparison input identity changed")
        data = os.read(descriptor, MAX_JSON_BYTES + 1)
        if len(data) != metadata.st_size or len(data) > MAX_JSON_BYTES:
            raise ComparisonError("comparison input size changed")
        return data
    finally:
        os.close(descriptor)


def _document(path: Path) -> tuple[dict[str, object], bytes]:
    raw = _regular_bytes(path)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ComparisonError(f"comparison JSON is invalid: {path.name}") from error
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise ComparisonError(f"comparison JSON is not one canonical object: {path.name}")
    return value, raw


def _metric_projection(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ComparisonError("measurement summary is absent")
    fields = {"count", "median_ns", "p95_ns", "samples_ns"}
    if set(value) != fields or any(type(value[name]) is not int for name in fields - {"samples_ns"}):
        raise ComparisonError("measurement summary is not closed")
    samples = value["samples_ns"]
    if not isinstance(samples, list) or len(samples) != value["count"]:
        raise ComparisonError("measurement sample count changed")
    return {
        "count": value["count"],
        "median_ns": value["median_ns"],
        "p95_ns": value["p95_ns"],
    }


def verify_slice_result(
    slice_name: str, root: Path, domain: ComparisonDomain
) -> VerifiedSlice:
    """Invoke the slice's independent verifier, then retain its checked identity."""

    if slice_name not in VERIFIERS:
        raise ComparisonError("comparison slice is unknown")
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise ComparisonError("comparison result root is invalid")
    verified = VERIFIERS[slice_name](root)
    result, result_bytes = _document(root / "RESULT.json")
    tool, _ = _document(root / "tool-manifest.json")
    contract = domain.slice(slice_name)
    mechanism = result.get("mechanism")
    source_commit = result.get("source_commit")
    architecture = tool.get("architecture")
    complete = result.get("complete")
    if (
        result.get("schema") != contract.result_schema
        or verified.get("mechanism", mechanism) != mechanism
        or mechanism not in MECHANISMS
        or architecture not in ARCHITECTURES
        or not isinstance(source_commit, str)
        or COMMIT.fullmatch(source_commit) is None
        or type(complete) is not bool
        or verified.get("complete", complete) is not complete
    ):
        raise ComparisonError("verified result identity disagrees with its contract")
    if slice_name != "measurement" and verified.get("schema") != contract.verification_schema:
        raise ComparisonError("independent verification schema changed")
    decision_matrix_sha256 = result.get("decision_matrix_sha256")
    if not isinstance(decision_matrix_sha256, str) or SHA256.fullmatch(decision_matrix_sha256) is None:
        raise ComparisonError("decision matrix identity is invalid")
    conclusion = result.get("conclusion")
    if not isinstance(conclusion, str):
        raise ComparisonError("result conclusion is invalid")

    measurement_domain_sha256: str | None = None
    residual_authority: tuple[str, ...] | None = None
    setup_summary: dict[str, object] | None = None
    request_summary: dict[str, object] | None = None
    if slice_name == "measurement":
        if result.get("architecture") != architecture:
            raise ComparisonError("measurement architecture identity disagrees")
        measurement_identity = result.get("measurement_domain_sha256")
        if not isinstance(measurement_identity, str) or SHA256.fullmatch(measurement_identity) is None:
            raise ComparisonError("measurement domain identity is invalid")
        measurement_domain_sha256 = measurement_identity
        if complete:
            if conclusion != contract.complete_conclusion:
                raise ComparisonError("complete measurement conclusion changed")
            raw_authority = result.get("residual_authority")
            if not isinstance(raw_authority, list) or not all(
                isinstance(item, str) for item in raw_authority
            ):
                raise ComparisonError("measurement residual authority is invalid")
            residual_authority = tuple(raw_authority)
            setup_summary = _metric_projection(result.get("setup_summary"))
            request_summary = _metric_projection(result.get("request_summary"))
        elif conclusion != "network-measurement-incomplete":
            raise ComparisonError("incomplete measurement conclusion changed")
    else:
        if complete is not True or conclusion != contract.complete_conclusion:
            raise ComparisonError("functional result is incomplete")
        if (
            result.get("case_count") != contract.functional_case_count
            or result.get("matched_case_count") != contract.functional_case_count
            or verified.get("matched_case_count") != contract.functional_case_count
        ):
            raise ComparisonError("functional result coverage changed")

    return VerifiedSlice(
        slice=slice_name,
        mechanism=mechanism,
        architecture=architecture,
        source_commit=source_commit,
        result_schema=contract.result_schema,
        verification_schema=contract.verification_schema,
        result_sha256=hashlib.sha256(result_bytes).hexdigest(),
        decision_matrix_sha256=decision_matrix_sha256,
        measurement_domain_sha256=measurement_domain_sha256,
        complete=complete,
        conclusion=conclusion,
        residual_authority=residual_authority,
        setup_summary=setup_summary,
        request_summary=request_summary,
    )


def compare_verified_results(
    domain: ComparisonDomain,
    measurement: MeasurementDomain,
    verified: list[VerifiedSlice],
) -> dict[str, object]:
    """Derive the closed comparison without selecting a production mechanism."""

    expected = set(product(SLICES, MECHANISMS, ARCHITECTURES))
    indexed: dict[tuple[str, str, str], VerifiedSlice] = {}
    for item in verified:
        key = (item.slice, item.mechanism, item.architecture)
        if key in indexed:
            raise ComparisonError("comparison contains a duplicate result")
        indexed[key] = item
    if set(indexed) != expected:
        raise ComparisonError("comparison result inventory is incomplete")
    matrix_identities = {item.decision_matrix_sha256 for item in verified}
    if len(matrix_identities) != 1:
        raise ComparisonError("comparison inputs mix decision matrices")
    measurement_identities = {
        item.measurement_domain_sha256
        for item in verified
        if item.slice == "measurement"
    }
    if measurement_identities != {measurement.source_sha256}:
        raise ComparisonError("comparison inputs mix measurement domains")

    slice_sources = []
    for slice_name in SLICES:
        sources = {item.source_commit for item in verified if item.slice == slice_name}
        if len(sources) != 1:
            raise ComparisonError("one comparison slice mixes source commits")
        slice_sources.append({"slice": slice_name, "source_commit": next(iter(sources))})

    mechanisms = []
    for mechanism in MECHANISMS:
        profile = measurement.profile(mechanism)
        rows = [indexed[("measurement", mechanism, arch)] for arch in ARCHITECTURES]
        all_complete = all(
            indexed[(slice_name, mechanism, architecture)].complete
            for slice_name in SLICES
            for architecture in ARCHITECTURES
        )
        if all_complete:
            authorities = {row.residual_authority for row in rows}
            if authorities != {profile.expected_residual_authority}:
                raise ComparisonError("verified residual authority changed across architectures")
            classification = domain.classify(profile.expected_residual_authority)
            residual: list[str] | None = list(profile.expected_residual_authority)
        else:
            classification = "incomplete-experiment"
            residual = None
        measurements = [
            {
                "architecture": row.architecture,
                "complete": row.complete,
                "request": row.request_summary,
                "setup": row.setup_summary,
            }
            for row in rows
        ]
        mechanisms.append(
            {
                "classification": classification,
                "measurements": measurements,
                "mechanism": mechanism,
                "residual_authority": residual,
            }
        )

    complete = all(item.complete for item in verified)
    inputs = [
        {
            "architecture": indexed[key].architecture,
            "complete": indexed[key].complete,
            "mechanism": indexed[key].mechanism,
            "result_schema": indexed[key].result_schema,
            "result_sha256": indexed[key].result_sha256,
            "slice": indexed[key].slice,
            "source_commit": indexed[key].source_commit,
            "verification_schema": indexed[key].verification_schema,
        }
        for key in product(SLICES, MECHANISMS, ARCHITECTURES)
    ]
    return {
        "comparison_domain_sha256": domain.source_sha256,
        "complete": complete,
        "conclusion": (
            "network-candidates-ready-for-adr-review"
            if complete
            else "network-experiment-incomplete"
        ),
        "decision_matrix_sha256": next(iter(matrix_identities)),
        "inputs": inputs,
        "measurement_domain_sha256": measurement.source_sha256,
        "mechanisms": mechanisms,
        "production_selection": None,
        "schema": OUTPUT_SCHEMA,
        "slice_sources": slice_sources,
    }


def publish_new(path: Path, data: bytes) -> None:
    """Publish one comparison atomically enough to preserve no-replace semantics."""

    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
        raise ComparisonError("comparison output path is invalid")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o644)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise ComparisonError("comparison output write was incomplete")
            offset += written
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--comparison-domain", required=True, type=Path)
    result.add_argument("--measurement-domain", required=True, type=Path)
    result.add_argument("--routing", action="append", default=[], type=Path)
    result.add_argument("--resolution", action="append", default=[], type=Path)
    result.add_argument("--bypass", action="append", default=[], type=Path)
    result.add_argument("--measurement", action="append", default=[], type=Path)
    result.add_argument("--output", required=True, type=Path)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        domain = load_comparison_domain(arguments.comparison_domain)
        measurement = load_measurement_domain(arguments.measurement_domain)
        roots = {
            "routing-transport": arguments.routing,
            "resolution-indirection": arguments.resolution,
            "bypass-lifecycle": arguments.bypass,
            "measurement": arguments.measurement,
        }
        if any(len(values) != len(MECHANISMS) * len(ARCHITECTURES) for values in roots.values()):
            raise ComparisonError("every comparison slice requires exactly eight results")
        verified = [
            verify_slice_result(slice_name, root, domain)
            for slice_name in SLICES
            for root in roots[slice_name]
        ]
        encoded = canonical_json(compare_verified_results(domain, measurement, verified))
        publish_new(arguments.output, encoded)
        sys.stdout.buffer.write(encoded)
        return 0
    except (
        ComparisonDomainError,
        ComparisonError,
        MeasurementDomainError,
        OSError,
        ValueError,
        verify_bypass_lifecycle.VerificationError,
        verify_network_measurement.VerificationError,
        verify_resolution_indirection.VerificationError,
        verify_routing_transport.VerificationError,
    ) as error:
        print(f"network comparison failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
