#!/usr/bin/env python3
"""Independent verifier for the experiment 0001E network comparison."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass
from itertools import product
from pathlib import Path
from typing import Callable

try:
    import tomllib as toml
except ModuleNotFoundError:
    import tomli as toml  # type: ignore[no-redef]

from experiments.network_authority import verify_bypass_lifecycle
from experiments.network_authority import verify_network_measurement
from experiments.network_authority import verify_resolution_indirection
from experiments.network_authority import verify_routing_transport


MAX_JSON_BYTES = 1024 * 1024
ARCHITECTURES = ("x86_64", "aarch64")
MECHANISMS = (
    "landlock-port",
    "cgroup-endpoint",
    "explicit-broker",
    "preconnected-channel",
)
SLICES = (
    "routing-transport",
    "resolution-indirection",
    "bypass-lifecycle",
    "measurement",
)
CLASSIFICATIONS = (
    "ineligible-service-identity",
    "eligible-for-adr-review-with-explicit-operation-authority",
    "eligible-for-adr-review-with-service-session-authority",
    "incomplete-experiment",
)
SLICE_CONTRACTS = {
    "routing-transport": (
        "proofbound-runtime-routing-result/1",
        "proofbound-runtime-routing-verification/1",
        "routing-transport-slice-matched",
        16,
    ),
    "resolution-indirection": (
        "proofbound-runtime-resolution-result/1",
        "proofbound-runtime-resolution-verification/1",
        "resolution-indirection-slice-matched",
        18,
    ),
    "bypass-lifecycle": (
        "proofbound-runtime-bypass-result/1",
        "proofbound-runtime-bypass-verification/1",
        "bypass-lifecycle-slice-matched",
        18,
    ),
    "measurement": (
        "proofbound-runtime-network-measurement-result/1",
        "proofbound-runtime-network-measurement-verification/1",
        "network-measurement-complete",
        0,
    ),
}
AUTHORITY_RULES = {
    (
        "direct-tcp-to-any-address-on-allowed-port",
        "child-controlled-resolution",
        "child-controlled-tls",
        "arbitrary-application-bytes",
    ): "ineligible-service-identity",
    (
        "direct-tcp-to-selected-endpoint",
        "child-controlled-tls",
        "arbitrary-application-bytes",
    ): "ineligible-service-identity",
    (
        "registered-operation-via-mediator",
    ): "eligible-for-adr-review-with-explicit-operation-authority",
    (
        "arbitrary-application-bytes-on-authenticated-session",
    ): "eligible-for-adr-review-with-service-session-authority",
}
SLICE_VERIFIERS: dict[str, Callable[[Path], dict[str, object]]] = {
    "routing-transport": verify_routing_transport.verify,
    "resolution-indirection": verify_resolution_indirection.verify,
    "bypass-lifecycle": verify_bypass_lifecycle.verify,
    "measurement": verify_network_measurement.verify,
}


class VerificationError(Exception):
    """The comparison or one of its independently checked inputs is invalid."""


@dataclass(frozen=True)
class SliceFact:
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
    residual_authority: tuple[str, ...] | None
    setup: dict[str, int] | None
    request: dict[str, int] | None


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("comparison JSON contains a duplicate name")
        result[key] = value
    return result


def regular_bytes(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise VerificationError(f"comparison input is unavailable: {path.name}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_JSON_BYTES:
        raise VerificationError(f"comparison input is not bounded and regular: {path.name}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise VerificationError("comparison input identity changed")
        data = os.read(descriptor, MAX_JSON_BYTES + 1)
        if len(data) != metadata.st_size or len(data) > MAX_JSON_BYTES:
            raise VerificationError("comparison input size changed")
        return data
    finally:
        os.close(descriptor)


def document(path: Path) -> tuple[dict[str, object], bytes]:
    raw = regular_bytes(path)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"comparison JSON is invalid: {path.name}") from error
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise VerificationError(f"comparison JSON is not one canonical object: {path.name}")
    return value, raw


def verify_comparison_domain(path: Path) -> str:
    """Validate the comparison contract without using the producer parser."""

    if not path.is_absolute() or path.is_symlink():
        raise VerificationError("comparison domain path is invalid")
    raw = regular_bytes(path)
    try:
        value = toml.loads(raw.decode())
    except (UnicodeDecodeError, toml.TOMLDecodeError) as error:
        raise VerificationError("comparison domain does not decode") from error
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "architectures",
        "mechanisms",
        "slices",
        "classifications",
        "slice_contracts",
        "authority_rules",
    }:
        raise VerificationError("comparison domain root is not closed")
    if (
        value["schema"] != "proofbound-runtime-network-comparison-domain/1"
        or value["architectures"] != list(ARCHITECTURES)
        or value["mechanisms"] != list(MECHANISMS)
        or value["slices"] != list(SLICES)
        or value["classifications"] != list(CLASSIFICATIONS)
    ):
        raise VerificationError("comparison domain constants changed")
    expected_slices = [
        {
            "id": name,
            "result_schema": contract[0],
            "verification_schema": contract[1],
            "complete_conclusion": contract[2],
            "functional_case_count": contract[3],
        }
        for name, contract in ((name, SLICE_CONTRACTS[name]) for name in SLICES)
    ]
    expected_authorities = [
        {"residual_authority": list(authority), "classification": classification}
        for authority, classification in AUTHORITY_RULES.items()
    ]
    if value["slice_contracts"] != expected_slices or value["authority_rules"] != expected_authorities:
        raise VerificationError("comparison domain rules changed")
    return hashlib.sha256(raw).hexdigest()


def measurement_profiles(path: Path) -> tuple[str, dict[str, tuple[str, ...]]]:
    """Validate the measurement domain using the independent measurement codec."""

    if not path.is_absolute() or path.is_symlink():
        raise VerificationError("measurement domain path is invalid")
    raw = regular_bytes(path)
    decoded = None
    for mechanism in MECHANISMS:
        decoded = verify_network_measurement.parse_domain(raw, mechanism)
    if decoded is None or not isinstance(decoded.get("profiles"), list):
        raise VerificationError("measurement profiles are absent")
    profiles: dict[str, tuple[str, ...]] = {}
    for profile in decoded["profiles"]:
        if not isinstance(profile, dict):
            raise VerificationError("measurement profile is invalid")
        identifier = profile.get("id")
        residual = profile.get("expected_residual_authority")
        if (
            identifier not in MECHANISMS
            or not isinstance(residual, list)
            or not all(isinstance(item, str) for item in residual)
            or identifier in profiles
        ):
            raise VerificationError("measurement residual authority is invalid")
        profiles[identifier] = tuple(residual)
    if set(profiles) != set(MECHANISMS):
        raise VerificationError("measurement profile inventory is incomplete")
    return hashlib.sha256(raw).hexdigest(), profiles


def _metric(value: object) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != {
        "count",
        "median_ns",
        "p95_ns",
        "samples_ns",
    }:
        raise VerificationError("measurement summary is not closed")
    if any(type(value[name]) is not int for name in ("count", "median_ns", "p95_ns")):
        raise VerificationError("measurement summary value is invalid")
    samples = value["samples_ns"]
    if not isinstance(samples, list) or len(samples) != value["count"]:
        raise VerificationError("measurement sample inventory changed")
    return {
        "count": value["count"],
        "median_ns": value["median_ns"],
        "p95_ns": value["p95_ns"],
    }


def verified_fact(slice_name: str, root: Path) -> SliceFact:
    """Rerun one independent slice verifier and project only checked facts."""

    if slice_name not in SLICE_VERIFIERS:
        raise VerificationError("comparison slice is unknown")
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise VerificationError("comparison result root is invalid")
    report = SLICE_VERIFIERS[slice_name](root)
    result, result_bytes = document(root / "RESULT.json")
    tool, _ = document(root / "tool-manifest.json")
    result_schema, verification_schema, conclusion, case_count = SLICE_CONTRACTS[slice_name]
    mechanism = result.get("mechanism")
    architecture = tool.get("architecture")
    complete = result.get("complete")
    if (
        result.get("schema") != result_schema
        or mechanism not in MECHANISMS
        or architecture not in ARCHITECTURES
        or type(complete) is not bool
        or report.get("mechanism", mechanism) != mechanism
        or report.get("complete", complete) is not complete
    ):
        raise VerificationError("verified comparison input identity changed")
    if slice_name != "measurement" and (
        report.get("schema") != verification_schema
        or complete is not True
        or result.get("conclusion") != conclusion
        or result.get("case_count") != case_count
        or result.get("matched_case_count") != case_count
        or report.get("matched_case_count") != case_count
    ):
        raise VerificationError("verified functional result is incomplete")
    source_commit = result.get("source_commit")
    matrix = result.get("decision_matrix_sha256")
    if not isinstance(source_commit, str) or len(source_commit) != 40 or any(
        character not in "0123456789abcdef" for character in source_commit
    ):
        raise VerificationError("verified source identity is invalid")
    if not isinstance(matrix, str) or len(matrix) != 64 or any(
        character not in "0123456789abcdef" for character in matrix
    ):
        raise VerificationError("verified matrix identity is invalid")

    measurement_domain = None
    residual = None
    setup = None
    request = None
    if slice_name == "measurement":
        if result.get("architecture") != architecture:
            raise VerificationError("measurement architecture changed")
        measurement_domain = result.get("measurement_domain_sha256")
        if not isinstance(measurement_domain, str) or len(measurement_domain) != 64:
            raise VerificationError("measurement domain identity is invalid")
        if complete:
            if result.get("conclusion") != conclusion:
                raise VerificationError("complete measurement conclusion changed")
            authority = result.get("residual_authority")
            if not isinstance(authority, list) or not all(isinstance(item, str) for item in authority):
                raise VerificationError("measurement residual authority changed")
            residual = tuple(authority)
            setup = _metric(result.get("setup_summary"))
            request = _metric(result.get("request_summary"))
        elif result.get("conclusion") != "network-measurement-incomplete":
            raise VerificationError("incomplete measurement conclusion changed")

    return SliceFact(
        slice=slice_name,
        mechanism=mechanism,
        architecture=architecture,
        source_commit=source_commit,
        result_schema=result_schema,
        verification_schema=verification_schema,
        result_sha256=hashlib.sha256(result_bytes).hexdigest(),
        decision_matrix_sha256=matrix,
        measurement_domain_sha256=measurement_domain,
        complete=complete,
        residual_authority=residual,
        setup=setup,
        request=request,
    )


def derive_expected(
    facts: list[SliceFact],
    comparison_domain_sha256: str,
    measurement_domain_sha256: str,
    profiles: dict[str, tuple[str, ...]],
) -> dict[str, object]:
    """Independently derive the only acceptable comparison document."""

    expected_keys = set(product(SLICES, MECHANISMS, ARCHITECTURES))
    indexed: dict[tuple[str, str, str], SliceFact] = {}
    for fact in facts:
        key = (fact.slice, fact.mechanism, fact.architecture)
        if key in indexed:
            raise VerificationError("comparison result is duplicated")
        indexed[key] = fact
    if set(indexed) != expected_keys:
        raise VerificationError("comparison result inventory is incomplete")
    matrices = {fact.decision_matrix_sha256 for fact in facts}
    if len(matrices) != 1:
        raise VerificationError("comparison mixes decision matrices")
    measurement_domains = {
        fact.measurement_domain_sha256 for fact in facts if fact.slice == "measurement"
    }
    if measurement_domains != {measurement_domain_sha256}:
        raise VerificationError("comparison mixes measurement domains")

    slice_sources = []
    for slice_name in SLICES:
        sources = {fact.source_commit for fact in facts if fact.slice == slice_name}
        if len(sources) != 1:
            raise VerificationError("comparison slice mixes source commits")
        slice_sources.append({"slice": slice_name, "source_commit": next(iter(sources))})

    mechanisms = []
    for mechanism in MECHANISMS:
        rows = [indexed[("measurement", mechanism, architecture)] for architecture in ARCHITECTURES]
        all_complete = all(
            indexed[(slice_name, mechanism, architecture)].complete
            for slice_name in SLICES
            for architecture in ARCHITECTURES
        )
        if all_complete:
            residual = profiles[mechanism]
            if {row.residual_authority for row in rows} != {residual} or residual not in AUTHORITY_RULES:
                raise VerificationError("comparison residual authority changed")
            classification = AUTHORITY_RULES[residual]
            authority: list[str] | None = list(residual)
        else:
            classification = "incomplete-experiment"
            authority = None
        mechanisms.append(
            {
                "classification": classification,
                "measurements": [
                    {
                        "architecture": row.architecture,
                        "complete": row.complete,
                        "request": row.request,
                        "setup": row.setup,
                    }
                    for row in rows
                ],
                "mechanism": mechanism,
                "residual_authority": authority,
            }
        )

    complete = all(fact.complete for fact in facts)
    return {
        "comparison_domain_sha256": comparison_domain_sha256,
        "complete": complete,
        "conclusion": (
            "network-candidates-ready-for-adr-review"
            if complete
            else "network-experiment-incomplete"
        ),
        "decision_matrix_sha256": next(iter(matrices)),
        "inputs": [
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
        ],
        "measurement_domain_sha256": measurement_domain_sha256,
        "mechanisms": mechanisms,
        "production_selection": None,
        "schema": "proofbound-runtime-network-comparison/1",
        "slice_sources": slice_sources,
    }


def verify(
    comparison: Path,
    comparison_domain: Path,
    measurement_domain: Path,
    roots: dict[str, list[Path]],
) -> dict[str, object]:
    """Verify the exact comparison against all independently checked results."""

    if set(roots) != set(SLICES) or any(
        len(roots[slice_name]) != len(MECHANISMS) * len(ARCHITECTURES)
        for slice_name in SLICES
    ):
        raise VerificationError("every comparison slice requires exactly eight results")
    comparison_domain_sha256 = verify_comparison_domain(comparison_domain)
    measurement_domain_sha256, profiles = measurement_profiles(measurement_domain)
    facts = [
        verified_fact(slice_name, root)
        for slice_name in SLICES
        for root in roots[slice_name]
    ]
    expected = derive_expected(
        facts,
        comparison_domain_sha256,
        measurement_domain_sha256,
        profiles,
    )
    actual, raw = document(comparison)
    if actual != expected:
        raise VerificationError("comparison does not independently derive")
    return {
        "comparison_sha256": hashlib.sha256(raw).hexdigest(),
        "complete": actual["complete"],
        "schema": "proofbound-runtime-network-comparison-verification/1",
        "verified": True,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("comparison", type=Path)
    result.add_argument("--comparison-domain", required=True, type=Path)
    result.add_argument("--measurement-domain", required=True, type=Path)
    result.add_argument("--routing", action="append", default=[], type=Path)
    result.add_argument("--resolution", action="append", default=[], type=Path)
    result.add_argument("--bypass", action="append", default=[], type=Path)
    result.add_argument("--measurement", action="append", default=[], type=Path)
    return result


def main() -> int:
    arguments = parser().parse_args()
    roots = {
        "routing-transport": arguments.routing,
        "resolution-indirection": arguments.resolution,
        "bypass-lifecycle": arguments.bypass,
        "measurement": arguments.measurement,
    }
    try:
        print(
            json.dumps(
                verify(
                    arguments.comparison,
                    arguments.comparison_domain,
                    arguments.measurement_domain,
                    roots,
                ),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (
        OSError,
        ValueError,
        VerificationError,
        verify_bypass_lifecycle.VerificationError,
        verify_network_measurement.VerificationError,
        verify_resolution_indirection.VerificationError,
        verify_routing_transport.VerificationError,
    ) as error:
        print(f"network comparison verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
