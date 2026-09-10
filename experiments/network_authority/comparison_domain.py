#!/usr/bin/env python3
"""Closed deterministic comparison domain for experiment 0001E."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib as toml
except ModuleNotFoundError:
    import tomli as toml  # type: ignore[no-redef]


MAX_DOMAIN_BYTES = 65536
SCHEMA = "proofbound-runtime-network-comparison-domain/1"
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
ROOT_FIELDS = {
    "schema",
    "architectures",
    "mechanisms",
    "slices",
    "classifications",
    "slice_contracts",
    "authority_rules",
}
SLICE_FIELDS = {
    "id",
    "result_schema",
    "verification_schema",
    "complete_conclusion",
    "functional_case_count",
}
SLICE_RULES = {
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
AUTHORITY_RULES = (
    (
        (
            "direct-tcp-to-any-address-on-allowed-port",
            "child-controlled-resolution",
            "child-controlled-tls",
            "arbitrary-application-bytes",
        ),
        "ineligible-service-identity",
    ),
    (
        (
            "direct-tcp-to-selected-endpoint",
            "child-controlled-tls",
            "arbitrary-application-bytes",
        ),
        "ineligible-service-identity",
    ),
    (
        ("registered-operation-via-mediator",),
        "eligible-for-adr-review-with-explicit-operation-authority",
    ),
    (
        ("arbitrary-application-bytes-on-authenticated-session",),
        "eligible-for-adr-review-with-service-session-authority",
    ),
)


class ComparisonDomainError(Exception):
    """The deterministic comparison domain is incomplete or inconsistent."""


@dataclass(frozen=True)
class SliceContract:
    """One independently verified slice input contract."""

    identifier: str
    result_schema: str
    verification_schema: str
    complete_conclusion: str
    functional_case_count: int


@dataclass(frozen=True)
class AuthorityRule:
    """One exact residual-authority classification."""

    residual_authority: tuple[str, ...]
    classification: str


@dataclass(frozen=True)
class ComparisonDomain:
    """The validated experiment comparison contract."""

    source_sha256: str
    slice_contracts: tuple[SliceContract, ...]
    authority_rules: tuple[AuthorityRule, ...]

    def slice(self, identifier: str) -> SliceContract:
        matches = [item for item in self.slice_contracts if item.identifier == identifier]
        if len(matches) != 1:
            raise ComparisonDomainError("comparison slice contract is not unique")
        return matches[0]

    def classify(self, residual_authority: tuple[str, ...]) -> str:
        matches = [
            item.classification
            for item in self.authority_rules
            if item.residual_authority == residual_authority
        ]
        if len(matches) != 1:
            raise ComparisonDomainError("residual authority has no unique classification")
        return matches[0]


def _exact_list(value: object, expected: tuple[str, ...], field: str) -> None:
    if not isinstance(value, list) or tuple(value) != expected:
        raise ComparisonDomainError(f"comparison {field} is not exact")


def load_comparison_domain(path: Path) -> ComparisonDomain:
    """Read and validate the complete deterministic comparison contract."""

    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ComparisonDomainError("comparison domain is not one regular file")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_DOMAIN_BYTES:
        raise ComparisonDomainError("comparison domain size is invalid")
    try:
        decoded = toml.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, toml.TOMLDecodeError) as error:
        raise ComparisonDomainError("comparison domain does not decode") from error
    if not isinstance(decoded, dict) or set(decoded) != ROOT_FIELDS:
        raise ComparisonDomainError("comparison domain root is not closed")
    if decoded["schema"] != SCHEMA:
        raise ComparisonDomainError("comparison domain schema is unsupported")
    _exact_list(decoded["architectures"], ARCHITECTURES, "architectures")
    _exact_list(decoded["mechanisms"], MECHANISMS, "mechanisms")
    _exact_list(decoded["slices"], SLICES, "slices")
    _exact_list(decoded["classifications"], CLASSIFICATIONS, "classifications")

    raw_slices = decoded["slice_contracts"]
    if not isinstance(raw_slices, list) or len(raw_slices) != len(SLICES):
        raise ComparisonDomainError("comparison slice inventory is invalid")
    slice_contracts = []
    for index, value in enumerate(raw_slices):
        if not isinstance(value, dict) or set(value) != SLICE_FIELDS:
            raise ComparisonDomainError("comparison slice schema is not closed")
        identifier = value["id"]
        if identifier != SLICES[index]:
            raise ComparisonDomainError("comparison slice order is not exact")
        expected = SLICE_RULES[identifier]
        actual = (
            value["result_schema"],
            value["verification_schema"],
            value["complete_conclusion"],
            value["functional_case_count"],
        )
        if actual != expected or type(value["functional_case_count"]) is not int:
            raise ComparisonDomainError(f"comparison slice {identifier} changed")
        slice_contracts.append(SliceContract(identifier, *expected))

    raw_rules = decoded["authority_rules"]
    if not isinstance(raw_rules, list) or len(raw_rules) != len(AUTHORITY_RULES):
        raise ComparisonDomainError("comparison authority rule inventory is invalid")
    authority_rules = []
    for index, value in enumerate(raw_rules):
        if not isinstance(value, dict) or set(value) != {
            "residual_authority",
            "classification",
        }:
            raise ComparisonDomainError("comparison authority rule is not closed")
        residual, classification = AUTHORITY_RULES[index]
        if (
            not isinstance(value["residual_authority"], list)
            or tuple(value["residual_authority"]) != residual
            or value["classification"] != classification
        ):
            raise ComparisonDomainError("comparison authority rule changed")
        authority_rules.append(AuthorityRule(residual, classification))
    if len({item.residual_authority for item in authority_rules}) != len(authority_rules):
        raise ComparisonDomainError("comparison authority rules are ambiguous")

    return ComparisonDomain(
        source_sha256=hashlib.sha256(raw).hexdigest(),
        slice_contracts=tuple(slice_contracts),
        authority_rules=tuple(authority_rules),
    )
