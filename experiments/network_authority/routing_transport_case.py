#!/usr/bin/env python3
"""Closed routing/transport case domain for experiment 0001F."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib as toml
except ModuleNotFoundError:  # Python 3.10 uses the reference backport.
    import tomli as toml  # type: ignore[no-redef]


MAX_MATRIX_BYTES = 131072
SCHEMA = "proofbound-runtime-network-decision-matrix/1"
MECHANISMS = (
    "landlock-port",
    "cgroup-endpoint",
    "explicit-broker",
    "preconnected-channel",
)
OUTCOMES = {
    "allowed",
    "denied",
    "exposes-limitation",
    "unsupported-before-launch",
}
STAGES = {
    "plan",
    "prelaunch",
    "child-boundary",
    "resolver",
    "routing",
    "tls",
    "application-protocol",
    "lifecycle",
    "cleanup",
}
ROOT_FIELDS = {
    "schema",
    "architectures",
    "outcomes",
    "stages",
    "slices",
    "fixtures",
    "attempted_authorities",
    "parent_rows",
    "mechanisms",
    "cases",
}
CASE_FIELDS = {
    "id",
    "slice",
    "parent_rows",
    "fixture",
    "attempted_authority",
    "authority_exposure",
    "maximum_seconds",
    "expectations",
}
ROUTING_ACTIONS = {
    "exact-service-ipv4": ("tls-request-ipv4", "dual-stack-tls"),
    "exact-service-ipv6": ("tls-request-ipv6", "dual-stack-tls"),
    "undeclared-service-ipv4-443": ("raw-undeclared-ipv4", "dual-stack-tls"),
    "undeclared-service-ipv6-443": ("raw-undeclared-ipv6", "dual-stack-tls"),
    "literal-allowed-address": ("raw-literal-allowed", "dual-stack-tls"),
    "literal-undeclared-address": ("raw-literal-undeclared", "dual-stack-tls"),
    "allowed-endpoint-wrong-certificate": ("tls-wrong-certificate", "dual-stack-tls"),
    "alternate-endpoint-allowed-certificate": (
        "raw-alternate-allowed-certificate",
        "dual-stack-tls",
    ),
    "direct-tcp-other-port": ("direct-tcp-other-port", "socket-bypass"),
    "direct-udp-dns-shaped": ("direct-udp-dns-shaped", "socket-bypass"),
    "direct-udp-quic-shaped": ("direct-udp-quic-shaped", "socket-bypass"),
    "tcp-bind-listen": ("tcp-bind-listen", "socket-bypass"),
    "udp-bind": ("udp-bind", "socket-bypass"),
    "ipv4-mapped-ipv6": ("raw-ipv4-mapped-ipv6", "dual-stack-tls"),
    "non-scoped-ipv6-scope-id": ("reject-non-scoped-ipv6-scope-id", "dual-stack-tls"),
    "alternate-address-text": ("reject-alternate-address-text", "dual-stack-tls"),
}
ROUTING_CASE_IDS = tuple(ROUTING_ACTIONS)
FROZEN_ADDRESS_TEXT = {
    "non-scoped-ipv6-scope-id": "fd00::1%1",
    "alternate-address-text": "127.000.000.001",
}


class RoutingCaseError(Exception):
    """The routing slice domain or a plan address was not exact."""


@dataclass(frozen=True)
class Expectation:
    mechanism: str
    outcome: str
    stage: str


@dataclass(frozen=True)
class RoutingCase:
    identifier: str
    action: str
    fixture: str
    attempted_authority: str
    authority_exposure: bool
    maximum_seconds: int
    expectations: tuple[Expectation, ...]

    def expectation(self, mechanism: str) -> Expectation:
        matches = [item for item in self.expectations if item.mechanism == mechanism]
        if len(matches) != 1:
            raise RoutingCaseError("case mechanism expectation is not unique")
        return matches[0]


@dataclass(frozen=True)
class RoutingMatrix:
    source_sha256: str
    cases: tuple[RoutingCase, ...]


def parse_expectation(raw: object) -> Expectation:
    """Decode one exact mechanism=outcome@stage cell."""

    if not isinstance(raw, str) or raw.count("=") != 1 or raw.count("@") != 1:
        raise RoutingCaseError("expectation grammar is invalid")
    mechanism, remainder = raw.split("=", 1)
    outcome, stage = remainder.split("@", 1)
    if mechanism not in MECHANISMS or outcome not in OUTCOMES or stage not in STAGES:
        raise RoutingCaseError("expectation vocabulary is invalid")
    return Expectation(mechanism, outcome, stage)


def load_routing_matrix(path: Path) -> RoutingMatrix:
    """Read and strictly project the registered routing slice."""

    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise RoutingCaseError("decision matrix path is not one absolute regular file")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_MATRIX_BYTES:
        raise RoutingCaseError("decision matrix size is invalid")
    try:
        decoded = toml.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, toml.TOMLDecodeError) as error:
        raise RoutingCaseError("decision matrix does not decode") from error
    if not isinstance(decoded, dict) or set(decoded) != ROOT_FIELDS:
        raise RoutingCaseError("decision matrix root is not closed")
    if decoded["schema"] != SCHEMA:
        raise RoutingCaseError("decision matrix schema is unsupported")
    mechanisms = decoded["mechanisms"]
    if (
        not isinstance(mechanisms, list)
        or [item.get("id") for item in mechanisms if isinstance(item, dict)]
        != list(MECHANISMS)
    ):
        raise RoutingCaseError("mechanism inventory is not exact")
    raw_cases = decoded["cases"]
    if not isinstance(raw_cases, list):
        raise RoutingCaseError("case inventory is invalid")
    selected: list[RoutingCase] = []
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict) or set(raw_case) != CASE_FIELDS:
            raise RoutingCaseError("case schema is not closed")
        if raw_case["slice"] != "routing-transport":
            continue
        identifier = raw_case["id"]
        if identifier not in ROUTING_ACTIONS:
            raise RoutingCaseError("routing case identity is unknown")
        action, expected_fixture = ROUTING_ACTIONS[identifier]
        if raw_case["fixture"] != expected_fixture:
            raise RoutingCaseError("routing case fixture changed")
        if (
            not isinstance(raw_case["parent_rows"], list)
            or not raw_case["parent_rows"]
            or not all(isinstance(row, str) for row in raw_case["parent_rows"])
            or not isinstance(raw_case["attempted_authority"], str)
            or type(raw_case["authority_exposure"]) is not bool
            or type(raw_case["maximum_seconds"]) is not int
            or raw_case["maximum_seconds"] != 10
            or not isinstance(raw_case["expectations"], list)
        ):
            raise RoutingCaseError("routing case fields are invalid")
        expectations = tuple(parse_expectation(item) for item in raw_case["expectations"])
        if (
            len(expectations) != len(MECHANISMS)
            or tuple(item.mechanism for item in expectations) != MECHANISMS
        ):
            raise RoutingCaseError("routing case expectation coverage is not exact")
        selected.append(
            RoutingCase(
                identifier=identifier,
                action=action,
                fixture=expected_fixture,
                attempted_authority=raw_case["attempted_authority"],
                authority_exposure=raw_case["authority_exposure"],
                maximum_seconds=raw_case["maximum_seconds"],
                expectations=expectations,
            )
        )
    if tuple(item.identifier for item in selected) != ROUTING_CASE_IDS:
        raise RoutingCaseError("routing case inventory or order changed")
    return RoutingMatrix(hashlib.sha256(raw).hexdigest(), tuple(selected))


def plan_rejection(case_id: str) -> str | None:
    """Validate the two frozen prelaunch address-grammar attacks."""

    text = FROZEN_ADDRESS_TEXT.get(case_id)
    if text is None:
        if case_id not in ROUTING_ACTIONS:
            raise RoutingCaseError("routing case identity is unknown")
        return None
    base, separator, scope = text.partition("%")
    try:
        address = ipaddress.ip_address(base)
    except ValueError:
        return "address-text-not-canonical"
    if str(address) != base:
        return "address-text-not-canonical"
    if separator:
        if not scope.isascii() or not scope.isdecimal() or int(scope) == 0:
            return "scope-id-not-canonical"
        if address.version != 6 or not address.is_link_local:
            return "scope-id-not-allowed"
    return None
