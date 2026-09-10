#!/usr/bin/env python3
"""Closed resolution/indirection case domain for experiment 0001G."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib as toml
except ModuleNotFoundError:  # Python 3.10 uses the reference backport.
    import tomli as toml  # type: ignore[no-redef]

from experiments.network_authority.routing_transport_case import (
    CASE_FIELDS,
    MAX_MATRIX_BYTES,
    MECHANISMS,
    ROOT_FIELDS,
    SCHEMA,
    Expectation,
    parse_expectation,
)


RESOLUTION_ACTIONS = {
    "stable-a-and-aaaa": ("resolve-stable-dual-stack", "scripted-dns"),
    "ttl-rebind-to-undeclared": ("resolve-after-ttl", "scripted-dns"),
    "cname-to-declared-service": ("resolve-declared-alias", "scripted-dns"),
    "cname-to-undeclared-service": ("resolve-undeclared-alias", "scripted-dns"),
    "cname-loop-or-depth": ("reject-loop-and-depth", "scripted-dns"),
    "resolver-timeout": ("reject-resolver-timeout", "scripted-dns"),
    "resolver-truncated-tcp-fallback": ("resolve-truncated-with-tcp", "scripted-dns"),
    "resolver-malformed-response": ("reject-malformed-response", "scripted-dns"),
    "resolver-dnssec-flag-confusion": ("reject-unrequested-dnssec", "scripted-dns"),
    "redirect-undeclared-host": ("follow-redirect-host", "redirect-service"),
    "redirect-cleartext": ("follow-redirect-cleartext", "redirect-service"),
    "redirect-other-port": ("follow-redirect-port", "redirect-service"),
    "http-connect-target-confusion": ("send-http-connect", "proxy-service"),
    "socks-target-confusion": ("send-socks5-connect", "proxy-service"),
    "ambient-http-proxy": ("consume-http-proxy", "proxy-service"),
    "ambient-https-proxy": ("consume-https-proxy", "proxy-service"),
    "ambient-all-proxy": ("consume-all-proxy", "proxy-service"),
    "resolver-configuration-substitution": (
        "consume-substituted-resolver",
        "scripted-dns",
    ),
}
RESOLUTION_CASE_IDS = tuple(RESOLUTION_ACTIONS)
DNS_PLANS: dict[str, tuple[tuple[str, str, int, int], ...]] = {
    "stable-a-and-aaaa": (
        ("stable", "allowed.test", 1, 201),
        ("stable", "allowed.test", 28, 202),
    ),
    "ttl-rebind-to-undeclared": (
        ("rebind", "allowed.test", 1, 211),
        ("rebind", "allowed.test", 1, 212),
    ),
    "cname-to-declared-service": (("cname-allowed", "alias.test", 1, 221),),
    "cname-to-undeclared-service": (("cname-denied", "alias.test", 1, 231),),
    "cname-loop-or-depth": (
        ("cname-loop", "alias.test", 1, 241),
        ("cname-depth", "alias.test", 1, 242),
    ),
    "resolver-timeout": (("timeout", "allowed.test", 1, 251),),
    "resolver-truncated-tcp-fallback": (
        ("truncated-fallback", "allowed.test", 1, 261),
    ),
    "resolver-malformed-response": (("malformed", "allowed.test", 1, 271),),
    "resolver-dnssec-flag-confusion": (
        ("dnssec-confusion", "allowed.test", 1, 281),
    ),
    "resolver-configuration-substitution": (
        ("rebind", "allowed.test", 1, 291),
    ),
}
REDIRECT_SCRIPTS = {
    "redirect-undeclared-host": "redirect-host",
    "redirect-cleartext": "redirect-cleartext",
    "redirect-other-port": "redirect-port",
}
PROXY_PROTOCOLS = {
    "http-connect-target-confusion": "http-connect",
    "socks-target-confusion": "socks5",
}
AMBIENT_VARIABLES = {
    "ambient-http-proxy": "HTTP_PROXY",
    "ambient-https-proxy": "HTTPS_PROXY",
    "ambient-all-proxy": "ALL_PROXY",
}
PROXY_VALUE = "https://127.0.0.2:443"


class ResolutionCaseError(Exception):
    """The resolution slice domain or prelaunch identity was not exact."""


@dataclass(frozen=True)
class ResolutionCase:
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
            raise ResolutionCaseError("case mechanism expectation is not unique")
        return matches[0]


@dataclass(frozen=True)
class ResolutionMatrix:
    source_sha256: str
    cases: tuple[ResolutionCase, ...]


def _hex_digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def parameters_for(case_id: str) -> dict[str, object]:
    """Return the immutable attack and query vocabulary for one case."""

    if case_id not in RESOLUTION_ACTIONS:
        raise ResolutionCaseError("resolution case identity is unknown")
    if case_id in DNS_PLANS:
        queries = [
            {"identifier": identifier, "name": name, "question_type": question_type, "script": script}
            for script, name, question_type, identifier in DNS_PLANS[case_id]
        ]
        result: dict[str, object] = {"queries": queries}
        if case_id == "ttl-rebind-to-undeclared":
            result["minimum_ttl_wait_ns"] = 1_000_000_000
        if case_id == "resolver-truncated-tcp-fallback":
            result["transports"] = ["udp", "tcp"]
        if case_id == "resolver-configuration-substitution":
            result["configuration_attack"] = "replace-after-plan"
        return result
    if case_id in REDIRECT_SCRIPTS:
        return {"redirect_script": REDIRECT_SCRIPTS[case_id]}
    if case_id in PROXY_PROTOCOLS:
        return {"proxy_protocol": PROXY_PROTOCOLS[case_id]}
    return {
        "ambient_environment": {
            AMBIENT_VARIABLES[case_id]: PROXY_VALUE,
        },
        "proxy_protocol": "http-connect",
    }


def case_plan(
    case: ResolutionCase,
    mechanism: str,
    matrix_sha256: str,
    registered_resolver_sha256: str,
    substitute_resolver_sha256: str,
) -> dict[str, object]:
    """Freeze one expectation and all substitution inputs before execution."""

    if (
        mechanism not in MECHANISMS
        or not _hex_digest(matrix_sha256)
        or not _hex_digest(registered_resolver_sha256)
        or not _hex_digest(substitute_resolver_sha256)
        or registered_resolver_sha256 == substitute_resolver_sha256
    ):
        raise ResolutionCaseError("case plan identity is invalid")
    expectation = case.expectation(mechanism)
    return {
        "action": case.action,
        "case": case.identifier,
        "decision_matrix_sha256": matrix_sha256,
        "expectation": {"outcome": expectation.outcome, "stage": expectation.stage},
        "mechanism": mechanism,
        "parameters": parameters_for(case.identifier),
        "registered_environment": {},
        "registered_resolver_sha256": registered_resolver_sha256,
        "schema": "proofbound-runtime-resolution-case-plan/1",
        "substitute_resolver_sha256": substitute_resolver_sha256,
    }


def load_resolution_matrix(path: Path) -> ResolutionMatrix:
    """Read and strictly project the registered resolution slice."""

    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ResolutionCaseError("decision matrix path is not one absolute regular file")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_MATRIX_BYTES:
        raise ResolutionCaseError("decision matrix size is invalid")
    try:
        decoded = toml.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, toml.TOMLDecodeError) as error:
        raise ResolutionCaseError("decision matrix does not decode") from error
    if not isinstance(decoded, dict) or set(decoded) != ROOT_FIELDS or decoded["schema"] != SCHEMA:
        raise ResolutionCaseError("decision matrix root is not closed")
    mechanisms = decoded["mechanisms"]
    if (
        not isinstance(mechanisms, list)
        or [item.get("id") for item in mechanisms if isinstance(item, dict)] != list(MECHANISMS)
    ):
        raise ResolutionCaseError("mechanism inventory is not exact")
    raw_cases = decoded["cases"]
    if not isinstance(raw_cases, list):
        raise ResolutionCaseError("case inventory is invalid")
    selected: list[ResolutionCase] = []
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict) or set(raw_case) != CASE_FIELDS:
            raise ResolutionCaseError("case schema is not closed")
        if raw_case["slice"] != "resolution-indirection":
            continue
        identifier = raw_case["id"]
        if identifier not in RESOLUTION_ACTIONS:
            raise ResolutionCaseError("resolution case identity is unknown")
        action, expected_fixture = RESOLUTION_ACTIONS[identifier]
        if raw_case["fixture"] != expected_fixture:
            raise ResolutionCaseError("resolution case fixture changed")
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
            raise ResolutionCaseError("resolution case fields are invalid")
        try:
            expectations = tuple(parse_expectation(item) for item in raw_case["expectations"])
        except Exception as error:
            raise ResolutionCaseError("resolution expectation is invalid") from error
        if (
            len(expectations) != len(MECHANISMS)
            or tuple(item.mechanism for item in expectations) != MECHANISMS
        ):
            raise ResolutionCaseError("resolution expectation coverage is not exact")
        selected.append(
            ResolutionCase(
                identifier=identifier,
                action=action,
                fixture=expected_fixture,
                attempted_authority=raw_case["attempted_authority"],
                authority_exposure=raw_case["authority_exposure"],
                maximum_seconds=raw_case["maximum_seconds"],
                expectations=expectations,
            )
        )
    if tuple(item.identifier for item in selected) != RESOLUTION_CASE_IDS:
        raise ResolutionCaseError("resolution case inventory or order changed")
    return ResolutionMatrix(hashlib.sha256(raw).hexdigest(), tuple(selected))
