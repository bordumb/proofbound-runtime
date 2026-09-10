#!/usr/bin/env python3
"""Independent raw-cell classifier for experiment 0001G."""

from __future__ import annotations

from dataclasses import dataclass

from experiments.network_authority.resolution_indirection_case import ResolutionCase
from experiments.network_authority.routing_transport_case import MECHANISMS


RAW_SCHEMA = "proofbound-runtime-resolution-raw-cell/1"
RESOLVER_SCHEMA = "proofbound-runtime-resolution-fact/1"
RAW_FIELDS = {
    "case",
    "cleanup",
    "client_exit",
    "client_started",
    "dns_query_count",
    "mechanism",
    "network_events",
    "plan_rejection",
    "prelaunch_rejection",
    "proxy_complete_count",
    "proxy_contact_count",
    "resolver_events",
    "schema",
    "service_complete_count",
    "service_contact_count",
}
NETWORK_EVENTS = {
    "ambient-proxy-contact",
    "child-boundary-denied",
    "declared-response",
    "operation-rejected",
    "proxy-target-reached",
    "redirect-cleartext",
    "redirect-host",
    "redirect-port",
    "routing-denied",
    "undeclared-contact",
}
RESOLVER_REASONS = {
    "answer-inventory",
    "answer-metadata",
    "answer-truncated",
    "answer-type",
    "cname-ambiguous",
    "cname-disallowed",
    "cname-loop-or-depth",
    "dnssec-flags",
    "malformed",
    "question-identity",
    "response-header",
    "response-size",
    "tcp-fallback-required",
    "tcp-fallback-timeout",
    "terminal-address",
    "terminal-service",
    "timeout",
    "trailing-bytes",
    "truncated-ambiguous",
}


class ResolutionCellError(Exception):
    """A raw resolution cell was incomplete, ambiguous, or open-ended."""


@dataclass(frozen=True)
class ObservedCell:
    outcome: str
    stage: str


def resolved(address: str, terminal_name: str, *transports: str) -> dict[str, object]:
    """Build one closed successful resolver fact for orchestrators and tests."""

    return {
        "address": address,
        "event": "resolved",
        "reason": None,
        "schema": RESOLVER_SCHEMA,
        "terminal_name": terminal_name,
        "transports": list(transports),
    }


def rejected(reason: str, *transports: str) -> dict[str, object]:
    """Build one closed rejected resolver fact for orchestrators and tests."""

    return {
        "address": None,
        "event": "rejected",
        "reason": reason,
        "schema": RESOLVER_SCHEMA,
        "terminal_name": None,
        "transports": list(transports),
    }


def _resolver_fact(value: object) -> dict[str, object]:
    fields = {"address", "event", "reason", "schema", "terminal_name", "transports"}
    if not isinstance(value, dict) or set(value) != fields or value["schema"] != RESOLVER_SCHEMA:
        raise ResolutionCellError("resolver fact schema is not closed")
    transports = value["transports"]
    if (
        not isinstance(transports, list)
        or not transports
        or transports not in [["udp"], ["udp", "tcp"]]
    ):
        raise ResolutionCellError("resolver transport inventory is invalid")
    if value["event"] == "resolved":
        if (
            value["reason"] is not None
            or value["address"] not in {"127.0.0.1", "127.0.0.2", "fd00::1", "fd00::2"}
            or value["terminal_name"] not in {"allowed.test", "denied.test"}
        ):
            raise ResolutionCellError("resolved terminal identity is invalid")
    elif value["event"] == "rejected":
        if (
            value["reason"] not in RESOLVER_REASONS
            or value["address"] is not None
            or value["terminal_name"] is not None
        ):
            raise ResolutionCellError("resolver rejection identity is invalid")
    else:
        raise ResolutionCellError("resolver event is unknown")
    return value


def _validate_raw(raw: object, case: ResolutionCase, mechanism: str) -> dict[str, object]:
    if mechanism not in MECHANISMS:
        raise ResolutionCellError("raw mechanism is unknown")
    if not isinstance(raw, dict) or set(raw) != RAW_FIELDS:
        raise ResolutionCellError("raw cell schema is not closed")
    if (
        raw["schema"] != RAW_SCHEMA
        or raw["case"] != case.identifier
        or raw["mechanism"] != mechanism
        or type(raw["cleanup"]) is not bool
        or type(raw["client_started"]) is not bool
    ):
        raise ResolutionCellError("raw cell identity or booleans are invalid")
    if not raw["cleanup"]:
        raise ResolutionCellError("cell cleanup is incomplete")
    for field in (
        "dns_query_count",
        "proxy_complete_count",
        "proxy_contact_count",
        "service_complete_count",
        "service_contact_count",
    ):
        if type(raw[field]) is not int or not 0 <= raw[field] <= 4:
            raise ResolutionCellError("fixture observation count is invalid")
    if raw["client_started"]:
        if raw["client_exit"] != 0:
            raise ResolutionCellError("started client did not publish a closed observation")
    elif raw["client_exit"] is not None:
        raise ResolutionCellError("unstarted client has an exit observation")
    resolver_events = raw["resolver_events"]
    network_events = raw["network_events"]
    if not isinstance(resolver_events, list) or len(resolver_events) > 2:
        raise ResolutionCellError("resolver event inventory is invalid")
    if not isinstance(network_events, list) or len(network_events) > 2:
        raise ResolutionCellError("network event inventory is invalid")
    raw["resolver_events"] = [_resolver_fact(item) for item in resolver_events]
    if any(not isinstance(event, str) or event not in NETWORK_EVENTS for event in network_events):
        raise ResolutionCellError("network event vocabulary is invalid")
    if len(set(network_events)) != len(network_events):
        raise ResolutionCellError("network event inventory is duplicated")
    if raw["dns_query_count"] != sum(len(item["transports"]) for item in resolver_events):
        raise ResolutionCellError("DNS query and resolver fact counts disagree")
    if raw["plan_rejection"] is not None and raw["plan_rejection"] != "ambient-environment-present":
        raise ResolutionCellError("plan rejection vocabulary is invalid")
    if raw["prelaunch_rejection"] is not None and raw["prelaunch_rejection"] != "resolver-config-digest-mismatch":
        raise ResolutionCellError("prelaunch rejection vocabulary is invalid")
    if raw["plan_rejection"] is not None and raw["prelaunch_rejection"] is not None:
        raise ResolutionCellError("two pre-execution rejections are ambiguous")
    return raw


def _require_counts(
    raw: dict[str, object],
    *,
    service_contacts: int = 0,
    service_completions: int = 0,
    proxy_contacts: int = 0,
    proxy_completions: int = 0,
) -> None:
    actual = (
        raw["service_contact_count"],
        raw["service_complete_count"],
        raw["proxy_contact_count"],
        raw["proxy_complete_count"],
    )
    expected = (service_contacts, service_completions, proxy_contacts, proxy_completions)
    if actual != expected:
        raise ResolutionCellError("fixture counts do not match the classified exchange")


def classify(raw_value: object, case: ResolutionCase, mechanism: str) -> ObservedCell:
    """Derive one result without consulting the case expectation."""

    raw = _validate_raw(raw_value, case, mechanism)
    resolvers = raw["resolver_events"]
    network = raw["network_events"]
    if raw["plan_rejection"] is not None:
        if raw["client_started"] or resolvers or network:
            raise ResolutionCellError("plan rejection has execution observations")
        _require_counts(raw)
        return ObservedCell("denied", "plan")
    if raw["prelaunch_rejection"] is not None:
        if raw["client_started"] or resolvers or network:
            raise ResolutionCellError("prelaunch rejection has execution observations")
        _require_counts(raw)
        return ObservedCell("denied", "prelaunch")

    identifier = case.identifier
    allowed4 = resolved("127.0.0.1", "allowed.test", "udp")
    allowed6 = resolved("fd00::1", "allowed.test", "udp")
    denied = resolved("127.0.0.2", "denied.test", "udp")
    rebound = resolved("127.0.0.2", "allowed.test", "udp")

    if identifier == "stable-a-and-aaaa":
        if resolvers != [allowed4, allowed6] or network != ["declared-response"]:
            raise ResolutionCellError("stable dual-stack observations are incomplete")
        _require_counts(raw, service_contacts=2, service_completions=2)
        return ObservedCell("allowed", "application-protocol")
    if identifier == "cname-to-declared-service":
        if resolvers != [allowed4] or network != ["declared-response"]:
            raise ResolutionCellError("declared CNAME observations are incomplete")
        _require_counts(raw, service_contacts=1, service_completions=1)
        return ObservedCell("allowed", "application-protocol")
    if identifier == "resolver-truncated-tcp-fallback":
        allowed_tcp = resolved("127.0.0.1", "allowed.test", "udp", "tcp")
        if resolvers != [allowed_tcp] or network != ["declared-response"]:
            raise ResolutionCellError("TCP fallback observations are incomplete")
        _require_counts(raw, service_contacts=1, service_completions=1)
        return ObservedCell("allowed", "application-protocol")
    rejection_cases = {
        "cname-loop-or-depth": [
            rejected("cname-loop-or-depth", "udp"),
            rejected("cname-loop-or-depth", "udp"),
        ],
        "resolver-timeout": [rejected("timeout", "udp")],
        "resolver-malformed-response": [rejected("malformed", "udp")],
        "resolver-dnssec-flag-confusion": [rejected("dnssec-flags", "udp")],
    }
    if identifier in rejection_cases:
        if resolvers != rejection_cases[identifier] or network or raw["client_started"]:
            raise ResolutionCellError("resolver rejection observations are incomplete")
        _require_counts(raw)
        return ObservedCell("denied", "resolver")
    if identifier == "ttl-rebind-to-undeclared":
        if mechanism in {"explicit-broker", "preconnected-channel"}:
            if resolvers != [allowed4, rejected("terminal-address", "udp")] or network != ["declared-response"]:
                raise ResolutionCellError("policy refresh observations are incomplete")
            _require_counts(raw, service_contacts=1, service_completions=1)
            return ObservedCell("denied", "resolver")
        if resolvers != [allowed4, rebound]:
            raise ResolutionCellError("transparent refresh observations are incomplete")
        if mechanism == "landlock-port":
            if network != ["declared-response", "undeclared-contact"]:
                raise ResolutionCellError("Landlock refresh exposure is incomplete")
            _require_counts(raw, service_contacts=2, service_completions=1)
            return ObservedCell("exposes-limitation", "resolver")
        if network != ["declared-response", "routing-denied"]:
            raise ResolutionCellError("endpoint refresh denial is incomplete")
        _require_counts(raw, service_contacts=1, service_completions=1)
        return ObservedCell("denied", "routing")
    if identifier == "cname-to-undeclared-service":
        if mechanism in {"explicit-broker", "preconnected-channel"}:
            if resolvers != [rejected("terminal-service", "udp")] or network or raw["client_started"]:
                raise ResolutionCellError("policy CNAME rejection is incomplete")
            _require_counts(raw)
            return ObservedCell("denied", "resolver")
        if resolvers != [denied]:
            raise ResolutionCellError("transparent CNAME observation is incomplete")
        if mechanism == "landlock-port":
            if network != ["undeclared-contact"]:
                raise ResolutionCellError("Landlock CNAME exposure is incomplete")
            _require_counts(raw, service_contacts=1)
            return ObservedCell("exposes-limitation", "resolver")
        if network != ["routing-denied"]:
            raise ResolutionCellError("endpoint CNAME denial is incomplete")
        _require_counts(raw)
        return ObservedCell("denied", "routing")
    if identifier == "resolver-configuration-substitution":
        if mechanism != "landlock-port":
            raise ResolutionCellError("configuration substitution lacks prelaunch rejection")
        if resolvers != [rebound] or network != ["undeclared-contact"]:
            raise ResolutionCellError("substituted resolver exposure is incomplete")
        _require_counts(raw, service_contacts=1)
        return ObservedCell("exposes-limitation", "resolver")

    if identifier.startswith("redirect-"):
        redirect_event = {
            "redirect-undeclared-host": "redirect-host",
            "redirect-cleartext": "redirect-cleartext",
            "redirect-other-port": "redirect-port",
        }[identifier]
        if mechanism == "explicit-broker":
            if network != ["operation-rejected"]:
                raise ResolutionCellError("broker redirect rejection is incomplete")
            _require_counts(raw, service_contacts=1)
            return ObservedCell("denied", "application-protocol")
        if mechanism == "preconnected-channel":
            if network != [redirect_event, "child-boundary-denied"]:
                raise ResolutionCellError("channel redirect denial is incomplete")
            _require_counts(raw, service_contacts=1, service_completions=1)
            return ObservedCell("denied", "child-boundary")
        if identifier == "redirect-undeclared-host" and mechanism == "landlock-port":
            if network != [redirect_event, "undeclared-contact"]:
                raise ResolutionCellError("redirect host exposure is incomplete")
            _require_counts(raw, service_contacts=2, service_completions=1)
            return ObservedCell("exposes-limitation", "routing")
        if network != [redirect_event, "routing-denied"]:
            raise ResolutionCellError("redirect routing denial is incomplete")
        _require_counts(raw, service_contacts=1, service_completions=1)
        return ObservedCell("denied", "routing")

    if identifier in {"http-connect-target-confusion", "socks-target-confusion"}:
        if mechanism == "explicit-broker":
            if network != ["operation-rejected"]:
                raise ResolutionCellError("broker tunnel rejection is incomplete")
            _require_counts(raw)
            return ObservedCell("denied", "application-protocol")
        if network != ["proxy-target-reached"]:
            raise ResolutionCellError("proxy target exposure is incomplete")
        _require_counts(raw, proxy_contacts=1, proxy_completions=1)
        return ObservedCell("exposes-limitation", "application-protocol")

    if identifier.startswith("ambient-"):
        if mechanism in {"explicit-broker", "preconnected-channel"}:
            raise ResolutionCellError("ambient environment lacks plan rejection")
        if mechanism == "landlock-port":
            if network != ["ambient-proxy-contact"]:
                raise ResolutionCellError("ambient proxy exposure is incomplete")
            _require_counts(raw, proxy_contacts=1, proxy_completions=1)
            return ObservedCell("exposes-limitation", "routing")
        if network != ["routing-denied"]:
            raise ResolutionCellError("ambient proxy routing denial is incomplete")
        _require_counts(raw)
        return ObservedCell("denied", "routing")
    raise ResolutionCellError("case has no closed classification")


def raw_cell(
    case: ResolutionCase,
    mechanism: str,
    *,
    cleanup: bool = True,
    client_started: bool = False,
    dns_query_count: int = 0,
    network_events: list[str] | None = None,
    plan_rejection: str | None = None,
    prelaunch_rejection: str | None = None,
    proxy_complete_count: int = 0,
    proxy_contact_count: int = 0,
    resolver_events: list[dict[str, object]] | None = None,
    service_complete_count: int = 0,
    service_contact_count: int = 0,
) -> dict[str, object]:
    """Build the closed raw shape for orchestrators and mutation tests."""

    return {
        "case": case.identifier,
        "cleanup": cleanup,
        "client_exit": 0 if client_started else None,
        "client_started": client_started,
        "dns_query_count": dns_query_count,
        "mechanism": mechanism,
        "network_events": [] if network_events is None else network_events,
        "plan_rejection": plan_rejection,
        "prelaunch_rejection": prelaunch_rejection,
        "proxy_complete_count": proxy_complete_count,
        "proxy_contact_count": proxy_contact_count,
        "resolver_events": [] if resolver_events is None else resolver_events,
        "schema": RAW_SCHEMA,
        "service_complete_count": service_complete_count,
        "service_contact_count": service_contact_count,
    }
