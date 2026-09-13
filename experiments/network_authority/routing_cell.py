#!/usr/bin/env python3
"""Independent raw-cell classifier for experiment 0001F."""

from __future__ import annotations

import errno
from dataclasses import dataclass

from experiments.network_authority.routing_transport_case import (
    MECHANISMS,
    ROUTING_ACTIONS,
    RoutingCase,
)


RAW_SCHEMA = "proofbound-runtime-routing-raw-cell/1"
CLIENT_SCHEMA = "proofbound-runtime-routing-client-observation/1"
MEDIATOR_SCHEMA = "proofbound-runtime-routing-mediator-observation/1"
RAW_FIELDS = {
    "case",
    "cleanup",
    "client",
    "client_exit",
    "client_started",
    "fixture_complete",
    "fixture_contact",
    "mechanism",
    "mediator",
    "plan_rejection",
    "schema",
}
MEDIATOR_FIELDS = {"detail", "event", "schema", "stage"}
MEDIATOR_DETAILS = {
    "authenticated-exact-response",
    "certificate-rejected",
    "connector-endpoint-mismatch",
    "target-field-rejected",
}
DENIAL_STAGES = {"prelaunch", "routing", "tls", "application-protocol"}
ERROR_PHASES = {"socket", "connect", "bind", "listen", "tls", "datagram"}


class RoutingCellError(Exception):
    """A raw cell was incomplete, ambiguous, or outside the closed schema."""


@dataclass(frozen=True)
class ObservedCell:
    outcome: str
    stage: str


def hex_digest(value: object) -> bool:
    """Recognize one lowercase SHA-256 value."""

    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def validate_client(value: object, case: RoutingCase) -> dict[str, object]:
    """Validate one exact untrusted-client observation shape."""

    if not isinstance(value, dict):
        raise RoutingCellError("started client observation is absent")
    common = {"action", "case", "errno", "event", "phase", "schema"}
    event = value.get("event")
    fields = set(value)
    if event == "operation-error":
        expected_fields = common
    elif event == "certificate-rejected":
        expected_fields = {"action", "case", "event", "phase", "schema", "verify_code"}
    elif event == "exact-response":
        expected_fields = common | {"response_sha256", "tls_version"}
    elif event == "mediated-response":
        expected_fields = common | {"response_sha256"}
    elif event == "mediator-rejected":
        expected_fields = common | {"code"}
    elif event == "routing-connected":
        expected_fields = common
    elif event == "socket-sentinel":
        expected_fields = common | {"response_sha256"}
    elif event == "datagram-sentinel":
        expected_fields = common | {"request_sha256", "response_sha256"}
    elif event == "bind-succeeded":
        expected_fields = common
    else:
        raise RoutingCellError("client event is unknown")
    if fields != expected_fields:
        raise RoutingCellError("client observation schema is not closed")
    if (
        value["schema"] != CLIENT_SCHEMA
        or value["case"] != case.identifier
        or value["action"] != case.action
        or value["phase"] not in ERROR_PHASES | {"application-protocol"}
    ):
        raise RoutingCellError("client observation identity is not exact")
    if event == "operation-error":
        if type(value["errno"]) is not int or not 1 <= value["errno"] <= 4095:
            raise RoutingCellError("client error identity is invalid")
    elif event != "certificate-rejected" and value["errno"] is not None:
        raise RoutingCellError("successful client event contains an errno")
    if event == "certificate-rejected" and (
        value["phase"] != "tls"
        or type(value["verify_code"]) is not int
        or value["verify_code"] <= 0
    ):
        raise RoutingCellError("certificate rejection identity is invalid")
    if event == "mediator-rejected" and value["code"] not in {
        "certificate-rejected",
        "connector-endpoint-mismatch",
        "target-field-rejected",
    }:
        raise RoutingCellError("mediator rejection code is invalid")
    exact_phases = {
        "exact-response": "application-protocol",
        "mediated-response": "application-protocol",
        "mediator-rejected": "application-protocol",
        "routing-connected": "connect",
        "socket-sentinel": "application-protocol",
        "datagram-sentinel": "application-protocol",
    }
    if event in exact_phases and value["phase"] != exact_phases[event]:
        raise RoutingCellError("client event phase is inconsistent")
    if event == "bind-succeeded" and value["phase"] not in {"bind", "listen"}:
        raise RoutingCellError("bind success phase is inconsistent")
    if "response_sha256" in value and not hex_digest(value["response_sha256"]):
        raise RoutingCellError("client response digest is invalid")
    if "request_sha256" in value and not hex_digest(value["request_sha256"]):
        raise RoutingCellError("client request digest is invalid")
    if event == "exact-response" and value["tls_version"] != "TLSv1.3":
        raise RoutingCellError("client TLS version is not exact")
    return value


def validate_mediator(value: object) -> dict[str, object]:
    """Validate one trusted broker/connector observation."""

    if not isinstance(value, dict) or set(value) != MEDIATOR_FIELDS:
        raise RoutingCellError("mediator observation schema is not closed")
    if (
        value["schema"] != MEDIATOR_SCHEMA
        or value["event"] not in {"exact-response", "rejected"}
        or value["stage"] not in DENIAL_STAGES | {"application-protocol"}
        or value["detail"] not in MEDIATOR_DETAILS
    ):
        raise RoutingCellError("mediator observation vocabulary is invalid")
    if value["event"] == "exact-response" and (
        value["stage"] != "application-protocol"
        or value["detail"] != "authenticated-exact-response"
    ):
        raise RoutingCellError("mediator success identity is invalid")
    rejected_pairs = {
        ("prelaunch", "certificate-rejected"),
        ("tls", "certificate-rejected"),
        ("prelaunch", "connector-endpoint-mismatch"),
        ("routing", "connector-endpoint-mismatch"),
        ("application-protocol", "target-field-rejected"),
    }
    if value["event"] == "rejected" and (
        value["stage"], value["detail"]
    ) not in rejected_pairs:
        raise RoutingCellError("mediator rejection identity is invalid")
    return value


def classify(raw: object, case: RoutingCase, mechanism: str) -> ObservedCell:
    """Derive one outcome from raw markers without consulting the expectation."""

    if mechanism not in MECHANISMS:
        raise RoutingCellError("raw mechanism is unknown")
    if not isinstance(raw, dict) or set(raw) != RAW_FIELDS:
        raise RoutingCellError("raw cell schema is not closed")
    if (
        raw["schema"] != RAW_SCHEMA
        or raw["case"] != case.identifier
        or raw["mechanism"] != mechanism
        or type(raw["cleanup"]) is not bool
        or type(raw["client_started"]) is not bool
        or type(raw["fixture_contact"]) is not bool
        or type(raw["fixture_complete"]) is not bool
    ):
        raise RoutingCellError("raw cell identity or booleans are invalid")
    if not raw["cleanup"]:
        raise RoutingCellError("cell cleanup is incomplete")
    if raw["client_started"]:
        if type(raw["client_exit"]) is not int or not 0 <= raw["client_exit"] <= 255:
            raise RoutingCellError("started child exit is invalid")
        client = validate_client(raw["client"], case)
    else:
        if raw["client_exit"] is not None or raw["client"] is not None:
            raise RoutingCellError("unstarted child has an observation")
        client = None

    plan_rejection = raw["plan_rejection"]
    mediator_value = raw["mediator"]
    if plan_rejection is not None:
        if (
            plan_rejection
            not in {
                "address-text-not-canonical",
                "scope-id-not-allowed",
                "interface-cannot-represent-address",
            }
            or raw["client_started"]
            or mediator_value is not None
            or raw["fixture_contact"]
            or raw["fixture_complete"]
        ):
            raise RoutingCellError("plan rejection markers are inconsistent")
        return ObservedCell("denied", "plan")

    if mediator_value is not None:
        mediator = validate_mediator(mediator_value)
        if mediator["event"] == "rejected":
            stage = mediator["stage"]
            if stage == "prelaunch" and raw["client_started"]:
                raise RoutingCellError("prelaunch rejection started a child")
            if stage != "prelaunch" and not raw["client_started"]:
                raise RoutingCellError("post-launch mediator rejection lacks a child")
            if stage != "prelaunch" and (
                client is None
                or client["event"] != "mediator-rejected"
                or client["code"] != mediator["detail"]
            ):
                raise RoutingCellError("mediator and child rejection evidence disagree")
            if raw["fixture_complete"]:
                raise RoutingCellError("rejected mediator completed the fixture")
            if stage in {"routing", "tls"} and not raw["fixture_contact"]:
                raise RoutingCellError("post-connect mediator rejection lacks contact")
            return ObservedCell("denied", str(stage))
        if (
            not raw["client_started"]
            or raw["client_exit"] != 0
            or not raw["fixture_contact"]
            or not raw["fixture_complete"]
            or client is None
            or client["event"] != "mediated-response"
        ):
            raise RoutingCellError("mediator success markers are incomplete")
        return ObservedCell("allowed", "application-protocol")

    if client is None or raw["client_exit"] != 0:
        raise RoutingCellError("direct client observation is incomplete")
    event = client["event"]
    phase = client["phase"]
    if event == "operation-error":
        if phase in {"socket", "bind", "listen", "datagram"}:
            stage = "child-boundary"
            expected_errnos = {errno.EPERM}
        elif phase == "connect":
            stage = "routing"
            expected_errnos = {errno.EPERM, errno.EACCES}
        else:
            raise RoutingCellError("non-syscall error cannot prove a denial")
        if (
            client["errno"] not in expected_errnos
            or raw["fixture_contact"]
            or raw["fixture_complete"]
        ):
            raise RoutingCellError("denial errno or fixture markers are inconsistent")
        return ObservedCell("denied", stage)
    if event == "certificate-rejected":
        if not raw["fixture_contact"] or raw["fixture_complete"]:
            raise RoutingCellError("TLS denial lacks exact routing contact")
        return ObservedCell("denied", "tls")
    if event == "exact-response":
        if not raw["fixture_contact"] or not raw["fixture_complete"]:
            raise RoutingCellError("direct success lacks exact fixture completion")
        return ObservedCell("allowed", "application-protocol")
    if event in {"mediated-response", "mediator-rejected"}:
        raise RoutingCellError("mediated client event lacks trusted mediator evidence")
    if event == "routing-connected":
        if not raw["fixture_contact"] or raw["fixture_complete"]:
            raise RoutingCellError("routing exposure markers are inconsistent")
        return ObservedCell("exposes-limitation", "routing")
    if event in {"socket-sentinel", "datagram-sentinel", "bind-succeeded"}:
        if event != "bind-succeeded" and not raw["fixture_complete"]:
            raise RoutingCellError("bypass sentinel lacks fixture completion")
        stage = "routing" if event == "socket-sentinel" else "child-boundary"
        return ObservedCell("exposes-limitation", stage)
    raise RoutingCellError("client event has no classification")


def raw_cell(
    case: RoutingCase,
    mechanism: str,
    *,
    cleanup: bool = True,
    client: dict[str, object] | None = None,
    client_started: bool = False,
    fixture_contact: bool = False,
    fixture_complete: bool = False,
    mediator: dict[str, object] | None = None,
    plan_rejection: str | None = None,
) -> dict[str, object]:
    """Build the closed raw shape for orchestrators and test falsifiers."""

    return {
        "case": case.identifier,
        "cleanup": cleanup,
        "client": client,
        "client_exit": 0 if client_started else None,
        "client_started": client_started,
        "fixture_complete": fixture_complete,
        "fixture_contact": fixture_contact,
        "mechanism": mechanism,
        "mediator": mediator,
        "plan_rejection": plan_rejection,
        "schema": RAW_SCHEMA,
    }
