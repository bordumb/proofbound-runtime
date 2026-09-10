#!/usr/bin/env python3
"""Closed raw evidence classifier for experiment 0001H."""

from __future__ import annotations

import errno
from dataclasses import dataclass

from experiments.network_authority.bypass_lifecycle_case import BypassCase


RAW_SCHEMA = "proofbound-runtime-bypass-raw-cell/1"
RAW_FIELDS = {
    "case", "cleanup", "connection_count", "events", "mechanism",
    "plan_rejection", "prelaunch_rejection", "publication_preserved",
    "schema", "survivor_count", "syscall_attempts",
}


class BypassCellError(Exception):
    """Raw bypass evidence cannot select one closed outcome."""


@dataclass(frozen=True)
class ObservedCell:
    outcome: str
    stage: str


def _attempts(raw: dict[str, object], names: tuple[str, ...], errnos: tuple[int, ...]) -> None:
    attempts = raw["syscall_attempts"]
    if not isinstance(attempts, list) or len(attempts) != len(names):
        raise BypassCellError("syscall inventory changed")
    for value, name, number in zip(attempts, names, errnos):
        if value != {"errno": number, "result": "error", "syscall": name}:
            raise BypassCellError("syscall evidence changed")


def derive(raw: object, case: BypassCase, mechanism: str) -> ObservedCell:
    """Derive one result without consulting the registered expectation."""

    if not isinstance(raw, dict) or set(raw) != RAW_FIELDS:
        raise BypassCellError("raw bypass cell schema is not closed")
    if (
        raw["schema"] != RAW_SCHEMA or raw["case"] != case.identifier
        or raw["mechanism"] != mechanism or raw["cleanup"] is not True
        or type(raw["connection_count"]) is not int
        or type(raw["survivor_count"]) is not int
        or type(raw["publication_preserved"]) is not bool
        or not isinstance(raw["events"], list)
    ):
        raise BypassCellError("raw bypass identity is invalid")
    identifier = case.identifier
    if identifier in {"pathname-unix-socket", "abstract-unix-socket"}:
        suffix = "-abstract" if identifier.startswith("abstract") else ""
        _attempts(raw, (f"socket(AF_UNIX,SOCK_STREAM){suffix}",), (errno.EPERM,))
        return ObservedCell("denied", "child-boundary")
    if identifier.startswith("io-uring-"):
        _attempts(raw, ("io_uring_setup",), (errno.EPERM,))
        return ObservedCell("denied", "child-boundary")
    if identifier == "raw-and-packet-sockets":
        _attempts(raw, ("socket(AF_INET,SOCK_RAW)", "socket(AF_PACKET,SOCK_DGRAM)"), (errno.EPERM, errno.EPERM))
        return ObservedCell("denied", "child-boundary")
    if identifier == "inherited-connected-internet-socket":
        if raw["prelaunch_rejection"] != "foreign-descriptor-present" or raw["syscall_attempts"]:
            raise BypassCellError("inherited descriptor rejection changed")
        return ObservedCell("denied", "prelaunch")
    if identifier == "fork-exec-at-process-limit":
        _attempts(raw, ("fork",), (errno.EAGAIN,))
        return ObservedCell("denied", "child-boundary")
    if identifier == "concurrent-install-and-connect":
        if raw["events"] != ["child-stopped", "boundary-acknowledged", "child-released", "connect-denied"]:
            raise BypassCellError("install race sequence changed")
        return ObservedCell("denied", "child-boundary")
    if identifier.startswith("mediator-"):
        if mechanism in {"landlock-port", "cgroup-endpoint"}:
            if raw["plan_rejection"] != "mechanism-has-no-mediator" or raw["events"]:
                raise BypassCellError("non-mediator plan rejection changed")
            return ObservedCell("denied", "plan")
        expected = {
            "mediator-crash-before-release": ("mediator-crashed-before-release", "prelaunch"),
            "mediator-crash-during-exchange": ("mediator-crashed-during-exchange", "lifecycle"),
            "mediator-restart-substitution": ("mediator-identity-mismatch", "lifecycle"),
        }[identifier]
        if raw["events"] != [expected[0]]:
            raise BypassCellError("mediator lifecycle evidence changed")
        return ObservedCell("denied", expected[1])
    if "substitution" in identifier:
        expected = {
            "policy-program-map-rule-substitution": "native-policy-digest-mismatch",
            "resolver-and-trust-root-substitution": "resolver-trust-root-digest-mismatch",
            "certificate-and-channel-substitution": "certificate-channel-identity-mismatch",
            "executable-and-staged-client-substitution": "executable-client-digest-mismatch",
        }[identifier]
        if raw["prelaunch_rejection"] != expected:
            raise BypassCellError("substitution rejection changed")
        return ObservedCell("denied", "prelaunch")
    if identifier == "connection-reuse-beyond-count":
        if mechanism in {"landlock-port", "cgroup-endpoint"}:
            if raw["connection_count"] != 2 or raw["events"] != ["registered-exchange", "excess-exchange"]:
                raise BypassCellError("routing reuse exposure changed")
            return ObservedCell("exposes-limitation", "routing")
        expected = "operation-rejected" if mechanism == "explicit-broker" else "channel-closed-after-registered-exchange"
        stage = "application-protocol" if mechanism == "explicit-broker" else "lifecycle"
        if raw["connection_count"] != 1 or raw["events"] != ["registered-exchange", expected]:
            raise BypassCellError("mediated reuse denial changed")
        return ObservedCell("denied", stage)
    if identifier == "cleanup-and-namespace-teardown-failure":
        if raw["events"] != ["teardown-failure-injected", "failure-retained"] or raw["survivor_count"] != 0:
            raise BypassCellError("cleanup failure evidence changed")
        return ObservedCell("denied", "cleanup")
    if identifier == "existing-result-replacement":
        if raw["events"] != ["replacement-rejected"] or raw["publication_preserved"] is not True:
            raise BypassCellError("publication preservation changed")
        return ObservedCell("denied", "cleanup")
    raise BypassCellError("case has no closed derivation")


def raw_cell(case: BypassCase, mechanism: str, **changes: object) -> dict[str, object]:
    """Build the closed raw shape for orchestrators and falsifiers."""

    value: dict[str, object] = {
        "case": case.identifier, "cleanup": True, "connection_count": 0,
        "events": [], "mechanism": mechanism, "plan_rejection": None,
        "prelaunch_rejection": None, "publication_preserved": False,
        "schema": RAW_SCHEMA, "survivor_count": 0, "syscall_attempts": [],
    }
    if not set(changes).issubset(value):
        raise BypassCellError("raw bypass field is unknown")
    value.update(changes)
    return value
