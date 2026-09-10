#!/usr/bin/env python3
"""Closed bypass/lifecycle case domain for experiment 0001H."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib as toml
except ModuleNotFoundError:
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


BYPASS_ACTIONS = {
    "pathname-unix-socket": ("open-pathname-unix-stream", "socket-bypass"),
    "abstract-unix-socket": ("open-abstract-unix-stream", "socket-bypass"),
    "inherited-connected-internet-socket": ("inherit-connected-inet-stream", "socket-bypass"),
    "io-uring-socket-create-connect": ("submit-io-uring-socket-connect", "socket-bypass"),
    "io-uring-descriptor-send": ("submit-io-uring-descriptor-send", "socket-bypass"),
    "raw-and-packet-sockets": ("open-raw-and-packet-sockets", "socket-bypass"),
    "fork-exec-at-process-limit": ("fork-exec-at-limit", "lifecycle"),
    "concurrent-install-and-connect": ("race-install-with-connect", "lifecycle"),
    "mediator-crash-before-release": ("crash-mediator-before-release", "lifecycle"),
    "mediator-crash-during-exchange": ("crash-mediator-during-exchange", "lifecycle"),
    "mediator-restart-substitution": ("restart-substitute-mediator", "lifecycle"),
    "policy-program-map-rule-substitution": ("substitute-native-policy", "lifecycle"),
    "resolver-and-trust-root-substitution": ("substitute-resolver-trust-root", "lifecycle"),
    "certificate-and-channel-substitution": ("substitute-certificate-channel", "lifecycle"),
    "executable-and-staged-client-substitution": ("substitute-executable-client", "lifecycle"),
    "connection-reuse-beyond-count": ("reuse-beyond-one-connection", "lifecycle"),
    "cleanup-and-namespace-teardown-failure": ("inject-cleanup-failure", "lifecycle"),
    "existing-result-replacement": ("replace-existing-result", "publication"),
}
BYPASS_CASE_IDS = tuple(BYPASS_ACTIONS)


class BypassLifecycleError(Exception):
    """The bypass/lifecycle domain or immutable plan is invalid."""


@dataclass(frozen=True)
class BypassCase:
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
            raise BypassLifecycleError("case mechanism expectation is not unique")
        return matches[0]


@dataclass(frozen=True)
class BypassMatrix:
    source_sha256: str
    cases: tuple[BypassCase, ...]


def parameters_for(case_id: str) -> dict[str, object]:
    """Return the immutable operation parameters for one registered case."""

    if case_id not in BYPASS_ACTIONS:
        raise BypassLifecycleError("bypass case identity is unknown")
    if case_id == "pathname-unix-socket":
        return {"address": "cases/undeclared.sock", "family": "AF_UNIX"}
    if case_id == "abstract-unix-socket":
        return {"address_hex": "0070726f6f66626f756e642d756e6465636c61726564", "family": "AF_UNIX"}
    if case_id == "inherited-connected-internet-socket":
        return {"descriptor_inventory": "exact", "peer": "127.0.0.2:443"}
    if case_id.startswith("io-uring-"):
        return {"entries": 2, "opcode_set": ["socket", "connect", "send"]}
    if case_id == "raw-and-packet-sockets":
        return {"families": ["AF_INET", "AF_PACKET"], "types": ["SOCK_RAW", "SOCK_DGRAM"]}
    if case_id == "fork-exec-at-process-limit":
        return {"maximum_processes": 1, "operations": ["fork", "exec"]}
    if case_id == "concurrent-install-and-connect":
        return {"child_state": "stopped", "release_after": "boundary-acknowledged"}
    if case_id.startswith("mediator-"):
        return {"generation": 1, "identity": ["pid", "executable-sha256", "channel-peer"]}
    if "substitution" in case_id:
        return {"mutation_count": 1, "phase": "after-plan-before-release"}
    if case_id == "connection-reuse-beyond-count":
        return {"registered_connections": 1, "attempted_connections": 2}
    if case_id == "cleanup-and-namespace-teardown-failure":
        return {"injected_failure": "teardown", "survivor_count": 0}
    return {"publication": "no-replace", "sentinel": "existing-result"}


def case_plan(
    case: BypassCase,
    mechanism: str,
    matrix_sha256: str,
    subject_identities: dict[str, str],
) -> dict[str, object]:
    """Freeze the complete prelaunch identity and expectation."""

    if (
        mechanism not in MECHANISMS
        or len(matrix_sha256) != 64
        or any(character not in "0123456789abcdef" for character in matrix_sha256)
        or not subject_identities
    ):
        raise BypassLifecycleError("case plan identity is invalid")
    if any(
        not isinstance(name, str)
        or not name
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        for name, digest in subject_identities.items()
    ):
        raise BypassLifecycleError("subject identity is invalid")
    expectation = case.expectation(mechanism)
    return {
        "action": case.action,
        "case": case.identifier,
        "decision_matrix_sha256": matrix_sha256,
        "expectation": {"outcome": expectation.outcome, "stage": expectation.stage},
        "mechanism": mechanism,
        "parameters": parameters_for(case.identifier),
        "schema": "proofbound-runtime-bypass-case-plan/1",
        "subject_identities": dict(sorted(subject_identities.items())),
    }


def load_bypass_matrix(path: Path) -> BypassMatrix:
    """Read and strictly project the registered bypass/lifecycle slice."""

    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise BypassLifecycleError("decision matrix path is invalid")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_MATRIX_BYTES:
        raise BypassLifecycleError("decision matrix size is invalid")
    try:
        decoded = toml.loads(raw.decode())
    except (UnicodeDecodeError, toml.TOMLDecodeError) as error:
        raise BypassLifecycleError("decision matrix does not decode") from error
    if not isinstance(decoded, dict) or set(decoded) != ROOT_FIELDS or decoded["schema"] != SCHEMA:
        raise BypassLifecycleError("decision matrix root is not closed")
    mechanisms = decoded["mechanisms"]
    if not isinstance(mechanisms, list) or [item.get("id") for item in mechanisms if isinstance(item, dict)] != list(MECHANISMS):
        raise BypassLifecycleError("mechanism inventory is not exact")
    raw_cases = decoded["cases"]
    if not isinstance(raw_cases, list):
        raise BypassLifecycleError("case inventory is invalid")
    selected = []
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict) or set(raw_case) != CASE_FIELDS:
            raise BypassLifecycleError("case schema is not closed")
        if raw_case["slice"] != "bypass-lifecycle":
            continue
        identifier = raw_case["id"]
        if identifier not in BYPASS_ACTIONS:
            raise BypassLifecycleError("bypass case identity is unknown")
        action, fixture = BYPASS_ACTIONS[identifier]
        expectations = tuple(parse_expectation(item) for item in raw_case["expectations"])
        if (
            raw_case["fixture"] != fixture
            or not isinstance(raw_case["parent_rows"], list)
            or not raw_case["parent_rows"]
            or not all(isinstance(item, str) for item in raw_case["parent_rows"])
            or not isinstance(raw_case["attempted_authority"], str)
            or type(raw_case["authority_exposure"]) is not bool
            or type(raw_case["maximum_seconds"]) is not int
            or raw_case["maximum_seconds"] != 10
            or len(expectations) != len(MECHANISMS)
            or tuple(item.mechanism for item in expectations) != MECHANISMS
        ):
            raise BypassLifecycleError("bypass case fields are invalid")
        selected.append(BypassCase(identifier, action, fixture, raw_case["attempted_authority"], raw_case["authority_exposure"], 10, expectations))
    if tuple(item.identifier for item in selected) != BYPASS_CASE_IDS:
        raise BypassLifecycleError("bypass case inventory or order changed")
    return BypassMatrix(hashlib.sha256(raw).hexdigest(), tuple(selected))
