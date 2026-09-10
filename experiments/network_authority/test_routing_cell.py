"""Mutation and completeness tests for routing raw-cell classification."""

from __future__ import annotations

import errno
import unittest
from pathlib import Path

from experiments.network_authority.routing_cell import (
    CLIENT_SCHEMA,
    MEDIATOR_SCHEMA,
    RoutingCellError,
    classify,
    raw_cell,
)
from experiments.network_authority.routing_transport_case import (
    MECHANISMS,
    RoutingCase,
    load_routing_matrix,
    plan_rejection,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATRIX = load_routing_matrix(
    REPOSITORY_ROOT / "experiments/network_authority/decision-matrix.toml"
)


def client(case: RoutingCase, event: str, phase: str) -> dict[str, object]:
    result: dict[str, object] = {
        "action": case.action,
        "case": case.identifier,
        "errno": errno.EPERM if event == "operation-error" else None,
        "event": event,
        "phase": phase,
        "schema": CLIENT_SCHEMA,
    }
    if event in {"exact-response", "socket-sentinel", "datagram-sentinel"}:
        result["response_sha256"] = "a" * 64
    if event == "exact-response":
        result["tls_version"] = "TLSv1.3"
    if event == "datagram-sentinel":
        result["request_sha256"] = "b" * 64
    if event == "certificate-rejected":
        result.pop("errno")
        result["verify_code"] = 18
    return result


def mediator(event: str, stage: str, detail: str) -> dict[str, object]:
    return {
        "detail": detail,
        "event": event,
        "schema": MEDIATOR_SCHEMA,
        "stage": stage,
    }


class RoutingCellTests(unittest.TestCase):
    def case(self, identifier: str) -> RoutingCase:
        return next(item for item in MATRIX.cases if item.identifier == identifier)

    def observed_raw(self, case: RoutingCase, mechanism: str) -> dict[str, object]:
        identifier = case.identifier
        if identifier in {"non-scoped-ipv6-scope-id", "alternate-address-text"}:
            rejection = plan_rejection(identifier)
            self.assertIsNotNone(rejection)
            return raw_cell(case, mechanism, plan_rejection=rejection)
        if identifier == "ipv4-mapped-ipv6" and mechanism == "explicit-broker":
            return raw_cell(
                case, mechanism, plan_rejection="interface-cannot-represent-address"
            )
        if identifier == "ipv4-mapped-ipv6" and mechanism == "preconnected-channel":
            return raw_cell(
                case,
                mechanism,
                mediator=mediator(
                    "rejected", "prelaunch", "connector-endpoint-mismatch"
                ),
            )
        if identifier.startswith("exact-service-"):
            if mechanism in {"explicit-broker", "preconnected-channel"}:
                return raw_cell(
                    case,
                    mechanism,
                    client=client(case, "exact-response", "application-protocol"),
                    client_started=True,
                    fixture_contact=True,
                    fixture_complete=True,
                    mediator=mediator(
                        "exact-response",
                        "application-protocol",
                        "authenticated-exact-response",
                    ),
                )
            return raw_cell(
                case,
                mechanism,
                client=client(case, "exact-response", "application-protocol"),
                client_started=True,
                fixture_contact=True,
                fixture_complete=True,
            )
        if identifier == "allowed-endpoint-wrong-certificate":
            if mechanism == "preconnected-channel":
                return raw_cell(
                    case,
                    mechanism,
                    fixture_contact=True,
                    mediator=mediator("rejected", "prelaunch", "certificate-rejected"),
                )
            if mechanism == "explicit-broker":
                return raw_cell(
                    case,
                    mechanism,
                    client=client(case, "certificate-rejected", "tls"),
                    client_started=True,
                    fixture_contact=True,
                    mediator=mediator("rejected", "tls", "certificate-rejected"),
                )
            return raw_cell(
                case,
                mechanism,
                client=client(case, "certificate-rejected", "tls"),
                client_started=True,
                fixture_contact=True,
            )
        if identifier == "direct-tcp-other-port":
            phase = "connect" if mechanism in {"landlock-port", "cgroup-endpoint"} else "socket"
            return raw_cell(
                case,
                mechanism,
                client=client(case, "operation-error", phase),
                client_started=True,
            )
        if identifier in {
            "direct-udp-dns-shaped",
            "direct-udp-quic-shaped",
            "tcp-bind-listen",
            "udp-bind",
        }:
            phase = "bind" if identifier == "tcp-bind-listen" else "socket"
            return raw_cell(
                case,
                mechanism,
                client=client(case, "operation-error", phase),
                client_started=True,
            )
        if mechanism == "landlock-port":
            return raw_cell(
                case,
                mechanism,
                client=client(case, "routing-connected", "connect"),
                client_started=True,
                fixture_contact=True,
            )
        if mechanism == "cgroup-endpoint":
            if identifier == "literal-allowed-address":
                return raw_cell(
                    case,
                    mechanism,
                    client=client(case, "routing-connected", "connect"),
                    client_started=True,
                    fixture_contact=True,
                )
            return raw_cell(
                case,
                mechanism,
                client=client(case, "operation-error", "connect"),
                client_started=True,
            )
        if mechanism == "explicit-broker":
            stage = (
                "routing"
                if identifier == "alternate-endpoint-allowed-certificate"
                else "application-protocol"
            )
            detail = (
                "connector-endpoint-mismatch"
                if stage == "routing"
                else "target-field-rejected"
            )
            return raw_cell(
                case,
                mechanism,
                client=client(case, "operation-error", "tls"),
                client_started=True,
                mediator=mediator("rejected", stage, detail),
            )
        return raw_cell(
            case,
            mechanism,
            mediator=mediator("rejected", "prelaunch", "connector-endpoint-mismatch"),
        )

    def test_all_sixty_four_registered_cells_derive_exactly(self) -> None:
        observed = 0
        for case in MATRIX.cases:
            for mechanism in MECHANISMS:
                with self.subTest(case=case.identifier, mechanism=mechanism):
                    actual = classify(self.observed_raw(case, mechanism), case, mechanism)
                    expected = case.expectation(mechanism)
                    self.assertEqual((actual.outcome, actual.stage), (expected.outcome, expected.stage))
                    observed += 1
        self.assertEqual(observed, 64)

    def test_unknown_fields_missing_cleanup_and_generic_failure_fail_closed(self) -> None:
        case = self.case("exact-service-ipv4")
        valid = self.observed_raw(case, "landlock-port")
        mutated = dict(valid)
        mutated["unknown"] = True
        incomplete = dict(valid)
        incomplete["cleanup"] = False
        generic = dict(valid)
        generic["client_exit"] = 7
        for raw in (mutated, incomplete, generic):
            with self.subTest(raw=raw), self.assertRaises(RoutingCellError):
                classify(raw, case, "landlock-port")

    def test_missing_fixture_or_wrong_errno_cannot_prove_denial_or_success(self) -> None:
        allowed = self.case("exact-service-ipv4")
        missing_fixture = self.observed_raw(allowed, "landlock-port")
        missing_fixture["fixture_complete"] = False
        denied = self.case("direct-tcp-other-port")
        wrong_errno = self.observed_raw(denied, "landlock-port")
        wrong_errno["client"] = dict(wrong_errno["client"])
        wrong_errno["client"]["errno"] = errno.ECONNREFUSED
        for raw, case in ((missing_fixture, allowed), (wrong_errno, denied)):
            with self.subTest(case=case.identifier), self.assertRaises(RoutingCellError):
                classify(raw, case, "landlock-port")

    def test_eacces_is_routing_only_and_eperm_is_required_at_child_boundary(self) -> None:
        routing_case = self.case("direct-tcp-other-port")
        routing = self.observed_raw(routing_case, "landlock-port")
        routing["client"] = dict(routing["client"])
        routing["client"]["errno"] = errno.EACCES
        observed = classify(routing, routing_case, "landlock-port")
        self.assertEqual((observed.outcome, observed.stage), ("denied", "routing"))

        boundary_case = self.case("direct-udp-dns-shaped")
        boundary = self.observed_raw(boundary_case, "landlock-port")
        boundary["client"] = dict(boundary["client"])
        boundary["client"]["errno"] = errno.EACCES
        with self.assertRaises(RoutingCellError):
            classify(boundary, boundary_case, "landlock-port")

    def test_prelaunch_and_postlaunch_markers_cannot_be_swapped(self) -> None:
        case = self.case("literal-undeclared-address")
        prelaunch = self.observed_raw(case, "preconnected-channel")
        prelaunch["client_started"] = True
        prelaunch["client_exit"] = 0
        prelaunch["client"] = client(case, "operation-error", "tls")
        postlaunch = self.observed_raw(case, "explicit-broker")
        postlaunch["client_started"] = False
        postlaunch["client_exit"] = None
        postlaunch["client"] = None
        for raw, mechanism in (
            (prelaunch, "preconnected-channel"),
            (postlaunch, "explicit-broker"),
        ):
            with self.subTest(mechanism=mechanism), self.assertRaises(RoutingCellError):
                classify(raw, case, mechanism)

    def test_event_phase_and_mediator_detail_cannot_be_relabelled(self) -> None:
        case = self.case("exact-service-ipv4")
        wrong_phase = self.observed_raw(case, "landlock-port")
        wrong_phase["client"] = dict(wrong_phase["client"])
        wrong_phase["client"]["phase"] = "connect"
        wrong_mediator = self.observed_raw(case, "explicit-broker")
        wrong_mediator["mediator"] = dict(wrong_mediator["mediator"])
        wrong_mediator["mediator"]["detail"] = "certificate-rejected"
        for raw, mechanism in (
            (wrong_phase, "landlock-port"),
            (wrong_mediator, "explicit-broker"),
        ):
            with self.subTest(mechanism=mechanism), self.assertRaises(RoutingCellError):
                classify(raw, case, mechanism)


if __name__ == "__main__":
    unittest.main()
