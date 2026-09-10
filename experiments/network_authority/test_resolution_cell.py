"""Mutation and completeness tests for resolution raw-cell classification."""

from __future__ import annotations

import unittest
from pathlib import Path

from experiments.network_authority.resolution_cell import (
    ResolutionCellError,
    classify,
    raw_cell,
    rejected,
    resolved,
)
from experiments.network_authority.resolution_indirection_case import (
    ResolutionCase,
    load_resolution_matrix,
)
from experiments.network_authority.routing_transport_case import MECHANISMS


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATRIX = load_resolution_matrix(REPOSITORY_ROOT / "experiments/network_authority/decision-matrix.toml")


class ResolutionCellTests(unittest.TestCase):
    def case(self, identifier: str) -> ResolutionCase:
        return next(item for item in MATRIX.cases if item.identifier == identifier)

    def observed_raw(self, case: ResolutionCase, mechanism: str) -> dict[str, object]:
        identifier = case.identifier
        allowed4 = resolved("127.0.0.1", "allowed.test", "udp")
        allowed6 = resolved("fd00::1", "allowed.test", "udp")
        denied = resolved("127.0.0.2", "denied.test", "udp")
        if identifier == "stable-a-and-aaaa":
            return raw_cell(case, mechanism, client_started=True, dns_query_count=2, resolver_events=[allowed4, allowed6], network_events=["declared-response"], service_contact_count=2, service_complete_count=2)
        if identifier == "cname-to-declared-service":
            return raw_cell(case, mechanism, client_started=True, dns_query_count=1, resolver_events=[allowed4], network_events=["declared-response"], service_contact_count=1, service_complete_count=1)
        if identifier == "resolver-truncated-tcp-fallback":
            return raw_cell(case, mechanism, client_started=True, dns_query_count=2, resolver_events=[resolved("127.0.0.1", "allowed.test", "udp", "tcp")], network_events=["declared-response"], service_contact_count=1, service_complete_count=1)
        rejection = {
            "cname-loop-or-depth": [rejected("cname-loop-or-depth", "udp"), rejected("cname-loop-or-depth", "udp")],
            "resolver-timeout": [rejected("timeout", "udp")],
            "resolver-malformed-response": [rejected("malformed", "udp")],
            "resolver-dnssec-flag-confusion": [rejected("dnssec-flags", "udp")],
        }
        if identifier in rejection:
            events = rejection[identifier]
            return raw_cell(case, mechanism, dns_query_count=sum(len(item["transports"]) for item in events), resolver_events=events)
        if identifier == "ttl-rebind-to-undeclared":
            if mechanism in {"explicit-broker", "preconnected-channel"}:
                events = [allowed4, rejected("terminal-address", "udp")]
                return raw_cell(case, mechanism, client_started=True, dns_query_count=2, resolver_events=events, network_events=["declared-response"], service_contact_count=1, service_complete_count=1)
            events = [allowed4, resolved("127.0.0.2", "allowed.test", "udp")]
            network = ["declared-response", "undeclared-contact"] if mechanism == "landlock-port" else ["declared-response", "routing-denied"]
            contacts = 2 if mechanism == "landlock-port" else 1
            return raw_cell(case, mechanism, client_started=True, dns_query_count=2, resolver_events=events, network_events=network, service_contact_count=contacts, service_complete_count=1)
        if identifier == "cname-to-undeclared-service":
            if mechanism in {"explicit-broker", "preconnected-channel"}:
                return raw_cell(case, mechanism, dns_query_count=1, resolver_events=[rejected("terminal-service", "udp")])
            network = ["undeclared-contact"] if mechanism == "landlock-port" else ["routing-denied"]
            contacts = 1 if mechanism == "landlock-port" else 0
            return raw_cell(case, mechanism, client_started=True, dns_query_count=1, resolver_events=[denied], network_events=network, service_contact_count=contacts)
        if identifier == "resolver-configuration-substitution":
            if mechanism == "landlock-port":
                return raw_cell(case, mechanism, client_started=True, dns_query_count=1, resolver_events=[resolved("127.0.0.2", "allowed.test", "udp")], network_events=["undeclared-contact"], service_contact_count=1)
            return raw_cell(case, mechanism, prelaunch_rejection="resolver-config-digest-mismatch")
        if identifier.startswith("redirect-"):
            event = {"redirect-undeclared-host": "redirect-host", "redirect-cleartext": "redirect-cleartext", "redirect-other-port": "redirect-port"}[identifier]
            if mechanism == "explicit-broker":
                return raw_cell(case, mechanism, client_started=True, network_events=["operation-rejected"], service_contact_count=1, service_complete_count=1)
            if mechanism == "preconnected-channel":
                return raw_cell(case, mechanism, client_started=True, network_events=[event, "child-boundary-denied"], service_contact_count=1, service_complete_count=1)
            if mechanism == "landlock-port" and identifier == "redirect-undeclared-host":
                return raw_cell(case, mechanism, client_started=True, network_events=[event, "undeclared-contact"], service_contact_count=2, service_complete_count=1)
            return raw_cell(case, mechanism, client_started=True, network_events=[event, "routing-denied"], service_contact_count=1, service_complete_count=1)
        if identifier in {"http-connect-target-confusion", "socks-target-confusion"}:
            if mechanism == "explicit-broker":
                return raw_cell(case, mechanism, client_started=True, network_events=["operation-rejected"])
            return raw_cell(case, mechanism, client_started=True, network_events=["proxy-target-reached"], proxy_contact_count=1, proxy_complete_count=1)
        if identifier.startswith("ambient-"):
            if mechanism in {"explicit-broker", "preconnected-channel"}:
                return raw_cell(case, mechanism, plan_rejection="ambient-environment-present")
            if mechanism == "landlock-port":
                return raw_cell(case, mechanism, client_started=True, network_events=["ambient-proxy-contact"], proxy_contact_count=1, proxy_complete_count=1)
            return raw_cell(case, mechanism, client_started=True, network_events=["routing-denied"])
        raise AssertionError(identifier)

    def test_all_seventy_two_registered_cells_derive_exactly(self) -> None:
        observed = 0
        for case in MATRIX.cases:
            for mechanism in MECHANISMS:
                with self.subTest(case=case.identifier, mechanism=mechanism):
                    actual = classify(self.observed_raw(case, mechanism), case, mechanism)
                    expected = case.expectation(mechanism)
                    self.assertEqual((actual.outcome, actual.stage), (expected.outcome, expected.stage))
                    observed += 1
        self.assertEqual(observed, 72)

    def test_unknown_fields_cleanup_and_generic_failure_fail_closed(self) -> None:
        case = self.case("stable-a-and-aaaa")
        valid = self.observed_raw(case, "landlock-port")
        unknown = dict(valid)
        unknown["unknown"] = True
        cleanup = dict(valid)
        cleanup["cleanup"] = False
        generic = dict(valid)
        generic["client_exit"] = 7
        for raw in (unknown, cleanup, generic):
            with self.assertRaises(ResolutionCellError):
                classify(raw, case, "landlock-port")

    def test_counts_and_resolver_transports_cannot_be_relabelled(self) -> None:
        case = self.case("resolver-truncated-tcp-fallback")
        wrong_count = self.observed_raw(case, "landlock-port")
        wrong_count["dns_query_count"] = 1
        wrong_transport = self.observed_raw(case, "landlock-port")
        wrong_transport["resolver_events"] = [resolved("127.0.0.1", "allowed.test", "udp")]
        for raw in (wrong_count, wrong_transport):
            with self.assertRaises(ResolutionCellError):
                classify(raw, case, "landlock-port")

    def test_prelaunch_rejections_cannot_coexist_with_execution(self) -> None:
        ambient = self.case("ambient-http-proxy")
        raw = self.observed_raw(ambient, "explicit-broker")
        raw["client_started"] = True
        raw["client_exit"] = 0
        raw["network_events"] = ["operation-rejected"]
        with self.assertRaises(ResolutionCellError):
            classify(raw, ambient, "explicit-broker")

    def test_contact_or_event_substitution_fails_closed(self) -> None:
        case = self.case("redirect-undeclared-host")
        missing_contact = self.observed_raw(case, "landlock-port")
        missing_contact["service_contact_count"] = 1
        wrong_event = self.observed_raw(case, "cgroup-endpoint")
        wrong_event["network_events"] = ["redirect-host", "undeclared-contact"]
        for raw, mechanism in ((missing_contact, "landlock-port"), (wrong_event, "cgroup-endpoint")):
            with self.assertRaises(ResolutionCellError):
                classify(raw, case, mechanism)


if __name__ == "__main__":
    unittest.main()
