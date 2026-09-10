"""Exhaustive cell tests for experiment 0001H."""

from __future__ import annotations

import errno
import unittest
from pathlib import Path

from experiments.network_authority.bypass_cell import BypassCellError, derive, raw_cell
from experiments.network_authority.bypass_lifecycle_case import load_bypass_matrix
from experiments.network_authority.routing_transport_case import MECHANISMS


MATRIX = load_bypass_matrix(Path(__file__).resolve().parent / "decision-matrix.toml")


def observed(case, mechanism: str) -> dict[str, object]:
    identifier = case.identifier
    if identifier in {"pathname-unix-socket", "abstract-unix-socket"}:
        suffix = "-abstract" if identifier.startswith("abstract") else ""
        return raw_cell(case, mechanism, syscall_attempts=[{"errno": errno.EPERM, "result": "error", "syscall": f"socket(AF_UNIX,SOCK_STREAM){suffix}"}])
    if identifier.startswith("io-uring-"):
        return raw_cell(case, mechanism, syscall_attempts=[{"errno": errno.EPERM, "result": "error", "syscall": "io_uring_setup"}])
    if identifier == "raw-and-packet-sockets":
        return raw_cell(case, mechanism, syscall_attempts=[{"errno": errno.EPERM, "result": "error", "syscall": "socket(AF_INET,SOCK_RAW)"}, {"errno": errno.EPERM, "result": "error", "syscall": "socket(AF_PACKET,SOCK_DGRAM)"}])
    if identifier == "inherited-connected-internet-socket":
        return raw_cell(case, mechanism, prelaunch_rejection="foreign-descriptor-present")
    if identifier == "fork-exec-at-process-limit":
        return raw_cell(case, mechanism, syscall_attempts=[{"errno": errno.EAGAIN, "result": "error", "syscall": "fork"}])
    if identifier == "concurrent-install-and-connect":
        number = errno.EACCES if mechanism == "landlock-port" else errno.EPERM
        return raw_cell(case, mechanism, events=["child-stopped", "boundary-acknowledged", "child-released", "connect-denied"], syscall_attempts=[{"errno": number, "result": "error", "syscall": "connect-after-acknowledgement"}])
    if identifier.startswith("mediator-"):
        if mechanism in {"landlock-port", "cgroup-endpoint"}:
            return raw_cell(case, mechanism, plan_rejection="mechanism-has-no-mediator")
        event = {"mediator-crash-before-release": "mediator-crashed-before-release", "mediator-crash-during-exchange": "mediator-crashed-during-exchange", "mediator-restart-substitution": "mediator-identity-mismatch"}[identifier]
        return raw_cell(case, mechanism, events=[event])
    if "substitution" in identifier:
        rejection = {"policy-program-map-rule-substitution": "native-policy-digest-mismatch", "resolver-and-trust-root-substitution": "resolver-trust-root-digest-mismatch", "certificate-and-channel-substitution": "certificate-channel-identity-mismatch", "executable-and-staged-client-substitution": "executable-client-digest-mismatch"}[identifier]
        return raw_cell(case, mechanism, prelaunch_rejection=rejection)
    if identifier == "connection-reuse-beyond-count":
        if mechanism in {"landlock-port", "cgroup-endpoint"}:
            return raw_cell(case, mechanism, connection_count=2, events=["registered-exchange", "excess-exchange"])
        event = "operation-rejected" if mechanism == "explicit-broker" else "channel-closed-after-registered-exchange"
        return raw_cell(case, mechanism, connection_count=1, events=["registered-exchange", event])
    if identifier == "cleanup-and-namespace-teardown-failure":
        return raw_cell(case, mechanism, events=["teardown-failure-injected", "failure-retained"])
    return raw_cell(case, mechanism, events=["replacement-rejected"], publication_preserved=True)


class BypassCellTests(unittest.TestCase):
    def test_all_seventy_two_cells_derive_the_registered_result(self) -> None:
        for case in MATRIX.cases:
            for mechanism in MECHANISMS:
                with self.subTest(case=case.identifier, mechanism=mechanism):
                    value = derive(observed(case, mechanism), case, mechanism)
                    expected = case.expectation(mechanism)
                    self.assertEqual((value.outcome, value.stage), (expected.outcome, expected.stage))

    def test_mutations_fail_closed(self) -> None:
        case = MATRIX.cases[0]
        for mutation in ({"extra": True}, {"cleanup": False}, {"syscall_attempts": []}):
            raw = observed(case, "landlock-port")
            raw.update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(BypassCellError):
                derive(raw, case, "landlock-port")

    def test_unknown_raw_field_is_rejected_at_construction(self) -> None:
        with self.assertRaises(BypassCellError):
            raw_cell(MATRIX.cases[0], "landlock-port", unknown=True)


if __name__ == "__main__":
    unittest.main()
