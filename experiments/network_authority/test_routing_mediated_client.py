"""Falsifiers for the experiment 0001F mediated child vocabulary."""

from __future__ import annotations

import json
import socket
import struct
import threading
import unittest

from experiments.network_authority.explicit_broker import wire_json
from experiments.network_authority.routing_mediated_client import (
    ALLOWED_RESPONSE,
    DIRECT_CASES,
    EXECUTABLE_CASES,
    MediatedClientError,
    request_for_case,
    run,
)


class RoutingMediatedClientTests(unittest.TestCase):
    def exchange(self, case: str, response: bytes) -> tuple[dict[str, object], bytes]:
        parent, child = socket.socketpair()
        received: list[bytes] = []

        def serve() -> None:
            try:
                size = struct.unpack(">I", parent.recv(4))[0]
                request = bytearray()
                while len(request) < size:
                    request.extend(parent.recv(size - len(request)))
                received.append(bytes(request))
                parent.recv(1)
                parent.sendall(struct.pack(">I", len(response)) + response)
                parent.shutdown(socket.SHUT_WR)
            finally:
                parent.close()

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            result = run(case, child.fileno())
        finally:
            child.close()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        return result, received[0]

    def test_catalog_excludes_only_two_trusted_plan_rejections(self) -> None:
        self.assertEqual(len(EXECUTABLE_CASES), 14)
        self.assertEqual(len(DIRECT_CASES), 5)
        with self.assertRaises(MediatedClientError):
            request_for_case("alternate-address-text")

    def test_exact_response_records_only_child_visible_evidence(self) -> None:
        observed, request = self.exchange("exact-service-ipv4", ALLOWED_RESPONSE)
        self.assertEqual(observed["event"], "mediated-response")
        self.assertNotIn("tls_version", observed)
        self.assertEqual(
            json.loads(request), {"operation": "echo", "payload": "bounded payload"}
        )

    def test_target_attack_is_not_silently_canonicalized(self) -> None:
        response = wire_json({"code": "target-field-rejected", "status": "error"})
        observed, request = self.exchange("literal-allowed-address", response)
        self.assertEqual(observed["event"], "mediator-rejected")
        self.assertEqual(observed["code"], "target-field-rejected")
        self.assertEqual(json.loads(request)["target"], "127.0.0.1")

    def test_wrong_rejection_code_fails_closed(self) -> None:
        response = wire_json({"code": "target-field-rejected", "status": "error"})
        parent, child = socket.socketpair()

        def serve() -> None:
            size = struct.unpack(">I", parent.recv(4))[0]
            parent.recv(size)
            parent.recv(1)
            parent.sendall(struct.pack(">I", len(response)) + response)
            parent.shutdown(socket.SHUT_WR)
            parent.close()

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            with self.assertRaises(MediatedClientError):
                run("allowed-endpoint-wrong-certificate", child.fileno())
        finally:
            child.close()
            thread.join(timeout=2)

    def test_unconfined_direct_action_is_observed_as_exposure(self) -> None:
        parent, child = socket.socketpair()
        try:
            observed = run("udp-bind", child.fileno())
        finally:
            parent.close()
            child.close()
        self.assertEqual(observed["event"], "bind-succeeded")


if __name__ == "__main__":
    unittest.main()
