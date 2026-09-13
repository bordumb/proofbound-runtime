"""Falsifiers for the experiment 0001G explicit-operation mediator."""

from __future__ import annotations

import socket
import tempfile
import threading
import unittest
from pathlib import Path

from experiments.network_authority.explicit_broker import wire_json
from experiments.network_authority.resolution_broker import (
    ResolutionBrokerError,
    decode_request,
    serve,
)
from experiments.network_authority.resolution_network_client import execute


class ResolutionBrokerTests(unittest.TestCase):
    def test_request_grammar_distinguishes_operation_from_target_attack(self) -> None:
        operation = wire_json({"operation": "echo", "payload": "bounded payload"})
        targeted = wire_json({"operation": "echo", "payload": "bounded payload", "target": "denied.test:443"})
        decode_request(operation, "exact")
        decode_request(operation, "redirect-reject")
        decode_request(targeted, "proxy-reject")
        for payload, mode in ((targeted, "exact"), (operation, "proxy-reject"), (operation + b" ", "exact")):
            with self.subTest(mode=mode), self.assertRaises(ResolutionBrokerError):
                decode_request(payload, mode)

    def test_proxy_target_is_rejected_without_remote_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            broker, child = socket.socketpair()
            marker = root / "marker.json"
            session = root / "session.json"
            errors: list[BaseException] = []

            def target() -> None:
                try:
                    self.assertEqual(
                        serve(
                            broker.detach(), "proxy-reject", "127.0.0.1", 443,
                            root / "absent.pem", None, marker, session,
                        ),
                        0,
                    )
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=target)
            thread.start()
            events = execute(
                "broker-proxy-rejected", "127.0.0.1", 443,
                root / "absent.pem", child.fileno(),
            )
            child.close()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(events, ["operation-rejected"])
            self.assertTrue(marker.is_file())
            self.assertFalse(session.exists())


if __name__ == "__main__":
    unittest.main()
