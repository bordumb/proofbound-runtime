"""Falsifiers for experiment 0001F trusted mediator primitives."""

from __future__ import annotations

import json
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from experiments.network_authority.explicit_broker import wire_json
from experiments.network_authority.decision_http_fixture import serve_tls_fixture
from experiments.network_authority.routing_mediator import (
    MediatorError,
    MediatorRejection,
    decode_operation,
    exact_remote_exchange,
    marker,
    open_authenticated,
    serve_broker,
)


class RoutingMediatorTests(unittest.TestCase):
    def certificate(self, root: Path, name: str, stem: str) -> tuple[Path, Path]:
        certificate = root / f"{stem}-certificate.pem"
        private_key = root / f"{stem}-key.pem"
        completed = subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                f"/CN={name}",
                "-addext",
                f"subjectAltName=DNS:{name}",
                "-keyout",
                str(private_key),
                "-out",
                str(certificate),
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        return certificate, private_key

    def start_fixture(
        self, root: Path, certificate: Path, private_key: Path
    ) -> tuple[threading.Thread, list[BaseException], int, Path, Path]:
        ready = root / "ready.json"
        contact = root / "contact.json"
        observation = root / "fixture.json"
        errors: list[BaseException] = []

        def serve() -> None:
            try:
                serve_tls_fixture(
                    "127.0.0.1",
                    0,
                    "exact",
                    certificate,
                    private_key,
                    ready,
                    contact,
                    observation,
                )
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=serve)
        thread.start()
        for _ in range(100):
            if ready.is_file() or errors:
                break
            time.sleep(0.01)
        self.assertTrue(ready.is_file(), errors)
        port = json.loads(ready.read_bytes())["port"]
        return thread, errors, port, contact, observation

    def test_operation_schema_has_no_target_or_duplicate_escape(self) -> None:
        valid = wire_json({"operation": "echo", "payload": "bounded payload"})
        self.assertEqual(decode_operation(valid), "bounded payload")
        attacks = (
            b'{"operation":"echo","payload":"bounded payload","target":"127.0.0.1"}',
            b'{"operation":"echo","operation":"echo","payload":"bounded payload"}',
            b'{"operation": "echo", "payload": "bounded payload"}',
        )
        for attack in attacks:
            with self.subTest(attack=attack), self.assertRaises(MediatorRejection) as raised:
                decode_operation(attack)
            self.assertEqual(raised.exception.stage, "application-protocol")
            self.assertEqual(raised.exception.detail, "target-field-rejected")

    def test_marker_vocabulary_is_closed_by_cell_classifier_schema(self) -> None:
        self.assertEqual(
            marker("rejected", "routing", "connector-endpoint-mismatch"),
            {
                "detail": "connector-endpoint-mismatch",
                "event": "rejected",
                "schema": "proofbound-runtime-routing-mediator-observation/1",
                "stage": "routing",
            },
        )

    def test_broker_rejects_target_before_any_remote_connection(self) -> None:
        parent, child = socket.socketpair()
        request = wire_json(
            {
                "operation": "echo",
                "payload": "bounded payload",
                "target": "127.0.0.2",
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker_path = root / "marker.json"
            session_path = root / "session.json"
            results: list[int] = []

            def broker() -> None:
                results.append(
                    serve_broker(
                        parent.detach(),
                        "203.0.113.1",
                        "203.0.113.1",
                        443,
                        root / "absent-ca.pem",
                        marker_path,
                        session_path,
                    )
                )

            thread = threading.Thread(target=broker)
            thread.start()
            child.sendall(struct.pack(">I", len(request)) + request)
            child.shutdown(socket.SHUT_WR)
            size = struct.unpack(">I", child.recv(4))[0]
            response = child.recv(size)
            child.close()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(results, [7])
            self.assertEqual(
                response,
                wire_json({"code": "target-field-rejected", "status": "error"}),
            )
            self.assertEqual(json.loads(marker_path.read_bytes())["stage"], "application-protocol")
            self.assertFalse(session_path.exists())

    def test_invalid_addresses_fail_before_connection(self) -> None:
        for dial, expected in (
            ("127.000.000.001", "127.0.0.1"),
            ("fd00::1%1", "fd00::1"),
            ("127.0.0.1", "::1"),
        ):
            with self.subTest(dial=dial, expected=expected), self.assertRaises(MediatorError):
                open_authenticated(dial, expected, 443, Path("/absent"))

    def test_authenticated_session_records_exact_tls_and_http(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate, private_key = self.certificate(root, "allowed.test", "allowed")
            thread, errors, port, contact, observation = self.start_fixture(
                root, certificate, private_key
            )
            protected, session = open_authenticated(
                "127.0.0.1", "127.0.0.1", port, certificate
            )
            exact_remote_exchange(protected)
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(session["tls_version"], "TLSv1.3")
            self.assertEqual(session["peer_ip"], "127.0.0.1")
            self.assertTrue(contact.is_file())
            self.assertTrue(observation.is_file())

    def test_certificate_rejection_is_not_a_generic_tls_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trusted, _trusted_key = self.certificate(root, "allowed.test", "trusted")
            served, served_key = self.certificate(root, "denied.test", "served")
            thread, errors, port, contact, observation = self.start_fixture(
                root, served, served_key
            )
            with self.assertRaises(MediatorRejection) as raised:
                open_authenticated("127.0.0.1", "127.0.0.1", port, trusted)
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual((raised.exception.stage, raised.exception.detail), ("tls", "certificate-rejected"))
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ssl.SSLError)
            self.assertTrue(contact.is_file())
            self.assertFalse(observation.exists())


if __name__ == "__main__":
    unittest.main()
