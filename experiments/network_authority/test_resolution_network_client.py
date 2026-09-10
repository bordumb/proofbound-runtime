"""Falsifiers for the experiment 0001G boundary-executed client."""

from __future__ import annotations

import errno
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from experiments.network_authority.decision_http_fixture import serve_tls_fixture
from experiments.network_authority.resolution_network_client import (
    ResolutionNetworkClientError,
    execute,
    raw_contact,
)


class ResolutionNetworkClientTests(unittest.TestCase):
    def certificate(self, root: Path) -> tuple[Path, Path]:
        certificate = root / "certificate.pem"
        private_key = root / "private-key.pem"
        completed = subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "1", "-subj", "/CN=allowed.test", "-addext",
                "subjectAltName=DNS:allowed.test", "-keyout", str(private_key),
                "-out", str(certificate),
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        return certificate, private_key

    def start_http(self, root: Path, script: str) -> tuple[threading.Thread, list[BaseException], int, Path]:
        certificate, private_key = self.certificate(root)
        ready = root / "ready.json"
        contact = root / "contact.json"
        observation = root / "fixture.json"
        errors: list[BaseException] = []

        def target() -> None:
            try:
                serve_tls_fixture("127.0.0.1", 0, script, certificate, private_key, ready, contact, observation)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=target)
        thread.start()
        for _ in range(100):
            if ready.is_file() or errors:
                break
            time.sleep(0.01)
        self.assertTrue(ready.is_file(), errors)
        return thread, errors, json.loads(ready.read_bytes())["port"], certificate

    def test_exact_action_reaches_only_the_declared_response(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            thread, errors, port, certificate = self.start_http(root, "exact")
            self.assertEqual(execute("exact", "127.0.0.1", port, certificate), ["declared-response"])
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])

    def test_redirect_provenance_precedes_followup_denial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            thread, errors, port, certificate = self.start_http(root, "redirect-host")
            with mock.patch(
                "experiments.network_authority.resolution_network_client.raw_contact",
                return_value="routing-denied",
            ) as contact:
                events = execute("redirect-host", "127.0.0.1", port, certificate)
            thread.join(timeout=2)
            self.assertEqual(errors, [])
            self.assertEqual(events, ["redirect-host", "routing-denied"])
            contact.assert_called_once_with("127.0.0.2", 443)

    def test_socket_and_connect_denials_remain_distinct(self) -> None:
        denied_socket = OSError(errno.EPERM, "denied")
        with mock.patch("socket.socket", side_effect=denied_socket):
            self.assertEqual(raw_contact("127.0.0.1", 443), "child-boundary-denied")
        fake = mock.MagicMock()
        fake.__enter__.return_value = fake
        fake.connect.side_effect = OSError(errno.EACCES, "denied")
        with mock.patch("socket.socket", return_value=fake):
            self.assertEqual(raw_contact("127.0.0.2", 443), "routing-denied")

    def test_channel_redirect_uses_inherited_stream_then_attempts_followup(self) -> None:
        fixture, child = socket.socketpair()
        request, response, _event = __import__(
            "experiments.network_authority.decision_http_fixture",
            fromlist=["script_exchange"],
        ).script_exchange("redirect-port")
        errors: list[BaseException] = []

        def server() -> None:
            try:
                received = bytearray()
                while len(received) < len(request):
                    received.extend(fixture.recv(len(request) - len(received)))
                self.assertEqual(bytes(received), request)
                self.assertEqual(fixture.recv(1), b"")
                fixture.sendall(response)
                fixture.shutdown(socket.SHUT_WR)
            except BaseException as error:
                errors.append(error)
            finally:
                fixture.close()

        thread = threading.Thread(target=server)
        thread.start()
        with mock.patch(
            "experiments.network_authority.resolution_network_client.raw_contact",
            return_value="child-boundary-denied",
        ):
            events = execute("channel-redirect-port", "127.0.0.1", 443, Path("/absent"), child.fileno())
        child.close()
        thread.join(timeout=2)
        self.assertEqual(errors, [])
        self.assertEqual(events, ["redirect-port", "child-boundary-denied"])

    def test_unknown_action_and_ambient_descriptor_fail_closed(self) -> None:
        with self.assertRaises(ResolutionNetworkClientError):
            execute("unknown", "127.0.0.1", 443, Path("/absent"))
        descriptor = os.dup(1)
        try:
            with self.assertRaises(ResolutionNetworkClientError):
                execute("exact", "127.0.0.1", 443, Path("/absent"), descriptor)
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
