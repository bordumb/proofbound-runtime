"""Falsifiers for the decision matrix TLS and redirect fixture."""

from __future__ import annotations

import json
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from experiments.network_authority.decision_http_fixture import (
    SCRIPTS,
    HttpFixtureError,
    script_exchange,
    serve_tls_fixture,
    validate_response,
)


class DecisionHttpFixtureTests(unittest.TestCase):
    def test_every_script_has_one_exact_self_consistent_exchange(self) -> None:
        events = set()
        responses = set()
        for script in SCRIPTS:
            request, response, event = script_exchange(script)
            self.assertTrue(request.endswith(b"\r\n\r\n"))
            validate_response(response)
            events.add(event)
            responses.add(response)
        self.assertEqual(len(events), len(SCRIPTS))
        self.assertEqual(len(responses), len(SCRIPTS))
        with self.assertRaises(HttpFixtureError):
            script_exchange("unknown")

    def test_response_length_and_connection_are_closed(self) -> None:
        _, response, _ = script_exchange("exact")
        with self.assertRaises(HttpFixtureError):
            validate_response(response.replace(b"Content-Length: 32", b"Content-Length: 31"))
        with self.assertRaises(HttpFixtureError):
            validate_response(response.replace(b"Connection: close", b"Connection: keep-alive"))

    def certificate(self, root: Path) -> tuple[Path, Path]:
        certificate = root / "certificate.pem"
        private_key = root / "private-key.pem"
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
                "/CN=allowed.test",
                "-addext",
                "subjectAltName=DNS:allowed.test",
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

    def live_exchange(self, root: Path, bind_ip: str, script: str) -> dict[str, object]:
        certificate, private_key = self.certificate(root)
        ready = root / "ready.json"
        contact = root / "contact.json"
        observation = root / "observation.json"
        errors: list[BaseException] = []

        def target() -> None:
            try:
                serve_tls_fixture(
                    bind_ip,
                    0,
                    script,
                    certificate,
                    private_key,
                    ready,
                    contact,
                    observation,
                )
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=target)
        thread.start()
        for _ in range(100):
            if ready.is_file() or errors:
                break
            time.sleep(0.01)
        self.assertTrue(ready.is_file(), errors)
        endpoint = json.loads(ready.read_bytes())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(certificate))
        request, expected_response, _ = script_exchange(script)
        family = socket.AF_INET if endpoint["family"] == "ipv4" else socket.AF_INET6
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect((endpoint["address"], endpoint["port"]))
            with context.wrap_socket(
                connection,
                server_hostname="allowed.test",
                suppress_ragged_eofs=False,
            ) as protected:
                protected.settimeout(2)
                protected.sendall(request)
                response = bytearray()
                while True:
                    chunk = protected.recv(1024)
                    if not chunk:
                        break
                    response.extend(chunk)
                raw_socket = protected.unwrap()
                raw_socket.close()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(bytes(response), expected_response)
        contact_observation = json.loads(contact.read_bytes())
        self.assertEqual(contact_observation["event"], "tcp-accepted")
        self.assertEqual(contact_observation["family"], endpoint["family"])
        return json.loads(observation.read_bytes())

    def test_live_ipv4_exact_exchange_records_tls_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            observation = self.live_exchange(Path(temporary), "127.0.0.1", "exact")
        self.assertEqual(observation["event"], "exact-response")
        self.assertEqual(observation["sni"], "allowed.test")
        self.assertEqual(observation["tls_version"], "TLSv1.3")

    def test_live_ipv6_redirect_exchange_records_family_independently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            observation = self.live_exchange(Path(temporary), "::1", "redirect-host")
        self.assertEqual(observation["event"], "redirect-host")
        self.assertEqual(observation["sni"], "allowed.test")

    def test_failed_tls_still_records_routing_contact_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate, private_key = self.certificate(root)
            ready = root / "ready.json"
            contact = root / "contact.json"
            observation = root / "observation.json"
            errors: list[BaseException] = []

            def target() -> None:
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

            thread = threading.Thread(target=target)
            thread.start()
            for _ in range(100):
                if ready.is_file() or errors:
                    break
                time.sleep(0.01)
            endpoint = json.loads(ready.read_bytes())
            with socket.create_connection(
                (endpoint["address"], endpoint["port"]), timeout=2
            ) as connection:
                connection.sendall(b"not-tls\n")
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ssl.SSLError)
            self.assertEqual(json.loads(contact.read_bytes())["event"], "tcp-accepted")
            self.assertFalse(observation.exists())


if __name__ == "__main__":
    unittest.main()
