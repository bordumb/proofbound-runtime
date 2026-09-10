"""Falsifiers for the interactive decision proxy fixture."""

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

from experiments.network_authority.decision_proxy_fixture import (
    DENIED_SENTINEL,
    HTTP_CONNECT_REQUEST,
    HTTP_CONNECT_RESPONSE,
    PROBE,
    SOCKS_CONNECT_REQUEST,
    SOCKS_CONNECT_RESPONSE,
    SOCKS_GREETING,
    SOCKS_METHOD,
    ProxyFixtureError,
    read_exact,
    serve_http_connect,
    serve_proxy_fixture,
    serve_socks5,
)


class DecisionProxyFixtureTests(unittest.TestCase):
    def test_protocol_servers_reject_substitution(self) -> None:
        for server, request in (
            (serve_http_connect, HTTP_CONNECT_REQUEST),
            (serve_socks5, SOCKS_GREETING),
        ):
            fixture, client = socket.socketpair()
            errors: list[BaseException] = []

            def target() -> None:
                try:
                    server(fixture)  # type: ignore[arg-type]
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=target)
            thread.start()
            client.sendall(request[:-1] + bytes([request[-1] ^ 1]))
            client.close()
            thread.join(timeout=2)
            fixture.close()
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ProxyFixtureError)

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

    def live_exchange(self, root: Path, script: str) -> dict[str, object]:
        certificate, private_key = self.certificate(root)
        ready = root / "ready.json"
        observation = root / "observation.json"
        errors: list[BaseException] = []

        def target() -> None:
            try:
                serve_proxy_fixture(
                    "127.0.0.1",
                    0,
                    script,
                    certificate,
                    private_key,
                    ready,
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
        with socket.create_connection(
            (endpoint["address"], endpoint["port"]), timeout=2
        ) as connection:
            with context.wrap_socket(
                connection,
                server_hostname="allowed.test",
                suppress_ragged_eofs=False,
            ) as protected:
                protected.settimeout(2)
                if script == "http-connect":
                    protected.sendall(HTTP_CONNECT_REQUEST)
                    self.assertEqual(
                        read_exact(protected, len(HTTP_CONNECT_RESPONSE)),
                        HTTP_CONNECT_RESPONSE,
                    )
                else:
                    protected.sendall(SOCKS_GREETING)
                    self.assertEqual(read_exact(protected, len(SOCKS_METHOD)), SOCKS_METHOD)
                    protected.sendall(SOCKS_CONNECT_REQUEST)
                    self.assertEqual(
                        read_exact(protected, len(SOCKS_CONNECT_RESPONSE)),
                        SOCKS_CONNECT_RESPONSE,
                    )
                protected.sendall(PROBE)
                self.assertEqual(
                    read_exact(protected, len(DENIED_SENTINEL)), DENIED_SENTINEL
                )
                protected.sendall(b"\x00")
                raw_socket = protected.unwrap()
                raw_socket.close()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        return json.loads(observation.read_bytes())

    def test_live_http_connect_reaches_denied_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            observation = self.live_exchange(Path(temporary), "http-connect")
        self.assertEqual(observation["protocol"], "http-connect")
        self.assertEqual(observation["target"], "denied.test:443")

    def test_live_socks5_reaches_denied_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            observation = self.live_exchange(Path(temporary), "socks5")
        self.assertEqual(observation["protocol"], "socks5")
        self.assertEqual(observation["target"], "denied.test:443")


if __name__ == "__main__":
    unittest.main()
