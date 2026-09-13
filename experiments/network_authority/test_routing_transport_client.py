"""Falsifiers for the experiment 0001F direct-network case client."""

from __future__ import annotations

import argparse
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from experiments.network_authority.decision_http_fixture import serve_tls_fixture
from experiments.network_authority.decision_socket_fixture import (
    SocketFixtureConfig,
    serve_socket_fixture,
)
from experiments.network_authority.routing_transport_client import (
    EXECUTABLE_CASES,
    RoutingClientError,
    run,
)


class RoutingTransportClientTests(unittest.TestCase):
    def certificate(self, root: Path, name: str, stem: str) -> tuple[Path, Path]:
        certificate = root / f"{stem}-certificate.pem"
        private_key = root / f"{stem}-private-key.pem"
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

    def arguments(
        self,
        case: str,
        ca: Path,
        *,
        service_port: int,
        other_port: int = 8443,
    ) -> argparse.Namespace:
        return argparse.Namespace(
            case=case,
            allowed_ipv4="127.0.0.1",
            allowed_ipv6="::1",
            denied_ipv4="127.0.0.2",
            denied_ipv6="::2",
            service_port=service_port,
            other_port=other_port,
            allowed_ca=ca,
        )

    def start(self, target: object, ready: Path) -> tuple[threading.Thread, list[BaseException]]:
        errors: list[BaseException] = []

        def invoke() -> None:
            try:
                target()  # type: ignore[operator]
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=invoke)
        thread.start()
        for _ in range(100):
            if ready.is_file() or errors:
                break
            time.sleep(0.01)
        self.assertTrue(ready.is_file(), errors)
        return thread, errors

    def test_case_catalog_excludes_only_trusted_plan_rejections(self) -> None:
        self.assertEqual(len(EXECUTABLE_CASES), 14)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ca, _key = self.certificate(root, "allowed.test", "allowed")
            arguments = self.arguments("non-scoped-ipv6-scope-id", ca, service_port=443)
            with self.assertRaises(RoutingClientError):
                run(arguments)

    def test_command_marks_start_before_runtime_validation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            started = root / "started.txt"
            observation = root / "observation.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "experiments.network_authority.routing_transport_client",
                    "--case",
                    "exact-service-ipv4",
                    "--allowed-ipv4",
                    "127.0.0.1",
                    "--allowed-ipv6",
                    "::1",
                    "--denied-ipv4",
                    "127.0.0.2",
                    "--denied-ipv6",
                    "::2",
                    "--service-port",
                    "443",
                    "--other-port",
                    "8443",
                    "--allowed-ca",
                    str(root / "absent-ca.pem"),
                    "--started-file",
                    str(started),
                    "--observation",
                    str(observation),
                ],
                cwd=Path(__file__).resolve().parents[2],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 7)
            self.assertEqual(started.read_bytes(), b"started\n")
            self.assertFalse(observation.exists())

    def test_exact_tls_request_records_only_exact_response(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate, private_key = self.certificate(
                root, "allowed.test", "allowed"
            )
            ready = root / "ready.json"
            contact = root / "contact.json"
            fixture_observation = root / "fixture.json"
            thread, errors = self.start(
                lambda: serve_tls_fixture(
                    "127.0.0.1",
                    0,
                    "exact",
                    certificate,
                    private_key,
                    ready,
                    contact,
                    fixture_observation,
                ),
                ready,
            )
            import json

            port = json.loads(ready.read_bytes())["port"]
            observation = run(
                self.arguments("exact-service-ipv4", certificate, service_port=port)
            )
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(observation["event"], "exact-response")
            self.assertEqual(observation["tls_version"], "TLSv1.3")
            self.assertTrue(fixture_observation.is_file())

    def test_raw_route_and_wrong_certificate_have_distinct_phases(self) -> None:
        for case, server_name, expected_event, expected_phase in (
            ("literal-allowed-address", "allowed.test", "routing-connected", "connect"),
            (
                "allowed-endpoint-wrong-certificate",
                "denied.test",
                "certificate-rejected",
                "tls",
            ),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                allowed, _allowed_key = self.certificate(
                    root, "allowed.test", "allowed"
                )
                served, served_key = self.certificate(root, server_name, "served")
                ready = root / "ready.json"
                contact = root / "contact.json"
                fixture_observation = root / "fixture.json"
                thread, errors = self.start(
                    lambda: serve_tls_fixture(
                        "127.0.0.1",
                        0,
                        "exact",
                        served,
                        served_key,
                        ready,
                        contact,
                        fixture_observation,
                    ),
                    ready,
                )
                import json

                port = json.loads(ready.read_bytes())["port"]
                observation = run(self.arguments(case, allowed, service_port=port))
                thread.join(timeout=3)
                self.assertFalse(thread.is_alive())
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], ssl.SSLError)
                self.assertEqual(observation["event"], expected_event)
                self.assertEqual(observation["phase"], expected_phase)
                if case == "allowed-endpoint-wrong-certificate":
                    self.assertEqual(observation["event"], "certificate-rejected")
                    self.assertGreater(observation["verify_code"], 0)
                self.assertTrue(contact.is_file())
                self.assertFalse(fixture_observation.exists())

    def test_tcp_dns_and_quic_sentinels_are_exact(self) -> None:
        cases = {
            "direct-tcp-other-port": "tcp-connect",
            "direct-udp-dns-shaped": "udp-dns",
            "direct-udp-quic-shaped": "udp-quic",
        }
        for case, script in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                ca, _key = self.certificate(root, "allowed.test", "allowed")
                ready = root / "ready.json"
                fixture_observation = root / "fixture.json"
                config = SocketFixtureConfig(
                    script=script,
                    bind_ip="127.0.0.1",
                    port=0,
                    unix_path=None,
                    ready_file=ready,
                    observation_file=fixture_observation,
                )
                thread, errors = self.start(lambda: serve_socket_fixture(config), ready)
                import json

                port = json.loads(ready.read_bytes())["port"]
                observation = run(
                    self.arguments(case, ca, service_port=443, other_port=port)
                )
                thread.join(timeout=3)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertIn(
                    observation["event"], {"socket-sentinel", "datagram-sentinel"}
                )
                self.assertTrue(fixture_observation.is_file())

    def test_unconfined_bind_actions_are_observed_not_relabelled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ca, _key = self.certificate(root, "allowed.test", "allowed")
            for case in ("tcp-bind-listen", "udp-bind"):
                with self.subTest(case=case):
                    observation = run(
                        self.arguments(case, ca, service_port=443)
                    )
                    self.assertEqual(observation["event"], "bind-succeeded")
                    self.assertIsNone(observation["errno"])


if __name__ == "__main__":
    unittest.main()
