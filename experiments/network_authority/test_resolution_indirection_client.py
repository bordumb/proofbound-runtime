"""Falsifiers for the closed resolution and indirection client primitives."""

from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from experiments.network_authority.decision_http_fixture import serve_tls_fixture
from experiments.network_authority.decision_proxy_fixture import serve_proxy_fixture
from experiments.network_authority.resolution_indirection_client import (
    IndirectionClientError,
    http_exchange,
    proxy_exchange,
    resolve_once,
)
from experiments.network_authority.scripted_dns import TYPE_A, serve_dns


class ResolutionIndirectionClientTests(unittest.TestCase):
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

    def dns(self, root: Path, script: str, queries: int) -> tuple[threading.Thread, list[BaseException], int]:
        ready = root / "dns-ready.json"
        transcript = root / "dns-transcript.json"
        thread, errors = self.start(
            lambda: serve_dns("127.0.0.1", 0, script, queries, ready, transcript),
            ready,
        )
        return thread, errors, json.loads(ready.read_bytes())["port"]

    def test_generic_resolver_observes_declared_and_undeclared_terminals(self) -> None:
        for script, expected_name, expected_address in (
            ("stable", "allowed.test", "127.0.0.1"),
            ("cname-denied", "denied.test", "127.0.0.2"),
        ):
            with self.subTest(script=script), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                thread, errors, port = self.dns(root, script, 1)
                observation = resolve_once(
                    "127.0.0.1", port,
                    "allowed.test" if script == "stable" else "alias.test",
                    TYPE_A, 101, allow_cname=script != "stable",
                    require_declared=False, allow_tcp_fallback=False,
                )
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(observation["terminal_name"], expected_name)
                self.assertEqual(observation["address"], expected_address)

    def test_policy_resolver_rejects_undeclared_loop_depth_dnssec_and_malformed(self) -> None:
        for ordinal, script in enumerate(("cname-denied", "cname-loop", "cname-depth", "dnssec-confusion", "malformed")):
            with self.subTest(script=script), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                thread, errors, port = self.dns(root, script, 1)
                observation = resolve_once(
                    "127.0.0.1", port,
                    "alias.test" if script.startswith("cname-") else "allowed.test",
                    TYPE_A, 111 + ordinal, allow_cname=script.startswith("cname-"),
                    require_declared=True, allow_tcp_fallback=False,
                )
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(observation["event"], "resolver-rejected")

    def test_truncated_udp_uses_one_exact_tcp_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            thread, errors, port = self.dns(root, "truncated-fallback", 2)
            observation = resolve_once(
                "127.0.0.1", port, "allowed.test", TYPE_A, 121,
                allow_cname=False, require_declared=True, allow_tcp_fallback=True,
            )
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(observation["event"], "resolved")
            self.assertEqual([item["transport"] for item in observation["responses"]], ["udp", "tcp"])

    def test_timeout_is_a_closed_resolver_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            thread, errors, port = self.dns(root, "timeout", 1)
            observation = resolve_once(
                "127.0.0.1", port, "allowed.test", TYPE_A, 131,
                allow_cname=False, require_declared=True, allow_tcp_fallback=False,
                timeout_seconds=0.1,
            )
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(observation["reason"], "timeout")
            self.assertEqual(observation["responses"], [])

    def test_exact_redirect_and_both_proxy_transcripts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate, private_key = self.certificate(root)
            ready = root / "http-ready.json"
            contact = root / "http-contact.json"
            fixture_observation = root / "http-observation.json"
            thread, errors = self.start(
                lambda: serve_tls_fixture(
                    "127.0.0.1", 0, "redirect-host", certificate, private_key,
                    ready, contact, fixture_observation,
                ),
                ready,
            )
            observed = http_exchange(
                "127.0.0.1", json.loads(ready.read_bytes())["port"],
                certificate, "redirect-host",
            )
            thread.join(timeout=2)
            self.assertEqual(errors, [])
            self.assertEqual(observed["location"], "https://denied.test/v1/echo")

        for protocol in ("http-connect", "socks5"):
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                certificate, private_key = self.certificate(root)
                ready = root / "proxy-ready.json"
                contact = root / "proxy-contact.json"
                fixture_observation = root / "proxy-observation.json"
                thread, errors = self.start(
                    lambda: serve_proxy_fixture(
                        "127.0.0.1", 0, protocol, certificate, private_key,
                        ready, contact, fixture_observation,
                    ),
                    ready,
                )
                observed = proxy_exchange(
                    "127.0.0.1", json.loads(ready.read_bytes())["port"],
                    certificate, protocol,
                )
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(observed["event"], "proxy-target-reached")

    def test_open_inputs_fail_before_contact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate, _private_key = self.certificate(root)
            with self.assertRaises(IndirectionClientError):
                proxy_exchange("127.0.0.1", 443, certificate, "open-proxy")
            with self.assertRaises(IndirectionClientError):
                resolve_once(
                    "127.0.0.2", 53, "allowed.test", TYPE_A, 1,
                    allow_cname=False, require_declared=True,
                    allow_tcp_fallback=False,
                )


if __name__ == "__main__":
    unittest.main()
