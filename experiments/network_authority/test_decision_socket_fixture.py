"""Falsifiers for the decision matrix socket-bypass fixture."""

from __future__ import annotations

import json
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from experiments.network_authority.decision_socket_fixture import (
    ABSTRACT_NAME,
    PROBE,
    SENTINEL,
    SCRIPTS,
    SocketFixtureConfig,
    SocketFixtureError,
    observation_document,
    serve_socket_fixture,
    validate_config,
)


class DecisionSocketFixtureTests(unittest.TestCase):
    def config(
        self,
        root: Path,
        script: str,
        *,
        bind_ip: str | None = None,
        port: int | None = None,
        unix_path: Path | None = None,
    ) -> SocketFixtureConfig:
        return SocketFixtureConfig(
            script=script,
            bind_ip=bind_ip,
            port=port,
            unix_path=unix_path,
            ready_file=root / "ready.json",
            observation_file=root / "observation.json",
        )

    def test_configuration_domain_is_closed_and_loopback_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for script in {"tcp-connect", "udp-send"}:
                address = validate_config(
                    self.config(root, script, bind_ip="127.0.0.1", port=0)
                )
                self.assertIsNotNone(address)
            self.assertIsNone(
                validate_config(
                    self.config(root, "pathname-unix", unix_path=root / "target.sock")
                )
            )
            with self.assertRaises(SocketFixtureError):
                validate_config(self.config(root, "unknown"))
            with self.assertRaises(SocketFixtureError):
                validate_config(
                    self.config(root, "tcp-connect", bind_ip="192.0.2.1", port=443)
                )
            with self.assertRaises(SocketFixtureError):
                validate_config(
                    self.config(
                        root,
                        "udp-send",
                        bind_ip="127.0.0.1",
                        port=0,
                        unix_path=root / "mixed.sock",
                    )
                )

    def test_observation_is_canonical_and_script_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self.config(
                Path(temporary), "tcp-connect", bind_ip="127.0.0.1", port=0
            )
            document = observation_document(config, "ipv4")
        self.assertTrue(document.endswith(b"\n"))
        parsed = json.loads(document)
        self.assertEqual(parsed["script"], "tcp-connect")
        self.assertEqual(len(parsed["probe_sha256"]), 64)
        self.assertEqual(len(parsed["response_sha256"]), 64)

    def run_target(self, config: SocketFixtureConfig) -> tuple[threading.Thread, list[BaseException]]:
        errors: list[BaseException] = []

        def target() -> None:
            try:
                serve_socket_fixture(config)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=target)
        thread.start()
        for _ in range(100):
            if config.ready_file.is_file() or errors:
                break
            time.sleep(0.01)
        self.assertTrue(config.ready_file.is_file(), errors)
        return thread, errors

    def finish_target(
        self,
        config: SocketFixtureConfig,
        thread: threading.Thread,
        errors: list[BaseException],
    ) -> dict[str, object]:
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        return json.loads(config.observation_file.read_bytes())

    def test_live_tcp_and_udp_targets_require_exact_probe(self) -> None:
        for script, socket_type in {
            "tcp-connect": socket.SOCK_STREAM,
            "udp-send": socket.SOCK_DGRAM,
        }.items():
            with self.subTest(script=script), tempfile.TemporaryDirectory() as temporary:
                config = self.config(
                    Path(temporary), script, bind_ip="127.0.0.1", port=0
                )
                thread, errors = self.run_target(config)
                ready = json.loads(config.ready_file.read_bytes())
                with socket.socket(socket.AF_INET, socket_type) as client:
                    client.settimeout(2)
                    client.connect((ready["address"], ready["port"]))
                    client.sendall(PROBE)
                    if socket_type == socket.SOCK_STREAM:
                        client.shutdown(socket.SHUT_WR)
                    self.assertEqual(client.recv(len(SENTINEL)), SENTINEL)
                observation = self.finish_target(config, thread, errors)
                self.assertEqual(observation["script"], script)
                self.assertEqual(observation["family"], "ipv4")

    def test_live_pathname_target_is_removed_after_exchange(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target_path = root / "target.sock"
            config = self.config(
                root, "pathname-unix", unix_path=target_path
            )
            thread, errors = self.run_target(config)
            ready = json.loads(config.ready_file.read_bytes())
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect(ready["address"])
                client.sendall(PROBE)
                client.shutdown(socket.SHUT_WR)
                self.assertEqual(client.recv(len(SENTINEL)), SENTINEL)
            observation = self.finish_target(config, thread, errors)
            self.assertEqual(observation["family"], "unix-pathname")
            self.assertFalse(target_path.exists())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux abstract namespace")
    def test_live_abstract_target_has_no_pathname(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self.config(Path(temporary), "abstract-unix")
            thread, errors = self.run_target(config)
            ready = json.loads(config.ready_file.read_bytes())
            self.assertEqual(ready["address"], "@" + ABSTRACT_NAME.decode("ascii"))
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect(b"\x00" + ABSTRACT_NAME)
                client.sendall(PROBE)
                client.shutdown(socket.SHUT_WR)
                self.assertEqual(client.recv(len(SENTINEL)), SENTINEL)
            observation = self.finish_target(config, thread, errors)
            self.assertEqual(observation["family"], "unix-abstract")

    def test_malformed_datagram_cannot_publish_an_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self.config(
                Path(temporary), "udp-send", bind_ip="127.0.0.1", port=0
            )
            thread, errors = self.run_target(config)
            ready = json.loads(config.ready_file.read_bytes())
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(2)
                client.sendto(b"wrong-probe", (ready["address"], ready["port"]))
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], SocketFixtureError)
            self.assertFalse(config.observation_file.exists())


if __name__ == "__main__":
    unittest.main()
