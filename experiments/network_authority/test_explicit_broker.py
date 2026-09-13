#!/usr/bin/env python3
"""Falsifiers for the explicit broker framing and request boundary."""

from __future__ import annotations

import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from experiments.network_authority.explicit_broker import (
    MAX_FRAME_BYTES,
    ProtocolError,
    decode_request,
    read_frame,
    serve_broker,
    wire_json,
)


class ProtocolTests(unittest.TestCase):
    def test_direct_entrypoint_resolves_repository_package(self) -> None:
        entrypoint = Path(__file__).with_name("explicit_broker.py").resolve()
        with tempfile.TemporaryDirectory() as temporary:
            completed = subprocess.run(
                [sys.executable, str(entrypoint), "--help"],
                cwd=temporary,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_exact_request_is_accepted(self) -> None:
        request = wire_json({"operation": "echo", "payload": "bounded payload"})
        self.assertEqual(decode_request(request), "bounded payload")

    def test_request_shape_and_canonical_form_fail_closed(self) -> None:
        invalid = (
            b"",
            b"not-json",
            b'{"operation":"echo","payload":"x","target":"denied.test"}',
            b'{"operation":"echo","operation":"echo","payload":"x"}',
            b'{"operation": "echo", "payload": "x"}',
            b'{"operation":"other","payload":"x"}',
            b'{"operation":"echo","payload":""}',
            wire_json({"operation": "echo", "payload": "x" * 1025}),
            b"\xff",
        )
        for request in invalid:
            with self.subTest(request=request[:80]):
                with self.assertRaises(ProtocolError):
                    decode_request(request)

    def test_frame_length_truncation_and_trailing_bytes_fail_closed(self) -> None:
        payloads = (
            struct.pack(">I", 0),
            struct.pack(">I", MAX_FRAME_BYTES + 1),
            struct.pack(">I", 2) + b"x",
            struct.pack(">I", 1) + b"xy",
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                reader, writer = socket.socketpair()
                with reader, writer:
                    writer.sendall(payload)
                    writer.shutdown(socket.SHUT_WR)
                    with self.assertRaises(ProtocolError):
                        read_frame(reader)

    def test_target_substitution_is_rejected_before_fetch(self) -> None:
        broker_channel, client_channel = socket.socketpair()
        fetch_calls: list[object] = []

        def forbidden_fetch(*arguments: object) -> None:
            fetch_calls.append(arguments)

        with tempfile.TemporaryDirectory() as temporary:
            thread_result: list[int] = []

            def run() -> None:
                thread_result.append(
                    serve_broker(
                        broker_channel.detach(),
                        "127.0.0.1",
                        443,
                        "allowed.test",
                        Path(temporary) / "ca.pem",
                        forbidden_fetch,
                    )
                )

            thread = threading.Thread(target=run)
            thread.start()
            with client_channel:
                request = b'{"operation":"echo","payload":"x","target":"denied.test"}'
                client_channel.sendall(struct.pack(">I", len(request)) + request)
                client_channel.shutdown(socket.SHUT_WR)
                header = client_channel.recv(4)
                self.assertEqual(len(header), 4)
                size = struct.unpack(">I", header)[0]
                response = client_channel.recv(size)
                self.assertEqual(
                    response,
                    wire_json({"code": "request-failed", "status": "error"}),
                )
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(thread_result, [7])
            self.assertEqual(fetch_calls, [])

    def test_exact_request_fetches_fixed_service_and_returns_payload(self) -> None:
        broker_channel, client_channel = socket.socketpair()
        fetch_calls: list[object] = []

        def observed_fetch(*arguments: object) -> None:
            fetch_calls.append(arguments)

        with tempfile.TemporaryDirectory() as temporary:
            ca_path = Path(temporary) / "ca.pem"
            thread_result: list[int] = []

            def run() -> None:
                thread_result.append(
                    serve_broker(
                        broker_channel.detach(),
                        "127.0.0.1",
                        443,
                        "allowed.test",
                        ca_path,
                        observed_fetch,
                    )
                )

            thread = threading.Thread(target=run)
            thread.start()
            with client_channel:
                request = wire_json({"operation": "echo", "payload": "exact"})
                client_channel.sendall(struct.pack(">I", len(request)) + request)
                client_channel.shutdown(socket.SHUT_WR)
                size = struct.unpack(">I", client_channel.recv(4))[0]
                response = client_channel.recv(size)
                self.assertEqual(
                    response,
                    wire_json({"payload": "exact", "status": "ok"}),
                )
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(thread_result, [0])
            self.assertEqual(
                fetch_calls,
                [("127.0.0.1", 443, "allowed.test", ca_path)],
            )


if __name__ == "__main__":
    unittest.main()
