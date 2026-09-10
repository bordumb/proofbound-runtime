"""Falsifiers for the preconnected channel's child client."""

from __future__ import annotations

import socket
import threading
import unittest

from experiments.network_authority.preconnected_case_client import (
    exchange,
    request_case_result,
)
from experiments.network_authority.preconnected_channel import (
    ALLOWED_REQUEST,
    ALLOWED_RESPONSE,
    MAX_DIRECTION_BYTES,
)


class PreconnectedCaseClientTests(unittest.TestCase):
    def test_exchange_is_exact_and_half_closes(self) -> None:
        server, child = socket.socketpair()
        received = bytearray()

        def serve() -> None:
            while True:
                chunk = server.recv(1024)
                if not chunk:
                    break
                received.extend(chunk)
            server.sendall(ALLOWED_RESPONSE)
            server.shutdown(socket.SHUT_WR)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            self.assertEqual(exchange(child.fileno(), ALLOWED_REQUEST), ALLOWED_RESPONSE)
        finally:
            thread.join(timeout=2)
            server.close()
            child.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(bytes(received), ALLOWED_REQUEST)

    def test_response_identity_is_required(self) -> None:
        server, child = socket.socketpair()

        def serve() -> None:
            while server.recv(1024):
                pass
            server.sendall(b"wrong")
            server.shutdown(socket.SHUT_WR)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            self.assertEqual(
                request_case_result(child.fileno(), ALLOWED_REQUEST, ALLOWED_RESPONSE),
                7,
            )
        finally:
            thread.join(timeout=2)
            server.close()
            child.close()

    def test_oversized_response_is_rejected(self) -> None:
        server, child = socket.socketpair()

        def serve() -> None:
            while server.recv(1024):
                pass
            server.sendall(b"x" * (MAX_DIRECTION_BYTES + 1))
            server.shutdown(socket.SHUT_WR)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            self.assertEqual(
                request_case_result(child.fileno(), ALLOWED_REQUEST, ALLOWED_RESPONSE),
                7,
            )
        finally:
            thread.join(timeout=2)
            server.close()
            child.close()


if __name__ == "__main__":
    unittest.main()
