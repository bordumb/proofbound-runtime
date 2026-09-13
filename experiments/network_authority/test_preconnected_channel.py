"""Falsifiers for the transparent preconnected channel."""

from __future__ import annotations

import socket
import unittest

from experiments.network_authority.preconnected_channel import (
    ALLOWED_REQUEST,
    ALLOWED_RESPONSE,
    CONNECT_REQUEST,
    CONNECT_RESPONSE,
    MAX_DIRECTION_BYTES,
    UNDECLARED_PATH_REQUEST,
    UNDECLARED_PATH_RESPONSE,
    ConnectorError,
    read_bounded,
    relay_session,
    request_result,
    validate_fixed_response,
)


class FakeProtected:
    """Small exact TLS-session stand-in for relay boundary tests."""

    def __init__(self, response: bytes) -> None:
        self.response = response
        self.sent = b""
        self.unwrapped = False
        self.raw_parent, self.raw_child = socket.socketpair()

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, size: int) -> bytes:
        result = self.response[:size]
        self.response = self.response[size:]
        return result

    def unwrap(self) -> socket.socket:
        self.unwrapped = True
        self.raw_child.close()
        return self.raw_parent


class PreconnectedChannelTests(unittest.TestCase):
    def test_fixture_corpus_is_exact(self) -> None:
        self.assertEqual(request_result(ALLOWED_REQUEST), ("allowed-request", ALLOWED_RESPONSE))
        self.assertEqual(
            request_result(UNDECLARED_PATH_REQUEST),
            ("undeclared-path-observed", UNDECLARED_PATH_RESPONSE),
        )
        self.assertEqual(
            request_result(CONNECT_REQUEST),
            ("connect-shape-observed", CONNECT_RESPONSE),
        )
        with self.assertRaises(ConnectorError):
            request_result(ALLOWED_REQUEST + b"x")

    def test_fixed_responses_bind_their_body_lengths(self) -> None:
        for response in (ALLOWED_RESPONSE, UNDECLARED_PATH_RESPONSE, CONNECT_RESPONSE):
            validate_fixed_response(response)
        with self.assertRaises(ConnectorError):
            validate_fixed_response(CONNECT_RESPONSE.replace(b"Length: 22", b"Length: 23"))

    def test_read_bounded_rejects_empty_and_oversized_streams(self) -> None:
        class Reader:
            def __init__(self, chunks: list[bytes]) -> None:
                self.chunks = chunks

            def recv(self, _size: int) -> bytes:
                return self.chunks.pop(0)

        with self.assertRaises(ConnectorError):
            read_bounded(Reader([b""]))
        with self.assertRaises(ConnectorError):
            read_bounded(Reader([b"x" * (MAX_DIRECTION_BYTES + 1)]))

    def test_relay_is_transparent_and_observes_shutdown(self) -> None:
        connector, child = socket.socketpair()
        protected = FakeProtected(ALLOWED_RESPONSE)
        try:
            child.sendall(ALLOWED_REQUEST)
            child.shutdown(socket.SHUT_WR)
            observation = relay_session(connector, protected)  # type: ignore[arg-type]
            received = bytearray()
            while True:
                chunk = child.recv(1024)
                if not chunk:
                    break
                received.extend(chunk)
            self.assertEqual(bytes(received), ALLOWED_RESPONSE)
            self.assertEqual(protected.sent, ALLOWED_REQUEST)
            self.assertTrue(protected.unwrapped)
            self.assertEqual(
                observation,
                {
                    "child_to_service_bytes": len(ALLOWED_REQUEST),
                    "service_to_child_bytes": len(ALLOWED_RESPONSE),
                    "tls_shutdown_observed": True,
                },
            )
        finally:
            connector.close()
            child.close()
            protected.raw_parent.close()
            protected.raw_child.close()


if __name__ == "__main__":
    unittest.main()
