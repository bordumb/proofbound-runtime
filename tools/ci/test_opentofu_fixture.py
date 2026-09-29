"""Closed DNS behavior for the local OpenTofu egress fixture."""

import struct
import socket
import threading
import unittest

from tools.ci.opentofu_fixture import DnsTcpServer, dns_answer, dns_tcp_handler


def question(name: str, kind: int) -> bytes:
    wire_name = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"
    return b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0" + wire_name + struct.pack("!HH", kind, 1)


class OpenTofuFixtureTests(unittest.TestCase):
    def test_only_the_declared_name_receives_a_local_answer(self) -> None:
        response, kind = dns_answer(question("api.fixture.test", 1), "api.fixture.test", bytes([10, 20, 30, 40]))
        self.assertEqual(kind, "A")
        self.assertEqual(response[:2], b"\x12\x34")
        self.assertEqual(response[6:8], b"\0\x01")
        self.assertTrue(response.endswith(bytes([10, 20, 30, 40])))

        response, kind = dns_answer(question("api.fixture.test", 28), "api.fixture.test", bytes([10, 20, 30, 40]))
        self.assertEqual(kind, "AAAA")
        self.assertEqual(response[6:8], b"\0\0")

        for name in ("outside.fixture.test", "api.fixture.test.attacker.example"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                dns_answer(question(name, 1), "api.fixture.test", bytes([10, 20, 30, 40]))

    def test_dns_over_tcp_uses_length_framing(self) -> None:
        def answer(packet: bytes) -> bytes | None:
            try:
                return dns_answer(packet, "api.fixture.test", bytes([10, 20, 30, 40]))[0]
            except ValueError:
                return None

        with DnsTcpServer(("127.0.0.1", 0), dns_tcp_handler(answer)) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                query = question("api.fixture.test", 1)
                with socket.create_connection(server.server_address, timeout=2) as client:
                    client.settimeout(2)
                    client.sendall(struct.pack("!H", len(query)) + query)
                    length = struct.unpack("!H", client.recv(2))[0]
                    response = bytearray()
                    while len(response) < length:
                        response.extend(client.recv(length - len(response)))
                self.assertEqual(response[:2], b"\x12\x34")
                self.assertTrue(response.endswith(bytes([10, 20, 30, 40])))
                with socket.create_connection(server.server_address, timeout=2) as client:
                    client.settimeout(2)
                    query = question("outside.fixture.test", 1)
                    client.sendall(struct.pack("!H", len(query)) + query)
                    self.assertEqual(client.recv(1), b"")
            finally:
                server.shutdown()
                thread.join()


if __name__ == "__main__":
    unittest.main()
