#!/usr/bin/env python3
"""Local DNS and TLS API for the declared-egress OpenTofu workload.

The fixture listens only on the explicitly supplied host address and never
forwards a DNS query or opens an outbound connection.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import socketserver
import ssl
import struct
import threading


def dns_answer(packet: bytes, name: str, address: bytes) -> tuple[bytes, str]:
    """Answer one IN/A question for the fixture name; reject everything else."""
    if len(packet) < 17 or packet[2] & 0x80 or packet[4:6] != b"\x00\x01":
        raise ValueError("invalid DNS question")
    offset = 12
    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        width = packet[offset]
        offset += 1
        if width == 0:
            break
        if width > 63 or offset + width > len(packet):
            raise ValueError("invalid DNS label")
        labels.append(packet[offset:offset + width].decode("ascii"))
        offset += width
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS type")
    question = ".".join(labels)
    kind, query_class = struct.unpack("!HH", packet[offset:offset + 4])
    if query_class != 1 or question != name or kind not in (1, 28):
        raise ValueError("undeclared DNS question")
    end = offset + 4
    answer_count = 1 if kind == 1 else 0
    header = packet[:2] + b"\x81\x80" + b"\x00\x01" + struct.pack("!H", answer_count) + b"\x00" * 4
    answer = b""
    if answer_count:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + address
    return header + packet[12:end] + answer, "A" if kind == 1 else "AAAA"


class DnsServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class DnsTcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def dns_tcp_handler(answer):
    """Bind the DNS-over-TCP framing to one closed fixture answer function."""

    class DnsTcpHandler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(2)
            try:
                prefix = self.rfile.read(2)
                if len(prefix) != 2:
                    return
                length = struct.unpack("!H", prefix)[0]
                if not 0 < length <= 4096:
                    return
                packet = self.rfile.read(length)
                if len(packet) != length:
                    return
            except (TimeoutError, OSError):
                return
            response = answer(packet)
            if response is not None:
                self.wfile.write(struct.pack("!H", len(response)) + response)

    return DnsTcpHandler


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", required=True)
    parser.add_argument("--api-port", required=True, type=int)
    parser.add_argument("--dns-port", required=True, type=int)
    parser.add_argument("--name", default="api.fixture.test")
    parser.add_argument("--cert", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--ready", required=True, type=Path)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--token-file", required=True, type=Path)
    args = parser.parse_args()
    address = ipaddress.IPv4Address(args.address)
    if not address.is_private or address.is_loopback or address.is_link_local:
        raise SystemExit("fixture API requires a non-loopback private IPv4 host address")
    token = args.token_file.read_text(encoding="ascii").strip()
    if not token or any(character.isspace() for character in token):
        raise SystemExit("invalid fixture token")
    events_lock = threading.Lock()
    records: dict[str, dict[str, str]] = {}

    def record(event: dict[str, object]) -> None:
        with events_lock, args.events.open("a", encoding="utf-8") as destination:
            destination.write(json.dumps(event, sort_keys=True) + "\n")

    def answer_and_record(packet: bytes) -> bytes | None:
        try:
            response, kind = dns_answer(packet, args.name, address.packed)
        except (UnicodeDecodeError, ValueError):
            record({"channel": "dns", "result": "rejected"})
            return None
        record({"channel": "dns", "name": args.name, "type": kind})
        return response

    class DnsHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            packet, connection = self.request
            response = answer_and_record(packet)
            if response is not None:
                connection.sendto(response, self.client_address)

    class ApiHandler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_arguments: object) -> None:
            pass

        def respond(self, status: int, value: dict[str, object]) -> None:
            body = json.dumps(value, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def authorized(self) -> bool:
            if self.headers.get("Authorization") == f"Bearer {token}":
                return True
            self.respond(401, {"error": "unauthorized"})
            return False

        def do_GET(self) -> None:
            if not self.authorized():
                return
            if self.path == "/health":
                record({"channel": "api", "method": "GET", "path": self.path})
                self.respond(200, {"ok": True})
            elif self.path.startswith("/records/"):
                identifier = self.path.removeprefix("/records/")
                record({"channel": "api", "method": "GET", "path": self.path})
                if identifier in records:
                    self.respond(200, records[identifier])
                else:
                    self.respond(404, {"error": "not-found"})
            elif self.path == "/records":
                record({"channel": "api", "method": "GET", "path": self.path})
                self.respond(200, {"records": list(records.values())})
            else:
                self.respond(404, {"error": "not-found"})

        def put_record(self, path: str, method: str) -> None:
            if not self.authorized():
                return
            if self.path != path:
                self.respond(404, {"error": "not-found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 4096:
                self.respond(400, {"error": "body-bound"})
                return
            try:
                value = json.loads(self.rfile.read(length))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.respond(400, {"error": "invalid-json"})
                return
            if not isinstance(value, dict) or value.get("id") != "proofbound-fixture" or value.get("value") != "applied":
                self.respond(400, {"error": "invalid-record"})
                return
            records[value["id"]] = value
            record({"channel": "api", "method": method, "path": self.path})
            self.respond(200, value)

        def do_POST(self) -> None:
            self.put_record("/records", "POST")

        def do_PUT(self) -> None:
            self.put_record("/records/proofbound-fixture", "PUT")

        def do_DELETE(self) -> None:
            if not self.authorized():
                return
            identifier = self.path.removeprefix("/records/")
            records.pop(identifier, None)
            record({"channel": "api", "method": "DELETE", "path": self.path})
            self.respond(200, {"id": identifier})

    with DnsServer(("127.0.0.1", args.dns_port), DnsHandler) as dns_server, \
            DnsTcpServer(("127.0.0.1", args.dns_port), dns_tcp_handler(answer_and_record)) as dns_tcp_server, \
            ThreadingHTTPServer((args.address, args.api_port), ApiHandler) as api_server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        api_server.socket = context.wrap_socket(api_server.socket, server_side=True)
        dns_threads = [
            threading.Thread(target=server.serve_forever, daemon=True)
            for server in (dns_server, dns_tcp_server)
        ]
        for thread in dns_threads:
            thread.start()
        args.ready.touch(exist_ok=False)
        try:
            api_server.serve_forever()
        finally:
            dns_server.shutdown()
            dns_tcp_server.shutdown()
            for thread in dns_threads:
                thread.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
