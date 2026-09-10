#!/usr/bin/env python3
"""Bounded explicit-channel broker and TLS fixture for experiment 0001C."""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import ssl
import struct
import sys
from pathlib import Path
from typing import Callable

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.record_common import write_new


MAX_FRAME_BYTES = 4096
MAX_PAYLOAD_BYTES = 1024
MAX_HTTP_BYTES = 8192
FIXED_RESPONSE = b"0123456789abcdef0123456789abcdef"
HTTP_REQUEST = (
    b"GET /v1/echo HTTP/1.1\r\n"
    b"Host: allowed.test\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)


class ProtocolError(Exception):
    """The local frame or remote fixture response violated the frozen grammar."""


def wire_json(value: object) -> bytes:
    """Encode canonical JSON without whitespace or a trailing newline."""

    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build a JSON object while rejecting duplicate names."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate JSON field")
        result[key] = value
    return result


def decode_request(data: bytes) -> str:
    """Decode the one exact request and return its payload."""

    if not data or len(data) > MAX_FRAME_BYTES:
        raise ProtocolError("request size outside the frame bound")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError("request is not UTF-8") from error
    try:
        value = json.loads(text, object_pairs_hook=unique_object)
    except (json.JSONDecodeError, ProtocolError) as error:
        raise ProtocolError("request is not unique JSON") from error
    if not isinstance(value, dict) or set(value) != {"operation", "payload"}:
        raise ProtocolError("request fields are not exact")
    if value["operation"] != "echo" or not isinstance(value["payload"], str):
        raise ProtocolError("request operation or payload type is invalid")
    payload = value["payload"]
    payload_size = len(payload.encode("utf-8"))
    if payload_size == 0 or payload_size > MAX_PAYLOAD_BYTES:
        raise ProtocolError("request payload size is invalid")
    if wire_json(value) != data:
        raise ProtocolError("request JSON is not canonical")
    return payload


def read_exact(channel: socket.socket, size: int) -> bytes:
    """Read exactly size bytes or reject truncation."""

    result = bytearray()
    while len(result) < size:
        chunk = channel.recv(size - len(result))
        if not chunk:
            raise ProtocolError("frame is truncated")
        result.extend(chunk)
    return bytes(result)


def read_frame(channel: socket.socket) -> bytes:
    """Read one bounded frame followed by peer write shutdown."""

    size = struct.unpack(">I", read_exact(channel, 4))[0]
    if size == 0 or size > MAX_FRAME_BYTES:
        raise ProtocolError("frame length is invalid")
    payload = read_exact(channel, size)
    if channel.recv(1) != b"":
        raise ProtocolError("frame has trailing bytes")
    return payload


def write_frame(channel: socket.socket, payload: bytes) -> None:
    """Write one bounded frame and close the write direction."""

    if not payload or len(payload) > MAX_FRAME_BYTES:
        raise ProtocolError("response frame length is invalid")
    channel.sendall(struct.pack(">I", len(payload)) + payload)
    channel.shutdown(socket.SHUT_WR)


def parse_http_response(data: bytes) -> None:
    """Accept only the fixed TLS fixture response."""

    head, separator, body = data.partition(b"\r\n\r\n")
    if not separator or body != FIXED_RESPONSE:
        raise ProtocolError("remote application response is not exact")
    lines = head.split(b"\r\n")
    if lines != [
        b"HTTP/1.1 200 OK",
        b"Content-Type: application/octet-stream",
        b"Content-Length: 32",
        b"Connection: close",
    ]:
        raise ProtocolError("remote HTTP metadata is not exact")


def fetch_service(endpoint_ip: str, endpoint_port: int, service: str, ca_path: Path) -> None:
    """Authenticate and read the one fixed HTTPS service response."""

    address = str(ipaddress.IPv4Address(endpoint_ip))
    if not 1 <= endpoint_port <= 65535 or service != "allowed.test":
        raise ProtocolError("broker configuration is outside the control")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(ca_path))
    with socket.create_connection((address, endpoint_port), timeout=3) as connection:
        with context.wrap_socket(connection, server_hostname=service) as protected:
            protected.settimeout(3)
            protected.sendall(HTTP_REQUEST)
            response = bytearray()
            while True:
                chunk = protected.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > MAX_HTTP_BYTES:
                    raise ProtocolError("remote response exceeded its bound")
    parse_http_response(bytes(response))


def serve_broker(
    descriptor: int,
    endpoint_ip: str,
    endpoint_port: int,
    service: str,
    ca_path: Path,
    fetch: Callable[[str, int, str, Path], None] = fetch_service,
) -> int:
    """Serve one request on one inherited local channel."""

    with socket.socket(fileno=descriptor) as channel:
        try:
            payload = decode_request(read_frame(channel))
            fetch(endpoint_ip, endpoint_port, service, ca_path)
            response = wire_json({"payload": payload, "status": "ok"})
            write_frame(channel, response)
            return 0
        except (OSError, ProtocolError, ssl.SSLError, ValueError):
            try:
                write_frame(channel, wire_json({"code": "request-failed", "status": "error"}))
            except (OSError, ProtocolError):
                pass
            return 7


def serve_fixture(
    bind_ip: str,
    port: int,
    certificate: Path,
    private_key: Path,
    ready_file: Path,
) -> int:
    """Serve one exact TLS fixture response."""

    address = str(ipaddress.IPv4Address(bind_ip))
    if not 1 <= port <= 65535 or not ready_file.is_absolute():
        raise ProtocolError("fixture configuration is invalid")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(certificate), keyfile=str(private_key))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((address, port))
        listener.listen(1)
        listener.settimeout(10)
        write_new(ready_file, b"ready\n")
        connection, _ = listener.accept()
        with connection:
            with context.wrap_socket(connection, server_side=True) as protected:
                protected.settimeout(3)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    chunk = protected.recv(1024)
                    if not chunk:
                        raise ProtocolError("fixture request is truncated")
                    request.extend(chunk)
                    if len(request) > MAX_FRAME_BYTES:
                        raise ProtocolError("fixture request exceeded its bound")
                if bytes(request) != HTTP_REQUEST:
                    raise ProtocolError("fixture request is not exact")
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/octet-stream\r\n"
                    b"Content-Length: 32\r\n"
                    b"Connection: close\r\n"
                    b"\r\n"
                    + FIXED_RESPONSE
                )
                protected.sendall(response)
    return 0


def parser() -> argparse.ArgumentParser:
    """Build the closed command-line interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    subparsers = result.add_subparsers(dest="mode", required=True)
    broker = subparsers.add_parser("broker", allow_abbrev=False)
    broker.add_argument("--fd", type=int, required=True)
    broker.add_argument("--endpoint-ip", required=True)
    broker.add_argument("--endpoint-port", type=int, required=True)
    broker.add_argument("--service", required=True)
    broker.add_argument("--ca-certificate", type=Path, required=True)
    fixture = subparsers.add_parser("fixture", allow_abbrev=False)
    fixture.add_argument("--bind-ip", required=True)
    fixture.add_argument("--port", type=int, required=True)
    fixture.add_argument("--certificate", type=Path, required=True)
    fixture.add_argument("--private-key", type=Path, required=True)
    fixture.add_argument("--ready-file", type=Path, required=True)
    return result


def main() -> int:
    """Run one broker or fixture instance."""

    arguments = parser().parse_args()
    try:
        if arguments.mode == "broker":
            return serve_broker(
                arguments.fd,
                arguments.endpoint_ip,
                arguments.endpoint_port,
                arguments.service,
                arguments.ca_certificate,
            )
        return serve_fixture(
            arguments.bind_ip,
            arguments.port,
            arguments.certificate,
            arguments.private_key,
            arguments.ready_file,
        )
    except (OSError, ProtocolError, ssl.SSLError, ValueError) as error:
        print(f"explicit broker control failed: {error}", file=sys.stderr)
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
