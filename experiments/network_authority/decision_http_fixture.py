#!/usr/bin/env python3
"""Bounded dual-stack TLS and redirect fixture for experiment 0001E."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import socket
import ssl
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.record_common import canonical_json, write_new


MAX_HTTP_BYTES = 4096
FIXED_BODY = b"0123456789abcdef0123456789abcdef"
SCRIPTS = {
    "exact",
    "undeclared-path",
    "redirect-host",
    "redirect-cleartext",
    "redirect-port",
}
EXACT_REQUEST = (
    b"GET /v1/echo HTTP/1.1\r\n"
    b"Host: allowed.test\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)
UNDECLARED_PATH_REQUEST = (
    b"GET /undeclared HTTP/1.1\r\n"
    b"Host: allowed.test\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)
REDIRECT_REQUEST = (
    b"GET /v1/redirect HTTP/1.1\r\n"
    b"Host: allowed.test\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)


class HttpFixtureError(Exception):
    """A fixture request, response, or identity was outside the frozen grammar."""


def http_response(status: bytes, headers: tuple[bytes, ...], body: bytes) -> bytes:
    """Build one closed HTTP response with an exact body length."""

    if (
        not status.startswith(b"HTTP/1.1 ")
        or b"\r" in body
        or b"\n" in body
        or len(body) > MAX_HTTP_BYTES
        or any(b"\r" in header or b"\n" in header for header in headers)
    ):
        raise HttpFixtureError("HTTP response input is invalid")
    lines = [
        status,
        *headers,
        b"Content-Length: " + str(len(body)).encode("ascii"),
        b"Connection: close",
    ]
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def script_exchange(script: str) -> tuple[bytes, bytes, str]:
    """Return one exact request, response, and public observation."""

    if script == "exact":
        return (
            EXACT_REQUEST,
            http_response(
                b"HTTP/1.1 200 OK",
                (b"Content-Type: application/octet-stream",),
                FIXED_BODY,
            ),
            "exact-response",
        )
    if script == "undeclared-path":
        return (
            UNDECLARED_PATH_REQUEST,
            http_response(b"HTTP/1.1 404 Not Found", (), b"undeclared-path-observed"),
            "undeclared-path-observed",
        )
    locations = {
        "redirect-host": b"https://denied.test/v1/echo",
        "redirect-cleartext": b"http://allowed.test/v1/echo",
        "redirect-port": b"https://allowed.test:8443/v1/echo",
    }
    if script in locations:
        location = locations[script]
        return (
            REDIRECT_REQUEST,
            http_response(b"HTTP/1.1 302 Found", (b"Location: " + location,), b""),
            script,
        )
    raise HttpFixtureError("HTTP fixture script is unknown")


def validate_response(response: bytes) -> None:
    """Require one self-consistent closed HTTP response."""

    head, separator, body = response.partition(b"\r\n\r\n")
    if not separator or not head.startswith(b"HTTP/1.1 "):
        raise HttpFixtureError("HTTP response grammar is invalid")
    lines = head.split(b"\r\n")
    lengths = [line[16:] for line in lines if line.startswith(b"Content-Length: ")]
    connections = [line for line in lines if line.startswith(b"Connection: ")]
    if (
        len(lengths) != 1
        or lengths[0] != str(len(body)).encode("ascii")
        or connections != [b"Connection: close"]
    ):
        raise HttpFixtureError("HTTP response metadata is not exact")


def serve_tls_fixture(
    bind_ip: str,
    port: int,
    script: str,
    certificate: Path,
    private_key: Path,
    ready_file: Path,
    contact_file: Path,
    observation_file: Path,
) -> int:
    """Serve one exact TLS 1.3 HTTP exchange on IPv4 or IPv6."""

    address = ipaddress.ip_address(bind_ip)
    if (
        not 0 <= port <= 65535
        or script not in SCRIPTS
        or not ready_file.is_absolute()
        or not contact_file.is_absolute()
        or not observation_file.is_absolute()
        or len({ready_file, contact_file, observation_file}) != 3
    ):
        raise HttpFixtureError("TLS fixture configuration is invalid")
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=str(certificate), keyfile=str(private_key))
    server_names: list[str | None] = []
    context.set_servername_callback(
        lambda _protected, server_name, _context: server_names.append(server_name)
    )
    expected_request, response, event = script_exchange(script)
    validate_response(response)
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((str(address), port))
        listener.listen(1)
        listener.settimeout(8)
        actual_port = listener.getsockname()[1]
        write_new(
            ready_file,
            canonical_json(
                {
                    "address": str(address),
                    "family": "ipv4" if address.version == 4 else "ipv6",
                    "port": actual_port,
                    "schema": "proofbound-runtime-decision-http-ready/1",
                }
            ),
        )
        connection, peer = listener.accept()
        with connection:
            write_new(
                contact_file,
                canonical_json(
                    {
                        "event": "tcp-accepted",
                        "family": "ipv4" if address.version == 4 else "ipv6",
                        "peer_ip": peer[0],
                        "schema": "proofbound-runtime-decision-http-contact/1",
                    }
                ),
            )
            with context.wrap_socket(connection, server_side=True) as protected:
                protected.settimeout(3)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    chunk = protected.recv(1024)
                    if not chunk:
                        raise HttpFixtureError("TLS fixture request is truncated")
                    request.extend(chunk)
                    if len(request) > MAX_HTTP_BYTES:
                        raise HttpFixtureError("TLS fixture request exceeded its bound")
                if bytes(request) != expected_request:
                    raise HttpFixtureError("TLS fixture request is not exact")
                if server_names != ["allowed.test"]:
                    raise HttpFixtureError("TLS fixture SNI is not exact")
                protected.sendall(response)
                raw_socket = protected.unwrap()
                raw_socket.close()
    write_new(
        observation_file,
        canonical_json(
            {
                "event": event,
                "peer_ip": peer[0],
                "request_sha256": hashlib.sha256(expected_request).hexdigest(),
                "response_sha256": hashlib.sha256(response).hexdigest(),
                "schema": "proofbound-runtime-decision-http-observation/1",
                "sni": "allowed.test",
                "tls_version": "TLSv1.3",
            }
        ),
    )
    return 0


def parser() -> argparse.ArgumentParser:
    """Build the fixture's closed command interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--bind-ip", required=True)
    result.add_argument("--port", type=int, required=True)
    result.add_argument("--script", choices=sorted(SCRIPTS), required=True)
    result.add_argument("--certificate", type=Path, required=True)
    result.add_argument("--private-key", type=Path, required=True)
    result.add_argument("--ready-file", type=Path, required=True)
    result.add_argument("--contact-file", type=Path, required=True)
    result.add_argument("--observation-file", type=Path, required=True)
    return result


def main() -> int:
    """Run one bounded TLS/redirect fixture."""

    arguments = parser().parse_args()
    try:
        return serve_tls_fixture(
            arguments.bind_ip,
            arguments.port,
            arguments.script,
            arguments.certificate,
            arguments.private_key,
            arguments.ready_file,
            arguments.contact_file,
            arguments.observation_file,
        )
    except (HttpFixtureError, OSError, ssl.SSLError, ValueError) as error:
        print(f"decision HTTP fixture failed: {error}", file=sys.stderr)
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
