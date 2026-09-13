#!/usr/bin/env python3
"""Interactive CONNECT and SOCKS tunnel fixture for experiment 0001E."""

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


MAX_EXCHANGE_BYTES = 4096
SCRIPTS = {"http-connect", "socks5"}
TARGET = "denied.test:443"
PROBE = b"tunnel-probe\n"
DENIED_SENTINEL = b"denied-service-sentinel\n"
HTTP_CONNECT_REQUEST = (
    b"CONNECT denied.test:443 HTTP/1.1\r\n"
    b"Host: denied.test:443\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)
HTTP_CONNECT_RESPONSE = b"HTTP/1.1 200 Connection Established\r\n\r\n"
SOCKS_GREETING = b"\x05\x01\x00"
SOCKS_METHOD = b"\x05\x00"
SOCKS_CONNECT_REQUEST = b"\x05\x01\x00\x03\x0bdenied.test\x01\xbb"
SOCKS_CONNECT_RESPONSE = b"\x05\x00\x00\x01\x7f\x00\x00\x02\x01\xbb"


class ProxyFixtureError(Exception):
    """A proxy exchange or identity was outside the frozen protocol."""


def read_exact(channel: socket.socket, size: int) -> bytes:
    """Read one exact positive bounded protocol field."""

    if not 1 <= size <= MAX_EXCHANGE_BYTES:
        raise ProxyFixtureError("proxy read bound is invalid")
    result = bytearray()
    while len(result) < size:
        chunk = channel.recv(size - len(result))
        if not chunk:
            raise ProxyFixtureError("proxy exchange is truncated")
        result.extend(chunk)
    return bytes(result)


def serve_http_connect(protected: ssl.SSLSocket) -> dict[str, object]:
    """Serve one exact CONNECT tunnel and denied-service sentinel."""

    request = read_exact(protected, len(HTTP_CONNECT_REQUEST))
    if request != HTTP_CONNECT_REQUEST:
        raise ProxyFixtureError("HTTP CONNECT request is not exact")
    protected.sendall(HTTP_CONNECT_RESPONSE)
    probe = read_exact(protected, len(PROBE))
    if probe != PROBE:
        raise ProxyFixtureError("HTTP CONNECT tunnel probe is not exact")
    protected.sendall(DENIED_SENTINEL)
    return {
        "protocol": "http-connect",
        "request_sha256": hashlib.sha256(request).hexdigest(),
        "target": TARGET,
        "tunnel_probe_sha256": hashlib.sha256(probe).hexdigest(),
    }


def serve_socks5(protected: ssl.SSLSocket) -> dict[str, object]:
    """Serve one exact SOCKS5 domain tunnel and denied-service sentinel."""

    greeting = read_exact(protected, len(SOCKS_GREETING))
    if greeting != SOCKS_GREETING:
        raise ProxyFixtureError("SOCKS greeting is not exact")
    protected.sendall(SOCKS_METHOD)
    request = read_exact(protected, len(SOCKS_CONNECT_REQUEST))
    if request != SOCKS_CONNECT_REQUEST:
        raise ProxyFixtureError("SOCKS connect request is not exact")
    protected.sendall(SOCKS_CONNECT_RESPONSE)
    probe = read_exact(protected, len(PROBE))
    if probe != PROBE:
        raise ProxyFixtureError("SOCKS tunnel probe is not exact")
    protected.sendall(DENIED_SENTINEL)
    return {
        "protocol": "socks5",
        "request_sha256": hashlib.sha256(request).hexdigest(),
        "target": TARGET,
        "tunnel_probe_sha256": hashlib.sha256(probe).hexdigest(),
    }


def serve_proxy_fixture(
    bind_ip: str,
    port: int,
    script: str,
    certificate: Path,
    private_key: Path,
    ready_file: Path,
    contact_file: Path,
    observation_file: Path,
) -> int:
    """Serve one TLS-authenticated interactive proxy transcript."""

    address = ipaddress.ip_address(bind_ip)
    if (
        not 0 <= port <= 65535
        or script not in SCRIPTS
        or not ready_file.is_absolute()
        or not contact_file.is_absolute()
        or not observation_file.is_absolute()
        or len({ready_file, contact_file, observation_file}) != 3
    ):
        raise ProxyFixtureError("proxy fixture configuration is invalid")
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=str(certificate), keyfile=str(private_key))
    server_names: list[str | None] = []
    context.set_servername_callback(
        lambda _protected, server_name, _context: server_names.append(server_name)
    )
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
                    "schema": "proofbound-runtime-decision-proxy-ready/1",
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
                        "schema": "proofbound-runtime-decision-proxy-contact/1",
                    }
                ),
            )
            with context.wrap_socket(connection, server_side=True) as protected:
                protected.settimeout(3)
                if server_names != ["allowed.test"]:
                    raise ProxyFixtureError("proxy TLS SNI is not exact")
                if script == "http-connect":
                    observation = serve_http_connect(protected)
                else:
                    observation = serve_socks5(protected)
                if read_exact(protected, 1) != b"\x00":
                    raise ProxyFixtureError("proxy close marker is not exact")
                raw_socket = protected.unwrap()
                raw_socket.close()
    write_new(
        observation_file,
        canonical_json(
            {
                **observation,
                "peer_ip": peer[0],
                "schema": "proofbound-runtime-decision-proxy-observation/1",
                "sni": "allowed.test",
                "tls_version": "TLSv1.3",
            }
        ),
    )
    return 0


def parser() -> argparse.ArgumentParser:
    """Build the proxy fixture's closed command interface."""

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
    """Run one bounded proxy fixture."""

    arguments = parser().parse_args()
    try:
        return serve_proxy_fixture(
            arguments.bind_ip,
            arguments.port,
            arguments.script,
            arguments.certificate,
            arguments.private_key,
            arguments.ready_file,
            arguments.contact_file,
            arguments.observation_file,
        )
    except (OSError, ProxyFixtureError, ssl.SSLError, ValueError) as error:
        print(f"decision proxy fixture failed: {error}", file=sys.stderr)
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
