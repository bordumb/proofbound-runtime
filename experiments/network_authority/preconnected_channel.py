#!/usr/bin/env python3
"""One authenticated transparent channel for experiment 0001D."""

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

from experiments.network_authority.record_common import write_new


MAX_DIRECTION_BYTES = 4096
ALLOWED_REQUEST = (
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
CONNECT_REQUEST = (
    b"CONNECT denied.test:443 HTTP/1.1\r\n"
    b"Host: denied.test:443\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)
FIXED_BODY = b"0123456789abcdef0123456789abcdef"
ALLOWED_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Length: 32\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    + FIXED_BODY
)
UNDECLARED_PATH_RESPONSE = (
    b"HTTP/1.1 404 Not Found\r\n"
    b"Content-Length: 24\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"undeclared-path-observed"
)
CONNECT_RESPONSE = (
    b"HTTP/1.1 405 Method Not Allowed\r\n"
    b"Content-Length: 22\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"connect-shape-observed"
)


class ConnectorError(Exception):
    """The frozen connector, channel, or fixture contract was violated."""


def validate_fixed_response(response: bytes) -> None:
    """Require one self-consistent bounded fixed HTTP response."""

    head, separator, body = response.partition(b"\r\n\r\n")
    if not separator or not head.startswith(b"HTTP/1.1 "):
        raise ConnectorError("fixed response grammar is invalid")
    lengths = [
        line.removeprefix(b"Content-Length: ")
        for line in head.split(b"\r\n")
        if line.startswith(b"Content-Length: ")
    ]
    if len(lengths) != 1 or lengths[0] != str(len(body)).encode("ascii"):
        raise ConnectorError("fixed response length is invalid")


def request_result(request: bytes) -> tuple[str, bytes]:
    """Return the fixed fixture observation and response for exact bytes."""

    if request == ALLOWED_REQUEST:
        result = "allowed-request", ALLOWED_RESPONSE
    elif request == UNDECLARED_PATH_REQUEST:
        result = "undeclared-path-observed", UNDECLARED_PATH_RESPONSE
    elif request == CONNECT_REQUEST:
        result = "connect-shape-observed", CONNECT_RESPONSE
    else:
        raise ConnectorError("fixture request is outside the frozen corpus")
    validate_fixed_response(result[1])
    return result


def read_bounded(channel: object, maximum: int = MAX_DIRECTION_BYTES) -> bytes:
    """Read through EOF while enforcing one positive byte bound."""

    if maximum <= 0:
        raise ConnectorError("channel bound is invalid")
    result = bytearray()
    while True:
        chunk = channel.recv(min(1024, maximum + 1 - len(result)))
        if not chunk:
            break
        result.extend(chunk)
        if len(result) > maximum:
            raise ConnectorError("channel direction exceeded its byte bound")
    if not result:
        raise ConnectorError("channel direction was empty")
    return bytes(result)


def relay_session(channel: socket.socket, protected: ssl.SSLSocket) -> dict[str, object]:
    """Relay one bounded request and response over one authenticated session."""

    request = read_bounded(channel)
    protected.sendall(request)
    response = read_bounded(protected)
    raw_socket = protected.unwrap()
    raw_socket.close()
    channel.sendall(response)
    channel.shutdown(socket.SHUT_WR)
    return {
        "child_to_service_bytes": len(request),
        "service_to_child_bytes": len(response),
        "tls_shutdown_observed": True,
    }


def authenticated_session(
    dial_ip: str,
    expected_ip: str,
    port: int,
    service: str,
    ca_path: Path,
) -> tuple[ssl.SSLSocket, dict[str, object]]:
    """Open and authenticate the one exact TLS 1.3 session."""

    dial_address = str(ipaddress.IPv4Address(dial_ip))
    expected_address = str(ipaddress.IPv4Address(expected_ip))
    if not 1 <= port <= 65535 or service != "allowed.test" or not ca_path.is_absolute():
        raise ConnectorError("connector configuration is outside the control")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(ca_path))
    connection = socket.create_connection((dial_address, port), timeout=3)
    try:
        peer = connection.getpeername()
        local = connection.getsockname()
        if peer != (expected_address, port):
            raise ConnectorError("connected routing endpoint is not exact")
        protected = context.wrap_socket(
            connection,
            server_hostname=service,
            suppress_ragged_eofs=False,
        )
        protected.settimeout(3)
        certificate = protected.getpeercert(binary_form=True)
        cipher = protected.cipher()
        if protected.version() != "TLSv1.3" or not certificate or cipher is None:
            raise ConnectorError("authenticated TLS observations are incomplete")
        return protected, {
            "cipher": cipher[0],
            "local_ip": local[0],
            "local_port": local[1],
            "peer_certificate_sha256": hashlib.sha256(certificate).hexdigest(),
            "peer_ip": peer[0],
            "peer_port": peer[1],
            "service_name": service,
            "tls_version": protected.version(),
        }
    except BaseException:
        connection.close()
        raise


def serve_fixture(
    bind_ip: str,
    port: int,
    certificate: Path,
    private_key: Path,
    ready_file: Path,
    observation_file: Path,
) -> int:
    """Serve one exact corpus request with authenticated TLS shutdown."""

    address = str(ipaddress.IPv4Address(bind_ip))
    if (
        not 1 <= port <= 65535
        or not ready_file.is_absolute()
        or not observation_file.is_absolute()
    ):
        raise ConnectorError("fixture configuration is invalid")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=str(certificate), keyfile=str(private_key))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((address, port))
        listener.listen(1)
        listener.settimeout(8)
        write_new(ready_file, b"ready\n")
        connection, _ = listener.accept()
        with connection:
            with context.wrap_socket(connection, server_side=True) as protected:
                protected.settimeout(3)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    chunk = protected.recv(1024)
                    if not chunk:
                        raise ConnectorError("fixture request is truncated")
                    request.extend(chunk)
                    if len(request) > MAX_DIRECTION_BYTES:
                        raise ConnectorError("fixture request exceeded its bound")
                observation, response = request_result(bytes(request))
                write_new(observation_file, (observation + "\n").encode("ascii"))
                protected.sendall(response)
                raw_socket = protected.unwrap()
                raw_socket.close()
    return 0


def serve_plaintext_fixture(
    bind_ip: str, port: int, ready_file: Path, observation_file: Path
) -> int:
    """Accept one TLS-shaped contact without speaking TLS."""

    address = str(ipaddress.IPv4Address(bind_ip))
    if (
        not 1 <= port <= 65535
        or not ready_file.is_absolute()
        or not observation_file.is_absolute()
    ):
        raise ConnectorError("plaintext fixture configuration is invalid")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((address, port))
        listener.listen(1)
        listener.settimeout(8)
        write_new(ready_file, b"ready\n")
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(3)
            contact = connection.recv(1024)
            if not contact:
                raise ConnectorError("plaintext fixture received no contact")
            write_new(observation_file, b"plaintext-contact-observed\n")
    return 0


def parser() -> argparse.ArgumentParser:
    """Build the fixture's closed command interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--bind-ip", required=True)
    result.add_argument("--port", type=int, required=True)
    result.add_argument("--certificate", type=Path, required=True)
    result.add_argument("--private-key", type=Path, required=True)
    result.add_argument("--ready-file", type=Path, required=True)
    result.add_argument("--observation-file", type=Path, required=True)
    result.add_argument("--plaintext", action="store_true")
    return result


def main() -> int:
    """Run one deterministic fixture instance."""

    arguments = parser().parse_args()
    try:
        if arguments.plaintext:
            return serve_plaintext_fixture(
                arguments.bind_ip,
                arguments.port,
                arguments.ready_file,
                arguments.observation_file,
            )
        return serve_fixture(
            arguments.bind_ip,
            arguments.port,
            arguments.certificate,
            arguments.private_key,
            arguments.ready_file,
            arguments.observation_file,
        )
    except (ConnectorError, OSError, ssl.SSLError, ValueError) as error:
        print(f"preconnected channel fixture failed: {error}", file=sys.stderr)
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
