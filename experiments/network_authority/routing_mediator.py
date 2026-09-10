#!/usr/bin/env python3
"""Trusted broker and connector primitives for experiment 0001F."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import resource
import socket
import ssl
import struct
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.decision_http_fixture import (
    EXACT_REQUEST,
    script_exchange,
)
from experiments.network_authority.explicit_broker import MAX_FRAME_BYTES, wire_json
from experiments.network_authority.record_common import canonical_json, write_new
from experiments.network_authority.routing_cell import MEDIATOR_SCHEMA
from experiments.network_authority.routing_mediated_client import (
    ALLOWED_REQUEST,
    ALLOWED_RESPONSE,
)


MAX_REMOTE_BYTES = 8192


class MediatorError(Exception):
    """Trusted mediator setup or evidence was incomplete."""


class MediatorRejection(Exception):
    """The mediator rejected one exact request at a named policy stage."""

    def __init__(self, stage: str, detail: str):
        super().__init__(f"{stage}: {detail}")
        self.stage = stage
        self.detail = detail


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Decode a JSON object only when every name occurs once."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise MediatorRejection("application-protocol", "target-field-rejected")
        result[key] = value
    return result


def decode_operation(data: bytes) -> str:
    """Accept the one target-free broker operation and return its payload."""

    if not data or len(data) > MAX_FRAME_BYTES:
        raise MediatorRejection("application-protocol", "target-field-rejected")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MediatorRejection(
            "application-protocol", "target-field-rejected"
        ) from error
    if (
        not isinstance(value, dict)
        or set(value) != {"operation", "payload"}
        or value != {"operation": "echo", "payload": "bounded payload"}
        or wire_json(value) != data
    ):
        raise MediatorRejection("application-protocol", "target-field-rejected")
    return "bounded payload"


def read_exact(channel: socket.socket, size: int) -> bytes:
    """Read one exact positive bounded byte count."""

    if not 1 <= size <= MAX_REMOTE_BYTES:
        raise MediatorError("mediator read bound is invalid")
    result = bytearray()
    while len(result) < size:
        chunk = channel.recv(size - len(result))
        if not chunk:
            raise MediatorError("mediator input is truncated")
        result.extend(chunk)
    return bytes(result)


def read_frame(channel: socket.socket) -> bytes:
    """Read one bounded frame followed by peer write closure."""

    size = struct.unpack(">I", read_exact(channel, 4))[0]
    if size == 0 or size > MAX_FRAME_BYTES:
        raise MediatorRejection("application-protocol", "target-field-rejected")
    payload = read_exact(channel, size)
    if channel.recv(1) != b"":
        raise MediatorRejection("application-protocol", "target-field-rejected")
    return payload


def write_frame(channel: socket.socket, payload: bytes) -> None:
    """Write one bounded frame and close the write direction."""

    if not payload or len(payload) > MAX_FRAME_BYTES:
        raise MediatorError("mediator response frame is invalid")
    channel.sendall(struct.pack(">I", len(payload)) + payload)
    channel.shutdown(socket.SHUT_WR)


def marker(event: str, stage: str, detail: str) -> dict[str, object]:
    """Build the closed trusted mediator marker used by cell derivation."""

    return {
        "detail": detail,
        "event": event,
        "schema": MEDIATOR_SCHEMA,
        "stage": stage,
    }


def ready_marker() -> dict[str, object]:
    """Return the measurement-only broker readiness marker."""

    return {
        "schema": "proofbound-runtime-routing-mediator-ready/1",
        "state": "waiting-for-operation",
    }


def resource_observation() -> dict[str, object]:
    """Return the broker process high-water resident-set observation."""

    maximum_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if maximum_rss <= 0:
        raise MediatorError("mediator resident-set observation is invalid")
    return {
        "maximum_process_count": 1,
        "maximum_resident_set_bytes": maximum_rss * 1024,
        "schema": "proofbound-runtime-routing-mediator-resource/1",
    }


def canonical_address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Require one canonical IP address without a scope identifier."""

    if "%" in text:
        raise MediatorError("mediator address includes a scope identifier")
    try:
        address = ipaddress.ip_address(text)
    except ValueError as error:
        raise MediatorError("mediator address is invalid") from error
    if str(address) != text:
        raise MediatorError("mediator address is not canonical")
    return address


def open_authenticated(
    dial_address: str,
    expected_address: str,
    port: int,
    ca_certificate: Path,
) -> tuple[ssl.SSLSocket, dict[str, object]]:
    """Connect, bind the exact peer tuple, and authenticate TLS 1.3."""

    dial = canonical_address(dial_address)
    expected = canonical_address(expected_address)
    if dial.version != expected.version or not 1 <= port <= 65535:
        raise MediatorError("mediator endpoint configuration is invalid")
    family = socket.AF_INET if dial.version == 4 else socket.AF_INET6
    connection = socket.socket(family, socket.SOCK_STREAM)
    connection.settimeout(3)
    try:
        connection.connect((str(dial), port))
        peer = connection.getpeername()
        local = connection.getsockname()
        if peer[0] != str(expected) or peer[1] != port:
            raise MediatorRejection("routing", "connector-endpoint-mismatch")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(ca_certificate))
        try:
            protected = context.wrap_socket(
                connection,
                server_hostname="allowed.test",
                suppress_ragged_eofs=False,
            )
        except ssl.SSLCertVerificationError as error:
            raise MediatorRejection("tls", "certificate-rejected") from error
        certificate = protected.getpeercert(binary_form=True)
        cipher = protected.cipher()
        if protected.version() != "TLSv1.3" or not certificate or cipher is None:
            protected.close()
            raise MediatorError("mediator TLS observations are incomplete")
        protected.settimeout(3)
        return protected, {
            "cipher": cipher[0],
            "local_ip": local[0],
            "local_port": local[1],
            "peer_certificate_sha256": hashlib.sha256(certificate).hexdigest(),
            "peer_ip": peer[0],
            "peer_port": peer[1],
            "schema": "proofbound-runtime-routing-session-observation/1",
            "service_name": "allowed.test",
            "tls_version": "TLSv1.3",
        }
    except BaseException:
        connection.close()
        raise


def exact_remote_exchange(protected: ssl.SSLSocket) -> bytes:
    """Perform the exact registered HTTP exchange over authenticated TLS."""

    expected = script_exchange("exact")[1]
    protected.sendall(EXACT_REQUEST)
    response = read_exact(protected, len(expected))
    if protected.recv(1) != b"" or response != expected:
        raise MediatorError("mediator remote response is not exact")
    raw = protected.unwrap()
    raw.close()
    return response


def relay_transparent(channel: socket.socket, protected: ssl.SSLSocket) -> bytes:
    """Relay one exact HTTP exchange without altering child-visible bytes."""

    request = bytearray()
    while len(request) < len(EXACT_REQUEST):
        chunk = channel.recv(len(EXACT_REQUEST) - len(request))
        if not chunk:
            raise MediatorError("transparent request is truncated")
        request.extend(chunk)
    if bytes(request) != EXACT_REQUEST or channel.recv(1) != b"":
        raise MediatorError("transparent request is not exact")
    response = exact_remote_exchange(protected)
    channel.sendall(response)
    channel.shutdown(socket.SHUT_WR)
    return response


def serve_broker(
    descriptor: int,
    dial_address: str,
    expected_address: str,
    port: int,
    ca_certificate: Path,
    marker_path: Path,
    session_path: Path,
) -> int:
    """Serve one explicit operation through a trusted TLS mediator."""

    with socket.socket(fileno=descriptor) as channel:
        try:
            payload = decode_operation(read_frame(channel))
            protected, session = open_authenticated(
                dial_address, expected_address, port, ca_certificate
            )
            with protected:
                exact_remote_exchange(protected)
            response = wire_json({"payload": payload, "status": "ok"})
            write_new(session_path, canonical_json(session))
            write_new(
                marker_path,
                canonical_json(
                    marker(
                        "exact-response",
                        "application-protocol",
                        "authenticated-exact-response",
                    )
                ),
            )
            write_frame(channel, response)
            return 0
        except MediatorRejection as rejection:
            write_new(
                marker_path,
                canonical_json(marker("rejected", rejection.stage, rejection.detail)),
            )
            try:
                write_frame(
                    channel,
                    wire_json({"code": rejection.detail, "status": "error"}),
                )
            except (MediatorError, OSError):
                pass
            return 7


def parser() -> argparse.ArgumentParser:
    """Build the explicit broker process interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--fd", type=int, required=True)
    result.add_argument("--dial-address", required=True)
    result.add_argument("--expected-address", required=True)
    result.add_argument("--port", type=int, required=True)
    result.add_argument("--ca-certificate", type=Path, required=True)
    result.add_argument("--marker", type=Path, required=True)
    result.add_argument("--session-observation", type=Path, required=True)
    result.add_argument("--ready", type=Path)
    result.add_argument("--resource-observation", type=Path)
    return result


def main() -> int:
    """Run one explicit broker exchange."""

    arguments = parser().parse_args()
    try:
        paths = [
            arguments.ca_certificate,
            arguments.marker,
            arguments.session_observation,
        ]
        if arguments.ready is not None:
            paths.append(arguments.ready)
        if arguments.resource_observation is not None:
            paths.append(arguments.resource_observation)
        if (
            arguments.fd < 3
            or any(not path.is_absolute() for path in paths)
            or len(set(paths)) != len(paths)
        ):
            raise MediatorError("routing broker arguments are invalid")
        if arguments.ready is not None:
            write_new(arguments.ready, canonical_json(ready_marker()))
        result = serve_broker(
            arguments.fd,
            arguments.dial_address,
            arguments.expected_address,
            arguments.port,
            arguments.ca_certificate,
            arguments.marker,
            arguments.session_observation,
        )
        if arguments.resource_observation is not None:
            write_new(
                arguments.resource_observation,
                canonical_json(resource_observation()),
            )
        return result
    except (MediatorError, OSError, ssl.SSLError, ValueError) as error:
        print(f"routing mediator failed: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
