#!/usr/bin/env python3
"""Untrusted direct-network client for experiment 0001F mechanisms A and B."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import socket
import ssl
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.decision_http_fixture import (
    EXACT_REQUEST,
    script_exchange,
)
from experiments.network_authority.decision_socket_fixture import (
    DNS_PROBE,
    PROBE,
    QUIC_PROBE,
    SENTINEL,
)
from experiments.network_authority.record_common import canonical_json, write_new
from experiments.network_authority.routing_transport_case import ROUTING_ACTIONS


MAX_RESPONSE_BYTES = 4096
EXECUTABLE_CASES = tuple(
    case_id
    for case_id in ROUTING_ACTIONS
    if case_id
    not in {"non-scoped-ipv6-scope-id", "alternate-address-text"}
)


class RoutingClientError(Exception):
    """The direct client configuration or response was outside its grammar."""


def exact_address(text: str, version: int) -> str:
    """Require one canonical IP address of the selected family."""

    try:
        address = ipaddress.ip_address(text)
    except ValueError as error:
        raise RoutingClientError("client address is invalid") from error
    if address.version != version or str(address) != text:
        raise RoutingClientError("client address is not canonical for its family")
    return text


def error_event(case_id: str, action: str, phase: str, error: OSError) -> dict[str, object]:
    """Retain an exact syscall/TLS failure without interpreting its meaning."""

    return {
        "action": action,
        "case": case_id,
        "errno": error.errno,
        "event": "operation-error",
        "phase": phase,
        "schema": "proofbound-runtime-routing-client-observation/1",
    }


def certificate_event(
    case_id: str,
    action: str,
    error: ssl.SSLCertVerificationError,
) -> dict[str, object]:
    """Retain certificate verification as distinct from syscall errno."""

    return {
        "action": action,
        "case": case_id,
        "event": "certificate-rejected",
        "phase": "tls",
        "schema": "proofbound-runtime-routing-client-observation/1",
        "verify_code": error.verify_code,
    }


def read_exact(channel: object, size: int) -> bytes:
    """Read one exact positive bounded response."""

    if not 1 <= size <= MAX_RESPONSE_BYTES:
        raise RoutingClientError("response bound is invalid")
    result = bytearray()
    while len(result) < size:
        chunk = channel.recv(size - len(result))  # type: ignore[attr-defined]
        if not chunk:
            raise RoutingClientError("response is truncated")
        result.extend(chunk)
    return bytes(result)


def tls_request(
    case_id: str,
    action: str,
    family: int,
    address: str,
    port: int,
    ca_certificate: Path,
) -> dict[str, object]:
    """Perform the one exact TLS 1.3 request or retain its failure phase."""

    try:
        connection = socket.socket(family, socket.SOCK_STREAM)
    except OSError as error:
        return error_event(case_id, action, "socket", error)
    with connection:
        connection.settimeout(3)
        try:
            connection.connect((address, port))
        except OSError as error:
            return error_event(case_id, action, "connect", error)
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
            return certificate_event(case_id, action, error)
        except OSError as error:
            return error_event(case_id, action, "tls", error)
        with protected:
            protected.settimeout(3)
            expected_response = script_exchange("exact")[1]
            try:
                protected.sendall(EXACT_REQUEST)
                response = read_exact(protected, len(expected_response))
                if response != expected_response:
                    raise RoutingClientError("TLS response is not exact")
                raw = protected.unwrap()
                raw.close()
            except OSError as error:
                return error_event(case_id, action, "application-protocol", error)
            return {
                "action": action,
                "case": case_id,
                "errno": None,
                "event": "exact-response",
                "phase": "application-protocol",
                "response_sha256": hashlib.sha256(response).hexdigest(),
                "schema": "proofbound-runtime-routing-client-observation/1",
                "tls_version": "TLSv1.3",
            }


def raw_routing_contact(
    case_id: str,
    action: str,
    family: int,
    address: str,
    port: int,
) -> dict[str, object]:
    """Attempt a raw route and send deterministic non-TLS bytes if it opens."""

    try:
        connection = socket.socket(family, socket.SOCK_STREAM)
    except OSError as error:
        return error_event(case_id, action, "socket", error)
    with connection:
        connection.settimeout(3)
        try:
            connection.connect((address, port))
        except OSError as error:
            return error_event(case_id, action, "connect", error)
        os.write(connection.fileno(), b"not-tls\n")
        connection.shutdown(socket.SHUT_WR)
        return {
            "action": action,
            "case": case_id,
            "errno": None,
            "event": "routing-connected",
            "phase": "connect",
            "schema": "proofbound-runtime-routing-client-observation/1",
        }


def socket_sentinel(
    case_id: str,
    action: str,
    address: str,
    port: int,
) -> dict[str, object]:
    """Attempt the direct TCP sentinel exchange on the undeclared port."""

    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as error:
        return error_event(case_id, action, "socket", error)
    with connection:
        connection.settimeout(3)
        try:
            connection.connect((address, port))
        except OSError as error:
            return error_event(case_id, action, "connect", error)
        os.write(connection.fileno(), PROBE)
        connection.shutdown(socket.SHUT_WR)
        response = read_exact(connection, len(SENTINEL))
        if response != SENTINEL:
            raise RoutingClientError("socket sentinel response is not exact")
        return {
            "action": action,
            "case": case_id,
            "errno": None,
            "event": "socket-sentinel",
            "phase": "application-protocol",
            "response_sha256": hashlib.sha256(response).hexdigest(),
            "schema": "proofbound-runtime-routing-client-observation/1",
        }


def datagram_attempt(
    case_id: str,
    action: str,
    address: str,
    port: int,
    payload: bytes,
) -> dict[str, object]:
    """Attempt one exact DNS- or QUIC-shaped datagram."""

    try:
        channel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as error:
        return error_event(case_id, action, "socket", error)
    with channel:
        channel.settimeout(3)
        try:
            channel.sendto(payload, (address, port))
            response = channel.recv(MAX_RESPONSE_BYTES)
        except OSError as error:
            return error_event(case_id, action, "datagram", error)
        if response != SENTINEL:
            raise RoutingClientError("datagram sentinel response is not exact")
        return {
            "action": action,
            "case": case_id,
            "errno": None,
            "event": "datagram-sentinel",
            "phase": "application-protocol",
            "request_sha256": hashlib.sha256(payload).hexdigest(),
            "response_sha256": hashlib.sha256(response).hexdigest(),
            "schema": "proofbound-runtime-routing-client-observation/1",
        }


def bind_attempt(case_id: str, action: str, socket_type: int) -> dict[str, object]:
    """Attempt TCP listen or UDP bind while preserving the exact failure phase."""

    try:
        channel = socket.socket(socket.AF_INET, socket_type)
    except OSError as error:
        return error_event(case_id, action, "socket", error)
    with channel:
        try:
            channel.bind(("127.0.0.1", 0))
        except OSError as error:
            return error_event(case_id, action, "bind", error)
        if socket_type == socket.SOCK_STREAM:
            try:
                channel.listen(1)
            except OSError as error:
                return error_event(case_id, action, "listen", error)
        return {
            "action": action,
            "case": case_id,
            "errno": None,
            "event": "bind-succeeded",
            "phase": "listen" if socket_type == socket.SOCK_STREAM else "bind",
            "schema": "proofbound-runtime-routing-client-observation/1",
        }


def run(arguments: argparse.Namespace) -> dict[str, object]:
    """Execute one case without consulting its registered expectation."""

    case_id = arguments.case
    if case_id not in EXECUTABLE_CASES:
        raise RoutingClientError("routing client case is not executable")
    action = ROUTING_ACTIONS[case_id][0]
    allowed4 = exact_address(arguments.allowed_ipv4, 4)
    allowed6 = exact_address(arguments.allowed_ipv6, 6)
    denied4 = exact_address(arguments.denied_ipv4, 4)
    denied6 = exact_address(arguments.denied_ipv6, 6)
    if not 1 <= arguments.service_port <= 65535 or not 1 <= arguments.other_port <= 65535:
        raise RoutingClientError("routing client port is invalid")
    if not arguments.allowed_ca.is_absolute() or not arguments.allowed_ca.is_file():
        raise RoutingClientError("routing client trust root is invalid")

    if case_id == "exact-service-ipv4":
        return tls_request(case_id, action, socket.AF_INET, allowed4, arguments.service_port, arguments.allowed_ca)
    if case_id == "exact-service-ipv6":
        return tls_request(case_id, action, socket.AF_INET6, allowed6, arguments.service_port, arguments.allowed_ca)
    if case_id == "allowed-endpoint-wrong-certificate":
        return tls_request(case_id, action, socket.AF_INET, allowed4, arguments.service_port, arguments.allowed_ca)
    raw_targets = {
        "undeclared-service-ipv4-443": (socket.AF_INET, denied4),
        "undeclared-service-ipv6-443": (socket.AF_INET6, denied6),
        "literal-allowed-address": (socket.AF_INET, allowed4),
        "literal-undeclared-address": (socket.AF_INET, denied4),
        "alternate-endpoint-allowed-certificate": (socket.AF_INET, denied4),
        "ipv4-mapped-ipv6": (socket.AF_INET6, f"::ffff:{allowed4}"),
    }
    if case_id in raw_targets:
        family, address = raw_targets[case_id]
        return raw_routing_contact(case_id, action, family, address, arguments.service_port)
    if case_id == "direct-tcp-other-port":
        return socket_sentinel(case_id, action, allowed4, arguments.other_port)
    if case_id == "direct-udp-dns-shaped":
        return datagram_attempt(case_id, action, allowed4, arguments.other_port, DNS_PROBE)
    if case_id == "direct-udp-quic-shaped":
        return datagram_attempt(case_id, action, allowed4, arguments.other_port, QUIC_PROBE)
    if case_id == "tcp-bind-listen":
        return bind_attempt(case_id, action, socket.SOCK_STREAM)
    return bind_attempt(case_id, action, socket.SOCK_DGRAM)


def parser() -> argparse.ArgumentParser:
    """Build the closed direct-client interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--case", choices=EXECUTABLE_CASES, required=True)
    result.add_argument("--allowed-ipv4", required=True)
    result.add_argument("--allowed-ipv6", required=True)
    result.add_argument("--denied-ipv4", required=True)
    result.add_argument("--denied-ipv6", required=True)
    result.add_argument("--service-port", type=int, required=True)
    result.add_argument("--other-port", type=int, required=True)
    result.add_argument("--allowed-ca", type=Path, required=True)
    result.add_argument("--observation", type=Path, required=True)
    return result


def main() -> int:
    """Run one direct-network case and publish its raw observation once."""

    arguments = parser().parse_args()
    try:
        if not arguments.observation.is_absolute():
            raise RoutingClientError("routing client observation path is invalid")
        write_new(arguments.observation, canonical_json(run(arguments)))
        return 0
    except (OSError, RoutingClientError, ValueError) as error:
        print(f"routing transport client failed: {error}", file=sys.stderr)
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
