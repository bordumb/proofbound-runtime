#!/usr/bin/env python3
"""Closed resolver, redirect, and proxy client primitives for experiment 0001G."""

from __future__ import annotations

import hashlib
import socket
import ssl
import struct
from pathlib import Path

from experiments.network_authority.decision_http_fixture import script_exchange
from experiments.network_authority.decision_proxy_fixture import (
    DENIED_SENTINEL,
    HTTP_CONNECT_REQUEST,
    HTTP_CONNECT_RESPONSE,
    PROBE,
    SOCKS_CONNECT_REQUEST,
    SOCKS_CONNECT_RESPONSE,
    SOCKS_GREETING,
    SOCKS_METHOD,
)
from experiments.network_authority.scripted_dns import (
    FLAG_TC,
    MAX_PACKET_BYTES,
    DnsError,
    build_query,
    read_exact as dns_read_exact,
    validate_resolution,
)


MAX_APPLICATION_BYTES = 4096
DNS_REJECTION_CODES = {
    "DNS response size is invalid": "response-size",
    "DNS response header is outside the frozen grammar": "response-header",
    "unregistered DNSSEC assertion": "dnssec-flags",
    "DNS response question identity changed": "question-identity",
    "DNS response requires exact TCP fallback": "tcp-fallback-required",
    "truncated DNS response carried ambiguous data": "truncated-ambiguous",
    "DNS answer header is truncated": "answer-truncated",
    "DNS answer metadata is invalid": "answer-metadata",
    "DNS CNAME answer is ambiguous": "cname-ambiguous",
    "DNS address answer is ambiguous": "address-ambiguous",
    "DNS answer type is outside the query": "answer-type",
    "DNS response has trailing bytes": "trailing-bytes",
    "DNS CNAME is not allowed by policy": "cname-disallowed",
    "DNS CNAME chain loops or exceeds its bound": "cname-loop-or-depth",
    "DNS terminal service is undeclared": "terminal-service",
    "DNS answer inventory is not one exact chain": "answer-inventory",
    "DNS answer changed the registered endpoint": "terminal-address",
}


class IndirectionClientError(Exception):
    """A client input or peer transcript was outside the frozen grammar."""


def _read_to_close(channel: socket.socket, maximum: int) -> bytes:
    """Read one close-delimited response with an exact positive bound."""

    if not 1 <= maximum <= MAX_APPLICATION_BYTES:
        raise IndirectionClientError("application response bound is invalid")
    result = bytearray()
    while True:
        chunk = channel.recv(min(1024, maximum + 1 - len(result)))
        if not chunk:
            return bytes(result)
        result.extend(chunk)
        if len(result) > maximum:
            raise IndirectionClientError("application response exceeded its bound")


def _read_exact(channel: socket.socket, size: int) -> bytes:
    """Read one exact bounded application protocol field."""

    if not 1 <= size <= MAX_APPLICATION_BYTES:
        raise IndirectionClientError("application read size is invalid")
    result = bytearray()
    while len(result) < size:
        chunk = channel.recv(size - len(result))
        if not chunk:
            raise IndirectionClientError("application response is truncated")
        result.extend(chunk)
    return bytes(result)


def _dns_rejection(error: DnsError) -> str:
    """Map every accepted DNS parser diagnostic to one stable code."""

    try:
        return DNS_REJECTION_CODES[str(error)]
    except KeyError as missing:
        raise IndirectionClientError("DNS rejection diagnostic is unregistered") from missing


def resolve_once(
    server_ip: str,
    server_port: int,
    name: str,
    question_type: int,
    identifier: int,
    *,
    allow_cname: bool,
    require_declared: bool,
    allow_tcp_fallback: bool,
    timeout_seconds: float = 1.0,
) -> dict[str, object]:
    """Perform one exact UDP query and at most one registered TCP fallback."""

    if (
        server_ip != "127.0.0.1"
        or not 1 <= server_port <= 65535
        or not 0 < timeout_seconds <= 3
    ):
        raise IndirectionClientError("resolver endpoint or deadline is invalid")
    query = build_query(identifier, name, question_type)
    base: dict[str, object] = {
        "name": name,
        "query_hex": query.hex(),
        "query_sha256": hashlib.sha256(query).hexdigest(),
        "question_type": question_type,
        "schema": "proofbound-runtime-resolution-observation/1",
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            channel.settimeout(timeout_seconds)
            sent = channel.sendto(query, (server_ip, server_port))
            if sent != len(query):
                raise IndirectionClientError("DNS UDP query was truncated")
            response, peer = channel.recvfrom(MAX_PACKET_BYTES + 1)
    except socket.timeout:
        return {**base, "event": "resolver-rejected", "reason": "timeout", "responses": []}
    if peer != (server_ip, server_port) or len(response) > MAX_PACKET_BYTES:
        raise IndirectionClientError("DNS UDP response source or size is invalid")
    responses = [
        {
            "response_hex": response.hex(),
            "response_sha256": hashlib.sha256(response).hexdigest(),
            "transport": "udp",
        }
    ]
    truncated = len(response) >= 4 and bool(struct.unpack("!H", response[2:4])[0] & FLAG_TC)
    if truncated and allow_tcp_fallback:
        try:
            with socket.create_connection((server_ip, server_port), timeout_seconds) as channel:
                channel.settimeout(timeout_seconds)
                channel.sendall(struct.pack("!H", len(query)) + query)
                size = struct.unpack("!H", dns_read_exact(channel, 2))[0]
                if not 1 <= size <= MAX_PACKET_BYTES:
                    raise IndirectionClientError("DNS TCP response size is invalid")
                response = dns_read_exact(channel, size)
                if channel.recv(1) != b"":
                    raise IndirectionClientError("DNS TCP response has trailing framing")
        except socket.timeout:
            return {
                **base,
                "event": "resolver-rejected",
                "reason": "tcp-fallback-timeout",
                "responses": responses,
            }
        responses.append(
            {
                "response_hex": response.hex(),
                "response_sha256": hashlib.sha256(response).hexdigest(),
                "transport": "tcp",
            }
        )
    try:
        resolution = validate_resolution(
            query,
            response,
            allow_cname=allow_cname,
            require_declared=require_declared,
        )
    except DnsError as error:
        reason = (
            "malformed"
            if response == struct.pack("!H", identifier) + b"malformed"
            else _dns_rejection(error)
        )
        return {
            **base,
            "event": "resolver-rejected",
            "reason": reason,
            "responses": responses,
        }
    return {
        **base,
        "address": resolution.address,
        "cname_chain": list(resolution.cname_chain),
        "event": "resolved",
        "responses": responses,
        "terminal_name": resolution.terminal_name,
        "ttl": resolution.ttl,
    }


def _tls_channel(
    address: str, port: int, ca_certificate: Path, timeout_seconds: float
) -> ssl.SSLSocket:
    """Open the one TLS 1.3 channel authenticated as `allowed.test`."""

    if (
        address not in {"127.0.0.1", "127.0.0.2", "::1", "fd00::1", "fd00::2"}
        or not 1 <= port <= 65535
        or not ca_certificate.is_absolute()
        or not ca_certificate.is_file()
        or not 0 < timeout_seconds <= 3
    ):
        raise IndirectionClientError("TLS endpoint, trust root, or deadline is invalid")
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    connection = socket.socket(family, socket.SOCK_STREAM)
    connection.settimeout(timeout_seconds)
    try:
        connection.connect((address, port))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(ca_certificate))
        protected = context.wrap_socket(
            connection,
            server_hostname="allowed.test",
            suppress_ragged_eofs=False,
        )
        protected.settimeout(timeout_seconds)
        return protected
    except BaseException:
        connection.close()
        raise


def http_exchange(
    address: str,
    port: int,
    ca_certificate: Path,
    script: str,
    *,
    timeout_seconds: float = 2.0,
) -> dict[str, object]:
    """Perform one exact declared HTTP or redirect exchange."""

    request, expected, event = script_exchange(script)
    channel = _tls_channel(address, port, ca_certificate, timeout_seconds)
    try:
        channel.sendall(request)
        response = _read_exact(channel, len(expected))
        if response != expected:
            raise IndirectionClientError("HTTP response is not exact")
        raw_channel = channel.unwrap()
        raw_channel.close()
    finally:
        channel.close()
    head = response.partition(b"\r\n\r\n")[0]
    locations = [line[10:] for line in head.split(b"\r\n") if line.startswith(b"Location: ")]
    if (event.startswith("redirect-") and len(locations) != 1) or (
        not event.startswith("redirect-") and locations
    ):
        raise IndirectionClientError("HTTP redirect inventory is not exact")
    return {
        "event": event,
        "location": locations[0].decode("ascii") if locations else None,
        "request_sha256": hashlib.sha256(request).hexdigest(),
        "response_sha256": hashlib.sha256(response).hexdigest(),
        "schema": "proofbound-runtime-indirection-http-observation/1",
        "tls_version": "TLSv1.3",
    }


def proxy_exchange(
    address: str,
    port: int,
    ca_certificate: Path,
    protocol: str,
    *,
    timeout_seconds: float = 2.0,
) -> dict[str, object]:
    """Perform the exact CONNECT or SOCKS target-confusion transcript."""

    if protocol not in {"http-connect", "socks5"}:
        raise IndirectionClientError("proxy protocol is unknown")
    channel = _tls_channel(address, port, ca_certificate, timeout_seconds)
    try:
        if protocol == "http-connect":
            request = HTTP_CONNECT_REQUEST
            channel.sendall(request)
            if _read_exact(channel, len(HTTP_CONNECT_RESPONSE)) != HTTP_CONNECT_RESPONSE:
                raise IndirectionClientError("HTTP CONNECT response is not exact")
        else:
            request = SOCKS_CONNECT_REQUEST
            channel.sendall(SOCKS_GREETING)
            if _read_exact(channel, len(SOCKS_METHOD)) != SOCKS_METHOD:
                raise IndirectionClientError("SOCKS method is not exact")
            channel.sendall(request)
            if _read_exact(channel, len(SOCKS_CONNECT_RESPONSE)) != SOCKS_CONNECT_RESPONSE:
                raise IndirectionClientError("SOCKS connect response is not exact")
        channel.sendall(PROBE)
        sentinel = _read_exact(channel, len(DENIED_SENTINEL))
        if sentinel != DENIED_SENTINEL:
            raise IndirectionClientError("proxy sentinel is not exact")
        channel.sendall(b"\x00")
        raw_channel = channel.unwrap()
        raw_channel.close()
    finally:
        channel.close()
    return {
        "event": "proxy-target-reached",
        "protocol": protocol,
        "request_sha256": hashlib.sha256(request).hexdigest(),
        "schema": "proofbound-runtime-indirection-proxy-observation/1",
        "sentinel_sha256": hashlib.sha256(sentinel).hexdigest(),
        "target": "denied.test:443",
        "tls_version": "TLSv1.3",
    }
