#!/usr/bin/env python3
"""Boundary-executed network client for experiment 0001G."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import os
import socket
import struct
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

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
from experiments.network_authority.explicit_broker import MAX_FRAME_BYTES, wire_json
from experiments.network_authority.record_common import canonical_json, write_new
from experiments.network_authority.resolution_indirection_client import (
    http_exchange,
    proxy_exchange,
)


SCHEMA = "proofbound-runtime-resolution-network-observation/1"
ACTIONS = {
    "exact",
    "raw-contact",
    "redirect-host",
    "redirect-cleartext",
    "redirect-port",
    "proxy-http",
    "proxy-socks",
    "channel-redirect-host",
    "channel-redirect-cleartext",
    "channel-redirect-port",
    "channel-exact",
    "channel-proxy-http",
    "channel-proxy-socks",
    "broker-redirect-rejected",
    "broker-proxy-rejected",
    "broker-exact",
}
REDIRECT_TARGETS = {
    "redirect-host": ("127.0.0.2", 443),
    "redirect-cleartext": ("127.0.0.1", 80),
    "redirect-port": ("127.0.0.1", 8443),
}
BROKER_CODES = {
    "broker-redirect-rejected": "redirect-rejected",
    "broker-proxy-rejected": "proxy-target-rejected",
}


class ResolutionNetworkClientError(Exception):
    """A network action, local channel, or peer transcript was invalid."""


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise ResolutionNetworkClientError("channel write was short")
        view = view[written:]


def _read_exact(descriptor: int, size: int) -> bytes:
    if not 1 <= size <= MAX_FRAME_BYTES:
        raise ResolutionNetworkClientError("channel read bound is invalid")
    result = bytearray()
    while len(result) < size:
        chunk = os.read(descriptor, size - len(result))
        if not chunk:
            raise ResolutionNetworkClientError("channel response is truncated")
        result.extend(chunk)
    return bytes(result)


def _shutdown_write(descriptor: int) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.shutdown(descriptor, socket.SHUT_WR) != 0:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value))


def raw_contact(address: str, port: int) -> str:
    """Attempt one raw TCP contact and retain the native denial layer."""

    if address not in {"127.0.0.1", "127.0.0.2", "fd00::1", "fd00::2"} or not 1 <= port <= 65535:
        raise ResolutionNetworkClientError("raw target is outside the frozen topology")
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        channel = socket.socket(family, socket.SOCK_STREAM)
    except OSError as error:
        if error.errno == errno.EPERM:
            return "child-boundary-denied"
        raise
    with channel:
        channel.settimeout(2)
        try:
            channel.connect((address, port))
        except OSError as error:
            if error.errno in {errno.EPERM, errno.EACCES}:
                return "routing-denied"
            raise
        channel.sendall(b"not-tls\n")
        channel.shutdown(socket.SHUT_WR)
        return "undeclared-contact"


def _channel_http(descriptor: int, script: str) -> str:
    request, response, event = script_exchange(script)
    _write_all(descriptor, request)
    _shutdown_write(descriptor)
    if _read_exact(descriptor, len(response)) != response or os.read(descriptor, 1) != b"":
        raise ResolutionNetworkClientError("channel HTTP response is not exact")
    return event


def _channel_proxy(descriptor: int, protocol: str) -> str:
    if protocol == "http-connect":
        _write_all(descriptor, HTTP_CONNECT_REQUEST)
        if _read_exact(descriptor, len(HTTP_CONNECT_RESPONSE)) != HTTP_CONNECT_RESPONSE:
            raise ResolutionNetworkClientError("channel CONNECT response is not exact")
    elif protocol == "socks5":
        _write_all(descriptor, SOCKS_GREETING)
        if _read_exact(descriptor, len(SOCKS_METHOD)) != SOCKS_METHOD:
            raise ResolutionNetworkClientError("channel SOCKS method is not exact")
        _write_all(descriptor, SOCKS_CONNECT_REQUEST)
        if _read_exact(descriptor, len(SOCKS_CONNECT_RESPONSE)) != SOCKS_CONNECT_RESPONSE:
            raise ResolutionNetworkClientError("channel SOCKS response is not exact")
    else:
        raise ResolutionNetworkClientError("channel proxy protocol is unknown")
    _write_all(descriptor, PROBE)
    if _read_exact(descriptor, len(DENIED_SENTINEL)) != DENIED_SENTINEL:
        raise ResolutionNetworkClientError("channel proxy sentinel is not exact")
    _write_all(descriptor, b"\x00")
    _shutdown_write(descriptor)
    if os.read(descriptor, 1) != b"":
        raise ResolutionNetworkClientError("channel proxy response has trailing bytes")
    return "proxy-target-reached"


def _broker_rejection(descriptor: int, expected_code: str) -> str:
    value = {"operation": "echo", "payload": "bounded payload"}
    if expected_code == "proxy-target-rejected":
        value["target"] = "denied.test:443"
    request = wire_json(value)
    _write_all(descriptor, struct.pack(">I", len(request)) + request)
    _shutdown_write(descriptor)
    size = struct.unpack(">I", _read_exact(descriptor, 4))[0]
    response = _read_exact(descriptor, size)
    if os.read(descriptor, 1) != b"" or response != wire_json({"code": expected_code, "status": "error"}):
        raise ResolutionNetworkClientError("broker rejection is not exact")
    return "operation-rejected"


def _broker_exact(descriptor: int) -> str:
    request = wire_json({"operation": "echo", "payload": "bounded payload"})
    _write_all(descriptor, struct.pack(">I", len(request)) + request)
    _shutdown_write(descriptor)
    size = struct.unpack(">I", _read_exact(descriptor, 4))[0]
    response = _read_exact(descriptor, size)
    expected = wire_json({"payload": "bounded payload", "status": "ok"})
    if os.read(descriptor, 1) != b"" or response != expected:
        raise ResolutionNetworkClientError("broker success response is not exact")
    return "declared-response"


def execute(
    action: str,
    address: str,
    port: int,
    ca_certificate: Path,
    descriptor: int | None = None,
) -> list[str]:
    """Execute one closed action without consulting its expected outcome."""

    if action not in ACTIONS:
        raise ResolutionNetworkClientError("network action is unknown")
    if action.startswith("channel-") or action.startswith("broker-"):
        if descriptor is None or descriptor < 3:
            raise ResolutionNetworkClientError("channel action lacks its registered descriptor")
    elif descriptor is not None:
        raise ResolutionNetworkClientError("direct action received an ambient descriptor")

    if action == "exact":
        observation = http_exchange(address, port, ca_certificate, "exact")
        if observation["event"] != "exact-response":
            raise ResolutionNetworkClientError("exact service event changed")
        return ["declared-response"]
    if action == "raw-contact":
        return [raw_contact(address, port)]
    if action in REDIRECT_TARGETS:
        observation = http_exchange(address, port, ca_certificate, action)
        if observation["event"] != action:
            raise ResolutionNetworkClientError("redirect event changed")
        target_address, target_port = REDIRECT_TARGETS[action]
        return [action, raw_contact(target_address, target_port)]
    if action in {"proxy-http", "proxy-socks"}:
        protocol = "http-connect" if action == "proxy-http" else "socks5"
        observation = proxy_exchange(address, port, ca_certificate, protocol)
        if observation["event"] != "proxy-target-reached":
            raise ResolutionNetworkClientError("proxy event changed")
        return ["proxy-target-reached"]
    if action == "channel-exact":
        event = _channel_http(descriptor or -1, "exact")
        if event != "exact-response":
            raise ResolutionNetworkClientError("channel exact response changed")
        return ["declared-response"]
    if action.startswith("channel-redirect-"):
        script = action.removeprefix("channel-")
        event = _channel_http(descriptor or -1, script)
        target_address, target_port = REDIRECT_TARGETS[script]
        return [event, raw_contact(target_address, target_port)]
    if action in {"channel-proxy-http", "channel-proxy-socks"}:
        protocol = "http-connect" if action.endswith("http") else "socks5"
        return [_channel_proxy(descriptor or -1, protocol)]
    if action == "broker-exact":
        return [_broker_exact(descriptor or -1)]
    return [_broker_rejection(descriptor or -1, BROKER_CODES[action])]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--action", choices=sorted(ACTIONS), required=True)
    result.add_argument("--address", required=True)
    result.add_argument("--port", type=int, required=True)
    result.add_argument("--ca-certificate", type=Path, required=True)
    result.add_argument("--fd", type=int)
    result.add_argument("--started-file", type=Path, required=True)
    result.add_argument("--observation", type=Path, required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if (
            not arguments.started_file.is_absolute()
            or not arguments.observation.is_absolute()
            or arguments.started_file == arguments.observation
            or not arguments.ca_certificate.is_absolute()
        ):
            raise ResolutionNetworkClientError("network client paths are invalid")
        write_new(arguments.started_file, b"started\n")
        events = execute(
            arguments.action,
            arguments.address,
            arguments.port,
            arguments.ca_certificate,
            arguments.fd,
        )
        write_new(
            arguments.observation,
            canonical_json(
                {
                    "action": arguments.action,
                    "events": events,
                    "schema": SCHEMA,
                    "transcript_sha256": hashlib.sha256("\n".join(events).encode()).hexdigest(),
                }
            ),
        )
        return 0
    except (OSError, ResolutionNetworkClientError, ValueError) as error:
        print(f"resolution network client failed: {error}", file=sys.stderr)
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
