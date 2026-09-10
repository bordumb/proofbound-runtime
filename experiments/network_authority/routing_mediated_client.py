#!/usr/bin/env python3
"""Untrusted channel client for experiment 0001F mechanisms C and D."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
import socket
import struct
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.explicit_broker import MAX_FRAME_BYTES, wire_json
from experiments.network_authority.record_common import canonical_json, write_new
from experiments.network_authority.routing_transport_case import ROUTING_ACTIONS
from experiments.network_authority.routing_transport_client import (
    bind_attempt,
    datagram_attempt,
    socket_sentinel,
)


EXCLUDED_CASES = {"non-scoped-ipv6-scope-id", "alternate-address-text"}
EXECUTABLE_CASES = tuple(case for case in ROUTING_ACTIONS if case not in EXCLUDED_CASES)
DIRECT_CASES = {
    "direct-tcp-other-port",
    "direct-udp-dns-shaped",
    "direct-udp-quic-shaped",
    "tcp-bind-listen",
    "udp-bind",
}
TARGET_CASES = {
    "undeclared-service-ipv4-443": "127.0.0.2",
    "undeclared-service-ipv6-443": "fd00::2",
    "literal-allowed-address": "127.0.0.1",
    "literal-undeclared-address": "127.0.0.2",
}
ERROR_CODES = {
    **{case: "target-field-rejected" for case in TARGET_CASES},
    "allowed-endpoint-wrong-certificate": "certificate-rejected",
    "alternate-endpoint-allowed-certificate": "connector-endpoint-mismatch",
}
ALLOWED_REQUEST = wire_json({"operation": "echo", "payload": "bounded payload"})
ALLOWED_RESPONSE = wire_json({"payload": "bounded payload", "status": "ok"})


class MediatedClientError(Exception):
    """The retained channel or response was outside the closed grammar."""


def write_all(descriptor: int, data: bytes) -> None:
    """Write all frame bytes through the retained descriptor."""

    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise MediatedClientError("mediated request write was short")
        view = view[written:]


def read_exact(descriptor: int, size: int) -> bytes:
    """Read exactly one positive bounded size."""

    if not 1 <= size <= MAX_FRAME_BYTES:
        raise MediatedClientError("mediated response size is invalid")
    result = bytearray()
    while len(result) < size:
        chunk = os.read(descriptor, size - len(result))
        if not chunk:
            raise MediatedClientError("mediated response is truncated")
        result.extend(chunk)
    return bytes(result)


def exchange(descriptor: int, payload: bytes) -> bytes:
    """Exchange one length-delimited request and response."""

    if not payload or len(payload) > MAX_FRAME_BYTES:
        raise MediatedClientError("mediated request size is invalid")
    write_all(descriptor, struct.pack(">I", len(payload)) + payload)
    library = ctypes.CDLL(None, use_errno=True)
    if library.shutdown(descriptor, socket.SHUT_WR) != 0:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value))
    size = struct.unpack(">I", read_exact(descriptor, 4))[0]
    response = read_exact(descriptor, size)
    if os.read(descriptor, 1) != b"":
        raise MediatedClientError("mediated response has trailing bytes")
    return response


def request_for_case(case_id: str) -> bytes:
    """Return one exact child-visible request without target canonicalization."""

    if case_id in TARGET_CASES:
        return wire_json(
            {
                "operation": "echo",
                "payload": "bounded payload",
                "target": TARGET_CASES[case_id],
            }
        )
    if case_id in EXECUTABLE_CASES and case_id not in DIRECT_CASES:
        return ALLOWED_REQUEST
    raise MediatedClientError("routing case has no mediated request")


def observation(
    case_id: str, event: str, *, response: bytes, code: str | None = None
) -> dict[str, object]:
    """Build one closed child observation from exact received bytes."""

    result: dict[str, object] = {
        "action": ROUTING_ACTIONS[case_id][0],
        "case": case_id,
        "errno": None,
        "event": event,
        "phase": "application-protocol",
        "schema": "proofbound-runtime-routing-client-observation/1",
    }
    if event == "mediated-response":
        result["response_sha256"] = hashlib.sha256(response).hexdigest()
    elif event == "mediator-rejected" and code is not None:
        result["code"] = code
    else:
        raise MediatedClientError("mediated observation event is invalid")
    return result


def run(case_id: str, descriptor: int) -> dict[str, object]:
    """Run one child action without interpreting trusted mediator state."""

    action = ROUTING_ACTIONS[case_id][0]
    if case_id == "direct-tcp-other-port":
        return socket_sentinel(case_id, action, "127.0.0.1", 8443)
    if case_id == "direct-udp-dns-shaped":
        from experiments.network_authority.decision_socket_fixture import DNS_PROBE

        return datagram_attempt(case_id, action, "127.0.0.1", 8443, DNS_PROBE)
    if case_id == "direct-udp-quic-shaped":
        from experiments.network_authority.decision_socket_fixture import QUIC_PROBE

        return datagram_attempt(case_id, action, "127.0.0.1", 8443, QUIC_PROBE)
    if case_id == "tcp-bind-listen":
        return bind_attempt(case_id, action, socket.SOCK_STREAM)
    if case_id == "udp-bind":
        return bind_attempt(case_id, action, socket.SOCK_DGRAM)

    response = exchange(descriptor, request_for_case(case_id))
    if case_id in {"exact-service-ipv4", "exact-service-ipv6"}:
        if response != ALLOWED_RESPONSE:
            raise MediatedClientError("mediated success response is not exact")
        return observation(case_id, "mediated-response", response=response)
    code = ERROR_CODES.get(case_id)
    expected = wire_json({"code": code, "status": "error"})
    if code is None or response != expected:
        raise MediatedClientError("mediated rejection response is not exact")
    return observation(case_id, "mediator-rejected", response=response, code=code)


def parser() -> argparse.ArgumentParser:
    """Build the closed mediated-client interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--case", choices=EXECUTABLE_CASES, required=True)
    result.add_argument("--fd", type=int, required=True)
    result.add_argument("--started-file", type=Path, required=True)
    result.add_argument("--observation", type=Path, required=True)
    return result


def main() -> int:
    """Publish child start and its exact raw observation once."""

    arguments = parser().parse_args()
    try:
        if (
            arguments.fd < 3
            or not arguments.started_file.is_absolute()
            or not arguments.observation.is_absolute()
            or arguments.started_file == arguments.observation
        ):
            raise MediatedClientError("mediated client arguments are invalid")
        write_new(arguments.started_file, b"started\n")
        write_new(arguments.observation, canonical_json(run(arguments.case, arguments.fd)))
        return 0
    except (MediatedClientError, OSError, ValueError) as error:
        print(f"routing mediated client failed: {error}", file=sys.stderr)
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
