#!/usr/bin/env python3
"""Trusted explicit-operation mediator for experiment 0001G."""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.decision_http_fixture import script_exchange
from experiments.network_authority.explicit_broker import wire_json
from experiments.network_authority.record_common import canonical_json, write_new
from experiments.network_authority.routing_mediator import (
    exact_remote_exchange,
    open_authenticated,
    read_exact,
    read_frame,
    write_frame,
)


MODES = {"exact", "redirect-reject", "proxy-reject"}
SCHEMA = "proofbound-runtime-resolution-broker-observation/1"


class ResolutionBrokerError(Exception):
    """The broker request, remote response, or configuration was invalid."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ResolutionBrokerError("broker request contains duplicate names")
        result[key] = value
    return result


def decode_request(data: bytes, mode: str) -> None:
    """Require the one request shape registered for a mediator mode."""

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ResolutionBrokerError("broker request does not decode") from error
    expected: dict[str, object] = {"operation": "echo", "payload": "bounded payload"}
    if mode == "proxy-reject":
        expected["target"] = "denied.test:443"
    if value != expected or wire_json(value) != data:
        raise ResolutionBrokerError("broker request shape is not exact")


def _redirect_exchange(protected: ssl.SSLSocket, script: str) -> None:
    request, expected, _event = script_exchange(script)
    protected.sendall(request)
    response = read_exact(protected, len(expected))
    if response != expected:
        raise ResolutionBrokerError("broker redirect response is not exact")
    raw = protected.unwrap()
    raw.close()


def serve(
    descriptor: int,
    mode: str,
    address: str,
    port: int,
    ca_certificate: Path,
    redirect_script: str | None,
    marker_path: Path,
    session_path: Path,
) -> int:
    """Serve one explicit request and publish its trusted decision once."""

    if mode not in MODES:
        raise ResolutionBrokerError("broker mode is unknown")
    with socket.socket(fileno=descriptor) as channel:
        decode_request(read_frame(channel), mode)
        if mode == "proxy-reject":
            code = "proxy-target-rejected"
            write_new(marker_path, canonical_json({"code": code, "event": "rejected", "schema": SCHEMA}))
            write_frame(channel, wire_json({"code": code, "status": "error"}))
            return 0
        protected, session = open_authenticated(address, address, port, ca_certificate)
        write_new(session_path, canonical_json(session))
        if mode == "exact":
            exact_remote_exchange(protected)
            write_new(marker_path, canonical_json({"code": None, "event": "exact-response", "schema": SCHEMA}))
            write_frame(channel, wire_json({"payload": "bounded payload", "status": "ok"}))
            return 0
        if redirect_script not in {"redirect-host", "redirect-cleartext", "redirect-port"}:
            protected.close()
            raise ResolutionBrokerError("redirect script is invalid")
        _redirect_exchange(protected, redirect_script)
        code = "redirect-rejected"
        write_new(marker_path, canonical_json({"code": code, "event": "rejected", "schema": SCHEMA}))
        write_frame(channel, wire_json({"code": code, "status": "error"}))
        return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--fd", type=int, required=True)
    result.add_argument("--mode", choices=sorted(MODES), required=True)
    result.add_argument("--address", required=True)
    result.add_argument("--port", type=int, required=True)
    result.add_argument("--ca-certificate", type=Path, required=True)
    result.add_argument("--redirect-script")
    result.add_argument("--marker", type=Path, required=True)
    result.add_argument("--session-observation", type=Path, required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if (
            arguments.fd < 3
            or not arguments.ca_certificate.is_absolute()
            or not arguments.marker.is_absolute()
            or not arguments.session_observation.is_absolute()
            or arguments.marker == arguments.session_observation
        ):
            raise ResolutionBrokerError("broker paths or descriptor are invalid")
        return serve(
            arguments.fd,
            arguments.mode,
            arguments.address,
            arguments.port,
            arguments.ca_certificate,
            arguments.redirect_script,
            arguments.marker,
            arguments.session_observation,
        )
    except (OSError, ResolutionBrokerError, ssl.SSLError, ValueError) as error:
        print(f"resolution broker failed: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
