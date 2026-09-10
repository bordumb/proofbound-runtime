#!/usr/bin/env python3
"""Bounded socket targets for experiment 0001E bypass cases."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import socket
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.record_common import canonical_json, write_new


MAX_EXCHANGE_BYTES = 256
PROBE = b"proofbound-socket-bypass-probe\n"
SENTINEL = b"proofbound-socket-bypass-sentinel\n"
ABSTRACT_NAME = b"proofbound-runtime-decision-socket-v1"
SCRIPTS = {
    "tcp-connect",
    "udp-send",
    "pathname-unix",
    "abstract-unix",
}


class SocketFixtureError(Exception):
    """A socket target or exchange was outside the frozen fixture grammar."""


@dataclass(frozen=True)
class SocketFixtureConfig:
    """Closed configuration for one single-exchange socket target."""

    script: str
    bind_ip: str | None
    port: int | None
    unix_path: Path | None
    ready_file: Path
    observation_file: Path


def validate_config(config: SocketFixtureConfig) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Reject ambiguous, externally reachable, or noncanonical configurations."""

    if (
        config.script not in SCRIPTS
        or not config.ready_file.is_absolute()
        or not config.observation_file.is_absolute()
        or config.ready_file == config.observation_file
    ):
        raise SocketFixtureError("socket fixture configuration is invalid")
    if config.script in {"tcp-connect", "udp-send"}:
        if config.bind_ip is None or config.port is None or config.unix_path is not None:
            raise SocketFixtureError("network socket configuration is incomplete")
        try:
            address = ipaddress.ip_address(config.bind_ip)
        except ValueError as error:
            raise SocketFixtureError("network bind address is invalid") from error
        if not address.is_loopback or not 0 <= config.port <= 65535:
            raise SocketFixtureError("network socket must use a loopback address and valid port")
        return address
    if config.bind_ip is not None or config.port is not None:
        raise SocketFixtureError("Unix socket configuration includes network fields")
    if config.script == "pathname-unix":
        if (
            config.unix_path is None
            or not config.unix_path.is_absolute()
            or config.unix_path.exists()
            or len(os.fsencode(config.unix_path)) > 96
        ):
            raise SocketFixtureError("pathname Unix socket configuration is invalid")
        return None
    if config.unix_path is not None or not sys.platform.startswith("linux"):
        raise SocketFixtureError("abstract Unix sockets require Linux and no pathname")
    return None


def read_probe(channel: socket.socket) -> bytes:
    """Read exactly one bounded stream probe followed by write-half closure."""

    received = bytearray()
    while len(received) < len(PROBE):
        chunk = channel.recv(len(PROBE) - len(received))
        if not chunk:
            raise SocketFixtureError("socket probe is truncated")
        received.extend(chunk)
        if len(received) > MAX_EXCHANGE_BYTES:
            raise SocketFixtureError("socket probe exceeded its bound")
    probe = bytes(received)
    if probe != PROBE:
        raise SocketFixtureError("socket probe is not exact")
    if channel.recv(1) != b"":
        raise SocketFixtureError("socket probe has trailing bytes")
    return probe


def ready_document(
    config: SocketFixtureConfig,
    address: str,
    family: str,
    port: int | None,
) -> bytes:
    """Encode the exact endpoint needed by the attack client."""

    document: dict[str, object] = {
        "address": address,
        "family": family,
        "schema": "proofbound-runtime-decision-socket-ready/1",
        "script": config.script,
    }
    if port is not None:
        document["port"] = port
    return canonical_json(document)


def observation_document(config: SocketFixtureConfig, family: str) -> bytes:
    """Encode one successful, exact exchange without ambient peer identity."""

    return canonical_json(
        {
            "family": family,
            "probe_sha256": hashlib.sha256(PROBE).hexdigest(),
            "response_sha256": hashlib.sha256(SENTINEL).hexdigest(),
            "schema": "proofbound-runtime-decision-socket-observation/1",
            "script": config.script,
        }
    )


def serve_stream(
    listener: socket.socket,
    config: SocketFixtureConfig,
    address: str,
    family: str,
    port: int | None,
) -> None:
    """Publish readiness and complete one exact stream exchange."""

    listener.listen(1)
    listener.settimeout(8)
    write_new(config.ready_file, ready_document(config, address, family, port))
    connection, _peer = listener.accept()
    with connection:
        connection.settimeout(3)
        read_probe(connection)
        connection.sendall(SENTINEL)


def serve_socket_fixture(config: SocketFixtureConfig) -> int:
    """Serve one bounded target and publish an immutable observation."""

    parsed_address = validate_config(config)
    family_name: str
    if config.script == "tcp-connect":
        if parsed_address is None or config.port is None:
            raise SocketFixtureError("validated TCP configuration lost its endpoint")
        family = socket.AF_INET if parsed_address.version == 4 else socket.AF_INET6
        family_name = "ipv4" if parsed_address.version == 4 else "ipv6"
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((str(parsed_address), config.port))
            actual_port = listener.getsockname()[1]
            serve_stream(listener, config, str(parsed_address), family_name, actual_port)
    elif config.script == "udp-send":
        if parsed_address is None or config.port is None:
            raise SocketFixtureError("validated UDP configuration lost its endpoint")
        family = socket.AF_INET if parsed_address.version == 4 else socket.AF_INET6
        family_name = "ipv4" if parsed_address.version == 4 else "ipv6"
        with socket.socket(family, socket.SOCK_DGRAM) as target:
            target.bind((str(parsed_address), config.port))
            target.settimeout(8)
            actual_port = target.getsockname()[1]
            write_new(
                config.ready_file,
                ready_document(config, str(parsed_address), family_name, actual_port),
            )
            probe, peer = target.recvfrom(MAX_EXCHANGE_BYTES + 1)
            if probe != PROBE:
                raise SocketFixtureError("datagram probe is not exact")
            target.sendto(SENTINEL, peer)
    elif config.script == "pathname-unix":
        if config.unix_path is None:
            raise SocketFixtureError("validated pathname configuration lost its path")
        family_name = "unix-pathname"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(config.unix_path))
                serve_stream(
                    listener,
                    config,
                    str(config.unix_path),
                    family_name,
                    None,
                )
        finally:
            config.unix_path.unlink(missing_ok=True)
    else:
        family_name = "unix-abstract"
        abstract_address = b"\x00" + ABSTRACT_NAME
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(abstract_address)
            serve_stream(
                listener,
                config,
                "@" + ABSTRACT_NAME.decode("ascii"),
                family_name,
                None,
            )
    write_new(config.observation_file, observation_document(config, family_name))
    return 0


def parser() -> argparse.ArgumentParser:
    """Build the fixture's closed command interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--script", choices=sorted(SCRIPTS), required=True)
    result.add_argument("--bind-ip")
    result.add_argument("--port", type=int)
    result.add_argument("--unix-path", type=Path)
    result.add_argument("--ready-file", type=Path, required=True)
    result.add_argument("--observation-file", type=Path, required=True)
    return result


def main() -> int:
    """Run one bounded socket target."""

    arguments = parser().parse_args()
    config = SocketFixtureConfig(
        script=arguments.script,
        bind_ip=arguments.bind_ip,
        port=arguments.port,
        unix_path=arguments.unix_path,
        ready_file=arguments.ready_file,
        observation_file=arguments.observation_file,
    )
    try:
        return serve_socket_fixture(config)
    except (OSError, SocketFixtureError, ValueError) as error:
        print(f"decision socket fixture failed: {error}", file=sys.stderr)
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
