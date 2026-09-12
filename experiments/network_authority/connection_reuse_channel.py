#!/usr/bin/env python3
"""One-use broker/channel protocols for experiment 0001H."""

from __future__ import annotations

import errno
import os
import socket
import struct

from experiments.network_authority.connection_reuse_fixture import PROBE, SENTINEL, _read, _write
from experiments.network_authority.explicit_broker import wire_json


REQUEST = wire_json({"operation": "echo", "payload": "bounded payload"})
RESPONSE = wire_json({"payload": "bounded payload", "status": "ok"})
REJECTED = wire_json({"code": "connection-count-exceeded", "status": "error"})


def _frame(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _read_frame(descriptor: int) -> bytes:
    size = struct.unpack(">I", _read(descriptor, 4))[0]
    if not 1 <= size <= 4096:
        raise ValueError("reuse frame size is invalid")
    return _read(descriptor, size)


def broker_server(descriptor: int) -> list[str]:
    try:
        if _read_frame(descriptor) != REQUEST:
            raise ValueError("first broker request changed")
        _write(descriptor, _frame(RESPONSE))
        if _read_frame(descriptor) != REQUEST:
            raise ValueError("second broker request changed")
        _write(descriptor, _frame(REJECTED))
        return ["registered-exchange", "operation-rejected"]
    finally:
        os.close(descriptor)


def broker_client(descriptor: int) -> list[str]:
    _write(descriptor, _frame(REQUEST))
    if _read_frame(descriptor) != RESPONSE:
        raise ValueError("first broker response changed")
    _write(descriptor, _frame(REQUEST))
    if _read_frame(descriptor) != REJECTED:
        raise ValueError("second broker response changed")
    return ["registered-exchange", "operation-rejected"]


def channel_server(descriptor: int) -> list[str]:
    if _read(descriptor, len(PROBE)) != PROBE:
        raise ValueError("first channel request changed")
    _write(descriptor, SENTINEL)
    os.close(descriptor)
    return ["registered-exchange", "channel-closed-after-registered-exchange"]


def channel_client(descriptor: int) -> list[str]:
    _write(descriptor, PROBE)
    if _read(descriptor, len(SENTINEL)) != SENTINEL:
        raise ValueError("first channel response changed")
    try:
        _write(descriptor, PROBE)
    except OSError as error:
        if error.errno not in {errno.EPIPE, errno.ECONNRESET}:
            raise
    else:
        try:
            if os.read(descriptor, 1) != b"":
                raise ValueError("closed channel returned bytes")
        except OSError as error:
            if error.errno != errno.ECONNRESET:
                raise
    return ["registered-exchange", "channel-closed-after-registered-exchange"]
