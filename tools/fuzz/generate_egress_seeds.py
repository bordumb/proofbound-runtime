#!/usr/bin/env python3
"""Reproduce the retained raw-input corpus for the egress parser fuzz targets."""

from pathlib import Path


ROOT = Path(__file__).resolve().parent / "corpus"


def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def record(payload: bytes) -> bytes:
    return b"\x16\x03\x01" + u16(len(payload)) + payload


def hello(name: bytes) -> bytes:
    names = u16(len(name) + 3) + b"\x00" + u16(len(name)) + name
    extension = b"\x00\x00" + u16(len(names)) + names
    body = (
        b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01"
        + b"\x01\x00" + u16(len(extension)) + extension
    )
    return b"\x01" + len(body).to_bytes(3, "big") + body


def main() -> None:
    connect = {
        "valid": b"CONNECT api.example:443 HTTP/1.1\r\n\r\n",
        "noncanonical": b"CONNECT 127.0.00.1:443 HTTP/1.1\r\n\r\n",
        "malformed": b"CONNECT api.example:443 HTTP/9.9\r\n\r\n",
        "incomplete": b"CONNECT api.example:443 HTTP/1.1\r\n",
        "oversized": b"CONNECT api.example:443 HTTP/1.1\r\nX-Fill: "
        + b"a" * 8192 + b"\r\n\r\n",
    }
    handshake = hello(b"API.EXAMPLE")
    client_hello = {
        "valid": record(handshake),
        "split-records": record(handshake[:8]) + record(handshake[8:]),
        "truncated": record(handshake)[:-1],
        "wrong-content-type": b"\x17" + record(handshake)[1:],
    }
    for name, data in connect.items():
        path = ROOT / "connect" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    for name, data in client_hello.items():
        path = ROOT / "client-hello" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


if __name__ == "__main__":
    main()
