"""Small independent decoder for the version 2 CBOR conformance vectors.

This module deliberately has no dependency on a Runtime crate or on the
eventual producer codec. It implements only the closed CBOR subset admitted by
ADR 0003 and fails on every representation excluded by RFC 8949 section 4.2.1.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class CborError(ValueError):
    """The input is not one complete admitted deterministic-CBOR item."""


@dataclass
class _Decoder:
    data: bytes
    max_depth: int
    max_items: int
    offset: int = 0
    items: int = 0

    def take(self, length: int) -> bytes:
        end = self.offset + length
        if length < 0 or end > len(self.data):
            raise CborError("truncated item")
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        if additional == 24:
            value = self.take(1)[0]
            if value < 24:
                raise CborError("non-shortest argument")
            return value
        widths = {25: 2, 26: 4, 27: 8}
        width = widths.get(additional)
        if width is None:
            if additional == 31:
                raise CborError("indefinite length")
            raise CborError("reserved additional information")
        value = int.from_bytes(self.take(width), "big")
        minimum = {2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[width]
        if value < minimum:
            raise CborError("non-shortest argument")
        return value

    def item(self, depth: int = 0) -> Any:
        if depth > self.max_depth:
            raise CborError("nesting limit exceeded")
        self.items += 1
        if self.items > self.max_items:
            raise CborError("item limit exceeded")
        if self.offset >= len(self.data):
            raise CborError("missing item")

        initial = self.take(1)[0]
        major = initial >> 5
        additional = initial & 0x1F

        if major == 7:
            if additional == 20:
                return False
            if additional == 21:
                return True
            if additional == 22:
                return None
            raise CborError("unadmitted simple or floating-point value")

        argument = self.argument(additional)
        if major == 0:
            return argument
        if major == 1:
            return -1 - argument
        if major == 2:
            return self.take(argument)
        if major == 3:
            try:
                return self.take(argument).decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise CborError("invalid UTF-8 text") from error
        if major == 4:
            return [self.item(depth + 1) for _ in range(argument)]
        if major == 5:
            result: dict[str, Any] = {}
            previous_encoding: bytes | None = None
            for _ in range(argument):
                key_start = self.offset
                key = self.item(depth + 1)
                key_encoding = self.data[key_start : self.offset]
                if not isinstance(key, str):
                    raise CborError("map key is not text")
                if previous_encoding is not None and key_encoding <= previous_encoding:
                    raise CborError("map keys are duplicated or out of order")
                previous_encoding = key_encoding
                result[key] = self.item(depth + 1)
            return result
        if major == 6:
            raise CborError("tag is not admitted")
        raise CborError("unknown major type")


def decode_strict(
    data: bytes, *, max_bytes: int = 16 * 1024 * 1024, max_depth: int = 128,
    max_items: int = 1_000_000
) -> Any:
    """Decode exactly one deterministic item from the admitted CBOR subset."""

    if not data or len(data) > max_bytes:
        raise CborError("input size is outside the decoder bounds")
    decoder = _Decoder(data=data, max_depth=max_depth, max_items=max_items)
    value = decoder.item()
    if decoder.offset != len(data):
        raise CborError("trailing bytes")
    return value


def json_projection(value: Any, path: tuple[str, ...] = ()) -> Any:
    """Return the golden-vector JSON projection; never committed or verified."""

    if isinstance(value, bytes):
        return f"hex:{value.hex()}"
    if type(value) is int and decimal_projection_path(path):
        return str(value)
    if isinstance(value, list):
        return [json_projection(entry, path) for entry in value]
    if isinstance(value, dict):
        return {
            key: json_projection(entry, (*path, key)) for key, entry in value.items()
        }
    return value


def decimal_projection_path(path: tuple[str, ...]) -> bool:
    """Identify CBOR integers rendered as exact decimal strings in JSON views."""

    if not path:
        return False
    field = path[-1]
    return field in {
        "size",
        "size_bytes",
        "inode",
        "mount_id",
        "started_ns",
        "finished_ns",
        "memory_bytes",
        "swap_bytes",
        "stdout_bytes",
        "stderr_bytes",
        "memory.max",
        "memory.swap.max",
        "memory_peak_bytes",
        "swap_peak_bytes",
    } or any(parent in {"memory_events", "swap_events"} for parent in path)
