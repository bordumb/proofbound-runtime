#!/usr/bin/env python3
"""Strict deterministic DNS transcripts for network decision experiments."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass


TYPE_A = 1
TYPE_CNAME = 5
TYPE_AAAA = 28
CLASS_IN = 1
FLAG_QR = 0x8000
FLAG_AA = 0x0400
FLAG_TC = 0x0200
FLAG_RD = 0x0100
FLAG_AD = 0x0020
ALLOWED_IPV4 = ipaddress.IPv4Address("127.0.0.1")
DENIED_IPV4 = ipaddress.IPv4Address("127.0.0.2")
ALLOWED_IPV6 = ipaddress.IPv6Address("fd00::1")
DENIED_IPV6 = ipaddress.IPv6Address("fd00::2")
TTL = 1
MAX_PACKET_BYTES = 512
SCRIPTS = {
    "stable",
    "rebind",
    "cname-allowed",
    "cname-denied",
    "cname-loop",
    "truncated-fallback",
    "malformed",
    "dnssec-confusion",
    "timeout",
}


class DnsError(Exception):
    """A DNS message or script value is outside the frozen grammar."""


@dataclass(frozen=True)
class Query:
    """One exact Internet-class A or AAAA question."""

    identifier: int
    name: str
    question_type: int
    recursion_desired: bool
    question_bytes: bytes


@dataclass(frozen=True)
class Resolution:
    """One validated declared-service resolution observation."""

    address: str
    cname_chain: tuple[str, ...]
    question_type: int
    ttl: int


def encode_name(name: str) -> bytes:
    """Encode one canonical lower-case absolute DNS name."""

    if not name or name.endswith(".") or name.lower() != name:
        raise DnsError("DNS name is not canonical")
    result = bytearray()
    labels = name.split(".")
    for label in labels:
        try:
            encoded = label.encode("ascii")
        except UnicodeEncodeError as error:
            raise DnsError("DNS label is not ASCII") from error
        if (
            not encoded
            or len(encoded) > 63
            or encoded[0] == ord("-")
            or encoded[-1] == ord("-")
            or any(
                not (
                    ord("a") <= byte <= ord("z")
                    or ord("0") <= byte <= ord("9")
                    or byte == ord("-")
                )
                for byte in encoded
            )
        ):
            raise DnsError("DNS label is outside the experiment grammar")
        result.append(len(encoded))
        result.extend(encoded)
    result.append(0)
    if len(result) > 255:
        raise DnsError("DNS name exceeds its wire bound")
    return bytes(result)


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode one uncompressed canonical question name."""

    labels = []
    start = offset
    while True:
        if offset >= len(data):
            raise DnsError("DNS name is truncated")
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or length > 63 or offset + length > len(data):
            raise DnsError("DNS question name encoding is invalid")
        try:
            label = data[offset : offset + length].decode("ascii")
        except UnicodeDecodeError as error:
            raise DnsError("DNS question label is not ASCII") from error
        labels.append(label)
        offset += length
    name = ".".join(labels)
    if encode_name(name) != data[start:offset]:
        raise DnsError("DNS question name is not canonical")
    return name, offset


def decode_owner(data: bytes, offset: int, question_name: str) -> tuple[str, int]:
    """Decode the one allowed question pointer or a canonical full owner."""

    if data[offset : offset + 2] == b"\xc0\x0c":
        return question_name, offset + 2
    return decode_name(data, offset)


def parse_query(data: bytes) -> Query:
    """Parse one closed standard query without extension records."""

    if len(data) < 12 or len(data) > MAX_PACKET_BYTES:
        raise DnsError("DNS query size is invalid")
    identifier, flags, questions, answers, authorities, additionals = struct.unpack(
        "!HHHHHH", data[:12]
    )
    if (
        identifier == 0
        or flags & ~FLAG_RD
        or questions != 1
        or answers != 0
        or authorities != 0
        or additionals != 0
    ):
        raise DnsError("DNS query header is outside the frozen grammar")
    name, offset = decode_name(data, 12)
    if offset + 4 != len(data):
        raise DnsError("DNS question has trailing or missing fields")
    question_type, question_class = struct.unpack("!HH", data[offset:])
    if question_type not in {TYPE_A, TYPE_AAAA} or question_class != CLASS_IN:
        raise DnsError("DNS question type or class is unsupported")
    return Query(
        identifier=identifier,
        name=name,
        question_type=question_type,
        recursion_desired=bool(flags & FLAG_RD),
        question_bytes=data[12:],
    )


def build_query(identifier: int, name: str, question_type: int) -> bytes:
    """Build one canonical recursive test query."""

    if not 1 <= identifier <= 65535 or question_type not in {TYPE_A, TYPE_AAAA}:
        raise DnsError("DNS query input is invalid")
    return (
        struct.pack("!HHHHHH", identifier, FLAG_RD, 1, 0, 0, 0)
        + encode_name(name)
        + struct.pack("!HH", question_type, CLASS_IN)
    )


def resource_record(record_type: int, value: str, owner: str | None = None) -> bytes:
    """Encode one answer for the question name or one exact CNAME target."""

    if record_type == TYPE_A:
        payload = ipaddress.IPv4Address(value).packed
    elif record_type == TYPE_AAAA:
        payload = ipaddress.IPv6Address(value).packed
    elif record_type == TYPE_CNAME:
        payload = encode_name(value)
    else:
        raise DnsError("DNS answer type is unsupported")
    return (
        (b"\xc0\x0c" if owner is None else encode_name(owner))
        + struct.pack("!HHIH", record_type, CLASS_IN, TTL, len(payload))
        + payload
    )


def address_record(
    question_type: int, allowed: bool, owner: str | None = None
) -> bytes:
    """Return the registered address answer for one family."""

    if question_type == TYPE_A:
        value = ALLOWED_IPV4 if allowed else DENIED_IPV4
    elif question_type == TYPE_AAAA:
        value = ALLOWED_IPV6 if allowed else DENIED_IPV6
    else:
        raise DnsError("DNS address family is unsupported")
    return resource_record(question_type, str(value), owner)


def response_for(
    query_data: bytes, script: str, ordinal: int, transport: str
) -> bytes | None:
    """Produce one deterministic scripted response or an exact timeout."""

    query = parse_query(query_data)
    if script not in SCRIPTS or ordinal < 0 or transport not in {"udp", "tcp"}:
        raise DnsError("DNS script invocation is invalid")
    if script == "timeout":
        return None
    if script == "malformed":
        return struct.pack("!H", query.identifier) + b"malformed"

    flags = FLAG_QR | FLAG_AA | (FLAG_RD if query.recursion_desired else 0)
    answers = []
    if script == "truncated-fallback" and transport == "udp":
        flags |= FLAG_TC
    elif script == "dnssec-confusion":
        flags |= FLAG_AD
        answers.append(address_record(query.question_type, True))
    elif script == "stable" or script == "truncated-fallback":
        answers.append(address_record(query.question_type, True))
    elif script == "rebind":
        answers.append(address_record(query.question_type, ordinal == 0))
    elif script == "cname-allowed":
        answers.extend(
            [
                resource_record(TYPE_CNAME, "allowed.test"),
                address_record(query.question_type, True, "allowed.test"),
            ]
        )
    elif script == "cname-denied":
        answers.extend(
            [
                resource_record(TYPE_CNAME, "denied.test"),
                address_record(query.question_type, False, "denied.test"),
            ]
        )
    elif script == "cname-loop":
        answers.extend(
            [
                resource_record(TYPE_CNAME, "loop.test"),
                resource_record(TYPE_CNAME, query.name, "loop.test"),
            ]
        )
    else:
        raise DnsError("DNS script is incomplete")
    response = (
        struct.pack("!HHHHHH", query.identifier, flags, 1, len(answers), 0, 0)
        + query.question_bytes
        + b"".join(answers)
    )
    if len(response) > MAX_PACKET_BYTES:
        raise DnsError("DNS response exceeded its packet bound")
    return response


def validate_resolution(
    query_data: bytes,
    response_data: bytes,
    *,
    allow_cname: bool,
) -> Resolution:
    """Validate one response as the frozen `allowed.test` resolution."""

    query = parse_query(query_data)
    if len(response_data) < 12 or len(response_data) > MAX_PACKET_BYTES:
        raise DnsError("DNS response size is invalid")
    identifier, flags, questions, answers, authorities, additionals = struct.unpack(
        "!HHHHHH", response_data[:12]
    )
    allowed_flags = FLAG_QR | FLAG_AA | FLAG_RD | FLAG_TC | FLAG_AD
    if (
        identifier != query.identifier
        or flags & ~allowed_flags
        or not flags & FLAG_QR
        or not flags & FLAG_AA
        or bool(flags & FLAG_RD) != query.recursion_desired
        or questions != 1
        or authorities != 0
        or additionals != 0
    ):
        raise DnsError("DNS response header is outside the frozen grammar")
    if flags & FLAG_AD:
        raise DnsError("unregistered DNSSEC assertion")
    question_end = 12 + len(query.question_bytes)
    if response_data[12:question_end] != query.question_bytes:
        raise DnsError("DNS response question identity changed")
    if flags & FLAG_TC:
        if answers != 0 or question_end != len(response_data):
            raise DnsError("truncated DNS response carried ambiguous data")
        raise DnsError("DNS response requires exact TCP fallback")

    offset = question_end
    cnames: dict[str, str] = {}
    addresses: dict[str, str] = {}
    record_count = 0
    while record_count < answers:
        owner, offset = decode_owner(response_data, offset, query.name)
        if offset + 10 > len(response_data):
            raise DnsError("DNS answer header is truncated")
        record_type, record_class, ttl, size = struct.unpack(
            "!HHIH", response_data[offset : offset + 10]
        )
        offset += 10
        if (
            record_class != CLASS_IN
            or ttl != TTL
            or offset + size > len(response_data)
        ):
            raise DnsError("DNS answer metadata is invalid")
        payload = response_data[offset : offset + size]
        offset += size
        if record_type == TYPE_CNAME:
            target, consumed = decode_name(payload, 0)
            if consumed != len(payload) or owner in cnames or owner in addresses:
                raise DnsError("DNS CNAME answer is ambiguous")
            cnames[owner] = target
        elif record_type == query.question_type:
            expected_size = 4 if record_type == TYPE_A else 16
            if size != expected_size or owner in addresses or owner in cnames:
                raise DnsError("DNS address answer is ambiguous")
            addresses[owner] = str(ipaddress.ip_address(payload))
        else:
            raise DnsError("DNS answer type is outside the query")
        record_count += 1
    if offset != len(response_data):
        raise DnsError("DNS response has trailing bytes")

    chain = [query.name]
    current = query.name
    while current in cnames:
        if not allow_cname:
            raise DnsError("DNS CNAME is not allowed by policy")
        current = cnames[current]
        if current in chain or len(chain) >= 4:
            raise DnsError("DNS CNAME chain loops or exceeds its bound")
        chain.append(current)
    if current != "allowed.test":
        raise DnsError("DNS terminal service is undeclared")
    if set(cnames) != set(chain[:-1]) or set(addresses) != {current}:
        raise DnsError("DNS answer inventory is not one exact chain")
    expected_address = ALLOWED_IPV4 if query.question_type == TYPE_A else ALLOWED_IPV6
    if addresses[current] != str(expected_address):
        raise DnsError("DNS answer changed the registered endpoint")
    return Resolution(
        address=addresses[current],
        cname_chain=tuple(chain),
        question_type=query.question_type,
        ttl=TTL,
    )
