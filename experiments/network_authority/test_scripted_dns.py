"""Falsifiers for deterministic DNS decision transcripts."""

from __future__ import annotations

import struct
import unittest

from experiments.network_authority.scripted_dns import (
    FLAG_AD,
    FLAG_TC,
    TYPE_A,
    TYPE_AAAA,
    DnsError,
    build_query,
    parse_query,
    response_for,
)


class ScriptedDnsTests(unittest.TestCase):
    def test_query_round_trip_is_closed(self) -> None:
        for question_type in (TYPE_A, TYPE_AAAA):
            wire = build_query(17, "allowed.test", question_type)
            query = parse_query(wire)
            self.assertEqual(query.identifier, 17)
            self.assertEqual(query.name, "allowed.test")
            self.assertEqual(query.question_type, question_type)
            self.assertTrue(query.recursion_desired)
        with self.assertRaises(DnsError):
            parse_query(build_query(17, "allowed.test", TYPE_A) + b"x")
        with self.assertRaises(DnsError):
            build_query(1, "Allowed.test", TYPE_A)

    def test_stable_and_rebind_answers_are_distinct_and_repeatable(self) -> None:
        query = build_query(19, "allowed.test", TYPE_A)
        stable = response_for(query, "stable", 0, "udp")
        self.assertEqual(stable, response_for(query, "stable", 0, "udp"))
        first = response_for(query, "rebind", 0, "udp")
        second = response_for(query, "rebind", 1, "udp")
        self.assertNotEqual(first, second)
        self.assertIn(b"\x7f\x00\x00\x01", first or b"")
        self.assertIn(b"\x7f\x00\x00\x02", second or b"")

    def test_cname_scripts_bind_declared_denied_and_loop_targets(self) -> None:
        query = build_query(23, "alias.test", TYPE_AAAA)
        allowed = response_for(query, "cname-allowed", 0, "tcp") or b""
        denied = response_for(query, "cname-denied", 0, "tcp") or b""
        looped = response_for(query, "cname-loop", 0, "tcp") or b""
        self.assertEqual(allowed.count(b"\x07allowed\x04test\x00"), 2)
        self.assertEqual(denied.count(b"\x06denied\x04test\x00"), 2)
        self.assertEqual(looped.count(b"\x04loop\x04test\x00"), 2)
        self.assertNotEqual(allowed, denied)

    def test_truncation_malformed_dnssec_and_timeout_are_exact(self) -> None:
        query = build_query(29, "allowed.test", TYPE_A)
        truncated = response_for(query, "truncated-fallback", 0, "udp") or b""
        completed = response_for(query, "truncated-fallback", 0, "tcp") or b""
        malformed = response_for(query, "malformed", 0, "udp") or b""
        dnssec = response_for(query, "dnssec-confusion", 0, "udp") or b""
        self.assertTrue(struct.unpack("!H", truncated[2:4])[0] & FLAG_TC)
        self.assertFalse(struct.unpack("!H", completed[2:4])[0] & FLAG_TC)
        self.assertEqual(malformed, b"\x00\x1dmalformed")
        self.assertTrue(struct.unpack("!H", dnssec[2:4])[0] & FLAG_AD)
        self.assertIsNone(response_for(query, "timeout", 0, "udp"))

    def test_open_query_and_script_grammars_fail_closed(self) -> None:
        query = bytearray(build_query(31, "allowed.test", TYPE_A))
        query[2] |= 0x80
        with self.assertRaises(DnsError):
            parse_query(bytes(query))
        with self.assertRaises(DnsError):
            response_for(build_query(31, "allowed.test", TYPE_A), "unknown", 0, "udp")
        with self.assertRaises(DnsError):
            response_for(build_query(31, "allowed.test", TYPE_A), "stable", -1, "udp")


if __name__ == "__main__":
    unittest.main()
