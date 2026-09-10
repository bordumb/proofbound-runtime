"""Falsifiers for deterministic DNS decision transcripts."""

from __future__ import annotations

import struct
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from experiments.network_authority.scripted_dns import (
    FLAG_AD,
    FLAG_TC,
    TYPE_A,
    TYPE_AAAA,
    DnsError,
    build_query,
    parse_query,
    read_exact,
    response_for,
    serve_dns,
    validate_resolution,
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

    def test_over_depth_cname_chain_is_distinct_and_rejected(self) -> None:
        query = build_query(27, "alias.test", TYPE_A)
        response = response_for(query, "cname-depth", 0, "udp") or b""
        self.assertIn(b"\x07depth-1\x04test\x00", response)
        self.assertIn(b"\x07depth-3\x04test\x00", response)
        self.assertNotEqual(response, response_for(query, "cname-loop", 0, "udp"))
        with self.assertRaisesRegex(DnsError, "loops or exceeds"):
            validate_resolution(query, response, allow_cname=True)

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

    def test_declared_resolution_accepts_only_exact_address_and_cname_policy(self) -> None:
        stable_query = build_query(37, "allowed.test", TYPE_A)
        stable = response_for(stable_query, "stable", 0, "udp")
        self.assertIsNotNone(stable)
        resolution = validate_resolution(stable_query, stable or b"", allow_cname=False)
        self.assertEqual(resolution.address, "127.0.0.1")
        self.assertEqual(resolution.cname_chain, ("allowed.test",))

        alias_query = build_query(41, "alias.test", TYPE_AAAA)
        aliased = response_for(alias_query, "cname-allowed", 0, "udp")
        self.assertIsNotNone(aliased)
        resolution = validate_resolution(alias_query, aliased or b"", allow_cname=True)
        self.assertEqual(resolution.address, "fd00::1")
        self.assertEqual(resolution.cname_chain, ("alias.test", "allowed.test"))
        with self.assertRaises(DnsError):
            validate_resolution(alias_query, aliased or b"", allow_cname=False)

    def test_rebinding_cname_confusion_and_dnssec_fail_closed(self) -> None:
        query = build_query(43, "allowed.test", TYPE_A)
        for script, ordinal in (
            ("rebind", 1),
            ("dnssec-confusion", 0),
            ("truncated-fallback", 0),
        ):
            response = response_for(query, script, ordinal, "udp")
            self.assertIsNotNone(response)
            with self.assertRaises(DnsError):
                validate_resolution(query, response or b"", allow_cname=False)

        alias_query = build_query(47, "alias.test", TYPE_A)
        for script in ("cname-denied", "cname-loop", "cname-depth"):
            response = response_for(alias_query, script, 0, "udp")
            self.assertIsNotNone(response)
            with self.assertRaises(DnsError):
                validate_resolution(alias_query, response or b"", allow_cname=True)

    def test_response_identity_and_inventory_are_exact(self) -> None:
        query = build_query(53, "allowed.test", TYPE_A)
        response = bytearray(response_for(query, "stable", 0, "udp") or b"")
        response[1] ^= 1
        with self.assertRaises(DnsError):
            validate_resolution(query, bytes(response), allow_cname=False)

    def start_server(
        self, root: Path, script: str, queries: int
    ) -> tuple[threading.Thread, Path, Path, list[BaseException]]:
        ready = root / "ready.json"
        transcript = root / "transcript.json"
        errors: list[BaseException] = []

        def target() -> None:
            try:
                serve_dns("127.0.0.1", 0, script, queries, ready, transcript)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=target)
        thread.start()
        for _ in range(100):
            if ready.is_file() or errors:
                break
            time.sleep(0.01)
        self.assertTrue(ready.is_file(), errors)
        return thread, ready, transcript, errors

    def test_udp_server_publishes_one_exact_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            thread, ready, transcript, errors = self.start_server(root, "stable", 1)
            endpoint = json.loads(ready.read_bytes())
            query = build_query(59, "allowed.test", TYPE_A)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(2)
                client.sendto(query, (endpoint["address"], endpoint["port"]))
                response, _ = client.recvfrom(512)
            resolution = validate_resolution(query, response, allow_cname=False)
            self.assertEqual(resolution.address, "127.0.0.1")
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            recorded = json.loads(transcript.read_bytes())
            self.assertEqual(recorded["script"], "stable")
            self.assertEqual(recorded["queries"][0]["transport"], "udp")

    def test_truncated_udp_requires_exact_tcp_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            thread, ready, transcript, errors = self.start_server(
                root, "truncated-fallback", 2
            )
            endpoint = json.loads(ready.read_bytes())
            query = build_query(61, "allowed.test", TYPE_AAAA)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(2)
                udp.sendto(query, (endpoint["address"], endpoint["port"]))
                truncated, _ = udp.recvfrom(512)
            with self.assertRaises(DnsError):
                validate_resolution(query, truncated, allow_cname=False)
            with socket.create_connection(
                (endpoint["address"], endpoint["port"]), timeout=2
            ) as tcp:
                tcp.sendall(struct.pack("!H", len(query)) + query)
                size = struct.unpack("!H", read_exact(tcp, 2))[0]
                completed = read_exact(tcp, size)
            resolution = validate_resolution(query, completed, allow_cname=False)
            self.assertEqual(resolution.address, "fd00::1")
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            recorded = json.loads(transcript.read_bytes())
            self.assertEqual(
                [entry["transport"] for entry in recorded["queries"]],
                ["udp", "tcp"],
            )

    def test_timeout_has_no_fallback_and_records_no_response(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            thread, ready, transcript, errors = self.start_server(root, "timeout", 1)
            endpoint = json.loads(ready.read_bytes())
            query = build_query(67, "allowed.test", TYPE_A)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(0.1)
                client.sendto(query, (endpoint["address"], endpoint["port"]))
                with self.assertRaises(socket.timeout):
                    client.recvfrom(512)
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            recorded = json.loads(transcript.read_bytes())
            self.assertIsNone(recorded["queries"][0]["response_sha256"])

        response = bytearray(response_for(query, "stable", 0, "udp") or b"")
        response.extend(b"x")
        with self.assertRaises(DnsError):
            validate_resolution(query, bytes(response), allow_cname=False)


if __name__ == "__main__":
    unittest.main()
