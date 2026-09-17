"""Independent mutation guards for the proposed RT-5 connector engine."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DNS_SOURCE = (ROOT / "crates/proofbound-runtime-connector/src/dns.rs").read_text(
    encoding="utf-8"
)
TLS_SOURCE = (ROOT / "crates/proofbound-runtime-connector/src/tls.rs").read_text(
    encoding="utf-8"
)


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unclosed function: {signature}")


def require_guards(body: str, guards: tuple[str, ...]) -> None:
    for guard in guards:
        if guard not in body:
            raise AssertionError(f"missing production guard: {guard}")


class ConnectorSourceContractTests(unittest.TestCase):
    def test_dns_resolution_applies_merged_alias_lifetime_and_canonical_deduplication(self) -> None:
        body = function_body(DNS_SOURCE, "pub fn resolve_service(")
        guards = (
            "let chain = reconcile_chains(",
            "canonicalize_answers(&mut answers);",
            "apply_chain_expiry(&mut answers, &chain);",
            "answer.effective_expires_ns <= elapsed_ns(started)",
        )
        require_guards(body, guards)
        for guard in guards:
            with self.subTest(removed=guard):
                with self.assertRaises(AssertionError):
                    require_guards(body.replace(guard, "", 1), guards)

    def test_dns_wire_path_calls_parser_and_alias_observation_guards(self) -> None:
        exchange = function_body(DNS_SOURCE, "fn exchange_query(")
        parser = function_body(DNS_SOURCE, "fn parse_response(")
        require_guards(
            exchange,
            (
                "write_all_until(&mut stream",
                "read_exact_until(&mut stream",
                "let parsed = parse_response(",
            ),
        )
        require_guards(
            parser,
            (
                "let record = cname_observation(",
                "cnames.entry(owner).or_default().push(record);",
                "if cursor != bytes.len()",
            ),
        )

    def test_tls_authentication_calls_explicit_provider_exact_san_and_deadline_guards(self) -> None:
        authenticate = function_body(TLS_SOURCE, "pub fn authenticate_service(")
        guards = (
            "let config = build_config(tls, trust_root_bytes)",
            "terminal_absolute_deadline_kind(",
            "terminal_connect_failure(",
            "MeteredTcpStream::new(",
            "require_exact_dns_san(&certificates[0], service)",
        )
        require_guards(authenticate, guards)
        for guard in guards:
            with self.subTest(removed=guard):
                with self.assertRaises(AssertionError):
                    require_guards(authenticate.replace(guard, ""), guards)

    def test_tls_configuration_selects_ring_and_disables_reuse(self) -> None:
        body = function_body(TLS_SOURCE, "fn build_config(")
        guards = (
            "rustls::crypto::ring::default_provider()",
            "ClientConfig::builder_with_provider(provider)",
            "config.resumption = Resumption::disabled();",
            "config.enable_early_data = false;",
        )
        require_guards(body, guards)
        for guard in guards:
            with self.subTest(removed=guard):
                with self.assertRaises(AssertionError):
                    require_guards(body.replace(guard, "", 1), guards)

    def test_tls_transport_calls_handshake_and_session_deadline_guards(self) -> None:
        read = function_body(TLS_SOURCE, "impl Read for MeteredTcpStream")
        write = function_body(TLS_SOURCE, "impl Write for MeteredTcpStream")
        require_guards(read, ("self.remaining_time()?", "self.remaining()?"))
        require_guards(write, ("self.remaining_time()?", "self.remaining()?"))

    def test_proxy_calls_both_directional_limits_and_session_guard(self) -> None:
        body = function_body(TLS_SOURCE, "pub fn proxy_authenticated_channel(")
        guards = (
            "session.require_active()",
            "session.child_to_service_limit",
            ".service_to_child_limit",
            "session.stream.conn.send_close_notify();",
        )
        require_guards(body, guards)
        self.assertNotIn("TcpStream::connect", body)
        for guard in guards:
            with self.subTest(removed=guard):
                with self.assertRaises(AssertionError):
                    require_guards(body.replace(guard, "", 1), guards)


if __name__ == "__main__":
    unittest.main()
