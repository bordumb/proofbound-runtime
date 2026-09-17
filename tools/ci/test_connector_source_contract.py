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


def text_between(source: str, start: str, end: str) -> str:
    opening = source.index(start)
    closing = source.index(end, opening + len(start))
    return source[opening:closing]


class ConnectorSourceContractTests(unittest.TestCase):
    def test_dns_resolution_applies_merged_alias_lifetime_and_canonical_deduplication(self) -> None:
        body = function_body(DNS_SOURCE, "pub fn resolve_service(")
        guards = (
            "let chain = reconcile_chains(",
            "canonicalize_answers(&mut answers);",
            "apply_chain_expiry(&mut answers, &chain);",
            "answer.effective_expires_ns <= resolution.elapsed_ns()",
            "if Instant::now() >= deadline",
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
            "terminal_connect_failure(",
            "MeteredTcpStream::new(",
            "require_exact_dns_san(&certificates[0], service)",
        )
        finalization_guards = (
            "let implementation_identity = digest(TLS_IMPLEMENTATION);",
            "let certificate_chain_identity = certificate_chain_identity(certificates);",
            "let authenticated_ns = resolution.elapsed_ns();",
            "if let Some(kind) = terminal_absolute_deadline_kind(",
            "let active_at = Instant::now();",
        )
        require_guards(authenticate, guards)
        for guard in guards:
            with self.subTest(removed=guard):
                with self.assertRaises(AssertionError):
                    require_guards(authenticate.replace(guard, "", 1), guards)

        finalization = text_between(
            authenticate,
            "let handshake_bytes",
            "Ok(AuthenticatedTlsSession",
        )
        require_guards(finalization, finalization_guards)
        for guard in finalization_guards:
            with self.subTest(removed=guard):
                with self.assertRaises(AssertionError):
                    require_guards(
                        finalization.replace(guard, "", 1), finalization_guards
                    )
        ordered = tuple(finalization.index(guard) for guard in finalization_guards)
        self.assertEqual(ordered, tuple(sorted(ordered)))

        connected = function_body(authenticate, "Ok(stream) =>")
        failed = function_body(authenticate, "Err(error) =>")
        terminal_guard = "terminal_absolute_deadline_kind("
        require_guards(connected, (terminal_guard,))
        require_guards(failed, (terminal_guard,))
        with self.assertRaises(AssertionError):
            require_guards(connected.replace(terminal_guard, "", 1), (terminal_guard,))
        with self.assertRaises(AssertionError):
            require_guards(failed.replace(terminal_guard, "", 1), (terminal_guard,))

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
        common_guards = (
            "session.require_active()",
            "session.stream.conn.send_close_notify();",
        )
        child_guards = (
            ".checked_add(count_u64)",
            ".is_none_or(|total| total > session.child_to_service_limit)",
            "session.child_to_service_bytes += count_u64;",
        )
        service_write_guards = (
            "session.service_to_child_bytes = session",
            ".checked_add(",
        )
        service_read_guards = (
            ".checked_sub(session.service_to_child_bytes)",
            "let permitted = if remaining == 0",
            "Ok(count) if remaining == 0",
        )
        service_write = text_between(
            body,
            "if pending_offset < pending_child.len()",
            "if child_open",
        )
        child_read = text_between(body, "if child_open", "if !child_open")
        service_read = text_between(
            body,
            "if pending_child.is_empty()",
            "if !peer_open",
        )
        require_guards(body, common_guards)
        require_guards(child_read, child_guards)
        require_guards(service_write, service_write_guards)
        require_guards(service_read, service_read_guards)
        self.assertNotIn("TcpStream::connect", body)
        for segment, guards in (
            (body, common_guards),
            (child_read, child_guards),
            (service_write, service_write_guards),
            (service_read, service_read_guards),
        ):
            for guard in guards:
                with self.subTest(removed=guard):
                    with self.assertRaises(AssertionError):
                        require_guards(segment.replace(guard, "", 1), guards)


if __name__ == "__main__":
    unittest.main()
