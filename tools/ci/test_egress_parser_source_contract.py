"""Independent exact-body mutation witnesses for the egress wire parsers."""

from pathlib import Path
import unittest


SOURCE = (
    Path(__file__).resolve().parents[2]
    / "crates/proofbound-runtime-linux/src/egress_proxy.rs"
).read_text(encoding="utf-8")


GUARDS = {
    "pub fn parse_connect_head(": (
        '.windows(4)',
        'window == b"\\r\\n\\r\\n"',
        'input.len() >= MAX_CONNECT_HEAD_BYTES',
        'if end > MAX_CONNECT_HEAD_BYTES',
        'let request = request\n        .strip_suffix(b"\\r")',
        'let line = line\n            .strip_suffix(b"\\r")',
        'if method != b"CONNECT"',
        'words.next().is_some() || !matches!(version, b"HTTP/1.0" | b"HTTP/1.1")',
        'parse_authority(authority)?',
        'if colon == 0',
        'is_http_token(*byte)',
        '(0x20..=0x7e).contains(byte)',
    ),
    "fn parse_authority(": (
        'authority.is_empty() || !authority.is_ascii()',
        "if authority[0] == b'['",
        "*byte == b']'",
        "authority.get(close + 1) != Some(&b':')",
        "address.contains('%')",
        'Ipv6Addr::from_str(address)',
        'parsed.to_ipv4_mapped().is_some()',
        "host.contains(':') || host.is_empty()",
        'address.to_string() != host',
        "byte.is_ascii_digit() || byte == b'.'",
        'EgressName::new(lowercase)',
    ),
    "fn parse_port(": (
        "bytes.is_empty() || bytes.len() > 5 || (bytes.len() > 1 && bytes[0] == b'0')",
        '!bytes.iter().all(u8::is_ascii_digit)',
        '.parse::<u16>()',
        'TcpPort::new(port)',
    ),
    "pub fn parse_client_hello_sni(": (
        'record_count < MAX_CLIENT_HELLO_RECORDS',
        'input.len() - cursor < 5',
        'header[0] != 22 || header[1] != 3 || !(1..=3).contains(&header[2])',
        'length == 0 || length > MAX_CLIENT_HELLO_BYTES',
        'input.len() - cursor < length',
        'handshake.len().saturating_add(length) > MAX_CLIENT_HELLO_BYTES',
        'handshake[0] != 1',
        'declared > MAX_CLIENT_HELLO_BYTES - 4',
        'parse_client_hello_body(&handshake[4..4 + declared])',
        'record_count == MAX_CLIENT_HELLO_RECORDS',
    ),
    "fn parse_client_hello_body(": (
        'session_length > 32',
        'cipher_length == 0 || cipher_length % 2 != 0',
        'compression_length == 0',
        'take_tls(&mut body, extension_length)?',
        'if !body.is_empty()',
        '!seen.insert(kind)',
        'kind == 0xfe0d',
        'if kind == 0 {',
        'name.ok_or(SniParseError::Absent)',
    ),
    "fn parse_server_name_extension(": (
        'value.len() != length',
        'kind != 0',
        '!value.is_empty() || !name.is_ascii()',
        'EgressName::new(name.to_ascii_lowercase())',
    ),
}


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
    raise AssertionError(f"unclosed production parser: {signature}")


def require_guards(body: str, guards: tuple[str, ...]) -> None:
    for guard in guards:
        if guard not in body:
            raise AssertionError(f"missing production parser guard: {guard}")


class EgressParserSourceContractTests(unittest.TestCase):
    def test_every_registered_guard_has_a_deletion_witness(self) -> None:
        for signature, guards in GUARDS.items():
            body = function_body(SOURCE, signature)
            require_guards(body, guards)
            for guard in guards:
                with self.subTest(parser=signature, removed=guard):
                    with self.assertRaises(AssertionError):
                        require_guards(body.replace(guard, "", 1), guards)


if __name__ == "__main__":
    unittest.main()
