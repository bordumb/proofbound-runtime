//! Stdin fuzz target for the bounded CONNECT parser.

use std::io::{self, Read as _};

use proofbound_runtime_linux::egress_proxy::parse_connect_head;

fn main() {
    let mut input = Vec::new();
    io::stdin()
        .take(65_536)
        .read_to_end(&mut input)
        .expect("read fuzz input");
    if let Ok(parsed) = parse_connect_head(&input) {
        assert!(parsed.payload_offset >= 4 && parsed.payload_offset <= input.len());
        assert_eq!(
            &input[parsed.payload_offset - 4..parsed.payload_offset],
            b"\r\n\r\n"
        );
        assert_eq!(
            parse_connect_head(&input[..parsed.payload_offset]),
            Ok(parsed)
        );
    }
}
