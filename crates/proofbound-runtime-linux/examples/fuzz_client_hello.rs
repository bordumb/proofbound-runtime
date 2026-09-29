//! Stdin fuzz target for the bounded TLS ClientHello SNI parser.

use std::io::{self, Read as _};

use proofbound_runtime_core::EgressName;
use proofbound_runtime_linux::egress_proxy::parse_client_hello_sni;

fn main() {
    let mut input = Vec::new();
    io::stdin()
        .take(65_536)
        .read_to_end(&mut input)
        .expect("read fuzz input");
    if let Ok(name) = parse_client_hello_sni(&input) {
        assert_eq!(EgressName::new(name.as_str()), Ok(name));
    }
}
