#[cfg(target_os = "linux")]
fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let result = proofbound_runtime_linux::egress_proxy_process::parse_proxy_bootstrap(&arguments)
        .and_then(proofbound_runtime_linux::egress_proxy_process::run_proxy_process);
    if let Err(error) = result {
        eprintln!("{}", error.code());
        std::process::exit(125);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("egress.proxy.os.unsupported");
    std::process::exit(125);
}
