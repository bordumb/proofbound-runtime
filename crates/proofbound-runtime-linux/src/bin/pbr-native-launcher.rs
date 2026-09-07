#[cfg(target_os = "linux")]
fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let result = (|| {
        let bootstrap = proofbound_runtime_linux::parse_launcher_bootstrap(&arguments)?;
        let channel = proofbound_runtime_linux::LauncherChannel::from_inherited_descriptor(
            bootstrap.channel_descriptor(),
        )?;
        proofbound_runtime_linux::run_launcher(
            &channel,
            bootstrap.identity(),
            bootstrap.architecture(),
            bootstrap.landlock_abi(),
        )
    })();
    if let Err(error) = result {
        eprintln!("{}", error.code());
        std::process::exit(125);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("launcher.os.unsupported");
    std::process::exit(125);
}
