#![forbid(unsafe_code)]

mod doctor;

use std::env;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::Path;
use std::process::ExitCode;

use proofbound_runtime_linux::{CapabilityReport, probe_capabilities};

const SUCCESS: u8 = 0;
const INVALID_INPUT: u8 = 2;
const UNSUPPORTED_BOUNDARY: u8 = 3;

fn main() -> ExitCode {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    ExitCode::from(run_with(
        env::args_os(),
        probe_capabilities,
        &mut stdout,
        &mut stderr,
    ))
}

fn run_with<I, P, W, E>(args: I, probe: P, stdout: &mut W, stderr: &mut E) -> u8
where
    I: IntoIterator<Item = OsString>,
    P: FnOnce(&Path) -> CapabilityReport,
    W: io::Write,
    E: io::Write,
{
    let mut args = args.into_iter();
    let _program = args.next();
    let Some(command) = args.next() else {
        return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
    };
    if command == "--help" || command == "-h" {
        if args.next().is_some() {
            return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
        }
        return write_success(stdout, "usage: pbr <doctor|plan|run|inspect> [options]");
    }
    if command == "--version" {
        if args.next().is_some() {
            return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
        }
        return write_success(stdout, concat!("pbr ", env!("CARGO_PKG_VERSION")));
    }
    if command != "doctor" {
        return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
    }
    let Some(option) = args.next() else {
        return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
    };
    if option != OsStr::new("--cgroup-root") {
        return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
    }
    let Some(cgroup_root) = args.next() else {
        return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
    };
    if args.next().is_some() {
        return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
    }

    match doctor::write_report(&probe(Path::new(&cgroup_root)), stdout) {
        Ok(true) => SUCCESS,
        Ok(false) => UNSUPPORTED_BOUNDARY,
        Err(_) => fail(stderr, INVALID_INPUT, "cli.output.write-failed"),
    }
}

fn write_success(output: &mut impl io::Write, text: &str) -> u8 {
    if writeln!(output, "{text}").is_ok() {
        SUCCESS
    } else {
        INVALID_INPUT
    }
}

fn fail(stderr: &mut impl io::Write, exit_code: u8, code: &str) -> u8 {
    let _ignored = writeln!(stderr, "pbr: {code}");
    exit_code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn doctor_reports_unsupported_hosts_with_exit_three() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(
            args(&["pbr", "doctor", "--cgroup-root", "/unsupported"]),
            probe_capabilities,
            &mut stdout,
            &mut stderr,
        );
        let value: serde_json::Value = serde_json::from_slice(&stdout).expect("doctor writes JSON");

        assert_eq!(code, UNSUPPORTED_BOUNDARY);
        assert_eq!(value["supported"], false);
        assert!(stderr.is_empty());
    }

    #[test]
    fn usage_is_closed() {
        for values in [
            &["pbr"][..],
            &["pbr", "doctor"][..],
            &["pbr", "doctor", "--unknown", "/tmp"][..],
            &["pbr", "doctor", "--cgroup-root", "/tmp", "extra"][..],
            &["pbr", "unknown"][..],
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code = run_with(
                args(values),
                |_| unreachable!("invalid usage does not probe"),
                &mut stdout,
                &mut stderr,
            );
            assert_eq!(code, INVALID_INPUT);
            assert!(stdout.is_empty());
            assert_eq!(stderr, b"pbr: cli.usage.invalid\n");
        }
    }

    #[test]
    fn help_and_version_are_successful() {
        for option in ["--help", "--version"] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code = run_with(
                args(&["pbr", option]),
                |_| unreachable!("informational option does not probe"),
                &mut stdout,
                &mut stderr,
            );
            assert_eq!(code, SUCCESS);
            assert!(!stdout.is_empty());
            assert!(stderr.is_empty());
        }
    }
}
