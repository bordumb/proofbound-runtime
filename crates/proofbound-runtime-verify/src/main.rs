#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use proofbound_runtime_verify::verify_receipt;

const SUCCESS: u8 = 0;
const INVALID_INPUT: u8 = 2;

fn main() -> ExitCode {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    ExitCode::from(run_with(
        env::args_os(),
        |path| fs::read(path),
        &mut stdout,
        &mut stderr,
    ))
}

fn run_with<I, R, W, E>(args: I, mut read: R, stdout: &mut W, stderr: &mut E) -> u8
where
    I: IntoIterator<Item = OsString>,
    R: FnMut(&Path) -> io::Result<Vec<u8>>,
    W: io::Write,
    E: io::Write,
{
    let mut args = args.into_iter();
    let _program = args.next();
    let Some(argument) = args.next() else {
        return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
    };
    if args.next().is_some() {
        return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
    }
    if argument == "--help" || argument == "-h" {
        return write_success(stdout, "usage: pbr-verify <receipt>");
    }
    if argument == "--version" {
        return write_success(stdout, concat!("pbr-verify ", env!("CARGO_PKG_VERSION")));
    }

    let path = PathBuf::from(argument);
    let input = match read(&path) {
        Ok(input) => input,
        Err(_) => return fail(stderr, INVALID_INPUT, "receipt.input.read-failed"),
    };
    match verify_receipt(&input) {
        Ok(report) => write_success(stdout, &report.machine_json()),
        Err(error) => fail(stderr, error.exit_code(), error.code()),
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
    let _ignored = writeln!(stderr, "pbr-verify: {code}");
    exit_code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn usage_failures_are_invalid_input() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(
            args(&["pbr-verify"]),
            |_| unreachable!("usage failure does not read"),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, INVALID_INPUT);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"pbr-verify: cli.usage.invalid\n");
    }

    #[test]
    fn read_failures_are_invalid_input() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(
            args(&["pbr-verify", "missing.json"]),
            |_| Err(io::Error::from(io::ErrorKind::NotFound)),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, INVALID_INPUT);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"pbr-verify: receipt.input.read-failed\n");
    }

    #[test]
    fn verification_failures_use_exit_seven_and_the_typed_code() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(
            args(&["pbr-verify", "receipt.json"]),
            |_| Ok(br#"{"schema":"#.to_vec()),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 7);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"pbr-verify: receipt.schema.malformed-json\n");
    }

    #[test]
    fn help_and_version_are_successful() {
        for option in ["--help", "--version"] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code = run_with(
                args(&["pbr-verify", option]),
                |_| unreachable!("informational option does not read"),
                &mut stdout,
                &mut stderr,
            );
            assert_eq!(code, SUCCESS);
            assert!(!stdout.is_empty());
            assert!(stderr.is_empty());
        }
    }
}
