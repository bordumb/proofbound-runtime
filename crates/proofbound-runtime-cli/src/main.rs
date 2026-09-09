#![forbid(unsafe_code)]

mod doctor;
mod inspect;
mod plan;
mod run;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
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
        |path| fs::read_to_string(path),
        &mut stdout,
        &mut stderr,
    ))
}

fn run_with<I, P, R, W, E>(args: I, probe: P, mut read: R, stdout: &mut W, stderr: &mut E) -> u8
where
    I: IntoIterator<Item = OsString>,
    P: FnOnce(&Path) -> CapabilityReport,
    R: FnMut(&Path) -> io::Result<String>,
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
    if command == "plan" {
        let Some(subcommand) = args.next() else {
            return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
        };
        let Some(option) = args.next() else {
            return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
        };
        let Some(plan_path) = args.next() else {
            return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
        };
        if subcommand != "check" || option != OsStr::new("--plan") || args.next().is_some() {
            return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
        }
        let input = match read(Path::new(&plan_path)) {
            Ok(input) => input,
            Err(_) => return fail(stderr, INVALID_INPUT, "plan.input.read-failed"),
        };
        return match plan::write_check(&input, stdout) {
            Ok(()) => SUCCESS,
            Err(error) => fail(stderr, INVALID_INPUT, error.code()),
        };
    }
    if command == "run" {
        let Some(plan_option) = args.next() else {
            return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
        };
        let Some(plan_path) = args.next() else {
            return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
        };
        let Some(receipt_option) = args.next() else {
            return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
        };
        let Some(receipt_path) = args.next() else {
            return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
        };
        let Some(cgroup_option) = args.next() else {
            return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
        };
        let Some(cgroup_root) = args.next() else {
            return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
        };
        if plan_option != OsStr::new("--plan")
            || receipt_option != OsStr::new("--receipt")
            || cgroup_option != OsStr::new("--cgroup-root")
            || args.next().is_some()
        {
            return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
        }
        return match run::execute(
            Path::new(&plan_path),
            Path::new(&receipt_path),
            Path::new(&cgroup_root),
        ) {
            Ok(report) => match serde_json::to_writer(&mut *stdout, &report)
                .and_then(|()| writeln!(stdout).map_err(serde_json::Error::io))
            {
                Ok(()) => SUCCESS,
                Err(_) => fail(stderr, INVALID_INPUT, "cli.output.write-failed"),
            },
            Err(error) => fail(stderr, error.exit_code(), error.code()),
        };
    }
    if command == "inspect" {
        let Some(receipt_path) = args.next() else {
            return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
        };
        if args.next().is_some() {
            return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
        }
        return match inspect::execute(Path::new(&receipt_path), stdout) {
            Ok(()) => SUCCESS,
            Err(error) => fail(stderr, INVALID_INPUT, error.code()),
        };
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
    let explain = match args.next() {
        None => false,
        Some(option) if option == OsStr::new("--explain") => true,
        Some(_) => return fail(stderr, INVALID_INPUT, "cli.usage.invalid"),
    };
    if args.next().is_some() {
        return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
    }

    let report = probe(Path::new(&cgroup_root));
    let result = if explain {
        doctor::write_explanation(&report, stdout)
    } else {
        doctor::write_report(&report, stdout)
    };
    match result {
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
            |_| unreachable!("doctor does not read a plan"),
            &mut stdout,
            &mut stderr,
        );
        let value: serde_json::Value = serde_json::from_slice(&stdout).expect("doctor writes JSON");

        assert_eq!(code, UNSUPPORTED_BOUNDARY);
        assert_eq!(value["supported"], false);
        assert!(stderr.is_empty());
    }

    #[test]
    fn doctor_explanation_uses_a_separate_schema_and_same_exit_class() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(
            args(&[
                "pbr",
                "doctor",
                "--cgroup-root",
                "/unsupported",
                "--explain",
            ]),
            probe_capabilities,
            |_| unreachable!("doctor does not read a plan"),
            &mut stdout,
            &mut stderr,
        );
        let value: serde_json::Value =
            serde_json::from_slice(&stdout).expect("doctor writes explanation JSON");

        assert_eq!(code, UNSUPPORTED_BOUNDARY);
        assert_eq!(value["schema"], "proofbound-runtime-doctor-explanation/1");
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
            &[
                "pbr",
                "run",
                "--plan",
                "plan.toml",
                "--receipt",
                "receipt.json",
                "--cgroup-root",
                "/cgroup",
                "extra",
            ][..],
            &["pbr", "doctor", "--explain", "--cgroup-root", "/tmp"][..],
            &[
                "pbr",
                "doctor",
                "--cgroup-root",
                "/tmp",
                "--explain",
                "extra",
            ][..],
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code = run_with(
                args(values),
                |_| unreachable!("invalid usage does not probe"),
                |_| unreachable!("invalid usage does not read"),
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
                |_| unreachable!("informational option does not read"),
                &mut stdout,
                &mut stderr,
            );
            assert_eq!(code, SUCCESS);
            assert!(!stdout.is_empty());
            assert!(stderr.is_empty());
        }
    }

    #[test]
    fn plan_check_reads_once_and_does_not_probe() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(
            args(&["pbr", "plan", "check", "--plan", "plan.toml"]),
            |_| unreachable!("plan check does not probe"),
            |path| {
                assert_eq!(path, Path::new("plan.toml"));
                Ok(crate::plan::TEST_PLAN.to_owned())
            },
            &mut stdout,
            &mut stderr,
        );
        let report: serde_json::Value =
            serde_json::from_slice(&stdout).expect("check report is JSON");

        assert_eq!(code, SUCCESS);
        assert_eq!(report["id"], "cli.plan-check");
        assert!(stderr.is_empty());
    }

    #[test]
    fn plan_read_failure_has_a_stable_error() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(
            args(&["pbr", "plan", "check", "--plan", "missing.toml"]),
            |_| unreachable!("plan check does not probe"),
            |_| Err(io::Error::from(io::ErrorKind::NotFound)),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, INVALID_INPUT);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"pbr: plan.input.read-failed\n");
    }
}
