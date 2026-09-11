#![forbid(unsafe_code)]

mod doctor;
mod inspect;
mod plan;
mod preflight;
mod run;
mod run_diagnostic;
mod scaffold;

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
        |path| fs::read(path),
        &mut stdout,
        &mut stderr,
    ))
}

fn run_with<I, P, R, W, E>(args: I, probe: P, mut read: R, stdout: &mut W, stderr: &mut E) -> u8
where
    I: IntoIterator<Item = OsString>,
    P: FnOnce(&Path) -> CapabilityReport,
    R: FnMut(&Path) -> io::Result<Vec<u8>>,
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
        return write_success(
            stdout,
            "usage: pbr <doctor|plan|preflight|run|inspect> [options]",
        );
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
        if subcommand == "scaffold" {
            let Some(executable_option) = args.next() else {
                return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
            };
            let Some(executable) = args.next() else {
                return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
            };
            let Some(profile_option) = args.next() else {
                return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
            };
            let Some(profile) = args.next() else {
                return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
            };
            if executable_option != OsStr::new("--executable")
                || profile_option != OsStr::new("--host-profile")
                || args.next().is_some()
            {
                return fail(stderr, INVALID_INPUT, "cli.usage.invalid");
            }
            let Some(profile) = profile.to_str() else {
                return fail(stderr, INVALID_INPUT, "scaffold.profile.unsupported");
            };
            return match scaffold::execute(Path::new(&executable), profile, stdout) {
                Ok(()) => SUCCESS,
                Err(error) => fail(stderr, INVALID_INPUT, error.code()),
            };
        }
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
        return match plan::write_check_bytes(&input, stdout) {
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
            Err(error) => fail_run(stderr, error),
        };
    }
    if command == "preflight" {
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
        let (report, exit_code, error_code) = match preflight::execute(
            Path::new(&plan_path),
            Path::new(&receipt_path),
            Path::new(&cgroup_root),
            probe,
        ) {
            Ok(report) => (report, SUCCESS, None),
            Err(error) => (error.report(), error.exit_code(), Some(error.code())),
        };
        if serde_json::to_writer(&mut *stdout, &report)
            .and_then(|()| writeln!(stdout).map_err(serde_json::Error::io))
            .is_err()
        {
            return fail(stderr, INVALID_INPUT, "cli.output.write-failed");
        }
        return error_code.map_or(exit_code, |code| fail(stderr, exit_code, code));
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

fn fail_run(stderr: &mut impl io::Write, error: run_diagnostic::RunError) -> u8 {
    let _ignored = writeln!(
        stderr,
        "pbr: phase={} rule={} code={}",
        error.phase().as_str(),
        error.rule().as_str(),
        error.code()
    );
    error.exit_code()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn v2_plan_bytes() -> Vec<u8> {
        include_str!("../../../schemas/vectors/v2/execution-plan.cbor.hex")
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = core::str::from_utf8(pair).expect("fixture is ASCII");
                u8::from_str_radix(text, 16).expect("fixture is hexadecimal")
            })
            .collect()
    }

    fn static_elf_bytes() -> Vec<u8> {
        let mut bytes = vec![0_u8; 64];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes
    }

    #[test]
    fn doctor_reports_unsupported_hosts_with_exit_three() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(
            args(&["pbr", "doctor", "--cgroup-root", "/unsupported"]),
            probe_capabilities,
            |_| -> io::Result<Vec<u8>> { unreachable!("doctor does not read a plan") },
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
            |_| -> io::Result<Vec<u8>> { unreachable!("doctor does not read a plan") },
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
            &[
                "pbr",
                "preflight",
                "--plan",
                "plan.toml",
                "--receipt",
                "receipt.json",
                "--cgroup-root",
            ][..],
            &[
                "pbr",
                "preflight",
                "--receipt",
                "receipt.json",
                "--plan",
                "plan.toml",
                "--cgroup-root",
                "/cgroup",
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
                |_| -> io::Result<Vec<u8>> { unreachable!("invalid usage does not read") },
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
                |_| -> io::Result<Vec<u8>> { unreachable!("informational option does not read") },
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
                Ok(v2_plan_bytes())
            },
            &mut stdout,
            &mut stderr,
        );
        let report: serde_json::Value =
            serde_json::from_slice(&stdout).expect("check report is JSON");

        assert_eq!(code, SUCCESS);
        assert_eq!(report["id"], "golden-v2");
        assert!(stderr.is_empty());
    }

    #[test]
    fn plan_read_failure_has_a_stable_error() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(
            args(&["pbr", "plan", "check", "--plan", "missing.toml"]),
            |_| unreachable!("plan check does not probe"),
            |_| Err::<Vec<u8>, _>(io::Error::from(io::ErrorKind::NotFound)),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, INVALID_INPUT);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"pbr: plan.input.read-failed\n");
    }

    #[test]
    fn plan_scaffold_is_a_non_policy_and_does_not_probe_or_use_plan_reader() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::temp_dir().join(format!(
            "proofbound-runtime-main-scaffold-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create scaffold fixture root");
        let executable = root.join("program");
        fs::write(&executable, static_elf_bytes()).expect("write static ELF");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("make fixture executable");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(
            vec![
                OsString::from("pbr"),
                OsString::from("plan"),
                OsString::from("scaffold"),
                OsString::from("--executable"),
                executable.into_os_string(),
                OsString::from("--host-profile"),
                OsString::from("linux-glibc-x86-64-v1"),
            ],
            |_| unreachable!("scaffold does not probe execution capabilities"),
            |_| -> io::Result<Vec<u8>> {
                unreachable!("scaffold does not use the plan-input reader")
            },
            &mut stdout,
            &mut stderr,
        );
        let report: serde_json::Value =
            serde_json::from_slice(&stdout).expect("scaffold report is JSON");

        assert_eq!(code, SUCCESS);
        assert_eq!(report["schema"], "proofbound-runtime-plan-scaffold/1");
        assert_eq!(report["safe_policy"], false);
        assert!(stderr.is_empty());
        fs::remove_dir_all(root).expect("remove scaffold fixture root");
    }

    #[test]
    fn preflight_failure_is_structured_and_preserves_the_machine_code() {
        let missing = std::env::temp_dir().join(format!(
            "proofbound-runtime-missing-preflight-plan-{}",
            std::process::id()
        ));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(
            vec![
                OsString::from("pbr"),
                OsString::from("preflight"),
                OsString::from("--plan"),
                missing.into_os_string(),
                OsString::from("--receipt"),
                OsString::from("receipt.json"),
                OsString::from("--cgroup-root"),
                OsString::from("/cgroup"),
            ],
            |_| unreachable!("missing plan fails before capability probing"),
            |_| -> io::Result<Vec<u8>> { unreachable!("preflight uses identified plan input") },
            &mut stdout,
            &mut stderr,
        );
        let report: serde_json::Value =
            serde_json::from_slice(&stdout).expect("preflight failure is JSON");

        assert_eq!(code, INVALID_INPUT);
        assert_eq!(
            report,
            serde_json::json!({
                "schema": "proofbound-runtime-preflight/1",
                "ready": false,
                "phase": "plan-input",
                "code": "plan.input.read-failed",
            })
        );
        assert_eq!(stderr, b"pbr: plan.input.read-failed\n");
    }

    #[test]
    fn run_failure_renders_one_closed_bounded_diagnostic() {
        let error = run_diagnostic::RunError::unsupported(
            run_diagnostic::RunPhase::HostCapabilities,
            run_diagnostic::RunRule::HostSupported,
            "platform.cgroup-v2.controller-missing",
        );
        let mut stderr = Vec::new();

        assert_eq!(fail_run(&mut stderr, error), UNSUPPORTED_BOUNDARY);
        assert_eq!(
            stderr,
            b"pbr: phase=host-capabilities rule=host-supported code=platform.cgroup-v2.controller-missing\n"
        );
        assert_eq!(stderr.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert!(stderr.len() < 256);
    }
}
