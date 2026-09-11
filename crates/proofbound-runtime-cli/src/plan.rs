use std::io;

use proofbound_runtime_core::{
    AuthorityError, ExecutionPlan, FileAccess, NetworkMode, PathRole, PlanError,
    normalize_authority, parse_execution_plan,
};
use serde_json::{Value, json};

const REPORT_SCHEMA: &str = "proofbound-runtime-plan-check/1";

#[cfg(test)]
pub(crate) const TEST_PLAN: &str = r#"
schema = "proofbound-runtime-plan/1"
id = "cli.plan-check"
[command]
executable = "/bin/tool"
arguments = ["format", "src"]
working_directory = "."
[authority]
network = "deny"
environment = ["PATH", "LANG", "PATH"]
read = ["src", "src"]
runtime_read = []
write = ["out"]
execute = ["/bin/tool"]
[limits]
wall_time_ms = 100
stdout_bytes = 200
stderr_bytes = 300
processes = 2
"#;

#[derive(Debug)]
pub(crate) enum CheckError {
    Plan(PlanError),
    Normalize(AuthorityError),
    Output,
}

impl CheckError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Plan(error) => error.code(),
            Self::Normalize(error) => error.code(),
            Self::Output => "cli.output.write-failed",
        }
    }
}

pub(crate) fn write_check(input: &str, output: &mut impl io::Write) -> Result<(), CheckError> {
    let plan = parse_execution_plan(input).map_err(CheckError::Plan)?;
    let report = checked_plan_json(&plan)?;
    serde_json::to_writer(&mut *output, &report).map_err(|_| CheckError::Output)?;
    writeln!(output).map_err(|_| CheckError::Output)
}

pub(crate) fn checked_plan_json(plan: &ExecutionPlan) -> Result<Value, CheckError> {
    let normalized =
        normalize_authority(plan.authority().clone()).map_err(CheckError::Normalize)?;
    let limits = normalized.limits();
    Ok(json!({
        "schema": REPORT_SCHEMA,
        "id": plan.id().as_str(),
        "command": {
            "executable": plan.command().executable().as_str(),
            "arguments": plan.command().arguments().iter()
                .map(|argument| argument.as_str())
                .collect::<Vec<_>>(),
            "working_directory": plan.command().working_directory().as_str(),
        },
        "authority": {
            "network": network_name(normalized.network()),
            "environment": normalized.environment().iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>(),
            "paths": normalized.paths().iter().map(|entry| json!({
                "path": entry.path().as_str(),
                "access": access_name(entry.access()),
                "role": role_name(entry.role()),
            })).collect::<Vec<_>>(),
            "limits": {
                "wall_time_ms": limits.wall_time().milliseconds(),
                "stdout_bytes": limits.stdout().get(),
                "stderr_bytes": limits.stderr().get(),
                "processes": limits.processes().get(),
            },
        },
    }))
}

const fn access_name(access: FileAccess) -> &'static str {
    match access {
        FileAccess::Read => "read",
        FileAccess::Write => "write",
        FileAccess::Execute => "execute",
    }
}

const fn role_name(role: PathRole) -> &'static str {
    match role {
        PathRole::ProjectInput => "project-input",
        PathRole::OutputRoot => "output-root",
        PathRole::RuntimeExecutable => "runtime-executable",
        PathRole::RuntimeLoaderExecutable => "runtime-loader-executable",
        PathRole::RuntimeLibrary => "runtime-library",
    }
}

const fn network_name(network: NetworkMode) -> &'static str {
    match network {
        NetworkMode::Deny => "deny",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = core::str::from_utf8(pair).expect("fixture is ASCII");
                u8::from_str_radix(text, 16).expect("fixture is hexadecimal")
            })
            .collect()
    }

    #[test]
    fn version_two_check_projects_decoded_cbor_without_reusing_json_as_input() {
        let input = decode_hex(include_str!(
            "../../../schemas/vectors/v2/execution-plan.cbor.hex"
        ));
        let mut output = Vec::new();
        write_check_bytes(&input, &mut output).expect("valid v2 plan checks");
        let report: Value = serde_json::from_slice(&output).expect("report is JSON");

        assert_eq!(report["schema"], "proofbound-runtime-plan-check/2");
        assert_eq!(report["authority"]["limits"]["memory_bytes"], "65536");
        assert_eq!(report["authority"]["limits"]["swap_bytes"], "0");
    }

    #[test]
    fn check_explains_the_canonical_normalized_plan() {
        let mut output = Vec::new();
        write_check(TEST_PLAN, &mut output).expect("valid plan checks");
        let report: Value = serde_json::from_slice(&output).expect("report is JSON");

        assert_eq!(report["schema"], REPORT_SCHEMA);
        assert_eq!(report["id"], "cli.plan-check");
        assert_eq!(report["command"]["arguments"], json!(["format", "src"]));
        assert_eq!(report["authority"]["environment"], json!(["LANG", "PATH"]));
        assert_eq!(
            report["authority"]["paths"],
            json!([
                {"path":"/bin/tool","access":"execute","role":"runtime-executable"},
                {"path":"out","access":"write","role":"output-root"},
                {"path":"src","access":"read","role":"project-input"}
            ])
        );
    }

    #[test]
    fn invalid_plans_retain_the_core_machine_code() {
        let mut output = Vec::new();
        let error = write_check("schema = [", &mut output).expect_err("malformed plan is rejected");
        assert_eq!(error.code(), "plan.schema.malformed-toml");
        assert!(output.is_empty());
    }
}
