use std::io;

use proofbound_runtime_core::{
    AuthorityError, ExecutionPlan, FileAccess, NetworkMode, PathRole, PlanError,
    normalize_authority, parse_execution_plan_for_execution,
};
use serde_json::{Value, json};

const REPORT_SCHEMA: &str = "proofbound-runtime-plan-check/1";
const REPORT_SCHEMA_V2: &str = "proofbound-runtime-plan-check/2";

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

pub(crate) fn write_check_bytes(
    input: &[u8],
    output: &mut impl io::Write,
) -> Result<(), CheckError> {
    let plan = parse_execution_plan_for_execution(input).map_err(CheckError::Plan)?;
    let report = checked_plan_json(&plan)?;
    serde_json::to_writer(&mut *output, &report).map_err(|_| CheckError::Output)?;
    writeln!(output).map_err(|_| CheckError::Output)
}

pub(crate) fn checked_plan_json(plan: &ExecutionPlan) -> Result<Value, CheckError> {
    let normalized =
        normalize_authority(plan.authority().clone()).map_err(CheckError::Normalize)?;
    let limits = normalized.limits();
    let mut limit_projection = json!({
        "wall_time_ms": limits.wall_time().milliseconds(),
        "stdout_bytes": limits.stdout().get(),
        "stderr_bytes": limits.stderr().get(),
        "processes": limits.processes().get(),
    });
    if let (Some(memory), Some(swap)) = (limits.memory(), limits.swap()) {
        let object = limit_projection
            .as_object_mut()
            .expect("limit projection is an object");
        object.insert("memory_bytes".to_owned(), json!(memory.get().to_string()));
        object.insert("swap_bytes".to_owned(), json!(swap.get().to_string()));
    }
    Ok(json!({
        "schema": if limits.is_version_two() { REPORT_SCHEMA_V2 } else { REPORT_SCHEMA },
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
            "limits": limit_projection,
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
    fn invalid_plans_retain_the_core_machine_code() {
        let mut output = Vec::new();
        let error =
            write_check_bytes(b"schema = [", &mut output).expect_err("malformed plan is rejected");
        assert_eq!(error.code(), "plan.schema.malformed-cbor");
        assert!(output.is_empty());
    }
}
