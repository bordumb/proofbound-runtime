use std::fs;
use std::path::Path;

use proofbound_runtime_core::{
    ArtifactIdentity, ArtifactRole, ExecutionPlan, FileAccess, PathRole, compile_policy,
    normalize_authority, parse_execution_plan,
};
use proofbound_runtime_linux::{
    CapabilityReport, OutputRootError, OutputRootPreflight, ProbeError, ResolutionError,
    ResolvedReadPath, RootedPathResolver, identify_external_artifact,
};
use serde_json::{Value, json};

const INVALID_INPUT: u8 = 2;
const UNSUPPORTED_BOUNDARY: u8 = 3;
const IDENTITY_DRIFT: u8 = 4;
const REPORT_SCHEMA: &str = "proofbound-runtime-preflight/1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreflightError {
    exit_code: u8,
    phase: &'static str,
    code: &'static str,
}

impl PreflightError {
    pub(crate) const fn exit_code(self) -> u8 {
        self.exit_code
    }

    pub(crate) const fn code(self) -> &'static str {
        self.code
    }

    pub(crate) fn report(self) -> Value {
        json!({
            "schema": REPORT_SCHEMA,
            "ready": false,
            "phase": self.phase,
            "code": self.code,
        })
    }

    const fn invalid(phase: &'static str, code: &'static str) -> Self {
        Self {
            exit_code: INVALID_INPUT,
            phase,
            code,
        }
    }

    const fn unsupported(phase: &'static str, code: &'static str) -> Self {
        Self {
            exit_code: UNSUPPORTED_BOUNDARY,
            phase,
            code,
        }
    }

    const fn identity(phase: &'static str, code: &'static str) -> Self {
        Self {
            exit_code: IDENTITY_DRIFT,
            phase,
            code,
        }
    }
}

pub(crate) fn execute<P>(
    plan_path: &Path,
    receipt_path: &Path,
    cgroup_root: &Path,
    probe: P,
) -> Result<Value, PreflightError>
where
    P: FnOnce(&Path) -> CapabilityReport,
{
    let canonical_plan = fs::canonicalize(plan_path)
        .map_err(|_| PreflightError::invalid("plan-input", "plan.input.read-failed"))?;
    let plan_source = identify_external_artifact(&canonical_plan, ArtifactRole::ExecutionPlan)
        .map_err(|error| map_resolution("plan-input", error))?;
    let plan_bytes = plan_source
        .read_bytes()
        .map_err(|error| map_resolution("plan-input", error))?;
    let plan_text = core::str::from_utf8(&plan_bytes)
        .map_err(|_| PreflightError::invalid("plan-input", "plan.input.utf8-invalid"))?;
    let plan = parse_execution_plan(plan_text)
        .map_err(|error| PreflightError::invalid("plan-validation", error.code()))?;
    let normalized = normalize_authority(plan.authority().clone())
        .map_err(|error| PreflightError::invalid("authority-normalization", error.code()))?;
    let compiled = compile_policy(normalized);
    let plan_root = canonical_plan
        .parent()
        .ok_or_else(|| PreflightError::invalid("plan-root", "plan.input.parent-unavailable"))?;
    let resolver =
        RootedPathResolver::open(plan_root).map_err(|error| map_resolution("plan-root", error))?;

    let supported = probe(cgroup_root).require_supported().map_err(map_probe)?;
    let receipt_target =
        crate::run::prepare_receipt_path(receipt_path).map_err(|error| PreflightError {
            exit_code: error.exit_code(),
            phase: "receipt-target",
            code: error.code(),
        })?;
    let output_authority = compiled
        .filesystem()
        .rules()
        .iter()
        .find(|rule| rule.access() == FileAccess::Write && rule.role() == PathRole::OutputRoot)
        .ok_or_else(|| {
            PreflightError::invalid("output-root", "plan.authority.output-root.count")
        })?;
    let output_root =
        OutputRootPreflight::inspect(&resolver, output_authority.path()).map_err(map_output)?;
    let working_directory = resolver
        .resolve_working_directory(plan.command().working_directory())
        .map_err(|error| map_resolution("working-directory", error))?;
    let executable = resolver
        .discover_executable(plan.command().executable(), supported.architecture())
        .map_err(|error| map_resolution("executable-closure", error))?;
    let mut inputs = resolve_read_authority(&resolver, &compiled)?;
    inputs.sort_by(|left, right| {
        left.identity()
            .cmp(right.identity())
            .then_with(|| left.requested_path().cmp(right.requested_path()))
    });

    plan_source
        .revalidate_identity()
        .map_err(|error| map_resolution("identity-revalidation", error))?;
    executable
        .revalidate_identities()
        .map_err(|error| map_resolution("identity-revalidation", error))?;
    working_directory
        .revalidate_identity()
        .map_err(|error| map_resolution("identity-revalidation", error))?;
    for input in &inputs {
        input
            .revalidate_identity()
            .map_err(|error| map_resolution("identity-revalidation", error))?;
    }

    success_report(
        &plan,
        &plan_source,
        &supported,
        &executable,
        &working_directory,
        &inputs,
        &output_root,
        &receipt_target,
    )
}

fn resolve_read_authority(
    resolver: &RootedPathResolver,
    compiled: &proofbound_runtime_core::CompiledPolicy,
) -> Result<Vec<ResolvedReadPath>, PreflightError> {
    compiled
        .filesystem()
        .rules()
        .iter()
        .filter(|rule| rule.access() == FileAccess::Read)
        .map(|rule| {
            let role = match rule.role() {
                PathRole::ProjectInput => ArtifactRole::ProjectInput,
                PathRole::RuntimeLibrary => ArtifactRole::RuntimeLibrary,
                _ => {
                    return Err(PreflightError::invalid(
                        "read-authority",
                        "plan.authority.read.role-invalid",
                    ));
                }
            };
            resolver
                .resolve_read_path(rule.path(), role)
                .map_err(|error| map_resolution("read-authority", error))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn success_report(
    plan: &ExecutionPlan,
    plan_source: &proofbound_runtime_linux::ResolvedFile,
    supported: &proofbound_runtime_linux::SupportedLinux,
    executable: &proofbound_runtime_linux::ExecutableClosure,
    working_directory: &proofbound_runtime_linux::ResolvedDirectory,
    inputs: &[ResolvedReadPath],
    output_root: &OutputRootPreflight,
    receipt_target: &Path,
) -> Result<Value, PreflightError> {
    let plan_source = path_artifact(
        "plan-input",
        plan_source.requested_path(),
        plan_source.resolved_target(),
        plan_source.identity(),
    )?;
    let executable_file = path_artifact(
        "executable-closure",
        executable.executable().requested_path(),
        executable.executable().resolved_target(),
        executable.executable().identity(),
    )?;
    let interpreter = executable
        .loader()
        .map(|loader| {
            path_artifact(
                "executable-closure",
                loader.requested_path(),
                loader.resolved_target(),
                loader.identity(),
            )
        })
        .transpose()?;
    let working_directory = path_artifact(
        "working-directory",
        working_directory.requested_path(),
        working_directory.resolved_target(),
        working_directory.identity(),
    )?;
    let inputs = inputs
        .iter()
        .map(|input| {
            path_artifact(
                "read-authority",
                input.requested_path(),
                input.resolved_target(),
                input.identity(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cgroup_directory = utf8_path(
        "host-capabilities",
        "platform.cgroup-v2.path-utf8-invalid",
        supported.cgroup_v2().directory(),
    )?;
    let output_requested = utf8_path(
        "output-root",
        "output.path.utf8-invalid",
        output_root.requested_path(),
    )?;
    let output_parent = utf8_path(
        "output-root",
        "output.path.utf8-invalid",
        output_root.resolved_parent(),
    )?;
    let output_target = utf8_path(
        "output-root",
        "output.path.utf8-invalid",
        output_root.resolved_target(),
    )?;
    let receipt_target = utf8_path(
        "receipt-target",
        "receipt.path.utf8-invalid",
        receipt_target,
    )?;

    Ok(json!({
        "schema": REPORT_SCHEMA,
        "ready": true,
        "caveat": "preflight.point-in-time",
        "plan_id": plan.id().as_str(),
        "plan_source": plan_source,
        "platform": {
            "architecture": supported.architecture().as_str(),
            "kernel_release": supported.kernel_release(),
            "landlock_abi": supported.landlock_abi().get(),
            "seccomp_actions": supported.seccomp().available_actions(),
            "cgroup_v2": {
                "directory": cgroup_directory,
                "mount_id": supported.cgroup_v2().mount_id(),
                "directory_inode": supported.cgroup_v2().directory_inode(),
                "controllers": supported.cgroup_v2().controllers(),
            },
        },
        "command": {
            "executable": executable_file,
            "interpreter": interpreter,
            "working_directory": working_directory,
        },
        "inputs": inputs,
        "output_root": {
            "requested": output_requested,
            "resolved_parent": output_parent,
            "resolved_target": output_target,
        },
        "receipt": {
            "resolved_target": receipt_target,
        },
    }))
}

fn path_artifact(
    phase: &'static str,
    requested: &Path,
    resolved: &Path,
    identity: &ArtifactIdentity,
) -> Result<Value, PreflightError> {
    Ok(json!({
        "requested": utf8_path(phase, "preflight.path.utf8-invalid", requested)?,
        "resolved": utf8_path(phase, "preflight.path.utf8-invalid", resolved)?,
        "artifact": artifact(identity),
    }))
}

fn artifact(identity: &ArtifactIdentity) -> Value {
    json!({
        "role": identity.role().as_str(),
        "sha256": identity.digest().to_hex(),
        "size": identity.size(),
        "mode": identity.mode().get(),
    })
}

fn utf8_path<'a>(
    phase: &'static str,
    code: &'static str,
    path: &'a Path,
) -> Result<&'a str, PreflightError> {
    path.to_str()
        .ok_or_else(|| PreflightError::invalid(phase, code))
}

const fn map_probe(error: ProbeError) -> PreflightError {
    PreflightError::unsupported("host-capabilities", error.code())
}

const fn map_resolution(phase: &'static str, error: ResolutionError) -> PreflightError {
    match error {
        ResolutionError::UnsupportedOperatingSystem | ResolutionError::Openat2Unavailable => {
            PreflightError::unsupported(phase, error.code())
        }
        ResolutionError::IdentityMismatch | ResolutionError::IdentityDrift => {
            PreflightError::identity(phase, error.code())
        }
        _ => PreflightError::invalid(phase, error.code()),
    }
}

const fn map_output(error: OutputRootError) -> PreflightError {
    match error {
        OutputRootError::UnsupportedOperatingSystem | OutputRootError::Openat2Unavailable => {
            PreflightError::unsupported("output-root", error.code())
        }
        OutputRootError::IdentityDrift => PreflightError::identity("output-root", error.code()),
        _ => PreflightError::invalid("output-root", error.code()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTACK_CATALOG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/attacks/preflight/orchestration-v1.toml"
    ));

    #[test]
    fn preflight_attack_catalog_is_closed() {
        let expected = [
            "invalid-plan",
            "unsupported-host",
            "receipt-preexists",
            "output-preexists",
            "plan-root-escape",
            "runtime-root-symlink",
            "executable-architecture-substitution",
            "interpreter-substitution",
            "identity-drift",
            "preflight-as-receipt",
        ];
        assert!(ATTACK_CATALOG.starts_with("schema = \"proofbound-runtime-preflight-attacks/1\""));
        assert_eq!(ATTACK_CATALOG.matches("[[case]]").count(), expected.len());
        for id in expected {
            assert!(ATTACK_CATALOG.contains(&format!("id = \"{id}\"")));
        }
    }

    #[test]
    fn failure_report_is_closed_and_typed() {
        let error =
            PreflightError::unsupported("host-capabilities", "platform.cgroup-v2.unavailable");
        assert_eq!(error.exit_code(), UNSUPPORTED_BOUNDARY);
        assert_eq!(
            error.report(),
            json!({
                "schema": "proofbound-runtime-preflight/1",
                "ready": false,
                "phase": "host-capabilities",
                "code": "platform.cgroup-v2.unavailable",
            })
        );
    }

    #[test]
    fn artifact_projection_uses_receipt_identity_fields() {
        let identity = ArtifactIdentity::new(
            ArtifactRole::RuntimeExecutable,
            proofbound_runtime_core::Sha256Digest::from_bytes([0xab; 32]),
            42,
            proofbound_runtime_core::FileMode::new(0o755).expect("valid mode"),
        );
        assert_eq!(
            artifact(&identity),
            json!({
                "role": "runtime-executable",
                "sha256": "abababababababababababababababababababababababababababababababab",
                "size": 42,
                "mode": 493,
            })
        );
    }
}
