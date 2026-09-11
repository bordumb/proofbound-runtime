//! Closed version 2 receipt decoding over the verifier-owned CBOR codec.

use core::num::NonZeroU32;

use serde_json::Value as Json;

use crate::cbor::Value;
use crate::decode::{
    DecodeError, DecodedReceipt, RecordedEligibility, WireArchitecture, WireArtifact,
    WireArtifactRole, WireBoundary, WireBoundaryState, WireCapture, WireCgroup, WireCommand,
    WireEligibility, WireEligibilityStatus, WireObservations, WireOutcome, WirePlan, WirePlatform,
    WirePolicy, WireReason, WireReceipt, WireResources, WireRuntime, WireStream, WireStreams,
    WireTcbEntry,
};
use crate::{BoundaryState, CaptureState, EligibilityInput, OutcomeState, StructureState};

const SCHEMA: &str = "proofbound-runtime-execution-receipt/2";
const POLICY: &str = "proofbound-runtime-linux-policy/2";
const MAX_RESOURCE_BYTES: u64 = 1_099_511_627_776;
const RESOURCE_QUANTUM: u64 = 65_536;

pub(crate) fn decode_v2_receipt(input: &[u8]) -> Result<DecodedReceipt, DecodeError> {
    let root = crate::cbor::decode(input).map_err(|_| DecodeError::MalformedCbor)?;
    let top = exact_map(
        &root,
        &[
            "plan",
            "schema",
            "inputs",
            "policy",
            "runtime",
            "streams",
            "command",
            "outcome",
            "outputs",
            "boundary",
            "producer",
            "platform",
            "resources",
            "eligibility",
            "environment",
            "execution_id",
            "observations",
            "product_version",
            "assumptions",
            "output_root",
            "trusted_computing_base",
        ],
    )?;
    if text(field(top, "schema")?)? != SCHEMA {
        return Err(DecodeError::UnsupportedVersion);
    }

    let plan = parse_plan(field(top, "plan")?)?;
    let policy = parse_policy(field(top, "policy")?)?;
    let platform = parse_platform(field(top, "platform")?)?;
    let runtime = parse_runtime(field(top, "runtime")?)?;
    let command = parse_command(field(top, "command")?)?;
    let inputs = parse_artifacts(field(top, "inputs")?)?;
    let environment = parse_text_array(field(top, "environment")?)?;
    let output_root = parse_artifact(field(top, "output_root")?)?;
    let boundary = parse_boundary(field(top, "boundary")?)?;
    let observations = parse_observations(field(top, "observations")?)?;
    let streams = parse_streams(field(top, "streams")?)?;
    let outcome = parse_outcome(field(top, "outcome")?)?;
    let outputs = parse_artifacts(field(top, "outputs")?)?;
    let producer = parse_artifact(field(top, "producer")?)?;
    let assumptions = parse_text_array(field(top, "assumptions")?)?;
    let trusted_computing_base = parse_tcb(field(top, "trusted_computing_base")?)?;
    let resources = parse_resources(field(top, "resources")?)?;
    let eligibility = parse_eligibility(field(top, "eligibility")?)?;
    let recorded_eligibility = match eligibility.status {
        WireEligibilityStatus::Reusable if eligibility.reasons.is_empty() => {
            RecordedEligibility::Reusable
        }
        WireEligibilityStatus::NonReusable if !eligibility.reasons.is_empty() => {
            RecordedEligibility::NonReusable(eligibility.reasons.clone())
        }
        _ => return Err(DecodeError::InvalidSchema),
    };

    let boundary_state = match boundary.state {
        WireBoundaryState::Installed => BoundaryState::Installed,
        WireBoundaryState::Incomplete => BoundaryState::Incomplete,
    };
    let outcome_state = outcome_state(outcome)?;
    let limit_events = [
        resources.memory_events[1] != 0,
        resources.memory_events[2] != 0,
        resources.memory_events[3] != 0,
        resources.memory_events[4] != 0,
        resources.memory_events[5] != 0,
        resources.swap_events[0] != 0,
        resources.swap_events[1] != 0,
    ];
    let eligibility_input = EligibilityInput::new_v2(
        boundary_state,
        outcome_state,
        capture_state(streams.stdout.capture),
        capture_state(streams.stderr.capture),
        StructureState::Valid,
        limit_events,
    );
    let execution_id = uuid_text(bytes_exact::<16>(field(top, "execution_id")?)?);
    let wire = WireReceipt {
        schema: SCHEMA.to_owned(),
        product_version: text(field(top, "product_version")?)?.to_owned(),
        execution_id,
        plan,
        policy,
        platform,
        runtime,
        command,
        inputs,
        environment,
        output_root,
        boundary,
        observations,
        streams,
        outcome,
        outputs,
        eligibility,
        producer,
        assumptions,
        trusted_computing_base,
    };
    let projection = project(&root)?;
    Ok(DecodedReceipt::from_v2(
        projection,
        wire,
        eligibility_input,
        recorded_eligibility,
        resources,
    ))
}

fn parse_plan(value: &Value) -> Result<WirePlan, DecodeError> {
    let map = exact_map(value, &["id", "source", "normalized"])?;
    Ok(WirePlan {
        id: text(field(map, "id")?)?.to_owned(),
        source: parse_artifact(field(map, "source")?)?,
        normalized: parse_artifact(field(map, "normalized")?)?,
    })
}

fn parse_policy(value: &Value) -> Result<WirePolicy, DecodeError> {
    let map = exact_map(value, &["identity", "model_version"])?;
    let model_version = text(field(map, "model_version")?)?.to_owned();
    if model_version != POLICY {
        return Err(DecodeError::InvalidSchema);
    }
    Ok(WirePolicy {
        identity: parse_artifact(field(map, "identity")?)?,
        model_version,
    })
}

fn parse_platform(value: &Value) -> Result<WirePlatform, DecodeError> {
    let map = exact_map(
        value,
        &[
            "architecture",
            "landlock_abi",
            "kernel_release",
            "operating_system",
            "seccomp_features",
            "cgroup_controllers",
        ],
    )?;
    let operating_system = text(field(map, "operating_system")?)?.to_owned();
    if operating_system != "linux" {
        return Err(DecodeError::InvalidSchema);
    }
    let architecture = match text(field(map, "architecture")?)? {
        "x86_64" => WireArchitecture::X86_64,
        "aarch64" => WireArchitecture::Aarch64,
        _ => return Err(DecodeError::InvalidSchema),
    };
    let landlock_abi = u32::try_from(unsigned(field(map, "landlock_abi")?)?)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(DecodeError::InvalidSchema)?;
    Ok(WirePlatform {
        operating_system,
        architecture,
        kernel_release: text(field(map, "kernel_release")?)?.to_owned(),
        landlock_abi,
        seccomp_features: parse_text_array(field(map, "seccomp_features")?)?,
        cgroup_controllers: parse_text_array(field(map, "cgroup_controllers")?)?,
    })
}

fn parse_runtime(value: &Value) -> Result<WireRuntime, DecodeError> {
    let map = exact_map(value, &["runtime", "launcher"])?;
    Ok(WireRuntime {
        runtime: parse_artifact(field(map, "runtime")?)?,
        launcher: parse_artifact(field(map, "launcher")?)?,
    })
}

fn parse_command(value: &Value) -> Result<WireCommand, DecodeError> {
    let map = exact_map(
        value,
        &[
            "loader",
            "executable",
            "arguments_sha256",
            "working_directory",
        ],
    )?;
    let loader = match field(map, "loader")? {
        Value::Null => None,
        value => Some(parse_artifact(value)?),
    };
    Ok(WireCommand {
        executable: parse_artifact(field(map, "executable")?)?,
        loader,
        working_directory: parse_artifact(field(map, "working_directory")?)?,
        arguments_sha256: hex(bytes_exact::<32>(field(map, "arguments_sha256")?)?),
    })
}

fn parse_boundary(value: &Value) -> Result<WireBoundary, DecodeError> {
    let map = exact_map(value, &["state", "cgroup", "execution_id", "policy_sha256"])?;
    let state = match text(field(map, "state")?)? {
        "installed" => WireBoundaryState::Installed,
        "incomplete" => WireBoundaryState::Incomplete,
        _ => return Err(DecodeError::InvalidSchema),
    };
    let cgroup = exact_map(field(map, "cgroup")?, &["inode", "mount_id"])?;
    Ok(WireBoundary {
        state,
        execution_id: uuid_text(bytes_exact::<16>(field(map, "execution_id")?)?),
        policy_sha256: hex(bytes_exact::<32>(field(map, "policy_sha256")?)?),
        cgroup: WireCgroup {
            mount_id: unsigned(field(cgroup, "mount_id")?)?.to_string(),
            inode: unsigned(field(cgroup, "inode")?)?.to_string(),
        },
    })
}

fn parse_observations(value: &Value) -> Result<WireObservations, DecodeError> {
    let map = exact_map(value, &["clock", "started_ns", "finished_ns"])?;
    let clock = text(field(map, "clock")?)?.to_owned();
    if clock != "linux-monotonic" {
        return Err(DecodeError::InvalidSchema);
    }
    Ok(WireObservations {
        clock,
        started_ns: unsigned(field(map, "started_ns")?)?.to_string(),
        finished_ns: unsigned(field(map, "finished_ns")?)?.to_string(),
    })
}

fn parse_streams(value: &Value) -> Result<WireStreams, DecodeError> {
    let map = exact_map(value, &["stderr", "stdout"])?;
    Ok(WireStreams {
        stdout: parse_stream(field(map, "stdout")?)?,
        stderr: parse_stream(field(map, "stderr")?)?,
    })
}

fn parse_stream(value: &Value) -> Result<WireStream, DecodeError> {
    let map = exact_map(value, &["capture", "artifact"])?;
    let capture = match text(field(map, "capture")?)? {
        "complete" => WireCapture::Complete,
        "truncated" => WireCapture::Truncated,
        _ => return Err(DecodeError::InvalidSchema),
    };
    Ok(WireStream {
        artifact: parse_artifact(field(map, "artifact")?)?,
        capture,
    })
}

fn parse_outcome(value: &Value) -> Result<WireOutcome, DecodeError> {
    let Value::Map(map) = value else {
        return Err(DecodeError::InvalidSchema);
    };
    match text(field(map, "kind")?)? {
        "exited" => {
            exact_map(value, &["kind", "code"])?;
            Ok(WireOutcome::Exited {
                code: signed_i32(field(map, "code")?)?,
            })
        }
        "signaled" => {
            exact_map(value, &["kind", "signal"])?;
            let signal = u32::try_from(unsigned(field(map, "signal")?)?)
                .ok()
                .filter(|value| *value != 0)
                .ok_or(DecodeError::InvalidSchema)?;
            Ok(WireOutcome::Signaled { signal })
        }
        "timed-out" => {
            exact_map(value, &["kind"])?;
            Ok(WireOutcome::TimedOut)
        }
        "denied" => {
            exact_map(value, &["kind"])?;
            Ok(WireOutcome::Denied)
        }
        "launcher-failed" => {
            exact_map(value, &["kind"])?;
            Ok(WireOutcome::LauncherFailed)
        }
        "incomplete" => {
            exact_map(value, &["kind"])?;
            Ok(WireOutcome::Incomplete)
        }
        _ => Err(DecodeError::InvalidSchema),
    }
}

fn parse_resources(value: &Value) -> Result<WireResources, DecodeError> {
    let map = exact_map(value, &["terminal", "configured", "limit_events"])?;
    let configured = exact_map(
        field(map, "configured")?,
        &[
            "pids.max",
            "memory.max",
            "memory.oom.group",
            "memory.swap.max",
        ],
    )?;
    let processes = u32::try_from(unsigned(field(configured, "pids.max")?)?)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(DecodeError::InvalidSchema)?;
    let memory = unsigned(field(configured, "memory.max")?)?;
    let swap = unsigned(field(configured, "memory.swap.max")?)?;
    if !(RESOURCE_QUANTUM..=MAX_RESOURCE_BYTES).contains(&memory)
        || memory % RESOURCE_QUANTUM != 0
        || swap > MAX_RESOURCE_BYTES
        || swap % RESOURCE_QUANTUM != 0
        || unsigned(field(configured, "memory.oom.group")?)? != 1
    {
        return Err(DecodeError::InvalidSchema);
    }

    let terminal = exact_map(
        field(map, "terminal")?,
        &[
            "swap_events",
            "memory_events",
            "swap_peak_bytes",
            "memory_peak_bytes",
        ],
    )?;
    let memory_map = exact_map(
        field(terminal, "memory_events")?,
        &["low", "oom", "high", "max", "oom_kill", "oom_group_kill"],
    )?;
    let swap_map = exact_map(field(terminal, "swap_events")?, &["max", "fail"])?;
    Ok(WireResources {
        processes,
        memory,
        swap,
        memory_peak: unsigned(field(terminal, "memory_peak_bytes")?)?,
        swap_peak: unsigned(field(terminal, "swap_peak_bytes")?)?,
        memory_events: [
            unsigned(field(memory_map, "low")?)?,
            unsigned(field(memory_map, "high")?)?,
            unsigned(field(memory_map, "max")?)?,
            unsigned(field(memory_map, "oom")?)?,
            unsigned(field(memory_map, "oom_kill")?)?,
            unsigned(field(memory_map, "oom_group_kill")?)?,
        ],
        swap_events: [
            unsigned(field(swap_map, "max")?)?,
            unsigned(field(swap_map, "fail")?)?,
        ],
        limit_events: parse_reason_array(field(map, "limit_events")?)?,
    })
}

fn parse_eligibility(value: &Value) -> Result<WireEligibility, DecodeError> {
    let map = exact_map(value, &["status", "reasons"])?;
    let status = match text(field(map, "status")?)? {
        "reusable" => WireEligibilityStatus::Reusable,
        "non-reusable" => WireEligibilityStatus::NonReusable,
        _ => return Err(DecodeError::InvalidSchema),
    };
    Ok(WireEligibility {
        status,
        reasons: parse_reason_array(field(map, "reasons")?)?,
    })
}

fn parse_reason_array(value: &Value) -> Result<Vec<WireReason>, DecodeError> {
    array(value)?
        .iter()
        .map(|value| reason(text(value)?))
        .collect()
}

fn reason(value: &str) -> Result<WireReason, DecodeError> {
    match value {
        "boundary-incomplete" => Ok(WireReason::BoundaryIncomplete),
        "exit-code-nonzero" => Ok(WireReason::ExitCodeNonzero),
        "process-signaled" => Ok(WireReason::ProcessSignaled),
        "timed-out" => Ok(WireReason::TimedOut),
        "denied" => Ok(WireReason::Denied),
        "launcher-failed" => Ok(WireReason::LauncherFailed),
        "execution-incomplete" => Ok(WireReason::ExecutionIncomplete),
        "stdout-truncated" => Ok(WireReason::StdoutTruncated),
        "stderr-truncated" => Ok(WireReason::StderrTruncated),
        "receipt-malformed" => Ok(WireReason::ReceiptMalformed),
        "memory-high" => Ok(WireReason::MemoryHigh),
        "memory-max" => Ok(WireReason::MemoryMax),
        "memory-oom" => Ok(WireReason::MemoryOom),
        "memory-oom-kill" => Ok(WireReason::MemoryOomKill),
        "memory-oom-group-kill" => Ok(WireReason::MemoryOomGroupKill),
        "swap-max" => Ok(WireReason::SwapMax),
        "swap-fail" => Ok(WireReason::SwapFail),
        _ => Err(DecodeError::InvalidSchema),
    }
}

fn parse_artifacts(value: &Value) -> Result<Vec<WireArtifact>, DecodeError> {
    array(value)?.iter().map(parse_artifact).collect()
}

fn parse_artifact(value: &Value) -> Result<WireArtifact, DecodeError> {
    let map = exact_map(value, &["mode", "role", "size", "sha256"])?;
    let mode = u16::try_from(unsigned(field(map, "mode")?)?)
        .ok()
        .filter(|value| *value <= 0o7777)
        .ok_or(DecodeError::InvalidSchema)?;
    Ok(WireArtifact {
        role: artifact_role(text(field(map, "role")?)?)?,
        sha256: hex(bytes_exact::<32>(field(map, "sha256")?)?),
        size: unsigned(field(map, "size")?)?.to_string(),
        mode,
    })
}

fn artifact_role(value: &str) -> Result<WireArtifactRole, DecodeError> {
    match value {
        "execution-plan" => Ok(WireArtifactRole::ExecutionPlan),
        "normalized-plan" => Ok(WireArtifactRole::NormalizedPlan),
        "compiled-policy" => Ok(WireArtifactRole::CompiledPolicy),
        "runtime-binary" => Ok(WireArtifactRole::RuntimeBinary),
        "launcher-binary" => Ok(WireArtifactRole::LauncherBinary),
        "verifier-binary" => Ok(WireArtifactRole::VerifierBinary),
        "runtime-executable" => Ok(WireArtifactRole::RuntimeExecutable),
        "runtime-loader-executable" => Ok(WireArtifactRole::RuntimeLoaderExecutable),
        "runtime-library" => Ok(WireArtifactRole::RuntimeLibrary),
        "working-directory" => Ok(WireArtifactRole::WorkingDirectory),
        "project-input" => Ok(WireArtifactRole::ProjectInput),
        "output-root" => Ok(WireArtifactRole::OutputRoot),
        "standard-output" => Ok(WireArtifactRole::StandardOutput),
        "standard-error" => Ok(WireArtifactRole::StandardError),
        "output-artifact" => Ok(WireArtifactRole::OutputArtifact),
        _ => Err(DecodeError::InvalidSchema),
    }
}

fn parse_tcb(value: &Value) -> Result<Vec<WireTcbEntry>, DecodeError> {
    let entries = array(value)?;
    if entries.is_empty() {
        return Err(DecodeError::InvalidSchema);
    }
    entries
        .iter()
        .map(|value| {
            let map = exact_map(value, &["role", "identity"])?;
            Ok(WireTcbEntry {
                role: text(field(map, "role")?)?.to_owned(),
                identity: text(field(map, "identity")?)?.to_owned(),
            })
        })
        .collect()
}

fn parse_text_array(value: &Value) -> Result<Vec<String>, DecodeError> {
    array(value)?
        .iter()
        .map(|value| Ok(text(value)?.to_owned()))
        .collect()
}

fn outcome_state(outcome: WireOutcome) -> Result<OutcomeState, DecodeError> {
    Ok(match outcome {
        WireOutcome::Exited { code } => OutcomeState::Exited { code },
        WireOutcome::Signaled { signal } => OutcomeState::Signaled {
            signal: NonZeroU32::new(signal).ok_or(DecodeError::InvalidSchema)?,
        },
        WireOutcome::TimedOut => OutcomeState::TimedOut,
        WireOutcome::Denied => OutcomeState::Denied,
        WireOutcome::LauncherFailed => OutcomeState::LauncherFailed,
        WireOutcome::Incomplete => OutcomeState::Incomplete,
    })
}

const fn capture_state(value: WireCapture) -> CaptureState {
    match value {
        WireCapture::Complete => CaptureState::Complete,
        WireCapture::Truncated => CaptureState::Truncated,
    }
}

fn exact_map<'a>(value: &'a Value, names: &[&str]) -> Result<&'a [(String, Value)], DecodeError> {
    let Value::Map(map) = value else {
        return Err(DecodeError::InvalidSchema);
    };
    if map.len() != names.len()
        || !names
            .iter()
            .all(|name| map.iter().any(|(key, _)| key == name))
    {
        return Err(DecodeError::InvalidSchema);
    }
    Ok(map)
}

fn field<'a>(map: &'a [(String, Value)], name: &str) -> Result<&'a Value, DecodeError> {
    map.iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
        .ok_or(DecodeError::InvalidSchema)
}

fn array(value: &Value) -> Result<&[Value], DecodeError> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(DecodeError::InvalidSchema),
    }
}

fn text(value: &Value) -> Result<&str, DecodeError> {
    match value {
        Value::Text(value) => Ok(value),
        _ => Err(DecodeError::InvalidSchema),
    }
}

fn unsigned(value: &Value) -> Result<u64, DecodeError> {
    match value {
        Value::Unsigned(value) => Ok(*value),
        _ => Err(DecodeError::InvalidSchema),
    }
}

fn bytes_exact<const N: usize>(value: &Value) -> Result<&[u8; N], DecodeError> {
    let Value::Bytes(bytes) = value else {
        return Err(DecodeError::InvalidSchema);
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| DecodeError::InvalidSchema)
}

fn signed_i32(value: &Value) -> Result<i32, DecodeError> {
    let value = match value {
        Value::Unsigned(value) => i64::try_from(*value).map_err(|_| DecodeError::InvalidSchema)?,
        Value::Negative(argument) => -1_i128
            .checked_sub(i128::from(*argument))
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(DecodeError::InvalidSchema)?,
        _ => return Err(DecodeError::InvalidSchema),
    };
    i32::try_from(value).map_err(|_| DecodeError::InvalidSchema)
}

fn uuid_text(bytes: &[u8; 16]) -> String {
    let encoded = hex(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &encoded[0..8],
        &encoded[8..12],
        &encoded[12..16],
        &encoded[16..20],
        &encoded[20..32]
    )
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn project(value: &Value) -> Result<Json, DecodeError> {
    Ok(match value {
        Value::Unsigned(value) => Json::from(*value),
        Value::Negative(argument) => {
            let value = -1_i128
                .checked_sub(i128::from(*argument))
                .and_then(|value| i64::try_from(value).ok())
                .ok_or(DecodeError::InvalidSchema)?;
            Json::from(value)
        }
        Value::Bytes(bytes) => Json::String(format!("hex:{}", hex(bytes))),
        Value::Text(value) => Json::String(value.clone()),
        Value::Array(values) => Json::Array(values.iter().map(project).collect::<Result<_, _>>()?),
        Value::Map(values) => Json::Object(
            values
                .iter()
                .map(|(key, value)| Ok((key.clone(), project(value)?)))
                .collect::<Result<_, DecodeError>>()?,
        ),
        Value::Bool(value) => Json::Bool(*value),
        Value::Null => Json::Null,
    })
}
