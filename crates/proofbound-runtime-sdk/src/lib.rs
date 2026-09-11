#![forbid(unsafe_code)]

//! Convenience construction and projection decoding for Proofbound Runtime.
//!
//! This crate never executes a workload or embeds Runtime verification and
//! Linux-boundary semantics. Execution remains a separate `pbr` process.

use std::collections::BTreeSet;
use std::fmt;

use proofbound_runtime_core::{ExecutionId, PlanError, parse_execution_plan_for_execution};
use serde_json::{Map, Value};

const PLAN_SCHEMA: &str = "proofbound-runtime-plan/2";
const RESULT_SCHEMA: &str = "proofbound-runtime-run-result/2";

/// Closed logical inputs for one version 2 execution plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanV2Input {
    pub id: String,
    pub executable: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    pub read: Vec<String>,
    pub runtime_read: Vec<String>,
    pub write: Vec<String>,
    pub execute: Vec<String>,
    pub environment: Vec<String>,
    pub processes: u32,
    pub wall_time_ms: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub memory_bytes: u64,
    pub swap_bytes: u64,
}

/// One semantically validated deterministic-CBOR version 2 plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanV2 {
    bytes: Vec<u8>,
}

impl PlanV2 {
    /// Encodes the closed input and reuses the production parser for semantic
    /// validation before returning any bytes.
    pub fn new(input: PlanV2Input) -> Result<Self, SdkError> {
        require_unique(&input.read)?;
        require_unique(&input.runtime_read)?;
        require_unique(&input.write)?;
        require_unique(&input.execute)?;
        require_unique(&input.environment)?;
        if input.write.len() != 1
            || input.execute.len() != 1
            || input.execute[0] != input.executable
        {
            return Err(SdkError::PlanShape);
        }
        let value = Cbor::Map(vec![
            ("id", Cbor::Text(input.id)),
            ("schema", Cbor::Text(PLAN_SCHEMA.to_owned())),
            (
                "limits",
                Cbor::Map(vec![
                    ("processes", Cbor::Unsigned(u64::from(input.processes))),
                    ("swap_bytes", Cbor::Unsigned(input.swap_bytes)),
                    ("stderr_bytes", Cbor::Unsigned(input.stderr_bytes)),
                    ("stdout_bytes", Cbor::Unsigned(input.stdout_bytes)),
                    ("memory_bytes", Cbor::Unsigned(input.memory_bytes)),
                    ("wall_time_ms", Cbor::Unsigned(input.wall_time_ms)),
                ]),
            ),
            (
                "command",
                Cbor::Map(vec![
                    ("arguments", text_array(input.arguments)),
                    ("executable", Cbor::Text(input.executable)),
                    ("working_directory", Cbor::Text(input.working_directory)),
                ]),
            ),
            (
                "authority",
                Cbor::Map(vec![
                    ("read", text_array(input.read)),
                    ("write", text_array(input.write)),
                    ("execute", text_array(input.execute)),
                    ("network", Cbor::Text("deny".to_owned())),
                    ("environment", text_array(input.environment)),
                    ("runtime_read", text_array(input.runtime_read)),
                ]),
            ),
        ]);
        let mut bytes = Vec::new();
        encode(&value, &mut bytes)?;
        parse_execution_plan_for_execution(&bytes).map_err(SdkError::Plan)?;
        Ok(Self { bytes })
    }

    /// Returns the exact deterministic-CBOR plan bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the validated wrapper and returns its exact bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Closed child outcome projected by `pbr run`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunOutcome {
    Exited { code: u8 },
    Signaled { signal: u8 },
    TimedOut,
    Denied,
    LauncherFailed,
    Incomplete,
}

/// Strictly decoded JSON control projection from `pbr run`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunResultProjection {
    receipt: String,
    execution_id: [u8; 16],
    commitment: [u8; 32],
    outcome: RunOutcome,
}

impl RunResultProjection {
    /// Decodes one closed result object. The JSON bytes are display/control
    /// data and are never returned as receipt verification input.
    pub fn from_json(input: &[u8]) -> Result<Self, SdkError> {
        let value: Value = serde_json::from_slice(input).map_err(|_| SdkError::ResultMalformed)?;
        let mut root = object(value)?;
        require_keys(
            &root,
            &["commitment", "execution_id", "outcome", "receipt", "schema"],
        )?;
        if text(take(&mut root, "schema")?)? != RESULT_SCHEMA {
            return Err(SdkError::ResultSchema);
        }
        let receipt = text(take(&mut root, "receipt")?)?.to_owned();
        if receipt.is_empty() {
            return Err(SdkError::ResultField);
        }
        let commitment = decode_prefixed::<32>(text(take(&mut root, "commitment")?)?)?;
        let execution_id = decode_prefixed::<16>(text(take(&mut root, "execution_id")?)?)?;
        ExecutionId::from_bytes(execution_id).map_err(|_| SdkError::ResultField)?;
        let outcome = decode_outcome(take(&mut root, "outcome")?)?;
        Ok(Self {
            receipt,
            execution_id,
            commitment,
            outcome,
        })
    }

    #[must_use]
    pub fn receipt(&self) -> &str {
        &self.receipt
    }

    #[must_use]
    pub fn execution_id(&self) -> &[u8; 16] {
        &self.execution_id
    }

    #[must_use]
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    #[must_use]
    pub fn outcome(&self) -> &RunOutcome {
        &self.outcome
    }
}

/// Stable SDK construction and projection errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdkError {
    PlanShape,
    PlanDuplicate,
    Plan(PlanError),
    CborBound,
    ResultMalformed,
    ResultSchema,
    ResultUnknownField,
    ResultField,
}

impl SdkError {
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::PlanShape => "sdk.plan.shape-invalid",
            Self::PlanDuplicate => "sdk.plan.duplicate",
            Self::Plan(error) => error.code(),
            Self::CborBound => "sdk.plan.cbor-bound",
            Self::ResultMalformed => "sdk.result.malformed-json",
            Self::ResultSchema => "sdk.result.schema-unsupported",
            Self::ResultUnknownField => "sdk.result.unknown-field",
            Self::ResultField => "sdk.result.field-invalid",
        }
    }
}

impl fmt::Display for SdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for SdkError {}

#[derive(Clone, Debug)]
enum Cbor {
    Unsigned(u64),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(&'static str, Cbor)>),
}

fn text_array(values: Vec<String>) -> Cbor {
    Cbor::Array(values.into_iter().map(Cbor::Text).collect())
}

fn encode(value: &Cbor, output: &mut Vec<u8>) -> Result<(), SdkError> {
    match value {
        Cbor::Unsigned(value) => encode_argument(0, *value, output),
        Cbor::Text(value) => {
            encode_argument(3, value.len() as u64, output)?;
            output.extend_from_slice(value.as_bytes());
            Ok(())
        }
        Cbor::Array(values) => {
            encode_argument(4, values.len() as u64, output)?;
            for value in values {
                encode(value, output)?;
            }
            Ok(())
        }
        Cbor::Map(entries) => {
            let mut encoded = entries
                .iter()
                .map(|(key, value)| {
                    let mut key_bytes = Vec::new();
                    encode(&Cbor::Text((*key).to_owned()), &mut key_bytes)?;
                    let mut value_bytes = Vec::new();
                    encode(value, &mut value_bytes)?;
                    Ok((key_bytes, value_bytes))
                })
                .collect::<Result<Vec<_>, SdkError>>()?;
            encoded.sort_by(|left, right| left.0.cmp(&right.0));
            encode_argument(5, encoded.len() as u64, output)?;
            for (key, value) in encoded {
                output.extend_from_slice(&key);
                output.extend_from_slice(&value);
            }
            Ok(())
        }
    }
}

fn encode_argument(major: u8, value: u64, output: &mut Vec<u8>) -> Result<(), SdkError> {
    match value {
        0..=23 => output.push((major << 5) | value as u8),
        24..=0xff => {
            output.push((major << 5) | 24);
            output.push(value as u8);
        }
        0x100..=0xffff => {
            output.push((major << 5) | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push((major << 5) | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push((major << 5) | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
    Ok(())
}

fn require_unique(values: &[String]) -> Result<(), SdkError> {
    if values.iter().collect::<BTreeSet<_>>().len() == values.len() {
        Ok(())
    } else {
        Err(SdkError::PlanDuplicate)
    }
}

fn object(value: Value) -> Result<Map<String, Value>, SdkError> {
    value.as_object().cloned().ok_or(SdkError::ResultField)
}

fn require_keys(root: &Map<String, Value>, expected: &[&str]) -> Result<(), SdkError> {
    let actual = root.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(SdkError::ResultUnknownField)
    }
}

fn take(root: &mut Map<String, Value>, name: &str) -> Result<Value, SdkError> {
    root.remove(name).ok_or(SdkError::ResultField)
}

fn text(value: Value) -> Result<String, SdkError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(SdkError::ResultField)
}

fn decode_outcome(value: Value) -> Result<RunOutcome, SdkError> {
    let mut outcome = object(value)?;
    let kind = outcome
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(SdkError::ResultField)?
        .to_owned();
    match kind.as_str() {
        "exited" => {
            require_keys(&outcome, &["code", "kind"])?;
            let code = take(&mut outcome, "code")?
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or(SdkError::ResultField)?;
            Ok(RunOutcome::Exited { code })
        }
        "signaled" => {
            require_keys(&outcome, &["kind", "signal"])?;
            let signal = take(&mut outcome, "signal")?
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or(SdkError::ResultField)?;
            Ok(RunOutcome::Signaled { signal })
        }
        "timed-out" | "denied" | "launcher-failed" | "incomplete" => {
            require_keys(&outcome, &["kind"])?;
            Ok(match kind.as_str() {
                "timed-out" => RunOutcome::TimedOut,
                "denied" => RunOutcome::Denied,
                "launcher-failed" => RunOutcome::LauncherFailed,
                "incomplete" => RunOutcome::Incomplete,
                _ => unreachable!(),
            })
        }
        _ => Err(SdkError::ResultField),
    }
}

fn decode_prefixed<const N: usize>(value: String) -> Result<[u8; N], SdkError> {
    let value = value.strip_prefix("hex:").ok_or(SdkError::ResultField)?;
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SdkError::ResultField);
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(output)
}

fn nibble(value: u8) -> Result<u8, SdkError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(SdkError::ResultField),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden_input() -> PlanV2Input {
        PlanV2Input {
            id: "golden-v2".to_owned(),
            executable: "bin/hello".to_owned(),
            arguments: Vec::new(),
            working_directory: ".".to_owned(),
            read: Vec::new(),
            runtime_read: Vec::new(),
            write: vec!["out".to_owned()],
            execute: vec!["bin/hello".to_owned()],
            environment: Vec::new(),
            processes: 2,
            wall_time_ms: 1_000,
            stdout_bytes: 1_024,
            stderr_bytes: 1_024,
            memory_bytes: 65_536,
            swap_bytes: 0,
        }
    }

    #[test]
    fn rust_plan_matches_the_frozen_v2_golden() {
        let plan = PlanV2::new(golden_input()).expect("golden plan validates");
        let expected = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/vectors/v2/execution-plan.cbor.hex"
        ))
        .split_whitespace()
        .collect::<String>();
        assert_eq!(hex(plan.as_bytes()), expected);
    }

    #[test]
    fn duplicate_or_mismatched_authority_is_rejected_before_encoding() {
        let mut duplicate = golden_input();
        duplicate.read = vec!["input".to_owned(), "input".to_owned()];
        assert_eq!(PlanV2::new(duplicate), Err(SdkError::PlanDuplicate));
        let mut mismatch = golden_input();
        mismatch.execute = vec!["bin/other".to_owned()];
        assert_eq!(PlanV2::new(mismatch), Err(SdkError::PlanShape));
    }

    #[test]
    fn run_result_projection_is_closed_and_validates_external_identities() {
        let input = br#"{"schema":"proofbound-runtime-run-result/2","outcome":{"kind":"exited","code":0},"receipt":"receipt.cbor","commitment":"hex:0909090909090909090909090909090909090909090909090909090909090909","execution_id":"hex:00000000000040008000000000000000"}"#;
        let result = RunResultProjection::from_json(input).expect("projection validates");
        assert_eq!(result.outcome(), &RunOutcome::Exited { code: 0 });
        assert_eq!(result.receipt(), "receipt.cbor");

        let unknown = input
            .strip_suffix(b"}")
            .unwrap()
            .iter()
            .copied()
            .chain(b",\"verified\":true}".iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(
            RunResultProjection::from_json(&unknown),
            Err(SdkError::ResultUnknownField)
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
