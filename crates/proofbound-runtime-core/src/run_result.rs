//! Defines the closed run-result wire objects and their display projections.

use std::path::Path;

use serde_json::{Value as Json, json};

use crate::wire_v2::Value as Cbor;
use crate::{ExecutionId, ExecutionOutcome, Sha256Digest};

const SCHEMA: &str = "proofbound-runtime-run-result/2";
const SCHEMA_V3: &str = "proofbound-runtime-run-result/3";

/// Contains one validated version 2 run-result control object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunResultV2 {
    receipt: String,
    execution_id: ExecutionId,
    commitment: Sha256Digest,
    outcome: ExecutionOutcome,
}

/// Contains the version 3 control object with the same terminal facts and a
/// separate schema identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunResultV3(RunResultV2);

impl RunResultV3 {
    /// Validates the closed version 3 control facts.
    pub fn new(
        receipt: &Path,
        execution_id: ExecutionId,
        commitment: Sha256Digest,
        outcome: ExecutionOutcome,
    ) -> Result<Self, RunResultError> {
        RunResultV2::new(receipt, execution_id, commitment, outcome).map(Self)
    }

    /// Returns the deterministic version 3 CBOR bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        crate::wire_v2::encode(&self.0.cbor_value_with_schema(SCHEMA_V3))
            .expect("a validated run result fits the bounded encoder")
    }

    /// Returns a display-only JSON projection.
    #[must_use]
    pub fn json_projection(&self) -> Json {
        self.0.json_projection_with_schema(SCHEMA_V3)
    }
}

impl RunResultV2 {
    /// Validates a receipt path and the closed version 2 outcome domain.
    pub fn new(
        receipt: &Path,
        execution_id: ExecutionId,
        commitment: Sha256Digest,
        outcome: ExecutionOutcome,
    ) -> Result<Self, RunResultError> {
        let receipt = receipt
            .to_str()
            .filter(|value| !value.is_empty())
            .ok_or(RunResultError::ReceiptPathInvalid)?
            .to_owned();
        if matches!(outcome, ExecutionOutcome::Exited { code } if !(0..=255).contains(&code)) {
            return Err(RunResultError::OutcomeInvalid);
        }
        Ok(Self {
            receipt,
            execution_id,
            commitment,
            outcome,
        })
    }

    /// Returns the deterministic-CBOR bytes committed by the control object.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        crate::wire_v2::encode(&self.cbor_value_with_schema(SCHEMA))
            .expect("a validated run result always fits the bounded encoder")
    }

    /// Returns a JSON projection that is never a verification input.
    #[must_use]
    pub fn json_projection(&self) -> Json {
        self.json_projection_with_schema(SCHEMA)
    }

    fn json_projection_with_schema(&self, schema: &str) -> Json {
        json!({
            "schema": schema,
            "outcome": outcome_json(self.outcome),
            "receipt": self.receipt,
            "commitment": format!("hex:{}", self.commitment.to_hex()),
            "execution_id": format!("hex:{}", hex(self.execution_id.as_bytes())),
        })
    }

    fn cbor_value_with_schema(&self, schema: &str) -> Cbor {
        Cbor::Map(vec![
            ("schema".to_owned(), Cbor::Text(schema.to_owned())),
            ("outcome".to_owned(), outcome_cbor(self.outcome)),
            ("receipt".to_owned(), Cbor::Text(self.receipt.clone())),
            (
                "commitment".to_owned(),
                Cbor::Bytes(self.commitment.as_bytes().to_vec()),
            ),
            (
                "execution_id".to_owned(),
                Cbor::Bytes(self.execution_id.as_bytes().to_vec()),
            ),
        ])
    }
}

/// Identifies invalid v2 run-result construction input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunResultError {
    /// The receipt path is empty or not UTF-8.
    ReceiptPathInvalid,
    /// The exit code is outside the closed portable process-exit range.
    OutcomeInvalid,
}

fn outcome_cbor(outcome: ExecutionOutcome) -> Cbor {
    let (kind, detail) = match outcome {
        ExecutionOutcome::Exited { code } => (
            "exited",
            Some((
                "code",
                Cbor::Unsigned(u64::try_from(code).expect("validated exit code")),
            )),
        ),
        ExecutionOutcome::Signaled { signal } => (
            "signaled",
            Some(("signal", Cbor::Unsigned(u64::from(signal.get())))),
        ),
        ExecutionOutcome::TimedOut => ("timed-out", None),
        ExecutionOutcome::Denied => ("denied", None),
        ExecutionOutcome::LauncherFailed => ("launcher-failed", None),
        ExecutionOutcome::Incomplete => ("incomplete", None),
    };
    let mut fields = vec![("kind".to_owned(), Cbor::Text(kind.to_owned()))];
    if let Some((name, value)) = detail {
        fields.push((name.to_owned(), value));
    }
    Cbor::Map(fields)
}

fn outcome_json(outcome: ExecutionOutcome) -> Json {
    match outcome {
        ExecutionOutcome::Exited { code } => json!({"kind": "exited", "code": code}),
        ExecutionOutcome::Signaled { signal } => {
            json!({"kind": "signaled", "signal": signal.get()})
        }
        ExecutionOutcome::TimedOut => json!({"kind": "timed-out"}),
        ExecutionOutcome::Denied => json!({"kind": "denied"}),
        ExecutionOutcome::LauncherFailed => json!({"kind": "launcher-failed"}),
        ExecutionOutcome::Incomplete => json!({"kind": "incomplete"}),
    }
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{ExecutionId, ExecutionOutcome, Sha256Digest};

    #[test]
    fn version_two_run_result_matches_the_frozen_cbor_golden() {
        let execution_id =
            ExecutionId::from_bytes([0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0])
                .expect("golden execution ID is version 4");
        let result = super::RunResultV2::new(
            Path::new("receipt.cbor"),
            execution_id,
            Sha256Digest::from_bytes([9; 32]),
            ExecutionOutcome::Exited { code: 0 },
        )
        .expect("golden run result is valid");
        let expected = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/vectors/v2/run-result.cbor.hex"
        ))
        .split_whitespace()
        .collect::<String>();
        assert_eq!(encode_hex(&result.canonical_bytes()), expected);
        assert_eq!(
            result.json_projection()["schema"],
            "proofbound-runtime-run-result/2"
        );
    }

    #[test]
    fn version_three_run_result_matches_its_separate_golden() {
        let execution_id =
            ExecutionId::from_bytes([0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0])
                .expect("golden execution ID is version 4");
        let result = super::RunResultV3::new(
            Path::new("receipt.cbor"),
            execution_id,
            Sha256Digest::from_bytes([9; 32]),
            ExecutionOutcome::Exited { code: 0 },
        )
        .expect("golden run result is valid");
        let expected = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/vectors/v3/run-result.cbor.hex"
        ))
        .split_whitespace()
        .collect::<String>();
        assert_eq!(encode_hex(&result.canonical_bytes()), expected);
        assert_eq!(
            result.json_projection()["schema"],
            "proofbound-runtime-run-result/3"
        );
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
