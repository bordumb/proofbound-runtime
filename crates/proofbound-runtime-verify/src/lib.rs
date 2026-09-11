#![forbid(unsafe_code)]

//! Defines independent receipt verification decisions.

mod canonical;
mod cbor;
mod commitment;
mod decode;
mod decode_v2;
mod derive;
mod error;
mod identity;

#[cfg(test)]
mod attack_tests;
#[cfg(test)]
mod test_support;

pub use canonical::{CanonicalError, validate_canonical_receipt};
pub use commitment::{CommitmentError, ReceiptCommitment};
pub use decode::{
    CompositionArtifact, CompositionTcbEntry, DecodeError, DecodedReceipt, ReceiptAcceptanceFacts,
    ReceiptCompositionFacts, RecordedEligibility, decode_receipt,
};
pub use derive::{
    BoundaryState, CaptureState, EligibilityDecision, EligibilityInput, FailureReason,
    FailureReasons, OutcomeState, StructureState, derive_eligibility,
};
pub use error::VerifyError;
pub use identity::{ValidationError, validate_receipt};

/// Contains one independently verified receipt decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReport {
    commitment: ReceiptCommitment,
    eligibility: EligibilityDecision,
}

impl VerificationReport {
    /// Returns the independently derived eligibility decision.
    #[must_use]
    pub const fn eligibility(&self) -> &EligibilityDecision {
        &self.eligibility
    }

    /// Returns the externally supplied commitment that was verified.
    #[must_use]
    pub const fn commitment(&self) -> ReceiptCommitment {
        self.commitment
    }

    /// Returns one compact machine-readable JSON result.
    #[must_use]
    pub fn machine_json(&self) -> String {
        let (status, reasons) = match &self.eligibility {
            EligibilityDecision::Reusable => ("reusable", Vec::new()),
            EligibilityDecision::NonReusable(reasons) => (
                "non-reusable",
                reasons
                    .as_slice()
                    .iter()
                    .map(|reason| reason.as_str())
                    .collect(),
            ),
        };
        serde_json::json!({
            "eligibility": {"reasons": reasons, "status": status},
            "receipt_commitment": self.commitment.to_text(),
            "valid": true
        })
        .to_string()
    }
}

/// Independently validates canonical bytes, identities, and eligibility.
pub fn verify_receipt(
    input: &[u8],
    expected: ReceiptCommitment,
) -> Result<VerificationReport, VerifyError> {
    let decoded = validate_canonical_receipt(input)?;
    expected.verify(input)?;
    validate_receipt(&decoded)?;
    Ok(VerificationReport {
        commitment: expected,
        eligibility: derive_eligibility(&decoded.eligibility_input()),
    })
}

#[cfg(test)]
mod verification_tests {
    use super::*;
    use crate::test_support::{bytes, receipt};

    #[test]
    fn complete_pipeline_reports_reusable_receipt_as_machine_json() {
        let input = bytes(&receipt());
        let commitment = ReceiptCommitment::for_bytes(&input);
        let report = verify_receipt(&input, commitment).expect("fixture verifies");
        assert_eq!(report.eligibility(), &EligibilityDecision::Reusable);
        assert_eq!(report.commitment(), commitment);
        assert_eq!(
            report.machine_json(),
            format!(
                "{{\"eligibility\":{{\"reasons\":[],\"status\":\"reusable\"}},\"receipt_commitment\":\"{}\",\"valid\":true}}",
                commitment.to_text()
            )
        );
    }

    #[test]
    fn complete_pipeline_preserves_typed_failure() {
        let mut forged = receipt();
        forged["eligibility"]["status"] = serde_json::json!("non-reusable");
        forged["eligibility"]["reasons"] = serde_json::json!(["denied"]);
        let input = bytes(&forged);
        assert_eq!(
            verify_receipt(&input, ReceiptCommitment::for_bytes(&input)),
            Err(VerifyError::Validation(
                ValidationError::EligibilityMismatch
            ))
        );
    }

    #[test]
    fn complete_pipeline_rejects_a_canonical_substitution() {
        let original = bytes(&receipt());
        let commitment = ReceiptCommitment::for_bytes(&original);
        let mut substituted = receipt();
        substituted["command"]["executable"]["sha256"] = serde_json::json!("f".repeat(64));
        assert_eq!(
            verify_receipt(&bytes(&substituted), commitment),
            Err(VerifyError::Commitment(CommitmentError::Mismatch))
        );
    }
}
