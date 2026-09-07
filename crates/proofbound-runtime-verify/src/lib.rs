#![forbid(unsafe_code)]

//! Defines independent receipt verification decisions.

mod canonical;
mod decode;
mod derive;
mod error;
mod identity;

#[cfg(test)]
mod test_support;

pub use canonical::{CanonicalError, validate_canonical_receipt};
pub use decode::{DecodeError, DecodedReceipt, RecordedEligibility, decode_receipt};
pub use derive::{
    BoundaryState, CaptureState, EligibilityDecision, EligibilityInput, FailureReason,
    FailureReasons, OutcomeState, StructureState, derive_eligibility,
};
pub use error::VerifyError;
pub use identity::{ValidationError, validate_receipt};

/// Contains one independently verified receipt decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReport {
    eligibility: EligibilityDecision,
}

impl VerificationReport {
    /// Returns the independently derived eligibility decision.
    #[must_use]
    pub const fn eligibility(&self) -> &EligibilityDecision {
        &self.eligibility
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
            "valid": true
        })
        .to_string()
    }
}

/// Independently validates canonical bytes, identities, and eligibility.
pub fn verify_receipt(input: &[u8]) -> Result<VerificationReport, VerifyError> {
    let decoded = validate_canonical_receipt(input)?;
    validate_receipt(&decoded)?;
    Ok(VerificationReport {
        eligibility: derive_eligibility(&decoded.eligibility_input()),
    })
}

#[cfg(test)]
mod verification_tests {
    use super::*;
    use crate::test_support::{bytes, receipt};

    #[test]
    fn complete_pipeline_reports_reusable_receipt_as_machine_json() {
        let report = verify_receipt(&bytes(&receipt())).expect("fixture verifies");
        assert_eq!(report.eligibility(), &EligibilityDecision::Reusable);
        assert_eq!(
            report.machine_json(),
            r#"{"eligibility":{"reasons":[],"status":"reusable"},"valid":true}"#
        );
    }

    #[test]
    fn complete_pipeline_preserves_typed_failure() {
        let mut forged = receipt();
        forged["eligibility"]["status"] = serde_json::json!("non-reusable");
        forged["eligibility"]["reasons"] = serde_json::json!(["denied"]);
        assert_eq!(
            verify_receipt(&bytes(&forged)),
            Err(VerifyError::Validation(
                ValidationError::EligibilityMismatch
            ))
        );
    }
}
