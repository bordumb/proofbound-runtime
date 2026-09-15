//! Produces both non-production diagnostic artifacts as one exact subject.

use core::fmt;

use crate::artifact::{DiagnosticArtifactError, DiagnosticReceipt, DiagnosticReceiptParts};
use crate::draft::{DraftError, PlanDraft, PlanDraftInputs, build_plan_draft};

/// Contains the diagnostic receipt and its derived non-policy plan draft.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticArtifacts {
    receipt: DiagnosticReceipt,
    draft: PlanDraft,
}

impl DiagnosticArtifacts {
    /// Returns the non-reusable diagnostic receipt.
    #[must_use]
    pub const fn receipt(&self) -> &DiagnosticReceipt {
        &self.receipt
    }

    /// Returns the reviewable non-policy plan draft.
    #[must_use]
    pub const fn draft(&self) -> &PlanDraft {
        &self.draft
    }
}

/// Constructs both diagnostic artifacts from one validated input set.
pub fn build_diagnostic_artifacts(
    parts: DiagnosticReceiptParts,
    inputs: PlanDraftInputs,
) -> Result<DiagnosticArtifacts, DiagnosticProducerError> {
    let receipt = DiagnosticReceipt::construct(parts).map_err(DiagnosticProducerError::Receipt)?;
    let draft = build_plan_draft(&receipt, inputs).map_err(DiagnosticProducerError::Draft)?;
    Ok(DiagnosticArtifacts { receipt, draft })
}

/// Identifies which diagnostic artifact construction stage failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticProducerError {
    /// Diagnostic receipt construction failed.
    Receipt(DiagnosticArtifactError),
    /// Plan-draft construction failed.
    Draft(DraftError),
}

impl fmt::Display for DiagnosticProducerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Receipt(error) => write!(formatter, "diagnostic.producer.receipt: {error}"),
            Self::Draft(error) => write!(formatter, "diagnostic.producer.draft: {error}"),
        }
    }
}

impl std::error::Error for DiagnosticProducerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::tests::fixture_parts;
    use crate::draft::DraftPathScope;

    #[test]
    fn aggregate_subject_matches_both_canonical_vectors() {
        let artifacts = build_diagnostic_artifacts(
            fixture_parts(),
            PlanDraftInputs {
                path_scope: Some(
                    DraftPathScope::new(
                        ["/workspace".to_owned()],
                        "/workspace/user-home".to_owned(),
                        ["/workspace/.tmp".to_owned()],
                    )
                    .expect("fixture path scope"),
                ),
                ..PlanDraftInputs::default()
            },
        )
        .expect("diagnostic artifacts");
        assert_eq!(
            artifacts.receipt().as_bytes(),
            include_bytes!("../../../schemas/vectors/diagnostic/diagnostic-receipt.json")
                .strip_suffix(b"\n")
                .unwrap_or(include_bytes!(
                    "../../../schemas/vectors/diagnostic/diagnostic-receipt.json"
                ))
        );
        assert_eq!(
            artifacts.draft().as_bytes(),
            include_bytes!("../../../schemas/vectors/diagnostic/plan-draft.json")
                .strip_suffix(b"\n")
                .unwrap_or(include_bytes!(
                    "../../../schemas/vectors/diagnostic/plan-draft.json"
                ))
        );
    }
}
