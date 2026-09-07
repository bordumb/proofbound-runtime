#![forbid(unsafe_code)]

//! Defines independent receipt verification decisions.

mod canonical;
mod decode;
mod derive;

#[cfg(test)]
mod test_support;

pub use canonical::{CanonicalError, validate_canonical_receipt};
pub use decode::{DecodeError, DecodedReceipt, RecordedEligibility, decode_receipt};
pub use derive::{
    BoundaryState, CaptureState, EligibilityDecision, EligibilityInput, FailureReason,
    FailureReasons, OutcomeState, StructureState, derive_eligibility,
};
