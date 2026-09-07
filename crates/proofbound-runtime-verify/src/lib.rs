#![forbid(unsafe_code)]

//! Defines independent receipt verification decisions.

mod decode;
mod derive;

pub use decode::{DecodeError, DecodedReceipt, RecordedEligibility, decode_receipt};
pub use derive::{
    BoundaryState, CaptureState, EligibilityDecision, EligibilityInput, FailureReason,
    FailureReasons, OutcomeState, StructureState, derive_eligibility,
};
