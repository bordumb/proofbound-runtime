#![forbid(unsafe_code)]

//! Defines independent receipt verification decisions.

mod derive;

pub use derive::{
    BoundaryState, CaptureState, EligibilityDecision, EligibilityInput, FailureReason,
    FailureReasons, OutcomeState, StructureState, derive_eligibility,
};
