//! Composes independent verifier failures without erasing typed causes.

use core::fmt;

use crate::{CanonicalError, ValidationError};

/// Identifies one failure from the complete independent verifier pipeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    /// Canonical decoding or byte validation failed.
    Canonical(CanonicalError),
    /// Identity or semantic validation failed.
    Validation(ValidationError),
}

impl VerifyError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Canonical(error) => error.code(),
            Self::Validation(error) => error.code(),
        }
    }

    /// Returns the stable independent-verification exit code.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        7
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            Self::Validation(error) => Some(error),
        }
    }
}

impl From<CanonicalError> for VerifyError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

impl From<ValidationError> for VerifyError {
    fn from(error: ValidationError) -> Self {
        Self::Validation(error)
    }
}
