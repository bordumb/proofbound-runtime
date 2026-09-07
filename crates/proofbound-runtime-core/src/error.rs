//! Defines the shared machine-readable error contract for pure runtime code.

use core::fmt;

use crate::{AuthorityError, IdentityError, PlanError};

/// Identifies one stable command exit-code class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ErrorClass {
    /// User input or a plan is invalid.
    InvalidInput = 2,
    /// The requested platform boundary is unavailable or unsupported.
    UnsupportedBoundary = 3,
    /// A security-relevant identity changed before execution.
    IdentityDrift = 4,
    /// Boundary installation or launcher sequencing failed.
    Launcher = 5,
    /// Receipt construction or canonical encoding failed.
    ReceiptConstruction = 6,
    /// Independent receipt verification failed.
    Verification = 7,
}

impl ErrorClass {
    /// Returns the stable process exit code for this class.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        self as u8
    }
}

/// Exposes an error's stable machine code and exit-code class.
///
/// Callers may render any human diagnostic they need, but automated behavior
/// must use this interface instead of parsing `Display` output.
pub trait MachineError: std::error::Error {
    /// Returns the stable machine-readable error code.
    fn machine_code(&self) -> &'static str;

    /// Returns the stable command exit-code class.
    fn error_class(&self) -> ErrorClass;
}

impl MachineError for AuthorityError {
    fn machine_code(&self) -> &'static str {
        (*self).code()
    }

    fn error_class(&self) -> ErrorClass {
        ErrorClass::InvalidInput
    }
}

impl MachineError for IdentityError {
    fn machine_code(&self) -> &'static str {
        (*self).code()
    }

    fn error_class(&self) -> ErrorClass {
        ErrorClass::InvalidInput
    }
}

impl MachineError for PlanError {
    fn machine_code(&self) -> &'static str {
        (*self).code()
    }

    fn error_class(&self) -> ErrorClass {
        ErrorClass::InvalidInput
    }
}

/// Erases the concrete pure-core error type without erasing its machine
/// contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreError {
    /// Authority validation failed.
    Authority(AuthorityError),
    /// Artifact-identity validation failed.
    Identity(IdentityError),
    /// Execution-plan validation failed.
    Plan(PlanError),
}

impl MachineError for CoreError {
    fn machine_code(&self) -> &'static str {
        match self {
            Self::Authority(error) => error.machine_code(),
            Self::Identity(error) => error.machine_code(),
            Self::Plan(error) => error.machine_code(),
        }
    }

    fn error_class(&self) -> ErrorClass {
        match self {
            Self::Authority(error) => error.error_class(),
            Self::Identity(error) => error.error_class(),
            Self::Plan(error) => error.error_class(),
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.machine_code())
    }
}

impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::Plan(error) => Some(error),
        }
    }
}

impl From<AuthorityError> for CoreError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}

impl From<IdentityError> for CoreError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

impl From<PlanError> for CoreError {
    fn from(error: PlanError) -> Self {
        Self::Plan(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_classes_have_the_frozen_exit_codes() {
        assert_eq!(ErrorClass::InvalidInput.exit_code(), 2);
        assert_eq!(ErrorClass::UnsupportedBoundary.exit_code(), 3);
        assert_eq!(ErrorClass::IdentityDrift.exit_code(), 4);
        assert_eq!(ErrorClass::Launcher.exit_code(), 5);
        assert_eq!(ErrorClass::ReceiptConstruction.exit_code(), 6);
        assert_eq!(ErrorClass::Verification.exit_code(), 7);
    }

    #[test]
    fn type_erasure_preserves_machine_contract_and_source() {
        let error = CoreError::from(PlanError::UnsupportedVersion);
        assert_eq!(error.machine_code(), "plan.schema.unsupported-version");
        assert_eq!(error.error_class(), ErrorClass::InvalidInput);
        assert_eq!(error.to_string(), error.machine_code());
        assert!(std::error::Error::source(&error).is_some());
    }
}
