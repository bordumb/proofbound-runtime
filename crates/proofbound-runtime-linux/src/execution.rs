//! Creates fresh execution identities before native boundary installation.

use core::fmt;
#[cfg(target_os = "linux")]
use std::io::Read as _;

use proofbound_runtime_core::ExecutionId;

/// Identifies one native execution-setup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionSetupError {
    /// The host operating system is not Linux.
    UnsupportedOperatingSystem,
    /// The operating-system random source did not return a complete identity.
    RandomUnavailable,
}

impl ExecutionSetupError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "execution.os.unsupported",
            Self::RandomUnavailable => "execution.id.random-unavailable",
        }
    }
}

impl fmt::Display for ExecutionSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ExecutionSetupError {}

/// Creates a fresh RFC 4122 version 4 execution identity.
pub fn fresh_execution_id() -> Result<ExecutionId, ExecutionSetupError> {
    #[cfg(target_os = "linux")]
    {
        let mut bytes = [0_u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut bytes))
            .map_err(|_| ExecutionSetupError::RandomUnavailable)?;
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        ExecutionId::from_bytes(bytes).map_err(|_| ExecutionSetupError::RandomUnavailable)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(ExecutionSetupError::UnsupportedOperatingSystem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_distinct() {
        assert_ne!(
            ExecutionSetupError::UnsupportedOperatingSystem.code(),
            ExecutionSetupError::RandomUnavailable.code()
        );
    }
}
