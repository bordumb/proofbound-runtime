//! Validates an externally supplied commitment to exact receipt bytes.

use core::fmt;

use sha2::{Digest, Sha256};

const PREFIX: &str = "sha256:";

/// Contains one exact SHA-256 commitment to canonical receipt bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptCommitment([u8; 32]);

impl ReceiptCommitment {
    /// Parses `sha256:` followed by exactly 64 lowercase hexadecimal digits.
    pub fn parse(value: &str) -> Result<Self, CommitmentError> {
        let Some(hex) = value.strip_prefix(PREFIX) else {
            return Err(CommitmentError::InvalidEncoding);
        };
        let input = hex.as_bytes();
        if input.len() != 64 {
            return Err(CommitmentError::InvalidEncoding);
        }
        let mut bytes = [0_u8; 32];
        for (index, output) in bytes.iter_mut().enumerate() {
            *output = (hex_nibble(input[index * 2])? << 4) | hex_nibble(input[index * 2 + 1])?;
        }
        Ok(Self(bytes))
    }

    /// Computes the commitment to exact receipt bytes.
    #[must_use]
    pub fn for_bytes(input: &[u8]) -> Self {
        Self(Sha256::digest(input).into())
    }

    /// Returns the algorithm-qualified lowercase commitment.
    #[must_use]
    pub fn to_text(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(PREFIX.len() + 64);
        output.push_str(PREFIX);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }

    pub(crate) fn verify(self, input: &[u8]) -> Result<(), CommitmentError> {
        if Self::for_bytes(input) == self {
            Ok(())
        } else {
            Err(CommitmentError::Mismatch)
        }
    }
}

/// Identifies one receipt-commitment failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitmentError {
    /// The commitment lacks the exact algorithm-qualified encoding.
    InvalidEncoding,
    /// Exact receipt bytes differ from the trusted commitment.
    Mismatch,
}

impl CommitmentError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncoding => "receipt.commitment.invalid",
            Self::Mismatch => "receipt.commitment.mismatch",
        }
    }
}

impl fmt::Display for CommitmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CommitmentError {}

fn hex_nibble(value: u8) -> Result<u8, CommitmentError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(CommitmentError::InvalidEncoding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_round_trip_is_exact() {
        let commitment = ReceiptCommitment::for_bytes(b"receipt");
        assert_eq!(
            ReceiptCommitment::parse(&commitment.to_text()),
            Ok(commitment)
        );
        assert_eq!(commitment.verify(b"receipt"), Ok(()));
    }

    #[test]
    fn rejects_unqualified_noncanonical_and_mismatched_commitments() {
        assert_eq!(
            ReceiptCommitment::parse(&"0".repeat(64)),
            Err(CommitmentError::InvalidEncoding)
        );
        assert_eq!(
            ReceiptCommitment::parse(&format!("sha256:{}", "A".repeat(64))),
            Err(CommitmentError::InvalidEncoding)
        );
        assert_eq!(
            ReceiptCommitment::for_bytes(b"receipt").verify(b"substitution"),
            Err(CommitmentError::Mismatch)
        );
    }
}
