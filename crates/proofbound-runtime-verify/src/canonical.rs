//! Independently validates canonical execution-receipt bytes.

use core::cell::Cell;
use core::fmt;
use std::collections::HashSet;

use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::{DecodeError, DecodedReceipt, decode_receipt};

/// Identifies one canonical receipt validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalError {
    /// The receipt contains a duplicate object member name.
    DuplicateKey,
    /// The receipt bytes are not the canonical encoding of their value.
    BytesMismatch,
    /// Strict receipt decoding failed.
    Decode(DecodeError),
}

impl CanonicalError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DuplicateKey => "receipt.canonical.duplicate-key",
            Self::BytesMismatch => "receipt.canonical.bytes-mismatch",
            Self::Decode(error) => error.code(),
        }
    }
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CanonicalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::DuplicateKey | Self::BytesMismatch => None,
        }
    }
}

impl From<DecodeError> for CanonicalError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

/// Validates duplicate-free canonical bytes and returns the strict receipt.
pub fn validate_canonical_receipt(input: &[u8]) -> Result<DecodedReceipt, CanonicalError> {
    reject_duplicate_keys(input)?;
    let decoded = decode_receipt(input)?;
    let encoded = serde_json::to_vec(decoded.value()).map_err(|_| CanonicalError::BytesMismatch)?;
    if encoded != input {
        return Err(CanonicalError::BytesMismatch);
    }
    Ok(decoded)
}

fn reject_duplicate_keys(input: &[u8]) -> Result<(), CanonicalError> {
    let duplicate = Cell::new(false);
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    DuplicateDetector {
        duplicate: &duplicate,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| CanonicalError::Decode(DecodeError::MalformedJson))?;
    deserializer
        .end()
        .map_err(|_| CanonicalError::Decode(DecodeError::MalformedJson))?;
    if duplicate.get() {
        return Err(CanonicalError::DuplicateKey);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct DuplicateDetector<'a> {
    duplicate: &'a Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for DuplicateDetector<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for DuplicateDetector<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(self)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                self.duplicate.set(true);
            }
            map.next_value_seed(self)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{bytes, receipt};

    #[test]
    fn accepts_the_exact_canonical_encoding() {
        let canonical = bytes(&receipt());
        let decoded = validate_canonical_receipt(&canonical).expect("canonical receipt validates");
        assert_eq!(decoded.value(), &receipt());
    }

    #[test]
    fn rejects_whitespace_and_member_reordering() {
        let canonical = bytes(&receipt());
        let mut whitespace = canonical.clone();
        whitespace.push(b'\n');
        assert_eq!(
            validate_canonical_receipt(&whitespace),
            Err(CanonicalError::BytesMismatch)
        );

        let canonical_text = String::from_utf8(canonical).expect("fixture is UTF-8");
        let schema = "\"schema\":\"proofbound-runtime-receipt/1\"";
        let without_schema = canonical_text.replacen(&format!(",{schema}"), "", 1);
        let reordered = format!("{{{schema},{}", &without_schema[1..]);
        assert_ne!(reordered, canonical_text);
        assert_eq!(
            validate_canonical_receipt(reordered.as_bytes()),
            Err(CanonicalError::BytesMismatch)
        );
    }

    #[test]
    fn rejects_duplicate_keys_at_any_depth() {
        let canonical = String::from_utf8(bytes(&receipt())).expect("fixture is UTF-8");
        let duplicate = canonical.replacen("\"plan\":{", "\"plan\":{\"id\":\"substitution\",", 1);
        assert_eq!(
            validate_canonical_receipt(duplicate.as_bytes()),
            Err(CanonicalError::DuplicateKey)
        );
    }

    #[test]
    fn preserves_strict_decode_errors() {
        assert_eq!(
            validate_canonical_receipt(br#"{"schema":"#),
            Err(CanonicalError::Decode(DecodeError::MalformedJson))
        );
    }
}
