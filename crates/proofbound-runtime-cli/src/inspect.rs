use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use serde::de::{DeserializeSeed as _, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Number, Value};

const MAX_RECEIPT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectError {
    Read,
    TooLarge,
    AmbiguousJson,
    Output,
}

impl InspectError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Read => "inspect.input.read-failed",
            Self::TooLarge => "inspect.input.too-large",
            Self::AmbiguousJson => "inspect.input.ambiguous-json",
            Self::Output => "cli.output.write-failed",
        }
    }
}

pub(crate) fn execute(path: &Path, output: &mut impl io::Write) -> Result<(), InspectError> {
    let metadata = fs::metadata(path).map_err(|_| InspectError::Read)?;
    if metadata.len() > MAX_RECEIPT_BYTES as u64 {
        return Err(InspectError::TooLarge);
    }
    let input = fs::read(path).map_err(|_| InspectError::Read)?;
    write_inspection(&input, output)
}

fn write_inspection(input: &[u8], output: &mut impl io::Write) -> Result<(), InspectError> {
    if input.len() > MAX_RECEIPT_BYTES {
        return Err(InspectError::TooLarge);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = UniqueValue
        .deserialize(&mut deserializer)
        .and_then(|value| {
            deserializer.end()?;
            Ok(value)
        })
        .map_err(|_| InspectError::AmbiguousJson)?;
    serde_json::to_writer_pretty(&mut *output, &value).map_err(|_| InspectError::Output)?;
    writeln!(output).map_err(|_| InspectError::Output)
}

#[derive(Clone, Copy)]
struct UniqueValue;

impl<'de> serde::de::DeserializeSeed<'de> for UniqueValue {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for UniqueValue {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an unambiguous JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(UniqueValue)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate object key"));
            }
            values.insert(key, map.next_value_seed(UniqueValue)?);
        }
        Ok(Value::Object(values.into_iter().collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspection_only_formats_generic_json() {
        let mut output = Vec::new();
        write_inspection(br#"{"z":1,"a":{"present":true}}"#, &mut output)
            .expect("generic JSON is inspectable");
        assert_eq!(
            String::from_utf8(output).expect("inspection is UTF-8"),
            "{\n  \"a\": {\n    \"present\": true\n  },\n  \"z\": 1\n}\n"
        );
    }

    #[test]
    fn inspection_rejects_ambiguous_or_oversized_carriers() {
        for input in [br#"{"a":1,"a":2}"#.as_slice(), br#"{"a":]"#.as_slice()] {
            assert_eq!(
                write_inspection(input, &mut Vec::new()),
                Err(InspectError::AmbiguousJson)
            );
        }
        assert_eq!(
            write_inspection(&vec![b' '; MAX_RECEIPT_BYTES + 1], &mut Vec::new()),
            Err(InspectError::TooLarge)
        );
    }

    #[test]
    fn inspection_projects_a_decoded_v2_cbor_receipt_as_json() {
        let hex = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/vectors/v2/execution-receipt.cbor.hex"
        ));
        let compact = hex.split_whitespace().collect::<String>();
        let input = compact
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(core::str::from_utf8(pair).expect("hex is UTF-8"), 16)
                    .expect("golden vector is hex")
            })
            .collect::<Vec<_>>();
        let mut output = Vec::new();
        write_inspection(&input, &mut output).expect("v2 receipt is inspectable");
        let projection: Value = serde_json::from_slice(&output).expect("projection is JSON");
        assert_eq!(
            projection["schema"],
            "proofbound-runtime-execution-receipt/2"
        );
        assert!(projection.get("resources").is_some());
    }
}
