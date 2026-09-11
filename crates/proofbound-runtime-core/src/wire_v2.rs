//! Production-side decoder for the closed deterministic-CBOR v2 wire subset.
//!
//! The independent verifier owns a separate implementation. This module is
//! intentionally private to the producer/core side of the Runtime.

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Value {
    Unsigned(u64),
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Self>),
    Map(Vec<(String, Self)>),
    Bool(bool),
    Null,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Invalid,
    NonDeterministic,
    LimitExceeded,
}

const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 128;
const MAX_ITEMS: usize = 1_000_000;

pub(crate) fn decode(input: &[u8]) -> Result<Value, Error> {
    if input.is_empty() || input.len() > MAX_BYTES {
        return Err(Error::LimitExceeded);
    }
    let mut decoder = Decoder {
        input,
        offset: 0,
        items: 0,
    };
    let value = decoder.item(0)?;
    if decoder.offset != input.len() {
        return Err(Error::Invalid);
    }
    Ok(value)
}

pub(crate) fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    encode_item(value, &mut output)?;
    Ok(output)
}

/// Assembles one deterministic text-keyed map from separately encoded,
/// canonical field values. The receipt binding boundary works over these exact
/// value bytes, so this operation must not decode and reconstruct them.
pub(crate) fn encode_bound_map(values: Vec<(String, Vec<u8>)>) -> Result<Vec<u8>, Error> {
    let mut entries = Vec::new();
    entries
        .try_reserve(values.len())
        .map_err(|_| Error::LimitExceeded)?;
    for (key, value) in values {
        let mut key_encoding = Vec::new();
        encode_item(&Value::Text(key), &mut key_encoding)?;
        let decoded = decode(&value)?;
        if encode(&decoded)? != value {
            return Err(Error::NonDeterministic);
        }
        entries.push((key_encoding, value));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(Error::Invalid);
    }
    let mut output = Vec::new();
    encode_length(5, entries.len(), &mut output)?;
    for (key, value) in entries {
        output.extend_from_slice(&key);
        output.extend_from_slice(&value);
    }
    Ok(output)
}

fn encode_item(value: &Value, output: &mut Vec<u8>) -> Result<(), Error> {
    match value {
        Value::Unsigned(value) => encode_argument(0, *value, output),
        Value::Negative(argument) => encode_argument(1, *argument, output),
        Value::Bytes(value) => {
            encode_length(2, value.len(), output)?;
            output.extend_from_slice(value);
        }
        Value::Text(value) => {
            encode_length(3, value.len(), output)?;
            output.extend_from_slice(value.as_bytes());
        }
        Value::Array(values) => {
            encode_length(4, values.len(), output)?;
            for value in values {
                encode_item(value, output)?;
            }
        }
        Value::Map(values) => encode_map(values, output)?,
        Value::Bool(value) => output.push(if *value { 0xf5 } else { 0xf4 }),
        Value::Null => output.push(0xf6),
    }
    Ok(())
}

fn encode_map(values: &[(String, Value)], output: &mut Vec<u8>) -> Result<(), Error> {
    let mut entries = Vec::new();
    entries
        .try_reserve(values.len())
        .map_err(|_| Error::LimitExceeded)?;
    for (key, value) in values {
        let mut key_encoding = Vec::new();
        encode_item(&Value::Text(key.clone()), &mut key_encoding)?;
        entries.push((key_encoding, value));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(Error::Invalid);
    }
    encode_length(5, entries.len(), output)?;
    for (key_encoding, value) in entries {
        output.extend_from_slice(&key_encoding);
        encode_item(value, output)?;
    }
    Ok(())
}

fn encode_length(major: u8, length: usize, output: &mut Vec<u8>) -> Result<(), Error> {
    let length = u64::try_from(length).map_err(|_| Error::LimitExceeded)?;
    encode_argument(major, length, output);
    Ok(())
}

fn encode_argument(major: u8, argument: u64, output: &mut Vec<u8>) {
    let prefix = major << 5;
    if argument < 24 {
        output.push(prefix | u8::try_from(argument).expect("argument is smaller than 24"));
    } else if let Ok(value) = u8::try_from(argument) {
        output.extend_from_slice(&[prefix | 24, value]);
    } else if let Ok(value) = u16::try_from(argument) {
        output.push(prefix | 25);
        output.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(argument) {
        output.push(prefix | 26);
        output.extend_from_slice(&value.to_be_bytes());
    } else {
        output.push(prefix | 27);
        output.extend_from_slice(&argument.to_be_bytes());
    }
}

struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
    items: usize,
}

impl Decoder<'_> {
    fn take(&mut self, length: usize) -> Result<&[u8], Error> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(Error::LimitExceeded)?;
        let value = self.input.get(self.offset..end).ok_or(Error::Invalid)?;
        self.offset = end;
        Ok(value)
    }

    fn argument(&mut self, additional: u8) -> Result<u64, Error> {
        if additional < 24 {
            return Ok(u64::from(additional));
        }
        let (width, minimum) = match additional {
            24 => (1, 24),
            25 => (2, 1 << 8),
            26 => (4, 1 << 16),
            27 => (8, 1 << 32),
            31 => return Err(Error::NonDeterministic),
            _ => return Err(Error::Invalid),
        };
        let bytes = self.take(width)?;
        let mut full = [0_u8; 8];
        full[8 - width..].copy_from_slice(bytes);
        let value = u64::from_be_bytes(full);
        if value < minimum {
            return Err(Error::NonDeterministic);
        }
        Ok(value)
    }

    fn item(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH || self.items >= MAX_ITEMS {
            return Err(Error::LimitExceeded);
        }
        self.items += 1;
        let initial = *self.take(1)?.first().ok_or(Error::Invalid)?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        if major == 7 {
            return match additional {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(Error::Invalid),
            };
        }
        let argument = self.argument(additional)?;
        match major {
            0 => Ok(Value::Unsigned(argument)),
            1 => Ok(Value::Negative(argument)),
            2 => Ok(Value::Bytes(self.take(to_usize(argument)?)?.to_vec())),
            3 => {
                let bytes = self.take(to_usize(argument)?)?;
                let text = core::str::from_utf8(bytes).map_err(|_| Error::Invalid)?;
                Ok(Value::Text(text.to_owned()))
            }
            4 => {
                let count = bounded_count(argument)?;
                let mut values = Vec::new();
                values
                    .try_reserve(count)
                    .map_err(|_| Error::LimitExceeded)?;
                for _ in 0..count {
                    values.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(values))
            }
            5 => self.map(argument, depth),
            6 => Err(Error::Invalid),
            _ => Err(Error::Invalid),
        }
    }

    fn map(&mut self, argument: u64, depth: usize) -> Result<Value, Error> {
        let count = bounded_count(argument)?;
        let mut values = Vec::new();
        values
            .try_reserve(count)
            .map_err(|_| Error::LimitExceeded)?;
        let mut previous: Option<&[u8]> = None;
        for _ in 0..count {
            let key_start = self.offset;
            let key = match self.item(depth + 1)? {
                Value::Text(key) => key,
                _ => return Err(Error::Invalid),
            };
            let key_encoding = self
                .input
                .get(key_start..self.offset)
                .ok_or(Error::Invalid)?;
            if previous.is_some_and(|previous| key_encoding <= previous) {
                return Err(Error::NonDeterministic);
            }
            previous = Some(key_encoding);
            let value = self.item(depth + 1)?;
            values.push((key, value));
        }
        Ok(Value::Map(values))
    }
}

fn to_usize(value: u64) -> Result<usize, Error> {
    usize::try_from(value).map_err(|_| Error::LimitExceeded)
}

fn bounded_count(value: u64) -> Result<usize, Error> {
    let value = to_usize(value)?;
    if value > MAX_ITEMS {
        return Err(Error::LimitExceeded);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_noncanonical_and_unadmitted_encodings() {
        let attacks: &[&[u8]] = &[
            &[0x18, 0x17],
            &[0x9f, 0xff],
            &[0xa1, 0x00, 0x00],
            &[0xa2, 0x61, b'b', 0x00, 0x61, b'a', 0x00],
            &[0xa2, 0x61, b'a', 0x00, 0x61, b'a', 0x01],
            &[0x00, 0x00],
            &[0xc0, 0x00],
            &[0xf9, 0x00, 0x00],
        ];
        for attack in attacks {
            assert!(decode(attack).is_err());
        }
    }

    #[test]
    fn encoder_uses_bytewise_text_key_order_and_shortest_arguments() {
        let value = Value::Map(vec![
            ("memory.max".to_owned(), Value::Unsigned(65_536)),
            ("pids.max".to_owned(), Value::Unsigned(2)),
        ]);
        let encoded = encode(&value).expect("fixture encodes");
        assert_eq!(
            decode(&encoded),
            Ok(Value::Map(vec![
                ("pids.max".to_owned(), Value::Unsigned(2)),
                ("memory.max".to_owned(), Value::Unsigned(65_536)),
            ]))
        );
        assert!(encoded.windows(9).any(|window| window == b"hpids.max"));
    }

    #[test]
    fn bound_map_preserves_canonical_field_value_bytes() {
        let first = encode(&Value::Unsigned(65_536)).expect("field encodes");
        let second = encode(&Value::Text("value".to_owned())).expect("field encodes");
        let encoded = encode_bound_map(vec![
            ("longer".to_owned(), first.clone()),
            ("a".to_owned(), second.clone()),
        ])
        .expect("map encodes");

        assert!(encoded.windows(first.len()).any(|window| window == first));
        assert!(encoded.windows(second.len()).any(|window| window == second));
        assert_eq!(encode(&decode(&encoded).expect("map decodes")), Ok(encoded));
    }
}
