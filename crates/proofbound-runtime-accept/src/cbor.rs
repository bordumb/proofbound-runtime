//! Strict policy decoder and deterministic decision encoder.

use serde_json::Value as Json;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Value {
    Unsigned(u64),
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Self>),
    Map(Vec<(String, Self)>),
    Bool(bool),
    Null,
}

const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_DEPTH: usize = 128;
const MAX_ITEMS: usize = 1_000_000;

pub(crate) fn decode_model(input: &[u8]) -> Result<Json, ()> {
    project(&decode(input)?, &mut Vec::new())
}

pub(crate) fn project_json(input: &[u8]) -> Result<Json, ()> {
    project(&decode(input)?, &mut Vec::new())
}

pub(crate) fn encode_model(value: &Json) -> Result<Vec<u8>, ()> {
    let mut output = Vec::new();
    encode_json(value, &mut Vec::new(), &mut output)?;
    Ok(output)
}

fn decode(input: &[u8]) -> Result<Value, ()> {
    if input.is_empty() || input.len() > MAX_BYTES {
        return Err(());
    }
    let mut decoder = Decoder {
        input,
        offset: 0,
        items: 0,
    };
    let value = decoder.item(0)?;
    if decoder.offset != input.len() {
        return Err(());
    }
    Ok(value)
}

struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
    items: usize,
}

impl Decoder<'_> {
    fn take(&mut self, length: usize) -> Result<&[u8], ()> {
        let end = self.offset.checked_add(length).ok_or(())?;
        let value = self.input.get(self.offset..end).ok_or(())?;
        self.offset = end;
        Ok(value)
    }

    fn argument(&mut self, additional: u8) -> Result<u64, ()> {
        if additional < 24 {
            return Ok(u64::from(additional));
        }
        let (width, minimum) = match additional {
            24 => (1, 24),
            25 => (2, 1 << 8),
            26 => (4, 1 << 16),
            27 => (8, 1 << 32),
            _ => return Err(()),
        };
        let bytes = self.take(width)?;
        let mut full = [0_u8; 8];
        full[8 - width..].copy_from_slice(bytes);
        let value = u64::from_be_bytes(full);
        (value >= minimum).then_some(value).ok_or(())
    }

    fn item(&mut self, depth: usize) -> Result<Value, ()> {
        if depth > MAX_DEPTH || self.items >= MAX_ITEMS {
            return Err(());
        }
        self.items += 1;
        let initial = *self.take(1)?.first().ok_or(())?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        if major == 7 {
            return match additional {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(()),
            };
        }
        let argument = self.argument(additional)?;
        match major {
            0 => Ok(Value::Unsigned(argument)),
            1 => Ok(Value::Negative(argument)),
            2 => Ok(Value::Bytes(self.take(to_usize(argument)?)?.to_vec())),
            3 => {
                let bytes = self.take(to_usize(argument)?)?;
                Ok(Value::Text(
                    core::str::from_utf8(bytes).map_err(|_| ())?.to_owned(),
                ))
            }
            4 => {
                let count = bounded_count(argument)?;
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(values))
            }
            5 => self.map(argument, depth),
            _ => Err(()),
        }
    }

    fn map(&mut self, argument: u64, depth: usize) -> Result<Value, ()> {
        let count = bounded_count(argument)?;
        let mut values = Vec::with_capacity(count);
        let mut previous: Option<&[u8]> = None;
        for _ in 0..count {
            let start = self.offset;
            let key = match self.item(depth + 1)? {
                Value::Text(key) => key,
                _ => return Err(()),
            };
            let encoded = self.input.get(start..self.offset).ok_or(())?;
            if previous.is_some_and(|value| encoded <= value) {
                return Err(());
            }
            previous = Some(encoded);
            values.push((key, self.item(depth + 1)?));
        }
        Ok(Value::Map(values))
    }
}

fn project(value: &Value, path: &mut Vec<String>) -> Result<Json, ()> {
    Ok(match value {
        Value::Unsigned(value) => Json::from(*value),
        Value::Negative(argument) => Json::from(
            -1_i128
                .checked_sub(i128::from(*argument))
                .and_then(|value| i64::try_from(value).ok())
                .ok_or(())?,
        ),
        Value::Bytes(bytes) => Json::String(project_bytes(bytes, path)?),
        Value::Text(value) => Json::String(value.clone()),
        Value::Array(values) => Json::Array(
            values
                .iter()
                .map(|v| project(v, path))
                .collect::<Result<_, _>>()?,
        ),
        Value::Map(values) => {
            let mut object = serde_json::Map::with_capacity(values.len());
            for (key, value) in values {
                path.push(key.clone());
                object.insert(key.clone(), project(value, path)?);
                path.pop();
            }
            Json::Object(object)
        }
        Value::Bool(value) => Json::Bool(*value),
        Value::Null => Json::Null,
    })
}

fn project_bytes(bytes: &[u8], path: &[String]) -> Result<String, ()> {
    match path.last().map(String::as_str) {
        Some("execution_id") if bytes.len() == 16 => {
            let value = hex(bytes);
            Ok(format!(
                "{}-{}-{}-{}-{}",
                &value[0..8],
                &value[8..12],
                &value[12..16],
                &value[16..20],
                &value[20..32]
            ))
        }
        Some("project_revision") if bytes.len() == 20 => Ok(hex(bytes)),
        Some(_) if bytes.len() == 32 => Ok(format!("sha256:{}", hex(bytes))),
        _ => Err(()),
    }
}

fn encode_json(value: &Json, path: &mut Vec<String>, output: &mut Vec<u8>) -> Result<(), ()> {
    match value {
        Json::Null => output.push(0xf6),
        Json::Bool(value) => output.push(if *value { 0xf5 } else { 0xf4 }),
        Json::Number(value) => encode_argument(0, value.as_u64().ok_or(())?, output),
        Json::String(value) => encode_string(value, path, output)?,
        Json::Array(values) => {
            encode_length(4, values.len(), output)?;
            for value in values {
                encode_json(value, path, output)?;
            }
        }
        Json::Object(values) => {
            let mut entries = Vec::with_capacity(values.len());
            for (key, value) in values {
                let mut encoded = Vec::new();
                encode_text(key, &mut encoded)?;
                entries.push((encoded, key, value));
            }
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            encode_length(5, entries.len(), output)?;
            for (key_bytes, key, value) in entries {
                output.extend_from_slice(&key_bytes);
                path.push(key.clone());
                encode_json(value, path, output)?;
                path.pop();
            }
        }
    }
    Ok(())
}

fn encode_string(value: &str, path: &[String], output: &mut Vec<u8>) -> Result<(), ()> {
    match path.last().map(String::as_str) {
        Some("execution_id") => encode_bytes(&parse_uuid(value)?, output)?,
        Some("project_revision") => encode_bytes(&parse_hex_exact(value, 20)?, output)?,
        Some(
            "sha256"
            | "policy_sha256"
            | "payload_sha256"
            | "decision_id"
            | "composition_id"
            | "policy_identity"
            | "execution_commitment",
        ) => {
            encode_bytes(&parse_digest(value)?, output)?;
        }
        _ => encode_text(value, output)?,
    }
    Ok(())
}

fn parse_digest(value: &str) -> Result<Vec<u8>, ()> {
    parse_hex_exact(value.strip_prefix("sha256:").ok_or(())?, 32)
}

fn parse_uuid(value: &str) -> Result<Vec<u8>, ()> {
    if value.len() != 36
        || ![8, 13, 18, 23]
            .into_iter()
            .all(|i| value.as_bytes().get(i) == Some(&b'-'))
    {
        return Err(());
    }
    parse_hex_exact(&value.replace('-', ""), 16)
}

fn parse_hex_exact(value: &str, length: usize) -> Result<Vec<u8>, ()> {
    if value.len() != length.checked_mul(2).ok_or(())? {
        return Err(());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn nibble(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(()),
    }
}

fn encode_text(value: &str, output: &mut Vec<u8>) -> Result<(), ()> {
    encode_length(3, value.len(), output)?;
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_bytes(value: &[u8], output: &mut Vec<u8>) -> Result<(), ()> {
    encode_length(2, value.len(), output)?;
    output.extend_from_slice(value);
    Ok(())
}

fn encode_length(major: u8, value: usize, output: &mut Vec<u8>) -> Result<(), ()> {
    encode_argument(major, u64::try_from(value).map_err(|_| ())?, output);
    Ok(())
}

fn encode_argument(major: u8, value: u64, output: &mut Vec<u8>) {
    if value < 24 {
        output.push((major << 5) | u8::try_from(value).unwrap_or(0));
    } else if let Ok(value) = u8::try_from(value) {
        output.extend_from_slice(&[(major << 5) | 24, value]);
    } else if let Ok(value) = u16::try_from(value) {
        output.push((major << 5) | 25);
        output.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        output.push((major << 5) | 26);
        output.extend_from_slice(&value.to_be_bytes());
    } else {
        output.push((major << 5) | 27);
        output.extend_from_slice(&value.to_be_bytes());
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn to_usize(value: u64) -> Result<usize, ()> {
    usize::try_from(value).map_err(|_| ())
}
fn bounded_count(value: u64) -> Result<usize, ()> {
    let value = to_usize(value)?;
    (value <= MAX_ITEMS).then_some(value).ok_or(())
}
