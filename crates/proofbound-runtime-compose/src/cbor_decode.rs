//! Verifier-side deterministic-CBOR decoder for composed receipts.

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

pub(crate) fn project_composed_v2(input: &[u8]) -> Result<Json, ()> {
    project(&decode(input)?, &mut Vec::new(), false)
}

pub(crate) fn decode_composed_v2_model(input: &[u8]) -> Result<Json, ()> {
    project(&decode(input)?, &mut Vec::new(), true)
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
        if value < minimum {
            return Err(());
        }
        Ok(value)
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
                let text = core::str::from_utf8(bytes).map_err(|_| ())?;
                Ok(Value::Text(text.to_owned()))
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
            let key_start = self.offset;
            let key = match self.item(depth + 1)? {
                Value::Text(key) => key,
                _ => return Err(()),
            };
            let key_encoding = self.input.get(key_start..self.offset).ok_or(())?;
            if previous.is_some_and(|previous| key_encoding <= previous) {
                return Err(());
            }
            previous = Some(key_encoding);
            values.push((key, self.item(depth + 1)?));
        }
        Ok(Value::Map(values))
    }
}

fn project(value: &Value, path: &mut Vec<String>, model: bool) -> Result<Json, ()> {
    Ok(match value {
        Value::Unsigned(value)
            if exact_decimal_path(path)
                && (!model || path.last().is_some_and(|field| field == "size")) =>
        {
            Json::String(value.to_string())
        }
        Value::Unsigned(value) => Json::from(*value),
        Value::Negative(argument) => {
            let value = -1_i128
                .checked_sub(i128::from(*argument))
                .and_then(|value| i64::try_from(value).ok())
                .ok_or(())?;
            Json::from(value)
        }
        Value::Bytes(bytes) if model => Json::String(model_bytes(bytes, path)?),
        Value::Bytes(bytes) => Json::String(format!("hex:{}", hex(bytes))),
        Value::Text(value) => Json::String(value.clone()),
        Value::Array(values) => Json::Array(
            values
                .iter()
                .map(|value| project(value, path, model))
                .collect::<Result<_, _>>()?,
        ),
        Value::Map(values) => {
            let mut object = serde_json::Map::with_capacity(values.len());
            for (key, value) in values {
                path.push(key.clone());
                object.insert(key.clone(), project(value, path, model)?);
                path.pop();
            }
            Json::Object(object)
        }
        Value::Bool(value) => Json::Bool(*value),
        Value::Null => Json::Null,
    })
}

fn model_bytes(bytes: &[u8], path: &[String]) -> Result<String, ()> {
    let field = path.last().map(String::as_str).ok_or(())?;
    if field == "execution_id" {
        if bytes.len() != 16 {
            return Err(());
        }
        let value = hex(bytes);
        return Ok(format!(
            "{}-{}-{}-{}-{}",
            &value[0..8],
            &value[8..12],
            &value[12..16],
            &value[16..20],
            &value[20..32]
        ));
    }
    if field == "project_revision" {
        return (bytes.len() == 20).then(|| hex(bytes)).ok_or(());
    }
    if is_digest_path(path) {
        return (bytes.len() == 32)
            .then(|| format!("sha256:{}", hex(bytes)))
            .ok_or(());
    }
    Err(())
}

fn is_digest_path(path: &[String]) -> bool {
    let field = path.last().map(String::as_str);
    matches!(
        field,
        Some("composition_id" | "commitment" | "payload_sha256" | "sha256" | "evidence")
    ) || field == Some("identity") && path.iter().any(|part| part == "artifact_observations")
        || field == Some("dependencies")
}

fn exact_decimal_path(path: &[String]) -> bool {
    matches!(path.last().map(String::as_str), Some("size" | "size_bytes"))
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
    if value > MAX_ITEMS {
        return Err(());
    }
    Ok(value)
}
