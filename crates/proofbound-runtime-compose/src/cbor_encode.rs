//! Producer-only deterministic-CBOR encoding for composed receipts.

use serde_json::Value;

pub(crate) fn encode_composed_v2(value: &Value) -> Result<Vec<u8>, ()> {
    let mut output = Vec::new();
    encode_json(value, &mut Vec::new(), &mut output)?;
    Ok(output)
}

fn encode_json(value: &Value, path: &mut Vec<String>, output: &mut Vec<u8>) -> Result<(), ()> {
    match value {
        Value::Null => output.push(0xf6),
        Value::Bool(value) => output.push(if *value { 0xf5 } else { 0xf4 }),
        Value::Number(value) => {
            let value = value.as_u64().ok_or(())?;
            encode_argument(0, value, output);
        }
        Value::String(value) => encode_string(value, path, output)?,
        Value::Array(values) => {
            encode_length(4, values.len(), output)?;
            for value in values {
                encode_json(value, path, output)?;
            }
        }
        Value::Object(values) => {
            let mut entries = Vec::with_capacity(values.len());
            for (key, value) in values {
                let mut encoded_key = Vec::new();
                encode_text(key, &mut encoded_key)?;
                entries.push((encoded_key, key, value));
            }
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            encode_length(5, entries.len(), output)?;
            for (encoded_key, key, value) in entries {
                output.extend_from_slice(&encoded_key);
                path.push(key.clone());
                encode_json(value, path, output)?;
                path.pop();
            }
        }
    }
    Ok(())
}

fn encode_string(value: &str, path: &[String], output: &mut Vec<u8>) -> Result<(), ()> {
    let field = path.last().map(String::as_str).ok_or(())?;
    if field == "size" {
        let value = value.parse::<u64>().map_err(|_| ())?;
        encode_argument(0, value, output);
    } else if field == "execution_id" {
        encode_bytes(&parse_uuid(value)?, output)?;
    } else if field == "project_revision" {
        encode_bytes(&parse_hex_exact(value, 20)?, output)?;
    } else if is_digest_path(path) {
        let digest = value.strip_prefix("sha256:").ok_or(())?;
        encode_bytes(&parse_hex_exact(digest, 32)?, output)?;
    } else {
        encode_text(value, output)?;
    }
    Ok(())
}

fn is_digest_path(path: &[String]) -> bool {
    let field = path.last().map(String::as_str);
    matches!(
        field,
        Some("composition_id" | "commitment" | "payload_sha256" | "sha256" | "evidence")
    ) || field == Some("identity") && path.iter().any(|part| part == "artifact_observations")
        || field == Some("dependencies")
}

fn parse_uuid(value: &str) -> Result<Vec<u8>, ()> {
    if value.len() != 36
        || ![8, 13, 18, 23]
            .into_iter()
            .all(|index| value.as_bytes().get(index) == Some(&b'-'))
    {
        return Err(());
    }
    let compact = value.replace('-', "");
    parse_hex_exact(&compact, 16)
}

fn parse_hex_exact(value: &str, length: usize) -> Result<Vec<u8>, ()> {
    if value.len() != length.checked_mul(2).ok_or(())? {
        return Err(());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(value: u8) -> Result<u8, ()> {
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

fn encode_length(major: u8, length: usize, output: &mut Vec<u8>) -> Result<(), ()> {
    encode_argument(major, u64::try_from(length).map_err(|_| ())?, output);
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
