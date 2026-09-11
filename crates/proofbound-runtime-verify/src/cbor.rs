//! Independent deterministic-CBOR decoder for version 2 receipt verification.

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
                let text = core::str::from_utf8(self.take(to_usize(argument)?)?)
                    .map_err(|_| Error::Invalid)?;
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
            values.push((key, self.item(depth + 1)?));
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
        Err(Error::LimitExceeded)
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independently_rejects_non_deterministic_cbor() {
        for attack in [
            &[0x18, 0x17][..],
            &[0x9f, 0xff],
            &[0xa1, 0x00, 0x00],
            &[0xa2, 0x61, b'b', 0x00, 0x61, b'a', 0x00],
            &[0xa2, 0x61, b'a', 0x00, 0x61, b'a', 0x01],
            &[0xc0, 0x00],
            &[0xf9, 0x00, 0x00],
        ] {
            assert!(decode(attack).is_err());
        }
    }
}
