//! Writes canonical diagnostic JSON within one fixed byte bound.

use std::io::{self, Write};

use serde::Serialize;

/// Identifies a bounded canonical JSON write failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanonicalWriteError {
    /// The encoded bytes exceed the declared output bound.
    BoundExceeded,
    /// JSON encoding failed for another reason.
    EncodingFailed,
}

/// Streams JSON bytes and refuses a write that exceeds the declared bound.
pub(crate) struct BoundedCanonicalJson {
    bytes: Vec<u8>,
    limit: usize,
    bound_exceeded: bool,
}

impl BoundedCanonicalJson {
    /// Creates one empty bounded writer.
    pub(crate) fn new(limit: u64) -> Result<Self, CanonicalWriteError> {
        let limit = usize::try_from(limit).map_err(|_| CanonicalWriteError::BoundExceeded)?;
        Ok(Self {
            bytes: Vec::new(),
            limit,
            bound_exceeded: false,
        })
    }

    /// Writes fixed JSON syntax.
    pub(crate) fn raw(&mut self, bytes: &[u8]) -> Result<(), CanonicalWriteError> {
        self.write_all(bytes).map_err(|_| self.error())
    }

    /// Writes one JSON value without buffering the complete containing object.
    pub(crate) fn value<T: Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), CanonicalWriteError> {
        serde_json::to_writer(&mut *self, value).map_err(|_| self.error())
    }

    /// Writes one JSON array from a lazy value iterator.
    pub(crate) fn sequence<I, T>(&mut self, values: I) -> Result<(), CanonicalWriteError>
    where
        I: IntoIterator<Item = T>,
        T: Serialize,
    {
        self.raw(b"[")?;
        let mut first = true;
        for value in values {
            if !first {
                self.raw(b",")?;
            }
            first = false;
            self.value(&value)?;
        }
        self.raw(b"]")
    }

    /// Returns the complete bytes after every bounded write succeeds.
    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn error(&self) -> CanonicalWriteError {
        if self.bound_exceeded {
            CanonicalWriteError::BoundExceeded
        } else {
            CanonicalWriteError::EncodingFailed
        }
    }
}

impl Write for BoundedCanonicalJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next_length) = self.bytes.len().checked_add(bytes.len()) else {
            self.bound_exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "diagnostic JSON bound exceeded",
            ));
        };
        if next_length > self.limit {
            self.bound_exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "diagnostic JSON bound exceeded",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
