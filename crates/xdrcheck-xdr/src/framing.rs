//! RFC 5531 record marking, as stellar-core writes its meta stream and golden files.
//!
//! Each record is a 4-byte big-endian mark followed by the record bytes. Bit 31 of the mark is
//! the last-fragment flag; the low 31 bits are the fragment length. stellar-core writes every
//! record as one fragment, so a mark with bit 31 clear is rejected
//! ([`FramingError::LastFragmentBitClear`]) rather than joined with the next fragment. The
//! library's `Frame<T>` is not used: it ignores the mark's length.

use crate::codec::{self, Limits};
use crate::error::{Error, FramingError, Malformed, Result};
use stellar_xdr::Type;

const LAST_FRAGMENT: u32 = 0x8000_0000;

/// One record of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    /// Record number, from 0.
    pub index: usize,
    /// Byte offset of the record mark in the stream.
    pub offset: usize,
    /// The record bytes, without the mark.
    pub payload: &'a [u8],
}

/// Iterator over the records of a record-marked stream. Yields an error for the first framing
/// fault and then stops.
#[derive(Debug, Clone)]
pub struct Records<'a> {
    stream: &'a [u8],
    pos: usize,
    index: usize,
    failed: bool,
}

/// Split a record-marked stream into records lazily.
pub fn records(stream: &[u8]) -> Records<'_> {
    Records {
        stream,
        pos: 0,
        index: 0,
        failed: false,
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = Result<Record<'a>, FramingError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.pos == self.stream.len() {
            return None;
        }
        let r = self.read_one();
        if r.is_err() {
            self.failed = true;
        }
        Some(r)
    }
}

impl<'a> Records<'a> {
    fn read_one(&mut self) -> Result<Record<'a>, FramingError> {
        let offset = self.pos;
        let rest = &self.stream[offset..];
        let (index, available) = (self.index, rest.len());
        let Some(mark) = rest.get(..4) else {
            return Err(FramingError::Truncated {
                index,
                offset,
                declared: 4,
                available,
            });
        };
        let mark = u32::from_be_bytes(mark.try_into().expect("4 bytes"));
        if mark & LAST_FRAGMENT == 0 {
            return Err(FramingError::LastFragmentBitClear {
                index,
                offset,
                mark,
            });
        }
        let declared = (mark & !LAST_FRAGMENT) as usize;
        let Some(payload) = rest[4..].get(..declared) else {
            return Err(FramingError::Truncated {
                index,
                offset,
                declared,
                available: available - 4,
            });
        };
        self.pos = offset + 4 + declared;
        self.index += 1;
        Ok(Record {
            index,
            offset,
            payload,
        })
    }
}

/// Split a whole stream, failing on the first framing fault.
pub fn split(stream: &[u8]) -> Result<Vec<Record<'_>>> {
    records(stream).map(|r| r.map_err(Error::from)).collect()
}

/// Check that a record holds exactly one value of `type_name` and return it decoded. A value that
/// needs more bytes than the mark declares, or ends before the declared length, is a
/// [`FramingError::LengthMismatch`]. Runs on the large-stack thread of `limits`.
pub fn decode_record(type_name: &str, record: &Record<'_>, limits: &Limits) -> Result<Type> {
    codec::decode(type_name, record.payload, limits).map_err(|e| record_error(type_name, record, e))
}

/// Split a stream and check every record holds exactly one value of `type_name` that re-encodes
/// byte-exactly. Returns the records. Stops at the first error, so a corrupted mark is reported
/// at the record where it occurs.
pub fn split_checked<'a>(
    type_name: &str,
    stream: &'a [u8],
    limits: &Limits,
) -> Result<Vec<Record<'a>>> {
    let mut out = Vec::new();
    for r in records(stream) {
        let r = r?;
        check_record(type_name, &r, limits)?;
        out.push(r);
    }
    Ok(out)
}

/// Check that a record holds exactly one value of `type_name` that re-encodes byte-exactly
/// (length faults as in [`decode_record`]).
pub fn check_record(type_name: &str, record: &Record<'_>, limits: &Limits) -> Result<()> {
    codec::roundtrip(type_name, record.payload, limits)
        .map_err(|e| record_error(type_name, record, e))
}

/// Turn "value ran out of bytes" and "bytes left after the value" inside a record into a
/// length mismatch between the mark and the value.
fn record_error(type_name: &str, record: &Record<'_>, e: Error) -> Error {
    let detail = match e {
        Error::Malformed {
            reason: Malformed::UnexpectedEof,
            ..
        } => "needs more bytes".to_string(),
        Error::Malformed {
            reason: Malformed::TrailingBytes { consumed, .. },
            ..
        } => format!("ends after {consumed} bytes"),
        other => return other,
    };
    Error::Framing(FramingError::LengthMismatch {
        index: record.index,
        offset: record.offset,
        declared: record.payload.len(),
        type_name: type_name.to_string(),
        detail,
    })
}

/// Append one record (mark + payload) to `out`.
pub fn write_record(out: &mut Vec<u8>, payload: &[u8]) -> Result<(), FramingError> {
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|n| n & LAST_FRAGMENT == 0)
        .ok_or(FramingError::RecordTooLarge(payload.len()))?;
    out.extend_from_slice(&(len | LAST_FRAGMENT).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Build a record-marked stream from payloads.
pub fn frame<'p>(payloads: impl IntoIterator<Item = &'p [u8]>) -> Result<Vec<u8>, FramingError> {
    let mut out = Vec::new();
    for p in payloads {
        write_record(&mut out, p)?;
    }
    Ok(out)
}
