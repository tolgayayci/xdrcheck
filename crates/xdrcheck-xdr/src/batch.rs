//! SEP-54 data-lake objects: a zstd-compressed `LedgerCloseMetaBatch`
//! `{ uint32 startSequence; uint32 endSequence; LedgerCloseMeta ledgerCloseMetas<>; }`.
//!
//! [`unpack_object`] decompresses and splits a batch into the exact byte slices of its ledgers,
//! checking each one against the [`Gate`], decoding it under the [`Limits`] and re-encoding it
//! byte-exactly. [`pack_object`] builds the batch for one or more ledgers and compresses it.

use std::io::Cursor;

use stellar_xdr::{LedgerCloseMeta, Limited, ReadXdr, Type};

use crate::codec::{self, Limits};
use crate::error::{Error, Malformed, Result};
use crate::ledger::{ledger_info, Gate, LedgerInfo};

const NAME: &str = "LedgerCloseMetaBatch";

/// Default zstd level for [`pack_object`].
pub const DEFAULT_ZSTD_LEVEL: i32 = 3;

/// A decoded batch: its header and the verbatim bytes of each `LedgerCloseMeta`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    /// `startSequence`.
    pub start_sequence: u32,
    /// `endSequence`.
    pub end_sequence: u32,
    /// Each ledger's XDR, in batch order.
    pub ledgers: Vec<Vec<u8>>,
    /// Header information of each ledger, parallel to `ledgers`.
    pub infos: Vec<LedgerInfo>,
}

/// The most a lake object may decompress to: 512 MiB, about four times the largest lake object the
/// corpus holds. A larger output is an error, not an allocation.
pub const MAX_LAKE_OBJECT: u64 = 512 << 20;

/// Decompress a lake object (a zstd frame) of at most [`MAX_LAKE_OBJECT`] bytes.
pub fn decompress(object: &[u8]) -> Result<Vec<u8>> {
    decompress_bounded(object, MAX_LAKE_OBJECT)
}

/// Decompress zstd `data`, failing as soon as the output exceeds `max` bytes: at most `max + 1` bytes
/// are ever produced, whatever the frame claims. Every zstd decompression of the tools goes through
/// this function.
pub fn decompress_bounded(data: &[u8], max: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    zstd::stream::Decoder::new(data)?
        .take(max.saturating_add(1))
        .read_to_end(&mut out)?;
    if out.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("decompresses to more than {max} bytes"),
        )
        .into());
    }
    Ok(out)
}

/// Compress with zstd at `level`.
pub fn compress(bytes: &[u8], level: i32) -> Result<Vec<u8>> {
    Ok(zstd::stream::encode_all(bytes, level)?)
}

/// Decompress a lake object and split its batch (see [`split_batch`]).
pub fn unpack_object(object: &[u8], limits: &Limits, gate: &Gate) -> Result<Batch> {
    split_batch(&decompress(object)?, limits, gate)
}

/// Split the XDR of a `LedgerCloseMetaBatch` into its ledgers' bytes.
///
/// Every ledger is checked against `gate` (typed refusal), decoded under `limits` and re-encoded
/// byte-exactly. The header must agree with the ledgers: `startSequence` is the first ledger's
/// sequence and `endSequence` the last one's. Trailing bytes are malformed.
pub fn split_batch(xdr: &[u8], limits: &Limits, gate: &Gate) -> Result<Batch> {
    let malformed = |reason: Malformed| Error::Malformed {
        type_name: NAME.to_string(),
        reason,
    };
    let word = |at: usize| -> Result<u32> {
        xdr.get(at..at + 4)
            .map(|b| u32::from_be_bytes(b.try_into().expect("4 bytes")))
            .ok_or(malformed(Malformed::UnexpectedEof))
    };
    let (start_sequence, end_sequence, count) = (word(0)?, word(4)?, word(8)? as usize);
    let mut pos = 12;
    let mut ledgers = Vec::with_capacity(count.min(1024));
    let mut infos = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let rest = &xdr[pos..];
        let info = ledger_info(rest)?;
        gate.check(&info)?;
        let len = codec::with_stack(limits.stack_size, || read_one_ledger(rest, limits))?;
        ledgers.push(rest[..len].to_vec());
        infos.push(info);
        pos += len;
    }
    if pos != xdr.len() {
        return Err(malformed(Malformed::TrailingBytes {
            consumed: pos,
            len: xdr.len(),
            trailing: xdr.len() - pos,
        }));
    }
    if let (Some(first), Some(last)) = (infos.first(), infos.last()) {
        if first.sequence != start_sequence || last.sequence != end_sequence {
            return Err(malformed(Malformed::Batch(format!(
                "header range {start_sequence}..={end_sequence} but ledgers {}..={}",
                first.sequence, last.sequence
            ))));
        }
    }
    Ok(Batch {
        start_sequence,
        end_sequence,
        ledgers,
        infos,
    })
}

/// Read one `LedgerCloseMeta` from the front of `rest`, re-encode it and check the bytes match.
/// Returns its length. Must run on a large stack.
fn read_one_ledger(rest: &[u8], limits: &Limits) -> Result<usize> {
    let name = "LedgerCloseMeta";
    let xdr_limits = limits.xdr(rest.len());
    let len_limit = xdr_limits.len;
    let mut r = Limited::new(Cursor::new(rest), xdr_limits);
    let v = LedgerCloseMeta::read_xdr(&mut r)
        .map_err(|e| Error::from_xdr_read(name, e, len_limit, rest.len()))?;
    let len = usize::try_from(r.inner.position()).expect("cursor position fits usize");
    let out = codec::encode_here(&Type::LedgerCloseMeta(Box::new(v)), limits, len)?;
    codec::compare(name, "xdr", &rest[..len], &out)?;
    Ok(len)
}

/// Build the XDR of a `LedgerCloseMetaBatch` holding `ledgers` (at least one), with
/// `startSequence` and `endSequence` taken from the first and last ledger headers. Ledger bytes
/// are copied verbatim; each is checked against `gate`.
pub fn build_batch(ledgers: &[&[u8]], gate: &Gate) -> Result<Vec<u8>> {
    let infos = ledgers
        .iter()
        .map(|l| {
            let info = ledger_info(l)?;
            gate.check(&info)?;
            Ok(info)
        })
        .collect::<Result<Vec<_>>>()?;
    let (Some(first), Some(last)) = (infos.first(), infos.last()) else {
        return Err(Error::Malformed {
            type_name: NAME.to_string(),
            reason: Malformed::Batch("a batch needs at least one ledger".into()),
        });
    };
    let count = u32::try_from(ledgers.len()).map_err(|_| Error::Malformed {
        type_name: NAME.to_string(),
        reason: Malformed::Batch("too many ledgers".into()),
    })?;
    let mut out = Vec::with_capacity(12 + ledgers.iter().map(|l| l.len()).sum::<usize>());
    for n in [first.sequence, last.sequence, count] {
        out.extend_from_slice(&n.to_be_bytes());
    }
    for l in ledgers {
        out.extend_from_slice(l);
    }
    Ok(out)
}

/// Build and zstd-compress a lake object for `ledgers` (see [`build_batch`]).
pub fn pack_object(ledgers: &[&[u8]], gate: &Gate, level: i32) -> Result<Vec<u8>> {
    compress(&build_batch(ledgers, gate)?, level)
}

#[cfg(test)]
mod bomb_tests {
    use super::*;

    /// A frame of `n` zero bytes, written in pieces so the test never holds the plaintext.
    fn zeros_frame(n: u64) -> Vec<u8> {
        use std::io::Write;
        let mut enc = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
        let chunk = vec![0u8; 1 << 20];
        let mut left = n;
        while left > 0 {
            let k = left.min(chunk.len() as u64) as usize;
            enc.write_all(&chunk[..k]).unwrap();
            left -= k as u64;
        }
        enc.finish().unwrap()
    }

    /// A 1 GiB bomb (under 1 MiB compressed) stops at the cap: the error comes after at most
    /// `max + 1` bytes of output, not after the 1 GiB.
    #[test]
    fn a_bomb_stops_at_the_cap() {
        let bomb = zeros_frame(1 << 30);
        assert!(bomb.len() < 1 << 20, "bomb is {} bytes", bomb.len());
        let started = std::time::Instant::now();
        let e = decompress_bounded(&bomb, 1 << 20).unwrap_err();
        assert!(e.to_string().contains("more than 1048576 bytes"), "{e}");
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        // At the cap exactly, the output is returned.
        let small = zeros_frame(4096);
        assert_eq!(decompress_bounded(&small, 4096).unwrap().len(), 4096);
        assert!(decompress_bounded(&small, 4095).is_err());
        assert_eq!(decompress(&small).unwrap().len(), 4096);
    }
}
