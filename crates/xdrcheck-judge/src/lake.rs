//! Reading ledgers: a zstd-compressed `LedgerCloseMetaBatch` (one data-lake object), or a raw
//! `LedgerCloseMeta`/batch XDR file.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use stellar_xdr::{LedgerCloseMeta, LedgerCloseMetaBatch, Limits, ReadXdr};

/// Largest decompressed object accepted.
pub const MAX_OBJECT: u64 = 512 << 20;

fn limits() -> Limits {
    Limits {
        depth: 1000,
        len: MAX_OBJECT as usize,
    }
}

/// Decode the bytes of one lake object (zstd or plain), batch or single ledger.
pub fn decode(bytes: &[u8]) -> Result<Vec<LedgerCloseMeta>> {
    let raw: Vec<u8> = if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let mut out = Vec::new();
        zstd::stream::Decoder::new(bytes)?
            .take(MAX_OBJECT + 1)
            .read_to_end(&mut out)?;
        anyhow::ensure!(out.len() as u64 <= MAX_OBJECT, "object too large");
        out
    } else {
        bytes.to_vec()
    };
    if let Ok(b) = LedgerCloseMetaBatch::from_xdr(&raw, limits()) {
        return Ok(b.ledger_close_metas.to_vec());
    }
    Ok(vec![
        LedgerCloseMeta::from_xdr(&raw, limits()).context("not a LedgerCloseMeta(Batch)")?
    ])
}

pub fn read_file(p: &Path) -> Result<Vec<LedgerCloseMeta>> {
    let b = std::fs::read(p).with_context(|| format!("read {}", p.display()))?;
    decode(&b).with_context(|| format!("decode {}", p.display()))
}
