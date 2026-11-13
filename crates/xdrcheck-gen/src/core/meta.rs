//! Incremental reader of the node's `METADATA_OUTPUT_STREAM` file.
//!
//! stellar-core appends one RFC 5531 record per closed ledger and flushes it (no fsync). The reader keeps
//! the bytes it has not consumed yet and hands out one complete record at a time; each record is checked
//! with `xdrcheck_xdr::split_ledger_stream` (the oracle gate, exactly one `LedgerCloseMeta`, byte-exact
//! re-encode) before it is returned.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use xdrcheck_xdr::{Gate, LedgerInfo, Limits};

/// One ledger as read from the stream.
#[derive(Debug, Clone)]
pub struct MetaRecord {
    /// Header facts read from the record.
    pub info: LedgerInfo,
    /// The `LedgerCloseMeta` bytes, without the record mark.
    pub bytes: Vec<u8>,
    /// Index of the record in the stream, from 0.
    pub index: usize,
}

/// Reads records from a growing meta stream file.
#[derive(Debug)]
pub struct MetaReader {
    path: PathBuf,
    file: Option<File>,
    pending: Vec<u8>,
    records: usize,
}

impl MetaReader {
    /// A reader for `path`; the file may not exist yet.
    pub fn new(path: &Path) -> MetaReader {
        MetaReader {
            path: path.to_path_buf(),
            file: None,
            pending: Vec::new(),
            records: 0,
        }
    }

    /// Path of the stream file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Records returned so far.
    pub fn records_read(&self) -> usize {
        self.records
    }

    /// Return the next complete record if one has been written, without waiting.
    pub fn try_next(&mut self) -> Result<Option<MetaRecord>> {
        if self.file.is_none() {
            match File::open(&self.path) {
                Ok(f) => self.file = Some(f),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e).with_context(|| format!("open {}", self.path.display())),
            }
        }
        let f = self.file.as_mut().expect("opened above");
        f.read_to_end(&mut self.pending)
            .with_context(|| format!("read {}", self.path.display()))?;
        let Some(mark) = self.pending.get(..4) else {
            return Ok(None);
        };
        let len = (u32::from_be_bytes(mark.try_into().expect("4 bytes")) & 0x7fff_ffff) as usize;
        if self.pending.len() < 4 + len {
            return Ok(None);
        }
        let framed: Vec<u8> = self.pending.drain(..4 + len).collect();
        let index = self.records;
        let (info, payload) = {
            let mut ledgers =
                xdrcheck_xdr::split_ledger_stream(&framed, &Limits::default(), &Gate::default())
                    .with_context(|| {
                        format!("meta stream record {index} in {}", self.path.display())
                    })?;
            let (info, payload) = ledgers.pop().expect("one record in, one ledger out");
            (info, payload.to_vec())
        };
        self.records += 1;
        Ok(Some(MetaRecord {
            info,
            bytes: payload,
            index,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn partial_records_wait_for_the_rest() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/xdrcheck-gen-unit")
            .join(format!("meta-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("meta.xdr");
        let mut r = MetaReader::new(&path);
        assert!(r.try_next().unwrap().is_none(), "no file yet");
        let mut f = File::create(&path).unwrap();
        // A mark announcing 8 bytes, then only 4 of them.
        f.write_all(&[0x80, 0, 0, 8, 0, 0, 0, 0]).unwrap();
        f.flush().unwrap();
        assert!(r.try_next().unwrap().is_none(), "record incomplete");
        f.write_all(&[0, 0, 0, 0]).unwrap();
        f.flush().unwrap();
        // Eight zero bytes are not a LedgerCloseMeta: the record is complete and refused.
        assert!(r.try_next().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
