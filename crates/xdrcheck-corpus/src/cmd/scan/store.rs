//! Scan output: the per-partition journal (resume), the aggregate of a partition, and its final
//! immutable files (Parquet, a refusal pack, `MANIFEST.json`; the provenance sidecar sits outside
//! the byte-identical set).
//!
//! A partition is complete if and only if its `MANIFEST.json` exists and every file it names has
//! the recorded sha256. Final files are written to a temporary name, fsynced and renamed; the
//! manifest is written last the same way; then the journal is removed. The files depend only on
//! the set of ledger records, never on the order they were journaled in or where a run was killed.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, ensure, Context, Result};
use parquet::basic::{Compression, ZstdLevel};
use parquet::data_type::{BoolType, ByteArray, ByteArrayType, Int32Type, Int64Type};
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::shape::{Component, LedgerShapes, VocabHit};

/// One ledger's row (`ledgers`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerRow {
    pub seq: u32,
    pub object_bytes: u64,
    pub xdr_bytes: u64,
    pub object_sha256: String,
    pub etag: Option<String>,
    pub md5_matches_etag: Option<bool>,
    pub close_time: u64,
    pub header_version: u32,
    pub protocol_applied: u32,
    pub lcm_arm: u32,
    pub header_hash: String,
    pub prev_hash: String,
    pub tx_count: u32,
    pub op_count: u32,
    pub soroban_tx_count: u32,
    pub ledger_shape: String,
    pub invariants: u32,
    pub tx_hash_mismatches: u32,
}

/// Invariant bits of [`LedgerRow::invariants`].
pub mod inv {
    pub const BATCH_OK: u32 = 1;
    pub const ROUNDTRIP_OK: u32 = 2;
    pub const WALK_OK: u32 = 4;
    pub const HEADER_HASH_OK: u32 = 8;
    pub const TX_HASH_OK: u32 = 16;
    pub const META_MATCHES: u32 = 32;
    pub const TX_SET_HASH_OK: u32 = 64;
    pub const RESULT_HASH_OK: u32 = 128;
}

/// Facts that change without the bytes changing (or are timings): the sidecar.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Prov {
    pub seq: u32,
    pub source: String,
    pub last_modified: Option<String>,
    pub core_version: Option<String>,
    pub galexie_version: Option<String>,
    pub meta_protocol: Option<String>,
    pub file_mtime: Option<String>,
    pub tries: u32,
    pub fetch_us: u64,
    pub decode_us: u64,
    pub shape_us: u64,
}

/// A refused object, kept with its bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefusalRec {
    pub seq: u32,
    pub stage: String,
    pub class: String,
    pub error: String,
    pub sha256: Option<String>,
    pub bytes_hex: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerRec {
    pub row: LedgerRow,
    pub shapes: LedgerShapes,
    pub prov: Prov,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Rec {
    Ledger(Box<LedgerRec>),
    Refusal(RefusalRec, Prov),
}

/// Test hooks for the resume check: `XDRCHECK_SCAN_KILL=journal:N` aborts half way through the N-th
/// journal record this process writes; `XDRCHECK_SCAN_KILL=rename:K` aborts after the K-th rename of a
/// partition's final files.
pub fn kill_hook(what: &str) -> Option<u64> {
    let v = std::env::var("XDRCHECK_SCAN_KILL").ok()?;
    let (w, n) = v.split_once(':')?;
    (w == what).then(|| n.parse().ok()).flatten()
}

static JOURNAL_WRITES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static RENAMES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The append-only journal of a partition in progress: `[u32 len][4-byte sha256 prefix][JSON]`.
pub struct Journal {
    f: File,
    since_sync: u32,
    pos: u64,
}

impl Journal {
    /// Open (or create) the journal and return the records of its valid prefix; a torn tail is cut.
    /// Open (or create) the journal, handing each record of its valid prefix to `each` in order
    /// (streamed: the journal is never held in memory); a torn tail is cut.
    pub fn open(path: &Path, mut each: impl FnMut(u64, Rec) -> Result<()>) -> Result<Journal> {
        let mut valid = 0u64;
        if path.exists() {
            let mut r = std::io::BufReader::with_capacity(1 << 20, File::open(path)?);
            let mut head = [0u8; 8];
            let mut payload = Vec::new();
            loop {
                if r.read_exact(&mut head).is_err() {
                    break;
                }
                let n = u32::from_be_bytes(head[..4].try_into().unwrap()) as usize;
                payload.resize(n, 0);
                if r.read_exact(&mut payload).is_err() {
                    break;
                }
                if Sha256::digest(&payload)[..4] != head[4..] {
                    break;
                }
                let Ok(rec) = serde_json::from_slice::<Rec>(&payload) else {
                    break;
                };
                each(valid, rec)?;
                valid += 8 + n as u64;
            }
        }
        let f = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)?;
        f.set_len(valid)?;
        f.sync_all()?;
        let mut j = Journal {
            f,
            since_sync: 0,
            pos: valid,
        };
        use std::io::Seek;
        j.f.seek(std::io::SeekFrom::End(0))?;
        Ok(j)
    }

    /// Append a record; returns its offset.
    pub fn append(&mut self, r: &Rec) -> Result<u64> {
        let payload = serde_json::to_vec(r)?;
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&Sha256::digest(&payload)[..4]);
        frame.extend_from_slice(&payload);
        let k = JOURNAL_WRITES.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        if kill_hook("journal") == Some(k) {
            self.f.write_all(&frame[..frame.len() / 2])?;
            self.f.sync_all()?;
            eprintln!("XDRCHECK_SCAN_KILL: aborting during journal record {k}");
            std::process::abort();
        }
        self.f.write_all(&frame)?;
        let at = self.pos;
        self.pos += frame.len() as u64;
        self.since_sync += 1;
        if self.since_sync >= 32 {
            self.f.sync_data()?;
            self.since_sync = 0;
        }
        Ok(at)
    }

    /// Read the record at `offset` of a journal file.
    pub fn read_at(f: &File, offset: u64) -> Result<Rec> {
        use std::os::unix::fs::FileExt;
        let mut head = [0u8; 8];
        f.read_exact_at(&mut head, offset)?;
        let n = u32::from_be_bytes(head[..4].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; n];
        f.read_exact_at(&mut payload, offset + 8)?;
        ensure!(
            Sha256::digest(&payload)[..4] == head[4..],
            "journal record at {offset} is damaged"
        );
        Ok(serde_json::from_slice(&payload)?)
    }

    pub fn sync(&mut self) -> Result<()> {
        self.f.sync_data()?;
        Ok(())
    }
}

/// The ledgers an id occurs in, as count and range: every insert of one ledger comes from one
/// record, so a ledger is counted when it differs from the last one inserted.
#[derive(Debug, Clone, Default)]
struct LedgerSet {
    n: usize,
    last_seen: Option<u32>,
    min: Option<u32>,
    max: Option<u32>,
}

impl LedgerSet {
    fn insert(&mut self, seq: u32) {
        if self.last_seen != Some(seq) {
            self.n += 1;
            self.last_seen = Some(seq);
            self.min = Some(self.min.map_or(seq, |m| m.min(seq)));
            self.max = Some(self.max.map_or(seq, |m| m.max(seq)));
        }
    }
    fn len(&self) -> usize {
        self.n
    }
    fn is_empty(&self) -> bool {
        self.n == 0
    }
    fn first(&self) -> Option<&u32> {
        self.min.as_ref()
    }
    fn last(&self) -> Option<&u32> {
        self.max.as_ref()
    }
}

#[derive(Debug, Clone, Default)]
struct CompAgg {
    comp: Option<Component>,
    tx_count: u64,
    ledgers: LedgerSet,
}

#[derive(Debug, Clone, Default)]
struct ShapeAgg {
    shape: Option<super::shape::TxShape>,
    tx_count: u64,
    ledgers: LedgerSet,
}

/// Everything a partition's final files are made of.
#[derive(Default)]
pub struct Agg {
    /// Ledger -> offset of its record in the partition's journal. Ledger rows, occurrences and
    /// provenance are read back from the journal at the end, a row group at a time, so memory holds
    /// only the dictionaries.
    pub ledgers: BTreeMap<u32, u64>,
    comps: BTreeMap<String, CompAgg>,
    shapes: BTreeMap<String, ShapeAgg>,
    vocab: BTreeMap<(String, Vec<u8>), (u64, BTreeSet<u32>)>,
    pub refusals: BTreeMap<u32, RefusalRec>,
    refusal_prov: BTreeMap<u32, Prov>,
}

/// Default ledgers per Parquet row group of the per-ledger tables (`scan run --group-ledgers`).
pub const GROUP_LEDGERS: usize = 2000;
/// Rows per Parquet row group of the dictionary tables.
pub const DICT_ROWS: usize = 10_000;

impl Agg {
    /// Ids of the components this partition already holds (the journal stores each one's tokens once).
    pub fn known(&self, id: &str) -> bool {
        self.comps.get(id).is_some_and(|c| c.comp.is_some())
    }

    pub fn add(&mut self, r: &Rec, offset: u64) -> Result<()> {
        match r {
            Rec::Refusal(f, p) => {
                self.refusals.insert(f.seq, f.clone());
                self.refusal_prov.insert(f.seq, p.clone());
            }
            Rec::Ledger(l) => {
                let seq = l.row.seq;
                ensure!(
                    !self.ledgers.contains_key(&seq),
                    "ledger {seq} twice in one partition"
                );
                self.ledgers.insert(seq, offset);
                for (id, c) in &l.shapes.components {
                    let a = self.comps.entry(id.clone()).or_default();
                    if a.comp.is_none() {
                        a.comp = Some(c.clone());
                    }
                }
                let lid = l.row.ledger_shape.clone();
                self.comps.entry(lid).or_default().ledgers.insert(seq);
                for (i, t) in l.shapes.txs.iter().enumerate() {
                    let _ = i;
                    let id = super::shape::hex16(&t.id());
                    let s = self.shapes.entry(id).or_default();
                    if s.shape.is_none() {
                        s.shape = Some(t.clone());
                    }
                    s.tx_count += 1;
                    s.ledgers.insert(seq);
                    let mut ids: BTreeSet<&str> =
                        [t.e.as_str(), t.r.as_str(), t.f.as_str(), t.m.as_str()].into();
                    if let Some(a) = &t.a {
                        ids.insert(a);
                    }
                    for (o, _) in &t.ops {
                        ids.insert(o);
                    }
                    for c in ids {
                        let a = self.comps.entry(c.to_string()).or_default();
                        a.tx_count += 1;
                        a.ledgers.insert(seq);
                    }
                }
                let mut seen = BTreeSet::new();
                for VocabHit { kind, text } in &l.shapes.vocab {
                    let e = self.vocab.entry((kind.clone(), text.clone())).or_default();
                    e.0 += 1;
                    if seen.insert((kind, text)) {
                        e.1.insert(seq);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn done(&self) -> BTreeSet<u32> {
        self.ledgers
            .keys()
            .chain(self.refusals.keys())
            .copied()
            .collect()
    }
}

// ---------- Parquet ----------

pub enum Col {
    I32(Vec<Option<i32>>),
    I64(Vec<Option<i64>>),
    Bool(Vec<Option<bool>>),
    Bin(Vec<Option<Vec<u8>>>),
    Utf8(Vec<Option<String>>),
}

impl Col {
    fn len(&self) -> usize {
        match self {
            Col::I32(v) => v.len(),
            Col::I64(v) => v.len(),
            Col::Bool(v) => v.len(),
            Col::Bin(v) => v.len(),
            Col::Utf8(v) => v.len(),
        }
    }
}

pub struct Table {
    pub cols: Vec<(&'static str, bool, Col)>,
}

fn levels<T: Clone>(v: &[Option<T>]) -> (Vec<T>, Vec<i16>) {
    let defs = v.iter().map(|x| x.is_some() as i16).collect();
    (v.iter().flatten().cloned().collect(), defs)
}

/// A Parquet file written a row group at a time into memory (compressed).
pub struct ParquetOut {
    w: SerializedFileWriter<Vec<u8>>,
}

fn schema_of(t: &Table) -> Result<parquet::schema::types::TypePtr> {
    let mut msg = String::from("message t {\n");
    for (name, nullable, c) in &t.cols {
        let rep = if *nullable { "OPTIONAL" } else { "REQUIRED" };
        let (ty, ann) = match c {
            Col::I32(_) => ("INT32", ""),
            Col::I64(_) => ("INT64", ""),
            Col::Bool(_) => ("BOOLEAN", ""),
            Col::Bin(_) => ("BYTE_ARRAY", ""),
            Col::Utf8(_) => ("BYTE_ARRAY", " (UTF8)"),
        };
        msg.push_str(&format!("  {rep} {ty} {name}{ann};\n"));
    }
    msg.push('}');
    Ok(Arc::new(parquet::schema::parser::parse_message_type(&msg)?))
}

impl ParquetOut {
    /// `template` gives the schema (its rows are not written).
    pub fn new(template: &Table, level: i32, group_rows: usize) -> Result<ParquetOut> {
        let props = Arc::new(
            WriterProperties::builder()
                .set_created_by("xcc-corpus scan, parquet 59.3.0".into())
                .set_compression(Compression::ZSTD(ZstdLevel::try_new(level)?))
                .set_max_row_group_row_count(Some(group_rows.max(1)))
                .build(),
        );
        Ok(ParquetOut {
            w: SerializedFileWriter::new(Vec::new(), schema_of(template)?, props)?,
        })
    }

    /// Write `t` as one row group.
    pub fn group(&mut self, t: &Table) -> Result<()> {
        let rows = t.cols.first().map(|c| c.2.len()).unwrap_or(0);
        let mut rg = self.w.next_row_group()?;
        for (name, nullable, c) in &t.cols {
            ensure!(
                c.len() == rows,
                "column {name}: {} rows, not {rows}",
                c.len()
            );
            let mut cw = rg.next_column()?.context("column count")?;
            macro_rules! put {
                ($ty:ty, $v:expr) => {{
                    let (vals, defs) = levels($v);
                    cw.typed::<$ty>()
                        .write_batch(&vals, nullable.then_some(&defs[..]), None)?;
                }};
            }
            match c {
                Col::I32(v) => put!(Int32Type, v),
                Col::I64(v) => put!(Int64Type, v),
                Col::Bool(v) => put!(BoolType, v),
                Col::Bin(v) => {
                    let v: Vec<Option<ByteArray>> =
                        v.iter().map(|x| x.clone().map(ByteArray::from)).collect();
                    put!(ByteArrayType, &v)
                }
                Col::Utf8(v) => {
                    let v: Vec<Option<ByteArray>> = v
                        .iter()
                        .map(|x| x.clone().map(|s| ByteArray::from(s.into_bytes())))
                        .collect();
                    put!(ByteArrayType, &v)
                }
            }
            cw.close()?;
        }
        rg.close()?;
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        Ok(self.w.into_inner()?)
    }
}

/// Write `t` as one Parquet file: one row group, zstd at `level`, a fixed `created_by`.
pub fn parquet_bytes(t: &Table, level: i32) -> Result<Vec<u8>> {
    let rows = t.cols.first().map(|c| c.2.len()).unwrap_or(0);
    let mut o = ParquetOut::new(t, level, rows)?;
    o.group(t)?;
    o.finish()
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_default()
}

/// Write `bytes` to `path` through a temporary file, fsync and rename.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("")
    ));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(d) = path.parent() {
        let d = if d.as_os_str().is_empty() {
            Path::new(".")
        } else {
            d
        };
        File::open(d)?.sync_all()?;
    }
    let k = RENAMES.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    if kill_hook("rename") == Some(k) {
        eprintln!(
            "XDRCHECK_SCAN_KILL: aborting after rename {k} ({})",
            path.display()
        );
        std::process::abort();
    }
    Ok(())
}

/// The files of a finished partition.
pub struct Finished {
    pub files: BTreeMap<String, Vec<u8>>,
    pub rows: BTreeMap<String, usize>,
    pub provenance: Vec<u8>,
    pub first_last_hash: (Option<String>, Option<String>),
}

fn ledger_table(l: &[LedgerRow]) -> Table {
    let i32c =
        |f: &dyn Fn(&LedgerRow) -> i64| Col::I32(l.iter().map(|r| Some(f(r) as i32)).collect());
    let i64c = |f: &dyn Fn(&LedgerRow) -> i64| Col::I64(l.iter().map(|r| Some(f(r))).collect());
    let ledgers = Table {
        cols: vec![
            ("seq", false, i32c(&|r| r.seq as i64)),
            ("object_bytes", false, i64c(&|r| r.object_bytes as i64)),
            ("xdr_bytes", false, i64c(&|r| r.xdr_bytes as i64)),
            (
                "object_sha256",
                false,
                Col::Bin(l.iter().map(|r| Some(unhex(&r.object_sha256))).collect()),
            ),
            (
                "etag",
                true,
                Col::Bin(l.iter().map(|r| r.etag.as_deref().map(unhex)).collect()),
            ),
            (
                "md5_matches_etag",
                true,
                Col::Bool(l.iter().map(|r| r.md5_matches_etag).collect()),
            ),
            ("close_time", false, i64c(&|r| r.close_time as i64)),
            ("header_version", false, i32c(&|r| r.header_version as i64)),
            (
                "protocol_applied",
                false,
                i32c(&|r| r.protocol_applied as i64),
            ),
            ("lcm_arm", false, i32c(&|r| r.lcm_arm as i64)),
            (
                "header_hash",
                false,
                Col::Bin(l.iter().map(|r| Some(unhex(&r.header_hash))).collect()),
            ),
            (
                "prev_hash",
                false,
                Col::Bin(l.iter().map(|r| Some(unhex(&r.prev_hash))).collect()),
            ),
            ("tx_count", false, i32c(&|r| r.tx_count as i64)),
            ("op_count", false, i32c(&|r| r.op_count as i64)),
            (
                "soroban_tx_count",
                false,
                i32c(&|r| r.soroban_tx_count as i64),
            ),
            (
                "ledger_shape",
                false,
                Col::Bin(l.iter().map(|r| Some(unhex(&r.ledger_shape))).collect()),
            ),
            ("invariants", false, i32c(&|r| r.invariants as i64)),
            (
                "tx_hash_mismatches",
                false,
                i32c(&|r| r.tx_hash_mismatches as i64),
            ),
        ],
    };
    ledgers
}

fn occ_table(occ: &[((u32, String), Vec<u16>)]) -> Table {
    Table {
        cols: vec![
            (
                "seq",
                false,
                Col::I32(occ.iter().map(|((s, _), _)| Some(*s as i32)).collect()),
            ),
            (
                "tx_shape",
                false,
                Col::Bin(occ.iter().map(|((_, t), _)| Some(unhex(t))).collect()),
            ),
            (
                "n",
                false,
                Col::I32(occ.iter().map(|(_, v)| Some(v.len() as i32)).collect()),
            ),
            (
                "tx_index",
                false,
                Col::Bin(
                    occ.iter()
                        .map(|(_, v)| Some(v.iter().flat_map(|i| i.to_be_bytes()).collect()))
                        .collect(),
                ),
            ),
        ],
    }
}

impl Agg {
    pub fn tables(
        &self,
        level: i32,
        dict_level: i32,
        journal: &Path,
        group_ledgers: usize,
    ) -> Result<Finished> {
        let group_ledgers = group_ledgers.max(1);
        let mut files = BTreeMap::new();
        let mut rows = BTreeMap::new();
        let jf = File::open(journal).with_context(|| journal.display().to_string())?;
        let mut lw = ParquetOut::new(&ledger_table(&[]), level, group_ledgers)?;
        let mut ow = ParquetOut::new(&occ_table(&[]), level, usize::MAX)?;
        let mut prov: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        let (mut n_ledgers, mut n_occ) = (0usize, 0usize);
        let mut first_last: (Option<String>, Option<String>) = (None, None);
        let seqs: Vec<(u32, u64)> = self.ledgers.iter().map(|(s, o)| (*s, *o)).collect();
        for chunk in seqs.chunks(group_ledgers) {
            let mut lrows = Vec::with_capacity(chunk.len());
            let mut occ: Vec<((u32, String), Vec<u16>)> = Vec::new();
            for (seq, off) in chunk {
                let Rec::Ledger(l) = Journal::read_at(&jf, *off)? else {
                    bail!("journal record of {seq} is not a ledger");
                };
                let mut per: BTreeMap<String, Vec<u16>> = BTreeMap::new();
                for (i, t) in l.shapes.txs.iter().enumerate() {
                    per.entry(super::shape::hex16(&t.id()))
                        .or_default()
                        .push(i as u16);
                }
                occ.extend(per.into_iter().map(|(k, v)| ((*seq, k), v)));
                let mut line = serde_json::to_vec(&l.prov)?;
                line.push(b'\n');
                prov.insert(*seq, line);
                if first_last.0.is_none() {
                    first_last.0 = Some(l.row.header_hash.clone());
                }
                first_last.1 = Some(l.row.header_hash.clone());
                lrows.push(l.row);
            }
            n_ledgers += lrows.len();
            n_occ += occ.len();
            lw.group(&ledger_table(&lrows))?;
            ow.group(&occ_table(&occ))?;
        }
        if seqs.is_empty() {
            lw.group(&ledger_table(&[]))?;
            ow.group(&occ_table(&[]))?;
        }
        for (seq, p) in &self.refusal_prov {
            let mut line = serde_json::to_vec(p)?;
            line.push(b'\n');
            prov.insert(*seq, line);
        }
        rows.insert("ledgers.parquet".to_string(), n_ledgers);
        files.insert("ledgers.parquet".to_string(), lw.finish()?);
        rows.insert("occurrences.parquet".to_string(), n_occ);
        files.insert("occurrences.parquet".to_string(), ow.finish()?);
        let first_last_hash = first_last;

        let comps: Vec<(&String, &CompAgg)> = self
            .comps
            .iter()
            .filter(|(_, c)| !c.ledgers.is_empty())
            .collect();
        for (id, c) in &comps {
            ensure!(c.comp.is_some(), "component {id} has no tokens");
        }
        let comp_table = |comps: &[(&String, &CompAgg)]| Table {
            cols: vec![
                (
                    "component",
                    false,
                    Col::Bin(comps.iter().map(|(id, _)| Some(unhex(id))).collect()),
                ),
                (
                    "kind",
                    false,
                    Col::Utf8(
                        comps
                            .iter()
                            .map(|(_, c)| Some(c.comp.as_ref().unwrap().kind.to_string()))
                            .collect(),
                    ),
                ),
                (
                    "op_type",
                    true,
                    Col::Utf8(
                        comps
                            .iter()
                            .map(|(_, c)| c.comp.as_ref().unwrap().op_type.clone())
                            .collect(),
                    ),
                ),
                (
                    "tokens",
                    false,
                    Col::Utf8(
                        comps
                            .iter()
                            .map(|(_, c)| Some(c.comp.as_ref().unwrap().tokens.join("\n")))
                            .collect(),
                    ),
                ),
                (
                    "tx_count",
                    false,
                    Col::I64(comps.iter().map(|(_, c)| Some(c.tx_count as i64)).collect()),
                ),
                (
                    "ledger_count",
                    false,
                    Col::I64(
                        comps
                            .iter()
                            .map(|(_, c)| Some(c.ledgers.len() as i64))
                            .collect(),
                    ),
                ),
                (
                    "min_seq",
                    false,
                    Col::I32(
                        comps
                            .iter()
                            .map(|(_, c)| c.ledgers.first().map(|&s| s as i32))
                            .collect(),
                    ),
                ),
                (
                    "max_seq",
                    false,
                    Col::I32(
                        comps
                            .iter()
                            .map(|(_, c)| c.ledgers.last().map(|&s| s as i32))
                            .collect(),
                    ),
                ),
            ],
        };
        rows.insert("components.parquet".to_string(), comps.len());
        let mut cw = ParquetOut::new(&comp_table(&[]), dict_level, DICT_ROWS)?;
        if comps.is_empty() {
            cw.group(&comp_table(&[]))?;
        }
        for ch in comps.chunks(DICT_ROWS) {
            cw.group(&comp_table(ch))?;
        }
        files.insert("components.parquet".to_string(), cw.finish()?);

        let sh: Vec<(&String, &ShapeAgg)> = self.shapes.iter().collect();
        fn s(a: &ShapeAgg) -> &super::shape::TxShape {
            a.shape.as_ref().unwrap()
        }
        let shape_table = |sh: &[(&String, &ShapeAgg)]| Table {
            cols: vec![
                (
                    "tx_shape",
                    false,
                    Col::Bin(sh.iter().map(|(id, _)| Some(unhex(id))).collect()),
                ),
                (
                    "e",
                    false,
                    Col::Bin(sh.iter().map(|(_, a)| Some(unhex(&s(a).e))).collect()),
                ),
                (
                    "a",
                    true,
                    Col::Bin(
                        sh.iter()
                            .map(|(_, a)| s(a).a.as_deref().map(unhex))
                            .collect(),
                    ),
                ),
                (
                    "r",
                    false,
                    Col::Bin(sh.iter().map(|(_, a)| Some(unhex(&s(a).r))).collect()),
                ),
                (
                    "f",
                    false,
                    Col::Bin(sh.iter().map(|(_, a)| Some(unhex(&s(a).f))).collect()),
                ),
                (
                    "m",
                    false,
                    Col::Bin(sh.iter().map(|(_, a)| Some(unhex(&s(a).m))).collect()),
                ),
                (
                    "ops",
                    false,
                    Col::Utf8(
                        sh.iter()
                            .map(|(_, a)| {
                                Some(
                                    s(a).ops
                                        .iter()
                                        .map(|(o, c)| format!("{o}*{c}"))
                                        .collect::<Vec<_>>()
                                        .join(","),
                                )
                            })
                            .collect(),
                    ),
                ),
                (
                    "op_count_class",
                    false,
                    Col::Utf8(
                        sh.iter()
                            .map(|(_, a)| Some(s(a).op_count_class.clone()))
                            .collect(),
                    ),
                ),
                (
                    "tx_count",
                    false,
                    Col::I64(sh.iter().map(|(_, a)| Some(a.tx_count as i64)).collect()),
                ),
                (
                    "ledger_count",
                    false,
                    Col::I64(
                        sh.iter()
                            .map(|(_, a)| Some(a.ledgers.len() as i64))
                            .collect(),
                    ),
                ),
                (
                    "min_seq",
                    false,
                    Col::I32(
                        sh.iter()
                            .map(|(_, a)| a.ledgers.first().map(|&x| x as i32))
                            .collect(),
                    ),
                ),
                (
                    "max_seq",
                    false,
                    Col::I32(
                        sh.iter()
                            .map(|(_, a)| a.ledgers.last().map(|&x| x as i32))
                            .collect(),
                    ),
                ),
            ],
        };
        rows.insert("tx_shapes.parquet".to_string(), sh.len());
        let mut tw = ParquetOut::new(&shape_table(&[]), dict_level, DICT_ROWS)?;
        if sh.is_empty() {
            tw.group(&shape_table(&[]))?;
        }
        for ch in sh.chunks(DICT_ROWS) {
            tw.group(&shape_table(ch))?;
        }
        files.insert("tx_shapes.parquet".to_string(), tw.finish()?);

        let vo: Vec<(&(String, Vec<u8>), &(u64, BTreeSet<u32>))> = self.vocab.iter().collect();
        let vocab = Table {
            cols: vec![
                (
                    "kind",
                    false,
                    Col::Utf8(vo.iter().map(|((k, _), _)| Some(k.clone())).collect()),
                ),
                (
                    "text",
                    false,
                    Col::Bin(vo.iter().map(|((_, t), _)| Some(t.clone())).collect()),
                ),
                (
                    "events",
                    false,
                    Col::I64(vo.iter().map(|(_, (n, _))| Some(*n as i64)).collect()),
                ),
                (
                    "ledgers",
                    false,
                    Col::I64(vo.iter().map(|(_, (_, l))| Some(l.len() as i64)).collect()),
                ),
            ],
        };
        rows.insert("vocab.parquet".to_string(), vo.len());
        files.insert(
            "vocab.parquet".to_string(),
            parquet_bytes(&vocab, dict_level)?,
        );

        if !self.refusals.is_empty() {
            let rf: Vec<&RefusalRec> = self.refusals.values().collect();
            let mut pack = Vec::new();
            let mut offs = Vec::new();
            for r in &rf {
                let b = unhex(&r.bytes_hex);
                offs.push((pack.len() as i64, b.len() as i64));
                pack.extend(b);
            }
            let refusals = Table {
                cols: vec![
                    (
                        "seq",
                        false,
                        Col::I32(rf.iter().map(|r| Some(r.seq as i32)).collect()),
                    ),
                    (
                        "stage",
                        false,
                        Col::Utf8(rf.iter().map(|r| Some(r.stage.clone())).collect()),
                    ),
                    (
                        "class",
                        false,
                        Col::Utf8(rf.iter().map(|r| Some(r.class.clone())).collect()),
                    ),
                    (
                        "error",
                        false,
                        Col::Utf8(rf.iter().map(|r| Some(r.error.clone())).collect()),
                    ),
                    (
                        "note",
                        false,
                        Col::Utf8(rf.iter().map(|r| Some(r.note.clone())).collect()),
                    ),
                    (
                        "sha256",
                        true,
                        Col::Bin(rf.iter().map(|r| r.sha256.as_deref().map(unhex)).collect()),
                    ),
                    (
                        "pack_offset",
                        false,
                        Col::I64(offs.iter().map(|o| Some(o.0)).collect()),
                    ),
                    (
                        "pack_len",
                        false,
                        Col::I64(offs.iter().map(|o| Some(o.1)).collect()),
                    ),
                ],
            };
            rows.insert("refusals.parquet".to_string(), rf.len());
            files.insert(
                "refusals.parquet".to_string(),
                parquet_bytes(&refusals, level)?,
            );
            rows.insert("refusals.pack".to_string(), rf.len());
            files.insert("refusals.pack".to_string(), pack);
        }

        let prov: Vec<u8> = prov.into_values().flatten().collect();
        let provenance = xdrcheck_xdr::batch::compress(&prov, 3)?;
        Ok(Finished {
            files,
            rows,
            provenance,
            first_last_hash,
        })
    }
}

/// Write a finished partition: files, sidecar, then `MANIFEST.json`.
#[allow(clippy::too_many_arguments)]
pub fn finish(
    dir: &Path,
    part: &str,
    agg: &Agg,
    header: serde_json::Value,
    level: i32,
    dict_level: i32,
    journal: &Path,
    group_ledgers: usize,
) -> Result<()> {
    let f = agg.tables(level, dict_level, journal, group_ledgers)?;
    let mut files = serde_json::Map::new();
    for (name, bytes) in &f.files {
        write_atomic(&dir.join(name), bytes)?;
        files.insert(
            name.clone(),
            json!({"bytes": bytes.len(), "sha256": xdrcheck_xdr::sha256_hex(bytes), "rows": f.rows[name]}),
        );
    }
    write_atomic(&dir.join("provenance.jsonl.zst"), &f.provenance)?;
    let mut m = serde_json::Map::new();
    m.insert("partition".into(), json!(part));
    m.insert("header".into(), header);
    m.insert(
        "range".into(),
        json!([agg.done().first().copied(), agg.done().last().copied()]),
    );
    m.insert("ledgers".into(), json!(agg.ledgers.len()));
    m.insert("refusals".into(), json!(agg.refusals.len()));
    m.insert("first_header_hash".into(), json!(f.first_last_hash.0));
    m.insert("last_header_hash".into(), json!(f.first_last_hash.1));
    m.insert("files".into(), serde_json::Value::Object(files));
    let mut text = serde_json::to_vec_pretty(&serde_json::Value::Object(m))?;
    text.push(b'\n');
    write_atomic(&dir.join("MANIFEST.json"), &text)?;
    Ok(())
}

/// Whether `dir` holds a complete partition (manifest present, every file's sha256 as recorded).
pub fn verify_partition(dir: &Path) -> Result<bool> {
    let m = dir.join("MANIFEST.json");
    if !m.exists() {
        return Ok(false);
    }
    let v: serde_json::Value = serde_json::from_slice(&fs::read(&m)?)?;
    let files = v["files"].as_object().context("manifest without files")?;
    for (name, f) in files {
        let b = fs::read(dir.join(name)).with_context(|| format!("{}: {name}", dir.display()))?;
        if xdrcheck_xdr::sha256_hex(&b) != f["sha256"].as_str().unwrap_or("") {
            bail!("{}: {name} does not match its manifest", dir.display());
        }
    }
    Ok(true)
}

/// Every partition directory under a run, in name order.
pub fn partitions(run: &Path) -> Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = fs::read_dir(run)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.join("MANIFEST.json").exists())
        .collect();
    v.sort();
    Ok(v)
}
