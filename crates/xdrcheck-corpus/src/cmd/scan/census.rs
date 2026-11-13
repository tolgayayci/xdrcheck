//! Census of a whole run with bounded memory, in two phases.
//!
//! **`census-extract`** reads one unit (a partition directory) at a time, projects its stored G3
//! components and transaction shapes to G0–G3 with the same [`report::project`] that `scan ablate`
//! uses, and writes one sorted run file per unit. **`census-merge`** merges the run files k ways
//! (at most `--fan-in` open at once, in as many passes as needed) and writes, per level and kind,
//! the ids with their totals, plus a summary. Memory depends on one unit (phase 1) or on the fan-in
//! (phase 2), never on the size of the run.
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{bail, ensure, Context, Result};

use super::report::{self, level, project, RunData};
use super::shape::Id;

const MAGIC: &[u8; 8] = b"XCCCEN01";
const REC: usize = 46;
const TRAILER: u8 = 0xFF;
/// Level byte of the per-unit ledger facts (sorts before the shape levels).
const FACTS: u8 = 0;
const LEVELS: [(u8, &str); 4] = [(1, "G0"), (2, "G1"), (3, "G2"), (4, "G3")];
/// Kind byte of transaction shapes (component kinds are their upper-case letters).
const TX: u8 = b't';
const ZSTD_LEVEL: i32 = 3;

const RUNS_README: &str = "\
Census run files (xdrcheck-corpus scan census-extract), one per unit: <unit>.cen

Format: one zstd stream (level 3). Bytes: magic \"XCCCEN01\", then fixed 46-byte records,
little-endian, sorted by (level, kind, id), keys unique within a file:
  level u8 | kind u8 | id [16] | occ u64 | aux u64 | first u32 | last u32 | units u32
then one trailer record with level 0xFF and occ = number of records before it. A file without
its trailer is incomplete. Files are written as <name>.tmp and renamed when complete.

level 1..4 = G0..G3, ids projected from the stored G3 tokens exactly as `scan ablate` does.
kind: component kind letter (E A O R F M L) or 't' for transaction shapes.
occ: transactions holding the id (tx shapes: transactions of that shape; components: for each
  stored tx shape, the distinct projected ids it references get its tx_count, so a transaction
  counts once per id); for L (ledger components): ledgers. aux = 0.
first/last: smallest/largest ledger holding the id in the unit. units = 1.
level 0 (facts), kind 'P': id = protocol (header ledgerVersion) u32 BE, LedgerCloseMeta arm
  u32 BE, 8 zero bytes; occ = ledgers, aux = transactions, first/last = ledger range.
census-merge writes intermediate files in the same format (units summed).
";

#[derive(clap::Args, Debug)]
pub struct ExtractArgs {
    /// Merged run directory (read only)
    #[arg(long)]
    pub run: PathBuf,
    /// Output directory for the per-unit run files
    #[arg(long)]
    pub out: PathBuf,
    /// File with unit directory names (one per line); default: every unit of the run
    #[arg(long)]
    pub units_from: Option<PathBuf>,
    /// Units extracted in parallel
    #[arg(long, default_value_t = 1)]
    pub jobs: usize,
}

#[derive(clap::Args, Debug)]
pub struct MergeArgs {
    /// Directory holding the phase-1 run files (`*.cen`)
    #[arg(long)]
    pub runs: PathBuf,
    /// Output directory
    #[arg(long)]
    pub out: PathBuf,
    /// Run files open at once per merge
    #[arg(long, default_value_t = 256)]
    pub fan_in: usize,
    /// Merges of one intermediate pass run in parallel
    #[arg(long, default_value_t = 1)]
    pub jobs: usize,
}

// ---------- records and run files ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rec {
    level: u8,
    kind: u8,
    id: Id,
    occ: u64,
    aux: u64,
    first: u32,
    last: u32,
    units: u32,
}

type Key = (u8, u8, Id);

impl Rec {
    fn new(level: u8, kind: u8, id: Id) -> Rec {
        Rec {
            level,
            kind,
            id,
            occ: 0,
            aux: 0,
            first: u32::MAX,
            last: 0,
            units: 1,
        }
    }
    fn key(&self) -> Key {
        (self.level, self.kind, self.id)
    }
    fn span(&mut self, first: u32, last: u32) {
        self.first = self.first.min(first);
        self.last = self.last.max(last);
    }
    fn absorb(&mut self, o: &Rec) {
        self.occ += o.occ;
        self.aux += o.aux;
        self.span(o.first, o.last);
        self.units += o.units;
    }
    fn put(&self, b: &mut [u8; REC]) {
        b[0] = self.level;
        b[1] = self.kind;
        b[2..18].copy_from_slice(&self.id);
        b[18..26].copy_from_slice(&self.occ.to_le_bytes());
        b[26..34].copy_from_slice(&self.aux.to_le_bytes());
        b[34..38].copy_from_slice(&self.first.to_le_bytes());
        b[38..42].copy_from_slice(&self.last.to_le_bytes());
        b[42..46].copy_from_slice(&self.units.to_le_bytes());
    }
    fn get(b: &[u8; REC]) -> Rec {
        let u64_at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        Rec {
            level: b[0],
            kind: b[1],
            id: b[2..18].try_into().unwrap(),
            occ: u64_at(18),
            aux: u64_at(26),
            first: u32_at(34),
            last: u32_at(38),
            units: u32_at(42),
        }
    }
}

fn tmp_of(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Writes `<dst>.tmp`, renamed to `dst` by [`RunWriter::finish`].
struct RunWriter {
    enc: zstd::Encoder<'static, BufWriter<File>>,
    n: u64,
    last: Option<Key>,
    dst: PathBuf,
}

impl RunWriter {
    fn create(dst: &Path) -> Result<RunWriter> {
        let f = File::create(tmp_of(dst)).with_context(|| dst.display().to_string())?;
        let mut enc = zstd::Encoder::new(BufWriter::with_capacity(1 << 20, f), ZSTD_LEVEL)?;
        enc.write_all(MAGIC)?;
        Ok(RunWriter {
            enc,
            n: 0,
            last: None,
            dst: dst.to_path_buf(),
        })
    }
    fn push(&mut self, r: &Rec) -> Result<()> {
        ensure!(
            self.last.is_none_or(|l| l < r.key()),
            "{}: records out of order",
            self.dst.display()
        );
        self.last = Some(r.key());
        let mut b = [0u8; REC];
        r.put(&mut b);
        self.enc.write_all(&b)?;
        self.n += 1;
        Ok(())
    }
    fn finish(mut self) -> Result<u64> {
        let mut t = Rec::new(TRAILER, 0, [0; 16]);
        t.occ = self.n;
        t.units = 0;
        t.first = 0;
        let mut b = [0u8; REC];
        t.put(&mut b);
        self.enc.write_all(&b)?;
        let f = self
            .enc
            .finish()?
            .into_inner()
            .map_err(|e| e.into_error())?;
        f.sync_all()?;
        drop(f);
        fs::rename(tmp_of(&self.dst), &self.dst)?;
        Ok(fs::metadata(&self.dst)?.len())
    }
}

struct RunReader {
    r: BufReader<zstd::Decoder<'static, BufReader<File>>>,
    n: u64,
    done: bool,
    path: PathBuf,
}

impl RunReader {
    fn open(path: &Path) -> Result<RunReader> {
        let f = File::open(path).with_context(|| path.display().to_string())?;
        let mut r = BufReader::with_capacity(1 << 16, zstd::Decoder::new(f)?);
        let mut m = [0u8; 8];
        r.read_exact(&mut m)
            .with_context(|| format!("{}: no header", path.display()))?;
        ensure!(&m == MAGIC, "{}: not a census run file", path.display());
        Ok(RunReader {
            r,
            n: 0,
            done: false,
            path: path.to_path_buf(),
        })
    }
    fn next(&mut self) -> Result<Option<Rec>> {
        if self.done {
            return Ok(None);
        }
        let mut b = [0u8; REC];
        self.r
            .read_exact(&mut b)
            .with_context(|| format!("{}: truncated (no trailer)", self.path.display()))?;
        let rec = Rec::get(&b);
        if rec.level == TRAILER {
            ensure!(
                rec.occ == self.n,
                "{}: trailer says {} records, read {}",
                self.path.display(),
                rec.occ,
                self.n
            );
            let mut x = [0u8; 1];
            ensure!(
                self.r.read(&mut x)? == 0,
                "{}: bytes after the trailer",
                self.path.display()
            );
            self.done = true;
            return Ok(None);
        }
        self.n += 1;
        Ok(Some(rec))
    }
}

/// Merges sorted run files, yielding one aggregated record per key in key order.
struct Merger {
    readers: Vec<RunReader>,
    heads: Vec<Option<Rec>>,
    heap: BinaryHeap<Reverse<(Key, usize)>>,
}

impl Merger {
    fn open(paths: &[PathBuf]) -> Result<Merger> {
        let mut m = Merger {
            readers: Vec::with_capacity(paths.len()),
            heads: Vec::with_capacity(paths.len()),
            heap: BinaryHeap::new(),
        };
        for (i, p) in paths.iter().enumerate() {
            let mut r = RunReader::open(p)?;
            let h = r.next()?;
            if let Some(h) = &h {
                m.heap.push(Reverse((h.key(), i)));
            }
            m.readers.push(r);
            m.heads.push(h);
        }
        Ok(m)
    }
    fn take(&mut self, i: usize) -> Result<Rec> {
        let r = self.heads[i].take().unwrap();
        let n = self.readers[i].next()?;
        if let Some(n) = &n {
            ensure!(
                n.key() > r.key(),
                "{}: records out of order",
                self.readers[i].path.display()
            );
            self.heap.push(Reverse((n.key(), i)));
        }
        self.heads[i] = n;
        Ok(r)
    }
    fn next(&mut self) -> Result<Option<Rec>> {
        let Some(Reverse((k, i))) = self.heap.pop() else {
            return Ok(None);
        };
        let mut acc = self.take(i)?;
        while let Some(Reverse((k2, _))) = self.heap.peek() {
            if *k2 != k {
                break;
            }
            let Reverse((_, j)) = self.heap.pop().unwrap();
            let r = self.take(j)?;
            acc.absorb(&r);
        }
        Ok(Some(acc))
    }
}

// ---------- phase 1 ----------

#[derive(Default)]
struct UnitCheck {
    /// G3 ids whose shape-derived occurrences differ from the stored tx_count sum.
    g3_mismatch: usize,
    /// Whether the transaction-shape occurrences add up to the ledgers' tx_count.
    tx_mismatch: bool,
}

fn extract_unit(dir: &Path) -> Result<(Vec<Rec>, UnitCheck)> {
    let mut d = RunData::default();
    // stored id -> (tx_count, ledger_count, min_seq, max_seq)
    let mut cst: HashMap<Id, (u64, u64, u32, u32)> = HashMap::new();
    for r in report::rows(&dir.join("components.parquet"))? {
        let i = report::id(&r[0]);
        let st = (
            report::int(&r[4]) as u64,
            report::int(&r[5]) as u64,
            report::int(&r[6]) as u32,
            report::int(&r[7]) as u32,
        );
        ensure!(
            d.comps.insert(i, report::comp_of_row(&r)).is_none(),
            "{}: component {} twice",
            dir.display(),
            hex::encode(i)
        );
        cst.insert(i, st);
    }
    // stored id -> (tx_count, min_seq, max_seq)
    let mut sst: HashMap<Id, (u64, u32, u32)> = HashMap::new();
    for r in report::rows(&dir.join("tx_shapes.parquet"))? {
        let i = report::id(&r[0]);
        let st = (
            report::int(&r[8]) as u64,
            report::int(&r[10]) as u32,
            report::int(&r[11]) as u32,
        );
        ensure!(
            d.shapes.insert(i, report::shape_of_row(&r)).is_none(),
            "{}: tx shape {} twice",
            dir.display(),
            hex::encode(i)
        );
        sst.insert(i, st);
    }
    for (i, s) in &d.shapes {
        for c in s.comps() {
            ensure!(
                d.comps.contains_key(c),
                "{}: tx shape {} references component {} not in the unit",
                dir.display(),
                hex::encode(i),
                hex::encode(c)
            );
        }
    }
    // (protocol, lcm arm) -> (ledgers, txs, min, max)
    let mut facts: BTreeMap<(u32, u32), (u64, u64, u32, u32)> = BTreeMap::new();
    let mut ledger_txs = 0u64;
    for r in report::rows(&dir.join("ledgers.parquet"))? {
        let seq = report::int(&r[0]) as u32;
        let (hv, arm, txc) = (
            report::int(&r[7]) as u32,
            report::int(&r[9]) as u32,
            report::int(&r[12]) as u64,
        );
        let ls = report::id(&r[15]);
        ensure!(
            d.comps.contains_key(&ls),
            "{}: ledger {seq} component {} not in the unit",
            dir.display(),
            hex::encode(ls)
        );
        let e = facts.entry((hv, arm)).or_insert((0, 0, u32::MAX, 0));
        e.0 += 1;
        e.1 += txc;
        e.2 = e.2.min(seq);
        e.3 = e.3.max(seq);
        ledger_txs += txc;
    }
    let mut out: Vec<Rec> = Vec::new();
    for ((hv, arm), (n, txs, lo, hi)) in &facts {
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&hv.to_be_bytes());
        id[4..8].copy_from_slice(&arm.to_be_bytes());
        let mut r = Rec::new(FACTS, b'P', id);
        r.occ = *n;
        r.aux = *txs;
        r.span(*lo, *hi);
        out.push(r);
    }
    let mut check = UnitCheck::default();
    for (lv, name) in LEVELS {
        let p = project(&d, &level(name));
        let mut m: HashMap<(u8, Id), Rec> = HashMap::new();
        let mut stored: HashMap<(u8, Id), u64> = HashMap::new();
        for (i, c) in &d.comps {
            let (tx, lc, lo, hi) = cst[i];
            let k = (c.kind as u8, p.comp[i]);
            let e = m.entry(k).or_insert_with(|| Rec::new(lv, k.0, k.1));
            e.span(lo, hi);
            if c.kind == 'L' {
                e.occ += lc;
            } else {
                *stored.entry(k).or_default() += tx;
            }
        }
        let mut shape_txs = 0u64;
        for (si, s) in &d.shapes {
            let (tx, lo, hi) = sst[si];
            shape_txs += tx;
            let ids: BTreeSet<(u8, Id)> = s
                .comps()
                .map(|c| (d.comps[c].kind as u8, p.comp[c]))
                .collect();
            for k in ids {
                m.get_mut(&k).unwrap().occ += tx;
            }
            let k = (TX, p.shape[si]);
            let e = m.entry(k).or_insert_with(|| Rec::new(lv, k.0, k.1));
            e.occ += tx;
            e.span(lo, hi);
        }
        if shape_txs != ledger_txs {
            check.tx_mismatch = true;
        }
        if name == "G3" {
            check.g3_mismatch = stored.iter().filter(|(k, n)| m[*k].occ != **n).count();
        }
        out.extend(m.into_values());
    }
    out.sort_by_key(|r| r.key());
    Ok((out, check))
}

fn unit_list(a: &ExtractArgs) -> Result<Vec<PathBuf>> {
    let Some(f) = &a.units_from else {
        return super::store::partitions(&a.run);
    };
    let mut v = Vec::new();
    for l in fs::read_to_string(f)?.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let name = Path::new(l).file_name().context("unit name")?;
        let p = a.run.join(name);
        ensure!(
            p.join("MANIFEST.json").exists(),
            "{}: not a unit of the run",
            p.display()
        );
        v.push(p);
    }
    v.sort();
    v.dedup();
    Ok(v)
}

pub fn extract(a: ExtractArgs) -> Result<()> {
    let units = unit_list(&a)?;
    fs::create_dir_all(&a.out)?;
    let readme = a.out.join("README.txt");
    if fs::read(&readme).ok().as_deref() != Some(RUNS_README.as_bytes()) {
        fs::write(tmp_of(&readme), RUNS_README)?;
        fs::rename(tmp_of(&readme), &readme)?;
    }
    let todo: Vec<&PathBuf> = units
        .iter()
        .filter(|u| !a.out.join(run_name(u)).exists())
        .collect();
    eprintln!(
        "census-extract: {} units, {} already done, {} to do, {} jobs",
        units.len(),
        units.len() - todo.len(),
        todo.len(),
        a.jobs.max(1)
    );
    let next = AtomicUsize::new(0);
    let errs: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let warn: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let done = AtomicUsize::new(0);
    let t0 = Instant::now();
    std::thread::scope(|sc| {
        for _ in 0..a.jobs.max(1) {
            sc.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= todo.len() || !errs.lock().unwrap().is_empty() {
                    return;
                }
                let u = todo[i];
                let t = Instant::now();
                let res = extract_unit(u).and_then(|(recs, chk)| {
                    let mut w = RunWriter::create(&a.out.join(run_name(u)))?;
                    for r in &recs {
                        w.push(r)?;
                    }
                    Ok((recs.len(), w.finish()?, chk))
                });
                match res {
                    Ok((n, bytes, chk)) => {
                        let k = done.fetch_add(1, Ordering::SeqCst) + 1;
                        let name = u.file_name().unwrap().to_string_lossy().to_string();
                        if chk.g3_mismatch > 0 || chk.tx_mismatch {
                            warn.lock().unwrap().push(format!(
                                "{name}: g3 occurrence mismatches {}, tx sum mismatch {}",
                                chk.g3_mismatch, chk.tx_mismatch
                            ));
                        }
                        eprintln!(
                            "[{k}/{}] {name}: {n} records, {bytes} bytes, {:.2} s (elapsed {:.0} s)",
                            todo.len(),
                            t.elapsed().as_secs_f64(),
                            t0.elapsed().as_secs_f64()
                        );
                    }
                    Err(e) => errs
                        .lock()
                        .unwrap()
                        .push(format!("{}: {e:#}", u.display())),
                }
            });
        }
    });
    for w in warn.into_inner().unwrap() {
        eprintln!("check: {w}");
    }
    let errs = errs.into_inner().unwrap();
    if !errs.is_empty() {
        bail!("{} unit(s) failed: {}", errs.len(), errs.join("; "));
    }
    eprintln!(
        "census-extract: done in {:.0} s",
        t0.elapsed().as_secs_f64()
    );
    Ok(())
}

fn run_name(unit: &Path) -> String {
    format!("{}.cen", unit.file_name().unwrap().to_string_lossy())
}

// ---------- phase 2 ----------

fn kind_name(k: u8) -> String {
    if k == TX {
        "tx".into()
    } else {
        (k as char).to_string()
    }
}

fn level_name(l: u8) -> &'static str {
    LEVELS
        .iter()
        .find(|(b, _)| *b == l)
        .map(|(_, n)| *n)
        .unwrap_or("?")
}

#[derive(Default)]
struct Stats {
    distinct: u64,
    once: u64,
    le10: u64,
    one_unit: u64,
    total: u64,
    hist: BTreeMap<u64, u64>,
    era5m: BTreeMap<u32, u64>,
    era_proto: BTreeMap<u32, u64>,
}

impl Stats {
    fn pct(&self, q: f64) -> u64 {
        let rank = ((q * self.distinct as f64).ceil() as u64).max(1);
        let mut seen = 0;
        for (v, n) in &self.hist {
            seen += n;
            if seen >= rank {
                return *v;
            }
        }
        0
    }
}

const ERA: u32 = 5_000_000;

fn merge_into(paths: &[PathBuf], dst: &Path) -> Result<()> {
    let mut m = Merger::open(paths)?;
    let mut w = RunWriter::create(dst)?;
    while let Some(r) = m.next()? {
        w.push(&r)?;
    }
    w.finish()?;
    Ok(())
}

struct ShapeOut {
    enc: zstd::Encoder<'static, BufWriter<File>>,
    dst: PathBuf,
}

impl ShapeOut {
    fn create(dst: PathBuf) -> Result<ShapeOut> {
        let f = File::create(tmp_of(&dst))?;
        let mut enc = zstd::Encoder::new(BufWriter::with_capacity(1 << 20, f), ZSTD_LEVEL)?;
        enc.write_all(b"id\toccurrences\tfirst_ledger\tlast_ledger\tunits\n")?;
        Ok(ShapeOut { enc, dst })
    }
    fn finish(self) -> Result<()> {
        let f = self
            .enc
            .finish()?
            .into_inner()
            .map_err(|e| e.into_error())?;
        f.sync_all()?;
        drop(f);
        fs::rename(tmp_of(&self.dst), &self.dst)?;
        Ok(())
    }
}

fn write_atomic(p: &Path, b: &[u8]) -> Result<()> {
    fs::write(tmp_of(p), b)?;
    fs::rename(tmp_of(p), p)?;
    Ok(())
}

pub fn merge(a: MergeArgs) -> Result<()> {
    let fan_in = a.fan_in.max(2);
    let mut inputs: Vec<PathBuf> = Vec::new();
    let mut tmps = 0usize;
    for e in fs::read_dir(&a.runs)? {
        let p = e?.path();
        let n = p.file_name().unwrap().to_string_lossy().to_string();
        if n.ends_with(".cen") {
            inputs.push(p);
        } else if n.ends_with(".cen.tmp") {
            tmps += 1;
        }
    }
    ensure!(
        tmps == 0,
        "{}: {tmps} unfinished run file(s) (*.cen.tmp): finish census-extract first",
        a.runs.display()
    );
    ensure!(!inputs.is_empty(), "{}: no run files", a.runs.display());
    inputs.sort();
    fs::create_dir_all(&a.out)?;
    let work = a.out.join("merge-tmp");
    fs::create_dir_all(&work)?;
    let mut listing = String::new();
    for p in &inputs {
        listing.push_str(&format!(
            "{}\t{}\n",
            p.file_name().unwrap().to_string_lossy(),
            fs::metadata(p)?.len()
        ));
    }
    let lp = work.join("inputs.tsv");
    match fs::read_to_string(&lp) {
        Ok(old) if old != listing => bail!(
            "{}: the inputs changed since the last merge; remove {} to start over",
            a.runs.display(),
            work.display()
        ),
        Ok(_) => {}
        Err(_) => write_atomic(&lp, listing.as_bytes())?,
    }
    let t0 = Instant::now();
    eprintln!("census-merge: {} run files, fan-in {fan_in}", inputs.len());
    let mut cur = inputs;
    let mut pass = 0usize;
    while cur.len() > fan_in {
        let chunks: Vec<&[PathBuf]> = cur.chunks(fan_in).collect();
        let outs: Vec<PathBuf> = (0..chunks.len())
            .map(|j| work.join(format!("p{pass}-{j:06}.cen")))
            .collect();
        let next = AtomicUsize::new(0);
        let errs: Mutex<Vec<String>> = Mutex::new(Vec::new());
        std::thread::scope(|sc| {
            for _ in 0..a.jobs.max(1) {
                sc.spawn(|| loop {
                    let j = next.fetch_add(1, Ordering::SeqCst);
                    if j >= chunks.len() || !errs.lock().unwrap().is_empty() {
                        return;
                    }
                    if outs[j].exists() {
                        continue;
                    }
                    let t = Instant::now();
                    match merge_into(chunks[j], &outs[j]) {
                        Ok(()) => eprintln!(
                            "pass {pass}: {}/{} merged ({} files) in {:.1} s",
                            j + 1,
                            chunks.len(),
                            chunks[j].len(),
                            t.elapsed().as_secs_f64()
                        ),
                        Err(e) => errs.lock().unwrap().push(format!("{e:#}")),
                    }
                });
            }
        });
        let errs = errs.into_inner().unwrap();
        if !errs.is_empty() {
            bail!("merge pass {pass} failed: {}", errs.join("; "));
        }
        cur = outs;
        pass += 1;
    }
    final_pass(&cur, &a.out)?;
    fs::remove_dir_all(&work)?;
    eprintln!("census-merge: done in {:.0} s", t0.elapsed().as_secs_f64());
    Ok(())
}

fn final_pass(paths: &[PathBuf], out: &Path) -> Result<()> {
    let mut m = Merger::open(paths)?;
    // (protocol, arm) -> facts record
    let mut facts: Vec<Rec> = Vec::new();
    // first ledger of each protocol, ascending
    let mut proto_start: Vec<(u32, u32)> = Vec::new();
    let mut stats: BTreeMap<(u8, u8), Stats> = BTreeMap::new();
    let mut cur: Option<((u8, u8), ShapeOut)> = None;
    while let Some(r) = m.next()? {
        if r.level == FACTS {
            facts.push(r);
            continue;
        }
        if proto_start.is_empty() && !facts.is_empty() {
            let mut first: BTreeMap<u32, u32> = BTreeMap::new();
            for f in &facts {
                let hv = u32::from_be_bytes(f.id[..4].try_into().unwrap());
                let e = first.entry(hv).or_insert(u32::MAX);
                *e = (*e).min(f.first);
            }
            proto_start = first.into_iter().map(|(p, s)| (s, p)).collect();
            proto_start.sort();
        }
        let lk = (r.level, r.kind);
        if cur.as_ref().is_none_or(|(k, _)| *k != lk) {
            if let Some((_, w)) = cur.take() {
                w.finish()?;
            }
            let dst = out.join(format!(
                "shapes-{}-{}.tsv.zst",
                level_name(r.level),
                kind_name(r.kind)
            ));
            cur = Some((lk, ShapeOut::create(dst)?));
        }
        let w = &mut cur.as_mut().unwrap().1;
        writeln!(
            w.enc,
            "{}\t{}\t{}\t{}\t{}",
            hex::encode(r.id),
            r.occ,
            r.first,
            r.last,
            r.units
        )?;
        let s = stats.entry(lk).or_default();
        s.distinct += 1;
        s.once += (r.occ == 1) as u64;
        s.le10 += (r.occ <= 10) as u64;
        s.one_unit += (r.units == 1) as u64;
        s.total += r.occ;
        *s.hist.entry(r.occ).or_default() += 1;
        *s.era5m.entry(r.first / ERA).or_default() += 1;
        let p = proto_start
            .iter()
            .rev()
            .find(|(st, _)| *st <= r.first)
            .map(|x| x.1)
            .unwrap_or(0);
        *s.era_proto.entry(p).or_default() += 1;
    }
    if let Some((_, w)) = cur.take() {
        w.finish()?;
    }
    let eras: BTreeSet<u32> = stats
        .values()
        .flat_map(|s| s.era5m.keys().copied())
        .collect();
    let protos: BTreeSet<u32> = stats
        .values()
        .flat_map(|s| s.era_proto.keys().copied())
        .collect();
    let mut t = String::from(
        "level\tkind\tdistinct\tocc_eq_1\tocc_le_10\tin_one_unit\tocc_total\tocc_p50\tocc_p90\tocc_p99\tocc_p999\tocc_max",
    );
    for e in &eras {
        t.push_str(&format!(
            "\tfirst_{}M-{}M",
            e * (ERA / 1_000_000),
            (e + 1) * (ERA / 1_000_000)
        ));
    }
    for p in &protos {
        t.push_str(&format!("\tfirst_p{p}"));
    }
    t.push('\n');
    for ((l, k), s) in &stats {
        t.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            level_name(*l),
            kind_name(*k),
            s.distinct,
            s.once,
            s.le10,
            s.one_unit,
            s.total,
            s.pct(0.5),
            s.pct(0.9),
            s.pct(0.99),
            s.pct(0.999),
            s.hist.keys().next_back().copied().unwrap_or(0)
        ));
        for e in &eras {
            t.push_str(&format!("\t{}", s.era5m.get(e).copied().unwrap_or(0)));
        }
        for p in &protos {
            t.push_str(&format!("\t{}", s.era_proto.get(p).copied().unwrap_or(0)));
        }
        t.push('\n');
    }
    let mut f = String::from("protocol\tlcm_arm\tledgers\ttxs\tfirst_ledger\tlast_ledger\tunits\n");
    for r in &facts {
        f.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            u32::from_be_bytes(r.id[..4].try_into().unwrap()),
            u32::from_be_bytes(r.id[4..8].try_into().unwrap()),
            r.occ,
            r.aux,
            r.first,
            r.last,
            r.units
        ));
    }
    write_atomic(&out.join("facts.tsv"), f.as_bytes())?;
    write_atomic(&out.join("summary.tsv"), t.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trip_and_merge() {
        let dir = std::env::temp_dir().join(format!("xdrcheck-census-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let mk = |id: u8, occ: u64, f: u32| {
            let mut r = Rec::new(1, b'E', [id; 16]);
            r.occ = occ;
            r.span(f, f + 1);
            r
        };
        let a = [mk(1, 2, 10), mk(3, 1, 30)];
        let b = [mk(1, 5, 5), mk(2, 1, 20)];
        for (n, rs) in [("a.cen", &a), ("b.cen", &b)] {
            let mut w = RunWriter::create(&dir.join(n)).unwrap();
            for r in rs.iter() {
                w.push(r).unwrap();
            }
            w.finish().unwrap();
        }
        let mut m = Merger::open(&[dir.join("a.cen"), dir.join("b.cen")]).unwrap();
        let mut got = Vec::new();
        while let Some(r) = m.next().unwrap() {
            got.push(r);
        }
        assert_eq!(got.len(), 3);
        assert_eq!(
            (got[0].occ, got[0].first, got[0].last, got[0].units),
            (7, 5, 11, 2)
        );
        assert_eq!(got[1].id, [2; 16]);
        fs::remove_dir_all(&dir).unwrap();
    }
}
