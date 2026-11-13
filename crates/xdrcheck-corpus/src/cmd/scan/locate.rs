//! `scan locate-build` and `scan locate`: where in history a token, a G3 component or a G3
//! transaction shape occurs, without re-reading the scan.
//!
//! A *posting* is (ledger, transaction index, multiplicity). The transaction index is the scan's
//! apply index (0-based); [`LEDGER_TX`] marks a ledger-level posting (a token carried by the ledger
//! component). Multiplicity is the number of distinct G3 components of the transaction (or ledger)
//! that carry the token, so the sum of multiplicities equals the token census `occurrences`; for
//! components and shapes it is 1.
//!
//! Keys whose census occurrences are at most `--cap` keep every posting. Larger keys keep the first
//! N, the last N and N postings at evenly spaced ranks in between, plus exact totals (occurrences,
//! postings, distinct ledgers, first and last ledger).
//!
//! Build, resumable at every stage (files written as `.tmp` and renamed):
//! 1. per unit (`p1/`): exact totals of the capped keys and all postings of the others;
//! 2. ranks: from the global totals, the ranks each capped key keeps, per unit;
//! 3. per unit holding a kept rank (`p2/`): those postings, expanded only in the ledgers that hold them;
//! 4. buckets by key range (`buckets/`), then `keys.idx` + `postings.dat` in key order.
//!
//! Index files (little-endian):
//! - `meta.json`: key counts per type (tokens, components, shapes in this order), N, cap, sources.
//! - `keys.idx`: one 64-byte row per key, in key order (each type sorted by id): id[16] |
//!   occurrences u64 | postings u64 | ledgers u32 | first u32 | last u32 | stored u32 | flags u32
//!   (bit 0 capped, bit 1 block zstd) | offset u64 | bytes u32.
//! - `postings.dat`: per key one block of LEB128 varints (seq delta, tx, multiplicity), zstd when
//!   flagged.
//! - `tokens.tsv`: token id, kind, class, token text, in key order.
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{bail, ensure, Context, Result};

use super::report::{self, level, project, RunData};
use super::shape::Id;
use super::tokens::token_id;
use super::units::{self, check_manifest, Unit, COMP_KINDS};

/// Transaction index of a ledger-level posting.
pub const LEDGER_TX: u16 = u16::MAX;
const ROW: usize = 64;
const NONE: u32 = u32::MAX;

#[derive(clap::Args, Debug)]
pub struct BuildArgs {
    /// Merged run directory (read only)
    #[arg(long)]
    pub run: PathBuf,
    /// Census directory of the same run (`census-merge` output)
    #[arg(long)]
    pub census: PathBuf,
    /// Token census of the same run (`token-census` output `tokens.tsv.zst`)
    #[arg(long)]
    pub tokens: PathBuf,
    /// Output directory (index and work files)
    #[arg(long)]
    pub out: PathBuf,
    /// File with unit directory names (one per line); default: every unit of the run
    #[arg(long)]
    pub units_from: Option<PathBuf>,
    /// Accept units that do not follow each other (a partial view)
    #[arg(long)]
    pub allow_gaps: bool,
    /// Units worked in parallel
    #[arg(long, default_value_t = 4)]
    pub jobs: usize,
    /// Postings kept at each end and in between for a capped key
    #[arg(long, default_value_t = 1000)]
    pub n: u64,
    /// Keys with more census occurrences than this are capped
    #[arg(long, default_value_t = 100_000)]
    pub cap: u64,
    /// Postings per bucket of the final stage (memory: 16 bytes each)
    #[arg(long, default_value_t = 40_000_000)]
    pub bucket_postings: u64,
    /// Stop after stage 1 (timing runs)
    #[arg(long)]
    pub stage1_only: bool,
    /// Keep the work files (`p1/`, `p2/`, `buckets/`) after the index is written
    #[arg(long)]
    pub keep_work: bool,
}

#[derive(clap::Args, Debug)]
pub struct QueryArgs {
    /// Index directory (`locate-build --out`)
    #[arg(long)]
    pub index: PathBuf,
    /// Token text or token id (32 hex)
    #[arg(long)]
    pub token: Option<String>,
    /// G3 component id (the census id, 32 hex)
    #[arg(long)]
    pub component: Option<String>,
    /// G3 transaction shape id (the census id, 32 hex)
    #[arg(long)]
    pub shape: Option<String>,
    /// Token class `K|class` (e.g. `V|u64band`): every token of the class
    #[arg(long)]
    pub class: Option<String>,
    /// Only ledgers in `a..b` (inclusive; either side may be empty)
    #[arg(long)]
    pub era: Option<String>,
    /// Postings printed per key (0 = all stored)
    #[arg(long, default_value_t = 0)]
    pub limit: usize,
    /// Print only the per-key summary line
    #[arg(long)]
    pub summary: bool,
}

#[derive(clap::Args, Debug)]
pub struct CheckArgs {
    /// Index directory
    #[arg(long)]
    pub index: PathBuf,
    /// Token census `tokens.tsv.zst`
    #[arg(long)]
    pub tokens: PathBuf,
    /// Pilot index directory (`components.tsv.zst`, `tx_shapes.tsv.zst`, `ledgers.tsv.zst`)
    #[arg(long)]
    pub pilot: Option<PathBuf>,
    /// Tokens sampled (the rarest and most common 20 included)
    #[arg(long, default_value_t = 200)]
    pub sample: usize,
    /// Compare with the pilot only on ledgers in `a..b` (an index built over part of the run)
    #[arg(long)]
    pub era: Option<String>,
    /// Output TSV of the per-token comparison
    #[arg(long)]
    pub out: PathBuf,
}

// ---------- keys ----------

struct Keys {
    tok_ids: Vec<Id>,
    tok_text: HashMap<String, u32>,
    comp_ids: Vec<Id>,
    shape_ids: Vec<Id>,
    /// census occurrences, first, last per key
    occ: Vec<u64>,
    first: Vec<u32>,
    last: Vec<u32>,
    /// capped-key index or NONE
    big: Vec<u32>,
    big_keys: Vec<u32>,
    /// token texts in key order: (id hex, kind, class, text)
    tok_rows: Vec<(String, String, String, String)>,
}

impl Keys {
    fn n_tok(&self) -> u32 {
        self.tok_ids.len() as u32
    }
    fn n_comp(&self) -> u32 {
        self.comp_ids.len() as u32
    }
    fn total(&self) -> usize {
        self.tok_ids.len() + self.comp_ids.len() + self.shape_ids.len()
    }
    fn comp_key(&self, id: &Id) -> Option<u32> {
        self.comp_ids
            .binary_search(id)
            .ok()
            .map(|i| self.n_tok() + i as u32)
    }
    fn shape_key(&self, id: &Id) -> Option<u32> {
        self.shape_ids
            .binary_search(id)
            .ok()
            .map(|i| self.n_tok() + self.n_comp() + i as u32)
    }

    fn load(a: &BuildArgs) -> Result<Keys> {
        // tokens: (id, kind, class, text, occ, first, last)
        let mut toks: Vec<(Id, String, String, String, u64, u32, u32)> = Vec::new();
        units::each_tsv_zst(&a.tokens, |c| {
            ensure!(c.len() >= 8, "short line");
            let id = units::unhex16(c[0])?;
            ensure!(id == token_id(c[3]), "token id of {:?} differs", c[3]);
            toks.push((
                id,
                c[1].into(),
                c[2].into(),
                c[3].into(),
                c[5].parse()?,
                c[6].parse()?,
                c[7].parse()?,
            ));
            Ok(())
        })?;
        toks.sort_by_key(|x| x.0);
        let mut comps: Vec<(Id, u64, u32, u32)> = Vec::new();
        for k in COMP_KINDS {
            units::each_census(&a.census, "G3", k, |id, o, f, l| {
                comps.push((id, o, f, l));
                Ok(())
            })?;
        }
        comps.sort_by_key(|x| x.0);
        let mut shapes: Vec<(Id, u64, u32, u32)> = Vec::new();
        units::each_tsv_zst(&a.census.join("shapes-G3-tx.tsv.zst"), |c| {
            ensure!(c.len() >= 4, "short line");
            shapes.push((
                units::unhex16(c[0])?,
                c[1].parse()?,
                c[2].parse()?,
                c[3].parse()?,
            ));
            Ok(())
        })?;
        shapes.sort_by_key(|x| x.0);
        for w in comps.windows(2) {
            ensure!(w[0].0 != w[1].0, "component id twice in the census");
        }
        let total = toks.len() + comps.len() + shapes.len();
        let mut k = Keys {
            tok_ids: toks.iter().map(|t| t.0).collect(),
            tok_text: HashMap::new(),
            comp_ids: comps.iter().map(|t| t.0).collect(),
            shape_ids: shapes.iter().map(|t| t.0).collect(),
            occ: Vec::with_capacity(total),
            first: Vec::with_capacity(total),
            last: Vec::with_capacity(total),
            big: Vec::with_capacity(total),
            big_keys: Vec::new(),
            tok_rows: Vec::new(),
        };
        for (i, t) in toks.iter().enumerate() {
            k.tok_text.insert(t.3.clone(), i as u32);
            k.occ.push(t.4);
            k.first.push(t.5);
            k.last.push(t.6);
        }
        k.tok_rows = toks
            .into_iter()
            .map(|t| (hex::encode(t.0), t.1, t.2, t.3))
            .collect();
        for (_, o, f, l) in comps.iter().chain(shapes.iter()) {
            k.occ.push(*o);
            k.first.push(*f);
            k.last.push(*l);
        }
        for (i, o) in k.occ.iter().enumerate() {
            if *o > a.cap {
                k.big.push(k.big_keys.len() as u32);
                k.big_keys.push(i as u32);
            } else {
                k.big.push(NONE);
            }
        }
        Ok(k)
    }
}

// ---------- one unit ----------

/// One unit, resolved to keys: per stored shape its key list, per ledger its ledger-level list,
/// and the occurrence rows grouped by ledger.
struct UnitKeys {
    /// key lists, (key, multiplicity), sorted by key
    lists: Vec<Vec<(u32, u16)>>,
    /// per ledger (ascending): (seq, ledger-level list index or NONE, rows: (list index, tx indexes))
    ledgers: Vec<(u32, u32, Vec<(u32, Vec<u16>)>)>,
}

fn resolve_unit(k: &Keys, u: &Unit) -> Result<UnitKeys> {
    check_manifest(&u.dir)?;
    let name = u.name();
    let mut d = RunData::default();
    for r in report::rows(&u.dir.join("components.parquet"))? {
        d.comps.insert(report::id(&r[0]), report::comp_of_row(&r));
    }
    for r in report::rows(&u.dir.join("tx_shapes.parquet"))? {
        d.shapes.insert(report::id(&r[0]), report::shape_of_row(&r));
    }
    let p = project(&d, &level("G3"));
    // stored component -> (component key, token keys)
    let mut comp: HashMap<Id, (u32, Vec<u32>)> = HashMap::with_capacity(d.comps.len());
    for (sid, c) in &d.comps {
        let g3 = p.comp[sid];
        let ck = k
            .comp_key(&g3)
            .with_context(|| format!("{name}: component {} not in the census", hex::encode(g3)))?;
        let mut tl: Vec<u32> = Vec::with_capacity(c.tokens.len());
        for t in &c.tokens {
            tl.push(
                *k.tok_text
                    .get(t)
                    .with_context(|| format!("{name}: token {t:?} not in the token census"))?,
            );
        }
        tl.sort_unstable();
        tl.dedup();
        comp.insert(*sid, (ck, tl));
    }
    let mut lists: Vec<Vec<(u32, u16)>> = Vec::new();
    // key lists of components seen together: (sorted distinct component keys) -> list
    let build = |cks: &mut Vec<(u32, &Vec<u32>)>, extra: Option<u32>| -> Vec<(u32, u16)> {
        cks.sort_by_key(|x| x.0);
        cks.dedup_by_key(|x| x.0);
        let mut m: BTreeMap<u32, u16> = BTreeMap::new();
        for (ck, tl) in cks.iter() {
            *m.entry(*ck).or_default() += 1;
            for t in tl.iter() {
                *m.entry(*t).or_default() += 1;
            }
        }
        if let Some(x) = extra {
            *m.entry(x).or_default() += 1;
        }
        m.into_iter().collect()
    };
    let mut shape_list: HashMap<Id, u32> = HashMap::with_capacity(d.shapes.len());
    for (sid, s) in &d.shapes {
        let g3 = p.shape[sid];
        let sk = k
            .shape_key(&g3)
            .with_context(|| format!("{name}: tx shape {} not in the census", hex::encode(g3)))?;
        let mut cks: Vec<(u32, &Vec<u32>)> = Vec::new();
        for c in s.comps() {
            let e = comp
                .get(c)
                .with_context(|| format!("{name}: shape references a missing component"))?;
            cks.push((e.0, &e.1));
        }
        shape_list.insert(*sid, lists.len() as u32);
        lists.push(build(&mut cks, Some(sk)));
    }
    let mut lcomp_list: HashMap<Id, u32> = HashMap::new();
    let mut by_seq: BTreeMap<u32, (u32, Vec<(u32, Vec<u16>)>)> = BTreeMap::new();
    for r in report::rows(&u.dir.join("ledgers.parquet"))? {
        let seq = report::int(&r[0]) as u32;
        let ls = report::id(&r[15]);
        let li = match lcomp_list.get(&ls) {
            Some(x) => *x,
            None => {
                let e = comp
                    .get(&ls)
                    .with_context(|| format!("{name}: ledger {seq} component missing"))?;
                let mut cks = vec![(e.0, &e.1)];
                let x = lists.len() as u32;
                lists.push(build(&mut cks, None));
                lcomp_list.insert(ls, x);
                x
            }
        };
        by_seq.insert(seq, (li, Vec::new()));
    }
    for r in report::rows(&u.dir.join("occurrences.parquet"))? {
        let seq = report::int(&r[0]) as u32;
        let sid = report::id(&r[1]);
        let ix: Vec<u16> = report::bytes(&r[3])
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        let li = *shape_list
            .get(&sid)
            .with_context(|| format!("{name}: occurrence of an unknown tx shape"))?;
        let e = by_seq
            .get_mut(&seq)
            .with_context(|| format!("{name}: occurrence in ledger {seq} without a ledger row"))?;
        e.1.push((li, ix));
    }
    let ledgers = by_seq
        .into_iter()
        .map(|(s, (li, rows))| (s, li, rows))
        .collect();
    Ok(UnitKeys { lists, ledgers })
}

// ---------- binary helpers ----------

type Posting = (u32, u32, u16, u16);

fn put_postings(w: &mut (impl Write + ?Sized), v: &[Posting]) -> Result<()> {
    w.write_all(&(v.len() as u64).to_le_bytes())?;
    let mut b = Vec::with_capacity(v.len() * 12);
    for (k, s, t, m) in v {
        b.extend_from_slice(&k.to_le_bytes());
        b.extend_from_slice(&s.to_le_bytes());
        b.extend_from_slice(&t.to_le_bytes());
        b.extend_from_slice(&m.to_le_bytes());
    }
    w.write_all(&b)?;
    Ok(())
}

fn get_postings(r: &mut impl Read) -> Result<Vec<Posting>> {
    let mut n8 = [0u8; 8];
    r.read_exact(&mut n8)?;
    let n = u64::from_le_bytes(n8) as usize;
    let mut b = vec![0u8; n * 12];
    r.read_exact(&mut b)?;
    Ok(b.as_chunks::<12>()
        .0
        .iter()
        .map(|c| {
            (
                u32::from_le_bytes(c[0..4].try_into().unwrap()),
                u32::from_le_bytes(c[4..8].try_into().unwrap()),
                u16::from_le_bytes(c[8..10].try_into().unwrap()),
                u16::from_le_bytes(c[10..12].try_into().unwrap()),
            )
        })
        .collect())
}

fn write_zst_atomic(p: &Path, f: impl FnOnce(&mut dyn Write) -> Result<()>) -> Result<()> {
    let tmp = units::tmp_of(p);
    let mut enc = zstd::Encoder::new(BufWriter::with_capacity(1 << 20, File::create(&tmp)?), 3)?;
    f(&mut enc)?;
    let file = enc.finish()?.into_inner().map_err(|e| e.into_error())?;
    file.sync_all()?;
    fs::rename(&tmp, p)?;
    Ok(())
}

fn open_zst(p: &Path) -> Result<BufReader<zstd::Decoder<'static, BufReader<File>>>> {
    Ok(BufReader::with_capacity(
        1 << 20,
        zstd::Decoder::new(File::open(p).with_context(|| p.display().to_string())?)?,
    ))
}

/// Totals of a capped key in one unit (or overall).
#[derive(Clone, Copy, Default)]
struct BigSt {
    occ: u64,
    ent: u64,
    led: u32,
    first: u32,
    last: u32,
}

// ---------- stage 1 ----------

fn stage1(k: &Keys, u: &Unit) -> Result<(Vec<(u32, BigSt)>, Vec<Posting>)> {
    let uk = resolve_unit(k, u)?;
    let nb = k.big_keys.len();
    let mut st: Vec<BigSt> = vec![BigSt::default(); nb];
    let mut seen_at: Vec<u32> = vec![0; nb];
    let mut touched: Vec<u32> = Vec::new();
    let mut small: Vec<Posting> = Vec::new();
    let ledger_tx = [LEDGER_TX];
    for (seq, li, rows) in &uk.ledgers {
        let items = std::iter::once((*li, &ledger_tx[..]))
            .chain(rows.iter().map(|(l, ix)| (*l, ix.as_slice())));
        for (l, txs) in items {
            let n = txs.len() as u64;
            for &(key, m) in &uk.lists[l as usize] {
                let b = k.big[key as usize];
                if b == NONE {
                    for t in txs {
                        small.push((key, *seq, *t, m));
                    }
                    continue;
                }
                let s = &mut st[b as usize];
                if s.ent == 0 {
                    touched.push(b);
                    s.first = *seq;
                }
                s.occ += n * m as u64;
                s.ent += n;
                if seen_at[b as usize] != *seq {
                    seen_at[b as usize] = *seq;
                    s.led += 1;
                    s.last = *seq;
                }
            }
        }
    }
    touched.sort_unstable();
    small.sort_unstable();
    Ok((
        touched.into_iter().map(|b| (b, st[b as usize])).collect(),
        small,
    ))
}

fn p1_paths(out: &Path, u: &Unit) -> (PathBuf, PathBuf) {
    let d = out.join("p1");
    (
        d.join(format!("{}.small.zst", u.name())),
        d.join(format!("{}.big.zst", u.name())),
    )
}

fn write_big(p: &Path, v: &[(u32, BigSt)]) -> Result<()> {
    write_zst_atomic(p, |w| {
        w.write_all(&(v.len() as u64).to_le_bytes())?;
        for (b, s) in v {
            w.write_all(&b.to_le_bytes())?;
            w.write_all(&s.occ.to_le_bytes())?;
            w.write_all(&s.ent.to_le_bytes())?;
            w.write_all(&s.led.to_le_bytes())?;
            w.write_all(&s.first.to_le_bytes())?;
            w.write_all(&s.last.to_le_bytes())?;
        }
        Ok(())
    })
}

fn read_big(p: &Path) -> Result<Vec<(u32, BigSt)>> {
    let mut r = open_zst(p)?;
    let mut n8 = [0u8; 8];
    r.read_exact(&mut n8)?;
    let n = u64::from_le_bytes(n8) as usize;
    let mut b = vec![0u8; n * 32];
    r.read_exact(&mut b)?;
    Ok(b.as_chunks::<32>()
        .0
        .iter()
        .map(|c| {
            let u = |a: usize| u32::from_le_bytes(c[a..a + 4].try_into().unwrap());
            let q = |a: usize| u64::from_le_bytes(c[a..a + 8].try_into().unwrap());
            (
                u(0),
                BigSt {
                    occ: q(4),
                    ent: q(12),
                    led: u(20),
                    first: u(24),
                    last: u(28),
                },
            )
        })
        .collect())
}

// ---------- stage 2: ranks ----------

/// The `i`-th kept rank of a key with `e` postings (`count` of them).
fn kept_count(e: u64, n: u64) -> u64 {
    if e <= 3 * n {
        e
    } else {
        3 * n
    }
}
fn kept_rank(e: u64, n: u64, i: u64) -> u64 {
    if e <= 3 * n {
        return i;
    }
    if i < n {
        i
    } else if i < 2 * n {
        let j = i - n;
        n + ((2 * j + 1) * (e - 2 * n)) / (2 * n)
    } else {
        e - n + (i - 2 * n)
    }
}

// ---------- stage 3 ----------

/// Postings of the requested local ranks: `req` = (key, sorted local ranks).
fn stage3(k: &Keys, u: &Unit, req: &[(u32, Vec<u32>)]) -> Result<Vec<Posting>> {
    let uk = resolve_unit(k, u)?;
    let want: HashMap<u32, usize> = req.iter().enumerate().map(|(i, r)| (r.0, i)).collect();
    // per list: (request index, multiplicity) of the requested keys it carries
    let lw: Vec<Vec<(usize, u16)>> = uk
        .lists
        .iter()
        .map(|l| {
            l.iter()
                .filter_map(|(key, m)| want.get(key).map(|i| (*i, *m)))
                .collect()
        })
        .collect();
    let mut cnt: Vec<u64> = vec![0; req.len()];
    let mut cur: Vec<usize> = vec![0; req.len()];
    let mut lcnt: Vec<u64> = vec![0; req.len()];
    let mut out: Vec<Posting> = Vec::new();
    let ledger_tx = [LEDGER_TX];
    for (seq, li, rows) in &uk.ledgers {
        let items: Vec<(u32, &[u16])> = std::iter::once((*li, &ledger_tx[..]))
            .chain(rows.iter().map(|(l, ix)| (*l, ix.as_slice())))
            .collect();
        let mut touched: Vec<usize> = Vec::new();
        for (l, txs) in &items {
            for &(ri, _) in &lw[*l as usize] {
                if lcnt[ri] == 0 {
                    touched.push(ri);
                }
                lcnt[ri] += txs.len() as u64;
            }
        }
        for ri in touched {
            let ranks = &req[ri].1;
            let (lo, hi) = (cnt[ri], cnt[ri] + lcnt[ri]);
            if cur[ri] < ranks.len() && (ranks[cur[ri]] as u64) < hi {
                let mut txs: Vec<(u16, u16)> = Vec::new();
                for (l, ix) in &items {
                    if let Some(&(_, m)) = lw[*l as usize].iter().find(|x| x.0 == ri) {
                        txs.extend(ix.iter().map(|t| (*t, m)));
                    }
                }
                txs.sort_unstable();
                ensure!(txs.len() as u64 == hi - lo, "ledger {seq}: posting count");
                while cur[ri] < ranks.len() && (ranks[cur[ri]] as u64) < hi {
                    let (t, m) = txs[(ranks[cur[ri]] as u64 - lo) as usize];
                    out.push((req[ri].0, *seq, t, m));
                    cur[ri] += 1;
                }
            }
            cnt[ri] = hi;
            lcnt[ri] = 0;
        }
    }
    for (ri, r) in req.iter().enumerate() {
        ensure!(
            cur[ri] == r.1.len(),
            "{}: key {} has {} postings, rank {} requested",
            u.name(),
            r.0,
            cnt[ri],
            r.1.get(cur[ri]).copied().unwrap_or(0)
        );
    }
    out.sort_unstable();
    Ok(out)
}

// ---------- build ----------

fn varint(b: &mut Vec<u8>, mut x: u64) {
    while x >= 0x80 {
        b.push((x as u8) | 0x80);
        x >>= 7;
    }
    b.push(x as u8);
}

fn unvarint(b: &[u8], pos: &mut usize) -> Result<u64> {
    let mut x = 0u64;
    let mut sh = 0;
    loop {
        ensure!(*pos < b.len(), "truncated block");
        let c = b[*pos];
        *pos += 1;
        x |= ((c & 0x7f) as u64) << sh;
        if c & 0x80 == 0 {
            return Ok(x);
        }
        sh += 7;
    }
}

pub fn build(a: BuildArgs) -> Result<()> {
    let t0 = Instant::now();
    let list = units::list(&a.run, a.units_from.as_deref(), a.allow_gaps)?;
    for d in ["p1", "p2", "buckets"] {
        fs::create_dir_all(a.out.join(d))?;
    }
    let k = Keys::load(&a)?;
    eprintln!(
        "locate: {} units; keys: {} tokens, {} components, {} shapes; {} capped ({:.0} s)",
        list.len(),
        k.tok_ids.len(),
        k.comp_ids.len(),
        k.shape_ids.len(),
        k.big_keys.len(),
        t0.elapsed().as_secs_f64()
    );

    // Stage 1
    let todo: Vec<&Unit> = list
        .iter()
        .filter(|u| {
            let (s, b) = p1_paths(&a.out, u);
            !(s.exists() && b.exists())
        })
        .collect();
    let done = AtomicUsize::new(0);
    let small_n = AtomicUsize::new(0);
    units::par_each(&todo, a.jobs, |_, u| {
        let (big, small) = stage1(&k, u)?;
        let (sp, bp) = p1_paths(&a.out, u);
        write_zst_atomic(&sp, |w| put_postings(w, &small))?;
        write_big(&bp, &big)?;
        small_n.fetch_add(small.len(), Ordering::Relaxed);
        let n = done.fetch_add(1, Ordering::SeqCst) + 1;
        if n.is_multiple_of(500) || n == todo.len() {
            eprintln!(
                "stage 1: [{n}/{}] small postings {} ({:.0} s)",
                todo.len(),
                small_n.load(Ordering::Relaxed),
                t0.elapsed().as_secs_f64()
            );
        }
        Ok(())
    })?;
    eprintln!("stage 1 done ({:.0} s)", t0.elapsed().as_secs_f64());
    if a.stage1_only {
        return Ok(());
    }

    // Stage 2: totals of the capped keys, then the ranks each unit holds.
    let nb = k.big_keys.len();
    let mut tot: Vec<BigSt> = vec![BigSt::default(); nb];
    // Read the per-unit totals twice (never all in memory): totals first, then ranks.
    units::par_ordered(
        &list,
        a.jobs,
        64,
        |u| read_big(&p1_paths(&a.out, u).1),
        |_, ub| {
            for (b, s) in ub {
                let t = &mut tot[b as usize];
                if t.ent == 0 {
                    t.first = s.first;
                }
                t.occ += s.occ;
                t.ent += s.ent;
                t.led += s.led;
                t.last = s.last;
            }
            Ok(())
        },
    )?;
    let mut cum: Vec<u64> = vec![0; nb];
    let mut next: Vec<u64> = vec![0; nb];
    let mut reqs: Vec<Vec<(u32, Vec<u32>)>> = vec![Vec::new(); list.len()];
    let mut n_req = 0usize;
    units::par_ordered(
        &list,
        a.jobs,
        64,
        |u| read_big(&p1_paths(&a.out, u).1),
        |ui, ub| {
            for (b, s) in ub {
                let bi = b as usize;
                let e = tot[bi].ent;
                let kc = kept_count(e, a.n);
                let hi = cum[bi] + s.ent;
                let mut r: Vec<u32> = Vec::new();
                while next[bi] < kc {
                    let rk = kept_rank(e, a.n, next[bi]);
                    if rk >= hi {
                        break;
                    }
                    r.push((rk - cum[bi]) as u32);
                    next[bi] += 1;
                }
                cum[bi] = hi;
                if !r.is_empty() {
                    n_req += r.len();
                    reqs[ui].push((k.big_keys[bi], r));
                }
            }
            Ok(())
        },
    )?;
    for bi in 0..nb {
        ensure!(
            next[bi] == kept_count(tot[bi].ent, a.n),
            "capped key {}: ranks not all placed",
            k.big_keys[bi]
        );
    }
    let units_req: Vec<usize> = (0..list.len()).filter(|i| !reqs[*i].is_empty()).collect();
    eprintln!(
        "stage 2: {} kept ranks in {} units ({:.0} s)",
        n_req,
        units_req.len(),
        t0.elapsed().as_secs_f64()
    );

    // Stage 3
    let p2 = |u: &Unit| a.out.join("p2").join(format!("{}.zst", u.name()));
    let todo3: Vec<usize> = units_req
        .iter()
        .copied()
        .filter(|i| !p2(&list[*i]).exists())
        .collect();
    let done = AtomicUsize::new(0);
    units::par_each(&todo3, a.jobs, |_, ui| {
        let u = &list[*ui];
        let v = stage3(&k, u, &reqs[*ui])?;
        write_zst_atomic(&p2(u), |w| put_postings(w, &v))?;
        let n = done.fetch_add(1, Ordering::SeqCst) + 1;
        if n.is_multiple_of(500) || n == todo3.len() {
            eprintln!(
                "stage 3: [{n}/{}] ({:.0} s)",
                todo3.len(),
                t0.elapsed().as_secs_f64()
            );
        }
        Ok(())
    })?;
    drop(reqs);

    // Stage 4a: buckets by key range (sizes from census occurrences).
    let mut bounds: Vec<u32> = vec![0];
    let mut acc = 0u64;
    for key in 0..k.total() {
        let est = if k.big[key] == NONE {
            k.occ[key]
        } else {
            3 * a.n
        };
        if acc + est > a.bucket_postings && acc > 0 {
            bounds.push(key as u32);
            acc = 0;
        }
        acc += est;
    }
    bounds.push(k.total() as u32);
    let nbk = bounds.len() - 1;
    let bdir = a.out.join("buckets");
    let bdone = bdir.join("DONE");
    if !bdone.exists() {
        let mut ws: Vec<zstd::Encoder<'static, BufWriter<File>>> = (0..nbk)
            .map(|i| {
                Ok(zstd::Encoder::new(
                    BufWriter::with_capacity(
                        1 << 18,
                        File::create(bdir.join(format!("{i:04}.zst")))?,
                    ),
                    1,
                )?)
            })
            .collect::<Result<_>>()?;
        let route =
            |ws: &mut Vec<zstd::Encoder<'static, BufWriter<File>>>, v: &[Posting]| -> Result<()> {
                for p in v {
                    let bi = bounds.partition_point(|b| *b <= p.0) - 1;
                    let mut r = [0u8; 12];
                    r[0..4].copy_from_slice(&p.0.to_le_bytes());
                    r[4..8].copy_from_slice(&p.1.to_le_bytes());
                    r[8..10].copy_from_slice(&p.2.to_le_bytes());
                    r[10..12].copy_from_slice(&p.3.to_le_bytes());
                    ws[bi].write_all(&r)?;
                }
                Ok(())
            };
        units::par_ordered(
            &list,
            a.jobs,
            16,
            |u| {
                let mut v = get_postings(&mut open_zst(&p1_paths(&a.out, u).0)?)?;
                if p2(u).exists() {
                    v.extend(get_postings(&mut open_zst(&p2(u))?)?);
                }
                Ok(v)
            },
            |i, v| {
                route(&mut ws, &v)?;
                if (i + 1).is_multiple_of(2000) {
                    eprintln!(
                        "stage 4a: [{}/{}] ({:.0} s)",
                        i + 1,
                        list.len(),
                        t0.elapsed().as_secs_f64()
                    );
                }
                Ok(())
            },
        )?;
        for w in ws {
            w.finish()?.flush()?;
        }
        fs::write(&bdone, format!("{nbk}\n"))?;
    }

    // Stage 4b: index files in key order.
    let mut idx = BufWriter::with_capacity(
        1 << 20,
        File::create(units::tmp_of(&a.out.join("keys.idx")))?,
    );
    let mut dat = BufWriter::with_capacity(
        1 << 20,
        File::create(units::tmp_of(&a.out.join("postings.dat")))?,
    );
    let mut off = 0u64;
    let mut check = [[0u64; 4]; 3]; // per type: keys, occ mismatch, first/last mismatch, without postings
    let mut bad: Vec<String> = Vec::new();
    let types = [
        k.n_tok() as usize,
        (k.n_tok() + k.n_comp()) as usize,
        k.total(),
    ];
    let mut stored_total = 0u64;
    for bi in 0..nbk {
        let mut b = Vec::new();
        zstd::Decoder::new(File::open(bdir.join(format!("{bi:04}.zst")))?)?.read_to_end(&mut b)?;
        let mut v: Vec<Posting> = b
            .as_chunks::<12>()
            .0
            .iter()
            .map(|c| {
                (
                    u32::from_le_bytes(c[0..4].try_into().unwrap()),
                    u32::from_le_bytes(c[4..8].try_into().unwrap()),
                    u16::from_le_bytes(c[8..10].try_into().unwrap()),
                    u16::from_le_bytes(c[10..12].try_into().unwrap()),
                )
            })
            .collect();
        drop(b);
        v.sort_unstable();
        let mut j = 0usize;
        for key in bounds[bi]..bounds[bi + 1] {
            let s = j;
            while j < v.len() && v[j].0 == key {
                j += 1;
            }
            let ps = &v[s..j];
            let ki = key as usize;
            let (st, capped) = if k.big[ki] == NONE {
                let mut st = BigSt {
                    first: ps.first().map(|p| p.1).unwrap_or(0),
                    last: ps.last().map(|p| p.1).unwrap_or(0),
                    ..Default::default()
                };
                let mut prev = 0u32;
                for p in ps {
                    st.occ += p.3 as u64;
                    st.ent += 1;
                    if p.1 != prev {
                        st.led += 1;
                        prev = p.1;
                    }
                }
                (st, false)
            } else {
                (tot[k.big[ki] as usize], true)
            };
            let ty = types.iter().position(|t| ki < *t).unwrap();
            check[ty][0] += 1;
            if st.occ != k.occ[ki] || st.first != k.first[ki] || st.last != k.last[ki] {
                if st.occ != k.occ[ki] {
                    check[ty][1] += 1;
                } else {
                    check[ty][2] += 1;
                }
                if bad.len() < 1000 {
                    bad.push(format!(
                        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                        ["token", "component", "shape"][ty],
                        hex::encode(key_id(&k, ki)),
                        st.occ,
                        k.occ[ki],
                        st.first,
                        k.first[ki],
                        st.last,
                        k.last[ki]
                    ));
                }
            }
            if ps.is_empty() {
                check[ty][3] += 1;
            }
            // block
            let mut raw = Vec::with_capacity(ps.len() * 4);
            let mut prev = 0u32;
            for p in ps {
                varint(&mut raw, (p.1 - prev) as u64);
                varint(&mut raw, p.2 as u64);
                varint(&mut raw, p.3 as u64);
                prev = p.1;
            }
            let mut flags = capped as u32;
            let blk = if raw.len() > 256 {
                flags |= 2;
                zstd::encode_all(&raw[..], 3)?
            } else {
                raw
            };
            dat.write_all(&blk)?;
            let mut row = [0u8; ROW];
            row[0..16].copy_from_slice(&key_id(&k, ki));
            row[16..24].copy_from_slice(&st.occ.to_le_bytes());
            row[24..32].copy_from_slice(&st.ent.to_le_bytes());
            row[32..36].copy_from_slice(&st.led.to_le_bytes());
            row[36..40].copy_from_slice(&st.first.to_le_bytes());
            row[40..44].copy_from_slice(&st.last.to_le_bytes());
            row[44..48].copy_from_slice(&(ps.len() as u32).to_le_bytes());
            row[48..52].copy_from_slice(&flags.to_le_bytes());
            row[52..60].copy_from_slice(&off.to_le_bytes());
            row[60..64].copy_from_slice(&(blk.len() as u32).to_le_bytes());
            idx.write_all(&row)?;
            off += blk.len() as u64;
            stored_total += ps.len() as u64;
        }
        ensure!(
            j == v.len(),
            "bucket {bi}: postings of keys outside its range"
        );
        if (bi + 1).is_multiple_of(10) || bi + 1 == nbk {
            eprintln!(
                "stage 4b: [{}/{nbk}] ({:.0} s)",
                bi + 1,
                t0.elapsed().as_secs_f64()
            );
        }
    }
    for (w, n) in [(idx, "keys.idx"), (dat, "postings.dat")] {
        let f = w.into_inner().map_err(|e| e.into_error())?;
        f.sync_all()?;
        fs::rename(units::tmp_of(&a.out.join(n)), a.out.join(n))?;
    }
    let mut t = String::from("token_id\tkind\tclass\ttoken\n");
    for r in &k.tok_rows {
        t.push_str(&format!("{}\t{}\t{}\t{}\n", r.0, r.1, r.2, r.3));
    }
    units::write_atomic(&a.out.join("tokens.tsv"), t.as_bytes())?;
    let mut c =
        String::from("type\tkeys\toccurrences_differ\tfirst_or_last_differ\twithout_postings\n");
    for (i, n) in ["token", "component", "shape"].iter().enumerate() {
        c.push_str(&format!(
            "{n}\t{}\t{}\t{}\t{}\n",
            check[i][0], check[i][1], check[i][2], check[i][3]
        ));
    }
    c.push_str("# differing keys (first 1000): type, id, occ, census occ, first, census first, last, census last\n");
    for l in &bad {
        c.push_str(l);
        c.push('\n');
    }
    units::write_atomic(&a.out.join("check-census.tsv"), c.as_bytes())?;
    let meta = serde_json::json!({
        "format": "xcc.locate/v1",
        "tokens": k.n_tok(),
        "components": k.n_comp(),
        "shapes": k.shape_ids.len(),
        "n": a.n,
        "cap": a.cap,
        "units": list.len(),
        "first_unit": list.first().map(|u| u.name()),
        "last_unit": list.last().map(|u| u.name()),
        "run": a.run,
        "census": a.census,
        "token_census": a.tokens,
        "stored_postings": stored_total,
        "postings_bytes": off,
        "ledger_tx": LEDGER_TX,
    });
    units::write_atomic(
        &a.out.join("meta.json"),
        serde_json::to_string_pretty(&meta)?.as_bytes(),
    )?;
    print!("{c}");
    if !a.keep_work {
        for d in ["p1", "p2", "buckets"] {
            fs::remove_dir_all(a.out.join(d))?;
        }
    }
    eprintln!(
        "locate: {stored_total} postings stored, {off} bytes, done in {:.0} s",
        t0.elapsed().as_secs_f64()
    );
    if check.iter().any(|c| c[1] + c[2] + c[3] > 0) {
        bail!("census check differs: see check-census.tsv");
    }
    Ok(())
}

fn key_id(k: &Keys, ki: usize) -> Id {
    let (t, c) = (k.n_tok() as usize, k.n_comp() as usize);
    if ki < t {
        k.tok_ids[ki]
    } else if ki < t + c {
        k.comp_ids[ki - t]
    } else {
        k.shape_ids[ki - t - c]
    }
}

// ---------- reading the index ----------

pub struct Index {
    idx: File,
    dat: File,
    /// key ranges per type: tokens, components, shapes
    ranges: [(u64, u64); 3],
    pub tokens: Vec<(String, String, String, String)>,
}

#[derive(Debug, Clone)]
pub struct KeyRow {
    pub id: Id,
    pub occ: u64,
    pub postings: u64,
    pub ledgers: u32,
    pub first: u32,
    pub last: u32,
    pub stored: u32,
    pub capped: bool,
    zstd: bool,
    off: u64,
    len: u32,
}

impl Index {
    pub fn open(dir: &Path) -> Result<Index> {
        let m: serde_json::Value = serde_json::from_slice(
            &fs::read(dir.join("meta.json")).with_context(|| dir.display().to_string())?,
        )?;
        let t = m["tokens"].as_u64().context("meta tokens")?;
        let c = m["components"].as_u64().context("meta components")?;
        let s = m["shapes"].as_u64().context("meta shapes")?;
        let mut tokens = Vec::new();
        for l in fs::read_to_string(dir.join("tokens.tsv"))?.lines().skip(1) {
            let c: Vec<&str> = l.splitn(4, '\t').collect();
            ensure!(c.len() == 4, "tokens.tsv: short line");
            tokens.push((c[0].into(), c[1].into(), c[2].into(), c[3].into()));
        }
        Ok(Index {
            idx: File::open(dir.join("keys.idx"))?,
            dat: File::open(dir.join("postings.dat"))?,
            ranges: [(0, t), (t, t + c), (t + c, t + c + s)],
            tokens,
        })
    }

    fn row(&mut self, i: u64) -> Result<KeyRow> {
        let mut b = [0u8; ROW];
        self.idx.seek(SeekFrom::Start(i * ROW as u64))?;
        self.idx.read_exact(&mut b)?;
        let u = |a: usize| u32::from_le_bytes(b[a..a + 4].try_into().unwrap());
        let q = |a: usize| u64::from_le_bytes(b[a..a + 8].try_into().unwrap());
        Ok(KeyRow {
            id: b[0..16].try_into().unwrap(),
            occ: q(16),
            postings: q(24),
            ledgers: u(32),
            first: u(36),
            last: u(40),
            stored: u(44),
            capped: u(48) & 1 != 0,
            zstd: u(48) & 2 != 0,
            off: q(52),
            len: u(60),
        })
    }

    /// The row of `id` in type `ty` (0 tokens, 1 components, 2 shapes).
    pub fn find(&mut self, ty: usize, id: &Id) -> Result<Option<KeyRow>> {
        let (mut lo, mut hi) = self.ranges[ty];
        while lo < hi {
            let mid = (lo + hi) / 2;
            let r = self.row(mid)?;
            match r.id.cmp(id) {
                std::cmp::Ordering::Equal => return Ok(Some(r)),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        Ok(None)
    }

    /// Stored postings of a key: (seq, tx, multiplicity).
    pub fn postings(&mut self, r: &KeyRow) -> Result<Vec<(u32, u16, u16)>> {
        let mut b = vec![0u8; r.len as usize];
        self.dat.seek(SeekFrom::Start(r.off))?;
        self.dat.read_exact(&mut b)?;
        if r.zstd {
            b = zstd::decode_all(&b[..])?;
        }
        let mut out = Vec::with_capacity(r.stored as usize);
        let (mut pos, mut seq) = (0usize, 0u32);
        while pos < b.len() {
            seq += unvarint(&b, &mut pos)? as u32;
            let t = unvarint(&b, &mut pos)? as u16;
            let m = unvarint(&b, &mut pos)? as u16;
            out.push((seq, t, m));
        }
        ensure!(out.len() == r.stored as usize, "block length");
        Ok(out)
    }
}

fn parse_era(s: &str) -> Result<(u32, u32)> {
    let (a, b) = s.split_once("..").context("--era a..b")?;
    Ok((
        if a.is_empty() { 0 } else { a.parse()? },
        if b.is_empty() { u32::MAX } else { b.parse()? },
    ))
}

pub fn query(a: QueryArgs) -> Result<()> {
    let mut ix = Index::open(&a.index)?;
    let (lo, hi) = match &a.era {
        Some(e) => parse_era(e)?,
        None => (0, u32::MAX),
    };
    // (type, id, label)
    let mut keys: Vec<(usize, Id, String)> = Vec::new();
    if let Some(t) = &a.token {
        let id = if t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit()) {
            units::unhex16(t)?
        } else {
            token_id(t)
        };
        let label = ix
            .tokens
            .iter()
            .find(|r| r.0 == hex::encode(id))
            .map(|r| r.3.clone())
            .unwrap_or_else(|| t.clone());
        keys.push((0, id, label));
    }
    if let Some(c) = &a.component {
        keys.push((1, units::unhex16(c)?, String::from("-")));
    }
    if let Some(s) = &a.shape {
        keys.push((2, units::unhex16(s)?, String::from("-")));
    }
    if let Some(c) = &a.class {
        let (kind, class) = c.split_once('|').context("--class K|class")?;
        for r in &ix.tokens {
            if r.1 == kind && r.2 == class {
                keys.push((0, units::unhex16(&r.0)?, r.3.clone()));
            }
        }
        ensure!(keys.iter().any(|k| k.0 == 0), "no token in class {c}");
    }
    ensure!(
        !keys.is_empty(),
        "give --token, --component, --shape or --class"
    );
    let out = std::io::stdout();
    let mut w = BufWriter::new(out.lock());
    let tys = ["token", "component", "shape"];
    if a.summary {
        writeln!(w, "type\tid\toccurrences\tpostings\tledgers\tfirst_ledger\tlast_ledger\tstored\tcapped\tlabel")?;
    } else {
        writeln!(w, "type\tid\tseq\ttx\tmult\tlabel")?;
    }
    for (ty, id, label) in keys {
        let Some(r) = ix.find(ty, &id)? else {
            eprintln!("{} {} not in the index", tys[ty], hex::encode(id));
            continue;
        };
        if a.summary {
            writeln!(
                w,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{label}",
                tys[ty],
                hex::encode(id),
                r.occ,
                r.postings,
                r.ledgers,
                r.first,
                r.last,
                r.stored,
                r.capped
            )?;
            continue;
        }
        eprintln!(
            "# {} {}: occurrences {}, postings {}, ledgers {}, ledgers {}..{}, stored {}{}",
            tys[ty],
            hex::encode(id),
            r.occ,
            r.postings,
            r.ledgers,
            r.first,
            r.last,
            r.stored,
            if r.capped {
                " (capped: first, evenly spaced, last)"
            } else {
                ""
            }
        );
        let mut n = 0usize;
        for (s, t, m) in ix.postings(&r)? {
            if s < lo || s > hi {
                continue;
            }
            if a.limit > 0 && n >= a.limit {
                break;
            }
            let tx = if t == LEDGER_TX {
                "L".to_string()
            } else {
                t.to_string()
            };
            writeln!(
                w,
                "{}\t{}\t{s}\t{tx}\t{m}\t{label}",
                tys[ty],
                hex::encode(id)
            )?;
            n += 1;
        }
    }
    Ok(())
}

// ---------- check ----------

/// Compare the index with the token census (sampled tokens) and, given `--pilot`, with the pilot
/// index on its kept ledgers (uncapped tokens: equal posting sets; capped: stored postings found).
pub fn check(a: CheckArgs) -> Result<()> {
    let mut ix = Index::open(&a.index)?;
    // census rows: id -> (text, occ, first, last)
    let mut cen: Vec<(Id, String, u64, u32, u32)> = Vec::new();
    units::each_tsv_zst(&a.tokens, |c| {
        cen.push((
            units::unhex16(c[0])?,
            c[3].into(),
            c[5].parse()?,
            c[6].parse()?,
            c[7].parse()?,
        ));
        Ok(())
    })?;
    // sample: 20 rarest, 20 most common, the rest evenly spaced over the id order (deterministic)
    let mut by_occ: Vec<usize> = (0..cen.len()).collect();
    by_occ.sort_by(|x, y| (cen[*x].2, &cen[*x].0).cmp(&(cen[*y].2, &cen[*y].0)));
    let mut pick: Vec<usize> = by_occ[..20.min(cen.len())].to_vec();
    pick.extend(by_occ[cen.len().saturating_sub(20)..].iter().copied());
    let rest = a.sample.saturating_sub(pick.len()).max(1);
    let mut by_id: Vec<usize> = (0..cen.len()).collect();
    by_id.sort_by(|x, y| cen[*x].0.cmp(&cen[*y].0));
    for i in 0..rest {
        pick.push(by_id[i * by_id.len() / rest]);
    }
    pick.sort_unstable();
    pick.dedup();
    let mut rows: Vec<(usize, KeyRow, Vec<(u32, u16, u16)>)> = Vec::new();
    for &i in &pick {
        let r = ix
            .find(0, &cen[i].0)?
            .with_context(|| format!("token {} missing", cen[i].1))?;
        let p = ix.postings(&r)?;
        rows.push((i, r, p));
    }
    // pilot: per sampled token, postings on the kept ledgers
    let mut pilot: Option<Vec<HashMap<(u32, u16), u16>>> = None;
    let mut pilot_n: Vec<u64> = vec![0; rows.len()];
    let mut kept: Vec<u32> = Vec::new();
    let (elo, ehi) = match &a.era {
        Some(e) => parse_era(e)?,
        None => (0, u32::MAX),
    };
    if let Some(pd) = &a.pilot {
        let tix: HashMap<&str, usize> = rows
            .iter()
            .enumerate()
            .map(|(j, r)| (cen[r.0].1.as_str(), j))
            .collect();
        let mut comp_t: HashMap<String, Vec<usize>> = HashMap::new();
        units::each_tsv_zst(&pd.join("components.tsv.zst"), |c| {
            let mut v: Vec<usize> = c[2]
                .split(' ')
                .filter_map(|t| tix.get(t).copied())
                .collect();
            v.sort_unstable();
            v.dedup();
            if !v.is_empty() {
                comp_t.insert(c[0].to_string(), v);
            }
            Ok(())
        })?;
        // Only the stored postings of capped tokens are looked up; uncapped ones are collected whole.
        let want: Vec<HashMap<(u32, u16), u16>> = rows
            .iter()
            .map(|r| {
                if r.1.capped {
                    r.2.iter().map(|p| ((p.0, p.1), p.2)).collect()
                } else {
                    HashMap::new()
                }
            })
            .collect();
        let mut got: Vec<HashMap<(u32, u16), u16>> = vec![HashMap::new(); rows.len()];
        let add = |j: usize,
                   s: u32,
                   t: u16,
                   got: &mut Vec<HashMap<(u32, u16), u16>>,
                   pn: &mut Vec<u64>| {
            pn[j] += 1;
            if !rows[j].1.capped || want[j].contains_key(&(s, t)) {
                *got[j].entry((s, t)).or_default() += 1;
            }
        };
        units::each_tsv_zst(&pd.join("ledgers.tsv.zst"), |c| {
            let s: u32 = c[0].parse()?;
            if s < elo || s > ehi {
                return Ok(());
            }
            kept.push(s);
            if let Some(v) = comp_t.get(c[6]) {
                for &j in v {
                    add(j, s, LEDGER_TX, &mut got, &mut pilot_n);
                }
            }
            Ok(())
        })?;
        units::each_tsv_zst(&pd.join("tx_shapes.tsv.zst"), |c| {
            let s: u32 = c[0].parse()?;
            if s < elo || s > ehi {
                return Ok(());
            }
            let t: u16 = c[1].parse()?;
            let mut seen: Vec<usize> = Vec::new();
            let mut cs: Vec<&str> = c[3]
                .split(',')
                .filter_map(|x| x.split_once(':').map(|y| y.1.split('*').next().unwrap()))
                .collect();
            cs.sort_unstable();
            cs.dedup();
            for cid in cs {
                if let Some(v) = comp_t.get(cid) {
                    seen.extend(v.iter().copied());
                }
            }
            seen.sort_unstable();
            let mut i = 0;
            while i < seen.len() {
                let j = seen[i];
                let mut m = 0;
                while i < seen.len() && seen[i] == j {
                    m += 1;
                    i += 1;
                }
                pilot_n[j] += 1;
                if !rows[j].1.capped || want[j].contains_key(&(s, t)) {
                    got[j].insert((s, t), m);
                }
            }
            Ok(())
        })?;
        kept.sort_unstable();
        pilot = Some(got);
    }
    let in_kept = |s: u32| kept.binary_search(&s).is_ok();
    let mut out = String::from("token\tcensus_occ\tindex_occ\tcensus_first\tindex_first\tcensus_last\tindex_last\tcapped\tpostings\tstored\tcensus_ok\tpilot_postings\tindex_kept_postings\tpilot_ok\tpilot_note\n");
    let (mut cen_ok, mut pil_ok, mut pil_n) = (0, 0, 0);
    for (j, (i, r, ps)) in rows.iter().enumerate() {
        let c = &cen[*i];
        let ok = r.occ == c.2 && r.first == c.3 && r.last == c.4;
        cen_ok += ok as usize;
        let (mut pn, mut kn, mut pok, mut note) = (
            String::from("-"),
            String::from("-"),
            String::from("-"),
            String::new(),
        );
        if let Some(got) = &pilot {
            pil_n += 1;
            let mine: HashMap<(u32, u16), u16> = ps
                .iter()
                .filter(|p| in_kept(p.0))
                .map(|p| ((p.0, p.1), p.2))
                .collect();
            pn = pilot_n[j].to_string();
            kn = mine.len().to_string();
            let good = if r.capped {
                let miss = mine
                    .iter()
                    .filter(|(k, m)| got[j].get(k) != Some(m))
                    .count();
                note = format!(
                    "capped: {} of {} stored kept postings found in the pilot",
                    mine.len() - miss,
                    mine.len()
                );
                miss == 0
            } else {
                let miss = mine
                    .iter()
                    .filter(|(k, m)| got[j].get(k) != Some(m))
                    .count();
                let extra = got[j].keys().filter(|k| !mine.contains_key(k)).count();
                note = format!("missing_in_pilot {miss}, extra_in_pilot {extra}");
                miss == 0 && extra == 0
            };
            pil_ok += good as usize;
            pok = good.to_string();
        }
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{ok}\t{pn}\t{kn}\t{pok}\t{note}\n",
            c.1, c.2, r.occ, c.3, r.first, c.4, r.last, r.capped, r.postings, r.stored
        ));
    }
    units::write_atomic(&a.out, out.as_bytes())?;
    println!(
        "sampled tokens {}: census equal {cen_ok}; pilot checked {pil_n}, equal {pil_ok}",
        rows.len()
    );
    if cen_ok != rows.len() || pil_ok != pil_n {
        bail!("differences: see {}", a.out.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_ranks_are_first_spaced_last() {
        // small keys keep everything
        assert_eq!(kept_count(5, 3), 5);
        assert_eq!(
            (0..5).map(|i| kept_rank(5, 3, i)).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
        let (e, n) = (100u64, 3u64);
        let r: Vec<u64> = (0..kept_count(e, n)).map(|i| kept_rank(e, n, i)).collect();
        assert_eq!(r.len(), 9);
        assert_eq!(&r[..3], &[0, 1, 2]);
        assert_eq!(&r[6..], &[97, 98, 99]);
        assert!(r.windows(2).all(|w| w[0] < w[1]), "{r:?}");
        assert!(r[3..6].iter().all(|x| (3..97).contains(x)));
    }

    #[test]
    fn varint_blocks_round_trip() {
        let mut b = Vec::new();
        for x in [0u64, 1, 127, 128, 300, u32::MAX as u64, LEDGER_TX as u64] {
            varint(&mut b, x);
        }
        let mut pos = 0;
        let got: Vec<u64> = (0..7).map(|_| unvarint(&b, &mut pos).unwrap()).collect();
        assert_eq!(
            got,
            vec![0, 1, 127, 128, 300, u32::MAX as u64, LEDGER_TX as u64]
        );
        assert!(unvarint(&b, &mut pos).is_err());
    }
}
