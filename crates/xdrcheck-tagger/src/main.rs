//! xdrcheck-tagger: one streaming pass over ledger bytes that tags the dangerous values the shape
//! grammar does not record (wide integers, ids above 2^53 / 2^63, bytes in text fields, weights,
//! bounds, nesting depth, map key order, failed transactions with events, token-like events of
//! contracts that are not Stellar Asset Contracts, zero-amount pool legs and path hops, changes to
//! accounts an operation does not name).
//!
//! `run` reads a lake-layout directory (`<partition>/<object>.xdr.zst` and an `index.tsv` of
//! `seq, path, size`), one output set per lake partition, written atomically: a partition whose
//! summary exists is skipped (resume). `merge` joins the partitions in ledger order into
//! `tags.tsv.zst`, `tag-summary.tsv`, `sac-contracts.tsv` and `depth-hist.tsv`.
//!
//! Rows (`tags.tsv.zst`): seq, tx (apply index, 0-based), tx hash, tag, field path, value. One row
//! per (transaction, tag, path); a value `v;n=k` means k hits in the transaction, v the largest.
//! Rows are capped per (tag, path) and partition (`--row-cap`); the summary counts are exact.
#![allow(clippy::type_complexity)]
mod tag;

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{bail, ensure, Context, Result};
use clap::Parser;
use stellar_xdr::{LedgerCloseMetaBatch, Limits, ReadXdr};

const PUBNET: &str = "Public Global Stellar Network ; September 2015";
const CANDIDATE: &str = "balance_candidate";

#[derive(Parser)]
#[command(
    name = "xdrcheck-tagger",
    about = "Tag dangerous values in ledger bytes"
)]
enum Cli {
    /// Tag every ledger of a lake-layout directory, one output set per partition
    Run(RunArgs),
    /// Join the partition outputs into the final files
    Merge(MergeArgs),
}

#[derive(clap::Args)]
struct RunArgs {
    /// Lake-layout directory (`<partition>/<object>.xdr.zst`)
    #[arg(long)]
    root: PathBuf,
    /// `seq<TAB>path<TAB>size` of the ledgers (default: ROOT/index.tsv)
    #[arg(long)]
    index: Vec<PathBuf>,
    /// Output directory
    #[arg(long)]
    out: PathBuf,
    /// Partitions worked at once
    #[arg(long, default_value_t = 8)]
    jobs: usize,
    /// Only ledgers in a..b (inclusive)
    #[arg(long)]
    range: Option<String>,
    /// Rows written per (tag, path) and partition
    #[arg(long, default_value_t = 5000)]
    row_cap: u64,
    /// Network passphrase (SAC ids, transaction hashes)
    #[arg(long, default_value = PUBNET)]
    passphrase: String,
    /// Check each object's size against the index
    #[arg(long, default_value_t = true)]
    check_size: bool,
}

#[derive(clap::Args)]
struct MergeArgs {
    /// Output directory of `run` (one or more; partitions are joined in ledger order)
    #[arg(long)]
    out: Vec<PathBuf>,
    /// Directory for the merged files (default: the first --out)
    #[arg(long)]
    to: Option<PathBuf>,
}

fn main() -> ExitCode {
    let r = match Cli::parse() {
        Cli::Run(a) => run(a),
        Cli::Merge(a) => merge(a),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xdrcheck-tagger: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn tmp_of(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

fn write_atomic(p: &Path, b: &[u8]) -> Result<()> {
    fs::write(tmp_of(p), b)?;
    fs::rename(tmp_of(p), p)?;
    Ok(())
}

/// Summary of one (tag, path).
#[derive(Clone, Default)]
struct Sum {
    hits: u64,
    txs: u64,
    ledgers: u64,
    first: u32,
    last: u32,
    last_seq: u32,
    max: (u32, String),
    max_at: String,
    first_at: String,
    rows: u64,
}

impl Sum {
    fn line(&self, tag: &str, path: &str) -> String {
        format!(
            "{tag}\t{path}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.hits,
            self.txs,
            self.ledgers,
            self.first,
            self.last,
            self.max_at,
            self.first_at,
            self.rows
        )
    }
    fn parse(c: &[&str]) -> Result<(String, String, Sum)> {
        ensure!(c.len() == 10, "summary line with {} columns", c.len());
        Ok((
            c[0].into(),
            c[1].into(),
            Sum {
                hits: c[2].parse()?,
                txs: c[3].parse()?,
                ledgers: c[4].parse()?,
                first: c[5].parse()?,
                last: c[6].parse()?,
                last_seq: 0,
                max: (0, String::new()),
                max_at: c[7].into(),
                first_at: c[8].into(),
                rows: c[9].parse()?,
            },
        ))
    }
}

const SUM_HEADER: &str = "tag\tpath\thits\ttxs\tledgers\tfirst_ledger\tlast_ledger\tmax_example\tfirst_example\trows_written";

fn clean(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

fn parse_range(s: &str) -> Result<(u32, u32)> {
    let (a, b) = s.split_once("..").context("range a..b")?;
    Ok((
        if a.is_empty() { 0 } else { a.parse()? },
        if b.is_empty() { u32::MAX } else { b.parse()? },
    ))
}

fn run(a: RunArgs) -> Result<()> {
    let t0 = Instant::now();
    let parts_dir = a.out.join("parts");
    fs::create_dir_all(&parts_dir)?;
    let idx = if a.index.is_empty() {
        vec![a.root.join("index.tsv")]
    } else {
        a.index.clone()
    };
    let (lo, hi) = match &a.range {
        Some(r) => parse_range(r)?,
        None => (0, u32::MAX),
    };
    let mut parts: BTreeMap<String, Vec<(u32, String, u64)>> = BTreeMap::new();
    for f in &idx {
        for l in BufReader::new(File::open(f).with_context(|| f.display().to_string())?).lines() {
            let l = l?;
            let c: Vec<&str> = l.split('\t').collect();
            if c.len() < 3 || c[0] == "seq" {
                continue;
            }
            let seq: u32 = c[0].parse()?;
            if seq < lo || seq > hi {
                continue;
            }
            let part = c[1].split('/').next().unwrap().to_string();
            parts
                .entry(part)
                .or_default()
                .push((seq, c[1].to_string(), c[2].parse()?));
        }
    }
    let mut todo: Vec<(String, Vec<(u32, String, u64)>)> = parts
        .into_iter()
        .filter(|(p, _)| !parts_dir.join(format!("{p}.sum.tsv")).exists())
        .collect();
    for (_, v) in todo.iter_mut() {
        v.sort();
        v.dedup_by_key(|x| x.0);
    }
    // largest first, for an even finish
    todo.sort_by_key(|(_, v)| std::cmp::Reverse(v.iter().map(|x| x.2).sum::<u64>()));
    let total: usize = todo.iter().map(|x| x.1.len()).sum();
    eprintln!("tagger: {} partitions, {} ledgers to do", todo.len(), total);
    let net = tag::Net::new(&a.passphrase);
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let errs: Mutex<Vec<String>> = Mutex::new(Vec::new());
    std::thread::scope(|sc| {
        for _ in 0..a.jobs.max(1) {
            std::thread::Builder::new()
                .stack_size(512 << 20)
                .spawn_scoped(sc, || loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    if i >= todo.len() {
                        return;
                    }
                    let (p, ls) = &todo[i];
                    if let Err(e) = partition(&a, &net, &parts_dir, p, ls) {
                        errs.lock().unwrap().push(format!("{p}: {e:#}"));
                    }
                    let n = done.fetch_add(ls.len(), Ordering::SeqCst) + ls.len();
                    eprintln!(
                        "[{}/{}] {p} ({} ledgers) {:.0} s",
                        n,
                        total,
                        ls.len(),
                        t0.elapsed().as_secs_f64()
                    );
                })
                .unwrap();
        }
    });
    let errs = errs.into_inner().unwrap();
    if !errs.is_empty() {
        bail!("{} partitions failed: {}", errs.len(), errs.join("; "));
    }
    eprintln!("tagger: done in {:.0} s", t0.elapsed().as_secs_f64());
    Ok(())
}

fn partition(
    a: &RunArgs,
    net: &tag::Net,
    dir: &Path,
    p: &str,
    ledgers: &[(u32, String, u64)],
) -> Result<()> {
    let rows_p = dir.join(format!("{p}.rows.tsv.zst"));
    let mut rows = zstd::Encoder::new(
        BufWriter::with_capacity(1 << 20, File::create(tmp_of(&rows_p))?),
        3,
    )?;
    let mut sums: BTreeMap<(String, String), Sum> = BTreeMap::new();
    let mut t = tag::Tagger::new(net);
    let mut errs = String::new();
    let mut n_tx = 0u64;
    let limits = Limits {
        depth: 4000,
        len: 1 << 30,
    };
    for (seq, path, size) in ledgers {
        let raw = fs::read(a.root.join(path)).with_context(|| format!("{seq}: {path}"))?;
        if a.check_size && raw.len() as u64 != *size {
            errs.push_str(&format!("{seq}\tsize\t{} != {size}\n", raw.len()));
            continue;
        }
        let mut dec = Vec::new();
        zstd::Decoder::new(&raw[..])?.read_to_end(&mut dec)?;
        let batch = match LedgerCloseMetaBatch::from_xdr(&dec, limits.clone()) {
            Ok(b) => b,
            Err(e) => {
                errs.push_str(&format!("{seq}\tdecode\t{e}\n"));
                continue;
            }
        };
        for lcm in batch.ledger_close_metas.iter() {
            let (s, txs) = match tag::ledger(&mut t, lcm) {
                Ok(x) => x,
                Err(e) => {
                    errs.push_str(&format!("{seq}\ttag\t{}\n", clean(&format!("{e:#}"))));
                    continue;
                }
            };
            for tx in txs {
                n_tx += 1;
                // collapse per (tag, path): count, largest value
                let mut m: BTreeMap<(String, String), (u64, tag::Hit)> = BTreeMap::new();
                for h in tx.hits {
                    let k = (h.tag.clone(), h.path.clone());
                    match m.get_mut(&k) {
                        Some(e) => {
                            e.0 += 1;
                            if h.mag > e.1.mag {
                                e.1 = h;
                            }
                        }
                        None => {
                            m.insert(k, (1, h));
                        }
                    }
                }
                for ((tg, pa), (n, h)) in m {
                    let v = clean(&h.value);
                    let val = if n > 1 {
                        format!("{v};n={n}")
                    } else {
                        v.clone()
                    };
                    let at = format!("{s}:{}={}", tx.tx, v);
                    let cand = tg == CANDIDATE;
                    let e = sums.entry((tg.clone(), pa.clone())).or_insert_with(|| Sum {
                        first: s,
                        first_at: at.clone(),
                        ..Default::default()
                    });
                    e.hits += n;
                    e.txs += 1;
                    if e.last_seq != s {
                        e.ledgers += 1;
                        e.last_seq = s;
                    }
                    e.last = s;
                    if e.max_at.is_empty() || h.mag > e.max {
                        e.max = h.mag.clone();
                        e.max_at = at;
                    }
                    if cand || e.rows < row_cap(a.row_cap, &tg, &pa) {
                        e.rows += 1;
                        writeln!(rows, "{s}\t{}\t{}\t{tg}\t{pa}\t{val}", tx.tx, tx.hash)?;
                    }
                }
            }
        }
    }
    let f = rows.finish()?.into_inner().map_err(|e| e.into_error())?;
    f.sync_all()?;
    drop(f);
    fs::rename(tmp_of(&rows_p), &rows_p)?;
    let mut ev = String::new();
    for (c, asset) in &t.ev.sac {
        ev.push_str(&format!("sac\t{c}\t{}\n", clean(asset)));
    }
    for ((k, d), n) in &t.ev.depth {
        ev.push_str(&format!("depth\t{k}\t{d}\t{n}\n"));
    }
    ev.push_str(&format!("txs\t{n_tx}\t{}\n", ledgers.len()));
    write_atomic(&dir.join(format!("{p}.ev.tsv")), ev.as_bytes())?;
    write_atomic(&dir.join(format!("{p}.err.tsv")), errs.as_bytes())?;
    let mut s = format!("{SUM_HEADER}\n");
    for ((tg, pa), e) in &sums {
        if tg == CANDIDATE {
            continue;
        }
        s.push_str(&e.line(tg, pa));
        s.push('\n');
    }
    write_atomic(&dir.join(format!("{p}.sum.tsv")), s.as_bytes())?;
    Ok(())
}

/// Rows per (tag, path) and partition: large int64 values in ledger entries (trustline balances,
/// offers, pools) are common, so only a few examples are written; the summary stays exact.
fn row_cap(cap: u64, tag: &str, path: &str) -> u64 {
    if tag == "i64>=2^62" && path.starts_with("entry.") {
        cap.min(20)
    } else {
        cap
    }
}

/// First ledger of a partition name `XXXXXXXX--a-b`.
fn part_first(name: &str) -> u32 {
    name.split("--")
        .nth(1)
        .and_then(|r| r.split('-').next())
        .and_then(|x| x.parse().ok())
        .unwrap_or(0)
}

fn merge(a: MergeArgs) -> Result<()> {
    let to = a.to.clone().unwrap_or_else(|| a.out[0].clone());
    fs::create_dir_all(&to)?;
    // partitions in ledger order
    let mut parts: Vec<(u32, PathBuf, String)> = Vec::new();
    for o in &a.out {
        for e in fs::read_dir(o.join("parts"))? {
            let n = e?.file_name().to_string_lossy().to_string();
            if let Some(p) = n.strip_suffix(".sum.tsv") {
                parts.push((part_first(p), o.join("parts"), p.to_string()));
            }
        }
    }
    parts.sort();
    for w in parts.windows(2) {
        ensure!(
            w[0].0 != w[1].0 || w[0].2 != w[1].2,
            "partition {} twice",
            w[0].2
        );
    }
    // SAC set and depth histogram
    let mut sac: BTreeMap<String, String> = BTreeMap::new();
    let mut depth: BTreeMap<(String, u32), u64> = BTreeMap::new();
    let (mut txs, mut ledgers) = (0u64, 0u64);
    let mut errs = String::new();
    for (_, d, p) in &parts {
        for l in fs::read_to_string(d.join(format!("{p}.ev.tsv")))?.lines() {
            let c: Vec<&str> = l.split('\t').collect();
            match c[0] {
                "sac" => {
                    let e = sac.entry(c[1].into()).or_insert_with(|| c[2].into());
                    if e == "?" {
                        *e = c[2].into();
                    }
                }
                "depth" => {
                    *depth.entry((c[1].into(), c[2].parse()?)).or_default() +=
                        c[3].parse::<u64>()?
                }
                "txs" => {
                    txs += c[1].parse::<u64>()?;
                    ledgers += c[2].parse::<u64>()?;
                }
                _ => {}
            }
        }
        for l in fs::read_to_string(d.join(format!("{p}.err.tsv")))?.lines() {
            errs.push_str(&format!("{p}\t{l}\n"));
        }
    }
    // rows, with the balance candidates decided
    let out_p = to.join("tags.tsv.zst");
    let mut w = zstd::Encoder::new(
        BufWriter::with_capacity(1 << 20, File::create(tmp_of(&out_p))?),
        9,
    )?;
    writeln!(w, "seq\ttx\ttx_hash\ttag\tpath\tvalue")?;
    let mut cand: BTreeMap<(String, String), Sum> = BTreeMap::new();
    for (_, d, p) in &parts {
        let r = BufReader::new(zstd::Decoder::new(File::open(
            d.join(format!("{p}.rows.tsv.zst")),
        )?)?);
        for l in r.lines() {
            let l = l?;
            let c: Vec<&str> = l.splitn(6, '\t').collect();
            ensure!(c.len() == 6, "{p}: short row");
            if c[3] != CANDIDATE {
                writeln!(w, "{l}")?;
                continue;
            }
            let con = c[5]
                .strip_prefix("contract=")
                .and_then(|x| x.split(';').next())
                .unwrap_or("-");
            let tg = if sac.contains_key(con) {
                "sac_balance>=2^63"
            } else {
                "custom_balance>=2^63"
            };
            writeln!(w, "{}\t{}\t{}\t{tg}\t{}\t{}", c[0], c[1], c[2], c[4], c[5])?;
            let seq: u32 = c[0].parse()?;
            let v = c[5];
            let n: u64 = v
                .rsplit_once(";n=")
                .and_then(|x| x.1.parse().ok())
                .unwrap_or(1);
            let digits = v
                .split('=')
                .nth(2)
                .unwrap_or("")
                .trim_start_matches('-')
                .split(';')
                .next()
                .unwrap_or("")
                .to_string();
            let mag = (digits.len() as u32, digits);
            let at = format!("{seq}:{}={v}", c[1]);
            let e = cand.entry((tg.into(), c[4].into())).or_insert_with(|| Sum {
                first: seq,
                first_at: at.clone(),
                ..Default::default()
            });
            e.hits += n;
            e.txs += 1;
            e.rows += 1;
            if e.last_seq != seq {
                e.ledgers += 1;
                e.last_seq = seq;
            }
            e.last = seq;
            if e.max_at.is_empty() || mag > e.max {
                e.max = mag;
                e.max_at = at;
            }
        }
    }
    let f = w.finish()?.into_inner().map_err(|e| e.into_error())?;
    f.sync_all()?;
    drop(f);
    fs::rename(tmp_of(&out_p), &out_p)?;
    // summary
    let mut sums: BTreeMap<(String, String), Sum> = BTreeMap::new();
    for (_, d, p) in &parts {
        for (i, l) in fs::read_to_string(d.join(format!("{p}.sum.tsv")))?
            .lines()
            .enumerate()
        {
            if i == 0 {
                continue;
            }
            let c: Vec<&str> = l.split('\t').collect();
            let (tg, pa, s) = Sum::parse(&c).with_context(|| format!("{p}.sum.tsv"))?;
            match sums.get_mut(&(tg.clone(), pa.clone())) {
                None => {
                    sums.insert((tg, pa), s);
                }
                Some(e) => {
                    e.hits += s.hits;
                    e.txs += s.txs;
                    e.ledgers += s.ledgers;
                    e.last = s.last;
                    e.rows += s.rows;
                    if better(&s.max_at, &e.max_at) {
                        e.max_at = s.max_at;
                    }
                }
            }
        }
    }
    sums.extend(cand);
    let mut s = format!("{SUM_HEADER}\n");
    for ((tg, pa), e) in &sums {
        s.push_str(&e.line(tg, pa));
        s.push('\n');
    }
    write_atomic(&to.join("tag-summary.tsv"), s.as_bytes())?;
    let mut t = String::from("contract\tasset\n");
    for (c, x) in &sac {
        t.push_str(&format!("{c}\t{x}\n"));
    }
    write_atomic(&to.join("sac-contracts.tsv"), t.as_bytes())?;
    let mut t = String::from("kind\tdepth\tcount\n");
    for ((k, d), n) in &depth {
        t.push_str(&format!("{k}\t{d}\t{n}\n"));
    }
    write_atomic(&to.join("depth-hist.tsv"), t.as_bytes())?;
    write_atomic(&to.join("errors.tsv"), errs.as_bytes())?;
    let mut by_tag: HashMap<String, u64> = HashMap::new();
    for ((tg, _), e) in &sums {
        *by_tag.entry(tg.clone()).or_default() += e.hits;
    }
    eprintln!(
        "merge: {} partitions, {ledgers} ledgers, {txs} transactions, {} (tag, path) rows, {} SACs, {} error lines",
        parts.len(),
        sums.len(),
        sac.len(),
        errs.lines().count()
    );
    Ok(())
}

/// Whether example `a` (`seq:tx=value`) holds a larger value than `b` (numeric magnitude first).
fn better(a: &str, b: &str) -> bool {
    let num = |s: &str| -> (usize, String) {
        let v = s.split_once('=').map(|x| x.1).unwrap_or("");
        let v = v.rsplit('=').next().unwrap_or(v);
        let d: String = v
            .trim_start_matches('-')
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        (d.len(), d)
    };
    num(a) > num(b)
}
