//! `xdrcheck-corpus scan run`: walk lake ledgers into shape records (pilot of the mainnet scan), and
//! `xdrcheck-corpus scan <tool>`: the offline tools over a run's files (`report.rs`).
//!
//! **Input.** A plan (`--plan TSV` with a `seq` column and an optional `set` column filtered by
//! `--sets`, or `--seqs FILE`, one sequence per line), read from local packs (`--packs DIR`), a
//! directory laid out like the lake (`--lake DIR`), or the public lake over HTTPS (`--http URL`).
//!
//! **Per ledger.** Fetch; bounded zstd (`--max-object-bytes`); the oracle splits the batch, decodes
//! and re-encodes byte-exactly (`split_batch`); the typed decode gives the join of envelopes and
//! results (transaction hashes recomputed under the passphrase), the header hash and the two
//! set hashes; the definitions walk gives the tokens ([`shape`]). A failure at any stage is a
//! refusal: kept with its bytes, classified ([`classify`]), and the run goes on.
//!
//! **Output.** `--out DIR`: `run.json`, then one directory per 64,000-ledger lake partition
//! ([`store`]); `SHA256SUMS` over the manifests at the end. Partitions run newest first, `--jobs` at
//! a time; a partition in progress keeps a journal and a rerun resumes it.
#![allow(clippy::type_complexity, clippy::large_enum_variant)]

pub mod census;
pub mod chain;
pub mod cover;
pub mod entries;
pub mod locate;
pub mod ranges;
pub mod recall;
pub mod report;
pub mod shape;
pub mod slices;
pub mod source;
pub mod store;
pub mod supervise;
pub mod tokens;
pub mod units;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use md5::Md5;
use serde_json::json;
use sha2::{Digest, Sha256};
use xdrcheck_xdr::xdr::{LedgerCloseMeta, Limits as XdrLimits, WriteXdr};
use xdrcheck_xdr::{Gate, Limits};

use super::coverage::walk::{Defs, DEFINITIONS_SHA256};
use shape::{Ctx, Rules};
use source::{partition_of, Fetched, Source};
use store::{inv, Agg, Journal, LedgerRec, LedgerRow, Prov, Rec, RefusalRec};

static QUARANTINE: std::sync::OnceLock<std::collections::HashSet<u32>> = std::sync::OnceLock::new();

static THROTTLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Counters of a running `scan run`, written to `<out>/progress.json` every 10 s (read by `scan supervise`).
pub mod progress {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    pub static LEDGERS: AtomicU64 = AtomicU64::new(0);
    pub static OBJECT_BYTES: AtomicU64 = AtomicU64::new(0);
    pub static GETS: AtomicU64 = AtomicU64::new(0);
    pub static RETRIES: AtomicU64 = AtomicU64::new(0);
    pub static REFUSALS: AtomicU64 = AtomicU64::new(0);

    pub fn write(out: &Path, done: bool) {
        let v = serde_json::json!({
            "pid": std::process::id(),
            "unix_s": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            "ledgers": LEDGERS.load(Ordering::Relaxed),
            "object_bytes": OBJECT_BYTES.load(Ordering::Relaxed),
            "gets": GETS.load(Ordering::Relaxed),
            "retries": RETRIES.load(Ordering::Relaxed),
            "refusals": REFUSALS.load(Ordering::Relaxed),
            "http_throttled": super::source::pace::THROTTLED_ANSWERS.load(Ordering::Relaxed),
            "throttle_retries": super::source::pace::THROTTLE_RETRIED.load(Ordering::Relaxed),
            "rate_factor": super::source::pace::factor(),
            "done": done,
        });
        let _ = std::fs::create_dir_all(out);
        let tmp = out.join("progress.json.tmp");
        if std::fs::write(&tmp, v.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, out.join("progress.json"));
        }
    }

    /// Read the live GET cap from `file` (one number; missing or unreadable keeps the current cap).
    pub fn read_limit(file: &Path) {
        if let Some(n) = std::fs::read_to_string(file)
            .ok()
            .and_then(|t| t.trim().parse::<usize>().ok())
        {
            super::source::GET_LIMIT.store(n, Ordering::Relaxed);
        }
    }

    /// A thread that writes the file (and re-reads the live GET cap) every 10 s for as long as the
    /// process lives.
    pub fn start(
        out: PathBuf,
        limit: Option<PathBuf>,
        rate: Option<(PathBuf, usize)>,
    ) -> std::thread::JoinHandle<()> {
        let read_all = move |limit: &Option<PathBuf>, rate: &Option<(PathBuf, usize)>| {
            if let Some(f) = limit {
                read_limit(f);
            }
            if let Some((f, n)) = rate {
                if let Some(v) = std::fs::read_to_string(f)
                    .ok()
                    .and_then(|t| t.trim().parse::<f64>().ok())
                {
                    let per = (v.max(0.0) / *n as f64 * 1000.0) as u64;
                    super::source::pace::RATE_MILLI.store(per, Ordering::Relaxed);
                }
            }
        };
        read_all(&limit, &rate);
        std::thread::spawn(move || loop {
            write(&out, false);
            std::thread::sleep(std::time::Duration::from_secs(10));
            read_all(&limit, &rate);
        })
    }
}

pub const PUBNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

#[derive(clap::Subcommand, Debug)]
pub enum ScanCmd {
    /// Scan ledgers into shape records
    Run(RunArgs),
    /// Offline tools over a run's files
    #[command(flatten)]
    Tool(report::Tool),
}

#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: ScanCmd,
}

#[derive(clap::Args, Debug, Clone)]
pub struct RunArgs {
    /// Plan TSV with a `seq` column (and `set`, filtered by --sets)
    #[arg(long)]
    pub plan: Option<PathBuf>,
    /// Sets of the plan to scan, comma-separated (default: all)
    #[arg(long)]
    pub sets: Option<String>,
    /// File with one ledger sequence per line (instead of --plan)
    #[arg(long)]
    pub seqs: Option<PathBuf>,
    /// Range plan (`scan plan-ranges`): scan the units this worker is assigned
    #[arg(long)]
    pub ranges: Option<PathBuf>,
    /// Workers sharing the range plan (static assignment, no coordinator)
    #[arg(long, default_value_t = 1)]
    pub workers: usize,
    /// This worker's index, 0-based
    #[arg(long, default_value_t = 0)]
    pub worker: usize,
    /// Output directory of the run
    #[arg(long)]
    pub out: PathBuf,
    /// Local packs (`<partition>/objects.pack` + `objects.idx.tsv`)
    #[arg(long)]
    pub packs: Option<PathBuf>,
    /// A local directory laid out like the lake (`DIR/<key>`)
    #[arg(long)]
    pub lake: Option<PathBuf>,
    /// The public lake over HTTPS (base URL of the pubnet ledgers)
    #[arg(long)]
    pub http: Option<String>,
    /// Partitions worked at once
    #[arg(long, default_value_t = 1)]
    pub jobs: usize,
    /// Fetch threads per worker
    #[arg(long, default_value_t = 64)]
    pub fetch_jobs: usize,
    /// Ledgers fetched ahead of the one being decoded, per worker (at most 64)
    #[arg(long, default_value_t = 64)]
    pub window: usize,
    /// Parallel GETs over the whole process (HTTPS; at most 256)
    #[arg(long, default_value_t = 64)]
    pub max_inflight: usize,
    /// Ledgers to record as refusals (stage `quarantine`) without decoding: one number per line
    #[arg(long)]
    pub quarantine: Option<PathBuf>,
    /// Retries of one GET answered 429 / 503 / SlowDown before the worker stops (exit 3)
    #[arg(long, default_value_t = 10)]
    pub throttle_retries: u32,
    /// Rate cap of this process, GETs per second (0 = none)
    #[arg(long, default_value_t = 0.0)]
    pub max_gets_per_sec: f64,
    /// A file holding one number: the machine's GETs per second, shared by --workers processes;
    /// re-read every 10 s (`scan supervise --max-gets-per-sec`); overrides --max-gets-per-sec
    #[arg(long)]
    pub gets_rate_file: Option<PathBuf>,
    /// Throttled share of the answers over 30 s above which the process slows down (AIMD)
    #[arg(long, default_value_t = 0.05)]
    pub aimd_share: f64,
    /// Units of the range plan this worker leaves to another machine: one unit name per line
    /// (`w<i>/` prefixes are ignored). A listed unit this worker has already started is an error.
    #[arg(long)]
    pub skip_units: Option<PathBuf>,
    /// A file holding one number: the live cap on parallel GETs, re-read every 10 s (`scan supervise`)
    #[arg(long)]
    pub gets_limit_file: Option<PathBuf>,
    /// Rules file (default: the built-in `xcc.shape/v1` table)
    #[arg(long)]
    pub rules: Option<PathBuf>,
    /// Largest decompressed object accepted
    #[arg(long, default_value_t = 512 << 20)]
    pub max_object_bytes: u64,
    /// Independent reader command for refusal classification (gets the decompressed batch file;
    /// exit 0 = accepts); repeatable
    #[arg(long)]
    pub reader: Vec<String>,
    /// A second public lake for refusal classification (8 ledgers per batch)
    #[arg(long)]
    pub second_lake: Option<String>,
    /// Do not use the network to classify refusals
    #[arg(long)]
    pub offline: bool,
    /// zstd level of the record files and of the dictionaries
    #[arg(long, default_value_t = 3)]
    pub level: i32,
    #[arg(long, default_value_t = 9)]
    pub dict_level: i32,
    /// Highest ledger the run covers (recorded in run.json)
    #[arg(long)]
    pub tip: Option<u32>,
    /// Ledgers per Parquet row group of the per-ledger tables (bounds memory at the end of a partition)
    #[arg(long, default_value_t = store::GROUP_LEDGERS)]
    pub group_ledgers: usize,
    /// Stop when the output disk has less free space than this (bytes)
    #[arg(long, default_value_t = 200_000_000_000)]
    pub min_free: u64,
    /// Measurement only: put every planned ledger in one output group (memory of a large partition)
    #[arg(long, hide = true)]
    pub one_group: bool,
}

pub fn run(_corpus: &Path, a: Args) -> Result<ExitCode> {
    match a.cmd {
        ScanCmd::Run(r) => scan(&r),
        ScanCmd::Tool(t) => report::run(t),
    }
}

fn read_plan(a: &RunArgs) -> Result<(Vec<u32>, String)> {
    let mut seqs = BTreeSet::new();
    let text = if let Some(p) = &a.plan {
        let text = std::fs::read_to_string(p).with_context(|| format!("{}", p.display()))?;
        let sets: Option<BTreeSet<&str>> = a.sets.as_deref().map(|s| s.split(',').collect());
        let mut lines = text.lines();
        let head: Vec<&str> = lines.next().unwrap_or("").split('\t').collect();
        let cs = head
            .iter()
            .position(|h| *h == "seq")
            .context("plan has no seq column")?;
        let cset = head.iter().position(|h| *h == "set");
        for l in lines {
            let f: Vec<&str> = l.split('\t').collect();
            if let (Some(sets), Some(c)) = (&sets, cset) {
                if !sets.contains(f.get(c).copied().unwrap_or("")) {
                    continue;
                }
            }
            seqs.insert(f[cs].parse::<u32>()?);
        }
        text
    } else if let Some(p) = &a.ranges {
        let (v, sha) = ranges::assigned_seqs(p, a.workers, a.worker)?;
        seqs.extend(v);
        return Ok((seqs.into_iter().collect(), sha));
    } else if let Some(p) = &a.seqs {
        let text = std::fs::read_to_string(p)?;
        for l in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            seqs.insert(l.parse::<u32>()?);
        }
        text
    } else {
        bail!("give --plan or --seqs");
    };
    Ok((
        seqs.into_iter().collect(),
        xdrcheck_xdr::sha256_hex(text.as_bytes()),
    ))
}

fn free_bytes(dir: &Path) -> Result<u64> {
    let o = Command::new("df")
        .args(["-B1", "--output=avail"])
        .arg(dir)
        .output()?;
    let s = String::from_utf8_lossy(&o.stdout);
    s.lines()
        .nth(1)
        .and_then(|l| l.trim().parse().ok())
        .context("df")
}

struct Scan<'a> {
    a: &'a RunArgs,
    src: Source,
    ctx: Ctx<'a>,
    limits: Limits,
    gate: Gate,
    header: serde_json::Value,
}

fn scan(a: &RunArgs) -> Result<ExitCode> {
    let defs = Defs::pinned();
    let rules_text = match &a.rules {
        Some(p) => std::fs::read_to_string(p)?,
        None => shape::RULES_V1.to_string(),
    };
    let rules = Rules::parse(&rules_text, defs)?;
    let (seqs, plan_sha) = read_plan(a)?;
    if let Some(q) = &a.quarantine {
        let t = std::fs::read_to_string(q).with_context(|| q.display().to_string())?;
        let set = t
            .split_whitespace()
            .map(|x| x.parse::<u32>())
            .collect::<std::result::Result<_, _>>()?;
        let _ = QUARANTINE.set(set);
    }
    let src = match (&a.packs, &a.lake, &a.http) {
        (Some(p), None, None) => Source::packs(p.clone()),
        (None, Some(d), None) => Source::Dir(d.clone()),
        (None, None, Some(u)) => Source::http(
            u.trim_end_matches('/').to_string(),
            a.max_inflight.clamp(1, 256),
        ),
        _ => bail!("give exactly one of --packs, --lake, --http"),
    };
    std::fs::create_dir_all(&a.out)?;
    let network_id: [u8; 32] = Sha256::digest(PUBNET_PASSPHRASE.as_bytes()).into();
    let header = json!({
        "grammar": rules.file.grammar,
        "rules_sha256": rules.sha256,
        "definitions_sha256": DEFINITIONS_SHA256,
        "network": "pubnet",
    });
    let run_json = json!({
        "header": header,
        "plan_sha256": plan_sha,
        "ledgers_planned": seqs.len(),
        "tip": a.tip,
        // The name the existing scan output carries (the package had that name then); kept so runs stay uniform.
        "tool": "xcc-corpus",
        "tool_version": env!("CARGO_PKG_VERSION"),
        "seed": "xcc-scan-pilot-2026-11-16",
    });
    let rj = a.out.join("run.json");
    if rj.exists() {
        let old: serde_json::Value = serde_json::from_slice(&std::fs::read(&rj)?)?;
        if old["header"] != run_json["header"] || old["plan_sha256"] != run_json["plan_sha256"] {
            bail!(
                "{} belongs to a different run (header or plan differ)",
                rj.display()
            );
        }
    } else {
        let mut t = serde_json::to_vec_pretty(&run_json)?;
        t.push(b'\n');
        store::write_atomic(&rj, &t)?;
    }
    let mut parts: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for s in &seqs {
        let key = if a.one_group {
            "ALL".to_string()
        } else {
            partition_of(*s)
        };
        parts.entry(key).or_default().push(*s);
    }
    // Newest first: partition names are reversed, so name order is newest first.
    let mut order: Vec<(String, Vec<u32>)> = parts.into_iter().collect();
    if let Some(r) = &a.ranges {
        // A range plan names its units (a lake partition, or a part of one): one output directory each.
        let (units, _) = ranges::read(r)?;
        order = ranges::assign(&units, a.workers, a.worker)
            .into_iter()
            .map(|i| (units[i].name(), (units[i].first..=units[i].last).collect()))
            .collect();
        // Newest unit first.
        order.sort_by_key(|(_, s)| std::cmp::Reverse(s.first().copied()));
        if let Some(f) = &a.skip_units {
            let skip = ranges::read_skip(f)?;
            for (name, _) in &order {
                let d = a.out.join(name);
                if skip.contains(name) && d.exists() {
                    bail!(
                        "{} is in --skip-units but this worker has started it",
                        d.display()
                    );
                }
            }
            let before = order.len();
            order.retain(|(name, _)| !skip.contains(name));
            eprintln!(
                "skip-units: {} of this worker's {before} units left to another machine",
                before - order.len()
            );
        }
    } else if a.skip_units.is_some() {
        bail!("--skip-units needs --ranges");
    }
    let s = Scan {
        a,
        src,
        ctx: Ctx {
            defs,
            rules: &rules,
            network_id,
        },
        limits: Limits::default(),
        gate: Gate::default().reading_live(),
        header,
    };
    let next = AtomicUsize::new(0);
    {
        use std::sync::atomic::Ordering::Relaxed;
        source::pace::THROTTLE_RETRIES.store(a.throttle_retries, Relaxed);
        source::pace::RATE_MILLI.store((a.max_gets_per_sec.max(0.0) * 1000.0) as u64, Relaxed);
        source::pace::AIMD_SHARE_PPM.store((a.aimd_share.clamp(0.0, 1.0) * 1e6) as u64, Relaxed);
    }
    let rate = a.gets_rate_file.clone().map(|f| (f, a.workers.max(1)));
    let _progress = progress::start(a.out.clone(), a.gets_limit_file.clone(), rate);
    let errors = Mutex::new(Vec::new());
    let t0 = Instant::now();
    let done = AtomicUsize::new(0);
    std::thread::scope(|sc| {
        for _ in 0..a.jobs.max(1) {
            // Each worker runs on one big-stack thread, so per-ledger decoding runs in place instead of
            // on a fresh thread (and a fresh allocator arena) per ledger.
            sc.spawn(|| {
                xdrcheck_xdr::with_stack(s.limits.stack_size, || loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some((part, seqs)) = order.get(i) else {
                        break;
                    };
                    if let Err(e) = s.partition(part, seqs) {
                        if e.chain()
                            .any(|c| c.downcast_ref::<source::Throttled>().is_some())
                        {
                            THROTTLED.store(true, Ordering::SeqCst);
                        }
                        errors.lock().unwrap().push(format!("{part}: {e:#}"));
                        next.store(order.len(), Ordering::SeqCst);
                        break;
                    }
                    let d = done.fetch_add(1, Ordering::SeqCst) + 1;
                    eprintln!(
                        "[{d}/{}] {part} {} ledgers {:.0}s",
                        order.len(),
                        seqs.len(),
                        t0.elapsed().as_secs_f64()
                    );
                })
            });
        }
    });
    let errors = errors.into_inner().unwrap();
    progress::write(&a.out, true);
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("error: {e}");
        }
        // 3: the lake asked us to slow down (the supervisor waits and resumes); 2: anything else.
        return Ok(ExitCode::from(if THROTTLED.load(Ordering::SeqCst) {
            3
        } else {
            2
        }));
    }
    let mut sums = String::new();
    for p in store::partitions(&a.out)? {
        let m = p.join("MANIFEST.json");
        let rel = m.strip_prefix(&a.out)?.display().to_string();
        sums.push_str(&format!("{}  {rel}\n", xdrcheck_xdr::sha256_file(&m)?));
    }
    store::write_atomic(&a.out.join("SHA256SUMS"), sums.as_bytes())?;
    eprintln!(
        "scan done: {} partitions, {:.0}s",
        order.len(),
        t0.elapsed().as_secs_f64()
    );
    Ok(ExitCode::SUCCESS)
}

impl Scan<'_> {
    fn partition(&self, part: &str, seqs: &[u32]) -> Result<()> {
        let dir = self.a.out.join(part);
        std::fs::create_dir_all(&dir)?;
        if store::verify_partition(&dir)? {
            return Ok(());
        }
        if free_bytes(&self.a.out)? < self.a.min_free {
            bail!("free space under {} bytes; stopping", self.a.min_free);
        }
        let jpath = dir.join("journal.tmp");
        let mut agg = Agg::default();
        let mut journal = Journal::open(&jpath, |off, r| agg.add(&r, off))?;
        let done = agg.done();
        let todo: Vec<u32> = seqs
            .iter()
            .rev()
            .copied()
            .filter(|s| !done.contains(s))
            .collect();
        pipeline(
            &self.src,
            &todo,
            self.a.window,
            self.a.fetch_jobs,
            |seq, f| {
                let mut rec = self.ledger_guarded(seq, f);
                if matches!(rec, Rec::Refusal(..)) {
                    progress::REFUSALS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                if let Rec::Ledger(l) = &mut rec {
                    l.shapes.components.retain(|id, _| !agg.known(id));
                }
                let off = journal.append(&rec)?;
                progress::LEDGERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                agg.add(&rec, off)
            },
        )?;
        journal.sync()?;
        let mut header = self.header.clone();
        header["planned"] = json!(seqs.len());
        store::finish(
            &dir,
            part,
            &agg,
            header,
            self.a.level,
            self.a.dict_level,
            &jpath,
            self.a.group_ledgers,
        )?;
        std::fs::remove_file(&jpath)?;
        Ok(())
    }

    /// `ledger`, except that a quarantined ledger (`--quarantine`) is recorded without decoding and
    /// a panic while handling one ledger becomes that ledger's refusal (stage `panic`) instead of
    /// stopping the worker's whole share.
    fn ledger_guarded(&self, seq: u32, f: Fetched) -> Rec {
        let refuse = |stage: &str, error: String, obj: Option<&Vec<u8>>, note: &str| {
            Rec::Refusal(
                RefusalRec {
                    seq,
                    stage: stage.into(),
                    class: "ours".into(),
                    error,
                    sha256: obj.map(|o| xdrcheck_xdr::sha256_hex(o)),
                    bytes_hex: obj.map(hex::encode).unwrap_or_default(),
                    note: note.into(),
                },
                Prov {
                    seq,
                    source: self.src.name(),
                    ..Default::default()
                },
            )
        };
        if QUARANTINE.get().is_some_and(|q| q.contains(&seq)) {
            return refuse(
                "quarantine",
                "listed in --quarantine".into(),
                f.bytes.as_ref(),
                "not decoded on request",
            );
        }
        let obj = f.bytes.clone();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.ledger(seq, f))) {
            Ok(r) => r,
            Err(p) => {
                let msg = p
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| p.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "panic".into());
                refuse(
                    "panic",
                    msg,
                    obj.as_ref(),
                    "the scanner panicked on this ledger",
                )
            }
        }
    }

    fn ledger(&self, seq: u32, f: Fetched) -> Rec {
        if std::env::var("XDRCHECK_SCAN_PANIC_SEQ")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            == Some(seq)
        {
            panic!("test hook: XDRCHECK_SCAN_PANIC_SEQ={seq}");
        }
        use std::sync::atomic::Ordering::Relaxed;
        progress::GETS.fetch_add(f.tries.max(1) as u64, Relaxed);
        progress::RETRIES.fetch_add(f.tries.saturating_sub(1) as u64, Relaxed);
        progress::OBJECT_BYTES.fetch_add(
            f.bytes.as_ref().map(|b| b.len() as u64).unwrap_or(0),
            Relaxed,
        );
        let mut prov = Prov {
            seq,
            source: self.src.name(),
            last_modified: f.last_modified.clone(),
            core_version: f.meta.get("core-version").cloned(),
            galexie_version: f.meta.get("version").cloned(),
            meta_protocol: f.meta.get("protocol-version").cloned(),
            file_mtime: f.meta.get("file-mtime").cloned(),
            tries: f.tries,
            fetch_us: f.us,
            ..Default::default()
        };
        let Some(obj) = f.bytes.clone() else {
            let r = RefusalRec {
                seq,
                stage: "fetch".into(),
                class: "lake".into(),
                error: format!("HTTP {}: object missing inside a listed range", f.status),
                sha256: None,
                bytes_hex: String::new(),
                note: "a missing object in the plan".into(),
            };
            return Rec::Refusal(r, prov);
        };
        match self.ledger_inner(seq, &f, &obj, &mut prov) {
            Ok(rec) => rec,
            Err((stage, err, lcm_bytes)) => {
                let (class, note) = self.classify(seq, &stage, &err, &obj, lcm_bytes.as_deref());
                let r = RefusalRec {
                    seq,
                    stage,
                    class,
                    error: err,
                    sha256: Some(xdrcheck_xdr::sha256_hex(&obj)),
                    bytes_hex: hex::encode(&obj),
                    note,
                };
                Rec::Refusal(r, prov)
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn ledger_inner(
        &self,
        seq: u32,
        f: &Fetched,
        obj: &[u8],
        prov: &mut Prov,
    ) -> std::result::Result<Rec, (String, String, Option<Vec<u8>>)> {
        let fail = |stage: &str, e: String| (stage.to_string(), e, None);
        if let Some(p) = &f.problem {
            return Err(fail("fetch", p.clone()));
        }
        let t0 = Instant::now();
        let xdr = xdrcheck_xdr::batch::decompress_bounded(obj, self.a.max_object_bytes)
            .map_err(|e| fail("zstd", e.to_string()))?;
        let batch = xdrcheck_xdr::split_batch(&xdr, &self.limits, &self.gate).map_err(|e| {
            let stage = match &e {
                xdrcheck_xdr::Error::Malformed {
                    reason: xdrcheck_xdr::Malformed::TrailingBytes { .. },
                    ..
                }
                | xdrcheck_xdr::Error::Malformed {
                    reason: xdrcheck_xdr::Malformed::Batch(_),
                    ..
                } => "batch",
                xdrcheck_xdr::Error::RoundTrip { .. } => "roundtrip",
                _ => "decode",
            };
            fail(stage, e.to_string())
        })?;
        if batch.ledgers.len() != 1 || batch.infos[0].sequence != seq {
            return Err((
                "invariant".into(),
                format!(
                    "the object for {seq} holds {} ledger(s) starting at {}",
                    batch.ledgers.len(),
                    batch.start_sequence
                ),
                batch.ledgers.first().cloned(),
            ));
        }
        let blob = &batch.ledgers[0];
        let (limits, live, ctx) = (&self.limits, &self.gate, &self.ctx);
        let res = xdrcheck_xdr::with_stack(limits.stack_size, || {
            let lcm = xdrcheck_xdr::decode_ledger(blob, limits, live)
                .map_err(|e| ("decode".to_string(), e.to_string()))?;
            let header = match &lcm {
                LedgerCloseMeta::V0(m) => &m.ledger_header,
                LedgerCloseMeta::V1(m) => &m.ledger_header,
                LedgerCloseMeta::V2(m) => &m.ledger_header,
            };
            let hb = header
                .header
                .to_xdr(XdrLimits::none())
                .map_err(|e| ("decode".to_string(), e.to_string()))?;
            let hh: [u8; 32] = Sha256::digest(&hb).into();
            let t1 = Instant::now();
            let shapes = ctx
                .ledger(&lcm, blob)
                .map_err(|e| ("walk".to_string(), format!("{e:#}")))?;
            Ok((lcm, hh, shapes, t1.elapsed()))
        });
        let (lcm, recomputed, shapes, shape_t) =
            res.map_err(|(s, e): (String, String)| (s, e, Some(blob.clone())))?;
        prov.shape_us = shape_t.as_micros() as u64;
        prov.decode_us = (t0.elapsed() - shape_t).as_micros() as u64;
        let header = match &lcm {
            LedgerCloseMeta::V0(m) => &m.ledger_header,
            LedgerCloseMeta::V1(m) => &m.ledger_header,
            LedgerCloseMeta::V2(m) => &m.ledger_header,
        };
        if recomputed != header.hash.0 {
            return Err((
                "invariant".into(),
                "stored header hash is not the hash of the header".into(),
                Some(blob.clone()),
            ));
        }
        if shapes.tx_hash_mismatches > 0 {
            return Err((
                "join".into(),
                format!(
                    "{} transaction result(s) without an envelope under the pubnet passphrase",
                    shapes.tx_hash_mismatches
                ),
                Some(blob.clone()),
            ));
        }
        let hv = header.header.ledger_version;
        let applied = match shapes.upgraded_to {
            Some(v) if v == hv => {
                let mut p = hv - 1;
                while self.ctx.rules.file.skipped_protocols.contains(&p) && p > 1 {
                    p -= 1;
                }
                p
            }
            _ => hv,
        };
        let meta_ok = match (f.meta.get("protocol-version"), f.meta.get("start-ledger")) {
            (Some(p), Some(s)) => p == &hv.to_string() && s == &seq.to_string(),
            _ => true,
        };
        let md5_ok = f
            .etag
            .as_ref()
            .filter(|e| e.len() == 32)
            .map(|e| hex::encode(Md5::digest(obj)) == *e);
        let mut bits = inv::BATCH_OK
            | inv::ROUNDTRIP_OK
            | inv::WALK_OK
            | inv::HEADER_HASH_OK
            | inv::TX_HASH_OK;
        if meta_ok {
            bits |= inv::META_MATCHES;
        }
        if shapes.tx_set_hash_ok {
            bits |= inv::TX_SET_HASH_OK;
        }
        if shapes.result_hash_ok {
            bits |= inv::RESULT_HASH_OK;
        }
        let row = LedgerRow {
            seq,
            object_bytes: obj.len() as u64,
            xdr_bytes: xdr.len() as u64,
            object_sha256: xdrcheck_xdr::sha256_hex(obj),
            etag: f
                .etag
                .clone()
                .filter(|e| e.len() == 32 && e.chars().all(|c| c.is_ascii_hexdigit())),
            md5_matches_etag: md5_ok,
            close_time: header.header.scp_value.close_time.0,
            header_version: hv,
            protocol_applied: applied,
            lcm_arm: lcm.discriminant() as u32,
            header_hash: hex::encode(header.hash.0),
            prev_hash: hex::encode(header.header.previous_ledger_hash.0),
            tx_count: shapes.txs.len() as u32,
            op_count: shapes.op_count,
            soroban_tx_count: shapes.soroban_tx_count,
            ledger_shape: shape::hex16(&shapes.ledger.id()),
            invariants: bits,
            tx_hash_mismatches: shapes.tx_hash_mismatches,
        };
        Ok(Rec::Ledger(Box::new(LedgerRec {
            row,
            shapes,
            prov: prov.clone(),
        })))
    }

    /// Classify a refusal: `lake-transient` (a second fetch gives other bytes), `ours` (independent
    /// readers accept what we refused), `ours-pin` (an arm the pinned definitions lack above the
    /// gate), `core` / `lake` (all readers refuse; the second public lake has the same / other bytes),
    /// `unclassified` (a step could not run).
    fn classify(
        &self,
        seq: u32,
        stage: &str,
        err: &str,
        obj: &[u8],
        lcm: Option<&[u8]>,
    ) -> (String, String) {
        let mut notes = Vec::new();
        match self.src.get(seq, true) {
            Ok(f2) => {
                if f2.bytes.as_deref() != Some(obj) {
                    return (
                        "lake-transient".into(),
                        "a second fetch gave other bytes".into(),
                    );
                }
                notes.push("second fetch: same bytes".to_string());
            }
            Err(e) => notes.push(format!("second fetch failed: {e}")),
        }
        let decode_stage = matches!(stage, "zstd" | "batch" | "decode" | "roundtrip" | "walk");
        if decode_stage {
            // Unbounded decompression by the zstd command, then the independent readers.
            // Next to the run's files, never in the system temporary directory.
            let tmp = self
                .a
                .out
                .join(format!("refusal-{seq}-{}.tmp", std::process::id()));
            let z = tmp.with_extension("zst");
            let x = tmp.with_extension("xdr");
            let _ = std::fs::write(&z, obj);
            let unz = Command::new("zstd")
                .args(["-q", "-d", "-f", "--memory=2048MB", "-o"])
                .arg(&x)
                .arg(&z)
                .status();
            let _ = std::fs::remove_file(&z);
            if !matches!(unz, Ok(s) if s.success()) {
                notes.push("zstd command refuses the frame".into());
            } else if self.a.reader.is_empty() {
                let _ = std::fs::remove_file(&x);
                return (
                    "unclassified".into(),
                    format!("{}; no independent reader configured", notes.join("; ")),
                );
            } else {
                let mut accepts = 0;
                for r in &self.a.reader {
                    let ok = Command::new("sh")
                        .arg("-c")
                        .arg(format!("{r} \"$1\""))
                        .arg("sh")
                        .arg(&x)
                        .output();
                    let ok = matches!(ok, Ok(o) if o.status.success());
                    notes.push(format!(
                        "reader `{r}`: {}",
                        if ok { "accepts" } else { "refuses" }
                    ));
                    accepts += ok as usize;
                }
                let _ = std::fs::remove_file(&x);
                if accepts == self.a.reader.len() {
                    return ("ours".into(), notes.join("; "));
                }
                if stage == "walk" && (err.contains("no arm") || err.contains("undeclared")) {
                    return ("ours-pin".into(), notes.join("; "));
                }
            }
        }
        let Some(second) = self.a.second_lake.as_deref().filter(|_| !self.a.offline) else {
            return (
                "unclassified".into(),
                format!("{}; no second lake consulted", notes.join("; ")),
            );
        };
        match second_lake_ledger(second, seq) {
            Ok(Some(theirs)) => {
                let same = lcm.is_some_and(|ours| ours == &theirs[..]);
                notes.push(format!("second lake: {} bytes for {seq}", theirs.len()));
                if same {
                    ("core".into(), notes.join("; "))
                } else {
                    (
                        "lake".into(),
                        format!("{}; the second lake serves other bytes", notes.join("; ")),
                    )
                }
            }
            Ok(None) => (
                "unclassified".into(),
                format!("{}; the second lake has no such ledger", notes.join("; ")),
            ),
            Err(e) => (
                "unclassified".into(),
                format!("{}; second lake: {e:#}", notes.join("; ")),
            ),
        }
    }
}

/// Fetch `todo` with `threads` fetch threads, at most `window` ledgers ahead of the consumer, and hand
/// each object to `consume` in `todo` order (so the outcome does not depend on fetch timing). A fetch
/// error (a throttle answer among them) stops the fetchers and is returned.
pub fn pipeline(
    src: &Source,
    todo: &[u32],
    window: usize,
    threads: usize,
    mut consume: impl FnMut(u32, Fetched) -> Result<()>,
) -> Result<()> {
    use std::sync::Condvar;
    let window = window.clamp(1, 64);
    let threads = threads.clamp(1, window);
    struct St {
        next: usize,
        consumed: usize,
        stop: bool,
        ready: BTreeMap<usize, Result<Fetched>>,
    }
    let st = Mutex::new(St {
        next: 0,
        consumed: 0,
        stop: false,
        ready: BTreeMap::new(),
    });
    let cv = Condvar::new();
    std::thread::scope(|sc| -> Result<()> {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let i = {
                    let mut g = st.lock().unwrap();
                    while !g.stop && g.next < todo.len() && g.next >= g.consumed + window {
                        g = cv.wait(g).unwrap();
                    }
                    if g.stop || g.next >= todo.len() {
                        return;
                    }
                    g.next += 1;
                    g.next - 1
                };
                let r = src.get(todo[i], false);
                let mut g = st.lock().unwrap();
                if r.is_err() {
                    g.stop = true;
                }
                g.ready.insert(i, r);
                cv.notify_all();
            });
        }
        let mut out = Ok(());
        for (i, &seq) in todo.iter().enumerate() {
            let r = {
                let mut g = st.lock().unwrap();
                loop {
                    if let Some(r) = g.ready.remove(&i) {
                        break Some(r);
                    }
                    if g.stop && i >= g.next {
                        // Fetching stopped before this ledger was taken.
                        break None;
                    }
                    g = cv.wait(g).unwrap();
                }
            };
            let res = match r {
                Some(Ok(f)) => consume(seq, f),
                Some(Err(e)) => Err(e.context(format!("fetch {seq}"))),
                None => Err(anyhow::anyhow!("fetch stopped before {seq}")),
            };
            let mut g = st.lock().unwrap();
            g.consumed = i + 1;
            if res.is_err() {
                g.stop = true;
            }
            cv.notify_all();
            drop(g);
            if let Err(e) = res {
                out = Err(e);
                break;
            }
        }
        {
            let mut g = st.lock().unwrap();
            g.stop = true;
            cv.notify_all();
        }
        out
    })
}

/// The exact `LedgerCloseMeta` bytes of `seq` from a lake with 8 ledgers per batch and 64,000
/// batches per partition.
pub fn second_lake_ledger(base: &str, seq: u32) -> Result<Option<Vec<u8>>> {
    let per = 8u32;
    let part = 64_000 * per;
    let s = seq / per * per;
    let p = seq / part * part;
    let key = format!(
        "{:08X}--{}-{}/{:08X}--{}-{}.xdr.zst",
        u32::MAX - p,
        p,
        p + part - 1,
        u32::MAX - s,
        s,
        s + per - 1
    );
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(120)))
        .http_status_as_error(false)
        .build()
        .into();
    let f = source::http_get(&agent, &format!("{}/{key}", base.trim_end_matches('/')))?;
    let Some(obj) = f.bytes else { return Ok(None) };
    let xdr = xdrcheck_xdr::batch::decompress(&obj)?;
    let b = xdrcheck_xdr::split_batch(&xdr, &Limits::default(), &Gate::default().reading_live())?;
    Ok(b.infos
        .iter()
        .position(|i| i.sequence == seq)
        .map(|i| b.ledgers[i].clone()))
}
