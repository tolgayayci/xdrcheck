//! Offline tools over scan runs: projection to G0–G3 and ablation, greedy cover, saturation
//! curves, vocabulary candidates, sizes, the per-writer format table, ledger lists of a component,
//! run-to-run comparison, and the recall checks (`recall.rs`). They read only a run's files.
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::record::Field;
use sha2::{Digest, Sha256};

use super::shape::{shape_id, Id};

#[derive(clap::Subcommand, Debug)]
pub enum Tool {
    /// Distinct components and transaction shapes at G0–G3, and the ablation table
    Ablate(RunsArg),
    /// Kept-example cover at each level (components and whole transactions)
    Cover(CoverArgs),
    /// Saturation curves per era on the held-out set
    Saturation(SatArgs),
    /// Most common event symbols and data-map keys outside the closed vocabularies
    Vocab(VocabArgs),
    /// Record and dictionary bytes per ledger and per transaction, per era
    Size(SatArgs),
    /// Per writer era: what the lake serves
    Format(RunsArg),
    /// Ledgers holding a component (via the transaction shapes that contain it)
    Ledgers(LedgersArgs),
    /// Refusals of a run: stage, class, error, classification notes
    Refusals(RunsArg),
    /// Components whose tokens contain a text (id, kind, op type, matching tokens)
    Grep(GrepArgs),
    /// Ledger components: for each ledger, how many run ledgers within a window share its `L` id
    LedgerSep(LedgerSepArgs),
    /// Transaction-slice cover: one transaction per not yet covered component (ledgers ascending),
    /// as `seq<TAB>tx_index`
    SliceCover(SliceCoverArgs),
    /// Reader throughput: GET every listed ledger from the lake with N parallel requests, keep nothing
    FetchBench(FetchBenchArgs),
    /// Cut [first, tip] into a range plan balanced by bytes plus a fixed per-ledger cost
    PlanRanges(super::ranges::PlanArgs),
    /// Prove that run directories hold every ledger of a range plan exactly once
    Verify(super::ranges::VerifyArgs),
    /// Merge workers' run directories into one
    Merge(super::ranges::MergeArgs),
    /// Cut transaction slices out of captured overlay ledger entries
    CutSlices(super::slices::CutArgs),
    /// Run N scan workers of a range plan: restart on throttle or crash, heartbeat, watchdog
    Supervise(super::supervise::SuperviseArgs),
    /// List lake partitions (anonymous ListObjectsV2) into per-partition size files
    ListLake(super::ranges::ListArgs),
    /// Compare two runs file by file
    Diff(DiffArgs),
    /// Known-trigger recall with independent predicates
    Recall(super::recall::RecallArgs),
    /// Held-out recall: pinpointed transactions of corpus entries
    Heldout(super::recall::HeldoutArgs),
    /// Census phase 1: one sorted run file per unit (ids at G0–G3 with counts), unit by unit
    CensusExtract(super::census::ExtractArgs),
    /// Census phase 2: bounded k-way merge of the run files into per-level shape lists and a summary
    CensusMerge(super::census::MergeArgs),
    /// Greedy example covers (transactions, whole ledgers; ascending and rarest-first) per level,
    /// streaming unit by unit
    CoverStream(super::cover::CoverStreamArgs),
    /// Per token and per token class: carrying components, occurrences, ledger range; projection-step
    /// attribution of the O components
    TokenCensus(super::tokens::TokenCensusArgs),
    /// Header-hash chain, sequence gaps and invariant bits over every ledger, in ledger order
    ChainCheck(super::chain::ChainCheckArgs),
    /// Build the locate index: token, G3 component and G3 tx shape -> (ledger, transaction) postings
    LocateBuild(super::locate::BuildArgs),
    /// Where a token, token class, G3 component or G3 tx shape occurs (TSV)
    Locate(super::locate::QueryArgs),
    /// Check the locate index against the token census and the pilot index
    LocateCheck(super::locate::CheckArgs),
    /// The shape tokens of every corpus entry's focus transaction (or ledger), walked as `scan run` walks a
    /// mainnet ledger
    EntryTokens(super::entries::EntryTokensArgs),
}

#[derive(clap::Args, Debug)]
pub struct RunsArg {
    /// Run directories (merged)
    #[arg(long = "run", required = true)]
    pub runs: Vec<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct CoverArgs {
    #[arg(long = "run", required = true)]
    pub runs: Vec<PathBuf>,
    /// Plan TSV (seq, protocol_era, set, reason) for the per-size curve
    #[arg(long)]
    pub plan: Option<PathBuf>,
    /// Plan JSON with `eras` ([protocol, first, last]) for the per-era extrapolation
    #[arg(long)]
    pub plan_json: Option<PathBuf>,
    /// Levels or custom kind sets (`T+X+K`), comma-separated
    #[arg(long, default_value = "G0,G1,G2,G3")]
    pub levels: String,
    /// Weigh kept ledgers by decompressed XDR bytes instead of object bytes
    #[arg(long)]
    pub xdr_bytes: bool,
}

#[derive(clap::Args, Debug)]
pub struct SatArgs {
    #[arg(long = "run", required = true)]
    pub runs: Vec<PathBuf>,
    #[arg(long)]
    pub plan: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct VocabArgs {
    #[arg(long = "run", required = true)]
    pub runs: Vec<PathBuf>,
    #[arg(long, default_value_t = 40)]
    pub top: usize,
}

#[derive(clap::Args, Debug)]
pub struct LedgersArgs {
    #[arg(long = "run", required = true)]
    pub runs: Vec<PathBuf>,
    /// Component id (hex) at G3
    #[arg(long)]
    pub component: String,
}

#[derive(clap::Args, Debug)]
pub struct GrepArgs {
    #[arg(long = "run", required = true)]
    pub runs: Vec<PathBuf>,
    /// Text a token must contain
    #[arg(long)]
    pub token: String,
    /// Print the full token list of each match
    #[arg(long)]
    pub full: bool,
}

#[derive(clap::Args, Debug)]
pub struct LedgerSepArgs {
    #[arg(long = "run", required = true)]
    pub runs: Vec<PathBuf>,
    /// Ledgers to check, comma-separated
    #[arg(long, value_delimiter = ',')]
    pub seqs: Vec<u32>,
    /// Window (ledgers either side)
    #[arg(long, default_value_t = 100)]
    pub window: u32,
}

#[derive(clap::Args, Debug)]
pub struct SliceCoverArgs {
    #[arg(long = "run", required = true)]
    pub runs: Vec<PathBuf>,
    #[arg(long, default_value = "G3")]
    pub level: String,
}

#[derive(clap::Args, Debug)]
pub struct FetchBenchArgs {
    /// File with one ledger sequence per line
    #[arg(long)]
    pub seqs: PathBuf,
    /// Lake base URL (pubnet ledgers)
    #[arg(long)]
    pub http: String,
    /// Parallel GETs (at most 256)
    #[arg(long, default_value_t = 64)]
    pub parallel: usize,
}

#[derive(clap::Args, Debug)]
pub struct DiffArgs {
    pub a: PathBuf,
    pub b: PathBuf,
}

pub fn run(t: Tool) -> Result<ExitCode> {
    match t {
        Tool::PlanRanges(a) => return super::ranges::plan(a).map(|_| ExitCode::SUCCESS),
        Tool::Verify(a) => {
            return super::ranges::verify(a).map(|ok| {
                if ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            })
        }
        Tool::Merge(a) => return super::ranges::merge(a).map(|_| ExitCode::SUCCESS),
        Tool::CensusExtract(a) => return super::census::extract(a).map(|_| ExitCode::SUCCESS),
        Tool::CensusMerge(a) => return super::census::merge(a).map(|_| ExitCode::SUCCESS),
        Tool::CoverStream(a) => return super::cover::run(a).map(|_| ExitCode::SUCCESS),
        Tool::TokenCensus(a) => return super::tokens::run(a).map(|_| ExitCode::SUCCESS),
        Tool::ChainCheck(a) => return super::chain::run(a),
        Tool::LocateBuild(a) => return super::locate::build(a).map(|_| ExitCode::SUCCESS),
        Tool::Locate(a) => return super::locate::query(a).map(|_| ExitCode::SUCCESS),
        Tool::LocateCheck(a) => return super::locate::check(a).map(|_| ExitCode::SUCCESS),
        Tool::EntryTokens(a) => return super::entries::run(a).map(|_| ExitCode::SUCCESS),
        Tool::CutSlices(a) => return super::slices::cut(a).map(|_| ExitCode::SUCCESS),
        Tool::Supervise(a) => return super::supervise::run(a),
        Tool::ListLake(a) => return super::ranges::list_lake(a).map(|_| ExitCode::SUCCESS),
        Tool::Ablate(a) => ablate(&RunData::load(&a.runs)?),
        Tool::Cover(a) => {
            let d = RunData::load(&a.runs)?;
            match (&a.plan, &a.plan_json) {
                (Some(p), Some(j)) => cover_extrapolate(&d, p, j, &a.levels, a.xdr_bytes),
                _ => cover(&d, a.plan.as_deref()),
            }
        }
        Tool::Saturation(a) => saturation(&RunData::load(&a.runs)?, &a.plan),
        Tool::Vocab(a) => vocab(&RunData::load(&a.runs)?, a.top),
        Tool::Size(a) => size(&a.runs, &RunData::load(&a.runs)?, &a.plan),
        Tool::Format(a) => format(&RunData::load(&a.runs)?),
        Tool::Ledgers(a) => ledgers(&RunData::load(&a.runs)?, &a.component),
        Tool::Diff(a) => diff(&a.a, &a.b),
        Tool::FetchBench(a) => {
            use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
            let seqs: Vec<u32> = std::fs::read_to_string(&a.seqs)?
                .lines()
                .filter_map(|l| l.trim().parse().ok())
                .collect();
            let n = a.parallel.clamp(1, 256);
            let src = super::source::Source::http(a.http.trim_end_matches('/').to_string(), n);
            let (next, bytes, ok, gone, retried) = (
                AtomicUsize::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            );
            let err = std::sync::Mutex::new(None::<String>);
            let t0 = std::time::Instant::now();
            std::thread::scope(|sc| {
                for _ in 0..n {
                    sc.spawn(|| loop {
                        let i = next.fetch_add(1, Ordering::SeqCst);
                        if i >= seqs.len() || err.lock().unwrap().is_some() {
                            return;
                        }
                        match src.get(seqs[i], false) {
                            Ok(f) => {
                                if let Some(b) = &f.bytes {
                                    let _ = xdrcheck_xdr::sha256_hex(b);
                                    bytes.fetch_add(b.len() as u64, Ordering::Relaxed);
                                    ok.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    gone.fetch_add(1, Ordering::Relaxed);
                                }
                                if f.tries > 1 {
                                    retried.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Err(e) => {
                                *err.lock().unwrap() = Some(format!("{e:#}"));
                                return;
                            }
                        }
                    });
                }
            });
            let t = t0.elapsed().as_secs_f64();
            let (b, k) = (bytes.load(Ordering::Relaxed), ok.load(Ordering::Relaxed));
            println!(
                "parallel {n}: {k} objects, {:.1} MB in {t:.1} s = {:.1} GET/s, {:.1} MB/s; missing {}; retried {}; stop: {}",
                b as f64 / 1e6,
                k as f64 / t,
                b as f64 / 1e6 / t,
                gone.load(Ordering::Relaxed),
                retried.load(Ordering::Relaxed),
                err.into_inner().unwrap().unwrap_or_else(|| "none".into())
            );
            Ok(())
        }
        Tool::SliceCover(a) => {
            let d = RunData::load(&a.runs)?;
            let p = project(&d, &level(&a.level));
            let mut covered: HashSet<Id> = HashSet::new();
            let mut n = 0usize;
            let mut xdr_ledgers = 0u64;
            for (seq, sh, ix) in &d.occ {
                let ids: Vec<Id> = d.shapes[sh].comps().map(|c| p.comp[c]).collect();
                if ids.iter().any(|i| !covered.contains(i)) {
                    covered.extend(ids);
                    n += 1;
                    xdr_ledgers += d
                        .ledgers
                        .get(seq)
                        .map(|l| l.xdr_bytes / l.tx_count.max(1) as u64)
                        .unwrap_or(0);
                    println!("{seq}\t{}", ix[0]);
                }
            }
            eprintln!(
                "slices {n}; components covered {}; est. xdr bytes {xdr_ledgers}",
                covered.len()
            );
            Ok(())
        }
        Tool::LedgerSep(a) => {
            let d = RunData::load(&a.runs)?;
            let p = project(&d, &level("G3"));
            println!("seq\tL_id\tneighbours_in_run\tsame_L_id\tL_tokens");
            for s in &a.seqs {
                let Some(l) = d.ledgers.get(s) else {
                    println!("{s}\t-\tnot in the run");
                    continue;
                };
                let id = p
                    .comp
                    .get(&l.ledger_shape)
                    .copied()
                    .unwrap_or(l.ledger_shape);
                let lo = s.saturating_sub(a.window);
                let nb: Vec<(&u32, &LRow)> = d
                    .ledgers
                    .range(lo..=s + a.window)
                    .filter(|(q, _)| *q != s)
                    .collect();
                let same = nb
                    .iter()
                    .filter(|(_, r)| {
                        p.comp
                            .get(&r.ledger_shape)
                            .copied()
                            .unwrap_or(r.ledger_shape)
                            == id
                    })
                    .count();
                let nt = d
                    .comps
                    .get(&l.ledger_shape)
                    .map(|c| c.tokens.len())
                    .unwrap_or(0);
                println!("{s}\t{}\t{}\t{same}\t{nt}", hex::encode(id), nb.len());
            }
            Ok(())
        }
        Tool::Grep(a) => {
            let d = RunData::load(&a.runs)?;
            let mut ids: Vec<(&Id, &Comp)> = d
                .comps
                .iter()
                .filter(|(_, c)| c.tokens.iter().any(|t| t.contains(&a.token)))
                .collect();
            ids.sort_by_key(|x| x.0);
            for (i, c) in ids {
                println!(
                    "{}\t{}\t{}",
                    hex::encode(i),
                    c.kind,
                    c.op_type.clone().unwrap_or_default()
                );
                for t in c.tokens.iter().filter(|t| a.full || t.contains(&a.token)) {
                    println!("    {t}");
                }
            }
            Ok(())
        }
        Tool::Refusals(a) => {
            let d = RunData::load(&a.runs)?;
            println!("seq\tstage\tclass\terror\tnote");
            for (s, st, c, e, n) in &d.refusals {
                println!("{s}\t{st}\t{c}\t{e}\t{n}");
            }
            Ok(())
        }
        Tool::Recall(a) => super::recall::recall(a),
        Tool::Heldout(a) => super::recall::heldout(a),
    }?;
    Ok(ExitCode::SUCCESS)
}

// ---------- loading ----------

#[allow(dead_code)]
pub struct Comp {
    pub kind: char,
    pub op_type: Option<String>,
    pub tokens: Vec<String>,
}

pub struct Shape {
    pub e: Id,
    pub a: Option<Id>,
    pub r: Id,
    pub f: Id,
    pub m: Id,
    pub ops: Vec<(Id, String)>,
    pub opc: String,
}

impl Shape {
    pub fn comps(&self) -> impl Iterator<Item = &Id> {
        [&self.e, &self.r, &self.f, &self.m]
            .into_iter()
            .chain(self.a.iter())
            .chain(self.ops.iter().map(|o| &o.0))
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct LRow {
    pub object_bytes: u64,
    pub xdr_bytes: u64,
    pub tx_count: u32,
    pub header_version: u32,
    pub protocol_applied: u32,
    pub lcm_arm: u32,
    pub ledger_shape: Id,
    pub invariants: u32,
    pub md5_ok: Option<bool>,
}

#[derive(Default)]
pub struct RunData {
    pub comps: HashMap<Id, Comp>,
    pub shapes: HashMap<Id, Shape>,
    /// (seq, tx shape, apply indexes)
    pub occ: Vec<(u32, Id, Vec<u16>)>,
    pub ledgers: BTreeMap<u32, LRow>,
    pub vocab: BTreeMap<(String, Vec<u8>), (u64, u64)>,
    pub refusals: Vec<(u32, String, String, String, String)>,
    pub core: HashMap<u32, String>,
    /// partition dir -> file -> bytes
    pub files: BTreeMap<String, BTreeMap<String, u64>>,
    pub part_of: HashMap<u32, String>,
}

pub(super) fn rows(path: &Path) -> Result<Vec<Vec<Field>>> {
    let r =
        SerializedFileReader::new(File::open(path).with_context(|| path.display().to_string())?)?;
    let mut out = Vec::new();
    for row in r.get_row_iter(None)? {
        let row = row?;
        out.push(row.get_column_iter().map(|(_, f)| f.clone()).collect());
    }
    Ok(out)
}

pub(super) fn int(f: &Field) -> i64 {
    match f {
        Field::Int(i) => *i as i64,
        Field::Long(i) => *i,
        _ => 0,
    }
}
pub(super) fn bytes(f: &Field) -> Vec<u8> {
    match f {
        Field::Bytes(b) => b.data().to_vec(),
        Field::Str(s) => s.as_bytes().to_vec(),
        _ => Vec::new(),
    }
}
pub(super) fn text(f: &Field) -> Option<String> {
    match f {
        Field::Str(s) => Some(s.clone()),
        Field::Bytes(b) => Some(String::from_utf8_lossy(b.data()).to_string()),
        _ => None,
    }
}
pub(super) fn id(f: &Field) -> Id {
    bytes(f).try_into().unwrap_or([0; 16])
}
fn unhex16(s: &str) -> Id {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or([0; 16])
}

/// A `components.parquet` row (component, kind, op_type, tokens, …) as a [`Comp`].
pub fn comp_of_row(r: &[Field]) -> Comp {
    Comp {
        kind: text(&r[1])
            .unwrap_or_default()
            .chars()
            .next()
            .unwrap_or('?'),
        op_type: text(&r[2]),
        tokens: text(&r[3])
            .unwrap_or_default()
            .split('\n')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
    }
}

/// A `tx_shapes.parquet` row (tx_shape, e, a, r, f, m, ops, op_count_class, …) as a [`Shape`].
pub fn shape_of_row(r: &[Field]) -> Shape {
    let a = bytes(&r[2]);
    Shape {
        e: id(&r[1]),
        a: (a.len() == 16).then(|| a.try_into().unwrap()),
        r: id(&r[3]),
        f: id(&r[4]),
        m: id(&r[5]),
        ops: text(&r[6])
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| {
                let (i, c) = s.split_once('*').unwrap_or((s, "1"));
                (unhex16(i), c.to_string())
            })
            .collect(),
        opc: text(&r[7]).unwrap_or_default(),
    }
}

impl RunData {
    pub fn load(runs: &[PathBuf]) -> Result<RunData> {
        let mut d = RunData::default();
        for run in runs {
            for p in super::store::partitions(run)? {
                let pname = p.file_name().unwrap().to_string_lossy().to_string();
                let m: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(p.join("MANIFEST.json"))?)?;
                let fe = d
                    .files
                    .entry(format!("{}/{pname}", run.display()))
                    .or_default();
                for (n, f) in m["files"].as_object().context("files")? {
                    fe.insert(n.clone(), f["bytes"].as_u64().unwrap_or(0));
                }
                fe.insert(
                    "MANIFEST.json".into(),
                    std::fs::metadata(p.join("MANIFEST.json"))?.len(),
                );
                for r in rows(&p.join("components.parquet"))? {
                    d.comps.entry(id(&r[0])).or_insert_with(|| comp_of_row(&r));
                }
                for r in rows(&p.join("tx_shapes.parquet"))? {
                    d.shapes
                        .entry(id(&r[0]))
                        .or_insert_with(|| shape_of_row(&r));
                }
                for r in rows(&p.join("occurrences.parquet"))? {
                    let ix = bytes(&r[3])
                        .chunks(2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect();
                    d.occ.push((int(&r[0]) as u32, id(&r[1]), ix));
                }
                for r in rows(&p.join("ledgers.parquet"))? {
                    let seq = int(&r[0]) as u32;
                    d.part_of.insert(seq, format!("{}/{pname}", run.display()));
                    d.ledgers.insert(
                        seq,
                        LRow {
                            object_bytes: int(&r[1]) as u64,
                            xdr_bytes: int(&r[2]) as u64,
                            md5_ok: match &r[5] {
                                Field::Bool(b) => Some(*b),
                                _ => None,
                            },
                            header_version: int(&r[7]) as u32,
                            protocol_applied: int(&r[8]) as u32,
                            lcm_arm: int(&r[9]) as u32,
                            tx_count: int(&r[12]) as u32,
                            ledger_shape: id(&r[15]),
                            invariants: int(&r[16]) as u32,
                        },
                    );
                }
                for r in rows(&p.join("vocab.parquet"))? {
                    let e = d
                        .vocab
                        .entry((text(&r[0]).unwrap_or_default(), bytes(&r[1])))
                        .or_default();
                    e.0 += int(&r[2]) as u64;
                    e.1 += int(&r[3]) as u64;
                }
                if p.join("refusals.parquet").exists() {
                    for r in rows(&p.join("refusals.parquet"))? {
                        d.refusals.push((
                            int(&r[0]) as u32,
                            text(&r[1]).unwrap_or_default(),
                            text(&r[2]).unwrap_or_default(),
                            text(&r[3]).unwrap_or_default(),
                            text(&r[4]).unwrap_or_default(),
                        ));
                    }
                }
                let prov = xdrcheck_xdr::batch::decompress_bounded(
                    &std::fs::read(p.join("provenance.jsonl.zst"))?,
                    1 << 30,
                )?;
                for l in prov.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                    let v: serde_json::Value = serde_json::from_slice(l)?;
                    if let (Some(s), Some(c)) = (v["seq"].as_u64(), v["core_version"].as_str()) {
                        d.core.insert(s as u32, c.to_string());
                    }
                }
            }
        }
        d.occ.sort();
        d.occ.dedup();
        Ok(d)
    }
}

// ---------- views ----------

/// A projection of the stored G3 tokens: the kinds kept, minus dropped kinds and classes.
#[derive(Clone, Debug)]
pub struct View {
    pub name: String,
    pub kinds: BTreeSet<String>,
    pub drop_classes: BTreeSet<String>,
}

/// A level (`G0`…`G3`) or a custom set of kinds joined by `+` (`T+X+K+V+R+L`).
pub fn level(name: &str) -> View {
    if name.contains('+') {
        return View {
            name: name.into(),
            kinds: name.split('+').map(|s| s.to_string()).collect(),
            drop_classes: BTreeSet::new(),
        };
    }
    let k: &[&str] = match name {
        "G0" => &["T"],
        "G1" => &["T", "A", "O", "E"],
        "G2" => &["T", "A", "O", "E", "L", "V", "S", "K", "X"],
        _ => &["T", "A", "O", "E", "L", "V", "S", "K", "X", "D", "R"],
    };
    View {
        name: name.into(),
        kinds: k.iter().map(|s| s.to_string()).collect(),
        drop_classes: BTreeSet::new(),
    }
}

impl View {
    pub fn keeps(&self, t: &str) -> bool {
        let mut it = t.splitn(3, '|');
        let (k, c) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
        self.kinds.contains(k) && !self.drop_classes.contains(c)
    }
}

pub struct Projected {
    pub comp: HashMap<Id, Id>,
    pub shape: HashMap<Id, Id>,
}

/// The level tag hashed into every projected id of view `v`.
pub fn view_tag(v: &View) -> String {
    format!(
        "{}|{}",
        v.kinds.iter().cloned().collect::<Vec<_>>().join(","),
        v.drop_classes.iter().cloned().collect::<Vec<_>>().join(",")
    )
}

/// The id of one component under view `v` (`tag` = [`view_tag`] of `v`).
pub fn project_comp(tag: &str, v: &View, c: &Comp) -> Id {
    shape_id(
        tag,
        &c.kind.to_string(),
        c.tokens.iter().filter(|t| v.keeps(t)).map(|s| s.as_str()),
    )
}

pub fn project(d: &RunData, v: &View) -> Projected {
    let tag = view_tag(v);
    let comp: HashMap<Id, Id> = d
        .comps
        .iter()
        .map(|(i, c)| (*i, project_comp(&tag, v, c)))
        .collect();
    let shape = d
        .shapes
        .iter()
        .map(|(i, s)| {
            let p = |x: &Id| hex::encode(comp.get(x).copied().unwrap_or(*x));
            let mut refs: BTreeSet<String> = [
                format!("E:{}", p(&s.e)),
                format!("R:{}", p(&s.r)),
                format!("F:{}", p(&s.f)),
                format!("M:{}", p(&s.m)),
            ]
            .into();
            if let Some(a) = &s.a {
                refs.insert(format!("A:{}", p(a)));
            }
            for (o, c) in &s.ops {
                refs.insert(format!("O:{}*{c}", p(o)));
            }
            refs.insert(format!("ops={}", s.opc));
            (*i, shape_id(&tag, "tx", refs.iter().map(|s| s.as_str())))
        })
        .collect();
    Projected { comp, shape }
}

fn counts(d: &RunData, p: &Projected) -> (BTreeMap<char, usize>, usize) {
    let mut per: BTreeMap<char, HashSet<Id>> = BTreeMap::new();
    for (i, c) in &d.comps {
        per.entry(c.kind).or_default().insert(p.comp[i]);
    }
    let shapes: HashSet<Id> = p.shape.values().copied().collect();
    (
        per.into_iter().map(|(k, s)| (k, s.len())).collect(),
        shapes.len(),
    )
}

fn ablate(d: &RunData) -> Result<()> {
    println!("view\tE\tA\tO\tR\tF\tM\tL\ttx_shapes");
    let line = |name: &str, v: &View| {
        let (c, s) = counts(d, &project(d, v));
        let g = |k| c.get(&k).copied().unwrap_or(0);
        println!(
            "{name}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{s}",
            g('E'),
            g('A'),
            g('O'),
            g('R'),
            g('F'),
            g('M'),
            g('L')
        );
    };
    for l in ["G0", "G1", "G2", "G3"] {
        line(l, &level(l));
    }
    for k in ["A", "O", "E", "L", "V", "S", "K", "X", "D", "R"] {
        let mut v = level("G3");
        v.kinds.remove(k);
        line(&format!("G3 -kind {k}"), &v);
    }
    let mut classes = BTreeSet::new();
    for c in d.comps.values() {
        for t in &c.tokens {
            let mut it = t.splitn(3, '|');
            let k = it.next().unwrap_or("");
            if k != "T" {
                classes.insert(format!("{k}|{}", it.next().unwrap_or("")));
            }
        }
    }
    for kc in classes {
        let (k, c) = kc.split_once('|').unwrap();
        if ["A", "O", "E"].contains(&k) && c != "elemopt" {
            continue;
        }
        let mut v = level("G3");
        v.drop_classes.insert(c.to_string());
        line(&format!("G3 -class {kc}"), &v);
    }
    Ok(())
}

// ---------- cover ----------

/// Kept-ledger cover of every id: the §4.4 rule (ids ascending; an uncovered id keeps its
/// smallest ledger by (bytes, seq), and everything that ledger holds is covered) and the classic
/// greedy (the ledger covering most uncovered ids first). Returns (kept ledgers, kept bytes) of each.
pub fn cover_of(
    ids_by_ledger: &BTreeMap<u32, BTreeSet<Id>>,
    bytes: &BTreeMap<u32, u64>,
) -> ((usize, u64), (usize, u64)) {
    let mut ledgers_of: BTreeMap<Id, Vec<u32>> = BTreeMap::new();
    for (s, ids) in ids_by_ledger {
        for i in ids {
            ledgers_of.entry(*i).or_default().push(*s);
        }
    }
    let b = |s: &u32| bytes.get(s).copied().unwrap_or(0);
    let mut covered: HashSet<Id> = HashSet::new();
    let mut kept = BTreeSet::new();
    for (i, ls) in &ledgers_of {
        if covered.contains(i) {
            continue;
        }
        let s = *ls.iter().min_by_key(|s| (b(s), **s)).unwrap();
        kept.insert(s);
        covered.extend(ids_by_ledger[&s].iter().copied());
    }
    let rule = (kept.len(), kept.iter().map(b).sum());
    // Greedy (lazy evaluation of gains).
    let mut covered: HashSet<Id> = HashSet::new();
    let mut heap: std::collections::BinaryHeap<(usize, std::cmp::Reverse<u32>)> = ids_by_ledger
        .iter()
        .map(|(s, ids)| (ids.len(), std::cmp::Reverse(*s)))
        .collect();
    let mut gkept = Vec::new();
    while covered.len() < ledgers_of.len() {
        let Some((g, std::cmp::Reverse(s))) = heap.pop() else {
            break;
        };
        let now = ids_by_ledger[&s]
            .iter()
            .filter(|i| !covered.contains(*i))
            .count();
        if now == 0 {
            continue;
        }
        if now < g {
            heap.push((now, std::cmp::Reverse(s)));
            continue;
        }
        gkept.push(s);
        covered.extend(ids_by_ledger[&s].iter().copied());
    }
    (rule, (gkept.len(), gkept.iter().map(b).sum()))
}

pub fn ids_by_ledger(
    d: &RunData,
    p: &Projected,
    what: &str,
    keep: &dyn Fn(u32) -> bool,
) -> BTreeMap<u32, BTreeSet<Id>> {
    let mut m: BTreeMap<u32, BTreeSet<Id>> = BTreeMap::new();
    for (seq, sh, _) in &d.occ {
        if !keep(*seq) {
            continue;
        }
        let e = m.entry(*seq).or_default();
        if what == "tx" {
            e.insert(p.shape[sh]);
        } else {
            for c in d.shapes[sh].comps() {
                e.insert(p.comp[c]);
            }
        }
    }
    if what != "tx" {
        for (seq, l) in &d.ledgers {
            if keep(*seq) {
                m.entry(*seq).or_default().insert(
                    p.comp
                        .get(&l.ledger_shape)
                        .copied()
                        .unwrap_or(l.ledger_shape),
                );
            }
        }
    }
    m
}

fn cover(d: &RunData, plan: Option<&Path>) -> Result<()> {
    let bytes: BTreeMap<u32, u64> = d
        .ledgers
        .iter()
        .map(|(s, l)| (*s, l.object_bytes))
        .collect();
    let plan = plan.map(read_plan).transpose()?;
    // Prefix fractions of the random strata (by hash rank) for the growth curve.
    let fracs = [0.125, 0.25, 0.5, 1.0];
    println!(
        "level\tobject\tledgers_in\tdistinct\trule_kept\trule_bytes\tgreedy_kept\tgreedy_bytes"
    );
    for l in ["G0", "G1", "G2", "G3"] {
        let p = project(d, &level(l));
        for what in ["components", "tx"] {
            let all = ids_by_ledger(d, &p, what, &|_| true);
            let distinct: HashSet<&Id> = all.values().flatten().collect();
            let ((rk, rb), (gk, gb)) = cover_of(&all, &bytes);
            println!(
                "{l}\t{what}\t{}\t{}\t{rk}\t{rb}\t{gk}\t{gb}",
                all.len(),
                distinct.len()
            );
            if let Some(plan) = &plan {
                let rand: Vec<u32> = rank_order(plan, |r| {
                    r.set == "sample" && r.reason.starts_with("random")
                });
                for f in fracs {
                    let n = ((rand.len() as f64) * f) as usize;
                    let keep: HashSet<u32> = rand[..n].iter().copied().collect();
                    let sub = ids_by_ledger(d, &p, what, &|s| keep.contains(&s));
                    let distinct: HashSet<&Id> = sub.values().flatten().collect();
                    let ((rk, rb), (gk, gb)) = cover_of(&sub, &bytes);
                    println!(
                        "{l}\t{what}@random{f}\t{}\t{}\t{rk}\t{rb}\t{gk}\t{gb}",
                        sub.len(),
                        distinct.len()
                    );
                }
            }
        }
    }
    Ok(())
}

// ---------- plan, saturation ----------

pub struct PlanRow {
    pub seq: u32,
    pub era: String,
    pub set: String,
    pub reason: String,
}

pub fn read_plan(p: &Path) -> Result<Vec<PlanRow>> {
    let t = std::fs::read_to_string(p)?;
    let mut v = Vec::new();
    for l in t.lines().skip(1) {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 4 {
            continue;
        }
        v.push(PlanRow {
            seq: f[0].parse()?,
            era: f[1].to_string(),
            set: f[2].to_string(),
            reason: f[3].to_string(),
        });
    }
    Ok(v)
}

fn rank(era: &str, seq: u32) -> [u8; 32] {
    Sha256::digest(format!("xcc-scan-pilot-2026-11-16/{era}/{seq}").as_bytes()).into()
}

pub fn rank_order(plan: &[PlanRow], f: impl Fn(&PlanRow) -> bool) -> Vec<u32> {
    let mut v: Vec<(&str, u32)> = plan
        .iter()
        .filter(|r| f(r))
        .map(|r| (r.era.as_str(), r.seq))
        .collect();
    v.sort_by_key(|(e, s)| rank(e, *s));
    v.into_iter().map(|x| x.1).collect()
}

fn saturation(d: &RunData, plan: &Path) -> Result<()> {
    let plan = read_plan(plan)?;
    let mut eras: Vec<String> = plan
        .iter()
        .map(|r| r.era.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    eras.sort_by_key(|e| e.parse::<u32>().unwrap_or(0));
    let mut occ_by: HashMap<u32, Vec<(Id, usize)>> = HashMap::new();
    for (s, sh, ix) in &d.occ {
        occ_by.entry(*s).or_default().push((*sh, ix.len()));
    }
    println!("level\tobject\tera\tn_train\tdistinct_train\tchao1\theldout_ledgers\tunseen_ids\tnew_per_10k\theldout_txs\tshare_txs_unseen\tbeta");
    for l in ["G0", "G1", "G2", "G3"] {
        let p = project(d, &level(l));
        for what in ["O", "tx"] {
            for era in &eras {
                let train = rank_order(&plan, |r| {
                    &r.era == era && r.set == "sample" && r.reason.starts_with("random")
                });
                let train: Vec<u32> = train
                    .into_iter()
                    .filter(|s| d.ledgers.contains_key(s))
                    .collect();
                let held: Vec<u32> = plan
                    .iter()
                    .filter(|r| &r.era == era && r.set == "heldout")
                    .map(|r| r.seq)
                    .filter(|s| d.ledgers.contains_key(s))
                    .collect();
                if train.is_empty() || held.is_empty() {
                    continue;
                }
                let ids_of = |s: u32| -> Vec<(Id, usize)> {
                    let mut v = Vec::new();
                    for (sh, n) in occ_by.get(&s).map(|x| &x[..]).unwrap_or(&[]) {
                        if what == "tx" {
                            v.push((p.shape[sh], *n));
                        } else {
                            for o in &d.shapes[sh].ops {
                                v.push((p.comp[&o.0], *n));
                            }
                        }
                    }
                    v
                };
                let mut prev: Option<(usize, usize)> = None;
                for n in [250usize, 500, 1000, 2500, usize::MAX] {
                    let n = n.min(train.len());
                    let mut seen: HashMap<Id, usize> = HashMap::new();
                    for &s in &train[..n] {
                        let ids: HashSet<Id> = ids_of(s).into_iter().map(|x| x.0).collect();
                        for i in ids {
                            *seen.entry(i).or_default() += 1;
                        }
                    }
                    let f1 = seen.values().filter(|&&c| c == 1).count() as f64;
                    let f2 = seen.values().filter(|&&c| c == 2).count() as f64;
                    let chao = seen.len() as f64
                        + if f2 > 0.0 {
                            f1 * f1 / (2.0 * f2)
                        } else {
                            f1 * (f1 - 1.0) / 2.0
                        };
                    let mut unseen = HashSet::new();
                    let (mut txs, mut txs_unseen) = (0usize, 0usize);
                    for &s in &held {
                        for (sh, cnt) in occ_by.get(&s).map(|x| &x[..]).unwrap_or(&[]) {
                            txs += cnt;
                            let ids: Vec<Id> = if what == "tx" {
                                vec![p.shape[sh]]
                            } else {
                                d.shapes[sh].ops.iter().map(|o| p.comp[&o.0]).collect()
                            };
                            let new: Vec<&Id> =
                                ids.iter().filter(|i| !seen.contains_key(*i)).collect();
                            if !new.is_empty() {
                                txs_unseen += cnt;
                            }
                            unseen.extend(new.into_iter().copied());
                        }
                    }
                    let beta = match prev {
                        Some((pn, ps)) if pn < n && ps > 0 => {
                            ((seen.len() as f64) / ps as f64).ln() / ((n as f64) / pn as f64).ln()
                        }
                        _ => f64::NAN,
                    };
                    println!(
                        "{l}\t{what}\t{era}\t{n}\t{}\t{chao:.0}\t{}\t{}\t{:.1}\t{txs}\t{:.4}\t{beta:.2}",
                        seen.len(),
                        held.len(),
                        unseen.len(),
                        unseen.len() as f64 * 10_000.0 / held.len() as f64,
                        if txs > 0 { txs_unseen as f64 / txs as f64 } else { 0.0 }
                    );
                    prev = Some((n, seen.len()));
                    if n == train.len() {
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

// ---------- vocab, size, format, ledgers, diff ----------

fn vocab(d: &RunData, top: usize) -> Result<()> {
    for kind in ["event-symbol", "map-key"] {
        let mut v: Vec<(&Vec<u8>, &(u64, u64))> = d
            .vocab
            .iter()
            .filter(|((k, _), _)| k == kind)
            .map(|((_, t), c)| (t, c))
            .collect();
        v.sort_by(|a, b| {
            b.1 .1
                .cmp(&a.1 .1)
                .then(b.1 .0.cmp(&a.1 .0))
                .then(a.0.cmp(b.0))
        });
        println!("# {kind}: {} distinct", v.len());
        println!("rank\ttext\tledgers\tevents");
        for (i, (t, (e, l))) in v.iter().take(top).enumerate() {
            println!(
                "{}\t{}\t{l}\t{e}",
                i + 1,
                String::from_utf8_lossy(t).escape_debug()
            );
        }
    }
    Ok(())
}

fn size(runs: &[PathBuf], d: &RunData, plan: &Path) -> Result<()> {
    let plan = read_plan(plan)?;
    let era_of: HashMap<u32, String> = plan.iter().map(|r| (r.seq, r.era.clone())).collect();
    // Majority era of each partition directory.
    let mut part_eras: HashMap<String, BTreeMap<String, usize>> = HashMap::new();
    for (s, p) in &d.part_of {
        *part_eras
            .entry(p.clone())
            .or_default()
            .entry(era_of.get(s).cloned().unwrap_or("?".into()))
            .or_default() += 1;
    }
    #[derive(Default)]
    struct E {
        ledgers: u64,
        txs: u64,
        obj: u64,
        xdr: u64,
        rec: u64,
        dict: u64,
        other: u64,
    }
    let mut by: BTreeMap<u32, E> = BTreeMap::new();
    let mut tot = E::default();
    for (p, files) in &d.files {
        let era: u32 = part_eras
            .get(p)
            .and_then(|m| m.iter().max_by_key(|x| x.1))
            .and_then(|x| x.0.parse().ok())
            .unwrap_or(0);
        let e = by.entry(era).or_default();
        for (n, b) in files {
            match n.as_str() {
                "ledgers.parquet" | "occurrences.parquet" => e.rec += b,
                "components.parquet" | "tx_shapes.parquet" => e.dict += b,
                _ => e.other += b,
            }
        }
    }
    for (s, l) in &d.ledgers {
        let era: u32 = d
            .part_of
            .get(s)
            .and_then(|p| part_eras.get(p))
            .and_then(|m| m.iter().max_by_key(|x| x.1))
            .and_then(|x| x.0.parse().ok())
            .unwrap_or(0);
        let e = by.entry(era).or_default();
        e.ledgers += 1;
        e.txs += l.tx_count as u64;
        e.obj += l.object_bytes;
        e.xdr += l.xdr_bytes;
    }
    let _ = runs;
    println!("era\tledgers\ttxs\tobject_bytes_per_ledger\trecord_bytes_per_ledger\tdict_bytes_per_ledger\tother_bytes_per_ledger\trecord_bytes_per_tx\tdict_bytes_per_tx\txdr_bytes_per_ledger\txdr_bytes_per_tx");
    for (era, e) in &by {
        let pl = |x: u64| x as f64 / e.ledgers.max(1) as f64;
        let pt = |x: u64| x as f64 / e.txs.max(1) as f64;
        println!(
            "{era}\t{}\t{}\t{:.0}\t{:.1}\t{:.1}\t{:.1}\t{:.3}\t{:.3}\t{:.0}\t{:.0}",
            e.ledgers,
            e.txs,
            pl(e.obj),
            pl(e.rec),
            pl(e.dict),
            pl(e.other),
            pt(e.rec),
            pt(e.dict),
            pl(e.xdr),
            pt(e.xdr)
        );
        tot.ledgers += e.ledgers;
        tot.txs += e.txs;
        tot.obj += e.obj;
        tot.xdr += e.xdr;
        tot.rec += e.rec;
        tot.dict += e.dict;
        tot.other += e.other;
    }
    println!(
        "all\t{}\t{}\t{:.0}\t{:.1}\t{:.1}\t{:.1}\t{:.3}\t{:.3}\t{:.0}\t{:.0}",
        tot.ledgers,
        tot.txs,
        tot.obj as f64 / tot.ledgers.max(1) as f64,
        tot.rec as f64 / tot.ledgers.max(1) as f64,
        tot.dict as f64 / tot.ledgers.max(1) as f64,
        tot.other as f64 / tot.ledgers.max(1) as f64,
        tot.rec as f64 / tot.txs.max(1) as f64,
        tot.dict as f64 / tot.txs.max(1) as f64,
        tot.xdr as f64 / tot.ledgers.max(1) as f64,
        tot.xdr as f64 / tot.txs.max(1) as f64
    );
    Ok(())
}

fn format(d: &RunData) -> Result<()> {
    // Per ledger: the T tokens of its L component and of its transactions' M and F components.
    let mut by_seq: HashMap<u32, BTreeSet<&str>> = HashMap::new();
    for (s, sh, _) in &d.occ {
        let e = by_seq.entry(*s).or_default();
        let shp = &d.shapes[sh];
        for c in [&shp.m, &shp.f, &shp.e, &shp.r]
            .into_iter()
            .chain(shp.ops.iter().map(|o| &o.0))
        {
            for t in &d.comps[c].tokens {
                if t.starts_with("T|") || t.starts_with("X|") {
                    e.insert(t.as_str());
                }
            }
        }
    }
    let probes: &[(&str, &[&str])] = &[
        ("lcm_ext", &["LedgerCloseMetaExt::"]),
        ("tx_meta", &["T|arm|TransactionMeta::"]),
        ("soroban_meta_ext", &["SorobanTransactionMetaExt::"]),
        ("diag_events", &["ContractEventType=DIAGNOSTIC"]),
        ("tx_events", &["TransactionEventStage="]),
        ("fee_events", &["#ev=CONTRACT:fee:"]),
        ("transfer_events", &["#ev=CONTRACT:transfer:"]),
        ("restored", &["LedgerEntryChangeType=LEDGER_ENTRY_RESTORED"]),
        ("header_ext", &["LedgerHeaderExt::"]),
        ("stellar_value_ext", &["StellarValueExt::"]),
        (
            "tx_set",
            &["TransactionPhase::", "T|arm|GeneralizedTransactionSet::"],
        ),
        ("envelopes", &["T|arm|TransactionEnvelope::"]),
    ];
    let mut groups: BTreeMap<(String, u32, u32), (u64, u32, BTreeMap<&str, BTreeSet<String>>)> =
        BTreeMap::new();
    let mut invs: BTreeMap<(String, u32, u32), ([u64; 5], Vec<u32>)> = BTreeMap::new();
    for (s, l) in &d.ledgers {
        let core = d.core.get(s).cloned().unwrap_or_else(|| "?".into());
        let core = core.split(" (").next().unwrap_or(&core).to_string();
        let g = groups
            .entry((core, l.protocol_applied, l.lcm_arm))
            .or_insert((0, *s, BTreeMap::new()));
        g.0 += 1;
        let inv = invs
            .entry((
                d.core
                    .get(s)
                    .cloned()
                    .unwrap_or_default()
                    .split(" (")
                    .next()
                    .unwrap_or("")
                    .to_string(),
                l.protocol_applied,
                l.lcm_arm,
            ))
            .or_insert(([0u64; 5], Vec::new()));
        for (i, bit) in [32u32, 64, 128].into_iter().enumerate() {
            if l.invariants & bit == 0 {
                inv.0[i] += 1;
                if inv.1.len() < 3 {
                    inv.1.push(*s);
                }
            }
        }
        if l.md5_ok == Some(false) {
            inv.0[3] += 1;
        }
        if l.md5_ok.is_none() {
            inv.0[4] += 1;
        }
        let mut toks: BTreeSet<&str> = by_seq.get(s).cloned().unwrap_or_default();
        if let Some(c) = d.comps.get(&l.ledger_shape) {
            toks.extend(c.tokens.iter().map(|s| s.as_str()));
        }
        for (name, pats) in probes {
            let e = g.2.entry(name).or_default();
            for t in &toks {
                for pat in pats.iter() {
                    if t.contains(pat) {
                        let v = t
                            .split(pat)
                            .nth(1)
                            .unwrap_or("")
                            .split([':', '|', '[', ','])
                            .next()
                            .unwrap_or("")
                            .to_string();
                        e.insert(if v.is_empty() { "yes".into() } else { v });
                    }
                }
            }
        }
    }
    let names: Vec<&str> = probes.iter().map(|p| p.0).collect();
    println!(
        "core\tprotocol_applied\tlcm_arm\tledgers\texample\t{}",
        names.join("\t")
    );
    for ((core, p, arm), (n, ex, m)) in &groups {
        let cols: Vec<String> = names
            .iter()
            .map(|k| {
                m.get(k)
                    .map(|s| s.iter().cloned().collect::<Vec<_>>().join(","))
                    .unwrap_or_default()
            })
            .map(|s| if s.is_empty() { "-".into() } else { s })
            .collect();
        println!("{core}\t{p}\tv{arm}\t{n}\t{ex}\t{}", cols.join("\t"));
    }
    println!();
    println!("core\tprotocol_applied\tlcm_arm\tmeta_mismatch\ttx_set_hash_fail\tresult_hash_fail\tmd5_etag_fail\tno_etag\texamples");
    for ((core, p, arm), (c, ex)) in &invs {
        println!(
            "{core}\t{p}\tv{arm}\t{}\t{}\t{}\t{}\t{}\t{ex:?}",
            c[0], c[1], c[2], c[3], c[4]
        );
    }
    Ok(())
}

/// `comp` is a component id (hex), or `token:<text>` for every component holding a token that
/// contains the text.
fn ledgers(d: &RunData, comp: &str) -> Result<()> {
    let wanted: HashSet<Id> = if let Some(t) = comp.strip_prefix("token:") {
        d.comps
            .iter()
            .filter(|(_, c)| c.tokens.iter().any(|x| x.contains(t)))
            .map(|(i, _)| *i)
            .collect()
    } else {
        let c = unhex16(comp);
        if !d.comps.contains_key(&c) {
            bail!("no component {comp}");
        }
        [c].into()
    };
    let shapes: HashSet<&Id> = d
        .shapes
        .iter()
        .filter(|(_, s)| s.comps().any(|x| wanted.contains(x)))
        .map(|(i, _)| i)
        .collect();
    let mut out: BTreeMap<u32, Vec<u16>> = BTreeMap::new();
    for (s, sh, ix) in &d.occ {
        if shapes.contains(sh) {
            out.entry(*s).or_default().extend(ix);
        }
    }
    println!(
        "# component {comp}: {} transaction shapes, {} ledgers",
        shapes.len(),
        out.len()
    );
    for (s, ix) in out {
        let mut ix = ix;
        ix.sort();
        println!(
            "{s}\t{}",
            ix.iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    Ok(())
}

fn diff(a: &Path, b: &Path) -> Result<()> {
    let pa = super::store::partitions(a)?;
    let pb = super::store::partitions(b)?;
    let names = |v: &[PathBuf]| {
        v.iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect::<BTreeSet<_>>()
    };
    let (na, nb) = (names(&pa), names(&pb));
    let mut diffs = 0;
    let mut files = 0;
    for n in na.symmetric_difference(&nb) {
        println!("only in one run: {n}");
        diffs += 1;
    }
    for n in na.intersection(&nb) {
        let ma: serde_json::Value =
            serde_json::from_slice(&std::fs::read(a.join(n).join("MANIFEST.json"))?)?;
        let mb: serde_json::Value =
            serde_json::from_slice(&std::fs::read(b.join(n).join("MANIFEST.json"))?)?;
        let fa = ma["files"].as_object().cloned().unwrap_or_default();
        for (f, v) in &fa {
            files += 1;
            let ha = xdrcheck_xdr::sha256_hex(&std::fs::read(a.join(n).join(f))?);
            let hb = std::fs::read(b.join(n).join(f))
                .map(|x| xdrcheck_xdr::sha256_hex(&x))
                .unwrap_or_default();
            if ha != hb || v["sha256"] != mb["files"][f]["sha256"] {
                println!("differs: {n}/{f}");
                diffs += 1;
            }
        }
        files += 1;
        if std::fs::read(a.join(n).join("MANIFEST.json"))?
            != std::fs::read(b.join(n).join("MANIFEST.json"))?
        {
            println!("differs: {n}/MANIFEST.json");
            diffs += 1;
        }
    }
    println!(
        "partitions {} / {}; files compared {files}; differences {diffs}",
        na.len(),
        nb.len()
    );
    Ok(())
}

/// Per era: greedy cover of the hash-ranked random ledgers at growing prefixes, a power law fitted on
/// the segments, extrapolated to the era's ledger count. The sum over eras counts a shape seen in two
/// eras twice (an upper bound).
fn cover_extrapolate(
    d: &RunData,
    plan: &Path,
    plan_json: &Path,
    levels: &str,
    xdr: bool,
) -> Result<()> {
    let plan = read_plan(plan)?;
    let pj: serde_json::Value = serde_json::from_slice(&std::fs::read(plan_json)?)?;
    let bytes: BTreeMap<u32, u64> = d
        .ledgers
        .iter()
        .map(|(s, l)| (*s, if xdr { l.xdr_bytes } else { l.object_bytes }))
        .collect();
    println!("level\tobject\tera\tN_era\tn\tdistinct\tgreedy_kept\tgreedy_bytes\tbeta_lo\tbeta_mid\tbeta_hi\text_kept_lo\text_kept_mid\text_kept_hi\text_bytes_mid\text_bytes_hi\td_beta_mid\td_beta_hi\text_distinct_mid\text_distinct_hi\tcapped_kept_mid\tcapped_kept_hi");
    for l in levels.split(',') {
        let p = project(d, &level(l));
        for what in ["components", "tx"] {
            for e in pj["eras"].as_array().context("eras")? {
                let era = e[0].as_u64().unwrap_or(0).to_string();
                let n_era = e[2].as_u64().unwrap_or(0) - e[1].as_u64().unwrap_or(0) + 1;
                let train: Vec<u32> = rank_order(&plan, |r| {
                    r.era == era && r.set == "sample" && r.reason.starts_with("random")
                })
                .into_iter()
                .filter(|s| d.ledgers.contains_key(s))
                .collect();
                if train.len() < 100 {
                    continue;
                }
                let mut pts = Vec::new();
                for n in [250usize, 500, 1000, 2000, usize::MAX] {
                    let n = n.min(train.len());
                    let keep: HashSet<u32> = train[..n].iter().copied().collect();
                    let sub = ids_by_ledger(d, &p, what, &|s| keep.contains(&s));
                    let distinct: HashSet<&Id> = sub.values().flatten().collect();
                    let (_, (gk, gb)) = cover_of(&sub, &bytes);
                    pts.push((n, distinct.len(), gk, gb));
                    if n == train.len() {
                        break;
                    }
                }
                let slope = |a: &(usize, usize, usize, u64), b: &(usize, usize, usize, u64)| {
                    if b.0 > a.0 && a.2 > 0 && b.2 > 0 {
                        ((b.2 as f64) / a.2 as f64).ln() / ((b.0 as f64) / a.0 as f64).ln()
                    } else {
                        f64::NAN
                    }
                };
                let ss: Vec<f64> = pts
                    .windows(2)
                    .map(|w| slope(&w[0], &w[1]))
                    .filter(|x| x.is_finite())
                    .collect();
                let last = *pts.last().unwrap();
                let mid = ss.last().copied().unwrap_or(1.0).clamp(0.0, 1.0);
                let lo = ss
                    .iter()
                    .copied()
                    .fold(f64::INFINITY, f64::min)
                    .clamp(0.0, 1.0);
                let hi = ss
                    .iter()
                    .copied()
                    .fold(f64::NEG_INFINITY, f64::max)
                    .clamp(0.0, 1.0);
                let ext = |b: f64| {
                    ((last.2 as f64) * (n_era as f64 / last.0 as f64).powf(b)).min(n_era as f64)
                };
                let per = if last.2 > 0 {
                    last.3 as f64 / last.2 as f64
                } else {
                    0.0
                };
                // Distinct ids at the same prefixes: a cover never needs more ledgers than there are
                // ids, so the extrapolated distinct count caps the extrapolated cover.
                let ds: Vec<f64> = pts
                    .windows(2)
                    .filter(|w| w[1].0 > w[0].0 && w[0].1 > 0)
                    .map(|w| {
                        ((w[1].1 as f64) / w[0].1 as f64).ln()
                            / ((w[1].0 as f64) / w[0].0 as f64).ln()
                    })
                    .filter(|x| x.is_finite())
                    .collect();
                let dmid = ds.last().copied().unwrap_or(1.0).clamp(0.0, 1.0);
                let dhi = ds
                    .iter()
                    .copied()
                    .fold(f64::NEG_INFINITY, f64::max)
                    .clamp(0.0, 1.0);
                let dext = |b: f64| (last.1 as f64) * (n_era as f64 / last.0 as f64).powf(b);
                println!(
                    "{l}\t{what}\t{era}\t{n_era}\t{}\t{}\t{}\t{}\t{lo:.3}\t{mid:.3}\t{hi:.3}\t{:.0}\t{:.0}\t{:.0}\t{:.0}\t{:.0}\t{dmid:.3}\t{dhi:.3}\t{:.0}\t{:.0}\t{:.0}\t{:.0}",
                    last.0,
                    last.1,
                    last.2,
                    last.3,
                    ext(lo),
                    ext(mid),
                    ext(hi),
                    ext(mid) * per,
                    ext(hi) * per,
                    dext(dmid),
                    dext(dhi),
                    ext(mid).min(dext(dmid)),
                    ext(hi).min(dext(dhi))
                );
            }
        }
    }
    Ok(())
}
