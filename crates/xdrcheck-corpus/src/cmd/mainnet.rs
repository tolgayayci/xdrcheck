//! `xdrcheck-corpus mainnet`: the mainnet tier (`corpus/mainnet/`), real pubnet transactions that together
//! hold every transaction-level shape token of the mainnet scan (`corpus/mainnet/README.md` states the claim).
//!
//! The tier is a locator file, not a copy: `tier.jsonl` names one transaction per line (ledger, apply index,
//! hash, the public-lake object that holds it and that object's sha256, each part's offset, length and sha256 in
//! the ledger, the token ids it newly covers) and `tier.json` is its header. The bytes stay in the public lake.
//!
//! - `fetch` fills `<cache>/mainnet/objects/<lake key>` from the public lake (plain HTTPS GETs; `--from DIR`
//!   copies from a directory laid out like the lake instead). Every object is checked against its sha256 and
//!   length before it is kept; one already in the cache with the right hash is not fetched again, so a full
//!   cache needs no network. An object whose bytes differ from the tier's hash is kept beside it as
//!   `<key>.drift` and reported: the lake rewrote it.
//! - `check` reads only the cache. Per line: object sha256 and length, decompression, the batch split (with
//!   its byte-exact re-encode), the ledger at `blob_offset`; the transaction is cut again with `scan
//!   cut-slices`' code and every part must have the line's name, type, path, offset, length and sha256 and
//!   round-trip byte-exactly through rs-stellar-xdr; the ledger is walked with the scan's emitter (`scan run`'s
//!   cut into components, grammar `xcc.shape/v1`) and the line's tokens must be the transaction's tokens that
//!   no earlier line holds (so the file is a greedy cover in its own order); the union of every line's
//!   tokens must be the header's count, and so must the union of every walked transaction's tokens.
//! - `build` writes the two files from the scan's private outputs (the rare-first token cover and the token
//!   table, `scan cover-stream` and `scan token-census`) and a directory of the lake objects. It recomputes the
//!   cover's order key (rarest token's occurrence, ledger, transaction shape id, first apply index of that
//!   shape) from the walk and fails unless every row's new-token count and rarest occurrence are the cover's.
//!
//! Exit codes: 0 every check passed, 1 a check failed (or an object drifted), 2 the tool could not run.
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use xdrcheck_xdr::{Gate, Limits};

use super::coverage::walk::Defs;
use super::intake::lake::{self, Network};
use super::intake::pins::Pins;
use super::scan::shape::{Ctx, Rules, RULES_V1};
use super::scan::slices::{cut_parts, TxParts};
use super::scan::source::http_get;
use super::scan::tokens::token_id;

pub const HEADER_SCHEMA: &str = "xcc.mainnet.tier/v1";
pub const LINE_SCHEMA: &str = "xcc.mainnet.tx/v1";

#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(subcommand)]
    cmd: Sub,
}

#[derive(clap::Subcommand, Debug)]
enum Sub {
    /// Fill the cache with the tier's lake objects (network step; offline when the cache is full)
    Fetch(FetchArgs),
    /// Check the tier from the cache: hash chain, cut, round trip, tokens
    Check(CheckArgs),
    /// Write tier.jsonl and tier.json from the scan's token cover and token table
    Build(BuildArgs),
    /// Write the token coverage statement (evidence/results/mainnet-coverage.json); --check compares
    Coverage(CoverageArgs),
}

#[derive(clap::Args, Debug)]
struct CoverageArgs {
    /// Tier directory (holds tier.json and tier.jsonl); default <corpus>/mainnet
    #[arg(long)]
    tier: Option<PathBuf>,
    /// The statement file; default evidence/results/mainnet-coverage.json beside the corpus root
    #[arg(long)]
    out: Option<PathBuf>,
    /// Compare with the file instead of writing it; exit 1 when it differs
    #[arg(long)]
    check: bool,
}

#[derive(clap::Args, Debug)]
struct Common {
    /// Tier directory (holds tier.json and tier.jsonl); default <corpus>/mainnet
    #[arg(long)]
    tier: Option<PathBuf>,
    /// Kit cache root; the objects go under <cache>/mainnet/objects (default $XDRCHECK_CACHE,
    /// $XDRCHECK_CACHE_DIR, or $HOME/.cache/xdrcheck)
    #[arg(long)]
    cache: Option<PathBuf>,
    /// Objects handled in parallel
    #[arg(long, default_value_t = 4)]
    jobs: usize,
}

#[derive(clap::Args, Debug)]
struct FetchArgs {
    #[command(flatten)]
    c: Common,
    /// Copy the objects from this directory, laid out like the lake (<dir>/<lake key>), instead of the lake
    #[arg(long)]
    from: Option<PathBuf>,
    /// Base URL of the pubnet lake (default: from pins.toml [public_lake])
    #[arg(long)]
    lake_url: Option<String>,
}

#[derive(clap::Args, Debug)]
struct CheckArgs {
    #[command(flatten)]
    c: Common,
    /// Write the per-line results (TSV) here
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct BuildArgs {
    #[command(flatten)]
    c: Common,
    /// The rare-first token cover (`scan cover-stream`, cover-TOK-tx-rare.tsv[.zst])
    #[arg(long)]
    cover: PathBuf,
    /// The token table (`scan token-census`, tokens.tsv[.zst])
    #[arg(long)]
    token_table: PathBuf,
    /// Directory of the lake objects (<dir>/<lake key>); default the cache
    #[arg(long)]
    objects: Option<PathBuf>,
    /// First and last ledger of the scan the cover comes from
    #[arg(long, default_value = "2..65505999")]
    scan_range: String,
    /// The cover file holds only some rows of a cover (a test fixture): do not require each row's count of
    /// new tokens nor the union to be every transaction-level token of the table
    #[arg(long)]
    partial: bool,
}

/// One part of a line: name, XDR type, JSON path in the ledger, byte offset in the ledger, length, sha256.
pub type PartRow = (String, String, String, usize, usize, String);

/// One line of `tier.jsonl`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Line {
    pub ledger: u32,
    pub tx_index: usize,
    pub tx_hash: String,
    /// Header protocol version (`ledger_version`).
    pub protocol: u32,
    /// `LedgerCloseMeta` arm.
    pub lcm_version: u32,
    pub lake_key: String,
    pub object_sha256: String,
    pub object_bytes: u64,
    /// Offset of the ledger's `LedgerCloseMeta` in the decompressed object.
    pub blob_offset: usize,
    pub parts: Vec<PartRow>,
    /// Token ids (hex) this transaction holds that no earlier line holds, sorted.
    pub tokens: Vec<String>,
    /// Occurrences of the transaction's rarest token in the scan's token table.
    pub rarity: u64,
}

pub fn run(corpus: &Path, a: Args) -> Result<ExitCode> {
    match a.cmd {
        Sub::Fetch(f) => fetch(corpus, f),
        Sub::Check(c) => check(corpus, c),
        Sub::Build(b) => build(corpus, b),
        Sub::Coverage(c) => coverage(corpus, c),
    }
}

fn tier_dir(corpus: &Path, c: &Common) -> PathBuf {
    c.tier.clone().unwrap_or_else(|| corpus.join("mainnet"))
}

fn cache_root(c: &Common) -> Result<PathBuf> {
    if let Some(p) = &c.cache {
        return Ok(p.clone());
    }
    for v in ["XDRCHECK_CACHE", "XDRCHECK_CACHE_DIR"] {
        if let Some(p) = std::env::var_os(v).filter(|p| !p.is_empty()) {
            return Ok(PathBuf::from(p));
        }
    }
    xdrcheck_xdr::userdir::home_cache().context("set --cache, XDRCHECK_CACHE or HOME")
}

fn objects_dir(c: &Common) -> Result<PathBuf> {
    Ok(cache_root(c)?.join("mainnet").join("objects"))
}

fn read_text(p: &Path) -> Result<String> {
    let raw = std::fs::read(p).with_context(|| p.display().to_string())?;
    if p.extension().is_some_and(|e| e == "zst") {
        Ok(String::from_utf8(xdrcheck_xdr::batch::decompress(&raw)?)?)
    } else {
        Ok(String::from_utf8(raw)?)
    }
}

/// The header and lines of a tier directory; the header's sha256 of `tier.jsonl` must match.
pub fn load(dir: &Path) -> Result<(serde_json::Value, Vec<Line>)> {
    let hp = dir.join("tier.json");
    let header: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&hp).with_context(|| hp.display().to_string())?)
            .with_context(|| hp.display().to_string())?;
    ensure!(
        header["schema"] == HEADER_SCHEMA,
        "{}: schema is not {HEADER_SCHEMA}",
        hp.display()
    );
    let lp = dir.join("tier.jsonl");
    let raw = std::fs::read(&lp).with_context(|| lp.display().to_string())?;
    let sha = xdrcheck_xdr::sha256_hex(&raw);
    ensure!(
        header["lines"]["sha256"] == sha.as_str(),
        "{}: sha256 is {sha}, tier.json says {}",
        lp.display(),
        header["lines"]["sha256"]
    );
    let mut lines = Vec::new();
    let text = std::str::from_utf8(&raw).with_context(|| lp.display().to_string())?;
    for (n, l) in text.lines().enumerate() {
        let line: Line =
            serde_json::from_str(l).with_context(|| format!("{} line {}", lp.display(), n + 1))?;
        lines.push(line);
    }
    Ok((header, lines))
}

/// Run `f` over `items` on `jobs` threads with the decoder's stack; results in item order.
fn par_map<T: Sync, R: Send>(
    items: &[T],
    jobs: usize,
    f: impl Fn(&T) -> R + Sync,
) -> Result<Vec<R>> {
    let next = AtomicUsize::new(0);
    let out: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    let stack = Limits::default().stack_size;
    std::thread::scope(|s| -> Result<()> {
        let mut hs = Vec::new();
        for _ in 0..jobs.max(1) {
            hs.push(
                std::thread::Builder::new()
                    .stack_size(stack)
                    .spawn_scoped(s, || loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(it) = items.get(i) else { break };
                        let r = f(it);
                        out.lock().unwrap()[i] = Some(r);
                    })?,
            );
        }
        for h in hs {
            h.join()
                .map_err(|_| anyhow::anyhow!("a worker thread panicked"))?;
        }
        Ok(())
    })?;
    Ok(out
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|r| r.unwrap())
        .collect())
}

// --- the walk shared by build and check ---

/// What one transaction of a walked ledger gives.
struct TxWalk {
    idx: usize,
    parts: TxParts,
    /// Token ids of every transaction-level component of the transaction.
    tokens: BTreeSet<[u8; 16]>,
    shape: [u8; 16],
    first_idx: usize,
}

struct ObjWalk {
    object_sha256: String,
    object_bytes: u64,
    blob_offset: usize,
    protocol: u32,
    lcm_version: u32,
    /// The ledger's XDR (for the slice checks).
    blob: Vec<u8>,
    txs: Vec<TxWalk>,
}

struct Walker {
    defs: &'static Defs,
    rules: Rules,
    network_id: [u8; 32],
    limits: Limits,
    gate: Gate,
}

impl Walker {
    fn new() -> Result<Walker> {
        let defs = Defs::pinned();
        Ok(Walker {
            defs,
            rules: Rules::parse(RULES_V1, defs)?,
            network_id: Sha256::digest(Network::Pubnet.passphrase().as_bytes()).into(),
            limits: Limits::default(),
            gate: Gate::default().reading_live(),
        })
    }

    /// Hash, decompress, split, decode, cut and walk ledger `seq` of `obj` (runs on the caller's stack,
    /// which must be the decoder's).
    fn walk(&self, obj: &[u8], seq: u32, idxs: &[usize]) -> Result<ObjWalk> {
        let dec = xdrcheck_xdr::batch::decompress(obj).context("decompress")?;
        let batch = xdrcheck_xdr::split_batch(&dec, &self.limits, &self.gate).context("batch")?;
        let k = batch
            .infos
            .iter()
            .position(|i| i.sequence == seq)
            .with_context(|| format!("the object holds no ledger {seq}"))?;
        let blob_offset = 12 + batch.ledgers[..k].iter().map(Vec::len).sum::<usize>();
        let blob = batch.ledgers[k].clone();
        ensure!(
            dec.get(blob_offset..blob_offset + blob.len()) == Some(&blob[..]),
            "ledger {seq} is not at offset {blob_offset} of the decompressed object"
        );
        let lcm = xdrcheck_xdr::decode_ledger(&blob, &self.limits, &self.gate)?;
        let ctx = Ctx {
            defs: self.defs,
            rules: &self.rules,
            network_id: self.network_id,
        };
        let sh = ctx.ledger(&lcm, &blob)?;
        ensure!(
            sh.tx_hash_mismatches == 0,
            "ledger {seq}: {} results do not join an envelope under the pubnet passphrase",
            sh.tx_hash_mismatches
        );
        let ids: Vec<[u8; 16]> = sh.txs.iter().map(|t| t.id()).collect();
        let mut txs = Vec::new();
        for (i, got) in cut_parts(&lcm, &blob, self.network_id, idxs)? {
            let parts = got.with_context(|| {
                format!(
                    "ledger {seq} has {} transactions, not {}",
                    sh.txs.len(),
                    i + 1
                )
            })?;
            let tx = &sh.txs[i];
            let mut cids = vec![&tx.e, &tx.r, &tx.f, &tx.m];
            if let Some(a) = &tx.a {
                cids.push(a);
            }
            for (o, _) in &tx.ops {
                cids.push(o);
            }
            let mut tokens = BTreeSet::new();
            for cid in cids {
                let c = sh.components.get(cid).context("component missing")?;
                ensure!(
                    c.kind != 'L',
                    "ledger {seq} tx {i}: a ledger-level component"
                );
                for t in &c.tokens {
                    tokens.insert(token_id(t));
                }
            }
            let shape = ids[i];
            let first_idx = ids.iter().position(|x| *x == shape).unwrap();
            txs.push(TxWalk {
                idx: i,
                parts,
                tokens,
                shape,
                first_idx,
            });
        }
        let protocol = batch.infos[k].protocol;
        Ok(ObjWalk {
            object_sha256: xdrcheck_xdr::sha256_hex(obj),
            object_bytes: obj.len() as u64,
            blob_offset,
            protocol,
            lcm_version: lcm.discriminant() as u32,
            blob,
            txs,
        })
    }
}

fn part_rows(p: &TxParts) -> Vec<PartRow> {
    p.parts
        .iter()
        .map(|x| {
            (
                x.name.clone(),
                x.xdr_type.to_string(),
                x.path.clone(),
                x.offset,
                x.bytes.len(),
                xdrcheck_xdr::sha256_hex(&x.bytes),
            )
        })
        .collect()
}

/// Lines grouped by ledger, in ledger order: (ledger, lake key, line numbers).
fn by_ledger(lines: &[Line]) -> Vec<(u32, String, Vec<usize>)> {
    let mut m: BTreeMap<u32, (String, Vec<usize>)> = BTreeMap::new();
    for (n, l) in lines.iter().enumerate() {
        m.entry(l.ledger)
            .or_insert_with(|| (l.lake_key.clone(), Vec::new()))
            .1
            .push(n);
    }
    m.into_iter().map(|(s, (k, v))| (s, k, v)).collect()
}

// --- fetch ---

fn fetch(corpus: &Path, a: FetchArgs) -> Result<ExitCode> {
    let t0 = Instant::now();
    let (_, lines) = load(&tier_dir(corpus, &a.c))?;
    let dest = objects_dir(&a.c)?;
    let mut objs: BTreeMap<String, (u32, String, u64)> = BTreeMap::new();
    for l in &lines {
        ensure!(
            l.lake_key == lake::object_key(l.ledger),
            "ledger {}: lake key {} is not the lake's key for it",
            l.ledger,
            l.lake_key
        );
        objs.insert(
            l.lake_key.clone(),
            (l.ledger, l.object_sha256.clone(), l.object_bytes),
        );
    }
    let todo: Vec<(String, u32, String, u64)> = objs
        .into_iter()
        .map(|(k, (s, h, n))| (k, s, h, n))
        .collect();
    // Only made when an object is missing: a full cache needs no network.
    let base = match &a.lake_url {
        Some(u) => u.trim_end_matches('/').to_string(),
        None => {
            let pins = Pins::load(corpus)?;
            let loc = lake::locate(&pins, Network::Pubnet, 2)?;
            loc.url
                .strip_suffix(&format!("/{}", loc.key))
                .context("lake URL")?
                .to_string()
        }
    };
    let agent: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    let counts = Mutex::new(BTreeMap::<&'static str, (usize, u64)>::new());
    let problems = Mutex::new(Vec::<String>::new());
    let done = AtomicUsize::new(0);
    let total = todo.len();
    par_map(&todo, a.c.jobs, |(key, _seq, sha, bytes)| {
        let r = (|| -> Result<&'static str> {
            let path = dest.join(key);
            if path.exists() {
                let have = std::fs::read(&path)?;
                if xdrcheck_xdr::sha256_hex(&have) == *sha && have.len() as u64 == *bytes {
                    return Ok("cached");
                }
            }
            let got = match &a.from {
                Some(d) => std::fs::read(d.join(key))
                    .with_context(|| format!("{key} in {}", d.display()))?,
                None => {
                    let ag = agent.get_or_init(|| {
                        ureq::Agent::config_builder()
                            .timeout_global(Some(std::time::Duration::from_secs(300)))
                            .http_status_as_error(false)
                            .user_agent("xdrcheck-corpus-mainnet")
                            .build()
                            .into()
                    });
                    let url = format!("{base}/{key}");
                    let f = http_get(ag, &url)?;
                    match f.bytes {
                        Some(b) if f.status == 200 => b,
                        _ => bail!("{url}: HTTP {}", f.status),
                    }
                }
            };
            std::fs::create_dir_all(path.parent().unwrap())?;
            if xdrcheck_xdr::sha256_hex(&got) != *sha || got.len() as u64 != *bytes {
                let drift = path.with_extension("zst.drift");
                std::fs::write(&drift, &got)?;
                bail!(
                    "drift: {key} is {} bytes with sha256 {}, the tier says {bytes} bytes, {sha} (kept as {})",
                    got.len(),
                    xdrcheck_xdr::sha256_hex(&got),
                    drift.display()
                );
            }
            let tmp = path.with_extension("zst.tmp");
            std::fs::write(&tmp, &got)?;
            std::fs::rename(&tmp, &path)?;
            Ok(if a.from.is_some() {
                "copied"
            } else {
                "fetched"
            })
        })();
        match r {
            Ok(what) => {
                let mut c = counts.lock().unwrap();
                let e = c.entry(what).or_default();
                e.0 += 1;
                e.1 += *bytes;
            }
            Err(e) => problems.lock().unwrap().push(format!("{key}: {e:#}")),
        }
        let n = done.fetch_add(1, Ordering::Relaxed) + 1;
        if n % 500 == 0 {
            eprintln!("mainnet fetch: {n}/{total}");
        }
    })?;
    let counts = counts.into_inner().unwrap();
    let problems = problems.into_inner().unwrap();
    for (k, (n, b)) in &counts {
        println!("{k}: {n} objects, {b} bytes");
    }
    for p in &problems {
        println!("FAIL {p}");
    }
    println!(
        "mainnet fetch: {} objects in {}, {} failed, {:.0} s",
        total,
        dest.display(),
        problems.len(),
        t0.elapsed().as_secs_f64()
    );
    Ok(if problems.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

// --- check ---

/// Per-line result of the object checks.
struct LineCheck {
    problems: Vec<String>,
    /// Every token of the transaction (empty when the walk failed).
    walked: BTreeSet<[u8; 16]>,
}

fn check_object(
    w: &Walker,
    dir: &Path,
    lines: &[Line],
    seq: u32,
    key: &str,
    ns: &[usize],
) -> Vec<(usize, LineCheck)> {
    let fail_all = |msg: String| {
        ns.iter()
            .map(|&n| {
                (
                    n,
                    LineCheck {
                        problems: vec![msg.clone()],
                        walked: BTreeSet::new(),
                    },
                )
            })
            .collect::<Vec<_>>()
    };
    let path = dir.join(key);
    let obj = match std::fs::read(&path) {
        Ok(o) => o,
        Err(e) => {
            return fail_all(format!(
                "lake object {key} not in the cache ({e}); run `xdrcheck-corpus mainnet fetch`"
            ))
        }
    };
    let first = &lines[ns[0]];
    if xdrcheck_xdr::sha256_hex(&obj) != first.object_sha256
        || obj.len() as u64 != first.object_bytes
    {
        return fail_all(format!(
            "lake object {key}: {} bytes, sha256 {}; the tier says {} bytes, {}",
            obj.len(),
            xdrcheck_xdr::sha256_hex(&obj),
            first.object_bytes,
            first.object_sha256
        ));
    }
    let idxs: Vec<usize> = ns.iter().map(|&n| lines[n].tx_index).collect();
    let ow = match w.walk(&obj, seq, &idxs) {
        Ok(o) => o,
        Err(e) => return fail_all(format!("ledger {seq}: {e:#}")),
    };
    let mut out = Vec::new();
    for (&n, tx) in ns.iter().zip(&ow.txs) {
        let l = &lines[n];
        let mut p = Vec::new();
        for (what, got, want) in [
            (
                "object sha256",
                ow.object_sha256.clone(),
                l.object_sha256.clone(),
            ),
            (
                "blob_offset",
                ow.blob_offset.to_string(),
                l.blob_offset.to_string(),
            ),
            ("protocol", ow.protocol.to_string(), l.protocol.to_string()),
            (
                "lcm_version",
                ow.lcm_version.to_string(),
                l.lcm_version.to_string(),
            ),
            ("tx_hash", hex::encode(tx.parts.hash), l.tx_hash.clone()),
            ("tx_index", tx.idx.to_string(), l.tx_index.to_string()),
        ] {
            if got != want {
                p.push(format!("{what} is {got}, the line says {want}"));
            }
        }
        // The bytes the line names, read at its offsets, against its hashes; then the fresh cut.
        for (name, typ, _, off, len, sha) in &l.parts {
            match ow.blob.get(*off..off + len) {
                None => p.push(format!(
                    "{name}: [{off}, {}) is outside the ledger",
                    off + len
                )),
                Some(b) => {
                    if xdrcheck_xdr::sha256_hex(b) != *sha {
                        p.push(format!("{name}: bytes at {off} do not have sha256 {sha}"));
                    }
                    if let Err(e) = xdrcheck_xdr::roundtrip(typ, b, &w.limits) {
                        p.push(format!("{name}: {typ} round trip: {e}"));
                    }
                }
            }
        }
        let fresh = part_rows(&tx.parts);
        if fresh != l.parts {
            p.push(format!(
                "the parts cut from the ledger differ from the line's: cut {:?}, line {:?}",
                fresh, l.parts
            ));
        }
        for t in &l.tokens {
            match hex::decode(t)
                .ok()
                .and_then(|b| <[u8; 16]>::try_from(b).ok())
            {
                Some(id) if tx.tokens.contains(&id) => {}
                Some(_) => p.push(format!("token {t} is not among the transaction's tokens")),
                None => p.push(format!("token {t} is not a 16-byte hex id")),
            }
        }
        out.push((
            n,
            LineCheck {
                problems: p,
                walked: tx.tokens.clone(),
            },
        ));
    }
    out
}

fn check(corpus: &Path, a: CheckArgs) -> Result<ExitCode> {
    let t0 = Instant::now();
    let tier = tier_dir(corpus, &a.c);
    let (header, lines) = load(&tier)?;
    let dir = objects_dir(&a.c)?;
    let w = Walker::new()?;
    let groups = by_ledger(&lines);
    let done = AtomicUsize::new(0);
    let res = par_map(&groups, a.c.jobs, |(seq, key, ns)| {
        let r = check_object(&w, &dir, &lines, *seq, key, ns);
        let n = done.fetch_add(1, Ordering::Relaxed) + 1;
        if n % 500 == 0 {
            eprintln!("mainnet check: {n}/{} ledgers", groups.len());
        }
        r
    })?;
    let mut per: Vec<Option<LineCheck>> = (0..lines.len()).map(|_| None).collect();
    for (n, c) in res.into_iter().flatten() {
        per[n] = Some(c);
    }
    let mut per: Vec<LineCheck> = per.into_iter().map(|c| c.unwrap()).collect();

    // Order: each line's tokens are exactly the walked tokens no earlier line holds.
    let mut covered: BTreeSet<[u8; 16]> = BTreeSet::new();
    let mut walked_all: BTreeSet<[u8; 16]> = BTreeSet::new();
    let mut seen_tx: BTreeSet<(u32, usize)> = BTreeSet::new();
    let mut last_rarity = 0u64;
    for (l, c) in lines.iter().zip(per.iter_mut()) {
        if !seen_tx.insert((l.ledger, l.tx_index)) {
            c.problems
                .push("the transaction is on an earlier line too".into());
        }
        if l.rarity < last_rarity {
            c.problems.push(format!(
                "rarity {} is below the previous line's {last_rarity}: not in cover order",
                l.rarity
            ));
        }
        last_rarity = l.rarity;
        let mut sorted = l.tokens.clone();
        sorted.sort();
        sorted.dedup();
        if sorted != l.tokens {
            c.problems.push("tokens are not sorted and distinct".into());
        }
        if l.tokens.is_empty() {
            c.problems.push("the line covers no token".into());
        }
        if !c.walked.is_empty() {
            let new: BTreeSet<String> = c.walked.difference(&covered).map(hex::encode).collect();
            let listed: BTreeSet<String> = l.tokens.iter().cloned().collect();
            if new != listed {
                c.problems.push(format!(
                    "tokens are not the transaction's tokens that no earlier line holds: {} listed, {} new",
                    listed.len(),
                    new.len()
                ));
            }
            covered.extend(c.walked.iter().copied());
            walked_all.extend(c.walked.iter().copied());
        }
    }
    let mut listed_all: BTreeSet<&str> = BTreeSet::new();
    for l in &lines {
        listed_all.extend(l.tokens.iter().map(String::as_str));
    }
    let mut global = Vec::new();
    let want = |k: &str| header["counts"][k].as_u64().unwrap_or(u64::MAX);
    let ledgers = groups.len() as u64;
    let parts: u64 = lines.iter().map(|l| l.parts.len() as u64).sum();
    for (what, got) in [
        ("tokens", listed_all.len() as u64),
        ("transactions", lines.len() as u64),
        ("ledgers", ledgers),
        ("parts", parts),
    ] {
        if got != want(what) {
            global.push(format!("{got} {what}, tier.json says {}", want(what)));
        }
    }
    if walked_all.len() as u64 != want("tokens") {
        global.push(format!(
            "the walked transactions hold {} distinct tokens, tier.json says {}",
            walked_all.len(),
            want("tokens")
        ));
    }
    let failed: Vec<(&Line, &LineCheck)> = lines
        .iter()
        .zip(per.iter())
        .filter(|(_, c)| !c.problems.is_empty())
        .collect();
    if let Some(o) = &a.out {
        let mut f = std::io::BufWriter::new(std::fs::File::create(o)?);
        writeln!(f, "ledger\ttx_index\tparts\ttokens\tresult")?;
        for (l, c) in lines.iter().zip(per.iter()) {
            let r = if c.problems.is_empty() {
                "pass".to_string()
            } else {
                c.problems.join("; ").replace(['\t', '\n'], " ")
            };
            writeln!(
                f,
                "{}\t{}\t{}\t{}\t{r}",
                l.ledger,
                l.tx_index,
                l.parts.len(),
                l.tokens.len()
            )?;
        }
        f.flush()?;
    }
    for (l, c) in failed.iter().take(50) {
        for p in &c.problems {
            println!("FAIL {}-{}: {p}", l.ledger, l.tx_index);
        }
    }
    if failed.len() > 50 {
        println!("... {} more failed lines", failed.len() - 50);
    }
    for g in &global {
        println!("FAIL {g}");
    }
    println!(
        "mainnet check: {} transactions, {} ledgers, {} parts (hash chain, cut, round trip), {} tokens listed, {} walked; {} lines failed, {} totals failed, {:.0} s",
        lines.len(),
        ledgers,
        parts,
        listed_all.len(),
        walked_all.len(),
        failed.len(),
        global.len(),
        t0.elapsed().as_secs_f64()
    );
    Ok(if failed.is_empty() && global.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

// --- coverage ---

pub const COVERAGE_SCHEMA: &str = "xdrcheck.results.mainnet-coverage/v1";

/// How many of the tier's tokens the tier holds, and how many a transaction of a curated corpus entry holds:
/// the tokens of the focus transaction's components (E, A, R, F, M, O) of every `LedgerCloseMeta` variant, walked
/// as `scan entry-tokens` walks them.
fn coverage(corpus: &Path, a: CoverageArgs) -> Result<ExitCode> {
    let tier = a.tier.clone().unwrap_or_else(|| corpus.join("mainnet"));
    let (header, lines) = load(&tier)?;
    let listed: BTreeSet<&str> = lines
        .iter()
        .flat_map(|l| l.tokens.iter().map(String::as_str))
        .collect();
    let rows = super::scan::entries::walk(corpus)?;
    let mut curated: BTreeSet<String> = BTreeSet::new();
    for (_, _, k, t) in &rows {
        if ["E", "A", "R", "F", "M", "O"].contains(&k.as_str()) {
            let id = hex::encode(token_id(t));
            if listed.contains(id.as_str()) {
                curated.insert(id);
            }
        }
    }
    let total = header["counts"]["tokens"].as_u64().context("tier.json: counts.tokens")?;
    let (first, last) = (&header["scan"]["first_ledger"], &header["scan"]["last_ledger"]);
    let thousands = |n: u64| {
        let s = n.to_string();
        let mut o = String::new();
        for (i, c) in s.chars().enumerate() {
            if i > 0 && (s.len() - i) % 3 == 0 {
                o.push(',');
            }
            o.push(c);
        }
        o
    };
    let statement = format!(
        "mainnet transaction-level token coverage: {} of {} in the mainnet tier; {} of {} in the curated corpus",
        thousands(listed.len() as u64),
        thousands(total),
        thousands(curated.len() as u64),
        thousands(total)
    );
    let doc = serde_json::json!({
        "schema": COVERAGE_SCHEMA,
        "generated_by": "make results-mainnet",
        "statement": statement,
        "scope": format!(
            "transaction-level shape tokens (grammar xcc.shape/v1; components A, E, F, M, O, R) that occur in pubnet ledgers {first}..{last} as the public data lake serves them; corpus/mainnet/README.md says what is and is not claimed"
        ),
        "tokens": total,
        "mainnet_tier": {
            "tokens_held": listed.len(),
            "transactions": lines.len(),
            "ledgers": header["counts"]["ledgers"],
            "how": "the union of tier.jsonl's token lists; make verify-mainnet proves it against the lake objects",
        },
        "curated": {
            "tokens_held": curated.len(),
            "how": "tokens of the focus transaction of every LedgerCloseMeta variant of corpus/index.json, walked with the scan's emitter (scan entry-tokens)",
        },
    });
    // Sorted keys, two-space indentation (evidence/results/README.md).
    fn sorted(v: serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let b: BTreeMap<String, serde_json::Value> =
                    m.into_iter().map(|(k, v)| (k, sorted(v))).collect();
                serde_json::Value::Object(b.into_iter().collect())
            }
            x => x,
        }
    }
    let mut text = serde_json::to_string_pretty(&sorted(doc))?;
    text.push('\n');
    let out = match a.out {
        Some(p) => p,
        None => corpus
            .canonicalize()?
            .parent()
            .context("corpus root has no parent")?
            .join("evidence/results/mainnet-coverage.json"),
    };
    if a.check {
        let old = std::fs::read_to_string(&out).unwrap_or_default();
        if old != text {
            println!(
                "{}: differs from a fresh generation (run make results-mainnet)",
                out.display()
            );
            return Ok(ExitCode::from(1));
        }
        println!("{}: current ({statement})", out.display());
    } else {
        std::fs::create_dir_all(out.parent().unwrap())?;
        std::fs::write(&out, &text)?;
        println!("{}: written ({statement})", out.display());
    }
    Ok(ExitCode::SUCCESS)
}

// --- build ---

fn build(corpus: &Path, a: BuildArgs) -> Result<ExitCode> {
    let t0 = Instant::now();
    let (first, last) = a
        .scan_range
        .split_once("..")
        .context("--scan-range FIRST..LAST")?;
    let (first, last): (u32, u32) = (first.parse()?, last.parse()?);
    // Token table: occurrences of every transaction-level token.
    let mut occ: BTreeMap<[u8; 16], u64> = BTreeMap::new();
    let table = read_text(&a.token_table)?;
    let mut rows = table.lines();
    let head: Vec<&str> = rows
        .next()
        .context("empty token table")?
        .split('\t')
        .collect();
    let col = |n: &str| {
        head.iter()
            .position(|h| *h == n)
            .with_context(|| format!("token table: no {n} column"))
    };
    let (ci, co, ck) = (
        col("token_id")?,
        col("occurrences")?,
        col("component_kinds")?,
    );
    for r in rows {
        let f: Vec<&str> = r.split('\t').collect();
        if f[ck].chars().any(|k| k != 'L') {
            let id: [u8; 16] = hex::decode(f[ci])?
                .try_into()
                .map_err(|_| anyhow::anyhow!("token id {}", f[ci]))?;
            occ.insert(id, f[co].parse()?);
        }
    }
    // Cover rows.
    let cover = read_text(&a.cover)?;
    let mut crow: Vec<(u32, usize, usize, u64)> = Vec::new();
    for (n, r) in cover.lines().enumerate() {
        if n == 0 {
            ensure!(
                r == "ledger\ttx_index\tnew_ids\tkey_occurrence",
                "cover: unexpected header {r:?}"
            );
            continue;
        }
        let f: Vec<&str> = r.split('\t').collect();
        crow.push((f[0].parse()?, f[1].parse()?, f[2].parse()?, f[3].parse()?));
    }
    let objects = match &a.objects {
        Some(d) => d.clone(),
        None => objects_dir(&a.c)?,
    };
    let mut groups: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (n, r) in crow.iter().enumerate() {
        groups.entry(r.0).or_default().push(n);
    }
    let groups: Vec<(u32, Vec<usize>)> = groups.into_iter().collect();
    let w = Walker::new()?;
    let done = AtomicUsize::new(0);
    let walked = par_map(&groups, a.c.jobs, |(seq, ns)| -> Result<(u32, ObjWalk)> {
        let key = lake::object_key(*seq);
        let obj = std::fs::read(objects.join(&key)).with_context(|| key.clone())?;
        let idxs: Vec<usize> = ns.iter().map(|&n| crow[n].1).collect();
        let r = w
            .walk(&obj, *seq, &idxs)
            .with_context(|| format!("ledger {seq}"))?;
        let n = done.fetch_add(1, Ordering::Relaxed) + 1;
        if n % 500 == 0 {
            eprintln!("mainnet build: {n}/{} ledgers", groups.len());
        }
        Ok((*seq, r))
    })?;
    struct Row {
        key: (u64, u32, [u8; 16], usize),
        line: Line,
        tokens: BTreeSet<[u8; 16]>,
        new_ids: usize,
    }
    let mut out: Vec<Row> = Vec::new();
    for (g, r) in groups.iter().zip(walked) {
        let (seq, ow) = r?;
        for (&n, tx) in g.1.iter().zip(&ow.txs) {
            let (_, idx, new_ids, key_occ) = crow[n];
            let mut rarity = u64::MAX;
            for t in &tx.tokens {
                let o = occ.get(t).with_context(|| {
                    format!(
                        "{seq} {idx}: token {} is not a transaction-level token of the table",
                        hex::encode(t)
                    )
                })?;
                rarity = rarity.min(*o);
            }
            ensure!(
                rarity == key_occ,
                "{seq} {idx}: rarest token occurs {rarity} times, the cover says {key_occ}"
            );
            out.push(Row {
                key: (rarity, seq, tx.shape, tx.first_idx),
                line: Line {
                    ledger: seq,
                    tx_index: idx,
                    tx_hash: hex::encode(tx.parts.hash),
                    protocol: ow.protocol,
                    lcm_version: ow.lcm_version,
                    lake_key: lake::object_key(seq),
                    object_sha256: ow.object_sha256.clone(),
                    object_bytes: ow.object_bytes,
                    blob_offset: ow.blob_offset,
                    parts: part_rows(&tx.parts),
                    tokens: Vec::new(),
                    rarity,
                },
                tokens: tx.tokens.clone(),
                new_ids,
            });
        }
    }
    out.sort_by(|x, y| x.key.cmp(&y.key));
    let mut covered: BTreeSet<[u8; 16]> = BTreeSet::new();
    for r in &mut out {
        let new: Vec<String> = r.tokens.difference(&covered).map(hex::encode).collect();
        ensure!(
            a.partial || new.len() == r.new_ids,
            "{} {}: {} new tokens in the cover's order, the cover says {}",
            r.line.ledger,
            r.line.tx_index,
            new.len(),
            r.new_ids
        );
        covered.extend(r.tokens.iter().copied());
        r.line.tokens = new;
    }
    let target: BTreeSet<[u8; 16]> = occ.keys().copied().collect();
    ensure!(
        a.partial || covered == target,
        "the cover holds {} tokens, the table has {} transaction-level tokens ({} missing)",
        covered.len(),
        target.len(),
        target.difference(&covered).count()
    );
    let dir = tier_dir(corpus, &a.c);
    std::fs::create_dir_all(&dir)?;
    let mut text = Vec::new();
    for r in &out {
        serde_json::to_writer(&mut text, &r.line)?;
        text.push(b'\n');
    }
    std::fs::write(dir.join("tier.jsonl"), &text)?;
    let ledgers: BTreeSet<u32> = out.iter().map(|r| r.line.ledger).collect();
    let mut objs: BTreeMap<&str, u64> = BTreeMap::new();
    for r in &out {
        objs.insert(&r.line.lake_key, r.line.object_bytes);
    }
    let mut protocols: BTreeMap<u32, u64> = BTreeMap::new();
    for r in &out {
        *protocols.entry(r.line.protocol).or_default() += 1;
    }
    let pins = Pins::load(corpus)?;
    let store = lake::locate(&pins, Network::Pubnet, first)?.store;
    let header = serde_json::json!({
        "schema": HEADER_SCHEMA,
        "line_schema": LINE_SCHEMA,
        "network": "pubnet",
        "passphrase": Network::Pubnet.passphrase(),
        "lake": {"store": store, "layout": "SEP-54, one ledger per object"},
        "scan": {
            "first_ledger": first,
            "last_ledger": last,
            "grammar": "xcc.shape/v1",
            "tokens": "transaction-level: tokens of the components A, E, F, M, O and R (evidence/mainnet-scan/README.md)",
        },
        "cover": {
            "order": "rarest first: the occurrence of the transaction's rarest token, then ledger, transaction shape id at level G3, first apply index of that shape in the ledger",
            "rarity": "occurrences of the transaction's rarest token in the scan's token table: the sum over the distinct components carrying it of the transactions holding each, so an upper bound on the transactions that carry it",
        },
        "counts": {
            "transactions": out.len(),
            "ledgers": ledgers.len(),
            "tokens": covered.len(),
            "parts": out.iter().map(|r| r.line.parts.len()).sum::<usize>(),
            "part_bytes": out.iter().flat_map(|r| r.line.parts.iter().map(|p| p.4 as u64)).sum::<u64>(),
            "object_bytes": objs.values().sum::<u64>(),
            "per_protocol": protocols,
        },
        "lines": {"file": "tier.jsonl", "sha256": xdrcheck_xdr::sha256_hex(&text)},
    });
    let mut h = serde_json::to_vec_pretty(&header)?;
    h.push(b'\n');
    std::fs::write(dir.join("tier.json"), h)?;
    println!(
        "mainnet build: {} transactions, {} ledgers, {} tokens, {:.0} s",
        out.len(),
        ledgers.len(),
        covered.len(),
        t0.elapsed().as_secs_f64()
    );
    Ok(ExitCode::SUCCESS)
}
