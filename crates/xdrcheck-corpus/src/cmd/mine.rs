//! `xdrcheck-corpus mine --network N --range A..B --want PREDICATES`: stream public-lake objects and
//! keep only the ledgers that show a wanted shape.
//!
//! **Source.** The stores of `pins.toml` `[public_lake]`, read anonymously over HTTPS with `curl`
//! (the same transport as `capture`), or with `--lake DIR` a local directory laid out like a
//! store (`DIR/<SEP-54 key>`), which needs no network. A `429` or `5xx` answer is retried after
//! its `Retry-After` (at most [`MAX_RETRY_WAIT`] seconds, [`MAX_RETRIES`] times); a `403` or
//! `404` is a missing ledger, and [`GONE_RUN_END`] of them in a row end the range (past the tip,
//! or a reset testnet epoch).
//!
//! **Decision.** Each object is unpacked by the oracle under the corpus gate (`corpus.json`), and
//! each ledger is walked against the pinned XDR definitions ([`super::coverage::walk`]). A ledger
//! above the gate's protocol (the network upgraded before the pins moved) is read with the
//! protocol ceiling lifted and counted; one that no longer decodes is listed with the unknown shape
//! it holds instead of ending the run ([`mine`]). Ledgers
//! are decided in ascending sequence order, so the outcome does not depend on the fetch
//! concurrency. With `--pick smallest` (the default) every ledger of the range is looked at and a
//! ledger is kept when it is among the `--first K` smallest objects (by bytes, then sequence) of a
//! predicate it matches; a corpus entry made from it then costs as little as the network allows.
//! With `--pick first` a ledger is kept when it matches a predicate that has fewer than K ledgers
//! kept, and the run ends once every predicate is satisfied. `--max-bytes` caps the kept objects
//! (a ledger that would pass it is not kept). `--except FILE` drops the predicates an earlier
//! run's `mined.json` already satisfied: mine testnet first, then pubnet with
//! `--except <testnet>/mined.json`, so an arm testnet shows is never taken from the larger pubnet
//! ledgers. Nothing but the kept objects and `mined.json` is written.
//!
//! **Predicates** (`--want`, comma-separated):
//! - `arm:<id>` an arm or optional state, as `coverage --arms` names it
//!   (`StellarValueExt::STELLAR_VALUE_EMPTY_TX_SET_MS`, `TxSetComponentTxsMaybeDiscountedFee.baseFee?none`);
//! - `bytes:<id>` the same, found inside `ConfigUpgradeSet` bytes held in contract data;
//! - `enum:<Enum=MEMBER>` an enum value read anywhere;
//! - `result:<CODE>` any result arm whose case is CODE (`txFROZEN_KEY_ACCESSED`);
//! - `class:<name>` a value class: `u64-high`, `i128-negative`, `i128-hi-nonzero`, `i256-negative`,
//!   `non-utf8-string`, `count-at-limit`, `ledger-upgrades`;
//! - `depth:<N>` an `SCVal` nested at least N deep;
//! - `meta:v0|v1|v2` the `LedgerCloseMeta` arm; `upgrades` (= `class:ledger-upgrades`);
//!   `scp` (= `arm:SCPHistoryEntry::v0`); `any` every ledger (to preserve a perishable range);
//! - `uncovered` every arm and optional state of the `LedgerCloseMetaBatch` universe that no
//!   committed corpus input covers (as `coverage --arms` counts it), each its own predicate.
//!
//! **Output** (`--out DIR`, default `<cache>/mined`): `DIR/<network>/<seq>/<object>` verbatim, and
//! `DIR/mined.json` with, per kept ledger, the store, key, object sha256, the header hash as
//! stored and as recomputed from the header, the protocol, whether every transaction hash was
//! recomputed from its envelope, and the predicates it matched and was kept for; and the corpus gate
//! (`max_protocol`), how many ledgers above it decoded (`above_max_protocol`), the highest such
//! protocol, and the ledgers above it that did not (`undecoded`). Re-running the same command gives
//! the same kept set.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use xdrcheck_xdr::xdr::{LedgerCloseMeta, Limits as XdrLimits, WriteXdr};
use xdrcheck_xdr::{Gate, Limits};

use super::coverage::walk::{Class, Defs, IdKind, Tally};
use super::intake::lake::{self, Network};
use super::intake::pins::Pins;

/// Longest wait honoured from a `Retry-After` header, in seconds.
pub const MAX_RETRY_WAIT: u64 = 120;
/// Consecutive missing ledgers that end a range (the tip of the lake, or a reset epoch).
pub const GONE_RUN_END: u32 = 64;
/// Retries of one object after `429` or `5xx`.
pub const MAX_RETRIES: u32 = 5;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// `pubnet` or `testnet` (the current testnet epoch pinned in pins.toml)
    #[arg(long)]
    pub network: String,
    /// Inclusive ledger range `A..B`
    #[arg(long)]
    pub range: String,
    /// Wanted predicates, comma-separated (see the module documentation)
    #[arg(long, required = true)]
    pub want: String,
    /// Ledgers kept per predicate
    #[arg(long, default_value_t = 1)]
    pub first: usize,
    /// `smallest`: keep the K smallest matching objects per predicate over the whole range;
    /// `first`: keep the first K matching ledgers and stop once every predicate has them
    #[arg(long, default_value = "smallest")]
    pub pick: String,
    /// `mined.json` of an earlier run: drop the predicates it already satisfied (repeatable)
    #[arg(long)]
    pub except: Vec<PathBuf>,
    /// Stop keeping once this many object bytes are kept
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    pub max_bytes: u64,
    /// Look at every STEP-th ledger of the range only
    #[arg(long, default_value_t = 1)]
    pub step: u32,
    /// Objects fetched at once
    #[arg(long, default_value_t = 8)]
    pub jobs: usize,
    /// Read objects from a local directory laid out like a store instead of the lake
    #[arg(long)]
    pub lake: Option<PathBuf>,
    /// Output directory (default `<cache>/mined`)
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// One wanted predicate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Pred {
    Any,
    Id(usize),
    InBytes(usize),
    Class(Class),
    Depth(u32),
}

/// Parsed `--want`: the predicates and their display names.
pub struct Wants {
    pub preds: Vec<(String, Pred)>,
}

impl Wants {
    pub fn parse(corpus: &Path, want: &str) -> Result<Wants> {
        let d = Defs::pinned();
        let id = |l: &str| {
            d.id(l)
                .with_context(|| format!("no arm, state or enum value {l}"))
        };
        let mut preds: Vec<(String, Pred)> = Vec::new();
        for w in want.split(',').map(str::trim).filter(|w| !w.is_empty()) {
            let (k, v) = w.split_once(':').unwrap_or((w, ""));
            match k {
                "arm" | "enum" => preds.push((w.to_string(), Pred::Id(id(v)?))),
                "bytes" => preds.push((w.to_string(), Pred::InBytes(id(v)?))),
                "result" => {
                    let mut n = 0;
                    for i in 0..d.len() {
                        let l = d.label(i);
                        if d.kind(i) == IdKind::Arm
                            && l.split_once("::").is_some_and(|(u, c)| {
                                c == v
                                    && d.discriminant_enum(u)
                                        .is_some_and(|e| e.ends_with("ResultCode"))
                            })
                        {
                            preds.push((format!("result:{l}"), Pred::Id(i)));
                            n += 1;
                        }
                    }
                    ensure!(n > 0, "no result arm has case {v}");
                }
                "class" => preds.push((
                    w.to_string(),
                    Pred::Class(
                        Class::ALL
                            .into_iter()
                            .find(|c| c.name() == v)
                            .with_context(|| format!("unknown value class {v}"))?,
                    ),
                )),
                "depth" => preds.push((w.to_string(), Pred::Depth(v.parse()?))),
                "meta" => preds.push((
                    w.to_string(),
                    Pred::Id(id(&format!("LedgerCloseMeta::{v}"))?),
                )),
                "upgrades" => preds.push((w.to_string(), Pred::Class(Class::LedgerUpgrades))),
                "any" => preds.push((w.to_string(), Pred::Any)),
                "scp" => preds.push((w.to_string(), Pred::Id(id("SCPHistoryEntry::v0")?))),
                "uncovered" => {
                    let g = super::coverage::arms::gather(corpus, false, None, None)?;
                    for r in super::coverage::arms::rows(corpus, &g)? {
                        if !r.covered() {
                            preds.push((format!("arm:{}", r.label), Pred::Id(id(&r.label)?)));
                        }
                    }
                }
                _ => bail!("unknown predicate {w}"),
            }
        }
        ensure!(!preds.is_empty(), "--want names no predicate");
        let mut seen = BTreeSet::new();
        preds.retain(|(n, _)| seen.insert(n.clone()));
        Ok(Wants { preds })
    }

    /// Drop the predicates an earlier run (its `mined.json`) kept at least `first` ledgers for.
    pub fn except(&mut self, mined: &Value, first: usize) -> usize {
        let done = |n: &str| {
            mined["kept_per_predicate"][n]
                .as_u64()
                .is_some_and(|c| c as usize >= first)
        };
        let before = self.preds.len();
        self.preds.retain(|(n, _)| !done(n));
        before - self.preds.len()
    }

    /// The predicates `t` matches, by index.
    pub fn matches(&self, t: &Tally) -> Vec<usize> {
        self.preds
            .iter()
            .enumerate()
            .filter(|(_, (_, p))| match p {
                Pred::Any => true,
                Pred::Id(i) => t.hit(*i) > 0,
                Pred::InBytes(i) => t.hit_in_bytes(*i) > 0,
                Pred::Class(c) => t.class(*c) > 0,
                Pred::Depth(n) => t.max_scval_depth >= *n,
            })
            .map(|(i, _)| i)
            .collect()
    }
}

/// Where objects come from.
pub enum Source {
    Lake { pins: Pins },
    Dir(PathBuf),
}

/// What fetching one ledger gave.
pub enum Got {
    Object(Vec<u8>),
    Gone(u16),
}

impl Source {
    fn store(&self, network: Network, seq: u32) -> Result<(String, String)> {
        match self {
            Source::Lake { pins } => {
                let l = lake::locate(pins, network, seq)?;
                Ok((l.store, l.key))
            }
            Source::Dir(d) => Ok((d.display().to_string(), lake::object_key(seq))),
        }
    }

    fn get(&self, network: Network, seq: u32) -> Result<Got> {
        match self {
            Source::Dir(d) => match std::fs::read(d.join(lake::object_key(seq))) {
                Ok(b) => Ok(Got::Object(b)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Got::Gone(404)),
                Err(e) => Err(e.into()),
            },
            Source::Lake { pins } => {
                let url = lake::locate(pins, network, seq)?.url;
                for attempt in 0..=MAX_RETRIES {
                    let (status, headers, body) = match curl_get(&url) {
                        Ok(r) => r,
                        // A transport failure (reset, timeout) is retried like a 5xx.
                        Err(e) if attempt < MAX_RETRIES => {
                            let wait = 2u64.pow(attempt + 1);
                            eprintln!("{e:#}; retrying in {wait}s");
                            std::thread::sleep(std::time::Duration::from_secs(wait));
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                    match status {
                        200 => return Ok(Got::Object(body)),
                        403 | 404 => return Ok(Got::Gone(status)),
                        429 | 500..=599 if attempt < MAX_RETRIES => {
                            let wait = retry_after(&headers)
                                .unwrap_or(2u64.pow(attempt + 1))
                                .min(MAX_RETRY_WAIT);
                            eprintln!("{url}: HTTP {status}, retrying in {wait}s");
                            std::thread::sleep(std::time::Duration::from_secs(wait));
                        }
                        s => bail!("{url}: HTTP {s}"),
                    }
                }
                bail!("{url}: gave up after {MAX_RETRIES} retries")
            }
        }
    }
}

/// `GET` with the response headers on stderr; returns (status, headers, body).
fn curl_get(url: &str) -> Result<(u16, String, Vec<u8>)> {
    let out = Command::new("curl")
        .args(["-sS", "--max-time", "300", "-D", "/dev/stderr", url])
        .output()
        .context("run curl (is it installed?)")?;
    ensure!(
        out.status.success(),
        "curl {url} failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let headers = String::from_utf8_lossy(&out.stderr).to_string();
    let status = headers
        .split("\r\n\r\n")
        .filter(|b| b.trim_start().starts_with("HTTP/"))
        .last()
        .and_then(|b| b.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .context("no HTTP status from curl")?;
    Ok((status, headers, out.stdout))
}

/// `Retry-After` in seconds (the delta form; an HTTP date counts as absent).
pub fn retry_after(headers: &str) -> Option<u64> {
    headers.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.trim()
            .eq_ignore_ascii_case("retry-after")
            .then(|| v.trim().parse().ok())
            .flatten()
    })
}

/// One kept ledger.
#[derive(Debug, Clone)]
pub struct Kept {
    pub seq: u32,
    pub record: Value,
    pub object: Vec<u8>,
}

/// The outcome of one run.
pub struct Mined {
    pub kept: Vec<Kept>,
    pub looked_at: u64,
    /// Ledgers the source does not have (`403`/`404`).
    pub missing: u64,
    /// Ledgers that could not be fetched after the retries (reported, not decided).
    pub unfetched: Vec<u32>,
    pub fetched_bytes: u64,
    pub ended: String,
    /// Kept ledgers per predicate.
    pub per_pred: Vec<usize>,
    /// Objects whose ledger protocol is above the corpus gate and that still decoded.
    pub above_max: u64,
    /// The highest such protocol (0 when none).
    pub highest_protocol: u32,
    /// Objects above the corpus gate that did not decode: sequence, protocol, the oracle's error and
    /// the unknown shape.
    pub undecoded: Vec<Value>,
}

/// How kept ledgers are chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pick {
    /// The K smallest matching objects per predicate over the whole range.
    Smallest,
    /// The first K matching ledgers per predicate; the run ends when every predicate has them.
    First,
}

impl Pick {
    pub fn parse(s: &str) -> Result<Pick> {
        match s {
            "smallest" => Ok(Pick::Smallest),
            "first" => Ok(Pick::First),
            _ => bail!("--pick {s}: expected smallest or first"),
        }
    }
}

/// The K smallest candidates of each predicate, by (object bytes, sequence).
#[derive(Debug, Default)]
pub struct Smallest {
    pub k: usize,
    /// Per predicate, sorted ascending.
    pub best: Vec<Vec<(u64, u32)>>,
}

impl Smallest {
    pub fn new(k: usize, preds: usize) -> Smallest {
        Smallest {
            k: k.max(1),
            best: vec![Vec::new(); preds],
        }
    }

    /// Offer a ledger matching `matched`; true when it entered some predicate's K smallest.
    pub fn offer(&mut self, seq: u32, bytes: u64, matched: &[usize]) -> bool {
        let mut entered = false;
        for &i in matched {
            let b = &mut self.best[i];
            let at = b.partition_point(|&c| c < (bytes, seq));
            if at < self.k {
                b.insert(at, (bytes, seq));
                b.truncate(self.k);
                entered = true;
            }
        }
        entered
    }

    /// The predicates whose K smallest hold `seq`.
    pub fn kept_for(&self, seq: u32) -> Vec<usize> {
        (0..self.best.len())
            .filter(|&i| self.best[i].iter().any(|&(_, s)| s == seq))
            .collect()
    }
}

pub struct Plan<'a> {
    pub network: Network,
    pub from: u32,
    pub to: u32,
    pub step: u32,
    pub first: usize,
    pub pick: Pick,
    pub max_bytes: u64,
    pub jobs: usize,
    pub wants: &'a Wants,
    pub gate: Gate,
}

/// Where a lake object leaves the pinned XDR definitions: the error of a definitions walk over its
/// `LedgerCloseMetaBatch` (for example `TransactionMeta: no arm for 5`), which names the union or
/// enum and the value the definitions do not declare.
pub fn unknown_shapes(object: &[u8]) -> String {
    let xdr = match xdrcheck_xdr::batch::decompress(object) {
        Ok(x) => x,
        Err(e) => return format!("the object does not decompress: {e}"),
    };
    let walked = xdrcheck_xdr::with_stack(Limits::default().stack_size, || {
        Defs::pinned().walk("LedgerCloseMetaBatch", &xdr, &mut Tally::default())
    });
    match walked {
        Ok(()) => "the definitions walk accepts every value; only the oracle's checks refuse it"
            .to_string(),
        Err(e) => format!("{e:#}"),
    }
}

/// Run the miner over `plan`'s range.
///
/// The live network can be ahead of the corpus gate (`plan.gate`) after an upgrade that came with
/// little notice. Ledgers above the gate are read with its protocol ceiling lifted
/// ([`Gate::reading_live`]): one that decodes is decided like any other and counted in
/// `above_max`; one that does not is listed in `undecoded` with the unknown shape it holds
/// ([`unknown_shapes`]), and the run goes on.
pub fn mine(source: &Source, plan: &Plan) -> Result<Mined> {
    let d = Defs::pinned();
    let limits = Limits::default();
    let live = plan.gate.reading_live();
    let mut out = Mined {
        kept: Vec::new(),
        looked_at: 0,
        missing: 0,
        unfetched: Vec::new(),
        fetched_bytes: 0,
        ended: "range end".to_string(),
        per_pred: vec![0; plan.wants.preds.len()],
        above_max: 0,
        highest_protocol: 0,
        undecoded: Vec::new(),
    };
    let mut kept_bytes = 0u64;
    let mut smallest = Smallest::new(plan.first, plan.wants.preds.len());
    let mut gone_run = 0u32;
    let seqs: Vec<u32> = (plan.from..=plan.to)
        .step_by(plan.step.max(1) as usize)
        .collect();
    'outer: for window in seqs.chunks(plan.jobs.max(1) * 4) {
        // Fetch a window concurrently, then decide in sequence order.
        let fetched: Vec<(u32, Result<Got>)> = std::thread::scope(|s| {
            let chunks: Vec<_> = window
                .chunks(window.len().div_ceil(plan.jobs.max(1)))
                .map(|c| {
                    s.spawn(move || {
                        c.iter()
                            .map(|&q| (q, source.get(plan.network, q)))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            chunks
                .into_iter()
                .flat_map(|h| h.join().expect("fetch thread"))
                .collect()
        });
        for (seq, got) in fetched {
            let got = match got {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("warning: ledger {seq} not fetched: {e:#}");
                    out.unfetched.push(seq);
                    continue;
                }
            };
            let object = match got {
                Got::Object(b) => {
                    gone_run = 0;
                    b
                }
                Got::Gone(status) => {
                    out.missing += 1;
                    gone_run += 1;
                    if gone_run >= GONE_RUN_END {
                        out.ended = format!(
                            "ledger {seq}: HTTP {status} for {GONE_RUN_END} ledgers in a row (past the tip or gone)"
                        );
                        break 'outer;
                    }
                    continue;
                }
            };
            out.looked_at += 1;
            if out.looked_at.is_multiple_of(1000) {
                eprintln!(
                    "mine: {} ledgers looked at (at {seq}), {} kept",
                    out.looked_at,
                    out.kept.len()
                );
            }
            out.fetched_bytes += object.len() as u64;
            let batch = match xdrcheck_xdr::unpack_object(&object, &limits, &live) {
                Ok(b) => b,
                Err(e) => {
                    // Above the gate an undecodable ledger is the expected sign of a new shape:
                    // record which definition the bytes leave and go on. At or below it, the
                    // oracle's refusal stands.
                    let Some(p) = lake::object_protocol(&object)
                        .filter(|&p| plan.gate.above_max(p).is_some())
                    else {
                        return Err(anyhow::Error::from(e)).with_context(|| {
                            format!("ledger {seq}: the oracle does not accept the object")
                        });
                    };
                    let unknown = unknown_shapes(&object);
                    eprintln!(
                        "warning: ledger {seq} (protocol {p}) does not decode with the pinned \
                         definitions: {unknown}"
                    );
                    out.undecoded.push(json!({
                        "ledger_seq": seq,
                        "protocol": p,
                        "oracle_error": format!("{e}"),
                        "unknown": unknown,
                    }));
                    continue;
                }
            };
            if let Some(p) = batch.infos.iter().map(|i| i.protocol).max() {
                if let Some(w) = plan.gate.above_max(p) {
                    if out.above_max == 0 {
                        eprintln!("warning: ledger {seq}: {w}");
                    }
                    out.above_max += 1;
                    out.highest_protocol = out.highest_protocol.max(p);
                }
            }
            let mut t = Tally::default();
            let walked = xdrcheck_xdr::with_stack(limits.stack_size, || -> Result<()> {
                for l in &batch.ledgers {
                    d.walk("LedgerCloseMeta", l, &mut t)?;
                }
                Ok(())
            });
            walked.with_context(|| format!("ledger {seq}: walk"))?;
            let matched = plan.wants.matches(&t);
            if plan.pick == Pick::Smallest {
                let size = object.len() as u64;
                if matched.is_empty() || !smallest.offer(seq, size, &matched) {
                    continue;
                }
                let (store, key) = source.store(plan.network, seq)?;
                let mut record = check_ledger(&batch, plan, seq, &store, &key, &object, &limits)?;
                record["matched"] = json!(matched
                    .iter()
                    .map(|&i| plan.wants.preds[i].0.clone())
                    .collect::<Vec<_>>());
                out.kept.push(Kept {
                    seq,
                    record,
                    object,
                });
                // Keep only the ledgers some predicate still holds.
                out.kept.retain(|k| !smallest.kept_for(k.seq).is_empty());
                continue;
            }
            let wanted: Vec<usize> = matched
                .iter()
                .copied()
                .filter(|&i| out.per_pred[i] < plan.first)
                .collect();
            if wanted.is_empty() {
                continue;
            }
            if kept_bytes + object.len() as u64 > plan.max_bytes {
                out.ended = format!("byte cap {} reached at ledger {seq}", plan.max_bytes);
                break 'outer;
            }
            for &i in &wanted {
                out.per_pred[i] += 1;
            }
            kept_bytes += object.len() as u64;
            let (store, key) = source.store(plan.network, seq)?;
            let record = check_ledger(&batch, plan, seq, &store, &key, &object, &limits)?;
            let names = |ix: &[usize]| -> Vec<String> {
                ix.iter().map(|&i| plan.wants.preds[i].0.clone()).collect()
            };
            let mut record = record;
            record["matched"] = json!(names(&matched));
            record["kept_for"] = json!(names(&wanted));
            out.kept.push(Kept {
                seq,
                record,
                object,
            });
            if out.per_pred.iter().all(|&n| n >= plan.first) {
                out.ended = "every predicate satisfied".to_string();
                break 'outer;
            }
        }
    }
    if plan.pick == Pick::Smallest {
        let mut total = 0u64;
        let mut over = Vec::new();
        out.kept.retain(|k| {
            total += k.object.len() as u64;
            if total > plan.max_bytes {
                over.push(k.seq);
                total -= k.object.len() as u64;
                false
            } else {
                true
            }
        });
        if !over.is_empty() {
            out.ended = format!(
                "range end; byte cap {} left out ledgers {over:?}",
                plan.max_bytes
            );
        }
        for k in &mut out.kept {
            let ix = smallest.kept_for(k.seq);
            for &i in &ix {
                out.per_pred[i] += 1;
            }
            k.record["kept_for"] = json!(ix
                .iter()
                .map(|&i| plan.wants.preds[i].0.clone())
                .collect::<Vec<_>>());
        }
    }
    Ok(out)
}

/// The independent checks of a kept ledger: header hash recomputed, transaction hashes recomputed
/// from the envelopes under the network passphrase.
fn check_ledger(
    batch: &xdrcheck_xdr::Batch,
    plan: &Plan,
    seq: u32,
    store: &str,
    key: &str,
    object: &[u8],
    limits: &Limits,
) -> Result<Value> {
    ensure!(
        batch.ledgers.len() == 1 && batch.infos[0].sequence == seq,
        "ledger {seq}: the object holds {} ledgers starting at {}",
        batch.ledgers.len(),
        batch.start_sequence
    );
    let blob = &batch.ledgers[0];
    let info = &batch.infos[0];
    let live = plan.gate.reading_live();
    let summary = super::intake::ledger::summarise(blob, plan.network.passphrase(), limits, &live)
        .with_context(|| format!("ledger {seq}: transaction hashes"))?;
    let lcm = xdrcheck_xdr::with_stack(limits.stack_size, || {
        xdrcheck_xdr::decode_ledger(blob, limits, &live)
    })?;
    let header = match &lcm {
        LedgerCloseMeta::V0(m) => &m.ledger_header,
        LedgerCloseMeta::V1(m) => &m.ledger_header,
        LedgerCloseMeta::V2(m) => &m.ledger_header,
    };
    let recomputed = hex::encode(Sha256::digest(header.header.to_xdr(XdrLimits::none())?));
    let stored = hex::encode(info.header_hash);
    ensure!(
        recomputed == stored,
        "ledger {seq}: stored header hash {stored} is not the hash of the header ({recomputed})"
    );
    Ok(json!({
        "network": plan.network.name(),
        "passphrase": plan.network.passphrase(),
        "ledger_seq": seq,
        "protocol": info.protocol,
        "ledger_close_meta_version": info.ledger_close_meta_version,
        "store": store,
        "key": key,
        "object_sha256": xdrcheck_xdr::sha256_hex(object),
        "object_bytes": object.len(),
        "blob_sha256": xdrcheck_xdr::sha256_hex(blob),
        "header_hash": stored,
        "header_hash_recomputed": true,
        "previous_ledger_hash": hex::encode(header.header.previous_ledger_hash.0),
        "tx_count": summary.tx_hashes.len(),
        "close_time": summary.close_time,
        "tx_hashes_recomputed": true,
        "above_max_protocol": plan.gate.above_max(info.protocol).is_some(),
    }))
}

/// Parse `A..B` (inclusive).
pub fn parse_range(s: &str) -> Result<(u32, u32)> {
    let (a, b) = s
        .split_once("..")
        .with_context(|| format!("range {s:?} is not A..B"))?;
    let (a, b): (u32, u32) = (a.trim().parse()?, b.trim().parse()?);
    ensure!(a <= b, "range {s}: start after end");
    Ok((a, b))
}

/// Write the kept objects and `mined.json` under `out`. `max_protocol` is the corpus gate the run
/// compared ledgers with.
pub fn write(
    out: &Path,
    args_echo: &Value,
    m: &Mined,
    wants: &Wants,
    max_protocol: u32,
) -> Result<()> {
    let mut list = Vec::new();
    for k in &m.kept {
        let net = k.record["network"].as_str().unwrap_or_default();
        let key = k.record["key"].as_str().unwrap_or_default();
        let dir = out.join(net).join(k.seq.to_string());
        std::fs::create_dir_all(&dir)?;
        let name = key.rsplit('/').next().unwrap_or(key);
        super::intake::util::write_atomic(&dir.join(name), &k.object)?;
        list.push(k.record.clone());
    }
    let per: BTreeMap<String, usize> = wants
        .preds
        .iter()
        .zip(&m.per_pred)
        .map(|((n, _), &c)| (n.clone(), c))
        .collect();
    let j = json!({
        "schema": "xcc.mined/v1",
        "command": args_echo,
        "looked_at": m.looked_at,
        "missing": m.missing,
        "unfetched": m.unfetched,
        "fetched_bytes": m.fetched_bytes,
        "ended": m.ended,
        "kept_per_predicate": per,
        "kept": list,
        "max_protocol": max_protocol,
        "above_max_protocol": m.above_max,
        "highest_protocol_above_max": (m.highest_protocol > 0).then_some(m.highest_protocol),
        "undecoded": m.undecoded,
    });
    std::fs::create_dir_all(out)?;
    super::intake::util::write_json(&out.join("mined.json"), &j)
}

pub fn run(corpus: &Path, a: Args) -> Result<ExitCode> {
    let network = Network::parse(&a.network)?;
    let (from, to) = parse_range(&a.range)?;
    let mut wants = Wants::parse(corpus, &a.want)?;
    for e in &a.except {
        let j: Value = serde_json::from_slice(
            &std::fs::read(e).with_context(|| format!("read {}", e.display()))?,
        )
        .with_context(|| format!("{} is not JSON", e.display()))?;
        let n = wants.except(&j, a.first);
        println!("{}: {n} predicates already satisfied, dropped", e.display());
    }
    ensure!(
        !wants.preds.is_empty(),
        "every predicate is already satisfied"
    );
    let gate = Gate::from_corpus_json(&corpus.join("corpus.json"))?.unwrap_or_default();
    let source = match &a.lake {
        Some(d) => Source::Dir(d.clone()),
        None => Source::Lake {
            pins: Pins::load(corpus)?,
        },
    };
    let out_dir = match &a.out {
        Some(o) => o.clone(),
        None => super::intake::golden::cache_root()?.join("mined"),
    };
    let plan = Plan {
        network,
        from,
        to,
        step: a.step,
        first: a.first,
        pick: Pick::parse(&a.pick)?,
        max_bytes: a.max_bytes,
        jobs: a.jobs,
        wants: &wants,
        gate,
    };
    let m = mine(&source, &plan)?;
    let echo = json!({
        "network": a.network, "range": a.range, "want": a.want, "first": a.first, "pick": a.pick,
        "except": a.except.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "max_bytes": a.max_bytes, "step": a.step,
        "source": if a.lake.is_some() { "local directory" } else { "public lake" },
    });
    write(&out_dir, &echo, &m, &wants, gate.max_protocol)?;
    println!(
        "mined {} {}..{}: looked at {} ledgers ({} missing, {} bytes), kept {}; ended: {}",
        network.name(),
        from,
        to,
        m.looked_at,
        m.missing,
        m.fetched_bytes,
        m.kept.len(),
        m.ended
    );
    for ((n, _), c) in wants.preds.iter().zip(&m.per_pred) {
        if *c > 0 || wants.preds.len() <= 40 {
            println!("  {n}: {c}");
        }
    }
    for k in &m.kept {
        println!("  kept {} for {}", k.seq, k.record["kept_for"]);
    }
    if m.above_max > 0 || !m.undecoded.is_empty() {
        println!(
            "warning: {} ledgers above the corpus gate {} decoded (highest protocol {}), {} did not \
             (listed under undecoded in mined.json): the network has moved past the pins; see \
             docs/maintenance.md, section 5.2",
            m.above_max,
            gate.max_protocol,
            m.highest_protocol,
            m.undecoded.len()
        );
    }
    println!("wrote {}", out_dir.join("mined.json").display());
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
    }

    /// A two-object lake laid out like the testnet store, from the corpus's vendored objects.
    fn fixture_lake(name: &str) -> (PathBuf, u32, u32) {
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"));
        let root = target
            .join("xdrcheck-test-mine")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (a, b) = (5_277_327u32, 5_277_328u32);
        for seq in [a, b] {
            let key = lake::object_key(seq);
            let src = corpus()
                .join("objects/testnet")
                .join(seq.to_string())
                .join(key.rsplit('/').next().unwrap());
            let dst = root.join("lake").join(&key);
            std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
            std::fs::copy(&src, &dst).unwrap();
        }
        (root, a, b)
    }

    fn run_once(root: &Path, out: &str, from: u32, to: u32, pick: Pick) -> Vec<(u32, Value)> {
        let wants = Wants::parse(
            &corpus(),
            "meta:v1,meta:v2,class:u64-high,upgrades,arm:StellarValueExt::STELLAR_VALUE_EMPTY_TX_SET_MS",
        )
        .unwrap();
        let plan = Plan {
            network: Network::Testnet,
            from,
            to: to + 1, // one past the fixture: a missing ledger
            step: 1,
            first: 1,
            pick,
            max_bytes: 1 << 30,
            jobs: 2,
            wants: &wants,
            gate: Gate::from_corpus_json(&corpus().join("corpus.json"))
                .unwrap()
                .unwrap_or_default(),
        };
        let m = mine(&Source::Dir(root.join("lake")), &plan).unwrap();
        assert_eq!((m.ended.as_str(), m.missing), ("range end", 1));
        write(
            &root.join(out),
            &json!({}),
            &m,
            &wants,
            plan.gate.max_protocol,
        )
        .unwrap();
        m.kept
            .into_iter()
            .map(|k| (k.seq, k.record["kept_for"].clone()))
            .collect()
    }

    #[test]
    fn mine_keeps_the_same_ledgers_on_two_runs() {
        let (root, a, b) = fixture_lake("same");
        let one = run_once(&root, "one", a, b, Pick::Smallest);
        let two = run_once(&root, "two", a, b, Pick::Smallest);
        assert!(!one.is_empty());
        assert_eq!(one, two);
        // Ledger a is the smaller object and comes first: both picks keep it; written objects are
        // the lake's bytes.
        assert_eq!(one[0].0, a);
        assert_eq!(run_once(&root, "first", a, b, Pick::First)[0].0, a);
        let j: Value =
            serde_json::from_slice(&std::fs::read(root.join("one/mined.json")).unwrap()).unwrap();
        for k in j["kept"].as_array().unwrap() {
            let key = k["key"].as_str().unwrap();
            let seq = k["ledger_seq"].as_u64().unwrap();
            let kept = root
                .join("one/testnet")
                .join(seq.to_string())
                .join(key.rsplit('/').next().unwrap());
            assert_eq!(
                xdrcheck_xdr::sha256_file(&kept).unwrap(),
                k["object_sha256"].as_str().unwrap()
            );
            assert_eq!(k["header_hash_recomputed"], true);
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A lake object rewritten as a network ahead of the pins would write it: the ledger header's
    /// protocol set to `protocol` (and the stored header hash recomputed), and with `unknown_arm`
    /// the first transaction's `TransactionMeta` discriminant set to 99, a shape no definition has.
    pub(crate) fn synthetic_object(object: &[u8], protocol: u32, unknown_arm: bool) -> Vec<u8> {
        use xdrcheck_xdr::xdr::{Hash, ReadXdr};
        let xdr = xdrcheck_xdr::batch::decompress(object).unwrap();
        let mut lcm = LedgerCloseMeta::from_xdr(&xdr[12..], XdrLimits::none()).unwrap();
        let (header, meta) = match &mut lcm {
            LedgerCloseMeta::V0(m) => (&mut m.ledger_header, None),
            LedgerCloseMeta::V1(m) => (
                &mut m.ledger_header,
                m.tx_processing
                    .first()
                    .map(|t| t.tx_apply_processing.clone()),
            ),
            LedgerCloseMeta::V2(m) => (
                &mut m.ledger_header,
                m.tx_processing
                    .first()
                    .map(|t| t.tx_apply_processing.clone()),
            ),
        };
        header.header.ledger_version = protocol;
        header.hash = Hash(Sha256::digest(header.header.to_xdr(XdrLimits::none()).unwrap()).into());
        let mut bytes = lcm.to_xdr(XdrLimits::none()).unwrap();
        if unknown_arm {
            let m = meta
                .expect("the fixture ledger has a transaction")
                .to_xdr(XdrLimits::none())
                .unwrap();
            let at: Vec<usize> = bytes
                .windows(m.len())
                .enumerate()
                .filter(|(_, w)| *w == m.as_slice())
                .map(|(i, _)| i)
                .collect();
            assert_eq!(at.len(), 1, "the transaction meta is found once");
            bytes[at[0]..at[0] + 4].copy_from_slice(&99u32.to_be_bytes());
        }
        let mut batch = xdr[..12].to_vec();
        batch.extend_from_slice(&bytes);
        xdrcheck_xdr::batch::compress(&batch, 3).unwrap()
    }

    /// The network ahead of the pins: a ledger one protocol above the gate that still decodes is
    /// mined and marked; one that holds a shape the definitions lack is listed with that shape and
    /// the run goes on; at or below the gate the same unknown shape still ends the run.
    #[test]
    fn mine_reads_ledgers_above_the_gate_and_names_unknown_shapes() {
        let (root, a, b) = fixture_lake("above");
        let gate = Gate::from_corpus_json(&corpus().join("corpus.json"))
            .unwrap()
            .unwrap_or_default();
        let next = gate.max_protocol + 1;
        let path = |seq: u32| root.join("lake").join(lake::object_key(seq));
        let (oa, ob) = (
            std::fs::read(path(a)).unwrap(),
            std::fs::read(path(b)).unwrap(),
        );
        std::fs::write(path(a), synthetic_object(&oa, next, false)).unwrap();
        std::fs::write(path(b), synthetic_object(&ob, next, true)).unwrap();
        let wants = Wants::parse(&corpus(), "any").unwrap();
        let plan = Plan {
            network: Network::Testnet,
            from: a,
            to: b,
            step: 1,
            first: 5,
            pick: Pick::First,
            max_bytes: 1 << 30,
            jobs: 1,
            wants: &wants,
            gate,
        };
        let m = mine(&Source::Dir(root.join("lake")), &plan).unwrap();
        assert_eq!((m.above_max, m.highest_protocol), (1, next));
        assert_eq!(m.kept.len(), 1);
        assert_eq!(m.kept[0].seq, a);
        assert_eq!(m.kept[0].record["protocol"], next);
        assert_eq!(m.kept[0].record["above_max_protocol"], true);
        assert_eq!(m.undecoded.len(), 1);
        assert_eq!(m.undecoded[0]["ledger_seq"], b);
        assert_eq!(m.undecoded[0]["protocol"], next);
        let unknown = m.undecoded[0]["unknown"].as_str().unwrap();
        assert!(
            unknown.contains("TransactionMeta: no arm for 99"),
            "{unknown}"
        );
        write(&root.join("out"), &json!({}), &m, &wants, gate.max_protocol).unwrap();
        let j: Value =
            serde_json::from_slice(&std::fs::read(root.join("out/mined.json")).unwrap()).unwrap();
        assert_eq!(j["above_max_protocol"], 1);
        assert_eq!(j["highest_protocol_above_max"], next);
        assert_eq!(j["undecoded"][0]["ledger_seq"], b);

        // The same unknown shape at the gate's own protocol is a refusal, as before.
        std::fs::write(path(b), synthetic_object(&ob, gate.max_protocol, true)).unwrap();
        let e = mine(&Source::Dir(root.join("lake")), &plan).err().unwrap();
        assert!(
            format!("{e:#}").contains("the oracle does not accept the object"),
            "{e:#}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn smallest_keeps_the_k_smallest_per_predicate() {
        let mut s = Smallest::new(1, 2);
        assert!(s.offer(10, 900, &[0, 1]));
        assert!(s.offer(11, 500, &[0]));
        assert!(!s.offer(12, 950, &[0, 1]));
        // A tie in bytes goes to the lower sequence.
        assert!(!s.offer(13, 900, &[1]));
        assert_eq!((s.kept_for(10), s.kept_for(11)), (vec![1], vec![0]));
        assert!(s.kept_for(12).is_empty());
        let mut w = Wants {
            preds: vec![("a".into(), Pred::Any), ("b".into(), Pred::Depth(3))],
        };
        assert_eq!(
            w.except(&json!({"kept_per_predicate": {"a": 1, "b": 0}}), 1),
            1
        );
        assert_eq!(w.preds[0].0, "b");
    }

    #[test]
    fn mine_predicates_parse() {
        let w = Wants::parse(&corpus(), "uncovered,result:txFROZEN_KEY_ACCESSED,depth:10").unwrap();
        assert!(w.preds.iter().any(|(n, _)| n == "depth:10"));
        assert!(w
            .preds
            .iter()
            .any(|(n, _)| n == "result:TransactionResultResult::txFROZEN_KEY_ACCESSED"));
        assert!(Wants::parse(&corpus(), "arm:NoSuch::ARM").is_err());
        assert_eq!(retry_after("HTTP/1.1 503\r\nRetry-After: 7\r\n"), Some(7));
        assert_eq!(parse_range("5..9").unwrap(), (5, 9));
    }
}
