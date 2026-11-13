//! AG-4, the golden mirror (`docs/architecture.md`, `docs/manifest.md` §4.7), computed on the
//! corpus's own bytes.
//!
//! **What "agree" can mean.** A local-core entry and a golden from stellar-core's own tests are
//! written by the same stellar-core release but by different runs: other accounts, keys, ledger
//! numbers, close times, setups and meta flags. Their bytes can never be equal. What can be equal is
//! the *shape*: which arms, optional fields, lengths, ledger-entry changes and result codes the
//! transaction has. AG-4 compares two measures of it, both recomputed from both sets of bytes on
//! every run, and claims nothing beyond them:
//!
//! - the **profile-free skeleton** ([`profile_free`], `xdrcheck_meta::skeleton`): envelope, result,
//!   fee processing, every ledger-entry change, contract events and return value, post-apply fee
//!   processing; union arms, enum values and exact array lengths kept, every other leaf masked
//!   (including the presence of an optional integer), and the parts that exist only because a meta
//!   flag is set removed from both sides;
//! - the **reduced shape tokens** (`ag4_shape`): the scan's own tokens of each component, which
//!   record what the skeleton masks: optional presence, the fields each updated entry changed, flag
//!   transitions, operation-versus-effect relations and event signatures; meta-flag parts and the
//!   account's sequence-time fields (run timing) removed.
//!
//! **Tiers.** `corpus/mirrors.json` is the committed, reviewable result of a search over the whole
//! golden set:
//!
//! - `mapped` (the transaction tier): the variants whose focus transaction has both the skeleton and
//!   the reduced tokens of a golden transaction, with the first such golden in index order;
//! - `operations` (the operation tier), for entries without such a golden: the variants every
//!   distinct operation of which has a golden operation of the same reduced shape (body, result,
//!   ledger-entry changes, Soroban contract events), one golden per operation shape. This tier says
//!   nothing about the envelope, fee processing or transaction-level meta;
//! - `unmapped`: every local-core entry without a golden transaction, with the reason;
//! - `golden_operations`: every reduced operation shape of the golden set with its first golden
//!   (the golden side of the reverse coverage; `coverage` adds the entries that hold each shape).
//!
//! `verify --checks ag4 --write-mirrors` rewrites the file from a fresh search. That every
//! local-core entry is listed is also checked without the golden cache, by `coverage --check`.
//!
//! **Rows.**
//! - one per listed variant: its measures, computed now from its blob, equal the named golden's,
//!   computed now from the golden file (whose sha256 must match the index);
//! - one per unlisted local-core variant that the search now finds a golden transaction or golden
//!   operations for (the list is stale: fail);
//! - whole-corpus runs: `mirrors.json` (every local-core entry is listed exactly once, nothing else
//!   is, and `golden_operations` equals a fresh computation) and `floor:ag4` (at least one AG-4
//!   row, and every entry either tier lists has passing rows: fewer passing entries than listed
//!   fails).
//!
//! The `mirrors` block of a manifest entry (recorded hashes of one-off mirror runs) is provenance,
//! not part of this check. A missing golden cache is a tool error (exit 2).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use xdrcheck_meta::skeleton::{canon, diff, tx_skeleton, Skeleton};
use xdrcheck_xdr::xdr::LedgerCloseMeta;

use super::ag4_shape::{ledger_tokens, op_ref_json, OpShape, TxTokens};
use super::load::Entry;
use super::model::{Check, Counts, Ctx, Row};

/// stellar-core's fixed unit-test passphrase, under which every golden is written.
const CORE_TEST_PASSPHRASE: &str = "(V) (;,,;) (V)";

/// The committed mapping, relative to the corpus root.
pub const MIRRORS_FILE: &str = "mirrors.json";

/// Reason recorded for an entry no golden covers.
const NO_GOLDEN: &str = "no golden covers this shape";

/// Reason recorded for an entry without a golden transaction of its shape, every operation of
/// which (in at least one variant) has a golden operation of the same reduced shape.
const OPS_ONLY: &str =
    "no golden transaction of this shape; every operation has a golden operation of the same shape";

/// Reason recorded for an entry whose ledgers hold no transaction (an upgrade or empty ledger):
/// there is no focus transaction to compare.
const NO_TX: &str = "no transaction: a ledger-level pattern";

/// Operation arms whose contract events stellar-core emits whatever the meta flags.
const SOROBAN_OPS: [&str; 3] = [
    "invoke_host_function",
    "extend_footprint_ttl",
    "restore_footprint",
];

// --- The profile-free skeleton. ----------------------------------------------------------------

/// A transaction skeleton reduced to the parts no meta flag changes, with its hash.
#[derive(Debug, Clone)]
pub struct Shape {
    pub sections: Map<String, Value>,
    pub hash: String,
}

/// Remove from a transaction skeleton every part that exists only because a meta flag is set
/// (stellar-core v30.0.0 `src/transactions/EventManager.cpp`, `TransactionMeta.cpp`):
///
/// - `meta.diagnostic_events`, and `diagnostic_events` inside `soroban_meta`
///   (`ENABLE_SOROBAN_DIAGNOSTIC_EVENTS`);
/// - `meta.events`, the transaction-level fee events, and the `events` of every operation that is
///   not a Soroban operation (`EMIT_CLASSIC_EVENTS`; `BACKFILL_STELLAR_ASSET_EVENTS` before
///   Protocol 23);
/// - `ext` inside `soroban_meta` (`EMIT_SOROBAN_TRANSACTION_META_EXT_V1`).
///
/// A Soroban operation's events are contract events, emitted under every profile, and stay.
pub fn profile_free(s: &Skeleton) -> Shape {
    let mut sections = s.sections.clone();
    sections.remove("meta.diagnostic_events");
    sections.remove("meta.events");
    let soroban = sections
        .get("envelope")
        .map(operation_arms)
        .unwrap_or_default()
        .into_iter()
        .map(|arm| SOROBAN_OPS.contains(&arm.as_str()))
        .collect::<Vec<_>>();
    if let Some(items) = sections
        .get_mut("meta.operations")
        .and_then(|o| o.get_mut("items"))
        .and_then(Value::as_array_mut)
    {
        for (i, op) in items.iter_mut().enumerate() {
            if !soroban.get(i).copied().unwrap_or(false) {
                if let Some(o) = op.as_object_mut() {
                    o.remove("events");
                }
            }
        }
    }
    if let Some(m) = sections
        .get_mut("meta.soroban_meta")
        .and_then(|v| v.get_mut("?"))
        .and_then(Value::as_object_mut)
    {
        m.remove("ext");
        m.remove("diagnostic_events");
    }
    let hash = hex::encode(Sha256::digest(
        canon(&Value::Object(sections.clone())).as_bytes(),
    ));
    Shape { sections, hash }
}

/// The operation arms of an envelope skeleton, in order (the first `operations` array found, which
/// for a fee bump is the inner transaction's).
fn operation_arms(env: &Value) -> Vec<String> {
    fn find(v: &Value) -> Option<&Vec<Value>> {
        match v {
            Value::Object(o) => {
                if let Some(items) = o
                    .get("operations")
                    .and_then(|ops| ops.get("items"))
                    .and_then(Value::as_array)
                {
                    return Some(items);
                }
                o.values().find_map(find)
            }
            Value::Array(a) => a.iter().find_map(find),
            _ => None,
        }
    }
    find(env)
        .into_iter()
        .flatten()
        .map(|op| op["body"]["|"].as_str().unwrap_or("").to_string())
        .collect()
}

/// A cheap key every transaction with an equal skeleton shares: the meta arm and every object key
/// of the result's JSON (union arm and field names). Used to skip goldens that cannot match.
fn result_key(lcm: &LedgerCloseMeta, tx: usize) -> Option<String> {
    let (result, meta) = match lcm {
        LedgerCloseMeta::V0(v) => v
            .tx_processing
            .get(tx)
            .map(|t| (&t.result, t.tx_apply_processing.name()))?,
        LedgerCloseMeta::V1(v) => v
            .tx_processing
            .get(tx)
            .map(|t| (&t.result, t.tx_apply_processing.name()))?,
        LedgerCloseMeta::V2(v) => v
            .tx_processing
            .get(tx)
            .map(|t| (&t.result, t.tx_apply_processing.name()))?,
    };
    fn keys(v: &Value, out: &mut String) {
        match v {
            Value::Object(o) => {
                for (k, x) in o {
                    out.push_str(k);
                    out.push('{');
                    keys(x, out);
                    out.push('}');
                }
            }
            Value::Array(a) => {
                out.push('[');
                a.iter().for_each(|x| keys(x, out));
                out.push(']');
            }
            Value::String(s) if s.chars().all(|c| c.is_ascii_lowercase() || c == '_') => {
                out.push_str(s);
            }
            _ => out.push('.'),
        }
    }
    let mut out = format!("{meta}:");
    keys(&serde_json::to_value(&result.result).ok()?, &mut out);
    Some(out)
}

fn tx_count(lcm: &LedgerCloseMeta) -> usize {
    match lcm {
        LedgerCloseMeta::V0(v) => v.tx_processing.len(),
        LedgerCloseMeta::V1(v) => v.tx_processing.len(),
        LedgerCloseMeta::V2(v) => v.tx_processing.len(),
    }
}

// --- The golden set. ---------------------------------------------------------------------------

/// One golden transaction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GoldenRef {
    pub file: String,
    pub frame_index: usize,
    pub tx_index: usize,
}

impl GoldenRef {
    fn to_json(&self) -> Value {
        json!({"file": self.file, "frame_index": self.frame_index, "tx_index": self.tx_index})
    }

    fn from_json(v: &Value) -> Option<GoldenRef> {
        Some(GoldenRef {
            file: v["file"].as_str()?.to_string(),
            frame_index: v["frame_index"].as_u64()? as usize,
            tx_index: v["tx_index"].as_u64()? as usize,
        })
    }
}

/// The golden set of `corpus.json` `tiers.bulk`: tag, cache directory and file → sha256.
struct GoldenSet {
    tag: String,
    index: String,
    root: std::path::PathBuf,
    files: Vec<(String, String)>,
}

impl GoldenSet {
    fn load(ctx: &Ctx) -> Result<GoldenSet> {
        let Some(bulk) = ctx.corpus_json.as_ref().map(|c| &c["tiers"]["bulk"]) else {
            bail!("ag4 needs corpus.json with tiers.bulk (the golden set)");
        };
        let (Some(tag), Some(index)) = (bulk["ref"].as_str(), bulk["file_index"].as_str()) else {
            bail!("corpus.json tiers.bulk needs `ref` and `file_index`");
        };
        let path = ctx.corpus.join(index);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading the golden file index {}", path.display()))?;
        let root = ctx.goldens.join(tag);
        if !root.is_dir() {
            bail!(
                "ag4: the golden set is not in the cache ({} does not exist); run `xdrcheck-corpus fetch-goldens {tag}` or pass --goldens",
                root.display()
            );
        }
        let mut files = Vec::new();
        for line in text
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        {
            let Some((sha, file)) = line.split_once("  ") else {
                bail!("{}: not `<sha256>  <path>`: {line}", path.display());
            };
            let file = file.trim_start_matches('*');
            let file = match bulk["path"].as_str() {
                Some(dir) if !file.starts_with(&format!("{dir}/")) => format!("{dir}/{file}"),
                _ => file.to_string(),
            };
            files.push((file, sha.to_string()));
        }
        Ok(GoldenSet {
            tag: tag.to_string(),
            index: index.to_string(),
            root,
            files,
        })
    }

    /// The bytes of one golden file, checked against the index.
    fn read(&self, file: &str) -> Result<Vec<u8>, String> {
        let Some((_, sha)) = self.files.iter().find(|(f, _)| f == file) else {
            return Err(format!("golden {file} is not in the golden set index"));
        };
        let data = std::fs::read(self.root.join(file)).map_err(|e| {
            format!(
                "golden {file} is not in the cache ({e}); run `xdrcheck-corpus fetch-goldens {}`",
                self.tag
            )
        })?;
        let got = xdrcheck_xdr::sha256_hex(&data);
        if &got != sha {
            return Err(format!(
                "golden {file}: sha256 is {got}, the index says {sha}"
            ));
        }
        Ok(data)
    }
}

/// The profile-free shape of transaction `tx` of a decoded ledger.
fn shape_of(lcm: &LedgerCloseMeta, tx: usize, passphrase: &str) -> Result<Shape, String> {
    tx_skeleton(lcm, tx, Some(passphrase))
        .map(|s| profile_free(&s))
        .map_err(|e| e.to_string())
}

/// The reduced shape tokens of a golden ledger. Every golden is written under stellar-core's test
/// passphrase; the passphrases of the public networks and of a standalone network are tried after
/// it (as `scan entry-tokens` does), so a golden set built from other ledgers (the tests' fixtures)
/// still joins its transactions.
fn golden_ledger_tokens(lcm: &LedgerCloseMeta, blob: &[u8]) -> anyhow::Result<Vec<TxTokens>> {
    let mut first = None;
    for pass in [
        CORE_TEST_PASSPHRASE,
        "Test SDF Network ; September 2015",
        "Public Global Stellar Network ; September 2015",
        "Standalone Network ; February 2017",
    ] {
        match ledger_tokens(lcm, blob, pass) {
            Ok(t) => return Ok(t),
            Err(e) => {
                first.get_or_insert(e);
            }
        }
    }
    Err(first.expect("at least one passphrase was tried"))
}

/// Both measures of one transaction: the profile-free skeleton and the reduced shape tokens.
#[derive(Debug, Clone)]
pub struct Both {
    pub shape: Shape,
    pub tokens: TxTokens,
}

impl Both {
    /// The pairing key: equal keys mean equal skeletons and equal reduced tokens.
    fn key(&self) -> String {
        format!("{}:{}", self.shape.hash, self.tokens.id)
    }
}

fn both_of(
    lcm: &LedgerCloseMeta,
    blob: &[u8],
    tx: usize,
    passphrase: &str,
) -> Result<Both, String> {
    let shape = shape_of(lcm, tx, passphrase)?;
    let all = if passphrase == CORE_TEST_PASSPHRASE {
        golden_ledger_tokens(lcm, blob)
    } else {
        ledger_tokens(lcm, blob, passphrase)
    };
    let mut all = all.map_err(|e| format!("shape tokens: {e:#}"))?;
    if tx >= all.len() {
        return Err(format!("shape tokens: no transaction {tx}"));
    }
    Ok(Both {
        shape,
        tokens: all.swap_remove(tx),
    })
}

/// One golden ledger, decoded, with its record bytes.
fn golden_ledger(
    ctx: &Ctx,
    set: &GoldenSet,
    file: &str,
    frame: usize,
) -> Result<(LedgerCloseMeta, Vec<u8>), String> {
    let data = set.read(file)?;
    let records = xdrcheck_xdr::split(&data).map_err(|e| format!("golden {file}: {e}"))?;
    let rec = records.get(frame).ok_or_else(|| {
        format!(
            "golden {file} has {} records, no frame {frame}",
            records.len()
        )
    })?;
    let lcm = xdrcheck_xdr::decode_ledger(rec.payload, &ctx.limits, &ctx.gate)
        .map_err(|e| format!("golden {file} frame {frame}: {e}"))?;
    Ok((lcm, rec.payload.to_vec()))
}

/// Both measures of one golden transaction, read now from the cache.
fn golden_both(ctx: &Ctx, set: &GoldenSet, g: &GoldenRef) -> Result<Both, String> {
    let (lcm, blob) = golden_ledger(ctx, set, &g.file, g.frame_index)?;
    both_of(&lcm, &blob, g.tx_index, CORE_TEST_PASSPHRASE).map_err(|e| {
        format!(
            "golden {} frame {} tx {}: {e}",
            g.file, g.frame_index, g.tx_index
        )
    })
}

/// The reduced shape tokens of every transaction of one golden ledger, read now from the cache.
fn golden_txs(
    ctx: &Ctx,
    set: &GoldenSet,
    file: &str,
    frame: usize,
) -> Result<Vec<TxTokens>, String> {
    let (lcm, blob) = golden_ledger(ctx, set, file, frame)?;
    golden_ledger_tokens(&lcm, &blob).map_err(|e| format!("golden {file} frame {frame}: {e:#}"))
}

/// Search the whole golden set for each wanted (result key, pairing key): the first golden
/// transaction in index order whose profile-free skeleton and reduced tokens both equal.
fn search(
    ctx: &Ctx,
    set: &GoldenSet,
    wanted: &BTreeMap<String, BTreeSet<String>>,
) -> Result<HashMap<String, GoldenRef>> {
    let mut found: HashMap<String, GoldenRef> = HashMap::new();
    let all: usize = wanted.values().map(BTreeSet::len).sum();
    for (file, _) in &set.files {
        if found.len() == all {
            break;
        }
        let data = set.read(file).map_err(anyhow::Error::msg)?;
        let records = xdrcheck_xdr::split(&data).with_context(|| format!("golden {file}"))?;
        for rec in records {
            // A golden this oracle does not decode cannot be a counterpart; AG-3 reports it.
            let Ok(lcm) = xdrcheck_xdr::decode_ledger(rec.payload, &ctx.limits, &ctx.gate) else {
                continue;
            };
            for tx in 0..tx_count(&lcm) {
                let Some(hashes) = result_key(&lcm, tx).and_then(|k| wanted.get(&k)) else {
                    continue;
                };
                if hashes.iter().all(|h| found.contains_key(h)) {
                    continue;
                }
                let Ok(shape) = shape_of(&lcm, tx, CORE_TEST_PASSPHRASE) else {
                    continue;
                };
                if !hashes
                    .iter()
                    .any(|h| h.starts_with(&format!("{}:", shape.hash)))
                {
                    continue;
                }
                let Ok(both) = both_of(&lcm, rec.payload, tx, CORE_TEST_PASSPHRASE) else {
                    continue;
                };
                let key = both.key();
                if hashes.contains(&key) && !found.contains_key(&key) {
                    found.insert(
                        key,
                        GoldenRef {
                            file: file.clone(),
                            frame_index: rec.index,
                            tx_index: tx,
                        },
                    );
                }
            }
        }
    }
    Ok(found)
}

// --- Local-core variants. ----------------------------------------------------------------------

/// One local-core variant with its own shape and result key.
struct Local {
    entry: String,
    variant: String,
    caps: Vec<i64>,
    /// The ledger holds no transaction; nothing to compare.
    no_tx: bool,
    /// (result key, both measures of the focus transaction).
    shape: Result<(String, Both), String>,
}

fn local_variants(ctx: &Ctx, entries: &[&Entry]) -> Vec<Local> {
    let mut out = Vec::new();
    for e in entries {
        for v in e.variants() {
            if v["source"]["kind"] != "local-core" {
                continue;
            }
            let mut no_tx = false;
            let shape = (|| -> Result<(String, Both), String> {
                let path = ctx.resolve(
                    v["blob"]["path"]
                        .as_str()
                        .ok_or("variant has no blob.path")?,
                );
                let bytes = std::fs::read(&path).map_err(|e| format!("blob: {e}"))?;
                let lcm = xdrcheck_xdr::decode_ledger(&bytes, &ctx.limits, &ctx.gate)
                    .map_err(|e| e.to_string())?;
                if tx_count(&lcm) == 0 {
                    no_tx = true;
                    return Err("the ledger holds no transaction".into());
                }
                let tx = v["focus"]["tx_index"].as_u64().unwrap_or(0) as usize;
                let pass = v["passphrase"]
                    .as_str()
                    .ok_or("variant has no passphrase")?;
                let key = result_key(&lcm, tx).ok_or("focus transaction not in the ledger")?;
                Ok((key, both_of(&lcm, &bytes, tx, pass)?))
            })();
            out.push(Local {
                entry: e.id.clone(),
                variant: e.variant_key(v),
                caps: e.caps(),
                no_tx,
                shape,
            });
        }
    }
    out
}

// --- The golden operation index and the corpus's operation shapes. -----------------------------

/// One reduced operation shape of the golden set: where it first occurs and how often.
struct GoldenOp {
    op_type: String,
    result: String,
    first: GoldenRef,
    transactions: u64,
}

/// Every reduced operation shape of the golden set, by shape id (first occurrence in index order).
fn golden_ops(ctx: &Ctx, set: &GoldenSet) -> Result<BTreeMap<String, GoldenOp>> {
    let mut out: BTreeMap<String, GoldenOp> = BTreeMap::new();
    for (file, _) in &set.files {
        let data = set.read(file).map_err(anyhow::Error::msg)?;
        let records = xdrcheck_xdr::split(&data).with_context(|| format!("golden {file}"))?;
        for rec in records {
            // A golden this oracle does not decode cannot be a counterpart; AG-3 reports it.
            let Ok(lcm) = xdrcheck_xdr::decode_ledger(rec.payload, &ctx.limits, &ctx.gate) else {
                continue;
            };
            let Ok(txs) = golden_ledger_tokens(&lcm, rec.payload) else {
                continue;
            };
            for (tx, t) in txs.iter().enumerate() {
                for (op, _) in &t.ops {
                    let g = out.entry(op.id.clone()).or_insert_with(|| GoldenOp {
                        op_type: op.op_type.clone(),
                        result: op.result(),
                        first: GoldenRef {
                            file: file.clone(),
                            frame_index: rec.index,
                            tx_index: tx,
                        },
                        transactions: 0,
                    });
                    g.transactions += 1;
                }
            }
        }
    }
    Ok(out)
}

/// The golden side of the reverse coverage: every reduced operation shape of the golden set with
/// its operation type, result, first golden and number of golden transactions. Which corpus entries
/// hold each shape is computed from the corpus alone by `xdrcheck-corpus coverage`
/// (`ag4_shape::corpus_op_shapes`), so adding an entry needs no golden cache to stay current.
fn golden_coverage(golden: &BTreeMap<String, GoldenOp>) -> Value {
    let mut sorted: Vec<(&String, &GoldenOp)> = golden.iter().collect();
    sorted.sort_by(|a, b| {
        (&a.1.op_type, &a.1.result, &a.1.first, a.0).cmp(&(
            &b.1.op_type,
            &b.1.result,
            &b.1.first,
            b.0,
        ))
    });
    let shapes: Vec<Value> = sorted
        .into_iter()
        .map(|(id, g)| {
            json!({
                "shape": id,
                "op_type": g.op_type,
                "result": g.result,
                "golden": g.first.to_json(),
                "golden_transactions": g.transactions,
            })
        })
        .collect();
    json!({
        "description": "Every reduced operation shape (the scan's shape tokens of one operation: body, result, ledger-entry changes, Soroban contract events; meta-flag and timing parts removed, docs/manifest.md section 4.7) of stellar-core's golden set at the pinned tag, with the first golden that holds it. `xdrcheck-corpus coverage` adds, from the corpus alone, the entries whose focus transaction holds each shape (corpus/COVERAGE.md, \"Golden operation shapes\").",
        "shapes_total": golden.len(),
        "shapes": shapes,
    })
}

// --- The committed mapping. --------------------------------------------------------------------

/// One operation of a local-core variant and its golden counterpart (the operation tier).
#[derive(Debug, Clone, PartialEq)]
struct OpRef {
    op_type: String,
    shape: String,
    golden: GoldenRef,
}

/// `mirrors.json`: entry → variant → golden, the operation tier, the unmapped entries and the
/// reverse coverage.
#[derive(Default)]
struct Mapping {
    mapped: BTreeMap<String, BTreeMap<String, GoldenRef>>,
    /// Entry → variant → every distinct reduced operation shape of the focus transaction with a
    /// golden operation of that shape. Only entries without a transaction counterpart.
    operations: BTreeMap<String, BTreeMap<String, Vec<OpRef>>>,
    /// Entry → why it has no transaction counterpart.
    unmapped: BTreeMap<String, String>,
    /// The reverse coverage as committed.
    golden_operations: Value,
}

impl Mapping {
    fn read(corpus: &Path) -> Result<Option<Mapping>> {
        let path = corpus.join(MIRRORS_FILE);
        if !path.is_file() {
            return Ok(None);
        }
        let j: Value = serde_json::from_slice(&std::fs::read(&path)?)
            .with_context(|| format!("{} is not JSON", path.display()))?;
        let mut m = Mapping::default();
        for e in j["mapped"].as_array().into_iter().flatten() {
            let id = e["entry"].as_str().unwrap_or("").to_string();
            let mut vs = BTreeMap::new();
            for (k, g) in e["variants"].as_object().into_iter().flatten() {
                let g = GoldenRef::from_json(g)
                    .with_context(|| format!("{MIRRORS_FILE}: {id} {k}: bad golden reference"))?;
                vs.insert(k.clone(), g);
            }
            m.mapped.insert(id, vs);
        }
        for e in j["operations"].as_array().into_iter().flatten() {
            let id = e["entry"].as_str().unwrap_or("").to_string();
            let mut vs = BTreeMap::new();
            for (k, ops) in e["variants"].as_object().into_iter().flatten() {
                let mut list = Vec::new();
                for o in ops.as_array().into_iter().flatten() {
                    let g = GoldenRef::from_json(o).with_context(|| {
                        format!("{MIRRORS_FILE}: operations {id} {k}: bad golden reference")
                    })?;
                    list.push(OpRef {
                        op_type: o["op_type"].as_str().unwrap_or("").to_string(),
                        shape: o["shape"].as_str().unwrap_or("").to_string(),
                        golden: g,
                    });
                }
                vs.insert(k.clone(), list);
            }
            m.operations.insert(id, vs);
        }
        for e in j["unmapped"].as_array().into_iter().flatten() {
            m.unmapped.insert(
                e["entry"].as_str().unwrap_or("").to_string(),
                e["reason"].as_str().unwrap_or(NO_GOLDEN).to_string(),
            );
        }
        m.golden_operations = j["golden_operations"].clone();
        Ok(Some(m))
    }

    fn write(&self, corpus: &Path, set: &GoldenSet, locals: &[Local]) -> Result<()> {
        let mut by_entry: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for l in locals {
            by_entry.entry(&l.entry).or_default().push(&l.variant);
        }
        let mapped: Vec<Value> = self
            .mapped
            .iter()
            .map(|(id, vs)| {
                let others: Vec<&str> = by_entry
                    .get(id.as_str())
                    .into_iter()
                    .flatten()
                    .filter(|k| !vs.contains_key(**k))
                    .copied()
                    .collect();
                let variants: Map<String, Value> =
                    vs.iter().map(|(k, g)| (k.clone(), g.to_json())).collect();
                json!({"entry": id, "variants": variants, "variants_without_golden": others})
            })
            .collect();
        let operations: Vec<Value> = self
            .operations
            .iter()
            .map(|(id, vs)| {
                let variants: Map<String, Value> = vs
                    .iter()
                    .map(|(k, ops)| {
                        let list: Vec<Value> = ops
                            .iter()
                            .map(|o| {
                                let op = OpShape {
                                    op_type: o.op_type.clone(),
                                    id: o.shape.clone(),
                                    tokens: BTreeSet::new(),
                                };
                                op_ref_json(
                                    &o.golden.file,
                                    o.golden.frame_index,
                                    o.golden.tx_index,
                                    &op,
                                )
                            })
                            .collect();
                        (k.clone(), json!(list))
                    })
                    .collect();
                json!({"entry": id, "variants": variants})
            })
            .collect();
        let unmapped: Vec<Value> = self
            .unmapped
            .iter()
            .map(|(id, why)| json!({"entry": id, "reason": why}))
            .collect();
        let doc = json!({
            "schema": "xcc.mirrors/v1",
            "description": "Golden counterparts of local-core entries (check AG-4, docs/manifest.md section 4.7). `mapped`: the local-core variants whose focus transaction has both the profile-free structural skeleton and the reduced shape tokens of a transaction of stellar-core's golden set, with the first such golden in index order. `operations`: for the other entries, the variants every operation of whose focus transaction has a golden operation of the same reduced shape (one golden per distinct operation shape). `unmapped`: every local-core entry without a transaction counterpart, with the reason. `golden_operations`: every reduced operation shape of the golden set with its first golden; `xdrcheck-corpus coverage` adds the corpus entries that hold each one. Written by `xdrcheck-corpus verify --checks ag4 --write-mirrors`; checked by `verify --checks ag4`.",
            "core_tag": set.tag,
            "golden_index": set.index,
            "counts": {
                "local_core_entries": self.mapped.len() + self.unmapped.len(),
                "mapped": self.mapped.len(),
                "unmapped": self.unmapped.len(),
                "unmapped_no_transaction": self.unmapped.values().filter(|w| *w == NO_TX).count(),
                "unmapped_every_operation_mapped": self.operations.len(),
            },
            "mapped": mapped,
            "operations": operations,
            "unmapped": unmapped,
            "golden_operations": self.golden_operations,
        });
        let path = corpus.join(MIRRORS_FILE);
        let mut text = serde_json::to_string_pretty(&doc)?;
        text.push('\n');
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))
    }
}

/// The operation-tier list of one variant: every distinct operation shape with its golden, when
/// every one has a golden.
fn op_tier(tokens: &TxTokens, golden: &BTreeMap<String, GoldenOp>) -> Option<Vec<OpRef>> {
    if tokens.ops.is_empty() {
        return None;
    }
    tokens
        .ops
        .iter()
        .map(|(o, _)| {
            golden.get(&o.id).map(|g| OpRef {
                op_type: o.op_type.clone(),
                shape: o.id.clone(),
                golden: g.first.clone(),
            })
        })
        .collect()
}

// --- The check. --------------------------------------------------------------------------------

/// The AG-4 rows over `selected` (all of `all` on a whole-corpus run). With `write`, the mapping is
/// first recomputed from a full search and written to `mirrors.json`.
pub fn rows(
    ctx: &Ctx,
    all: &[Entry],
    selected: &[&Entry],
    whole: bool,
    write: bool,
    counts: &mut Counts,
) -> Result<Vec<Row>> {
    if write && !whole {
        bail!("--write-mirrors needs a whole-corpus run (no --entries)");
    }
    let set = GoldenSet::load(ctx)?;
    let locals = xdrcheck_xdr::with_stack(ctx.limits.stack_size, || local_variants(ctx, selected));

    let committed_file = Mapping::read(&ctx.corpus)?;
    let tx_listed = |m: &Mapping, l: &Local| {
        m.mapped
            .get(&l.entry)
            .is_some_and(|vs| vs.contains_key(&l.variant))
    };
    let op_listed = |m: &Mapping, l: &Local| {
        m.operations
            .get(&l.entry)
            .is_some_and(|vs| vs.contains_key(&l.variant))
    };
    // The golden operation index is needed to write, for the reverse coverage of a whole run, and to
    // look for counterparts of variants neither tier lists.
    let need_ops = write
        || whole
        || committed_file.as_ref().is_none_or(|m| {
            locals
                .iter()
                .any(|l| !l.no_tx && !tx_listed(m, l) && !op_listed(m, l))
        });
    let gops = if need_ops {
        xdrcheck_xdr::with_stack(ctx.limits.stack_size, || golden_ops(ctx, &set))?
    } else {
        BTreeMap::new()
    };
    let coverage = whole.then(|| golden_coverage(&gops));

    let committed = if write {
        let wanted = wanted(&locals, |_| true);
        let found = xdrcheck_xdr::with_stack(ctx.limits.stack_size, || search(ctx, &set, &wanted))?;
        let mut m = Mapping::default();
        for l in &locals {
            if let Some(g) = l.shape.as_ref().ok().and_then(|(_, s)| found.get(&s.key())) {
                m.mapped
                    .entry(l.entry.clone())
                    .or_default()
                    .insert(l.variant.clone(), g.clone());
            }
        }
        for l in &locals {
            if m.mapped.contains_key(&l.entry) {
                continue;
            }
            if let Some(ops) = l
                .shape
                .as_ref()
                .ok()
                .and_then(|(_, s)| op_tier(&s.tokens, &gops))
            {
                m.operations
                    .entry(l.entry.clone())
                    .or_default()
                    .insert(l.variant.clone(), ops);
            }
        }
        for l in &locals {
            if m.mapped.contains_key(&l.entry) {
                continue;
            }
            let all_no_tx = locals
                .iter()
                .filter(|o| o.entry == l.entry)
                .all(|o| o.no_tx);
            let why = if all_no_tx {
                NO_TX
            } else if m.operations.contains_key(&l.entry) {
                OPS_ONLY
            } else {
                NO_GOLDEN
            };
            m.unmapped.insert(l.entry.clone(), why.to_string());
        }
        m.golden_operations = coverage.clone().unwrap_or(Value::Null);
        m.write(&ctx.corpus, &set, &locals)?;
        m
    } else {
        match committed_file {
            Some(m) => m,
            None => {
                return Ok(vec![Row::new(
                    Check::Ag4,
                    MIRRORS_FILE,
                    None,
                    vec![format!(
                        "{MIRRORS_FILE} is missing; run `xdrcheck-corpus verify --checks ag4 --write-mirrors`"
                    )],
                )])
            }
        }
    };
    let listed = |l: &Local| {
        committed
            .mapped
            .get(&l.entry)
            .and_then(|vs| vs.get(&l.variant))
    };
    let listed_ops = |l: &Local| {
        committed
            .operations
            .get(&l.entry)
            .and_then(|vs| vs.get(&l.variant))
    };

    // Variants the list does not map: search, so a newly covered shape is not missed.
    let unlisted = wanted(&locals, |l| listed(l).is_none());
    let found = if write || unlisted.is_empty() {
        HashMap::new()
    } else {
        xdrcheck_xdr::with_stack(ctx.limits.stack_size, || search(ctx, &set, &unlisted))?
    };

    let mut out = Vec::new();
    let mut golden_cache: HashMap<GoldenRef, Result<Both, String>> = HashMap::new();
    let mut golden_tx_cache: HashMap<(String, usize), Result<Vec<TxTokens>, String>> =
        HashMap::new();
    let mut without = 0u64;
    let mut no_tx = 0u64;
    let mut op_rows = 0u64;
    for l in &locals {
        if l.no_tx {
            no_tx += 1;
            continue;
        }
        let problems = match (listed(l), listed_ops(l), &l.shape) {
            (Some(g), _, shape) => {
                let gs = golden_cache.entry(g.clone()).or_insert_with(|| {
                    xdrcheck_xdr::with_stack(ctx.limits.stack_size, || golden_both(ctx, &set, g))
                });
                compare(shape, gs, g)
            }
            (None, Some(ops), shape) => {
                op_rows += 1;
                compare_ops(ops, shape, |file, frame| {
                    golden_tx_cache
                        .entry((file.to_string(), frame))
                        .or_insert_with(|| {
                            xdrcheck_xdr::with_stack(ctx.limits.stack_size, || {
                                golden_txs(ctx, &set, file, frame)
                            })
                        })
                        .clone()
                })
            }
            (None, None, Ok((_, s))) => match (found.get(&s.key()), op_tier(&s.tokens, &gops)) {
                (Some(g), _) => vec![format!(
                    "the profile-free skeleton equals golden {} frame {} tx {} and so do the reduced shape tokens, but {MIRRORS_FILE} does not map this variant; run `xdrcheck-corpus verify --checks ag4 --write-mirrors`",
                    g.file, g.frame_index, g.tx_index
                )],
                (None, Some(_)) => vec![format!(
                    "every operation has a golden operation of the same reduced shape, but {MIRRORS_FILE} does not list this variant under `operations`; run `xdrcheck-corpus verify --checks ag4 --write-mirrors`"
                )],
                (None, None) => {
                    without += 1;
                    continue;
                }
            },
            (None, None, Err(e)) => vec![format!("skeleton of the variant's focus transaction: {e}")],
        };
        let mut r = Row::new(Check::Ag4, &l.entry, Some(&l.variant), problems);
        r.caps = l.caps.clone();
        out.push(r);
    }
    counts.add("ag4_local_core_variants", locals.len() as u64);
    counts.add("ag4_variants_without_golden", without);
    counts.add("ag4_variants_without_transaction", no_tx);
    counts.add("ag4_variants_operation_tier", op_rows);

    if whole {
        let mut p = list_problems(all, &committed);
        if let Some(cov) = &coverage {
            if *cov != committed.golden_operations {
                p.push(format!(
                    "{MIRRORS_FILE} `golden_operations` is not the golden operation shapes computed now (the golden set or the shape rules changed); run `xdrcheck-corpus verify --checks ag4 --write-mirrors`"
                ));
            }
        }
        out.push(Row::new(Check::Ag4, MIRRORS_FILE, None, p));
        out.push(Row::new(
            Check::Ag4,
            "floor:ag4",
            None,
            floor_problems(&out, &committed),
        ));
        counts.add("ag4_entries_mapped", committed.mapped.len() as u64);
        counts.add(
            "ag4_entries_operation_tier",
            committed.operations.len() as u64,
        );
        counts.add("ag4_entries_unmapped", committed.unmapped.len() as u64);
    }
    Ok(out)
}

/// (result key → pairing keys) of the local variants `pick` selects.
fn wanted(locals: &[Local], pick: impl Fn(&Local) -> bool) -> BTreeMap<String, BTreeSet<String>> {
    let mut w: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for l in locals.iter().filter(|l| pick(l)) {
        if let Ok((k, s)) = &l.shape {
            w.entry(k.clone()).or_default().insert(s.key());
        }
    }
    w
}

fn compare(
    local: &Result<(String, Both), String>,
    golden: &Result<Both, String>,
    g: &GoldenRef,
) -> Vec<String> {
    let (l, gs) = match (local, golden) {
        (Err(e), _) => return vec![format!("skeleton of the variant's focus transaction: {e}")],
        (_, Err(e)) => return vec![e.clone()],
        (Ok((_, l)), Ok(gs)) => (l, gs),
    };
    let mut out = Vec::new();
    if l.shape.hash != gs.shape.hash {
        let as_skel = |s: &Shape| Skeleton {
            tx_index: None,
            tx_hash: None,
            sections: s.sections.clone(),
            section_hashes: Map::new(),
            hash: s.hash.clone(),
        };
        let d = diff(&as_skel(&l.shape), &as_skel(&gs.shape));
        let mut msg = format!(
            "profile-free skeleton {} differs from golden {} frame {} tx {} ({}) at {} path(s):",
            l.shape.hash,
            g.file,
            g.frame_index,
            g.tx_index,
            gs.shape.hash,
            d.len()
        );
        for x in d.iter().take(5) {
            msg.push_str(&format!(
                " {} ({} vs {});",
                x.path,
                short(&x.a),
                short(&x.b)
            ));
        }
        out.push(msg);
    }
    if l.tokens.id != gs.tokens.id {
        let d = l.tokens.diff(&gs.tokens, 5);
        out.push(format!(
            "reduced shape tokens differ from golden {} frame {} tx {}: {}",
            g.file,
            g.frame_index,
            g.tx_index,
            d.join("; ")
        ));
    }
    out
}

/// The operation tier: the variant's distinct operation shapes are exactly the listed ones, and
/// each listed golden transaction, read now, has an operation of that shape.
fn compare_ops(
    ops: &[OpRef],
    local: &Result<(String, Both), String>,
    mut golden: impl FnMut(&str, usize) -> Result<Vec<TxTokens>, String>,
) -> Vec<String> {
    let l = match local {
        Err(e) => return vec![format!("shape of the variant's focus transaction: {e}")],
        Ok((_, l)) => l,
    };
    let mut out = Vec::new();
    let have: BTreeSet<&str> = l.tokens.ops.iter().map(|(o, _)| o.id.as_str()).collect();
    let listed: BTreeSet<&str> = ops.iter().map(|o| o.shape.as_str()).collect();
    for (o, _) in &l.tokens.ops {
        if !listed.contains(o.id.as_str()) {
            out.push(format!(
                "operation {} (shape {}) is not listed in {MIRRORS_FILE}",
                o.op_type, o.id
            ));
        }
    }
    for o in ops {
        if !have.contains(o.shape.as_str()) {
            out.push(format!(
                "listed operation {} (shape {}) is not an operation of this transaction",
                o.op_type, o.shape
            ));
            continue;
        }
        let g = &o.golden;
        match golden(&g.file, g.frame_index) {
            Err(e) => out.push(e),
            Ok(txs) => match txs.get(g.tx_index) {
                None => out.push(format!(
                    "golden {} frame {} has no transaction {}",
                    g.file, g.frame_index, g.tx_index
                )),
                Some(t) => {
                    if !t.ops.iter().any(|(x, _)| x.id == o.shape) {
                        let mine = l
                            .tokens
                            .ops
                            .iter()
                            .find(|(x, _)| x.id == o.shape)
                            .map(|(x, _)| x);
                        let near = t
                            .ops
                            .iter()
                            .find(|(x, _)| x.op_type == o.op_type)
                            .map(|(x, _)| x);
                        let mut msg = format!(
                            "golden {} frame {} tx {} has no {} operation of shape {}",
                            g.file, g.frame_index, g.tx_index, o.op_type, o.shape
                        );
                        if let (Some(a), Some(b)) = (mine, near) {
                            let d: Vec<String> = a
                                .tokens
                                .difference(&b.tokens)
                                .map(|t| format!("only here: {t}"))
                                .chain(
                                    b.tokens
                                        .difference(&a.tokens)
                                        .map(|t| format!("only in the golden: {t}")),
                                )
                                .take(5)
                                .collect();
                            msg.push_str(&format!(": {}", d.join("; ")));
                        }
                        out.push(msg);
                    }
                }
            },
        }
    }
    out
}

fn short(v: &Value) -> String {
    let s = canon(v);
    if s.chars().count() > 80 {
        format!("{}…", s.chars().take(80).collect::<String>())
    } else {
        s
    }
}

/// Every local-core entry is listed once (mapped or unmapped), and nothing else is; every entry
/// of the operation tier is a listed unmapped local-core entry with that reason.
fn list_problems(all: &[Entry], m: &Mapping) -> Vec<String> {
    let local: BTreeSet<&str> = all
        .iter()
        .filter(|e| {
            e.variants()
                .iter()
                .any(|v| v["source"]["kind"] == "local-core")
        })
        .map(|e| e.id.as_str())
        .collect();
    let mut p = Vec::new();
    for id in &local {
        match (m.mapped.contains_key(*id), m.unmapped.contains_key(*id)) {
            (false, false) => p.push(format!("local-core entry {id} is not listed")),
            (true, true) => p.push(format!("{id} is listed as both mapped and unmapped")),
            _ => {}
        }
    }
    for id in m.mapped.keys().chain(m.unmapped.keys()) {
        if !local.contains(id.as_str()) {
            p.push(format!("{id} is listed but is not a local-core entry"));
        }
    }
    for id in m.operations.keys() {
        if m.unmapped.get(id).map(String::as_str) != Some(OPS_ONLY) {
            p.push(format!(
                "{id} is listed under `operations` but not as unmapped with the reason \"{OPS_ONLY}\""
            ));
        }
    }
    for (id, why) in &m.unmapped {
        if why == OPS_ONLY && !m.operations.contains_key(id) {
            p.push(format!(
                "{id} has the reason \"{OPS_ONLY}\" but no `operations` list"
            ));
        }
    }
    if !p.is_empty() {
        p.push("run `xdrcheck-corpus verify --checks ag4 --write-mirrors`".into());
    }
    p
}

/// golden-agreement's floor: at least one AG-4 row comparing a transaction, and every entry the list maps
/// (either tier) has all its listed variants passing — fewer passing entries than the list fails.
fn floor_problems(rows: &[Row], m: &Mapping) -> Vec<String> {
    let variant_rows: Vec<&Row> = rows.iter().filter(|r| r.variant.is_some()).collect();
    let mut p = Vec::new();
    if variant_rows.is_empty() || m.mapped.is_empty() {
        p.push("no AG-4 row: no local-core variant is compared with a golden".into());
    }
    let passes = |id: &String, keys: Vec<&String>| {
        keys.into_iter().all(|k| {
            variant_rows
                .iter()
                .any(|r| r.ok && &r.entry == id && r.variant.as_deref() == Some(k.as_str()))
        })
    };
    let passing = m
        .mapped
        .iter()
        .filter(|(id, vs)| passes(id, vs.keys().collect()))
        .count();
    if passing < m.mapped.len() {
        p.push(format!(
            "{passing} of the {} entries {MIRRORS_FILE} maps pass AG-4",
            m.mapped.len()
        ));
    }
    let passing_ops = m
        .operations
        .iter()
        .filter(|(id, vs)| passes(id, vs.keys().collect()))
        .count();
    if passing_ops < m.operations.len() {
        p.push(format!(
            "{passing_ops} of the {} entries {MIRRORS_FILE} lists under `operations` pass AG-4",
            m.operations.len()
        ));
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skel(sections: Value) -> Skeleton {
        Skeleton {
            tx_index: Some(0),
            tx_hash: None,
            sections: sections.as_object().unwrap().clone(),
            section_hashes: Map::new(),
            hash: String::new(),
        }
    }

    fn env(arms: &[&str]) -> Value {
        let items: Vec<Value> = arms
            .iter()
            .map(|a| json!({"source_account": null, "body": {"|": a, "v": "#x"}}))
            .collect();
        json!({"|": "tx", "v": {"tx": {"operations": {"n": items.len(), "items": items}}, "signatures": {"n": 1, "items": ["#s"]}}})
    }

    #[test]
    fn flag_dependent_parts_are_removed() {
        let a = skel(json!({
            "envelope": env(&["payment", "invoke_host_function"]),
            "meta.operations": {"n": 2, "items": [
                {"changes": {"n": 2, "items": []}, "events": {"n": 1, "items": ["#e"]}},
                {"changes": {"n": 1, "items": []}, "events": {"n": 3, "items": ["#e", "#e", "#e"]}},
            ]},
            "meta.soroban_meta": {"?": {"ext": {"|": "v1", "v": "#x"}, "return_value": "#v"}},
            "meta.events": {"n": 2, "items": ["#f", "#f"]},
            "meta.diagnostic_events": {"n": 9, "items": []},
        }));
        let b = skel(json!({
            "envelope": env(&["payment", "invoke_host_function"]),
            "meta.operations": {"n": 2, "items": [
                {"changes": {"n": 2, "items": []}, "events": {"n": 0, "items": []}},
                {"changes": {"n": 1, "items": []}, "events": {"n": 3, "items": ["#e", "#e", "#e"]}},
            ]},
            "meta.soroban_meta": {"?": {"ext": {"|": "v0"}, "return_value": "#v"}},
            "meta.events": {"n": 0, "items": []},
            "meta.diagnostic_events": {"n": 0, "items": []},
        }));
        assert_eq!(profile_free(&a).hash, profile_free(&b).hash);
    }

    #[test]
    fn contract_events_and_changes_still_count() {
        let base = json!({
            "envelope": env(&["invoke_host_function"]),
            "meta.operations": {"n": 1, "items": [
                {"changes": {"n": 1, "items": []}, "events": {"n": 1, "items": ["#e"]}},
            ]},
        });
        let mut fewer_events = base.clone();
        fewer_events["meta.operations"]["items"][0]["events"] = json!({"n": 0, "items": []});
        let mut more_changes = base.clone();
        more_changes["meta.operations"]["items"][0]["changes"] = json!({"n": 2, "items": []});
        let h = |v: &Value| profile_free(&skel(v.clone())).hash;
        assert_ne!(h(&base), h(&fewer_events));
        assert_ne!(h(&base), h(&more_changes));
    }

    fn tokens(op_tok: &str) -> TxTokens {
        let op = OpShape {
            op_type: "ALLOW_TRUST".into(),
            id: format!("id-{op_tok}"),
            tokens: BTreeSet::from([op_tok.to_string()]),
        };
        TxTokens {
            parts: BTreeMap::from([(
                'R',
                BTreeSet::from(["A|arm|res.result::txSUCCESS".to_string()]),
            )]),
            ops: vec![(op, "1".into())],
            op_count_class: "1".into(),
            id: format!("tx-{op_tok}"),
        }
    }

    fn both(op_tok: &str) -> Both {
        let shape = profile_free(&skel(json!({"envelope": env(&["allow_trust"])})));
        Both {
            shape,
            tokens: tokens(op_tok),
        }
    }

    #[test]
    fn equal_skeletons_with_other_values_do_not_agree() {
        // An AllowTrust to "maintain liabilities" and one to "authorized" have one skeleton.
        let g = GoldenRef {
            file: "f".into(),
            frame_index: 0,
            tx_index: 0,
        };
        let here = both("D|upd|op:ALLOW_TRUST#upd:TRUSTLINE:{data.TRUSTLINE.flags=1>2}");
        let there = both("D|upd|op:ALLOW_TRUST#upd:TRUSTLINE:{data.TRUSTLINE.flags=0>1}");
        assert_eq!(here.shape.hash, there.shape.hash);
        assert_ne!(here.key(), there.key());
        let p = compare(&Ok(("k".into(), here.clone())), &Ok(there), &g);
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(p[0].contains("reduced shape tokens differ"), "{p:?}");
        assert!(
            p[0].contains("flags=1>2") && p[0].contains("flags=0>1"),
            "{p:?}"
        );
        assert!(compare(&Ok(("k".into(), here.clone())), &Ok(here), &g).is_empty());
    }

    #[test]
    fn the_operation_tier_needs_every_operation_and_the_golden_operation() {
        let here = both("D|upd|op:ALLOW_TRUST#upd:TRUSTLINE:{data.TRUSTLINE.flags=1>2}");
        let other = tokens("D|upd|op:ALLOW_TRUST#upd:TRUSTLINE:{data.TRUSTLINE.flags=0>1}");
        let r = |shape: &str| OpRef {
            op_type: "ALLOW_TRUST".into(),
            shape: shape.into(),
            golden: GoldenRef {
                file: "f".into(),
                frame_index: 0,
                tx_index: 0,
            },
        };
        let mine = here.tokens.ops[0].0.id.clone();
        let local = Ok(("k".to_string(), here.clone()));
        // The golden transaction has the operation: pass.
        let ok = compare_ops(&[r(&mine)], &local, |_, _| Ok(vec![here.tokens.clone()]));
        assert!(ok.is_empty(), "{ok:?}");
        // It does not: fail, naming the differing token.
        let bad = compare_ops(&[r(&mine)], &local, |_, _| Ok(vec![other.clone()]));
        assert_eq!(bad.len(), 1, "{bad:?}");
        assert!(bad[0].contains("flags=1>2"), "{bad:?}");
        // An operation the list leaves out, and a listed one the transaction lacks: fail.
        let missing = compare_ops(&[], &local, |_, _| Ok(vec![here.tokens.clone()]));
        assert!(
            missing.iter().any(|p| p.contains("is not listed")),
            "{missing:?}"
        );
        let extra = compare_ops(&[r(&mine), r("elsewhere")], &local, |_, _| {
            Ok(vec![here.tokens.clone()])
        });
        assert!(
            extra
                .iter()
                .any(|p| p.contains("is not an operation of this transaction")),
            "{extra:?}"
        );
    }

    #[test]
    fn floor_fails_on_zero_rows_and_on_fewer_than_the_list() {
        let mut m = Mapping::default();
        assert!(!floor_problems(&[], &m).is_empty());
        let g = GoldenRef {
            file: "f".into(),
            frame_index: 0,
            tx_index: 0,
        };
        m.mapped.insert(
            "a/x".into(),
            BTreeMap::from([("testnet".into(), g.clone())]),
        );
        m.mapped
            .insert("a/y".into(), BTreeMap::from([("testnet".into(), g)]));
        let ok = Row::new(Check::Ag4, "a/x", Some("testnet"), vec![]);
        let bad = Row::new(Check::Ag4, "a/y", Some("testnet"), vec!["differs".into()]);
        assert!(!floor_problems(&[ok.clone(), bad], &m).is_empty());
        assert!(!floor_problems(std::slice::from_ref(&ok), &m).is_empty());
        let ok2 = Row::new(Check::Ag4, "a/y", Some("testnet"), vec![]);
        assert!(floor_problems(&[ok.clone(), ok2.clone()], &m).is_empty());
        // An entry of the operation tier counts too.
        m.operations.insert(
            "a/z".into(),
            BTreeMap::from([("pubnet".into(), Vec::new())]),
        );
        assert!(!floor_problems(&[ok.clone(), ok2.clone()], &m).is_empty());
        let ok3 = Row::new(Check::Ag4, "a/z", Some("pubnet"), vec![]);
        assert!(floor_problems(&[ok, ok2, ok3], &m).is_empty());
    }
}
