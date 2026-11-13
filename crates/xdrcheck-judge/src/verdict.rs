//! Verdicts: an indexer's exported rows against the judge's facts.
//!
//! Both inputs are JSONL sorted by ledger (ascending). They are merge-joined one ledger at a
//! time, so memory is bounded by the largest ledger. See README.md for the row schema.

#![allow(clippy::type_complexity)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Lines, Write};
use std::iter::Peekable;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::facts::Fact;
use crate::scope::{KindScope, Scope, Seen};

/// One indexer row (the common export schema).
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct Row {
    pub kind: String,
    pub ledger: u32,
    #[serde(default)]
    pub tx_hash: Option<String>,
    #[serde(default)]
    pub tx_index: Option<u32>,
    #[serde(default)]
    pub op_index: Option<u32>,
    #[serde(default)]
    pub holder: Option<String>,
    #[serde(default)]
    pub asset: Option<String>,
    #[serde(default)]
    pub amount: Option<String>,
    #[serde(default)]
    pub entry_key: Option<String>,
    #[serde(default)]
    pub change: Option<String>,
    /// Entry rows: the entry by name instead of `entry_key` (see `read::key_subject`), or by parts:
    /// `entry_type` + `account` (+ `asset` / `token` (a SAC id) / `pool` (hex) for a trustline, `data_name`).
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub entry_type: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub pool: Option<String>,
    #[serde(default)]
    pub data_name: Option<String>,
    /// Entry rows: the attribute changed (see `facts::EntryFieldFact`; `flags:set` / `flags:clear` carry the
    /// bits in `new`), and its values before / after where the row states them.
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub old: Option<String>,
    #[serde(default)]
    pub new: Option<String>,
    #[serde(default)]
    pub contract: Option<String>,
    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub to_muxed_id: Option<String>,
    #[serde(default)]
    pub muxed_id: Option<String>,
    #[serde(default)]
    pub tx_count: Option<u32>,
    #[serde(default)]
    pub protocol: Option<u32>,
    #[serde(default)]
    pub close_time: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Compare only `op:*` and `reconcile:*` balance parts (the indexer exports no fee rows).
    pub nofee: bool,
    pub kinds: BTreeSet<String>,
    pub roles: BTreeSet<String>,
    /// The target's declared scope (kinds, comparison modes, out-of-scope rules).
    pub scope: Option<Scope>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Verdict {
    pub ledger: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    pub verdict: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub class: String,
    /// The scope rule that put this verdict out of scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_rule: Option<String>,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub evidence: Value,
}

#[derive(Serialize, Default, Debug)]
pub struct Summary {
    pub ledgers: u64,
    pub txs: u64,
    pub kinds: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub scope: String,
    pub verdicts: BTreeMap<String, u64>,
    /// In-scope classes.
    pub classes: BTreeMap<String, u64>,
    /// Out-of-scope verdicts by rule id, and by rule id and class.
    pub out_of_scope: BTreeMap<String, u64>,
    pub out_of_scope_classes: BTreeMap<String, u64>,
    /// Truth items no row was compared with, because the kind is extra-only or the target does not claim
    /// them (`<kind>:<reason>`).
    pub not_compared: BTreeMap<String, u64>,
}

/// Normalise an address: `M…` → its `G…` base; others unchanged.
pub fn base(a: &str) -> String {
    if a.starts_with('M') {
        if let Ok(m) = a.parse::<stellar_xdr::MuxedAccount>() {
            return crate::read::muxed(&m).0;
        }
    }
    if a.starts_with('C') && a.len() > 56 {
        if let Ok(s) = a.parse::<stellar_xdr::ScAddress>() {
            return crate::read::sc_address(&s).0;
        }
    }
    a.to_string()
}

struct Grouped<I: Iterator<Item = std::io::Result<String>>> {
    lines: Peekable<I>,
    what: &'static str,
    last: u32,
}

impl<I: Iterator<Item = std::io::Result<String>>> Grouped<I> {
    fn peek_ledger(&mut self) -> Result<Option<u32>> {
        loop {
            match self.lines.peek() {
                None => return Ok(None),
                Some(Err(_)) => {
                    let e = self.lines.next().unwrap().unwrap_err();
                    return Err(e.into());
                }
                Some(Ok(l)) if l.trim().is_empty() => {
                    self.lines.next();
                }
                Some(Ok(l)) => {
                    let v: LedgerOnly = serde_json::from_str(l)
                        .with_context(|| format!("{}: bad line", self.what))?;
                    if v.ledger < self.last {
                        bail!(
                            "{} not sorted by ledger ({} after {})",
                            self.what,
                            v.ledger,
                            self.last
                        );
                    }
                    return Ok(Some(v.ledger));
                }
            }
        }
    }
    fn take(&mut self, ledger: u32) -> Result<Vec<String>> {
        let mut out = Vec::new();
        while self.peek_ledger()? == Some(ledger) {
            out.push(self.lines.next().unwrap()?);
        }
        self.last = ledger;
        Ok(out)
    }
}

#[derive(Deserialize)]
struct LedgerOnly {
    ledger: u32,
}

fn open(p: &Path, what: &'static str) -> Result<Grouped<Lines<BufReader<File>>>> {
    Ok(Grouped {
        lines: BufReader::new(File::open(p).with_context(|| format!("open {}", p.display()))?)
            .lines()
            .peekable(),
        what,
        last: 0,
    })
}

const FAMILIES: [&str; 5] = [
    "balance_change",
    "participant",
    "entry_change",
    "token_event",
    "ledger",
];

/// How one row kind is compared.
#[derive(Clone, Debug)]
struct KindPlan {
    family: String,
    extra_only: bool,
    nofee: bool,
    lifecycle: Option<BTreeSet<String>>,
    fields: Option<BTreeSet<String>>,
}

fn plans(kinds: &BTreeSet<String>, cfg: &Config) -> Result<BTreeMap<String, KindPlan>> {
    let mut out = BTreeMap::new();
    for k in kinds {
        let ks: KindScope = cfg
            .scope
            .as_ref()
            .and_then(|s| s.kinds.get(k).cloned())
            .unwrap_or_default();
        let family = ks.compare.clone().unwrap_or_else(|| k.clone());
        if !FAMILIES.contains(&family.as_str()) {
            bail!("kind {k}: no fact family {family:?} to compare with");
        }
        out.insert(
            k.clone(),
            KindPlan {
                family,
                extra_only: ks.extra_only(),
                nofee: match ks.fee.as_deref() {
                    Some(f) => f == "nofee",
                    None => cfg.nofee,
                },
                lifecycle: ks.lifecycle.map(|v| v.into_iter().collect()),
                fields: ks.fields.map(|v| v.into_iter().collect()),
            },
        );
    }
    Ok(out)
}

pub fn run(facts: &Path, rows: &Path, out: &Path, cfg: &Config) -> Result<Summary> {
    // Pre-pass over rows: kinds present and the last ledger exported.
    let mut kinds_present = BTreeSet::new();
    let mut max_row_ledger = 0u32;
    for l in BufReader::new(File::open(rows)?).lines() {
        let l = l?;
        if l.trim().is_empty() {
            continue;
        }
        let r: Row = serde_json::from_str(&l).context("rows: bad line")?;
        kinds_present.insert(r.kind);
        max_row_ledger = max_row_ledger.max(r.ledger);
    }
    // --kinds, else the scope's kinds, else the kinds the rows contain; with no rows at all, every kind (so an
    // indexer that exported nothing is a halt, not a clean run).
    let scope_kinds: BTreeSet<String> = cfg
        .scope
        .as_ref()
        .map(|s| s.kinds.keys().cloned().collect())
        .unwrap_or_default();
    let kinds: BTreeSet<String> = if !cfg.kinds.is_empty() {
        cfg.kinds.clone()
    } else if !scope_kinds.is_empty() {
        scope_kinds
    } else if kinds_present.is_empty() {
        FAMILIES.iter().map(|s| s.to_string()).collect()
    } else {
        kinds_present
    };
    let plans = plans(&kinds, cfg)?;
    let mut summary = Summary {
        kinds: kinds.iter().cloned().collect(),
        scope: cfg
            .scope
            .as_ref()
            .map(|s| format!("{}@{}", s.target, s.at))
            .unwrap_or_default(),
        ..Default::default()
    };
    let mut fr = open(facts, "facts")?;
    let mut rr = open(rows, "rows")?;
    let mut w = BufWriter::new(File::create(out)?);
    let mut halted = false;
    let emit = |v: Verdict, w: &mut BufWriter<File>, s: &mut Summary| -> Result<()> {
        *s.verdicts.entry(v.verdict.to_string()).or_default() += 1;
        if let Some(r) = &v.scope_rule {
            *s.out_of_scope.entry(r.clone()).or_default() += 1;
            *s.out_of_scope_classes
                .entry(format!("{r} {}", v.class))
                .or_default() += 1;
        } else if !v.class.is_empty() {
            *s.classes.entry(v.class.clone()).or_default() += 1;
        }
        serde_json::to_writer(&mut *w, &v)?;
        w.write_all(b"\n")?;
        Ok(())
    };
    let not_in_facts = |rl: u32, n: usize| Verdict {
        ledger: rl,
        tx_index: None,
        tx_hash: None,
        verdict: "extra",
        kind: "ledger".into(),
        class: "ledger:extra:not_in_facts".into(),
        scope_rule: None,
        evidence: json!({ "rows": n }),
    };
    while let Some(l) = fr.peek_ledger()? {
        // Rows for ledgers the facts do not cover.
        while let Some(rl) = rr.peek_ledger()? {
            if rl >= l {
                break;
            }
            let n = rr.take(rl)?.len();
            emit(not_in_facts(rl, n), &mut w, &mut summary)?;
        }
        let fl: Vec<Fact> = fr
            .take(l)?
            .iter()
            .map(|s| serde_json::from_str(s).context("facts: bad line"))
            .collect::<Result<_>>()?;
        let rl: Vec<Row> = rr
            .take(l)?
            .iter()
            .map(|s| serde_json::from_str(s).context("rows: bad line"))
            .collect::<Result<_>>()?;
        summary.ledgers += 1;
        let vs = judge_one(
            l,
            &fl,
            &rl,
            &plans,
            cfg,
            max_row_ledger,
            &mut halted,
            &mut summary.not_compared,
        );
        for v in vs {
            if v.verdict == "ok" {
                summary.txs += 1;
            }
            emit(v, &mut w, &mut summary)?;
        }
    }
    while let Some(rl) = rr.peek_ledger()? {
        let n = rr.take(rl)?.len();
        emit(not_in_facts(rl, n), &mut w, &mut summary)?;
    }
    w.flush()?;
    Ok(summary)
}

fn pi(s: &str) -> Option<i128> {
    s.trim().parse().ok()
}

/// How a wrong balance value differs from the truth.
fn value_reason(truth: i128, got: i128) -> &'static str {
    let wrap = truth as i64 as i128;
    if truth != wrap && got == wrap {
        return "int64_wrap";
    }
    if truth > i64::MAX as i128 && got == i64::MAX as i128 {
        return "int64_clamp";
    }
    if truth < i64::MIN as i128 && got == i64::MIN as i128 {
        return "int64_clamp";
    }
    if got == 0 {
        return "zero";
    }
    if got == -truth {
        return "sign";
    }
    let d = (got - truth).abs();
    if d <= 10 {
        return "small_diff";
    }
    if truth != 0 && got % truth == 0 {
        return "multiple";
    }
    "other"
}

struct TxInfo {
    hash: String,
    success: bool,
}

/// A truth token event, as compared.
#[derive(Clone, Debug)]
struct TEv {
    key: (String, String, String, String, String),
    to_muxed_id: Option<String>,
    asset: Option<String>,
    op_index: Option<u32>,
}

/// A truth lifecycle item of an entry.
#[derive(Clone, Debug)]
struct TLife {
    op: Option<u32>,
    subject: String,
    entry_type: String,
    change: String,
}

/// A truth attribute item of an entry (flags expanded to `flags:set` / `flags:clear`).
#[derive(Clone, Debug)]
struct TField {
    op: Option<u32>,
    subject: String,
    entry_type: String,
    field: String,
    old: Option<String>,
    new: Option<String>,
    /// For `flags:*`: the entry's flags before and after the op.
    flags_state: Option<(u64, u64)>,
}

fn family_of(field: &str) -> &str {
    field.split(':').next().unwrap_or(field)
}

/// Expand a fact's attribute change into comparable items (`flags` → `flags:set` / `flags:clear` bits).
fn expand_field(f: &crate::facts::EntryFieldFact) -> Vec<TField> {
    let mk = |field: String, old: Option<String>, new: Option<String>| TField {
        op: f.op_index,
        subject: f.subject.clone(),
        entry_type: f.entry_type.clone(),
        field,
        old,
        new,
        flags_state: None,
    };
    if f.field == "flags" {
        let o: u64 = f.old.as_deref().and_then(|v| v.parse().ok()).unwrap_or(0);
        let n: u64 = f.new.as_deref().and_then(|v| v.parse().ok()).unwrap_or(0);
        let mut v = Vec::new();
        if n & !o != 0 {
            v.push(mk("flags:set".into(), None, Some((n & !o).to_string())));
        }
        if o & !n != 0 && f.new.is_some() {
            v.push(mk("flags:clear".into(), None, Some((o & !n).to_string())));
        }
        for t in v.iter_mut() {
            t.flags_state = Some((o, n));
        }
        return v;
    }
    vec![mk(f.field.clone(), f.old.clone(), f.new.clone())]
}

/// The entry a row names (see `Row`), with `c2a` mapping SAC ids to their assets.
fn row_subject(r: &Row, c2a: &HashMap<String, String>) -> Option<String> {
    use stellar_xdr::ReadXdr;
    if let Some(s) = &r.subject {
        return Some(s.clone());
    }
    if let Some(k) = &r.entry_key {
        let k = stellar_xdr::LedgerKey::from_xdr_base64(k, stellar_xdr::Limits::none()).ok()?;
        return Some(crate::read::key_subject(&k));
    }
    let acct = r.account.as_deref().map(base)?;
    match r.entry_type.as_deref()? {
        "account" => Some(format!("account:{acct}")),
        "trustline" => {
            let asset = if let Some(p) = &r.pool {
                format!("pool:{}", p.to_lowercase())
            } else {
                let a = r.token.as_deref().or(r.asset.as_deref())?;
                if a.starts_with('C') && a.len() == 56 {
                    c2a.get(a)
                        .cloned()
                        .unwrap_or_else(|| format!("unresolved:{a}"))
                } else {
                    a.to_string()
                }
            };
            Some(format!("trustline:{acct}:{asset}"))
        }
        "data" => Some(format!(
            "data:{acct}:{}",
            hex::encode(r.data_name.as_deref()?.as_bytes())
        )),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn judge_one(
    ledger: u32,
    facts: &[Fact],
    rows: &[Row],
    plans: &BTreeMap<String, KindPlan>,
    cfg: &Config,
    max_row_ledger: u32,
    halted: &mut bool,
    not_compared: &mut BTreeMap<String, u64>,
) -> Vec<Verdict> {
    let mut out: Vec<Verdict> = Vec::new();
    let mut txs: BTreeMap<u32, TxInfo> = BTreeMap::new();
    let mut by_hash: HashMap<String, u32> = HashMap::new();
    let mut sac: HashMap<String, String> = HashMap::new();
    let mut nonsac_contracts: BTreeSet<String> = BTreeSet::new();
    let mut ledger_fact = None;
    // Truth per tx: balances (net, nofee), participants, entry lifecycle and attributes, token events.
    let mut t_bal: [BTreeMap<u32, BTreeMap<(String, String), (i128, bool)>>; 2] =
        [BTreeMap::new(), BTreeMap::new()];
    let mut t_part: BTreeMap<u32, BTreeMap<String, (Vec<String>, Vec<String>)>> = BTreeMap::new();
    let mut t_life: BTreeMap<Option<u32>, Vec<TLife>> = BTreeMap::new();
    let mut t_field: BTreeMap<Option<u32>, Vec<TField>> = BTreeMap::new();
    let mut t_ev: BTreeMap<u32, Vec<TEv>> = BTreeMap::new();
    for f in facts {
        match f {
            Fact::Ledger(l) => ledger_fact = Some(l.clone()),
            Fact::Sac(s) => {
                sac.insert(s.contract.clone(), s.asset.clone());
            }
            Fact::Tx(t) => {
                by_hash.insert(t.tx_hash.clone(), t.tx_index);
                if let Some(h) = &t.inner_hash {
                    by_hash.insert(h.clone(), t.tx_index);
                }
                txs.insert(
                    t.tx_index,
                    TxInfo {
                        hash: t.tx_hash.clone(),
                        success: t.success,
                    },
                );
            }
            Fact::BalanceChange(b) => {
                if !b.contract.is_empty() {
                    sac.insert(b.contract.clone(), b.asset.clone());
                }
                let Some(i) = b.tx_index else { continue };
                let nofee: i128 = b
                    .parts
                    .iter()
                    .filter(|(k, _)| k.starts_with("op:") || k.starts_with("reconcile:"))
                    .filter_map(|(_, v)| pi(v))
                    .sum();
                let net = pi(&b.amount).unwrap_or(0);
                for (slot, n) in [(0usize, net), (1, nofee)] {
                    if n != 0 || !b.complete {
                        t_bal[slot]
                            .entry(i)
                            .or_default()
                            .insert((b.holder.clone(), b.asset.clone()), (n, b.complete));
                    }
                }
            }
            Fact::NonsacBalance(n) => {
                nonsac_contracts.insert(n.contract.clone());
            }
            Fact::Participant(p) => {
                if cfg.roles.is_empty() || p.roles.iter().any(|r| cfg.roles.contains(r)) {
                    t_part
                        .entry(p.tx_index)
                        .or_default()
                        .insert(p.address.clone(), (p.roles.clone(), p.muxed_ids.clone()));
                }
            }
            Fact::EntryChange(e) => {
                if let Some(c) = &e.asset_contract {
                    // subject `trustline:G…:CODE:ISSUER`: the asset is everything after the account.
                    if let Some(asset) = e.subject.splitn(3, ':').nth(2) {
                        sac.entry(c.clone()).or_insert_with(|| asset.to_string());
                    }
                }
                t_life.entry(e.tx_index).or_default().push(TLife {
                    op: e.op_index,
                    subject: e.subject.clone(),
                    entry_type: e.entry_type.clone(),
                    change: e.change.clone(),
                });
            }
            Fact::EntryField(e) => {
                t_field
                    .entry(e.tx_index)
                    .or_default()
                    .extend(expand_field(e));
            }
            Fact::TokenEvent(e) => {
                if !e.sac {
                    nonsac_contracts.insert(e.contract.clone());
                }
                t_ev.entry(e.tx_index).or_default().push(TEv {
                    key: (
                        e.contract.clone(),
                        e.event.clone(),
                        e.from.clone().unwrap_or_default(),
                        e.to.clone().unwrap_or_default(),
                        e.amount.clone().unwrap_or_default(),
                    ),
                    to_muxed_id: e.to_muxed_id.clone(),
                    asset: e.asset.clone(),
                    op_index: e.op_index,
                });
            }
            Fact::EventWithoutAmount(e) => {
                if !e.sac {
                    nonsac_contracts.insert(e.contract.clone());
                }
            }
            Fact::Unknown(_) => {}
        }
    }
    let Some(lf) = ledger_fact else {
        return out;
    };
    let norm_asset = |a: &str| -> String {
        if a.starts_with('C') {
            if let Some(x) = sac.get(a) {
                return x.clone();
            }
        }
        a.to_string()
    };
    let mk =
        |tx: Option<u32>, verdict: &'static str, kind: &str, class: String, ev: Value| Verdict {
            ledger,
            tx_index: tx,
            tx_hash: tx.and_then(|i| txs.get(&i).map(|t| t.hash.clone())),
            verdict,
            kind: kind.to_string(),
            class,
            scope_rule: None,
            evidence: ev,
        };
    let fam = |k: &str| plans.get(k).map(|p| p.family.as_str()).unwrap_or("");

    // Rows by tx.
    let mut r_by_tx: BTreeMap<Option<u32>, Vec<&Row>> = BTreeMap::new();
    for r in rows {
        if !plans.contains_key(&r.kind) {
            continue;
        }
        let tx = match (&r.tx_hash, r.tx_index) {
            (Some(h), _) => match by_hash.get(&h.to_lowercase()) {
                Some(i) => Some(*i),
                None => {
                    out.push(mk(
                        None,
                        "extra",
                        &r.kind,
                        format!("{}:extra:unknown_tx", r.kind),
                        json!({ "row": r }),
                    ));
                    continue;
                }
            },
            (None, Some(i)) if txs.contains_key(&i) => Some(i),
            (None, Some(_)) => {
                out.push(mk(
                    None,
                    "extra",
                    &r.kind,
                    format!("{}:extra:unknown_tx", r.kind),
                    json!({ "row": r }),
                ));
                continue;
            }
            (None, None) if fam(&r.kind) == "ledger" || fam(&r.kind) == "entry_change" => None,
            (None, None) => {
                out.push(mk(
                    None,
                    "extra",
                    &r.kind,
                    format!("{}:extra:no_tx_ref", r.kind),
                    json!({ "row": r }),
                ));
                continue;
            }
        };
        r_by_tx.entry(tx).or_default().push(r);
    }

    // Halt / skip: the truth has comparable items but the indexer exported nothing for the ledger.
    let truth_has = plans
        .values()
        .filter(|p| !p.extra_only)
        .any(|p| match p.family.as_str() {
            "balance_change" => !t_bal[p.nofee as usize].is_empty(),
            "participant" => !t_part.is_empty(),
            "entry_change" => t_life.keys().any(|k| k.is_some()),
            "token_event" => !t_ev.is_empty(),
            _ => false,
        });
    let rows_tx = r_by_tx.keys().any(|k| k.is_some());
    if truth_has && !rows_tx {
        if ledger > max_row_ledger {
            if !*halted {
                *halted = true;
                out.push(mk(
                    None,
                    "halt",
                    "ledger",
                    "ledger:halt".into(),
                    json!({ "last_exported_ledger": max_row_ledger, "tx_count": lf.tx_count }),
                ));
            }
        } else {
            out.push(mk(
                None,
                "skip",
                "ledger",
                "ledger:skip".into(),
                json!({ "tx_count": lf.tx_count }),
            ));
        }
        return out;
    }

    // Ledger rows.
    for (k, p) in plans.iter().filter(|(_, p)| p.family == "ledger") {
        let lr: Vec<&&Row> = r_by_tx
            .get(&None)
            .map(|v| v.iter().filter(|r| &r.kind == k).collect())
            .unwrap_or_default();
        if lr.is_empty() {
            if p.extra_only {
                *not_compared.entry(format!("{k}:extra_only")).or_default() += 1;
            } else {
                out.push(mk(None, "missing", k, format!("{k}:missing"), Value::Null));
            }
        } else {
            if lr.len() > 1 {
                out.push(mk(
                    None,
                    "duplicate",
                    k,
                    format!("{k}:duplicate"),
                    json!({"rows": lr.len()}),
                ));
            }
            let r = lr[0];
            for (field, got, want) in [
                (
                    "tx_count",
                    r.tx_count.map(u64::from),
                    u64::from(lf.tx_count),
                ),
                (
                    "protocol",
                    r.protocol.map(u64::from),
                    u64::from(lf.protocol),
                ),
                ("close_time", r.close_time, lf.close_time),
            ] {
                if let Some(g) = got {
                    if g != want {
                        out.push(mk(
                            None,
                            "wrong_value",
                            k,
                            format!("{k}:wrong_value:{field}"),
                            json!({ "truth": want, "row": g }),
                        ));
                    }
                }
            }
        }
    }
    // Ledger-level entry changes (upgrades, evictions).
    for (k, p) in plans.iter().filter(|(_, p)| p.family == "entry_change") {
        let rows_l: Vec<&Row> = r_by_tx
            .get(&None)
            .map(|v| v.iter().copied().filter(|r| &r.kind == k).collect())
            .unwrap_or_default();
        if !rows_l.is_empty() {
            entry_compare(
                k,
                p,
                None,
                t_life.get(&None).map(Vec::as_slice).unwrap_or(&[]),
                t_field.get(&None).map(Vec::as_slice).unwrap_or(&[]),
                &rows_l,
                &sac,
                &mut out,
                not_compared,
                &mk,
            );
        }
    }

    let mut bad_tx: BTreeSet<Option<u32>> = out.iter().map(|v| v.tx_index).collect();
    for (&i, info) in &txs {
        let rows_t: Vec<&Row> = r_by_tx.get(&Some(i)).cloned().unwrap_or_default();
        let n0 = out.len();
        for (k, p) in plans {
            let rows_k: Vec<&Row> = rows_t.iter().copied().filter(|r| &r.kind == k).collect();
            match p.family.as_str() {
                "balance_change" => {
                    let truth = t_bal[p.nofee as usize].get(&i).cloned().unwrap_or_default();
                    balance_compare(
                        k,
                        p,
                        i,
                        info,
                        &truth,
                        &rows_k,
                        &norm_asset,
                        &nonsac_contracts,
                        &mut out,
                        not_compared,
                        &mk,
                    );
                }
                "participant" => {
                    let truth = t_part.get(&i).cloned().unwrap_or_default();
                    // Issuers of the assets the transaction moved: an extra participant that issues one is
                    // named with it, so a target's issuer convention can be declared.
                    let mut issued: BTreeMap<String, String> = BTreeMap::new();
                    let assets = t_bal[0]
                        .get(&i)
                        .into_iter()
                        .flat_map(|m| m.keys().map(|(_, a)| a.clone()))
                        .chain(
                            t_ev.get(&i)
                                .into_iter()
                                .flatten()
                                .filter_map(|e| e.asset.clone()),
                        );
                    for a in assets {
                        if let Some(iss) = crate::read::asset_issuer(&a) {
                            issued.entry(iss.to_string()).or_insert(a.clone());
                        }
                    }
                    participant_compare(
                        k,
                        p,
                        i,
                        info,
                        &truth,
                        &issued,
                        &rows_k,
                        &mut out,
                        not_compared,
                        &mk,
                    );
                }
                "entry_change" => entry_compare(
                    k,
                    p,
                    Some(i),
                    t_life.get(&Some(i)).map(Vec::as_slice).unwrap_or(&[]),
                    t_field.get(&Some(i)).map(Vec::as_slice).unwrap_or(&[]),
                    &rows_k,
                    &sac,
                    &mut out,
                    not_compared,
                    &mk,
                ),
                "token_event" => event_compare(
                    k,
                    p,
                    i,
                    info,
                    t_ev.get(&i).map(Vec::as_slice).unwrap_or(&[]),
                    &rows_k,
                    &norm_asset,
                    &mut out,
                    not_compared,
                    &mk,
                ),
                _ => {}
            }
        }
        // Scope rules on this transaction's verdicts.
        apply_scope(cfg, &mut out[n0..], Some(info.success));
        let in_scope_bad = out[n0..].iter().any(|v| v.scope_rule.is_none());
        if !in_scope_bad && !bad_tx.contains(&Some(i)) {
            out.push(mk(Some(i), "ok", "", String::new(), Value::Null));
        }
        bad_tx.insert(Some(i));
    }
    out
}

fn apply_scope(cfg: &Config, vs: &mut [Verdict], success: Option<bool>) {
    let Some(sc) = &cfg.scope else { return };
    for v in vs.iter_mut() {
        if v.verdict == "ok" || v.scope_rule.is_some() {
            continue;
        }
        let seen = Seen {
            kind: &v.kind,
            verdict: v.verdict,
            class: &v.class,
            evidence: &v.evidence,
            success,
        };
        if let Some(r) = sc.rules.iter().find(|r| r.matches(&seen)) {
            v.scope_rule = Some(r.id.clone());
            v.verdict = "out_of_scope";
        }
    }
}

type Mk<'a> = dyn Fn(Option<u32>, &'static str, &str, String, Value) -> Verdict + 'a;

#[allow(clippy::too_many_arguments)]
fn balance_compare(
    k: &str,
    p: &KindPlan,
    i: u32,
    info: &TxInfo,
    truth: &BTreeMap<(String, String), (i128, bool)>,
    rows: &[&Row],
    norm_asset: &dyn Fn(&str) -> String,
    nonsac_contracts: &BTreeSet<String>,
    out: &mut Vec<Verdict>,
    not_compared: &mut BTreeMap<String, u64>,
    mk: &Mk<'_>,
) {
    let mut got: BTreeMap<(String, String), Vec<(i128, Option<u32>, &Row)>> = BTreeMap::new();
    for r in rows {
        let (Some(h), Some(a), Some(am)) = (&r.holder, &r.asset, &r.amount) else {
            out.push(mk(
                Some(i),
                "wrong_value",
                k,
                format!("{k}:malformed_row"),
                json!({"row": r}),
            ));
            continue;
        };
        let Some(n) = pi(am) else {
            out.push(mk(
                Some(i),
                "wrong_value",
                k,
                format!("{k}:bad_amount"),
                json!({"row": r}),
            ));
            continue;
        };
        got.entry((base(h), norm_asset(a)))
            .or_default()
            .push((n, r.op_index, r));
    }
    let mut keys: BTreeSet<(String, String)> = truth.keys().cloned().collect();
    keys.extend(got.keys().cloned());
    for key in keys {
        let t = truth.get(&key);
        let g = got.get(&key);
        let gsum: i128 = g.map(|v| v.iter().map(|x| x.0).sum()).unwrap_or(0);
        let ev = |t: Option<i128>| {
            json!({"holder": key.0, "asset": key.1, "truth": t.map(|x| x.to_string()),
                   "rows": gsum.to_string(), "row_count": g.map(|v| v.len()).unwrap_or(0)})
        };
        // A holder whose every asset is unknown in this tx (`*`).
        let t = t.or_else(|| {
            truth
                .get(&(key.0.clone(), "*".to_string()))
                .filter(|x| !x.1)
        });
        match t {
            Some((_, false)) => {
                out.push(mk(
                    Some(i),
                    "unknown",
                    k,
                    format!("{k}:unknown_truth"),
                    ev(None),
                ));
            }
            Some((tv, true)) => {
                let Some(v) = g else {
                    if p.extra_only {
                        *not_compared.entry(format!("{k}:extra_only")).or_default() += 1;
                    } else {
                        out.push(mk(
                            Some(i),
                            "missing",
                            k,
                            format!("{k}:missing"),
                            ev(Some(*tv)),
                        ));
                    }
                    continue;
                };
                if gsum != *tv {
                    // Duplicate: removing repeated identical rows restores the truth.
                    let mut seen = BTreeSet::new();
                    let mut dedup: i128 = 0;
                    let mut dup = false;
                    for (n, op, _) in v {
                        if seen.insert((*n, *op)) {
                            dedup += n;
                        } else {
                            dup = true;
                        }
                    }
                    let (verdict, class) = if dup && dedup == *tv {
                        ("duplicate", format!("{k}:duplicate"))
                    } else {
                        let mut c = format!("{k}:wrong_value:{}", value_reason(*tv, gsum));
                        if !info.success {
                            c.push_str(":failed_tx");
                        }
                        ("wrong_value", c)
                    };
                    out.push(mk(Some(i), verdict, k, class, ev(Some(*tv))));
                }
            }
            None => {
                if gsum == 0 {
                    continue;
                }
                let class = if key.1.starts_with('C') && key.1.len() == 56 && !key.1.contains(':') {
                    if nonsac_contracts.contains(&key.1) {
                        format!("{k}:extra:non_sac_contract")
                    } else {
                        format!("{k}:extra:unverified_contract")
                    }
                } else if !info.success {
                    format!("{k}:extra:failed_tx")
                } else {
                    format!("{k}:extra")
                };
                out.push(mk(Some(i), "extra", k, class, ev(None)));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn participant_compare(
    k: &str,
    p: &KindPlan,
    i: u32,
    info: &TxInfo,
    truth: &BTreeMap<String, (Vec<String>, Vec<String>)>,
    issued: &BTreeMap<String, String>,
    rows: &[&Row],
    out: &mut Vec<Verdict>,
    not_compared: &mut BTreeMap<String, u64>,
    mk: &Mk<'_>,
) {
    let mut got: BTreeMap<String, Vec<&Row>> = BTreeMap::new();
    for r in rows {
        let Some(a) = r.holder.as_ref() else {
            out.push(mk(
                Some(i),
                "wrong_value",
                k,
                format!("{k}:malformed_row"),
                json!({"row": r}),
            ));
            continue;
        };
        got.entry(base(a)).or_default().push(r);
    }
    // A claimant named by CreateClaimableBalance and nothing else is not a participant by the judge's
    // convention: absent is fine, present is `extra:claimant`.
    let claimant_only = |roles: &[String]| roles.len() == 1 && roles[0] == "claimant";
    for (a, (roles, mx)) in truth {
        match got.get(a) {
            None if claimant_only(roles) => {}
            None if p.extra_only => {
                *not_compared.entry(format!("{k}:extra_only")).or_default() += 1;
            }
            None => out.push(mk(
                Some(i),
                "missing",
                k,
                format!("{k}:missing:{}", roles.join("+")),
                json!({"address": a, "roles": roles, "muxed_ids": mx}),
            )),
            Some(v) if claimant_only(roles) => out.push(mk(
                Some(i),
                "extra",
                k,
                format!("{k}:extra:claimant"),
                json!({"address": a, "roles": roles, "rows": v.len()}),
            )),
            Some(v) => {
                if v.len() > 1 {
                    out.push(mk(
                        Some(i),
                        "duplicate",
                        k,
                        format!("{k}:duplicate"),
                        json!({"address": a, "rows": v.len()}),
                    ));
                }
                for r in v {
                    if let Some(m) = &r.muxed_id {
                        if !mx.contains(m) {
                            out.push(mk(
                                Some(i),
                                "wrong_value",
                                k,
                                format!("{k}:wrong_value:muxed_id"),
                                json!({"address": a, "truth": mx, "row": m}),
                            ));
                        }
                    }
                }
            }
        }
    }
    for (a, v) in &got {
        if !truth.contains_key(a) {
            let class = if info.success {
                format!("{k}:extra")
            } else {
                format!("{k}:extra:failed_tx")
            };
            let mut ev = json!({"address": a, "rows": v.len()});
            if let Some(asset) = issued.get(a) {
                ev["asset"] = json!(asset);
            }
            out.push(mk(Some(i), "extra", k, class, ev));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn event_compare(
    k: &str,
    p: &KindPlan,
    i: u32,
    info: &TxInfo,
    truth: &[TEv],
    rows: &[&Row],
    norm_asset: &dyn Fn(&str) -> String,
    out: &mut Vec<Verdict>,
    not_compared: &mut BTreeMap<String, u64>,
    mk: &Mk<'_>,
) {
    type Key = (String, String, String, String, String);
    let row_key = |r: &Row| -> Key {
        (
            r.contract.clone().unwrap_or_default(),
            r.event.clone().unwrap_or_default(),
            r.from.as_deref().map(base).unwrap_or_default(),
            r.to.as_deref().map(base).unwrap_or_default(),
            r.amount
                .as_deref()
                .and_then(pi)
                .map(|n| n.to_string())
                .unwrap_or_default(),
        )
    };
    let mut used = vec![false; truth.len()];
    let mut unmatched_rows: Vec<(&Row, Key)> = Vec::new();
    let mut tcount: BTreeMap<&Key, u32> = BTreeMap::new();
    for t in truth {
        *tcount.entry(&t.key).or_default() += 1;
    }
    for r in rows {
        let key = row_key(r);
        let pos = truth
            .iter()
            .enumerate()
            .position(|(j, t)| !used[j] && t.key == key);
        let Some(j) = pos else {
            unmatched_rows.push((r, key));
            continue;
        };
        used[j] = true;
        let t = &truth[j];
        // The optional fields a row states must agree with the matched event.
        let mut diffs: Vec<(&str, Value, Value)> = Vec::new();
        match (&r.to_muxed_id, &t.to_muxed_id) {
            (Some(g), w) if Some(g) != w.as_ref() => {
                diffs.push(("to_muxed_id", json!(w), json!(g)))
            }
            (None, Some(w)) => diffs.push(("to_muxed_id_absent", json!(w), Value::Null)),
            _ => {}
        }
        if let (Some(g), Some(w)) = (&r.asset, &t.asset) {
            if &norm_asset(g) != w {
                diffs.push(("asset", json!(w), json!(g)));
            }
        }
        if let (Some(g), Some(w)) = (r.op_index, t.op_index) {
            if g != w {
                diffs.push(("op_index", json!(w), json!(g)));
            }
        }
        for (f, w, g) in diffs {
            out.push(mk(
                Some(i),
                "wrong_value",
                k,
                format!("{k}:wrong_value:{f}"),
                json!({"event_name": key.1, "event": key, "field": f, "truth": w, "row": g}),
            ));
        }
    }
    let mut missing: Vec<&Key> = truth
        .iter()
        .enumerate()
        .filter(|(j, _)| !used[*j])
        .map(|(_, t)| &t.key)
        .collect();
    for (_, key) in &unmatched_rows {
        if tcount.get(key).copied().unwrap_or(0) > 0 {
            out.push(mk(
                Some(i),
                "duplicate",
                k,
                format!("{k}:duplicate"),
                json!({"event_name": key.1, "event": key, "truth": tcount[key]}),
            ));
            continue;
        }
        let pair = missing
            .iter()
            .position(|m| m.0 == key.0 && m.1 == key.1 && m.2 == key.2 && m.3 == key.3);
        match pair {
            Some(pp) => {
                let m = missing.remove(pp);
                let reason = match (pi(&m.4), pi(&key.4)) {
                    (Some(a), Some(b)) => value_reason(a, b),
                    _ => "other",
                };
                out.push(mk(
                    Some(i),
                    "wrong_value",
                    k,
                    format!("{k}:wrong_value:{reason}"),
                    json!({"event_name": key.1, "truth": m, "row": key}),
                ));
            }
            None => {
                let class = if !info.success {
                    format!("{k}:extra:failed_tx")
                } else {
                    format!("{k}:extra")
                };
                out.push(mk(
                    Some(i),
                    "extra",
                    k,
                    class,
                    json!({"event_name": key.1, "row": key}),
                ));
            }
        }
    }
    for m in missing {
        if p.extra_only {
            *not_compared.entry(format!("{k}:extra_only")).or_default() += 1;
            continue;
        }
        out.push(mk(
            Some(i),
            "missing",
            k,
            format!("{k}:missing"),
            json!({"event_name": m.1, "event": m}),
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn entry_compare(
    k: &str,
    p: &KindPlan,
    tx: Option<u32>,
    life: &[TLife],
    fields: &[TField],
    rows: &[&Row],
    c2a: &HashMap<String, String>,
    out: &mut Vec<Verdict>,
    not_compared: &mut BTreeMap<String, u64>,
    mk: &Mk<'_>,
) {
    let mut lused = vec![false; life.len()];
    let mut fused = vec![false; fields.len()];
    let op_ok = |row: Option<u32>, t: Option<u32>| row.is_none() || row == t;
    // Subjects created in an op of this tx: a flags row with no bits on a new entry is the target's
    // initial-state row, told apart from a no-op on an existing entry.
    let created: BTreeSet<(Option<u32>, &str)> = life
        .iter()
        .filter(|l| l.change == "created")
        .map(|l| (l.op, l.subject.as_str()))
        .collect();
    let mut field_rows: Vec<(&Row, String)> = Vec::new();
    let mut life_rows: Vec<(&Row, String)> = Vec::new();
    for r in rows {
        let Some(subject) = row_subject(r, c2a) else {
            out.push(mk(
                tx,
                "wrong_value",
                k,
                format!("{k}:malformed_row"),
                json!({"row": r}),
            ));
            continue;
        };
        if r.field.is_some() {
            field_rows.push((r, subject));
        } else {
            life_rows.push((r, subject));
        }
    }
    // Rows are matched in passes, so a looser match never takes an item an exact match needs.
    // Lifecycle: exact (op, subject, change); an `updated` row standing for any change of the entry in that
    // op; the same change in another op (`wrong_value:op_index`); else extra.
    let mut ldone = vec![false; life_rows.len()];
    for pass in 0..4 {
        for (ri, (r, subject)) in life_rows.iter().enumerate() {
            if ldone[ri] {
                continue;
            }
            let change = r.change.clone().unwrap_or_default();
            let etype = subject.split(':').next().unwrap_or("").to_string();
            let find = |exact_op: bool, any_change: bool, lused: &[bool]| {
                life.iter().enumerate().position(|(j, t)| {
                    !lused[j]
                        && &t.subject == subject
                        && (!exact_op || op_ok(r.op_index, t.op))
                        && (t.change == change || (any_change && change == "updated"))
                })
            };
            match pass {
                0 => {
                    if let Some(j) = find(true, false, &lused) {
                        lused[j] = true;
                        ldone[ri] = true;
                    }
                }
                1 => {
                    // An `updated` row stands for any change of the entry in its op, matched or not (one
                    // entry can be the subject of several such rows: an indexer derives them per effect).
                    let none = vec![false; life.len()];
                    if change == "updated" && find(true, true, &none).is_some() {
                        ldone[ri] = true;
                    }
                }
                2 => {
                    if let Some(j) = find(false, false, &lused) {
                        lused[j] = true;
                        ldone[ri] = true;
                        out.push(mk(
                            tx,
                            "wrong_value",
                            k,
                            format!("{k}:wrong_value:op_index"),
                            json!({"subject": subject, "entry_type": etype, "change": change,
                                   "truth": life[j].op, "row": r.op_index}),
                        ));
                    }
                }
                _ => {
                    ldone[ri] = true;
                    out.push(mk(
                        tx,
                        "extra",
                        k,
                        format!("{k}:extra:{etype}:{change}"),
                        json!({"subject": subject, "entry_type": etype, "change": change,
                               "op_index": r.op_index}),
                    ));
                }
            }
        }
    }
    // Fields: exact (op, subject, field); a signer with another key of the same entry (the truth key sharing
    // the longest prefix: `wrong_value:signer_key`); the same field in another op; else extra (`noop` when
    // the row states no change).
    let mut fdone = vec![false; field_rows.len()];
    for pass in 0..5 {
        for (ri, (r, subject)) in field_rows.iter().enumerate() {
            if fdone[ri] {
                continue;
            }
            let field = r.field.clone().unwrap_or_default();
            let fam = family_of(&field).to_string();
            let etype = subject.split(':').next().unwrap_or("").to_string();
            let ev = |t: Option<&TField>| {
                json!({"subject": subject, "entry_type": etype, "field": field, "op_index": r.op_index,
                       "truth": t.map(|t| json!({"field": t.field, "old": t.old, "new": t.new, "op_index": t.op})),
                       "row": {"old": r.old, "new": r.new}})
            };
            let cand = |exact_op: bool, same_field: bool, fused: &[bool]| -> Vec<usize> {
                fields
                    .iter()
                    .enumerate()
                    .filter(|(j, t)| {
                        !fused[*j]
                            && &t.subject == subject
                            && (!exact_op || op_ok(r.op_index, t.op))
                            && if same_field {
                                t.field == field
                            } else {
                                family_of(&t.field) == fam
                            }
                    })
                    .map(|(j, _)| j)
                    .collect()
            };
            match pass {
                0 | 1 => {
                    let agrees = |t: &TField| {
                        !((r.old.is_some() && r.old != t.old)
                            || (r.new.is_some() && r.new != t.new))
                    };
                    let c = cand(true, true, &fused);
                    // Pass 0 takes only items whose values the row states correctly, pass 1 any item
                    // of the same field (a wrong value).
                    let pick = if pass == 0 {
                        c.iter().copied().find(|&j| agrees(&fields[j]))
                    } else {
                        c.first().copied()
                    };
                    if let Some(j) = pick {
                        fused[j] = true;
                        fdone[ri] = true;
                        let t = &fields[j];
                        if !agrees(t) {
                            // Flag bits beyond the change that were already in the stated state (a clear of
                            // a flag that was not set): the row restates the flags rather than the change.
                            let class = match (flag_bits(r), t.flags_state) {
                                (Some(b), Some(st)) if restates(&field, b, t, st) => {
                                    format!("{k}:wrong_value:restated_bits:{etype}:{fam}")
                                }
                                _ => format!("{k}:wrong_value:{etype}:{fam}"),
                            };
                            out.push(mk(tx, "wrong_value", k, class, ev(Some(t))));
                        }
                    }
                }
                2 => {
                    if fam != "signer" {
                        continue;
                    }
                    let common = |a: &str, b: &str| {
                        a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
                    };
                    if let Some(j) = cand(true, false, &fused)
                        .into_iter()
                        .max_by_key(|&j| (common(&fields[j].field, &field), std::cmp::Reverse(j)))
                    {
                        fused[j] = true;
                        fdone[ri] = true;
                        out.push(mk(
                            tx,
                            "wrong_value",
                            k,
                            format!("{k}:wrong_value:{etype}:signer_key"),
                            ev(Some(&fields[j])),
                        ));
                    }
                }
                3 => {
                    if let Some(&j) = cand(false, true, &fused).first() {
                        fused[j] = true;
                        fdone[ri] = true;
                        out.push(mk(
                            tx,
                            "wrong_value",
                            k,
                            format!("{k}:wrong_value:op_index"),
                            ev(Some(&fields[j])),
                        ));
                    }
                }
                _ => {
                    fdone[ri] = true;
                    // A value said to be gone from an entry removed in this op: the removal says so.
                    let removed = life.iter().any(|t| {
                        &t.subject == subject && op_ok(r.op_index, t.op) && t.change == "removed"
                    });
                    if removed && r.new.is_none() {
                        continue;
                    }
                    let zero_bits = (field == "flags:set" || field == "flags:clear")
                        && r.new.as_deref().map(|v| v.parse::<u64>().ok() == Some(0)) == Some(true);
                    // Flag bits that leave the entry's flags in this op as they were.
                    let state = fields
                        .iter()
                        .find(|t| {
                            &t.subject == subject
                                && op_ok(r.op_index, t.op)
                                && t.flags_state.is_some()
                        })
                        .and_then(|t| t.flags_state);
                    let unchanged_bits = match (flag_bits(r), state) {
                        (Some(b), Some((o, _))) if field == "flags:set" => b & !o == 0,
                        (Some(b), Some((o, _))) if field == "flags:clear" => b & o == 0,
                        _ => false,
                    };
                    // The entry changed in this op but not in this attribute: the row states a change of
                    // a value that stayed as it was.
                    let touched = life.iter().any(|t| {
                        &t.subject == subject
                            && op_ok(r.op_index, t.op)
                            && (t.change == "updated" || t.change == "created")
                    });
                    // Flags rows are bits of one value; other fields (one threshold, one signer) stand alone.
                    let fam_changed = fields.iter().any(|t| {
                        &t.subject == subject
                            && op_ok(r.op_index, t.op)
                            && if fam == "flags" {
                                family_of(&t.field) == fam
                            } else {
                                t.field == field
                            }
                    });
                    let noop = (r.old.is_some() && r.old == r.new)
                        || zero_bits
                        || unchanged_bits
                        || (touched && !fam_changed);
                    let class = if noop && created.contains(&(r.op_index, subject.as_str())) {
                        format!("{k}:extra:noop_on_create:{etype}:{fam}")
                    } else if zero_bits {
                        // A flags row with no bits at all: it states nothing.
                        format!("{k}:extra:noop_empty:{etype}:{fam}")
                    } else if noop {
                        format!("{k}:extra:noop:{etype}:{fam}")
                    } else {
                        format!("{k}:extra:{etype}:{fam}")
                    };
                    out.push(mk(tx, "extra", k, class, ev(None)));
                }
            }
        }
    }
    // Truth the target claims and no row matched.
    for (j, t) in life.iter().enumerate() {
        if lused[j] {
            continue;
        }
        let claim = format!("{}:{}", t.entry_type, t.change);
        let claimed = p
            .lifecycle
            .as_ref()
            .map(|c| c.contains(&claim))
            .unwrap_or(true);
        if p.extra_only || !claimed {
            let why = if p.extra_only {
                "extra_only"
            } else {
                "unclaimed"
            };
            *not_compared
                .entry(format!("{k}:{why}:{claim}"))
                .or_default() += 1;
            continue;
        }
        out.push(mk(
            tx,
            "missing",
            k,
            format!("{k}:missing:{claim}"),
            json!({"subject": t.subject, "entry_type": t.entry_type, "change": t.change, "op_index": t.op}),
        ));
    }
    for (j, t) in fields.iter().enumerate() {
        if fused[j] {
            continue;
        }
        let claim = format!("{}:{}", t.entry_type, family_of(&t.field));
        let claimed = p
            .fields
            .as_ref()
            .map(|c| c.contains(&claim))
            .unwrap_or(false);
        if p.extra_only || !claimed {
            let why = if p.extra_only {
                "extra_only"
            } else {
                "unclaimed"
            };
            *not_compared
                .entry(format!("{k}:{why}:{claim}"))
                .or_default() += 1;
            continue;
        }
        let on_create = if created.contains(&(t.op, t.subject.as_str())) {
            "missing_on_create"
        } else {
            "missing"
        };
        out.push(mk(
            tx,
            "missing",
            k,
            format!("{k}:{on_create}:{claim}"),
            json!({"subject": t.subject, "entry_type": t.entry_type, "field": t.field,
                   "old": t.old, "new": t.new, "op_index": t.op}),
        ));
    }
}

/// The bits of a `flags:set` / `flags:clear` row.
fn flag_bits(r: &Row) -> Option<u64> {
    match r.field.as_deref() {
        Some("flags:set") | Some("flags:clear") => r.new.as_deref()?.parse().ok(),
        _ => None,
    }
}

/// A flags row whose bits hold the change's bits plus bits already in the stated state.
fn restates(field: &str, bits: u64, t: &TField, (old, new): (u64, u64)) -> bool {
    let want: u64 = t.new.as_deref().and_then(|v| v.parse().ok()).unwrap_or(0);
    if bits & want != want {
        return false;
    }
    let extra = bits & !want;
    match field {
        "flags:set" => extra & !old == 0 && extra & !new == 0,
        "flags:clear" => extra & old == 0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_reasons() {
        let wide: i128 = (1i128 << 64) + 5;
        assert_eq!(value_reason(wide, 5), "int64_wrap");
        assert_eq!(value_reason(wide, i64::MAX as i128), "int64_clamp");
        assert_eq!(value_reason(100, 101), "small_diff");
        assert_eq!(value_reason(100, -100), "sign");
        assert_eq!(value_reason(100, 0), "zero");
        assert_eq!(value_reason(100, 200), "multiple");
        assert_eq!(value_reason(100, 1234), "other");
    }

    #[test]
    fn muxed_addresses_normalise_to_base() {
        let m = stellar_xdr::MuxedAccount::MuxedEd25519(stellar_xdr::MuxedAccountMed25519 {
            id: 7,
            ed25519: stellar_xdr::Uint256([2; 32]),
        });
        let g = stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256([2; 32])).to_string();
        assert_eq!(base(&m.to_string()), g);
        assert_eq!(base(&g), g);
    }
}
