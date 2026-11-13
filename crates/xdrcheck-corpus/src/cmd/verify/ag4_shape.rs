//! AG-4's second measure: the scan's shape tokens of a transaction, reduced to what no meta flag
//! and no run timing changes (`docs/manifest.md` §4.7).
//!
//! The structural skeleton ([`super::ag4::profile_free`]) keeps arms and exact lengths but masks
//! every value, including the presence of an optional integer (`set_flags` and
//! `high_threshold` look alike whether set or not) and every flag or threshold value. Two
//! transactions with equal skeletons can therefore apply different patterns (an `AllowTrust` to
//! "maintain liabilities" and one to "authorized"). The scan's token emitter
//! ([`crate::cmd::scan::shape`], grammar `xcc.shape/v1`) records exactly those facts: optional
//! presence, the set of fields each updated entry changed, flag transitions (`flags=1>2`), the
//! operation-versus-effect relations, event signatures and length classes. AG-4 compares both.
//!
//! **Reduction.** From every component of the transaction (E envelope, A authorization, R result,
//! F fee processing, M transaction meta, O one per operation: body, result, meta changes, events):
//!
//! - type-level tokens (kind `T`) are dropped: they record which types occur anywhere, including
//!   inside diagnostic events, so they cannot be attributed to a place;
//! - tokens of the parts `profile_free` removes are dropped: transaction-level events and
//!   diagnostic events (`meta.v4.events`, every `diagnosticEvents`), `sorobanMeta.ext`, and the
//!   event signatures (`X`) of operations that are not Soroban operations (classic events exist
//!   only under `EMIT_CLASSIC_EVENTS`). The contract events of a v3 meta's `sorobanMeta.events`
//!   are kept, as `profile_free` keeps them;
//! - in the field list of an updated entry (`D|upd`), the account's `seqLedger` and `seqTime` are
//!   removed: stellar-core writes both on every sequence-number bump, so whether they appear as
//!   changed depends only on whether the previous bump was in a ledger with another sequence or
//!   close time, a property of the run's timing (stellar-core's tests close ledgers at a fixed
//!   time), not of the transaction.
//!
//! Nothing else is masked: a token that differs is a difference.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use xdrcheck_xdr::xdr::LedgerCloseMeta;

use crate::cmd::coverage::walk::Defs;
use crate::cmd::scan::shape::{Ctx, Rules, RULES_V1};

/// Soroban operation types (token spelling): their events are contract events, kept.
const SOROBAN_OPS: [&str; 3] = [
    "INVOKE_HOST_FUNCTION",
    "EXTEND_FOOTPRINT_TTL",
    "RESTORE_FOOTPRINT",
];

fn rules() -> &'static Rules {
    static R: OnceLock<Rules> = OnceLock::new();
    R.get_or_init(|| Rules::parse(RULES_V1, Defs::pinned()).expect("the built-in rules parse"))
}

/// Whether a token of component `kind` survives the reduction.
fn keep(tok: &str) -> bool {
    let mut parts = tok.splitn(3, '|');
    let (Some(kind), Some(_class), Some(body)) = (parts.next(), parts.next(), parts.next()) else {
        return true;
    };
    if kind == "T" {
        return false;
    }
    if body.contains("meta.v4.events")
        || body.contains("diagnosticEvents")
        || body.contains("sorobanMeta.ext")
    {
        return false;
    }
    if kind == "X" {
        if body.starts_with("txev:") {
            return false;
        }
        if let Some(rest) = body.strip_prefix("op:") {
            let op = rest.split('#').next().unwrap_or("");
            if !SOROBAN_OPS.contains(&op) {
                return false;
            }
        }
    }
    true
}

/// The token after the reduction (only `D|upd` field lists change).
fn norm(tok: &str) -> String {
    if !tok.starts_with("D|upd|") {
        return tok.to_string();
    }
    let Some((head, fields)) = tok.split_once(":{") else {
        return tok.to_string();
    };
    let fields = fields.strip_suffix('}').unwrap_or(fields);
    let kept: Vec<&str> = fields
        .split(',')
        .filter(|f| !(f.ends_with(".seqLedger") || f.ends_with(".seqTime")))
        .collect();
    format!("{head}:{{{}}}", kept.join(","))
}

fn reduce(tokens: &[String]) -> BTreeSet<String> {
    tokens.iter().filter(|t| keep(t)).map(|t| norm(t)).collect()
}

/// The 16-byte hex id of a reduced token set.
fn set_id(kind: &str, toks: &BTreeSet<String>) -> String {
    let mut h = Sha256::new();
    h.update(b"xcc.ag4-shape/v1\n");
    h.update(kind.as_bytes());
    for t in toks {
        h.update(b"\n");
        h.update(t.as_bytes());
    }
    hex::encode(&h.finalize()[..16])
}

/// One operation's reduced shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpShape {
    pub op_type: String,
    pub id: String,
    pub tokens: BTreeSet<String>,
}

impl OpShape {
    /// The operation's innermost result arm (`ALLOW_TRUST_SUCCESS`, `opNO_ACCOUNT`, …).
    pub fn result(&self) -> String {
        self.tokens
            .iter()
            .filter_map(|t| t.strip_prefix("A|arm|opres"))
            .filter_map(|rest| rest.rsplit_once("::").map(|(path, arm)| (path.len(), arm)))
            .max()
            .map(|(_, arm)| arm.to_string())
            .unwrap_or_default()
    }
}

/// One transaction's reduced shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxTokens {
    /// E, A, R, F, M (A absent when the transaction has no authorization entry).
    pub parts: BTreeMap<char, BTreeSet<String>>,
    /// The distinct operation shapes, each with the class of its multiplicity (`1`, `2`, `3-4`, …).
    pub ops: Vec<(OpShape, String)>,
    /// The class of the number of operations.
    pub op_count_class: String,
    /// Hash over every part, every distinct operation shape with its multiplicity class and the
    /// operation-count class: two transactions with the same id have the same reduced shape.
    pub id: String,
}

impl TxTokens {
    /// Differences against another transaction, at most `max` lines.
    pub fn diff(&self, other: &TxTokens, max: usize) -> Vec<String> {
        let mut out = Vec::new();
        let empty = BTreeSet::new();
        let kinds: BTreeSet<char> = self
            .parts
            .keys()
            .chain(other.parts.keys())
            .copied()
            .collect();
        for k in kinds {
            let a = self.parts.get(&k).unwrap_or(&empty);
            let b = other.parts.get(&k).unwrap_or(&empty);
            for t in a.difference(b) {
                out.push(format!("{k} only here: {t}"));
            }
            for t in b.difference(a) {
                out.push(format!("{k} only in the golden: {t}"));
            }
        }
        for (o, class) in &self.ops {
            if other.ops.iter().any(|(g, c)| g.id == o.id && c == class) {
                continue;
            }
            match other.ops.iter().find(|(g, _)| g.op_type == o.op_type) {
                Some((g, c)) => {
                    if g.id == o.id {
                        out.push(format!(
                            "O {}: multiplicity {class} here, {c} in the golden",
                            o.op_type
                        ));
                    }
                    for t in o.tokens.difference(&g.tokens) {
                        out.push(format!("O {} only here: {t}", o.op_type));
                    }
                    for t in g.tokens.difference(&o.tokens) {
                        out.push(format!("O {} only in the golden: {t}", o.op_type));
                    }
                }
                None => out.push(format!(
                    "O {}: no operation of this type in the golden",
                    o.op_type
                )),
            }
        }
        for (g, _) in &other.ops {
            if !self.ops.iter().any(|(o, _)| o.op_type == g.op_type) {
                out.push(format!("O {}: only in the golden", g.op_type));
            }
        }
        if self.op_count_class != other.op_count_class {
            out.push(format!(
                "operation count class {} here, {} in the golden",
                self.op_count_class, other.op_count_class
            ));
        }
        out.truncate(max);
        out
    }
}

/// The reduced shapes of every transaction of a ledger, in apply order, joined under `passphrase`.
pub fn ledger_tokens(
    lcm: &LedgerCloseMeta,
    blob: &[u8],
    passphrase: &str,
) -> Result<Vec<TxTokens>> {
    let ctx = Ctx {
        defs: Defs::pinned(),
        rules: rules(),
        network_id: Sha256::digest(passphrase.as_bytes()).into(),
    };
    let sh = ctx.ledger(lcm, blob)?;
    if sh.tx_hash_mismatches > 0 {
        bail!(
            "{} transaction(s) do not join their envelope under the passphrase",
            sh.tx_hash_mismatches
        );
    }
    let comp = |id: &str| -> Result<&crate::cmd::scan::shape::Component> {
        sh.components
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("component {id} missing"))
    };
    let mut out = Vec::new();
    for tx in &sh.txs {
        let mut parts = BTreeMap::new();
        for (k, id) in [('E', &tx.e), ('R', &tx.r), ('F', &tx.f), ('M', &tx.m)] {
            parts.insert(k, reduce(&comp(id)?.tokens));
        }
        if let Some(a) = &tx.a {
            parts.insert('A', reduce(&comp(a)?.tokens));
        }
        out.push((parts, &tx.ops, &tx.op_count_class));
    }
    // The scan keeps the distinct operation components of a transaction with the class of their
    // multiplicity; two scan components can reduce to one shape, so the reduced list is merged
    // again (the larger class wins: equal ids then mean equal reduced shapes).
    let mut txs = Vec::new();
    for (parts, ops, count_class) in out {
        let mut list: Vec<(OpShape, String)> = Vec::new();
        for (id, class) in ops.iter() {
            let c = comp(id)?;
            let toks = reduce(&c.tokens);
            let op = OpShape {
                op_type: c.op_type.clone().unwrap_or_default(),
                id: set_id("O", &toks),
                tokens: toks,
            };
            match list.iter_mut().find(|(o, _)| o.id == op.id) {
                Some((_, c)) => {
                    if class_rank(class) > class_rank(c) {
                        *c = class.clone();
                    }
                }
                None => list.push((op, class.clone())),
            }
        }
        list.sort_by(|a, b| a.0.id.cmp(&b.0.id));
        let mut h = Sha256::new();
        h.update(b"xcc.ag4-shape/v1 tx");
        for (k, toks) in &parts {
            h.update(b"\n");
            h.update(set_id(&k.to_string(), toks).as_bytes());
        }
        for (o, class) in &list {
            h.update(format!("\nO:{}*{class}", o.id).as_bytes());
        }
        h.update(format!("\nops={count_class}").as_bytes());
        txs.push(TxTokens {
            parts,
            ops: list,
            op_count_class: count_class.clone(),
            id: hex::encode(&h.finalize()[..16]),
        });
    }
    Ok(txs)
}

/// The reduced operation shapes of every corpus entry's focus transaction, read from the
/// manifest and blobs of `corpus` alone: shape → source kind → entries. A variant that is not a
/// `LedgerCloseMeta`, has no focus transaction, or does not decode or join is skipped (other checks
/// report those).
pub fn corpus_op_shapes(
    corpus: &Path,
) -> Result<BTreeMap<String, BTreeMap<String, BTreeSet<String>>>> {
    let limits = xdrcheck_xdr::Limits::default();
    let gate = xdrcheck_xdr::Gate::default().reading_live();
    let mut out: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    for (id, path) in super::load::json_files(&corpus.join("manifest"))? {
        let Ok(m) = serde_json::from_slice::<Value>(&std::fs::read(&path)?) else {
            continue;
        };
        for v in m["variants"].as_array().into_iter().flatten() {
            if v["xdr_type"] != "LedgerCloseMeta" {
                continue;
            }
            let (Some(blob), Some(pass), Some(tx)) = (
                v["blob"]["path"].as_str(),
                v["passphrase"].as_str(),
                v["focus"]["tx_index"].as_u64(),
            ) else {
                continue;
            };
            let Ok(bytes) = std::fs::read(corpus.join(blob)) else {
                continue;
            };
            let ops = xdrcheck_xdr::with_stack(limits.stack_size, || -> Option<Vec<String>> {
                let lcm = xdrcheck_xdr::decode_ledger(&bytes, &limits, &gate).ok()?;
                let txs = ledger_tokens(&lcm, &bytes, pass).ok()?;
                Some(
                    txs.get(tx as usize)?
                        .ops
                        .iter()
                        .map(|(o, _)| o.id.clone())
                        .collect(),
                )
            });
            let kind = v["source"]["kind"].as_str().unwrap_or("?").to_string();
            for op in ops.into_iter().flatten() {
                out.entry(op)
                    .or_default()
                    .entry(kind.clone())
                    .or_default()
                    .insert(id.clone());
            }
        }
    }
    Ok(out)
}

/// Order of a class label (`1` < `2` < `3-4` < `>4`): its first number, `>` after every bound.
fn class_rank(c: &str) -> (u8, u64) {
    match c.strip_prefix('>') {
        Some(n) => (1, n.parse().unwrap_or(u64::MAX)),
        None => (
            0,
            c.split('-')
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0),
        ),
    }
}

/// A reference to a golden operation, as recorded in `mirrors.json`.
pub fn op_ref_json(file: &str, frame: usize, tx: usize, op: &OpShape) -> Value {
    json!({"file": file, "frame_index": frame, "tx_index": tx, "op_type": op.op_type, "shape": op.id})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_and_timing_parts_are_reduced() {
        assert!(!keep("T|arm|Memo::MEMO_NONE"));
        assert!(!keep("L|len|meta.v4.diagnosticEvents#len=3"));
        assert!(!keep(
            "X|ev|txev:TRANSACTION_EVENT_STAGE_BEFORE_ALL_TXS#ev=CONTRACT:fee"
        ));
        assert!(!keep(
            "X|ev|op:PAYMENT#ev=CONTRACT:transfer:[ADDR:ACCOUNT]:I128"
        ));
        assert!(keep(
            "X|ev|op:INVOKE_HOST_FUNCTION#ev=CONTRACT:transfer:[ADDR:ACCOUNT]:I128"
        ));
        assert!(keep(
            "D|upd|op:ALLOW_TRUST#upd:TRUSTLINE:{data.TRUSTLINE.flags=1>2}"
        ));
        assert_eq!(
            norm("D|upd|txBefore#upd:ACCOUNT:{data.ACCOUNT.ext.v1.ext.v2.ext.v3.seqLedger,data.ACCOUNT.ext.v1.ext.v2.ext.v3.seqTime,data.ACCOUNT.seqNum}"),
            "D|upd|txBefore#upd:ACCOUNT:{data.ACCOUNT.seqNum}"
        );
    }
}
