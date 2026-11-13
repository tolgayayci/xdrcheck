//! The oracle side of a mutant: strict decode with the pinned `stellar-xdr` (decode, re-encode,
//! byte equality, no trailing bytes), the ledger hashes a mutation invalidates, and the reference
//! extractor's facts.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use stellar_xdr::{
    GeneralizedTransactionSet, Hash, LedgerCloseMeta, LedgerEntryChange, LedgerEntryChanges,
    Limits as XLimits, TransactionEnvelope, TransactionMeta, TransactionPhase,
    TransactionResultPair, TransactionResultResult, TransactionResultSet, TxSetComponent, WriteXdr,
};
use xdrcheck_xdr::{Gate, Limits};

/// The oracle's answer for one input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Verdict {
    pub accepts: bool,
    /// The refusal, when refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Strict decode and byte-exact re-encode of `bytes` as `xdr_type`.
pub fn check(xdr_type: &str, bytes: &[u8]) -> Verdict {
    match xdrcheck_xdr::roundtrip(xdr_type, bytes, &Limits::default()) {
        Ok(()) => Verdict {
            accepts: true,
            reason: None,
        },
        Err(e) => Verdict {
            accepts: false,
            reason: Some(short(&e.to_string())),
        },
    }
}

fn short(s: &str) -> String {
    s.chars().take(240).collect()
}

/// The network ID of a passphrase.
pub fn network_id(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase.as_bytes()).into()
}

fn xl() -> XLimits {
    XLimits {
        depth: Limits::default().depth,
        len: usize::MAX,
    }
}

/// Every envelope of the ledger's transaction set, in set order.
pub fn envelopes(lcm: &LedgerCloseMeta) -> Vec<&TransactionEnvelope> {
    fn gts(s: &GeneralizedTransactionSet) -> Vec<&TransactionEnvelope> {
        let GeneralizedTransactionSet::V1(v1) = s;
        let mut out = Vec::new();
        for p in v1.phases.iter() {
            match p {
                TransactionPhase::V0(comps) => {
                    for c in comps.iter() {
                        let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) = c;
                        out.extend(c.txs.iter());
                    }
                }
                TransactionPhase::V1(par) => {
                    for stage in par.execution_stages.iter() {
                        for cluster in stage.0.iter() {
                            out.extend(cluster.0.iter());
                        }
                    }
                }
            }
        }
        out
    }
    match lcm {
        LedgerCloseMeta::V0(v) => v.tx_set.txs.iter().collect(),
        LedgerCloseMeta::V1(v) => gts(&v.tx_set),
        LedgerCloseMeta::V2(v) => gts(&v.tx_set),
    }
}

/// The hashes an envelope is known by: its own, and for a fee bump its inner transaction's.
fn hashes(e: &TransactionEnvelope, nid: [u8; 32]) -> Vec<[u8; 32]> {
    let mut out = vec![e.hash(nid).unwrap_or([0; 32])];
    if let TransactionEnvelope::TxFeeBump(fb) = e {
        let stellar_xdr::FeeBumpTransactionInnerTx::Tx(inner) = &fb.tx.inner_tx;
        out.push(inner.tx.hash(nid).unwrap_or([0; 32]));
    }
    out
}

fn results_mut(lcm: &mut LedgerCloseMeta) -> Vec<&mut TransactionResultPair> {
    match lcm {
        LedgerCloseMeta::V0(v) => v.tx_processing.iter_mut().map(|t| &mut t.result).collect(),
        LedgerCloseMeta::V1(v) => v.tx_processing.iter_mut().map(|t| &mut t.result).collect(),
        LedgerCloseMeta::V2(v) => v.tx_processing.iter_mut().map(|t| &mut t.result).collect(),
    }
}

fn results(lcm: &LedgerCloseMeta) -> Vec<&TransactionResultPair> {
    match lcm {
        LedgerCloseMeta::V0(v) => v.tx_processing.iter().map(|t| &t.result).collect(),
        LedgerCloseMeta::V1(v) => v.tx_processing.iter().map(|t| &t.result).collect(),
        LedgerCloseMeta::V2(v) => v.tx_processing.iter().map(|t| &t.result).collect(),
    }
}

/// What resealing did.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reseal {
    pub tx_hashes_replaced: usize,
    pub tx_set_hash: bool,
    pub result_hash: bool,
    pub header_hash: bool,
}

/// Recompute the hashes a mutation of `lcm` (made from `orig`) invalidates: every transaction
/// result's hash (and a fee bump's inner hash) whose envelope changed, the header's transaction
/// set hash and result set hash, and the header hash. The SCP value signature cannot be redone
/// without the validator's key and is left as it was.
pub fn reseal(
    lcm: &mut LedgerCloseMeta,
    orig: &LedgerCloseMeta,
    passphrase: &str,
) -> Result<Reseal> {
    let nid = network_id(passphrase);
    let mut out = Reseal::default();
    let old: Vec<Vec<[u8; 32]>> = envelopes(orig).iter().map(|e| hashes(e, nid)).collect();
    let new: Vec<Vec<[u8; 32]>> = envelopes(lcm).iter().map(|e| hashes(e, nid)).collect();
    let mut map = std::collections::HashMap::new();
    if old.len() == new.len() {
        for (o, n) in old.iter().zip(&new) {
            for (a, b) in o.iter().zip(n) {
                if a != b {
                    map.insert(*a, *b);
                }
            }
        }
    }
    for r in results_mut(lcm) {
        if let Some(n) = map.get(&r.transaction_hash.0) {
            r.transaction_hash = Hash(*n);
            out.tx_hashes_replaced += 1;
        }
        match &mut r.result.result {
            TransactionResultResult::TxFeeBumpInnerSuccess(p)
            | TransactionResultResult::TxFeeBumpInnerFailed(p) => {
                if let Some(n) = map.get(&p.transaction_hash.0) {
                    p.transaction_hash = Hash(*n);
                    out.tx_hashes_replaced += 1;
                }
            }
            _ => {}
        }
    }
    let set_hash: [u8; 32] = match &*lcm {
        LedgerCloseMeta::V0(m) => {
            let mut h = Sha256::new();
            h.update(m.tx_set.previous_ledger_hash.0);
            for e in m.tx_set.txs.iter() {
                h.update(e.to_xdr(xl())?);
            }
            h.finalize().into()
        }
        LedgerCloseMeta::V1(m) => Sha256::digest(m.tx_set.to_xdr(xl())?).into(),
        LedgerCloseMeta::V2(m) => Sha256::digest(m.tx_set.to_xdr(xl())?).into(),
    };
    let set = TransactionResultSet {
        results: results(lcm)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow!("too many results"))?,
    };
    let result_hash: [u8; 32] = Sha256::digest(set.to_xdr(xl())?).into();
    macro_rules! header {
        ($v:expr) => {{
            let h = &mut $v.ledger_header.header;
            out.tx_set_hash = h.scp_value.tx_set_hash.0 != set_hash;
            h.scp_value.tx_set_hash = Hash(set_hash);
            out.result_hash = h.tx_set_result_hash.0 != result_hash;
            h.tx_set_result_hash = Hash(result_hash);
            let hh: [u8; 32] = Sha256::digest(h.to_xdr(xl())?).into();
            out.header_hash = $v.ledger_header.hash.0 != hh;
            $v.ledger_header.hash = Hash(hh);
        }};
    }
    match lcm {
        LedgerCloseMeta::V0(v) => header!(v),
        LedgerCloseMeta::V1(v) => header!(v),
        LedgerCloseMeta::V2(v) => header!(v),
    }
    Ok(out)
}

/// The SDK-visible hashes of a ledger, from the bytes alone: the hash of every envelope in apply
/// order (the order of the transaction processing list, matched through the result hashes the
/// unmutated ledger records), and the header hash.
pub fn ledger_hashes(
    lcm: &LedgerCloseMeta,
    orig: &LedgerCloseMeta,
    passphrase: &str,
) -> (Vec<String>, String) {
    let nid = network_id(passphrase);
    let orig_env: Vec<[u8; 32]> = envelopes(orig)
        .iter()
        .map(|e| e.hash(nid).unwrap_or([0; 32]))
        .collect();
    let new_env: Vec<[u8; 32]> = envelopes(lcm)
        .iter()
        .map(|e| e.hash(nid).unwrap_or([0; 32]))
        .collect();
    let mut out = Vec::new();
    for (i, r) in results(orig).iter().enumerate() {
        let pos = orig_env.iter().position(|h| *h == r.transaction_hash.0);
        let h = match pos.and_then(|p| new_env.get(p)) {
            Some(h) => *h,
            None => results(lcm)
                .get(i)
                .map(|r| r.transaction_hash.0)
                .unwrap_or([0; 32]),
        };
        out.push(hex::encode(h));
    }
    let header_hash = match lcm {
        LedgerCloseMeta::V0(v) => hex::encode(v.ledger_header.hash.0),
        LedgerCloseMeta::V1(v) => hex::encode(v.ledger_header.hash.0),
        LedgerCloseMeta::V2(v) => hex::encode(v.ledger_header.hash.0),
    };
    (out, header_hash)
}

/// Every change list of a ledger.
pub fn change_lists(lcm: &LedgerCloseMeta) -> Vec<&LedgerEntryChanges> {
    fn meta(m: &TransactionMeta) -> Vec<&LedgerEntryChanges> {
        match m {
            TransactionMeta::V0(ops) => ops.iter().map(|o| &o.changes).collect(),
            TransactionMeta::V1(m) => std::iter::once(&m.tx_changes)
                .chain(m.operations.iter().map(|o| &o.changes))
                .collect(),
            TransactionMeta::V2(m) => [&m.tx_changes_before, &m.tx_changes_after]
                .into_iter()
                .chain(m.operations.iter().map(|o| &o.changes))
                .collect(),
            TransactionMeta::V3(m) => [&m.tx_changes_before, &m.tx_changes_after]
                .into_iter()
                .chain(m.operations.iter().map(|o| &o.changes))
                .collect(),
            TransactionMeta::V4(m) => [&m.tx_changes_before, &m.tx_changes_after]
                .into_iter()
                .chain(m.operations.iter().map(|o| &o.changes))
                .collect(),
        }
    }
    let mut out = Vec::new();
    match lcm {
        LedgerCloseMeta::V0(v) => {
            for t in v.tx_processing.iter() {
                out.push(&t.fee_processing);
                out.extend(meta(&t.tx_apply_processing));
            }
            out.extend(v.upgrades_processing.iter().map(|u| &u.changes));
        }
        LedgerCloseMeta::V1(v) => {
            for t in v.tx_processing.iter() {
                out.push(&t.fee_processing);
                out.extend(meta(&t.tx_apply_processing));
            }
            out.extend(v.upgrades_processing.iter().map(|u| &u.changes));
        }
        LedgerCloseMeta::V2(v) => {
            for t in v.tx_processing.iter() {
                out.push(&t.fee_processing);
                out.extend(meta(&t.tx_apply_processing));
                out.push(&t.post_tx_apply_fee_processing);
            }
            out.extend(v.upgrades_processing.iter().map(|u| &u.changes));
        }
    }
    out
}

/// The cross-structure rule a ledger breaks, if any: stellar-core emits a transaction set holding
/// the envelope of every processed transaction, and an operation result for every operation of a
/// transaction that ran. A valid-preserving mutation can break either while every part stays valid
/// XDR; a reader may then refuse the ledger, and its facts have no single right answer.
pub fn consistency(lcm: &LedgerCloseMeta, passphrase: &str) -> Option<&'static str> {
    for list in change_lists(lcm) {
        for (i, c) in list.iter().enumerate() {
            if matches!(
                c,
                LedgerEntryChange::Updated(_) | LedgerEntryChange::Removed(_)
            ) {
                let before = i.checked_sub(1).map(|j| &list[j]);
                let paired = before.is_some_and(|b| {
                    matches!(
                        b,
                        LedgerEntryChange::State(_) | LedgerEntryChange::Restored(_)
                    ) && xdrcheck_meta::normalise::change_key(b) == xdrcheck_meta::normalise::change_key(c)
                });
                if !paired {
                    return Some("an updated or removed entry no longer follows its own state");
                }
            }
        }
    }
    let nid = network_id(passphrase);
    let envs = envelopes(lcm);
    let res = results(lcm);
    if envs.len() != res.len() {
        return Some("the transaction set and the processing list no longer match");
    }
    let by_hash: std::collections::HashMap<[u8; 32], &TransactionEnvelope> = envs
        .iter()
        .map(|e| (e.hash(nid).unwrap_or([0; 32]), *e))
        .collect();
    for r in res {
        let Some(env) = by_hash.get(&r.transaction_hash.0) else {
            return Some("a processed transaction's envelope is not in the transaction set");
        };
        let ops = match env {
            TransactionEnvelope::TxV0(e) => e.tx.operations.len(),
            TransactionEnvelope::Tx(e) => e.tx.operations.len(),
            TransactionEnvelope::TxFeeBump(e) => {
                let stellar_xdr::FeeBumpTransactionInnerTx::Tx(i) = &e.tx.inner_tx;
                i.tx.operations.len()
            }
        };
        let got = match &r.result.result {
            TransactionResultResult::TxSuccess(o) | TransactionResultResult::TxFailed(o) => {
                Some(o.len())
            }
            TransactionResultResult::TxFeeBumpInnerSuccess(p)
            | TransactionResultResult::TxFeeBumpInnerFailed(p) => match &p.result.result {
                stellar_xdr::InnerTransactionResultResult::TxSuccess(o)
                | stellar_xdr::InnerTransactionResultResult::TxFailed(o) => Some(o.len()),
                _ => None,
            },
            _ => None,
        };
        if got.is_some_and(|n| n != ops) {
            return Some("an operation result list no longer matches its transaction's operations");
        }
    }
    None
}

/// Decode a ledger with the oracle's limits and the corpus gate.
pub fn decode_ledger(bytes: &[u8], gate: &Gate) -> Result<LedgerCloseMeta> {
    Ok(xdrcheck_xdr::decode_ledger(bytes, &Limits::default(), gate)?)
}

/// Encode a ledger.
pub fn encode_ledger(lcm: LedgerCloseMeta) -> Result<Vec<u8>> {
    Ok(xdrcheck_xdr::encode(
        &stellar_xdr::Type::LedgerCloseMeta(Box::new(lcm)),
        &Limits::default(),
    )?)
}

/// The reference extractor's facts for a ledger, as JSON (the whole extraction, apply order).
pub fn facts(lcm: &LedgerCloseMeta, passphrase: &str) -> Result<Value> {
    let ext = xdrcheck_meta::extract::extract(lcm, passphrase).map_err(|e| anyhow!("{e}"))?;
    Ok(serde_json::to_value(&ext)?)
}

/// The reference extractor's facts in the manifest's `expect` vocabulary, for the focus
/// transaction.
pub fn expect_facts(lcm: &LedgerCloseMeta, passphrase: &str, focus: usize) -> Result<Value> {
    let ext = xdrcheck_meta::extract::extract(lcm, passphrase).map_err(|e| anyhow!("{e}"))?;
    Ok(ext.expect_json(focus)["expect"].clone())
}
