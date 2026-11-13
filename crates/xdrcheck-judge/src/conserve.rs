//! Conservation self-check over one ledger's facts.
//!
//! Per transaction:
//! - fee scope: the native deltas of the non-operation parts (`fee`, `before`, `after`, `refund`)
//!   sum to `-fee_charged`; with transaction-level fee events (meta v4) these also sum to
//!   `fee_charged`.
//! - operation scope: per asset, the deltas of the `op:*` and `reconcile:*` parts sum to zero,
//!   unless the difference is explained: by verified SAC events (mint, burn, clawback, transfers
//!   from or to the issuer), by an inflation operation, by a pre-protocol-8 repeated account merge,
//!   or (meta below v4, which carries no classic events) by the issuer taking part in the
//!   transaction. Whatever is left is a residual with a class: a judge bug or a lead.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::facts::Fact;
use crate::read::asset_issuer;

#[derive(Serialize, Clone, Debug)]
pub struct Residual {
    pub ledger: u32,
    pub tx_index: u32,
    pub tx_hash: String,
    pub asset: String,
    pub scope: &'static str,
    pub sum: String,
    pub expected: String,
    pub class: String,
}

#[derive(Default, Debug, Clone, Serialize)]
pub struct Tally {
    pub ledgers: u64,
    pub txs: u64,
    pub pairs_checked: u64,
    pub explained: BTreeMap<String, u64>,
    pub residual: BTreeMap<String, u64>,
    pub unknown: BTreeMap<String, u64>,
    pub lcm_versions: BTreeMap<u32, u64>,
    pub meta_versions: BTreeMap<u32, u64>,
    pub protocols: BTreeMap<u32, u64>,
}

impl Tally {
    pub fn merge(&mut self, o: &Tally) {
        self.ledgers += o.ledgers;
        self.txs += o.txs;
        self.pairs_checked += o.pairs_checked;
        for (a, b) in [
            (&mut self.explained, &o.explained),
            (&mut self.residual, &o.residual),
            (&mut self.unknown, &o.unknown),
        ] {
            for (k, v) in b {
                *a.entry(k.clone()).or_default() += v;
            }
        }
        for (a, b) in [
            (&mut self.lcm_versions, &o.lcm_versions),
            (&mut self.meta_versions, &o.meta_versions),
            (&mut self.protocols, &o.protocols),
        ] {
            for (k, v) in b {
                *a.entry(*k).or_default() += v;
            }
        }
    }
}

fn p(s: &str) -> i128 {
    s.parse().unwrap_or(0)
}

/// Check one ledger's facts. Returns the residuals and adds to `tally`.
pub fn check(facts: &[Fact], tally: &mut Tally) -> Vec<Residual> {
    let mut out = Vec::new();
    let mut protocol = 0;
    // Per-tx gathered views.
    struct T<'a> {
        tx: Option<&'a crate::facts::TxFact>,
        bal: Vec<&'a crate::facts::BalanceFact>,
        ev: Vec<&'a crate::facts::EventFact>,
        parts: BTreeSet<&'a str>,
        incomplete: bool,
    }
    let mut txs: BTreeMap<u32, T<'_>> = BTreeMap::new();
    let slot = |i: u32, txs: &mut BTreeMap<u32, T<'_>>| {
        txs.entry(i).or_insert_with(|| T {
            tx: None,
            bal: vec![],
            ev: vec![],
            parts: BTreeSet::new(),
            incomplete: false,
        });
    };
    for f in facts {
        match f {
            Fact::Ledger(l) => {
                tally.ledgers += 1;
                protocol = l.protocol;
                *tally.lcm_versions.entry(l.lcm_version).or_default() += 1;
                *tally.protocols.entry(l.protocol).or_default() += 1;
            }
            Fact::Tx(t) => {
                slot(t.tx_index, &mut txs);
                txs.get_mut(&t.tx_index).unwrap().tx = Some(t);
                tally.txs += 1;
                *tally.meta_versions.entry(t.meta_version).or_default() += 1;
            }
            Fact::BalanceChange(b) => {
                if let Some(i) = b.tx_index {
                    slot(i, &mut txs);
                    let e = txs.get_mut(&i).unwrap();
                    e.bal.push(b);
                    if !b.complete {
                        e.incomplete = true;
                    }
                }
            }
            Fact::TokenEvent(e) => {
                slot(e.tx_index, &mut txs);
                txs.get_mut(&e.tx_index).unwrap().ev.push(e);
            }
            Fact::Participant(pf) => {
                slot(pf.tx_index, &mut txs);
                txs.get_mut(&pf.tx_index).unwrap().parts.insert(&pf.address);
            }
            Fact::Unknown(u) => {
                *tally.unknown.entry(u.class.clone()).or_default() += 1;
            }
            _ => {}
        }
    }
    for (i, t) in &txs {
        let Some(tx) = t.tx else { continue };
        let mut res = |asset: &str, scope: &'static str, sum: i128, exp: i128, class: String| {
            out.push(Residual {
                ledger: tx.ledger,
                tx_index: *i,
                tx_hash: tx.tx_hash.clone(),
                asset: asset.to_string(),
                scope,
                sum: sum.to_string(),
                expected: exp.to_string(),
                class,
            });
        };
        if t.incomplete {
            *tally
                .residual
                .entry("skipped:incomplete_truth".into())
                .or_default() += 1;
            continue;
        }
        // Fee scope.
        let mut fee_sum: i128 = 0;
        let mut op_sum: BTreeMap<&str, i128> = BTreeMap::new();
        for b in &t.bal {
            for (k, v) in &b.parts {
                let v = p(v);
                if k.starts_with("op:") || k.starts_with("reconcile:") {
                    *op_sum.entry(&b.asset).or_default() += v;
                } else if b.asset == "native" {
                    fee_sum += v;
                } else {
                    res(&b.asset, "fee", v, 0, format!("fee:non_native_part:{k}"));
                }
            }
        }
        tally.pairs_checked += 1;
        let fee_events: Vec<_> = t.ev.iter().filter(|e| e.event == "fee" && e.sac).collect();
        let ev_fee: i128 = fee_events
            .iter()
            .map(|e| e.amount.as_deref().map(p).unwrap_or(0))
            .sum();
        let charged = i128::from(tx.fee_charged);
        if fee_sum != -charged {
            // Before protocol 21 a fee-bump result's `feeCharged` does not reflect the Soroban
            // refund (stellar-core `FeeBumpMutableTransactionResult::finalizeFeeRefund`); the
            // ledger and the fee events agree with each other.
            if protocol == 20
                && tx.result_code.starts_with("TxFeeBump")
                && !fee_events.is_empty()
                && fee_sum == -ev_fee
            {
                *tally
                    .explained
                    .entry("explained:p20_feebump_fee_charged_excludes_refund".into())
                    .or_default() += 1;
            } else {
                let c = format!("fee:mismatch:meta_v{}", tx.meta_version);
                *tally.residual.entry(c.clone()).or_default() += 1;
                res("native", "fee", fee_sum, -charged, c);
            }
        } else if !fee_events.is_empty() && ev_fee != charged {
            let c = "fee:event_mismatch".to_string();
            *tally.residual.entry(c.clone()).or_default() += 1;
            res("native", "fee", ev_fee, charged, c);
        }
        // Operation scope.
        let mut explained_by_events: BTreeMap<&str, i128> = BTreeMap::new();
        let mut has_events: BTreeSet<&str> = BTreeSet::new();
        for e in &t.ev {
            if !e.sac || e.event == "fee" || e.phase != "op" {
                continue;
            }
            let Some(asset) = e.asset.as_deref() else {
                continue;
            };
            let n = e.amount.as_deref().map(p).unwrap_or(0);
            let issuer = asset_issuer(asset);
            let d = match e.event.as_str() {
                "mint" => n,
                "burn" | "clawback" => -n,
                "transfer" => {
                    let mut d = 0;
                    if issuer.is_some() && e.from.as_deref() == issuer {
                        d += n;
                    }
                    if issuer.is_some() && e.to.as_deref() == issuer {
                        d -= n;
                    }
                    d
                }
                _ => 0,
            };
            if matches!(e.event.as_str(), "mint" | "burn" | "clawback" | "transfer") {
                has_events.insert(asset);
            }
            *explained_by_events.entry(asset).or_default() += d;
        }
        let mut assets: BTreeSet<&str> = op_sum.keys().copied().collect();
        assets.extend(explained_by_events.keys().copied());
        for asset in assets {
            let r = op_sum.get(asset).copied().unwrap_or(0);
            let ev = explained_by_events.get(asset).copied().unwrap_or(0);
            if r == 0 && ev == 0 {
                continue;
            }
            let issuer = asset_issuer(asset);
            let ops = &tx.op_types;
            let class: Option<String> = if r == ev && has_events.contains(asset) {
                Some("explained:sac_events".into())
            } else if asset == "native" && r > 0 && ops.iter().any(|o| o == "Inflation") && ev == 0
            {
                Some("explained:inflation".into())
            } else if asset == "native"
                && r > 0
                && protocol < 8
                && ops.iter().filter(|o| *o == "AccountMerge").count() >= 2
            {
                Some("explained:pre_p8_double_merge".into())
            } else if tx.meta_version < 4 && issuer.is_some_and(|i| t.parts.contains(i)) && ev == 0
            {
                Some("explained:issuer_party".into())
            } else {
                None
            };
            match class {
                Some(c) => *tally.explained.entry(c).or_default() += 1,
                None => {
                    let kind = if asset == "native" {
                        "native"
                    } else {
                        "credit"
                    };
                    let c = format!(
                        "op:unexplained:{kind}:meta_v{}:{}{}",
                        tx.meta_version,
                        if tx.success { "ok" } else { "failed" },
                        if ev != 0 { ":events_differ" } else { "" }
                    );
                    *tally.residual.entry(c.clone()).or_default() += 1;
                    res(asset, "op", r, ev, c);
                }
            }
        }
    }
    out
}
