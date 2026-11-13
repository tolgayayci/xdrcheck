//! Conservation check of the reference extractor: for every holder and asset a transaction's
//! operations touched, the net of the expected movements must equal the holder's balance delta in
//! the operations' entry changes.
//!
//! Balances are read from the entries that hold them: an account's native balance, a trustline's
//! balance (pool-share trustlines are not token balances and are left out), a claimable balance's
//! amount (holder `B…`), a constant-product pool's two reserves (holder `L…`), and a Stellar Asset
//! Contract's `Balance` contract-data entry (holder `C…` or `G…`, asset the contract). A movement
//! of a classic asset to or from a contract counts against that asset's SAC balance entry. The fee
//! and fee refund are not operation effects and are left out on both sides.
//!
//! Checked is every holder-asset pair the movements name or whose balance changed. Not checked are a
//! pair whose asset the extractor flagged `balance_delta_ambiguous` in that transaction (it states it
//! cannot produce those movements), a movement leg it cannot place (a contract asset held by an
//! account), and a custom token (a contract asset with no SAC-shaped balance entry), whose storage
//! layout is the contract's own.

use std::collections::{BTreeMap, BTreeSet};

use stellar_xdr::{
    ContractDataDurability, LedgerCloseMeta, LedgerEntry, LedgerEntryChanges, LedgerEntryData,
    LiquidityPoolEntryBody, ScAddress, ScVal, TrustLineAsset,
};

use super::{
    account_strkey, asset_string, cb_strkey, contract_strkey, i128_of, meta_parts, network_id,
    parse_asset, pool_strkey, sac_contract_id, sym, transitions, tx_views, Extraction, Transition,
};

/// One violation: transaction, holder, asset, the net of the movements and the balance delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub tx_index: usize,
    pub holder: String,
    pub asset: String,
    pub movements: i128,
    pub delta: i128,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tx {}: {} {}: movements net {}, balance delta {}",
            self.tx_index, self.holder, self.asset, self.movements, self.delta
        )
    }
}

/// The balances one entry holds, as (holder, asset key, amount). The asset key is the classic asset
/// string for accounts, trustlines, claimable balances and pools, and the contract strkey for a
/// contract-data balance.
fn balances(e: &LedgerEntry) -> Vec<(String, String, i128)> {
    match &e.data {
        LedgerEntryData::Account(a) => vec![(
            account_strkey(&a.account_id),
            "native".into(),
            a.balance.into(),
        )],
        LedgerEntryData::Trustline(t) => match &t.asset {
            TrustLineAsset::PoolShare(_) => vec![],
            _ => vec![(
                account_strkey(&t.account_id),
                super::trustline_asset_string(&t.asset),
                t.balance.into(),
            )],
        },
        LedgerEntryData::ClaimableBalance(c) => vec![(
            cb_strkey(&c.balance_id),
            asset_string(&c.asset),
            c.amount.into(),
        )],
        LedgerEntryData::LiquidityPool(p) => {
            let LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) = &p.body;
            let holder = pool_strkey(&p.liquidity_pool_id);
            vec![
                (
                    holder.clone(),
                    asset_string(&cp.params.asset_a),
                    cp.reserve_a.into(),
                ),
                (
                    holder,
                    asset_string(&cp.params.asset_b),
                    cp.reserve_b.into(),
                ),
            ]
        }
        LedgerEntryData::ContractData(d) if d.durability == ContractDataDurability::Persistent => {
            // A SAC balance: key [Symbol("Balance"), Address(holder)], value {amount, authorized, clawback}.
            let ScVal::Vec(Some(key)) = &d.key else {
                return vec![];
            };
            if key.len() != 2 || sym(&key[0]) != Some("Balance") {
                return vec![];
            }
            let ScVal::Address(holder) = &key[1] else {
                return vec![];
            };
            let ScVal::Map(Some(m)) = &d.val else {
                return vec![];
            };
            let Some(amount) = m
                .iter()
                .find(|e| sym(&e.key) == Some("amount"))
                .and_then(|e| i128_of(&e.val))
            else {
                return vec![];
            };
            let ScAddress::Contract(c) = &d.contract else {
                return vec![];
            };
            vec![(super::base_address(holder), contract_strkey(c.0 .0), amount)]
        }
        _ => vec![],
    }
}

/// Balance deltas of a list of change lists, per (holder, asset key).
fn deltas(lists: &[&LedgerEntryChanges]) -> BTreeMap<(String, String), i128> {
    let mut out: BTreeMap<(String, String), i128> = BTreeMap::new();
    let mut add = |e: &LedgerEntry, sign: i128| {
        for (h, a, n) in balances(e) {
            *out.entry((h, a)).or_default() += sign * n;
        }
    };
    for list in lists {
        for t in transitions(list) {
            match t {
                Transition::Created(e) => add(e, 1),
                Transition::Updated(Some(pre), post) => {
                    add(pre, -1);
                    add(post, 1);
                }
                Transition::Removed(Some(pre), _) => add(pre, -1),
                Transition::Updated(None, _)
                | Transition::Removed(None, _)
                | Transition::Restored(_) => {}
            }
        }
    }
    out.retain(|_, v| *v != 0);
    out
}

/// The conservation check over one extraction of `lcm`. Returns every violation.
pub fn check(lcm: &LedgerCloseMeta, passphrase: &str, ext: &Extraction) -> Vec<Violation> {
    let nid = network_id(passphrase);
    // A classic asset's SAC strkey, for movements to or from a contract.
    let sac = |asset: &str| parse_asset(asset).map(|a| contract_strkey(sac_contract_id(&a, nid)));
    let views = tx_views(lcm);
    let mut out = Vec::new();
    for tx in &ext.txs {
        let Some(view) = views.get(tx.index) else {
            continue;
        };
        let parts = meta_parts(view.meta);
        let delta = deltas(&parts.ops);
        let ambiguous: BTreeSet<String> = tx
            .flags
            .iter()
            .filter(|f| f.kind == "balance_delta_ambiguous")
            .filter_map(|f| f.detail.split_once(": ").map(|(a, _)| a.to_string()))
            .collect();
        // The asset key a movement's asset has for a holder: a contract holder of a classic asset
        // holds it in the SAC's balance entry.
        let key_for = |holder: &str, asset: &str| -> Option<String> {
            if holder.starts_with('C') {
                if asset.starts_with('C') {
                    return Some(asset.to_string());
                }
                return sac(asset);
            }
            if asset.starts_with('C') {
                // A token contract's own asset held by an account: a SAC keeps it in the account's
                // trustline (not modelled here); a custom token in its own storage.
                return None;
            }
            Some(asset.to_string())
        };
        let mut net: BTreeMap<(String, String), i128> = BTreeMap::new();
        let mut skip: BTreeSet<(String, String)> = BTreeSet::new();
        for m in &tx.movements {
            if matches!(m.kind, "fee" | "fee_refund") {
                continue;
            }
            let Ok(amount) = m.amount.parse::<i128>() else {
                continue;
            };
            let mut leg = |who: &Option<super::AccountRef>, sign: i128| {
                if let Some(r) = who {
                    match key_for(&r.address, &m.asset) {
                        Some(k) => *net.entry((r.address.clone(), k)).or_default() += sign * amount,
                        None => {
                            skip.insert((r.address.clone(), m.asset.clone()));
                        }
                    }
                }
            };
            match m.kind {
                "transfer" => {
                    leg(&m.from, -1);
                    leg(&m.to, 1);
                }
                "mint" => leg(&m.to, 1),
                "burn" | "clawback" => leg(&m.from, -1),
                _ => {}
            }
        }
        // Contracts whose balances appear in SAC-shaped entries; another contract asset is a custom
        // token with a storage layout of its own.
        let sac_shaped: BTreeSet<String> = delta
            .keys()
            .map(|(_, a)| a.clone())
            .filter(|a| a.starts_with('C'))
            .collect();
        let mut keys: BTreeSet<(String, String)> = net.keys().cloned().collect();
        keys.extend(delta.keys().cloned());
        for k in keys {
            let (holder, asset) = &k;
            if ambiguous.contains(asset) || skip.contains(&k) {
                continue;
            }
            if asset.starts_with('C') && !sac_shaped.contains(asset) {
                continue;
            }
            let (m, d) = (
                net.get(&k).copied().unwrap_or(0),
                delta.get(&k).copied().unwrap_or(0),
            );
            if m != d {
                out.push(Violation {
                    tx_index: tx.index,
                    holder: holder.clone(),
                    asset: asset.clone(),
                    movements: m,
                    delta: d,
                });
            }
        }
    }
    out
}
