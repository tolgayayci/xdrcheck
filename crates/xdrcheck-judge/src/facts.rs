//! Ground truth of one ledger, from its own entry changes.
//!
//! Every fact is computed from the `LedgerCloseMeta` alone (plus an optional registry of known
//! Stellar Asset Contracts). Where the meta does not determine a value (an updated or removed
//! balance-bearing entry with no prior state anywhere in the ledger), the judge says so with an
//! `unknown` fact and marks the balance fact incomplete; it never reads such a gap as zero.

#![allow(clippy::type_complexity)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use stellar_xdr::{
    Asset, ContractDataDurability, ContractDataEntry, ContractEvent, LedgerCloseMeta, LedgerEntry,
    LedgerEntryChange, LedgerEntryChanges, LedgerEntryData, LedgerEntryExt, LedgerKey,
    LiquidityPoolEntryBody, OperationBody, ScAddress, ScVal, TransactionEventStage,
    TransactionResultResult,
};

use crate::read::{self, *};

/// One JSONL fact. Field order is fixed by the struct definitions, so output is deterministic.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Fact {
    Ledger(LedgerFact),
    Sac(SacFact),
    Tx(TxFact),
    BalanceChange(BalanceFact),
    NonsacBalance(NonsacBalanceFact),
    Participant(ParticipantFact),
    EntryChange(EntryFact),
    EntryField(EntryFieldFact),
    TokenEvent(EventFact),
    /// A token-named event (transfer, mint, burn, clawback, approve, fee) whose data carries no i128 amount:
    /// not a token movement.
    EventWithoutAmount(EventFact),
    Unknown(UnknownFact),
}

impl Fact {
    pub fn ledger(&self) -> u32 {
        match self {
            Fact::Ledger(f) => f.ledger,
            Fact::Sac(f) => f.ledger,
            Fact::Tx(f) => f.ledger,
            Fact::BalanceChange(f) => f.ledger,
            Fact::NonsacBalance(f) => f.ledger,
            Fact::Participant(f) => f.ledger,
            Fact::EntryChange(f) => f.ledger,
            Fact::EntryField(f) => f.ledger,
            Fact::TokenEvent(f) => f.ledger,
            Fact::EventWithoutAmount(f) => f.ledger,
            Fact::Unknown(f) => f.ledger,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LedgerFact {
    pub ledger: u32,
    pub hash: String,
    pub protocol: u32,
    pub close_time: u64,
    pub lcm_version: u32,
    pub tx_count: u32,
    pub failed_count: u32,
    pub upgrade_changes: u32,
    pub evicted: u32,
}

/// A contract the judge verified as the Stellar Asset Contract of `asset` (its id is the hash of
/// the asset under the network passphrase).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SacFact {
    pub ledger: u32,
    pub contract: String,
    pub asset: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TxFact {
    pub ledger: u32,
    pub tx_index: u32,
    pub tx_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inner_hash: Option<String>,
    pub success: bool,
    pub result_code: String,
    pub op_codes: Vec<String>,
    pub op_types: Vec<String>,
    pub fee_charged: i64,
    pub meta_version: u32,
}

/// Net balance change of one holder in one asset over one transaction (or a ledger-level change
/// when `tx_index` is absent). `asset` is `native` or `CODE:ISSUER`; a classic asset held by a
/// contract through its SAC uses the same asset string. `parts` splits the net by where it came
/// from: `fee`, `before`, `op:<i>`, `after`, `refund`, `reconcile:<i>` (P23 SAC reconciliation of a
/// restored hot-archive entry), `upgrade`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BalanceFact {
    pub ledger: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    pub holder: String,
    pub asset: String,
    /// The asset's SAC contract id.
    pub contract: String,
    pub amount: String,
    pub parts: BTreeMap<String, String>,
    pub via: Vec<String>,
    pub complete: bool,
}

/// A balance-shaped contract-data entry (`[Balance, address]`) of a contract that is not a
/// verified SAC: a custom token's own storage. Never counted as a balance.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NonsacBalanceFact {
    pub ledger: u32,
    pub tx_index: u32,
    pub tx_hash: String,
    pub contract: String,
    pub holder: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ParticipantFact {
    pub ledger: u32,
    pub tx_index: u32,
    pub tx_hash: String,
    pub address: String,
    pub muxed_ids: Vec<String>,
    pub roles: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EntryFact {
    pub ledger: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_index: Option<u32>,
    pub phase: String,
    pub change: String,
    pub entry_type: String,
    pub key: String,
    /// The entry by name (`account:G…`, `trustline:G…:CODE:ISSUER`, …; see `read::key_subject`).
    pub subject: String,
    /// For a trustline of a classic asset: the asset's SAC id, so rows naming the asset by contract match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_contract: Option<String>,
}

/// One attribute of an account, trustline or data entry that an operation (or phase) changed, from the
/// entry's state before to after. Fields: `signer:<hex>` (weight; the master key is the account's own
/// ed25519 signer, its weight the master weight; hex = `read::signer_hex`), `threshold:low|med|high`, `flags`,
/// `home_domain` (hex) for accounts; `limit`, `flags` for trustlines; `value` (hex) for data entries. `old` is
/// absent for a value that did not exist (a new entry, a new signer), `new` for one that no longer does.
/// A created entry lists its non-default values; a removed entry lists none (the removal says it all).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EntryFieldFact {
    pub ledger: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_index: Option<u32>,
    pub phase: String,
    pub entry_type: String,
    pub subject: String,
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EventFact {
    pub ledger: u32,
    pub tx_index: u32,
    pub tx_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_index: Option<u32>,
    pub phase: String,
    pub event_index: u32,
    pub contract: String,
    pub sac: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_muxed_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    pub topics: Vec<String>,
    pub data: String,
    pub reconciliation: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UnknownFact {
    pub ledger: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_index: Option<u32>,
    pub class: String,
    pub detail: String,
}

/// Judge configuration.
#[derive(Clone, Debug)]
pub struct Options {
    pub network_id: [u8; 32],
    /// Extra SAC candidates: asset strings (each is verified by hashing).
    pub sac_registry: Vec<String>,
}

impl Options {
    pub fn mainnet() -> Self {
        Self::new(read::MAINNET)
    }
    pub fn new(passphrase: &str) -> Self {
        Options {
            network_id: network_id(passphrase),
            sac_registry: Vec::new(),
        }
    }
}

/// Token-like event names.
const TOKEN_EVENTS: [&str; 6] = ["transfer", "mint", "burn", "clawback", "approve", "fee"];

/// SAC ids known in one ledger: contract id → asset string.
struct Sacs {
    nid: [u8; 32],
    map: HashMap<[u8; 32], String>,
    seen_assets: BTreeSet<String>,
    used: BTreeMap<String, String>,
}

impl Sacs {
    fn add_asset(&mut self, a: &Asset) {
        let s = asset_string(a);
        if self.seen_assets.insert(s.clone()) {
            self.map.insert(sac_contract_id(a, self.nid), s);
        }
    }
    fn add_str(&mut self, s: &str) {
        if self.seen_assets.contains(s) {
            return;
        }
        if let Some(a) = parse_asset(s) {
            self.add_asset(&a);
        }
    }
    fn get(&mut self, id: &[u8; 32]) -> Option<String> {
        let a = self.map.get(id)?.clone();
        self.used.insert(contract_strkey(id), a.clone());
        Some(a)
    }
}

fn collect_assets_from_entry(e: &LedgerEntry, s: &mut Sacs) {
    match &e.data {
        LedgerEntryData::Trustline(t) => {
            if let Some(a) = trustline_asset(&t.asset) {
                s.add_asset(&a)
            }
        }
        LedgerEntryData::ClaimableBalance(c) => s.add_asset(&c.asset),
        LedgerEntryData::LiquidityPool(p) => {
            let LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) = &p.body;
            s.add_asset(&cp.params.asset_a);
            s.add_asset(&cp.params.asset_b);
        }
        _ => {}
    }
}

fn collect_assets(list: &LedgerEntryChanges, s: &mut Sacs) {
    for c in list.0.iter() {
        match c {
            LedgerEntryChange::State(e)
            | LedgerEntryChange::Created(e)
            | LedgerEntryChange::Updated(e)
            | LedgerEntryChange::Restored(e) => collect_assets_from_entry(e, s),
            LedgerEntryChange::Removed(LedgerKey::Trustline(k)) => {
                if let Some(a) = trustline_asset(&k.asset) {
                    s.add_asset(&a)
                }
            }
            LedgerEntryChange::Removed(_) => {}
        }
    }
}

fn collect_event_assets(e: &ContractEvent, s: &mut Sacs) {
    let (topics, _) = event_topics(e);
    for t in topics {
        if let ScVal::String(st) = t {
            if let Ok(st) = std::str::from_utf8(st.0.as_slice()) {
                s.add_str(st);
            }
        }
    }
}

/// The `[Balance, address]` key shape.
fn balance_key(d: &ContractDataEntry) -> Option<&ScAddress> {
    if d.durability != ContractDataDurability::Persistent {
        return None;
    }
    let ScVal::Vec(Some(key)) = &d.key else {
        return None;
    };
    if key.len() != 2 || sym(&key[0]) != Some("Balance") {
        return None;
    }
    match &key[1] {
        ScVal::Address(a) => Some(a),
        _ => None,
    }
}

fn balance_amount(v: &ScVal) -> Option<i128> {
    match v {
        ScVal::Map(Some(m)) => m
            .iter()
            .find(|e| sym(&e.key) == Some("amount"))
            .and_then(|e| i128_of(&e.val)),
        other => i128_of(other),
    }
}

/// A balance an entry holds.
enum Held {
    /// A token balance: holder, asset string, amount, kind of entry.
    Bal(String, String, i128, &'static str),
    /// A balance-shaped entry of an unverified contract: contract, holder, amount.
    Nonsac(String, String, Option<i128>),
    /// A SAC balance entry whose value does not parse.
    Unparsed(String, String),
}

fn held(e: &LedgerEntry, sacs: &mut Sacs) -> Vec<Held> {
    match &e.data {
        LedgerEntryData::Account(a) => vec![Held::Bal(
            account_strkey(&a.account_id),
            "native".into(),
            a.balance.into(),
            "account",
        )],
        LedgerEntryData::Trustline(t) => match trustline_asset(&t.asset) {
            Some(asset) => vec![Held::Bal(
                account_strkey(&t.account_id),
                asset_string(&asset),
                t.balance.into(),
                "trustline",
            )],
            None => vec![],
        },
        LedgerEntryData::ClaimableBalance(c) => vec![Held::Bal(
            cb_strkey(&c.balance_id),
            asset_string(&c.asset),
            c.amount.into(),
            "claimable_balance",
        )],
        LedgerEntryData::LiquidityPool(p) => {
            let LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) = &p.body;
            let h = pool_strkey(&p.liquidity_pool_id);
            vec![
                Held::Bal(
                    h.clone(),
                    asset_string(&cp.params.asset_a),
                    cp.reserve_a.into(),
                    "liquidity_pool",
                ),
                Held::Bal(
                    h,
                    asset_string(&cp.params.asset_b),
                    cp.reserve_b.into(),
                    "liquidity_pool",
                ),
            ]
        }
        LedgerEntryData::ContractData(d) => {
            let Some(holder) = balance_key(d) else {
                return vec![];
            };
            let holder = sc_address(holder).0;
            let ScAddress::Contract(cid) = &d.contract else {
                return vec![];
            };
            let id = cid.0 .0;
            match sacs.get(&id) {
                Some(asset) => match &d.val {
                    ScVal::Map(_) => match balance_amount(&d.val) {
                        Some(n) => vec![Held::Bal(holder, asset, n, "sac_balance")],
                        None => vec![Held::Unparsed(contract_strkey(&id), holder)],
                    },
                    _ => vec![Held::Unparsed(contract_strkey(&id), holder)],
                },
                None => vec![Held::Nonsac(
                    contract_strkey(&id),
                    holder,
                    balance_amount(&d.val),
                )],
            }
        }
        _ => vec![],
    }
}

fn balance_bearing(k: &LedgerKey) -> bool {
    match k {
        LedgerKey::Account(_)
        | LedgerKey::Trustline(_)
        | LedgerKey::ClaimableBalance(_)
        | LedgerKey::LiquidityPool(_) => true,
        LedgerKey::ContractData(d) => {
            matches!(&d.key, ScVal::Vec(Some(v)) if v.len() == 2 && sym(&v[0]) == Some("Balance"))
        }
        _ => false,
    }
}

/// The address that owns an entry (by its key).
fn key_owner(k: &LedgerKey) -> Option<String> {
    match k {
        LedgerKey::Account(a) => Some(account_strkey(&a.account_id)),
        LedgerKey::Trustline(t) => Some(account_strkey(&t.account_id)),
        LedgerKey::Offer(o) => Some(account_strkey(&o.seller_id)),
        LedgerKey::Data(d) => Some(account_strkey(&d.account_id)),
        LedgerKey::ClaimableBalance(c) => Some(cb_strkey(&c.balance_id)),
        LedgerKey::LiquidityPool(p) => Some(pool_strkey(&p.liquidity_pool_id)),
        LedgerKey::ContractData(d) => Some(sc_address(&d.contract).0),
        _ => None,
    }
}

/// Per-transaction accumulator.
#[derive(Default)]
struct TxAcc {
    /// (holder, asset) → part → amount; and the entry kinds it came from.
    bal: BTreeMap<(String, String), (BTreeMap<String, i128>, BTreeSet<&'static str>)>,
    incomplete: BTreeSet<(String, String)>,
    nonsac: BTreeMap<(String, String), Option<i128>>,
    entries: Vec<EntryFact>,
    fields: Vec<EntryFieldFact>,
    unknown: Vec<UnknownFact>,
    participants: BTreeMap<String, (BTreeSet<u64>, BTreeSet<&'static str>)>,
    /// Restored verified-SAC balances per op: (contract strkey, holder) multiset.
    restored_sac: BTreeMap<usize, Vec<(String, String, String)>>,
}

impl TxAcc {
    fn part(&mut self, holder: &str, asset: &str, part: &str, n: i128, via: &'static str) -> bool {
        let e = self
            .bal
            .entry((holder.to_string(), asset.to_string()))
            .or_default();
        e.1.insert(via);
        let slot = e.0.entry(part.to_string()).or_insert(0);
        match slot.checked_add(n) {
            Some(v) => {
                *slot = v;
                true
            }
            None => false,
        }
    }
    fn participant(&mut self, addr: &str, mux: Option<u64>, role: &'static str) {
        let e = self.participants.entry(addr.to_string()).or_default();
        if let Some(m) = mux {
            e.0.insert(m);
        }
        e.1.insert(role);
    }
}

/// Latest known state of balance-bearing entries in this ledger, used when a change list has no
/// `STATE` for an entry it updates or removes. `None` = removed.
type Last = HashMap<LedgerKey, Option<LedgerEntry>>;

struct Walk<'a> {
    ledger: u32,
    tx_index: Option<u32>,
    tx_hash: Option<&'a str>,
    op_index: Option<u32>,
    phase: &'a str,
    part: String,
}

fn walk(
    list: &LedgerEntryChanges,
    w: &Walk<'_>,
    acc: &mut TxAcc,
    last: &mut Last,
    sacs: &mut Sacs,
) {
    let mut pre: HashMap<LedgerKey, &LedgerEntry> = HashMap::new();
    let add = |acc: &mut TxAcc, sacs: &mut Sacs, e: &LedgerEntry, sign: i128| {
        for h in held(e, sacs) {
            match h {
                Held::Bal(holder, asset, n, via) => {
                    if !acc.part(&holder, &asset, &w.part, sign * n, via) {
                        acc.incomplete.insert((holder.clone(), asset.clone()));
                        acc.unknown.push(UnknownFact {
                            ledger: w.ledger,
                            tx_index: w.tx_index,
                            class: "i128_overflow".into(),
                            detail: format!("{holder} {asset}"),
                        });
                    }
                }
                Held::Nonsac(c, holder, n) => {
                    let slot = acc.nonsac.entry((c, holder)).or_insert(Some(0));
                    *slot = match (*slot, n) {
                        (Some(a), Some(b)) => a.checked_add(sign * b),
                        _ => None,
                    };
                }
                Held::Unparsed(c, holder) => acc.unknown.push(UnknownFact {
                    ledger: w.ledger,
                    tx_index: w.tx_index,
                    class: "sac_balance_unparsed".into(),
                    detail: format!("{c} {holder}"),
                }),
            }
        }
    };
    let entry_fact = |change: &str, k: &LedgerKey, sacs: &Sacs| EntryFact {
        ledger: w.ledger,
        tx_index: w.tx_index,
        tx_hash: w.tx_hash.map(str::to_string),
        op_index: w.op_index,
        phase: w.phase.to_string(),
        change: change.to_string(),
        entry_type: entry_type(k).to_string(),
        key: key_base64(k),
        subject: key_subject(k),
        asset_contract: match k {
            LedgerKey::Trustline(t) => {
                trustline_asset(&t.asset).map(|a| contract_strkey(&sac_contract_id(&a, sacs.nid)))
            }
            _ => None,
        },
    };
    for c in list.0.iter() {
        match c {
            LedgerEntryChange::State(e) => {
                pre.insert(e.to_key(), e);
            }
            LedgerEntryChange::Created(e) => {
                let k = e.to_key();
                acc.entries.push(entry_fact("created", &k, sacs));
                field_diff(w, acc, &k, None, Some(e));
                if has_fields(&k) {
                    last.insert(k.clone(), Some(e.clone()));
                }
                if let Some(o) = key_owner(&k) {
                    acc.participant(&o, None, "entry");
                }
                if balance_bearing(&k) {
                    add(acc, sacs, e, 1);
                    last.insert(k, Some(e.clone()));
                }
            }
            LedgerEntryChange::Updated(e) => {
                let k = e.to_key();
                acc.entries.push(entry_fact("updated", &k, sacs));
                if has_fields(&k) {
                    let prior: Option<LedgerEntry> = match pre.get(&k) {
                        Some(p) => Some((*p).clone()),
                        None => last.get(&k).cloned().flatten(),
                    };
                    match &prior {
                        Some(p) => field_diff(w, acc, &k, Some(p), Some(e)),
                        None => acc.unknown.push(UnknownFact {
                            ledger: w.ledger,
                            tx_index: w.tx_index,
                            class: "fields_without_prior_state".into(),
                            detail: format!("{} {}", w.part, key_base64(&k)),
                        }),
                    }
                    if !balance_bearing(&k) {
                        last.insert(k.clone(), Some(e.clone()));
                    }
                }
                if let Some(o) = key_owner(&k) {
                    acc.participant(&o, None, "entry");
                }
                if balance_bearing(&k) {
                    let prior: Option<LedgerEntry> = match pre.get(&k) {
                        Some(p) => Some((*p).clone()),
                        None => last.get(&k).cloned().flatten(),
                    };
                    match prior {
                        Some(p) => {
                            add(acc, sacs, &p, -1);
                            add(acc, sacs, e, 1);
                        }
                        None => missing_pre(w, acc, sacs, e, "updated"),
                    }
                    last.insert(k, Some(e.clone()));
                }
            }
            LedgerEntryChange::Removed(k) => {
                acc.entries.push(entry_fact("removed", k, sacs));
                if has_fields(k) && !balance_bearing(k) {
                    last.insert(k.clone(), None);
                }
                if let Some(o) = key_owner(k) {
                    acc.participant(&o, None, "entry");
                }
                if balance_bearing(k) {
                    let prior: Option<LedgerEntry> = match pre.get(k) {
                        Some(p) => Some((*p).clone()),
                        None => last.get(k).cloned().flatten(),
                    };
                    match prior {
                        Some(p) => add(acc, sacs, &p, -1),
                        None => {
                            acc.unknown.push(UnknownFact {
                                ledger: w.ledger,
                                tx_index: w.tx_index,
                                class: "removed_without_prior_state".into(),
                                detail: format!("{} {}", w.part, key_base64(k)),
                            });
                            if let Some(o) = key_owner(k) {
                                // The asset is known from the key for accounts and trustlines;
                                // for claimable balances and pools every asset of the holder
                                // is unknown (`*`).
                                let asset = match k {
                                    LedgerKey::Account(_) => "native".to_string(),
                                    LedgerKey::Trustline(t) => trustline_asset(&t.asset)
                                        .map(|a| asset_string(&a))
                                        .unwrap_or_else(|| "*".into()),
                                    _ => "*".into(),
                                };
                                acc.incomplete.insert((o, asset));
                            }
                        }
                    }
                    last.insert(k.clone(), None);
                }
            }
            LedgerEntryChange::Restored(e) => {
                let k = e.to_key();
                acc.entries.push(entry_fact("restored", &k, sacs));
                if let Some(o) = key_owner(&k) {
                    acc.participant(&o, None, "entry");
                }
                pre.insert(k.clone(), e);
                if balance_bearing(&k) {
                    // A restore brings back the value the entry had when archived: no balance
                    // change. (P23 reconciliation is handled with the op's events.)
                    if let (Some(op), LedgerEntryData::ContractData(d)) = (w.op_index, &e.data) {
                        if let (Some(holder), ScAddress::Contract(cid)) =
                            (balance_key(d), &d.contract)
                        {
                            if let Some(asset) = sacs.get(&cid.0 .0) {
                                acc.restored_sac.entry(op as usize).or_default().push((
                                    contract_strkey(&cid.0 .0),
                                    sc_address(holder).0,
                                    asset,
                                ));
                            }
                        }
                    }
                    last.insert(k, Some(e.clone()));
                }
            }
        }
    }
}

/// Entries whose attributes are diffed into `entry_field` facts.
fn has_fields(k: &LedgerKey) -> bool {
    matches!(
        k,
        LedgerKey::Account(_) | LedgerKey::Trustline(_) | LedgerKey::Data(_)
    )
}

/// The diffed attributes of an entry (see `EntryFieldFact`).
fn entry_fields(e: &LedgerEntry) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    match &e.data {
        LedgerEntryData::Account(a) => {
            let stellar_xdr::PublicKey::PublicKeyTypeEd25519(pk) = &a.account_id.0;
            let master = signer_hex(&stellar_xdr::SignerKey::Ed25519(pk.clone()));
            if a.thresholds.0[0] > 0 {
                m.insert(format!("signer:{master}"), a.thresholds.0[0].to_string());
            }
            for sg in a.signers.iter() {
                m.insert(
                    format!("signer:{}", signer_hex(&sg.key)),
                    sg.weight.to_string(),
                );
            }
            for (i, n) in ["low", "med", "high"].iter().enumerate() {
                m.insert(format!("threshold:{n}"), a.thresholds.0[i + 1].to_string());
            }
            m.insert("flags".into(), a.flags.to_string());
            m.insert(
                "home_domain".into(),
                hex::encode(a.home_domain.0.as_slice()),
            );
        }
        LedgerEntryData::Trustline(t) => {
            m.insert("limit".into(), t.limit.to_string());
            m.insert("flags".into(), t.flags.to_string());
        }
        LedgerEntryData::Data(d) => {
            m.insert("value".into(), hex::encode(d.data_value.0.as_slice()));
        }
        _ => {}
    }
    if let LedgerEntryExt::V1(v1) = &e.ext {
        if let Some(sp) = &v1.sponsoring_id.0 {
            m.insert("sponsor".into(), account_strkey(sp));
        }
    }
    m
}

/// A field's value an absent entry is taken to have (a created entry lists only values other than these).
fn default_field(field: &str) -> bool {
    field.starts_with("threshold:") || field == "flags" || field == "home_domain"
}

fn field_diff(
    w: &Walk<'_>,
    acc: &mut TxAcc,
    k: &LedgerKey,
    old: Option<&LedgerEntry>,
    new: Option<&LedgerEntry>,
) {
    if !has_fields(k) {
        return;
    }
    let o = old.map(entry_fields).unwrap_or_default();
    let n = new.map(entry_fields).unwrap_or_default();
    let mut names: BTreeSet<&String> = o.keys().collect();
    names.extend(n.keys());
    for f in names {
        let (ov, nv) = (o.get(f), n.get(f));
        if ov == nv {
            continue;
        }
        if old.is_none() && default_field(f) && nv.map(|v| v == "0" || v.is_empty()) == Some(true) {
            continue;
        }
        acc.fields.push(EntryFieldFact {
            ledger: w.ledger,
            tx_index: w.tx_index,
            tx_hash: w.tx_hash.map(str::to_string),
            op_index: w.op_index,
            phase: w.phase.to_string(),
            entry_type: entry_type(k).to_string(),
            subject: key_subject(k),
            field: f.clone(),
            old: ov.cloned(),
            new: nv.cloned(),
        });
    }
}

fn missing_pre(w: &Walk<'_>, acc: &mut TxAcc, sacs: &mut Sacs, e: &LedgerEntry, what: &str) {
    for h in held(e, sacs) {
        if let Held::Bal(holder, asset, _, _) = h {
            acc.incomplete.insert((holder, asset));
        }
    }
    acc.unknown.push(UnknownFact {
        ledger: w.ledger,
        tx_index: w.tx_index,
        class: format!("{what}_without_prior_state"),
        detail: format!("{} {}", w.part, key_base64(&e.to_key())),
    });
}

fn stage_name(s: TransactionEventStage) -> &'static str {
    match s {
        TransactionEventStage::BeforeAllTxs => "tx:before_all_txs",
        TransactionEventStage::AfterTx => "tx:after_tx",
        TransactionEventStage::AfterAllTxs => "tx:after_all_txs",
    }
}

/// A decoded token-like event.
struct TokenEv {
    contract: String,
    sac: bool,
    asset: Option<String>,
    name: String,
    from: Option<(String, Option<u64>)>,
    to: Option<(String, Option<u64>)>,
    spender: Option<String>,
    to_muxed_id: Option<String>,
    amount: Option<i128>,
    topics: Vec<String>,
    data: String,
}

/// Decode a token-like event. Returns None for other events.
fn token_event(e: &ContractEvent, sacs: &mut Sacs) -> Option<TokenEv> {
    let cid = event_contract(e)?;
    let (topics, data) = event_topics(e);
    let name = sym(topics.first()?)?;
    if !TOKEN_EVENTS.contains(&name) {
        return None;
    }
    let addrs: Vec<(String, Option<u64>)> = topics[1..]
        .iter()
        .filter_map(|t| match t {
            ScVal::Address(a) => Some(sc_address(a)),
            _ => None,
        })
        .collect();
    let named_asset: Option<String> = topics.iter().rev().find_map(|t| match t {
        ScVal::String(s) => std::str::from_utf8(s.0.as_slice()).ok().map(str::to_string),
        _ => None,
    });
    let sac_asset = sacs.get(&cid);
    // A SAC event names its own asset (fee events name none and come from the native SAC).
    let sac = match (&sac_asset, &named_asset) {
        (Some(a), Some(n)) => a == n,
        (Some(a), None) => a == "native" && name == "fee",
        _ => false,
    };
    let (from, to, spender) = match name {
        "transfer" => (addrs.first().cloned(), addrs.get(1).cloned(), None),
        "mint" => (None, addrs.last().cloned(), None),
        "burn" => (addrs.first().cloned(), None, None),
        "clawback" => (addrs.last().cloned(), None, None),
        "approve" => (
            addrs.first().cloned(),
            None,
            addrs.get(1).map(|a| a.0.clone()),
        ),
        "fee" => (addrs.first().cloned(), None, None),
        _ => (None, None, None),
    };
    let mut to_muxed_id: Option<String> = to.as_ref().and_then(|t| t.1).map(|m| m.to_string());
    let amount = match data {
        ScVal::I128(_) => i128_of(data),
        ScVal::Map(Some(m)) => {
            for en in m.iter() {
                if sym(&en.key) == Some("to_muxed_id") {
                    // A Void id is no id.
                    let v = match &en.val {
                        ScVal::Void => None,
                        ScVal::U64(n) => Some(n.to_string()),
                        ScVal::String(s) => Some(format!("string:{}", hex::encode(s.0.as_slice()))),
                        ScVal::Bytes(b) => Some(format!("bytes:{}", hex::encode(b.0.as_slice()))),
                        other => Some(other.name().to_string()),
                    };
                    if v.is_some() {
                        to_muxed_id = v;
                    }
                }
            }
            balance_amount(data)
        }
        ScVal::Vec(Some(v)) if name == "approve" => v.first().and_then(i128_of),
        _ => None,
    };
    Some(TokenEv {
        contract: contract_strkey(&cid),
        sac,
        asset: if sac { sac_asset } else { None },
        name: name.to_string(),
        from,
        to,
        spender,
        to_muxed_id,
        amount,
        topics: topics.iter().map(|t| t.name().to_string()).collect(),
        data: data.name().to_string(),
    })
}

#[allow(clippy::too_many_arguments)]
fn event_fact(
    ledger: u32,
    tx_index: u32,
    hash: &str,
    op_index: Option<u32>,
    phase: &str,
    event_index: u32,
    t: TokenEv,
    reconciliation: bool,
) -> EventFact {
    EventFact {
        ledger,
        tx_index,
        tx_hash: hash.to_string(),
        op_index,
        phase: phase.to_string(),
        event_index,
        contract: t.contract,
        sac: t.sac,
        asset: t.asset,
        event: t.name,
        from: t.from.map(|x| x.0),
        to: t.to.map(|x| x.0).or(t.spender),
        to_muxed_id: t.to_muxed_id,
        amount: t.amount.map(|n| n.to_string()),
        topics: t.topics,
        data: t.data,
        reconciliation,
    }
}

fn result_parts(r: &TransactionResultResult) -> (bool, String, Vec<String>) {
    use stellar_xdr::InnerTransactionResultResult as I;
    let ops = |v: &[stellar_xdr::OperationResult]| v.iter().map(op_code).collect::<Vec<_>>();
    match r {
        TransactionResultResult::TxSuccess(v) => (true, r.name().into(), ops(v)),
        TransactionResultResult::TxFailed(v) => (false, r.name().into(), ops(v)),
        TransactionResultResult::TxFeeBumpInnerSuccess(p)
        | TransactionResultResult::TxFeeBumpInnerFailed(p) => {
            let inner = &p.result.result;
            let (ok, v) = match inner {
                I::TxSuccess(v) => (true, ops(v)),
                I::TxFailed(v) => (false, ops(v)),
                _ => (false, vec![]),
            };
            (
                ok && matches!(r, TransactionResultResult::TxFeeBumpInnerSuccess(_)),
                format!("{}/{}", r.name(), inner.name()),
                v,
            )
        }
        other => (false, other.name().into(), vec![]),
    }
}

fn op_code(r: &stellar_xdr::OperationResult) -> String {
    use stellar_xdr::OperationResult as R;
    use stellar_xdr::OperationResultTr as T;
    match r {
        R::OpInner(t) => {
            let inner = match t {
                T::CreateAccount(x) => x.name(),
                T::Payment(x) => x.name(),
                T::PathPaymentStrictReceive(x) => x.name(),
                T::ManageSellOffer(x) => x.name(),
                T::CreatePassiveSellOffer(x) => x.name(),
                T::SetOptions(x) => x.name(),
                T::ChangeTrust(x) => x.name(),
                T::AllowTrust(x) => x.name(),
                T::AccountMerge(x) => x.name(),
                T::Inflation(x) => x.name(),
                T::ManageData(x) => x.name(),
                T::BumpSequence(x) => x.name(),
                T::ManageBuyOffer(x) => x.name(),
                T::PathPaymentStrictSend(x) => x.name(),
                T::CreateClaimableBalance(x) => x.name(),
                T::ClaimClaimableBalance(x) => x.name(),
                T::BeginSponsoringFutureReserves(x) => x.name(),
                T::EndSponsoringFutureReserves(x) => x.name(),
                T::RevokeSponsorship(x) => x.name(),
                T::Clawback(x) => x.name(),
                T::ClawbackClaimableBalance(x) => x.name(),
                T::SetTrustLineFlags(x) => x.name(),
                T::LiquidityPoolDeposit(x) => x.name(),
                T::LiquidityPoolWithdraw(x) => x.name(),
                T::InvokeHostFunction(x) => x.name(),
                T::ExtendFootprintTtl(x) => x.name(),
                T::RestoreFootprint(x) => x.name(),
            };
            format!("{}:{}", t.name(), inner)
        }
        other => other.name().to_string(),
    }
}

/// Judge one ledger.
pub fn judge_ledger(lcm: &LedgerCloseMeta, opts: &Options) -> anyhow::Result<Vec<Fact>> {
    let hdr = read::header(lcm);
    let ledger = hdr.header.ledger_seq;
    let protocol = hdr.header.ledger_version;
    let nid = opts.network_id;
    let views = tx_views(lcm);
    let metas: Vec<MetaParts<'_>> = views.iter().map(|v| meta_parts(v.meta)).collect();

    // SAC candidates: native, every classic asset in the ledger's entries, every string topic of
    // every event, the registry. Each is verified by hashing, so a wrong candidate costs nothing.
    let mut sacs = Sacs {
        nid,
        map: HashMap::new(),
        seen_assets: BTreeSet::new(),
        used: BTreeMap::new(),
    };
    sacs.add_asset(&Asset::Native);
    for a in &opts.sac_registry {
        sacs.add_str(a);
    }
    for (v, m) in views.iter().zip(&metas) {
        collect_assets(v.fee, &mut sacs);
        if let Some(p) = v.post {
            collect_assets(p, &mut sacs);
        }
        for l in m.before.iter().chain(m.after.iter()).chain(m.ops.iter()) {
            collect_assets(l, &mut sacs);
        }
        for evs in &m.op_events {
            for e in evs {
                collect_event_assets(e, &mut sacs);
            }
        }
        for (_, e) in &m.tx_events {
            collect_event_assets(e, &mut sacs);
        }
    }
    for l in upgrade_lists(lcm) {
        collect_assets(l, &mut sacs);
    }

    // Envelopes by hash.
    let mut env_by_hash: HashMap<[u8; 32], Env> = HashMap::new();
    for e in envelopes(lcm) {
        let h = e.hash(nid).map_err(|err| anyhow::anyhow!("hash: {err}"))?;
        env_by_hash.insert(h, env_parts(e, nid));
    }

    let mut facts: Vec<Fact> = Vec::new();
    let mut last: Last = HashMap::new();
    let mut accs: Vec<TxAcc> = views.iter().map(|_| TxAcc::default()).collect();
    let hashes: Vec<String> = views
        .iter()
        .map(|v| hex::encode(v.result.transaction_hash.0))
        .collect();

    // Fees are charged for the whole set before any transaction applies.
    for (i, v) in views.iter().enumerate() {
        let w = Walk {
            ledger,
            tx_index: Some(i as u32),
            tx_hash: Some(&hashes[i]),
            op_index: None,
            phase: "fee",
            part: "fee".into(),
        };
        walk(v.fee, &w, &mut accs[i], &mut last, &mut sacs);
    }
    let mut tx_facts = Vec::new();
    let mut events_out: Vec<Vec<EventFact>> = Vec::new();
    let mut failed = 0u32;
    for (i, v) in views.iter().enumerate() {
        let m = &metas[i];
        let acc = &mut accs[i];
        let hash = hashes[i].clone();
        let mk = |phase: &'static str, part: String, op: Option<u32>| Walk {
            ledger,
            tx_index: Some(i as u32),
            tx_hash: Some(&hashes[i]),
            op_index: op,
            phase,
            part,
        };
        if let Some(l) = m.before {
            walk(
                l,
                &mk("before", "before".into(), None),
                acc,
                &mut last,
                &mut sacs,
            );
        }
        for (oi, l) in m.ops.iter().enumerate() {
            walk(
                l,
                &mk("op", format!("op:{oi}"), Some(oi as u32)),
                acc,
                &mut last,
                &mut sacs,
            );
        }
        if let Some(l) = m.after {
            walk(
                l,
                &mk("after", "after".into(), None),
                acc,
                &mut last,
                &mut sacs,
            );
        }

        // Envelope, result.
        let env = env_by_hash.get(&v.result.transaction_hash.0);
        let (success, code, op_codes) = result_parts(&v.result.result.result);
        if !success {
            failed += 1;
        }
        let mut op_types = Vec::new();
        match env {
            Some(env) => {
                if let Some(fs) = &env.fee_source {
                    let (a, mx) = muxed(fs);
                    acc.participant(&a, mx, "fee_payer");
                } else {
                    let (a, mx) = muxed(&env.source);
                    acc.participant(&a, mx, "fee_payer");
                }
                let (a, mx) = muxed(&env.source);
                acc.participant(&a, mx, "source");
                for op in &env.ops {
                    op_types.push(op.body.name().to_string());
                    if let Some(s) = &op.source_account {
                        let (a, mx) = muxed(s);
                        acc.participant(&a, mx, "op_source");
                    }
                    for (a, mx) in op_counterparties(op) {
                        acc.participant(&a, mx, "counterparty");
                    }
                    for a in op_claimants(op) {
                        acc.participant(&a, None, "claimant");
                    }
                }
            }
            None => acc.unknown.push(UnknownFact {
                ledger,
                tx_index: Some(i as u32),
                class: "envelope_not_found".into(),
                detail: hash.clone(),
            }),
        }

        // Events.
        let mut evs: Vec<EventFact> = Vec::new();
        for (oix, l) in m.op_events.iter().enumerate() {
            let oi = Some(oix as u32);
            // P23 SAC reconciliation: leading mint/burn events of an InvokeHostFunction op that
            // match a hot-archive-restored SAC balance of that op, at most one per entry.
            let mut restored = if protocol == 23 {
                acc.restored_sac.get(&oix).cloned().unwrap_or_default()
            } else {
                Vec::new()
            };
            let is_ihf = env
                .and_then(|e| e.ops.get(oix))
                .map(|o| matches!(o.body, OperationBody::InvokeHostFunction(_)))
                .unwrap_or(false);
            let decoded: Vec<Option<TokenEv>> =
                l.iter().map(|e| token_event(e, &mut sacs)).collect();
            // Candidates: the leading run of SAC mint/burn events on a restored balance.
            let mut cands: Vec<(usize, String, String, i128)> = Vec::new();
            if is_ihf && !restored.is_empty() {
                for (ei, t) in decoded.iter().enumerate() {
                    let Some(t) = t else { break };
                    let who = match t.name.as_str() {
                        "mint" => t.to.as_ref().map(|x| x.0.clone()),
                        "burn" => t.from.as_ref().map(|x| x.0.clone()),
                        _ => None,
                    };
                    let pos = who.and_then(|h| {
                        restored
                            .iter()
                            .position(|(c, hh, _)| *c == t.contract && *hh == h)
                    });
                    match (t.sac, pos, t.amount) {
                        (true, Some(p), Some(n)) => {
                            let (_, h, a) = restored.remove(p);
                            cands.push((ei, h, a, if t.name == "mint" { n } else { -n }));
                        }
                        _ => break,
                    }
                }
            }
            // Reconciliation events are a prefix of the candidates. A genuine mint or burn shows
            // in the op's entry deltas, a reconciliation does not: take the longest prefix with
            // which every asset's op deltas plus reconciliation equal its SAC events' net supply
            // change; if none fits, all candidates (and conservation will flag the transaction).
            let recon_n = if cands.is_empty() {
                0
            } else {
                let part = format!("op:{oix}");
                let mut op_sum: BTreeMap<&str, i128> = BTreeMap::new();
                for ((_, asset), (parts, _)) in &acc.bal {
                    if let Some(v) = parts.get(&part) {
                        *op_sum.entry(asset.as_str()).or_default() += v;
                    }
                }
                let mut ev_sum: BTreeMap<&str, i128> = BTreeMap::new();
                for t in decoded.iter().flatten() {
                    let (Some(asset), Some(n)) = (t.asset.as_deref(), t.amount) else {
                        continue;
                    };
                    let issuer = asset_issuer(asset);
                    let d = match t.name.as_str() {
                        "mint" => n,
                        "burn" | "clawback" => -n,
                        "transfer" => {
                            let mut d = 0;
                            if issuer.is_some() && t.from.as_ref().map(|x| x.0.as_str()) == issuer {
                                d += n;
                            }
                            if issuer.is_some() && t.to.as_ref().map(|x| x.0.as_str()) == issuer {
                                d -= n;
                            }
                            d
                        }
                        _ => 0,
                    };
                    *ev_sum.entry(asset).or_default() += d;
                }
                (0..=cands.len())
                    .rev()
                    .find(|&j| {
                        let mut rec: BTreeMap<&str, i128> = BTreeMap::new();
                        for c in &cands[..j] {
                            *rec.entry(c.2.as_str()).or_default() += c.3;
                        }
                        cands.iter().all(|c| {
                            let a = c.2.as_str();
                            op_sum.get(a).copied().unwrap_or(0) + rec.get(a).copied().unwrap_or(0)
                                == ev_sum.get(a).copied().unwrap_or(0)
                        })
                    })
                    .unwrap_or(cands.len())
            };
            let recon_idx: BTreeSet<usize> = cands[..recon_n].iter().map(|c| c.0).collect();
            for (_, h, a, signed) in cands[..recon_n].iter() {
                let part = format!("reconcile:{oix}");
                acc.part(h, a, &part, *signed, "sac_balance");
            }
            for (ei, t) in decoded.into_iter().enumerate() {
                let Some(t) = t else { continue };
                if t.sac {
                    for who in [&t.from, &t.to].into_iter().flatten() {
                        acc.participant(&who.0, who.1, "event");
                    }
                }
                let recon = recon_idx.contains(&ei);
                evs.push(event_fact(
                    ledger, i as u32, &hash, oi, "op", ei as u32, t, recon,
                ));
            }
        }
        for (ei, (stage, e)) in m.tx_events.iter().enumerate() {
            let Some(t) = token_event(e, &mut sacs) else {
                continue;
            };
            if t.sac {
                for who in [&t.from, &t.to].into_iter().flatten() {
                    acc.participant(&who.0, who.1, "event");
                }
            }
            evs.push(event_fact(
                ledger,
                i as u32,
                &hash,
                None,
                stage_name(*stage),
                ei as u32,
                t,
                false,
            ));
        }
        events_out.push(evs);

        tx_facts.push(TxFact {
            ledger,
            tx_index: i as u32,
            tx_hash: hash,
            inner_hash: env.and_then(|e| e.inner_hash).map(hex::encode),
            success,
            result_code: code,
            op_codes,
            op_types,
            fee_charged: v.result.result.fee_charged,
            meta_version: m.version,
        });
    }
    // Post-apply fee processing (refunds) runs after every transaction applied.
    for (i, v) in views.iter().enumerate() {
        if let Some(p) = v.post {
            let w = Walk {
                ledger,
                tx_index: Some(i as u32),
                tx_hash: Some(&hashes[i]),
                op_index: None,
                phase: "refund",
                part: "refund".into(),
            };
            walk(p, &w, &mut accs[i], &mut last, &mut sacs);
        }
    }
    // Upgrades, then evictions: ledger-level.
    let mut ledger_acc = TxAcc::default();
    let ups = upgrade_lists(lcm);
    let mut upgrade_changes = 0u32;
    for l in &ups {
        upgrade_changes += l.0.len() as u32;
        let w = Walk {
            ledger,
            tx_index: None,
            tx_hash: None,
            op_index: None,
            phase: "upgrade",
            part: "upgrade".into(),
        };
        walk(l, &w, &mut ledger_acc, &mut last, &mut sacs);
    }
    let evicted = evicted_keys(lcm);
    for k in &evicted {
        ledger_acc.entries.push(EntryFact {
            ledger,
            tx_index: None,
            tx_hash: None,
            op_index: None,
            phase: "eviction".into(),
            change: "evicted".into(),
            entry_type: entry_type(k).into(),
            key: key_base64(k),
            subject: key_subject(k),
            asset_contract: None,
        });
    }

    let lcm_version = match lcm {
        LedgerCloseMeta::V0(_) => 0,
        LedgerCloseMeta::V1(_) => 1,
        LedgerCloseMeta::V2(_) => 2,
    };
    facts.push(Fact::Ledger(LedgerFact {
        ledger,
        hash: hex::encode(hdr.hash.0),
        protocol,
        close_time: hdr.header.scp_value.close_time.0,
        lcm_version,
        tx_count: views.len() as u32,
        failed_count: failed,
        upgrade_changes,
        evicted: evicted.len() as u32,
    }));
    let mut sac_cache: HashMap<String, String> = HashMap::new();
    let mut sac_of = |asset: &str| -> String {
        sac_cache
            .entry(asset.to_string())
            .or_insert_with(|| {
                parse_asset(asset)
                    .map(|a| contract_strkey(&sac_contract_id(&a, nid)))
                    .unwrap_or_default()
            })
            .clone()
    };
    let mut tx_out: Vec<Vec<Fact>> = Vec::new();
    for (i, acc) in accs.iter_mut().enumerate() {
        let mut out = vec![Fact::Tx(tx_facts[i].clone())];
        emit_acc(
            ledger,
            Some(i as u32),
            Some(&hashes[i]),
            acc,
            &mut out,
            &mut sac_of,
        );
        for e in std::mem::take(&mut events_out[i]) {
            if e.amount.is_some() {
                out.push(Fact::TokenEvent(e));
            } else {
                out.push(Fact::EventWithoutAmount(e));
            }
        }
        tx_out.push(out);
    }
    let mut lvl = Vec::new();
    emit_acc(ledger, None, None, &mut ledger_acc, &mut lvl, &mut sac_of);
    for (c, a) in &sacs.used {
        facts.push(Fact::Sac(SacFact {
            ledger,
            contract: c.clone(),
            asset: a.clone(),
        }));
    }
    for o in tx_out {
        facts.extend(o);
    }
    facts.extend(lvl);
    Ok(facts)
}

fn emit_acc(
    ledger: u32,
    tx_index: Option<u32>,
    tx_hash: Option<&str>,
    acc: &mut TxAcc,
    out: &mut Vec<Fact>,
    sac_of: &mut impl FnMut(&str) -> String,
) {
    // Holders are participants.
    let holders: Vec<String> = acc
        .bal
        .iter()
        .filter(|(_, (p, _))| p.values().any(|v| *v != 0))
        .map(|((h, _), _)| h.clone())
        .collect();
    for h in holders {
        acc.participant(&h, None, "holder");
    }
    for ((holder, asset), (parts, via)) in &acc.bal {
        let complete = !acc.incomplete.contains(&(holder.clone(), asset.clone()));
        let mut net: Option<i128> = Some(0);
        for v in parts.values() {
            net = net.and_then(|n| n.checked_add(*v));
        }
        let parts_s: BTreeMap<String, String> = parts
            .iter()
            .filter(|(_, v)| **v != 0)
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect();
        let Some(net) = net else {
            out.push(Fact::Unknown(UnknownFact {
                ledger,
                tx_index,
                class: "i128_overflow".into(),
                detail: format!("{holder} {asset}"),
            }));
            continue;
        };
        if parts_s.is_empty() && complete {
            continue;
        }
        out.push(Fact::BalanceChange(BalanceFact {
            ledger,
            tx_index,
            tx_hash: tx_hash.map(str::to_string),
            holder: holder.clone(),
            asset: asset.clone(),
            contract: sac_of(asset),
            amount: net.to_string(),
            parts: parts_s,
            via: via.iter().map(|s| s.to_string()).collect(),
            complete,
        }));
    }
    // Incomplete keys that never got a part.
    for (holder, asset) in &acc.incomplete {
        if !acc.bal.contains_key(&(holder.clone(), asset.clone())) {
            out.push(Fact::BalanceChange(BalanceFact {
                ledger,
                tx_index,
                tx_hash: tx_hash.map(str::to_string),
                holder: holder.clone(),
                asset: asset.clone(),
                contract: sac_of(asset),
                amount: "0".into(),
                parts: BTreeMap::new(),
                via: vec![],
                complete: false,
            }));
        }
    }
    if let (Some(ti), Some(th)) = (tx_index, tx_hash) {
        for ((c, h), n) in &acc.nonsac {
            if *n == Some(0) {
                continue;
            }
            out.push(Fact::NonsacBalance(NonsacBalanceFact {
                ledger,
                tx_index: ti,
                tx_hash: th.to_string(),
                contract: c.clone(),
                holder: h.clone(),
                amount: n.map(|x| x.to_string()),
            }));
        }
        for (addr, (mx, roles)) in &acc.participants {
            out.push(Fact::Participant(ParticipantFact {
                ledger,
                tx_index: ti,
                tx_hash: th.to_string(),
                address: addr.clone(),
                muxed_ids: mx.iter().map(|m| m.to_string()).collect(),
                roles: roles.iter().map(|r| r.to_string()).collect(),
            }));
        }
    }
    for e in acc.entries.drain(..) {
        out.push(Fact::EntryChange(e));
    }
    for f in acc.fields.drain(..) {
        out.push(Fact::EntryField(f));
    }
    for u in acc.unknown.drain(..) {
        out.push(Fact::Unknown(u));
    }
}
