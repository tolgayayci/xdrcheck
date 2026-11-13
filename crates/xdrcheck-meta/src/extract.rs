//! The reference extractor: an independent derivation of who a transaction affected
//! and how, from what stellar-core actually changed.
//!
//! Sources, by standing:
//! - **Ledger-entry changes** (fee processing, changes before and after, operation changes,
//!   post-apply fee processing) are written by core from real state deltas. They establish every
//!   participant and every state change.
//! - **Contract events** of successful Soroban calls are consensus data; classic-operation and fee
//!   events are a node-flag-dependent view of the same deltas. Token-shaped events yield movements,
//!   keyed on the contract that **emitted** them (the emitting-contract rule).
//! - **Diagnostic events** are non-consensus and attacker-influenced: never read.
//! - **The envelope** is read for two things only: the operation type at an index (the `cause` of a
//!   change), and the `MuxedAccount` form of an account the meta already made a participant (an
//!   alias). It never adds a participant. It also lists the addresses a failed transaction or an
//!   authorization entry *names*, as `must_not_include` candidates for the author to confirm.
//!
//! Per transaction, in apply order (the order of the ledger's transaction processing list):
//! 1. fee: the account whose balance fee processing decreased is the fee payer, the decrease a `fee`
//!    movement; a balance increase in post-apply fee processing (or, in a `LedgerCloseMeta` v0/v1,
//!    which has none, in the changes after, whatever the `TransactionMeta` version) is a
//!    `fee_refund`. Fee events, when present, must agree; they are not counted;
//! 2. outcome from the result arm (`tx_success` / `tx_fee_bump_inner_success`);
//! 3. transaction-level changes: the account whose sequence number changed is the source
//!    (`sequence_bumped`); signer removals there are `signer_removed`;
//! 4. failed transaction: stop; every other address the envelope names is a must-not candidate;
//! 5. operation changes, `state` paired with the following `updated` / `removed` of the same key,
//!    classified into the manifest's state-change kinds. Entries with no address of their own
//!    (contract code; a TTL whose entry is not found among the keys the transaction touched) are
//!    attributed to the source; a TTL found to belong to contract data is the contract's. The
//!    address of a changed pool or balance gets the role `liquidity_pool` / `claimable_balance`,
//!    and an affected account named as a claimant of a balance created or claimed gets `claimant`;
//! 6. token-shaped events → movements, with the emitting-contract rule;
//! 7. created nonce entries → `authorizer` (no state change is recorded for a nonce entry);
//!    addresses only in authorization entries → candidates;
//! 8. muxed aliases from the envelope for participants that already exist;
//! 9. whole-ledger counts (`manifest.md` §6.2).
//!
//! The output uses the manifest's `expect` vocabulary (`corpus/schema/manifest-entry.schema.json`);
//! [`agree`] compares it with a hand-written `expect` block.

pub mod agree;
pub mod conserve;
pub mod entry;

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountEntry, AccountEntryExt, AccountEntryExtensionV1Ext, AccountId, Asset,
    ClaimableBalanceId, ContractDataDurability, ContractEvent, ContractEventBody,
    ContractEventType, ContractExecutable, ContractId, ContractIdPreimage,
    GeneralizedTransactionSet, Hash, HashIdPreimage, HashIdPreimageContractId, LedgerCloseMeta,
    LedgerEntry, LedgerEntryChange, LedgerEntryChanges, LedgerEntryData, LedgerEntryExt, LedgerKey,
    Limits, MuxedAccount, Operation, OperationBody, PoolId, PublicKey, ScAddress, ScVal, SignerKey,
    TransactionEnvelope, TransactionMeta, TransactionPhase, TransactionResultPair,
    TransactionResultResult, TrustLineAsset, TxSetComponent, Uint256, WriteXdr,
};

/// Errors the extractor can return.
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    /// A transaction in the processing list has no envelope with that hash in the transaction set
    /// (wrong passphrase, or an inconsistent ledger).
    #[error("transaction {index} ({hash}): no envelope with this hash in the transaction set under the given passphrase")]
    EnvelopeNotFound {
        /// Apply-order index.
        index: usize,
        /// Hex hash from the result pair.
        hash: String,
    },
    /// Encoding a value for hashing or JSON failed.
    #[error("{0}")]
    Encode(String),
}

type Result<T> = std::result::Result<T, ExtractError>;

/// The network ID: SHA-256 of the passphrase.
pub fn network_id(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase.as_bytes()).into()
}

/// The Stellar Asset Contract ID of a classic asset on a network.
pub fn sac_contract_id(asset: &Asset, network_id: [u8; 32]) -> [u8; 32] {
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(network_id),
        contract_id_preimage: ContractIdPreimage::Asset(asset.clone()),
    });
    let bytes = preimage
        .to_xdr(Limits::none())
        .expect("a contract-ID preimage always encodes");
    Sha256::digest(bytes).into()
}

/// The `C…` strkey of a contract ID.
pub fn contract_strkey(id: [u8; 32]) -> String {
    ScAddress::Contract(ContractId(Hash(id))).to_string()
}

/// `native`, `CODE:ISSUER`.
pub fn asset_string(asset: &Asset) -> String {
    match asset {
        Asset::Native => "native".into(),
        Asset::CreditAlphanum4(a) => format!("{}:{}", a.asset_code, a.issuer),
        Asset::CreditAlphanum12(a) => format!("{}:{}", a.asset_code, a.issuer),
    }
}

/// Parse `native` or `CODE:ISSUER` (the SEP-11 form an event's fourth topic carries).
pub fn parse_asset(s: &str) -> Option<Asset> {
    if s == "native" {
        return Some(Asset::Native);
    }
    let (code, issuer) = s.split_once(':')?;
    let issuer: AccountId = issuer.parse().ok()?;
    if code.is_empty() || code.len() > 12 {
        return None;
    }
    let mut buf = [0u8; 12];
    buf[..code.len()].copy_from_slice(code.as_bytes());
    Some(if code.len() <= 4 {
        Asset::CreditAlphanum4(stellar_xdr::AlphaNum4 {
            asset_code: stellar_xdr::AssetCode4(buf[..4].try_into().unwrap()),
            issuer,
        })
    } else {
        Asset::CreditAlphanum12(stellar_xdr::AlphaNum12 {
            asset_code: stellar_xdr::AssetCode12(buf),
            issuer,
        })
    })
}

fn trustline_asset_string(asset: &TrustLineAsset) -> String {
    match asset {
        TrustLineAsset::Native => "native".into(),
        TrustLineAsset::CreditAlphanum4(a) => format!("{}:{}", a.asset_code, a.issuer),
        TrustLineAsset::CreditAlphanum12(a) => format!("{}:{}", a.asset_code, a.issuer),
        TrustLineAsset::PoolShare(PoolId(Hash(h))) => format!("liquidity_pool:{}", hex::encode(h)),
    }
}

fn trustline_classic_asset(asset: &TrustLineAsset) -> Option<Asset> {
    match asset {
        TrustLineAsset::Native => Some(Asset::Native),
        TrustLineAsset::CreditAlphanum4(a) => Some(Asset::CreditAlphanum4(a.clone())),
        TrustLineAsset::CreditAlphanum12(a) => Some(Asset::CreditAlphanum12(a.clone())),
        TrustLineAsset::PoolShare(_) => None,
    }
}

fn pool_strkey(id: &PoolId) -> String {
    ScAddress::LiquidityPool(id.clone()).to_string()
}

fn account_strkey(id: &AccountId) -> String {
    id.to_string()
}

/// The base address of an `ScAddress`: muxed information dropped.
pub fn base_address(a: &ScAddress) -> String {
    match a {
        ScAddress::MuxedAccount(m) => {
            AccountId(PublicKey::PublicKeyTypeEd25519(m.ed25519.clone())).to_string()
        }
        ScAddress::MuxedContract(m) => ScAddress::Contract(m.contract_id.clone()).to_string(),
        other => other.to_string(),
    }
}

fn muxed_base(m: &MuxedAccount) -> (String, Option<u64>) {
    match m {
        MuxedAccount::Ed25519(k) => (
            AccountId(PublicKey::PublicKeyTypeEd25519(k.clone())).to_string(),
            None,
        ),
        MuxedAccount::MuxedEd25519(mm) => (
            AccountId(PublicKey::PublicKeyTypeEd25519(mm.ed25519.clone())).to_string(),
            Some(mm.id),
        ),
    }
}

fn xdr_hex<T: WriteXdr>(v: &T) -> String {
    hex::encode(
        v.to_xdr(Limits::none())
            .expect("a decoded value re-encodes"),
    )
}

fn json_of<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

/// The union arm name of an XDR-JSON value: the string itself, or the single key of an object.
fn arm(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Object(m) if m.len() == 1 => m.keys().next().cloned().unwrap_or_default(),
        _ => String::new(),
    }
}

fn i128_of(v: &ScVal) -> Option<i128> {
    match v {
        ScVal::I128(p) => Some((i128::from(p.hi) << 64) | i128::from(p.lo)),
        _ => None,
    }
}

fn sym(v: &ScVal) -> Option<&str> {
    match v {
        ScVal::Symbol(s) => std::str::from_utf8(s.0.as_slice()).ok(),
        _ => None,
    }
}

fn entry_type_name(k: &LedgerKey) -> &'static str {
    match k {
        LedgerKey::Account(_) => "account",
        LedgerKey::Trustline(_) => "trustline",
        LedgerKey::Offer(_) => "offer",
        LedgerKey::Data(_) => "data",
        LedgerKey::ClaimableBalance(_) => "claimable_balance",
        LedgerKey::LiquidityPool(_) => "liquidity_pool",
        LedgerKey::ContractData(_) => "contract_data",
        LedgerKey::ContractCode(_) => "contract_code",
        LedgerKey::ConfigSetting(_) => "config_setting",
        LedgerKey::Ttl(_) => "ttl",
    }
}

fn is_classic(d: &LedgerEntryData) -> bool {
    matches!(
        d,
        LedgerEntryData::Account(_)
            | LedgerEntryData::Trustline(_)
            | LedgerEntryData::Offer(_)
            | LedgerEntryData::Data(_)
            | LedgerEntryData::ClaimableBalance(_)
            | LedgerEntryData::LiquidityPool(_)
    )
}

fn entry_sponsor(e: &LedgerEntry) -> Option<String> {
    match &e.ext {
        LedgerEntryExt::V1(v1) => v1.sponsoring_id.0.as_ref().map(account_strkey),
        LedgerEntryExt::V0 => None,
    }
}

fn account_v2(a: &AccountEntry) -> Option<&stellar_xdr::AccountEntryExtensionV2> {
    match &a.ext {
        AccountEntryExt::V1(v1) => match &v1.ext {
            AccountEntryExtensionV1Ext::V2(v2) => Some(v2),
            AccountEntryExtensionV1Ext::V0 => None,
        },
        AccountEntryExt::V0 => None,
    }
}

// ----------------------------------------------------------------------------------------------
// Output vocabulary
// ----------------------------------------------------------------------------------------------

/// An address as the manifest's `account` object.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AccountRef {
    /// Base address.
    pub address: String,
    /// Muxed ID (decimal) when the event carried one (movements only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub muxed_id: Option<String>,
}

impl AccountRef {
    fn new(address: String) -> Self {
        AccountRef {
            address,
            muxed_id: None,
        }
    }
}

/// A participant (`participants.must_include` item).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Participant {
    /// Base address.
    pub address: String,
    /// Muxed ID from the envelope (an alias, never an identity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub muxed_id: Option<String>,
    /// The envelope's muxed form of the address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_chain_form: Option<String>,
    /// Why the address is a participant.
    pub roles: BTreeSet<String>,
}

/// A `must_not_include` item.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MustNot {
    /// Base address.
    pub address: String,
    /// Why.
    pub because: String,
}

/// A typed signer (`state_changes[].signer`).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SignerFact {
    /// `ed25519`, `pre_auth_tx`, `hash_x`, `ed25519_signed_payload`.
    #[serde(rename = "type")]
    pub type_: String,
    /// Canonical strkey.
    pub key: String,
    /// Payload of a signed-payload signer, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_hex: Option<String>,
    /// Weight (after the change; before it for a removal).
    pub weight: u32,
}

/// A state change.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StateChange {
    /// One of the manifest's state-change kinds.
    pub kind: &'static str,
    /// Apply-order transaction index.
    pub tx_index: usize,
    /// Operation index; absent for transaction-level changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_index: Option<usize>,
    /// Owner of the changed entry.
    pub account: AccountRef,
    /// Asset when the change concerns one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    /// Signer for signer kinds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<SignerFact>,
    /// Fixed detail keys per kind.
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub detail: Map<String, Value>,
    /// The envelope's operation type at that index, or `contract-call`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
}

/// The `routing` of a movement.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Routing {
    /// `absent`, `void`, `u64`, `text`, `bytes`.
    #[serde(rename = "type")]
    pub type_: &'static str,
    /// The value (decimal for u64, text as UTF-8, bytes as hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// A movement.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Movement {
    /// `transfer`, `mint`, `burn`, `clawback`, `fee`, `fee_refund`.
    pub kind: &'static str,
    /// Apply-order transaction index.
    pub tx_index: usize,
    /// Operation index for event-derived movements.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_index: Option<usize>,
    /// `native`, `CODE:ISSUER` or a contract address.
    pub asset: String,
    /// Decimal amount in the asset's smallest unit.
    pub amount: String,
    /// Source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<AccountRef>,
    /// Destination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<AccountRef>,
    /// The event's `to_muxed_id`, typed; absent for fee movements.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing: Option<Routing>,
    /// Only on proposed must-not movements: `0`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
}

/// Something the author must look at.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Flag {
    /// `forged_asset_claim`, `sac_asset_topic_mismatch`, `fee_event_disagrees`,
    /// `sac_event_address_without_entry_change`, `balance_delta_ambiguous`, `muxed_alias_conflict`.
    pub kind: &'static str,
    /// Operation index when the flag concerns one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_index: Option<usize>,
    /// Human-readable detail.
    pub detail: String,
}

/// An address an event of a non-asset contract named; not a participant.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NamedByContract {
    /// Base address in the topic.
    pub address: String,
    /// The emitting contract.
    pub contract: String,
    /// Event kind.
    pub event: String,
    /// Operation index.
    pub op_index: usize,
}

/// Whole-ledger counts (`manifest.md` §6.2).
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct LedgerCounts {
    /// Length of the transaction processing list.
    pub transactions: usize,
    /// Operations in the envelopes (inner transaction for fee bumps).
    pub operations: usize,
    /// Transaction-level plus operation-level events (Soroban meta events for v3); no diagnostics.
    pub events: usize,
    /// Every ledger-entry change, upgrades included.
    pub entry_changes: usize,
}

/// One `expect.transactions[]` item.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TxSummary {
    /// Apply-order index.
    pub index: usize,
    /// Hex hash.
    pub hash: String,
    /// Result arm is `tx_success` or `tx_fee_bump_inner_success`.
    pub successful: bool,
    /// Result arm, XDR-JSON name.
    pub result_code: String,
    /// `<operation>.<code>` per operation (inner results for fee bumps).
    pub operation_result_codes: Vec<String>,
    /// Decimal fee charged.
    pub fee_charged: String,
    /// Fee bumps: inner transaction hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner_hash: Option<String>,
    /// Fee bumps: inner success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner_successful: Option<bool>,
    /// Fee bumps: inner result arm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner_result_code: Option<String>,
}

/// Everything derived for one transaction.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TxFacts {
    /// Apply-order index.
    pub index: usize,
    /// Hex hash.
    pub hash: String,
    /// Participants established by meta (envelope aliases attached).
    pub participants: Vec<Participant>,
    /// Must-not candidates (envelope-only addresses) and proposals from forged events.
    pub must_not_include: Vec<MustNot>,
    /// State changes.
    pub state_changes: Vec<StateChange>,
    /// Movements.
    pub movements: Vec<Movement>,
    /// Proposed `count: 0` movements (forged asset claims).
    pub proposed_must_not_movements: Vec<Movement>,
    /// Addresses named by events of contracts that are not the named asset's contract.
    pub named_by_contract: Vec<NamedByContract>,
    /// Items for the author.
    pub flags: Vec<Flag>,
    /// `events` (fee events present, so classic events were emitted) or `balance_deltas`.
    pub movement_basis: &'static str,
    /// `agree`, `absent` or `disagree`.
    pub fee_events: &'static str,
}

/// The extractor's output for one ledger.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Extraction {
    /// Whole-ledger counts.
    pub ledger: LedgerCounts,
    /// Every transaction, apply order.
    pub transactions: Vec<TxSummary>,
    /// Facts per transaction, apply order.
    pub txs: Vec<TxFacts>,
}

impl Extraction {
    /// The focus transaction's facts in the manifest's `expect` vocabulary, with the whole-ledger
    /// counts and transaction list, and the extractor's own notes under `extractor`.
    pub fn expect_json(&self, focus: usize) -> Value {
        // A ledger with no transactions (an empty or upgrade-only ledger) has only ledger facts.
        let Some(tx) = self.txs.get(focus) else {
            return json!({
                "expect": {
                    "ledger": json_of(&self.ledger),
                    "transactions": json_of(&self.transactions),
                },
                "extractor": {},
            });
        };
        let mut mv: Vec<Value> = tx.movements.iter().map(json_of).collect();
        mv.extend(tx.proposed_must_not_movements.iter().map(json_of));
        json!({
            "expect": {
                "ledger": json_of(&self.ledger),
                "transactions": json_of(&self.transactions),
                "participants": {
                    "must_include": json_of(&tx.participants),
                    "must_not_include": json_of(&tx.must_not_include),
                },
                "state_changes": json_of(&tx.state_changes),
                "movements": mv,
            },
            "extractor": {
                "tx_index": tx.index,
                "tx_hash": tx.hash,
                "movement_basis": tx.movement_basis,
                "fee_events": tx.fee_events,
                "named_by_contract": json_of(&tx.named_by_contract),
                "flags": json_of(&tx.flags),
            }
        })
    }
}

// ----------------------------------------------------------------------------------------------
// Reading the ledger
// ----------------------------------------------------------------------------------------------

/// One transaction's pieces of a `LedgerCloseMeta`, version-independent.
struct TxView<'a> {
    result: &'a TransactionResultPair,
    fee: &'a LedgerEntryChanges,
    meta: &'a TransactionMeta,
    post: Option<&'a LedgerEntryChanges>,
}

fn tx_views(lcm: &LedgerCloseMeta) -> Vec<TxView<'_>> {
    match lcm {
        LedgerCloseMeta::V0(v) => v
            .tx_processing
            .iter()
            .map(|t| TxView {
                result: &t.result,
                fee: &t.fee_processing,
                meta: &t.tx_apply_processing,
                post: None,
            })
            .collect(),
        LedgerCloseMeta::V1(v) => v
            .tx_processing
            .iter()
            .map(|t| TxView {
                result: &t.result,
                fee: &t.fee_processing,
                meta: &t.tx_apply_processing,
                post: None,
            })
            .collect(),
        LedgerCloseMeta::V2(v) => v
            .tx_processing
            .iter()
            .map(|t| TxView {
                result: &t.result,
                fee: &t.fee_processing,
                meta: &t.tx_apply_processing,
                post: Some(&t.post_tx_apply_fee_processing),
            })
            .collect(),
    }
}

fn generalized_envelopes(s: &GeneralizedTransactionSet) -> Vec<&TransactionEnvelope> {
    let GeneralizedTransactionSet::V1(set) = s;
    let mut out = Vec::new();
    for phase in set.phases.iter() {
        match phase {
            TransactionPhase::V0(components) => {
                for c in components.iter() {
                    let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) = c;
                    out.extend(c.txs.iter());
                }
            }
            TransactionPhase::V1(p) => {
                for stage in p.execution_stages.iter() {
                    for cluster in stage.0.iter() {
                        out.extend(cluster.0.iter());
                    }
                }
            }
        }
    }
    out
}

fn envelopes(lcm: &LedgerCloseMeta) -> Vec<&TransactionEnvelope> {
    match lcm {
        LedgerCloseMeta::V0(v) => v.tx_set.txs.iter().collect(),
        LedgerCloseMeta::V1(v) => generalized_envelopes(&v.tx_set),
        LedgerCloseMeta::V2(v) => generalized_envelopes(&v.tx_set),
    }
}

fn upgrade_changes(lcm: &LedgerCloseMeta) -> usize {
    match lcm {
        LedgerCloseMeta::V0(v) => v
            .upgrades_processing
            .iter()
            .map(|u| u.changes.0.len())
            .sum(),
        LedgerCloseMeta::V1(v) => v
            .upgrades_processing
            .iter()
            .map(|u| u.changes.0.len())
            .sum(),
        LedgerCloseMeta::V2(v) => v
            .upgrades_processing
            .iter()
            .map(|u| u.changes.0.len())
            .sum(),
    }
}

/// The envelope's parts the extractor may read.
struct Env {
    /// Fee-bump fee source.
    fee_source: Option<MuxedAccount>,
    /// The (inner) transaction source.
    source: MuxedAccount,
    /// The (inner) operations.
    ops: Vec<Operation>,
    /// The Soroban footprint's keys (read-only and read-write). Used only to name the entry a TTL
    /// entry belongs to: a TTL key is the sha256 of that entry's key, so a match is proven by the
    /// hash, not taken on the envelope's word.
    footprint: Vec<LedgerKey>,
}

fn footprint(ext: &stellar_xdr::TransactionExt) -> Vec<LedgerKey> {
    match ext {
        stellar_xdr::TransactionExt::V1(d) => {
            let f = &d.resources.footprint;
            f.read_only
                .iter()
                .chain(f.read_write.iter())
                .cloned()
                .collect()
        }
        stellar_xdr::TransactionExt::V0 => Vec::new(),
    }
}

fn env_parts(e: &TransactionEnvelope) -> Env {
    match e {
        TransactionEnvelope::TxV0(v) => Env {
            fee_source: None,
            source: MuxedAccount::Ed25519(v.tx.source_account_ed25519.clone()),
            ops: v.tx.operations.to_vec(),
            footprint: Vec::new(),
        },
        TransactionEnvelope::Tx(v) => Env {
            fee_source: None,
            source: v.tx.source_account.clone(),
            ops: v.tx.operations.to_vec(),
            footprint: footprint(&v.tx.ext),
        },
        TransactionEnvelope::TxFeeBump(v) => {
            let stellar_xdr::FeeBumpTransactionInnerTx::Tx(inner) = &v.tx.inner_tx;
            Env {
                fee_source: Some(v.tx.fee_source.clone()),
                source: inner.tx.source_account.clone(),
                ops: inner.tx.operations.to_vec(),
                footprint: footprint(&inner.tx.ext),
            }
        }
    }
}

/// Contract-data and contract-code keys the transaction touched (any change list, and the
/// footprint), by the sha256 of their XDR — the key of their TTL entry.
fn ttl_owners(lists: &[&LedgerEntryChanges], env: &Env) -> BTreeMap<[u8; 32], LedgerKey> {
    let mut out = BTreeMap::new();
    let mut add = |k: LedgerKey| {
        if matches!(k, LedgerKey::ContractData(_) | LedgerKey::ContractCode(_)) {
            if let Ok(b) = k.to_xdr(Limits::none()) {
                out.insert(Sha256::digest(b).into(), k);
            }
        }
    };
    for l in lists {
        for c in l.0.iter() {
            match c {
                LedgerEntryChange::State(e)
                | LedgerEntryChange::Created(e)
                | LedgerEntryChange::Updated(e)
                | LedgerEntryChange::Restored(e) => add(e.to_key()),
                LedgerEntryChange::Removed(k) => add(k.clone()),
            }
        }
    }
    for k in &env.footprint {
        add(k.clone());
    }
    out
}

/// Operation-level change lists and events, and transaction-level events, of one meta.
struct MetaParts<'a> {
    before: Vec<&'a LedgerEntryChanges>,
    after: Option<&'a LedgerEntryChanges>,
    ops: Vec<&'a LedgerEntryChanges>,
    op_events: Vec<Vec<&'a ContractEvent>>,
    tx_events: Vec<&'a ContractEvent>,
}

fn meta_parts(m: &TransactionMeta) -> MetaParts<'_> {
    let mut p = MetaParts {
        before: Vec::new(),
        after: None,
        ops: Vec::new(),
        op_events: Vec::new(),
        tx_events: Vec::new(),
    };
    match m {
        TransactionMeta::V0(ops) => p.ops = ops.iter().map(|o| &o.changes).collect(),
        TransactionMeta::V1(v) => {
            p.before.push(&v.tx_changes);
            p.ops = v.operations.iter().map(|o| &o.changes).collect();
        }
        TransactionMeta::V2(v) => {
            p.before.push(&v.tx_changes_before);
            p.after = Some(&v.tx_changes_after);
            p.ops = v.operations.iter().map(|o| &o.changes).collect();
        }
        TransactionMeta::V3(v) => {
            p.before.push(&v.tx_changes_before);
            p.after = Some(&v.tx_changes_after);
            p.ops = v.operations.iter().map(|o| &o.changes).collect();
            // A Soroban transaction has exactly one operation; its events are that operation's.
            if let Some(s) = &v.soroban_meta {
                p.op_events = vec![s.events.iter().collect()];
            }
        }
        TransactionMeta::V4(v) => {
            p.before.push(&v.tx_changes_before);
            p.after = Some(&v.tx_changes_after);
            p.ops = v.operations.iter().map(|o| &o.changes).collect();
            p.op_events = v
                .operations
                .iter()
                .map(|o| o.events.iter().collect())
                .collect();
            p.tx_events = v.events.iter().map(|e| &e.event).collect();
        }
    }
    p.op_events
        .resize_with(p.ops.len().max(p.op_events.len()), Vec::new);
    p
}

/// A paired transition of one ledger entry inside one change list.
enum Transition<'a> {
    Created(&'a LedgerEntry),
    Updated(Option<&'a LedgerEntry>, &'a LedgerEntry),
    Removed(Option<&'a LedgerEntry>, &'a LedgerKey),
    Restored(&'a LedgerEntry),
}

fn transitions(changes: &LedgerEntryChanges) -> Vec<Transition<'_>> {
    let mut pre: BTreeMap<LedgerKey, &LedgerEntry> = BTreeMap::new();
    let mut out = Vec::new();
    for c in changes.0.iter() {
        match c {
            LedgerEntryChange::State(e) => {
                pre.insert(e.to_key(), e);
            }
            LedgerEntryChange::Created(e) => out.push(Transition::Created(e)),
            LedgerEntryChange::Updated(e) => {
                out.push(Transition::Updated(pre.get(&e.to_key()).copied(), e))
            }
            LedgerEntryChange::Removed(k) => out.push(Transition::Removed(pre.get(k).copied(), k)),
            LedgerEntryChange::Restored(e) => {
                pre.insert(e.to_key(), e);
                out.push(Transition::Restored(e));
            }
        }
    }
    out
}

/// Every address string an XDR-JSON value names (G, M, C, B, L strkeys), as base addresses.
fn addresses_in(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::String(s) if matches!(s.len(), 56 | 58 | 69) => {
            if let Ok(a) = s.parse::<ScAddress>() {
                out.insert(base_address(&a));
            }
        }
        Value::Array(a) => a.iter().for_each(|x| addresses_in(x, out)),
        Value::Object(m) => m.values().for_each(|x| addresses_in(x, out)),
        _ => {}
    }
}

// ----------------------------------------------------------------------------------------------
// Per-transaction derivation
// ----------------------------------------------------------------------------------------------

struct Builder<'a> {
    index: usize,
    network_id: [u8; 32],
    env: &'a Env,
    participants: Vec<Participant>,
    state_changes: Vec<StateChange>,
    movements: Vec<Movement>,
    proposed: Vec<Movement>,
    must_not: Vec<MustNot>,
    named: Vec<NamedByContract>,
    flags: Vec<Flag>,
    /// The account whose sequence number the transaction moved (meta-established). Changes to
    /// entries with no address of their own (contract code, an unresolved TTL) are attributed to it.
    source: Option<String>,
    /// TTL key → the contract-data or contract-code key it belongs to.
    ttl_owners: BTreeMap<[u8; 32], LedgerKey>,
    /// Accounts named as claimants of a claimable balance this transaction created or claimed.
    claimants: BTreeSet<String>,
}

/// The role of a participant that is a pool or balance entry's own address.
fn entry_role(address: &str) -> Option<&'static str> {
    match address.as_bytes().first() {
        Some(b'L') => Some("liquidity_pool"),
        Some(b'B') => Some("claimable_balance"),
        _ => None,
    }
}

fn claimant_accounts(cb: &stellar_xdr::ClaimableBalanceEntry) -> Vec<String> {
    cb.claimants
        .iter()
        .map(|c| {
            let stellar_xdr::Claimant::ClaimantTypeV0(v) = c;
            account_strkey(&v.destination)
        })
        .collect()
}

impl Builder<'_> {
    fn role(&mut self, address: &str, role: Option<&str>) {
        let p = match self.participants.iter_mut().find(|p| p.address == address) {
            Some(p) => p,
            None => {
                self.participants.push(Participant {
                    address: address.to_string(),
                    muxed_id: None,
                    on_chain_form: None,
                    roles: BTreeSet::new(),
                });
                self.participants.last_mut().unwrap()
            }
        };
        if let Some(r) = role {
            p.roles.insert(r.to_string());
        }
    }

    fn is_participant(&self, address: &str) -> bool {
        self.participants.iter().any(|p| p.address == address)
    }

    #[allow(clippy::too_many_arguments)]
    fn change(
        &mut self,
        kind: &'static str,
        op_index: Option<usize>,
        account: String,
        asset: Option<String>,
        signer: Option<SignerFact>,
        detail: Map<String, Value>,
        cause: Option<String>,
    ) {
        self.state_changes.push(StateChange {
            kind,
            tx_index: self.index,
            op_index,
            account: AccountRef::new(account),
            asset,
            signer,
            detail,
            cause,
        });
    }

    /// A change to an entry with no address of its own, attributed to the transaction's source.
    /// Without a meta-established source the change cannot be attributed and is flagged instead.
    fn source_change(
        &mut self,
        kind: &'static str,
        op_index: Option<usize>,
        detail: Map<String, Value>,
        cause: Option<String>,
    ) {
        match self.source.clone() {
            Some(s) => self.change(kind, op_index, s, None, None, detail, cause),
            None => self.flags.push(Flag {
                kind: "unattributed_change",
                op_index,
                detail: format!("{kind} with no account whose sequence number moved"),
            }),
        }
    }

    fn cause(&self, op_index: usize, data: &LedgerEntryData) -> Option<String> {
        let op = self.env.ops.get(op_index)?;
        if matches!(op.body, OperationBody::InvokeHostFunction(_)) && is_classic(data) {
            return Some("contract-call".into());
        }
        Some(arm(&json_of(&op.body)))
    }
}

fn signer_fact(key: &SignerKey, weight: u32) -> (SignerFact, Map<String, Value>) {
    let mut detail = Map::new();
    detail.insert("signer_key_xdr_hex".into(), json!(xdr_hex(key)));
    let (type_, payload_hex) = match key {
        SignerKey::Ed25519(k) => {
            detail.insert(
                "signer_ed25519_key".into(),
                json!(AccountId(PublicKey::PublicKeyTypeEd25519(k.clone())).to_string()),
            );
            ("ed25519", None)
        }
        SignerKey::PreAuthTx(_) => ("pre_auth_tx", None),
        SignerKey::HashX(_) => ("hash_x", None),
        SignerKey::Ed25519SignedPayload(p) => {
            detail.insert(
                "signer_ed25519_key".into(),
                json!(AccountId(PublicKey::PublicKeyTypeEd25519(p.ed25519.clone())).to_string()),
            );
            detail.insert("payload_bytes".into(), json!(p.payload.len()));
            (
                "ed25519_signed_payload",
                Some(hex::encode(p.payload.as_slice())),
            )
        }
    };
    (
        SignerFact {
            type_: type_.into(),
            key: key.to_string(),
            payload_hex,
            weight,
        },
        detail,
    )
}

fn signer_sponsors(a: &AccountEntry) -> Vec<Option<String>> {
    match account_v2(a) {
        Some(v2) => v2
            .signer_sponsoring_i_ds
            .iter()
            .map(|s| s.0.as_ref().map(account_strkey))
            .collect(),
        None => vec![None; a.signers.len()],
    }
}

/// Signer differences between two versions of an account.
fn signer_diff(
    b: &mut Builder<'_>,
    op_index: Option<usize>,
    before: &AccountEntry,
    after: &AccountEntry,
    cause: Option<String>,
) -> bool {
    let owner = account_strkey(&after.account_id);
    let old: BTreeMap<Vec<u8>, (u32, Option<String>, &SignerKey)> = before
        .signers
        .iter()
        .zip(signer_sponsors(before))
        .map(|(s, sp)| (xdr_hex(&s.key).into_bytes(), (s.weight, sp, &s.key)))
        .collect();
    let new: BTreeMap<Vec<u8>, (u32, Option<String>, &SignerKey)> = after
        .signers
        .iter()
        .zip(signer_sponsors(after))
        .map(|(s, sp)| (xdr_hex(&s.key).into_bytes(), (s.weight, sp, &s.key)))
        .collect();
    let mut any = false;
    for (k, (w, sp, key)) in &new {
        match old.get(k) {
            None => {
                let (fact, mut detail) = signer_fact(key, *w);
                if let Some(s) = sp {
                    detail.insert("sponsor".into(), json!(s));
                }
                b.change(
                    "signer_added",
                    op_index,
                    owner.clone(),
                    None,
                    Some(fact),
                    detail,
                    cause.clone(),
                );
                any = true;
            }
            Some((w0, _, _)) if w0 != w => {
                let (fact, mut detail) = signer_fact(key, *w);
                detail.insert("weight_before".into(), json!(w0));
                if let Some(s) = sp {
                    detail.insert("sponsor".into(), json!(s));
                }
                b.change(
                    "signer_changed",
                    op_index,
                    owner.clone(),
                    None,
                    Some(fact),
                    detail,
                    cause.clone(),
                );
                any = true;
            }
            _ => {}
        }
    }
    for (k, (w, sp, key)) in &old {
        if !new.contains_key(k) {
            let (fact, mut detail) = signer_fact(key, *w);
            detail.insert("weight_before".into(), json!(w));
            if let Some(s) = sp {
                detail.insert("sponsor".into(), json!(s));
            }
            b.change(
                "signer_removed",
                op_index,
                owner.clone(),
                None,
                Some(fact),
                detail,
                cause.clone(),
            );
            any = true;
        }
    }
    if any {
        b.role(&owner, Some("signer_owner"));
    }
    any
}

fn trustline_flags(flags: u32) -> Map<String, Value> {
    let mut d = Map::new();
    d.insert("flags".into(), json!(flags));
    d.insert("authorized".into(), json!(flags & 1 != 0));
    d.insert(
        "authorized_to_maintain_liabilities".into(),
        json!(flags & 2 != 0),
    );
    d.insert("clawback_enabled".into(), json!(flags & 4 != 0));
    d
}

fn issuer_key_hex(a: &Asset) -> Option<String> {
    let issuer = match a {
        Asset::Native => return None,
        Asset::CreditAlphanum4(x) => &x.issuer,
        Asset::CreditAlphanum12(x) => &x.issuer,
    };
    let PublicKey::PublicKeyTypeEd25519(Uint256(k)) = &issuer.0;
    Some(hex::encode(k))
}

fn pool_detail(p: &stellar_xdr::LiquidityPoolEntry) -> Map<String, Value> {
    let stellar_xdr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) = &p.body;
    let mut d = Map::new();
    d.insert(
        "pool_id".into(),
        json!(hex::encode(p.liquidity_pool_id.0 .0)),
    );
    d.insert(
        "pool_strkey".into(),
        json!(pool_strkey(&p.liquidity_pool_id)),
    );
    d.insert("asset_a".into(), json!(asset_string(&cp.params.asset_a)));
    d.insert("asset_b".into(), json!(asset_string(&cp.params.asset_b)));
    d.insert("fee_bp".into(), json!(cp.params.fee));
    d.insert("reserve_a".into(), json!(cp.reserve_a.to_string()));
    d.insert("reserve_b".into(), json!(cp.reserve_b.to_string()));
    d.insert(
        "total_shares".into(),
        json!(cp.total_pool_shares.to_string()),
    );
    d.insert(
        "pool_shares_trust_line_count".into(),
        json!(cp.pool_shares_trust_line_count.to_string()),
    );
    if let Some(h) = issuer_key_hex(&cp.params.asset_a) {
        d.insert("asset_a_issuer_key_hex".into(), json!(h));
    }
    if let Some(h) = issuer_key_hex(&cp.params.asset_b) {
        d.insert("asset_b_issuer_key_hex".into(), json!(h));
    }
    d
}

fn is_nonce(e: &stellar_xdr::ContractDataEntry) -> bool {
    matches!(e.key, ScVal::LedgerKeyNonce(_))
}

fn durability(d: ContractDataDurability) -> &'static str {
    match d {
        ContractDataDurability::Temporary => "temporary",
        ContractDataDurability::Persistent => "persistent",
    }
}

fn cb_strkey(id: &ClaimableBalanceId) -> String {
    id.to_string()
}

/// Step 5: classify one operation's change list.
fn classify_op(b: &mut Builder<'_>, op_index: usize, changes: &LedgerEntryChanges) {
    let trs = transitions(changes);
    // Accounts' number of sub-entries after this operation, for `num_sub_entries_after`.
    let mut sub_entries: BTreeMap<String, u32> = BTreeMap::new();
    for t in &trs {
        if let Transition::Updated(_, e) | Transition::Created(e) = t {
            if let LedgerEntryData::Account(a) = &e.data {
                sub_entries.insert(account_strkey(&a.account_id), a.num_sub_entries);
            }
        }
    }
    // Native balance increases inside this operation (for `merged_into`).
    let mut credited: Vec<(String, i64)> = Vec::new();
    for t in &trs {
        if let Transition::Updated(Some(pre), post) = t {
            if let (LedgerEntryData::Account(a0), LedgerEntryData::Account(a1)) =
                (&pre.data, &post.data)
            {
                if a1.balance > a0.balance {
                    credited.push((account_strkey(&a1.account_id), a1.balance - a0.balance));
                }
            }
        }
    }
    let op = Some(op_index);
    for t in &trs {
        let (data, key) = match t {
            Transition::Created(e) | Transition::Updated(_, e) | Transition::Restored(e) => {
                (Some(&e.data), e.to_key())
            }
            Transition::Removed(pre, k) => (pre.map(|p| &p.data), (*k).clone()),
        };
        let cause = data.and_then(|d| b.cause(op_index, d));
        match t {
            Transition::Restored(e) => match &e.data {
                LedgerEntryData::ContractData(cd) => {
                    let owner = base_address(&cd.contract);
                    let mut d = Map::new();
                    d.insert("entry_type".into(), json!(entry_type_name(&key)));
                    d.insert("key_xdr_hex".into(), json!(xdr_hex(&key)));
                    b.change("entry_restored", op, owner.clone(), None, None, d, cause);
                    b.role(&owner, Some("contract"));
                }
                // Contract code has no address: the restore is attributed to the source.
                LedgerEntryData::ContractCode(c) => {
                    let mut d = Map::new();
                    d.insert("entry_type".into(), json!(entry_type_name(&key)));
                    d.insert("key_xdr_hex".into(), json!(xdr_hex(&key)));
                    d.insert("wasm_hash".into(), json!(hex::encode(c.hash.0)));
                    b.source_change("entry_restored", op, d, cause);
                }
                // Only contract data and code are archived, so nothing else is restored. Every type
                // is named: a new entry type does not compile until it is considered here.
                LedgerEntryData::Account(_)
                | LedgerEntryData::Trustline(_)
                | LedgerEntryData::Offer(_)
                | LedgerEntryData::Data(_)
                | LedgerEntryData::ClaimableBalance(_)
                | LedgerEntryData::LiquidityPool(_)
                | LedgerEntryData::ConfigSetting(_)
                | LedgerEntryData::Ttl(_) => {}
            },
            Transition::Created(e) => classify_created(b, op_index, e, cause, &sub_entries),
            Transition::Updated(pre, e) => classify_updated(b, op_index, *pre, e, cause),
            Transition::Removed(pre, _) => {
                if let Some(pre) = pre {
                    classify_removed(b, op_index, pre, cause, &credited);
                }
            }
        }
    }
}

fn classify_created(
    b: &mut Builder<'_>,
    op_index: usize,
    e: &LedgerEntry,
    cause: Option<String>,
    sub_entries: &BTreeMap<String, u32>,
) {
    let op = Some(op_index);
    let sponsor = entry_sponsor(e);
    if let Some(s) = &sponsor {
        b.role(s, Some("sponsor"));
    }
    match &e.data {
        LedgerEntryData::Account(a) => {
            let owner = account_strkey(&a.account_id);
            let mut d = Map::new();
            d.insert("starting_balance".into(), json!(a.balance.to_string()));
            if let Some(s) = sponsor {
                d.insert("sponsor".into(), json!(s));
            }
            b.change("account_created", op, owner.clone(), None, None, d, cause);
            b.role(&owner, Some("destination"));
        }
        LedgerEntryData::Trustline(t) => {
            let owner = account_strkey(&t.account_id);
            let mut d = Map::new();
            d.insert("balance".into(), json!(t.balance.to_string()));
            d.insert("limit".into(), json!(t.limit.to_string()));
            d.extend(trustline_flags(t.flags));
            if let Some(s) = sponsor {
                d.insert("sponsor".into(), json!(s));
            }
            if let Some(n) = sub_entries.get(&owner) {
                d.insert("num_sub_entries_after".into(), json!(n));
            }
            if let TrustLineAsset::PoolShare(id) = &t.asset {
                d.insert("pool_strkey".into(), json!(pool_strkey(id)));
            }
            b.change(
                "trustline_created",
                op,
                owner.clone(),
                Some(trustline_asset_string(&t.asset)),
                None,
                d,
                cause,
            );
            b.role(&owner, Some("trustline_owner"));
        }
        LedgerEntryData::Offer(o) => offer_change(b, op_index, o, "created", cause),
        LedgerEntryData::Data(de) => data_change(b, op_index, de, "created", cause),
        LedgerEntryData::ClaimableBalance(cb) => {
            let id = cb_strkey(&cb.balance_id);
            let mut d = Map::new();
            d.insert("balance_id".into(), json!(id));
            d.insert("amount".into(), json!(cb.amount.to_string()));
            d.insert("claimants".into(), json!(cb.claimants.len()));
            if let Some(s) = sponsor {
                d.insert("sponsor".into(), json!(s));
            }
            b.change(
                "claimable_balance_created",
                op,
                id.clone(),
                Some(asset_string(&cb.asset)),
                None,
                d,
                cause,
            );
            b.role(&id, Some("claimable_balance"));
            b.claimants.extend(claimant_accounts(cb));
        }
        LedgerEntryData::LiquidityPool(p) => {
            let id = pool_strkey(&p.liquidity_pool_id);
            b.change(
                "liquidity_pool_created",
                op,
                id.clone(),
                None,
                None,
                pool_detail(p),
                cause,
            );
            b.role(&id, Some("liquidity_pool"));
        }
        LedgerEntryData::ContractData(cd) => {
            let owner = base_address(&cd.contract);
            if is_nonce(cd) {
                // A created nonce entry proves this address authenticated (VF-48).
                b.role(&owner, Some("authorizer"));
                return;
            }
            if let ScVal::ContractInstance(inst) = &cd.val {
                if matches!(cd.key, ScVal::LedgerKeyContractInstance) {
                    let mut d = Map::new();
                    d.insert("contract".into(), json!(owner));
                    match &inst.executable {
                        ContractExecutable::Wasm(h) => {
                            d.insert("executable".into(), json!("wasm"));
                            d.insert("wasm_hash".into(), json!(hex::encode(h.0)));
                        }
                        ContractExecutable::StellarAsset => {
                            d.insert("executable".into(), json!("stellar_asset"));
                        }
                        other => {
                            d.insert("executable".into(), json!(arm(&json_of(other))));
                        }
                    }
                    b.change("contract_deployed", op, owner.clone(), None, None, d, cause);
                    b.role(&owner, Some("contract"));
                    return;
                }
            }
            contract_data_change(b, op_index, cd, "created", cause);
        }
        // Contract code has no address of its own: the upload is attributed to the source.
        LedgerEntryData::ContractCode(c) => {
            let mut d = Map::new();
            d.insert("wasm_hash".into(), json!(hex::encode(c.hash.0)));
            d.insert("code_bytes".into(), json!(c.code.len()));
            b.source_change("contract_code_created", op, d, cause);
        }
        // A new entry's TTL is part of its creation; settings are bookkeeping.
        LedgerEntryData::Ttl(_) | LedgerEntryData::ConfigSetting(_) => {}
    }
}

fn classify_updated(
    b: &mut Builder<'_>,
    op_index: usize,
    pre: Option<&LedgerEntry>,
    e: &LedgerEntry,
    cause: Option<String>,
) {
    let op = Some(op_index);
    let Some(pre) = pre else {
        // An update with no preceding state: core always writes the pair, so note it.
        b.flags.push(Flag {
            kind: "unpaired_update",
            op_index: op,
            detail: format!(
                "{} updated without a preceding state",
                entry_type_name(&e.to_key())
            ),
        });
        return;
    };
    let (s0, s1) = (entry_sponsor(pre), entry_sponsor(e));
    let owner_of = |d: &LedgerEntryData| -> Option<String> {
        match d {
            LedgerEntryData::Account(a) => Some(account_strkey(&a.account_id)),
            LedgerEntryData::Trustline(t) => Some(account_strkey(&t.account_id)),
            LedgerEntryData::Offer(o) => Some(account_strkey(&o.seller_id)),
            LedgerEntryData::Data(d) => Some(account_strkey(&d.account_id)),
            LedgerEntryData::ClaimableBalance(c) => Some(cb_strkey(&c.balance_id)),
            LedgerEntryData::LiquidityPool(p) => Some(pool_strkey(&p.liquidity_pool_id)),
            LedgerEntryData::ContractData(c) => Some(base_address(&c.contract)),
            // No sponsorable owner. Named, so a new entry type does not compile until it is
            // considered here.
            LedgerEntryData::ContractCode(_)
            | LedgerEntryData::ConfigSetting(_)
            | LedgerEntryData::Ttl(_) => None,
        }
    };
    if s0 != s1 {
        if let Some(owner) = owner_of(&e.data) {
            let mut d = Map::new();
            d.insert("entry_type".into(), json!(entry_type_name(&e.to_key())));
            if let Some(s) = &s0 {
                d.insert("sponsor_before".into(), json!(s));
                b.role(s, Some("sponsor"));
            }
            if let Some(s) = &s1 {
                d.insert("sponsor_after".into(), json!(s));
                b.role(s, Some("sponsor"));
            }
            b.change(
                "sponsorship_changed",
                op,
                owner.clone(),
                None,
                None,
                d,
                cause.clone(),
            );
            b.role(&owner, entry_role(&owner));
        }
    }
    match (&pre.data, &e.data) {
        (LedgerEntryData::Account(a0), LedgerEntryData::Account(a1)) => {
            let owner = account_strkey(&a1.account_id);
            if a0.balance != a1.balance {
                let mut d = Map::new();
                d.insert("delta".into(), json!((a1.balance - a0.balance).to_string()));
                d.insert("balance_after".into(), json!(a1.balance.to_string()));
                b.change(
                    "balance_changed",
                    op,
                    owner.clone(),
                    Some("native".into()),
                    None,
                    d,
                    cause.clone(),
                );
            }
            signer_diff(b, op, a0, a1, cause.clone());
            if a0.thresholds != a1.thresholds {
                let t = a1.thresholds.0;
                let mut d = Map::new();
                d.insert("master_weight".into(), json!(t[0]));
                d.insert("low".into(), json!(t[1]));
                d.insert("medium".into(), json!(t[2]));
                d.insert("high".into(), json!(t[3]));
                b.change(
                    "thresholds_changed",
                    op,
                    owner.clone(),
                    None,
                    None,
                    d,
                    cause.clone(),
                );
            }
            account_fields(b, op, &owner, a0, a1, cause);
            // Sponsoring counters: the account is a sponsor.
            let counters = |a: &AccountEntry| account_v2(a).map(|v| v.num_sponsoring).unwrap_or(0);
            if counters(a1) > counters(a0) {
                b.role(&owner, Some("sponsor"));
            }
            // A sub-entry-count or sequence-ledger change alone has no state-change kind; the
            // account is still affected.
            b.role(&owner, None);
        }
        (LedgerEntryData::Ttl(t0), LedgerEntryData::Ttl(t1))
            if t1.live_until_ledger_seq > t0.live_until_ledger_seq =>
        {
            ttl_extended(b, op, t0, t1, cause)
        }
        (LedgerEntryData::Trustline(t0), LedgerEntryData::Trustline(t1)) => {
            let owner = account_strkey(&t1.account_id);
            let asset = trustline_asset_string(&t1.asset);
            if t0.balance != t1.balance {
                let mut d = Map::new();
                d.insert("delta".into(), json!((t1.balance - t0.balance).to_string()));
                d.insert("balance_after".into(), json!(t1.balance.to_string()));
                b.change(
                    "balance_changed",
                    op,
                    owner.clone(),
                    Some(asset.clone()),
                    None,
                    d,
                    cause.clone(),
                );
            }
            if t0.flags != t1.flags {
                b.change(
                    "trustline_flags_changed",
                    op,
                    owner.clone(),
                    Some(asset.clone()),
                    None,
                    trustline_flags(t1.flags),
                    cause.clone(),
                );
            }
            if t0.limit != t1.limit {
                let mut d = Map::new();
                d.insert("limit".into(), json!(t1.limit.to_string()));
                d.insert("limit_before".into(), json!(t0.limit.to_string()));
                b.change(
                    "trustline_limit_changed",
                    op,
                    owner.clone(),
                    Some(asset),
                    None,
                    d,
                    cause,
                );
            }
            b.role(&owner, Some("trustline_owner"));
        }
        (LedgerEntryData::Offer(_), LedgerEntryData::Offer(o)) => {
            offer_change(b, op_index, o, "updated", cause)
        }
        (LedgerEntryData::Data(d0), LedgerEntryData::Data(d)) => {
            // Like trustline limits and thresholds: an update that writes the same value back
            // is no state change. The owner is still affected.
            if d0.data_value != d.data_value {
                data_change(b, op_index, d, "updated", cause)
            } else {
                b.role(&account_strkey(&d.account_id), None);
            }
        }
        (LedgerEntryData::LiquidityPool(_), LedgerEntryData::LiquidityPool(p)) => {
            let id = pool_strkey(&p.liquidity_pool_id);
            b.change(
                "liquidity_pool_changed",
                op,
                id.clone(),
                None,
                None,
                pool_detail(p),
                cause,
            );
            b.role(&id, Some("liquidity_pool"));
        }
        (LedgerEntryData::ContractData(_), LedgerEntryData::ContractData(cd)) if !is_nonce(cd) => {
            contract_data_change(b, op_index, cd, "updated", cause);
        }
        // An update must keep its state's type; core never writes otherwise.
        (p, d) if p.discriminant() != d.discriminant() => b.flags.push(Flag {
            kind: "update_type_changed",
            op_index: op,
            detail: format!(
                "{} updated from a {} state",
                d.discriminant().name(),
                p.discriminant().name()
            ),
        }),
        // Updates with no fact of their own: a TTL that did not grow, a nonce, contract code,
        // settings, a claimable balance (never updated in place). The other types are matched
        // above whatever their content. Every type is named: a new entry type does not compile
        // until it is classified here.
        (
            _,
            LedgerEntryData::Ttl(_)
            | LedgerEntryData::ContractData(_)
            | LedgerEntryData::ContractCode(_)
            | LedgerEntryData::ConfigSetting(_)
            | LedgerEntryData::ClaimableBalance(_)
            | LedgerEntryData::Account(_)
            | LedgerEntryData::Trustline(_)
            | LedgerEntryData::Offer(_)
            | LedgerEntryData::Data(_)
            | LedgerEntryData::LiquidityPool(_),
        ) => {}
    }
}

fn classify_removed(
    b: &mut Builder<'_>,
    op_index: usize,
    pre: &LedgerEntry,
    cause: Option<String>,
    credited: &[(String, i64)],
) {
    let op = Some(op_index);
    match &pre.data {
        LedgerEntryData::Account(a) => {
            let owner = account_strkey(&a.account_id);
            let mut d = Map::new();
            d.insert("balance_transferred".into(), json!(a.balance.to_string()));
            let into: Vec<_> = credited
                .iter()
                .filter(|(addr, n)| *n == a.balance && *addr != owner)
                .collect();
            if let [(addr, _)] = into.as_slice() {
                d.insert("merged_into".into(), json!(addr));
            }
            b.change("account_removed", op, owner.clone(), None, None, d, cause);
            b.role(&owner, None);
        }
        LedgerEntryData::Trustline(t) => {
            let owner = account_strkey(&t.account_id);
            let mut d = Map::new();
            d.insert("balance".into(), json!(t.balance.to_string()));
            if let TrustLineAsset::PoolShare(id) = &t.asset {
                d.insert("pool_strkey".into(), json!(pool_strkey(id)));
            }
            b.change(
                "trustline_removed",
                op,
                owner.clone(),
                Some(trustline_asset_string(&t.asset)),
                None,
                d,
                cause,
            );
            b.role(&owner, Some("trustline_owner"));
        }
        LedgerEntryData::Offer(o) => offer_change(b, op_index, o, "removed", cause),
        LedgerEntryData::Data(de) => data_change(b, op_index, de, "removed", cause),
        LedgerEntryData::ClaimableBalance(cb) => {
            let id = cb_strkey(&cb.balance_id);
            let mut d = Map::new();
            d.insert("balance_id".into(), json!(id));
            d.insert("amount".into(), json!(cb.amount.to_string()));
            b.change(
                "claimable_balance_claimed",
                op,
                id.clone(),
                Some(asset_string(&cb.asset)),
                None,
                d,
                cause,
            );
            b.role(&id, Some("claimable_balance"));
            b.claimants.extend(claimant_accounts(cb));
        }
        LedgerEntryData::LiquidityPool(p) => {
            let id = pool_strkey(&p.liquidity_pool_id);
            let mut d = Map::new();
            d.insert(
                "pool_id".into(),
                json!(hex::encode(p.liquidity_pool_id.0 .0)),
            );
            d.insert("pool_strkey".into(), json!(id));
            b.change(
                "liquidity_pool_removed",
                op,
                id.clone(),
                None,
                None,
                d,
                cause,
            );
            b.role(&id, Some("liquidity_pool"));
        }
        LedgerEntryData::ContractData(cd) if !is_nonce(cd) => {
            contract_data_change(b, op_index, cd, "removed", cause);
        }
        // No fact of their own: a nonce, contract code, settings and TTLs. Every type is named: a
        // new entry type does not compile until it is classified here.
        LedgerEntryData::ContractData(_)
        | LedgerEntryData::ContractCode(_)
        | LedgerEntryData::ConfigSetting(_)
        | LedgerEntryData::Ttl(_) => {}
    }
}

/// Account flags, home domain and inflation destination, diffed between two versions of an
/// account.
fn account_fields(
    b: &mut Builder<'_>,
    op: Option<usize>,
    owner: &str,
    a0: &AccountEntry,
    a1: &AccountEntry,
    cause: Option<String>,
) {
    if a0.flags != a1.flags {
        let f = a1.flags;
        let mut d = Map::new();
        d.insert("flags".into(), json!(f));
        d.insert("flags_before".into(), json!(a0.flags));
        d.insert("auth_required".into(), json!(f & 1 != 0));
        d.insert("auth_revocable".into(), json!(f & 2 != 0));
        d.insert("auth_immutable".into(), json!(f & 4 != 0));
        d.insert("auth_clawback_enabled".into(), json!(f & 8 != 0));
        let o = owner.to_string();
        b.change("account_flags_changed", op, o, None, None, d, cause.clone());
    }
    if a0.home_domain != a1.home_domain {
        let (now, before) = (a1.home_domain.as_slice(), a0.home_domain.as_slice());
        let mut d = Map::new();
        d.insert("home_domain_hex".into(), json!(hex::encode(now)));
        // The text forms only where the bytes are UTF-8; the hex is always exact.
        if let Ok(s) = std::str::from_utf8(now) {
            d.insert("home_domain".into(), json!(s));
        }
        if let Ok(s) = std::str::from_utf8(before) {
            d.insert("home_domain_before".into(), json!(s));
        }
        let o = owner.to_string();
        b.change("home_domain_changed", op, o, None, None, d, cause.clone());
    }
    if a0.inflation_dest != a1.inflation_dest {
        let mut d = Map::new();
        match &a1.inflation_dest {
            Some(a) => d.insert("inflation_destination".into(), json!(account_strkey(a))),
            None => d.insert("cleared".into(), json!(true)),
        };
        if let Some(a) = &a0.inflation_dest {
            d.insert(
                "inflation_destination_before".into(),
                json!(account_strkey(a)),
            );
        }
        let o = owner.to_string();
        b.change("inflation_destination_changed", op, o, None, None, d, cause);
    }
}

/// A TTL entry whose `live_until_ledger_seq` grew. The entry it belongs to is found by hash among
/// the keys the transaction touched; a contract-data entry's change is the contract's, contract
/// code's (or an unresolved key's) the source's. It adds no participant: the host extends TTLs as
/// a side effect of access, so the kind is ambient.
fn ttl_extended(
    b: &mut Builder<'_>,
    op: Option<usize>,
    t0: &stellar_xdr::TtlEntry,
    t1: &stellar_xdr::TtlEntry,
    cause: Option<String>,
) {
    let mut d = Map::new();
    d.insert("key_hash".into(), json!(hex::encode(t1.key_hash.0)));
    d.insert("live_until_ledger".into(), json!(t1.live_until_ledger_seq));
    d.insert(
        "live_until_ledger_before".into(),
        json!(t0.live_until_ledger_seq),
    );
    let owner = b.ttl_owners.get(&t1.key_hash.0).cloned();
    if let Some(k) = &owner {
        d.insert("entry_type".into(), json!(entry_type_name(k)));
        d.insert("key_xdr_hex".into(), json!(xdr_hex(k)));
    }
    match owner {
        Some(LedgerKey::ContractData(k)) => {
            let contract = base_address(&k.contract);
            d.insert("contract".into(), json!(contract));
            b.change("ttl_extended", op, contract, None, None, d, cause);
        }
        Some(LedgerKey::ContractCode(k)) => {
            d.insert("wasm_hash".into(), json!(hex::encode(k.hash.0)));
            b.source_change("ttl_extended", op, d, cause);
        }
        _ => b.source_change("ttl_extended", op, d, cause),
    }
}

fn offer_change(
    b: &mut Builder<'_>,
    op_index: usize,
    o: &stellar_xdr::OfferEntry,
    change: &str,
    cause: Option<String>,
) {
    let owner = account_strkey(&o.seller_id);
    let mut d = Map::new();
    d.insert("offer_id".into(), json!(o.offer_id.to_string()));
    d.insert("change".into(), json!(change));
    d.insert("selling".into(), json!(asset_string(&o.selling)));
    d.insert("buying".into(), json!(asset_string(&o.buying)));
    d.insert("amount".into(), json!(o.amount.to_string()));
    d.insert("price_n".into(), json!(o.price.n));
    d.insert("price_d".into(), json!(o.price.d));
    b.change(
        "offer_changed",
        Some(op_index),
        owner.clone(),
        None,
        None,
        d,
        cause,
    );
    // The seller of an offer that some other account's operation crossed is a counterparty; the
    // owner's own offer edits leave the role to the post-pass.
    b.role(&owner, None);
}

fn data_change(
    b: &mut Builder<'_>,
    op_index: usize,
    de: &stellar_xdr::DataEntry,
    change: &str,
    cause: Option<String>,
) {
    let owner = account_strkey(&de.account_id);
    let mut d = Map::new();
    d.insert(
        "name".into(),
        json!(String::from_utf8_lossy(de.data_name.as_slice())),
    );
    d.insert(
        "value_hex".into(),
        json!(hex::encode(de.data_value.as_slice())),
    );
    d.insert("change".into(), json!(change));
    b.change(
        "data_entry_changed",
        Some(op_index),
        owner.clone(),
        None,
        None,
        d,
        cause,
    );
    b.role(&owner, None);
}

fn contract_data_change(
    b: &mut Builder<'_>,
    op_index: usize,
    cd: &stellar_xdr::ContractDataEntry,
    change: &str,
    cause: Option<String>,
) {
    let owner = base_address(&cd.contract);
    let mut d = Map::new();
    d.insert("contract".into(), json!(owner));
    d.insert("key_xdr_hex".into(), json!(xdr_hex(&cd.key)));
    d.insert("durability".into(), json!(durability(cd.durability)));
    d.insert("change".into(), json!(change));
    b.change(
        "contract_data_changed",
        Some(op_index),
        owner.clone(),
        None,
        None,
        d,
        cause,
    );
    b.role(&owner, Some("contract"));
}

/// Classic assets whose entries this transaction changed (trustlines), plus native.
fn changed_assets(lists: &[&LedgerEntryChanges]) -> Vec<Asset> {
    let mut out = vec![Asset::Native];
    for l in lists {
        for c in l.0.iter() {
            if let LedgerEntryChange::State(e)
            | LedgerEntryChange::Created(e)
            | LedgerEntryChange::Updated(e)
            | LedgerEntryChange::Restored(e) = c
            {
                if let LedgerEntryData::Trustline(t) = &e.data {
                    if let Some(a) = trustline_classic_asset(&t.asset) {
                        if !out.contains(&a) {
                            out.push(a);
                        }
                    }
                }
            }
        }
    }
    out
}

/// A token-shaped event.
struct TokenEvent {
    kind: &'static str,
    from: Option<String>,
    to: Option<String>,
    sep11: Option<String>,
    amount: i128,
    routing: Routing,
}

fn token_event(e: &ContractEvent) -> Option<TokenEvent> {
    if e.type_ != ContractEventType::Contract {
        return None;
    }
    let ContractEventBody::V0(body) = &e.body;
    let topics = body.topics.as_slice();
    let kind = match sym(topics.first()?)? {
        "transfer" => "transfer",
        "mint" => "mint",
        "burn" => "burn",
        "clawback" => "clawback",
        _ => return None,
    };
    let addrs: Vec<String> = topics[1..]
        .iter()
        .filter_map(|t| match t {
            ScVal::Address(a) => Some(base_address(a)),
            _ => None,
        })
        .collect();
    let sep11 = match topics.last() {
        Some(ScVal::String(s)) if topics.len() > 1 => {
            Some(String::from_utf8_lossy(s.0.as_slice()).into_owned())
        }
        _ => None,
    };
    let (amount, routing) = match &body.data {
        ScVal::I128(_) => (
            i128_of(&body.data)?,
            Routing {
                type_: "absent",
                value: None,
            },
        ),
        ScVal::Map(Some(m)) => {
            let mut amount = None;
            let mut routing = Routing {
                type_: "absent",
                value: None,
            };
            for entry in m.0.iter() {
                match sym(&entry.key) {
                    Some("amount") => amount = i128_of(&entry.val),
                    Some("to_muxed_id") => {
                        routing = match &entry.val {
                            ScVal::Void => Routing {
                                type_: "void",
                                value: None,
                            },
                            ScVal::U64(n) => Routing {
                                type_: "u64",
                                value: Some(n.to_string()),
                            },
                            ScVal::String(s) => Routing {
                                type_: "text",
                                value: Some(String::from_utf8_lossy(s.0.as_slice()).into_owned()),
                            },
                            ScVal::Bytes(bs) => Routing {
                                type_: "bytes",
                                value: Some(hex::encode(bs.0.as_slice())),
                            },
                            _ => return None,
                        }
                    }
                    _ => {}
                }
            }
            (amount?, routing)
        }
        _ => return None,
    };
    let (from, to) = match kind {
        "transfer" if addrs.len() >= 2 => (Some(addrs[0].clone()), Some(addrs[1].clone())),
        "mint" => (None, Some(addrs.last()?.clone())),
        "burn" | "clawback" => (Some(addrs.last()?.clone()), None),
        _ => return None,
    };
    Some(TokenEvent {
        kind,
        from,
        to,
        sep11,
        amount,
        routing,
    })
}

/// Step 6 for one event.
fn event_movement(b: &mut Builder<'_>, op_index: usize, e: &ContractEvent, candidates: &[Asset]) {
    let Some(t) = token_event(e) else {
        return;
    };
    let Some(ContractId(Hash(emitter))) = e.contract_id.clone() else {
        return;
    };
    let emitter_str = contract_strkey(emitter);
    let named_classic = t.sep11.as_deref().and_then(parse_asset);
    // The emitter is a Stellar Asset Contract only if its ID derives from one of the candidate
    // assets (the transaction's changed classic assets, native, and the asset the event names —
    // the last is used only to test the derivation, never trusted on its own).
    let mut pool: Vec<Asset> = candidates.to_vec();
    if let Some(a) = &named_classic {
        if !pool.contains(a) {
            pool.push(a.clone());
        }
    }
    let sac_asset = pool
        .iter()
        .find(|a| sac_contract_id(a, b.network_id) == emitter)
        .cloned();
    let acct = |a: &Option<String>, muxed: Option<String>| {
        a.clone().map(|address| AccountRef {
            address,
            muxed_id: muxed,
        })
    };
    let to_muxed = (t.routing.type_ == "u64")
        .then(|| t.routing.value.clone())
        .flatten();
    match sac_asset {
        Some(asset) => {
            if let (Some(named), Some(raw)) = (&named_classic, &t.sep11) {
                if *named != asset {
                    b.flags.push(Flag {
                        kind: "sac_asset_topic_mismatch",
                        op_index: Some(op_index),
                        detail: format!("event of {} names {raw}", asset_string(&asset)),
                    });
                }
            }
            for a in t.from.iter().chain(t.to.iter()) {
                if !b.is_participant(a) {
                    b.flags.push(Flag {
                        kind: "sac_event_address_without_entry_change",
                        op_index: Some(op_index),
                        detail: format!(
                            "{} event of {} names {a}, whose entries did not change",
                            t.kind,
                            asset_string(&asset)
                        ),
                    });
                }
            }
            b.movements.push(Movement {
                kind: t.kind,
                tx_index: b.index,
                op_index: Some(op_index),
                asset: asset_string(&asset),
                amount: t.amount.to_string(),
                from: acct(&t.from, None),
                to: acct(&t.to, to_muxed),
                routing: Some(t.routing.clone()),
                count: None,
            });
        }
        None => {
            for a in t.from.iter().chain(t.to.iter()) {
                b.named.push(NamedByContract {
                    address: a.clone(),
                    contract: emitter_str.clone(),
                    event: t.kind.into(),
                    op_index,
                });
            }
            match named_classic {
                // A forged asset claim: the extractor records no movement for it, only a proposed
                // `count: 0` item on the claimed classic asset and a must-not fact for the
                // "recipient". A reader may still record the event as the emitter's own-token
                // movement; an entry allows that with an `unverified` movement of the emitting
                // contract that states the forbidden address exactly as its endpoint, which spares
                // that record (and only it) from the must-not fact (`docs/manifest.md` P-5, M-7).
                Some(classic) => {
                    let claimed = asset_string(&classic);
                    b.flags.push(Flag {
                        kind: "forged_asset_claim",
                        op_index: Some(op_index),
                        detail: format!(
                            "{} event from {emitter_str} names {claimed}, whose asset contract is {}",
                            t.kind,
                            contract_strkey(sac_contract_id(&classic, b.network_id))
                        ),
                    });
                    b.proposed.push(Movement {
                        kind: t.kind,
                        tx_index: b.index,
                        op_index: Some(op_index),
                        asset: claimed.clone(),
                        amount: t.amount.to_string(),
                        from: acct(&t.from, None),
                        to: acct(&t.to, None),
                        routing: None,
                        count: Some(0),
                    });
                    let recipient = t.to.clone().or(t.from.clone());
                    if let Some(r) = recipient {
                        if !b.is_participant(&r) {
                            b.must_not.push(MustNot {
                                address: r,
                                because: format!(
                                    "named by a {} event of {emitter_str}, which is not the {claimed} asset contract; no entry of it changed",
                                    t.kind
                                ),
                            });
                        }
                    }
                }
                None => {
                    // A contract token: the movement is the contract's claim about its own token,
                    // never a classic balance fact. Its balances live in its own storage, so the
                    // addresses it names are counterparties of that token.
                    b.movements.push(Movement {
                        kind: t.kind,
                        tx_index: b.index,
                        op_index: Some(op_index),
                        asset: emitter_str.clone(),
                        amount: t.amount.to_string(),
                        from: acct(&t.from, None),
                        to: acct(&t.to, to_muxed),
                        routing: Some(t.routing.clone()),
                        count: None,
                    });
                    for a in t.from.iter().chain(t.to.iter()) {
                        b.role(a, Some("counterparty"));
                    }
                }
            }
        }
    }
}

/// Fee and refund from fee processing and post-apply processing (step 1). Returns the fee payer.
fn fee_step(
    b: &mut Builder<'_>,
    fee: &LedgerEntryChanges,
    refunds: &[&LedgerEntryChanges],
) -> Option<String> {
    let mut payer = None;
    for t in transitions(fee) {
        if let Transition::Updated(Some(pre), post) = t {
            if let (LedgerEntryData::Account(a0), LedgerEntryData::Account(a1)) =
                (&pre.data, &post.data)
            {
                let who = account_strkey(&a1.account_id);
                if a1.balance < a0.balance {
                    b.role(&who, Some("fee_payer"));
                    b.movements.push(Movement {
                        kind: "fee",
                        tx_index: b.index,
                        op_index: None,
                        asset: "native".into(),
                        amount: (a0.balance - a1.balance).to_string(),
                        from: Some(AccountRef::new(who.clone())),
                        to: None,
                        routing: None,
                        count: None,
                    });
                    payer = Some(who.clone());
                }
                if a0.seq_num != a1.seq_num {
                    // Before Protocol 10 the sequence number was bumped in fee processing.
                    b.role(&who, Some("source"));
                    b.source = Some(who.clone());
                }
            }
        }
    }
    for list in refunds {
        for t in transitions(list) {
            if let Transition::Updated(Some(pre), post) = t {
                if let (LedgerEntryData::Account(a0), LedgerEntryData::Account(a1)) =
                    (&pre.data, &post.data)
                {
                    let who = account_strkey(&a1.account_id);
                    if a1.balance > a0.balance && payer.as_deref() == Some(who.as_str()) {
                        b.movements.push(Movement {
                            kind: "fee_refund",
                            tx_index: b.index,
                            op_index: None,
                            asset: "native".into(),
                            amount: (a1.balance - a0.balance).to_string(),
                            from: None,
                            to: Some(AccountRef::new(who)),
                            routing: None,
                            count: None,
                        });
                    }
                }
            }
        }
    }
    payer
}

/// Cross-check fee events against the fee movements. Returns (`present`, `agree`).
fn fee_events_check(b: &mut Builder<'_>, events: &[&ContractEvent]) -> (bool, bool) {
    let native = sac_contract_id(&Asset::Native, b.network_id);
    let (mut charged, mut refunded, mut present) = (0i128, 0i128, false);
    for e in events {
        let ContractEventBody::V0(body) = &e.body;
        if body.topics.first().and_then(sym) != Some("fee") {
            continue;
        }
        if e.contract_id.as_ref().map(|c| c.0 .0) != Some(native) {
            b.flags.push(Flag {
                kind: "fee_event_disagrees",
                op_index: None,
                detail: "a fee event not emitted by the native asset contract".into(),
            });
            continue;
        }
        present = true;
        match i128_of(&body.data) {
            Some(n) if n >= 0 => charged += n,
            Some(n) => refunded += -n,
            None => {}
        }
    }
    if !present {
        return (false, true);
    }
    let sum = |kind: &str| -> i128 {
        b.movements
            .iter()
            .filter(|m| m.kind == kind)
            .filter_map(|m| m.amount.parse::<i128>().ok())
            .sum()
    };
    let agree = sum("fee") == charged && sum("fee_refund") == refunded;
    if !agree {
        b.flags.push(Flag {
            kind: "fee_event_disagrees",
            op_index: None,
            detail: format!(
                "fee events charge {charged} and refund {refunded}; entry changes charge {} and refund {}",
                sum("fee"),
                sum("fee_refund")
            ),
        });
    }
    (true, agree)
}

/// The token balances one entry holds, as (asset, holder, amount): an account's native balance, a
/// trustline's balance (a pool-share trustline holds no token), a claimable balance's amount
/// (holder `B…`) and a constant-product pool's two reserves (holder `L…`).
fn held_balances(e: &LedgerEntry) -> Vec<(String, String, i64)> {
    match &e.data {
        LedgerEntryData::Account(a) => {
            vec![("native".into(), account_strkey(&a.account_id), a.balance)]
        }
        LedgerEntryData::Trustline(t) if !matches!(t.asset, TrustLineAsset::PoolShare(_)) => {
            vec![(
                trustline_asset_string(&t.asset),
                account_strkey(&t.account_id),
                t.balance,
            )]
        }
        LedgerEntryData::ClaimableBalance(c) => {
            vec![(asset_string(&c.asset), cb_strkey(&c.balance_id), c.amount)]
        }
        LedgerEntryData::LiquidityPool(p) => {
            let stellar_xdr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) = &p.body;
            let holder = pool_strkey(&p.liquidity_pool_id);
            vec![
                (
                    asset_string(&cp.params.asset_a),
                    holder.clone(),
                    cp.reserve_a,
                ),
                (asset_string(&cp.params.asset_b), holder, cp.reserve_b),
            ]
        }
        _ => vec![],
    }
}

/// `docs/manifest.md` §6.11: classic movements from balance deltas, when classic events were not emitted.
///
/// Every holder's net delta per asset is taken over the operation's changes, with created entries
/// counting from zero and removed ones down to zero, so an account created or merged away, a
/// claimable balance created or claimed and a pool's reserves pair like any other balance. Per asset,
/// one debit and one equal credit are a transfer; a lone credit when the operation's source issues the
/// asset is a mint, and a lone debit paid to the asset's issuer is a burn. Anything else is flagged.
fn delta_movements(b: &mut Builder<'_>, op_index: usize, changes: &LedgerEntryChanges) {
    let mut net: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
    let mut add = |e: &LedgerEntry, sign: i64| {
        for (asset, holder, n) in held_balances(e) {
            *net.entry(asset).or_default().entry(holder).or_default() += sign * n;
        }
    };
    for t in transitions(changes) {
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
    let op = b.env.ops.get(op_index);
    let op_source = op
        .and_then(|o| o.source_account.as_ref())
        .map_or_else(|| muxed_base(&b.env.source).0, |m| muxed_base(m).0);
    let paid_to = op.and_then(|o| match &o.body {
        OperationBody::Payment(p) => Some(muxed_base(&p.destination).0),
        OperationBody::PathPaymentStrictReceive(p) => Some(muxed_base(&p.destination).0),
        OperationBody::PathPaymentStrictSend(p) => Some(muxed_base(&p.destination).0),
        _ => None,
    });
    for (asset, holders) in net {
        let ds: Vec<(String, i64)> = holders.into_iter().filter(|(_, d)| *d != 0).collect();
        if ds.is_empty() {
            continue;
        }
        let issuer = asset.split_once(':').map(|(_, i)| i.to_string());
        let neg: Vec<_> = ds.iter().filter(|d| d.1 < 0).collect();
        let pos: Vec<_> = ds.iter().filter(|d| d.1 > 0).collect();
        let movement = |kind: &'static str,
                        amount: i64,
                        from: Option<&String>,
                        to: Option<&String>| Movement {
            kind,
            tx_index: b.index,
            op_index: Some(op_index),
            asset: asset.clone(),
            amount: amount.to_string(),
            from: from.map(|f| AccountRef::new(f.clone())),
            to: to.map(|t| AccountRef::new(t.clone())),
            routing: None,
            count: None,
        };
        let m = match (neg.as_slice(), pos.as_slice()) {
            ([(from, n)], [(to, p)]) if -*n == *p => {
                Some(movement("transfer", *p, Some(from), Some(to)))
            }
            ([], [(to, p)]) if issuer.as_deref() == Some(op_source.as_str()) => {
                Some(movement("mint", *p, None, Some(to)))
            }
            ([(from, n)], []) if issuer.is_some() && issuer == paid_to => {
                Some(movement("burn", -*n, Some(from), None))
            }
            _ => None,
        };
        match m {
            Some(m) => b.movements.push(m),
            None => b.flags.push(Flag {
                kind: "balance_delta_ambiguous",
                op_index: Some(op_index),
                detail: format!(
                    "{asset}: {} balance deltas do not pair into one transfer",
                    ds.len()
                ),
            }),
        }
    }
}

/// Muxed forms the envelope gives to accounts (tx source, fee source, operation sources,
/// destinations, clawback sources): base → (id, M… form).
fn envelope_muxed(env: &Env) -> Vec<(String, u64, String)> {
    let mut all: Vec<&MuxedAccount> = vec![&env.source];
    all.extend(env.fee_source.iter());
    for op in &env.ops {
        all.extend(op.source_account.iter());
        match &op.body {
            OperationBody::Payment(p) => all.push(&p.destination),
            OperationBody::PathPaymentStrictReceive(p) => all.push(&p.destination),
            OperationBody::PathPaymentStrictSend(p) => all.push(&p.destination),
            OperationBody::AccountMerge(m) => all.push(m),
            OperationBody::Clawback(c) => all.push(&c.from),
            // No muxed account in the body. Every operation is named: a new operation does not
            // compile until its muxed accounts are considered here.
            OperationBody::CreateAccount(_)
            | OperationBody::ManageSellOffer(_)
            | OperationBody::CreatePassiveSellOffer(_)
            | OperationBody::SetOptions(_)
            | OperationBody::ChangeTrust(_)
            | OperationBody::AllowTrust(_)
            | OperationBody::Inflation
            | OperationBody::ManageData(_)
            | OperationBody::BumpSequence(_)
            | OperationBody::ManageBuyOffer(_)
            | OperationBody::CreateClaimableBalance(_)
            | OperationBody::ClaimClaimableBalance(_)
            | OperationBody::BeginSponsoringFutureReserves(_)
            | OperationBody::EndSponsoringFutureReserves
            | OperationBody::RevokeSponsorship(_)
            | OperationBody::ClawbackClaimableBalance(_)
            | OperationBody::SetTrustLineFlags(_)
            | OperationBody::LiquidityPoolDeposit(_)
            | OperationBody::LiquidityPoolWithdraw(_)
            | OperationBody::InvokeHostFunction(_)
            | OperationBody::ExtendFootprintTtl(_)
            | OperationBody::RestoreFootprint(_) => {}
        }
    }
    all.into_iter()
        .filter_map(|m| {
            let (base, id) = muxed_base(m);
            id.map(|id| (base, id, m.to_string()))
        })
        .collect()
}

fn derive_tx(index: usize, view: &TxView<'_>, env: &Env, network_id: [u8; 32]) -> Result<TxFacts> {
    let hash = hex::encode(view.result.transaction_hash.0);
    let mut b = Builder {
        index,
        network_id,
        env,
        participants: Vec::new(),
        state_changes: Vec::new(),
        movements: Vec::new(),
        proposed: Vec::new(),
        must_not: Vec::new(),
        named: Vec::new(),
        flags: Vec::new(),
        source: None,
        ttl_owners: BTreeMap::new(),
        claimants: BTreeSet::new(),
    };
    let parts = meta_parts(view.meta);
    {
        let lists: Vec<&LedgerEntryChanges> = parts
            .before
            .iter()
            .copied()
            .chain(parts.after)
            .chain(parts.ops.iter().copied())
            .collect();
        b.ttl_owners = ttl_owners(&lists, env);
    }

    // 1. Fee. A LedgerCloseMeta without post-apply fee processing (v0, v1) carries the Soroban
    // refund in the changes after, whatever the TransactionMeta version: v3 as nodes emitted it,
    // v4 in lake objects regenerated by a later stellar-core.
    let mut refund_lists: Vec<&LedgerEntryChanges> = view.post.into_iter().collect();
    if view.post.is_none() {
        refund_lists.extend(parts.after);
    }
    fee_step(&mut b, view.fee, &refund_lists);
    let (fee_events_present, fee_agree) = fee_events_check(&mut b, &parts.tx_events);

    // 2. Outcome.
    let successful = matches!(
        view.result.result.result,
        TransactionResultResult::TxSuccess(_) | TransactionResultResult::TxFeeBumpInnerSuccess(_)
    );

    // 3. Transaction-level changes.
    let tx_level: Vec<&LedgerEntryChanges> =
        parts.before.iter().copied().chain(parts.after).collect();
    for list in &tx_level {
        for t in transitions(list) {
            if let Transition::Updated(Some(pre), post) = t {
                if let (LedgerEntryData::Account(a0), LedgerEntryData::Account(a1)) =
                    (&pre.data, &post.data)
                {
                    let who = account_strkey(&a1.account_id);
                    if a0.seq_num != a1.seq_num {
                        b.role(&who, Some("source"));
                        b.source = Some(who.clone());
                        let mut d = Map::new();
                        d.insert("sequence_after".into(), json!(a1.seq_num.0.to_string()));
                        b.change("sequence_bumped", None, who.clone(), None, None, d, None);
                    }
                    // One-time (pre-auth) signer removals; failed transactions keep them too.
                    let removed = a0
                        .signers
                        .iter()
                        .any(|s| !a1.signers.iter().any(|s1| s1.key == s.key));
                    if removed {
                        signer_diff(&mut b, None, a0, a1, None);
                    }
                }
            }
        }
    }

    // 4. Failed: stop; every other address the envelope names is a candidate.
    if !successful {
        let mut named = BTreeSet::new();
        for op in &env.ops {
            addresses_in(&json_of(op), &mut named);
        }
        for a in named {
            if !b.is_participant(&a) {
                b.must_not.push(MustNot {
                    address: a,
                    because: "named in the envelope of a failed transaction; only the fee payer and the source changed (candidate)".into(),
                });
            }
        }
    } else {
        // 5. Operation changes.
        for (i, changes) in parts.ops.iter().enumerate() {
            classify_op(&mut b, i, changes);
        }
        // 6. Events (operation-level; transaction-level events are fee events, checked above).
        let all_lists: Vec<&LedgerEntryChanges> = tx_level
            .iter()
            .copied()
            .chain(parts.ops.iter().copied())
            .chain(std::iter::once(view.fee))
            .collect();
        let candidates = changed_assets(&all_lists);
        for (i, events) in parts.op_events.iter().enumerate() {
            for e in events {
                event_movement(&mut b, i, e, &candidates);
            }
        }
        // `docs/manifest.md` §6.11: without classic events, classic movements come from balance deltas.
        if !fee_events_present {
            for (i, changes) in parts.ops.iter().enumerate() {
                let soroban = env
                    .ops
                    .get(i)
                    .is_some_and(|op| matches!(op.body, OperationBody::InvokeHostFunction(_)));
                if !soroban {
                    delta_movements(&mut b, i, changes);
                }
            }
        }
        // 7. Addresses only in authorization entries.
        let (mut in_auth, mut elsewhere) = (BTreeSet::new(), BTreeSet::new());
        for op in &env.ops {
            match &op.body {
                OperationBody::InvokeHostFunction(f) => {
                    addresses_in(&json_of(&f.auth), &mut in_auth);
                    addresses_in(&json_of(&f.host_function), &mut elsewhere);
                }
                other => addresses_in(&json_of(other), &mut elsewhere),
            }
            if let Some(s) = &op.source_account {
                elsewhere.insert(muxed_base(s).0);
            }
        }
        elsewhere.insert(muxed_base(&env.source).0);
        for a in in_auth.difference(&elsewhere) {
            if !b.is_participant(a) {
                b.must_not.push(MustNot {
                    address: a.clone(),
                    because: "named only in an authorization entry; no nonce entry and no changed entry (candidate)".into(),
                });
            }
        }
    }

    // Post-pass: claimants of a balance the transaction created or claimed that are affected
    // anyway get that role; an affected address with no specific role is a counterparty.
    for p in &mut b.participants {
        if b.claimants.contains(&p.address) {
            p.roles.insert("claimant".into());
        }
        if p.roles.is_empty() {
            p.roles.insert("counterparty".into());
        }
    }

    // 8. Muxed aliases, attached to existing participants only: the envelope's MuxedAccounts, then
    // the u64 routing IDs of the transaction's own token events (the ledger carries that ID).
    let mut aliases = envelope_muxed(env);
    for m in &b.movements {
        if let Some(to) = &m.to {
            let id = to.muxed_id.as_deref().and_then(|i| i.parse::<u64>().ok());
            if let (Some(id), Ok(AccountId(PublicKey::PublicKeyTypeEd25519(k)))) =
                (id, to.address.parse::<AccountId>())
            {
                let form = MuxedAccount::MuxedEd25519(stellar_xdr::MuxedAccountMed25519 {
                    id,
                    ed25519: k,
                })
                .to_string();
                if !aliases
                    .iter()
                    .any(|(b0, i0, _)| *b0 == to.address && *i0 == id)
                {
                    aliases.push((to.address.clone(), id, form));
                }
            }
        }
    }
    for (base, id, form) in aliases {
        if let Some(p) = b.participants.iter_mut().find(|p| p.address == base) {
            match &p.muxed_id {
                None => {
                    p.muxed_id = Some(id.to_string());
                    p.on_chain_form = Some(form);
                }
                Some(existing) if *existing != id.to_string() => b.flags.push(Flag {
                    kind: "muxed_alias_conflict",
                    op_index: None,
                    detail: format!("{base} appears with muxed IDs {existing} and {id}"),
                }),
                _ => {}
            }
        }
    }

    Ok(TxFacts {
        index,
        hash,
        participants: b.participants,
        must_not_include: b.must_not,
        state_changes: b.state_changes,
        movements: b.movements,
        proposed_must_not_movements: b.proposed,
        named_by_contract: b.named,
        flags: b.flags,
        movement_basis: if fee_events_present {
            "events"
        } else {
            "balance_deltas"
        },
        fee_events: match (fee_events_present, fee_agree) {
            (false, _) => "absent",
            (true, true) => "agree",
            (true, false) => "disagree",
        },
    })
}

fn tx_summary(index: usize, view: &TxView<'_>) -> TxSummary {
    let r = &view.result.result;
    let result_json = json_of(&r.result);
    let op_codes = |v: &Value| -> Vec<String> {
        v.as_array()
            .map(|ops| {
                ops.iter()
                    .map(|o| match o {
                        Value::Object(m) if m.contains_key("op_inner") => {
                            let tr = &m["op_inner"];
                            let op = arm(tr);
                            let code = tr.get(&op).map(arm).unwrap_or_default();
                            format!("{op}.{code}")
                        }
                        other => arm(other),
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let code = arm(&result_json);
    let (mut ops, mut inner_hash, mut inner_successful, mut inner_code) =
        (Vec::new(), None, None, None);
    match &r.result {
        TransactionResultResult::TxFeeBumpInnerSuccess(p)
        | TransactionResultResult::TxFeeBumpInnerFailed(p) => {
            inner_hash = Some(hex::encode(p.transaction_hash.0));
            let inner = json_of(&p.result.result);
            let ic = arm(&inner);
            inner_successful = Some(ic == "tx_success");
            ops = op_codes(&inner[&ic]);
            inner_code = Some(ic);
        }
        _ => {
            if let Some(v) = result_json.get(&code) {
                ops = op_codes(v);
            }
        }
    }
    TxSummary {
        index,
        hash: hex::encode(view.result.transaction_hash.0),
        successful: matches!(
            r.result,
            TransactionResultResult::TxSuccess(_)
                | TransactionResultResult::TxFeeBumpInnerSuccess(_)
        ),
        result_code: code,
        operation_result_codes: ops,
        fee_charged: r.fee_charged.to_string(),
        inner_hash,
        inner_successful,
        inner_result_code: inner_code,
    }
}

/// Run the extractor over one ledger. `passphrase` is the variant's network passphrase: it maps
/// result hashes to envelopes and derives Stellar Asset Contract IDs.
///
/// Values can be deeply nested; call this on a large stack (see [`xdrcheck_xdr::with_stack`]).
pub fn extract(lcm: &LedgerCloseMeta, passphrase: &str) -> Result<Extraction> {
    let nid = network_id(passphrase);
    let mut by_hash: BTreeMap<[u8; 32], &TransactionEnvelope> = BTreeMap::new();
    for e in envelopes(lcm) {
        let h = e
            .hash(nid)
            .map_err(|err| ExtractError::Encode(err.to_string()))?;
        by_hash.insert(h, e);
    }
    let views = tx_views(lcm);
    let mut ledger = LedgerCounts {
        transactions: views.len(),
        entry_changes: upgrade_changes(lcm),
        ..LedgerCounts::default()
    };
    let (mut transactions, mut txs) = (Vec::new(), Vec::new());
    for (i, v) in views.iter().enumerate() {
        let env = by_hash
            .get(&v.result.transaction_hash.0)
            .map(|e| env_parts(e))
            .ok_or_else(|| ExtractError::EnvelopeNotFound {
                index: i,
                hash: hex::encode(v.result.transaction_hash.0),
            })?;
        let parts = meta_parts(v.meta);
        ledger.operations += env.ops.len();
        ledger.events +=
            parts.tx_events.len() + parts.op_events.iter().map(Vec::len).sum::<usize>();
        ledger.entry_changes += v.fee.0.len()
            + v.post.map_or(0, |p| p.0.len())
            + parts.before.iter().map(|l| l.0.len()).sum::<usize>()
            + parts.after.map_or(0, |l| l.0.len())
            + parts.ops.iter().map(|l| l.0.len()).sum::<usize>();
        transactions.push(tx_summary(i, v));
        txs.push(derive_tx(i, v, &env, nid)?);
    }
    Ok(Extraction {
        ledger,
        transactions,
        txs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const PUBNET: &str = "Public Global Stellar Network ; September 2015";

    /// Every distinct vendored `LedgerCloseMeta` blob of a positive manifest variant on `passphrase`.
    fn corpus_ledgers(passphrase: &str) -> Vec<(String, Vec<u8>)> {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
        let mut out: Vec<(String, Vec<u8>)> = Vec::new();
        let mut stack = vec![corpus.join("manifest")];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                let j: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
                for v in j["variants"].as_array().into_iter().flatten() {
                    let blob = v["blob"]["path"].as_str().unwrap_or("").to_string();
                    if v["xdr_type"] == "LedgerCloseMeta"
                        && v["passphrase"] == passphrase
                        && j["negative"] != true
                        && !out.iter().any(|(b, _)| *b == blob)
                    {
                        out.push((blob.clone(), std::fs::read(corpus.join(&blob)).unwrap()));
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// The refund the bytes show for one transaction of a ledger without post-apply fee
    /// processing: the fee payer's balance increase in the changes after, and the negated
    /// negative fee events. Read directly from the decoded value, not through the extractor.
    fn refund_in_bytes(view: &TxView<'_>, payer: &str) -> (i64, i128) {
        let (after, events): (&LedgerEntryChanges, Vec<&ContractEvent>) = match view.meta {
            TransactionMeta::V2(m) => (&m.tx_changes_after, Vec::new()),
            TransactionMeta::V3(m) => (&m.tx_changes_after, Vec::new()),
            TransactionMeta::V4(m) => (
                &m.tx_changes_after,
                m.events.iter().map(|e| &e.event).collect(),
            ),
            TransactionMeta::V0(_) | TransactionMeta::V1(_) => return (0, 0),
        };
        let mut pre = None;
        let mut delta = 0;
        for c in after.0.iter() {
            match c {
                LedgerEntryChange::State(e) => pre = Some(e),
                LedgerEntryChange::Updated(e) => {
                    if let (Some(p), LedgerEntryData::Account(a1)) = (pre, &e.data) {
                        if let LedgerEntryData::Account(a0) = &p.data {
                            if account_strkey(&a1.account_id) == payer {
                                delta += a1.balance - a0.balance;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        let mut evented = 0i128;
        for e in events {
            let ContractEventBody::V0(body) = &e.body;
            if body.topics.first().and_then(sym) == Some("fee") {
                if let Some(n) = i128_of(&body.data).filter(|n| *n < 0) {
                    evented += -n;
                }
            }
        }
        (delta, evented)
    }

    /// A LedgerCloseMeta v0/v1 has no post-apply fee processing, so a Soroban refund is in the
    /// transaction's changes after whatever the TransactionMeta version, including the v4 meta of
    /// regenerated Protocol 20–22 lake objects. Over every vendored pubnet ledger of that shape,
    /// each refund the bytes show is a `fee_refund` movement of that amount and the fee events
    /// agree; at least one such refund exists.
    #[test]
    fn refund_after_apply_is_read_without_post_apply_fee_processing() {
        let mut refunds = 0;
        for (blob, bytes) in corpus_ledgers(PUBNET) {
            xdrcheck_xdr::with_stack(xdrcheck_xdr::DEFAULT_STACK_SIZE, || {
                let lcm = xdrcheck_xdr::decode_ledger(
                    &bytes,
                    &xdrcheck_xdr::Limits::default(),
                    &xdrcheck_xdr::Gate::default(),
                )
                .unwrap();
                if matches!(lcm, LedgerCloseMeta::V2(_)) {
                    return;
                }
                let ext = extract(&lcm, PUBNET).unwrap();
                for (view, tx) in tx_views(&lcm).iter().zip(&ext.txs) {
                    let Some(payer) = tx
                        .participants
                        .iter()
                        .find(|p| p.roles.contains("fee_payer"))
                        .map(|p| p.address.clone())
                    else {
                        continue;
                    };
                    let (delta, evented) = refund_in_bytes(view, &payer);
                    let got: i64 = tx
                        .movements
                        .iter()
                        .filter(|m| m.kind == "fee_refund")
                        .map(|m| m.amount.parse::<i64>().unwrap())
                        .sum();
                    let at = format!("{blob} tx {}", tx.index);
                    assert_eq!(got, delta, "{at}: fee_refund vs the changes after");
                    if tx.fee_events != "absent" {
                        assert_eq!(i128::from(delta), evented, "{at}: refund fee event");
                        assert_eq!(tx.fee_events, "agree", "{at}: {:?}", tx.flags);
                    }
                    if delta > 0 {
                        refunds += 1;
                    }
                }
            });
        }
        assert!(
            refunds > 0,
            "no refund after apply in a LedgerCloseMeta v0/v1 ledger"
        );
    }

    /// The classification matches name every entry type. An update whose type differs from its
    /// state is flagged, not passed over; a type with no fact of its own yields nothing.
    #[test]
    fn update_classification_is_explicit() {
        let env = Env {
            fee_source: None,
            source: MuxedAccount::default(),
            ops: Vec::new(),
            footprint: Vec::new(),
        };
        let mut b = Builder {
            index: 0,
            network_id: [0; 32],
            env: &env,
            participants: Vec::new(),
            state_changes: Vec::new(),
            movements: Vec::new(),
            proposed: Vec::new(),
            must_not: Vec::new(),
            named: Vec::new(),
            flags: Vec::new(),
            source: None,
            ttl_owners: BTreeMap::new(),
            claimants: BTreeSet::new(),
        };
        let entry = |data: LedgerEntryData| LedgerEntry {
            last_modified_ledger_seq: 1,
            data,
            ext: LedgerEntryExt::V0,
        };
        let account = entry(LedgerEntryData::default());
        let ttl = entry(LedgerEntryData::Ttl(Default::default()));
        classify_updated(&mut b, 0, Some(&ttl), &ttl, None);
        assert!(b.flags.is_empty() && b.state_changes.is_empty());
        classify_updated(&mut b, 0, Some(&ttl), &account, None);
        assert_eq!(b.flags.len(), 1);
        assert_eq!(b.flags[0].kind, "update_type_changed");
        assert_eq!(b.flags[0].detail, "Account updated from a Ttl state");
    }
}
