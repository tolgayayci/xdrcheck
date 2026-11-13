//! Values derived from a variant's bytes with the oracle, which `xdrcheck-corpus verify` compares with
//! what the entry states and the generator writes (`docs/manifest.md` §4.2 and §10.1):
//!
//! - `variants[].requires`: the XDR features of the pinned definitions the value uses that older
//!   definitions lack. Each feature is one detector over the decoded sidecar; adding a feature is
//!   adding a detector and its name to the schema's enum.
//! - `variants[].derived.l1`: what an SDK's object layer reads from the variant's focus — the
//!   focus transaction's memo type and the focus operation's type, source, counterpart address,
//!   muxed ID, asset, pool ID and offer ID. The closed key list and each key's source are fixed
//!   here; conformance drivers report the same keys and the runner compares them with these.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use xdrcheck_xdr::xdr::{
    ChangeTrustAsset, GeneralizedTransactionSet, LedgerCloseMeta, Limits as XdrLimits, Memo,
    MuxedAccount, Operation, OperationBody, ReadXdr, ScAddress, TransactionEnvelope,
    TransactionPhase, TxSetComponent, WriteXdr,
};
use xdrcheck_xdr::{Gate, Limits};

// ---------------------------------------------------------------------------------------------
// requires

/// Feature name → detector over `(xdr_type, decoded JSON)`.
type Detector = fn(&str, &Value) -> bool;

/// The features, in the order the schema lists them.
const FEATURES: &[(&str, Detector)] = &[
    ("stellar_value_signed_ms", stellar_value_signed_ms),
    ("sc_address_type_muxed_contract", sc_address_muxed_contract),
];

/// The features the decoded value uses. Walks the JSON; call it on a large stack for deep values.
pub fn requires(xdr_type: &str, json: &Value) -> BTreeSet<&'static str> {
    FEATURES
        .iter()
        .filter(|(_, f)| f(xdr_type, json))
        .map(|(n, _)| *n)
        .collect()
}

/// [`requires`] of a sidecar's uncompressed text, parsed, walked and dropped on the large stack.
pub fn requires_of_sidecar(
    xdr_type: &str,
    sidecar: &[u8],
    limits: &Limits,
) -> Result<BTreeSet<&'static str>, String> {
    let json = xdrcheck_xdr::parse_json(sidecar, limits).map_err(|e| e.to_string())?;
    Ok(xdrcheck_xdr::with_stack(limits.stack_size, move || {
        let r = requires(xdr_type, &json);
        drop(json);
        r
    }))
}

/// A `StellarValue` whose `ext` is a millisecond close-time arm, `signed_ms` (arm 3) or
/// `empty_tx_set_ms` (arm 4), both added with Protocol 30 (CAP-0088): under a ledger header's
/// `scp_value`, or the value itself. A reader built before them decodes neither.
fn stellar_value_signed_ms(xdr_type: &str, json: &Value) -> bool {
    fn signed_ms(sv: &Value) -> bool {
        sv.get("ext")
            .is_some_and(|e| e.get("signed_ms").is_some() || e.get("empty_tx_set_ms").is_some())
    }
    fn walk(v: &Value) -> bool {
        match v {
            Value::Object(m) => m
                .iter()
                .any(|(k, x)| (k == "scp_value" && signed_ms(x)) || walk(x)),
            Value::Array(a) => a.iter().any(walk),
            _ => false,
        }
    }
    (xdr_type == "StellarValue" && signed_ms(json)) || walk(json)
}

/// An `SCAddress` of type `SC_ADDRESS_TYPE_MUXED_CONTRACT`: SEP-51 renders it as a `W…` strkey,
/// which no other XDR value renders as.
fn sc_address_muxed_contract(_: &str, json: &Value) -> bool {
    match json {
        Value::String(s) => {
            s.len() == 69
                && s.starts_with('W')
                && matches!(s.parse::<ScAddress>(), Ok(ScAddress::MuxedContract(_)))
        }
        Value::Array(a) => a.iter().any(|x| sc_address_muxed_contract("", x)),
        Value::Object(m) => m.values().any(|x| sc_address_muxed_contract("", x)),
        _ => false,
    }
}

// ---------------------------------------------------------------------------------------------
// derived.l1

/// The `derived.l1` values the variant's focus implies. `focus` is the variant's `focus` object.
/// Ledgers: the transaction at `focus.tx_index` (found by hash under `passphrase`) and its
/// operation `focus.op_index`; `TransactionEnvelope`: the value and operation `focus.op_index`;
/// `Operation`: the value; `Memo`: the value. Other types imply nothing.
pub fn l1(
    xdr_type: &str,
    bytes: &[u8],
    passphrase: &str,
    focus: &Value,
    limits: &Limits,
    gate: &Gate,
) -> Result<Map<String, Value>, String> {
    let op_index = focus["op_index"].as_u64().map(|i| i as usize);
    xdrcheck_xdr::with_stack(limits.stack_size, || {
        let mut out = Map::new();
        match xdr_type {
            "LedgerCloseMeta" => {
                let Some(tx) = focus["tx_index"].as_u64() else {
                    return Ok(out);
                };
                let lcm = xdrcheck_xdr::decode_ledger(bytes, limits, gate).map_err(|e| e.to_string())?;
                let env = focus_envelope(&lcm, tx as usize, passphrase)?;
                envelope_keys(&env, op_index, &mut out)?;
            }
            "TransactionEnvelope" => {
                let env = decode::<TransactionEnvelope>(xdr_type, bytes, limits)?;
                envelope_keys(&env, op_index, &mut out)?;
            }
            "Operation" => operation_keys(&decode::<Operation>(xdr_type, bytes, limits)?, &mut out),
            "Memo" => {
                out.insert(
                    "memo_type".into(),
                    json!(memo_type(&decode::<Memo>(xdr_type, bytes, limits)?)),
                );
            }
            _ => {}
        }
        Ok(out)
    })
}

/// Decode on the current (large-stack) thread under the oracle's limits.
fn decode<T: ReadXdr>(xdr_type: &str, bytes: &[u8], limits: &Limits) -> Result<T, String> {
    T::from_xdr(bytes, limits.xdr(bytes.len())).map_err(|e| format!("{xdr_type}: {e}"))
}

/// Every envelope of a generalized transaction set, in set order.
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

/// The envelope of apply-order transaction `tx`: the one whose hash under the passphrase is the
/// result's transaction hash.
fn focus_envelope(
    lcm: &LedgerCloseMeta,
    tx: usize,
    passphrase: &str,
) -> Result<TransactionEnvelope, String> {
    let nid = crate::extract::network_id(passphrase);
    let (hashes, envs): (Vec<[u8; 32]>, Vec<&TransactionEnvelope>) = match lcm {
        LedgerCloseMeta::V0(m) => (
            m.tx_processing
                .iter()
                .map(|t| t.result.transaction_hash.0)
                .collect(),
            m.tx_set.txs.iter().collect(),
        ),
        LedgerCloseMeta::V1(m) => (
            m.tx_processing
                .iter()
                .map(|t| t.result.transaction_hash.0)
                .collect(),
            generalized_envelopes(&m.tx_set),
        ),
        LedgerCloseMeta::V2(m) => (
            m.tx_processing
                .iter()
                .map(|t| t.result.transaction_hash.0)
                .collect(),
            generalized_envelopes(&m.tx_set),
        ),
    };
    let want = hashes
        .get(tx)
        .ok_or_else(|| format!("focus.tx_index {tx} is past the last transaction"))?;
    for e in envs {
        if e.hash(nid).map_err(|e| e.to_string())? == *want {
            return Ok(e.clone());
        }
    }
    Err(format!(
        "no envelope hashes to transaction {tx}'s hash under the variant's passphrase"
    ))
}

fn envelope_keys(
    env: &TransactionEnvelope,
    op_index: Option<usize>,
    out: &mut Map<String, Value>,
) -> Result<(), String> {
    let (memo, ops): (&Memo, Vec<&Operation>) = match env {
        TransactionEnvelope::TxV0(v) => (&v.tx.memo, v.tx.operations.iter().collect()),
        TransactionEnvelope::Tx(v) => (&v.tx.memo, v.tx.operations.iter().collect()),
        TransactionEnvelope::TxFeeBump(v) => {
            let xdrcheck_xdr::xdr::FeeBumpTransactionInnerTx::Tx(inner) = &v.tx.inner_tx;
            (&inner.tx.memo, inner.tx.operations.iter().collect())
        }
    };
    out.insert("memo_type".into(), json!(memo_type(memo)));
    if let Some(i) = op_index {
        let op = ops
            .get(i)
            .ok_or_else(|| format!("focus.op_index {i} is past the last operation"))?;
        operation_keys(op, out);
    }
    Ok(())
}

fn memo_type(m: &Memo) -> &'static str {
    match m {
        Memo::None => "none",
        Memo::Text(_) => "text",
        Memo::Id(_) => "id",
        Memo::Hash(_) => "hash",
        Memo::Return(_) => "return",
    }
}

fn muxed_id(m: &MuxedAccount) -> Option<u64> {
    match m {
        MuxedAccount::MuxedEd25519(x) => Some(x.id),
        MuxedAccount::Ed25519(_) => None,
    }
}

/// The operation keys: type, own source, counterpart address and its muxed ID (else the source's),
/// asset, pool ID and offer ID, each where the operation type has one.
fn operation_keys(op: &Operation, out: &mut Map<String, Value>) {
    use crate::extract::asset_string;
    let body = serde_json::to_value(&op.body).unwrap_or(Value::Null);
    let arm = match &body {
        Value::String(s) => s.clone(),
        Value::Object(m) => m.keys().next().cloned().unwrap_or_default(),
        _ => String::new(),
    };
    out.insert("operation_type".into(), json!(arm));
    if let Some(s) = &op.source_account {
        out.insert("operation_source".into(), json!(s.to_string()));
    }
    let address: Option<(String, Option<u64>)> = match &op.body {
        OperationBody::CreateAccount(o) => Some((o.destination.to_string(), None)),
        OperationBody::Payment(o) => Some((o.destination.to_string(), muxed_id(&o.destination))),
        OperationBody::PathPaymentStrictReceive(o) => {
            Some((o.destination.to_string(), muxed_id(&o.destination)))
        }
        OperationBody::PathPaymentStrictSend(o) => {
            Some((o.destination.to_string(), muxed_id(&o.destination)))
        }
        OperationBody::AccountMerge(m) => Some((m.to_string(), muxed_id(m))),
        OperationBody::AllowTrust(o) => Some((o.trustor.to_string(), None)),
        OperationBody::SetTrustLineFlags(o) => Some((o.trustor.to_string(), None)),
        OperationBody::Clawback(o) => Some((o.from.to_string(), muxed_id(&o.from))),
        OperationBody::BeginSponsoringFutureReserves(o) => Some((o.sponsored_id.to_string(), None)),
        _ => None,
    };
    let source_id = op.source_account.as_ref().and_then(muxed_id);
    if let Some((a, id)) = &address {
        out.insert("address".into(), json!(a));
        if let Some(id) = id.or(source_id) {
            out.insert("muxed_id".into(), json!(id.to_string()));
        }
    } else if let Some(id) = source_id {
        out.insert("muxed_id".into(), json!(id.to_string()));
    }
    let asset = match &op.body {
        OperationBody::Payment(o) => Some(asset_string(&o.asset)),
        OperationBody::PathPaymentStrictReceive(o) => Some(asset_string(&o.dest_asset)),
        OperationBody::PathPaymentStrictSend(o) => Some(asset_string(&o.dest_asset)),
        OperationBody::SetTrustLineFlags(o) => Some(asset_string(&o.asset)),
        OperationBody::Clawback(o) => Some(asset_string(&o.asset)),
        OperationBody::CreateClaimableBalance(o) => Some(asset_string(&o.asset)),
        OperationBody::ChangeTrust(o) => match &o.line {
            ChangeTrustAsset::Native => Some("native".to_string()),
            ChangeTrustAsset::CreditAlphanum4(a) => Some(format!("{}:{}", a.asset_code, a.issuer)),
            ChangeTrustAsset::CreditAlphanum12(a) => Some(format!("{}:{}", a.asset_code, a.issuer)),
            ChangeTrustAsset::PoolShare(_) => None,
        },
        _ => None,
    };
    if let Some(a) = asset {
        out.insert("asset".into(), json!(a));
    }
    let pool = match &op.body {
        OperationBody::ChangeTrust(o) => match &o.line {
            // The pool ID is the sha256 of the pool parameters' XDR.
            ChangeTrustAsset::PoolShare(p) => p
                .to_xdr(XdrLimits::none())
                .ok()
                .map(|b| hex::encode(Sha256::digest(b))),
            _ => None,
        },
        OperationBody::LiquidityPoolDeposit(o) => Some(hex::encode(o.liquidity_pool_id.0 .0)),
        OperationBody::LiquidityPoolWithdraw(o) => Some(hex::encode(o.liquidity_pool_id.0 .0)),
        _ => None,
    };
    if let Some(p) = pool {
        out.insert("pool_id".into(), json!(p));
    }
    let offer = match &op.body {
        OperationBody::ManageSellOffer(o) => Some(o.offer_id),
        OperationBody::ManageBuyOffer(o) => Some(o.offer_id),
        _ => None,
    };
    if let Some(o) = offer {
        out.insert("offer_id".into(), json!(o.to_string()));
    }
}

/// Compare a stored `derived.l1` with the implied one. Problems end with the full expected
/// object, so an author can copy it.
pub fn compare_l1(stored: &Value, want: &Map<String, Value>) -> Vec<String> {
    let have = stored.as_object().cloned().unwrap_or_default();
    let mut p = Vec::new();
    for (k, w) in want {
        match have.get(k) {
            None => p.push(format!(
                "derived.l1.{k} is implied by the focus and missing"
            )),
            Some(h) if h != w => p.push(format!("derived.l1.{k} is {h}, the oracle derives {w}")),
            _ => {}
        }
    }
    for k in have.keys().filter(|k| !want.contains_key(*k)) {
        p.push(format!("derived.l1.{k} is not implied by the focus"));
    }
    if !p.is_empty() {
        p.push(format!(
            "expected derived.l1 = {}",
            Value::Object(want.clone())
        ));
    }
    p
}

/// Compare a stored `requires` with the derived set.
pub fn compare_requires(stored: &Value, want: &BTreeSet<&'static str>) -> Vec<String> {
    if !stored.is_array() {
        return vec![format!(
            "requires is missing (it is mandatory on every variant); expected requires = {}",
            json!(want)
        )];
    }
    let have: BTreeSet<&str> = stored
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let want_str: BTreeSet<&str> = want.iter().copied().collect();
    if have == want_str {
        return vec![];
    }
    vec![format!(
        "requires is {:?}, the oracle derives {:?} from the sidecar; expected requires = {}",
        have,
        want_str,
        json!(want_str)
    )]
}
