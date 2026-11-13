//! Reading a `LedgerCloseMeta`: version-independent views of transactions, metas, envelopes,
//! addresses, assets and Stellar Asset Contract ids. Nothing here interprets balances.

use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, Asset, ClaimableBalanceId, ContractEvent, ContractEventBody, ContractId,
    ContractIdPreimage, GeneralizedTransactionSet, Hash, HashIdPreimage, HashIdPreimageContractId,
    LedgerCloseMeta, LedgerEntryChanges, LedgerKey, Limits, MuxedAccount, Operation, OperationBody,
    PoolId, PublicKey, ScAddress, ScVal, TransactionEnvelope, TransactionEventStage,
    TransactionMeta, TransactionPhase, TransactionResultPair, TrustLineAsset, TxSetComponent,
    WriteXdr,
};

/// The mainnet passphrase, the default network.
pub const MAINNET: &str = "Public Global Stellar Network ; September 2015";

/// SHA-256 of the passphrase.
pub fn network_id(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase.as_bytes()).into()
}

/// The contract id of the Stellar Asset Contract of `asset` on a network.
pub fn sac_contract_id(asset: &Asset, network_id: [u8; 32]) -> [u8; 32] {
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(network_id),
        contract_id_preimage: ContractIdPreimage::Asset(asset.clone()),
    });
    let bytes = preimage
        .to_xdr(Limits::none())
        .expect("a contract-id preimage always encodes");
    Sha256::digest(bytes).into()
}

pub fn contract_strkey(id: &[u8; 32]) -> String {
    ScAddress::Contract(ContractId(Hash(*id))).to_string()
}

/// `native` or `CODE:ISSUER`.
pub fn asset_string(asset: &Asset) -> String {
    match asset {
        Asset::Native => "native".into(),
        Asset::CreditAlphanum4(a) => format!("{}:{}", a.asset_code, a.issuer),
        Asset::CreditAlphanum12(a) => format!("{}:{}", a.asset_code, a.issuer),
    }
}

/// The issuer of a `CODE:ISSUER` asset string.
pub fn asset_issuer(asset: &str) -> Option<&str> {
    asset.split_once(':').map(|(_, i)| i)
}

/// Parse `native` or `CODE:ISSUER` (SEP-11). The code must be 1..=12 bytes of the asset-code
/// alphabet; anything else is not an asset.
pub fn parse_asset(s: &str) -> Option<Asset> {
    if s == "native" {
        return Some(Asset::Native);
    }
    let (code, issuer) = s.split_once(':')?;
    if code.is_empty() || code.len() > 12 || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let issuer: AccountId = issuer.parse().ok()?;
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

pub fn trustline_asset(asset: &TrustLineAsset) -> Option<Asset> {
    match asset {
        TrustLineAsset::Native => Some(Asset::Native),
        TrustLineAsset::CreditAlphanum4(a) => Some(Asset::CreditAlphanum4(a.clone())),
        TrustLineAsset::CreditAlphanum12(a) => Some(Asset::CreditAlphanum12(a.clone())),
        TrustLineAsset::PoolShare(_) => None,
    }
}

pub fn pool_strkey(id: &PoolId) -> String {
    ScAddress::LiquidityPool(id.clone()).to_string()
}

pub fn cb_strkey(id: &ClaimableBalanceId) -> String {
    ScAddress::ClaimableBalance(id.clone()).to_string()
}

pub fn account_strkey(id: &AccountId) -> String {
    id.to_string()
}

/// Base address and muxed id of an `ScAddress`.
pub fn sc_address(a: &ScAddress) -> (String, Option<u64>) {
    match a {
        ScAddress::MuxedAccount(m) => (
            AccountId(PublicKey::PublicKeyTypeEd25519(m.ed25519.clone())).to_string(),
            Some(m.id),
        ),
        ScAddress::MuxedContract(m) => (
            ScAddress::Contract(m.contract_id.clone()).to_string(),
            Some(m.id),
        ),
        other => (other.to_string(), None),
    }
}

/// Base `G…` address and muxed id of a `MuxedAccount`.
pub fn muxed(m: &MuxedAccount) -> (String, Option<u64>) {
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

pub fn i128_of(v: &ScVal) -> Option<i128> {
    match v {
        ScVal::I128(p) => Some((i128::from(p.hi) << 64) | i128::from(p.lo)),
        _ => None,
    }
}

pub fn sym(v: &ScVal) -> Option<&str> {
    match v {
        ScVal::Symbol(s) => std::str::from_utf8(s.0.as_slice()).ok(),
        _ => None,
    }
}

pub fn scval_kind(v: &ScVal) -> &'static str {
    v.name()
}

pub fn key_base64(k: &LedgerKey) -> String {
    use stellar_xdr::WriteXdr;
    k.to_xdr_base64(Limits::none())
        .expect("a decoded key re-encodes")
}

pub fn entry_type(k: &LedgerKey) -> &'static str {
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

/// One transaction of a ledger, in apply order.
pub struct TxView<'a> {
    pub result: &'a TransactionResultPair,
    pub fee: &'a LedgerEntryChanges,
    pub meta: &'a TransactionMeta,
    /// `postTxApplyFeeProcessing` (LCM v2 only).
    pub post: Option<&'a LedgerEntryChanges>,
}

pub fn tx_views(lcm: &LedgerCloseMeta) -> Vec<TxView<'_>> {
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

pub fn envelopes(lcm: &LedgerCloseMeta) -> Vec<&TransactionEnvelope> {
    match lcm {
        LedgerCloseMeta::V0(v) => v.tx_set.txs.iter().collect(),
        LedgerCloseMeta::V1(v) => generalized_envelopes(&v.tx_set),
        LedgerCloseMeta::V2(v) => generalized_envelopes(&v.tx_set),
    }
}

pub fn upgrade_lists(lcm: &LedgerCloseMeta) -> Vec<&LedgerEntryChanges> {
    let u = match lcm {
        LedgerCloseMeta::V0(v) => &v.upgrades_processing,
        LedgerCloseMeta::V1(v) => &v.upgrades_processing,
        LedgerCloseMeta::V2(v) => &v.upgrades_processing,
    };
    u.iter().map(|u| &u.changes).collect()
}

pub fn evicted_keys(lcm: &LedgerCloseMeta) -> Vec<&LedgerKey> {
    match lcm {
        LedgerCloseMeta::V0(_) => Vec::new(),
        LedgerCloseMeta::V1(v) => v.evicted_keys.iter().collect(),
        LedgerCloseMeta::V2(v) => v.evicted_keys.iter().collect(),
    }
}

pub fn header(lcm: &LedgerCloseMeta) -> &stellar_xdr::LedgerHeaderHistoryEntry {
    match lcm {
        LedgerCloseMeta::V0(v) => &v.ledger_header,
        LedgerCloseMeta::V1(v) => &v.ledger_header,
        LedgerCloseMeta::V2(v) => &v.ledger_header,
    }
}

/// The parts of an envelope the judge reads.
pub struct Env {
    pub fee_source: Option<MuxedAccount>,
    pub source: MuxedAccount,
    pub ops: Vec<Operation>,
    pub inner_hash: Option<[u8; 32]>,
}

pub fn env_parts(e: &TransactionEnvelope, nid: [u8; 32]) -> Env {
    match e {
        TransactionEnvelope::TxV0(v) => Env {
            fee_source: None,
            source: MuxedAccount::Ed25519(v.tx.source_account_ed25519.clone()),
            ops: v.tx.operations.to_vec(),
            inner_hash: None,
        },
        TransactionEnvelope::Tx(v) => Env {
            fee_source: None,
            source: v.tx.source_account.clone(),
            ops: v.tx.operations.to_vec(),
            inner_hash: None,
        },
        TransactionEnvelope::TxFeeBump(v) => {
            let stellar_xdr::FeeBumpTransactionInnerTx::Tx(inner) = &v.tx.inner_tx;
            Env {
                fee_source: Some(v.tx.fee_source.clone()),
                source: inner.tx.source_account.clone(),
                ops: inner.tx.operations.to_vec(),
                inner_hash: inner.hash(nid).ok(),
            }
        }
    }
}

/// The accounts an operation names besides its source (destinations, trustors, sponsored ids).
pub fn op_counterparties(op: &Operation) -> Vec<(String, Option<u64>)> {
    let acct = |a: &AccountId| (account_strkey(a), None);
    match &op.body {
        OperationBody::CreateAccount(o) => vec![acct(&o.destination)],
        OperationBody::Payment(o) => vec![muxed(&o.destination)],
        OperationBody::PathPaymentStrictReceive(o) => vec![muxed(&o.destination)],
        OperationBody::PathPaymentStrictSend(o) => vec![muxed(&o.destination)],
        OperationBody::AccountMerge(m) => vec![muxed(m)],
        OperationBody::Clawback(o) => vec![muxed(&o.from)],
        OperationBody::AllowTrust(o) => vec![acct(&o.trustor)],
        OperationBody::SetTrustLineFlags(o) => vec![acct(&o.trustor)],
        OperationBody::BeginSponsoringFutureReserves(o) => vec![acct(&o.sponsored_id)],
        _ => Vec::new(),
    }
}

/// The claimants an operation names (CreateClaimableBalance).
pub fn op_claimants(op: &Operation) -> Vec<String> {
    match &op.body {
        OperationBody::CreateClaimableBalance(o) => o
            .claimants
            .iter()
            .map(|c| {
                let stellar_xdr::Claimant::ClaimantTypeV0(v) = c;
                account_strkey(&v.destination)
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// A signer key as stored bytes in hex: the strkey version byte, then the key's payload (32 bytes for
/// ed25519, pre-auth-tx and hash-x keys; for a CAP-40 signed payload the XDR of the key: ed25519, length,
/// padded payload). This is the strkey's content without its checksum, for every signer type.
pub fn signer_hex(k: &stellar_xdr::SignerKey) -> String {
    use stellar_xdr::SignerKey as S;
    match k {
        S::Ed25519(u) => format!("30{}", hex::encode(u.0)),
        S::PreAuthTx(u) => format!("98{}", hex::encode(u.0)),
        S::HashX(u) => format!("b8{}", hex::encode(u.0)),
        S::Ed25519SignedPayload(p) => format!(
            "78{}",
            hex::encode(p.to_xdr(Limits::none()).expect("a decoded key re-encodes"))
        ),
    }
}

/// A stable, readable name of the ledger entry a key identifies: `account:G…`, `trustline:G…:CODE:ISSUER`
/// (or `:pool:<hex>`), `data:G…:<name hex>`, `offer:G…:<id>`, `claimable_balance:B…`, `liquidity_pool:L…`;
/// other entries `<type>:<key base64>`.
pub fn key_subject(k: &LedgerKey) -> String {
    match k {
        LedgerKey::Account(a) => format!("account:{}", account_strkey(&a.account_id)),
        LedgerKey::Trustline(t) => {
            let asset = match &t.asset {
                TrustLineAsset::PoolShare(p) => format!("pool:{}", hex::encode(p.0 .0)),
                other => trustline_asset(other)
                    .map(|a| asset_string(&a))
                    .unwrap_or_default(),
            };
            format!("trustline:{}:{}", account_strkey(&t.account_id), asset)
        }
        LedgerKey::Data(d) => format!(
            "data:{}:{}",
            account_strkey(&d.account_id),
            hex::encode(d.data_name.0.as_slice())
        ),
        LedgerKey::Offer(o) => format!("offer:{}:{}", account_strkey(&o.seller_id), o.offer_id),
        LedgerKey::ClaimableBalance(c) => format!("claimable_balance:{}", cb_strkey(&c.balance_id)),
        LedgerKey::LiquidityPool(p) => {
            format!("liquidity_pool:{}", pool_strkey(&p.liquidity_pool_id))
        }
        other => format!("{}:{}", entry_type(other), key_base64(other)),
    }
}

/// Operation-level change lists and events, and transaction-level events, of one meta.
pub struct MetaParts<'a> {
    pub version: u32,
    pub before: Option<&'a LedgerEntryChanges>,
    pub after: Option<&'a LedgerEntryChanges>,
    pub ops: Vec<&'a LedgerEntryChanges>,
    pub op_events: Vec<Vec<&'a ContractEvent>>,
    pub tx_events: Vec<(TransactionEventStage, &'a ContractEvent)>,
}

pub fn meta_parts(m: &TransactionMeta) -> MetaParts<'_> {
    let mut p = MetaParts {
        version: 0,
        before: None,
        after: None,
        ops: Vec::new(),
        op_events: Vec::new(),
        tx_events: Vec::new(),
    };
    match m {
        TransactionMeta::V0(ops) => p.ops = ops.iter().map(|o| &o.changes).collect(),
        TransactionMeta::V1(v) => {
            p.version = 1;
            p.before = Some(&v.tx_changes);
            p.ops = v.operations.iter().map(|o| &o.changes).collect();
        }
        TransactionMeta::V2(v) => {
            p.version = 2;
            p.before = Some(&v.tx_changes_before);
            p.after = Some(&v.tx_changes_after);
            p.ops = v.operations.iter().map(|o| &o.changes).collect();
        }
        TransactionMeta::V3(v) => {
            p.version = 3;
            p.before = Some(&v.tx_changes_before);
            p.after = Some(&v.tx_changes_after);
            p.ops = v.operations.iter().map(|o| &o.changes).collect();
            // A Soroban transaction has exactly one operation; its events are that operation's.
            if let Some(s) = &v.soroban_meta {
                p.op_events = vec![s.events.iter().collect()];
            }
        }
        TransactionMeta::V4(v) => {
            p.version = 4;
            p.before = Some(&v.tx_changes_before);
            p.after = Some(&v.tx_changes_after);
            p.ops = v.operations.iter().map(|o| &o.changes).collect();
            p.op_events = v
                .operations
                .iter()
                .map(|o| o.events.iter().collect())
                .collect();
            p.tx_events = v.events.iter().map(|e| (e.stage, &e.event)).collect();
        }
    }
    p.op_events
        .resize_with(p.ops.len().max(p.op_events.len()), Vec::new);
    p
}

pub fn event_topics(e: &ContractEvent) -> (&[ScVal], &ScVal) {
    let ContractEventBody::V0(b) = &e.body;
    (b.topics.as_slice(), &b.data)
}

pub fn event_contract(e: &ContractEvent) -> Option<[u8; 32]> {
    e.contract_id.as_ref().map(|c| c.0 .0)
}
