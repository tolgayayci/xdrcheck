//! Recall checks of the shape definition.
//!
//! `recall`: each case names a ledger and an independent predicate, evaluated on the oracle's typed
//! decode (not on tokens). The trigger transactions are those the predicate holds for; a case is
//! separated at a view when no trigger transaction's transaction shape equals that of a
//! non-trigger transaction of the same ledger, and its carrying token is present when every trigger
//! transaction's components hold the token the predicate names.
//!
//! `heldout`: pinpointed transactions of corpus entries; separated when no other transaction of
//! the ledger has the same transaction shape.
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use xdrcheck_xdr::xdr::{
    ContractEvent, ContractEventBody, FeeBumpTransactionInnerTx, LedgerCloseMeta, LedgerEntry,
    LedgerEntryChange, LedgerEntryData, LedgerKey, MuxedAccount, Operation, OperationBody, ScVal,
    SorobanTransactionMetaExt, TransactionEnvelope, TransactionExt, TransactionMeta,
};
use xdrcheck_xdr::{Gate, Limits};

use super::report::{level, project, RunData, View};
use super::shape::Id;
use super::source::Source;

#[derive(clap::Args, Debug)]
pub struct RecallArgs {
    #[arg(long = "run", required = true)]
    pub runs: Vec<PathBuf>,
    /// Local packs holding the case ledgers
    #[arg(long)]
    pub packs: Option<PathBuf>,
    /// A directory laid out like the lake holding the case ledgers
    #[arg(long)]
    pub lake: Option<PathBuf>,
    /// Cases TSV: name, seq, predicate, focus (tx hash prefix or -)
    #[arg(long)]
    pub cases: PathBuf,
    /// Extra views: custom kind sets (`T+X+K`), comma-separated
    #[arg(long, default_value = "")]
    pub views: String,
}

#[derive(clap::Args, Debug)]
pub struct HeldoutArgs {
    #[arg(long = "run", required = true)]
    pub runs: Vec<PathBuf>,
    /// Corpus manifest directory
    #[arg(long)]
    pub manifests: PathBuf,
    /// Ledgers the grammar was derived from (excluded), one per line
    #[arg(long)]
    pub exclude: PathBuf,
}

struct Tx<'a> {
    hash: String,
    env: &'a TransactionEnvelope,
    meta: &'a TransactionMeta,
    post: usize,
    res: &'a xdrcheck_xdr::xdr::TransactionResult,
}

impl<'a> Tx<'a> {
    fn ops(&self) -> &'a [Operation] {
        match self.env {
            TransactionEnvelope::TxV0(e) => &e.tx.operations,
            TransactionEnvelope::Tx(e) => &e.tx.operations,
            TransactionEnvelope::TxFeeBump(e) => {
                let FeeBumpTransactionInnerTx::Tx(i) = &e.tx.inner_tx;
                &i.tx.operations
            }
        }
    }
    fn ext(&self) -> Option<&'a TransactionExt> {
        match self.env {
            TransactionEnvelope::TxV0(_) => None,
            TransactionEnvelope::Tx(e) => Some(&e.tx.ext),
            TransactionEnvelope::TxFeeBump(e) => {
                let FeeBumpTransactionInnerTx::Tx(i) = &e.tx.inner_tx;
                Some(&i.tx.ext)
            }
        }
    }
    fn op_changes(&self, j: usize) -> &'a [LedgerEntryChange] {
        match self.meta {
            TransactionMeta::V0(v) => v.get(j).map(|o| &o.changes.0[..]).unwrap_or(&[]),
            TransactionMeta::V1(v) => v.operations.get(j).map(|o| &o.changes.0[..]).unwrap_or(&[]),
            TransactionMeta::V2(v) => v.operations.get(j).map(|o| &o.changes.0[..]).unwrap_or(&[]),
            TransactionMeta::V3(v) => v.operations.get(j).map(|o| &o.changes.0[..]).unwrap_or(&[]),
            TransactionMeta::V4(v) => v.operations.get(j).map(|o| &o.changes.0[..]).unwrap_or(&[]),
        }
    }
    fn events(&self) -> Vec<&'a ContractEvent> {
        match self.meta {
            TransactionMeta::V4(v) => v
                .operations
                .iter()
                .flat_map(|o| o.events.iter())
                .chain(v.events.iter().map(|t| &t.event))
                .collect(),
            TransactionMeta::V3(v) => v
                .soroban_meta
                .iter()
                .flat_map(|s| s.events.iter())
                .collect(),
            _ => Vec::new(),
        }
    }
    /// The first STATE → UPDATED pair of an entry of `kind` in operation `j`'s changes.
    fn pair(&self, j: usize, kind: &str) -> Option<(&'a LedgerEntryData, &'a LedgerEntryData)> {
        let ch = self.op_changes(j);
        for w in ch.windows(2) {
            if let (LedgerEntryChange::State(a), LedgerEntryChange::Updated(b)) = (&w[0], &w[1]) {
                if a.to_key() == b.to_key() && entry_kind(a) == kind {
                    return Some((&a.data, &b.data));
                }
            }
        }
        None
    }
}

fn entry_kind(e: &LedgerEntry) -> &'static str {
    match e.to_key() {
        LedgerKey::Account(_) => "ACCOUNT",
        LedgerKey::Trustline(_) => "TRUSTLINE",
        LedgerKey::Data(_) => "DATA",
        _ => "OTHER",
    }
}

fn topics(ev: &ContractEvent) -> &[ScVal] {
    let ContractEventBody::V0(b) = &ev.body;
    &b.topics
}
fn data(ev: &ContractEvent) -> &ScVal {
    let ContractEventBody::V0(b) = &ev.body;
    &b.data
}
fn is_sym(v: &ScVal, s: &str) -> bool {
    matches!(v, ScVal::Symbol(x) if x.0.as_vec() == s.as_bytes())
}
fn muxed_high(m: &MuxedAccount) -> bool {
    matches!(m, MuxedAccount::MuxedEd25519(x) if x.id >= 1 << 63)
}
fn gcd(a: i64, b: i64) -> i64 {
    if b == 0 {
        a.abs()
    } else {
        gcd(b, a % b)
    }
}

fn op_results_of(r: &xdrcheck_xdr::xdr::TransactionResult) -> &[xdrcheck_xdr::xdr::OperationResult] {
    use xdrcheck_xdr::xdr::{InnerTransactionResultResult as I, TransactionResultResult as R};
    match &r.result {
        R::TxSuccess(v) | R::TxFailed(v) => v,
        R::TxFeeBumpInnerSuccess(p) | R::TxFeeBumpInnerFailed(p) => match &p.result.result {
            I::TxSuccess(v) | I::TxFailed(v) => v,
            _ => &[],
        },
        _ => &[],
    }
}

fn claim_atoms(o: &xdrcheck_xdr::xdr::OperationResult) -> Vec<&xdrcheck_xdr::xdr::ClaimAtom> {
    use xdrcheck_xdr::xdr::{
        ManageBuyOfferResult, ManageSellOfferResult, OperationResult as O, OperationResultTr as T,
        PathPaymentStrictReceiveResult, PathPaymentStrictSendResult,
    };
    match o {
        O::OpInner(T::ManageSellOffer(ManageSellOfferResult::Success(x)))
        | O::OpInner(T::CreatePassiveSellOffer(ManageSellOfferResult::Success(x)))
        | O::OpInner(T::ManageBuyOffer(ManageBuyOfferResult::Success(x))) => {
            x.offers_claimed.iter().collect()
        }
        O::OpInner(T::PathPaymentStrictReceive(PathPaymentStrictReceiveResult::Success(x))) => {
            x.offers.iter().collect()
        }
        O::OpInner(T::PathPaymentStrictSend(PathPaymentStrictSendResult::Success(x))) => {
            x.offers.iter().collect()
        }
        _ => Vec::new(),
    }
}

fn muxed_ids(t: &Tx) -> Vec<u64> {
    let mut v = Vec::new();
    let mut m = |x: &MuxedAccount| {
        if let MuxedAccount::MuxedEd25519(x) = x {
            v.push(x.id);
        }
    };
    match t.env {
        TransactionEnvelope::Tx(e) => m(&e.tx.source_account),
        TransactionEnvelope::TxFeeBump(e) => {
            m(&e.tx.fee_source);
            let FeeBumpTransactionInnerTx::Tx(i) = &e.tx.inner_tx;
            m(&i.tx.source_account);
        }
        _ => {}
    }
    for o in t.ops() {
        if let Some(s) = &o.source_account {
            m(s);
        }
        match &o.body {
            OperationBody::Payment(x) => m(&x.destination),
            OperationBody::PathPaymentStrictReceive(x) => m(&x.destination),
            OperationBody::PathPaymentStrictSend(x) => m(&x.destination),
            OperationBody::AccountMerge(x) => m(x),
            OperationBody::Clawback(x) => m(&x.from),
            _ => {}
        }
    }
    v
}

fn sc_error_not_contract(v: &ScVal) -> bool {
    match v {
        ScVal::Error(e) => !matches!(e, xdrcheck_xdr::xdr::ScError::Contract(_)),
        ScVal::Vec(Some(x)) => x.0.iter().any(sc_error_not_contract),
        ScVal::Map(Some(m)) => {
            m.0.iter()
                .any(|e| sc_error_not_contract(&e.key) || sc_error_not_contract(&e.val))
        }
        _ => false,
    }
}

/// Every event of the transaction, diagnostic events included.
fn all_events<'a>(t: &Tx<'a>) -> Vec<&'a ContractEvent> {
    let mut v = t.events();
    match t.meta {
        TransactionMeta::V4(m) => v.extend(m.diagnostic_events.iter().map(|d| &d.event)),
        TransactionMeta::V3(m) => v.extend(
            m.soroban_meta
                .iter()
                .flat_map(|s| s.diagnostic_events.iter().map(|d| &d.event)),
        ),
        _ => {}
    }
    v
}

fn neg_i128(v: &ScVal) -> bool {
    match v {
        ScVal::I128(p) => p.hi < 0,
        ScVal::Vec(Some(x)) => x.0.iter().any(neg_i128),
        ScVal::Map(Some(m)) => m.0.iter().any(|e| neg_i128(&e.key) || neg_i128(&e.val)),
        _ => false,
    }
}

fn all_changes<'a>(t: &Tx<'a>) -> Vec<&'a LedgerEntryChange> {
    let mut v: Vec<&LedgerEntryChange> = Vec::new();
    for j in 0..t.ops().len() {
        v.extend(t.op_changes(j).iter());
    }
    match t.meta {
        TransactionMeta::V1(m) => v.extend(m.tx_changes.iter()),
        TransactionMeta::V2(m) => {
            v.extend(m.tx_changes_before.iter().chain(m.tx_changes_after.iter()))
        }
        TransactionMeta::V3(m) => {
            v.extend(m.tx_changes_before.iter().chain(m.tx_changes_after.iter()))
        }
        TransactionMeta::V4(m) => {
            v.extend(m.tx_changes_before.iter().chain(m.tx_changes_after.iter()))
        }
        _ => {}
    }
    v
}

fn ext_arm_changes(a: &LedgerEntry, b: &LedgerEntry) -> bool {
    if a.ext.discriminant() != b.ext.discriminant() {
        return true;
    }
    match (&a.data, &b.data) {
        (LedgerEntryData::Account(x), LedgerEntryData::Account(y)) => {
            x.ext.discriminant() != y.ext.discriminant()
        }
        (LedgerEntryData::Trustline(x), LedgerEntryData::Trustline(y)) => {
            x.ext.discriminant() != y.ext.discriminant()
        }
        _ => false,
    }
}

type Pred = fn(&Tx) -> bool;
type Carry = fn(&BTreeSet<&str>) -> bool;

fn any_tok(t: &BTreeSet<&str>, f: impl Fn(&str) -> bool) -> bool {
    t.iter().any(|x| f(x))
}

/// The independent predicates and the token each one must find.
fn predicate(name: &str) -> Option<(Pred, Carry)> {
    let p: (Pred, Carry) = match name {
        "legacy_mint_event" => (
            |t| {
                t.events().iter().any(|e| {
                    let tp = topics(e);
                    tp.len() == 3
                        && is_sym(&tp[0], "mint")
                        && matches!(tp[1], ScVal::Address(_))
                        && matches!(tp[2], ScVal::Address(_))
                })
            },
            |t| {
                any_tok(t, |x| {
                    x.starts_with("X|")
                        && x.contains(":mint:[ADDR:")
                        && x.matches("ADDR:").count() >= 2
                })
            },
        ),
        "mint_three_topics_string_by_invoke" => (
            |t| {
                t.ops()
                    .iter()
                    .any(|o| matches!(o.body, OperationBody::InvokeHostFunction(_)))
                    && t.events().iter().any(|e| {
                        let tp = topics(e);
                        tp.len() == 3 && is_sym(&tp[0], "mint") && matches!(tp[2], ScVal::String(_))
                    })
            },
            |t| {
                any_tok(t, |x| {
                    x.starts_with("X|") && x.contains(":mint:[") && x.contains(",STRING]")
                })
            },
        ),
        "v0_no_timebounds" => (
            |t| matches!(t.env, TransactionEnvelope::TxV0(e) if e.tx.time_bounds.is_none()),
            |t| t.contains("T|opt|TransactionV0.timeBounds?none"),
        ),
        "post_apply_fee_changes" => (
            |t| t.post > 0,
            |t| any_tok(t, |x| x.contains("|postfee#len=") && !x.ends_with("#len=0")),
        ),
        "soroban_meta_ext_v1" => (
            |t| match t.meta {
                TransactionMeta::V4(v) => {
                    matches!(&v.soroban_meta, Some(s) if matches!(s.ext, SorobanTransactionMetaExt::V1(_)))
                }
                TransactionMeta::V3(v) => {
                    matches!(&v.soroban_meta, Some(s) if matches!(s.ext, SorobanTransactionMetaExt::V1(_)))
                }
                _ => false,
            },
            |t| t.contains("T|arm|SorobanTransactionMetaExt::v1"),
        ),
        "footprint_code_not_first" => (
            |t| match t.ext() {
                Some(TransactionExt::V1(d)) => {
                    let ro = &d.resources.footprint.read_only;
                    !ro.is_empty()
                        && !matches!(ro[0], LedgerKey::ContractCode(_))
                        && ro.iter().any(|k| matches!(k, LedgerKey::ContractCode(_)))
                }
                _ => false,
            },
            |t| {
                any_tok(t, |x| {
                    x.contains("readOnly#first=")
                        && !x.contains("#first=CONTRACT_CODE")
                        && x.contains("CONTRACT_CODE")
                })
            },
        ),
        "soroban_fee_bump" => (
            |t| {
                matches!(t.env, TransactionEnvelope::TxFeeBump(_))
                    && matches!(t.ext(), Some(TransactionExt::V1(_)))
            },
            |t| {
                t.contains("T|arm|TransactionEnvelope::ENVELOPE_TYPE_TX_FEE_BUMP")
                    && t.contains("T|arm|TransactionExt::v1")
            },
        ),
        "price_unreduced" => (
            |t| {
                t.ops().iter().any(|o| {
                    let p = match &o.body {
                        OperationBody::ManageSellOffer(x) => Some(&x.price),
                        OperationBody::ManageBuyOffer(x) => Some(&x.price),
                        OperationBody::CreatePassiveSellOffer(x) => Some(&x.price),
                        _ => None,
                    };
                    p.is_some_and(|p| p.d != 0 && p.n != 0 && gcd(p.n as i64, p.d as i64) > 1)
                })
            },
            |t| any_tok(t, |x| x.ends_with("#price=unreduced")),
        ),
        "noop_change_trust" => (
            |t| {
                t.ops().iter().enumerate().any(|(j, o)| {
                matches!(o.body, OperationBody::ChangeTrust(_))
                    && matches!(t.pair(j, "TRUSTLINE"), Some((LedgerEntryData::Trustline(a), LedgerEntryData::Trustline(b))) if a.limit == b.limit)
            })
            },
            |t| any_tok(t, |x| x.ends_with("rel:change_trust:limit=same")),
        ),
        "set_options_same_threshold" => (
            |t| {
                t.ops()
                    .iter()
                    .enumerate()
                    .any(|(j, o)| match (&o.body, t.pair(j, "ACCOUNT")) {
                        (
                            OperationBody::SetOptions(s),
                            Some((LedgerEntryData::Account(a), LedgerEntryData::Account(b))),
                        ) => [
                            s.master_weight,
                            s.low_threshold,
                            s.med_threshold,
                            s.high_threshold,
                        ]
                        .iter()
                        .enumerate()
                        .any(|(i, v)| v.is_some() && a.thresholds.0[i] == b.thresholds.0[i]),
                        _ => false,
                    })
            },
            |t| {
                any_tok(t, |x| {
                    x.contains("rel:set_options:")
                        && (x.contains("Threshold=same") || x.contains("masterWeight=same"))
                })
            },
        ),
        "noop_manage_data" => (
            |t| {
                t.ops().iter().enumerate().any(|(j, o)| {
                matches!(o.body, OperationBody::ManageData(_))
                    && matches!(t.pair(j, "DATA"), Some((LedgerEntryData::Data(a), LedgerEntryData::Data(b))) if a.data_value == b.data_value)
            })
            },
            |t| any_tok(t, |x| x.ends_with("rel:manage_data:value=same")),
        ),
        "set_flags_some_already_set" => (
            |t| {
                t.ops()
                    .iter()
                    .enumerate()
                    .any(|(j, o)| match (&o.body, t.pair(j, "ACCOUNT")) {
                        (OperationBody::SetOptions(s), Some((LedgerEntryData::Account(a), _))) => {
                            s.set_flags.is_some_and(|f| f & a.flags != 0)
                        }
                        _ => false,
                    })
            },
            |t| any_tok(t, |x| x.ends_with("setFlags=some-already-set")),
        ),
        "allow_trust_revoke_from_authorized" => (
            |t| {
                t.ops()
                    .iter()
                    .enumerate()
                    .any(|(j, o)| match (&o.body, t.pair(j, "TRUSTLINE")) {
                        (
                            OperationBody::AllowTrust(s),
                            Some((LedgerEntryData::Trustline(a), _)),
                        ) => s.authorize == 0 && a.flags & 3 == 1,
                        _ => false,
                    })
            },
            |t| any_tok(t, |x| x.contains("rel:allow_trust:authorize=0:flags=1>")),
        ),
        "stlf_clear_unset" => (
            |t| {
                t.ops()
                    .iter()
                    .enumerate()
                    .any(|(j, o)| match (&o.body, t.pair(j, "TRUSTLINE")) {
                        (
                            OperationBody::SetTrustLineFlags(s),
                            Some((LedgerEntryData::Trustline(a), _)),
                        ) => s.clear_flags & !a.flags != 0,
                        _ => false,
                    })
            },
            |t| {
                any_tok(t, |x| {
                    x.contains("rel:stlf:") && x.ends_with("clear=some-already-clear")
                })
            },
        ),
        "stlf_set_already_set" => (
            |t| {
                t.ops()
                    .iter()
                    .enumerate()
                    .any(|(j, o)| match (&o.body, t.pair(j, "TRUSTLINE")) {
                        (
                            OperationBody::SetTrustLineFlags(s),
                            Some((LedgerEntryData::Trustline(a), _)),
                        ) => s.set_flags & a.flags != 0,
                        _ => false,
                    })
            },
            |t| any_tok(t, |x| x.contains("rel:stlf:set=some-already-set")),
        ),
        "extend_footprint_ttl" => (
            |t| {
                t.ops()
                    .iter()
                    .any(|o| matches!(o.body, OperationBody::ExtendFootprintTtl(_)))
            },
            |t| t.contains("T|arm|OperationBody::EXTEND_FOOTPRINT_TTL"),
        ),
        "muxed_id_high" => (
            |t| match t.env {
                TransactionEnvelope::Tx(e) => muxed_high(&e.tx.source_account),
                TransactionEnvelope::TxFeeBump(e) => {
                    let FeeBumpTransactionInnerTx::Tx(i) = &e.tx.inner_tx;
                    muxed_high(&e.tx.fee_source) || muxed_high(&i.tx.source_account)
                }
                _ => false,
            },
            |t| any_tok(t, |x| x.ends_with("#u64=>=2^63")),
        ),
        "to_muxed_id_in_event_data" => (
            |t| {
                t.events().iter().any(|e| matches!(data(e), ScVal::Map(Some(m)) if m.0.iter().any(|x| is_sym(&x.key, "to_muxed_id"))))
            },
            |t| any_tok(t, |x| x.starts_with("X|") && x.contains("to_muxed_id:")),
        ),
        "entry_ext_arm_changes" => (
            |t| {
                let ch = all_changes(t);
                ch.windows(2).any(|w| match (w[0], w[1]) {
                    (LedgerEntryChange::State(a), LedgerEntryChange::Updated(b)) => {
                        a.to_key() == b.to_key() && ext_arm_changes(a, b)
                    }
                    _ => false,
                })
            },
            |t| {
                any_tok(t, |x| {
                    x.starts_with("D|upd|") && x.contains("::v") && x.contains(">v")
                })
            },
        ),
        "mixed_claim_atoms" => (
            |t| {
                op_results_of(t.res).iter().any(|o| {
                    let arms: BTreeSet<i32> = claim_atoms(o)
                        .iter()
                        .map(|a| a.discriminant() as i32)
                        .collect();
                    arms.len() >= 2
                })
            },
            |t| {
                any_tok(t, |x| {
                    x.starts_with("K|") && x.matches("CLAIM_ATOM_TYPE_").count() >= 3
                })
            },
        ),
        "muxed_id_zero" => (
            |t| muxed_ids(t).contains(&0),
            |t| any_tok(t, |x| x.ends_with("#u64=0")),
        ),
        "muxed_id_2_53_to_2_63" => (
            |t| muxed_ids(t).iter().any(|i| (1 << 53..1 << 63).contains(i)),
            |t| any_tok(t, |x| x.ends_with("#u64=<2^63")),
        ),
        "negative_i128_in_events" => (
            |t| {
                t.events()
                    .iter()
                    .any(|e| topics(e).iter().any(neg_i128) || neg_i128(data(e)))
            },
            |t| any_tok(t, |x| x.contains("i128-negative")),
        ),
        "sc_error_not_contract_in_events" => (
            |t| {
                all_events(t).iter().any(|e| {
                    topics(e).iter().any(sc_error_not_contract) || sc_error_not_contract(data(e))
                })
            },
            |t| {
                any_tok(t, |x| {
                    x.starts_with("T|arm|SCError::SCE_") && !x.ends_with("SCE_CONTRACT")
                })
            },
        ),
        "invoke_creates_account" => (
            |t| {
                t.ops().iter().enumerate().any(|(j, o)| {
                    matches!(o.body, OperationBody::InvokeHostFunction(_))
                        && t.op_changes(j).iter().any(|c| matches!(c, LedgerEntryChange::Created(e) if matches!(e.data, LedgerEntryData::Account(_))))
                })
            },
            |t| {
                any_tok(t, |x| {
                    x.contains("op:INVOKE_HOST_FUNCTION#chg:CREATED:ACCOUNT")
                })
            },
        ),
        _ => return None,
    };
    Some(p)
}

fn load_ledger(src: &Source, seq: u32) -> Result<Vec<u8>> {
    let f = src.get(seq, false)?;
    let obj = f
        .bytes
        .with_context(|| format!("ledger {seq} not in the source"))?;
    let xdr = xdrcheck_xdr::batch::decompress(&obj)?;
    let b = xdrcheck_xdr::split_batch(&xdr, &Limits::default(), &Gate::default().reading_live())?;
    Ok(b.ledgers[0].clone())
}

fn txs_of<'a>(lcm: &'a LedgerCloseMeta) -> Result<Vec<Tx<'a>>> {
    let net: [u8; 32] = Sha256::digest(super::PUBNET_PASSPHRASE.as_bytes()).into();
    let mut envs: HashMap<[u8; 32], &TransactionEnvelope> = HashMap::new();
    let all: Vec<&TransactionEnvelope> = match lcm {
        LedgerCloseMeta::V0(m) => m.tx_set.txs.iter().collect(),
        LedgerCloseMeta::V1(m) => gen_envs(&m.tx_set),
        LedgerCloseMeta::V2(m) => gen_envs(&m.tx_set),
    };
    for e in all {
        envs.insert(e.hash(net)?, e);
    }
    let mut out = Vec::new();
    let mut push = |h: &[u8; 32],
                    meta: &'a TransactionMeta,
                    post: usize,
                    res: &'a xdrcheck_xdr::xdr::TransactionResult|
     -> Result<()> {
        let env = *envs.get(h).context("join")?;
        out.push(Tx {
            hash: hex::encode(h),
            env,
            meta,
            post,
            res,
        });
        Ok(())
    };
    match lcm {
        LedgerCloseMeta::V0(m) => m.tx_processing.iter().try_for_each(|t| {
            push(
                &t.result.transaction_hash.0,
                &t.tx_apply_processing,
                0,
                &t.result.result,
            )
        })?,
        LedgerCloseMeta::V1(m) => m.tx_processing.iter().try_for_each(|t| {
            push(
                &t.result.transaction_hash.0,
                &t.tx_apply_processing,
                0,
                &t.result.result,
            )
        })?,
        LedgerCloseMeta::V2(m) => m.tx_processing.iter().try_for_each(|t| {
            push(
                &t.result.transaction_hash.0,
                &t.tx_apply_processing,
                t.post_tx_apply_fee_processing.len(),
                &t.result.result,
            )
        })?,
    }
    Ok(out)
}

fn gen_envs(s: &xdrcheck_xdr::xdr::GeneralizedTransactionSet) -> Vec<&TransactionEnvelope> {
    let xdrcheck_xdr::xdr::GeneralizedTransactionSet::V1(s) = s;
    let mut out = Vec::new();
    for ph in s.phases.iter() {
        match ph {
            xdrcheck_xdr::xdr::TransactionPhase::V0(cs) => {
                for c in cs.iter() {
                    let xdrcheck_xdr::xdr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) = c;
                    out.extend(c.txs.iter());
                }
            }
            xdrcheck_xdr::xdr::TransactionPhase::V1(p) => {
                for st in p.execution_stages.iter() {
                    for cl in st.0.iter() {
                        out.extend(cl.0.iter());
                    }
                }
            }
        }
    }
    out
}

/// Apply index -> G3 tx shape, for one ledger.
fn shapes_of(d: &RunData, seq: u32) -> BTreeMap<u16, Id> {
    let mut m = BTreeMap::new();
    for (s, sh, ix) in &d.occ {
        if *s == seq {
            for i in ix {
                m.insert(*i, *sh);
            }
        }
    }
    m
}

fn views() -> Vec<View> {
    let mut v: Vec<View> = ["G0", "G1", "G2", "G3"].iter().map(|l| level(l)).collect();
    for k in ["L", "V", "S", "K", "X", "D", "R"] {
        let mut x = level("G3");
        x.kinds.remove(k);
        x.name = format!("G3-{k}");
        v.push(x);
    }
    v
}

pub fn recall(a: RecallArgs) -> Result<()> {
    let d = RunData::load(&a.runs)?;
    let src = match (&a.packs, &a.lake) {
        (Some(p), _) => Source::packs(p.clone()),
        (None, Some(l)) => Source::Dir(l.clone()),
        _ => bail!("give --packs or --lake"),
    };
    let mut vs = views();
    vs.extend(a.views.split(',').filter(|s| !s.is_empty()).map(level));
    let projs: Vec<_> = vs.iter().map(|v| project(&d, v)).collect();
    println!(
        "case\tseq\ttxs\ttrigger\tordinary\t{}\tcarrying\tfocus\tverdict",
        vs.iter()
            .map(|v| v.name.clone())
            .collect::<Vec<_>>()
            .join("\t")
    );
    for line in std::fs::read_to_string(&a.cases)?
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let f: Vec<&str> = line.split('\t').collect();
        let (name, seq, pname, focus) = (
            f[0],
            f[1].parse::<u32>()?,
            f[2],
            f.get(3).copied().unwrap_or("-"),
        );
        let (pred, carry) = predicate(pname).with_context(|| format!("no predicate {pname}"))?;
        let blob = match load_ledger(&src, seq) {
            Ok(b) => b,
            Err(e) => {
                println!("{name}\t{seq}\t-\t-\t-\tnot available: {e:#}");
                continue;
            }
        };
        let lcm = xdrcheck_xdr::with_stack(256 << 20, || {
            xdrcheck_xdr::decode_ledger(&blob, &Limits::default(), &Gate::default().reading_live())
        })?;
        let txs = txs_of(&lcm)?;
        let sh = shapes_of(&d, seq);
        if sh.len() != txs.len() {
            println!(
                "{name}\t{seq}\t{}\t-\t-\tnot in the run ({} shapes)",
                txs.len(),
                sh.len()
            );
            continue;
        }
        let pos: Vec<usize> = (0..txs.len()).filter(|&i| pred(&txs[i])).collect();
        let neg: Vec<usize> = (0..txs.len()).filter(|&i| !pred(&txs[i])).collect();
        let mut cols = Vec::new();
        for p in &projs {
            let negs: HashSet<Id> = neg.iter().map(|i| p.shape[&sh[&(*i as u16)]]).collect();
            let c = pos
                .iter()
                .filter(|i| negs.contains(&p.shape[&sh[&(**i as u16)]]))
                .count();
            cols.push(if neg.is_empty() {
                "-".to_string()
            } else {
                format!("{c}/{}", pos.len())
            });
        }
        let carrying = pos
            .iter()
            .filter(|&&i| {
                let s = &d.shapes[&sh[&(i as u16)]];
                let toks: BTreeSet<&str> = s
                    .comps()
                    .flat_map(|c| d.comps[c].tokens.iter().map(|x| x.as_str()))
                    .collect();
                carry(&toks)
            })
            .count();
        let focus_ok = if focus == "-" {
            "-".to_string()
        } else if pos.iter().any(|&i| txs[i].hash.starts_with(focus)) {
            "in-trigger-set".into()
        } else {
            "MISSING".into()
        };
        let g3 = &cols[3];
        let verdict = if pos.is_empty() {
            "NO-TRIGGER"
        } else if neg.is_empty() {
            "NOT-MEASURABLE"
        } else if g3.starts_with("0/") && carrying == pos.len() && focus_ok != "MISSING" {
            "SEPARATED"
        } else {
            "MISS"
        };
        println!(
            "{name}\t{seq}\t{}\t{}\t{}\t{}\t{carrying}/{}\t{focus_ok}\t{verdict}",
            txs.len(),
            pos.len(),
            neg.len(),
            cols.join("\t"),
            pos.len()
        );
    }
    Ok(())
}

pub fn heldout(a: HeldoutArgs) -> Result<()> {
    let d = RunData::load(&a.runs)?;
    let excl: HashSet<u32> = std::fs::read_to_string(&a.exclude)?
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect();
    let projs: Vec<_> = ["G0", "G1", "G2", "G3"]
        .iter()
        .map(|l| (l.to_string(), project(&d, &level(l))))
        .collect();
    let mut files = Vec::new();
    let mut stack = vec![a.manifests.clone()];
    while let Some(p) = stack.pop() {
        for e in std::fs::read_dir(&p)? {
            let e = e?.path();
            if e.is_dir() {
                stack.push(e);
            } else if e.extension().is_some_and(|x| x == "json") {
                files.push(e);
            }
        }
    }
    files.sort();
    println!("entry\tseq\ttx_index\ttxs\tG0\tG1\tG2\tG3_same_shape_txs\tverdict");
    for f in files {
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&f)?)?;
        let id = v["id"].as_str().unwrap_or("?").to_string();
        for var in v["variants"].as_array().cloned().unwrap_or_default() {
            if var["network"] != "pubnet" || var["source"]["kind"] != "history" {
                continue;
            }
            let seq = var["ledger_seq"].as_u64().unwrap_or(0) as u32;
            let Some(ti) = var["focus"]["tx_index"].as_u64() else {
                println!("{id}\t{seq}\t-\t-\t-\t-\t-\t-\tledger-level focus (not measured)");
                continue;
            };
            if excl.contains(&seq) {
                println!(
                    "{id}\t{seq}\t{ti}\t-\t-\t-\t-\t-\texcluded (grammar derived from this ledger)"
                );
                continue;
            }
            let sh = shapes_of(&d, seq);
            let Some(focus) = sh.get(&(ti as u16)) else {
                println!(
                    "{id}\t{seq}\t{ti}\t{}\t-\t-\t-\t-\tnot in the run",
                    sh.len()
                );
                continue;
            };
            let mut cols = Vec::new();
            let mut g3_same = Vec::new();
            for (l, p) in &projs {
                let fid = p.shape[focus];
                let same: Vec<u16> = sh
                    .iter()
                    .filter(|(i, s)| **i != ti as u16 && p.shape[*s] == fid)
                    .map(|(i, _)| *i)
                    .collect();
                cols.push(if same.is_empty() {
                    "unique".to_string()
                } else {
                    format!("{} share", same.len())
                });
                if l == "G3" {
                    g3_same = same;
                }
            }
            let verdict = if g3_same.is_empty() {
                "SEPARATED"
            } else {
                "SHARED"
            };
            let same_list = g3_same
                .iter()
                .take(8)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "{id}\t{seq}\t{ti}\t{}\t{}\t{}\t{}\t{same_list}\t{verdict}",
                sh.len(),
                cols[0],
                cols[1],
                cols[2]
            );
        }
    }
    Ok(())
}
