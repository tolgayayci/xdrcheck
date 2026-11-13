//! A model of how stellar-core 30.0.0 orders the transactions of one ledger, used to choose an
//! apply order (`order` on a scenario step group).
//!
//! Core applies a ledger's transactions in an order derived from the transaction-set hash
//! (`src/herder/TxSetFrame.cpp` at v30.0.0):
//!
//! - the set is serialised with every container sorted by the transactions' full hashes (sha256 of
//!   the envelope XDR): a legacy `TransactionSet` (before Protocol 20) hashes as
//!   `sha256(previous ledger hash ‖ each envelope)`, a `GeneralizedTransactionSet` as the sha256 of
//!   its XDR;
//! - a sequential phase (classic, and Soroban before Protocol 23) is applied per account batch: the
//!   i-th transaction (by sequence number) of every source account forms batch i, and each batch is
//!   sorted by `full hash XOR set hash` (`sortedForApplySequential`, `lessThanXored`);
//! - a parallel phase (Soroban from Protocol 23) keeps its stage and cluster structure; each
//!   cluster is sorted by `full hash XOR set hash`, and the stages by the same key of their first
//!   cluster's first transaction (`sortedForApplyParallel`);
//! - phases are applied in order (classic, then Soroban).
//!
//! The order therefore changes with every transaction byte and differs per passphrase. The model
//! needs the set's [`Shape`]: which phase, component, stage and cluster each transaction is in, and
//! the base fees. [`default_shape`] is what core builds without surge pricing (one component at the
//! ledger's base fee; at Protocol 23 and later every Soroban transaction in one cluster of one
//! stage); [`learn_shape`] reads the shape core actually built from a closed ledger, for a second
//! attempt when the default was wrong.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    DependentTxCluster, GeneralizedTransactionSet, Hash, LedgerCloseMeta, Limits, MuxedAccount,
    ParallelTxExecutionStage, ParallelTxsComponent, TransactionEnvelope, TransactionPhase,
    TransactionSetV1, TxSetComponent, TxSetComponentTxsMaybeDiscountedFee, WriteXdr,
};

/// First protocol with a generalized transaction set.
pub const FIRST_GENERALIZED: u32 = 20;
/// First protocol with a parallel Soroban phase.
pub const FIRST_PARALLEL: u32 = 23;

/// One transaction of the ledger, as the model needs it.
#[derive(Debug, Clone)]
pub struct ModelTx {
    pub envelope: TransactionEnvelope,
    /// sha256 of the envelope XDR (core's full hash).
    pub full_hash: [u8; 32],
    /// The (inner) source account's ed25519 key.
    pub source: [u8; 32],
    /// The (inner) sequence number.
    pub seq: i64,
    /// Whether the transaction is a Soroban one (`ext.v1`).
    pub soroban: bool,
}

impl ModelTx {
    pub fn new(envelope: TransactionEnvelope) -> Result<ModelTx> {
        let bytes = envelope.to_xdr(Limits::none())?;
        let (source, seq, soroban) = match &envelope {
            TransactionEnvelope::TxV0(e) => (e.tx.source_account_ed25519.0, e.tx.seq_num.0, false),
            TransactionEnvelope::Tx(e) => (
                muxed_key(&e.tx.source_account),
                e.tx.seq_num.0,
                matches!(e.tx.ext, stellar_xdr::TransactionExt::V1(_)),
            ),
            TransactionEnvelope::TxFeeBump(e) => match &e.tx.inner_tx {
                stellar_xdr::FeeBumpTransactionInnerTx::Tx(i) => (
                    muxed_key(&i.tx.source_account),
                    i.tx.seq_num.0,
                    matches!(i.tx.ext, stellar_xdr::TransactionExt::V1(_)),
                ),
            },
        };
        Ok(ModelTx {
            full_hash: Sha256::digest(&bytes).into(),
            envelope,
            source,
            seq,
            soroban,
        })
    }
}

fn muxed_key(m: &MuxedAccount) -> [u8; 32] {
    match m {
        MuxedAccount::Ed25519(k) => k.0,
        MuxedAccount::MuxedEd25519(m) => m.ed25519.0,
    }
}

/// Where each transaction sits in the set; transactions are indices into the model's list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shape {
    /// A legacy `TransactionSet` (before Protocol 20).
    Legacy,
    /// A `GeneralizedTransactionSet`, one entry per phase.
    Generalized(Vec<PhaseShape>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhaseShape {
    /// `TransactionPhase::V0`: components (base fee, transactions), in core's order (no base fee
    /// first, then ascending).
    Sequential(Vec<(Option<i64>, Vec<usize>)>),
    /// `TransactionPhase::V1`: base fee and stages of clusters.
    Parallel {
        base_fee: Option<i64>,
        stages: Vec<Vec<Vec<usize>>>,
    },
}

/// The shape core builds for these transactions at `protocol` with base fee `base_fee` when no lane
/// is full (no surge pricing).
pub fn default_shape(protocol: u32, base_fee: i64, txs: &[ModelTx]) -> Shape {
    if protocol < FIRST_GENERALIZED {
        return Shape::Legacy;
    }
    let (soroban, classic): (Vec<usize>, Vec<usize>) =
        (0..txs.len()).partition(|i| txs[*i].soroban);
    let sequential = |ids: Vec<usize>| {
        PhaseShape::Sequential(if ids.is_empty() {
            Vec::new()
        } else {
            vec![(Some(base_fee), ids)]
        })
    };
    let soroban_phase = if protocol < FIRST_PARALLEL {
        sequential(soroban)
    } else if soroban.is_empty() {
        PhaseShape::Parallel {
            base_fee: None,
            stages: Vec::new(),
        }
    } else {
        PhaseShape::Parallel {
            base_fee: Some(base_fee),
            stages: vec![vec![soroban]],
        }
    };
    Shape::Generalized(vec![sequential(classic), soroban_phase])
}

/// The shape core built, read from a closed ledger whose transactions are exactly `txs` (matched by
/// full hash).
pub fn learn_shape(lcm: &LedgerCloseMeta, txs: &[ModelTx]) -> Result<Shape> {
    let index: BTreeMap<[u8; 32], usize> = txs
        .iter()
        .enumerate()
        .map(|(i, t)| (t.full_hash, i))
        .collect();
    let slot = |e: &TransactionEnvelope| -> Result<usize> {
        let h: [u8; 32] = Sha256::digest(e.to_xdr(Limits::none())?).into();
        index.get(&h).copied().ok_or_else(|| {
            anyhow!(
                "the ledger holds a transaction ({}) the step group did not submit",
                hex::encode(h)
            )
        })
    };
    let set = match lcm {
        LedgerCloseMeta::V0(_) => return Ok(Shape::Legacy),
        LedgerCloseMeta::V1(m) => &m.tx_set,
        LedgerCloseMeta::V2(m) => &m.tx_set,
    };
    let GeneralizedTransactionSet::V1(v1) = set;
    let mut phases = Vec::new();
    for p in v1.phases.iter() {
        phases.push(match p {
            TransactionPhase::V0(components) => PhaseShape::Sequential(
                components
                    .iter()
                    .map(|c| {
                        let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) = c;
                        Ok((c.base_fee, c.txs.iter().map(slot).collect::<Result<_>>()?))
                    })
                    .collect::<Result<_>>()?,
            ),
            TransactionPhase::V1(pc) => PhaseShape::Parallel {
                base_fee: pc.base_fee,
                stages: pc
                    .execution_stages
                    .iter()
                    .map(|st| {
                        st.0.iter()
                            .map(|cl| cl.0.iter().map(slot).collect::<Result<Vec<_>>>())
                            .collect::<Result<Vec<_>>>()
                    })
                    .collect::<Result<_>>()?,
            },
        });
    }
    Ok(Shape::Generalized(phases))
}

/// What the model predicts for one set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prediction {
    /// The transaction-set (contents) hash.
    pub set_hash: [u8; 32],
    /// Transactions (indices) in apply order.
    pub order: Vec<usize>,
}

/// The set hash and apply order of `txs` placed as `shape` says, after a ledger with header hash
/// `previous`.
pub fn predict(shape: &Shape, txs: &[ModelTx], previous: [u8; 32]) -> Result<Prediction> {
    let by_hash = |ids: &mut Vec<usize>| ids.sort_by_key(|i| txs[*i].full_hash);
    match shape {
        Shape::Legacy => {
            let mut all: Vec<usize> = (0..txs.len()).collect();
            by_hash(&mut all);
            let mut h = Sha256::new();
            h.update(previous);
            for i in &all {
                h.update(txs[*i].envelope.to_xdr(Limits::none())?);
            }
            let set_hash: [u8; 32] = h.finalize().into();
            Ok(Prediction {
                order: sequential_order(&all, txs, &set_hash),
                set_hash,
            })
        }
        Shape::Generalized(phases) => {
            let env = |i: &usize| txs[*i].envelope.clone();
            let mut xdr_phases = Vec::new();
            // Each phase's transactions in the container order core serialises.
            let mut sorted: Vec<PhaseShape> = Vec::new();
            for p in phases {
                match p {
                    PhaseShape::Sequential(components) => {
                        let mut comps = components.clone();
                        comps.sort_by_key(|(fee, _)| *fee);
                        for (_, ids) in &mut comps {
                            by_hash(ids);
                        }
                        xdr_phases.push(TransactionPhase::V0(
                            comps
                                .iter()
                                .map(|(fee, ids)| {
                                    Ok(TxSetComponent::TxsetCompTxsMaybeDiscountedFee(
                                        TxSetComponentTxsMaybeDiscountedFee {
                                            base_fee: *fee,
                                            txs: ids
                                                .iter()
                                                .map(env)
                                                .collect::<Vec<_>>()
                                                .try_into()?,
                                        },
                                    ))
                                })
                                .collect::<Result<Vec<_>>>()?
                                .try_into()?,
                        ));
                        sorted.push(PhaseShape::Sequential(comps));
                    }
                    PhaseShape::Parallel { base_fee, stages } => {
                        let mut stages = stages.clone();
                        for stage in &mut stages {
                            for cluster in stage.iter_mut() {
                                by_hash(cluster);
                            }
                            stage.sort_by_key(|c| c.first().map(|i| txs[*i].full_hash));
                        }
                        stages.sort_by_key(|s| {
                            s.first().and_then(|c| c.first()).map(|i| txs[*i].full_hash)
                        });
                        xdr_phases.push(TransactionPhase::V1(ParallelTxsComponent {
                            base_fee: *base_fee,
                            execution_stages: stages
                                .iter()
                                .map(|st| {
                                    Ok(ParallelTxExecutionStage(
                                        st.iter()
                                            .map(|cl| {
                                                Ok(DependentTxCluster(
                                                    cl.iter()
                                                        .map(env)
                                                        .collect::<Vec<_>>()
                                                        .try_into()?,
                                                ))
                                            })
                                            .collect::<Result<Vec<_>>>()?
                                            .try_into()?,
                                    ))
                                })
                                .collect::<Result<Vec<_>>>()?
                                .try_into()?,
                        }));
                        sorted.push(PhaseShape::Parallel {
                            base_fee: *base_fee,
                            stages,
                        });
                    }
                }
            }
            let set = GeneralizedTransactionSet::V1(TransactionSetV1 {
                previous_ledger_hash: Hash(previous),
                phases: xdr_phases.try_into()?,
            });
            let set_hash: [u8; 32] = Sha256::digest(set.to_xdr(Limits::none())?).into();
            let mut order = Vec::new();
            for p in &sorted {
                match p {
                    PhaseShape::Sequential(comps) => {
                        let all: Vec<usize> = comps
                            .iter()
                            .flat_map(|(_, ids)| ids.iter().copied())
                            .collect();
                        order.extend(sequential_order(&all, txs, &set_hash));
                    }
                    PhaseShape::Parallel { stages, .. } => {
                        order.extend(parallel_order(stages, txs, &set_hash));
                    }
                }
            }
            Ok(Prediction { set_hash, order })
        }
    }
}

/// `full hash XOR set hash`, compared as bytes (`lessThanXored`).
fn xored(h: &[u8; 32], set: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = h[i] ^ set[i];
    }
    out
}

fn sequential_order(ids: &[usize], txs: &[ModelTx], set: &[u8; 32]) -> Vec<usize> {
    let mut queues: BTreeMap<[u8; 32], Vec<usize>> = BTreeMap::new();
    for i in ids {
        queues.entry(txs[*i].source).or_default().push(*i);
    }
    for q in queues.values_mut() {
        q.sort_by_key(|i| txs[*i].seq);
    }
    let depth = queues.values().map(Vec::len).max().unwrap_or(0);
    let mut out = Vec::new();
    for b in 0..depth {
        let mut batch: Vec<usize> = queues.values().filter_map(|q| q.get(b).copied()).collect();
        batch.sort_by_key(|i| xored(&txs[*i].full_hash, set));
        out.extend(batch);
    }
    out
}

fn parallel_order(stages: &[Vec<Vec<usize>>], txs: &[ModelTx], set: &[u8; 32]) -> Vec<usize> {
    let mut stages = stages.to_vec();
    for st in &mut stages {
        for cl in st.iter_mut() {
            cl.sort_by_key(|i| xored(&txs[*i].full_hash, set));
        }
    }
    stages.sort_by_key(|s| {
        s.first()
            .and_then(|c| c.first())
            .map(|i| xored(&txs[*i].full_hash, set))
    });
    stages.into_iter().flatten().flatten().collect()
}

/// The contents hash of the set a closed ledger holds, as core computes it.
pub fn set_hash_of(lcm: &LedgerCloseMeta) -> Result<[u8; 32]> {
    Ok(match lcm {
        LedgerCloseMeta::V0(m) => {
            let mut h = Sha256::new();
            h.update(m.tx_set.previous_ledger_hash.0);
            for e in m.tx_set.txs.iter() {
                h.update(e.to_xdr(Limits::none())?);
            }
            h.finalize().into()
        }
        LedgerCloseMeta::V1(m) => Sha256::digest(m.tx_set.to_xdr(Limits::none())?).into(),
        LedgerCloseMeta::V2(m) => Sha256::digest(m.tx_set.to_xdr(Limits::none())?).into(),
    })
}

/// Check that a prediction is complete: every transaction exactly once.
pub fn check_complete(p: &Prediction, n: usize) -> Result<()> {
    let mut seen = p.order.clone();
    seen.sort_unstable();
    if seen != (0..n).collect::<Vec<_>>() {
        bail!("the transaction-set shape does not place every transaction exactly once");
    }
    Ok(())
}
