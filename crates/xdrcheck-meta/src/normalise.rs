//! stellar-core's golden-comparison normalisation.
//!
//! Two emissions of the same ledger are the same when they are byte-equal after this normalisation,
//! which is exactly what stellar-core's `--check-lcm` compares (`src/util/MetaUtils.cpp` and
//! `lcmSemanticallyEqual` in `src/test/test.cpp`, stellar-core v30.0.0):
//!
//! 1. `normalizeMeta`: every `LedgerEntryChanges` vector in the places core sorts is sorted by the
//!    tuple (ledger key of the change, change-type rank, SHA-256 of the change's XDR). The places are
//!    `upgradesProcessing[].changes`, `txProcessing[].feeProcessing`, and inside each
//!    `TransactionMeta`: `txChanges` (v1), `txChangesBefore` / `txChangesAfter` (v2–v4) and every
//!    operation's `changes` (v0–v4). The rank is `STATE < CREATED < UPDATED < REMOVED < RESTORED`.
//!    `postTxApplyFeeProcessing` is **not** sorted, because core does not sort it; a regeneration that
//!    differs only in its order is a finding about core, not something to hide.
//! 2. `zeroNonDeterministicDiagnostics`: every diagnostic event (type `DIAGNOSTIC`) whose topics are
//!    exactly `[Symbol("core_metrics"), Symbol("invoke_time_nsecs")]` gets data `U64(0)`. Core looks
//!    only at TransactionMeta v3 (`sorobanMeta.diagnosticEvents`) and v4 (`diagnosticEvents`).
//!
//! Nothing else changes: transaction order, event order, evicted keys, envelopes and the header stay
//! as emitted. Normalised bytes are for comparison only and are never stored as corpus bytes.
//!
//! **Ledger-key order.** Core compares keys with the `operator<` that xdrpp generates: unions by
//! discriminant then arm, structs field by field, arrays, strings and vectors lexicographically
//! element by element (no length prefix), integers by value with their sign. The `Ord` that
//! `stellar-xdr` derives on `LedgerKey` is the same order: every union reachable from a ledger key
//! declares its arms in ascending discriminant order, enums carry their XDR values, and vectors and
//! strings compare as Rust slices. This differs from comparing the keys' XDR *bytes* (which put
//! the length of a variable-length field first); for an equality verdict either order works, but
//! only core's order makes our normalised bytes equal to what core's own normalisation produces.
//!
//! **Timing value of another type.** Core writes the zero through the `u64` accessor of the event's
//! data, which throws when the data is not a `u64`. We report that case as
//! [`NormaliseError::TimingDataNotU64`] instead of guessing.

use std::cmp::Ordering;

use sha2::{Digest, Sha256};
use stellar_xdr::{
    ContractEventBody, ContractEventType, DiagnosticEvent, LedgerCloseMeta, LedgerEntryChange,
    LedgerEntryChanges, LedgerKey, OperationMeta, OperationMetaV2, ScVal, TransactionMeta, VecM,
    WriteXdr,
};
use xdrcheck_xdr::{Gate, Limits};

/// What normalisation did to one ledger (or, summed, to a stream).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// `LedgerEntryChanges` vectors visited (sorted), including empty ones.
    pub vectors_sorted: usize,
    /// Vectors whose order changed by sorting.
    pub vectors_reordered: usize,
    /// Timing diagnostic events visited (whatever their value).
    pub timing_events: usize,
    /// Timing diagnostic events whose value was not already zero.
    pub timing_values_zeroed: usize,
}

impl std::ops::AddAssign for Stats {
    fn add_assign(&mut self, o: Stats) {
        self.vectors_sorted += o.vectors_sorted;
        self.vectors_reordered += o.vectors_reordered;
        self.timing_events += o.timing_events;
        self.timing_values_zeroed += o.timing_values_zeroed;
    }
}

/// Errors from normalisation.
#[derive(Debug, thiserror::Error)]
pub enum NormaliseError {
    /// Decoding, framing or encoding failed.
    #[error(transparent)]
    Xdr(#[from] xdrcheck_xdr::Error),
    /// A `core_metrics` / `invoke_time_nsecs` diagnostic event whose data is not a `u64` (stellar-core
    /// itself would throw here).
    #[error("transaction {tx_index}: timing diagnostic event {event_index} has data of type {found}, not u64")]
    TimingDataNotU64 {
        /// Index of the transaction in the ledger's transaction processing list.
        tx_index: usize,
        /// Index of the event in its diagnostic event list.
        event_index: usize,
        /// The `ScVal` arm found.
        found: &'static str,
    },
}

/// Normalise one decoded ledger in place: `normalizeMeta` then `zeroNonDeterministicDiagnostics`.
///
/// Values can be deeply nested; call this on a large stack (see [`xdrcheck_xdr::with_stack`]).
pub fn normalise(lcm: &mut LedgerCloseMeta) -> Result<Stats, NormaliseError> {
    let mut stats = Stats::default();
    macro_rules! body {
        ($v:expr) => {{
            for u in $v.upgrades_processing.iter_mut() {
                sort_changes(&mut u.changes, &mut stats);
            }
            for (i, tx) in $v.tx_processing.iter_mut().enumerate() {
                sort_changes(&mut tx.fee_processing, &mut stats);
                normalise_tx_meta_counted(&mut tx.tx_apply_processing, &mut stats);
                zero_timing(&mut tx.tx_apply_processing, i, &mut stats)?;
            }
        }};
    }
    match lcm {
        LedgerCloseMeta::V0(v) => body!(v),
        LedgerCloseMeta::V1(v) => body!(v),
        // `post_tx_apply_fee_processing` is deliberately left as emitted (core does not sort it).
        LedgerCloseMeta::V2(v) => body!(v),
    }
    Ok(stats)
}

/// stellar-core's `normalizeMeta(TransactionMeta&)`: sort the transaction's change vectors.
pub fn normalise_tx_meta(meta: &mut TransactionMeta) -> Stats {
    let mut stats = Stats::default();
    normalise_tx_meta_counted(meta, &mut stats);
    stats
}

fn normalise_tx_meta_counted(meta: &mut TransactionMeta, stats: &mut Stats) {
    match meta {
        TransactionMeta::V0(ops) => sort_ops(ops, stats),
        TransactionMeta::V1(m) => {
            sort_changes(&mut m.tx_changes, stats);
            sort_ops(&mut m.operations, stats);
        }
        TransactionMeta::V2(m) => {
            sort_changes(&mut m.tx_changes_before, stats);
            sort_changes(&mut m.tx_changes_after, stats);
            sort_ops(&mut m.operations, stats);
        }
        TransactionMeta::V3(m) => {
            sort_changes(&mut m.tx_changes_before, stats);
            sort_changes(&mut m.tx_changes_after, stats);
            sort_ops(&mut m.operations, stats);
        }
        TransactionMeta::V4(m) => {
            sort_changes(&mut m.tx_changes_before, stats);
            sort_changes(&mut m.tx_changes_after, stats);
            sort_ops_v2(&mut m.operations, stats);
        }
    }
}

fn sort_ops(ops: &mut VecM<OperationMeta>, stats: &mut Stats) {
    for op in ops.iter_mut() {
        sort_changes(&mut op.changes, stats);
    }
}

fn sort_ops_v2(ops: &mut VecM<OperationMetaV2>, stats: &mut Stats) {
    for op in ops.iter_mut() {
        sort_changes(&mut op.changes, stats);
    }
}

/// The ledger key a change is about: the entry's key, or for `REMOVED` the key itself.
pub fn change_key(change: &LedgerEntryChange) -> LedgerKey {
    match change {
        LedgerEntryChange::Created(e)
        | LedgerEntryChange::Updated(e)
        | LedgerEntryChange::State(e)
        | LedgerEntryChange::Restored(e) => e.to_key(),
        LedgerEntryChange::Removed(k) => k.clone(),
    }
}

/// Core's rank of a change type: `STATE < CREATED < UPDATED < REMOVED < RESTORED`.
pub fn change_rank(change: &LedgerEntryChange) -> u8 {
    match change {
        LedgerEntryChange::State(_) => 0,
        LedgerEntryChange::Created(_) => 1,
        LedgerEntryChange::Updated(_) => 2,
        LedgerEntryChange::Removed(_) => 3,
        LedgerEntryChange::Restored(_) => 4,
    }
}

/// Core's sort key of one change: (ledger key, rank, SHA-256 of the change's XDR).
fn sort_key(change: &LedgerEntryChange) -> (LedgerKey, u8, [u8; 32]) {
    let limits = stellar_xdr::Limits {
        depth: Limits::default().depth,
        len: usize::MAX,
    };
    // A change that decoded under the same depth limit always re-encodes.
    let bytes = change
        .to_xdr(limits)
        .expect("a decoded change re-encodes under the decode limits");
    (
        change_key(change),
        change_rank(change),
        Sha256::digest(&bytes).into(),
    )
}

/// Compare two changes the way core's `CmpLedgerEntryChanges` does.
pub fn compare_changes(a: &LedgerEntryChange, b: &LedgerEntryChange) -> Ordering {
    sort_key(a).cmp(&sort_key(b))
}

fn sort_changes(changes: &mut LedgerEntryChanges, stats: &mut Stats) {
    stats.vectors_sorted += 1;
    if changes.0.len() < 2 {
        return;
    }
    let mut keyed: Vec<_> = std::mem::take(&mut changes.0)
        .into_vec()
        .into_iter()
        .enumerate()
        .map(|(i, c)| (sort_key(&c), i, c))
        .collect();
    // Equal keys mean byte-identical changes, so the order among them does not matter.
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    if keyed.iter().enumerate().any(|(pos, (_, i, _))| pos != *i) {
        stats.vectors_reordered += 1;
    }
    let sorted: Vec<LedgerEntryChange> = keyed.into_iter().map(|(_, _, c)| c).collect();
    changes.0 = sorted
        .try_into()
        .expect("sorting keeps the vector's length within its bound");
}

/// Whether a diagnostic event is core's `core_metrics` / `invoke_time_nsecs` timing event.
pub fn is_timing_event(de: &DiagnosticEvent) -> bool {
    if de.event.type_ != ContractEventType::Diagnostic {
        return false;
    }
    let ContractEventBody::V0(body) = &de.event.body;
    match body.topics.as_slice() {
        [ScVal::Symbol(a), ScVal::Symbol(b)] => {
            a.0.as_slice() == b"core_metrics" && b.0.as_slice() == b"invoke_time_nsecs"
        }
        _ => false,
    }
}

fn zero_timing(
    meta: &mut TransactionMeta,
    tx_index: usize,
    stats: &mut Stats,
) -> Result<(), NormaliseError> {
    let events = match meta {
        TransactionMeta::V3(m) => match m.soroban_meta.as_mut() {
            Some(s) => &mut s.diagnostic_events,
            None => return Ok(()),
        },
        TransactionMeta::V4(m) => &mut m.diagnostic_events,
        // Classic meta versions carry no diagnostic events. Every arm is named: a new meta version
        // does not compile until its timing events are handled here.
        TransactionMeta::V0(_) | TransactionMeta::V1(_) | TransactionMeta::V2(_) => return Ok(()),
    };
    for (event_index, de) in events.iter_mut().enumerate() {
        if !is_timing_event(de) {
            continue;
        }
        stats.timing_events += 1;
        let ContractEventBody::V0(body) = &mut de.event.body;
        match &mut body.data {
            ScVal::U64(v) => {
                if *v != 0 {
                    stats.timing_values_zeroed += 1;
                }
                *v = 0;
            }
            other => {
                return Err(NormaliseError::TimingDataNotU64 {
                    tx_index,
                    event_index,
                    found: other.name(),
                })
            }
        }
    }
    Ok(())
}

/// Decode one `LedgerCloseMeta` (checked against `gate`), normalise it and re-encode it. Runs on a
/// large-stack thread.
pub fn normalise_ledger(
    bytes: &[u8],
    limits: &Limits,
    gate: &Gate,
) -> Result<(Vec<u8>, Stats), NormaliseError> {
    xdrcheck_xdr::with_stack(limits.stack_size, || {
        let mut lcm = xdrcheck_xdr::decode_ledger(bytes, limits, gate)?;
        let stats = normalise(&mut lcm)?;
        let value = stellar_xdr::Type::LedgerCloseMeta(Box::new(lcm));
        let out = xdrcheck_xdr::encode(&value, limits)?;
        Ok((out, stats))
    })
}

/// Normalise every ledger of a record-marked stream; the output is a record-marked stream of the
/// normalised ledgers in the same order.
pub fn normalise_stream(
    stream: &[u8],
    limits: &Limits,
    gate: &Gate,
) -> Result<(Vec<u8>, Stats), NormaliseError> {
    let mut out = Vec::with_capacity(stream.len());
    let mut stats = Stats::default();
    for (_, payload) in xdrcheck_xdr::split_ledger_stream(stream, limits, gate)? {
        let (n, s) = normalise_ledger(payload, limits, gate)?;
        xdrcheck_xdr::write_record(&mut out, &n).map_err(xdrcheck_xdr::Error::from)?;
        stats += s;
    }
    Ok((out, stats))
}

/// Whether input bytes are a record-marked stream rather than a bare `LedgerCloseMeta`: a record
/// mark has its top (last-fragment) bit set, while a `LedgerCloseMeta` starts with its small,
/// non-negative union discriminant.
pub fn looks_record_marked(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(|b| b & 0x80 != 0)
}

/// Whether two ledgers are normalised-identical (core's `lcmSemanticallyEqual` for one ledger).
pub fn normalised_equal(
    a: &[u8],
    b: &[u8],
    limits: &Limits,
    gate: &Gate,
) -> Result<bool, NormaliseError> {
    Ok(normalise_ledger(a, limits, gate)?.0 == normalise_ledger(b, limits, gate)?.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Classic meta versions carry no diagnostic events: zeroing timing leaves them as they are.
    #[test]
    fn classic_meta_has_no_timing_events() {
        let metas = [
            TransactionMeta::V0(Default::default()),
            TransactionMeta::V1(Default::default()),
            TransactionMeta::V2(Default::default()),
        ];
        for m in metas {
            let mut n = m.clone();
            let mut stats = Stats::default();
            zero_timing(&mut n, 0, &mut stats).unwrap();
            assert_eq!(n, m);
            assert_eq!(stats, Stats::default());
        }
    }
}
