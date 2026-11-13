//! Metamorphic rewrites of a ledger's meta that leave every fact a reader should store unchanged.
//!
//! stellar-core does not fix the order of the changes inside an operation's `LedgerEntryChanges`
//! (its golden comparison sorts them first; see [`crate::normalise`]), and its `core_metrics`
//! timing values are measured on the node that closed the ledger. Two nodes can therefore emit
//! different bytes for the same ledger. A reader whose stored facts change under these rewrites
//! depends on emission order or on timing.
//!
//! - [`permute_operation_changes`] reorders every operation's change list across ledger keys
//!   only: every change of one ledger key keeps its original order relative to the other changes of
//!   that key, and only changes of different keys trade places. Within that, a `STATE` change
//!   immediately followed by the `UPDATED` or `REMOVED` change of the same key is one *unit* (the
//!   before/after pair a reader matches), and so is a `RESTORED` change followed by the `UPDATED` or
//!   `REMOVED` change of the entry it restored (CAP-62: an entry restored and changed in the same
//!   transaction appears as `[restored, updated]`); a unit is never split by a change of another key.
//!   stellar-core never emits two changes of one key in another order, so a reader that pairs them
//!   by position must not be blamed for what a reorder within one key would do.
//! - [`set_timing`] overwrites every `core_metrics` / `invoke_time_nsecs` diagnostic value.
//!
//! The permutation is a pure function of the seed. A list with units of two or more ledger keys is
//! never left in its original order.

use stellar_xdr::{
    ContractEventBody, LedgerCloseMeta, LedgerEntryChange, LedgerEntryChanges, ScVal,
    TransactionMeta,
};

use crate::normalise::{change_key, is_timing_event};

/// What a permutation did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PermuteStats {
    /// Operation change lists visited.
    pub vectors: usize,
    /// Lists reordered (units of two or more ledger keys).
    pub permuted: usize,
    /// Units in the reordered lists.
    pub units: usize,
}

/// SplitMix64: the same small generator the mutation engine uses, so a seed means the same thing
/// in both places.
#[derive(Debug, Clone)]
pub struct SplitMix(pub u64);

impl SplitMix {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    /// A value in `0..n` (`n > 0`).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

/// The units of a change list, as index ranges in order.
pub fn change_units(changes: &[LedgerEntryChange]) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < changes.len() {
        let paired = matches!(
            changes[i],
            LedgerEntryChange::State(_) | LedgerEntryChange::Restored(_)
        ) && changes.get(i + 1).is_some_and(|next| {
            matches!(
                next,
                LedgerEntryChange::Updated(_) | LedgerEntryChange::Removed(_)
            ) && change_key(next) == change_key(&changes[i])
        });
        let n = if paired { 2 } else { 1 };
        out.push(i..i + n);
        i += n;
    }
    out
}

/// Reorder the units of one change list across ledger keys: the units of one key keep their
/// relative order. Returns the number of units when the list was reordered, `None` when its units
/// belong to fewer than two keys.
pub fn permute_changes(changes: &mut LedgerEntryChanges, rng: &mut SplitMix) -> Option<usize> {
    let units = change_units(&changes.0);
    // The key of every unit, as the index of its first appearance.
    let mut keys = Vec::new();
    let mut unit_key = Vec::with_capacity(units.len());
    for u in &units {
        let k = change_key(&changes.0[u.start]);
        let i = match keys.iter().position(|x| *x == k) {
            Some(i) => i,
            None => {
                keys.push(k);
                keys.len() - 1
            }
        };
        unit_key.push(i);
    }
    if keys.len() < 2 {
        return None;
    }
    // Shuffle the sequence of keys (one slot per unit), then fill every slot with the next unit of its
    // key: an interleaving that keeps each key's own order.
    let mut slots = unit_key.clone();
    for i in (1..slots.len()).rev() {
        slots.swap(i, rng.below(i + 1));
    }
    if slots == unit_key {
        // The identity: swap the first two neighbouring units of different keys.
        let i = (1..slots.len())
            .find(|&i| slots[i] != slots[i - 1])
            .expect("two keys");
        slots.swap(i - 1, i);
    }
    let mut queues: Vec<std::collections::VecDeque<usize>> = vec![Default::default(); keys.len()];
    for (u, k) in unit_key.iter().enumerate() {
        queues[*k].push_back(u);
    }
    let old = changes.0.to_vec();
    let mut out = Vec::with_capacity(old.len());
    for k in slots {
        let u = queues[k].pop_front().expect("one slot per unit");
        out.extend(old[units[u].clone()].iter().cloned());
    }
    changes.0 = out.try_into().expect("a permutation keeps the length");
    Some(units.len())
}

fn tx_meta_ops(meta: &mut TransactionMeta) -> Vec<&mut LedgerEntryChanges> {
    match meta {
        TransactionMeta::V0(ops) => ops.iter_mut().map(|o| &mut o.changes).collect(),
        TransactionMeta::V1(m) => m.operations.iter_mut().map(|o| &mut o.changes).collect(),
        TransactionMeta::V2(m) => m.operations.iter_mut().map(|o| &mut o.changes).collect(),
        TransactionMeta::V3(m) => m.operations.iter_mut().map(|o| &mut o.changes).collect(),
        TransactionMeta::V4(m) => m.operations.iter_mut().map(|o| &mut o.changes).collect(),
    }
}

/// Permute every operation's change list of every transaction. Values can be deep: call on a
/// large stack.
pub fn permute_operation_changes(lcm: &mut LedgerCloseMeta, seed: u64) -> PermuteStats {
    let mut rng = SplitMix(seed);
    let mut stats = PermuteStats::default();
    macro_rules! body {
        ($v:expr) => {
            for tx in $v.tx_processing.iter_mut() {
                for changes in tx_meta_ops(&mut tx.tx_apply_processing) {
                    stats.vectors += 1;
                    if let Some(n) = permute_changes(changes, &mut rng) {
                        stats.permuted += 1;
                        stats.units += n;
                    }
                }
            }
        };
    }
    match lcm {
        LedgerCloseMeta::V0(v) => body!(v),
        LedgerCloseMeta::V1(v) => body!(v),
        LedgerCloseMeta::V2(v) => body!(v),
    }
    stats
}

/// Set every `core_metrics` / `invoke_time_nsecs` diagnostic value to `value`. Returns the number of
/// events changed. Events whose data is not a `u64` are left alone.
pub fn set_timing(lcm: &mut LedgerCloseMeta, value: u64) -> usize {
    let mut n = 0;
    macro_rules! body {
        ($v:expr) => {
            for tx in $v.tx_processing.iter_mut() {
                let events = match &mut tx.tx_apply_processing {
                    TransactionMeta::V3(m) => match m.soroban_meta.as_mut() {
                        Some(s) => &mut s.diagnostic_events,
                        None => continue,
                    },
                    TransactionMeta::V4(m) => &mut m.diagnostic_events,
                    TransactionMeta::V0(_) | TransactionMeta::V1(_) | TransactionMeta::V2(_) => {
                        continue
                    }
                };
                for de in events.iter_mut() {
                    if !is_timing_event(de) {
                        continue;
                    }
                    let ContractEventBody::V0(body) = &mut de.event.body;
                    if let ScVal::U64(v) = &mut body.data {
                        if *v != value {
                            *v = value;
                            n += 1;
                        }
                    }
                }
            }
        };
    }
    match lcm {
        LedgerCloseMeta::V0(v) => body!(v),
        LedgerCloseMeta::V1(v) => body!(v),
        LedgerCloseMeta::V2(v) => body!(v),
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::{
        AccountEntry, AccountId, LedgerEntry, LedgerEntryData, LedgerEntryExt, LedgerKey,
        LedgerKeyAccount, PublicKey, Uint256,
    };

    fn account(b: u8, balance: i64) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::Account(AccountEntry {
                account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([b; 32]))),
                balance,
                ..Default::default()
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    fn account_key(b: u8) -> LedgerKey {
        LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([b; 32]))),
        })
    }

    /// The changes of each ledger key, in list order.
    fn per_key(list: &[LedgerEntryChange]) -> Vec<(LedgerKey, Vec<LedgerEntryChange>)> {
        let mut out: Vec<(LedgerKey, Vec<LedgerEntryChange>)> = Vec::new();
        for c in list {
            let k = change_key(c);
            match out.iter_mut().find(|(x, _)| *x == k) {
                Some((_, v)) => v.push(c.clone()),
                None => out.push((k, vec![c.clone()])),
            }
        }
        out.sort_by(|a, b| format!("{:?}", a.0).cmp(&format!("{:?}", b.0)));
        out
    }

    #[test]
    fn pairs_stay_together_and_order_changes() {
        let list = vec![
            LedgerEntryChange::State(account(1, 10)),
            LedgerEntryChange::Updated(account(1, 5)),
            LedgerEntryChange::Created(account(2, 5)),
            LedgerEntryChange::State(account(3, 7)),
            LedgerEntryChange::Removed(account_key(3)),
        ];
        assert_eq!(change_units(&list), vec![0..2, 2..3, 3..5]);
        // CAP-62: an entry restored and updated in one transaction is a [restored, updated] pair.
        let restored = vec![
            LedgerEntryChange::Restored(account(4, 1)),
            LedgerEntryChange::Restored(account(5, 1)),
            LedgerEntryChange::Updated(account(5, 2)),
        ];
        assert_eq!(change_units(&restored), vec![0..1, 1..3]);
        for seed in 0..32 {
            let mut c = LedgerEntryChanges(list.clone().try_into().unwrap());
            assert_eq!(permute_changes(&mut c, &mut SplitMix(seed)), Some(3));
            assert_ne!(c.0.to_vec(), list);
            let units = change_units(&c.0);
            assert_eq!(units.len(), 3, "seed {seed}: a pair was split");
        }
    }

    // Every change of one ledger key keeps its order, also when the key's changes are not a single
    // adjacent pair (an entry changed twice in one operation, a restore followed later by an update).
    #[test]
    fn changes_of_one_key_keep_their_order() {
        let list = vec![
            LedgerEntryChange::State(account(1, 10)),
            LedgerEntryChange::Updated(account(1, 9)),
            LedgerEntryChange::Restored(account(2, 1)),
            LedgerEntryChange::State(account(3, 7)),
            LedgerEntryChange::Updated(account(3, 6)),
            LedgerEntryChange::State(account(1, 9)),
            LedgerEntryChange::Updated(account(1, 8)),
            LedgerEntryChange::Updated(account(2, 2)),
            LedgerEntryChange::Created(account(4, 1)),
            LedgerEntryChange::State(account(3, 6)),
            LedgerEntryChange::Removed(account_key(3)),
        ];
        let want = per_key(&list);
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..256 {
            let mut c = LedgerEntryChanges(list.clone().try_into().unwrap());
            assert!(permute_changes(&mut c, &mut SplitMix(seed)).is_some());
            assert_ne!(c.0.to_vec(), list, "seed {seed}: left in order");
            assert_eq!(
                per_key(&c.0),
                want,
                "seed {seed}: a key's changes were reordered"
            );
            for u in change_units(&list).iter().filter(|u| u.len() == 2) {
                let at = c.0.iter().position(|x| *x == list[u.start]).unwrap();
                assert_eq!(
                    c.0.get(at + 1),
                    Some(&list[u.start + 1]),
                    "seed {seed}: a pair was split"
                );
            }
            seen.insert(format!("{:?}", c.0));
        }
        assert!(seen.len() > 10, "only {} orders over 256 seeds", seen.len());
        // One key only: nothing may move.
        let one = vec![
            LedgerEntryChange::Restored(account(2, 1)),
            LedgerEntryChange::State(account(2, 1)),
            LedgerEntryChange::Updated(account(2, 2)),
        ];
        let mut c = LedgerEntryChanges(one.clone().try_into().unwrap());
        assert_eq!(permute_changes(&mut c, &mut SplitMix(1)), None);
        assert_eq!(c.0.to_vec(), one);
    }
}
