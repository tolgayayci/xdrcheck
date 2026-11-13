//! What intake reads from one `LedgerCloseMeta` blob: header facts, the transaction hashes in
//! apply order, the meta versions, a protocol upgrade if any, and the check that every
//! transaction hash is recomputed from its envelope under the variant's passphrase (the `pinpoints`
//! check, `docs/manifest.md` §11 item 4), which proves the passphrase claim.

use std::collections::BTreeSet;

use anyhow::{bail, Result};
use stellar_xdr::{
    GeneralizedTransactionSet, LedgerCloseMeta, LedgerUpgrade, TransactionEnvelope,
    TransactionPhase, TxSetComponent,
};
use xdrcheck_xdr::{Gate, Limits};

/// Facts about one ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerSummary {
    /// `LedgerCloseMeta` arm.
    pub ledger_close_meta_version: i32,
    /// Header `ledger_version`.
    pub protocol: u32,
    /// Header `ledger_seq`.
    pub ledger_seq: u32,
    /// Header hash stored in the meta, hex.
    pub header_hash: String,
    /// Header close time, seconds.
    pub close_time: u64,
    /// Transaction hashes from the results, in apply order, hex.
    pub tx_hashes: Vec<String>,
    /// `TransactionMeta` arm per transaction, in apply order.
    pub transaction_meta_versions: Vec<i32>,
    /// New protocol version if the ledger carries a protocol-version upgrade. The header then
    /// shows the new version while the transactions were applied at the old one.
    pub protocol_upgrade: Option<u32>,
}

impl LedgerSummary {
    /// Apply-order index of the transaction with hash `hash` (hex, any case).
    pub fn tx_index(&self, hash: &str) -> Option<usize> {
        let hash = hash.to_ascii_lowercase();
        self.tx_hashes.iter().position(|h| *h == hash)
    }

    /// The `TransactionMeta` version when all transactions share one (or of `tx_index`).
    pub fn meta_version(&self, tx_index: Option<usize>) -> Option<i32> {
        if let Some(i) = tx_index {
            return self.transaction_meta_versions.get(i).copied();
        }
        let set: BTreeSet<i32> = self.transaction_meta_versions.iter().copied().collect();
        (set.len() == 1).then(|| *set.first().expect("one element"))
    }
}

/// Decode `blob` as a `LedgerCloseMeta` (gate, explicit limits), summarise it and check every
/// transaction hash against its envelope under `passphrase`. Runs on a large stack.
pub fn summarise(
    blob: &[u8],
    passphrase: &str,
    limits: &Limits,
    gate: &Gate,
) -> Result<LedgerSummary> {
    let stack = limits.stack_size;
    xdrcheck_xdr::with_stack(stack, || {
        let lcm = xdrcheck_xdr::decode_ledger(blob, limits, gate)?;
        let s = summary_of(&lcm);
        check_tx_hashes(&lcm, &s, passphrase)?;
        Ok(s)
    })
}

fn summary_of(lcm: &LedgerCloseMeta) -> LedgerSummary {
    let (header, results, upgrades) = match lcm {
        LedgerCloseMeta::V0(m) => (
            &m.ledger_header,
            m.tx_processing
                .iter()
                .map(|t| {
                    (
                        &t.result.transaction_hash,
                        t.tx_apply_processing.discriminant(),
                    )
                })
                .collect::<Vec<_>>(),
            &m.upgrades_processing,
        ),
        LedgerCloseMeta::V1(m) => (
            &m.ledger_header,
            m.tx_processing
                .iter()
                .map(|t| {
                    (
                        &t.result.transaction_hash,
                        t.tx_apply_processing.discriminant(),
                    )
                })
                .collect(),
            &m.upgrades_processing,
        ),
        LedgerCloseMeta::V2(m) => (
            &m.ledger_header,
            m.tx_processing
                .iter()
                .map(|t| {
                    (
                        &t.result.transaction_hash,
                        t.tx_apply_processing.discriminant(),
                    )
                })
                .collect(),
            &m.upgrades_processing,
        ),
    };
    LedgerSummary {
        ledger_close_meta_version: lcm.discriminant(),
        protocol: header.header.ledger_version,
        ledger_seq: header.header.ledger_seq,
        header_hash: hex::encode(header.hash.0),
        close_time: header.header.scp_value.close_time.0,
        tx_hashes: results.iter().map(|(h, _)| hex::encode(h.0)).collect(),
        transaction_meta_versions: results.iter().map(|(_, v)| *v).collect(),
        protocol_upgrade: upgrades.iter().find_map(|u| match u.upgrade {
            LedgerUpgrade::Version(v) => Some(v),
            _ => None,
        }),
    }
}

/// Every envelope of the ledger's transaction set.
fn envelopes(lcm: &LedgerCloseMeta) -> Vec<&TransactionEnvelope> {
    let set = match lcm {
        LedgerCloseMeta::V0(m) => return m.tx_set.txs.iter().collect(),
        LedgerCloseMeta::V1(m) => &m.tx_set,
        LedgerCloseMeta::V2(m) => &m.tx_set,
    };
    let GeneralizedTransactionSet::V1(set) = set;
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

/// Every result's transaction hash must be the hash of an envelope in the set under
/// `passphrase`, and the set must hold exactly the applied transactions.
fn check_tx_hashes(lcm: &LedgerCloseMeta, s: &LedgerSummary, passphrase: &str) -> Result<()> {
    let network_id: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(passphrase.as_bytes()).into()
    };
    let mut recomputed = BTreeSet::new();
    for e in envelopes(lcm) {
        recomputed.insert(hex::encode(e.hash(network_id)?));
    }
    let applied: BTreeSet<String> = s.tx_hashes.iter().cloned().collect();
    if applied != recomputed {
        let missing = applied.difference(&recomputed).count();
        bail!(
            "ledger {}: {missing} of {} transaction hashes are not recomputed from the envelopes under passphrase {passphrase:?} ({} envelopes)",
            s.ledger_seq,
            applied.len(),
            recomputed.len()
        );
    }
    Ok(())
}
