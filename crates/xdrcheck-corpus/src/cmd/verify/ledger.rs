//! Facts read from a `LedgerCloseMeta` by the oracle library itself: the transaction hashes in
//! the results (apply order), the hashes recomputed from the envelopes in the transaction set
//! under a network passphrase (`sha256(sha256(passphrase) ‖ envelope type ‖ transaction)`), and the
//! `TransactionMeta` arm of every transaction; and the ledger header, whose values a variant may
//! record under `derived.header`.

use sha2::{Digest, Sha256};
use xdrcheck_xdr::xdr::{
    GeneralizedTransactionSet, LedgerCloseMeta, LedgerHeader, TransactionEnvelope,
    TransactionPhase, TxSetComponent,
};
use xdrcheck_xdr::{Gate, Limits};

/// Transaction hashes of one ledger.
pub struct TxHashes {
    /// `tx_processing[i].result.transaction_hash`, in apply order.
    pub results: Vec<[u8; 32]>,
    /// Every envelope of the transaction set, hashed under the passphrase, in set order.
    pub envelopes: Vec<[u8; 32]>,
    /// `tx_processing[i].tx_apply_processing` arm (the `TransactionMeta` version), in apply order.
    pub meta_versions: Vec<i32>,
    /// The ledger header.
    pub header: LedgerHeader,
}

/// A ledger-header field a variant may record under `derived.header`, as the decimal string the
/// manifest holds; `None` for a name that is not one of them (`docs/manifest.md` §4.6).
pub fn header_field(h: &LedgerHeader, name: &str) -> Option<String> {
    Some(match name {
        "ledger_version" => h.ledger_version.to_string(),
        "total_coins" => h.total_coins.to_string(),
        "fee_pool" => h.fee_pool.to_string(),
        "base_fee" => h.base_fee.to_string(),
        "base_reserve" => h.base_reserve.to_string(),
        "max_tx_set_size" => h.max_tx_set_size.to_string(),
        _ => return None,
    })
}

/// Decode `bytes` as a ledger and collect its transaction hashes.
pub fn tx_hashes(
    bytes: &[u8],
    passphrase: &str,
    limits: &Limits,
    gate: &Gate,
) -> Result<TxHashes, String> {
    let network_id: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();
    // Decode, walk and drop on the large stack.
    xdrcheck_xdr::with_stack(limits.stack_size, || {
        let lcm = xdrcheck_xdr::decode_ledger(bytes, limits, gate).map_err(|e| e.to_string())?;
        let mut envelopes: Vec<&TransactionEnvelope> = Vec::new();
        let header = match &lcm {
            LedgerCloseMeta::V0(m) => m.ledger_header.header.clone(),
            LedgerCloseMeta::V1(m) => m.ledger_header.header.clone(),
            LedgerCloseMeta::V2(m) => m.ledger_header.header.clone(),
        };
        let processed: Vec<([u8; 32], i32)> = match &lcm {
            LedgerCloseMeta::V0(m) => {
                envelopes.extend(m.tx_set.txs.iter());
                m.tx_processing
                    .iter()
                    .map(|t| {
                        (
                            t.result.transaction_hash.0,
                            t.tx_apply_processing.discriminant(),
                        )
                    })
                    .collect()
            }
            LedgerCloseMeta::V1(m) => {
                generalized(&m.tx_set, &mut envelopes);
                m.tx_processing
                    .iter()
                    .map(|t| {
                        (
                            t.result.transaction_hash.0,
                            t.tx_apply_processing.discriminant(),
                        )
                    })
                    .collect()
            }
            LedgerCloseMeta::V2(m) => {
                generalized(&m.tx_set, &mut envelopes);
                m.tx_processing
                    .iter()
                    .map(|t| {
                        (
                            t.result.transaction_hash.0,
                            t.tx_apply_processing.discriminant(),
                        )
                    })
                    .collect()
            }
        };
        let envelopes = envelopes
            .iter()
            .map(|e| e.hash(network_id).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TxHashes {
            results: processed.iter().map(|(h, _)| *h).collect(),
            envelopes,
            meta_versions: processed.iter().map(|(_, v)| *v).collect(),
            header,
        })
    })
}

fn generalized<'a>(set: &'a GeneralizedTransactionSet, out: &mut Vec<&'a TransactionEnvelope>) {
    let GeneralizedTransactionSet::V1(set) = set;
    for phase in set.phases.iter() {
        match phase {
            TransactionPhase::V0(components) => {
                for c in components.iter() {
                    let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) = c;
                    out.extend(c.txs.iter());
                }
            }
            TransactionPhase::V1(parallel) => {
                for stage in parallel.execution_stages.iter() {
                    for cluster in stage.0.iter() {
                        out.extend(cluster.0.iter());
                    }
                }
            }
        }
    }
}
