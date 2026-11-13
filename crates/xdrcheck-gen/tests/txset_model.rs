//! The transaction-set model (`xdrcheck_gen::output::txset`) against every ledger stellar-core closed in
//! the committed chains: with the shape read from the ledger, the model reproduces core's set hash
//! and apply order exactly; and on every ledger without surge pricing (every component at the
//! ledger's base fee) the default shape is the shape core built.

use std::path::Path;

use stellar_xdr::{GeneralizedTransactionSet, LedgerCloseMeta, TransactionEnvelope};
use xdrcheck_gen::output::chain::{ledger_facts, stream_ledgers};
use xdrcheck_gen::output::sidecar::read_sidecar;
use xdrcheck_gen::output::txset::{
    default_shape, learn_shape, predict, set_hash_of, ModelTx, PhaseShape, Shape,
};
use xdrcheck_gen::scenario::network_id;

fn envelopes(lcm: &LedgerCloseMeta) -> Vec<TransactionEnvelope> {
    let set = match lcm {
        LedgerCloseMeta::V0(m) => return m.tx_set.txs.to_vec(),
        LedgerCloseMeta::V1(m) => &m.tx_set,
        LedgerCloseMeta::V2(m) => &m.tx_set,
    };
    let GeneralizedTransactionSet::V1(v1) = set;
    let mut out = Vec::new();
    for p in v1.phases.iter() {
        match p {
            stellar_xdr::TransactionPhase::V0(cs) => {
                for c in cs.iter() {
                    let stellar_xdr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) = c;
                    out.extend(c.txs.iter().cloned());
                }
            }
            stellar_xdr::TransactionPhase::V1(pc) => {
                for st in pc.execution_stages.iter() {
                    for cl in st.0.iter() {
                        out.extend(cl.0.iter().cloned());
                    }
                }
            }
        }
    }
    out
}

/// Whether every component of the set is at the ledger's base fee (no surge pricing).
fn at_base_fee(shape: &Shape, base_fee: i64) -> bool {
    match shape {
        Shape::Legacy => true,
        Shape::Generalized(phases) => phases.iter().all(|p| match p {
            PhaseShape::Sequential(cs) => cs.iter().all(|(f, _)| *f == Some(base_fee)),
            PhaseShape::Parallel {
                base_fee: f,
                stages,
            } => stages.is_empty() || *f == Some(base_fee),
        }),
    }
}

#[test]
fn model_reproduces_every_committed_ledger() {
    let chains = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/chains");
    let (mut ledgers, mut multi, mut default_held) = (0, 0, 0);
    for dir in std::fs::read_dir(&chains).unwrap() {
        let dir = dir.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        for f in std::fs::read_dir(&dir).unwrap() {
            let f = f.unwrap().path();
            if !f.to_string_lossy().ends_with(".meta.xdr.zst") {
                continue;
            }
            let index_path = f.to_string_lossy().replace(".meta.xdr.zst", ".json");
            let index: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&index_path).unwrap()).unwrap();
            let nid = network_id(index["passphrase"].as_str().unwrap());
            let stream = read_sidecar(&f).unwrap();
            for l in stream_ledgers(&stream).unwrap() {
                let facts = ledger_facts(l.bytes).unwrap();
                if facts.results.is_empty() {
                    continue;
                }
                let lcm = xdrcheck_xdr::decode_ledger(
                    l.bytes,
                    &xdrcheck_xdr::Limits::default(),
                    &xdrcheck_xdr::Gate::default(),
                )
                .unwrap();
                let envs = envelopes(&lcm);
                let txs: Vec<ModelTx> = envs
                    .iter()
                    .cloned()
                    .map(|e| ModelTx::new(e).unwrap())
                    .collect();
                let at = format!("{} ledger {}", f.display(), l.info.sequence);
                let header = &facts.header.header;
                let previous = header.previous_ledger_hash.0;
                let shape = learn_shape(&lcm, &txs).unwrap();
                let p = predict(&shape, &txs, previous).unwrap();
                assert_eq!(p.set_hash, set_hash_of(&lcm).unwrap(), "{at}: set hash");
                let order: Vec<[u8; 32]> = p
                    .order
                    .iter()
                    .map(|i| envs[*i].hash(nid).unwrap())
                    .collect();
                let applied: Vec<[u8; 32]> =
                    facts.results.iter().map(|r| r.transaction_hash.0).collect();
                assert_eq!(order, applied, "{at}: apply order");
                let d = default_shape(header.ledger_version, i64::from(header.base_fee), &txs);
                let dp = predict(&d, &txs, previous).unwrap();
                if at_base_fee(&shape, i64::from(header.base_fee)) {
                    assert_eq!(
                        dp.set_hash, p.set_hash,
                        "{at}: default shape, core built {shape:?}"
                    );
                    default_held += 1;
                }
                ledgers += 1;
                multi += usize::from(txs.len() > 1);
            }
        }
    }
    println!("{ledgers} ledgers ({multi} with several transactions); default shape held in {default_held}");
    assert!(
        multi > 0,
        "the committed chains hold multi-transaction ledgers"
    );
    assert!(default_held > 0);
}
