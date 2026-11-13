//! The state-change kinds for account fields, TTL extensions and contract code, and the entry
//! roles of pools: on vendored ledgers where the corpus has them, and on edited copies of vendored
//! ledgers where it does not yet.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, ContractCodeEntry, ContractCodeEntryExt, Hash, LedgerCloseMeta, LedgerEntryChange,
    LedgerEntryChanges, LedgerEntryData, PublicKey, TransactionMeta, Uint256,
};
use xdrcheck_meta::extract::{entry, extract, Extraction};
use xdrcheck_xdr::{Gate, Limits};

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

/// The first variant of an entry: its decoded ledger, passphrase and focus transaction.
fn ledger(id: &str) -> (LedgerCloseMeta, String, usize) {
    let e = entry::load_entry(&corpus(), id).unwrap();
    let v = &e.variants[0];
    let bytes = std::fs::read(corpus().join(&v.blob)).unwrap();
    let lcm = xdrcheck_xdr::decode_ledger(&bytes, &Limits::default(), &Gate::default()).unwrap();
    (lcm, v.passphrase.clone(), v.focus_tx)
}

fn run(lcm: &LedgerCloseMeta, passphrase: &str) -> Extraction {
    xdrcheck_xdr::with_stack(Limits::default().stack_size, || {
        extract(lcm, passphrase).unwrap()
    })
}

/// The focus transaction's state changes of `kind`, as JSON.
fn changes(ext: &Extraction, tx: usize, kind: &str) -> Vec<Value> {
    serde_json::to_value(&ext.txs[tx].state_changes)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == kind)
        .cloned()
        .collect()
}

fn source_of(ext: &Extraction, tx: usize) -> String {
    ext.txs[tx]
        .participants
        .iter()
        .find(|p| p.roles.contains("source"))
        .expect("a source")
        .address
        .clone()
}

/// The change list of operation `op` of transaction `tx`.
fn op_changes(lcm: &mut LedgerCloseMeta, tx: usize, op: usize) -> &mut LedgerEntryChanges {
    let meta = match lcm {
        LedgerCloseMeta::V0(v) => {
            &mut v
                .tx_processing
                .iter_mut()
                .nth(tx)
                .unwrap()
                .tx_apply_processing
        }
        LedgerCloseMeta::V1(v) => {
            &mut v
                .tx_processing
                .iter_mut()
                .nth(tx)
                .unwrap()
                .tx_apply_processing
        }
        LedgerCloseMeta::V2(v) => {
            &mut v
                .tx_processing
                .iter_mut()
                .nth(tx)
                .unwrap()
                .tx_apply_processing
        }
    };
    match meta {
        TransactionMeta::V0(ops) => &mut ops.iter_mut().nth(op).unwrap().changes,
        TransactionMeta::V1(m) => &mut m.operations.iter_mut().nth(op).unwrap().changes,
        TransactionMeta::V2(m) => &mut m.operations.iter_mut().nth(op).unwrap().changes,
        TransactionMeta::V3(m) => &mut m.operations.iter_mut().nth(op).unwrap().changes,
        TransactionMeta::V4(m) => &mut m.operations.iter_mut().nth(op).unwrap().changes,
    }
}

#[test]
fn ttl_extension_is_attributed_to_the_contract_and_names_its_key() {
    let (lcm, pass, tx) = ledger("cap-0046/extend-footprint-ttl-golden");
    let ext = run(&lcm, &pass);
    let ttl = changes(&ext, tx, "ttl_extended");
    assert!(!ttl.is_empty(), "no ttl_extended");
    for c in &ttl {
        let d = &c["detail"];
        assert_eq!(d["entry_type"], "contract_data", "{c}");
        assert_eq!(d["contract"], c["account"]["address"], "{c}");
        assert!(d["live_until_ledger"].as_u64() > d["live_until_ledger_before"].as_u64());
        // The TTL key is the sha256 of the entry's key.
        let key = hex::decode(d["key_xdr_hex"].as_str().unwrap()).unwrap();
        assert_eq!(d["key_hash"], json!(hex::encode(Sha256::digest(&key))));
    }
    // Ambient: it makes no participant of its own.
    let contract = ttl[0]["account"]["address"].as_str().unwrap();
    let only_ttl = ext.txs[tx]
        .state_changes
        .iter()
        .all(|c| c.account.address != contract || c.kind == "ttl_extended");
    if only_ttl {
        assert!(ext.txs[tx]
            .participants
            .iter()
            .all(|p| p.address != contract));
    }
}

#[test]
fn contract_code_upload_is_attributed_to_the_source() {
    let (lcm, pass, tx) = ledger("cap-0046/fee-bump-soroban-refund-to-fee-source-golden");
    let ext = run(&lcm, &pass);
    let code = changes(&ext, tx, "contract_code_created");
    assert_eq!(code.len(), 1, "{code:?}");
    assert_eq!(code[0]["account"]["address"], json!(source_of(&ext, tx)));
    assert_eq!(code[0]["detail"]["wasm_hash"].as_str().unwrap().len(), 64);
    assert!(code[0]["detail"]["code_bytes"].as_u64().unwrap() > 0);
}

#[test]
fn restored_contract_code_is_attributed_to_the_source() {
    let (mut lcm, pass, tx) = ledger("cap-0046/restore-footprint-golden");
    // Turn the restored contract-data entry of its (single, Soroban) operation into contract code.
    let mut done = false;
    for c in op_changes(&mut lcm, tx, 0).0.iter_mut() {
        if let LedgerEntryChange::Restored(e) = c {
            if matches!(e.data, LedgerEntryData::ContractData(_)) && !done {
                e.data = LedgerEntryData::ContractCode(ContractCodeEntry {
                    ext: ContractCodeEntryExt::V0,
                    hash: Hash([5; 32]),
                    code: vec![0, 97, 115, 109].try_into().unwrap(),
                });
                done = true;
            }
        }
    }
    assert!(done, "the ledger restores a contract-data entry");
    let ext = run(&lcm, &pass);
    let restored: Vec<Value> = changes(&ext, tx, "entry_restored")
        .into_iter()
        .filter(|c| c["detail"]["entry_type"] == "contract_code")
        .collect();
    assert_eq!(restored.len(), 1, "{restored:?}");
    assert_eq!(
        restored[0]["account"]["address"],
        json!(source_of(&ext, tx))
    );
    assert_eq!(
        restored[0]["detail"]["wasm_hash"],
        json!(hex::encode([5u8; 32]))
    );
}

#[test]
fn account_flags_home_domain_and_inflation_destination() {
    let (mut lcm, pass, tx) = ledger("cap-0040/signed-payload-signer-added");
    let dest = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([3; 32])));
    let mut before = None;
    for c in op_changes(&mut lcm, tx, 0).0.iter_mut() {
        if let LedgerEntryChange::Updated(e) = c {
            if let LedgerEntryData::Account(a) = &mut e.data {
                before = Some(a.flags);
                a.flags = 0b1010;
                a.home_domain = "example.org".as_bytes().to_vec().try_into().unwrap();
                a.inflation_dest = Some(dest.clone());
            }
        }
    }
    let flags_before = before.expect("the set-options operation updates the account");
    let ext = run(&lcm, &pass);
    let f = changes(&ext, tx, "account_flags_changed");
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(
        f[0]["detail"],
        json!({"flags": 10, "flags_before": flags_before, "auth_required": false,
               "auth_revocable": true, "auth_immutable": false, "auth_clawback_enabled": true})
    );
    let h = changes(&ext, tx, "home_domain_changed");
    assert_eq!(h[0]["detail"]["home_domain"], "example.org");
    assert_eq!(
        h[0]["detail"]["home_domain_hex"],
        hex::encode("example.org")
    );
    assert_eq!(h[0]["detail"]["home_domain_before"], "");
    let i = changes(&ext, tx, "inflation_destination_changed");
    assert_eq!(
        i[0]["detail"],
        json!({"inflation_destination": dest.to_string()})
    );
    assert_eq!(h[0]["account"], f[0]["account"]);
    // The inflation destination is named, not affected: it is no participant.
    assert!(ext.txs[tx]
        .participants
        .iter()
        .all(|p| p.address != dest.to_string()));
}

#[test]
fn a_changed_pool_has_the_liquidity_pool_role() {
    let (lcm, pass, tx) = ledger("cap-0038/pool-issuers-order-by-bytes-not-strkey");
    let ext = run(&lcm, &pass);
    let pools: Vec<_> = ext.txs[tx]
        .participants
        .iter()
        .filter(|p| p.address.starts_with('L'))
        .collect();
    assert!(!pools.is_empty());
    for p in pools {
        assert!(p.roles.contains("liquidity_pool"), "{p:?}");
        assert!(!p.roles.contains("counterparty"), "{p:?}");
    }
}

#[test]
fn a_data_entry_written_back_unchanged_is_no_state_change() {
    let (mut lcm, pass, tx) = ledger("classic/manage-data-unchanged-value");
    // As vendored: the manage_data writes the entry's current value back.
    let ext = run(&lcm, &pass);
    assert!(
        changes(&ext, tx, "data_entry_changed").is_empty(),
        "{:?}",
        ext.txs[tx].state_changes
    );
    let owner = source_of(&ext, tx);
    assert!(ext.txs[tx].participants.iter().any(|p| p.address == owner));
    // The same update with a different value after: one data_entry_changed.
    let mut done = false;
    for c in op_changes(&mut lcm, tx, 0).0.iter_mut() {
        if let LedgerEntryChange::Updated(e) = c {
            if let LedgerEntryData::Data(d) = &mut e.data {
                d.data_value = vec![1, 2, 3].try_into().unwrap();
                done = true;
            }
        }
    }
    assert!(done, "the manage_data updates a data entry");
    let ext = run(&lcm, &pass);
    let d = changes(&ext, tx, "data_entry_changed");
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(
        d[0]["detail"],
        json!({"name": "wde", "value_hex": "010203", "change": "updated"})
    );
    assert_eq!(d[0]["account"]["address"], json!(owner));
}
