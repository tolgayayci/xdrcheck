//! The reference extractor: its output satisfies the hand-written `expect` blocks of the
//! corpus entries for every variant; the agreement check is not vacuous; and the emitting-contract
//! rule holds on a synthetic ledger (a vendored blob whose decoded value is edited in the test).

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, ContractEvent, ContractEventBody, ContractEventType, ContractEventV0, ContractId,
    ExtensionPoint, Hash, Int128Parts, LedgerCloseMeta, PublicKey, ScAddress, ScString, ScSymbol,
    ScVal, TransactionMeta, Uint256,
};
use xdrcheck_meta::extract::{
    agree, contract_strkey, entry, extract, network_id, sac_contract_id, Extraction,
};
use xdrcheck_xdr::{Gate, Limits};

const ENTRIES: [&str; 3] = [
    "cap-0073/sac-trust-creates-trustline",
    "cap-0040/signed-payload-signer-added",
    "cap-0038/pool-issuers-order-by-bytes-not-strkey",
];

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

/// Every entry ID in the vendored corpus.
fn all_entries() -> Vec<String> {
    let root = corpus().join("manifest");
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if let Some(rel) = p.strip_prefix(&root).unwrap().to_str() {
                out.push(rel.trim_end_matches(".json").to_string());
            }
        }
    }
    out.sort();
    out
}

#[test]
fn extractor_satisfies_every_hand_written_expect_block() {
    let mut variants = 0;
    let ids = all_entries();
    for id in ENTRIES {
        assert!(ids.iter().any(|i| i == id), "{id}");
    }
    let mut bad = Vec::new();
    for id in &ids {
        let e = entry::load_entry(&corpus(), id).unwrap();
        for v in &e.variants {
            let run = entry::run_variant(&corpus(), &e, v, &Gate::default()).unwrap();
            eprintln!(
                "{}",
                serde_json::to_string(&run.output).expect("output serialises")
            );
            for d in run.disagreements {
                bad.push(format!("{id} {}: {d}", v.label));
            }
            variants += 1;
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
    assert!(variants >= 6, "{variants} variants");
}

/// The agreement check finds each kind of disagreement (it is not vacuous).
#[test]
fn agreement_check_reports_disagreements() {
    let e = entry::load_entry(&corpus(), ENTRIES[0]).unwrap();
    let v = &e.variants[0];
    let run = entry::run_variant(&corpus(), &e, v, &Gate::default()).unwrap();
    let nid = network_id(&v.passphrase);
    let base = agree::resolve_derived(&e.json["expect"], &v.derived).unwrap();
    assert!(agree::check(&base, &run.extraction, 0, nid).is_empty());
    let owner = v.derived["accounts"]["owner"].as_str().unwrap().to_string();

    let mutate = |f: &dyn Fn(&mut Value)| {
        let mut x = base.clone();
        f(&mut x);
        agree::check(&x, &run.extraction, 0, nid)
    };
    // Wrong asset on the created trustline.
    assert!(!mutate(&|x| x["state_changes"][0]["asset"] =
        json!("EURC:".to_string() + v.derived["accounts"]["issuer"].as_str().unwrap()))
    .is_empty());
    // A detail key with another value.
    assert!(!mutate(&|x| x["state_changes"][0]["detail"]["flags"] = json!(0)).is_empty());
    // A detail key the extractor does not derive for this change is not confirmed...
    let sponsor = json!(owner.clone());
    assert!(!mutate(&|x| x["state_changes"][0]["detail"]["sponsor"] = sponsor.clone()).is_empty());
    // ...unless the item is marked unverified.
    assert!(mutate(&|x| {
        x["state_changes"][0]["detail"]["sponsor"] = sponsor.clone();
        x["state_changes"][0]["unverified"] = json!("test");
    })
    .is_empty());
    // The only_if item is confirmed against the created trustline.
    let only_if = base["state_changes"]
        .as_array()
        .unwrap()
        .iter()
        .position(|i| i.get("only_if").is_some())
        .expect("an only_if item");
    assert!(!mutate(&|x| x["state_changes"][only_if]["detail"]["flags"] = json!(99)).is_empty());
    assert!(
        !mutate(&|x| x["state_changes"][only_if]["detail"]["initial"] = json!(false)).is_empty()
    );
    // A stated muxed ID the extractor does not derive.
    assert!(!mutate(&|x| x["participants"]["must_include"][0]["muxed_id"] = json!("5")).is_empty());
    assert!(mutate(&|x| {
        x["participants"]["must_include"][0]["muxed_id"] = json!("5");
        x["participants"]["must_include"][0]["unverified"] = json!("test");
    })
    .is_empty());
    // The owner listed as must-not.
    assert!(!mutate(
        &|x| x["participants"]["must_not_include"] = json!([{"address": owner, "because": "test"}])
    )
    .is_empty());
    // A fee movement with an amount the fee processing does not show.
    assert!(!mutate(&|x| x["movements"] = json!([
        {"kind": "fee", "asset": "native", "amount": "1", "from": {"address": owner}}
    ]))
    .is_empty());
    // Identical movements of two operations: an item stating its op_index counts only its own
    // operation's record, so the extractor's output (one item per operation) agrees with itself.
    {
        let mut ext = run.extraction.clone();
        let mut m = ext.txs[0]
            .movements
            .iter()
            .find(|m| m.kind != "fee")
            .expect("a non-fee movement")
            .clone();
        m.op_index = Some(0);
        let mut twin = m.clone();
        twin.op_index = Some(1);
        ext.txs[0].movements = vec![m, twin];
        let out = ext.expect_json(0);
        let mut x = base.clone();
        x["movements"] = out["expect"]["movements"].clone();
        assert_eq!(x["movements"].as_array().unwrap().len(), 2);
        assert!(agree::check(&x, &ext, 0, nid).is_empty());
        // Without op_index the item matches both records: one is not two.
        x["movements"] = json!([x["movements"][0].clone()]);
        x["movements"][0]
            .as_object_mut()
            .unwrap()
            .remove("op_index");
        assert!(!agree::check(&x, &ext, 0, nid).is_empty());
    }
    // Exactness: drop the only listed state change.
    assert!(!mutate(&|x| x["state_changes"] = json!([])).is_empty());
    // Whole-ledger count.
    assert!(!mutate(&|x| x["ledger"]["entry_changes"] = json!(8)).is_empty());
    // The entry names the asset by its contract address; the classic form is the same asset.
    let usdc = "USDC:".to_string() + v.derived["accounts"]["issuer"].as_str().unwrap();
    assert!(mutate(&|x| x["state_changes"][0]["asset"] = json!(usdc)).is_empty());
}

// --- Emitting-contract rule on synthetic test data. ---------------------------------------------

/// The blob of `cap-0073/sac-trust-creates-trustline` on the testnet passphrase at Protocol 30: one
/// SAC `trust` transaction whose third operation change creates the trustline.
fn trust_blob() -> PathBuf {
    let path = corpus().join("manifest/cap-0073/sac-trust-creates-trustline.json");
    let e: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let v = e["variants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["network"] == "testnet" && v["protocol"] == 30)
        .expect("a testnet variant at Protocol 30");
    corpus().join(v["blob"]["path"].as_str().unwrap())
}
const TESTNET: &str = "Test SDF Network ; September 2015";

fn address(a: &str) -> ScAddress {
    a.parse().unwrap()
}

fn symbol(s: &str) -> ScVal {
    ScVal::Symbol(ScSymbol(s.try_into().unwrap()))
}

fn i128(n: i128) -> ScVal {
    ScVal::I128(Int128Parts {
        hi: (n >> 64) as i64,
        lo: n as u64,
    })
}

/// A recipient that has no ledger entry in the ledger at all.
fn victim() -> String {
    AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7; 32]))).to_string()
}

/// The SAC `trust` ledger with one synthetic `transfer` event added to operation 0, emitted by
/// `emitter`, naming the owner, the victim and the given SEP-11 asset string.
fn ledger_with_event(emitter: [u8; 32], sep11: &str) -> (LedgerCloseMeta, String) {
    let bytes = std::fs::read(trust_blob()).unwrap();
    let mut lcm = xdrcheck_xdr::decode_ledger(&bytes, &Limits::default(), &Gate::default()).unwrap();
    let LedgerCloseMeta::V2(v) = &mut lcm else {
        panic!("v2 ledger")
    };
    let tx = v.tx_processing.iter_mut().next().unwrap();
    let TransactionMeta::V4(m) = &mut tx.tx_apply_processing else {
        panic!("v4 meta")
    };
    let owner = match &m.operations[0].changes.0[2] {
        stellar_xdr::LedgerEntryChange::Created(e) => match &e.data {
            stellar_xdr::LedgerEntryData::Trustline(t) => t.account_id.to_string(),
            _ => panic!("trustline"),
        },
        _ => panic!("created"),
    };
    let event = ContractEvent {
        ext: ExtensionPoint::V0,
        contract_id: Some(ContractId(Hash(emitter))),
        type_: ContractEventType::Contract,
        body: ContractEventBody::V0(ContractEventV0 {
            topics: vec![
                symbol("transfer"),
                ScVal::Address(address(&owner)),
                ScVal::Address(address(&victim())),
                ScVal::String(ScString(sep11.try_into().unwrap())),
            ]
            .try_into()
            .unwrap(),
            data: i128(1_000_000),
        }),
    };
    let op = m.operations.iter_mut().next().unwrap();
    let mut events = op.events.to_vec();
    events.push(event);
    op.events = events.try_into().unwrap();
    (lcm, owner)
}

fn run(lcm: &LedgerCloseMeta) -> Extraction {
    xdrcheck_xdr::with_stack(Limits::default().stack_size, || {
        extract(lcm, TESTNET).unwrap()
    })
}

/// `USDC:<issuer>` of the trust entry's first variant (the scenario names its issuer actor `issuer`).
fn usdc() -> String {
    let e = entry::load_entry(&corpus(), ENTRIES[0]).unwrap();
    let issuer = e.variants[0].derived["accounts"]["issuer"]
        .as_str()
        .unwrap();
    format!("USDC:{issuer}")
}

#[test]
fn forged_token_event_from_unrelated_contract_is_no_classic_movement() {
    let forger: [u8; 32] = Sha256::digest(b"synthetic test data: unrelated contract").into();
    let usdc = usdc();
    let (lcm, _) = ledger_with_event(forger, &usdc);
    let ext = run(&lcm);
    let tx = &ext.txs[0];
    let nid = network_id(TESTNET);
    let usdc_sac = contract_strkey(sac_contract_id(
        &xdrcheck_meta::extract::parse_asset(&usdc).unwrap(),
        nid,
    ));

    // No classic movement: nothing on the asset or its contract address besides the fee.
    assert!(!tx
        .movements
        .iter()
        .any(|m| m.asset == usdc || m.asset == usdc_sac));
    // No movement at all: the claim is recorded as addresses named by the forging contract.
    assert!(!tx.movements.iter().any(|m| m.kind == "transfer"));
    assert!(tx
        .named_by_contract
        .iter()
        .all(|n| n.contract == contract_strkey(forger)));
    // No participant: neither the victim nor the forging contract.
    assert!(!tx.participants.iter().any(|p| p.address == victim()));
    assert!(!tx
        .participants
        .iter()
        .any(|p| p.address == contract_strkey(forger)));
    assert_eq!(
        tx.participants.len(),
        1,
        "only the owner, from entry changes"
    );
    // Flagged, with the matching must-not facts proposed.
    assert!(tx.flags.iter().any(|f| f.kind == "forged_asset_claim"));
    assert!(tx.must_not_include.iter().any(|m| m.address == victim()));
    assert!(tx
        .proposed_must_not_movements
        .iter()
        .any(|m| m.asset == usdc && m.count == Some(0)));
    assert!(tx.named_by_contract.iter().any(|n| n.address == victim()));

    // The proposed must-not facts hold under the agreement check.
    let expect = json!({
        "participants": {"must_not_include": [{"address": victim(), "because": "forged event"}]},
        "movements": [{"kind": "transfer", "asset": usdc, "amount": "1000000", "count": 0}],
    });
    assert!(agree::check(&expect, &ext, 0, nid).is_empty());
    eprintln!("{}", serde_json::to_string(&ext.expect_json(0)).unwrap());
}

#[test]
fn same_event_from_the_asset_contract_is_a_classic_movement() {
    let nid = network_id(TESTNET);
    let usdc = usdc();
    let sac = sac_contract_id(&xdrcheck_meta::extract::parse_asset(&usdc).unwrap(), nid);
    let (lcm, owner) = ledger_with_event(sac, &usdc);
    let ext = run(&lcm);
    let tx = &ext.txs[0];
    let m: Vec<_> = tx
        .movements
        .iter()
        .filter(|m| m.kind == "transfer")
        .collect();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].asset, usdc);
    assert_eq!(m[0].from.as_ref().unwrap().address, owner);
    assert_eq!(m[0].to.as_ref().unwrap().address, victim());
    // The event adds the movement; it does not make the victim a participant (no entry changed).
    assert!(!tx.participants.iter().any(|p| p.address == victim()));
    assert!(tx
        .flags
        .iter()
        .any(|f| f.kind == "sac_event_address_without_entry_change"));
}

#[test]
fn contract_token_event_names_counterparties_of_that_token() {
    let token: [u8; 32] = Sha256::digest(b"synthetic test data: contract token").into();
    let (lcm, _) = ledger_with_event(token, "TOKEN");
    let ext = run(&lcm);
    let tx = &ext.txs[0];
    assert!(tx
        .movements
        .iter()
        .any(|m| m.kind == "transfer" && m.asset == contract_strkey(token)));
    let v = tx
        .participants
        .iter()
        .find(|p| p.address == victim())
        .unwrap();
    assert!(v.roles.contains("counterparty"));
    assert!(!tx.flags.iter().any(|f| f.kind == "forged_asset_claim"));
}

/// Every transaction of every vendored ledger and of the saved Protocol 28 chain is derived without
/// error, and every fee movement agrees with the fee events where they exist.
#[test]
fn whole_ledgers_extract_and_fee_events_agree() {
    let mut ledgers: Vec<(Vec<u8>, &str)> = Vec::new();
    for id in ENTRIES {
        let e = entry::load_entry(&corpus(), id).unwrap();
        for v in e.variants {
            let pass: &'static str = Box::leak(v.passphrase.into_boxed_str());
            ledgers.push((std::fs::read(corpus().join(&v.blob)).unwrap(), pass));
        }
    }
    let chain = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../evidence/wallet-backend-731/out/p28-mainnet/run-1/meta.xdr");
    if let Ok(stream) = std::fs::read(&chain) {
        for (_, l) in
            xdrcheck_xdr::split_ledger_stream(&stream, &Limits::default(), &Gate::default()).unwrap()
        {
            ledgers.push((l.to_vec(), "Public Global Stellar Network ; September 2015"));
        }
    }
    let mut txs = 0;
    for (bytes, pass) in &ledgers {
        let lcm = xdrcheck_xdr::decode_ledger(bytes, &Limits::default(), &Gate::default()).unwrap();
        let ext = xdrcheck_xdr::with_stack(Limits::default().stack_size, || {
            extract(&lcm, pass).unwrap()
        });
        for t in &ext.txs {
            for f in &t.flags {
                eprintln!("tx {} flag {}: {}", &t.hash[..8], f.kind, f.detail);
            }
            for m in &t.must_not_include {
                eprintln!(
                    "tx {} must-not candidate {}: {}",
                    &t.hash[..8],
                    m.address,
                    m.because
                );
            }
            assert_ne!(t.fee_events, "disagree", "tx {}: {:?}", t.hash, t.flags);
            assert!(t.participants.iter().any(|p| p.roles.contains("fee_payer")));
            txs += 1;
        }
    }
    assert!(txs > 30);
}
