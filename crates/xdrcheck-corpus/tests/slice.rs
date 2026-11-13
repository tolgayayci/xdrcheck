//! `xdrcheck-corpus slice`: the focus transaction envelope of the CAP-0038 issuer-ordering ledger is
//! cut out as an `xdr` entry whose bytes are exactly the parent's byte range.

mod common;

use std::path::Path;

use common::{copy_corpus, read_json, run};
use serde_json::json;
use sha2::{Digest, Sha256};

const PARENT: &str = "cap-0038/pool-issuers-order-by-bytes-not-strkey";
const ENVELOPE: &str = "/v2/tx_set/v1/phases/0/v0/0/txset_comp_txs_maybe_discounted_fee/txs/3";
const SLICE_ID: &str = "cap-0038/pool-issuers-order-envelope-slice";

/// Register the slice's ID in the scratch corpus' plan (IDs are born in plan.json).
fn plan_slice_id(corpus: &Path) {
    let path = corpus.join("plan.json");
    let mut plan = read_json(&path);
    let mut row = plan
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == PARENT)
        .unwrap()
        .clone();
    row["id"] = json!(SLICE_ID);
    row["kind"] = json!("xdr");
    row["members"] = json!([]);
    plan.as_array_mut().unwrap().push(row);
    std::fs::write(&path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
}

#[test]
fn focus_envelope_slice_is_the_parents_byte_range() {
    let corpus = copy_corpus("slice", "envelope");
    plan_slice_id(&corpus);
    let r = run(
        &corpus,
        &[
            "slice",
            PARENT,
            ENVELOPE,
            "--id",
            SLICE_ID,
            "--type",
            "TransactionEnvelope",
        ],
    );
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);

    let parent = read_json(&corpus.join(format!("manifest/{PARENT}.json")));
    let pv = &parent["variants"][0];
    let parent_blob = std::fs::read(corpus.join(pv["blob"]["path"].as_str().unwrap())).unwrap();
    let m = read_json(&corpus.join(format!("manifest/{SLICE_ID}.json")));
    let v = &m["variants"][0];
    assert_eq!(v["slice_of"]["entry"], PARENT);
    assert_eq!(v["slice_of"]["path"], ENVELOPE);
    assert_eq!(v["xdr_type"], "TransactionEnvelope");
    assert_eq!(v["passphrase"], pv["passphrase"]);
    assert_eq!(v["source"], pv["source"]);
    let offset = v["slice_of"]["byte_offset"].as_u64().unwrap() as usize;
    let slice = std::fs::read(corpus.join(v["blob"]["path"].as_str().unwrap())).unwrap();
    assert_eq!(&parent_blob[offset..offset + slice.len()], slice.as_slice());

    // The slice is the focus transaction: its hash under the variant's passphrase is the
    // manifest's focus hash.
    let env = xdrcheck_xdr::decode("TransactionEnvelope", &slice, &xdrcheck_xdr::Limits::default()).unwrap();
    let xdrcheck_xdr::xdr::Type::TransactionEnvelope(env) = env else {
        panic!("not an envelope")
    };
    let network_id: [u8; 32] = Sha256::digest(pv["passphrase"].as_str().unwrap().as_bytes()).into();
    assert_eq!(
        hex::encode(env.hash(network_id).unwrap()),
        pv["focus"]["tx_hash"].as_str().unwrap()
    );

    // The oracle gate accepts the slice's bytes and sidecar.
    let r = run(
        &corpus,
        &[
            "verify",
            "--checks",
            "hashes,roundtrip,sidecar,ids",
            "--entries",
            SLICE_ID,
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    // And re-rendering it changes nothing.
    let r = run(&corpus, &["render", SLICE_ID, "--check"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
}

#[test]
fn slices_that_cannot_be_cut_fail() {
    let corpus = copy_corpus("slice", "bad");
    plan_slice_id(&corpus);
    // A pointer that does not resolve.
    let r = run(
        &corpus,
        &[
            "slice",
            PARENT,
            "/v2/nope",
            "--id",
            SLICE_ID,
            "--type",
            "TransactionEnvelope",
        ],
    );
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(r.stdout.contains("does not resolve"), "{}", r.stdout);
    // The wrong type for the value at the pointer.
    let r = run(
        &corpus,
        &[
            "slice", PARENT, ENVELOPE, "--id", SLICE_ID, "--type", "ScVal",
        ],
    );
    assert_eq!(r.code, 1, "{}", r.stdout);
    // A wrong offset.
    let r = run(
        &corpus,
        &[
            "slice",
            PARENT,
            ENVELOPE,
            "--id",
            SLICE_ID,
            "--type",
            "TransactionEnvelope",
            "--offset",
            "0",
        ],
    );
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(r.stdout.contains("not at offset 0"), "{}", r.stdout);
    // An ID that is not planned is a tool error.
    let r = run(
        &corpus,
        &[
            "slice",
            PARENT,
            ENVELOPE,
            "--id",
            "cap-0038/unplanned",
            "--type",
            "TransactionEnvelope",
        ],
    );
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(!corpus.join(format!("manifest/{SLICE_ID}.json")).exists());
}
