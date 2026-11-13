//! SEP-54 lake objects: unpack a vendored object to its ledger and build it back.

mod common;

use xdrcheck_xdr::{Gate, Limits};

fn manifest_variant() -> serde_json::Value {
    let m: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            common::repo().join("corpus/manifest/cap-0040/signed-payload-signer-added.json"),
        )
        .unwrap(),
    )
    .unwrap();
    m["variants"][0].clone()
}

fn object() -> Vec<u8> {
    let dir = common::repo().join("corpus/objects/testnet/4437357");
    let path = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.to_str().unwrap().ends_with(".xdr.zst"))
        .expect("vendored lake object");
    std::fs::read(path).unwrap()
}

#[test]
fn lake_object_unpacks_to_manifest_blob() {
    let v = manifest_variant();
    let object = object();
    let src = &v["source"];
    assert_eq!(
        xdrcheck_xdr::sha256_hex(&object),
        src["object_sha256"].as_str().unwrap()
    );
    let decompressed = xdrcheck_xdr::batch::decompress(&object).unwrap();
    assert_eq!(
        xdrcheck_xdr::sha256_hex(&decompressed),
        src["decompressed_sha256"].as_str().unwrap()
    );

    let batch = xdrcheck_xdr::unpack_object(&object, &Limits::default(), &Gate::default()).unwrap();
    assert_eq!(batch.start_sequence, 4437357);
    assert_eq!(batch.end_sequence, 4437357);
    assert_eq!(batch.ledgers.len(), 1);
    assert_eq!(
        xdrcheck_xdr::sha256_hex(&batch.ledgers[0]),
        v["blob"]["sha256"].as_str().unwrap()
    );
    assert_eq!(batch.infos[0].sequence, 4437357);
    let offset = src["blob_offset"].as_u64().unwrap() as usize;
    assert_eq!(&decompressed[offset..], batch.ledgers[0].as_slice());

    // Building the batch back gives the lake's decompressed bytes exactly.
    let rebuilt = xdrcheck_xdr::build_batch(&[&batch.ledgers[0]], &Gate::default()).unwrap();
    assert_eq!(rebuilt, decompressed);

    // And our own compressed object unpacks to the same ledger.
    let ours = xdrcheck_xdr::pack_object(
        &[&batch.ledgers[0]],
        &Gate::default(),
        xdrcheck_xdr::batch::DEFAULT_ZSTD_LEVEL,
    )
    .unwrap();
    let again = xdrcheck_xdr::unpack_object(&ours, &Limits::default(), &Gate::default()).unwrap();
    assert_eq!(again, batch);
}

#[test]
fn multi_ledger_batch_round_trips() {
    let ledgers: Vec<Vec<u8>> = (2..=4)
        .map(|seq| {
            std::fs::read(common::repo().join(format!(
                "evidence/wallet-backend-731/out/p28-testnet/run-1/ledgers/{seq}.xdr"
            )))
            .unwrap()
        })
        .collect();
    let refs: Vec<&[u8]> = ledgers.iter().map(Vec::as_slice).collect();
    let xdr = xdrcheck_xdr::build_batch(&refs, &Gate::default()).unwrap();
    assert_eq!(&xdr[..12], &[0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 3]);
    // The whole batch is also a valid LedgerCloseMetaBatch to the library.
    xdrcheck_xdr::roundtrip("LedgerCloseMetaBatch", &xdr, &Limits::default()).unwrap();
    let batch = xdrcheck_xdr::split_batch(&xdr, &Limits::default(), &Gate::default()).unwrap();
    assert_eq!(batch.ledgers, ledgers);
    assert_eq!((batch.start_sequence, batch.end_sequence), (2, 4));

    // Header disagreeing with the ledgers is malformed; a trailing byte too.
    let mut bad = xdr.clone();
    bad[7] = 5;
    let e = xdrcheck_xdr::split_batch(&bad, &Limits::default(), &Gate::default()).unwrap_err();
    assert!(e.is_malformed(), "{e}");
    let mut bad = xdr.clone();
    bad.push(0);
    let e = xdrcheck_xdr::split_batch(&bad, &Limits::default(), &Gate::default()).unwrap_err();
    assert!(e.is_malformed(), "{e}");
}

#[test]
fn batch_with_unknown_arm_is_refused() {
    let mut ledger = common::some_ledger();
    ledger[..4].copy_from_slice(&3i32.to_be_bytes());
    let mut xdr = vec![0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1];
    xdr.extend_from_slice(&ledger);
    let e = xdrcheck_xdr::split_batch(&xdr, &Limits::default(), &Gate::default()).unwrap_err();
    assert!(
        matches!(
            e,
            xdrcheck_xdr::Error::Refusal(xdrcheck_xdr::Refusal::UnknownLedgerCloseMetaVersion {
                version: 3,
                ..
            })
        ),
        "{e}"
    );
    let e = xdrcheck_xdr::build_batch(&[&ledger], &Gate::default()).unwrap_err();
    assert!(e.is_refusal(), "{e}");
}
