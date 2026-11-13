//! Every vendored blob decodes as `LedgerCloseMeta`, round-trips byte-exactly through XDR and
//! SEP-51 JSON, and is named by its sha256.

mod common;

use xdrcheck_xdr::{xdr, Gate, Limits};

#[test]
fn six_blobs_decode_and_round_trip() {
    let blobs = common::blobs();
    // The six blobs of the first samples, and every blob added since.
    assert!(blobs.len() >= 6, "vendored blobs: {blobs:?}");
    let limits = Limits::default();
    for path in &blobs {
        let bytes = std::fs::read(path).unwrap();
        let stem = path.file_stem().unwrap().to_str().unwrap();
        assert_eq!(xdrcheck_xdr::sha256_hex(&bytes), stem, "{path:?}");
        assert_eq!(xdrcheck_xdr::sha256_file(path).unwrap(), stem, "{path:?}");

        xdrcheck_xdr::roundtrip("LedgerCloseMeta", &bytes, &limits).unwrap();
        xdrcheck_xdr::roundtrip_ledger(&bytes, &limits, &Gate::default()).unwrap();
        let json = xdrcheck_xdr::json_roundtrip("LedgerCloseMeta", &bytes, &limits).unwrap();
        assert_eq!(
            xdrcheck_xdr::json_to_xdr("LedgerCloseMeta", &json, &limits).unwrap(),
            bytes
        );

        // The cheap header read agrees with the full decode.
        let info = xdrcheck_xdr::ledger_info(&bytes).unwrap();
        let lcm = xdrcheck_xdr::decode_ledger(&bytes, &limits, &Gate::default()).unwrap();
        let (v, header) = match &lcm {
            xdr::LedgerCloseMeta::V0(m) => (0, &m.ledger_header),
            xdr::LedgerCloseMeta::V1(m) => (1, &m.ledger_header),
            xdr::LedgerCloseMeta::V2(m) => (2, &m.ledger_header),
        };
        assert_eq!(info.ledger_close_meta_version, v);
        assert_eq!(info.protocol, header.header.ledger_version);
        assert_eq!(info.sequence, header.header.ledger_seq);
        assert_eq!(info.header_hash, header.hash.0);

        let decoded = xdrcheck_xdr::decode("LedgerCloseMeta", &bytes, &limits).unwrap();
        assert_eq!(xdrcheck_xdr::encode(&decoded, &limits).unwrap(), bytes);
        assert_eq!(xdrcheck_xdr::to_json(&decoded, &limits).unwrap(), json);
    }
}

#[test]
fn cap_0040_blob_header_matches_manifest() {
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            common::repo().join("corpus/manifest/cap-0040/signed-payload-signer-added.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let variant = &manifest["variants"][0];
    let bytes = std::fs::read(
        common::repo()
            .join("corpus")
            .join(variant["blob"]["path"].as_str().unwrap()),
    )
    .unwrap();
    let info = xdrcheck_xdr::ledger_info(&bytes).unwrap();
    assert_eq!(
        u64::from(info.sequence),
        variant["ledger_seq"].as_u64().unwrap()
    );
    assert_eq!(
        u64::from(info.protocol),
        variant["protocol"].as_u64().unwrap()
    );
    assert_eq!(
        i64::from(info.ledger_close_meta_version),
        variant["meta"]["ledger_close_meta_version"]
            .as_i64()
            .unwrap()
    );
    assert_eq!(
        hex::encode(info.header_hash),
        variant["derived"]["ledger_hash"].as_str().unwrap()
    );
}

#[test]
fn trailing_bytes_and_unknown_type() {
    let mut bytes = common::some_ledger();
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    let e = xdrcheck_xdr::decode("LedgerCloseMeta", &bytes, &Limits::default()).unwrap_err();
    assert!(
        matches!(
            e,
            xdrcheck_xdr::Error::Malformed {
                reason: xdrcheck_xdr::Malformed::TrailingBytes { trailing: 4, .. },
                ..
            }
        ),
        "{e}"
    );
    let e = xdrcheck_xdr::decode("NoSuchType", &bytes, &Limits::default()).unwrap_err();
    assert!(matches!(e, xdrcheck_xdr::Error::UnknownType(_)), "{e}");
}
