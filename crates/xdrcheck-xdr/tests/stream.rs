//! Record-marked meta streams: a captured stellar-core stream splits into its ledgers; corrupted
//! marks are typed framing errors.

mod common;

use std::path::PathBuf;

use xdrcheck_xdr::{Error, FramingError, Gate, Limits};

fn run_dir() -> PathBuf {
    let wb = common::repo().join("evidence/wallet-backend-731/out/p28-testnet/run-1");
    if wb.join("meta.xdr").exists() {
        wb
    } else {
        common::repo().join("evidence/local-core/out/testnet/run-1")
    }
}

fn stream() -> Vec<u8> {
    std::fs::read(run_dir().join("meta.xdr")).unwrap()
}

#[test]
fn probe_stream_splits_into_its_ledgers() {
    let stream = stream();
    let ledgers =
        xdrcheck_xdr::split_ledger_stream(&stream, &Limits::default(), &Gate::default()).unwrap();

    // The probe's own per-ledger files (split by an independent script) are the expectation.
    let dir = run_dir().join("ledgers");
    let mut expected: Vec<(u32, Vec<u8>)> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            let seq = p.file_stem().unwrap().to_str().unwrap().parse().unwrap();
            (seq, std::fs::read(p).unwrap())
        })
        .collect();
    expected.sort();
    if run_dir().ends_with("p28-testnet/run-1") {
        assert_eq!(expected.len(), 23);
    }
    assert_eq!(ledgers.len(), expected.len());
    for ((info, payload), (seq, bytes)) in ledgers.iter().zip(&expected) {
        assert_eq!(info.sequence, *seq);
        assert_eq!(*payload, bytes.as_slice(), "ledger {seq}");
    }

    // Each record decodes on its own, and the generic splitter agrees.
    let records = xdrcheck_xdr::split_checked("LedgerCloseMeta", &stream, &Limits::default()).unwrap();
    assert_eq!(records.len(), expected.len());
    for r in &records {
        xdrcheck_xdr::framing::decode_record("LedgerCloseMeta", r, &Limits::default()).unwrap();
    }

    // The writer reproduces the stream byte for byte.
    let rewritten = xdrcheck_xdr::frame(records.iter().map(|r| r.payload)).unwrap();
    assert_eq!(rewritten, stream);
}

#[test]
fn local_core_streams_match_their_analysis() {
    for net in ["testnet", "mainnet"] {
        let dir = common::repo().join(format!("evidence/local-core/out/{net}/run-1"));
        let stream = std::fs::read(dir.join("meta.xdr")).unwrap();
        let analysis: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("analysis.json")).unwrap()).unwrap();
        let expected = analysis["ledgers"].as_array().unwrap();
        let ledgers =
            xdrcheck_xdr::split_ledger_stream(&stream, &Limits::default(), &Gate::default()).unwrap();
        assert_eq!(ledgers.len(), expected.len(), "{net}");
        for ((info, payload), want) in ledgers.iter().zip(expected) {
            assert_eq!(u64::from(info.sequence), want["ledger"].as_u64().unwrap());
            assert_eq!(u64::from(info.protocol), want["protocol"].as_u64().unwrap());
            assert_eq!(
                hex::encode(info.header_hash),
                want["header_hash"].as_str().unwrap()
            );
            assert_eq!(payload.len() as u64, want["raw_len"].as_u64().unwrap());
            assert_eq!(
                xdrcheck_xdr::sha256_hex(payload),
                want["raw_sha256"].as_str().unwrap()
            );
        }
    }
}

fn set_mark(stream: &mut [u8], offset: usize, mark: u32) {
    stream[offset..offset + 4].copy_from_slice(&mark.to_be_bytes());
}

fn mark_at(stream: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(stream[offset..offset + 4].try_into().unwrap())
}

fn split_err(stream: &[u8]) -> Error {
    xdrcheck_xdr::split_ledger_stream(stream, &Limits::default(), &Gate::default()).unwrap_err()
}

#[test]
fn mark_shorter_than_value_is_length_mismatch() {
    let mut s = stream();
    let m = mark_at(&s, 0);
    set_mark(&mut s, 0, m - 4);
    let e = split_err(&s);
    assert!(
        matches!(
            &e,
            Error::Framing(FramingError::LengthMismatch {
                index: 0,
                offset: 0,
                ..
            })
        ),
        "{e}"
    );
}

#[test]
fn mark_longer_than_value_is_length_mismatch() {
    let mut s = stream();
    let m = mark_at(&s, 0);
    set_mark(&mut s, 0, m + 4);
    let e = split_err(&s);
    assert!(
        matches!(
            &e,
            Error::Framing(FramingError::LengthMismatch {
                index: 0,
                offset: 0,
                ..
            })
        ),
        "{e}"
    );
}

#[test]
fn mark_past_end_is_truncated() {
    let mut s = stream();
    let records = xdrcheck_xdr::split(&s).unwrap();
    let last = records.last().unwrap();
    let (index, offset) = (last.index, last.offset);
    let m = mark_at(&s, offset);
    set_mark(&mut s, offset, m + 100);
    let e = split_err(&s);
    assert!(
        matches!(
            &e,
            Error::Framing(FramingError::Truncated { index: i, offset: o, .. }) if *i == index && *o == offset
        ),
        "{e}"
    );

    // A stream cut inside a mark.
    let mut s = stream();
    s.extend_from_slice(&[0x80, 0]);
    let e = split_err(&s);
    assert!(
        matches!(
            &e,
            Error::Framing(FramingError::Truncated {
                declared: 4,
                available: 2,
                ..
            })
        ),
        "{e}"
    );
}

#[test]
fn last_fragment_bit_clear_is_rejected() {
    let mut s = stream();
    let m = mark_at(&s, 0);
    set_mark(&mut s, 0, m & 0x7fff_ffff);
    let e = split_err(&s);
    assert!(
        matches!(
            &e,
            Error::Framing(FramingError::LastFragmentBitClear { index: 0, .. })
        ),
        "{e}"
    );
    // The plain splitter reports it too and then stops.
    let mut it = xdrcheck_xdr::records(&s);
    assert!(it.next().unwrap().is_err());
    assert!(it.next().is_none());
}

#[test]
fn writer_rejects_nothing_small_and_sets_bit_31() {
    let s = xdrcheck_xdr::frame([&[1u8, 2, 3][..], &[][..]]).unwrap();
    assert_eq!(s, [0x80, 0, 0, 3, 1, 2, 3, 0x80, 0, 0, 0]);
    let r = xdrcheck_xdr::split(&s).unwrap();
    assert_eq!(r.len(), 2);
    assert_eq!(r[1].payload, &[] as &[u8]);
}
