//! Typed refusals (unknown meta arm, protocol above the gate) and decode limits (depth on a
//! deep `ScVal`, length on an oversized length prefix).

mod common;

use xdrcheck_xdr::{Error, Gate, LimitKind, Limits, Refusal};

#[test]
fn unknown_ledger_close_meta_arm_is_a_refusal() {
    let mut bytes = common::some_ledger();
    bytes[..4].copy_from_slice(&3i32.to_be_bytes());
    let refused = |e: &Error| {
        matches!(
            e,
            Error::Refusal(Refusal::UnknownLedgerCloseMetaVersion { version: 3, max: 2 })
        )
    };
    let e = xdrcheck_xdr::decode("LedgerCloseMeta", &bytes, &Limits::default()).unwrap_err();
    assert!(refused(&e), "{e}");
    let e = xdrcheck_xdr::decode_ledger(&bytes, &Limits::default(), &Gate::default()).unwrap_err();
    assert!(refused(&e), "{e}");
    let e = xdrcheck_xdr::ledger_info(&bytes).unwrap_err();
    assert!(refused(&e), "{e}");
    let stream = xdrcheck_xdr::frame([bytes.as_slice()]).unwrap();
    let e =
        xdrcheck_xdr::split_ledger_stream(&stream, &Limits::default(), &Gate::default()).unwrap_err();
    assert!(refused(&e), "{e}");

    // A negative discriminant too.
    bytes[..4].copy_from_slice(&(-1i32).to_be_bytes());
    let e = xdrcheck_xdr::decode("LedgerCloseMeta", &bytes, &Limits::default()).unwrap_err();
    assert!(e.is_refusal() && !e.is_malformed(), "{e}");
}

#[test]
fn gate_refuses_protocol_and_version_above_max() {
    let bytes = common::some_ledger();
    let info = xdrcheck_xdr::ledger_info(&bytes).unwrap();
    let low_protocol = Gate {
        max_protocol: info.protocol - 1,
        ..Gate::default()
    };
    let e = xdrcheck_xdr::decode_ledger(&bytes, &Limits::default(), &low_protocol).unwrap_err();
    assert_eq!(
        e.to_string(),
        Error::from(Refusal::ProtocolAboveMax {
            protocol: info.protocol,
            max: info.protocol - 1
        })
        .to_string()
    );
    let low_version = Gate {
        max_ledger_close_meta_version: 1,
        ..Gate::default()
    };
    let e = xdrcheck_xdr::roundtrip_ledger(&bytes, &Limits::default(), &low_version).unwrap_err();
    assert!(
        matches!(
            e,
            Error::Refusal(Refusal::UnknownLedgerCloseMetaVersion { version: 2, max: 1 })
        ),
        "{e}"
    );
    // Within the gate, the same ledger is accepted.
    xdrcheck_xdr::roundtrip_ledger(&bytes, &Limits::default(), &Gate::default()).unwrap();
}

#[test]
fn gate_from_corpus_json() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("xdrcheck-xdr-gate-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("corpus.json");
    assert_eq!(Gate::from_corpus_json(&path).unwrap(), None);
    std::fs::write(
        &path,
        br#"{"max_protocol": 29, "max_ledger_close_meta_version": 1}"#,
    )
    .unwrap();
    assert_eq!(
        Gate::from_corpus_json(&path).unwrap(),
        Some(Gate {
            max_protocol: 29,
            max_ledger_close_meta_version: 1
        })
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `levels` nested `ScVal::Vec`, each holding one element, around an `ScVal::Void`.
/// Encoded by hand from Stellar-contract.x: SCV_VEC = 16, optional present = 1, length = 1;
/// SCV_VOID = 1.
fn nested_vec(levels: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(levels * 12 + 4);
    for _ in 0..levels {
        out.extend_from_slice(&[0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0, 1]);
    }
    out.extend_from_slice(&[0, 0, 0, 1]);
    out
}

/// Depth units the decoder spends on one nested `ScVal` vector level (the union arm, the optional
/// vector and its elements); the innermost value costs one more such level.
const UNITS_PER_VEC_LEVEL: u32 = 4;

/// The deepest `ScVal` vector nesting that decodes under a depth limit of `limit` units.
fn deepest_nested_vec(limit: u32) -> usize {
    (limit / UNITS_PER_VEC_LEVEL - 1) as usize
}

#[test]
fn depth_limit_boundary_follows_the_configured_limit() {
    // Small limits, including ones that are not a multiple of the unit cost: the deepest nesting
    // decodes and one level more is refused for depth, wherever the limit is set.
    for limit in [12, 13, 64, 99, 100, 103] {
        let n = deepest_nested_vec(limit);
        xdrcheck_xdr::roundtrip("ScVal", &nested_vec(n), &Limits::depth(limit))
            .unwrap_or_else(|e| panic!("{n} levels under depth {limit}: {e}"));
        let e = xdrcheck_xdr::roundtrip("ScVal", &nested_vec(n + 1), &Limits::depth(limit)).unwrap_err();
        assert!(
            e.is_limit_exceeded(),
            "{} levels under depth {limit}: {e}",
            n + 1
        );
    }
}

#[test]
fn deep_scval_respects_depth_limit() {
    let deep = nested_vec(2000);
    // 2,000 levels at four depth units each fit 10,000 units, on the large-stack thread.
    xdrcheck_xdr::roundtrip("ScVal", &deep, &Limits::depth(10_000)).unwrap();
    let e = xdrcheck_xdr::roundtrip("ScVal", &deep, &Limits::depth(500)).unwrap_err();
    assert!(
        matches!(
            e,
            Error::LimitExceeded {
                limit: LimitKind::Depth,
                ..
            }
        ),
        "{e}"
    );
    assert!(e.is_limit_exceeded() && !e.is_malformed() && !e.is_refusal());

    // A shallow value checks the JSON path too.
    let json = xdrcheck_xdr::json_roundtrip("ScVal", &nested_vec(3), &Limits::default()).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"vec": [{"vec": [{"vec": ["void"]}]}]})
    );
}

#[test]
fn deep_scval_round_trips_through_json() {
    // 2000 levels is 4000 nested JSON objects and arrays, far past serde_json's default limit
    // of 128; the oracle's JSON path must not stop there.
    let deep = nested_vec(2000);
    let limits = Limits::depth(10_000);
    xdrcheck_xdr::with_stack(limits.stack_size, || {
        let json = xdrcheck_xdr::json_roundtrip("ScVal", &deep, &limits).unwrap();
        let text = serde_json::to_vec(&json).unwrap();
        let parsed = xdrcheck_xdr::parse_json(&text, &limits).unwrap();
        assert_eq!(
            xdrcheck_xdr::json_to_xdr("ScVal", &parsed, &limits).unwrap(),
            deep
        );
        assert!(serde_json::from_slice::<serde_json::Value>(&text).is_err());
    });
}

#[test]
fn deep_decode_returns_value_without_crashing() {
    let deep = nested_vec(2000);
    let limits = Limits::depth(10_000);
    // Keep the deep value (and its recursive drop) on a large stack.
    xdrcheck_xdr::with_stack(limits.stack_size, || {
        let v = xdrcheck_xdr::decode("ScVal", &deep, &limits).unwrap();
        assert_eq!(xdrcheck_xdr::encode(&v, &limits).unwrap(), deep);
    });
}

#[test]
fn oversized_length_prefix_hits_length_limit() {
    // ScBytes (unbounded opaque<>) with a length prefix of 0xFFFFFFFF and no body: with the
    // length limit defaulting to the input size this fails before any large allocation, and
    // since the limit is the input itself it is reported as input ending inside the value.
    let bytes = [0xff, 0xff, 0xff, 0xff];
    let e = xdrcheck_xdr::decode("ScBytes", &bytes, &Limits::default()).unwrap_err();
    assert!(
        matches!(
            e,
            Error::Malformed {
                reason: xdrcheck_xdr::Malformed::UnexpectedEof,
                ..
            }
        ),
        "{e}"
    );
    // An explicit length limit below the input size is a limit, not malformed input.
    let blob = common::some_ledger();
    let small = Limits {
        len: Some(blob.len() / 2),
        ..Limits::default()
    };
    let e = xdrcheck_xdr::decode("LedgerCloseMeta", &blob, &small).unwrap_err();
    assert!(
        matches!(
            e,
            Error::LimitExceeded {
                limit: LimitKind::Len,
                ..
            }
        ),
        "{e}"
    );
    // A value cut short is malformed.
    let e = xdrcheck_xdr::decode("ScVal", &[0, 0, 0, 16, 0, 0, 0, 1], &Limits::default()).unwrap_err();
    assert!(
        matches!(
            e,
            Error::Malformed {
                reason: xdrcheck_xdr::Malformed::UnexpectedEof,
                ..
            }
        ),
        "{e}"
    );
}
