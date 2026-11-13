//! `xdr_json`: the byte round trip and the JSON rendering without the JSON → XDR half, for values
//! whose SEP-51 JSON is a declared round-trip exception.

use stellar_xdr::{SignerKey, SignerKeyEd25519SignedPayload, Uint256, WriteXdr};
use xdrcheck_xdr::{json_roundtrip, xdr_json, Error, Limits};

fn bytes_of(k: &SignerKey) -> Vec<u8> {
    k.to_xdr(stellar_xdr::Limits::none()).unwrap()
}

#[test]
fn renders_where_the_full_round_trip_renders() {
    let key = SignerKey::Ed25519(Uint256([7; 32]));
    let b = bytes_of(&key);
    let full = json_roundtrip("SignerKey", &b, &Limits::default()).unwrap();
    assert_eq!(xdr_json("SignerKey", &b, &Limits::default()).unwrap(), full);
}

/// A signed-payload signer with an empty payload: the XDR round-trips and renders, but the pinned
/// library does not parse its JSON back — the case the manifest's `json_roundtrip` exception is for.
/// A library upgrade that fixes it fails this test (and `verify` then reports the exception stale).
#[test]
fn empty_signed_payload() {
    let key = SignerKey::Ed25519SignedPayload(SignerKeyEd25519SignedPayload {
        ed25519: Uint256([9; 32]),
        payload: Vec::new().try_into().unwrap(),
    });
    let b = bytes_of(&key);
    let json = xdr_json("SignerKey", &b, &Limits::default()).unwrap();
    assert!(json.is_string(), "{json}");
    let e = json_roundtrip("SignerKey", &b, &Limits::default()).unwrap_err();
    assert!(matches!(e, Error::Json { .. }), "{e}");
}

#[test]
fn still_requires_the_byte_round_trip() {
    // SCV_BOOL with a boolean of 2 decodes leniently and re-encodes differently: the byte round
    // trip must still fail.
    let b = [0, 0, 0, 0, 0, 0, 0, 2];
    assert!(matches!(
        xdr_json("ScVal", &b, &Limits::default()),
        Err(Error::RoundTrip { stage: "xdr", .. }) | Err(Error::Malformed { .. })
    ));
    // Trailing bytes are still malformed.
    assert!(matches!(
        xdr_json("ScVal", &[0, 0, 0, 1, 0], &Limits::default()),
        Err(Error::Malformed { .. })
    ));
}
