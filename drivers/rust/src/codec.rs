//! L0 (codec round trip) and L2 (values as SEP-51 JSON, at pinpoints) over `stellar_xdr::Type`, the crate's
//! by-name type dispatch (feature `type_enum`).
//!
//! Decode profiles. `stellar-xdr` has no default `Limits`; every decode passes one:
//!
//! - `limits-default`: `Limits { depth: 500, len: <input length> }`, the Soroban host's default XDR depth with
//!   the length budget set to the input size, as the host's own comment asks for deserialisation.
//! - `limits-none`: `Limits::none()`, what the crate's CLI uses. Deep values then recurse until the decode
//!   thread's stack runs out (the process aborts; the orchestrator records the crash) and a length prefix
//!   is allocated before the body is read.
//!
//! `Type::read_xdr` spends one depth unit on its own dispatch level before it calls `T::read_xdr`, so the
//! driver passes `depth + 1` to keep the value under exactly the limit `T::from_xdr(bytes, limits)` would
//! give it (the self-test checks that the driver decodes exactly the nesting `ScVal::from_xdr` decodes at
//! the same depth, and refuses one level more).

use std::io::Cursor;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{Error, Limited, Limits, Type, TypeVariant, WriteXdr};

use crate::outcome::{Outcome, Reason};

/// The depth of the `limits-default` profile.
pub const DEFAULT_DEPTH: u32 = 500;

/// The depth unit `Type::read_xdr` spends on its dispatch level.
const DISPATCH_DEPTH: u32 = 1;

/// The longest re-encoding returned as hex when it differs from the input.
const MAX_REENCODED_HEX: usize = 4096;

pub const ENTRY_POINT: &str = "stellar_xdr::Type::from_xdr";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    LimitsDefault,
    LimitsNone,
}

impl Profile {
    pub const NAMES: [&'static str; 2] = ["limits-default", "limits-none"];

    pub fn parse(s: Option<&str>) -> Option<Profile> {
        match s {
            None | Some("limits-default") => Some(Profile::LimitsDefault),
            Some("limits-none") => Some(Profile::LimitsNone),
            _ => None,
        }
    }

    /// The limits for a value of `len` bytes, including the dispatch level of `Type`.
    pub fn limits(self, len: usize) -> Limits {
        match self {
            Profile::LimitsDefault => Limits {
                depth: DEFAULT_DEPTH + DISPATCH_DEPTH,
                len,
            },
            Profile::LimitsNone => Limits::none(),
        }
    }
}

/// Resolves an XDR type name: the crate's own spelling (`ScVal`), or the XDR spelling ignoring case (`SCVal`).
pub fn type_variant(name: &str) -> Option<TypeVariant> {
    if let Ok(v) = name.parse::<TypeVariant>() {
        return Some(v);
    }
    TypeVariant::VARIANTS
        .iter()
        .copied()
        .find(|v| v.name().eq_ignore_ascii_case(name))
}

fn variant_name(e: &Error) -> String {
    let d = format!("{e:?}");
    let end = d.find(['(', ' ', '{']).unwrap_or(d.len());
    format!("stellar_xdr::Error::{}", &d[..end])
}

/// The reason code for a decode error. `Invalid` covers a bad bool, optional flag, enum value or union arm and
/// trailing bytes alike; trailing bytes are told apart by [`decode`], the others stay `decode_error`.
pub fn code(e: &Error) -> &'static str {
    match e {
        Error::NonZeroPadding => "nonzero_padding",
        Error::LengthExceedsMax => "length_exceeds_max",
        Error::DepthLimitExceeded => "depth",
        // The length budget is the input size: a value that needs more bytes than the input holds.
        Error::LengthLimitExceeded => "length_exceeds_input",
        _ => "decode_error",
    }
}

/// The reason for an error from the library.
pub fn reason(e: &Error, entry_point: &str) -> Reason {
    Reason::new(code(e))
        .message(e.to_string())
        .class(variant_name(e))
        .entry_point(entry_point)
}

/// A rejected decode: the reason, and the lenient entry points that accepted the bytes anyway.
pub struct Rejected {
    pub reason: Reason,
    pub lenient: Vec<Value>,
}

impl Rejected {
    pub fn into_outcome(self, level: &str) -> Outcome {
        let o = Outcome::reject(self.reason);
        if level == "L0" && !self.lenient.is_empty() {
            return o.actual("lenient_entry_points", Value::Array(self.lenient));
        }
        o
    }
}

/// Decodes one value with the strict entry point (`Type::from_xdr`: the whole input must be consumed).
///
/// When it fails with `Invalid`, the same bytes are read once more with `Type::read_xdr`, which stops after
/// the value; if that succeeds and bytes are left, the strict entry point refused trailing bytes, and the
/// lenient one is reported as accepting them.
pub fn decode(tv: TypeVariant, bytes: &[u8], profile: Profile) -> Result<Type, Rejected> {
    match Type::from_xdr(tv, bytes, profile.limits(bytes.len())) {
        Ok(t) => Ok(t),
        Err(e) => {
            let mut reason = reason(&e, ENTRY_POINT);
            let mut lenient = Vec::new();
            if matches!(e, Error::Invalid) {
                let mut r = Limited::new(Cursor::new(bytes), profile.limits(bytes.len()));
                if Type::read_xdr(tv, &mut r).is_ok() {
                    let left = bytes.len() as u64 - r.inner.position();
                    if left > 0 {
                        reason.code = "trailing_bytes";
                        lenient.push(json!({
                            "entry_point": "stellar_xdr::Type::read_xdr",
                            "accepted": true,
                            "note": format!("reads the value and leaves {left} trailing bytes unread"),
                        }));
                    }
                }
            }
            Err(Rejected { reason, lenient })
        }
    }
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// L0: decode, check the whole input was consumed, re-encode, compare.
pub fn l0(tv: TypeVariant, bytes: &[u8], profile: Profile) -> Outcome {
    let t = match decode(tv, bytes, profile) {
        Ok(t) => t,
        Err(r) => return r.into_outcome("L0"),
    };
    let enc = match t.to_xdr(Limits::none()) {
        Ok(enc) => enc,
        Err(e) => {
            return Outcome::diverge(
                reason(&e, "stellar_xdr::WriteXdr::to_xdr")
                    .message(format!("re-encoding the decoded value failed: {e}")),
            )
            .actual("consumed_bytes", json!(bytes.len()));
        }
    };
    let mut actual = Map::new();
    actual.insert("consumed_bytes".into(), json!(bytes.len()));
    actual.insert("reencoded_sha256".into(), json!(sha256_hex(&enc)));
    if enc == bytes {
        return Outcome::ok(actual);
    }
    if enc.len() <= MAX_REENCODED_HEX {
        actual.insert("reencoded_hex".into(), json!(hex::encode(&enc)));
    }
    let mut o = Outcome::diverge(
        Reason::new("reencode_mismatch")
            .message(format!(
                "re-encoding is {} bytes and differs from the {}-byte input",
                enc.len(),
                bytes.len()
            ))
            .entry_point("stellar_xdr::WriteXdr::to_xdr"),
    );
    o.actual = actual;
    o
}

/// L2: decode, render the value as the library's SEP-51 JSON, and return it whole or at the pinpoints.
pub fn l2(tv: TypeVariant, bytes: &[u8], profile: Profile, pinpoints: Option<&[Value]>) -> Outcome {
    let t = match decode(tv, bytes, profile) {
        Ok(t) => t,
        Err(r) => return r.into_outcome("L2"),
    };
    let v = match serde_json::to_value(&t) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::reject(
                Reason::new("other")
                    .message(format!("the decoded value has no XDR-JSON rendering: {e}"))
                    .entry_point("serde_json::to_value"),
            )
        }
    };
    match pinpoints {
        None => Outcome::ok(Map::new()).actual("projection", v),
        Some(paths) => {
            let found: Vec<Value> = paths
                .iter()
                .map(|p| {
                    let p = p.as_str().unwrap_or_default();
                    match v.pointer(p) {
                        Some(x) => json!({"path": p, "found": true, "value": x}),
                        None => json!({"path": p, "found": false}),
                    }
                })
                .collect();
            Outcome::ok(Map::new()).actual("pinpoints", Value::Array(found))
        }
    }
}

/// Splits RFC 5531 record-marked bytes and returns frame `index`. Every frame must be a last fragment (bit 31
/// set) and its length must fit in the input.
pub fn frame(bytes: &[u8], index: usize) -> Result<&[u8], String> {
    let mut pos = 0usize;
    let mut i = 0usize;
    while pos < bytes.len() {
        let hdr: [u8; 4] = bytes
            .get(pos..pos + 4)
            .and_then(|h| h.try_into().ok())
            .ok_or_else(|| format!("frame {i}: truncated record mark at offset {pos}"))?;
        let mark = u32::from_be_bytes(hdr);
        if mark & 0x8000_0000 == 0 {
            return Err(format!(
                "frame {i}: record mark at offset {pos} is not a last fragment"
            ));
        }
        let len = (mark & 0x7fff_ffff) as usize;
        let body = bytes.get(pos + 4..pos + 4 + len).ok_or_else(|| {
            format!("frame {i}: record length {len} at offset {pos} exceeds the input")
        })?;
        if i == index {
            return Ok(body);
        }
        pos += 4 + len;
        i += 1;
    }
    Err(format!(
        "frame {index} not found: the input holds {i} frames"
    ))
}
