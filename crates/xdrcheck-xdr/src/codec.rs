//! Typed decode by XDR type name, byte-exact re-encode and SEP-51 JSON.
//!
//! Decoding always runs with explicit limits ([`Limits`]): a depth in `stellar-xdr` depth units
//! (one nested `ScVal` vector level costs four) and a byte length that defaults to the input
//! length. `Limits::none()` is never used: with no depth limit the library aborts the process on
//! stack overflow at about 12,000 nested levels. Decoding, encoding and JSON rendering run on a
//! dedicated thread with a large explicit stack ([`Limits::stack_size`], default 256 MiB) so that
//! values deep enough to pass the depth limit cannot overflow the stack either.
//!
//! Deeply nested values are also recursive to *drop* and to serialise. [`roundtrip`] and
//! [`json_roundtrip`] keep the value on the large-stack thread for its whole life; callers that
//! work with possibly deep values themselves should do so inside [`with_stack`].

use std::io::Cursor;
use std::str::FromStr;

use stellar_xdr::{Limited, Type, TypeVariant, WriteXdr};

use crate::error::{Error, Malformed, Refusal, Result};

/// Default depth limit in `stellar-xdr` depth units. Provisional: well above the
/// measured floor of about 2,000 units that stellar-core's admission of a bare `SCVal` needs. To be
/// replaced by the measured core admission boundary plus a margin once the boundary entries exist.
pub const DEFAULT_DEPTH: u32 = 6000;

/// Default stack size of the decode thread.
pub const DEFAULT_STACK_SIZE: usize = 256 * 1024 * 1024;

/// Decode and encode limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum nesting depth in `stellar-xdr` depth units.
    pub depth: u32,
    /// Maximum bytes read or written; `None` means the length of the input.
    pub len: Option<usize>,
    /// Stack size in bytes of the thread the codec runs on.
    pub stack_size: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            depth: DEFAULT_DEPTH,
            len: None,
            stack_size: DEFAULT_STACK_SIZE,
        }
    }
}

impl Limits {
    /// The default limits with the given depth.
    pub fn depth(depth: u32) -> Self {
        Limits {
            depth,
            ..Limits::default()
        }
    }

    /// The `stellar-xdr` limits for an input (or output) of `input_len` bytes.
    pub fn xdr(&self, input_len: usize) -> stellar_xdr::Limits {
        stellar_xdr::Limits {
            depth: self.depth,
            len: self.len.unwrap_or(input_len),
        }
    }
}

thread_local! {
    /// The stack size of the current thread when it was started by [`with_stack`].
    static BIG_STACK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Run `f` on a fresh thread with `stack_size` bytes of stack and return its result. Panics in
/// `f` are propagated to the caller. On a thread that `with_stack` itself started with at least
/// `stack_size` bytes, `f` runs in place: a long-lived worker started this way does not spawn a
/// thread (and get a fresh allocator arena) per call.
pub fn with_stack<T, F>(stack_size: usize, f: F) -> T
where
    T: Send,
    F: FnOnce() -> T + Send,
{
    if BIG_STACK.with(|b| b.get()) >= stack_size {
        return f();
    }
    std::thread::scope(|s| {
        let handle = std::thread::Builder::new()
            .name("xdrcheck-xdr".into())
            .stack_size(stack_size)
            .spawn_scoped(s, move || {
                BIG_STACK.with(|b| b.set(stack_size));
                f()
            })
            .expect("spawn decode thread");
        match handle.join() {
            Ok(v) => v,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}

/// Resolve an XDR type name (as in the `.x` files, e.g. `"LedgerCloseMeta"`, `"ScVal"`).
pub fn type_variant(type_name: &str) -> Result<TypeVariant> {
    TypeVariant::from_str(type_name).map_err(|_| Error::UnknownType(type_name.to_string()))
}

/// Decode `bytes` as one value of `type_name`. Trailing bytes are an error.
///
/// Runs on a large-stack thread. A `LedgerCloseMeta` whose union arm the pinned library does not
/// know is an [`Error::Refusal`], not a malformed input.
pub fn decode(type_name: &str, bytes: &[u8], limits: &Limits) -> Result<Type> {
    let variant = type_variant(type_name)?;
    with_stack(limits.stack_size, || decode_here(variant, bytes, limits))
}

/// Encode a value with the given limits (length defaults to unbounded for encoding unless set).
pub fn encode(value: &Type, limits: &Limits) -> Result<Vec<u8>> {
    with_stack(limits.stack_size, || encode_here(value, limits, usize::MAX))
}

/// Decode `bytes` as `type_name`, re-encode with the same limits, and fail with
/// [`Error::RoundTrip`] unless the bytes are identical.
pub fn roundtrip(type_name: &str, bytes: &[u8], limits: &Limits) -> Result<()> {
    let variant = type_variant(type_name)?;
    with_stack(limits.stack_size, || {
        let value = decode_here(variant, bytes, limits)?;
        let out = encode_here(&value, limits, bytes.len())?;
        compare(type_name, "xdr", bytes, &out)
    })
}

/// The SEP-51 JSON of a decoded value, as produced by the pinned `stellar-xdr` serde.
pub fn to_json(value: &Type, limits: &Limits) -> Result<serde_json::Value> {
    with_stack(limits.stack_size, || to_json_here(value))
}

/// Parse SEP-51 JSON as `type_name`.
///
/// Note: the library's serde ignores unknown object fields. Nesting is not limited by the JSON
/// parser (the decode thread's stack bounds it).
pub fn from_json(type_name: &str, json: &serde_json::Value, limits: &Limits) -> Result<Type> {
    let variant = type_variant(type_name)?;
    with_stack(limits.stack_size, || from_json_here(variant, json))
}

/// Parse SEP-51 JSON as `type_name` and encode it to XDR bytes.
pub fn json_to_xdr(type_name: &str, json: &serde_json::Value, limits: &Limits) -> Result<Vec<u8>> {
    let variant = type_variant(type_name)?;
    with_stack(limits.stack_size, || {
        let value = from_json_here(variant, json)?;
        encode_here(&value, limits, usize::MAX)
    })
}

/// The full oracle check of the project's version-pin decision for one value: decode → re-encode → byte equality →
/// SEP-51 JSON → parse back → re-encode → byte equality. Returns the JSON.
pub fn json_roundtrip(type_name: &str, bytes: &[u8], limits: &Limits) -> Result<serde_json::Value> {
    let variant = type_variant(type_name)?;
    with_stack(limits.stack_size, || {
        let value = decode_here(variant, bytes, limits)?;
        compare(
            type_name,
            "xdr",
            bytes,
            &encode_here(&value, limits, bytes.len())?,
        )?;
        let json = to_json_here(&value)?;
        let back = from_json_here(variant, &json)?;
        compare(
            type_name,
            "json",
            bytes,
            &encode_here(&back, limits, bytes.len())?,
        )?;
        Ok(json)
    })
}

/// The oracle check without its JSON half: decode → re-encode → byte equality → SEP-51 JSON.
/// Returns the JSON. For values whose SEP-51 JSON is a declared exception to the round trip (the
/// manifest's `variants[].json_roundtrip`): the bytes must still round-trip and the JSON is still
/// rendered, but it is not parsed back.
pub fn xdr_json(type_name: &str, bytes: &[u8], limits: &Limits) -> Result<serde_json::Value> {
    let variant = type_variant(type_name)?;
    with_stack(limits.stack_size, || {
        let value = decode_here(variant, bytes, limits)?;
        compare(
            type_name,
            "xdr",
            bytes,
            &encode_here(&value, limits, bytes.len())?,
        )?;
        to_json_here(&value)
    })
}

// --- Same-thread primitives. Callers must already be on a large stack. ---

/// Decode on the current thread. Checks the `LedgerCloseMeta` arm first so an unknown arm is a
/// refusal; reads exactly one value and reports trailing bytes as malformed.
pub(crate) fn decode_here(variant: TypeVariant, bytes: &[u8], limits: &Limits) -> Result<Type> {
    let name = variant.name();
    if variant == TypeVariant::LedgerCloseMeta {
        check_ledger_close_meta_arm(bytes, crate::ledger::KNOWN_MAX_LEDGER_CLOSE_META_VERSION)?;
    }
    let xdr_limits = limits.xdr(bytes.len());
    let len_limit = xdr_limits.len;
    let mut r = Limited::new(Cursor::new(bytes), xdr_limits);
    let value = Type::read_xdr(variant, &mut r)
        .map_err(|e| Error::from_xdr_read(name, e, len_limit, bytes.len()))?;
    let consumed = usize::try_from(r.inner.position()).expect("cursor position fits usize");
    if consumed != bytes.len() {
        return Err(Error::Malformed {
            type_name: name.to_string(),
            reason: Malformed::TrailingBytes {
                consumed,
                len: bytes.len(),
                trailing: bytes.len() - consumed,
            },
        });
    }
    Ok(value)
}

/// Encode on the current thread. The length limit is `limits.len`, else `default_len`.
pub(crate) fn encode_here(value: &Type, limits: &Limits, default_len: usize) -> Result<Vec<u8>> {
    let xdr_limits = stellar_xdr::Limits {
        depth: limits.depth,
        len: limits.len.unwrap_or(default_len),
    };
    let mut w = Limited::new(Cursor::new(Vec::new()), xdr_limits);
    value
        .write_xdr(&mut w)
        .map_err(|e| Error::from_xdr(value.name(), e))?;
    Ok(w.inner.into_inner())
}

pub(crate) fn to_json_here(value: &Type) -> Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|e| Error::Json {
        type_name: value.name().to_string(),
        message: e.to_string(),
    })
}

pub(crate) fn from_json_here(variant: TypeVariant, json: &serde_json::Value) -> Result<Type> {
    let err = |message: String| Error::Json {
        type_name: variant.name().to_string(),
        message,
    };
    // The library parses from a reader; the value is re-serialised to bytes once. Its own
    // `Type::from_json` keeps serde_json's limit of 128 nested arrays/objects, which a nested
    // `ScVal` of 64 levels already exceeds, so the deserializer is built here with the limit off
    // (we run on the large stack instead).
    let text = serde_json::to_vec(json).map_err(|e| err(e.to_string()))?;
    let mut de = serde_json::Deserializer::from_slice(&text);
    de.disable_recursion_limit();
    let value = Type::deserialize_json(variant, &mut de).map_err(|e| err(e.to_string()))?;
    de.end().map_err(|e| err(e.to_string()))?;
    Ok(value)
}

/// Parse JSON text without serde_json's nesting limit, on the large-stack thread. Use it for
/// sidecars of deeply nested values, which the default parser rejects past 128 levels.
pub fn parse_json(text: &[u8], limits: &Limits) -> Result<serde_json::Value> {
    with_stack(limits.stack_size, || {
        let mut de = serde_json::Deserializer::from_slice(text);
        de.disable_recursion_limit();
        let v = serde::Deserialize::deserialize(&mut de).and_then(|v| de.end().map(|()| v));
        v.map_err(|e| Error::Json {
            type_name: "JSON".into(),
            message: e.to_string(),
        })
    })
}

/// Refuse a `LedgerCloseMeta` whose discriminant is negative or above `max`. Input shorter than
/// a discriminant is left for the decoder to report.
pub(crate) fn check_ledger_close_meta_arm(bytes: &[u8], max: u32) -> Result<()> {
    if let Some(d) = bytes.get(..4) {
        let version = i32::from_be_bytes(d.try_into().expect("4 bytes"));
        if version < 0 || version as u32 > max {
            return Err(Refusal::UnknownLedgerCloseMetaVersion { version, max }.into());
        }
    }
    Ok(())
}

/// Byte comparison with a [`Error::RoundTrip`] describing the first difference.
pub(crate) fn compare(
    type_name: &str,
    stage: &'static str,
    input: &[u8],
    output: &[u8],
) -> Result<()> {
    if input == output {
        return Ok(());
    }
    let first_difference = input
        .iter()
        .zip(output)
        .position(|(a, b)| a != b)
        .unwrap_or(input.len().min(output.len()));
    Err(Error::RoundTrip {
        type_name: type_name.to_string(),
        stage,
        input_len: input.len(),
        output_len: output.len(),
        first_difference,
    })
}
