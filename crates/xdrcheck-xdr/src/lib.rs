//! XDR core for the corpus toolchain: typed decode by type name with explicit limits, byte-exact
//! re-encode, record-mark framing, `LedgerCloseMetaBatch` and zstd handling, hashing.
//!
//! The oracle is `stellar-xdr` 30.0.0 (re-exported as [`xdr`]); this crate adds what the oracle
//! design requires on top of it:
//!
//! - [`codec`]: [`decode`] by type name under explicit [`Limits`] on a large-stack thread,
//!   [`roundtrip`] (byte-exact re-encode), SEP-51 JSON ([`to_json`], [`from_json`],
//!   [`json_roundtrip`], and [`xdr_json`] for values whose JSON round trip is a declared
//!   exception).
//! - [`framing`]: an RFC 5531 record-mark reader and writer that checks the last-fragment bit and
//!   each record's exact length.
//! - [`batch`]: SEP-54 lake objects (zstd `LedgerCloseMetaBatch`) to ledgers and back.
//! - [`ledger`]: the fail-closed [`Gate`] (typed [`Refusal`]s) and a cheap header read.
//! - [`hash`]: sha256 hex of bytes and files.
//!
//! Errors are one type, [`Error`], whose variants separate refusal, malformed input, limit
//! exceeded, framing faults and round-trip mismatches.

pub mod batch;
pub mod codec;
pub mod error;
pub mod framing;
pub mod hash;
pub mod ledger;
pub mod spec;
pub mod userdir;

pub use stellar_xdr as xdr;

pub use batch::{build_batch, pack_object, split_batch, unpack_object, Batch};
pub use codec::{
    decode, encode, from_json, json_roundtrip, json_to_xdr, parse_json, roundtrip, to_json,
    type_variant, with_stack, xdr_json, Limits, DEFAULT_DEPTH, DEFAULT_STACK_SIZE,
};
pub use error::{Error, FramingError, LimitKind, Malformed, Refusal, Result};
pub use framing::{frame, records, split, split_checked, write_record, Record};
pub use hash::{sha256_file, sha256_hex};
pub use ledger::{
    decode_ledger, ledger_info, roundtrip_ledger, split_ledger_stream, Gate, LedgerInfo,
};
