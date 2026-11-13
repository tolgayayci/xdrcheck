//! The error type of the crate.
//!
//! Every failure falls into one of a few classes that callers must be able to tell apart:
//! a **refusal** (the input may be valid, but it is newer than this toolchain is pinned to
//! understand, so we refuse rather than guess), **malformed** input (the bytes are not a valid
//! encoding), a **limit exceeded** (the bytes may be valid but exceed the configured decode
//! limits), a **framing** error in a record-marked stream, or a **round-trip** mismatch (the
//! oracle re-encoded the value to different bytes).

use std::io;

/// Result alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Every error the crate returns.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Input this toolchain refuses to interpret (unknown or too-new meta version, protocol above
    /// the configured maximum).
    #[error("refused: {0}")]
    Refusal(#[from] Refusal),
    /// The bytes are not a valid XDR encoding of the requested type.
    #[error("malformed {type_name}: {reason}")]
    Malformed {
        /// XDR type being decoded.
        type_name: String,
        /// What was wrong.
        reason: Malformed,
    },
    /// A decode or encode limit was hit.
    #[error("{type_name}: {limit} limit exceeded")]
    LimitExceeded {
        /// XDR type being decoded or encoded.
        type_name: String,
        /// Which limit.
        limit: LimitKind,
    },
    /// A record-marked stream is not correctly framed.
    #[error("framing: {0}")]
    Framing(#[from] FramingError),
    /// Re-encoding the decoded value did not reproduce the input bytes.
    #[error("{type_name}: {stage} round trip differs (input {input_len} bytes, re-encoded {output_len} bytes, first difference at byte {first_difference})")]
    RoundTrip {
        /// XDR type.
        type_name: String,
        /// `"xdr"` for decode → encode, `"json"` for decode → JSON → decode → encode.
        stage: &'static str,
        /// Length of the original bytes.
        input_len: usize,
        /// Length of the re-encoded bytes.
        output_len: usize,
        /// Offset of the first differing byte (the shorter length if one is a prefix).
        first_difference: usize,
    },
    /// The type name is not an XDR type known to the pinned `stellar-xdr`.
    #[error("unknown XDR type name {0:?}")]
    UnknownType(String),
    /// SEP-51 JSON could not be produced or parsed.
    #[error("{type_name}: JSON: {message}")]
    Json {
        /// XDR type.
        type_name: String,
        /// The serde or library message.
        message: String,
    },
    /// I/O failure (files, zstd).
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
}

/// Reasons input is refused instead of decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The `LedgerCloseMeta` union discriminant is not an arm this toolchain knows, or is above
    /// the configured maximum meta version.
    #[error("LedgerCloseMeta version {version} is unknown (highest supported: {max})")]
    UnknownLedgerCloseMetaVersion {
        /// The discriminant read from the bytes.
        version: i32,
        /// Highest version accepted.
        max: u32,
    },
    /// The ledger header's protocol version is above the configured maximum.
    #[error("ledger protocol {protocol} is above the supported maximum {max}")]
    ProtocolAboveMax {
        /// `ledger_version` from the header.
        protocol: u32,
        /// Highest protocol accepted.
        max: u32,
    },
}

/// What made input malformed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Malformed {
    /// Bytes remained after the value.
    #[error("{trailing} trailing bytes after the value ({consumed} of {len} bytes consumed)")]
    TrailingBytes {
        /// Bytes consumed by the value.
        consumed: usize,
        /// Total input length.
        len: usize,
        /// `len - consumed`.
        trailing: usize,
    },
    /// The input ended in the middle of the value.
    #[error("unexpected end of input")]
    UnexpectedEof,
    /// Any other rejection by the XDR library (invalid discriminant, bad bool, non-zero padding,
    /// length above the XDR maximum, …).
    #[error("{0}")]
    Invalid(String),
    /// A `LedgerCloseMetaBatch` whose header disagrees with its ledgers.
    #[error("batch: {0}")]
    Batch(String),
}

/// Which decode or encode limit was hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    /// Nesting depth (`Limits::depth`, in `stellar-xdr` depth units).
    Depth,
    /// Byte length (`Limits::len`).
    Len,
}

impl std::fmt::Display for LimitKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LimitKind::Depth => "depth",
            LimitKind::Len => "length",
        })
    }
}

/// Errors of the RFC 5531 record-mark reader. `offset` is the byte offset of the record mark in
/// the stream.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FramingError {
    /// The last-fragment bit (bit 31) of a record mark is clear. stellar-core writes every record
    /// as a single fragment, so a clear bit means corruption or a foreign writer.
    #[error("record {index} at offset {offset}: last-fragment bit (bit 31) is clear (mark {mark:#010x})")]
    LastFragmentBitClear {
        /// Record number (0-based).
        index: usize,
        /// Offset of the mark.
        offset: usize,
        /// The raw 4-byte mark.
        mark: u32,
    },
    /// The stream ends inside a record mark or before the record's declared length.
    #[error("record {index} at offset {offset}: truncated, mark declares {declared} bytes but {available} remain")]
    Truncated {
        /// Record number (0-based).
        index: usize,
        /// Offset of the mark.
        offset: usize,
        /// Bytes the mark declares (4 when the mark itself is cut short).
        declared: usize,
        /// Bytes actually remaining.
        available: usize,
    },
    /// The record's declared length is not exactly the length of the one value it holds.
    #[error("record {index} at offset {offset}: mark declares {declared} bytes but the {type_name} value {detail}")]
    LengthMismatch {
        /// Record number (0-based).
        index: usize,
        /// Offset of the mark.
        offset: usize,
        /// Bytes the mark declares.
        declared: usize,
        /// Type the record was decoded as.
        type_name: String,
        /// "needs more bytes" or "ends after N bytes".
        detail: String,
    },
    /// A record payload too large to describe in 31 bits (writer side).
    #[error("record of {0} bytes does not fit a 31-bit record mark")]
    RecordTooLarge(usize),
}

impl Error {
    /// True for [`Error::Refusal`].
    pub fn is_refusal(&self) -> bool {
        matches!(self, Error::Refusal(_))
    }

    /// True for [`Error::LimitExceeded`].
    pub fn is_limit_exceeded(&self) -> bool {
        matches!(self, Error::LimitExceeded { .. })
    }

    /// True for [`Error::Malformed`].
    pub fn is_malformed(&self) -> bool {
        matches!(self, Error::Malformed { .. })
    }

    /// Classify a `stellar-xdr` error raised while reading `type_name` with a length limit of
    /// `len_limit` from an input of `input_len` bytes. The library charges the length limit
    /// before reading, so when the limit is the whole input, running past it means the input
    /// ended inside the value: malformed, not a limit.
    pub(crate) fn from_xdr_read(
        type_name: &str,
        e: stellar_xdr::Error,
        len_limit: usize,
        input_len: usize,
    ) -> Self {
        match e {
            stellar_xdr::Error::LengthLimitExceeded if len_limit >= input_len => Error::Malformed {
                type_name: type_name.to_string(),
                reason: Malformed::UnexpectedEof,
            },
            e => Error::from_xdr(type_name, e),
        }
    }

    /// Classify a `stellar-xdr` error raised while reading or writing `type_name`.
    pub(crate) fn from_xdr(type_name: &str, e: stellar_xdr::Error) -> Self {
        use stellar_xdr::Error as X;
        let type_name = type_name.to_string();
        match e {
            X::DepthLimitExceeded => Error::LimitExceeded {
                type_name,
                limit: LimitKind::Depth,
            },
            X::LengthLimitExceeded => Error::LimitExceeded {
                type_name,
                limit: LimitKind::Len,
            },
            X::Io(io) if io.kind() == io::ErrorKind::UnexpectedEof => Error::Malformed {
                type_name,
                reason: Malformed::UnexpectedEof,
            },
            other => Error::Malformed {
                type_name,
                reason: Malformed::Invalid(other.to_string()),
            },
        }
    }
}
