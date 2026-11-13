//! Intake: the code shared by `capture` and `refetch` (history capture) and by
//! `fetch-goldens` and `import-golden` (golden import).
//!
//! - [`lake`]: the public data lake (SEP-54 key formula, anonymous HTTPS fetch with `curl`), the
//!   normalised `capture.json` record and the object → blob chain.
//! - [`golden`]: stellar-core's golden tree (fetch from git at a tag, the bulk hash index, test
//!   name resolution, frame extraction) and the AG-1 and AG-3 checks that `verify` calls.
//! - [`ledger`]: the facts read from one `LedgerCloseMeta` blob, with the transaction-hash check.
//! - [`manifest`]: writing blobs and adding or updating one variant of a manifest entry.
//! - [`pins`]: the few `pins.toml` values intake needs.
//! - [`util`]: atomic file writes and UTC time stamps.
//!
//! This module only depends on external crates, so the integration tests include it directly.

pub mod golden;
pub mod lake;
pub mod ledger;
pub mod manifest;
pub mod pins;
pub mod util;

/// The XDR definitions every variant written here refers to (`pins.toml` `[stellar_xdr_definitions]`,
/// the definitions compiled into the pinned `stellar-xdr` 30.0.0).
pub const XDR_DEFINITIONS: &str = "stellar-xdr v30.0 (4f524bbac80c781c06e4fb5fc93a2d0d331d6705)";
