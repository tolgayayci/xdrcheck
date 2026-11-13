//! Generator core: run the pinned stellar-core as a standalone, manually closed node and read
//! back every ledger it closes.
//!
//! - [`binary`]: find the pinned binary (`scripts/fetch.d/stellar-core.sh` or `XDRCHECK_STELLAR_CORE`) and check
//!   its sha256 against `pins.toml`.
//! - [`config`]: the standalone configuration and the meta flag profiles (`lake`, `golden-test`, `custom`).
//! - [`node`]: start, submit (`tx?blob=`), arm upgrades, close at scheduled close times, query ledger
//!   entries, stop. A node never outlives its [`Node`] value.
//! - [`meta`]: the incremental meta stream reader (each record goes through the oracle gate).
//! - [`keys`]: root and label-derived keys, transaction hashing and signing.
//! - [`http`]: the plain HTTP client core's servers need.
//!
//! Typical use (the scenario side builds the envelopes):
//!
//! ```no_run
//! # fn main() -> anyhow::Result<()> {
//! use xdrcheck_gen::core::{CoreBinary, Node, NodeOptions, TESTNET_PASSPHRASE};
//! let bin = CoreBinary::locate()?.expect("run scripts/fetch.d/stellar-core.sh");
//! let mut node = Node::start(&bin, "target/runs/example".as_ref(), NodeOptions::new(TESTNET_PASSPHRASE))?;
//! let ledger = node.close()?; // ledger 2, closed at 1700000000
//! assert_eq!(ledger.sequence, 2);
//! node.stop()?;
//! # Ok(()) }
//! ```

pub mod binary;
pub mod config;
pub mod http;
pub mod keys;
pub mod meta;
pub mod node;

pub use binary::{cache_dir, core_pins, CoreBinary, CorePins};
pub use config::{MetaProfile, NodeConfig, META_FLAGS, NODE_SEED_LABEL};
pub use keys::{
    network_id, sign_transaction, tx_hash, Keypair, KEY_NAMESPACE, PUBNET_PASSPHRASE,
    TESTNET_PASSPHRASE,
};
pub use meta::{MetaReader, MetaRecord};
pub use node::{
    ClosePolicy, ClosedLedger, Node, NodeOptions, SubmitReply, SubmitStatus, MAX_CLOSE_TIME,
};
