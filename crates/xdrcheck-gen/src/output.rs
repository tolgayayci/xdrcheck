//! Generator output: turn a scenario run on a local stellar-core into corpus entries, and check a
//! regeneration against what is committed.
//!
//! One run is one scenario on one passphrase at one target protocol under one meta flag profile.
//!
//! 1. [`run::run`] starts a node, brings it up to the protocol ([`crate::upgrade::bring_up`]), and
//!    walks the scenario with the [`crate::scenario::Interpreter`]: before every ledger it tells the
//!    interpreter the ledger and close time the node will use, after every close it re-reads every
//!    actor's sequence number from the node, so the envelopes always carry real sequence numbers.
//!    Steps that share a ledger (`same_ledger_as`) are submitted together and closed once. Every
//!    transaction's result is checked against the step's `expect_result` / `expect_op_results`, and a
//!    step with `expect_submit_reject` must be refused at submission with that code. The run leaves
//!    `meta.xdr` (the node's record-marked meta stream) and `run.json` ([`RunRecord`]) in its run
//!    directory.
//! 2. [`write::write_run`] writes what the corpus keeps from a run: the blob of every ledger that holds
//!    an entry, its decoded sidecar ([`sidecar::sidecar_bytes`]), and the entry's variant for this
//!    network and protocol (created or replaced; the entry's authored fields are kept).
//!    [`chain::chain_index`] builds the chain index (`chains/<scenario>/p<NN>-<network>.json`) from the
//!    same run directory, which is also what `xdrcheck-corpus chain-index <run dir>` does for a kept run;
//!    the whole meta stream is kept next to it (`…/p<NN>-<network>.meta.xdr.zst`).
//! 3. [`twins::compare_twins`] asserts that a testnet and a public-passphrase run of the same scenario
//!    agree on every passphrase-independent value before anything is written.
//! 4. [`check::check_run`] compares a regeneration with a committed chain: per ledger equal header
//!    hashes, and for every ledger whose blob is in the corpus equal transaction hashes, equal results
//!    and byte-equal ledgers after stellar-core's golden-comparison normalisation.

pub mod chain;
pub mod check;
pub mod results;
pub mod run;
pub mod sidecar;
pub mod twins;
pub mod txset;
pub mod write;

use anyhow::{bail, Result};

pub use chain::{
    chain_id, chain_index, chain_index_path, chain_stream_path, read_run_dir, vendored_stream,
    write_chain_stream,
};
pub use check::{check_run, CheckOutcome};
pub use run::{run, ExpectationFailed, RunRecord, RunRequest, StepRecord};
pub use sidecar::sidecar_bytes;
pub use twins::compare_twins;
pub use write::{write_run, WriteSummary};

/// stellar-core's fixed unit-test passphrase.
pub const CORE_TEST_PASSPHRASE: &str = "(V) (;,,;) (V)";

/// A passphrase family, as manifests and chain indexes name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Network {
    Testnet,
    Pubnet,
    CoreTest,
}

impl Network {
    /// Every network, in the order variants are listed.
    pub const ALL: [Network; 3] = [Network::Testnet, Network::Pubnet, Network::CoreTest];

    pub fn name(self) -> &'static str {
        match self {
            Network::Testnet => "testnet",
            Network::Pubnet => "pubnet",
            Network::CoreTest => "core-test",
        }
    }

    pub fn passphrase(self) -> &'static str {
        match self {
            Network::Testnet => crate::core::TESTNET_PASSPHRASE,
            Network::Pubnet => crate::core::PUBNET_PASSPHRASE,
            Network::CoreTest => CORE_TEST_PASSPHRASE,
        }
    }

    pub fn parse(name: &str) -> Result<Network> {
        match Network::ALL.iter().find(|n| n.name() == name) {
            Some(n) => Ok(*n),
            None => bail!("unknown network {name:?} (testnet, pubnet or core-test)"),
        }
    }
}
