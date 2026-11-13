//! XDRCheck judge: indexer-neutral ground truth from a ledger's own entry changes, and verdicts
//! on an indexer's exported rows. See README.md for the fact and row schemas.

pub mod conserve;
pub mod facts;
pub mod lake;
pub mod read;
pub mod scope;
pub mod verdict;

pub use facts::{judge_ledger, Fact, Options};
