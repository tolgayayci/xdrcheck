//! Structure-aware mutation of corpus values.
//!
//! The engine decodes a corpus value with a schema-driven reader that keeps every node's byte
//! range ([`tree`]), mutates it at the type level ([`mutate`]: valid-preserving, metamorphic and
//! wire-invalid mutators), checks each mutant against the oracle and the reference extractor
//! ([`oracle`]), and writes the mutants as a corpus of their own ([`engine`]) that the
//! conformance and replay runners read unchanged. `xdrcheck mutate` (the Go command) runs the
//! readers, judges them and triages what disagrees; this crate is its mutation and oracle half,
//! driven through the `xdrcheck-mutate` binary.

pub mod engine;
pub mod mutate;
pub mod oracle;
pub mod promote;
pub mod schema;
pub mod tree;
