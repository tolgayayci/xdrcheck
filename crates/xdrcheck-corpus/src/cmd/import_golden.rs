//! `xdrcheck-corpus import-golden <tag> <test name> [--frame N] [--entry ID]`: import one
//! ledger of a stellar-core golden test from the fetched tree (`fetch-goldens <tag>` first) as a
//! `core-golden` variant.
//!
//! The human test name is resolved through the tree's `index.json` files (exact name, or the name
//! without its `protocol version N` section when that is unique); the file is checked against the
//! bulk index; `--frame` picks the ledger (0-based, required when the test closed more than one).
//! The frame must pass the gate, round-trip byte-exactly and have its transaction hashes
//! recomputed under the core test passphrase. The blob is written to `corpus/blobs/`, the variant
//! is checked with AG-1, and then added to or updated in `--entry`, or printed without it.
//!
//! The variant carries `meta.ledger_close_meta_version` and `meta.transaction_meta_version`; the
//! author adds `meta.profile: golden-test` with the test's `flags_source`, read from its code.
use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{bail, Result};

use super::intake::golden::{self, GoldenSource, Tree};
use super::intake::manifest::{upsert_variant, write_blob};

#[derive(clap::Args, Debug)]
pub struct Args {
    /// stellar-core tag of the fetched tree, e.g. v30.0.0
    pub tag: String,
    /// Human test name from index.json, e.g. "Trustline stellar asset contract|protocol version 30"
    pub test_name: String,
    /// Ledger of the test to import (0-based record index in the golden file)
    #[arg(long)]
    pub frame: Option<usize>,
    /// Manifest entry ID whose core-golden variant to add or update
    #[arg(long)]
    pub entry: Option<String>,
}

pub fn run(corpus: &Path, args: Args) -> Result<ExitCode> {
    let tree = Tree::open_tag(&args.tag)?;
    let gate = xdrcheck_xdr::Gate::from_corpus_json(&corpus.join("corpus.json"))?.unwrap_or_default();
    let mut index = BTreeMap::new();
    for tier in golden::TIERS {
        let p = golden::index_path(corpus, &args.tag, tier);
        if p.is_file() {
            index.extend(golden::read_index(&p)?);
        }
    }
    if index.is_empty() {
        eprintln!(
            "warning: no bulk index for {}; the golden file is not checked against one",
            args.tag
        );
    }
    let imported = golden::import(
        &tree,
        &args.test_name,
        args.frame,
        (!index.is_empty()).then_some(&index),
        &gate,
    )?;
    let blob_path = write_blob(corpus, &imported.blob)?;
    let variant = imported.variant(&tree);
    if let Err(f) = golden::ag1(
        &tree,
        &GoldenSource::from_json(&variant["source"])?,
        &imported.blob,
    )? {
        bail!("AG-1 fails on the imported variant: {f}");
    }
    let l = &imported.ledger;
    println!(
        "{:?} -> {} frame {} of {} (ledger {}, protocol {}, {} transactions); blob {} ({} bytes); AG-1 ok",
        imported.resolved.test_name,
        imported.resolved.file,
        imported.frame_index,
        imported.frames,
        l.ledger_seq,
        l.protocol,
        l.tx_hashes.len(),
        blob_path,
        imported.blob.len()
    );
    match &args.entry {
        Some(id) => {
            let u = upsert_variant(corpus, id, variant)?;
            println!("entry {id}: core-golden variant {u:?}");
        }
        None => println!("{}", serde_json::to_string_pretty(&variant)?),
    }
    Ok(ExitCode::SUCCESS)
}
