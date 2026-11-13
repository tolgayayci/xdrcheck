//! `xdrcheck-corpus fetch-goldens <tag>` (network step unless a local clone is named): fetch
//! stellar-core's golden tree at `tag` into `<cache>/goldens/<tag>/` and verify every tier that has
//! a bulk index (`corpus/bulk/core-<tag>-<tier>.sha256`) against it.
//!
//! The bytes come from `XDRCHECK_STELLAR_CORE_REPO` (a local clone holding the tag) when set, otherwise
//! from a shallow fetch of the tag from GitHub into the cache. At the tag pinned in `pins.toml` the
//! tag must resolve to the pinned commit. A tree already cached for the same commit is not fetched
//! again, so a second run is offline. Any integrity problem (wrong commit, a missing, changed or
//! unlisted file) exits 2. See [`intake::golden`](super::intake::golden).
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{bail, Result};

use super::intake::golden::{self, Origin};
use super::intake::pins::Pins;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// stellar-core tag, e.g. v30.0.0
    pub tag: String,
}

pub fn run(corpus: &Path, args: Args) -> Result<ExitCode> {
    let start = Instant::now();
    let pins = Pins::load(corpus)?;
    let dest = golden::tree_dir(&args.tag)?;
    let origin = Origin::from_env()?;
    let fetched = golden::fetch_tree(&args.tag, &dest, &origin, &pins)?;
    let tree = &fetched.tree;
    if fetched.written.is_empty() {
        println!(
            "{} at {}: cached tree at {}",
            tree.tag,
            tree.commit,
            tree.root.display()
        );
    }
    for (tier, files, bytes) in &fetched.written {
        println!(
            "{} at {}: wrote {}: {files} .xdr files, {bytes} bytes",
            tree.tag,
            tree.commit,
            golden::tier_dir(tier)
        );
    }
    let mut checked = 0;
    let mut problems = Vec::new();
    for tier in golden::TIERS {
        let index = golden::index_path(corpus, &args.tag, tier);
        if !index.is_file() {
            continue;
        }
        let c = golden::verify_tree(&tree.root, tier, &golden::read_index(&index)?)?;
        checked += 1;
        println!(
            "{}: {} listed in {}, {} verified, {} missing, {} mismatched, {} unlisted",
            golden::tier_dir(tier),
            c.listed,
            index.file_name().unwrap_or_default().to_string_lossy(),
            c.verified,
            c.missing.len(),
            c.mismatched.len(),
            c.unlisted.len()
        );
        if c.ok() {
            continue;
        }
        for (what, files) in [
            ("missing", &c.missing),
            ("mismatched", &c.mismatched),
            ("unlisted", &c.unlisted),
        ] {
            problems.extend(files.iter().map(|f| format!("{what}: {f}")));
        }
    }
    if checked == 0 {
        bail!(
            "no bulk index for {} under {}; create one with `sha256sum` over the tree's .xdr files (corpus/bulk/README.md)",
            args.tag,
            corpus.join("bulk").display()
        );
    }
    if !problems.is_empty() {
        for p in &problems {
            eprintln!("{p}");
        }
        bail!(
            "the golden tree does not match the bulk index ({} problems); remove {} to fetch it again",
            problems.len(),
            tree.root.display()
        );
    }
    println!(
        "fetch-goldens: {} verified in {:.1} s",
        tree.root.display(),
        start.elapsed().as_secs_f64()
    );
    Ok(ExitCode::SUCCESS)
}
