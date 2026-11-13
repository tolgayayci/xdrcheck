//! The `orphans` check: every file under `blobs/` and `decoded/` and every chain index under
//! `chains/` must be reached from a manifest entry. A blob is reached when a variant names it, a
//! sidecar when a variant's blob is its blob (blobs are `.xdr`, or `.wasm` for contract code), a chain index when a variant's blob is one of its
//! ledgers or an entry's `replay.chain` names it, and a chain's vendored meta stream when its index
//! names it (`stream.path`). Anything else is left over from an edit or a
//! regeneration and fails, so the corpus holds no bytes nobody reviews. Runs on whole-corpus runs
//! only. With an overlay corpus, its `blobs/` and `decoded/` are checked against the merged
//! entries too (overlay files are shown under `overlay:`); chains are public only.

use std::collections::HashSet;
use std::path::Path;

use serde_json::Value;

use super::load::Entry;
use super::model::{Check, Row};

/// One row per area (`blobs`, `decoded`, `chains`), listing what no entry reaches.
pub fn rows(roots: &[&Path], entries: &[Entry], chains: &[(String, Value)]) -> Vec<Row> {
    let corpus = roots[0];
    let mut blobs = HashSet::new();
    let mut chain_ids = HashSet::new();
    for e in entries {
        for v in e.variants() {
            if let Some(s) = v["blob"]["sha256"].as_str() {
                blobs.insert(s.to_string());
            }
        }
        if let Ok(j) = &e.json {
            if let Some(c) = j["replay"]["chain"].as_str() {
                chain_ids.insert(c.to_string());
            }
        }
    }
    let files = |dir: &str, suffixes: &[&str]| -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (i, root) in roots.iter().enumerate() {
            let prefix = if i == 0 { "" } else { "overlay:" };
            for sub in std::fs::read_dir(root.join(dir))
                .into_iter()
                .flatten()
                .flatten()
            {
                for f in std::fs::read_dir(sub.path())
                    .into_iter()
                    .flatten()
                    .flatten()
                {
                    let name = f.file_name().to_string_lossy().into_owned();
                    let rel = format!("{prefix}{dir}/{}/{name}", sub.file_name().to_string_lossy());
                    match suffixes.iter().find_map(|s| name.strip_suffix(s)) {
                        Some(stem) => out.push((rel, stem.to_string())),
                        None => out.push((rel, String::new())),
                    }
                }
            }
        }
        out.sort();
        out
    };
    let unreached = |list: Vec<(String, String)>| -> Vec<String> {
        list.into_iter()
            .filter(|(_, stem)| !blobs.contains(stem))
            .map(|(rel, _)| format!("{rel} is referenced by no manifest entry"))
            .collect()
    };
    let mut out = vec![
        Row::new(
            Check::Orphans,
            "blobs",
            None,
            unreached(files("blobs", &[".xdr", ".wasm"])),
        ),
        Row::new(
            Check::Orphans,
            "decoded",
            None,
            unreached(files("decoded", &[".json.zst"])),
        ),
    ];
    let mut p = Vec::new();
    for (rel, c) in chains {
        let reached = c["id"].as_str().is_some_and(|id| chain_ids.contains(id))
            || c["ledgers"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|r| r["blob_sha256"].as_str().is_some_and(|s| blobs.contains(s)));
        if !reached {
            p.push(format!(
                "{rel}: no manifest entry has a ledger of this chain or names it"
            ));
        }
    }
    let indexed: HashSet<&str> = chains.iter().map(|(rel, _)| rel.as_str()).collect();
    // A chain index may vendor its run's meta stream next to it (`stream.path`).
    let streams: HashSet<&str> = chains
        .iter()
        .filter_map(|(_, c)| c["stream"]["path"].as_str())
        .collect();
    for (rel, _) in files("chains", &[".json"]) {
        if !indexed.contains(rel.as_str()) && !streams.contains(rel.as_str()) {
            p.push(format!(
                "{rel} is neither a chain index nor a stream a chain index names"
            ));
        }
    }
    for d in std::fs::read_dir(corpus.join("chains"))
        .into_iter()
        .flatten()
        .flatten()
    {
        let rel = format!("chains/{}", d.file_name().to_string_lossy());
        if d.path().is_dir() && !indexed.iter().any(|i| i.starts_with(&format!("{rel}/"))) {
            p.push(format!("{rel}/ holds no chain index"));
        }
    }
    out.push(Row::new(Check::Orphans, "chains", None, p));
    out
}
