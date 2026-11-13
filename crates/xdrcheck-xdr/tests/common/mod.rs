//! Shared helpers for the integration tests.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The repository root (two levels above this crate).
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every vendored LedgerCloseMeta blob the manifest names, sorted by path (xdr entries hold other types).
pub fn blobs() -> Vec<PathBuf> {
    let corpus = repo().join("corpus");
    let mut out = std::collections::BTreeSet::new();
    let mut stack = vec![corpus.join("manifest")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let m: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
            for v in m["variants"].as_array().into_iter().flatten() {
                if let (Some("LedgerCloseMeta"), Some(rel)) =
                    (v["xdr_type"].as_str(), v["blob"]["path"].as_str())
                {
                    out.insert(corpus.join(rel));
                }
            }
        }
    }
    out.into_iter().collect()
}

/// The bytes of the first vendored blob (by path) of a `v2` ledger (for mutation tests).
pub fn some_ledger() -> Vec<u8> {
    blobs()
        .iter()
        .map(|p| std::fs::read(p).unwrap())
        .find(|b| b.starts_with(&[0, 0, 0, 2]))
        .expect("a vendored v2 LedgerCloseMeta")
}
