//! The `pins.toml` values intake uses: the stellar-core tag and commit (golden fetch), and the
//! public lake bucket and per-network prefixes (capture).
//!
//! `pins.toml` next to the corpus root is read when it exists; otherwise the copy compiled into the
//! binary is used. Only the few `key = "value"` lines needed are read, so no TOML dependency.

use std::path::Path;

use anyhow::{Context, Result};

const BUILT_IN: &str = include_str!("../../../../../pins.toml");

/// Intake's pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pins {
    /// `[stellar_core] version`, e.g. `30.0.0`; the golden tag is `v<version>`.
    pub core_version: String,
    /// `[stellar_core] commit`.
    pub core_commit: String,
    /// `[public_lake] bucket`, e.g. `s3://aws-public-blockchain/v1.1/stellar/ledgers`.
    pub lake_bucket: String,
    /// `[public_lake] pubnet`, the pubnet prefix under the bucket.
    pub lake_pubnet: String,
    /// `[public_lake] testnet`, the current testnet epoch prefix under the bucket.
    pub lake_testnet: String,
}

impl Pins {
    /// Read `pins.toml` from the parent of the corpus root, or fall back to the built-in copy.
    pub fn load(corpus: &Path) -> Result<Pins> {
        let beside = corpus
            .canonicalize()
            .ok()
            .and_then(|c| c.parent().map(|p| p.join("pins.toml")));
        match beside.filter(|p| p.is_file()) {
            Some(p) => {
                let text =
                    std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
                Pins::parse(&text).with_context(|| format!("in {}", p.display()))
            }
            None => Pins::parse(BUILT_IN).context("in the built-in pins.toml"),
        }
    }

    /// Parse the needed values out of the text of `pins.toml`.
    pub fn parse(text: &str) -> Result<Pins> {
        let get = |section: &str, key: &str| -> Result<String> {
            value(text, section, key).with_context(|| format!("[{section}] {key} not found"))
        };
        Ok(Pins {
            core_version: get("stellar_core", "version")?,
            core_commit: get("stellar_core", "commit")?,
            lake_bucket: get("public_lake", "bucket")?,
            lake_pubnet: get("public_lake", "pubnet")?,
            lake_testnet: get("public_lake", "testnet")?,
        })
    }

    /// The golden tag pinned by `pins.toml`, `v<version>`.
    pub fn core_tag(&self) -> String {
        format!("v{}", self.core_version)
    }
}

/// The string value of `key = "…"` inside `[section]` (comments after the value are ignored).
fn value(text: &str, section: &str, key: &str) -> Option<String> {
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == format!("[{section}]");
            continue;
        }
        if !inside {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k.trim() != key {
            continue;
        }
        let v = v.trim().strip_prefix('"')?;
        return v.split_once('"').map(|(s, _)| s.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_pins_parse() {
        let p = Pins::parse(BUILT_IN).unwrap();
        assert_eq!(p.core_version, "30.0.0");
        assert_eq!(p.core_commit.len(), 40);
        assert!(p.lake_testnet.starts_with("testnet/"));
    }
}
