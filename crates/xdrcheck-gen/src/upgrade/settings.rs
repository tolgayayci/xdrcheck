//! The vendored Soroban settings upgrade sets (`corpus/settings/`), embedded at build time.
//!
//! `corpus/settings/settings.json` lists, per target protocol, the sets applied after the protocol upgrade
//! (always `enable` first, then that protocol's network set), each with its upstream source and sha256.
//! Every embedded file is checked against the index before use, so a changed file cannot slip in under an
//! old hash. Protocol 28 has no upstream set; the index maps it to the Protocol 27 set and says so.
//! Protocols below 20 have no Soroban and need no set ([`ProtocolSettings::for_protocol`] returns
//! none); Protocol 20 has no upstream set and is not supported.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use stellar_xdr::{ConfigUpgradeSet, ReadXdr, WriteXdr};

use crate::core::keys::{sha256, KEY_NAMESPACE};

/// The first protocol with Soroban and its settings.
pub const FIRST_SOROBAN_PROTOCOL: u32 = 20;

const INDEX: &str = include_str!("../../../../corpus/settings/settings.json");

/// The embedded files, by name.
fn file(name: &str) -> Option<&'static [u8]> {
    Some(match name {
        "enable.xdr" => include_bytes!("../../../../corpus/settings/enable.xdr"),
        "p21-testnet.xdr" => include_bytes!("../../../../corpus/settings/p21-testnet.xdr"),
        "p22-testnet.xdr" => include_bytes!("../../../../corpus/settings/p22-testnet.xdr"),
        "p23-testnet.xdr" => include_bytes!("../../../../corpus/settings/p23-testnet.xdr"),
        "p24-testnet.xdr" => include_bytes!("../../../../corpus/settings/p24-testnet.xdr"),
        "p25-testnet.xdr" => include_bytes!("../../../../corpus/settings/p25-testnet.xdr"),
        "p26-testnet.xdr" => include_bytes!("../../../../corpus/settings/p26-testnet.xdr"),
        "p27-testnet.xdr" => include_bytes!("../../../../corpus/settings/p27-testnet.xdr"),
        "p29-testnet.xdr" => include_bytes!("../../../../corpus/settings/p29-testnet.xdr"),
        "p30-testnet.xdr" => include_bytes!("../../../../corpus/settings/p30-testnet.xdr"),
        "write-upgrade-bytes.wasm" => {
            include_bytes!("../../../../corpus/settings/write-upgrade-bytes.wasm")
        }
        _ => return None,
    })
}

#[derive(Debug, Deserialize)]
struct Index {
    salt_rule: String,
    upgrade_contract: FileRef,
    sets: BTreeMap<String, SetEntry>,
    protocols: BTreeMap<String, ProtocolEntry>,
}

#[derive(Debug, Deserialize)]
struct FileRef {
    file: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct SetEntry {
    file: String,
    sha256: String,
    upgrade_set_sha256: String,
    source: String,
}

#[derive(Debug, Deserialize)]
struct ProtocolEntry {
    sets: Vec<String>,
    source_protocol: Option<u32>,
    note: Option<String>,
}

fn index() -> Index {
    serde_json::from_str(INDEX).expect("corpus/settings/settings.json parses")
}

fn checked_file(name: &str, sha: &str) -> Result<&'static [u8]> {
    let bytes = file(name).ok_or_else(|| anyhow!("settings file {name} is not embedded"))?;
    let have = xdrcheck_xdr::sha256_hex(bytes);
    if have != sha {
        bail!("embedded {name} has sha256 {have}, settings.json says {sha}");
    }
    Ok(bytes)
}

/// One settings upgrade set.
#[derive(Debug, Clone)]
pub struct SettingsSet {
    /// File name under `corpus/settings/`, for example `p27-testnet.xdr`; also the salt label.
    pub file: String,
    /// sha256 of the file (base64 text, as vendored).
    pub sha256: String,
    /// Where the values come from.
    pub source: String,
    /// The XDR `ConfigUpgradeSet` bytes.
    pub upgrade_set: Vec<u8>,
}

impl SettingsSet {
    /// The decoded upgrade set.
    pub fn decode(&self) -> Result<ConfigUpgradeSet> {
        Ok(ConfigUpgradeSet::from_xdr(
            &self.upgrade_set,
            stellar_xdr::Limits {
                depth: 100,
                len: self.upgrade_set.len(),
            },
        )?)
    }

    /// The fixed salt of this set's upgrade contract: `sha256("xcc/settings-upgrade-salt/<file>")`.
    pub fn salt(&self) -> [u8; 32] {
        upgrade_salt(&self.file)
    }
}

/// `sha256("xcc/settings-upgrade-salt/<file>")`.
pub fn upgrade_salt(file: &str) -> [u8; 32] {
    sha256(format!("{KEY_NAMESPACE}/settings-upgrade-salt/{file}").as_bytes())
}

/// The settings applied for one target protocol.
#[derive(Debug, Clone)]
pub struct ProtocolSettings {
    /// The target protocol.
    pub protocol: u32,
    /// Sets in the order they are applied.
    pub sets: Vec<SettingsSet>,
    /// The protocol the network set was written for, when it is not `protocol`.
    pub source_protocol: Option<u32>,
    /// Why, when `source_protocol` is set.
    pub note: Option<String>,
    /// The salt rule, as recorded in chain indexes.
    pub salt_rule: String,
}

/// The `settings` object of a chain index (`chain-index.schema.json`).
#[derive(Debug, Clone, Serialize)]
pub struct ChainIndexSettings {
    /// Where the values came from.
    pub source: String,
    /// The protocol the set was written for, when different from the chain's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_protocol: Option<u32>,
    /// The files applied, with their sha256.
    pub files: Vec<ChainIndexFile>,
    /// How the salt is derived.
    pub salt_rule: String,
    /// Why `source_protocol` differs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// One file of [`ChainIndexSettings`].
#[derive(Debug, Clone, Serialize)]
pub struct ChainIndexFile {
    /// File name.
    pub name: String,
    /// sha256 of the file.
    pub sha256: String,
}

impl ProtocolSettings {
    /// The settings for `protocol`: none below [`FIRST_SOROBAN_PROTOCOL`], then the vendored sets
    /// (21 to 30).
    pub fn for_protocol(protocol: u32) -> Result<ProtocolSettings> {
        let idx = index();
        if protocol < FIRST_SOROBAN_PROTOCOL {
            return Ok(ProtocolSettings {
                protocol,
                sets: Vec::new(),
                source_protocol: None,
                note: Some(format!(
                    "Protocol {protocol} predates Soroban: no settings are applied."
                )),
                salt_rule: idx.salt_rule,
            });
        }
        let p = idx.protocols.get(&protocol.to_string()).ok_or_else(|| {
            anyhow!(
                "no Soroban settings are vendored for protocol {protocol} (have {:?})",
                idx.protocols.keys().collect::<Vec<_>>()
            )
        })?;
        let mut sets = Vec::new();
        for name in &p.sets {
            let e = idx
                .sets
                .get(name)
                .ok_or_else(|| anyhow!("settings.json names unknown set {name}"))?;
            let text = checked_file(&e.file, &e.sha256)?;
            let text =
                std::str::from_utf8(text).with_context(|| format!("{} is not text", e.file))?;
            let upgrade_set = ConfigUpgradeSet::from_xdr_base64(
                text,
                stellar_xdr::Limits {
                    depth: 100,
                    len: text.len(),
                },
            )
            .with_context(|| format!("{} is not a base64 ConfigUpgradeSet", e.file))?
            .to_xdr(stellar_xdr::Limits::none())?;
            if xdrcheck_xdr::sha256_hex(&upgrade_set) != e.upgrade_set_sha256 {
                bail!(
                    "{} decodes to bytes whose sha256 is not upgrade_set_sha256",
                    e.file
                );
            }
            sets.push(SettingsSet {
                file: e.file.clone(),
                sha256: e.sha256.clone(),
                source: e.source.clone(),
                upgrade_set,
            });
        }
        Ok(ProtocolSettings {
            protocol,
            sets,
            source_protocol: p.source_protocol,
            note: p.note.clone(),
            salt_rule: idx.salt_rule,
        })
    }

    /// The chain index `settings` object for a chain at this protocol.
    pub fn chain_index(&self) -> ChainIndexSettings {
        ChainIndexSettings {
            source: if self.sets.is_empty() {
                "none: no Soroban settings before Protocol 20".into()
            } else {
                self.sets
                    .iter()
                    .map(|s| s.source.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            },
            source_protocol: self.source_protocol,
            files: self
                .sets
                .iter()
                .map(|s| ChainIndexFile {
                    name: s.file.clone(),
                    sha256: s.sha256.clone(),
                })
                .collect(),
            salt_rule: self.salt_rule.clone(),
            note: self.note.clone(),
        }
    }
}

/// The settings-upgrade contract (`write(bytes) -> hash`), checked against the index.
pub fn upgrade_contract_wasm() -> Result<&'static [u8]> {
    let idx = index();
    checked_file(&idx.upgrade_contract.file, &idx.upgrade_contract.sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_protocol_21_to_30_has_settings() {
        for p in 21..=30 {
            let s = ProtocolSettings::for_protocol(p).unwrap();
            assert_eq!(s.sets.len(), 2);
            assert_eq!(s.sets[0].file, "enable.xdr");
            for set in &s.sets {
                // Canonical XDR: decoding and re-encoding gives the vendored bytes.
                let v = set.decode().unwrap();
                assert_eq!(
                    v.to_xdr(stellar_xdr::Limits::none()).unwrap(),
                    set.upgrade_set
                );
            }
        }
        let p28 = ProtocolSettings::for_protocol(28).unwrap();
        assert_eq!(p28.sets[1].file, "p27-testnet.xdr");
        assert_eq!(p28.source_protocol, Some(27));
        assert!(p28.note.is_some());
        assert!(ProtocolSettings::for_protocol(20).is_err());
        assert!(ProtocolSettings::for_protocol(19).unwrap().sets.is_empty());
        assert_eq!(upgrade_contract_wasm().unwrap().len(), 460);
    }

    #[test]
    fn vendored_xdr_is_the_vendored_json_encoded() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/settings");
        for (name, e) in index().sets {
            let json = std::fs::read_to_string(dir.join(format!("{name}.json"))).unwrap();
            let v: ConfigUpgradeSet = serde_json::from_str(&json).unwrap();
            let b64 = v.to_xdr_base64(stellar_xdr::Limits::none()).unwrap();
            let vendored = std::str::from_utf8(file(&e.file).unwrap()).unwrap();
            assert_eq!(b64, vendored.trim_end(), "{name}");
        }
    }
}
