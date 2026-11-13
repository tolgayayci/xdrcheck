//! Running the extractor on a manifest entry's variants: locate the blob, decode it, extract under
//! the variant's passphrase and compare with the entry's `expect` (resolved per variant).

use std::path::Path;

use anyhow::{bail, Context};
use serde_json::{json, Value};
use xdrcheck_xdr::{Gate, Limits};

use super::{agree, extract, network_id, Extraction};

/// One variant of an entry, as the extractor needs it.
#[derive(Debug, Clone)]
pub struct Variant {
    /// `network` or `network.pNN` (the sidecar naming: the suffix marks a variant that is not the
    /// highest protocol on its network).
    pub label: String,
    /// `network` field.
    pub network: String,
    /// `protocol` field.
    pub protocol: u64,
    /// The network passphrase.
    pub passphrase: String,
    /// Blob path relative to the corpus root.
    pub blob: String,
    /// The variant's `derived` block.
    pub derived: Value,
    /// Focus transaction (apply order); 0 when the variant has no focus.
    pub focus_tx: usize,
}

/// A manifest entry with its variants.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Entry ID.
    pub id: String,
    /// The parsed manifest JSON.
    pub json: Value,
    /// Variants in manifest order.
    pub variants: Vec<Variant>,
}

/// Read `<corpus>/manifest/<id>.json`.
pub fn load_entry(corpus: &Path, id: &str) -> anyhow::Result<Entry> {
    let path = corpus.join("manifest").join(format!("{id}.json"));
    let text = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let json: Value =
        serde_json::from_slice(&text).with_context(|| format!("parsing {}", path.display()))?;
    let raw = json["variants"].as_array().cloned().unwrap_or_default();
    let mut variants = Vec::new();
    for v in &raw {
        let network = v["network"].as_str().unwrap_or("none").to_string();
        let protocol = v["protocol"].as_u64().unwrap_or(0);
        let top = raw
            .iter()
            .filter(|w| w["network"] == v["network"])
            .filter_map(|w| w["protocol"].as_u64())
            .max()
            .unwrap_or(protocol);
        let label = if protocol == top {
            network.clone()
        } else {
            format!("{network}.p{protocol}")
        };
        if v["xdr_type"] != "LedgerCloseMeta" {
            continue;
        }
        variants.push(Variant {
            label,
            network,
            protocol,
            passphrase: v["passphrase"].as_str().unwrap_or("").to_string(),
            blob: v["blob"]["path"].as_str().unwrap_or("").to_string(),
            derived: v.get("derived").cloned().unwrap_or(Value::Null),
            focus_tx: v["focus"]["tx_index"].as_u64().unwrap_or(0) as usize,
        });
    }
    Ok(Entry {
        id: id.to_string(),
        json,
        variants,
    })
}

impl Entry {
    /// Select variants by `network` or `network.pNN`; `None` selects all.
    pub fn select(&self, which: Option<&str>) -> anyhow::Result<Vec<&Variant>> {
        let Some(w) = which else {
            return Ok(self.variants.iter().collect());
        };
        let chosen: Vec<&Variant> = self
            .variants
            .iter()
            .filter(|v| v.label == w || format!("{}.p{}", v.network, v.protocol) == w)
            .collect();
        if chosen.is_empty() {
            let labels: Vec<_> = self.variants.iter().map(|v| v.label.as_str()).collect();
            bail!("{}: no variant {w:?} (have {})", self.id, labels.join(", "));
        }
        Ok(chosen)
    }
}

/// The result of one variant.
#[derive(Debug, Clone)]
pub struct Run {
    /// The extraction.
    pub extraction: Extraction,
    /// Disagreements with the entry's `expect`; empty when they agree.
    pub disagreements: Vec<String>,
    /// JSON for printing: entry, variant, the focus transaction in `expect` vocabulary, notes.
    pub output: Value,
}

/// Decode the variant's blob, extract and compare with the entry's `expect`.
pub fn run_variant(corpus: &Path, entry: &Entry, v: &Variant, gate: &Gate) -> anyhow::Result<Run> {
    let path = corpus.join(&v.blob);
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let limits = Limits::default();
    let extraction =
        xdrcheck_xdr::with_stack(limits.stack_size, || -> anyhow::Result<Extraction> {
            let lcm = xdrcheck_xdr::decode_ledger(&bytes, &limits, gate)?;
            Ok(extract(&lcm, &v.passphrase)?)
        })?;
    let expect = agree::resolve_derived(&entry.json["expect"], &v.derived)
        .map_err(|e| anyhow::anyhow!("{}: {}: {e}", entry.id, v.label))?;
    let disagreements = agree::check(&expect, &extraction, v.focus_tx, network_id(&v.passphrase));
    let mut output = extraction.expect_json(v.focus_tx);
    let obj = output.as_object_mut().expect("object");
    obj.insert("entry".into(), json!(entry.id));
    obj.insert("variant".into(), json!(v.label));
    obj.insert("disagreements".into(), json!(disagreements));
    Ok(Run {
        extraction,
        disagreements,
        output,
    })
}
