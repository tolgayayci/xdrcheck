//! Corpus data read by `coverage`, `guide-table` and `guide-claims`: manifest entries (only the
//! fields these reports need), the entry plan and its canonical IDs.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// What the reports need from one manifest entry.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Entry ID (from the file path, `manifest/<id>.json`).
    pub id: String,
    /// `kind`.
    pub kind: String,
    /// `caps`.
    pub caps: Vec<u32>,
    /// `(source.kind, network)` of each variant.
    pub variants: Vec<(String, String)>,
    /// Every variant's blob exists under the corpus root with its recorded length.
    pub bytes_exist: bool,
    /// Listed as mapped in `corpus/mirrors.json`: a local-core entry with a golden counterpart,
    /// compared by AG-4 (`xdrcheck-corpus verify --checks ag4`).
    pub golden_mirror: bool,
    /// Listed under `operations` in `corpus/mirrors.json`: a local-core entry without a golden
    /// transaction of its shape, every operation of which has a golden operation of the same reduced
    /// shape (AG-4's operation tier).
    pub golden_operations: bool,
    /// `fields`: status list name → cited row or part IDs.
    pub fields: Vec<(String, Vec<String>)>,
}

impl Entry {
    /// The group part of the ID.
    pub fn group(&self) -> &str {
        self.id.split('/').next().unwrap_or("")
    }

    /// Has a testnet-passphrase and a pubnet-passphrase variant.
    pub fn twin(&self) -> bool {
        let has = |n: &str| self.variants.iter().any(|(_, net)| net == n);
        has("testnet") && has("pubnet")
    }

    /// Bytes a reader can be given: every `ledger` or `xdr` variant's blob exists; `api` and
    /// `strkey` entries carry their vectors in the manifest itself.
    pub fn has_bytes(&self) -> bool {
        match self.kind.as_str() {
            "ledger" | "xdr" => !self.variants.is_empty() && self.bytes_exist,
            _ => true,
        }
    }
}

/// Every manifest entry under `corpus/manifest/`, sorted by ID.
pub fn entries(corpus: &Path) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    walk(corpus, &corpus.join("manifest"), &mut out)?;
    out.sort_by(|a, b| a.id.cmp(&b.id));
    let mapped = golden_mirrors(corpus, "mapped")?;
    let operations = golden_mirrors(corpus, "operations")?;
    for e in &mut out {
        e.golden_mirror = mapped.contains(&e.id);
        e.golden_operations = operations.contains(&e.id);
    }
    Ok(out)
}

/// `corpus/mirrors.json` (`Value::Null` when the file is absent).
pub fn mirrors(corpus: &Path) -> Result<Value> {
    let p = corpus.join("mirrors.json");
    if !p.is_file() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&std::fs::read(&p)?).with_context(|| format!("{} is not JSON", p.display()))
}

/// The entries of one list of `corpus/mirrors.json` (`mapped`: a golden counterpart transaction;
/// `operations`: a golden counterpart for every operation; `unmapped`); empty when the file is
/// absent.
pub fn golden_mirrors(corpus: &Path, list: &str) -> Result<BTreeSet<String>> {
    Ok(mirrors(corpus)?[list]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m["entry"].as_str().map(str::to_string))
        .collect())
}

fn walk(corpus: &Path, dir: &Path, out: &mut Vec<Entry>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for e in std::fs::read_dir(dir).with_context(|| format!("list {}", dir.display()))? {
        let p = e?.path();
        if p.is_dir() {
            walk(corpus, &p, out)?;
            continue;
        }
        if p.extension().is_none_or(|x| x != "json") {
            continue;
        }
        let rel = p
            .strip_prefix(corpus.join("manifest"))
            .expect("under manifest")
            .with_extension("");
        let id = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        let v: Value = serde_json::from_slice(&std::fs::read(&p)?)
            .with_context(|| format!("{} is not JSON", p.display()))?;
        out.push(entry(corpus, id, &v));
    }
    Ok(())
}

fn entry(corpus: &Path, id: String, v: &Value) -> Entry {
    let variants = v["variants"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let bytes_exist = variants.iter().all(|x| {
        let b = &x["blob"];
        let path = b["path"].as_str().map(str::to_string).or_else(|| {
            b["sha256"]
                .as_str()
                .filter(|s| s.len() > 2)
                .map(|s| format!("blobs/{}/{s}.xdr", &s[..2]))
        });
        path.and_then(|p| std::fs::metadata(corpus.join(p)).ok())
            .is_some_and(|m| Some(m.len()) == b["bytes"].as_u64())
    });
    Entry {
        kind: v["kind"].as_str().unwrap_or("").to_string(),
        caps: v["caps"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| c.as_u64().map(|c| c as u32))
            .collect(),
        variants: variants
            .iter()
            .map(|x| {
                (
                    x["source"]["kind"].as_str().unwrap_or("").to_string(),
                    x["network"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect(),
        bytes_exist,
        golden_mirror: false,
        golden_operations: false,
        fields: v["fields"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(k, ids)| {
                let ids = ids
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect();
                (k.clone(), ids)
            })
            .collect(),
        id,
    }
}

/// One planned item of `corpus/plan.json`: a row, or one member of a family row.
#[derive(Debug, Clone)]
pub struct Planned {
    /// Canonical ID (`<row>` or `<row>.<member>`).
    pub id: String,
    /// `caps` of the row.
    pub caps: Vec<u32>,
    /// `priority` of the row (`M1-must`, `should`, `extra`).
    pub priority: String,
    /// The row plans variants on both testnet and pubnet.
    pub twin: bool,
}

impl Planned {
    /// The group part of the ID.
    pub fn group(&self) -> &str {
        self.id.split('/').next().unwrap_or("")
    }
}

/// Every planned item, in plan order.
pub fn plan(corpus: &Path) -> Result<Vec<Planned>> {
    let path = corpus.join("plan.json");
    let v: Value = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .with_context(|| format!("{} is not JSON", path.display()))?;
    let Some(rows) = v.as_array() else {
        bail!("{}: not an array of rows", path.display());
    };
    let mut out = Vec::new();
    for r in rows {
        let id = r["id"].as_str().context("a plan row has no id")?;
        let nets: Vec<&str> = r["networks"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let base = Planned {
            id: id.to_string(),
            caps: r["caps"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|c| c.as_u64().map(|c| c as u32))
                .collect(),
            priority: r["priority"].as_str().unwrap_or("").to_string(),
            twin: nets.contains(&"testnet") && nets.contains(&"pubnet"),
        };
        let members: Vec<&str> = r["members"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if members.is_empty() {
            out.push(base);
        } else {
            for m in members {
                out.push(Planned {
                    id: format!("{id}.{m}"),
                    ..base.clone()
                });
            }
        }
    }
    Ok(out)
}

/// Canonical entry IDs: every plan row ID and `<row>.<member>` (`docs/entry-ids.md`).
pub fn canonical_ids(corpus: &Path) -> Result<BTreeSet<String>> {
    let path = corpus.join("plan.json");
    let v: Value = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("read {}", path.display()))?,
    )?;
    let mut out = BTreeSet::new();
    for r in v.as_array().into_iter().flatten() {
        let Some(id) = r["id"].as_str() else { continue };
        out.insert(id.to_string());
        for m in r["members"].as_array().into_iter().flatten() {
            if let Some(m) = m.as_str() {
                out.insert(format!("{id}.{m}"));
            }
        }
    }
    Ok(out)
}
