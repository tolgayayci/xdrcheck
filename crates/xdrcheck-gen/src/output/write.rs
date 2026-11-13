//! Writing a run into a corpus root: blobs, sidecars, manifest variants and the chain index.
//!
//! - **Blob**: every ledger that holds an entry, at `blobs/<aa>/<sha256>.xdr`.
//! - **Variant**: keyed by (network, protocol). An existing variant with that key is replaced; the
//!   entry's other variants and its authored fields (`title`, `why`, `conformance`, …) are kept.
//!   The step's `expect`, `fields` and `mirrors`, when the scenario gives them, replace the entry's.
//! - **New entry**: when `manifest/<id>.json` does not exist, it is created from the entry's row in
//!   `plan.json` (title from the row's shape, `caps`, `protocol.introduced`), with a note saying the
//!   authored fields still need writing.
//! - **Sidecar**: one per blob, `decoded/<aa>/<blob sha256>.json.zst` (see [`super::sidecar`]).
//! - **Chain**: the index `chains/<id>.json` and the whole meta stream `chains/<id>.meta.xdr.zst`,
//!   so a replay can serve every ledger of the chain from the repository (see [`super::chain`]).
//! - **Variant protocol**: the protocol the ledger's transactions were applied at; on a ledger that
//!   upgrades the protocol the header already shows the new one, recorded as `header_protocol`
//!   ([`applied_protocol`]).
//! - **Derived values**: per variant, the ledger hash, transaction hashes, the focus transaction,
//!   accounts, contracts, the object-layer values `l1`, and the header values `derived.header`
//!   ([`DERIVED_HEADER_FIELDS`]).
//! - **Variant order**: protocol descending, then testnet, pubnet, core-test, none.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};

use super::chain::{
    chain_index, chain_index_path, ledger_facts, regenerate_command, stream_ledgers,
    write_chain_stream,
};
use super::run::{RunRecord, StepRecord};
use super::sidecar::{sidecar_bytes, sidecar_rel, write_sidecar};

/// What [`write_run`] wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteSummary {
    /// Entry IDs that got a variant.
    pub entries: Vec<String>,
    /// Entry IDs created from the plan.
    pub created: Vec<String>,
    /// Blob paths written (relative to the corpus root).
    pub blobs: Vec<String>,
    /// The chain index path.
    pub chain: String,
}

/// Write one run into the corpus at `corpus`.
pub fn write_run(corpus: &Path, rec: &RunRecord, stream: &[u8]) -> Result<WriteSummary> {
    let pins = Pins::read(corpus)?;
    let ledgers = stream_ledgers(stream)?;
    let stream_sha256 = xdrcheck_xdr::sha256_hex(stream);
    let mut summary = WriteSummary::default();
    for (i, (l, lr)) in ledgers.iter().zip(&rec.ledgers).enumerate() {
        if lr.entries.is_empty() {
            continue;
        }
        let previous = i.checked_sub(1).map(|j| ledgers[j].info.protocol);
        let (protocol, header_protocol) = applied_protocol(previous, l.info.protocol);
        let sha = xdrcheck_xdr::sha256_hex(l.bytes);
        let blob_rel = format!("blobs/{}/{sha}.xdr", &sha[..2]);
        write_file(&corpus.join(&blob_rel), l.bytes)?;
        summary.blobs.push(blob_rel.clone());
        let facts = ledger_facts(l.bytes)?;
        let hashes: Vec<String> = facts
            .results
            .iter()
            .map(|r| hex::encode(r.transaction_hash.0))
            .collect();
        let sidecar = sidecar_bytes("LedgerCloseMeta", l.bytes)?;
        write_sidecar(corpus, &sidecar_rel(&sha), &sidecar)?;
        // The XDR features the bytes need (`docs/manifest.md` §4.2); verify recomputes them.
        let limits = xdrcheck_xdr::Limits::default();
        let features = xdrcheck_meta::derive::requires_of_sidecar("LedgerCloseMeta", &sidecar, &limits)
            .map_err(|e| anyhow!("ledger {}: requires: {e}", lr.seq))?;
        for id in &lr.entries {
            let steps: Vec<&StepRecord> = rec
                .steps
                .iter()
                .filter(|s| s.entry.as_deref() == Some(id) && s.ledger == Some(lr.seq))
                .collect();
            let focus_step = steps
                .iter()
                .find(|s| s.tx_hash.is_some() && !s.excluded)
                .copied()
                .or(steps.first().copied())
                .ok_or_else(|| anyhow!("entry {id} in ledger {} has no step", lr.seq))?;
            let mut variant = json!({
                "network": rec.network,
                "passphrase": rec.passphrase,
                "protocol": protocol,
            });
            if let Some(h) = header_protocol {
                variant["header_protocol"] = json!(h);
            }
            let rest = json!({
                "ledger_seq": lr.seq,
                "xdr_type": "LedgerCloseMeta",
                "requires": features,
                "xdr_definitions": pins.xdr_definitions,
                "blob": {"sha256": sha, "bytes": l.bytes.len(), "path": blob_rel},
                "decoded": sidecar_rel(&sha),
                "decoded_sha256": xdrcheck_xdr::sha256_hex(&sidecar),
                "decoded_by": pins.decoded_by,
                "source": source(rec, &steps, focus_step, l.index, &stream_sha256),
            });
            if let (Some(v), Value::Object(rest)) = (variant.as_object_mut(), rest) {
                v.extend(rest);
            }
            let mut derived = Map::new();
            derived.insert("ledger_hash".into(), json!(hex::encode(l.info.header_hash)));
            derived.insert("header".into(), derived_header(&facts.header.header));
            if let Some(h) = focus_step.tx_hash.as_ref().filter(|_| !focus_step.excluded) {
                let i = hashes.iter().position(|x| x == h).ok_or_else(|| {
                    anyhow!(
                        "step {}: transaction {h} is not in ledger {}",
                        focus_step.id,
                        lr.seq
                    )
                })?;
                variant["focus"] = json!({
                    "tx_index": i,
                    "tx_hash": h,
                    "path": format!("/v{}/tx_processing/{i}", l.info.ledger_close_meta_version),
                });
                derived.insert("tx_hash".into(), json!(h));
                if let Some(fc) = &focus_step.fee_charged {
                    derived.insert("fee_charged".into(), json!(fc));
                }
                if let Some(inner) = &focus_step.inner_tx_hash {
                    derived.insert("inner_tx_hash".into(), json!(inner));
                }
            }
            derived.insert("tx_hashes".into(), json!(hashes));
            if !rec.contracts.is_empty() {
                derived.insert("contracts".into(), json!(rec.contracts));
            }
            // Actor label → `G…`, so one `expect` can name an actor as `${derived.accounts.<label>}`
            // across variants from other sources (a core golden's accounts differ).
            if !rec.accounts.is_empty() || rec.root.is_some() {
                let mut accounts = json!(rec.accounts);
                // The root account differs per passphrase; `${acct.root}` in a step's `expect`
                // becomes this reference.
                if let Some(r) = &rec.root {
                    accounts["root"] = json!(r);
                }
                derived.insert("accounts".into(), accounts);
            }
            // The object-layer values the focus implies (`docs/manifest.md` §10.1); verify
            // recomputes them.
            let l1 = xdrcheck_meta::derive::l1(
                "LedgerCloseMeta",
                l.bytes,
                &rec.passphrase,
                &variant["focus"],
                &limits,
                &xdrcheck_xdr::Gate::default(),
            )
            .map_err(|e| anyhow!("{id}: derived.l1: {e}"))?;
            if !l1.is_empty() {
                derived.insert("l1".into(), Value::Object(l1));
            }
            variant["derived"] = Value::Object(derived);
            let mut meta = json!({
                "ledger_close_meta_version": l.info.ledger_close_meta_version,
                "core_meta_flags": rec.core_meta_flags,
                "profile": rec.profile,
            });
            if let Some(v) = facts.transaction_meta_version {
                meta["transaction_meta_version"] = json!(v);
            }
            if let Some(g) = &rec.golden_test {
                meta["golden_test"] = g.clone();
            }
            variant["meta"] = meta;
            let created = upsert(corpus, id, rec, variant, &steps)?;
            if created {
                summary.created.push(id.clone());
            }
            if !summary.entries.contains(id) {
                summary.entries.push(id.clone());
            }
        }
    }
    let chain_rel = chain_index_path(rec);
    let index = chain_index(rec, stream)?;
    write_chain_stream(corpus, rec, stream)?;
    write_json(&corpus.join(&chain_rel), &index)?;
    summary.chain = chain_rel.display().to_string();
    Ok(summary)
}

/// The protocol a ledger's transactions were applied at, and the header's protocol when that is
/// another one (`docs/manifest.md` §4.2, `protocol` and `header_protocol`). Upgrades are applied
/// after the transaction set, so a ledger that upgrades the protocol already shows the new version
/// in its header while everything in it ran under the previous ledger's version — the form the
/// history captures of upgrade ledgers carry. `previous` is the header protocol of the ledger before
/// in the same stream. A run's first ledger (the bring-up's upgrade from the genesis protocol 0) has
/// none and keeps its header's protocol, the one the run targets: no transaction can run at
/// protocol 0, and the run's variants are keyed by that target.
pub fn applied_protocol(previous: Option<u32>, header: u32) -> (u32, Option<u32>) {
    match previous {
        Some(p) if p != 0 && p != header => (p, Some(header)),
        _ => (header, None),
    }
}

/// The ledger-header values every ledger variant records under `derived.header`, as decimal
/// strings, so one shared `expect` can pin a header field whose value differs per variant
/// (`${derived.header.fee_pool}`); `xdrcheck-corpus verify` checks each against the blob.
pub const DERIVED_HEADER_FIELDS: [&str; 6] = [
    "ledger_version",
    "total_coins",
    "fee_pool",
    "base_fee",
    "base_reserve",
    "max_tx_set_size",
];

/// [`DERIVED_HEADER_FIELDS`] of `h`.
pub fn derived_header(h: &stellar_xdr::LedgerHeader) -> Value {
    let values = [
        h.ledger_version.to_string(),
        h.total_coins.to_string(),
        h.fee_pool.to_string(),
        h.base_fee.to_string(),
        h.base_reserve.to_string(),
        h.max_tx_set_size.to_string(),
    ];
    Value::Object(
        DERIVED_HEADER_FIELDS
            .iter()
            .zip(values)
            .map(|(k, v)| (k.to_string(), Value::String(v)))
            .collect(),
    )
}

fn source(
    rec: &RunRecord,
    steps: &[&StepRecord],
    focus: &StepRecord,
    frame_index: usize,
    stream_sha256: &str,
) -> Value {
    let ids: Vec<&str> = steps.iter().map(|s| s.id.as_str()).collect();
    let soroban = if !focus.soroban {
        "not-applicable".to_string()
    } else {
        focus
            .soroban_resources
            .clone()
            .unwrap_or_else(|| "declared".into())
    };
    let inputs = &rec.inputs;
    let mut src = json!({
        "kind": "local-core",
        "core_version": rec.core.version,
        "core_commit": rec.core.commit,
        "core_binary_sha256": rec.core.binary_sha256,
        "scenario": rec.scenario,
        "scenario_sha256": rec.scenario_sha256,
        "step": ids.join(", "),
        "config_sha256": rec.core.config_sha256,
        "close_time": focus.close_time.to_string(),
        "stream_sha256": stream_sha256,
        "frame_index": frame_index,
        "generated_by": format!("xdrcheck-corpus gen {}", env!("CARGO_PKG_VERSION")),
        "soroban_resources": soroban,
        "inputs": inputs,
        "regenerate": regenerate_command(rec),
        "reproducibility": "normalised-identical",
    });
    if !rec.core.package_url.is_empty() {
        src["core_package"] =
            json!({"url": rec.core.package_url, "sha256": rec.core.package_sha256});
    }
    src
}

/// Insert or replace the variant in the entry; create the entry from the plan if needed. Returns
/// whether the entry was created.
fn upsert(
    corpus: &Path,
    id: &str,
    rec: &RunRecord,
    variant: Value,
    steps: &[&StepRecord],
) -> Result<bool> {
    let path = corpus.join(format!("manifest/{id}.json"));
    let (mut entry, created) = if path.is_file() {
        let e: Value = serde_json::from_slice(&std::fs::read(&path)?)
            .with_context(|| format!("{} is not JSON", path.display()))?;
        (e, false)
    } else {
        (skeleton(corpus, id, &rec.scenario_name)?, true)
    };
    for key in ["expect", "fields", "mirrors"] {
        let from_step = steps.iter().find_map(|s| match key {
            "expect" => s.expect.clone(),
            "fields" => s.fields.clone(),
            _ => s.mirrors.clone(),
        });
        if let Some(v) = from_step {
            entry[key] = v;
        }
    }
    let variants = entry["variants"]
        .as_array_mut()
        .ok_or_else(|| anyhow!("{id}: entry has no variants array"))?;
    variants
        .retain(|v| !(v["network"] == variant["network"] && v["protocol"] == variant["protocol"]));
    variants.push(variant);
    variants.sort_by_key(|v| {
        let p = v["protocol"].as_i64().unwrap_or(0);
        let n = ["testnet", "pubnet", "core-test", "none"]
            .iter()
            .position(|n| v["network"] == *n)
            .unwrap_or(9);
        (-p, n)
    });
    write_json(&path, &entry)?;
    Ok(created)
}

/// A new entry from its `plan.json` row.
fn skeleton(corpus: &Path, id: &str, scenario: &str) -> Result<Value> {
    let plan_path = corpus.join("plan.json");
    let plan: Value = serde_json::from_slice(
        &std::fs::read(&plan_path).with_context(|| format!("reading {}", plan_path.display()))?,
    )?;
    let row = plan
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["id"] == id)
        .ok_or_else(|| anyhow!("entry {id} is not in plan.json; entry IDs come from the plan"))?;
    let shape = row["shape"].as_str().unwrap_or(id);
    let mut title: String = shape.chars().filter(|c| *c != '`').collect();
    if title.chars().count() > 140 {
        title = title.chars().take(139).collect::<String>() + "…";
    }
    if title.chars().count() < 8 {
        bail!("plan row {id} has no usable shape for a title");
    }
    let mut entry = json!({
        "schema": "xcc.manifest.entry/v1",
        "id": id,
        "title": title,
        "kind": row["kind"],
        "caps": row["caps"],
        "protocol": {"introduced": row["protocol_min"]},
        "synthetic": false,
        // Bytes a local stellar-core wrote into a ledger: valid (docs/manifest.md section 9.5).
        "validity": "valid",
        "why": format!("{shape}."),
        "variants": [],
        "expect": {},
        "notes": format!("Created by xdrcheck-corpus gen from scenario {scenario}: the title and why are copied from the plan row and still need an author."),
    });
    // The schema requires a reason when no CAP introduced the pattern.
    if row["caps"].as_array().is_some_and(|c| c.is_empty()) {
        entry["caps_note"] = json!("No CAP introduced this pattern; the author must say why (placeholder written by xdrcheck-corpus gen).");
    }
    Ok(entry)
}

/// Pins quoted in variants, from `corpus.json` when present.
struct Pins {
    xdr_definitions: String,
    decoded_by: String,
}

impl Pins {
    fn read(corpus: &Path) -> Result<Pins> {
        let mut p = Pins {
            xdr_definitions: "stellar-xdr v30.0 (4f524bbac80c781c06e4fb5fc93a2d0d331d6705)".into(),
            decoded_by: super::sidecar::decoded_by(&Value::Null),
        };
        let cj = corpus.join("corpus.json");
        if cj.is_file() {
            let v: Value = serde_json::from_slice(&std::fs::read(&cj)?)?;
            p.decoded_by = super::sidecar::decoded_by(&v);
            let x = &v["pins"]["xdr_definitions"];
            if let (Some(t), Some(c)) = (x["tag"].as_str(), x["commit"].as_str()) {
                p.xdr_definitions = format!("stellar-xdr {t} ({c})");
            }
        }
        Ok(p)
    }
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

/// Pretty JSON with two-space indentation and a final newline. Non-ASCII characters (they occur only
/// inside strings, such as authored notes) are written as `\uXXXX` escapes, the form the corpus's
/// other writers (`xdrcheck-corpus render`) use, so a file gen rewrites stays byte-identical to theirs.
pub fn write_json(path: &Path, v: &Value) -> Result<()> {
    let pretty = serde_json::to_string_pretty(v)?;
    let mut text = String::with_capacity(pretty.len() + 1);
    for c in pretty.chars() {
        if c.is_ascii() {
            text.push(c);
        } else {
            let mut buf = [0u16; 2];
            for unit in c.encode_utf16(&mut buf) {
                text.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    text.push('\n');
    write_file(path, text.as_bytes())
}

/// Where the corpus keeps a blob.
pub fn blob_path(corpus: &Path, sha256: &str) -> PathBuf {
    corpus.join(format!(
        "blobs/{}/{sha256}.xdr",
        &sha256[..2.min(sha256.len())]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_ledgers_keep_the_applied_protocol() {
        // An ordinary ledger, and a run's first ledger (no previous one in the stream).
        assert_eq!(applied_protocol(Some(23), 23), (23, None));
        assert_eq!(applied_protocol(None, 30), (30, None));
        // The bring-up's upgrade from the genesis protocol keeps the target.
        assert_eq!(applied_protocol(Some(0), 30), (30, None));
        // A stepwise upgrade, and a jump over a protocol.
        assert_eq!(applied_protocol(Some(23), 24), (23, Some(24)));
        assert_eq!(applied_protocol(Some(13), 15), (13, Some(15)));
    }
}
