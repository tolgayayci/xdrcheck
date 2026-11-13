//! Writing intake results into the corpus: content-addressed blobs and one variant of a manifest
//! entry (`manifest.md` §2, §4.2).
//!
//! [`upsert_variant`] adds a variant, or updates the variant with the same key `(network,
//! protocol)`. On update, the fields intake derives from the bytes (`ledger_seq`, `xdr_type`,
//! `xdr_definitions`, `blob`, `source`, the meta versions, the derived hashes and the focus
//! transaction) are replaced and everything an author wrote (`decoded*`, `notes`, `meta.profile`,
//! other `derived` values, `focus.path` and `focus.op_index` while the focus transaction is
//! unchanged) is kept. A sidecar made stale by changed bytes is caught by `verify`.
//!
//! An entry that does not exist yet is started from its row in the ID registry (`plan.json`) as a
//! draft that the author completes; it does not pass `verify` until then.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use super::util::{read_json, write_atomic, write_json};

/// Corpus-relative path of a blob: `blobs/<aa>/<sha256>.xdr`.
pub fn blob_rel_path(sha256: &str) -> String {
    format!("blobs/{}/{sha256}.xdr", &sha256[..2])
}

/// Write `bytes` content-addressed under `corpus/blobs/`. An existing file must hold the same
/// bytes. Returns the corpus-relative path.
pub fn write_blob(corpus: &Path, bytes: &[u8]) -> Result<String> {
    let sha = xdrcheck_xdr::sha256_hex(bytes);
    let rel = blob_rel_path(&sha);
    let path = corpus.join(&rel);
    if path.exists() {
        let have = xdrcheck_xdr::sha256_file(&path)?;
        if have != sha {
            bail!("{} exists but its sha256 is {have}", path.display());
        }
    } else {
        write_atomic(&path, bytes)?;
    }
    Ok(rel)
}

/// Path of an entry's manifest file.
pub fn entry_path(corpus: &Path, id: &str) -> PathBuf {
    corpus.join("manifest").join(format!("{id}.json"))
}

/// Check an entry ID's spelling: `<group>/<slug>`, lower case letters, digits and hyphens, and `.`
/// in the slug, which joins a family row and its member (`<row>.<member>`).
pub fn check_entry_id(id: &str) -> Result<()> {
    let ok = |s: &str, dot: bool| {
        !s.is_empty()
            && s.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || (dot && b == b'.')
            })
    };
    match id.split_once('/') {
        Some((g, s)) if ok(g, false) && ok(s, true) => Ok(()),
        _ => bail!("entry ID {id:?} is not <group>/<slug>[.<member>] in lower case"),
    }
}

/// What [`upsert_variant`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upsert {
    /// A new entry file was started from the registry and the variant added.
    CreatedEntry,
    /// The variant was added to an existing entry.
    Added,
    /// The variant with the same `(network, protocol)` was updated.
    Updated,
}

/// Add or update `variant` in entry `id` (see the module documentation). Returns what was done.
pub fn upsert_variant(corpus: &Path, id: &str, variant: Value) -> Result<Upsert> {
    check_entry_id(id)?;
    let path = entry_path(corpus, id);
    let (mut entry, created) = if path.exists() {
        (read_json(&path)?, false)
    } else {
        (draft_entry(corpus, id)?, true)
    };
    let key = |v: &Value| (v.get("network").cloned(), v.get("protocol").cloned());
    let want = key(&variant);
    let variants = entry
        .as_object_mut()
        .context("manifest entry is not an object")?
        .entry("variants")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("variants is not an array")?;
    let outcome = match variants.iter_mut().find(|v| key(v) == want) {
        Some(old) => {
            *old = merge_variant(old, variant);
            Upsert::Updated
        }
        None => {
            variants.push(variant);
            if created {
                Upsert::CreatedEntry
            } else {
                Upsert::Added
            }
        }
    };
    write_json(&path, &entry)?;
    Ok(outcome)
}

/// Merge a freshly derived variant into an existing one, keeping authored fields.
fn merge_variant(old: &Value, new: Value) -> Value {
    let (Some(old), Value::Object(new)) = (old.as_object(), &new) else {
        return new;
    };
    let new = new.clone();
    let mut out: Map<String, Value> = old.clone();
    let same_focus_tx = old.get("focus").and_then(|f| f.get("tx_hash"))
        == new.get("focus").and_then(|f| f.get("tx_hash"));
    for (k, v) in new {
        match (k.as_str(), out.get_mut(&k)) {
            ("meta" | "derived", Some(Value::Object(have))) => {
                if let Value::Object(v) = v {
                    have.extend(v);
                }
            }
            ("focus", Some(Value::Object(have))) => {
                if !same_focus_tx {
                    have.remove("op_index");
                    have.remove("path");
                }
                if let Value::Object(v) = v {
                    have.extend(v);
                }
            }
            _ => {
                out.insert(k, v);
            }
        }
    }
    Value::Object(out)
}

/// The registry row an entry ID belongs to: the row with that ID, or for a family member
/// `<row>.<member>` the family row `<row>`, which must list `<member>` among its `members`.
fn registry_row<'a>(plan: &'a Value, id: &str) -> Result<&'a Value> {
    let rows = plan.as_array().context("plan.json is not an array")?;
    let find = |want: &str| rows.iter().find(|r| r.get("id") == Some(&json!(want)));
    if let Some(row) = find(id) {
        return Ok(row);
    }
    // The group has no `.`, so the first `.` joins the family row and its member.
    if let Some((family, member)) = id.split_once('.') {
        if let Some(row) = find(family) {
            let listed = row
                .get("members")
                .and_then(Value::as_array)
                .is_some_and(|m| m.iter().any(|m| m == member));
            if !listed {
                bail!("entry {id}: {member:?} is not a member of family row {family} in plan.json");
            }
            return Ok(row);
        }
    }
    bail!("entry {id} has no manifest file and is not in the ID registry (plan.json)")
}

/// A draft entry for `id` from its row in `corpus/plan.json` (the family row for a member ID).
fn draft_entry(corpus: &Path, id: &str) -> Result<Value> {
    let plan = read_json(&corpus.join("plan.json"))?;
    let row = registry_row(&plan, id)?;
    let mut title: String = row
        .get("shape")
        .and_then(Value::as_str)
        .unwrap_or(id)
        .replace('`', "");
    if title.chars().count() > 140 {
        title = title.chars().take(139).collect::<String>() + "…";
    }
    let mut e = json!({
        "schema": "xcc.manifest.entry/v1",
        "id": id,
        "title": title,
        "kind": row.get("kind").cloned().unwrap_or(json!("ledger")),
        "caps": row.get("caps").cloned().unwrap_or(json!([])),
        "protocol": {"introduced": row.get("protocol_min").cloned().unwrap_or(json!(0))},
        "synthetic": row.get("synthetic").cloned().unwrap_or(json!(false)),
        // A lake capture is bytes stellar-core wrote into a ledger: valid (docs/manifest.md §9.5).
        "validity": "valid",
        "why": "",
        "variants": [],
        "expect": {},
        "notes": "Draft started by xdrcheck-corpus intake from the ID registry: write title, why, expect, fields and shapes.",
    });
    if e["caps"].as_array().is_some_and(|c| c.is_empty()) {
        e["caps_note"] = json!("");
    }
    Ok(e)
}
