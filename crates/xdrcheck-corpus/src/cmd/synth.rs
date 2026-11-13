//! `xdrcheck-corpus synth <recipe>…` — build synthetic, `api` and `strkey` entries from recipe files
//! (recipe format: `corpus/schema/recipe.schema.json`).
//!
//! Constructions (exactly one per recipe):
//! - `hex`: the literal bytes;
//! - `json`: a SEP-51 JSON value of `xdr_type`, encoded by the oracle;
//! - `edit`: a base entry's blob with byte operations applied in order — `replace` overwrites
//!   bytes at `at`, `insert` inserts at `at`, `delete` removes `length` bytes at `at`, `append`
//!   adds bytes at the end (`at` must equal the current length);
//! - `nest`: `leaf` (SEP-51 JSON of `xdr_type`) wrapped `depth` times. Wrappers:
//!   `scv_vec` → `{"vec": [inner]}`; `scv_map` → `{"map": [{"key": "void", "val": inner}]}` (the shapes
//!   of `evidence/core-print-xdr/cases.py`);
//!   `sub_invocation` → `{"function": <leaf's function>, "sub_invocations": [inner]}`
//!   (`xdr_type` `SorobanAuthorizedInvocation`);
//! - `api`, `strkey`: the entry's `api` or `strkey` block (no bytes);
//! - `spec` (`spec` entries): a contract-spec blob — `container` `wasm` (a header-only Wasm module
//!   with one custom section per element of `sections`, each named `name`, default
//!   `contractspecv0`) or `xdr-stream` (exactly one section, written bare). A section's payload is
//!   its `entries` (SEP-51 JSON of `SCSpecEntry`, each encoded by the oracle and appended with no
//!   frame) with the byte `ops` of `edit` applied to the payload, so a vector the oracle refuses
//!   to encode (a name one byte over its bound, a truncated stream) is built from one it accepts.
//!   The variant carries `xdr_type` `SCSpecEntry` and the `container`; `expect.spec` is set from
//!   the bytes by the corpus's own section reader (`xdrcheck_xdr::spec`).
//!
//! For an `xdr` recipe synth writes the blob (`blobs/<aa>/<sha256>.xdr`), the variant (network
//! `none`, empty passphrase, the corpus' maximum protocol, `source.kind: synthetic` with the
//! recipe's path and reason) and, for a positive entry, the sidecar — a positive entry must pass
//! the oracle. Negative entries get no sidecar; synth reports what the oracle says about them.
//!
//! The manifest entry: if `manifest/<id>.json` exists, only its `none` variant (or `api`/`strkey`
//! block) is replaced and everything authored is kept. Otherwise a skeleton is written from the
//! entry's `plan.json` row (`caps`, `protocol.introduced`, `negative`) with `title` and `why` set
//! to `TODO` and an empty `expect`, so `verify --checks schema` fails until an author fills in
//! the title, the why and — for a negative entry — `expect.reject.reason`.
//!
//! The entry ID must exist in `plan.json` (an ID that is not in the plan does not exist).
//! Exit codes: 0 every recipe built, 1 a recipe failed, 2 tool error.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use super::render::{self, Oracle};

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Recipe files (JSON, `recipe.schema.json`).
    #[arg(required = true)]
    pub recipes: Vec<PathBuf>,
}

pub fn run(corpus: &Path, args: Args) -> Result<ExitCode> {
    let oracle = Oracle::new(corpus)?;
    let validator = recipe_validator(corpus)?;
    let mut bad = false;
    for path in &args.recipes {
        let text = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let recipe: Value = serde_json::from_slice(&text)
            .with_context(|| format!("{} is not JSON", path.display()))?;
        let errors: Vec<String> = validator
            .iter_errors(&recipe)
            .map(|e| format!("at {}: {e}", e.instance_path()))
            .collect();
        if !errors.is_empty() {
            println!(
                "FAIL {}: not a valid recipe: {}",
                path.display(),
                errors.join("; ")
            );
            bad = true;
            continue;
        }
        match synth_one(corpus, &oracle, path, &recipe) {
            Ok(lines) => lines.iter().for_each(|l| println!("{l}")),
            Err(e) => {
                println!("FAIL {}: {e:#}", path.display());
                bad = true;
            }
        }
    }
    // A replaced variant may leave its old sidecar unreferenced.
    for line in render::collect_garbage(corpus, false)? {
        println!("{line}");
    }
    Ok(ExitCode::from(if bad { 1 } else { 0 }))
}

fn synth_one(corpus: &Path, oracle: &Oracle, path: &Path, recipe: &Value) -> Result<Vec<String>> {
    let id = recipe["entry"].as_str().unwrap_or_default();
    let kind = recipe["kind"].as_str().unwrap_or_default();
    let row = plan_row(corpus, id)?;
    if row.kind != kind {
        bail!("recipe kind {kind} but plan.json says {id} is {}", row.kind);
    }
    let recipe_ref = recipe_ref(corpus, path);
    let construction = &recipe["construction"];
    let mut lines = Vec::new();
    let manifest = render::manifest_path(corpus, id);
    let mut entry = match std::fs::read(&manifest) {
        Ok(b) => serde_json::from_slice(&b)
            .with_context(|| format!("{} is not JSON", manifest.display()))?,
        Err(_) => {
            lines.push(format!(
                "skeleton manifest/{id}.json: author title, why{}",
                if row.negative {
                    " and expect.reject.reason"
                } else {
                    " and expect"
                }
            ));
            skeleton(id, &row, &recipe_ref)
        }
    };
    if entry["kind"] != kind {
        bail!(
            "manifest/{id}.json has kind {}, recipe has {kind}",
            entry["kind"]
        );
    }
    match kind {
        "api" | "strkey" => {
            entry[kind] = construction[kind].clone();
        }
        "spec" => {
            let c = &construction["spec"];
            let container = c["container"].as_str().unwrap_or("wasm");
            let bytes = spec_bytes(oracle, c)?;
            let blob = write_blob_ext(corpus, &bytes, spec_ext(container))?;
            lines.push(format!(
                "blob {} ({} bytes)",
                blob["path"].as_str().unwrap_or(""),
                bytes.len()
            ));
            let variant = json!({
                "network": "none",
                "passphrase": "",
                "protocol": oracle.gate.max_protocol,
                "xdr_type": "SCSpecEntry",
                "container": container,
                "requires": [],
                "xdr_definitions": xdr_definitions(corpus),
                "blob": blob,
                "source": {"kind": "synthetic", "recipe": recipe_ref, "reason": recipe["reason"]},
            });
            upsert_variant(&mut entry, variant)?;
            render::set_spec_expect(&mut entry, &bytes, container)?;
        }
        _ => {
            let xdr_type = recipe["xdr_type"].as_str().unwrap_or_default();
            xdrcheck_xdr::type_variant(xdr_type)?;
            let (bytes, base_entry) = build_bytes(corpus, oracle, xdr_type, construction)?;
            let blob = write_blob(corpus, &bytes)?;
            lines.push(format!(
                "blob {} ({} bytes)",
                blob["path"].as_str().unwrap_or(""),
                bytes.len()
            ));
            let mut source = json!({
                "kind": "synthetic",
                "recipe": recipe_ref,
                "reason": recipe["reason"],
            });
            if let Some(b) = base_entry {
                source["base_entry"] = json!(b);
            }
            let variant = json!({
                "network": "none",
                "passphrase": "",
                "protocol": oracle.gate.max_protocol,
                "xdr_type": xdr_type,
                // A negative value's features cannot be derived from bytes that do not decode;
                // a positive one's are derived with its sidecar below.
                "requires": [],
                "xdr_definitions": xdr_definitions(corpus),
                "blob": blob,
                "source": source,
            });
            let negative = entry["negative"].as_bool().unwrap_or(false);
            if negative {
                match oracle.render(xdr_type, &bytes) {
                    Ok(_) => lines.push(format!(
                        "note {id}: the oracle ACCEPTS these bytes as {xdr_type} (negative entry)"
                    )),
                    Err(e) => lines.push(format!("note {id}: the oracle rejects: {e}")),
                }
            }
            upsert_variant(&mut entry, variant)?;
            if !negative {
                write_sidecars(corpus, oracle, &mut entry, &bytes, &mut lines)?;
            }
        }
    }
    std::fs::create_dir_all(manifest.parent().expect("manifest has a parent"))?;
    std::fs::write(&manifest, render::manifest_text(&entry))?;
    lines.push(format!("wrote manifest/{id}.json"));
    Ok(lines)
}

/// The bytes a construction yields, and the base entry for an `edit`.
fn build_bytes(
    corpus: &Path,
    oracle: &Oracle,
    xdr_type: &str,
    c: &Value,
) -> Result<(Vec<u8>, Option<String>)> {
    if let Some(h) = c["hex"].as_str() {
        return Ok((hex::decode(h).context("hex construction")?, None));
    }
    if !c["json"].is_null() {
        return Ok((
            xdrcheck_xdr::json_to_xdr(xdr_type, &c["json"], &oracle.limits)?,
            None,
        ));
    }
    if let Some(n) = c.get("nest") {
        let json = nest(
            &n["leaf"],
            n["wrapper"].as_str().unwrap_or(""),
            n["depth"].as_u64().unwrap_or(0),
        )?;
        let bytes = xdrcheck_xdr::json_to_xdr(xdr_type, &json, &oracle.limits);
        // Drop the deep value on a large stack.
        xdrcheck_xdr::with_stack(oracle.limits.stack_size, move || drop(json));
        return Ok((bytes?, None));
    }
    if let Some(e) = c.get("edit") {
        let base = e["base_entry"].as_str().unwrap_or_default();
        let bytes = base_blob(corpus, base, e["base_variant"].as_str())?;
        return Ok((apply_edits(bytes, &e["ops"])?, Some(base.to_string())));
    }
    bail!("the construction yields no bytes")
}

/// The bytes of a `spec` construction.
fn spec_bytes(oracle: &Oracle, c: &Value) -> Result<Vec<u8>> {
    let container = c["container"].as_str().unwrap_or("wasm");
    let sections = c["sections"].as_array().context("spec: no sections")?;
    let mut payloads: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (i, s) in sections.iter().enumerate() {
        let mut payload = Vec::new();
        for e in s["entries"].as_array().into_iter().flatten() {
            payload.extend(
                xdrcheck_xdr::json_to_xdr("ScSpecEntry", e, &oracle.limits)
                    .with_context(|| format!("spec section {i}: an entry the oracle refuses"))?,
            );
        }
        if let Some(ops) = s.get("ops") {
            payload = apply_edits(payload, ops).with_context(|| format!("spec section {i}"))?;
        }
        let name = s["name"]
            .as_str()
            .unwrap_or("contractspecv0")
            .as_bytes()
            .to_vec();
        payloads.push((name, payload));
    }
    match container {
        "xdr-stream" => {
            if payloads.len() != 1 {
                bail!("spec: an xdr-stream holds exactly one section");
            }
            Ok(payloads.remove(0).1)
        }
        "wasm" => {
            let refs: Vec<(&[u8], &[u8])> = payloads
                .iter()
                .map(|(n, p)| (n.as_slice(), p.as_slice()))
                .collect();
            Ok(xdrcheck_xdr::spec::wasm_with_sections(&refs))
        }
        other => bail!("spec: unknown container {other:?}"),
    }
}

/// The blob file extension of a spec container.
pub(crate) fn spec_ext(container: &str) -> &'static str {
    if container == "wasm" {
        "wasm"
    } else {
        "xdr"
    }
}

/// Wrap `leaf` in `wrapper` `depth` times (iteratively, so depth is not bounded by recursion).
pub(crate) fn nest(leaf: &Value, wrapper: &str, depth: u64) -> Result<Value> {
    let function = leaf["function"].clone();
    if wrapper == "sub_invocation" && function.is_null() {
        bail!("nest wrapper sub_invocation needs a leaf with a `function`");
    }
    let mut v = leaf.clone();
    for _ in 0..depth {
        v = match wrapper {
            "scv_vec" => json!({ "vec": [v] }),
            "scv_map" => json!({ "map": [{ "key": "void", "val": v }] }),
            "sub_invocation" => json!({ "function": function, "sub_invocations": [v] }),
            other => bail!("unknown nest wrapper {other:?}"),
        };
    }
    Ok(v)
}

/// Apply `replace`/`insert`/`delete`/`append` operations in order.
pub(crate) fn apply_edits(mut bytes: Vec<u8>, ops: &Value) -> Result<Vec<u8>> {
    for (i, op) in ops.as_array().into_iter().flatten().enumerate() {
        let at = op["at"].as_u64().unwrap_or(0) as usize;
        let data = match op["hex"].as_str() {
            Some(h) => hex::decode(h).with_context(|| format!("op {i}: hex"))?,
            None => Vec::new(),
        };
        let len = bytes.len();
        match op["op"].as_str().unwrap_or_default() {
            "replace" => {
                if at + data.len() > len {
                    bail!(
                        "op {i}: replace of {} bytes at {at} runs past the end ({len})",
                        data.len()
                    );
                }
                bytes[at..at + data.len()].copy_from_slice(&data);
            }
            "insert" => {
                if at > len {
                    bail!("op {i}: insert at {at} is past the end ({len})");
                }
                bytes.splice(at..at, data);
            }
            "delete" => {
                let n = op["length"].as_u64().unwrap_or(0) as usize;
                if at + n > len {
                    bail!("op {i}: delete of {n} bytes at {at} runs past the end ({len})");
                }
                bytes.drain(at..at + n);
            }
            "append" => {
                if at != len {
                    bail!("op {i}: append at {at}, but the bytes end at {len}");
                }
                bytes.extend_from_slice(&data);
            }
            other => bail!("op {i}: unknown op {other:?}"),
        }
    }
    Ok(bytes)
}

/// The blob of a base entry's variant (by key `network` or `network@protocol`; default: the first).
fn base_blob(corpus: &Path, id: &str, key: Option<&str>) -> Result<Vec<u8>> {
    let path = render::manifest_path(corpus, id);
    let entry: Value = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("base entry {id}: {}", path.display()))?,
    )?;
    let v = select_variant(&entry, key).with_context(|| format!("base entry {id}"))?;
    let p = render::blob_path(corpus, v);
    std::fs::read(&p).with_context(|| format!("reading {}", p.display()))
}

/// A variant by key (`network` or `network@protocol`), or the first one.
pub(crate) fn select_variant<'a>(entry: &'a Value, key: Option<&str>) -> Result<&'a Value> {
    let variants = entry["variants"]
        .as_array()
        .context("entry has no variants")?;
    let Some(key) = key else {
        return variants.first().context("entry has no variants");
    };
    let (net, proto) = match key.split_once('@') {
        Some((n, p)) => (n, Some(p.parse::<u64>().context("variant key protocol")?)),
        None => (key, None),
    };
    let matching: Vec<&Value> = variants
        .iter()
        .filter(|v| v["network"] == net && proto.is_none_or(|p| v["protocol"].as_u64() == Some(p)))
        .collect();
    match matching.as_slice() {
        [v] => Ok(v),
        [] => bail!("no variant {key}"),
        _ => bail!("variant key {key} is ambiguous; use network@protocol"),
    }
}

/// Insert `variant` or replace the variant with the same (network, protocol).
pub(crate) fn upsert_variant(entry: &mut Value, mut variant: Value) -> Result<()> {
    let variants = entry
        .as_object_mut()
        .context("entry is not an object")?
        .entry("variants")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("variants is not an array")?;
    match variants
        .iter_mut()
        .find(|v| v["network"] == variant["network"] && v["protocol"] == variant["protocol"])
    {
        Some(old) => {
            // Keep authored fields of the old variant (focus, meta, derived, notes, …).
            if let (Some(o), Some(n)) = (old.as_object(), variant.as_object_mut()) {
                for (k, val) in o {
                    if !n.contains_key(k)
                        && !matches!(k.as_str(), "decoded" | "decoded_sha256" | "decoded_by")
                    {
                        n.insert(k.clone(), val.clone());
                    }
                }
            }
            *old = variant;
        }
        None => variants.push(variant),
    }
    Ok(())
}

/// Render the shared sidecar of `bytes` (`decoded/<aa>/<sha256>.json.zst`) and set the sidecar
/// fields of every variant whose blob it is.
pub(crate) fn write_sidecars(
    corpus: &Path,
    oracle: &Oracle,
    entry: &mut Value,
    bytes: &[u8],
    lines: &mut Vec<String>,
) -> Result<()> {
    let sha = xdrcheck_xdr::sha256_hex(bytes);
    let variants = entry["variants"].as_array_mut().context("no variants")?;
    let mut text: Option<String> = None;
    for v in variants.iter_mut() {
        if v["blob"]["sha256"] != sha.as_str() {
            continue;
        }
        let xdr_type = v["xdr_type"].as_str().unwrap_or_default().to_string();
        if text.is_none() {
            let rendered = oracle
                .render(&xdr_type, bytes)
                .with_context(|| format!("a positive entry must pass the oracle as {xdr_type}"))?;
            text = Some(render::sidecar_json(&rendered));
            xdrcheck_xdr::with_stack(oracle.limits.stack_size, move || drop(rendered));
        }
        let text = text.as_deref().expect("rendered above");
        let rel = render::sidecar_rel(&sha);
        let wrote = render::write_sidecar(corpus, &rel, text)?;
        render::set_sidecar_fields(v, &rel, text, &oracle.decoded_by);
        render::set_derived_fields(v, bytes, Some(text), oracle)?;
        lines.push(format!(
            "sidecar {rel}{}",
            if wrote { "" } else { " (unchanged)" }
        ));
    }
    Ok(())
}

/// Write a content-addressed blob; returns the manifest `blob` object.
pub(crate) fn write_blob(corpus: &Path, bytes: &[u8]) -> Result<Value> {
    write_blob_ext(corpus, bytes, "xdr")
}

/// Write a content-addressed blob with the given extension (`xdr`, or `wasm` for a contract).
pub(crate) fn write_blob_ext(corpus: &Path, bytes: &[u8], ext: &str) -> Result<Value> {
    let sha = xdrcheck_xdr::sha256_hex(bytes);
    let rel = format!("blobs/{}/{sha}.{ext}", &sha[..2]);
    let path = corpus.join(&rel);
    std::fs::create_dir_all(path.parent().expect("blob has a parent"))?;
    std::fs::write(&path, bytes)?;
    Ok(json!({ "sha256": sha, "bytes": bytes.len(), "path": rel }))
}

/// `stellar-xdr <tag> (<commit>)` from `corpus.json` pins.
pub(crate) fn xdr_definitions(corpus: &Path) -> String {
    let cj: Value = std::fs::read(corpus.join("corpus.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    let p = |k: &str, d: &str| {
        cj.pointer(k)
            .and_then(Value::as_str)
            .unwrap_or(d)
            .to_string()
    };
    format!(
        "stellar-xdr {} ({})",
        p("/pins/xdr_definitions/tag", "v30.0"),
        p(
            "/pins/xdr_definitions/commit",
            "4f524bbac80c781c06e4fb5fc93a2d0d331d6705"
        )
    )
}

/// What `plan.json` says about an entry ID (a row ID, or `<row ID>.<member>`).
pub(crate) struct PlanRow {
    pub kind: String,
    pub negative: bool,
    pub caps: Value,
    pub protocol_min: u64,
    pub synthetic: bool,
}

pub(crate) fn plan_row(corpus: &Path, id: &str) -> Result<PlanRow> {
    let path = corpus.join("plan.json");
    let plan: Value = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
    )?;
    for r in plan.as_array().into_iter().flatten() {
        let rid = r["id"].as_str().unwrap_or_default();
        let member_of = id
            .strip_prefix(rid)
            .and_then(|m| m.strip_prefix('.'))
            .is_some_and(|m| {
                r["members"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|x| x == m)
            });
        if rid == id || member_of {
            return Ok(PlanRow {
                kind: r["kind"].as_str().unwrap_or_default().to_string(),
                negative: r["negative"].as_bool().unwrap_or(false),
                caps: r["caps"].clone(),
                protocol_min: r["protocol_min"].as_u64().unwrap_or(1),
                synthetic: r["synthetic"].as_bool().unwrap_or(true),
            });
        }
    }
    bail!("entry {id} is not in plan.json; entry IDs are created there first")
}

/// A manifest skeleton for a new entry. `title` and `why` are `TODO` on purpose: they fail the
/// schema until an author writes them.
pub(crate) fn skeleton(id: &str, row: &PlanRow, made_by: &str) -> Value {
    let mut m = Map::new();
    m.insert("schema".into(), json!("xcc.manifest.entry/v1"));
    m.insert("id".into(), json!(id));
    m.insert("title".into(), json!("TODO"));
    m.insert("kind".into(), json!(row.kind));
    m.insert("caps".into(), row.caps.clone());
    if row.caps.as_array().is_none_or(Vec::is_empty) {
        m.insert("caps_note".into(), json!("TODO"));
    }
    m.insert("protocol".into(), json!({ "introduced": row.protocol_min }));
    m.insert("synthetic".into(), json!(row.synthetic));
    if row.negative {
        m.insert("negative".into(), json!(true));
    }
    // A starting point the author confirms (docs/manifest.md §9.5): a negative entry is malformed
    // unless its reject reason is a rule about decoded values (then invalid); the schema ties the
    // two together once the reason is written.
    m.insert(
        "validity".into(),
        json!(if row.negative { "malformed" } else { "valid" }),
    );
    m.insert("why".into(), json!("TODO"));
    // The body the entry kind needs, in the conventional position before `expect`.
    match row.kind.as_str() {
        "api" => m.insert("api".into(), json!({})),
        "strkey" => m.insert("strkey".into(), json!({})),
        _ => m.insert("variants".into(), json!([])),
    };
    m.insert("expect".into(), json!({}));
    m.insert(
        "notes".into(),
        json!(format!(
            "Skeleton written by xdrcheck-corpus from {made_by}; author the title, why and expect."
        )),
    );
    Value::Object(m)
}

/// The recipe's path relative to the corpus root when it lies inside it, else as given.
fn recipe_ref(corpus: &Path, path: &Path) -> String {
    let abs = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    abs(path)
        .strip_prefix(abs(corpus))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string_lossy().into_owned())
}

fn recipe_validator(corpus: &Path) -> Result<jsonschema::Validator> {
    let p = corpus.join("schema/recipe.schema.json");
    let schema: Value = serde_json::from_slice(
        &std::fs::read(&p).with_context(|| format!("reading {}", p.display()))?,
    )?;
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|e| anyhow::anyhow!("recipe schema does not compile: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits() {
        let b = vec![1, 2, 3, 4];
        let ops = json!([
            {"at": 1, "op": "replace", "hex": "ff"},
            {"at": 0, "op": "insert", "hex": "00"},
            {"at": 4, "op": "delete", "length": 1},
            {"at": 4, "op": "append", "hex": "aa"}
        ]);
        assert_eq!(
            apply_edits(b.clone(), &ops).unwrap(),
            vec![0, 1, 0xff, 3, 0xaa]
        );
        assert!(apply_edits(
            b.clone(),
            &json!([{"at": 3, "op": "replace", "hex": "0000"}])
        )
        .is_err());
        assert!(apply_edits(b, &json!([{"at": 2, "op": "append", "hex": "00"}])).is_err());
    }

    #[test]
    fn nesting() {
        assert_eq!(
            nest(&json!("void"), "scv_vec", 2).unwrap(),
            json!({"vec": [{"vec": ["void"]}]})
        );
        assert_eq!(
            nest(&json!("void"), "scv_map", 1).unwrap(),
            json!({"map": [{"key": "void", "val": "void"}]})
        );
        assert!(nest(&json!("void"), "sub_invocation", 1).is_err());
    }
}
