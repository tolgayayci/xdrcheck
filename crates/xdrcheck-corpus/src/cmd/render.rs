//! `xdrcheck-corpus render <entry>… [--all] [--check]` — write the SEP-51 sidecars, and
//! `render --print <entry> [--variant KEY] [--pretty]` — show one variant's decoded JSON.
//!
//! For every positive `ledger` and `xdr` variant: decode the blob with the oracle (gate, explicit
//! limits, byte-exact re-encode, JSON round trip — the same rendering `verify --checks sidecar`
//! compares against), write the sidecar, and set `decoded`, `decoded_sha256` and `decoded_by` in
//! the manifest variant. Negative entries get no sidecar; `api` and `strkey` entries have no bytes.
//!
//! Sidecar storage (docs/manifest.md §2):
//! - **one sidecar per blob**, shared by every variant (of any entry) whose blob it is, at
//!   `decoded/<aa>/<blob sha256>.json.zst` (the same two-character prefix as the blob);
//! - content: the oracle's JSON, compact (no whitespace, keys in the XDR field order the oracle
//!   emits) with a trailing newline, compressed as one zstd frame at level 19 with the content
//!   checksum;
//! - `decoded_sha256` is the sha256 of the **uncompressed** JSON, so it does not depend on the zstd
//!   build. A sidecar whose uncompressed content is already right is not rewritten.
//!
//! Writing also removes every file under `decoded/` that no manifest variant references (earlier
//! per-entry `.json` sidecars). `--check` writes nothing and exits 1 if any sidecar, manifest field
//! or stray file would change. Exit codes: 0 done (or no drift), 1 drift or an entry that cannot be
//! rendered, 2 tool error.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use xdrcheck_xdr::{Gate, Limits};

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Entry IDs to render.
    pub entries: Vec<String>,
    /// Render every manifest entry.
    #[arg(long)]
    pub all: bool,
    /// Report drift without writing anything.
    #[arg(long)]
    pub check: bool,
    /// Print the decoded JSON of this entry's variant to stdout instead of rendering.
    #[arg(long, value_name = "ENTRY", conflicts_with_all = ["all", "check"])]
    pub print: Option<String>,
    /// With --print: the variant (`network` or `network@protocol`); default: the first.
    #[arg(long, requires = "print")]
    pub variant: Option<String>,
    /// With --print: indent the JSON.
    #[arg(long, requires = "print")]
    pub pretty: bool,
}

pub fn run(corpus: &Path, args: Args) -> Result<ExitCode> {
    if let Some(id) = &args.print {
        return print(corpus, id, args.variant.as_deref(), args.pretty);
    }
    let ids = if args.all {
        if !args.entries.is_empty() {
            bail!("give entry IDs or --all, not both");
        }
        all_entry_ids(corpus)?
    } else {
        if args.entries.is_empty() {
            bail!("no entries given (pass entry IDs or --all)");
        }
        args.entries.clone()
    };
    let oracle = Oracle::new(corpus)?;
    let mut cache = HashMap::new();
    let mut bad = false;
    for id in &ids {
        let path = manifest_path(corpus, id);
        if !path.is_file() {
            bail!("no manifest entry {id} ({} does not exist)", path.display());
        }
        match render_entry(corpus, &oracle, id, args.check, &mut cache) {
            Ok(r) => {
                for line in &r.lines {
                    println!("{line}");
                }
                bad |= args.check && r.drift;
            }
            Err(e) => {
                println!("FAIL {id}: {e:#}");
                bad = true;
            }
        }
    }
    for line in collect_garbage(corpus, args.check)? {
        println!("{line}");
        bad |= args.check;
    }
    Ok(ExitCode::from(if bad { 1 } else { 0 }))
}

/// What rendering one entry did.
struct Outcome {
    lines: Vec<String>,
    drift: bool,
}

fn render_entry(
    corpus: &Path,
    oracle: &Oracle,
    id: &str,
    check: bool,
    cache: &mut HashMap<String, String>,
) -> Result<Outcome> {
    let path = manifest_path(corpus, id);
    let original = std::fs::read(&path)?;
    let mut entry: Value = serde_json::from_slice(&original)
        .with_context(|| format!("{} is not JSON", path.display()))?;
    let mut out = Outcome {
        lines: Vec::new(),
        drift: false,
    };
    let kind = entry["kind"].as_str().unwrap_or("").to_string();
    if kind == "spec" {
        // No sidecar: the expected facts come from the corpus's own section reader.
        let v = entry["variants"]
            .as_array()
            .and_then(|a| a.first())
            .context("spec entry has no variant")?
            .clone();
        let blob = std::fs::read(blob_path(corpus, &v))
            .with_context(|| format!("reading blob {}", blob_path(corpus, &v).display()))?;
        set_spec_expect(&mut entry, &blob, v["container"].as_str().unwrap_or(""))?;
        let new = manifest_text(&entry);
        if new.as_bytes() != original.as_slice() {
            out.drift = true;
            if check {
                out.lines.push(format!(
                    "DRIFT manifest/{id}.json: expect.spec would change"
                ));
            } else {
                std::fs::write(&path, new)?;
                out.lines.push(format!("updated manifest/{id}.json"));
            }
        }
        return Ok(out);
    }
    if kind != "ledger" && kind != "xdr" {
        out.lines
            .push(format!("skip {id}: kind {kind} has no bytes"));
        return Ok(out);
    }
    let negative = entry["negative"].as_bool() == Some(true);
    let variants = entry["variants"]
        .as_array_mut()
        .context("entry has no variants")?;
    if negative {
        // No sidecar; only `requires` is set (kept when stated, else `[]`).
        out.lines
            .push(format!("skip {id}: negative entries have no sidecar"));
        for v in variants.iter_mut() {
            set_derived_fields(v, &[], None, oracle)?;
        }
    }
    for v in variants.iter_mut().filter(|_| !negative) {
        let blob = std::fs::read(blob_path(corpus, v))
            .with_context(|| format!("reading blob {}", blob_path(corpus, v).display()))?;
        let sha = xdrcheck_xdr::sha256_hex(&blob);
        let xdr_type = v["xdr_type"].as_str().unwrap_or("").to_string();
        let text = match cache.get(&sha) {
            Some(t) => t.clone(),
            None => {
                // A declared JSON round-trip exception still renders; only JSON → XDR is skipped.
                let json = if v["json_roundtrip"]["skip"] == true {
                    oracle.render_without_json_roundtrip(&xdr_type, &blob)?
                } else {
                    oracle.render(&xdr_type, &blob)?
                };
                let t = sidecar_json(&json);
                cache.insert(sha.clone(), t.clone());
                t
            }
        };
        let rel = sidecar_rel(&sha);
        let current = read_sidecar_text(&corpus.join(&rel)).ok();
        if current.as_deref() == Some(text.as_bytes()) {
            out.lines.push(format!("unchanged {rel}"));
        } else {
            out.drift = true;
            if check {
                let why = if current.is_some() {
                    "differs from a fresh rendering"
                } else {
                    "missing"
                };
                out.lines.push(format!("DRIFT {rel}: {why}"));
            } else {
                write_sidecar(corpus, &rel, &text)?;
                out.lines.push(format!("rendered {rel}"));
            }
        }
        set_sidecar_fields(v, &rel, &text, &oracle.decoded_by);
        set_derived_fields(v, &blob, Some(&text), oracle)
            .with_context(|| format!("{id}: derived variant fields"))?;
    }
    let new = manifest_text(&entry);
    if new.as_bytes() != original.as_slice() {
        out.drift = true;
        if check {
            out.lines.push(format!(
                "DRIFT manifest/{id}.json: decoded, decoded_sha256, decoded_by, requires or derived.l1 would change"
            ));
        } else {
            std::fs::write(&path, new)?;
            out.lines.push(format!("updated manifest/{id}.json"));
        }
    }
    Ok(out)
}

/// Set a `spec` entry's `expect.spec` from its blob, read by the corpus's own section reader. A spec
/// entry holds one blob: every variant must have it.
pub(crate) fn set_spec_expect(entry: &mut Value, blob: &[u8], container: &str) -> Result<()> {
    let c = xdrcheck_xdr::spec::Container::parse(container).with_context(|| {
        format!("spec variant container {container:?}: want wasm or xdr-stream")
    })?;
    let sha = xdrcheck_xdr::sha256_hex(blob);
    for v in entry["variants"].as_array().into_iter().flatten() {
        if v["blob"]["sha256"] != sha.as_str() {
            bail!("a spec entry holds one blob; variant blobs differ");
        }
    }
    let facts = xdrcheck_xdr::spec::read(blob, c);
    let block = xdrcheck_xdr::spec::expect_block(&facts);
    let expect = entry
        .as_object_mut()
        .context("entry is not an object")?
        .entry("expect")
        .or_insert_with(|| json!({}));
    expect["spec"] = block;
    Ok(())
}

/// `render --print`: the variant's sidecar, decompressed, to stdout.
fn print(corpus: &Path, id: &str, variant: Option<&str>, pretty: bool) -> Result<ExitCode> {
    let path = manifest_path(corpus, id);
    let entry: Value = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("no manifest entry {id}"))?,
    )?;
    let v = super::synth::select_variant(&entry, variant)?;
    let Some(rel) = v["decoded"].as_str() else {
        bail!("{id}: the variant has no sidecar (negative entries have none)");
    };
    let text = read_sidecar_text(&corpus.join(rel))?;
    let out = if pretty {
        let limits = Limits::default();
        let value = xdrcheck_xdr::parse_json(&text, &limits)?;
        let s = pretty_json(&value);
        xdrcheck_xdr::with_stack(limits.stack_size, move || drop(value));
        s.into_bytes()
    } else {
        text
    };
    match std::io::stdout().lock().write_all(&out) {
        // A reader such as `head` closing the pipe early is not an error.
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        r => r?,
    }
    Ok(ExitCode::SUCCESS)
}

/// The oracle as `render`, `synth` and `slice` use it: the gate from `corpus.json`, the default
/// decode limits and the `decoded_by` string.
pub(crate) struct Oracle {
    pub gate: Gate,
    pub limits: Limits,
    pub decoded_by: String,
}

impl Oracle {
    pub fn new(corpus: &Path) -> Result<Oracle> {
        let cj_path = corpus.join("corpus.json");
        let gate = Gate::from_corpus_json(&cj_path)
            .with_context(|| format!("reading {}", cj_path.display()))?
            .unwrap_or_default();
        let cj: Value = std::fs::read(&cj_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null);
        let decoded_by = xdrcheck_gen::output::sidecar::decoded_by(&cj);
        Ok(Oracle {
            gate,
            limits: Limits::default(),
            decoded_by,
        })
    }

    /// The SEP-51 JSON of `bytes` as `xdr_type`, after the gate (for `LedgerCloseMeta`) and the
    /// full round trip (bytes → value → bytes, and → JSON → bytes).
    pub fn render(&self, xdr_type: &str, bytes: &[u8]) -> Result<Value> {
        if xdr_type == "LedgerCloseMeta" {
            self.gate.check(&xdrcheck_xdr::ledger_info(bytes)?)?;
        }
        Ok(xdrcheck_xdr::json_roundtrip(xdr_type, bytes, &self.limits)?)
    }

    /// As [`Oracle::render`] without JSON → bytes, for a variant whose `json_roundtrip` declares
    /// that half an exception (`verify` checks the exception is still needed).
    pub fn render_without_json_roundtrip(&self, xdr_type: &str, bytes: &[u8]) -> Result<Value> {
        if xdr_type == "LedgerCloseMeta" {
            self.gate.check(&xdrcheck_xdr::ledger_info(bytes)?)?;
        }
        Ok(xdrcheck_xdr::xdr_json(xdr_type, bytes, &self.limits)?)
    }
}

// ---------------------------------------------------------------------------------------------
// Sidecar storage, shared by render, synth, slice and verify.

/// Sidecar path of a blob, relative to the corpus root: `decoded/<aa>/<sha256>.json.zst`.
pub(crate) fn sidecar_rel(blob_sha: &str) -> String {
    xdrcheck_gen::output::sidecar::sidecar_rel(blob_sha)
}

/// Uncompressed sidecar content: compact JSON and a trailing newline.
pub(crate) fn sidecar_json(v: &Value) -> String {
    xdrcheck_gen::output::sidecar::sidecar_text(v)
}

/// The uncompressed content of a sidecar file.
pub(crate) fn read_sidecar_text(path: &Path) -> Result<Vec<u8>> {
    xdrcheck_gen::output::sidecar::read_sidecar(path)
}

/// Write a sidecar unless the file already holds exactly `text`. Returns whether it wrote.
pub(crate) fn write_sidecar(corpus: &Path, rel: &str, text: &str) -> Result<bool> {
    xdrcheck_gen::output::sidecar::write_sidecar(corpus, rel, text.as_bytes())
}

/// Remove (or with `check`, list) every file under `decoded/` that no manifest variant
/// references, and empty directories left behind.
pub(crate) fn collect_garbage(corpus: &Path, check: bool) -> Result<Vec<String>> {
    let mut referenced = HashSet::new();
    for id in all_entry_ids(corpus)? {
        let Ok(bytes) = std::fs::read(manifest_path(corpus, &id)) else {
            continue;
        };
        // An unreadable manifest keeps everything: never delete what might still be cited.
        let Ok(entry) = serde_json::from_slice::<Value>(&bytes) else {
            return Ok(vec![]);
        };
        for v in entry["variants"].as_array().into_iter().flatten() {
            if let Some(d) = v["decoded"].as_str() {
                referenced.insert(d.to_string());
            }
        }
    }
    let mut lines = Vec::new();
    let mut files = Vec::new();
    walk_files(&corpus.join("decoded"), &mut files)?;
    files.sort();
    for f in files {
        let rel = f
            .strip_prefix(corpus)
            .expect("under the corpus")
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        if referenced.contains(&rel) {
            continue;
        }
        if check {
            lines.push(format!("DRIFT {rel}: no variant references it"));
        } else {
            std::fs::remove_file(&f)?;
            lines.push(format!("removed {rel}"));
        }
    }
    if !check {
        remove_empty_dirs(&corpus.join("decoded"))?;
    }
    Ok(lines)
}

/// Remove (or with `check`, list) every blob (`blobs/**/*.xdr`) that no manifest variant and no
/// chain index references, and empty directories left behind. A variant references its `blob.path`
/// (else its content address), a chain index each row's `blob_sha256`. A manifest or chain index
/// that cannot be read keeps every blob: never delete what might still be cited.
pub(crate) fn collect_blob_garbage(corpus: &Path, check: bool) -> Result<Vec<String>> {
    let read = |p: &Path| -> Option<Value> {
        std::fs::read(p)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    };
    let mut referenced = HashSet::new();
    for id in all_entry_ids(corpus)? {
        let Some(entry) = read(&manifest_path(corpus, &id)) else {
            return Ok(vec![]);
        };
        for v in entry["variants"].as_array().into_iter().flatten() {
            referenced.insert(corpus_rel(corpus, &blob_path(corpus, v)));
        }
    }
    let mut chains = Vec::new();
    walk_files(&corpus.join("chains"), &mut chains)?;
    for c in chains
        .iter()
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
    {
        let Some(index) = read(c) else {
            return Ok(vec![]);
        };
        for row in index["ledgers"].as_array().into_iter().flatten() {
            if let Some(sha) = row["blob_sha256"].as_str() {
                referenced.insert(blob_rel(sha));
            }
        }
    }
    let mut lines = Vec::new();
    let mut files = Vec::new();
    walk_files(&corpus.join("blobs"), &mut files)?;
    files.sort();
    for f in files
        .iter()
        .filter(|p| p.extension().is_some_and(|x| x == "xdr"))
    {
        let rel = corpus_rel(corpus, f);
        if referenced.contains(&rel) {
            continue;
        }
        if check {
            lines.push(format!(
                "DRIFT {rel}: no variant or chain index references it"
            ));
        } else {
            std::fs::remove_file(f)?;
            lines.push(format!("removed {rel}"));
        }
    }
    if !check {
        remove_empty_dirs(&corpus.join("blobs"))?;
    }
    Ok(lines)
}

/// A path under the corpus root, relative to it, with `/` separators.
fn corpus_rel(corpus: &Path, p: &Path) -> String {
    p.strip_prefix(corpus)
        .unwrap_or(p)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn walk_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for e in std::fs::read_dir(dir)? {
        let p = e?.path();
        if p.is_dir() {
            walk_files(&p, out)?;
        } else {
            out.push(p);
        }
    }
    Ok(())
}

fn remove_empty_dirs(dir: &Path) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for e in std::fs::read_dir(dir)? {
        let p = e?.path();
        if p.is_dir() {
            remove_empty_dirs(&p)?;
            if std::fs::read_dir(&p)?.next().is_none() {
                std::fs::remove_dir(&p)?;
            }
        }
    }
    Ok(())
}

/// Nesting depth (arrays and objects) up to which `--print --pretty` indents.
pub(crate) const PRETTY_DEPTH: usize = 64;

/// Two-space pretty JSON up to [`PRETTY_DEPTH`], compact below it, and a trailing newline.
/// Identical to `serde_json::to_string_pretty` for shallower values.
pub(crate) fn pretty_json(v: &Value) -> String {
    let mut s = xdrcheck_xdr::with_stack(xdrcheck_xdr::DEFAULT_STACK_SIZE, || {
        let mut s = String::new();
        write_pretty(v, 0, &mut s);
        s
    });
    s.push('\n');
    s
}

fn write_pretty(v: &Value, depth: usize, out: &mut String) {
    let compact = |v: &Value| serde_json::to_string(v).expect("a JSON value serialises");
    if depth >= PRETTY_DEPTH {
        out.push_str(&compact(v));
        return;
    }
    let pad = |out: &mut String, d: usize| out.extend(std::iter::repeat_n("  ", d));
    match v {
        Value::Array(a) if !a.is_empty() => {
            out.push_str("[\n");
            for (i, x) in a.iter().enumerate() {
                pad(out, depth + 1);
                write_pretty(x, depth + 1, out);
                out.push_str(if i + 1 < a.len() { ",\n" } else { "\n" });
            }
            pad(out, depth);
            out.push(']');
        }
        Value::Object(m) if !m.is_empty() => {
            out.push_str("{\n");
            for (i, (k, x)) in m.iter().enumerate() {
                pad(out, depth + 1);
                out.push_str(&compact(&Value::String(k.clone())));
                out.push_str(": ");
                write_pretty(x, depth + 1, out);
                out.push_str(if i + 1 < m.len() { ",\n" } else { "\n" });
            }
            pad(out, depth);
            out.push('}');
        }
        other => out.push_str(&compact(other)),
    }
}

// ---------------------------------------------------------------------------------------------
// Manifest files

/// Manifest file text: two-space pretty JSON with non-ASCII escaped as `\uXXXX` (UTF-16) and a
/// trailing newline.
pub(crate) fn manifest_text(v: &Value) -> String {
    let pretty = serde_json::to_string_pretty(v).expect("a JSON value serialises");
    let mut s = String::with_capacity(pretty.len() + 1);
    for c in pretty.chars() {
        if c.is_ascii() {
            s.push(c);
        } else {
            // Non-ASCII characters only occur inside JSON strings, where an escape is equivalent.
            let mut buf = [0u16; 2];
            for unit in c.encode_utf16(&mut buf) {
                s.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    s.push('\n');
    s
}

/// Set `decoded`, `decoded_sha256` (of the uncompressed `text`) and `decoded_by` on a variant,
/// keeping the field order of an existing variant and inserting new fields after `blob`.
/// Set the variant fields the oracle derives (`docs/manifest.md` §4.2, §10.1): `requires`, placed
/// after `xdr_type` (and `framing` / `frame_index`), and `derived.l1`. With a sidecar (a positive
/// variant) both are derived; without one (a negative variant, whose bytes do not decode) an
/// existing `requires` is kept and a missing one becomes `[]`, and no `derived.l1` is implied.
pub(crate) fn set_derived_fields(
    v: &mut Value,
    bytes: &[u8],
    sidecar: Option<&str>,
    oracle: &Oracle,
) -> Result<()> {
    let xdr_type = v["xdr_type"].as_str().unwrap_or("").to_string();
    let requires = match sidecar {
        Some(text) => {
            json!(
                xdrcheck_meta::derive::requires_of_sidecar(&xdr_type, text.as_bytes(), &oracle.limits)
                    .map_err(|e| anyhow::anyhow!("requires: {e}"))?
            )
        }
        None => match &v["requires"] {
            Value::Array(a) => Value::Array(a.clone()),
            _ => json!([]),
        },
    };
    insert_after(
        v,
        &["xdr_type", "framing", "frame_index"],
        "requires",
        requires,
    );
    if sidecar.is_some() {
        let l1 = xdrcheck_meta::derive::l1(
            &xdr_type,
            bytes,
            v["passphrase"].as_str().unwrap_or(""),
            &v["focus"],
            &oracle.limits,
            &oracle.gate,
        )
        .map_err(|e| anyhow::anyhow!("derived.l1: {e}"))?;
        if l1.is_empty() {
            if let Some(d) = v.get_mut("derived").and_then(Value::as_object_mut) {
                d.remove("l1");
            }
        } else {
            if !v["derived"].is_object() {
                v["derived"] = json!({});
            }
            v["derived"]["l1"] = Value::Object(l1);
        }
    }
    Ok(())
}

/// Set `key` on an object, in place when present, else right after the last of `after` present.
fn insert_after(v: &mut Value, after: &[&str], key: &str, val: Value) {
    let Some(obj) = v.as_object_mut() else {
        return;
    };
    if let Some(slot) = obj.get_mut(key) {
        *slot = val;
        return;
    }
    let anchor = after.iter().rev().find(|k| obj.contains_key(**k)).copied();
    let old = std::mem::take(obj);
    let mut val = Some(val);
    for (k, x) in old {
        let here = Some(k.as_str()) == anchor;
        obj.insert(k, x);
        if here {
            obj.insert(key.to_string(), val.take().expect("inserted once"));
        }
    }
    if let Some(val) = val {
        obj.insert(key.to_string(), val);
    }
}

pub(crate) fn set_sidecar_fields(v: &mut Value, rel: &str, text: &str, decoded_by: &str) {
    let fields = [
        ("decoded", json!(rel)),
        (
            "decoded_sha256",
            json!(xdrcheck_xdr::sha256_hex(text.as_bytes())),
        ),
        ("decoded_by", json!(decoded_by)),
    ];
    let Some(obj) = v.as_object_mut() else {
        return;
    };
    if fields.iter().all(|(k, _)| obj.contains_key(*k)) {
        for (k, val) in fields {
            obj[k] = val;
        }
        return;
    }
    let mut out = serde_json::Map::new();
    let mut inserted = false;
    let old = std::mem::take(obj);
    for (k, val) in old {
        if fields.iter().any(|(f, _)| *f == k) {
            continue;
        }
        let after_blob = k == "blob";
        out.insert(k, val);
        if after_blob {
            for (f, val) in &fields {
                out.insert(f.to_string(), val.clone());
            }
            inserted = true;
        }
    }
    if !inserted {
        for (f, val) in fields {
            out.insert(f.to_string(), val);
        }
    }
    *obj = out;
}

pub(crate) fn manifest_path(corpus: &Path, id: &str) -> PathBuf {
    corpus.join("manifest").join(format!("{id}.json"))
}

/// A variant's blob file: `blob.path`, else the content address `blobs/<aa>/<sha256>.xdr`.
pub(crate) fn blob_path(corpus: &Path, v: &Value) -> PathBuf {
    match v["blob"]["path"].as_str() {
        Some(p) => corpus.join(p),
        None => {
            let sha = v["blob"]["sha256"].as_str().unwrap_or("");
            corpus.join(blob_rel(sha))
        }
    }
}

/// Content-addressed blob path relative to the corpus root.
pub(crate) fn blob_rel(sha: &str) -> String {
    format!("blobs/{}/{sha}.xdr", sha.get(..2).unwrap_or(""))
}

fn all_entry_ids(corpus: &Path) -> Result<Vec<String>> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
        for e in std::fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
            let p = e?.path();
            if p.is_dir() {
                walk(base, &p, out)?;
            } else if p.extension().is_some_and(|x| x == "json") {
                let rel = p.strip_prefix(base).expect("under base").with_extension("");
                out.push(
                    rel.components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("/"),
                );
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(&corpus.join("manifest"), &corpus.join("manifest"), &mut out)?;
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reading and re-writing every vendored manifest reproduces its bytes, so a tool that edits
    /// one field leaves the rest of the file alone.
    #[test]
    fn manifest_text_is_byte_faithful() {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
        let mut n = 0;
        for id in all_entry_ids(&corpus).unwrap() {
            let bytes = std::fs::read(manifest_path(&corpus, &id)).unwrap();
            let v: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(manifest_text(&v).as_bytes(), bytes.as_slice(), "{id}");
            n += 1;
        }
        assert!(n >= 3);
    }

    #[test]
    fn sidecar_frame_round_trips() {
        let text = sidecar_json(&json!({"a": [1, "b"], "c": {"d": null}}));
        assert_eq!(text, "{\"a\":[1,\"b\"],\"c\":{\"d\":null}}\n");
        let z = xdrcheck_gen::output::sidecar::compress_sidecar(text.as_bytes()).unwrap();
        // zstd magic, then a frame header whose descriptor has the checksum flag (bit 2) set.
        assert_eq!(&z[..4], &[0x28, 0xb5, 0x2f, 0xfd]);
        assert_ne!(z[4] & 0x04, 0);
        assert_eq!(
            zstd::stream::decode_all(z.as_slice()).unwrap(),
            text.as_bytes()
        );
        assert_eq!(sidecar_rel("ab12"), "decoded/ab/ab12.json.zst");
    }

    #[test]
    fn pretty_print_stops_indenting_deep_values() {
        xdrcheck_xdr::with_stack(xdrcheck_xdr::DEFAULT_STACK_SIZE, || {
            let mut v = json!("void");
            for _ in 0..750 {
                v = json!({ "vec": [v] });
            }
            let text = pretty_json(&v);
            assert!(text.len() < 20_000, "{} bytes", text.len());
            let back = xdrcheck_xdr::parse_json(text.as_bytes(), &Limits::default()).unwrap();
            assert!(back == v);
        });
        let shallow = json!({"a": [1, {"b": []}, {}], "c": "\u{2026}"});
        assert_eq!(
            pretty_json(&shallow),
            serde_json::to_string_pretty(&shallow).unwrap() + "\n"
        );
    }

    #[test]
    fn non_ascii_is_escaped_as_utf16() {
        let v = json!({"a": "x\u{2026}y\u{1F600}"});
        assert_eq!(
            manifest_text(&v),
            "{\n  \"a\": \"x\\u2026y\\ud83d\\ude00\"\n}\n"
        );
    }
}
