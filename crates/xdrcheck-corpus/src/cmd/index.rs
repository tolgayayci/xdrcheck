//! `xdrcheck-corpus index [--check]`: the flat entry index `corpus/index.json`.
//!
//! One row per manifest entry, so a consumer with only `jq` (or any JSON reader) finds an entry's
//! CAPs, kind, validity and bytes without walking `manifest/**`: `id`, `title`, `kind`, `caps`,
//! `rows` (the coverage rows of `COVERAGE.md` it counts under, the same rule as `xdrcheck-corpus
//! coverage`), `protocol`, `synthetic`, `validity`, `flags`, `sources` (the source kinds of its
//! variants), `tier` (`curated`, or `stress` for the entries a release archive ships in its
//! separate `stress/` root, `docs/release.md`), the manifest path, and per variant the network,
//! protocol, ledger, XDR type, validity, source kind, blob path and sha256, decoded sidecar path and
//! `decoded_sha256`, and `focus`. Paths are relative to the corpus root. Schema:
//! `corpus/schema/entry-index.schema.json`.
//!
//! The file is written with one entry per line, sorted by ID, so a diff shows changed entries. Per-arm
//! coverage is not repeated per entry (a ledger reaches hundreds of arms); `xdrcheck-corpus coverage
//! --arms --report FILE` lists the inputs that reach each arm.
//!
//! Without `--check` the file is written. `--check` writes nothing and fails (exit 1) when the
//! committed file differs from a fresh generation or a row fails the schema.
//!
//! `--plan` instead merges the plan fragments `corpus/plan.d/*.json` into `corpus/plan.json` ([`plan`]).
pub mod plan;

use std::path::Path;
use std::process::ExitCode;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use super::coverage;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Compare with the committed corpus/index.json instead of writing it
    #[arg(long)]
    pub check: bool,
    /// Merge the plan fragments corpus/plan.d/*.json into corpus/plan.json instead (with --check: fail when a
    /// fragment row is not in plan.json yet)
    #[arg(long)]
    pub plan: bool,
}

/// Schema ID of `index.json`.
pub const SCHEMA: &str = "xcc.index/v1";

/// A known divergence seen only under an address-space cap.
static AS_PROFILE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^address-space cap RLIMIT_AS [1-9][0-9]* ?(KiB|MiB|GiB)$").unwrap()
});

/// `docs/release.md` ("Stress entries"): the entries a release archive ships in its `stress/` root (the
/// `limits/` group, and entries with a known crash or hang, or a divergence seen only under an
/// address-space cap). The same rule as `scripts/release.sh`.
pub fn is_stress(e: &Value) -> bool {
    if e["id"].as_str().is_some_and(|i| i.starts_with("limits/")) {
        return true;
    }
    e["conformance"]["known_divergences"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|k| {
            (k["level"] != "replay"
                && matches!(k["outcome"].as_str(), Some("crash") | Some("hang")))
                || k["profile"]
                    .as_str()
                    .is_some_and(|p| AS_PROFILE.is_match(p))
        })
}

/// The index row of one manifest entry.
fn row(e: &Value, rows: &[String]) -> Value {
    let id = e["id"].as_str().unwrap_or_default();
    let validity = e["validity"].clone();
    let mut sources: Vec<&str> = Vec::new();
    let mut variants = Vec::new();
    for v in e["variants"].as_array().into_iter().flatten() {
        let kind = v["source"]["kind"].as_str().unwrap_or_default();
        if !sources.contains(&kind) {
            sources.push(kind);
        }
        variants.push(json!({
            "network": v["network"],
            "protocol": v["protocol"],
            "ledger_seq": v["ledger_seq"],
            "xdr_type": v["xdr_type"],
            "validity": if v["validity"].is_null() { validity.clone() } else { v["validity"].clone() },
            "source": kind,
            "blob": v["blob"]["path"],
            "sha256": v["blob"]["sha256"],
            "bytes": v["blob"]["bytes"],
            "decoded": v["decoded"],
            "decoded_sha256": v["decoded_sha256"],
            "focus": v["focus"],
        }));
    }
    sources.sort_unstable();
    let mut protocol = Map::new();
    protocol.insert("introduced".into(), e["protocol"]["introduced"].clone());
    if !e["protocol"]["removed"].is_null() {
        protocol.insert("removed".into(), e["protocol"]["removed"].clone());
    }
    json!({
        "id": id,
        "title": e["title"],
        "kind": e["kind"],
        "caps": e["caps"],
        "rows": rows,
        "protocol": protocol,
        "synthetic": e["synthetic"],
        "validity": validity,
        "flags": e["flags"].as_array().cloned().unwrap_or_default(),
        "sources": sources,
        "tier": if is_stress(e) { "stress" } else { "curated" },
        "manifest": format!("manifest/{id}.json"),
        "variants": variants,
    })
}

/// The index file's text: the header, then one compact entry per line.
pub fn generate(corpus: &Path) -> Result<(String, Value)> {
    let mut ignored = Vec::new();
    let inv = coverage::load_inventory(corpus, &mut ignored)?;
    let mut entries = Vec::new();
    for path in coverage::arms::files(&corpus.join("manifest"), ".json")? {
        let e: Value = serde_json::from_slice(&std::fs::read(&path)?)
            .with_context(|| format!("{} is not JSON", path.display()))?;
        let id = e["id"].as_str().unwrap_or_default();
        let group = id.split('/').next().unwrap_or_default();
        let caps: Vec<u32> = e["caps"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| c.as_u64().and_then(|c| u32::try_from(c).ok()))
            .collect();
        let rows: Vec<String> = inv
            .rows
            .iter()
            .filter(|r| r.counts(group, &caps))
            .map(|r| r.group.clone())
            .collect();
        entries.push(row(&e, &rows));
    }
    entries.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let mut text = format!("{{\n  \"schema\": \"{SCHEMA}\",\n  \"entries\": [\n");
    for (i, e) in entries.iter().enumerate() {
        text.push_str("    ");
        text.push_str(&serde_json::to_string(e)?);
        text.push_str(if i + 1 < entries.len() { ",\n" } else { "\n" });
    }
    text.push_str("  ]\n}\n");
    let value = json!({"schema": SCHEMA, "entries": entries});
    Ok((text, value))
}

fn schema_errors(corpus: &Path, index: &Value) -> Result<Vec<String>> {
    let schemas = super::verify::load::Schemas::load(corpus)?;
    Ok(schemas
        .errors("entry-index", index, 20)
        .into_iter()
        .map(|e| format!("index.json {e}"))
        .collect())
}

pub fn run(corpus: &Path, args: Args) -> Result<ExitCode> {
    if args.plan {
        return plan::run(corpus, args.check);
    }
    let (text, value) = generate(corpus)?;
    let mut problems = schema_errors(corpus, &value)?;
    let path = corpus.join("index.json");
    if args.check {
        match std::fs::read_to_string(&path) {
            Ok(have) if have == text => {}
            Ok(_) => problems.push(format!(
                "{} differs from a fresh generation; run `xdrcheck-corpus index`",
                path.display()
            )),
            Err(_) => problems.push(format!(
                "{} is missing; run `xdrcheck-corpus index`",
                path.display()
            )),
        }
    } else {
        std::fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    }
    let entries = value["entries"].as_array().map_or(0, Vec::len);
    println!(
        "index: {entries} entries{}",
        if args.check { " checked" } else { " written" }
    );
    for p in &problems {
        println!("FAIL {p}");
    }
    Ok(if problems.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stress_rule() {
        assert!(is_stress(&json!({"id": "limits/x"})));
        assert!(!is_stress(&json!({"id": "cap-0027/x"})));
        assert!(is_stress(
            &json!({"id": "a/b", "conformance": {"known_divergences": [
            {"level": "L0", "outcome": "crash"}]}})
        ));
        assert!(!is_stress(
            &json!({"id": "a/b", "conformance": {"known_divergences": [
            {"level": "replay", "outcome": "crash"}]}})
        ));
        assert!(is_stress(
            &json!({"id": "a/b", "conformance": {"known_divergences": [
            {"level": "L0", "outcome": "reject", "profile": "address-space cap RLIMIT_AS 4 GiB"}]}})
        ));
    }

    #[test]
    fn variant_validity_defaults_to_the_entry() {
        let e = json!({"id": "g/s", "validity": "malformed", "flags": ["trailing-bytes"],
            "protocol": {"introduced": 1},
            "variants": [{"network": "none", "blob": {"path": "blobs/aa/x.xdr", "sha256": "aa", "bytes": 1},
                "source": {"kind": "synthetic"}},
                {"network": "pubnet", "validity": "valid", "blob": {}, "source": {"kind": "history"}}]});
        let r = row(&e, &[]);
        assert_eq!(r["variants"][0]["validity"], "malformed");
        assert_eq!(r["variants"][1]["validity"], "valid");
        assert_eq!(r["sources"], json!(["history", "synthetic"]));
        assert_eq!(r["flags"], json!(["trailing-bytes"]));
        assert_eq!(r["tier"], "curated");
    }
}
