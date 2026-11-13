//! Output: the human summary on stdout and the `xcc.report/v1` file.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use serde_json::{json, Map, Value};

use super::load;
use super::model::{Check, Counts, Ctx, Row};
use super::Tier;

pub fn print_summary(tier: Tier, checks: &[Check], rows: &[Row], counts: &Counts) {
    let groups: Vec<String> = counts
        .groups
        .iter()
        .map(|(k, v)| format!("{k} {v}"))
        .collect();
    println!(
        "xdrcheck-corpus verify: tier {}; {}",
        tier.name(),
        groups.join(", ")
    );
    for &c in checks {
        let (pass, fail) = rows
            .iter()
            .filter(|r| r.check == c)
            .fold(
                (0, 0),
                |(p, f), r| if r.ok { (p + 1, f) } else { (p, f + 1) },
            );
        let note = if pass + fail == 0 {
            " (nothing it applies to)"
        } else {
            ""
        };
        println!("  {:<10} {pass:>5} pass {fail:>5} fail{note}", c.name());
    }
    for r in rows.iter().filter(|r| !r.ok) {
        let v = r
            .variant
            .as_deref()
            .map(|v| format!(" [{v}]"))
            .unwrap_or_default();
        println!("FAIL {} {}{v}: {}", r.check.name(), r.entry, r.detail);
    }
    let failed = rows.iter().filter(|r| !r.ok).count();
    println!(
        "result: {} ({} rows, {failed} failed)",
        if failed == 0 { "PASS" } else { "FAIL" },
        rows.len()
    );
}

/// sha256 of the manifest listing in `sha256sum` format (`<sha256>  manifest/<id>.json`, sorted by
/// path), which is what `corpus.json` `checksums.manifest` names.
pub(crate) fn manifest_sha256(corpus: &Path) -> Result<String> {
    let mut listing = String::new();
    for (rel, p) in load::json_files(&corpus.join("manifest"))? {
        let sha = xdrcheck_xdr::sha256_file(&p)?;
        listing.push_str(&format!("{sha}  manifest/{rel}.json\n"));
    }
    Ok(xdrcheck_xdr::sha256_hex(listing.as_bytes()))
}

/// [`manifest_sha256`] of the public and overlay manifests together (an overlay run's corpus).
fn merged_manifest_sha256(corpus: &Path, overlay: &Path) -> Result<String> {
    let mut lines = Vec::new();
    for root in [corpus, overlay] {
        for (rel, p) in load::json_files(&root.join("manifest"))? {
            let sha = xdrcheck_xdr::sha256_file(&p)?;
            lines.push((format!("manifest/{rel}.json"), sha));
        }
    }
    lines.sort();
    let listing: String = lines
        .iter()
        .map(|(rel, sha)| format!("{sha}  {rel}\n"))
        .collect();
    Ok(xdrcheck_xdr::sha256_hex(listing.as_bytes()))
}

pub fn write_report(
    ctx: &Ctx,
    tier: Tier,
    rows: &[Row],
    counts: &Counts,
    pins: &Path,
    out: &Path,
    wall: Duration,
) -> Result<()> {
    let cj = ctx.corpus_json.as_ref();
    let mut corpus = Map::new();
    corpus.insert(
        "version".into(),
        json!(cj
            .and_then(|c| c["corpus_version"].as_str())
            .unwrap_or("unversioned")),
    );
    corpus.insert(
        "manifest_sha256".into(),
        json!(match &ctx.overlay {
            None => manifest_sha256(&ctx.corpus)?,
            Some(ov) => merged_manifest_sha256(&ctx.corpus, ov)?,
        }),
    );
    if let Some(s) = cj.and_then(|c| c["entry_schema"].as_str()) {
        corpus.insert("schema".into(), json!(s));
    }
    corpus.insert("tier".into(), json!(tier.name()));

    let oracle_version = "30.0.0";
    let report_rows: Vec<Value> = rows
        .iter()
        .map(|r| {
            let mut row = Map::new();
            let vpart = r
                .variant
                .as_deref()
                .map(|v| format!(":{v}"))
                .unwrap_or_default();
            row.insert(
                "row_id".into(),
                json!(format!("corpus:{}:{}{vpart}", r.check.name(), r.entry)),
            );
            row.insert("tool".into(), json!("corpus"));
            row.insert("entry".into(), json!(r.entry));
            if let Some(v) = &r.variant {
                row.insert("variant".into(), json!(v));
            }
            row.insert(
                "target".into(),
                json!({
                    "name": "stellar-xdr",
                    "version": oracle_version,
                    "kind": "oracle",
                    "profile": format!("depth={}, len=input", ctx.limits.depth),
                }),
            );
            row.insert("failure".into(), json!(!r.ok));
            row.insert(
                "expectation".into(),
                json!(if r.ok { "expected" } else { "unexpected" }),
            );
            row.insert(
                "expected".into(),
                json!({"source": "default", "result": "pass"}),
            );
            if !r.caps.is_empty() {
                row.insert("caps".into(), json!(r.caps));
            }
            let mut corpus = Map::new();
            corpus.insert("check".into(), json!(r.check.name()));
            corpus.insert("ok".into(), json!(r.ok));
            if !r.detail.is_empty() {
                corpus.insert("detail".into(), json!(r.detail));
            }
            row.insert("corpus".into(), Value::Object(corpus));
            Value::Object(row)
        })
        .collect();

    let failures = rows.iter().filter(|r| !r.ok).count();
    let mut by_result: BTreeMap<String, u64> = BTreeMap::new();
    by_result.insert("pass".into(), (rows.len() - failures) as u64);
    by_result.insert("fail".into(), failures as u64);
    for (k, v) in &counts.groups {
        by_result.insert(format!("count:{k}"), *v);
    }

    let report = json!({
        "schema": "xcc.report/v1",
        "header": {
            // The name the frozen report format (xcc.report/v1) enumerates for this tool.
            "tool": {"name": "xcc-corpus verify", "version": env!("CARGO_PKG_VERSION")},
            "corpus": corpus,
            "pins": {
                "file_sha256": xdrcheck_xdr::sha256_file(pins)?,
                "values": {"stellar_xdr": oracle_version},
            },
            "mode": {"suite": format!("verify-{}", tier.name()), "overlay": ctx.overlay.is_some(), "offline": "not-enforced"},
            "run": {"wall_ms": wall.as_millis() as u64},
        },
        "rows": report_rows,
        "summary": {
            "rows": rows.len(),
            "failures": failures,
            "unexpected": failures,
            // Oracle rows never need a finding.
            "failures_without_finding": 0,
            "by_result": by_result,
        },
    });
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut text = serde_json::to_string_pretty(&report)?;
    text.push('\n');
    std::fs::write(out, text)?;
    Ok(())
}
