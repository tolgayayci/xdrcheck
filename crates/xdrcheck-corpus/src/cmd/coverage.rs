//! `xdrcheck-corpus coverage [--check]`: per-CAP coverage of the corpus. With `--arms`, per-arm
//! coverage instead ([`arms`]).
//!
//! Inputs: `corpus/caps.toml` (the CAP inventory as data: every CAP file of stellar-protocol, its
//! protocol, whether readers see a change, and the coverage row it counts under; plus the
//! protocol-gated and cross-cutting rows), the manifest (`corpus/manifest/`), and the entry plan
//! (`corpus/plan.json`).
//!
//! Outputs: `corpus/coverage.json` (frozen schema `coverage.schema.json`) and `corpus/COVERAGE.md`.
//! One row per reader-visible CAP group or other coverage group, with:
//! - `entries`: the manifest entries counting under it (an entry counts under the row of each CAP
//!   in its `caps` and under the row named by its ID's group);
//! - `by_source`: entries with at least one variant of each source kind;
//! - `twins`: entries with both a testnet and a pubnet variant; `mirrors`: local-core entries
//!   with a golden counterpart in `corpus/mirrors.json` (compared by AG-4);
//! - `gap_reason` when the row has no entry, or no twins: the reason stated in `caps.toml`, else
//!   the planned rows that will close the gap. The planned rows not yet in the corpus, with their
//!   priority, are listed in `COVERAGE.md` (the frozen JSON row has no field for them; their counts
//!   are in `totals`).
//!
//! `COVERAGE.md` ends with an "Arms" section: the committed-input tier of `--arms`, as covered and
//! uncovered arms and optional states per class of `corpus/arms.toml`, and the uncovered
//! `in-ledger` and `apply-time-result` ones by name. `--check` compares it like the rest of the file.
//!
//! Without `--check` the two files are written. `--check` writes nothing and fails (exit 1) when
//! a committed file differs from a fresh generation, or on any problem: a reader-visible row with
//! neither an entry nor a planned row nor a stated reason; a row with entries but no twins, no
//! planned twin row and no stated reason; an entry or planned row that counts under no row; a CAP
//! inventory that does not account for every CAP file once; output that fails the schema.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};

// `cmd/coverage/` would be caught by the `coverage/` ignore rule, so the module sits beside this file.
#[path = "arms.rs"]
pub mod arms;
#[path = "coverage_data.rs"]
pub mod data;
#[path = "arms_walk.rs"]
pub mod walk;

use data::{Entry, Planned};

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Compare with the committed files and check every row instead of writing
    #[arg(long, conflicts_with = "arms")]
    pub check: bool,
    #[command(flatten)]
    pub arm: arms::ArmArgs,
}

/// The source kinds of `by_source`, in schema order.
const SOURCES: [&str; 5] = [
    "local-core",
    "core-golden",
    "history",
    "history-archive",
    "synthetic",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapsFile {
    schema: String,
    stellar_protocol_commit: String,
    cap_files: usize,
    #[serde(default)]
    group: Vec<Record>,
    cap: Vec<Record>,
}

/// A `[[cap]]` or `[[group]]` record of `caps.toml`.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
struct Record {
    file: Option<String>,
    group: Option<String>,
    title: Option<String>,
    status: Option<String>,
    protocol: Option<u32>,
    protocol_note: Option<String>,
    #[serde(default = "yes")]
    reader_visible: bool,
    changed: Option<String>,
    reason: Option<String>,
    gap_reason: Option<String>,
    twins_reason: Option<String>,
}

fn yes() -> bool {
    true
}

/// One coverage row before counting.
#[derive(Debug, Clone)]
pub(crate) struct RowDef {
    pub(crate) group: String,
    title: String,
    protocol: Option<u32>,
    changed: String,
    gap_reason: Option<String>,
    twins_reason: Option<String>,
    /// CAP number for `cap-NNNN` rows.
    cap: Option<u32>,
    /// CAP files counted under it.
    files: Vec<String>,
}

impl RowDef {
    /// An entry or planned row with this ID group and these CAPs counts under the row.
    pub(crate) fn counts(&self, group: &str, caps: &[u32]) -> bool {
        group == self.group || self.cap.is_some_and(|c| caps.contains(&c))
    }
}

/// The CAP inventory, checked: every file once, reader-visible ones grouped, the others with a reason.
pub(crate) struct Inventory {
    caps: CapsFile,
    pub(crate) rows: Vec<RowDef>,
}

pub(crate) fn load_inventory(corpus: &Path, problems: &mut Vec<String>) -> Result<Inventory> {
    let path = corpus.join("caps.toml");
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let caps: CapsFile =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    ensure!(
        caps.schema == "xcc.caps/v1",
        "caps.toml: schema is not xcc.caps/v1"
    );
    let mut files = BTreeSet::new();
    let mut rows: BTreeMap<String, RowDef> = BTreeMap::new();
    for c in &caps.cap {
        let Some(file) = &c.file else {
            problems.push("caps.toml: a [[cap]] has no file".into());
            continue;
        };
        let stem = file.strip_suffix(".md").unwrap_or(file);
        let ok_name = stem.len() >= 8
            && stem.starts_with("cap-")
            && stem[4..8].bytes().all(|b| b.is_ascii_digit());
        if !ok_name {
            problems.push(format!(
                "caps.toml: {file} is not a cap-NNNN[-NN].md file name"
            ));
            continue;
        }
        if !files.insert(file.clone()) {
            problems.push(format!("caps.toml: {file} is listed twice"));
        }
        if c.title.is_none() || c.status.is_none() {
            problems.push(format!("caps.toml: {file} needs a title and a status"));
        }
        if !c.reader_visible {
            if c.reason.is_none() {
                problems.push(format!(
                    "caps.toml: {file} is not reader-visible and gives no reason"
                ));
            }
            continue;
        }
        let Some(group) = &c.group else {
            problems.push(format!(
                "caps.toml: {file} is reader-visible but names no group"
            ));
            continue;
        };
        let row = rows.entry(group.clone()).or_insert_with(|| RowDef {
            group: group.clone(),
            title: String::new(),
            protocol: None,
            changed: String::new(),
            gap_reason: None,
            twins_reason: None,
            cap: group.strip_prefix("cap-").and_then(|n| n.parse().ok()),
            files: Vec::new(),
        });
        row.files.push(file.clone());
        if stem == group {
            row.title = c.title.clone().unwrap_or_default();
            row.protocol = c.protocol;
            row.changed = c.changed.clone().unwrap_or_default();
            row.gap_reason = c.gap_reason.clone();
            row.twins_reason = c.twins_reason.clone();
        }
    }
    if files.len() != caps.cap_files {
        problems.push(format!(
            "caps.toml: {} CAP files listed, {} at stellar-protocol {}",
            files.len(),
            caps.cap_files,
            caps.stellar_protocol_commit
        ));
    }
    let mut out: Vec<RowDef> = Vec::new();
    for r in rows.into_values() {
        if r.title.is_empty() || r.changed.is_empty() {
            problems.push(format!(
                "caps.toml: row {} has no CAP file of its own name with a title and `changed`",
                r.group
            ));
        }
        out.push(r);
    }
    for g in &caps.group {
        let Some(group) = &g.group else {
            problems.push("caps.toml: a [[group]] has no group".into());
            continue;
        };
        if out.iter().any(|r| &r.group == group) {
            problems.push(format!("caps.toml: row {group} is defined twice"));
            continue;
        }
        if g.title.is_none() || g.changed.is_none() {
            problems.push(format!(
                "caps.toml: group {group} needs a title and `changed`"
            ));
        }
        out.push(RowDef {
            group: group.clone(),
            title: g.title.clone().unwrap_or_default(),
            protocol: g.protocol,
            changed: g.changed.clone().unwrap_or_default(),
            gap_reason: g.gap_reason.clone(),
            twins_reason: g.twins_reason.clone(),
            cap: None,
            files: Vec::new(),
        });
    }
    Ok(Inventory { caps, rows: out })
}

/// A counted coverage row.
struct Row<'a> {
    def: &'a RowDef,
    entries: Vec<&'a Entry>,
    missing: Vec<&'a Planned>,
    twins: usize,
    mirrors: usize,
    gap_reason: Option<String>,
}

fn priority_summary(missing: &[&Planned]) -> String {
    let n = |p: &str| missing.iter().filter(|m| m.priority == p).count();
    format!(
        "must {}, should {}, extra {}",
        n("M1-must"),
        n("should"),
        n("extra")
    )
}

fn count<'a>(
    inv: &'a Inventory,
    entries: &'a [Entry],
    plan: &'a [Planned],
    problems: &mut Vec<String>,
) -> Vec<Row<'a>> {
    let present: BTreeSet<&str> = entries.iter().map(|e| e.id.as_str()).collect();
    for e in entries {
        if !inv.rows.iter().any(|r| r.counts(e.group(), &e.caps)) {
            problems.push(format!("entry {} counts under no coverage row", e.id));
        }
        for c in &e.caps {
            let g = format!("cap-{c:04}");
            if !inv.rows.iter().any(|r| r.group == g) {
                problems.push(format!(
                    "entry {} cites CAP {c}, which caps.toml does not list as reader-visible",
                    e.id
                ));
            }
        }
    }
    for p in plan {
        if !inv.rows.iter().any(|r| r.counts(p.group(), &p.caps)) {
            problems.push(format!("planned {} counts under no coverage row", p.id));
        }
    }
    let mut rows = Vec::new();
    for def in &inv.rows {
        let es: Vec<&Entry> = entries
            .iter()
            .filter(|e| def.counts(e.group(), &e.caps))
            .collect();
        let missing: Vec<&Planned> = plan
            .iter()
            .filter(|p| def.counts(p.group(), &p.caps) && !present.contains(p.id.as_str()))
            .collect();
        let twins = es.iter().filter(|e| e.twin()).count();
        let mirrors = es.iter().filter(|e| e.golden_mirror).count();
        let mut parts = Vec::new();
        if es.is_empty() {
            if let Some(r) = &def.gap_reason {
                parts.push(r.clone());
            } else if !missing.is_empty() {
                parts.push(format!(
                    "no entry yet; {} planned ({})",
                    missing.len(),
                    priority_summary(&missing)
                ));
            } else {
                problems.push(format!(
                    "{}: reader-visible, but no entry, no planned row and no gap_reason in caps.toml",
                    def.group
                ));
            }
        }
        let twins_moot = es.is_empty() && def.gap_reason.is_some();
        if twins == 0 && !twins_moot {
            let planned_twins: Vec<&&Planned> = missing.iter().filter(|p| p.twin).collect();
            if let Some(r) = &def.twins_reason {
                parts.push(format!("no testnet and pubnet twins: {r}"));
            } else if let Some(first) = planned_twins.first() {
                parts.push(format!(
                    "no twins yet; planned with testnet and pubnet variants: {} (first {})",
                    planned_twins.len(),
                    first.id
                ));
            } else {
                problems.push(format!(
                    "{}: no entry with testnet and pubnet variants, no planned twin row and no twins_reason in caps.toml",
                    def.group
                ));
            }
        }
        rows.push(Row {
            def,
            entries: es,
            missing,
            twins,
            mirrors,
            gap_reason: (!parts.is_empty()).then(|| parts.join("; ")),
        });
    }
    rows
}

fn by_source(entries: &[&Entry]) -> BTreeMap<&'static str, usize> {
    SOURCES
        .iter()
        .map(|s| {
            (
                *s,
                entries
                    .iter()
                    .filter(|e| e.variants.iter().any(|(k, _)| k == s))
                    .count(),
            )
        })
        .collect()
}

fn coverage_json(
    version: &str,
    inv: &Inventory,
    rows: &[Row],
    entries: &[Entry],
    plan: &[Planned],
) -> Value {
    let mut out_rows = Vec::new();
    for r in rows {
        let bs = by_source(&r.entries);
        let mut by = serde_json::Map::new();
        for s in SOURCES {
            by.insert(s.into(), json!(bs[s]));
        }
        out_rows.push(json!({
            "group": r.def.group,
            "title": r.def.title,
            "protocol": r.def.protocol,
            "reader_visible": true,
            "entries": r.entries.iter().map(|e| e.id.clone()).collect::<Vec<_>>(),
            "by_source": by,
            "twins": r.twins,
            "mirrors": r.mirrors,
            "gap_reason": r.gap_reason,
        }));
    }
    let caps = &inv.caps.cap;
    let visible = caps.iter().filter(|c| c.reader_visible).count();
    let implemented =
        |c: &&Record| matches!(c.status.as_deref(), Some("Final") | Some("Implemented"));
    let present: BTreeSet<&str> = entries.iter().map(|e| e.id.as_str()).collect();
    let missing: Vec<&Planned> = plan
        .iter()
        .filter(|p| !present.contains(p.id.as_str()))
        .collect();
    let n_missing = |p: &str| missing.iter().filter(|m| m.priority == p).count();
    let all: Vec<&Entry> = entries.iter().collect();
    let src = by_source(&all);
    let mut totals = serde_json::Map::new();
    let mut t = |k: &str, v: usize| {
        totals.insert(k.into(), json!(v));
    };
    t("cap_files", caps.len());
    t("cap_files_reader_visible", visible);
    t(
        "cap_files_implemented_not_reader_visible",
        caps.iter()
            .filter(|c| !c.reader_visible && implemented(c))
            .count(),
    );
    t(
        "cap_files_not_implemented",
        caps.iter().filter(|c| !implemented(c)).count(),
    );
    t("rows", rows.len());
    t(
        "rows_cap",
        rows.iter().filter(|r| r.def.cap.is_some()).count(),
    );
    t(
        "rows_with_entries",
        rows.iter().filter(|r| !r.entries.is_empty()).count(),
    );
    t(
        "rows_with_twins",
        rows.iter().filter(|r| r.twins > 0).count(),
    );
    t(
        "rows_with_gap_reason",
        rows.iter().filter(|r| r.gap_reason.is_some()).count(),
    );
    t("entries", entries.len());
    t(
        "entries_with_twins",
        entries.iter().filter(|e| e.twin()).count(),
    );
    let local_core = |e: &&Entry| e.variants.iter().any(|(k, _)| k == "local-core");
    t(
        "entries_local_core_with_golden_mirror",
        entries
            .iter()
            .filter(local_core)
            .filter(|e| e.golden_mirror)
            .count(),
    );
    t(
        "entries_local_core_without_golden_mirror",
        entries
            .iter()
            .filter(local_core)
            .filter(|e| !e.golden_mirror)
            .count(),
    );
    t(
        "entries_local_core_with_golden_operations_only",
        entries
            .iter()
            .filter(local_core)
            .filter(|e| e.golden_operations)
            .count(),
    );
    for s in SOURCES {
        t(&format!("entries_{}", s.replace('-', "_")), src[s]);
    }
    t("planned", plan.len());
    t("planned_present", plan.len() - missing.len());
    t("planned_missing", missing.len());
    t("planned_missing_must", n_missing("M1-must"));
    t("planned_missing_should", n_missing("should"));
    t("planned_missing_extra", n_missing("extra"));
    // Entries with `caps: []`; each carries a `caps_note`.
    t(
        "entries_without_cap",
        entries.iter().filter(|e| e.caps.is_empty()).count(),
    );
    json!({
        "schema": "xcc.coverage/v1",
        "corpus_version": version,
        "rows": out_rows,
        "totals": totals,
    })
}

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn coverage_md(cov: &Value, inv: &Inventory, rows: &[Row]) -> String {
    let t = &cov["totals"];
    let mut md = String::new();
    md.push_str("# Corpus coverage by CAP\n\n");
    md.push_str("Generated by `xdrcheck-corpus coverage` from the manifest, `corpus/caps.toml` and the entry plan (`corpus/plan.json`). Do not edit; `xdrcheck-corpus coverage --check` fails when this file is stale.\n\n");
    md.push_str(&format!(
        "Corpus {}. stellar-protocol at `{}` has {} CAP files: {} change what a ledger reader sees and are counted in {} CAP rows below, {} are implemented with nothing new for a reader, {} are not implemented (accepted, draft or rejected). {} more rows cover protocol-gated changes without a CAP and cross-cutting encoding rules.\n\n",
        cov["corpus_version"].as_str().unwrap_or(""),
        inv.caps.stellar_protocol_commit,
        t["cap_files"], t["cap_files_reader_visible"], t["rows_cap"],
        t["cap_files_implemented_not_reader_visible"], t["cap_files_not_implemented"],
        t["rows"].as_u64().unwrap_or(0) - t["rows_cap"].as_u64().unwrap_or(0),
    ));
    md.push_str(&format!(
        "Entries: {} ({} with testnet and pubnet twins; of the local-core entries, {} match a golden transaction (mapped) and {} do not (unmapped), for {} of which every operation has a golden operation of the same shape). Planned: {}, of which {} are in the corpus and {} are not yet (must {}, should {}, extra {}). Rows with at least one entry: {} of {}; with twins: {}.\n\n",
        t["entries"], t["entries_with_twins"], t["entries_local_core_with_golden_mirror"],
        t["entries_local_core_without_golden_mirror"],
        t["entries_local_core_with_golden_operations_only"],
        t["planned"], t["planned_present"], t["planned_missing"],
        t["planned_missing_must"], t["planned_missing_should"], t["planned_missing_extra"],
        t["rows_with_entries"], t["rows"], t["rows_with_twins"],
    ));
    // Entries without a CAP count only under the row of their ID's group.
    let no_cap: Vec<String> = rows
        .iter()
        .filter_map(|r| {
            let n = r
                .entries
                .iter()
                .filter(|e| e.caps.is_empty() && e.group() == r.def.group)
                .count();
            (n > 0).then(|| format!("`{}` {n}", r.def.group))
        })
        .collect();
    md.push_str(&format!(
        "Entries without a CAP number: {}. Their pattern predates CAPs, shipped in a protocol upgrade without a CAP, or is an encoding rule, so no CAP number exists for it; such an entry has `caps: []` and a `caps_note` that says why, and is tagged with its protocol (`protocol.introduced`) and counted under the row of its group ({}).\n\n",
        t["entries_without_cap"],
        no_cap.join(", "),
    ));
    md.push_str("An entry counts under each CAP in its `caps` and under the group of its ID. Source columns count entries with at least one variant from that source. Twins: entries with both a testnet and a pubnet variant. Mirrors: local-core entries whose focus transaction has both the profile-free structural skeleton and the reduced shape tokens of a transaction in stellar-core's golden set, compared on both sets of bytes by AG-4 (`docs/manifest.md` section 4.7); `corpus/mirrors.json` lists them, the entries every operation of which has a golden operation of the same reduced shape (marked \"golden operations\" below; that tier says nothing about the envelope, fee processing or transaction-level meta), and every local-core entry that no golden covers. The section \"Golden operation shapes\" below gives the reverse view.\n\n");
    md.push_str("## Rows\n\n");
    md.push_str("| Row | Title | Protocol | Entries | local-core | core-golden | history | history-archive | synthetic | Twins | Mirrors | Planned, not yet in the corpus | Gap |\n");
    md.push_str(
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for (r, j) in rows
        .iter()
        .zip(cov["rows"].as_array().into_iter().flatten())
    {
        let b = &j["by_source"];
        let missing = if r.missing.is_empty() {
            "0".to_string()
        } else {
            format!("{} ({})", r.missing.len(), priority_summary(&r.missing))
        };
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            r.def.group,
            cell(&r.def.title),
            r.def.protocol.map_or("—".into(), |p| p.to_string()),
            r.entries.len(),
            b["local-core"],
            b["core-golden"],
            b["history"],
            b["history-archive"],
            b["synthetic"],
            r.twins,
            r.mirrors,
            missing,
            cell(r.gap_reason.as_deref().unwrap_or("—")),
        ));
    }
    md.push_str("\n## What each row covers\n\n");
    for r in rows {
        md.push_str(&format!(
            "- **{}** ({}): {}",
            r.def.group,
            cell(&r.def.title),
            r.def.changed
        ));
        if !r.def.files.is_empty() {
            md.push_str(&format!(". CAP files: {}", r.def.files.join(", ")));
        }
        md.push('\n');
        for e in &r.entries {
            let srcs: BTreeSet<&str> = e.variants.iter().map(|(k, _)| k.as_str()).collect();
            md.push_str(&format!(
                "  - `{}` ({}{}{})\n",
                e.id,
                srcs.into_iter().collect::<Vec<_>>().join(", "),
                if e.twin() { "; twins" } else { "" },
                if e.golden_mirror {
                    "; golden mirror"
                } else if e.golden_operations {
                    "; golden operations"
                } else {
                    ""
                },
            ));
        }
    }
    md.push_str("\n## Planned entries not yet in the corpus\n\n");
    for r in rows.iter().filter(|r| !r.missing.is_empty()) {
        md.push_str(&format!("### {}\n\n", r.def.group));
        for p in &r.missing {
            md.push_str(&format!(
                "- `{}` ({}{})\n",
                p.id,
                p.priority,
                if p.twin { ", testnet and pubnet" } else { "" }
            ));
        }
        md.push('\n');
    }
    md.push_str("## CAP files with no row of their own\n\n");
    md.push_str("| CAP file | Title | Status | Protocol | Why no entry |\n| --- | --- | --- | --- | --- |\n");
    for c in inv.caps.cap.iter().filter(|c| !c.reader_visible) {
        let protocol = c
            .protocol_note
            .clone()
            .or_else(|| c.protocol.map(|p| p.to_string()))
            .unwrap_or_else(|| "—".into());
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            c.file.as_deref().unwrap_or(""),
            cell(c.title.as_deref().unwrap_or("")),
            cell(c.status.as_deref().unwrap_or("")),
            cell(&protocol),
            cell(c.reason.as_deref().unwrap_or("")),
        ));
    }
    md
}

/// `corpus/mirrors.json` lists every local-core entry exactly once (`mapped` or `unmapped`) and no
/// other entry. AG-4 checks the same with the golden cache; this copy needs none, so an entry added
/// without `verify --checks ag4 --write-mirrors` fails here, in the per-pull-request coverage check.
fn mirror_list_problems(corpus: &Path, entries: &[Entry]) -> Result<Vec<String>> {
    if !corpus.join("mirrors.json").is_file() {
        return Ok(Vec::new());
    }
    let mapped = data::golden_mirrors(corpus, "mapped")?;
    let unmapped = data::golden_mirrors(corpus, "unmapped")?;
    let local: BTreeSet<&str> = entries
        .iter()
        .filter(|e| e.variants.iter().any(|(k, _)| k == "local-core"))
        .map(|e| e.id.as_str())
        .collect();
    let mut p = Vec::new();
    for id in &local {
        match (mapped.contains(*id), unmapped.contains(*id)) {
            (false, false) => p.push(format!(
                "corpus/mirrors.json does not list the local-core entry {id}; run `xdrcheck-corpus verify --checks ag4 --write-mirrors` (needs the golden cache: `make fetch`)"
            )),
            (true, true) => p.push(format!("corpus/mirrors.json lists {id} as both mapped and unmapped")),
            _ => {}
        }
    }
    for id in mapped.iter().chain(unmapped.iter()) {
        if !local.contains(id.as_str()) {
            p.push(format!("corpus/mirrors.json lists {id}, which is not a local-core entry"));
        }
    }
    Ok(p)
}

/// Sources whose bytes stellar-core emitted outside its own tests (a local run or a network).
const CORE_EMITTED: [&str; 3] = ["local-core", "history", "history-archive"];

/// The "Golden operation shapes" section of `COVERAGE.md` and its totals: every reduced operation
/// shape of the golden set (`corpus/mirrors.json`, `golden_operations`, written by `verify --checks
/// ag4 --write-mirrors`) and the corpus entries whose focus transaction holds it, computed now from
/// the corpus alone. Empty without the list.
fn golden_operations(m: &Value, corpus: &Path) -> Result<(String, Vec<(&'static str, u64)>)> {
    let g = &m["golden_operations"];
    let Some(shapes) = g["shapes"].as_array() else {
        return Ok((String::new(), Vec::new()));
    };
    let held = crate::cmd::verify::ag4_shape::corpus_op_shapes(corpus)?;
    let (mut core, mut imported, mut none) = (0u64, 0u64, 0u64);
    let mut by_type: BTreeMap<String, [u64; 4]> = BTreeMap::new();
    let mut uncovered = Vec::new();
    for s in shapes {
        let id = s["shape"].as_str().unwrap_or("");
        let op = s["op_type"].as_str().unwrap_or("").to_string();
        let row = by_type.entry(op).or_default();
        row[0] += 1;
        match held.get(id) {
            Some(k) if k.keys().any(|k| CORE_EMITTED.contains(&k.as_str())) => {
                core += 1;
                row[1] += 1;
            }
            Some(k) if !k.is_empty() => {
                imported += 1;
                row[2] += 1;
            }
            _ => {
                none += 1;
                row[3] += 1;
                uncovered.push(s);
            }
        }
    }
    let mut md = String::from("\n## Golden operation shapes\n\n");
    md.push_str(&format!(
        "The reverse view of AG-4: every reduced operation shape of stellar-core's golden set at `{}` (the scan's shape tokens of one operation: body, result, ledger-entry changes and Soroban contract events, with the meta-flag and timing parts removed; `docs/manifest.md` section 4.7; the list is `golden_operations` in `corpus/mirrors.json`), and whether a corpus entry's focus transaction has an operation of that shape. Of {} shapes, {core} are held by an entry whose bytes stellar-core emitted outside its own tests (local-core, history or history-archive), {imported} only by imported golden entries (the golden's own bytes), and {none} by no entry. A shape is a pattern of stellar-core's test suite, not necessarily a pattern a reader has trouble with; the uncovered ones are candidates, listed with the golden that first shows them.\n\n",
        m["core_tag"].as_str().unwrap_or(""),
        shapes.len(),
    ));
    md.push_str("| Operation | Golden shapes | Held by core-emitted entries | Only by imported goldens | Not held |\n| --- | --- | --- | --- | --- |\n");
    for (op, n) in &by_type {
        md.push_str(&format!("| {op} | {} | {} | {} | {} |\n", n[0], n[1], n[2], n[3]));
    }
    md.push_str("\n### Golden operation shapes no entry holds\n\n");
    let mut last = String::new();
    for s in uncovered {
        let op = s["op_type"].as_str().unwrap_or("");
        if op != last {
            md.push_str(&format!("\n- **{op}**\n"));
            last = op.to_string();
        }
        let gold = &s["golden"];
        md.push_str(&format!(
            "  - `{}` result `{}`: `{}` frame {} tx {} ({} golden transaction{})\n",
            s["shape"].as_str().unwrap_or(""),
            s["result"].as_str().unwrap_or(""),
            gold["file"].as_str().unwrap_or(""),
            gold["frame_index"],
            gold["tx_index"],
            s["golden_transactions"],
            if s["golden_transactions"] == 1 { "" } else { "s" },
        ));
    }
    let totals = vec![
        ("golden_operation_shapes", shapes.len() as u64),
        ("golden_operation_shapes_held_by_core_emitted_entries", core),
        ("golden_operation_shapes_held_only_by_imported_goldens", imported),
        ("golden_operation_shapes_not_held", none),
    ];
    Ok((md, totals))
}

/// The classes of `corpus/arms.toml`, in report order, with what each means.
const ARM_CLASSES: [(arms::Class, &str); 7] = [
    (arms::Class::InLedger, "built by stellar-core into ledgers"),
    (
        arms::Class::ApplyTimeResult,
        "a result code stellar-core can set while applying a transaction",
    ),
    (
        arms::Class::ValidationOnly,
        "set only while validating; a ledger never holds it",
    ),
    (
        arms::Class::StoredAsBytes,
        "in ledgers only as bytes (an upgrade set held in contract data)",
    ),
    (
        arms::Class::NeverBuilt,
        "valid to consensus, never built by stellar-core",
    ),
    (
        arms::Class::NotInLake,
        "built once, but the public lake's regenerated ledgers no longer hold it",
    ),
    (
        arms::Class::NotOnStandalone,
        "needs more than the one validator of a local standalone network",
    ),
];

/// The "Arms" section of `COVERAGE.md`: the curated tier of `xdrcheck-corpus coverage --arms`, as totals
/// per class and the uncovered `in-ledger` and `apply-time-result` arms and optional states by name.
fn arms_md(corpus: &Path) -> Result<String> {
    use walk::IdKind;
    let g = arms::gather(corpus, false, None, None)?;
    let rows = arms::rows(corpus, &g)?;
    let mut md = String::from("\n## Arms\n\n");
    md.push_str(&format!(
        "Generated from `xdrcheck-corpus coverage --arms` over the committed inputs ({} walked: manifest variants, chain meta streams, vendored lake objects). The universe is every union arm and optional-field state reachable from `{}` in the pinned XDR definitions. An arm is covered when a committed input holds it (or holds it inside upgrade-set bytes). Each arm's class comes from `corpus/arms.toml`; a `validation-only` or `never-built` class without indexer evidence is unverified, and its arms still count as uncovered.\n\n",
        g.inputs[0],
        arms::ROOT
    ));
    md.push_str("| Class | Meaning | Arms covered | Arms uncovered | Optional states covered | Optional states uncovered | Uncovered with the class unverified |\n| --- | --- | --- | --- | --- | --- | --- |\n");
    let count = |c: Option<arms::Class>, k: IdKind, covered: bool| {
        rows.iter()
            .filter(|r| c.is_none_or(|c| r.class == c) && r.kind == k && r.covered() == covered)
            .count()
    };
    let unverified = |c: Option<arms::Class>| {
        rows.iter()
            .filter(|r| c.is_none_or(|c| r.class == c) && r.unverified && !r.covered())
            .count()
    };
    for (c, meaning) in ARM_CLASSES {
        md.push_str(&format!(
            "| {} | {meaning} | {} | {} | {} | {} | {} |\n",
            c.name(),
            count(Some(c), IdKind::Arm, true),
            count(Some(c), IdKind::Arm, false),
            count(Some(c), IdKind::Opt, true),
            count(Some(c), IdKind::Opt, false),
            unverified(Some(c)),
        ));
    }
    md.push_str(&format!(
        "| **all** | | {} | {} | {} | {} | {} |\n",
        count(None, IdKind::Arm, true),
        count(None, IdKind::Arm, false),
        count(None, IdKind::Opt, true),
        count(None, IdKind::Opt, false),
        unverified(None),
    ));
    for c in [arms::Class::InLedger, arms::Class::ApplyTimeResult] {
        for (k, what) in [(IdKind::Arm, "arms"), (IdKind::Opt, "optional states")] {
            let names: Vec<&str> = rows
                .iter()
                .filter(|r| r.class == c && r.kind == k && !r.covered())
                .map(|r| r.label.as_str())
                .collect();
            if names.is_empty() {
                continue;
            }
            md.push_str(&format!(
                "\n### Uncovered {} {what} ({})\n\n",
                c.name(),
                names.len()
            ));
            for n in names {
                md.push_str(&format!("- `{n}`\n"));
            }
        }
    }
    Ok(md)
}

/// Validate the generated JSON against the frozen schema.
fn schema_errors(corpus: &Path, cov: &Value) -> Result<Vec<String>> {
    let path = corpus.join("schema/coverage.schema.json");
    let schema: Value = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("read {}", path.display()))?,
    )?;
    let v = jsonschema::draft202012::options()
        .build(&schema)
        .map_err(|e| anyhow::anyhow!("coverage schema does not compile: {e}"))?;
    Ok(v.iter_errors(cov)
        .map(|e| format!("coverage.json at {}: {e}", e.instance_path().as_str()))
        .collect())
}

/// Generate both files' text and every problem found.
pub fn generate(corpus: &Path) -> Result<(String, String, Vec<String>)> {
    let mut problems = Vec::new();
    let inv = load_inventory(corpus, &mut problems)?;
    let entries = data::entries(corpus)?;
    let plan = data::plan(corpus)?;
    let version = std::fs::read(corpus.join("corpus.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v["corpus_version"].as_str().map(str::to_string))
        .context("corpus.json has no corpus_version")?;
    let rows = count(&inv, &entries, &plan, &mut problems);
    let mut cov = coverage_json(&version, &inv, &rows, &entries, &plan);
    let (golden_md, golden_totals) = golden_operations(&data::mirrors(corpus)?, corpus)?;
    for (k, n) in golden_totals {
        cov["totals"][k] = json!(n);
    }
    problems.extend(schema_errors(corpus, &cov)?);
    let mut json_text = serde_json::to_string_pretty(&cov)?;
    json_text.push('\n');
    problems.extend(mirror_list_problems(corpus, &entries)?);
    let mut md = coverage_md(&cov, &inv, &rows);
    md.push_str(&golden_md);
    md.push_str(&arms_md(corpus)?);
    Ok((json_text, md, problems))
}

pub fn run(corpus: &Path, args: Args) -> Result<ExitCode> {
    if args.arm.arms {
        return arms::run(corpus, &args.arm);
    }
    let (json_text, md, mut problems) = generate(corpus)?;
    let json_path = corpus.join("coverage.json");
    let md_path = corpus.join("COVERAGE.md");
    if args.check {
        for (path, want) in [(&json_path, &json_text), (&md_path, &md)] {
            match std::fs::read_to_string(path) {
                Ok(have) if have == *want => {}
                Ok(_) => problems.push(format!(
                    "{} differs from a fresh generation; run `xdrcheck-corpus coverage`",
                    path.display()
                )),
                Err(_) => problems.push(format!(
                    "{} is missing; run `xdrcheck-corpus coverage`",
                    path.display()
                )),
            }
        }
    } else {
        std::fs::write(&json_path, &json_text)
            .with_context(|| format!("write {}", json_path.display()))?;
        std::fs::write(&md_path, &md).with_context(|| format!("write {}", md_path.display()))?;
    }
    let cov: Value = serde_json::from_str(&json_text)?;
    let t = &cov["totals"];
    println!(
        "coverage: {} rows ({} with entries, {} with twins), {} entries, {} CAP files, planned {} ({} missing: must {}, should {}, extra {})",
        t["rows"], t["rows_with_entries"], t["rows_with_twins"], t["entries"], t["cap_files"],
        t["planned"], t["planned_missing"], t["planned_missing_must"], t["planned_missing_should"], t["planned_missing_extra"]
    );
    for p in &problems {
        println!("FAIL {p}");
    }
    if problems.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}
