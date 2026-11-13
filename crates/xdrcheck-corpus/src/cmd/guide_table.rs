//! `xdrcheck-corpus guide-table [--check]`: the guide's field-by-field table, generated from
//! `corpus/fields.yaml` joined with the manifest's `fields` citations, into the marker blocks of
//! `guide/indexer-hardening.mdx`: `{/* BEGIN GENERATED: fields <group> */}` … `{/* END GENERATED */}`.
//!
//! **Lines.** One line per row, or one per part for a row with parts, each with one status. Groups
//! (the guide page's table sections): envelope VF-01…12, preconditions VF-13…18, memo VF-19, muxed VF-20…21,
//! operations VF-22…40, soroban VF-41…52, events VF-53 and later.
//!
//! **Demonstration.** The entries in a line's last column are regenerated from the manifest: the
//! entries that cite the line's ID, or its row's ID, in their `fields` block and whose bytes exist
//! (every `ledger`/`xdr` variant's blob is present; `api`/`strkey` entries carry their vectors).
//! `demonstrated_by` in `fields.yaml` is the planning list; it is shown only for lines not yet
//! published.
//!
//! **Published or not.** A line is published when its verification is not `unverified`, its status
//! is not `undetermined`, and it has a demonstrating entry or a `no_demonstration_reason`. Every
//! other line is listed under the group's table with the reason it is not published yet.
//!
//! **Failing conditions** (guide-table), each reported as `condition N`:
//! 1. an entry cites a row or part ID that does not exist in `fields.yaml`;
//! 2. an entry cites a row or part under a status list that differs from its status there;
//! 3. a row or part published in the committed table has no citing entry with bytes and no
//!    `no_demonstration_reason`;
//! 4. an entry ID in `fields.yaml` or anywhere in the guide page is not canonical;
//! 5. a committed block differs from the generated one (only with `--check`; without it the blocks
//!    are rewritten);
//! 6. a row or part with verification `unverified` or status `undetermined` is published in the
//!    committed table.
//!
//! Also failures: a marker block missing or duplicated, a row outside every group, an unparsable
//! code reference. Exit 1 on any failure.
//!
//! **Report.** `--report FILE` also writes an `xcc.report/v1` file, written whether the check passes
//! or not: one `corpus` row (check `guide-table`) per entry that cites a row or part in its `fields`
//! block. A problem that names an entry fails that entry's row; a problem that names no entry (a
//! committed block that differs, a missing block) fails every row, since the table as a whole then
//! disagrees with the manifest.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use serde::Deserialize;

use super::coverage::data::{self, Entry};
use super::guide_claims::{entry_ids, repo_root, PAGE};

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Compare the committed blocks with the generated ones instead of rewriting them
    #[arg(long)]
    pub check: bool,
    /// Also write the result as an xcc.report/v1 file (one row per citing entry)
    #[arg(long, value_name = "FILE")]
    pub report: Option<PathBuf>,
}

/// `(group, first row number, last row number)`.
const GROUPS: [(&str, u32, u32); 7] = [
    ("envelope", 1, 12),
    ("preconditions", 13, 18),
    ("memo", 19, 19),
    ("muxed", 20, 21),
    ("operations", 22, 40),
    ("soroban", 41, 52),
    ("events", 53, 999),
];

const STATUS_LISTS: [&str; 3] = ["validated", "partially_validated", "passed_through"];

#[derive(Debug, Deserialize)]
struct FieldsFile {
    pins: Pins,
    fields: Vec<Row>,
}

#[derive(Debug, Deserialize)]
struct Pins {
    stellar_core: Pin,
    stellar_xdr: Pin,
    soroban_env_host: Pin,
}

#[derive(Debug, Deserialize)]
struct Pin {
    tag: Option<String>,
    commit: String,
}

#[derive(Debug, Deserialize)]
struct Row {
    id: String,
    field: String,
    controlled_by: String,
    status: String,
    #[serde(default)]
    core_checks: Vec<CoreCheck>,
    reader_may_assume: Option<String>,
    reader_must_not_assume: Option<String>,
    #[serde(default)]
    result_code_when_rejected: Vec<String>,
    verification: String,
    verification_note: Option<String>,
    #[serde(default)]
    unverified_parts: Vec<String>,
    #[serde(default)]
    parts: Vec<Part>,
    #[serde(default)]
    demonstrated_by: Vec<String>,
    no_demonstration_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CoreCheck {
    stage: String,
    what: String,
    code_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Part {
    id: String,
    aspect: String,
    status: String,
    verification: String,
}

/// One line of the table: a row, or one part of it.
struct Line<'a> {
    id: String,
    row: &'a Row,
    aspect: Option<&'a str>,
    status: &'a str,
    verification: &'a str,
    entries: Vec<&'a str>,
}

impl Line<'_> {
    /// Why the line is not published, or `None` when it is.
    fn withheld(&self) -> Option<String> {
        if self.verification == "unverified" || self.status == "undetermined" {
            let why = self
                .row
                .unverified_parts
                .first()
                .or(self.row.verification_note.as_ref())
                .map(|s| format!(": {s}"))
                .unwrap_or_default();
            return Some(format!("not yet established{why}"));
        }
        if self.entries.is_empty() && self.row.no_demonstration_reason.is_none() {
            let planned = if self.row.demonstrated_by.is_empty() {
                String::new()
            } else {
                format!(
                    " (planned: {})",
                    self.row
                        .demonstrated_by
                        .iter()
                        .map(|e| format!("`{e}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            return Some(format!(
                "no corpus entry with bytes demonstrates it yet{planned}"
            ));
        }
        None
    }
}

fn row_number(id: &str) -> Option<u32> {
    id.strip_prefix("VF-")?
        .trim_end_matches(|c: char| c.is_ascii_lowercase())
        .parse()
        .ok()
}

fn group_of(id: &str) -> Option<&'static str> {
    let n = row_number(id)?;
    GROUPS
        .iter()
        .find(|(_, a, b)| (*a..=*b).contains(&n))
        .map(|g| g.0)
}

/// Escape text for a GFM table cell in MDX: `|` everywhere; `{`, `}`, `<`, `>` and `*` outside
/// code spans.
fn esc(text: &str) -> String {
    let mut out = String::new();
    for (i, part) in text.split('`').enumerate() {
        if i > 0 {
            out.push('`');
        }
        for c in part.chars() {
            match c {
                '|' => out.push_str("\\|"),
                '{' | '}' | '<' | '>' | '*' if i % 2 == 0 => {
                    out.push('\\');
                    out.push(c);
                }
                '\n' => out.push(' '),
                _ => out.push(c),
            }
        }
    }
    out
}

/// Links for a code reference `[xdr:|env:]path:1-2, 5; path2:9` at the pinned commits.
fn code_links(r: &str, pins: &Pins) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for seg in r.split(';').map(str::trim) {
        let (path, ranges) = seg
            .rsplit_once(':')
            .filter(|(p, _)| !p.is_empty())
            .ok_or_else(|| format!("unparsable code reference {seg:?}"))?;
        let (base, path) = if let Some(p) = path.strip_prefix("xdr:") {
            (
                format!(
                    "https://github.com/stellar/stellar-xdr/blob/{}",
                    pins.stellar_xdr.commit
                ),
                p,
            )
        } else if let Some(p) = path.strip_prefix("env:") {
            (
                format!(
                    "https://github.com/stellar/rs-soroban-env/blob/{}",
                    pins.soroban_env_host.commit
                ),
                p,
            )
        } else {
            let at = pins
                .stellar_core
                .tag
                .clone()
                .unwrap_or_else(|| pins.stellar_core.commit.clone());
            (
                format!("https://github.com/stellar/stellar-core/blob/{at}"),
                path,
            )
        };
        let file = path.rsplit('/').next().unwrap_or(path);
        for range in ranges.split(',').map(str::trim) {
            let (a, b) = range.split_once('-').unwrap_or((range, range));
            let (a, b): (u32, u32) = match (a.parse(), b.parse()) {
                (Ok(a), Ok(b)) if a >= 1 && b >= a => (a, b),
                _ => return Err(format!("bad line range {range:?} in {seg:?}")),
            };
            out.push(if a == b {
                format!("[{file} L{a}]({base}/{path}#L{a})")
            } else {
                format!("[{file} L{a}-{b}]({base}/{path}#L{a}-L{b})")
            });
        }
    }
    Ok(out)
}

fn status_words(s: &str) -> &str {
    match s {
        "partially_validated" => "partially validated",
        "passed_through" => "passed through",
        other => other,
    }
}

const HEADER: &str = "| ID | Field | Controlled by | Status | What core checks, and where | You may assume | You must not assume | Rejected with | Demonstrated by |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n";

fn render_line(l: &Line, pins: &Pins, problems: &mut Vec<String>) -> String {
    let r = l.row;
    let field = match l.aspect {
        Some(a) => format!("{}: {}", esc(&r.field), esc(a)),
        None => esc(&r.field),
    };
    let checks: Vec<String> = r
        .core_checks
        .iter()
        .map(|c| {
            let links = match c.code_ref.as_deref().map(|x| code_links(x, pins)) {
                Some(Ok(v)) => format!(" ({})", v.join(", ")),
                Some(Err(e)) => {
                    problems.push(format!("{}: {e}", r.id));
                    String::new()
                }
                None => String::new(),
            };
            format!("{}: {}{links}", c.stage, esc(&c.what))
        })
        .collect();
    let codes: Vec<String> = r
        .result_code_when_rejected
        .iter()
        .map(|c| format!("`{c}`"))
        .collect();
    let demo = if l.entries.is_empty() {
        format!(
            "none: {}",
            esc(r.no_demonstration_reason.as_deref().unwrap_or(""))
        )
    } else {
        l.entries
            .iter()
            .map(|e| format!("`{e}`"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
        l.id,
        field,
        esc(&r.controlled_by),
        status_words(l.status),
        checks.join(" "),
        esc(r.reader_may_assume.as_deref().unwrap_or("")),
        esc(r.reader_must_not_assume.as_deref().unwrap_or("")),
        codes.join(", "),
        demo
    )
}

/// The generated blocks (group → content between the markers) and every problem with the sources.
struct Generated {
    blocks: BTreeMap<&'static str, String>,
    /// Line ID → withheld reason (`None` = published).
    lines: BTreeMap<String, Option<String>>,
}

fn generate(
    fields: &FieldsFile,
    entries: &[Entry],
    canon: &BTreeSet<String>,
    problems: &mut Vec<String>,
) -> Generated {
    let mut status: BTreeMap<&str, &str> = BTreeMap::new();
    for r in &fields.fields {
        status.insert(&r.id, &r.status);
        for p in &r.parts {
            status.insert(&p.id, &p.status);
        }
    }
    // Conditions 1 and 2; citations by entries with bytes.
    let mut cited: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for e in entries {
        for (list, ids) in &e.fields {
            for id in ids {
                match status.get(id.as_str()) {
                    None => problems.push(format!(
                        "condition 1: {} cites {id}, which is not a row or part in fields.yaml",
                        e.id
                    )),
                    Some(s) if !STATUS_LISTS.contains(&list.as_str()) || s != list => problems
                        .push(format!(
                            "condition 2: {} cites {id} under {list}, but fields.yaml says {s}",
                            e.id
                        )),
                    Some(_) => {}
                }
                if e.has_bytes() {
                    cited.entry(id.as_str()).or_default().insert(&e.id);
                }
            }
        }
    }
    // Condition 4 (fields.yaml side).
    for r in &fields.fields {
        for d in &r.demonstrated_by {
            if !canon.contains(d) {
                problems.push(format!(
                    "condition 4: fields.yaml {}: demonstrated_by {d:?} is not a canonical entry ID",
                    r.id
                ));
            }
        }
    }
    let mut published: BTreeMap<&str, String> = BTreeMap::new();
    let mut withheld: BTreeMap<&str, String> = BTreeMap::new();
    let mut lines_out = BTreeMap::new();
    for r in &fields.fields {
        let Some(group) = group_of(&r.id) else {
            problems.push(format!("{}: in no group of the guide's field table", r.id));
            continue;
        };
        let row_cites = cited.get(r.id.as_str()).cloned().unwrap_or_default();
        let mut lines = Vec::new();
        if r.parts.is_empty() {
            lines.push(Line {
                id: r.id.clone(),
                row: r,
                aspect: None,
                status: &r.status,
                verification: &r.verification,
                entries: row_cites.iter().copied().collect(),
            });
        } else {
            for p in &r.parts {
                let mut es = row_cites.clone();
                es.extend(cited.get(p.id.as_str()).into_iter().flatten().copied());
                lines.push(Line {
                    id: p.id.clone(),
                    row: r,
                    aspect: Some(&p.aspect),
                    status: &p.status,
                    verification: &p.verification,
                    entries: es.into_iter().collect(),
                });
            }
        }
        for l in lines {
            let why = l.withheld();
            match &why {
                None => published.entry(group).or_default().push_str(&render_line(
                    &l,
                    &fields.pins,
                    problems,
                )),
                Some(w) => withheld.entry(group).or_default().push_str(&format!(
                    "- {} {}{}: {}\n",
                    l.id,
                    esc(&r.field),
                    l.aspect
                        .map(|a| format!(", {}", esc(a)))
                        .unwrap_or_default(),
                    w
                )),
            }
            lines_out.insert(l.id.clone(), why);
        }
    }
    let mut blocks = BTreeMap::new();
    for (g, _, _) in GROUPS {
        let mut b = String::from("\n\n");
        if let Some(t) = published.get(g) {
            b.push_str(HEADER);
            b.push_str(t);
            b.push('\n');
        }
        if let Some(w) = withheld.get(g) {
            b.push_str("Not in this table until they are established and demonstrated:\n\n");
            b.push_str(w);
            b.push('\n');
        }
        blocks.insert(g, b);
    }
    Generated {
        blocks,
        lines: lines_out,
    }
}

/// The marker blocks of the page: group → (start, end) byte range of the content between them.
fn find_blocks(page: &str, problems: &mut Vec<String>) -> BTreeMap<String, (usize, usize)> {
    const BEGIN: &str = "{/* BEGIN GENERATED: fields ";
    const END: &str = "{/* END GENERATED */}";
    let mut out = BTreeMap::new();
    let mut at = 0;
    while let Some(i) = page[at..].find(BEGIN).map(|i| i + at) {
        let Some(close) = page[i..].find("*/}").map(|c| c + i) else {
            problems.push(format!("{PAGE}: unterminated BEGIN GENERATED marker"));
            break;
        };
        let group = page[i + BEGIN.len()..close].trim().to_string();
        let start = close + 3;
        let Some(end) = page[start..].find(END).map(|e| e + start) else {
            problems.push(format!(
                "{PAGE}: BEGIN GENERATED: fields {group} has no END GENERATED"
            ));
            break;
        };
        if out.insert(group.clone(), (start, end)).is_some() {
            problems.push(format!("{PAGE}: block fields {group} appears twice"));
        }
        at = end + END.len();
    }
    out
}

/// IDs of the lines published in a committed block (first cell of each table row).
fn published_ids(block: &str) -> Vec<String> {
    block
        .lines()
        .filter_map(|l| l.trim().strip_prefix('|'))
        .filter_map(|l| l.split('|').next())
        .map(|c| c.trim().to_string())
        .filter(|c| c.starts_with("VF-"))
        .collect()
}

pub fn run(corpus: &Path, args: Args) -> Result<ExitCode> {
    let root = repo_root(corpus);
    let fields_path = corpus.join("fields.yaml");
    let fields: FieldsFile = serde_yaml::from_str(
        &std::fs::read_to_string(&fields_path)
            .with_context(|| format!("read {}", fields_path.display()))?,
    )
    .with_context(|| format!("parse {}", fields_path.display()))?;
    let entries = data::entries(corpus)?;
    let canon = data::canonical_ids(corpus)?;
    let page_path = root.join(PAGE);
    let page = std::fs::read_to_string(&page_path)
        .with_context(|| format!("read {}", page_path.display()))?;

    let mut problems = Vec::new();
    let gen = generate(&fields, &entries, &canon, &mut problems);
    let blocks = find_blocks(&page, &mut problems);
    for (g, _, _) in GROUPS {
        if !blocks.contains_key(g) {
            problems.push(format!("{PAGE}: no block for fields {g}"));
        }
    }
    for g in blocks.keys() {
        if !GROUPS.iter().any(|x| x.0 == g) {
            problems.push(format!("{PAGE}: unknown block fields {g}"));
        }
    }
    // Conditions 3, 5 and 6 on the committed blocks.
    for (g, (s, e)) in &blocks {
        let committed = &page[*s..*e];
        for id in published_ids(committed) {
            match gen.lines.get(&id) {
                None => problems.push(format!(
                    "{PAGE}: block {g} publishes {id}, which is not a row or part in fields.yaml"
                )),
                Some(Some(why)) if why.starts_with("not yet established") => {
                    problems.push(format!("condition 6: {PAGE}: {id} is published but {why}"))
                }
                Some(Some(why)) => {
                    problems.push(format!("condition 3: {PAGE}: {id} is published but {why}"))
                }
                Some(None) => {}
            }
        }
        if args.check {
            if let Some(want) = gen.blocks.get(g.as_str()) {
                if committed != want {
                    problems.push(format!(
                        "condition 5: {PAGE}: block fields {g} differs from the table generated from fields.yaml and the manifest; run `xdrcheck-corpus guide-table`"
                    ));
                }
            }
        }
    }
    // Condition 4 (the page side).
    let groups: BTreeSet<String> = canon
        .iter()
        .filter_map(|i| i.split('/').next().map(str::to_string))
        .collect();
    let mut named: BTreeSet<String> = entry_ids(&page, &groups)
        .into_iter()
        .map(str::to_string)
        .collect();
    for b in gen.blocks.values() {
        named.extend(entry_ids(b, &groups).into_iter().map(str::to_string));
    }
    for id in &named {
        if !canon.contains(id) {
            problems.push(format!(
                "condition 4: {PAGE}: {id:?} is not a canonical entry ID"
            ));
        }
    }

    if !args.check {
        let mut out = String::new();
        let mut at = 0;
        let mut ordered: Vec<(&String, &(usize, usize))> = blocks.iter().collect();
        ordered.sort_by_key(|(_, (s, _))| *s);
        for (g, (s, e)) in ordered {
            out.push_str(&page[at..*s]);
            match gen.blocks.get(g.as_str()) {
                Some(b) => out.push_str(b),
                None => out.push_str(&page[*s..*e]),
            }
            at = *e;
        }
        out.push_str(&page[at..]);
        if out != page {
            std::fs::write(&page_path, &out)
                .with_context(|| format!("write {}", page_path.display()))?;
        }
        // The rewritten blocks are what the conditions above now see.
        problems.retain(|p| !p.starts_with("condition 3:") && !p.starts_with("condition 6:"));
    }
    let n_pub = gen.lines.values().filter(|w| w.is_none()).count();
    println!(
        "guide-table: {} lines ({} published, {} not yet), {} entries cite rows",
        gen.lines.len(),
        n_pub,
        gen.lines.len() - n_pub,
        entries.iter().filter(|e| !e.fields.is_empty()).count()
    );
    for p in &problems {
        println!("FAIL {p}");
    }
    if let Some(out) = &args.report {
        write_report(corpus, &root, &entries, &problems, out)
            .with_context(|| format!("write {}", out.display()))?;
    }
    Ok(if problems.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// Whether `text` names the entry `id`: an occurrence not continued by another ID character (a
/// family member `id.member` or a longer ID is a different entry).
fn names_entry(text: &str, id: &str) -> bool {
    text.match_indices(id).any(|(at, _)| {
        let rest = &text[at + id.len()..];
        let mut chars = rest.chars();
        match chars.next() {
            None => true,
            Some(c) if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/') => false,
            Some('.') => !chars.next().is_some_and(|c| c.is_ascii_alphanumeric()),
            Some(_) => true,
        }
    })
}

/// The `--report` file: one `guide-table` row per entry that cites the table.
fn write_report(
    corpus: &Path,
    root: &Path,
    entries: &[Entry],
    problems: &[String],
    out: &Path,
) -> Result<()> {
    use serde_json::{json, Value};
    let citing: Vec<&Entry> = entries.iter().filter(|e| !e.fields.is_empty()).collect();
    let general: Vec<&String> = problems
        .iter()
        .filter(|p| !citing.iter().any(|e| names_entry(p, &e.id)))
        .collect();
    let mut rows = Vec::new();
    let mut failures = 0usize;
    for e in &citing {
        let mine: Vec<&String> = problems
            .iter()
            .filter(|p| names_entry(p, &e.id))
            .chain(general.iter().copied())
            .collect();
        let ok = mine.is_empty();
        if !ok {
            failures += 1;
        }
        let mut corpus_block = json!({"check": "guide-table", "ok": ok});
        if !ok {
            let detail: Vec<&str> = mine.iter().map(|p| p.as_str()).collect();
            corpus_block["detail"] = json!(detail.join("; "));
        }
        let mut row = json!({
            "row_id": format!("corpus:guide-table:{}", e.id),
            "tool": "corpus",
            "entry": e.id,
            "target": {"name": "xdrcheck-corpus guide-table", "version": env!("CARGO_PKG_VERSION"), "kind": "oracle"},
            "failure": !ok,
            "expectation": if ok { "expected" } else { "unexpected" },
            "expected": {"source": "default", "result": "pass"},
            "corpus": corpus_block,
        });
        if !e.caps.is_empty() {
            row["caps"] = json!(e.caps);
        }
        rows.push(row);
    }
    let corpus_json: Option<Value> = std::fs::read_to_string(corpus.join("corpus.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok());
    let version = corpus_json
        .as_ref()
        .and_then(|c| c["corpus_version"].as_str())
        .unwrap_or("unversioned")
        .to_string();
    let report = json!({
        "schema": "xcc.report/v1",
        "header": {
            "tool": {"name": "xdrcheck-corpus guide-table", "version": env!("CARGO_PKG_VERSION")},
            "corpus": {"version": version, "manifest_sha256": super::verify::report::manifest_sha256(corpus)?},
            "pins": {"file_sha256": xdrcheck_xdr::sha256_file(&root.join("pins.toml"))?},
            "mode": {"suite": "guide-table", "overlay": false, "offline": "not-enforced"},
        },
        "rows": rows,
        "summary": {
            "rows": citing.len(),
            "failures": failures,
            "unexpected": failures,
            "failures_without_finding": 0,
            "by_result": {"guide-table ok": citing.len() - failures, "guide-table failed": failures},
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

#[cfg(test)]
mod report_tests {
    use super::names_entry;

    #[test]
    fn names_entry_respects_id_boundaries() {
        assert!(names_entry("entry cap-0038/a cites VF-99", "cap-0038/a"));
        assert!(names_entry("cites cap-0038/a.", "cap-0038/a"));
        assert!(names_entry("(cap-0038/a)", "cap-0038/a"));
        assert!(!names_entry("cap-0038/a.member cites VF-99", "cap-0038/a"));
        assert!(!names_entry("cap-0038/a-b cites VF-99", "cap-0038/a"));
        assert!(!names_entry("nothing here", "cap-0038/a"));
    }
}
