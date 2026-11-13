//! `xdrcheck-corpus coverage --arms`: union-arm and optional-state coverage of the corpus.
//!
//! The universe is every union case and every optional field state reachable from
//! `LedgerCloseMetaBatch` in the pinned XDR definitions ([`super::walk`]). Every input the corpus
//! holds is walked as typed XDR after the oracle accepts it:
//!
//! - **curated**: each manifest variant blob (by its `xdr_type`), each chain's vendored meta stream
//!   (`chains/*/*.meta.xdr.zst`) and each vendored lake object (`objects/<network>/<seq>/`);
//! - **bulk** (`--bulk`): stellar-core's golden tree for the current protocol in the cache, when
//!   fetched (`xdrcheck-corpus fetch-goldens`);
//! - **mined** (`--mined DIR`): ledgers kept by `xdrcheck-corpus mine` that are not yet entries.
//!
//! Each arm gets a source label from the best curated or mined input that hits it: `real`
//! (history, history-archive and vendored lake objects), `local-core` (local-core, core-golden and
//! chain streams), `synthetic`, else `bulk` or `none`; and a class from `corpus/arms.toml`
//! ([`Class`]): result-code arms are `apply-time-result` unless stellar-core only sets the code while
//! validating (`validation-only`); everything else is `in-ledger` unless the file says otherwise,
//! with a reason. Arms found only inside `ConfigUpgradeSet` bytes held in contract data are
//! counted for the `stored-as-bytes` class. A `validation-only` or `never-built` class takes an
//! arm out of the uncovered list only with indexer evidence (a zero count over full history);
//! without it the class is `unverified` and the summary still counts the arm as uncovered.
//!
//! `--universe SCSpecEntry` counts the arms reachable from `SCSpecEntry` instead, over the entries
//! of every `spec` manifest entry (each contract interface read by `xdrcheck_xdr::spec`).
//!
//! `--fail-on-regression` compares the curated covered set with a baseline file (`--baseline
//! PATH`, else `$XDRCHECK_OVERLAY/arms-baseline.txt`; the baseline is not part of the public corpus)
//! and fails (exit 1) when a baseline arm or state is no longer covered; with no baseline it says
//! so and passes. `--write-baseline` rewrites that file from the current corpus. `--report PATH`
//! writes the full table as JSON.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use xdrcheck_xdr::xdr::Limited;

use super::walk::{Defs, IdKind, Tally};

/// The most a chain stream or golden file read by the arm walk may decompress to (the lake-object cap).
const MAX_ARMS_INPUT: u64 = xdrcheck_xdr::batch::MAX_LAKE_OBJECT;

/// The root type of the arm universe.
pub const ROOT: &str = "LedgerCloseMetaBatch";
/// Source labels, best first.
pub const SOURCES: [&str; 3] = ["real", "local-core", "synthetic"];

/// The class of an arm or optional state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    /// Built by stellar-core into ledgers.
    InLedger,
    /// A result code stellar-core can set while applying a transaction.
    ApplyTimeResult,
    /// Set or accepted only while validating; a ledger never holds it.
    ValidationOnly,
    /// Exists in ledgers only as bytes (an upgrade set held in contract data).
    StoredAsBytes,
    /// Valid to consensus, never built by stellar-core.
    NeverBuilt,
    /// Built by stellar-core once, but the public lake's regenerated ledgers no longer hold it.
    NotInLake,
    /// Needs more than the one validator a local standalone network runs.
    NotOnStandalone,
}

impl Class {
    pub fn name(self) -> &'static str {
        match self {
            Class::InLedger => "in-ledger",
            Class::ApplyTimeResult => "apply-time-result",
            Class::ValidationOnly => "validation-only",
            Class::StoredAsBytes => "stored-as-bytes",
            Class::NeverBuilt => "never-built",
            Class::NotInLake => "not-in-lake",
            Class::NotOnStandalone => "not-on-standalone",
        }
    }

    /// Classes that take an arm out of the uncovered list, and so need indexer evidence.
    pub fn needs_evidence(self) -> bool {
        matches!(self, Class::ValidationOnly | Class::NeverBuilt)
    }
}

/// Whether an `evidence` value is the indexer evidence the exclusion classes need.
fn indexer_evidence(e: &str) -> Result<bool> {
    match e {
        "unverified" => Ok(false),
        e if e.starts_with("indexer:") && e.len() > "indexer:".len() + 8 => Ok(true),
        e => bail!(
            "evidence {e:?}: expected `unverified` or `indexer: <query, ledger range, count 0>`"
        ),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClassFile {
    schema: String,
    root: String,
    /// Result-code case names stellar-core sets only while validating (beyond `*_MALFORMED`).
    validation_only_codes: Vec<String>,
    /// Evidence for the default validation-only rule and `validation_only_codes`.
    validation_only_evidence: String,
    #[serde(default)]
    arm: Vec<Override>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Override {
    id: String,
    class: Class,
    reason: String,
    /// Required for `validation-only` and `never-built`: `unverified` or `indexer: …`.
    evidence: Option<String>,
}

/// Classes and reasons for every id of the universe.
pub struct Classes {
    pub class: BTreeMap<usize, Class>,
    pub reason: BTreeMap<usize, String>,
    /// Ids whose `validation-only` or `never-built` class has no indexer evidence.
    pub unverified: BTreeSet<usize>,
}

/// Load `corpus/arms.toml` and classify every id of `universe`.
pub fn classify(corpus: &Path, d: &Defs, universe: &[usize]) -> Result<Classes> {
    let path = corpus.join("arms.toml");
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let f: ClassFile =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    ensure!(
        f.schema == "xcc.arms/v1",
        "{}: schema {}",
        path.display(),
        f.schema
    );
    ensure!(f.root == ROOT, "{}: root {}", path.display(), f.root);
    let in_universe: BTreeSet<usize> = universe.iter().copied().collect();
    let vo: BTreeSet<&str> = f.validation_only_codes.iter().map(String::as_str).collect();
    let vo_verified = indexer_evidence(&f.validation_only_evidence)
        .with_context(|| format!("{}: validation_only_evidence", path.display()))?;
    let mut class = BTreeMap::new();
    let mut reason = BTreeMap::new();
    let mut unverified = BTreeSet::new();
    for &id in universe {
        let label = d.label(id);
        let c = match (d.kind(id), label.split_once("::")) {
            (IdKind::Arm, Some((union, case))) if is_result_union(d, union) => {
                if case.ends_with("_MALFORMED") || vo.contains(case) {
                    reason.insert(
                        id,
                        "stellar-core sets this code only while validating (doCheckValid or commonValid), so a transaction carrying it never reaches a ledger".to_string(),
                    );
                    if !vo_verified {
                        unverified.insert(id);
                    }
                    Class::ValidationOnly
                } else {
                    Class::ApplyTimeResult
                }
            }
            _ => Class::InLedger,
        };
        class.insert(id, c);
    }
    for code in &vo {
        ensure!(
            universe
                .iter()
                .any(|&i| d.label(i).split_once("::").is_some_and(|(_, c)| c == *code)),
            "{}: validation-only code {code} is no arm of the universe",
            path.display()
        );
    }
    let mut seen = BTreeSet::new();
    for o in f.arm {
        let id = d
            .id(&o.id)
            .filter(|i| in_universe.contains(i))
            .with_context(|| {
                format!("{}: {} is not in the {ROOT} universe", path.display(), o.id)
            })?;
        ensure!(
            seen.insert(id),
            "{}: {} is listed twice",
            path.display(),
            o.id
        );
        ensure!(
            !o.reason.trim().is_empty(),
            "{}: {} has no reason",
            path.display(),
            o.id
        );
        unverified.remove(&id);
        match (&o.evidence, o.class.needs_evidence()) {
            (Some(e), true) => {
                if !indexer_evidence(e).with_context(|| format!("{}: {}", path.display(), o.id))? {
                    unverified.insert(id);
                }
            }
            (None, true) => bail!(
                "{}: {} is {} without `evidence` (`unverified`, or `indexer: …` with a zero count over full history)",
                path.display(),
                o.id,
                o.class.name()
            ),
            (Some(_), false) => bail!(
                "{}: {} has `evidence`, which only validation-only and never-built take",
                path.display(),
                o.id
            ),
            (None, false) => {}
        }
        class.insert(id, o.class);
        reason.insert(id, o.reason);
    }
    Ok(Classes {
        class,
        reason,
        unverified,
    })
}

/// A union is a result union when its discriminant is a `*ResultCode` enum (the operation and
/// transaction result codes among them).
fn is_result_union(d: &Defs, union: &str) -> bool {
    d.discriminant_enum(union)
        .is_some_and(|e| e.ends_with("ResultCode"))
}

/// One walked input.
pub struct Input<'a> {
    /// Entry id (curated variants), or a corpus-relative path.
    pub label: String,
    pub tier: usize,
    /// Index into [`SOURCES`], or `None` for bulk.
    pub source: Option<usize>,
    /// Definition type name.
    pub xdr_type: &'a str,
    pub bytes: Vec<u8>,
}

/// Hits per tier and per source, plus up to three contributing inputs per id.
pub struct Gathered {
    pub tiers: [Tally; 3],
    pub sources: [Tally; 3],
    pub by: Vec<Vec<String>>,
    pub inputs: [usize; 3],
    pub skipped: Vec<String>,
}

/// Walk every input of the corpus; `exclude` drops the curated variants of one entry.
pub fn gather(
    corpus: &Path,
    bulk: bool,
    mined: Option<&Path>,
    exclude: Option<&str>,
) -> Result<Gathered> {
    let d = Defs::pinned();
    let mut g = Gathered {
        tiers: Default::default(),
        sources: Default::default(),
        by: vec![Vec::new(); d.len()],
        inputs: [0; 3],
        skipped: Vec::new(),
    };
    let limits = xdrcheck_xdr::Limits::default();
    xdrcheck_xdr::with_stack(limits.stack_size, || -> Result<()> {
        each_input(corpus, bulk, mined, exclude, &mut |inp: Input| {
            let mut t = Tally::default();
            let xl = limits.xdr(inp.bytes.len());
            let ok = match xdrcheck_xdr::type_variant(oracle_name(inp.xdr_type)) {
                Ok(v) => xdrcheck_xdr::xdr::Type::read_xdr_to_end(
                    v,
                    &mut Limited::new(std::io::Cursor::new(&inp.bytes), xl),
                )
                .is_ok(),
                Err(_) => false,
            };
            if !ok {
                g.skipped
                    .push(format!("{} (the oracle does not accept it)", inp.label));
                return Ok(());
            }
            d.walk(inp.xdr_type, &inp.bytes, &mut t)
                .with_context(|| format!("walk {}", inp.label))?;
            g.inputs[inp.tier] += 1;
            g.tiers[inp.tier].merge(&t);
            if let Some(s) = inp.source {
                g.sources[s].merge(&t);
            }
            for (id, (&n, &b)) in t.counts.iter().zip(&t.in_bytes).enumerate() {
                if (n > 0 || b > 0) && g.by[id].len() < 3 && !g.by[id].contains(&inp.label) {
                    g.by[id].push(inp.label.clone());
                }
            }
            Ok(())
        })
    })?;
    Ok(g)
}

/// The oracle's type name for a definition name (`SCVal` → `ScVal`).
fn oracle_name(def: &str) -> &str {
    match def {
        "SCVal" => "ScVal",
        other => other,
    }
}

fn source_of_kind(kind: &str) -> Option<usize> {
    match kind {
        "history" | "history-archive" => Some(0),
        "local-core" | "core-golden" => Some(1),
        "synthetic" => Some(2),
        _ => None,
    }
}

/// Every input, in a fixed order: manifest variants by path, chain streams, lake objects, bulk,
/// mined.
fn each_input(
    corpus: &Path,
    bulk: bool,
    mined: Option<&Path>,
    exclude: Option<&str>,
    f: &mut dyn FnMut(Input) -> Result<()>,
) -> Result<()> {
    let d = Defs::pinned();
    for path in files(&corpus.join("manifest"), ".json")? {
        let j: Value = serde_json::from_slice(&std::fs::read(&path)?)
            .with_context(|| format!("{} is not JSON", path.display()))?;
        let id = j["id"].as_str().unwrap_or_default().to_string();
        // Contract specs are not ledger data: they form the SCSpecEntry universe.
        if exclude == Some(id.as_str()) || j["kind"] == "spec" {
            continue;
        }
        for v in j["variants"].as_array().into_iter().flatten() {
            let (Some(blob), Some(ty)) = (v["blob"]["path"].as_str(), v["xdr_type"].as_str())
            else {
                continue;
            };
            let Some(def) = d.type_name(ty) else { continue };
            let bytes =
                std::fs::read(corpus.join(blob)).with_context(|| format!("{id}: read {blob}"))?;
            f(Input {
                label: id.clone(),
                tier: 0,
                source: source_of_kind(v["source"]["kind"].as_str().unwrap_or("")),
                xdr_type: def,
                bytes,
            })?;
        }
    }
    for path in files(&corpus.join("chains"), ".meta.xdr.zst")? {
        let label = rel(corpus, &path);
        let raw = xdrcheck_xdr::batch::decompress_bounded(&std::fs::read(&path)?, MAX_ARMS_INPUT)
            .with_context(|| format!("decompress {label}"))?;
        for r in xdrcheck_xdr::records(&raw) {
            let r = r.with_context(|| format!("{label}: framing"))?;
            f(Input {
                label: label.clone(),
                tier: 0,
                source: Some(1),
                xdr_type: "LedgerCloseMeta",
                bytes: r.payload.to_vec(),
            })?;
        }
    }
    for path in files(&corpus.join("objects"), ".xdr.zst")? {
        if path
            .components()
            .any(|c| c.as_os_str() == "history-archive")
        {
            continue;
        }
        batch_input(corpus, &path, 0, Some(0), f)?;
    }
    if bulk {
        let root = crate::cmd::intake::golden::cache_root()?
            .join("goldens")
            .join(bulk_tag(corpus)?)
            .join("test-lcm-current");
        if !root.is_dir() {
            bail!(
                "--bulk: no golden tree at {}; run `xdrcheck-corpus fetch-goldens`",
                root.display()
            );
        }
        for path in files(&root, ".xdr")? {
            let raw = std::fs::read(&path)?;
            let label = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .display()
                .to_string();
            for r in xdrcheck_xdr::records(&raw) {
                let Ok(r) = r else { break };
                f(Input {
                    label: label.clone(),
                    tier: 1,
                    source: None,
                    xdr_type: "LedgerCloseMeta",
                    bytes: r.payload.to_vec(),
                })?;
            }
        }
    }
    if let Some(dir) = mined {
        for path in files(dir, ".xdr.zst")? {
            batch_input(dir, &path, 2, Some(0), f)?;
        }
    }
    Ok(())
}

/// A zstd `LedgerCloseMetaBatch` object, walked as one `LedgerCloseMetaBatch`.
fn batch_input(
    base: &Path,
    path: &Path,
    tier: usize,
    source: Option<usize>,
    f: &mut dyn FnMut(Input) -> Result<()>,
) -> Result<()> {
    let label = rel(base, path);
    let raw = xdrcheck_xdr::batch::decompress_bounded(&std::fs::read(path)?, MAX_ARMS_INPUT)
        .with_context(|| format!("decompress {label}"))?;
    f(Input {
        label,
        tier,
        source,
        xdr_type: ROOT,
        bytes: raw,
    })
}

fn bulk_tag(corpus: &Path) -> Result<String> {
    let j: Value = serde_json::from_slice(&std::fs::read(corpus.join("corpus.json"))?)?;
    Ok(j["tiers"]["bulk"]["ref"]
        .as_str()
        .context("corpus.json has no tiers.bulk.ref")?
        .to_string())
}

fn rel(base: &Path, p: &Path) -> String {
    p.strip_prefix(base).unwrap_or(p).display().to_string()
}

/// Files under `dir` ending in `suffix`, sorted by path.
pub fn files(dir: &Path, suffix: &str) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd {
            let p = e?.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.to_string_lossy().ends_with(suffix) {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// The per-id table.
pub struct Row {
    pub label: String,
    pub kind: IdKind,
    pub class: Class,
    pub reason: Option<String>,
    /// A `validation-only` or `never-built` class without indexer evidence.
    pub unverified: bool,
    pub tiers: [u64; 3],
    pub in_bytes: u64,
    /// Best source label.
    pub source: &'static str,
    pub by: Vec<String>,
}

impl Row {
    /// Covered by committed corpus inputs (curated, or curated upgrade-set bytes).
    pub fn covered(&self) -> bool {
        self.tiers[0] > 0 || self.in_bytes > 0
    }
}

pub fn rows(corpus: &Path, g: &Gathered) -> Result<Vec<Row>> {
    let d = Defs::pinned();
    let universe = d.universe(ROOT)?;
    let cl = classify(corpus, d, &universe)?;
    Ok(universe
        .iter()
        .map(|&id| {
            let tiers = [g.tiers[0].hit(id), g.tiers[1].hit(id), g.tiers[2].hit(id)];
            let in_bytes = g.tiers[0].hit_in_bytes(id) + g.tiers[2].hit_in_bytes(id);
            let source = (0..3)
                .find(|&s| g.sources[s].hit(id) + g.sources[s].hit_in_bytes(id) > 0)
                .map(|s| SOURCES[s])
                .unwrap_or(if tiers[1] > 0 { "bulk" } else { "none" });
            Row {
                label: d.label(id).to_string(),
                kind: d.kind(id),
                class: cl.class[&id],
                reason: cl.reason.get(&id).cloned(),
                unverified: cl.unverified.contains(&id),
                tiers,
                in_bytes,
                source,
                by: g.by[id].clone(),
            }
        })
        .collect())
}

/// Baseline ids the current rows no longer cover.
pub fn regressions(rows: &[Row], baseline: &str) -> Vec<String> {
    let covered: BTreeSet<&str> = rows
        .iter()
        .filter(|r| r.covered())
        .map(|r| r.label.as_str())
        .collect();
    baseline
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| !covered.contains(l))
        .map(str::to_string)
        .collect()
}

/// The baseline file text for `rows`.
pub fn baseline_text(rows: &[Row]) -> String {
    let mut s = String::from(
        "# Arms and optional states of LedgerCloseMetaBatch (XDR 30.0) that committed corpus inputs cover.\n\
         # Written by `xdrcheck-corpus coverage --arms --write-baseline`; `--fail-on-regression` fails when one is lost.\n",
    );
    let mut ids: Vec<&str> = rows
        .iter()
        .filter(|r| r.covered())
        .map(|r| r.label.as_str())
        .collect();
    ids.sort();
    for id in ids {
        s.push_str(id);
        s.push('\n');
    }
    s
}

#[derive(clap::Args, Debug, Default)]
pub struct ArmArgs {
    /// Per-arm and per-optional-state coverage instead of the per-CAP table
    #[arg(long)]
    pub arms: bool,
    /// With --arms: fail when an arm or state of the baseline is no longer covered
    #[arg(long, requires = "arms")]
    pub fail_on_regression: bool,
    /// With --arms: rewrite the baseline from the current corpus
    #[arg(long, requires = "arms")]
    pub write_baseline: bool,
    /// With --arms: the baseline file (default `$XDRCHECK_OVERLAY/arms-baseline.txt`)
    #[arg(long, requires = "arms")]
    pub baseline: Option<PathBuf>,
    /// With --arms: also walk the cached golden tree (bulk tier)
    #[arg(long, requires = "arms")]
    pub bulk: bool,
    /// With --arms: also walk ledgers kept by `xdrcheck-corpus mine` under this directory
    #[arg(long, requires = "arms")]
    pub mined: Option<PathBuf>,
    /// With --arms: write the full table as JSON
    #[arg(long, requires = "arms")]
    pub report: Option<PathBuf>,
    /// With --arms: the root type whose arms are counted: LedgerCloseMetaBatch (ledger data), or
    /// SCSpecEntry (the entries of every `spec` entry's contract interface)
    #[arg(long, requires = "arms", default_value = ROOT)]
    pub universe: String,
}

/// The root of the contract-spec arm universe.
pub const SPEC_ROOT: &str = "SCSpecEntry";

/// Walk every `SCSpecEntry` of every `spec` manifest entry, read from its blob by the corpus's own
/// section reader; `exclude` drops one entry.
pub fn gather_spec(corpus: &Path, exclude: Option<&str>) -> Result<Gathered> {
    let d = Defs::pinned();
    let mut g = Gathered {
        tiers: Default::default(),
        sources: Default::default(),
        by: vec![Vec::new(); d.len()],
        inputs: [0; 3],
        skipped: Vec::new(),
    };
    for path in files(&corpus.join("manifest"), ".json")? {
        let j: Value = serde_json::from_slice(&std::fs::read(&path)?)
            .with_context(|| format!("{} is not JSON", path.display()))?;
        let id = j["id"].as_str().unwrap_or_default().to_string();
        if j["kind"] != "spec" || exclude == Some(id.as_str()) {
            continue;
        }
        for v in j["variants"].as_array().into_iter().flatten() {
            let Some(blob) = v["blob"]["path"].as_str() else {
                continue;
            };
            let Some(c) = xdrcheck_xdr::spec::Container::parse(v["container"].as_str().unwrap_or(""))
            else {
                g.skipped.push(format!("{id} (no container)"));
                continue;
            };
            let bytes =
                std::fs::read(corpus.join(blob)).with_context(|| format!("{id}: read {blob}"))?;
            let facts = xdrcheck_xdr::spec::read(&bytes, c);
            let source = match v["source"]["kind"].as_str().unwrap_or("") {
                "contract-code" => Some(0),
                k => source_of_kind(k),
            };
            let mut t = Tally::default();
            for &(off, len) in &facts.spans {
                d.walk(SPEC_ROOT, &bytes[off..off + len], &mut t)
                    .with_context(|| format!("walk {id} at byte {off}"))?;
            }
            g.inputs[0] += 1;
            g.tiers[0].merge(&t);
            if let Some(s) = source {
                g.sources[s].merge(&t);
            }
            for (i, &n) in t.counts.iter().enumerate() {
                if n > 0 && g.by[i].len() < 3 && !g.by[i].contains(&id) {
                    g.by[i].push(id.clone());
                }
            }
        }
    }
    Ok(g)
}

/// `--arms --universe SCSpecEntry`: arm coverage of the contract-spec entries. Every arm is of
/// class `in-ledger` here (a contract's interface is stored in its code, which a ledger holds).
fn run_spec(corpus: &Path, a: &ArmArgs) -> Result<std::process::ExitCode> {
    if a.bulk || a.mined.is_some() || a.write_baseline || a.fail_on_regression {
        bail!(
            "--universe {SPEC_ROOT}: --bulk, --mined and the baseline flags apply to {ROOT} only"
        );
    }
    let d = Defs::pinned();
    let g = gather_spec(corpus, None)?;
    let universe = d.universe(SPEC_ROOT)?;
    let rows: Vec<Row> = universe
        .iter()
        .map(|&id| Row {
            label: d.label(id).to_string(),
            kind: d.kind(id),
            class: Class::InLedger,
            reason: None,
            unverified: false,
            tiers: [g.tiers[0].hit(id), 0, 0],
            in_bytes: 0,
            source: (0..3)
                .find(|&s| g.sources[s].hit(id) > 0)
                .map(|s| SOURCES[s])
                .unwrap_or("none"),
            by: g.by[id].clone(),
        })
        .collect();
    for (kind, name) in [(IdKind::Arm, "arms"), (IdKind::Opt, "optional states")] {
        let all: Vec<&Row> = rows.iter().filter(|r| r.kind == kind).collect();
        println!(
            "{name}: covered {}/{} ({SPEC_ROOT} universe)",
            all.iter().filter(|r| r.covered()).count(),
            all.len()
        );
    }
    println!(
        "inputs: spec entries {}; skipped {}",
        g.inputs[0],
        g.skipped.len()
    );
    println!("id\tsource\tcurated\tby");
    for r in &rows {
        println!(
            "{}\t{}\t{}\t{}",
            r.label,
            r.source,
            r.tiers[0],
            r.by.join(",")
        );
    }
    if let Some(p) = &a.report {
        let j = json!({
            "schema": "xcc.arms.report/v1",
            "root": SPEC_ROOT,
            "definitions_sha256": super::walk::DEFINITIONS_SHA256,
            "inputs": {"curated": g.inputs[0], "bulk": 0, "mined": 0},
            "skipped": g.skipped,
            "rows": rows.iter().map(|r| json!({
                "id": r.label,
                "kind": match r.kind { IdKind::Arm => "arm", IdKind::Opt => "optional", IdKind::EnumValue => "enum" },
                "class": r.class.name(),
                "source": r.source,
                "curated": r.tiers[0],
                "covered": r.covered(),
                "by": r.by,
            })).collect::<Vec<_>>(),
        });
        std::fs::write(p, serde_json::to_string_pretty(&j)? + "\n")
            .with_context(|| format!("write {}", p.display()))?;
    }
    Ok(std::process::ExitCode::SUCCESS)
}

pub fn run(corpus: &Path, a: &ArmArgs) -> Result<std::process::ExitCode> {
    match a.universe.as_str() {
        ROOT => {}
        SPEC_ROOT => return run_spec(corpus, a),
        other => bail!("--universe {other}: want {ROOT} or {SPEC_ROOT}"),
    }
    let g = gather(corpus, a.bulk, a.mined.as_deref(), None)?;
    let rows = rows(corpus, &g)?;
    let baseline_path = a.baseline.clone().or_else(|| {
        std::env::var_os("XDRCHECK_OVERLAY")
            .filter(|o| !o.is_empty())
            .map(|o| PathBuf::from(o).join("arms-baseline.txt"))
    });
    for (kind, name) in [(IdKind::Arm, "arms"), (IdKind::Opt, "optional states")] {
        let all: Vec<&Row> = rows.iter().filter(|r| r.kind == kind).collect();
        let cov = |t: usize| all.iter().filter(|r| r.tiers[t] > 0).count();
        let any = all
            .iter()
            .filter(|r| r.covered() || r.tiers[1] > 0 || r.tiers[2] > 0)
            .count();
        println!(
            "{name}: covered {}/{} (curated {}, bulk {}, mined {}, any tier {any}; in upgrade-set bytes {})",
            all.iter().filter(|r| r.covered()).count(),
            all.len(),
            cov(0),
            cov(1),
            cov(2),
            all.iter().filter(|r| r.in_bytes > 0).count(),
        );
    }
    println!(
        "inputs: curated {}, bulk {}, mined {}; skipped {}",
        g.inputs[0],
        g.inputs[1],
        g.inputs[2],
        g.skipped.len()
    );
    let mut all = g.tiers[0].clone();
    all.merge(&g.tiers[2]);
    println!(
        "value classes (curated and mined): {}; deepest SCVal nesting {}",
        super::walk::Class::ALL
            .iter()
            .map(|c| format!("{} {}", c.name(), all.class(*c)))
            .collect::<Vec<_>>()
            .join(", "),
        all.max_scval_depth
    );
    let mut by_class: BTreeMap<(&str, bool), usize> = BTreeMap::new();
    let mut unverified: BTreeMap<&str, usize> = BTreeMap::new();
    for r in &rows {
        *by_class.entry((r.class.name(), r.covered())).or_default() += 1;
        if r.unverified && !r.covered() {
            *unverified.entry(r.class.name()).or_default() += 1;
        }
    }
    for c in [
        Class::InLedger,
        Class::ApplyTimeResult,
        Class::ValidationOnly,
        Class::StoredAsBytes,
        Class::NeverBuilt,
        Class::NotInLake,
        Class::NotOnStandalone,
    ] {
        let y = by_class.get(&(c.name(), true)).copied().unwrap_or(0);
        let n = by_class.get(&(c.name(), false)).copied().unwrap_or(0);
        let u = unverified.get(c.name()).copied().unwrap_or(0);
        let note = if u > 0 {
            format!(" ({u} uncovered with the class unverified)")
        } else {
            String::new()
        };
        println!("class {}: covered {y}/{}{note}", c.name(), y + n);
    }
    let excluded = rows
        .iter()
        .filter(|r| !r.covered() && r.class.needs_evidence() && !r.unverified)
        .count();
    println!(
        "uncovered: {} ({excluded} excluded by an evidenced validation-only or never-built class)",
        rows.iter().filter(|r| !r.covered()).count() - excluded
    );
    println!("id\tclass\tsource\tcurated\tbulk\tmined\tin-bytes");
    for r in &rows {
        println!(
            "{}\t{}{}\t{}\t{}\t{}\t{}\t{}",
            r.label,
            r.class.name(),
            if r.unverified { "?" } else { "" },
            r.source,
            r.tiers[0],
            r.tiers[1],
            r.tiers[2],
            r.in_bytes
        );
    }
    if let Some(p) = &a.report {
        let j = json!({
            "schema": "xcc.arms.report/v1",
            "root": ROOT,
            "definitions_sha256": super::walk::DEFINITIONS_SHA256,
            "inputs": {"curated": g.inputs[0], "bulk": g.inputs[1], "mined": g.inputs[2]},
            "skipped": g.skipped,
            "rows": rows.iter().map(|r| json!({
                "id": r.label,
                "kind": match r.kind { IdKind::Arm => "arm", IdKind::Opt => "optional", IdKind::EnumValue => "enum" },
                "class": r.class.name(),
                "class_unverified": r.unverified,
                "reason": r.reason,
                "source": r.source,
                "curated": r.tiers[0], "bulk": r.tiers[1], "mined": r.tiers[2],
                "in_upgrade_set_bytes": r.in_bytes,
                "covered": r.covered(),
                "by": r.by,
            })).collect::<Vec<_>>(),
        });
        std::fs::write(p, serde_json::to_string_pretty(&j)? + "\n")
            .with_context(|| format!("write {}", p.display()))?;
    }
    if a.write_baseline {
        let p = baseline_path
            .as_ref()
            .context("--write-baseline: give --baseline PATH or set XDRCHECK_OVERLAY")?;
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(p, baseline_text(&rows))
            .with_context(|| format!("write {}", p.display()))?;
        println!("wrote {}", p.display());
    }
    if a.fail_on_regression {
        let Some(baseline_path) = baseline_path.filter(|p| p.is_file()) else {
            println!(
                "--fail-on-regression: skipped, no baseline (give --baseline PATH or set XDRCHECK_OVERLAY to a directory holding arms-baseline.txt)"
            );
            return Ok(std::process::ExitCode::SUCCESS);
        };
        let text = std::fs::read_to_string(&baseline_path)
            .with_context(|| format!("read {}", baseline_path.display()))?;
        let lost = regressions(&rows, &text);
        if !lost.is_empty() {
            for l in &lost {
                eprintln!("regression: {l} is in the baseline but no committed input covers it");
            }
            return Ok(std::process::ExitCode::from(1));
        }
        let gained = rows.iter().filter(|r| r.covered()).count()
            - text
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                .count();
        println!(
            "no regression against {} ({gained} newly covered; --write-baseline records them)",
            baseline_path.display()
        );
    }
    Ok(std::process::ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
    }

    #[test]
    fn classes_cover_the_universe() {
        let c = corpus();
        let g = gather(&c, false, None, None).unwrap();
        let rows = rows(&c, &g).unwrap();
        let arms = rows.iter().filter(|r| r.kind == IdKind::Arm).count();
        let opts = rows.iter().filter(|r| r.kind == IdKind::Opt).count();
        assert_eq!((arms, opts), (499, 58));
        // The committed corpus covers itself: its own baseline has no regression.
        assert_eq!(
            regressions(&rows, &baseline_text(&rows)),
            Vec::<String>::new()
        );
        // Apply-time codes stellar-core sets while applying are not validation-only.
        for id in [
            "TransactionResultResult::txBAD_AUTH_EXTRA",
            "TransactionResultResult::txINSUFFICIENT_BALANCE",
        ] {
            let r = rows.iter().find(|r| r.label == id).unwrap();
            assert_eq!(r.class, Class::ApplyTimeResult, "{id}");
        }
        // No exclusion class is claimed without evidence: every validation-only and never-built
        // row is either evidenced or marked unverified, and the file holds no indexer evidence yet.
        assert!(rows
            .iter()
            .filter(|r| r.class.needs_evidence())
            .all(|r| r.unverified));
        assert!(rows
            .iter()
            .filter(|r| !r.class.needs_evidence())
            .all(|r| !r.unverified));
    }

    #[test]
    fn evidence_values() {
        assert!(!indexer_evidence("unverified").unwrap());
        assert!(
            indexer_evidence("indexer: result code count over ledgers 2..60000000 = 0").unwrap()
        );
        assert!(indexer_evidence("code reading").is_err());
    }

    #[test]
    fn spec_universe_is_covered_by_the_spec_entries() {
        let c = corpus();
        let d = Defs::pinned();
        let universe = d.universe(SPEC_ROOT).unwrap();
        let arms: Vec<usize> = universe
            .iter()
            .copied()
            .filter(|&i| d.kind(i) == IdKind::Arm)
            .collect();
        // 6 entry kinds, 26 type definitions, 2 union case kinds.
        assert_eq!(arms.len(), 34);
        let g = gather_spec(&c, None).unwrap();
        let covered = arms.iter().filter(|&&i| g.tiers[0].hit(i) > 0).count();
        assert!(covered >= 30, "{covered} of 34 SCSpecEntry arms covered");
        // The ledger universe does not walk contract specs.
        let lg = gather(&c, false, None, None).unwrap();
        assert!(lg.skipped.iter().all(|s| !s.starts_with("contract-spec/")));
    }

    #[test]
    fn removing_a_covering_entry_is_a_regression() {
        let c = corpus();
        let g = gather(&c, false, None, None).unwrap();
        let full = rows(&c, &g).unwrap();
        let baseline = baseline_text(&full);
        // An arm covered by exactly one input, and that input is a manifest entry.
        let manifest_ids: BTreeSet<String> = files(&c.join("manifest"), ".json")
            .unwrap()
            .iter()
            .map(|p| {
                let j: Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
                j["id"].as_str().unwrap().to_string()
            })
            .collect();
        let only = full
            .iter()
            .find(|r| r.covered() && r.by.len() == 1 && manifest_ids.contains(&r.by[0]))
            .expect("some arm is covered by one entry only");
        let entry = only.by[0].clone();
        let g2 = gather(&c, false, None, Some(&entry)).unwrap();
        let lost = regressions(&rows(&c, &g2).unwrap(), &baseline);
        assert!(lost.contains(&only.label), "{entry}: {lost:?}");
    }
}
