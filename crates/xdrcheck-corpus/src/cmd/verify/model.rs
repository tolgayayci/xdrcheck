//! Shared types of `verify`: the checks, one result row, the run context and the entry counts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use xdrcheck_xdr::{Gate, Limits};

/// One check of the oracle gate. Names are the report schema's `corpus.check` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Check {
    Schema,
    Ids,
    Hashes,
    Roundtrip,
    Reject,
    Sidecar,
    Pinpoints,
    Ag1,
    Ag3,
    Ag4,
    Extractor,
    Orphans,
    Spec,
}

impl Check {
    pub fn name(self) -> &'static str {
        match self {
            Check::Schema => "schema",
            Check::Ids => "ids",
            Check::Hashes => "hashes",
            Check::Roundtrip => "roundtrip",
            Check::Reject => "reject",
            Check::Sidecar => "sidecar",
            Check::Pinpoints => "pinpoints",
            Check::Ag1 => "ag1",
            Check::Ag3 => "ag3",
            Check::Ag4 => "ag4",
            Check::Extractor => "extractor",
            Check::Orphans => "orphans",
            Check::Spec => "spec",
        }
    }

    /// Parse a check name; `pinpoint` is accepted for `pinpoints`.
    pub fn parse(s: &str) -> Option<Check> {
        Some(match s {
            "schema" => Check::Schema,
            "ids" => Check::Ids,
            "hashes" => Check::Hashes,
            "roundtrip" => Check::Roundtrip,
            "reject" => Check::Reject,
            "sidecar" => Check::Sidecar,
            "pinpoints" | "pinpoint" => Check::Pinpoints,
            "ag1" => Check::Ag1,
            "ag3" => Check::Ag3,
            "ag4" => Check::Ag4,
            "extractor" => Check::Extractor,
            "orphans" => Check::Orphans,
            "spec" => Check::Spec,
            _ => return None,
        })
    }
}

/// One result: an entry (or a chain index, `corpus.json`, a bulk file) × variant × check.
#[derive(Debug, Clone)]
pub struct Row {
    pub check: Check,
    /// Entry ID; for non-entry subjects a path such as `chains/x/y.json` or `bulk:<file>`.
    pub entry: String,
    /// Variant key (`network` or `network@protocol`), when the check is per variant.
    pub variant: Option<String>,
    pub ok: bool,
    /// What failed (empty when ok, or a short note).
    pub detail: String,
    pub caps: Vec<i64>,
}

impl Row {
    pub fn new(check: Check, entry: &str, variant: Option<&str>, problems: Vec<String>) -> Row {
        Row {
            check,
            entry: entry.to_string(),
            variant: variant.map(str::to_string),
            ok: problems.is_empty(),
            detail: problems.join("; "),
            caps: Vec::new(),
        }
    }
}

/// How many entries of each kind were seen; printed so nothing is skipped silently
/// (`docs/manifest.md` §11: round-trip, reject and no-bytes groups are counted separately).
#[derive(Debug, Default, Clone)]
pub struct Counts {
    /// Group name → count (`ledger`, `xdr`, `xdr-negative`, `api`, `strkey`, `variants`, …).
    pub groups: BTreeMap<String, u64>,
}

impl Counts {
    pub fn add(&mut self, group: &str, n: u64) {
        *self.groups.entry(group.to_string()).or_default() += n;
    }
}

/// Everything a check needs besides the entry.
pub struct Ctx {
    pub corpus: PathBuf,
    /// A private overlay's corpus directory (`<overlay>/corpus`), merged with the public corpus:
    /// its manifests, blobs and sidecars are read as if they were in `corpus`, and its
    /// `plan-rows.json` adds to `plan.json` (`docs/conformance-protocol.md`, private overlay).
    pub overlay: Option<PathBuf>,
    pub limits: Limits,
    pub gate: Gate,
    pub goldens: PathBuf,
    /// `corpus.json`, when present.
    pub corpus_json: Option<Value>,
    /// AG-4: rewrite `mirrors.json` from a fresh search of the golden set before checking.
    pub write_mirrors: bool,
}

impl Ctx {
    pub fn new(corpus: &Path, goldens: PathBuf) -> Result<Ctx> {
        let cj = corpus.join("corpus.json");
        let corpus_json = if cj.is_file() {
            Some(
                serde_json::from_slice(&std::fs::read(&cj)?)
                    .with_context(|| format!("{} is not JSON", cj.display()))?,
            )
        } else {
            None
        };
        let gate = Gate::from_corpus_json(&cj)
            .with_context(|| format!("reading the gate from {}", cj.display()))?
            .unwrap_or_default();
        Ok(Ctx {
            corpus: corpus.to_path_buf(),
            overlay: None,
            limits: Limits::default(),
            gate,
            goldens,
            corpus_json,
            write_mirrors: false,
        })
    }

    /// The file at `rel` (a corpus-relative path such as `blobs/ab/<sha>.xdr`): in the public
    /// corpus when it is there, else in the overlay corpus when that has it, else the public path
    /// (so the error names the public location).
    pub fn resolve(&self, rel: &str) -> PathBuf {
        let public = self.corpus.join(rel);
        if let Some(ov) = &self.overlay {
            let o = ov.join(rel);
            if !public.exists() && o.exists() {
                return o;
            }
        }
        public
    }

    /// The corpus roots in reading order: the public corpus, then the overlay corpus.
    pub fn roots(&self) -> Vec<&Path> {
        std::iter::once(self.corpus.as_path())
            .chain(self.overlay.as_deref())
            .collect()
    }

    /// `p` relative to whichever corpus root holds it, for messages.
    pub fn shown(&self, p: &Path) -> String {
        for r in self.roots() {
            if let Ok(rel) = p.strip_prefix(r) {
                return rel.display().to_string();
            }
        }
        p.display().to_string()
    }
}
