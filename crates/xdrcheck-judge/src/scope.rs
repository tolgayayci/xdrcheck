//! Per-target scope: what an indexer claims to export, declared once per target in a TOML file.
//!
//! A scope file names the row kinds the target exports and how each is compared (`[kinds.<row kind>]`), and
//! lists rules (`[[rule]]`) that move a verdict the target produces by design out of scope. Every rule names its
//! reason and cites the target's own code or documentation (`cite`), or says `UNCONFIRMED`. A verdict a rule
//! matches is written with `verdict: "out_of_scope"`, its original class and the rule id; nothing is dropped.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub target: String,
    /// The target commit or version the citations are read at.
    #[serde(default)]
    pub at: String,
    #[serde(default)]
    pub kinds: BTreeMap<String, KindScope>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

/// How rows of one kind are compared.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct KindScope {
    /// The fact family the rows are compared with: `balance_change`, `participant`, `entry_change`,
    /// `token_event`, `ledger` (default: the row kind itself).
    #[serde(default)]
    pub compare: Option<String>,
    /// `full` (missing and extra) or `extra_only` (a subset exporter: only what it wrote is checked).
    #[serde(default)]
    pub mode: Option<String>,
    /// Balance families: `net` (fees included) or `nofee` (operation parts only).
    #[serde(default)]
    pub fee: Option<String>,
    /// Entry family: lifecycle changes the target claims, `<entry_type>:<change>` (`account:created`).
    #[serde(default)]
    pub lifecycle: Option<Vec<String>>,
    /// Entry family: attribute families the target claims, `<entry_type>:<family>` (`account:signer`).
    #[serde(default)]
    pub fields: Option<Vec<String>>,
    /// Why this kind is compared the way it is, and where the target says so.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub cite: String,
}

impl KindScope {
    pub fn extra_only(&self) -> bool {
        self.mode.as_deref() == Some("extra_only")
    }
}

/// A rule moving matching verdicts out of scope. Every condition given must hold.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub reason: String,
    /// The target's own code or doc line that makes this by design, or `UNCONFIRMED`.
    pub cite: String,
    /// Row kinds (default: all).
    #[serde(default)]
    pub kinds: Vec<String>,
    /// Verdicts (`missing`, `extra`, `wrong_value`, …; default: any non-ok).
    #[serde(default)]
    pub verdicts: Vec<String>,
    /// Class prefixes (any).
    #[serde(default)]
    pub class_prefix: Vec<String>,
    /// First letter of the holder / participant address (any): `G`, `C`, `B`, `L`.
    #[serde(default)]
    pub holder_prefix: Vec<String>,
    /// The holder is the issuer of the asset.
    #[serde(default)]
    pub issuer_self: Option<bool>,
    /// The transaction failed (true) or succeeded (false).
    #[serde(default)]
    pub failed_tx: Option<bool>,
    /// Every truth role of the participant is in this list.
    #[serde(default)]
    pub roles_within: Vec<String>,
    /// Token event names (any).
    #[serde(default)]
    pub event: Vec<String>,
    /// Entry types (any).
    #[serde(default)]
    pub entry_type: Vec<String>,
}

pub fn load(p: &Path) -> Result<Scope> {
    let s = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
    let sc: Scope = toml::from_str(&s).with_context(|| format!("parse {}", p.display()))?;
    for r in &sc.rules {
        if r.id.is_empty() || r.reason.is_empty() || r.cite.is_empty() {
            bail!("{}: rule {:?} needs id, reason and cite", p.display(), r.id);
        }
    }
    for (k, ks) in &sc.kinds {
        if let Some(m) = &ks.mode {
            if m != "full" && m != "extra_only" {
                bail!("{}: kind {k}: mode must be full or extra_only", p.display());
            }
        }
        if let Some(f) = &ks.fee {
            if f != "net" && f != "nofee" {
                bail!("{}: kind {k}: fee must be net or nofee", p.display());
            }
        }
    }
    Ok(sc)
}

/// What a rule can see of one verdict.
pub struct Seen<'a> {
    pub kind: &'a str,
    pub verdict: &'a str,
    pub class: &'a str,
    pub evidence: &'a Value,
    pub success: Option<bool>,
}

fn ev_str<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| v.get(*k).and_then(Value::as_str))
}

impl Rule {
    pub fn matches(&self, s: &Seen<'_>) -> bool {
        if !self.kinds.is_empty() && !self.kinds.iter().any(|k| k == s.kind) {
            return false;
        }
        if !self.verdicts.is_empty() && !self.verdicts.iter().any(|v| v == s.verdict) {
            return false;
        }
        if !self.class_prefix.is_empty()
            && !self
                .class_prefix
                .iter()
                .any(|p| s.class.starts_with(p.as_str()))
        {
            return false;
        }
        let holder = ev_str(s.evidence, &["holder", "address"]);
        if !self.holder_prefix.is_empty() {
            let Some(h) = holder else { return false };
            if !self.holder_prefix.iter().any(|p| h.starts_with(p.as_str())) {
                return false;
            }
        }
        if let Some(want) = self.issuer_self {
            let issuer = ev_str(s.evidence, &["asset"]).and_then(crate::read::asset_issuer);
            let is = matches!((holder, issuer), (Some(h), Some(i)) if h == i);
            if is != want {
                return false;
            }
        }
        if let Some(want) = self.failed_tx {
            match s.success {
                Some(ok) if ok != want => {}
                _ => return false,
            }
        }
        if !self.roles_within.is_empty() {
            let Some(roles) = s.evidence.get("roles").and_then(Value::as_array) else {
                return false;
            };
            if roles.is_empty()
                || !roles.iter().all(|r| {
                    r.as_str()
                        .is_some_and(|r| self.roles_within.iter().any(|w| w == r))
                })
            {
                return false;
            }
        }
        if !self.event.is_empty() {
            let Some(e) = ev_str(s.evidence, &["event_name"]) else {
                return false;
            };
            if !self.event.iter().any(|x| x == e) {
                return false;
            }
        }
        if !self.entry_type.is_empty() {
            let Some(e) = ev_str(s.evidence, &["entry_type"]) else {
                return false;
            };
            if !self.entry_type.iter().any(|x| x == e) {
                return false;
            }
        }
        true
    }
}
