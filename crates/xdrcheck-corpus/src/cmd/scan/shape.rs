//! The shape of one ledger: components (`E A O R F M L`), their tokens (grammar `xcc.shape/v1`) and
//! their content-hash ids.
//!
//! A component is walked against the pinned definitions ([`Defs::walk_with`]) into a
//! [`TokenSink`]; the walk gives the type-level and place tokens (`T A O E L V S K`). The tokens that
//! need meaning (events `X`, ledger-entry changes `D`, operation-versus-effect relations `R`) are
//! read from the oracle's typed decode. Everything the emitter decides by name (sites, value
//! classes, vocabularies, class edges, relations) comes from [`Rules`], a data file.
//!
//! A token is `<kind>|<class>|<body>`. A component id at level `g` is
//! `sha256("xcc.shape/v1\n" g "\n" kind "\n" tokens…)[..16]` over the sorted tokens of the kinds
//! the level keeps; a transaction-shape id is the same hash over its component references.
use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use xdrcheck_xdr::xdr::{
    ContractEvent, ContractEventBody, GeneralizedTransactionSet, InnerTransactionResultResult,
    LedgerCloseMeta, LedgerEntry, LedgerEntryChange, LedgerEntryData, LedgerUpgrade,
    Limits as XdrLimits, Operation, OperationBody, OperationResult, ReadXdr, ScAddress, ScVal,
    TransactionEnvelope, TransactionExt, TransactionMeta, TransactionPhase, TransactionResult,
    TransactionResultResult, TxSetComponent, WriteXdr,
};

use crate::cmd::coverage::walk::{Class, Defs, Sink, Ty};

pub const RULES_V1: &str = include_str!("../../../data/scan-rules-v1.toml");

/// A 16-byte content id.
pub type Id = [u8; 16];

pub fn hex16(id: &Id) -> String {
    hex::encode(id)
}

/// The rules file.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct RulesFile {
    pub grammar: String,
    pub levels: BTreeMap<String, Vec<String>>,
    pub classes: ClassEdges,
    pub walk: WalkRules,
    pub values: Vec<ValueRule>,
    pub events: EventRules,
    pub changes: ChangeRules,
    pub relations: Vec<String>,
    #[serde(default)]
    pub drop_kinds: Vec<String>,
    #[serde(default)]
    pub drop_classes: Vec<String>,
    #[serde(default)]
    pub skipped_protocols: Vec<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ClassEdges {
    pub len: Vec<u64>,
    pub depth: Vec<u64>,
    pub nodes: Vec<u64>,
    pub count: Vec<u64>,
    pub ops: Vec<u64>,
    pub op_mult: Vec<u64>,
}

#[derive(Debug, Deserialize)]
pub struct WalkRules {
    pub sites: Vec<String>,
    pub summarised: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ValueRule {
    #[serde(rename = "type")]
    pub ty: Option<String>,
    pub field: Option<String>,
    pub leaf: Option<String>,
    pub class: String,
}

#[derive(Debug, Deserialize)]
pub struct EventRules {
    pub symbols: Vec<String>,
    pub map_keys: Vec<String>,
    pub u64band_keys: Vec<String>,
    pub max_topics: usize,
    pub max_keys: usize,
}

#[derive(Debug, Deserialize)]
pub struct ChangeRules {
    pub ignore: Vec<String>,
    pub per_byte: Vec<String>,
    pub old_new: Vec<String>,
}

/// Class label of `n` under `edges` (inclusive upper bounds): `0`, `3-4`, `>100`.
pub fn class_of(n: u64, edges: &[u64]) -> String {
    let mut lo = 0u64;
    for (i, &e) in edges.iter().enumerate() {
        if n <= e {
            // The first class is named by its edge alone (`0`, `1`): values start there.
            let from = if i == 0 { e } else { lo };
            return if from == e {
                e.to_string()
            } else {
                format!("{from}-{e}")
            };
        }
        lo = e + 1;
    }
    format!(">{}", edges.last().copied().unwrap_or(0))
}

/// The rules resolved against the definitions.
pub struct Rules {
    pub file: RulesFile,
    pub sha256: String,
    sites: BTreeSet<usize>,
    summarised: BTreeSet<usize>,
    type_values: BTreeMap<usize, String>,
    field_values: BTreeMap<(usize, String), String>,
    field_names: HashSet<String>,
    utf8: bool,
    pub symbols: BTreeSet<Vec<u8>>,
    pub map_keys: BTreeSet<Vec<u8>>,
    drop_kinds: BTreeSet<String>,
    drop_classes: BTreeSet<String>,
    pub mute_e: BTreeSet<usize>,
    pub mute_o: BTreeSet<usize>,
    pub mute_r: BTreeSet<usize>,
    pub mute_m: BTreeSet<usize>,
    pub mute_l: BTreeSet<usize>,
    pub none: BTreeSet<usize>,
    /// `T` token text per (class, id), `None` when the rules drop it.
    t_text: Vec<Option<String>>,
}

impl Rules {
    pub fn parse(text: &str, defs: &Defs) -> Result<Rules> {
        let file: RulesFile = toml::from_str(text).context("scan rules")?;
        if file.grammar != "xcc.shape/v1" {
            bail!("rules grammar {} is not xcc.shape/v1", file.grammar);
        }
        let idx = |n: &str| {
            defs.def_index(n)
                .with_context(|| format!("rules: no definition {n}"))
        };
        let set =
            |names: &[&str]| -> Result<BTreeSet<usize>> { names.iter().map(|n| idx(n)).collect() };
        let mut type_values = BTreeMap::new();
        let mut field_values = BTreeMap::new();
        let mut utf8 = false;
        for v in &file.values {
            match (&v.ty, &v.field, &v.leaf) {
                (Some(t), None, None) => {
                    type_values.insert(idx(t)?, v.class.clone());
                }
                (None, Some(f), None) => {
                    let (s, fname) = f.split_once('.').context("rules: field is Struct.field")?;
                    field_values.insert((idx(s)?, fname.to_string()), v.class.clone());
                }
                (None, None, Some(l)) if l == "string" => utf8 = true,
                _ => bail!("rules: a value rule names one of type, field, leaf=string"),
            }
        }
        let sites = file
            .walk
            .sites
            .iter()
            .map(|s| idx(s))
            .collect::<Result<_>>()?;
        let summarised = file
            .walk
            .summarised
            .iter()
            .map(|s| idx(s))
            .collect::<Result<_>>()?;
        let mut rules = Rules {
            sha256: xdrcheck_xdr::sha256_hex(text.as_bytes()),
            sites,
            summarised,
            type_values,
            field_names: field_values
                .keys()
                .map(|k: &(usize, String)| k.1.clone())
                .collect(),
            field_values,
            utf8,
            symbols: file
                .events
                .symbols
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
            map_keys: file
                .events
                .map_keys
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
            drop_kinds: file.drop_kinds.iter().cloned().collect(),
            drop_classes: file.drop_classes.iter().cloned().collect(),
            mute_e: set(&["Operation"])?,
            mute_o: set(&["SorobanAuthorizationEntry"])?,
            mute_r: set(&["OperationResult"])?,
            mute_m: set(&["OperationMeta", "OperationMetaV2"])?,
            mute_l: set(&[
                "TransactionEnvelope",
                "TransactionResultMeta",
                "TransactionResultMetaV1",
            ])?,
            none: BTreeSet::new(),
            t_text: Vec::new(),
            file,
        };
        let n = defs.len();
        rules.t_text = (0..T_CLASSES.len() * n)
            .map(|i| {
                let (c, id) = (T_CLASSES[i / n], i % n);
                rules
                    .keep("T", c)
                    .then(|| format!("T|{c}|{}", defs.label(id)))
            })
            .collect();
        Ok(rules)
    }

    pub fn len_class(&self, n: u64) -> String {
        class_of(n, &self.file.classes.len)
    }

    fn keep(&self, kind: &str, class: &str) -> bool {
        !self.drop_kinds.contains(kind) && !self.drop_classes.contains(class)
    }
}

/// A token set under construction.
#[derive(Default)]
pub struct Tokens(pub BTreeSet<String>);

impl Tokens {
    pub fn add(&mut self, rules: &Rules, kind: &str, class: &str, body: String) {
        if rules.keep(kind, class) {
            self.0.insert(format!("{kind}|{class}|{body}"));
        }
    }
}

struct Site {
    def: usize,
    path: String,
    arm_ids: BTreeSet<usize>,
    extra: BTreeSet<&'static str>,
    cur: u64,
    depth: u64,
    nodes: u64,
}

/// The token emitter: a [`Sink`] that follows the path and turns walk events into tokens.
pub struct TokenSink<'a> {
    defs: &'a Defs,
    rules: &'a Rules,
    mute: &'a BTreeSet<usize>,
    pub tokens: Tokens,
    path: String,
    seg_starts: Vec<usize>,
    /// Whether each pushed segment was written to `path` (paths are kept only in full mode).
    seg_real: Vec<bool>,
    defs_in: Vec<usize>,
    muted: u32,
    tonly: u32,
    site: Option<Site>,
    /// Type-level ids seen, a bit per (class index, id); turned into `T` tokens by [`TokenSink::done`].
    t_ids: Vec<u64>,
    /// 128-bit hashes of place tokens already emitted (to skip building duplicates).
    seen: HashSet<u128, std::hash::BuildHasherDefault<PassHasher>>,
}

/// A hasher for keys that are already hashes.
#[derive(Default)]
pub struct PassHasher(u64);

impl std::hash::Hasher for PassHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, b: &[u8]) {
        for c in b.chunks(8) {
            let mut w = [0u8; 8];
            w[..c.len()].copy_from_slice(c);
            self.0 ^= u64::from_le_bytes(w);
        }
    }
    fn write_u128(&mut self, v: u128) {
        self.0 = (v as u64) ^ ((v >> 64) as u64);
    }
}

/// Two independent multiply-rotate hashes over the parts, with their lengths (128 bits).
pub fn h128(parts: &[&[u8]]) -> u128 {
    const K1: u64 = 0x517c_c1b7_2722_0a95;
    const K2: u64 = 0x9e37_79b9_7f4a_7c15;
    let (mut a, mut b) = (0x243f_6a88_85a3_08d3u64, 0x1319_8a2e_0370_7344u64);
    let mut mix = |w: u64| {
        a = (a.rotate_left(5) ^ w).wrapping_mul(K1);
        b = (b.rotate_left(7) ^ w).wrapping_mul(K2);
    };
    for p in parts {
        mix(p.len() as u64);
        let (words, r) = p.as_chunks::<8>();
        for w in words {
            mix(u64::from_le_bytes(*w));
        }
        if !r.is_empty() {
            let mut w = [0u8; 8];
            w[..r.len()].copy_from_slice(r);
            mix(u64::from_le_bytes(w));
        }
    }
    ((a as u128) << 64) | b as u128
}

const T_CLASSES: [&str; 5] = ["arm", "opt", "enum", "bytes", "elemopt"];

impl<'a> TokenSink<'a> {
    pub fn new(defs: &'a Defs, rules: &'a Rules, mute: &'a BTreeSet<usize>) -> TokenSink<'a> {
        TokenSink {
            defs,
            rules,
            mute,
            tokens: Tokens::default(),
            path: String::new(),
            seg_starts: Vec::new(),
            seg_real: Vec::new(),
            defs_in: Vec::new(),
            muted: 0,
            tonly: 0,
            site: None,
            t_ids: vec![0; (T_CLASSES.len() * defs.len()).div_ceil(64)],
            seen: HashSet::default(),
        }
    }

    /// Walk one part of a component under `root` (`env`, `op`, `meta`…).
    pub fn walk(&mut self, root: &str, ty: &str, vector: bool, bytes: &[u8]) -> Result<()> {
        self.path.clear();
        self.path.push_str(root);
        self.defs.walk_with(ty, vector, bytes, self)
    }

    /// The component's sorted tokens.
    pub fn done(mut self) -> Vec<String> {
        let n = self.defs.len();
        let bits = std::mem::take(&mut self.t_ids);
        for (w, word) in bits.iter().enumerate() {
            let mut x = *word;
            while x != 0 {
                let i = w * 64 + x.trailing_zeros() as usize;
                x &= x - 1;
                let (c, id) = (i / n, i % n);
                if let Some(t) = &self.rules.t_text[i] {
                    self.tokens.0.insert(t.clone());
                } else if self.rules.t_text.is_empty() {
                    let label = self.defs.label(id).to_string();
                    self.tokens.add(self.rules, "T", T_CLASSES[c], label);
                }
            }
        }
        self.tokens.0.into_iter().collect()
    }

    fn full(&self) -> bool {
        self.muted == 0 && self.tonly == 0 && self.site.is_none()
    }

    fn add(&mut self, kind: &str, class: &str, body: String) {
        self.tokens.add(self.rules, kind, class, body);
    }

    /// Emit a place token `<path><parts…>` once.
    fn place(&mut self, kind: &str, class: &str, parts: &[&str]) {
        let mut hp: Vec<&[u8]> = Vec::with_capacity(parts.len() + 2);
        hp.push(kind.as_bytes());
        hp.push(self.path.as_bytes());
        hp.extend(parts.iter().map(|x| x.as_bytes()));
        if self.seen.insert(h128(&hp)) && self.rules.keep(kind, class) {
            let mut t = String::with_capacity(kind.len() + class.len() + self.path.len() + 32);
            t.push_str(kind);
            t.push('|');
            t.push_str(class);
            t.push('|');
            t.push_str(&self.path);
            for x in parts {
                t.push_str(x);
            }
            self.tokens.0.insert(t);
        }
    }

    fn tid(&mut self, c: usize, id: usize) {
        let i = c * self.defs.len() + id;
        self.t_ids[i / 64] |= 1 << (i % 64);
    }

    fn short(label: &str) -> &str {
        label.rsplit("::").next().unwrap_or(label)
    }

    fn last_seg(&self) -> &str {
        match self.seg_starts.last() {
            Some(&s) => self.path[s..].trim_start_matches('.'),
            None => "",
        }
    }
}

impl Sink for TokenSink<'_> {
    const DETAIL: bool = true;

    fn arm(&mut self, id: usize, in_bytes: bool) {
        if self.muted > 0 {
            return;
        }
        if in_bytes {
            self.tid(3, id);
            return;
        }
        self.tid(0, id);
        if let Some(site) = &mut self.site {
            site.arm_ids.insert(id);
        } else if self.tonly == 0 {
            let defs = self.defs;
            let case = Self::short(defs.label(id));
            self.place("A", "arm", &["::", case]);
        }
    }

    fn opt(&mut self, id: usize, in_bytes: bool) {
        if self.muted > 0 {
            return;
        }
        if in_bytes {
            self.tid(3, id);
            return;
        }
        self.tid(1, id);
        if self.full() {
            let suffix = if self.defs.label(id).ends_with("?some") {
                "?some"
            } else {
                "?none"
            };
            self.place("O", "opt", &[suffix]);
        }
    }

    fn enum_value(&mut self, id: usize, discriminant: bool, in_bytes: bool) {
        if self.muted > 0 {
            return;
        }
        if in_bytes {
            self.tid(3, id);
            return;
        }
        self.tid(2, id);
        if !discriminant && self.full() {
            let defs = self.defs;
            let member = defs.label(id).rsplit('=').next().unwrap_or("");
            self.place("E", "enum", &["=", member]);
        }
    }

    fn class(&mut self, c: Class) {
        if self.muted > 0 {
            return;
        }
        if let Some(site) = &mut self.site {
            match c {
                Class::I128Negative
                | Class::I128HiNonzero
                | Class::I256Negative
                | Class::NonUtf8String => {
                    site.extra.insert(c.name());
                }
                _ => {}
            }
        }
    }

    fn scval_depth(&mut self, _depth: u32) {}

    fn push(&mut self, seg: &str) {
        let real = self.full();
        self.seg_real.push(real);
        if !real {
            return;
        }
        self.seg_starts.push(self.path.len());
        if seg != "[]" {
            self.path.push('.');
        }
        self.path.push_str(seg);
    }

    fn pop(&mut self) {
        if self.seg_real.pop() == Some(true) {
            if let Some(s) = self.seg_starts.pop() {
                self.path.truncate(s);
            }
        }
    }

    fn len(&mut self, n: u32, max: Option<u32>) {
        if !self.full() {
            return;
        }
        let class = if max == Some(n) && n > 0 {
            "=max".to_string()
        } else {
            self.rules.len_class(n as u64)
        };
        self.place("L", "len", &["#len=", &class]);
    }

    fn vec_arms(&mut self, cases: &[usize]) {
        if !self.full() || cases.is_empty() {
            return;
        }
        let first = Self::short(self.defs.label(cases[0])).to_string();
        let set: BTreeSet<&str> = cases
            .iter()
            .map(|&c| Self::short(self.defs.label(c)))
            .collect();
        let suffix = format!(
            "#first={first}:set={{{}}}",
            set.into_iter().collect::<Vec<_>>().join(",")
        );
        self.place("K", "first", &[&suffix]);
    }

    fn leaf(&mut self, ty: &Ty, bytes: &[u8]) {
        if self.muted > 0 || self.tonly > 0 {
            return;
        }
        if let Ty::Str(_) = ty {
            if self.rules.utf8 && std::str::from_utf8(bytes).is_err() {
                if let Some(site) = &mut self.site {
                    site.extra.insert("non-utf8");
                } else {
                    self.place("V", "utf8", &["#non-utf8"]);
                }
            }
            return;
        }
        if self.site.is_some() || self.rules.field_values.is_empty() {
            return;
        }
        let seg = self.last_seg();
        if !self.rules.field_names.contains(seg) {
            return;
        }
        let Some(&d) = self.defs_in.last() else {
            return;
        };
        let Some(class) = self.rules.field_values.get(&(d, seg.to_string())).cloned() else {
            return;
        };
        let v = match bytes.len() {
            8 => u64::from_be_bytes(bytes.try_into().unwrap()),
            4 => u32::from_be_bytes(bytes.try_into().unwrap()) as u64,
            _ => return,
        };
        match class.as_str() {
            "u64band" => {
                let suffix = format!("#u64={}", u64_band(v));
                self.place("V", "u64band", &[&suffix]);
            }
            "zero" if v == 0 => self.place("V", "zero", &["#zero"]),
            _ => {}
        }
    }

    fn elem_opt(&mut self, some: bool) {
        if self.muted > 0 {
            return;
        }
        let state = if some { "some" } else { "none" };
        if let Some(&d) = self.defs_in.last() {
            // The vector's field is the segment before the trailing `[]`.
            let field = self
                .path
                .strip_suffix("[]")
                .and_then(|p| p.rsplit('.').next())
                .unwrap_or(self.last_seg())
                .to_string();
            let t = format!("{}.{field}[]?{state}", self.defs.def_name(d));
            self.add("T", "elemopt", t);
        }
        if self.full() {
            let suffix = format!("?{state}");
            self.place("O", "elemopt", &[&suffix]);
        }
    }

    fn enter(&mut self, def: usize) {
        if self.muted > 0 || self.mute.contains(&def) {
            self.muted += 1;
            return;
        }
        if let Some(site) = &mut self.site {
            if site.def == def {
                site.cur += 1;
                site.nodes += 1;
                site.depth = site.depth.max(site.cur);
            }
        } else if self.tonly == 0 && self.rules.sites.contains(&def) {
            self.site = Some(Site {
                def,
                path: self.path.clone(),
                arm_ids: BTreeSet::new(),
                extra: BTreeSet::new(),
                cur: 1,
                depth: 1,
                nodes: 1,
            });
        } else if self.rules.summarised.contains(&def) {
            self.tonly += 1;
        }
        self.defs_in.push(def);
    }

    fn exit(&mut self, def: usize, bytes: &[u8]) {
        if self.muted > 0 {
            self.muted -= 1;
            return;
        }
        self.defs_in.pop();
        if let Some(site) = &mut self.site {
            if site.def == def {
                site.cur -= 1;
                if site.cur == 0 {
                    let s = self.site.take().unwrap();
                    let mut arms: BTreeSet<String> = s
                        .arm_ids
                        .iter()
                        .map(|&id| {
                            let label = self.defs.label(id);
                            let case = Self::short(label);
                            if case.starts_with('v')
                                && case[1..].chars().all(|c| c.is_ascii_digit())
                            {
                                label.to_string()
                            } else {
                                case.to_string()
                            }
                        })
                        .collect();
                    arms.extend(s.extra.iter().map(|x| x.to_string()));
                    let c = &self.rules.file.classes;
                    let body = format!(
                        "{}:{}{{{}}}d={}n={}",
                        s.path,
                        self.defs.def_name(s.def),
                        arms.into_iter().collect::<Vec<_>>().join(","),
                        class_of(s.depth, &c.depth),
                        class_of(s.nodes, &c.nodes)
                    );
                    self.add("S", "site", body);
                }
            }
            return;
        }
        if self.rules.summarised.contains(&def) && self.tonly > 0 {
            self.tonly -= 1;
            return;
        }
        if self.tonly > 0 {
            return;
        }
        if let Some(class) = self.rules.type_values.get(&def) {
            if class == "price" && bytes.len() == 8 {
                let n = i32::from_be_bytes(bytes[..4].try_into().unwrap()) as i64;
                let d = i32::from_be_bytes(bytes[4..].try_into().unwrap()) as i64;
                let v = if n == 0 || d == 0 {
                    "#price=zero"
                } else if gcd(n.unsigned_abs(), d.unsigned_abs()) > 1 {
                    "#price=unreduced"
                } else {
                    "#price=reduced"
                };
                self.place("V", "price", &[v]);
            }
        }
    }
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

pub fn u64_band(v: u64) -> &'static str {
    if v == 0 {
        "0"
    } else if v < 1 << 53 {
        "<2^53"
    } else if v < 1 << 63 {
        "<2^63"
    } else {
        ">=2^63"
    }
}

/// Leaf values of a ledger entry, for the `STATE` → `UPDATED` diff: (path, value). Sites are one
/// leaf each (their encoding); a union arm is a leaf `path::` with its case label. Paths and values
/// go to two arenas; each leaf is (path hash, path range, value range).
struct LeafSink<'a> {
    defs: &'a Defs,
    rules: &'a Rules,
    path: String,
    seg_starts: Vec<usize>,
    site: Option<(usize, u32)>,
    scratch: String,
    paths: String,
    vals: Vec<u8>,
    out: Vec<(u128, u32, u32, u32, u32)>,
}

impl LeafSink<'_> {
    fn record(&mut self, suffix: &str, value: &[u8]) {
        self.scratch.clear();
        self.scratch.push_str(self.path.trim_start_matches('.'));
        self.scratch.push_str(suffix);
        if self
            .rules
            .file
            .changes
            .ignore
            .iter()
            .any(|i| self.scratch.ends_with(i.as_str()))
        {
            return;
        }
        let h = h128(&[self.scratch.as_bytes()]);
        let (ps, vs) = (self.paths.len() as u32, self.vals.len() as u32);
        self.paths.push_str(&self.scratch);
        self.vals.extend_from_slice(value);
        self.out
            .push((h, ps, self.scratch.len() as u32, vs, value.len() as u32));
    }
}

impl Sink for LeafSink<'_> {
    const DETAIL: bool = true;
    fn arm(&mut self, id: usize, _in_bytes: bool) {
        if self.site.is_none() {
            let defs = self.defs;
            let l = TokenSink::short(defs.label(id));
            self.record("::", l.as_bytes());
        }
    }
    fn opt(&mut self, _id: usize, _in_bytes: bool) {}
    fn enum_value(&mut self, _id: usize, _d: bool, _in_bytes: bool) {}
    fn class(&mut self, _c: Class) {}
    fn scval_depth(&mut self, _depth: u32) {}
    fn push(&mut self, seg: &str) {
        self.seg_starts.push(self.path.len());
        if seg != "[]" {
            self.path.push('.');
        }
        self.path.push_str(seg);
    }
    fn pop(&mut self) {
        if let Some(s) = self.seg_starts.pop() {
            self.path.truncate(s);
        }
    }
    fn len(&mut self, n: u32, _max: Option<u32>) {
        if self.site.is_none() {
            self.record("#len", &n.to_be_bytes());
        }
    }
    fn leaf(&mut self, _ty: &Ty, bytes: &[u8]) {
        if self.site.is_none() {
            self.record("", bytes);
        }
    }
    fn enter(&mut self, def: usize) {
        match &mut self.site {
            Some((d, n)) if *d == def => *n += 1,
            None if self.rules.sites.contains(&def) => self.site = Some((def, 1)),
            _ => {}
        }
    }
    fn exit(&mut self, def: usize, bytes: &[u8]) {
        if let Some((d, n)) = &mut self.site {
            if *d == def {
                *n -= 1;
                if *n == 0 {
                    self.site = None;
                    let defs = self.defs;
                    let suffix = format!(":{}", defs.def_name(def));
                    self.record(&suffix, bytes);
                }
            }
        }
    }
}

struct Leaves {
    paths: String,
    vals: Vec<u8>,
    /// Sorted by path hash; leaves of one path keep their walk order.
    out: Vec<(u128, u32, u32, u32, u32)>,
}

impl Leaves {
    fn path(&self, i: usize) -> &str {
        let (_, s, n, _, _) = self.out[i];
        &self.paths[s as usize..(s + n) as usize]
    }
    fn val(&self, i: usize) -> &[u8] {
        let (_, _, _, s, n) = self.out[i];
        &self.vals[s as usize..(s + n) as usize]
    }
    /// The run of leaves with the hash at `i`: (end index).
    fn run(&self, i: usize) -> usize {
        let h = self.out[i].0;
        let mut j = i;
        while j < self.out.len() && self.out[j].0 == h {
            j += 1;
        }
        j
    }
}

fn entry_leaves(defs: &Defs, rules: &Rules, e: &LedgerEntry) -> Result<Leaves> {
    let bytes = e.to_xdr(XdrLimits::none())?;
    let mut s = LeafSink {
        defs,
        rules,
        path: String::new(),
        seg_starts: Vec::new(),
        site: None,
        scratch: String::new(),
        paths: String::new(),
        vals: Vec::new(),
        out: Vec::new(),
    };
    defs.walk_with("LedgerEntry", false, &bytes, &mut s)?;
    let mut out = s.out;
    out.sort_by_key(|x| x.0);
    Ok(Leaves {
        paths: s.paths,
        vals: s.vals,
        out,
    })
}

/// The changed-leaf set between two versions of one entry (`NOOP` when nothing differs).
fn leaf_diff(defs: &Defs, rules: &Rules, a: &LedgerEntry, b: &LedgerEntry) -> Result<Vec<String>> {
    if a.data == b.data && a.ext == b.ext {
        return Ok(Vec::new());
    }
    let (la, lb) = (entry_leaves(defs, rules, a)?, entry_leaves(defs, rules, b)?);
    let mut out = BTreeSet::new();
    let ch = &rules.file.changes;
    let (mut i, mut j) = (0usize, 0usize);
    while i < la.out.len() || j < lb.out.len() {
        let ha = la.out.get(i).map(|x| x.0);
        let hb = lb.out.get(j).map(|x| x.0);
        let h = match (ha, hb) {
            (Some(x), Some(y)) => x.min(y),
            (Some(x), None) => x,
            (None, Some(y)) => y,
            (None, None) => break,
        };
        let (ia, ea) = if ha == Some(h) {
            (i, la.run(i))
        } else {
            (i, i)
        };
        let (ib, eb) = if hb == Some(h) {
            (j, lb.run(j))
        } else {
            (j, j)
        };
        i = ea;
        j = eb;
        let va: Option<Vec<&[u8]>> = (ea > ia).then(|| (ia..ea).map(|k| la.val(k)).collect());
        let vb: Option<Vec<&[u8]>> = (eb > ib).then(|| (ib..eb).map(|k| lb.val(k)).collect());
        if va == vb {
            continue;
        }
        let k: &str = if ea > ia { la.path(ia) } else { lb.path(ib) };
        let name = k.rsplit('.').next().unwrap_or(k);
        if let Some(base) = k.strip_suffix("::") {
            let s = |v: &Option<Vec<&[u8]>>| {
                v.as_ref()
                    .map(|x| {
                        x.iter()
                            .map(|b| String::from_utf8_lossy(b).to_string())
                            .collect::<Vec<_>>()
                            .join("+")
                    })
                    .unwrap_or_else(|| "-".into())
            };
            out.insert(format!("{base}::{}>{}", s(&va), s(&vb)));
        } else if ch.per_byte.iter().any(|p| p == name) {
            if let (Some(x), Some(y)) = (&va, &vb) {
                if x.len() == 1 && y.len() == 1 && x[0].len() == y[0].len() {
                    for (n, (p, q)) in x[0].iter().zip(y[0]).enumerate() {
                        if p != q {
                            out.insert(format!("{k}[{n}]"));
                        }
                    }
                    continue;
                }
            }
            out.insert(k.to_string());
        } else if ch.old_new.iter().any(|p| p == name) {
            let n = |v: &Option<Vec<&[u8]>>| {
                v.as_ref()
                    .and_then(|x| x.first())
                    .filter(|b| b.len() == 4)
                    .map(|b| u32::from_be_bytes(b[..].try_into().unwrap()).to_string())
                    .unwrap_or_else(|| "-".into())
            };
            out.insert(format!("{k}={}>{}", n(&va), n(&vb)));
        } else {
            out.insert(k.to_string());
        }
    }
    Ok(out.into_iter().collect())
}

/// One component: kind, operation type (for `O`), tokens.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Component {
    pub kind: char,
    pub op_type: Option<String>,
    pub tokens: Vec<String>,
}

pub fn shape_id<'t>(level: &str, kind: &str, tokens: impl IntoIterator<Item = &'t str>) -> Id {
    let mut h = Sha256::new();
    h.update(b"xcc.shape/v1\n");
    h.update(level.as_bytes());
    h.update(b"\n");
    h.update(kind.as_bytes());
    for t in tokens {
        h.update(b"\n");
        h.update(t.as_bytes());
    }
    h.finalize()[..16].try_into().unwrap()
}

impl Component {
    pub fn id(&self) -> Id {
        shape_id(
            "G3",
            &self.kind.to_string(),
            self.tokens.iter().map(|s| s.as_str()),
        )
    }
}

/// A transaction shape: its component references.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct TxShape {
    pub e: String,
    pub a: Option<String>,
    pub r: String,
    pub f: String,
    pub m: String,
    /// Distinct `O` ids (hex) with the class of their multiplicity, sorted.
    pub ops: Vec<(String, String)>,
    pub op_count_class: String,
}

impl TxShape {
    pub fn refs(&self) -> Vec<String> {
        let mut v = vec![
            format!("E:{}", self.e),
            format!("R:{}", self.r),
            format!("F:{}", self.f),
            format!("M:{}", self.m),
        ];
        if let Some(a) = &self.a {
            v.push(format!("A:{a}"));
        }
        for (o, c) in &self.ops {
            v.push(format!("O:{o}*{c}"));
        }
        v.push(format!("ops={}", self.op_count_class));
        v.sort();
        v
    }
    pub fn id(&self) -> Id {
        let r = self.refs();
        shape_id("G3", "tx", r.iter().map(|s| s.as_str()))
    }
}

/// Text that a closed vocabulary did not hold, for the lead to freeze the vocabularies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct VocabHit {
    /// `event-symbol` or `map-key`.
    pub kind: String,
    pub text: Vec<u8>,
}

/// Everything one ledger contributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerShapes {
    pub ledger: Component,
    pub txs: Vec<TxShape>,
    pub components: BTreeMap<String, Component>,
    pub vocab: Vec<VocabHit>,
    pub op_count: u32,
    pub soroban_tx_count: u32,
    pub tx_hash_mismatches: u32,
    pub upgraded_to: Option<u32>,
    pub tx_set_hash_ok: bool,
    pub result_hash_ok: bool,
}

pub struct Ctx<'a> {
    pub defs: &'a Defs,
    pub rules: &'a Rules,
    pub network_id: [u8; 32],
}

fn label(defs: &Defs, enum_name: &str, v: i32) -> String {
    defs.enum_member(enum_name, v).unwrap_or("?").to_string()
}

fn op_type(defs: &Defs, op: &Operation) -> String {
    label(defs, "OperationType", op.body.discriminant() as i32)
}

fn sc_kind(defs: &Defs, v: &ScVal) -> String {
    match v {
        ScVal::Address(a) => format!("ADDR:{}", addr_kind(a)),
        _ => label(defs, "SCValType", v.discriminant() as i32)
            .trim_start_matches("SCV_")
            .to_string(),
    }
}

fn addr_kind(a: &ScAddress) -> &'static str {
    match a {
        ScAddress::Account(_) => "ACCOUNT",
        ScAddress::Contract(_) => "CONTRACT",
        ScAddress::MuxedAccount(_) => "MUXED_ACCOUNT",
        ScAddress::ClaimableBalance(_) => "CLAIMABLE_BALANCE",
        ScAddress::LiquidityPool(_) => "LIQUIDITY_POOL",
        ScAddress::MuxedContract(_) => "MUXED_CONTRACT",
    }
}

impl Ctx<'_> {
    fn data_sig(&self, v: &ScVal, vocab: &mut Vec<VocabHit>) -> String {
        let r = self.rules;
        match v {
            ScVal::Map(Some(m)) => {
                if m.0.len() > r.file.events.max_keys {
                    for e in m.0.iter() {
                        self.note_key(&e.key, vocab);
                    }
                    return format!("MAP{{n={}}}", r.len_class(m.0.len() as u64));
                }
                let mut ks = Vec::new();
                for e in m.0.iter() {
                    let name = match &e.key {
                        ScVal::Symbol(s) if r.map_keys.contains(s.0.as_vec()) => {
                            String::from_utf8_lossy(s.0.as_vec()).to_string()
                        }
                        k => {
                            self.note_key(k, vocab);
                            "key:other".to_string()
                        }
                    };
                    let mut val = sc_kind(self.defs, &e.val);
                    if let (ScVal::U64(u), true) =
                        (&e.val, r.file.events.u64band_keys.contains(&name))
                    {
                        val = format!("{val}#u64={}", u64_band(*u));
                    }
                    ks.push(format!("{name}:{val}"));
                }
                format!("MAP{{{}}}", ks.join(","))
            }
            _ => sc_kind(self.defs, v),
        }
    }

    fn note_key(&self, k: &ScVal, vocab: &mut Vec<VocabHit>) {
        let text = match k {
            ScVal::Symbol(s) => s.0.as_vec().clone(),
            other => format!("<{}>", sc_kind(self.defs, other)).into_bytes(),
        };
        vocab.push(VocabHit {
            kind: "map-key".into(),
            text,
        });
    }

    fn event_sig(&self, ev: &ContractEvent, wh: &str, vocab: &mut Vec<VocabHit>) -> String {
        let r = self.rules;
        let ty = label(self.defs, "ContractEventType", ev.type_ as i32);
        let ContractEventBody::V0(b) = &ev.body;
        let topics = &b.topics;
        let head = match topics.first() {
            Some(ScVal::Symbol(s)) if r.symbols.contains(s.0.as_vec()) => {
                String::from_utf8_lossy(s.0.as_vec()).to_string()
            }
            Some(ScVal::Symbol(s)) => {
                vocab.push(VocabHit {
                    kind: "event-symbol".into(),
                    text: s.0.as_vec().clone(),
                });
                "sym:other".into()
            }
            _ => "nosym".into(),
        };
        let n = r.len_class(topics.len() as u64);
        if head == "sym:other" || head == "nosym" {
            return format!("{wh}#ev={ty}:{head}:n={n}:{}", sc_kind(self.defs, &b.data));
        }
        let data = self.data_sig(&b.data, vocab);
        if topics.len() > r.file.events.max_topics {
            return format!("{wh}#ev={ty}:{head}:n={n}:{data}");
        }
        let kinds: Vec<String> = topics
            .iter()
            .skip(1)
            .map(|t| sc_kind(self.defs, t))
            .collect();
        format!("{wh}#ev={ty}:{head}:[{}]:{data}", kinds.join(","))
    }

    /// `D` tokens of a change list; returns the (entry type, STATE, UPDATED) pairs.
    fn change_tokens<'c>(
        &self,
        changes: &'c [LedgerEntryChange],
        wh: &str,
        out: &mut Tokens,
    ) -> Result<Vec<(String, &'c LedgerEntry, &'c LedgerEntry)>> {
        let r = self.rules;
        let mut counts: BTreeMap<(String, String), u64> = BTreeMap::new();
        let mut pairs = Vec::new();
        let mut prev: Option<&LedgerEntry> = None;
        for c in changes {
            let arm = label(self.defs, "LedgerEntryChangeType", c.discriminant() as i32);
            let arm = arm.trim_start_matches("LEDGER_ENTRY_").to_string();
            let et = match c {
                LedgerEntryChange::Removed(k) => {
                    label(self.defs, "LedgerEntryType", k.discriminant() as i32)
                }
                LedgerEntryChange::Created(e)
                | LedgerEntryChange::Updated(e)
                | LedgerEntryChange::State(e)
                | LedgerEntryChange::Restored(e) => {
                    label(self.defs, "LedgerEntryType", e.data.discriminant() as i32)
                }
            };
            *counts.entry((arm, et.clone())).or_default() += 1;
            match c {
                LedgerEntryChange::State(e) => {
                    prev = Some(e);
                    continue;
                }
                LedgerEntryChange::Updated(e) => {
                    if let Some(p) = prev {
                        if p.to_key() == e.to_key() {
                            let leaves = leaf_diff(self.defs, r, p, e)?;
                            let set = if leaves.is_empty() {
                                "NOOP".to_string()
                            } else {
                                leaves.join(",")
                            };
                            out.add(r, "D", "upd", format!("{wh}#upd:{et}:{{{set}}}"));
                            pairs.push((et, p, e));
                        }
                    }
                }
                _ => {}
            }
            prev = None;
        }
        for ((arm, et), n) in counts {
            out.add(
                r,
                "D",
                "chg",
                format!("{wh}#chg:{arm}:{et}x{}", class_of(n, &r.file.classes.count)),
            );
        }
        Ok(pairs)
    }

    fn relations(
        &self,
        op: &Operation,
        pairs: &[(String, &LedgerEntry, &LedgerEntry)],
        wh: &str,
        out: &mut Tokens,
    ) {
        let r = self.rules;
        let on = |n: &str| r.file.relations.iter().any(|x| x == n);
        let of = |t: &'static str| {
            pairs
                .iter()
                .filter(move |p| p.0 == t)
                .map(|p| (&p.1.data, &p.2.data))
        };
        let same = |b: bool| if b { "same" } else { "changed" };
        match &op.body {
            OperationBody::ChangeTrust(_) if on("change_trust") => {
                for (a, b) in of("TRUSTLINE") {
                    if let (LedgerEntryData::Trustline(a), LedgerEntryData::Trustline(b)) = (a, b) {
                        out.add(
                            r,
                            "R",
                            "change_trust",
                            format!("{wh}#rel:change_trust:limit={}", same(a.limit == b.limit)),
                        );
                    }
                }
            }
            OperationBody::ManageData(_) if on("manage_data") => {
                for (a, b) in of("DATA") {
                    if let (LedgerEntryData::Data(a), LedgerEntryData::Data(b)) = (a, b) {
                        out.add(
                            r,
                            "R",
                            "manage_data",
                            format!(
                                "{wh}#rel:manage_data:value={}",
                                same(a.data_value == b.data_value)
                            ),
                        );
                    }
                }
            }
            OperationBody::SetOptions(o) if on("set_options") => {
                if let Some((LedgerEntryData::Account(a), LedgerEntryData::Account(b))) =
                    of("ACCOUNT").next_back()
                {
                    for (i, (name, set)) in [
                        ("masterWeight", o.master_weight),
                        ("lowThreshold", o.low_threshold),
                        ("medThreshold", o.med_threshold),
                        ("highThreshold", o.high_threshold),
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        if set.is_some() {
                            let s = same(a.thresholds.0[i] == b.thresholds.0[i]);
                            out.add(
                                r,
                                "R",
                                "set_options",
                                format!("{wh}#rel:set_options:{name}={s}"),
                            );
                        }
                    }
                    if let Some(f) = o.set_flags {
                        let v = if f & a.flags == 0 {
                            "all-new"
                        } else {
                            "some-already-set"
                        };
                        out.add(
                            r,
                            "R",
                            "set_options",
                            format!("{wh}#rel:set_options:setFlags={v}"),
                        );
                    }
                    if let Some(f) = o.clear_flags {
                        let v = if f & !a.flags == 0 {
                            "all-set"
                        } else {
                            "some-already-clear"
                        };
                        out.add(
                            r,
                            "R",
                            "set_options",
                            format!("{wh}#rel:set_options:clearFlags={v}"),
                        );
                    }
                }
            }
            OperationBody::AllowTrust(o) if on("allow_trust") => {
                for (a, b) in of("TRUSTLINE") {
                    if let (LedgerEntryData::Trustline(a), LedgerEntryData::Trustline(b)) = (a, b) {
                        out.add(
                            r,
                            "R",
                            "allow_trust",
                            format!(
                                "{wh}#rel:allow_trust:authorize={}:flags={}>{}",
                                o.authorize,
                                a.flags & 3,
                                b.flags & 3
                            ),
                        );
                    }
                }
            }
            OperationBody::SetTrustLineFlags(o) if on("set_trust_line_flags") => {
                for (a, b) in of("TRUSTLINE") {
                    if let (LedgerEntryData::Trustline(a), LedgerEntryData::Trustline(_)) = (a, b) {
                        let st = match o.set_flags {
                            0 => "none",
                            f if f & a.flags == 0 => "all-new",
                            _ => "some-already-set",
                        };
                        let cl = match o.clear_flags {
                            0 => "none",
                            f if f & !a.flags == 0 => "all-set",
                            _ => "some-already-clear",
                        };
                        out.add(
                            r,
                            "R",
                            "set_trust_line_flags",
                            format!("{wh}#rel:stlf:set={st}:clear={cl}"),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    fn walk_part<T: WriteXdr>(
        &self,
        sink: &mut TokenSink,
        root: &str,
        ty: &str,
        v: &T,
    ) -> Result<()> {
        let b = v.to_xdr(XdrLimits::none())?;
        sink.walk(root, ty, false, &b)
    }

    fn walk_vec<T: WriteXdr>(
        &self,
        sink: &mut TokenSink,
        root: &str,
        ty: &str,
        v: &[T],
    ) -> Result<()> {
        let mut b = (v.len() as u32).to_be_bytes().to_vec();
        for x in v {
            b.extend(x.to_xdr(XdrLimits::none())?);
        }
        sink.walk(root, ty, true, &b)
    }

    /// The shapes of one decoded ledger; `blob` is its exact XDR.
    pub fn ledger(&self, lcm: &LedgerCloseMeta, blob: &[u8]) -> Result<LedgerShapes> {
        let (defs, rules) = (self.defs, self.rules);
        let mut vocab = Vec::new();
        let mut comps: BTreeMap<String, Component> = BTreeMap::new();
        let mut put = |c: Component| -> String {
            let id = hex16(&c.id());
            comps.entry(id.clone()).or_insert(c);
            id
        };

        // L: the ledger without its transactions.
        let mut l = TokenSink::new(defs, rules, &rules.mute_l);
        l.walk("lcm", "LedgerCloseMeta", false, blob)
            .context("walk LedgerCloseMeta")?;
        let header = match lcm {
            LedgerCloseMeta::V0(m) => &m.ledger_header,
            LedgerCloseMeta::V1(m) => &m.ledger_header,
            LedgerCloseMeta::V2(m) => &m.ledger_header,
        };
        let mut upgraded_to = None;
        for (i, u) in header.header.scp_value.upgrades.iter().enumerate() {
            match LedgerUpgrade::from_xdr(u.0.as_slice(), XdrLimits::none()) {
                Ok(up) => {
                    if let LedgerUpgrade::Version(v) = up {
                        upgraded_to = Some(v);
                    }
                    let b = up.to_xdr(XdrLimits::none())?;
                    l.walk("upgrade", "LedgerUpgrade", false, &b)?;
                }
                Err(_) => l.add("V", "upgrade", format!("upgrade[{i}]#undecodable")),
            }
        }
        if upgraded_to.is_some_and(|v| v == header.header.ledger_version) {
            l.add("V", "proto", "ledger#protocol_applied!=header".into());
        }
        // Entry changes made by upgrades get the same `D` tokens as transaction changes.
        let upgrades_processing = match lcm {
            LedgerCloseMeta::V0(m) => &m.upgrades_processing,
            LedgerCloseMeta::V1(m) => &m.upgrades_processing,
            LedgerCloseMeta::V2(m) => &m.upgrades_processing,
        };
        for u in upgrades_processing.iter() {
            self.change_tokens(&u.changes.0, "upgrade", &mut l.tokens)?;
        }
        l.add(
            "V",
            "hdrver",
            format!("ledger#header_version={}", header.header.ledger_version),
        );
        let ledger = Component {
            kind: 'L',
            op_type: None,
            tokens: l.done(),
        };

        // The transaction set and the join.
        let mut envs: BTreeMap<[u8; 32], &TransactionEnvelope> = BTreeMap::new();
        let (tx_set_hash, legacy) = match lcm {
            LedgerCloseMeta::V0(m) => {
                let mut h = Sha256::new();
                h.update(m.tx_set.previous_ledger_hash.0);
                for e in m.tx_set.txs.iter() {
                    envs.insert(e.hash(self.network_id)?, e);
                    h.update(e.to_xdr(XdrLimits::none())?);
                }
                (<[u8; 32]>::from(h.finalize()), true)
            }
            LedgerCloseMeta::V1(m) => (gen_set(&m.tx_set, self.network_id, &mut envs)?, false),
            LedgerCloseMeta::V2(m) => (gen_set(&m.tx_set, self.network_id, &mut envs)?, false),
        };
        let _ = legacy;
        let tx_set_hash_ok = tx_set_hash == header.header.scp_value.tx_set_hash.0;

        struct P<'x> {
            pair: &'x xdrcheck_xdr::xdr::TransactionResultPair,
            fee: &'x [LedgerEntryChange],
            meta: &'x TransactionMeta,
            post: Option<&'x [LedgerEntryChange]>,
        }
        let procs: Vec<P> = match lcm {
            LedgerCloseMeta::V0(m) => m
                .tx_processing
                .iter()
                .map(|t| P {
                    pair: &t.result,
                    fee: &t.fee_processing.0,
                    meta: &t.tx_apply_processing,
                    post: None,
                })
                .collect(),
            LedgerCloseMeta::V1(m) => m
                .tx_processing
                .iter()
                .map(|t| P {
                    pair: &t.result,
                    fee: &t.fee_processing.0,
                    meta: &t.tx_apply_processing,
                    post: None,
                })
                .collect(),
            LedgerCloseMeta::V2(m) => m
                .tx_processing
                .iter()
                .map(|t| P {
                    pair: &t.result,
                    fee: &t.fee_processing.0,
                    meta: &t.tx_apply_processing,
                    post: Some(&t.post_tx_apply_fee_processing.0[..]),
                })
                .collect(),
        };
        let mut rh = Sha256::new();
        rh.update((procs.len() as u32).to_be_bytes());
        for p in &procs {
            rh.update(p.pair.to_xdr(XdrLimits::none())?);
        }
        let result_hash_ok = <[u8; 32]>::from(rh.finalize()) == header.header.tx_set_result_hash.0;

        let mut txs = Vec::with_capacity(procs.len());
        let mut mismatches = 0u32;
        let mut op_count = 0u32;
        let mut soroban = 0u32;
        for p in &procs {
            let Some(env) = envs.get(&p.pair.transaction_hash.0).copied() else {
                mismatches += 1;
                continue;
            };
            let (ops, ext) = match env {
                TransactionEnvelope::TxV0(e) => (&e.tx.operations[..], None),
                TransactionEnvelope::Tx(e) => (&e.tx.operations[..], Some(&e.tx.ext)),
                TransactionEnvelope::TxFeeBump(e) => {
                    let xdrcheck_xdr::xdr::FeeBumpTransactionInnerTx::Tx(i) = &e.tx.inner_tx;
                    (&i.tx.operations[..], Some(&i.tx.ext))
                }
            };
            op_count += ops.len() as u32;
            if matches!(ext, Some(TransactionExt::V1(_))) {
                soroban += 1;
            }
            // E
            let mut e = TokenSink::new(defs, rules, &rules.mute_e);
            self.walk_part(&mut e, "env", "TransactionEnvelope", env)?;
            let e_id = put(Component {
                kind: 'E',
                op_type: None,
                tokens: e.done(),
            });
            // A
            let mut a = TokenSink::new(defs, rules, &rules.none);
            let mut any_auth = false;
            for op in ops {
                if let OperationBody::InvokeHostFunction(ih) = &op.body {
                    if !ih.auth.is_empty() {
                        any_auth = true;
                        self.walk_vec(&mut a, "auth", "SorobanAuthorizationEntry", &ih.auth)?;
                    }
                }
            }
            let a_id = any_auth.then(|| {
                put(Component {
                    kind: 'A',
                    op_type: None,
                    tokens: a.done(),
                })
            });
            // R
            let res = &p.pair.result;
            let mut rr = TokenSink::new(defs, rules, &rules.mute_r);
            self.walk_part(&mut rr, "res", "TransactionResult", res)?;
            let r_id = put(Component {
                kind: 'R',
                op_type: None,
                tokens: rr.done(),
            });
            // F
            let mut f = TokenSink::new(defs, rules, &rules.none);
            self.walk_vec(&mut f, "fee", "LedgerEntryChange", p.fee)?;
            self.change_tokens(p.fee, "fee", &mut f.tokens)?;
            if let Some(post) = p.post {
                self.walk_vec(&mut f, "postfee", "LedgerEntryChange", post)?;
                self.change_tokens(post, "postfee", &mut f.tokens)?;
            }
            let f_id = put(Component {
                kind: 'F',
                op_type: None,
                tokens: f.done(),
            });
            // M
            let mut m = TokenSink::new(defs, rules, &rules.mute_m);
            self.walk_part(&mut m, "meta", "TransactionMeta", p.meta)?;
            let op_results = op_results(res);
            let op_meta_changes: Vec<&[LedgerEntryChange]>;
            let mut op_events: Vec<Vec<&ContractEvent>> = vec![Vec::new(); ops.len()];
            match p.meta {
                TransactionMeta::V0(v) => {
                    op_meta_changes = v.iter().map(|o| &o.changes.0[..]).collect()
                }
                TransactionMeta::V1(v) => {
                    self.change_tokens(&v.tx_changes.0, "txBefore", &mut m.tokens)?;
                    op_meta_changes = v.operations.iter().map(|o| &o.changes.0[..]).collect();
                }
                TransactionMeta::V2(v) => {
                    self.change_tokens(&v.tx_changes_before.0, "txBefore", &mut m.tokens)?;
                    self.change_tokens(&v.tx_changes_after.0, "txAfter", &mut m.tokens)?;
                    op_meta_changes = v.operations.iter().map(|o| &o.changes.0[..]).collect();
                }
                TransactionMeta::V3(v) => {
                    self.change_tokens(&v.tx_changes_before.0, "txBefore", &mut m.tokens)?;
                    self.change_tokens(&v.tx_changes_after.0, "txAfter", &mut m.tokens)?;
                    op_meta_changes = v.operations.iter().map(|o| &o.changes.0[..]).collect();
                    if let (Some(sm), Some(first)) = (&v.soroban_meta, op_events.first_mut()) {
                        first.extend(sm.events.iter());
                    }
                }
                TransactionMeta::V4(v) => {
                    self.change_tokens(&v.tx_changes_before.0, "txBefore", &mut m.tokens)?;
                    self.change_tokens(&v.tx_changes_after.0, "txAfter", &mut m.tokens)?;
                    op_meta_changes = v.operations.iter().map(|o| &o.changes.0[..]).collect();
                    for (j, o) in v.operations.iter().enumerate() {
                        if let Some(slot) = op_events.get_mut(j) {
                            slot.extend(o.events.iter());
                        }
                    }
                    for te in v.events.iter() {
                        let stage = label(defs, "TransactionEventStage", te.stage as i32);
                        let sig = self.event_sig(&te.event, &format!("txev:{stage}"), &mut vocab);
                        m.tokens.add(rules, "X", "ev", sig);
                    }
                }
            }
            let m_id = put(Component {
                kind: 'M',
                op_type: None,
                tokens: m.done(),
            });
            // O
            let mut o_ids: BTreeMap<String, u64> = BTreeMap::new();
            for (j, op) in ops.iter().enumerate() {
                let ot = op_type(defs, op);
                let wh = format!("op:{ot}");
                let mut o = TokenSink::new(defs, rules, &rules.mute_o);
                self.walk_part(&mut o, "op", "Operation", op)?;
                if let Some(r) = op_results.and_then(|v| v.get(j)) {
                    self.walk_part(&mut o, "opres", "OperationResult", r)?;
                }
                if let Some(ch) = op_meta_changes.get(j) {
                    let mut b = (ch.len() as u32).to_be_bytes().to_vec();
                    for c in ch.iter() {
                        b.extend(c.to_xdr(XdrLimits::none())?);
                    }
                    o.walk("opmeta.changes", "LedgerEntryChange", true, &b)?;
                    let pairs = self.change_tokens(ch, &wh, &mut o.tokens)?;
                    self.relations(op, &pairs, &wh, &mut o.tokens);
                }
                if let Some(evs) = op_events.get(j) {
                    for ev in evs {
                        let b = ev.to_xdr(XdrLimits::none())?;
                        o.walk("opmeta.events[]", "ContractEvent", false, &b)?;
                        let sig = self.event_sig(ev, &wh, &mut vocab);
                        o.tokens.add(rules, "X", "ev", sig);
                    }
                }
                let id = put(Component {
                    kind: 'O',
                    op_type: Some(ot),
                    tokens: o.done(),
                });
                *o_ids.entry(id).or_default() += 1;
            }
            let c = &rules.file.classes;
            txs.push(TxShape {
                e: e_id,
                a: a_id,
                r: r_id,
                f: f_id,
                m: m_id,
                ops: o_ids
                    .into_iter()
                    .map(|(id, n)| (id, class_of(n, &c.op_mult)))
                    .collect(),
                op_count_class: class_of(ops.len() as u64, &c.ops),
            });
        }
        let lid = hex16(&ledger.id());
        comps.insert(lid, ledger.clone());
        Ok(LedgerShapes {
            ledger,
            txs,
            components: comps,
            vocab,
            op_count,
            soroban_tx_count: soroban,
            tx_hash_mismatches: mismatches,
            upgraded_to,
            tx_set_hash_ok,
            result_hash_ok,
        })
    }
}

fn op_results(r: &TransactionResult) -> Option<&[OperationResult]> {
    match &r.result {
        TransactionResultResult::TxSuccess(v) | TransactionResultResult::TxFailed(v) => {
            Some(&v[..])
        }
        TransactionResultResult::TxFeeBumpInnerSuccess(p)
        | TransactionResultResult::TxFeeBumpInnerFailed(p) => match &p.result.result {
            InnerTransactionResultResult::TxSuccess(v)
            | InnerTransactionResultResult::TxFailed(v) => Some(&v[..]),
            _ => None,
        },
        _ => None,
    }
}

fn gen_set<'s>(
    set: &'s GeneralizedTransactionSet,
    network_id: [u8; 32],
    envs: &mut BTreeMap<[u8; 32], &'s TransactionEnvelope>,
) -> Result<[u8; 32]> {
    let GeneralizedTransactionSet::V1(s) = set;
    for phase in s.phases.iter() {
        match phase {
            TransactionPhase::V0(components) => {
                for c in components.iter() {
                    let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) = c;
                    for e in c.txs.iter() {
                        envs.insert(e.hash(network_id)?, e);
                    }
                }
            }
            TransactionPhase::V1(p) => {
                for stage in p.execution_stages.iter() {
                    for cluster in stage.0.iter() {
                        for e in cluster.0.iter() {
                            envs.insert(e.hash(network_id)?, e);
                        }
                    }
                }
            }
        }
    }
    Ok(Sha256::digest(set.to_xdr(XdrLimits::none())?).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        let e = [0, 1, 2, 4, 16, 100];
        let got: Vec<String> = [0, 1, 2, 3, 4, 5, 16, 17, 100, 101]
            .iter()
            .map(|&n| class_of(n, &e))
            .collect();
        assert_eq!(
            got,
            ["0", "1", "2", "3-4", "3-4", "5-16", "5-16", "17-100", "17-100", ">100"]
        );
        let d = [1, 2, 3, 8, 32, 99, 124, 199, 255, 374, 499];
        assert_eq!(class_of(125, &d), "125-199");
        assert_eq!(class_of(500, &d), ">499");
        assert_eq!(class_of(3, &[1, 2]), ">2");
    }

    #[test]
    fn rules_parse_against_the_pinned_definitions() {
        let r = Rules::parse(RULES_V1, Defs::pinned()).unwrap();
        assert_eq!(r.file.levels["G3"].len(), 11);
        assert!(r.symbols.contains(b"mint".as_slice()));
    }
}
