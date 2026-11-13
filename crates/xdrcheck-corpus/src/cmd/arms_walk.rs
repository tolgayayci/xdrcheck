//! Schema-driven XDR walker for arm coverage and shape predicates.
//!
//! The walker reads XDR bytes against the definitions compiled into the pinned `stellar-xdr`
//! 30.0.0 crate (its `xdr-definitions-json/xdr.json`, vendored compressed as
//! `data/xdr-definitions-v30.0.0.json.zst`). It is only run on bytes the oracle has already
//! decoded, and it must consume them exactly; any disagreement is a tool error, never a coverage
//! fact.
//!
//! What it records, per walked value ([`Tally`]):
//! - every union arm taken, as `Union::CASE` (enum discriminant) or `Union::v<N>` (integer
//!   discriminant), and for an arm whose type is optional, `Union::CASE?some|none`;
//! - every optional struct field state, `Struct.field?some|none`;
//! - every enum value read, `Enum=MEMBER`;
//! - value classes ([`Class`]): u64 at or above 2^63, negative or hi-nonzero i128 and i256,
//!   strings that are not UTF-8, vectors and strings at their declared maximum, ledgers
//!   carrying upgrades, and the deepest `SCVal` nesting seen.
//!
//! `SCV_BYTES` values that decode in the oracle as a non-empty `ConfigUpgradeSet` (how a network
//! upgrade proposal is stored in contract data) are walked too, into a separate tally: those
//! arms (the `_DELTA` config settings among them) exist in ledgers only as bytes.
//!
//! The arm universe of a root type ([`Defs::universe`]) is every union case and every optional
//! state reachable from it; from `LedgerCloseMetaBatch` at XDR 30.0 it is 499 arms and 58
//! optional states.
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use anyhow::{bail, ensure, Context, Result};
use serde_json::Value;

const DEFINITIONS_ZST: &[u8] = include_bytes!("../../data/xdr-definitions-v30.0.0.json.zst");
/// sha256 of the uncompressed definitions file as shipped in the `stellar-xdr` 30.0.0 crate.
pub const DEFINITIONS_SHA256: &str =
    "8c53e8376c42763f658bc181213516d6c7591842ba4b5fb6959effc2ce30cfde";

/// A resolved XDR type (typedefs substituted; struct, union and enum names kept as references).
#[derive(Debug, Clone)]
pub enum Ty {
    Int,
    UInt,
    Hyper,
    UHyper,
    Bool,
    OpaqueFixed(u32),
    OpaqueVar,
    Str(Option<u32>),
    VarArray(Box<Ty>, Option<u32>),
    Array(Box<Ty>, u32),
    Optional(Box<Ty>),
    Def(usize),
}

#[derive(Debug)]
struct Arm {
    /// (discriminant value, label, arm id)
    cases: Vec<(i32, String, usize)>,
    ty: Option<Ty>,
    /// Ids of `?some` / `?none` when the arm type is optional.
    opt: Option<(usize, usize)>,
}

/// A struct field: name, type, and the `?some` / `?none` ids when the type is optional.
type Field = (String, Ty, Option<(usize, usize)>);

#[derive(Debug)]
enum Kind {
    Struct(Vec<Field>),
    Union {
        disc_enum: Option<usize>,
        arms: Vec<Arm>,
    },
    Enum(HashMap<i32, usize>),
}

#[derive(Debug)]
struct Def {
    name: String,
    kind: Kind,
}

/// What an id names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdKind {
    Arm,
    Opt,
    EnumValue,
}

/// Value classes the walker detects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    U64High,
    I128Negative,
    I128HiNonzero,
    I256Negative,
    NonUtf8String,
    CountAtLimit,
    LedgerUpgrades,
}

impl Class {
    pub const ALL: [Class; 7] = [
        Class::U64High,
        Class::I128Negative,
        Class::I128HiNonzero,
        Class::I256Negative,
        Class::NonUtf8String,
        Class::CountAtLimit,
        Class::LedgerUpgrades,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Class::U64High => "u64-high",
            Class::I128Negative => "i128-negative",
            Class::I128HiNonzero => "i128-hi-nonzero",
            Class::I256Negative => "i256-negative",
            Class::NonUtf8String => "non-utf8-string",
            Class::CountAtLimit => "count-at-limit",
            Class::LedgerUpgrades => "ledger-upgrades",
        }
    }
}

/// The parsed definitions with an id for every arm, optional state and enum value.
pub struct Defs {
    defs: Vec<Def>,
    by_name: HashMap<String, usize>,
    /// Lower-case, underscore-free name → def index (to match the oracle's Rust type names).
    by_norm: HashMap<String, usize>,
    labels: Vec<String>,
    kinds: Vec<IdKind>,
    by_label: HashMap<String, usize>,
    /// Struct/union names whose fields or arms get special handling.
    special: Special,
}

#[derive(Default)]
struct Special {
    scval: Option<usize>,
    int128: Option<usize>,
    int256: Option<usize>,
    stellar_value: Option<usize>,
    config_upgrade_set: Option<usize>,
    scv_bytes_value: Option<i32>,
}

fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '_')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

impl Defs {
    /// The pinned definitions, parsed once.
    pub fn pinned() -> &'static Defs {
        static D: OnceLock<Defs> = OnceLock::new();
        D.get_or_init(|| {
            let raw = xdrcheck_xdr::batch::decompress_bounded(DEFINITIONS_ZST, 64 << 20)
                .expect("vendored definitions decompress");
            debug_assert_eq!(xdrcheck_xdr::sha256_hex(&raw), DEFINITIONS_SHA256);
            Defs::parse(&raw).expect("vendored definitions parse")
        })
    }

    /// Parse an `xdr.json` definitions file.
    pub fn parse(raw: &[u8]) -> Result<Defs> {
        let v: Value = serde_json::from_slice(raw).context("definitions are not JSON")?;
        let list = v["definitions"]
            .as_array()
            .context("definitions: no array")?;
        let mut json: HashMap<String, &Value> = HashMap::new();
        for d in list {
            let n = d["name"].as_str().context("definition without a name")?;
            json.insert(n.to_string(), d);
        }
        // Indices for struct, union and enum definitions.
        let mut by_name = HashMap::new();
        let mut names = Vec::new();
        for d in list {
            if matches!(d["kind"].as_str(), Some("struct" | "union" | "enum")) {
                let n = d["name"].as_str().unwrap().to_string();
                by_name.insert(n.clone(), names.len());
                names.push(n);
            }
        }
        let mut b = Builder {
            json: &json,
            by_name: &by_name,
            labels: Vec::new(),
            kinds: Vec::new(),
        };
        let mut defs = Vec::with_capacity(names.len());
        for n in &names {
            let d = json[n];
            let kind = match d["kind"].as_str().unwrap() {
                "struct" => {
                    let mut fields = Vec::new();
                    for f in d["fields"].as_array().context("struct without fields")? {
                        let fname = f["name"].as_str().context("field without name")?;
                        let ty = b.ty(&f["type"])?;
                        let opt = if matches!(ty, Ty::Optional(_)) {
                            Some((
                                b.id(format!("{n}.{fname}?some"), IdKind::Opt),
                                b.id(format!("{n}.{fname}?none"), IdKind::Opt),
                            ))
                        } else {
                            None
                        };
                        fields.push((fname.to_string(), ty, opt));
                    }
                    Kind::Struct(fields)
                }
                "union" => {
                    let dt = b.ty(&d["discriminant"]["type"])?;
                    let disc_enum = match dt {
                        Ty::Def(i) => Some(i),
                        Ty::Int | Ty::UInt => None,
                        other => bail!("{n}: discriminant {other:?}"),
                    };
                    let mut arms = Vec::new();
                    for a in d["arms"].as_array().context("union without arms")? {
                        let cases_json = a["cases"].as_array().context("arm without cases")?;
                        let mut cases = Vec::new();
                        for c in cases_json {
                            let value = c["value"].as_i64().context("case value")? as i32;
                            let label = match (disc_enum, c["name"].as_str()) {
                                (Some(_), Some(cn)) => cn.to_string(),
                                _ => format!("v{value}"),
                            };
                            let id = b.id(format!("{n}::{label}"), IdKind::Arm);
                            cases.push((value, label, id));
                        }
                        let ty = match a.get("type") {
                            Some(t) if !t.is_null() => Some(b.ty(t)?),
                            _ => None,
                        };
                        let opt = if matches!(ty, Some(Ty::Optional(_))) {
                            // One pair per case label (as armcov did); unions here have one case
                            // per optional arm.
                            let l = &cases[0].1;
                            Some((
                                b.id(format!("{n}::{l}?some"), IdKind::Opt),
                                b.id(format!("{n}::{l}?none"), IdKind::Opt),
                            ))
                        } else {
                            None
                        };
                        arms.push(Arm { cases, ty, opt });
                    }
                    Kind::Union { disc_enum, arms }
                }
                "enum" => {
                    let mut m = HashMap::new();
                    for mem in d["members"].as_array().context("enum without members")? {
                        let mn = mem["name"].as_str().context("member name")?;
                        let mv = mem["value"].as_i64().context("member value")? as i32;
                        m.insert(mv, b.id(format!("{n}={mn}"), IdKind::EnumValue));
                    }
                    Kind::Enum(m)
                }
                _ => unreachable!(),
            };
            defs.push(Def {
                name: n.clone(),
                kind,
            });
        }
        let (labels, kinds) = (b.labels, b.kinds);
        let by_label = labels
            .iter()
            .enumerate()
            .map(|(i, l)| (l.clone(), i))
            .collect();
        let by_norm = by_name.iter().map(|(k, v)| (norm(k), *v)).collect();
        let mut special = Special {
            scval: by_name.get("SCVal").copied(),
            int128: by_name.get("Int128Parts").copied(),
            int256: by_name.get("Int256Parts").copied(),
            stellar_value: by_name.get("StellarValue").copied(),
            config_upgrade_set: by_name.get("ConfigUpgradeSet").copied(),
            scv_bytes_value: None,
        };
        if let Some(Kind::Union { arms, .. }) = special.scval.map(|i| &defs[i].kind) {
            special.scv_bytes_value = arms
                .iter()
                .flat_map(|a| &a.cases)
                .find(|c| c.1 == "SCV_BYTES")
                .map(|c| c.0);
        }
        Ok(Defs {
            defs,
            by_name,
            by_norm,
            labels,
            kinds,
            by_label,
            special,
        })
    }

    /// Number of ids (arms, optional states and enum values).
    pub fn len(&self) -> usize {
        self.labels.len()
    }
    pub fn label(&self, id: usize) -> &str {
        &self.labels[id]
    }
    pub fn kind(&self, id: usize) -> IdKind {
        self.kinds[id]
    }
    pub fn id(&self, label: &str) -> Option<usize> {
        self.by_label.get(label).copied()
    }
    /// The definition name for an oracle type name (`ScVal` → `SCVal`).
    pub fn type_name(&self, oracle_name: &str) -> Option<&str> {
        self.by_name
            .get(oracle_name)
            .or_else(|| self.by_norm.get(&norm(oracle_name)))
            .map(|&i| self.defs[i].name.as_str())
    }

    /// Arm and optional-state ids reachable from `root`, in depth-first definition order.
    pub fn universe(&self, root: &str) -> Result<Vec<usize>> {
        let r = *self
            .by_name
            .get(root)
            .with_context(|| format!("no definition {root}"))?;
        let mut seen = vec![false; self.defs.len()];
        let mut out = Vec::new();
        self.reach_def(r, &mut seen, &mut out);
        let mut once = vec![false; self.len()];
        out.retain(|&i| !std::mem::replace(&mut once[i], true));
        Ok(out)
    }

    /// The enum name of a union's discriminant, when it is an enum.
    pub fn discriminant_enum(&self, union: &str) -> Option<&str> {
        match &self.defs[*self.by_name.get(union)?].kind {
            Kind::Union {
                disc_enum: Some(e), ..
            } => Some(self.defs[*e].name.as_str()),
            _ => None,
        }
    }

    fn reach_ty(&self, t: &Ty, seen: &mut [bool], out: &mut Vec<usize>) {
        match t {
            Ty::VarArray(e, _) | Ty::Array(e, _) | Ty::Optional(e) => self.reach_ty(e, seen, out),
            Ty::Def(i) => self.reach_def(*i, seen, out),
            _ => {}
        }
    }

    fn reach_def(&self, i: usize, seen: &mut [bool], out: &mut Vec<usize>) {
        if seen[i] {
            return;
        }
        seen[i] = true;
        match &self.defs[i].kind {
            Kind::Struct(fields) => {
                for (_, ty, opt) in fields {
                    if let Some((s, n)) = opt {
                        out.push(*s);
                        out.push(*n);
                    }
                    self.reach_ty(ty, seen, out);
                }
            }
            Kind::Union { arms, .. } => {
                for a in arms {
                    for c in &a.cases {
                        out.push(c.2);
                        if let Some(t) = &a.ty {
                            self.reach_ty(t, seen, out);
                        }
                        if let Some((s, n)) = a.opt {
                            out.push(s);
                            out.push(n);
                        }
                    }
                }
            }
            Kind::Enum(_) => {}
        }
    }

    /// Walk `bytes` as a value of definition `type_name`; the bytes must be consumed exactly.
    pub fn walk(&self, type_name: &str, bytes: &[u8], tally: &mut Tally) -> Result<()> {
        tally.ensure_len(self.len());
        self.walk_with(type_name, false, bytes, tally)
    }

    /// Walk `bytes` as a value of definition `type_name` (or, with `vector`, as a variable-length
    /// vector of it) into any [`Sink`]; the bytes must be consumed exactly.
    pub fn walk_with<S: Sink>(
        &self,
        type_name: &str,
        vector: bool,
        bytes: &[u8],
        sink: &mut S,
    ) -> Result<()> {
        let i = self
            .def_index(type_name)
            .with_context(|| format!("no definition {type_name}"))?;
        let mut w = Walker {
            d: self,
            b: bytes,
            pos: 0,
            scval_depth: 0,
            t: sink,
            in_bytes: false,
        };
        if vector {
            w.ty(&Ty::VarArray(Box::new(Ty::Def(i)), None))?;
        } else {
            w.def(i)?;
        }
        ensure!(
            w.pos == bytes.len(),
            "walker consumed {} of {} bytes of {type_name}",
            w.pos,
            bytes.len()
        );
        Ok(())
    }

    /// Index of a struct, union or enum definition.
    pub fn def_index(&self, name: &str) -> Option<usize> {
        self.by_name.get(name).copied()
    }
    /// Name of definition `i`.
    pub fn def_name(&self, i: usize) -> &str {
        &self.defs[i].name
    }
    /// The label of `enum_name`'s member with value `v` (`OperationType`, 6 -> `CHANGE_TRUST`).
    pub fn enum_member(&self, enum_name: &str, v: i32) -> Option<&str> {
        match &self.defs[*self.by_name.get(enum_name)?].kind {
            Kind::Enum(m) => m
                .get(&v)
                .map(|&id| self.labels[id].rsplit('=').next().unwrap_or("")),
            _ => None,
        }
    }
}

struct Builder<'a> {
    json: &'a HashMap<String, &'a Value>,
    by_name: &'a HashMap<String, usize>,
    labels: Vec<String>,
    kinds: Vec<IdKind>,
}

impl Builder<'_> {
    fn id(&mut self, label: String, kind: IdKind) -> usize {
        self.labels.push(label);
        self.kinds.push(kind);
        self.labels.len() - 1
    }

    fn ty(&mut self, t: &Value) -> Result<Ty> {
        let max = |k: &str| t[k].as_u64().map(|n| n as u32);
        Ok(match t["kind"].as_str().context("type without kind")? {
            "int" => Ty::Int,
            "unsigned_int" => Ty::UInt,
            "hyper" => Ty::Hyper,
            "unsigned_hyper" => Ty::UHyper,
            "bool" => Ty::Bool,
            "opaque_fixed" => Ty::OpaqueFixed(max("size").context("opaque_fixed size")?),
            "opaque_var" => Ty::OpaqueVar,
            "string" => Ty::Str(max("max_size")),
            "var_array" => Ty::VarArray(Box::new(self.ty(&t["element"])?), max("max_count")),
            "array" => Ty::Array(
                Box::new(self.ty(&t["element"])?),
                max("count").context("array count")?,
            ),
            "optional" => Ty::Optional(Box::new(self.ty(&t["element"])?)),
            "ref" => {
                let n = t["name"].as_str().context("ref without name")?;
                if let Some(&i) = self.by_name.get(n) {
                    Ty::Def(i)
                } else {
                    let d = self
                        .json
                        .get(n)
                        .with_context(|| format!("unknown type {n}"))?;
                    ensure!(
                        d["kind"] == "typedef",
                        "{n} is neither a type nor a typedef"
                    );
                    self.ty(&d["type"])?
                }
            }
            k => bail!("unknown type kind {k}"),
        })
    }
}

/// Counts per id plus value classes, for one walked input or a merged set.
#[derive(Debug, Clone, Default)]
pub struct Tally {
    pub counts: Vec<u64>,
    /// Arms and states found inside `ConfigUpgradeSet` bytes held in contract data.
    pub in_bytes: Vec<u64>,
    pub classes: BTreeMap<Class, u64>,
    pub max_scval_depth: u32,
}

impl Tally {
    pub fn ensure_len(&mut self, n: usize) {
        if self.counts.len() < n {
            self.counts.resize(n, 0);
            self.in_bytes.resize(n, 0);
        }
    }
    pub fn hit(&self, id: usize) -> u64 {
        self.counts.get(id).copied().unwrap_or(0)
    }
    pub fn hit_in_bytes(&self, id: usize) -> u64 {
        self.in_bytes.get(id).copied().unwrap_or(0)
    }
    pub fn class(&self, c: Class) -> u64 {
        self.classes.get(&c).copied().unwrap_or(0)
    }
    pub fn merge(&mut self, o: &Tally) {
        self.ensure_len(o.counts.len());
        for (a, b) in self.counts.iter_mut().zip(&o.counts) {
            *a += b;
        }
        for (a, b) in self.in_bytes.iter_mut().zip(&o.in_bytes) {
            *a += b;
        }
        for (c, n) in &o.classes {
            *self.classes.entry(*c).or_default() += n;
        }
        self.max_scval_depth = self.max_scval_depth.max(o.max_scval_depth);
    }
}

/// What a walk reports, event by event. [`Tally`] counts ids; the scan's token emitter
/// (`cmd/scan/shape.rs`) also follows the path (`push`/`pop`), the definitions entered, lengths,
/// leaf bytes and the arms of union vectors. `DETAIL = false` sinks pay for none of those.
pub trait Sink {
    /// Whether the walker reports paths, definitions, lengths and leaves.
    const DETAIL: bool = false;
    /// A union arm taken (`Union::CASE`).
    fn arm(&mut self, id: usize, in_bytes: bool);
    /// An optional state (`Struct.field?some|none`, `Union::CASE?some|none`).
    fn opt(&mut self, id: usize, in_bytes: bool);
    /// An enum value read; `discriminant` when it selects a union arm.
    fn enum_value(&mut self, id: usize, discriminant: bool, in_bytes: bool);
    /// A value class (never inside `ConfigUpgradeSet` bytes).
    fn class(&mut self, c: Class);
    /// The current `SCVal` nesting depth (never inside `ConfigUpgradeSet` bytes).
    fn scval_depth(&mut self, depth: u32);
    /// A path segment: a field name, `[]` for vector elements, or an arm's case label.
    fn push(&mut self, _seg: &str) {}
    fn pop(&mut self) {}
    /// A vector or string length, with the declared maximum.
    fn len(&mut self, _n: u32, _max: Option<u32>) {}
    /// For a vector whose element is a union: the case ids of its elements, in order.
    fn vec_arms(&mut self, _cases: &[usize]) {}
    /// A primitive leaf and its bytes (strings and opaques without length or padding).
    fn leaf(&mut self, _ty: &Ty, _bytes: &[u8]) {}
    /// The state of an optional that is a vector element (no id exists for it).
    fn elem_opt(&mut self, _some: bool) {}
    /// A struct, union or enum value begins.
    fn enter(&mut self, _def: usize) {}
    /// It ends; `bytes` is its encoding.
    fn exit(&mut self, _def: usize, _bytes: &[u8]) {}
}

impl Sink for Tally {
    #[inline]
    fn arm(&mut self, id: usize, in_bytes: bool) {
        self.mark(id, in_bytes);
    }
    #[inline]
    fn opt(&mut self, id: usize, in_bytes: bool) {
        self.mark(id, in_bytes);
    }
    #[inline]
    fn enum_value(&mut self, id: usize, _discriminant: bool, in_bytes: bool) {
        self.mark(id, in_bytes);
    }
    #[inline]
    fn class(&mut self, c: Class) {
        *self.classes.entry(c).or_default() += 1;
    }
    #[inline]
    fn scval_depth(&mut self, depth: u32) {
        self.max_scval_depth = self.max_scval_depth.max(depth);
    }
}

impl Tally {
    #[inline]
    fn mark(&mut self, id: usize, in_bytes: bool) {
        if in_bytes {
            self.in_bytes[id] += 1;
        } else {
            self.counts[id] += 1;
        }
    }
}

struct Walker<'a, 't, S: Sink> {
    d: &'a Defs,
    b: &'a [u8],
    pos: usize,
    scval_depth: u32,
    t: &'t mut S,
    in_bytes: bool,
}

impl<S: Sink> Walker<'_, '_, S> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        ensure!(
            self.pos + n <= self.b.len(),
            "walker ran past the end at {}",
            self.pos
        );
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn class(&mut self, c: Class) {
        if !self.in_bytes {
            self.t.class(c);
        }
    }
    fn padded(&mut self, n: usize) -> Result<&[u8]> {
        let pad = (4 - n % 4) % 4;
        let start = self.pos;
        self.take(n + pad)?;
        Ok(&self.b[start..start + n])
    }
    fn at_limit(&mut self, len: u32, max: Option<u32>) {
        if max.is_some_and(|m| m == len && m > 0) {
            self.class(Class::CountAtLimit);
        }
    }
    fn leaf_at(&mut self, t: &Ty, start: usize, n: usize) {
        if S::DETAIL {
            let b = self.b;
            self.t.leaf(t, &b[start..start + n]);
        }
    }

    fn ty(&mut self, t: &Ty) -> Result<()> {
        match t {
            Ty::Int | Ty::UInt | Ty::Bool => {
                let s = self.pos;
                self.take(4)?;
                self.leaf_at(t, s, 4);
            }
            Ty::Hyper => {
                let s = self.pos;
                self.take(8)?;
                self.leaf_at(t, s, 8);
            }
            Ty::UHyper => {
                let s = self.pos;
                if self.u64()? >= 1 << 63 {
                    self.class(Class::U64High);
                }
                self.leaf_at(t, s, 8);
            }
            Ty::OpaqueFixed(n) => {
                let s = self.pos;
                self.padded(*n as usize)?;
                self.leaf_at(t, s, *n as usize);
            }
            Ty::OpaqueVar => {
                // Opaques at their maximum are routine (every ed25519 signature is 64 bytes), so
                // only vectors and strings count for `count-at-limit`.
                let n = self.u32()?;
                let s = self.pos;
                self.padded(n as usize)?;
                self.leaf_at(t, s, n as usize);
            }
            Ty::Str(max) => {
                let n = self.u32()?;
                self.at_limit(n, *max);
                if S::DETAIL {
                    self.t.len(n, *max);
                }
                let s = self.pos;
                if std::str::from_utf8(self.padded(n as usize)?).is_err() {
                    self.class(Class::NonUtf8String);
                }
                self.leaf_at(t, s, n as usize);
            }
            Ty::VarArray(e, max) => {
                let n = self.u32()?;
                self.at_limit(n, *max);
                if !S::DETAIL {
                    for _ in 0..n {
                        self.ty(e)?;
                    }
                    return Ok(());
                }
                self.t.len(n, *max);
                let union = match **e {
                    Ty::Def(u) if matches!(self.d.defs[u].kind, Kind::Union { .. }) => Some(u),
                    _ => None,
                };
                let mut cases = Vec::new();
                self.t.push("[]");
                for _ in 0..n {
                    if let Some(u) = union {
                        if let Some(c) = self.peek_case(u) {
                            cases.push(c);
                        }
                    }
                    self.ty(e)?;
                }
                self.t.pop();
                if union.is_some() && n > 0 {
                    self.t.vec_arms(&cases);
                }
            }
            Ty::Array(e, n) => {
                if S::DETAIL {
                    self.t.push("[]");
                }
                for _ in 0..*n {
                    self.ty(e)?;
                }
                if S::DETAIL {
                    self.t.pop();
                }
            }
            Ty::Optional(e) => match self.u32()? {
                0 => {
                    if S::DETAIL {
                        self.t.elem_opt(false);
                    }
                }
                1 => {
                    if S::DETAIL {
                        self.t.elem_opt(true);
                    }
                    self.ty(e)?
                }
                f => bail!("optional flag {f} at {}", self.pos - 4),
            },
            Ty::Def(i) => self.def(*i)?,
        }
        Ok(())
    }

    /// The case id the union at the current position takes, without consuming anything.
    fn peek_case(&self, u: usize) -> Option<usize> {
        let v = i32::from_be_bytes(self.b.get(self.pos..self.pos + 4)?.try_into().ok()?);
        match &self.d.defs[u].kind {
            Kind::Union { arms, .. } => arms
                .iter()
                .find_map(|a| a.cases.iter().find(|c| c.0 == v).map(|c| c.2)),
            _ => None,
        }
    }

    /// Reads an optional and reports whether it was present.
    fn optional(&mut self, t: &Ty) -> Result<bool> {
        let Ty::Optional(e) = t else {
            self.ty(t)?;
            return Ok(true);
        };
        match self.u32()? {
            0 => Ok(false),
            1 => {
                self.ty(e)?;
                Ok(true)
            }
            f => bail!("optional flag {f} at {}", self.pos - 4),
        }
    }

    fn def(&mut self, i: usize) -> Result<()> {
        let start = self.pos;
        if S::DETAIL {
            self.t.enter(i);
        }
        self.def_body(i)?;
        if S::DETAIL {
            let b = self.b;
            self.t.exit(i, &b[start..self.pos]);
        }
        Ok(())
    }

    fn def_body(&mut self, i: usize) -> Result<()> {
        let d = self.d;
        let sp = &d.special;
        match &d.defs[i].kind {
            Kind::Struct(fields) => {
                let start = self.pos;
                for (name, ty, opt) in fields {
                    if S::DETAIL {
                        self.t.push(name);
                    }
                    if let Some((s, n)) = opt {
                        let some = self.optional(ty)?;
                        self.t.opt(if some { *s } else { *n }, self.in_bytes);
                    } else {
                        let before = self.pos;
                        self.ty(ty)?;
                        if Some(i) == sp.stellar_value
                            && name == "upgrades"
                            && self.b[before..before + 4] != [0, 0, 0, 0]
                        {
                            self.class(Class::LedgerUpgrades);
                        }
                    }
                    if S::DETAIL {
                        self.t.pop();
                    }
                }
                if Some(i) == sp.int128 {
                    let hi = i64::from_be_bytes(self.b[start..start + 8].try_into().unwrap());
                    if hi != 0 {
                        self.class(Class::I128HiNonzero);
                    }
                    if hi < 0 {
                        self.class(Class::I128Negative);
                    }
                } else if Some(i) == sp.int256 && self.b[start] & 0x80 != 0 {
                    self.class(Class::I256Negative);
                }
            }
            Kind::Enum(m) => {
                let v = self.u32()? as i32;
                let id = *m
                    .get(&v)
                    .with_context(|| format!("{}: undeclared value {v}", d.defs[i].name))?;
                self.t.enum_value(id, false, self.in_bytes);
            }
            Kind::Union { disc_enum, arms } => {
                let v = self.u32()? as i32;
                if let Some(e) = disc_enum {
                    if let Kind::Enum(m) = &d.defs[*e].kind {
                        if let Some(&id) = m.get(&v) {
                            self.t.enum_value(id, true, self.in_bytes);
                        }
                    }
                }
                let (arm, case) = arms
                    .iter()
                    .find_map(|a| a.cases.iter().find(|c| c.0 == v).map(|c| (a, c)))
                    .with_context(|| format!("{}: no arm for {v}", d.defs[i].name))?;
                self.t.arm(case.2, self.in_bytes);
                let is_scval = Some(i) == sp.scval;
                if is_scval {
                    self.scval_depth += 1;
                    if !self.in_bytes {
                        self.t.scval_depth(self.scval_depth);
                    }
                }
                if let Some(t) = &arm.ty {
                    if S::DETAIL {
                        self.t.push(&case.1);
                    }
                    if let Some((s, n)) = arm.opt {
                        let some = self.optional(t)?;
                        self.t.opt(if some { s } else { n }, self.in_bytes);
                    } else if is_scval && Some(v) == sp.scv_bytes_value && !self.in_bytes {
                        let n = self.u32()? as usize;
                        let start = self.pos;
                        self.padded(n)?;
                        if S::DETAIL {
                            self.t.len(n as u32, None);
                            self.leaf_at(&Ty::OpaqueVar, start, n);
                        }
                        self.maybe_upgrade_set(start, n);
                    } else {
                        self.ty(t)?;
                    }
                    if S::DETAIL {
                        self.t.pop();
                    }
                }
                if is_scval {
                    self.scval_depth -= 1;
                }
            }
        }
        Ok(())
    }

    /// Walk SCV_BYTES content that the oracle reads as a non-empty `ConfigUpgradeSet`.
    fn maybe_upgrade_set(&mut self, start: usize, n: usize) {
        let Some(cus) = self.d.special.config_upgrade_set else {
            return;
        };
        let bytes = &self.b[start..start + n];
        // A ConfigUpgradeSet starts with a small entry count and a small ConfigSettingID.
        if n < 8 || bytes[..3] != [0, 0, 0] || bytes[3] == 0 || bytes[4..7] != [0, 0, 0] {
            return;
        }
        use xdrcheck_xdr::xdr::ReadXdr;
        let limits = xdrcheck_xdr::Limits::default().xdr(n);
        if xdrcheck_xdr::xdr::ConfigUpgradeSet::from_xdr(bytes, limits).is_err() {
            return;
        }
        let mut inner = Walker {
            d: self.d,
            b: bytes,
            pos: 0,
            scval_depth: 0,
            t: &mut *self.t,
            in_bytes: true,
        };
        // The oracle accepted the bytes; a walker failure here would be a definitions mismatch.
        if inner.def(cus).is_err() || inner.pos != n {
            eprintln!("warning: ConfigUpgradeSet bytes the oracle accepts did not walk");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn universe_of_the_ledger_batch_at_xdr_30() {
        let d = Defs::pinned();
        let u = d.universe("LedgerCloseMetaBatch").unwrap();
        let arms = u.iter().filter(|&&i| d.kind(i) == IdKind::Arm).count();
        let opts = u.iter().filter(|&&i| d.kind(i) == IdKind::Opt).count();
        assert_eq!((arms, opts), (499, 58));
    }

    #[test]
    fn walks_an_scval_and_finds_classes() {
        use xdrcheck_xdr::xdr::{Int128Parts, ScVal, WriteXdr};
        let v = ScVal::Vec(Some(
            vec![
                ScVal::I128(Int128Parts { hi: -1, lo: 5 }),
                ScVal::U64(u64::MAX),
                ScVal::Timepoint(7u64.into()),
            ]
            .try_into()
            .unwrap(),
        ));
        let bytes = v.to_xdr(xdrcheck_xdr::xdr::Limits::none()).unwrap();
        let d = Defs::pinned();
        let mut t = Tally::default();
        d.walk("SCVal", &bytes, &mut t).unwrap();
        assert_eq!(t.hit(d.id("SCVal::SCV_TIMEPOINT").unwrap()), 1);
        assert_eq!(t.hit(d.id("SCVal::SCV_VEC?some").unwrap()), 1);
        assert_eq!(t.class(Class::I128Negative), 1);
        assert_eq!(t.class(Class::U64High), 1);
        assert_eq!(t.max_scval_depth, 2);
        assert_eq!(d.type_name("ScVal"), Some("SCVal"));
    }

    #[test]
    fn definitions_are_the_pinned_file() {
        let raw = zstd::decode_all(DEFINITIONS_ZST).unwrap();
        assert_eq!(xdrcheck_xdr::sha256_hex(&raw), DEFINITIONS_SHA256);
    }
}
