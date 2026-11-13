//! The mutators.
//!
//! Three classes:
//!
//! 1. **valid-preserving** — the result is still a valid value of the type (the oracle must accept
//!    it): applied to the typed tree and re-encoded.
//! 2. **metamorphic** — the result must give the same facts as the original: applied to the typed
//!    ledger (`xdrcheck_meta::permute`).
//! 3. **wire-invalid** — the oracle must refuse the result: applied to the bytes, at the offsets the
//!    typed tree gives.
//!
//! A [`Mutation`] names one mutator at one place (the node's location in the tree, its value path)
//! with one argument. Its ID is a hash of the entry, variant, seed, mutator, location and argument,
//! so the bytes of a mutant are a pure function of (entry, seed, mutator, path).

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::schema::{Schema, Shape, Ty, UNBOUNDED};
use crate::tree::{self, Node, Site, V};

/// A mutator class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
pub enum Class {
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "metamorphic")]
    Metamorphic,
    #[serde(rename = "wire-invalid")]
    Wire,
}

impl Class {
    pub fn number(self) -> u8 {
        match self {
            Class::Valid => 1,
            Class::Metamorphic => 2,
            Class::Wire => 3,
        }
    }
}

/// A mutator's description.
#[derive(Debug, Clone, Copy)]
pub struct Info {
    pub id: &'static str,
    pub class: Class,
    /// How many arguments it takes (the argument is chosen per site from the seed).
    pub args: u32,
    pub about: &'static str,
}

/// Every mutator.
pub const MUTATORS: &[Info] = &[
    Info { id: "union-arm", class: Class::Valid, args: 64, about: "switch a union to a sibling arm with a minimal payload" },
    Info { id: "address-kind", class: Class::Valid, args: 8, about: "switch an SCAddress or MuxedAccount to another kind (G, C, M, B, L, muxed contract)" },
    Info { id: "ext-arm", class: Class::Valid, args: 8, about: "switch an extension union to another arm" },
    Info { id: "int-edge", class: Class::Valid, args: 6, about: "set an integer to a boundary value (0, 1, -1, the type's min and max, 2^63, u32 max)" },
    Info { id: "wide-edge", class: Class::Valid, args: 5, about: "set an i128/u128/i256/u256 to a hi/lo edge" },
    Info { id: "opt-toggle", class: Class::Valid, args: 1, about: "make a present optional absent, or an absent one present with a minimal value" },
    Info { id: "array-resize", class: Class::Valid, args: 3, about: "resize a variable array or opaque to 0, 1 or its declared maximum" },
    Info { id: "text-bytes", class: Class::Valid, args: 4, about: "replace a string, symbol or asset code with NUL, non-UTF-8, escape-like or maximum-length bytes" },
    Info { id: "deepen", class: Class::Valid, args: 16, about: "wrap an SCVal in vectors, or an authorized invocation in sub-invocations, on a depth ladder" },
    Info { id: "map-keys", class: Class::Valid, args: 3, about: "duplicate a map key, swap two map entries, or reverse a map" },
    Info { id: "change-permute", class: Class::Metamorphic, args: 1, about: "permute each operation's change list in STATE/UPDATED|REMOVED pair units" },
    Info { id: "timing", class: Class::Metamorphic, args: 2, about: "zero or alter the core_metrics timing diagnostics" },
    Info { id: "bool-2", class: Class::Wire, args: 2, about: "a bool of 2 or 0xffffffff" },
    Info { id: "opt-flag-2", class: Class::Wire, args: 1, about: "an optional flag of 2" },
    Info { id: "padding-nonzero", class: Class::Wire, args: 1, about: "a non-zero padding byte" },
    Info { id: "disc-unknown", class: Class::Wire, args: 2, about: "a union discriminant without an arm" },
    Info { id: "enum-range", class: Class::Wire, args: 2, about: "an enum value outside the declared members" },
    Info { id: "len-over-remaining", class: Class::Wire, args: 3, about: "a length prefix above the remaining input" },
    Info { id: "len-over-max", class: Class::Wire, args: 1, about: "a length prefix above the declared maximum" },
    Info { id: "truncate", class: Class::Wire, args: 3, about: "cut the value short" },
    Info { id: "trailing", class: Class::Wire, args: 3, about: "append bytes after the value" },
];

/// The description of a mutator ID.
pub fn info(id: &str) -> Option<&'static Info> {
    MUTATORS.iter().find(|m| m.id == id)
}

/// One mutation: a mutator, a place and an argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mutation {
    pub id: String,
    pub mutator: String,
    pub class: Class,
    /// Child steps from the root, as `.`-joined numbers (empty for the root).
    pub loc: String,
    /// Value path.
    pub path: String,
    /// The path with indices generalised (`*`), for signatures.
    pub type_path: String,
    /// The most specific named type at the place.
    pub type_name: String,
    pub arg: u32,
    /// The node's byte range in the unmutated value.
    pub off: u32,
    pub end: u32,
}

/// The identity a mutation's ID is computed from.
#[derive(Debug, Clone)]
pub struct Origin<'a> {
    pub entry: &'a str,
    pub variant: usize,
    pub seed: u64,
}

pub fn mutation_id(o: &Origin<'_>, mutator: &str, loc: &str, arg: u32) -> String {
    let mut h = Sha256::new();
    h.update(format!(
        "{}\0{}\0{}\0{mutator}\0{loc}\0{arg}",
        o.entry, o.variant, o.seed
    ));
    format!("m{}", &hex::encode(h.finalize())[..12])
}

/// The argument a mutator takes at one place, from the seed.
pub fn pick_arg(o: &Origin<'_>, mutator: &str, loc: &str, n: u32) -> u32 {
    if n <= 1 {
        return 0;
    }
    let mut h = Sha256::new();
    h.update(format!(
        "arg\0{}\0{}\0{}\0{mutator}\0{loc}",
        o.entry, o.variant, o.seed
    ));
    let d = h.finalize();
    u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % n
}

fn loc_string(loc: &[u32]) -> String {
    loc.iter().map(u32::to_string).collect::<Vec<_>>().join(".")
}

/// Parse a location string.
pub fn parse_loc(s: &str) -> Result<Vec<u32>> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    s.split('.')
        .map(|x| x.parse::<u32>().map_err(|_| anyhow!("bad location {s}")))
        .collect()
}

/// Ledger paths valid-preserving mutators leave alone.
pub const PINNED_LEDGER_PATHS: &[&str] = &[
    "/ledgerHeader/header/ledgerVersion",
    "/ledgerHeader/header/ledgerSeq",
];

/// Every (mutator, place) the value admits, for the classes asked, with the argument the seed
/// picks. Metamorphic mutators apply to a whole ledger (`/`) and are listed only when
/// `ledger` is set; whether they change anything is known only when applied.
pub fn candidates(
    s: &Schema,
    sites: &[Site],
    root: &Node,
    o: &Origin<'_>,
    classes: &[Class],
    ledger: bool,
) -> Result<Vec<Mutation>> {
    let mut out = Vec::new();
    let want_any = |c: Class| classes.contains(&c);
    let mut push = |site: &Site, mutator: &str, nargs: u32| {
        let inf = info(mutator).expect("registered mutator");
        let loc = loc_string(&site.loc);
        let arg = pick_arg(o, mutator, &loc, nargs.min(inf.args).max(1));
        out.push(Mutation {
            id: mutation_id(o, mutator, &loc, arg),
            mutator: mutator.to_string(),
            class: inf.class,
            loc,
            path: site.path.clone(),
            type_path: site.type_path(),
            type_name: site
                .type_name
                .clone()
                .unwrap_or_else(|| prim_name(&site.ty)),
            arg,
            off: site.off,
            end: site.end,
        });
    };
    for site in sites {
        let (shape, _) = s.shape(&site.ty)?;
        let node = root
            .at(&site.loc)
            .ok_or_else(|| anyhow!("site {} vanished", site.path))?;
        // A ledger's own protocol version and sequence number, and its top-level arm, decide how the
        // whole ledger is read and served; a valid-preserving mutation there makes a different
        // ledger rather than a different value in it.
        let pinned = ledger
            && (site.loc.is_empty() || PINNED_LEDGER_PATHS.iter().any(|p| site.path.ends_with(p)));
        let want = |c: Class| want_any(c) && !(pinned && c == Class::Valid);
        let tname = site.type_name.as_deref().unwrap_or("");
        let field = site.field.as_deref().unwrap_or("");
        match (shape, &node.v) {
            (Shape::Union(_, arms), V::Union(..)) => {
                if want(Class::Valid) && arms.len() > 1 {
                    let m = if matches!(tname, "SCAddress" | "MuxedAccount") {
                        "address-kind"
                    } else if tname.ends_with("Ext") || field == "ext" || tname == "ExtensionPoint"
                    {
                        "ext-arm"
                    } else {
                        "union-arm"
                    };
                    push(site, m, arms.len() as u32 - 1);
                }
                if want(Class::Valid) && tname == "SCVal" {
                    push(site, "deepen", scval_rungs() as u32);
                }
                if want(Class::Valid) && tname == "SorobanAuthorizedInvocation" {
                    push(site, "deepen", 3);
                }
                if want(Class::Wire) {
                    push(site, "disc-unknown", 2);
                }
            }
            (Shape::Struct(_), V::Struct(_)) => {
                if want(Class::Valid)
                    && matches!(
                        tname,
                        "Int128Parts" | "UInt128Parts" | "Int256Parts" | "UInt256Parts"
                    )
                {
                    push(site, "wide-edge", 5);
                }
                if want(Class::Valid) && tname == "SorobanAuthorizedInvocation" {
                    push(site, "deepen", 3);
                }
            }
            (Shape::Enum(_), V::Enum(_)) => {
                if want(Class::Wire) {
                    push(site, "enum-range", 2);
                }
            }
            (Shape::Prim(p), v) => match (p, v) {
                (Ty::Int | Ty::UInt | Ty::Hyper | Ty::UHyper, _) => {
                    if want(Class::Valid) {
                        push(site, "int-edge", int_edges(p).len() as u32);
                    }
                }
                (Ty::Bool, _) => {
                    if want(Class::Wire) {
                        push(site, "bool-2", 2);
                    }
                }
                (Ty::Optional(_), _) => {
                    if want(Class::Valid) {
                        push(site, "opt-toggle", 1);
                    }
                    if want(Class::Wire) {
                        push(site, "opt-flag-2", 1);
                    }
                }
                (Ty::OpaqueFixed(_) | Ty::OpaqueVar(_) | Ty::Str(_), V::Bytes(b)) => {
                    let text =
                        matches!(p, Ty::Str(_)) || matches!(tname, "AssetCode4" | "AssetCode12");
                    if want(Class::Valid) && text {
                        push(site, "text-bytes", 4);
                    }
                    if want(Class::Valid) && matches!(p, Ty::OpaqueVar(_)) {
                        push(site, "array-resize", 3);
                    }
                    if want(Class::Wire) && b.len() % 4 != 0 {
                        push(site, "padding-nonzero", 1);
                    }
                    if want(Class::Wire) && !matches!(p, Ty::OpaqueFixed(_)) {
                        push(site, "len-over-remaining", 3);
                        if matches!(p, Ty::OpaqueVar(m) | Ty::Str(m) if *m != UNBOUNDED) {
                            push(site, "len-over-max", 1);
                        }
                    }
                }
                (Ty::VarArray(_, max), V::List(_)) => {
                    if want(Class::Valid) {
                        push(site, "array-resize", 3);
                        if tname == "SCMap" {
                            push(site, "map-keys", 3);
                        }
                    }
                    if want(Class::Wire) {
                        push(site, "len-over-remaining", 3);
                        if *max != UNBOUNDED {
                            push(site, "len-over-max", 1);
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
        if site.loc.is_empty() {
            if want(Class::Wire) {
                push(site, "truncate", 3);
                push(site, "trailing", 3);
            }
            if want(Class::Metamorphic) && ledger {
                push(site, "change-permute", 1);
                push(site, "timing", 2);
            }
        }
    }
    Ok(out)
}

fn prim_name(t: &Ty) -> String {
    match t {
        Ty::Int => "int",
        Ty::UInt => "unsigned int",
        Ty::Hyper => "hyper",
        Ty::UHyper => "unsigned hyper",
        Ty::Bool => "bool",
        Ty::OpaqueFixed(_) => "opaque[]",
        Ty::OpaqueVar(_) => "opaque<>",
        Ty::Str(_) => "string<>",
        Ty::Array(..) => "array[]",
        Ty::VarArray(..) => "array<>",
        Ty::Optional(_) => "optional",
        Ty::Ref(n) => n,
    }
    .to_string()
}

/// Integer boundary values of a type, as raw 64-bit patterns.
fn int_edges(t: &Ty) -> &'static [u64] {
    const I32: &[u64] = &[
        0,
        1,
        u32::MAX as u64, /* -1 */
        0x8000_0000,     /* min */
        0x7fff_ffff,     /* max */
    ];
    const U32: &[u64] = &[0, 1, u32::MAX as u64, 0x8000_0000];
    const I64: &[u64] = &[
        0,
        1,
        u64::MAX, /* -1 */
        1 << 63,  /* min */
        i64::MAX as u64,
        u32::MAX as u64,
    ];
    const U64: &[u64] = &[0, 1, 1 << 63, u64::MAX, u32::MAX as u64, i64::MAX as u64];
    match t {
        Ty::Int => I32,
        Ty::UInt => U32,
        Ty::Hyper => I64,
        _ => U64,
    }
}

/// The public SCVal ladder of `deepen`: wrap this many vectors.
pub const SCVAL_LADDER: [u32; 3] = [2, 16, 64];
/// The most `SCVal` nesting a public rung builds, counting the vectors and maps around the place and
/// inside the wrapped value: a public rung is shortened to stay at or below it.
pub const SCVAL_PUBLIC_MAX_NESTING: u32 = 96;

/// Further rungs read from the private overlay (`$XDRCHECK_OVERLAY/mutate/deepen.json`,
/// `{"scval": [N, …]}`), only when `XDRCHECK_OVERLAY` is set. They follow the public rungs and are not
/// shortened.
fn overlay_rungs() -> &'static [u32] {
    static RUNGS: std::sync::OnceLock<Vec<u32>> = std::sync::OnceLock::new();
    RUNGS.get_or_init(|| {
        let Some(dir) = std::env::var_os("XDRCHECK_OVERLAY").filter(|d| !d.is_empty()) else {
            return Vec::new();
        };
        let path = std::path::Path::new(&dir)
            .join("mutate")
            .join("deepen.json");
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        #[derive(Deserialize)]
        struct Rungs {
            #[serde(default)]
            scval: Vec<u32>,
        }
        match serde_json::from_str::<Rungs>(&text) {
            Ok(r) => r.scval,
            Err(e) => panic!("{}: {e}", path.display()),
        }
    })
}

/// The number of rungs of the SCVal ladder in this run.
pub fn scval_rungs() -> usize {
    SCVAL_LADDER.len() + overlay_rungs().len()
}

/// The wrap count of a rung, and whether it is a public one.
fn scval_rung(arg: u32) -> (u32, bool) {
    let i = arg as usize % scval_rungs();
    match SCVAL_LADDER.get(i) {
        Some(k) => (*k, true),
        None => (overlay_rungs()[i - SCVAL_LADDER.len()], false),
    }
}

/// A public rung of `k` wraps at `path`, shortened so the nesting stays at or below
/// [`SCVAL_PUBLIC_MAX_NESTING`].
fn public_wraps(k: u32, path: &str, node: &Node) -> u32 {
    let around = scval_levels_above(path) + scval_levels_within(node);
    k.min(SCVAL_PUBLIC_MAX_NESTING.saturating_sub(around))
}

/// The `SCVal` vectors and maps a value path passes through.
fn scval_levels_above(path: &str) -> u32 {
    path.split('/')
        .filter(|p| matches!(*p, "vec" | "map"))
        .count() as u32
}

/// An upper bound of the `SCVal` nesting inside a value: every vector level is at least three tree
/// levels (union, optional, list) and every map level four.
fn scval_levels_within(node: &Node) -> u32 {
    let mut height = 0u32;
    let mut stack = vec![(node, 1u32)];
    while let Some((n, d)) = stack.pop() {
        height = height.max(d);
        match &n.v {
            V::List(xs) | V::Struct(xs) => stack.extend(xs.iter().map(|x| (x, d + 1))),
            V::Union(_, Some(x)) | V::Opt(Some(x)) => stack.push((x, d + 1)),
            _ => {}
        }
    }
    height.div_ceil(3)
}
/// The authorized-invocation ladder of `deepen`.
pub const AUTH_LADDER: [u32; 3] = [2, 8, 32];

const TEXT_NUL: &[u8] = b"\0";
const TEXT_NON_UTF8: &[u8] = b"\xff\xfe\x80";
const TEXT_ESCAPE: &[u8] = b"\\u0000\"'%00<\x1b";

/// The protocol rule a valid-preserving mutation breaks, if any. XDR admits any bytes in a string or
/// a fixed opaque, but stellar-core admits only alphanumeric asset codes, symbols of
/// `[A-Za-z0-9_]`, and home domains and data names of printable ASCII; it never emits other values.
/// A reader may refuse such a value; reading it wrongly is still judged.
pub fn protocol_rule(m: &Mutation) -> Option<&'static str> {
    if m.mutator != "text-bytes" || m.arg % 4 == 3 {
        return None;
    }
    match m.type_name.as_str() {
        "AssetCode4" | "AssetCode12" => Some("an asset code must be alphanumeric"),
        "SCSymbol" => Some("a symbol is limited to [A-Za-z0-9_]"),
        "string32" | "string64" => Some("a home domain or data name is printable ASCII"),
        _ => None,
    }
}

/// Apply a class-1 mutation to the tree. `Ok(false)`: the place no longer exists or the mutation
/// changes nothing there (an earlier mutation of the same mutant replaced it).
pub fn apply_valid(s: &Schema, root_ty: &Ty, root: &mut Node, m: &Mutation) -> Result<bool> {
    let loc = parse_loc(&m.loc)?;
    let Ok(t) = tree::type_at(s, root_ty, root, &loc) else {
        return Ok(false);
    };
    let (shape, name) = s.shape(&t)?;
    let name = name.map(str::to_string).unwrap_or_else(|| prim_name(&t));
    // An earlier mutation of the same mutant may have replaced what was here.
    if name != m.type_name {
        return Ok(false);
    }
    let Some(node) = root.at_mut(&loc) else {
        return Ok(false);
    };
    let before = node.clone();
    match (m.mutator.as_str(), shape) {
        ("union-arm" | "address-kind" | "ext-arm", Shape::Union(_, arms)) => {
            let V::Union(d, _) = &node.v else {
                return Ok(false);
            };
            let others: Vec<_> = arms
                .iter()
                .filter(|a| !a.cases.iter().any(|(c, _)| c == d))
                .collect();
            let Some(arm) = others.get(m.arg as usize % others.len().max(1)) else {
                return Ok(false);
            };
            let payload = match &arm.ty {
                Some(at) => Some(Box::new(tree::minimal(s, at)?)),
                None => None,
            };
            node.v = V::Union(arm.cases[0].0, payload);
        }
        ("int-edge", Shape::Prim(p)) => {
            let e = int_edges(p);
            let raw = e[m.arg as usize % e.len()];
            node.v = match p {
                Ty::Int => V::I32(raw as u32 as i32),
                Ty::UInt => V::U32(raw as u32),
                Ty::Hyper => V::I64(raw as i64),
                Ty::UHyper => V::U64(raw),
                _ => return Ok(false),
            };
        }
        ("wide-edge", Shape::Struct(_)) => {
            let V::Struct(parts) = &mut node.v else {
                return Ok(false);
            };
            let signed = name.starts_with("Int");
            // (most significant word, every other word) per edge: 0, the type's max, its min, -1
            // (or for unsigned the all-ones value), and one past the 64-bit range.
            let (hi, rest): (u64, u64) = match m.arg % 5 {
                0 => (0, 0),
                1 => (if signed { i64::MAX as u64 } else { u64::MAX }, u64::MAX),
                2 => (if signed { 1 << 63 } else { 0 }, 0),
                3 => (u64::MAX, u64::MAX),
                _ => (0, 0),
            };
            let n = parts.len();
            for (i, p) in parts.iter_mut().enumerate() {
                let w = if i == 0 {
                    hi
                } else if m.arg % 5 == 4 {
                    if i == n - 2 {
                        1
                    } else {
                        0
                    }
                } else {
                    rest
                };
                p.v = match p.v {
                    V::I64(_) => V::I64(w as i64),
                    V::U64(_) => V::U64(w),
                    _ => return Ok(false),
                };
            }
        }
        ("opt-toggle", Shape::Prim(Ty::Optional(e))) => {
            node.v = match &node.v {
                V::Opt(Some(_)) => V::Opt(None),
                V::Opt(None) => V::Opt(Some(Box::new(tree::minimal(s, e)?))),
                _ => return Ok(false),
            };
        }
        ("array-resize", Shape::Prim(p)) => match (p, &mut node.v) {
            (Ty::VarArray(e, max), V::List(items)) => {
                let el = items
                    .first()
                    .cloned()
                    .map(Ok)
                    .unwrap_or_else(|| tree::minimal(s, e))?;
                let n = match m.arg % 3 {
                    0 => 0,
                    1 => 1,
                    _ => {
                        if *max == UNBOUNDED || *max > 1000 {
                            return Ok(false);
                        }
                        *max as usize
                    }
                };
                *items = vec![el; n];
            }
            (Ty::OpaqueVar(max), V::Bytes(b)) => {
                let n = match m.arg % 3 {
                    0 => 0,
                    1 => 1,
                    _ => {
                        if *max == UNBOUNDED || *max > 4096 {
                            return Ok(false);
                        }
                        *max as usize
                    }
                };
                let fill = b.first().copied().unwrap_or(0x61);
                *b = vec![fill; n];
            }
            _ => return Ok(false),
        },
        ("text-bytes", Shape::Prim(p)) => {
            let V::Bytes(b) = &mut node.v else {
                return Ok(false);
            };
            let (fixed, max) = match p {
                Ty::OpaqueFixed(n) => (true, *n as usize),
                Ty::Str(n) | Ty::OpaqueVar(n) => (false, (*n).min(4096) as usize),
                _ => return Ok(false),
            };
            let mut new = match m.arg % 4 {
                0 => TEXT_NUL.to_vec(),
                1 => TEXT_NON_UTF8.to_vec(),
                2 => TEXT_ESCAPE.to_vec(),
                _ => {
                    if max == 0 {
                        return Ok(false);
                    }
                    vec![b'a'; max]
                }
            };
            new.truncate(max);
            if fixed {
                new.resize(max, 0);
            }
            *b = new;
        }
        ("deepen", Shape::Union(..)) if name == "SCVal" => {
            let (mut k, public) = scval_rung(m.arg);
            if public {
                k = public_wraps(k, &m.path, node);
                if k == 0 {
                    return Ok(false);
                }
            }
            let mut cur = node.clone();
            for _ in 0..k {
                // SCV_VEC = 16: an optional SCVec holding the value.
                cur = Node::new(V::Union(
                    16,
                    Some(Box::new(Node::new(V::Opt(Some(Box::new(Node::new(
                        V::List(vec![cur]),
                    ))))))),
                ));
            }
            *node = cur;
        }
        ("deepen", Shape::Struct(_)) if name == "SorobanAuthorizedInvocation" => {
            let k = AUTH_LADDER[m.arg as usize % AUTH_LADDER.len()];
            let mut cur = node.clone();
            for _ in 0..k {
                let mut wrapper = cur.clone();
                let V::Struct(f) = &mut wrapper.v else {
                    return Ok(false);
                };
                // fields: function, subInvocations
                f[1] = Node::new(V::List(vec![cur]));
                cur = wrapper;
            }
            *node = cur;
        }
        ("map-keys", Shape::Prim(Ty::VarArray(..))) => {
            let V::List(items) = &mut node.v else {
                return Ok(false);
            };
            match m.arg % 3 {
                0 if !items.is_empty() => {
                    let dup = items[0].clone();
                    items.insert(1, dup);
                }
                1 if items.len() >= 2 => items.swap(0, 1),
                2 if items.len() >= 2 => items.reverse(),
                _ => return Ok(false),
            }
        }
        _ => return Ok(false),
    }
    Ok(*node != before)
}

/// Apply a class-3 mutation to the bytes of the unmutated value. `Ok(false)`: not applicable.
pub fn apply_wire(
    bytes: &mut Vec<u8>,
    m: &Mutation,
    s: &Schema,
    root_ty: &Ty,
    root: &Node,
) -> Result<bool> {
    let off = m.off as usize;
    let end = m.end as usize;
    if end > bytes.len() || off > end {
        bail!("mutation {} is outside the value", m.id);
    }
    let put = |bytes: &mut Vec<u8>, at: usize, w: u32| -> bool {
        if at + 4 > bytes.len() {
            return false;
        }
        bytes[at..at + 4].copy_from_slice(&w.to_be_bytes());
        true
    };
    let loc = parse_loc(&m.loc)?;
    let t = tree::type_at(s, root_ty, root, &loc)?;
    let (shape, _) = s.shape(&t)?;
    Ok(match m.mutator.as_str() {
        "bool-2" => put(
            bytes,
            off,
            if m.arg.is_multiple_of(2) { 2 } else { u32::MAX },
        ),
        "opt-flag-2" => put(bytes, off, 2),
        "padding-nonzero" => {
            if end == 0 || end - off < 1 {
                return Ok(false);
            }
            bytes[end - 1] = 0x01;
            true
        }
        "disc-unknown" => {
            let Shape::Union(disc, arms) = shape else {
                return Ok(false);
            };
            let cased: Vec<i32> = arms
                .iter()
                .flat_map(|a| a.cases.iter().map(|c| c.0))
                .collect();
            let w = if m.arg % 2 == 1 {
                0x7fff_ffff
            } else {
                // A declared enum member without an arm, else one past the largest case.
                s.enum_members(disc)
                    .and_then(|mem| mem.iter().map(|x| x.1).find(|v| !cased.contains(v)))
                    .unwrap_or_else(|| cased.iter().copied().max().unwrap_or(0).wrapping_add(1))
            };
            if cased.contains(&w) {
                return Ok(false);
            }
            put(bytes, off, w as u32)
        }
        "enum-range" => {
            let Shape::Enum(mem) = shape else {
                return Ok(false);
            };
            let w = if m.arg.is_multiple_of(2) {
                mem.iter().map(|x| x.1).max().unwrap_or(0).wrapping_add(1)
            } else {
                -1
            };
            if mem.iter().any(|x| x.1 == w) {
                return Ok(false);
            }
            put(bytes, off, w as u32)
        }
        "len-over-remaining" => {
            let remaining = bytes.len().saturating_sub(off + 4) as u64;
            // Just past the input, the largest signed 32-bit length, the largest unsigned one.
            let w = match m.arg % 3 {
                0 => (remaining + 1).min(u32::MAX as u64) as u32,
                1 => i32::MAX as u32,
                _ => u32::MAX,
            };
            put(bytes, off, w)
        }
        "len-over-max" => {
            let max = match shape {
                Shape::Prim(Ty::OpaqueVar(m) | Ty::Str(m) | Ty::VarArray(_, m)) => *m,
                _ => return Ok(false),
            };
            if max == UNBOUNDED {
                return Ok(false);
            }
            put(bytes, off, max + 1)
        }
        "truncate" => {
            let n = match m.arg % 3 {
                0 => 1,
                1 => 4,
                _ => bytes.len() / 2,
            };
            if n == 0 || n > bytes.len() {
                return Ok(false);
            }
            bytes.truncate(bytes.len() - n);
            true
        }
        "trailing" => {
            let n = [1usize, 2, 4][m.arg as usize % 3];
            bytes.extend(std::iter::repeat_n(0u8, n));
            true
        }
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vecs(n: u32) -> Node {
        let mut cur = Node::new(V::Union(0, None));
        for _ in 0..n {
            cur = Node::new(V::Union(
                16,
                Some(Box::new(Node::new(V::Opt(Some(Box::new(Node::new(
                    V::List(vec![cur]),
                ))))))),
            ));
        }
        cur
    }

    #[test]
    fn public_rungs_stay_within_the_public_nesting() {
        assert_eq!(public_wraps(64, "/args/0", &vecs(0)), 64);
        // 30 levels above, 20 within (counted from above): the rung is shortened.
        let path = "/args/0".to_string() + &"/vec/0".repeat(30);
        let k = public_wraps(64, &path, &vecs(20));
        assert!(k > 0 && k + 30 + 20 <= SCVAL_PUBLIC_MAX_NESTING, "{k}");
        assert_eq!(public_wraps(64, &path, &vecs(90)), 0);
        assert!(SCVAL_LADDER.iter().all(|k| *k <= SCVAL_PUBLIC_MAX_NESTING));
    }
}
