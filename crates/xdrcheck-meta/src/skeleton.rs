//! The structural skeleton (check AG-4, `docs/architecture.md`).
//!
//! A skeleton keeps a value's *shape* and drops its values, so a local-core run on the testnet or
//! public passphrase can be compared with a stellar-core golden although every key, hash and
//! signature differs. It is computed by a typed walk over the decoded value, after stellar-core's
//! golden-comparison normalisation ([`crate::normalise`]).
//!
//! **The walk.** The value is rendered as SEP-51 JSON by the pinned `stellar-xdr` 30.0.0 and walked
//! against that library's own JSON Schema of `LedgerCloseMeta` (vendored as
//! `skeleton/schema-LedgerCloseMeta.json`: the verbatim output of `stellar-xdr types schema --type
//! LedgerCloseMeta` of the `stellar-xdr` 30.0.0 command, sha256
//! `d294a794cbf71cca683e7b863fe970546844c64ed64b36be075faa401b1f616f`). The schema carries the XDR
//! types, so a void union arm and a string leaf never look alike:
//!
//! | construct | skeleton |
//! |---|---|
//! | struct | `{field: skeleton, …}` in declaration order |
//! | union | `{"|": arm}` for a void arm, `{"|": arm, "v": skeleton}` otherwise (arm names are the shape) |
//! | enum, bool | kept |
//! | optional | `null`, or `{"?": skeleton}`; an optional integer the schema writes as a type union (`["integer", "null"]`) is a leaf like any other, so its presence is masked (`#['integer', 'null']` whether set or not; AG-4 compares that presence through the scan's shape tokens) |
//! | array | `{"n": length, "items": [skeleton, …]}` |
//! | `ScSymbol` | kept (function, topic and map-key names are identifiers) |
//! | strkey-rendered unions (`ScAddress`, `MuxedAccount`, `SignerKey`, `PublicKey`, `AccountId`, `NodeId`, `ContractId`, `ClaimableBalanceId`, `PoolId`) | `#<Type>:<version letter>` (`G`, `M`, `C`, `W`, `P`, `T`, `X`, `B`, `L`) |
//! | every other leaf | `#<nearest named schema type>`, or the union-arm path (`#ScVal.u64`), or the JSON type (`#integer`) |
//!
//! No collapsing and no masks: array lengths, diagnostic events, signatures and footprints are all
//! inside the comparison.
//!
//! **Scope `tx`** (the AG-4 scope): one transaction in apply order — its envelope, result pair, fee
//! processing, every field of its apply meta (one section per field, plus the meta arm), post-apply
//! fee processing and the processing record's extension. **Scope `ledger`**: the whole normalised
//! `LedgerCloseMeta` as one section.
//!
//! **Hash.** Canonical JSON (compact, keys in insertion order, UTF-8 unescaped), SHA-256 per section
//! and over the object of all sections. These rules reproduce, hash for hash, the throwaway skeleton
//! script of the executed golden-mirror spike, including its leaf names.
//!
//! The spike sorted ledger-entry changes by the XDR bytes of their keys; this module uses the
//! normaliser's key, stellar-core's own order. The two orders agree on every executed mirror.

use std::sync::OnceLock;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    GeneralizedTransactionSet, LedgerCloseMeta, TransactionEnvelope, TransactionPhase,
    TxSetComponent,
};

use crate::normalise::{normalise, NormaliseError};

/// Errors from computing a skeleton.
#[derive(Debug, thiserror::Error)]
pub enum SkeletonError {
    /// Normalisation failed.
    #[error(transparent)]
    Normalise(#[from] NormaliseError),
    /// The transaction index is out of range.
    #[error("no transaction {index} (the ledger has {count})")]
    NoTransaction {
        /// Requested apply-order index.
        index: usize,
        /// Transactions in the ledger.
        count: usize,
    },
    /// The envelope of the transaction could not be found.
    #[error("transaction {index}: {reason}")]
    Envelope {
        /// Apply-order index.
        index: usize,
        /// Why.
        reason: String,
    },
    /// The value does not fit the schema (a different library version, or a bug).
    #[error("skeleton walk: {0}")]
    Walk(String),
}

type Result<T> = std::result::Result<T, SkeletonError>;

/// The vendored schema (see the module documentation for its origin).
const SCHEMA_TEXT: &str = include_str!("skeleton/schema-LedgerCloseMeta.json");

/// Unions the library renders as strkey strings; their skeleton keeps the version letter.
const STRKEY_UNIONS: [&str; 9] = [
    "ScAddress",
    "MuxedAccount",
    "SignerKey",
    "PublicKey",
    "AccountId",
    "NodeId",
    "ContractId",
    "ClaimableBalanceId",
    "PoolId",
];

fn schema() -> &'static Value {
    static S: OnceLock<Value> = OnceLock::new();
    S.get_or_init(|| serde_json::from_str(SCHEMA_TEXT).expect("vendored schema is JSON"))
}

/// A skeleton with its section hashes and overall hash.
#[derive(Debug, Clone, PartialEq)]
pub struct Skeleton {
    /// Apply-order transaction index (scope `tx`), `None` for scope `ledger`.
    pub tx_index: Option<usize>,
    /// Hex transaction hash (scope `tx`).
    pub tx_hash: Option<String>,
    /// Sections in order.
    pub sections: Map<String, Value>,
    /// SHA-256 of each section's canonical JSON.
    pub section_hashes: Map<String, Value>,
    /// SHA-256 of the canonical JSON of all sections.
    pub hash: String,
}

impl Skeleton {
    fn from_sections(
        sections: Map<String, Value>,
        tx_index: Option<usize>,
        tx_hash: Option<String>,
    ) -> Self {
        let section_hashes = sections
            .iter()
            .map(|(k, v)| (k.clone(), json!(sha256_hex(&canon(v)))))
            .collect();
        let hash = sha256_hex(&canon(&Value::Object(sections.clone())));
        Skeleton {
            tx_index,
            tx_hash,
            sections,
            section_hashes,
            hash,
        }
    }

    /// The skeleton as one JSON document.
    pub fn to_json(&self) -> Value {
        json!({
            "tx_index": self.tx_index,
            "tx_hash": self.tx_hash,
            "hash": self.hash,
            "section_hashes": self.section_hashes,
            "sections": self.sections,
        })
    }
}

/// Canonical JSON: compact, keys in insertion order, non-ASCII unescaped.
pub fn canon(v: &Value) -> String {
    serde_json::to_string(v).expect("JSON values serialise")
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v).map_err(|e| SkeletonError::Walk(e.to_string()))
}

// --- The schema-driven walk. -------------------------------------------------------------------

/// How Python's `str()` renders a JSON-schema `type` (the spike's fallback leaf name).
fn py_str(v: Option<&Value>) -> String {
    fn repr(v: &Value) -> String {
        match v {
            Value::String(s) => format!("'{s}'"),
            other => py(other),
        }
    }
    fn py(v: &Value) -> String {
        match v {
            Value::Null => "None".into(),
            Value::Bool(true) => "True".into(),
            Value::Bool(false) => "False".into(),
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Array(a) => format!("[{}]", a.iter().map(repr).collect::<Vec<_>>().join(", ")),
            Value::Object(_) => "{…}".into(),
        }
    }
    v.map_or_else(|| "None".into(), py)
}

struct Walker {
    defs: &'static Map<String, Value>,
}

/// A resolved schema node: the node, the nearest type name, and whether it is `ScSymbol`.
enum Node<'a> {
    Symbol,
    Schema(&'a Value, Option<String>),
}

impl Walker {
    fn new() -> Self {
        Walker {
            defs: schema()["definitions"]
                .as_object()
                .expect("schema has definitions"),
        }
    }

    fn resolve<'a>(&'a self, mut node: &'a Value, mut name: Option<String>) -> Result<Node<'a>> {
        while let Some(r) = node.get("$ref").and_then(Value::as_str) {
            let nm = r.rsplit('/').next().unwrap_or(r);
            if nm == "ScSymbol" {
                return Ok(Node::Symbol);
            }
            name = Some(nm.to_string());
            node = self
                .defs
                .get(nm)
                .ok_or_else(|| SkeletonError::Walk(format!("no schema definition {nm}")))?;
        }
        Ok(Node::Schema(node, name))
    }

    fn walk(&self, node: &Value, val: &Value, name: Option<String>) -> Result<Value> {
        let (node, name) = match self.resolve(node, name)? {
            Node::Symbol => return Ok(val.clone()),
            Node::Schema(n, name) => (n, name),
        };
        let err = |what: String| {
            SkeletonError::Walk(format!("{}: {what}", name.as_deref().unwrap_or("?")))
        };
        if let Some(any) = node.get("anyOf").and_then(Value::as_array) {
            if val.is_null() {
                return Ok(Value::Null);
            }
            let inner = any
                .iter()
                .find(|b| b.get("type") != Some(&json!("null")))
                .ok_or_else(|| err("optional without a value branch".into()))?;
            return Ok(json!({"?": self.walk(inner, val, name.clone())?}));
        }
        if let Some(one) = node.get("oneOf").and_then(Value::as_array) {
            if let Some(s) = val.as_str() {
                let known = one.iter().any(|b| {
                    b.get("type") == Some(&json!("string"))
                        && b.get("enum")
                            .and_then(Value::as_array)
                            .is_some_and(|e| e.iter().any(|x| x.as_str() == Some(s)))
                });
                return if known {
                    Ok(json!({"|": s}))
                } else {
                    Err(err(format!("void arm {s:?} not in schema")))
                };
            }
            let obj = val
                .as_object()
                .filter(|o| o.len() == 1)
                .ok_or_else(|| err(format!("union value is not a one-key object: {val}")))?;
            let (arm, inner) = obj.iter().next().expect("one key");
            for b in one {
                if b.get("type") == Some(&json!("object")) {
                    if let Some(sub) = b.get("properties").and_then(|p| p.get(arm)) {
                        let path = format!(
                            "{}.{arm}",
                            name.as_deref().filter(|n| !n.is_empty()).unwrap_or("union")
                        );
                        return Ok(json!({"|": arm, "v": self.walk(sub, inner, Some(path))?}));
                    }
                }
            }
            return Err(err(format!("arm {arm} not in schema")));
        }
        let t = node.get("type");
        if t == Some(&json!("string")) && node.get("enum").is_some() {
            return Ok(val.clone());
        }
        if t == Some(&json!("object")) {
            let empty = Map::new();
            let props = node
                .get("properties")
                .and_then(Value::as_object)
                .unwrap_or(&empty);
            let obj = val
                .as_object()
                .ok_or_else(|| err(format!("struct value is not an object: {val}")))?;
            let mut out = Map::new();
            for (k, v) in obj {
                let sub = props
                    .get(k)
                    .ok_or_else(|| err(format!("field {k} not in schema")))?;
                out.insert(k.clone(), self.walk(sub, v, None)?);
            }
            return Ok(Value::Object(out));
        }
        if t == Some(&json!("array")) {
            let items = val
                .as_array()
                .ok_or_else(|| err(format!("array value is not an array: {val}")))?;
            let item_schema = node
                .get("items")
                .ok_or_else(|| err("array without items".into()))?;
            let walked = items
                .iter()
                .map(|v| self.walk(item_schema, v, None))
                .collect::<Result<Vec<_>>>()?;
            return Ok(json!({"n": items.len(), "items": walked}));
        }
        if t == Some(&json!("boolean")) {
            return Ok(val.clone());
        }
        if let (Some(n), Some(s)) = (name.as_deref(), val.as_str()) {
            if STRKEY_UNIONS.contains(&n) {
                if let Some(c) = s.chars().next() {
                    return Ok(json!(format!("#{n}:{c}")));
                }
            }
        }
        Ok(json!(format!("#{}", name.unwrap_or_else(|| py_str(t)))))
    }

    fn walk_type(&self, type_name: &str, val: &Value) -> Result<Value> {
        self.walk(
            &json!({"$ref": format!("#/definitions/{type_name}")}),
            val,
            None,
        )
    }
}

// --- Sections. ---------------------------------------------------------------------------------

fn generalized_envelopes(s: &GeneralizedTransactionSet) -> Vec<&TransactionEnvelope> {
    let GeneralizedTransactionSet::V1(set) = s;
    let mut out = Vec::new();
    for phase in set.phases.iter() {
        match phase {
            TransactionPhase::V0(components) => {
                for c in components.iter() {
                    let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) = c;
                    out.extend(c.txs.iter());
                }
            }
            TransactionPhase::V1(p) => {
                for stage in p.execution_stages.iter() {
                    for cluster in stage.0.iter() {
                        out.extend(cluster.0.iter());
                    }
                }
            }
        }
    }
    out
}

fn envelopes(lcm: &LedgerCloseMeta) -> Vec<&TransactionEnvelope> {
    match lcm {
        LedgerCloseMeta::V0(v) => v.tx_set.txs.iter().collect(),
        LedgerCloseMeta::V1(v) => generalized_envelopes(&v.tx_set),
        LedgerCloseMeta::V2(v) => generalized_envelopes(&v.tx_set),
    }
}

/// The processing record of transaction `index` as JSON, and its hash.
fn processing_json(lcm: &LedgerCloseMeta, index: usize) -> Result<(Value, [u8; 32])> {
    let (count, rec) = match lcm {
        LedgerCloseMeta::V0(v) => (
            v.tx_processing.len(),
            v.tx_processing
                .get(index)
                .map(|t| (to_value(t), t.result.transaction_hash.0)),
        ),
        LedgerCloseMeta::V1(v) => (
            v.tx_processing.len(),
            v.tx_processing
                .get(index)
                .map(|t| (to_value(t), t.result.transaction_hash.0)),
        ),
        LedgerCloseMeta::V2(v) => (
            v.tx_processing.len(),
            v.tx_processing
                .get(index)
                .map(|t| (to_value(t), t.result.transaction_hash.0)),
        ),
    };
    let (json, hash) = rec.ok_or(SkeletonError::NoTransaction { index, count })?;
    Ok((json?, hash))
}

/// The envelope of the transaction with `hash`: the only envelope of a one-transaction ledger,
/// otherwise found by recomputing envelope hashes under `passphrase`.
fn envelope_for<'a>(
    lcm: &'a LedgerCloseMeta,
    index: usize,
    hash: [u8; 32],
    passphrase: Option<&str>,
) -> Result<&'a TransactionEnvelope> {
    let envs = envelopes(lcm);
    let count = match lcm {
        LedgerCloseMeta::V0(v) => v.tx_processing.len(),
        LedgerCloseMeta::V1(v) => v.tx_processing.len(),
        LedgerCloseMeta::V2(v) => v.tx_processing.len(),
    };
    if envs.len() == 1 && count == 1 {
        return Ok(envs[0]);
    }
    let Some(pass) = passphrase else {
        return Err(SkeletonError::Envelope {
            index,
            reason: format!(
                "{} envelopes: pairing by hash needs the network passphrase",
                envs.len()
            ),
        });
    };
    let nid: [u8; 32] = Sha256::digest(pass.as_bytes()).into();
    envs.into_iter()
        .find(|e| e.hash(nid).is_ok_and(|h| h == hash))
        .ok_or_else(|| SkeletonError::Envelope {
            index,
            reason: "no envelope in the transaction set has this hash under the passphrase".into(),
        })
}

/// The skeleton of transaction `tx_index` (apply order) of a ledger, after normalisation.
/// `passphrase` is needed only when the ledger holds more than one transaction.
///
/// Values can be deeply nested; call this on a large stack (see [`xdrcheck_xdr::with_stack`]).
pub fn tx_skeleton(
    lcm: &LedgerCloseMeta,
    tx_index: usize,
    passphrase: Option<&str>,
) -> Result<Skeleton> {
    let mut lcm = lcm.clone();
    normalise(&mut lcm)?;
    let (tp, hash) = processing_json(&lcm, tx_index)?;
    let env = to_value(envelope_for(&lcm, tx_index, hash, passphrase)?)?;
    let w = Walker::new();
    let mut sec = Map::new();
    sec.insert("envelope".into(), w.walk_type("TransactionEnvelope", &env)?);
    sec.insert(
        "result".into(),
        w.walk_type("TransactionResultPair", &tp["result"])?,
    );
    sec.insert(
        "fee_processing".into(),
        w.walk_type("LedgerEntryChanges", &tp["fee_processing"])?,
    );
    let full = w.walk_type("TransactionMeta", &tp["tx_apply_processing"])?;
    let inner = full
        .get("v")
        .and_then(Value::as_object)
        .ok_or_else(|| SkeletonError::Walk("transaction meta has no fields".into()))?;
    sec.insert(
        "meta.arm".into(),
        json!({"|": full["|"], "fields": inner.keys().collect::<Vec<_>>()}),
    );
    for (k, v) in inner {
        sec.insert(format!("meta.{k}"), v.clone());
    }
    if let Some(post) = tp.get("post_tx_apply_fee_processing") {
        sec.insert(
            "post_tx_apply_fee_processing".into(),
            w.walk_type("LedgerEntryChanges", post)?,
        );
    }
    if let Some(ext) = tp.get("ext") {
        sec.insert(
            "tx_result_meta.ext".into(),
            w.walk_type("ExtensionPoint", ext)?,
        );
    }
    Ok(Skeleton::from_sections(
        sec,
        Some(tx_index),
        Some(hex::encode(hash)),
    ))
}

/// The skeleton of a whole normalised ledger, as one section `ledger`.
///
/// Values can be deeply nested; call this on a large stack (see [`xdrcheck_xdr::with_stack`]).
pub fn ledger_skeleton(lcm: &LedgerCloseMeta) -> Result<Skeleton> {
    let mut lcm = lcm.clone();
    normalise(&mut lcm)?;
    let w = Walker::new();
    let v = w.walk(schema(), &to_value(&lcm)?, None)?;
    let mut sec = Map::new();
    sec.insert("ledger".into(), v);
    Ok(Skeleton::from_sections(sec, None, None))
}

// --- Differences. ------------------------------------------------------------------------------

/// One difference between two skeletons: a path and both sub-skeletons (`"<absent>"` when one
/// side lacks it).
#[derive(Debug, Clone, PartialEq)]
pub struct Difference {
    /// Dotted path, `[i]` for array items, `.len` for lengths, `|` for an arm.
    pub path: String,
    /// The first skeleton's part.
    pub a: Value,
    /// The second skeleton's part.
    pub b: Value,
}

fn same_kind(a: &Value, b: &Value) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
}

fn is_array_node(v: &Map<String, Value>) -> bool {
    v.len() == 2 && v.contains_key("n") && v.contains_key("items")
}

fn diff_into(a: &Value, b: &Value, path: &str, out: &mut Vec<Difference>) {
    let push = |out: &mut Vec<Difference>, p: String, a: &Value, b: &Value| {
        out.push(Difference {
            path: p,
            a: a.clone(),
            b: b.clone(),
        })
    };
    if !same_kind(a, b) {
        push(out, path.into(), a, b);
        return;
    }
    if let (Value::Object(x), Value::Object(y)) = (a, b) {
        if is_array_node(x) && is_array_node(y) {
            if x["n"] != y["n"] {
                push(out, format!("{path}.len"), &x["n"], &y["n"]);
            }
            let empty = Vec::new();
            let xi = x["items"].as_array().unwrap_or(&empty);
            let yi = y["items"].as_array().unwrap_or(&empty);
            for i in 0..xi.len().min(yi.len()) {
                diff_into(&xi[i], &yi[i], &format!("{path}[{i}]"), out);
            }
            let absent = json!("<absent>");
            for i in xi.len().min(yi.len())..xi.len().max(yi.len()) {
                push(
                    out,
                    format!("{path}[{i}]"),
                    xi.get(i).unwrap_or(&absent),
                    yi.get(i).unwrap_or(&absent),
                );
            }
            return;
        }
        if let (Some(p), Some(q)) = (x.get("|"), y.get("|")) {
            if p != q {
                push(out, format!("{path}|"), a, b);
                return;
            }
        }
        let absent = json!("<absent>");
        let keys: Vec<&String> = x
            .keys()
            .chain(y.keys().filter(|k| !x.contains_key(*k)))
            .collect();
        for k in keys {
            match (x.get(k), y.get(k)) {
                (Some(p), Some(q)) => {
                    let sub = if k == "|" || k == "v" {
                        path.to_string()
                    } else {
                        format!("{path}.{k}")
                    };
                    diff_into(p, q, &sub, out);
                }
                (p, q) => push(
                    out,
                    format!("{path}.{k}"),
                    p.unwrap_or(&absent),
                    q.unwrap_or(&absent),
                ),
            }
        }
        return;
    }
    if a != b {
        push(out, path.into(), a, b);
    }
}

/// Every differing path between two skeletons, section by section.
pub fn diff(a: &Skeleton, b: &Skeleton) -> Vec<Difference> {
    let mut out = Vec::new();
    let absent = json!("<absent>");
    let keys: Vec<&String> = a
        .sections
        .keys()
        .chain(b.sections.keys().filter(|k| !a.sections.contains_key(*k)))
        .collect();
    for k in keys {
        match (a.sections.get(k), b.sections.get(k)) {
            (Some(x), Some(y)) => diff_into(x, y, k, &mut out),
            (x, y) => out.push(Difference {
                path: k.clone(),
                a: x.unwrap_or(&absent).clone(),
                b: y.unwrap_or(&absent).clone(),
            }),
        }
    }
    out
}
