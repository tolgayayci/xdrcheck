//! The curated-tier checks. Each check returns a list of problems; an empty list is a pass.
//! Expected values come only from the manifest, the bytes and the pinned oracle library — never
//! from a reader under test.

use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use serde_json::Value;
use xdrcheck_xdr::{Error as XdrError, FramingError, LimitKind, Malformed, Refusal};

mod archive;
mod gzip;

use super::ledger::tx_hashes;
use super::load::{self, Entry, Schemas};
use super::model::{Check, Counts, Ctx, Row};

/// Run the requested checks over the manifest entries matching `glob`.
pub fn run_curated(ctx: &Ctx, checks: &[Check], glob: Option<&str>) -> Result<(Vec<Row>, Counts)> {
    let all = load::entries(&ctx.corpus, ctx.overlay.as_deref())?;
    let selected: Vec<&Entry> = all
        .iter()
        .filter(|e| glob.is_none_or(|g| load::glob_match(g, &e.id)))
        .collect();
    if glob.is_some() && selected.is_empty() {
        bail!(
            "--entries {:?} matches no manifest entry",
            glob.unwrap_or("")
        );
    }
    let wants = |c: Check| checks.contains(&c);
    let schemas = if wants(Check::Schema) {
        Some(Schemas::load(&ctx.corpus)?)
    } else {
        None
    };
    let canonical = if wants(Check::Ids) {
        Some(load::canonical_ids(&ctx.corpus, ctx.overlay.as_deref())?)
    } else {
        None
    };
    let chains: Vec<(String, Value)> = load::json_files(&ctx.corpus.join("chains"))?
        .into_iter()
        .map(|(rel, p)| {
            let v = std::fs::read(&p)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or(Value::Null);
            (format!("chains/{rel}.json"), v)
        })
        .collect();
    let mut id_count: HashMap<String, usize> = HashMap::new();
    for e in &all {
        if let Ok(j) = &e.json {
            if let Some(id) = j["id"].as_str() {
                *id_count.entry(id.to_string()).or_default() += 1;
            }
        }
    }

    let mut rows = Vec::new();
    let mut counts = Counts::default();
    for e in &selected {
        count_entry(e, &mut counts);
        let caps = e.caps();
        let mut push = |mut r: Row| {
            r.caps = caps.clone();
            rows.push(r);
        };
        if let Some(s) = &schemas {
            push(Row::new(Check::Schema, &e.id, None, schema_problems(e, s)));
        }
        if let Some(c) = &canonical {
            push(Row::new(
                Check::Ids,
                &e.id,
                None,
                id_problems(e, c, &id_count),
            ));
        }
        let kind = e.kind();
        if kind == "spec" {
            for v in e.variants() {
                let vc = VariantCtx::new(ctx, e, v);
                let key = e.variant_key(v);
                for &c in checks {
                    let problems = match c {
                        Check::Hashes => vc.hashes(&chains),
                        Check::Spec => vc.spec(),
                        _ => continue,
                    };
                    push(Row::new(c, &e.id, Some(&key), problems));
                }
            }
            continue;
        }
        if kind != "ledger" && kind != "xdr" {
            continue;
        }
        for v in e.variants() {
            let vc = VariantCtx::new(ctx, e, v);
            let key = e.variant_key(v);
            let positive = !e.negative();
            let golden = v["source"]["kind"] == "core-golden";
            for &c in checks {
                let problems = match c {
                    Check::Hashes => vc.hashes(&chains),
                    Check::Roundtrip if positive => vc.roundtrip(),
                    Check::Reject if !positive && kind == "xdr" => vc.reject(),
                    Check::Sidecar if positive => vc.sidecar(),
                    Check::Pinpoints if positive => vc.pinpoints(),
                    Check::Ag1 if golden => vc.ag1()?,
                    Check::Ag3 if golden => vc.ag3(),
                    Check::Extractor if positive && vc.xdr_type() == "LedgerCloseMeta" => {
                        vc.extractor()
                    }
                    _ => continue,
                };
                push(Row::new(c, &e.id, Some(&key), problems));
            }
        }
    }
    if wants(Check::Ag4) {
        rows.extend(super::ag4::rows(
            ctx,
            &all,
            &selected,
            glob.is_none(),
            ctx.write_mirrors,
            &mut counts,
        )?);
    }
    if wants(Check::Orphans) && glob.is_none() {
        rows.extend(super::orphans::rows(&ctx.roots(), &all, &chains));
    }
    // Files other than entries are schema-checked on a whole-corpus run only.
    if let (Some(s), None) = (&schemas, glob) {
        for (rel, v) in &chains {
            let problems = if v.is_null() {
                vec!["unreadable or not JSON".to_string()]
            } else {
                s.errors("chain-index", v, 5)
            };
            rows.push(Row::new(Check::Schema, rel, None, problems));
        }
        if let Some(cj) = &ctx.corpus_json {
            rows.push(Row::new(
                Check::Schema,
                "corpus.json",
                None,
                s.errors("corpus-index", cj, 5),
            ));
        }
    }
    Ok((rows, counts))
}

fn count_entry(e: &Entry, counts: &mut Counts) {
    counts.add("entries", 1);
    let n = e.variants().len() as u64;
    match (e.kind(), e.negative()) {
        ("ledger", _) => {
            counts.add("ledger", 1);
            counts.add("roundtrip_variants", n);
        }
        ("xdr", false) => {
            counts.add("xdr", 1);
            counts.add("roundtrip_variants", n);
        }
        ("xdr", true) => {
            counts.add("xdr_negative", 1);
            counts.add("reject_variants", n);
        }
        ("spec", false) => {
            counts.add("spec", 1);
            counts.add("spec_variants", n);
        }
        ("spec", true) => {
            counts.add("spec_negative", 1);
            counts.add("spec_variants", n);
        }
        ("api", _) => counts.add("api_no_bytes", 1),
        ("strkey", _) => counts.add("strkey_no_bytes", 1),
        _ => counts.add("unknown_kind", 1),
    }
    let golden = e
        .variants()
        .iter()
        .filter(|v| v["source"]["kind"] == "core-golden")
        .count() as u64;
    if golden > 0 {
        counts.add("core_golden_variants", golden);
    }
}

// ---------------------------------------------------------------------------------------------
// Entry-level checks

/// The negative-case vocabulary rules a schema leaves open (`docs/manifest.md` §9.5): every corpus
/// entry states `validity`; an `expect.reject.reason` comes with the flag of the same name; the
/// `core-lenient` flag is set exactly when `core_behaviour.accepts` is true. The schema itself ties
/// `validity` to `negative`, the reject reason and the `api` expectation.
fn validity_problems(j: &Value) -> Vec<String> {
    let mut p = Vec::new();
    if j["validity"].as_str().is_none() {
        p.push(
            "entry has no validity (valid, malformed, invalid or acceptable; docs/manifest.md §9.5)"
                .into(),
        );
    }
    let flags: Vec<&str> = j["flags"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if let Some(reason) = j["expect"]["reject"]["reason"].as_str() {
        let flag = reason.replace('_', "-");
        if !flags.contains(&flag.as_str()) {
            p.push(format!(
                "expect.reject.reason {reason} without the flag {flag}"
            ));
        }
    }
    let lenient = j["core_behaviour"]["accepts"].as_bool() == Some(true);
    if lenient != flags.contains(&"core-lenient") {
        p.push(if lenient {
            "core_behaviour.accepts is true but flags lacks core-lenient".into()
        } else {
            "flag core-lenient without core_behaviour.accepts true".into()
        });
    }
    p
}

/// JSON Schema plus the structural rules of `docs/manifest.md` §11 that a schema cannot state.
fn schema_problems(e: &Entry, schemas: &Schemas) -> Vec<String> {
    let j = match &e.json {
        Ok(j) => j,
        Err(err) => return vec![err.clone()],
    };
    let mut p = schemas.errors("manifest-entry", j, 5);
    let kind = e.kind();
    let negative = e.negative();
    let mut keys = HashSet::new();
    for (i, v) in e.variants().iter().enumerate() {
        let key = (v["network"].to_string(), v["protocol"].to_string());
        if !keys.insert(key) {
            p.push(format!(
                "variant {i}: (network, protocol) = ({}, {}) repeats an earlier variant",
                v["network"], v["protocol"]
            ));
        }
        if kind == "ledger" {
            for f in ["profile", "ledger_close_meta_version"] {
                if v["meta"][f].is_null() {
                    p.push(format!("variant {i}: ledger variant has no meta.{f}"));
                }
            }
            // A ledger with no transactions has no TransactionMeta to read a version from.
            let no_txs = j["expect"]["ledger"]["transactions"].as_u64() == Some(0);
            match (no_txs, v["meta"]["transaction_meta_version"].is_null()) {
                (false, true) => p.push(format!(
                    "variant {i}: ledger variant has no meta.transaction_meta_version"
                )),
                (true, false) => p.push(format!(
                    "variant {i}: meta.transaction_meta_version is stated for a ledger with no \
                     transactions (expect.ledger.transactions 0); there is no TransactionMeta to read it from"
                )),
                _ => {}
            }
        }
        if (kind == "ledger" || kind == "xdr") && !negative {
            for f in ["decoded", "decoded_sha256"] {
                if v[f].is_null() {
                    p.push(format!("variant {i}: positive {kind} variant has no {f}"));
                }
            }
        }
        if negative && !v["decoded"].is_null() {
            p.push(format!("variant {i}: negative entry has a decoded sidecar"));
        }
        // An upgrade ledger applies its transactions at the old protocol but its header already carries the
        // new one; the pattern it demonstrates (the header) is introduced at the header's protocol.
        let effective = v["header_protocol"].as_u64().or(v["protocol"].as_u64());
        if let (Some(intro), Some(proto)) = (j["protocol"]["introduced"].as_u64(), effective) {
            if intro > proto {
                p.push(format!(
                    "variant {i}: protocol {proto} is below protocol.introduced {intro}"
                ));
            }
        }
    }
    if negative && j["expect"]["reject"].is_null() {
        p.push("negative entry has no expect.reject".into());
    }
    p.extend(validity_problems(j));
    // A known divergence whose range does not parse would silently match nothing.
    let divergences = j["conformance"]["known_divergences"].as_array();
    for (i, d) in divergences.into_iter().flatten().enumerate() {
        if let Some(e) = super::ranges::problem(d["versions"].as_str().unwrap_or("")) {
            p.push(format!("conformance.known_divergences[{i}].versions: {e}"));
        }
        if let Some(r) = d["match"]["reason"].as_str() {
            if !schemas.driver_reasons.iter().any(|c| c == r) {
                p.push(format!(
                    "conformance.known_divergences[{i}].match.reason {r:?} is not a driver protocol reason code"
                ));
            }
        }
        p.extend(
            match_problems(j, d)
                .into_iter()
                .map(|e| format!("conformance.known_divergences[{i}].match: {e}")),
        );
    }
    p
}

/// What the schema cannot say about a known divergence's `match` block: `envelopes_parsed` and
/// `rejected_tx_index` describe L1 on a ledger, so the divergence must be at level L1 of a
/// `ledger` entry, and both must lie within the ledger's transactions when `expect.ledger`
/// counts them; a `rejected_tx_index` is an envelope the SDK refused, so the outcome is `reject`.
fn match_problems(j: &Value, d: &Value) -> Vec<String> {
    let mut p = Vec::new();
    let Some(m) = d["match"].as_object() else {
        return p;
    };
    let ledger_l1 = |key: &str| -> Option<String> {
        (j["kind"] != "ledger" || d["level"] != "L1")
            .then(|| format!("{key} applies only to a divergence at level L1 of a ledger entry"))
    };
    if m.contains_key("rejected_tx_index") && d["outcome"] != "reject" {
        p.push("rejected_tx_index needs outcome reject".into());
    }
    let txs = j["expect"]["ledger"]["transactions"].as_u64();
    if let Some(n) = m.get("envelopes_parsed").and_then(Value::as_u64) {
        p.extend(ledger_l1("envelopes_parsed"));
        if txs.is_some_and(|t| n > t) {
            p.push(format!(
                "envelopes_parsed {n} exceeds the ledger's {} transactions",
                txs.unwrap_or(0)
            ));
        }
    }
    if let Some(i) = m.get("rejected_tx_index").and_then(Value::as_u64) {
        p.extend(ledger_l1("rejected_tx_index"));
        if txs.is_some_and(|t| i >= t) {
            p.push(format!(
                "rejected_tx_index {i} is past the ledger's {} transactions",
                txs.unwrap_or(0)
            ));
        }
    }
    p
}

/// Path equals ID, ID canonical and unique, cited IDs canonical (as `scripts/py/check_ids.py`).
fn id_problems(
    e: &Entry,
    canonical: &HashSet<String>,
    id_count: &HashMap<String, usize>,
) -> Vec<String> {
    let j = match &e.json {
        Ok(j) => j,
        Err(err) => return vec![err.clone()],
    };
    let mut p = Vec::new();
    let id = j["id"].as_str().unwrap_or("");
    if id != e.id {
        p.push(format!(
            "id {id:?} does not match its path manifest/{}.json",
            e.id
        ));
    }
    if !canonical.contains(id) {
        p.push(format!("id {id:?} is not in plan.json"));
    }
    if id_count.get(id).copied().unwrap_or(0) > 1 {
        p.push(format!("id {id:?} is used by more than one manifest file"));
    }
    let mut cited = Vec::new();
    collect_cited(j, &mut cited);
    for c in cited {
        if load::looks_like_id(c) && !canonical.contains(c) {
            p.push(format!("cites unknown entry {c:?}"));
        }
    }
    p
}

fn collect_cited<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if matches!(k.as_str(), "entry" | "base_entry" | "parent") {
                    if let Some(s) = x.as_str() {
                        out.push(s);
                    }
                }
                collect_cited(x, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_cited(x, out)),
        _ => {}
    }
}

// ---------------------------------------------------------------------------------------------
// Variant-level checks

/// One variant with its blob and oracle output loaded at most once.
struct VariantCtx<'a> {
    ctx: &'a Ctx,
    entry: &'a Entry,
    v: &'a Value,
    blob: OnceCell<Result<Vec<u8>, String>>,
    oracle: OnceCell<Result<Value, String>>,
}

impl<'a> VariantCtx<'a> {
    fn new(ctx: &'a Ctx, entry: &'a Entry, v: &'a Value) -> Self {
        VariantCtx {
            ctx,
            entry,
            v,
            blob: OnceCell::new(),
            oracle: OnceCell::new(),
        }
    }

    fn xdr_type(&self) -> &str {
        self.v["xdr_type"].as_str().unwrap_or("")
    }

    fn blob_path(&self) -> PathBuf {
        let b = &self.v["blob"];
        match b["path"].as_str() {
            Some(p) => self.ctx.resolve(p),
            None => {
                let sha = b["sha256"].as_str().unwrap_or("");
                self.ctx
                    .resolve(&format!("blobs/{}/{sha}.xdr", sha.get(..2).unwrap_or("")))
            }
        }
    }

    fn blob(&self) -> Result<&[u8], String> {
        self.blob
            .get_or_init(|| {
                let p = self.blob_path();
                std::fs::read(&p).map_err(|e| format!("blob {}: {e}", self.ctx.shown(&p)))
            })
            .as_deref()
            .map_err(Clone::clone)
    }

    /// Whether the variant declares its JSON round trip an exception (`json_roundtrip.skip`).
    fn json_exception(&self) -> bool {
        self.v["json_roundtrip"]["skip"] == true
    }

    /// Decode → re-encode → JSON → re-encode under the oracle's limits and gate; the JSON. For a
    /// declared JSON round-trip exception the last step (JSON → bytes) is left out.
    fn oracle(&self) -> Result<&Value, String> {
        self.oracle
            .get_or_init(|| {
                let bytes = self.blob()?;
                let xdr_type = self.xdr_type();
                if self.json_exception() {
                    oracle_gate(self.ctx, xdr_type, bytes)
                        .and_then(|()| xdrcheck_xdr::xdr_json(xdr_type, bytes, &self.ctx.limits))
                        .map_err(|e| e.to_string())
                } else {
                    oracle_decode(self.ctx, xdr_type, bytes, true).map_err(|e| e.to_string())
                }
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    fn sidecar(&self) -> Vec<String> {
        let expected = match self.read_sidecar() {
            Ok(v) => v,
            Err(e) => return vec![e],
        };
        match self.oracle() {
            Err(e) => vec![format!("cannot render: {e}")],
            Ok(fresh) if *fresh == expected => vec![],
            Ok(fresh) => vec![format!(
                "sidecar differs from a fresh rendering at {}",
                first_difference(&expected, fresh, String::new())
            )],
        }
    }

    /// The sidecar's uncompressed JSON text, after checking it against `decoded_sha256`.
    fn sidecar_text(&self) -> Result<Vec<u8>, String> {
        let Some(d) = self.v["decoded"].as_str() else {
            return Err("variant has no decoded sidecar".into());
        };
        let text = crate::cmd::render::read_sidecar_text(&self.ctx.resolve(d))
            .map_err(|e| format!("sidecar {d}: {e:#}"))?;
        let got = xdrcheck_xdr::sha256_hex(&text);
        match self.v["decoded_sha256"].as_str() {
            Some(w) if w == got => Ok(text),
            Some(w) => Err(format!(
                "sidecar {d}: uncompressed sha256 is {got}, manifest says {w}"
            )),
            None => Err(format!("sidecar {d}: variant has no decoded_sha256")),
        }
    }

    fn read_sidecar(&self) -> Result<Value, String> {
        let text = self.sidecar_text()?;
        // Sidecars of deeply nested values exceed serde_json's default nesting limit.
        xdrcheck_xdr::parse_json(&text, &self.ctx.limits)
            .map_err(|e| format!("sidecar is not JSON: {e}"))
    }

    /// Bytes → value → identical bytes, always; and SEP-51 JSON → identical bytes unless the
    /// variant declares that half an exception, in which case the exception must still be needed.
    fn roundtrip(&self) -> Vec<String> {
        match self.oracle() {
            Ok(_) if self.json_exception() => self.stale_json_exception(),
            Ok(_) => vec![],
            Err(e) if e.contains("json round trip differs") || e.contains(": JSON: ") => vec![format!(
                "{e}; if the SEP-51 JSON of these bytes legitimately does not reproduce them, declare \
                 it with variants[].json_roundtrip {{\"skip\": true, \"reason\": \"…\"}}"
            )],
            Err(e) => vec![e],
        }
    }

    /// A declared JSON round-trip exception whose JSON round trip in fact succeeds is stale.
    fn stale_json_exception(&self) -> Vec<String> {
        let Ok(bytes) = self.blob() else {
            return vec![];
        };
        match xdrcheck_xdr::json_roundtrip(self.xdr_type(), bytes, &self.ctx.limits) {
            Ok(_) => vec![
                "variants[].json_roundtrip declares a JSON round-trip exception, but SEP-51 JSON \
                 reproduces the bytes: the exception is stale, remove it"
                    .into(),
            ],
            Err(XdrError::Json { .. } | XdrError::RoundTrip { stage: "json", .. }) => vec![],
            Err(e) => vec![e.to_string()],
        }
    }

    /// `spec`: the corpus's own section reader re-reads the blob; its facts must equal
    /// `expect.spec`. A negative entry must be one a correct reader refuses: more than one spec
    /// section, or a stream that does not end cleanly.
    fn spec(&self) -> Vec<String> {
        let mut p = Vec::new();
        let container = self.v["container"].as_str().unwrap_or("");
        let Some(c) = xdrcheck_xdr::spec::Container::parse(container) else {
            return vec![format!("container {container:?} is not wasm or xdr-stream")];
        };
        let bytes = match self.blob() {
            Ok(b) => b,
            Err(e) => return vec![e],
        };
        let facts = xdrcheck_xdr::spec::read(bytes, c);
        let got = xdrcheck_xdr::spec::expect_block(&facts);
        let want = &self
            .entry
            .json
            .as_ref()
            .map(|j| j["expect"]["spec"].clone())
            .unwrap_or_default();
        if &got != want {
            p.push(format!(
                "expect.spec differs from the bytes at {} (xdrcheck-corpus render rewrites it)",
                first_difference(want, &got, String::new())
            ));
        }
        let refusable = facts.sections.unwrap_or(1) > 1 || !facts.clean_end;
        if self.entry.negative() != refusable {
            p.push(if self.entry.negative() {
                "negative entry, but the bytes are one cleanly ending spec section".to_string()
            } else {
                format!(
                    "positive entry, but a correct reader must refuse the bytes ({})",
                    facts.error.clone().unwrap_or_else(|| format!(
                        "{} spec sections",
                        facts.sections.unwrap_or(0)
                    ))
                )
            });
        }
        p
    }

    fn hashes(&self, chains: &[(String, Value)]) -> Vec<String> {
        let mut p = Vec::new();
        let b = &self.v["blob"];
        let want = b["sha256"].as_str().unwrap_or("");
        let path = self.blob_path();
        let shown = self.ctx.shown(&path);
        if path.file_stem().and_then(|s| s.to_str()) != Some(want) {
            p.push(format!(
                "blob file {shown} is not named by its sha256 {want}"
            ));
        }
        match self.blob() {
            Err(e) => p.push(e),
            Ok(bytes) => {
                let got = xdrcheck_xdr::sha256_hex(bytes);
                if got != want {
                    p.push(format!(
                        "blob {shown}: sha256 is {got}, manifest says {want}"
                    ));
                }
                if b["bytes"].as_u64() != Some(bytes.len() as u64) {
                    p.push(format!(
                        "blob {shown}: {} bytes, manifest says {}",
                        bytes.len(),
                        b["bytes"]
                    ));
                }
            }
        }
        if let Some(d) = self.v["decoded"].as_str() {
            // One sidecar per blob, named by the blob's hash.
            let want_rel = crate::cmd::render::sidecar_rel(want);
            if d != want_rel {
                p.push(format!(
                    "sidecar path {d} is not {want_rel} (one sidecar per blob)"
                ));
            }
            if let Err(e) = self.sidecar_text() {
                p.push(e);
            }
        }
        let src = &self.v["source"];
        match src["kind"].as_str() {
            Some("history") => p.extend(self.history_chain(src)),
            Some("history-archive") => p.extend(archive::check(
                &self.ctx.corpus,
                &self.entry.id,
                self.v,
                self.blob(),
            )),
            // A chain-index row describes a whole ledger, not a slice of one.
            Some("local-core") if self.v["slice_of"].is_null() => {
                p.extend(self.chain_index_rows(src, chains))
            }
            _ => {}
        }
        p
    }

    /// Vendored lake object → sha256 → decompress → sha256 → ledger at `batch_index` and bytes
    /// at `blob_offset` equal the blob (`docs/manifest.md` §4.5).
    fn history_chain(&self, src: &Value) -> Vec<String> {
        let mut p = Vec::new();
        let object = match src["object_path"].as_str() {
            Some(op) => self.ctx.corpus.join(op),
            None => {
                let base = src["key"]
                    .as_str()
                    .unwrap_or("")
                    .rsplit('/')
                    .next()
                    .unwrap_or("");
                self.ctx.corpus.join(format!(
                    "objects/{}/{}/{base}",
                    self.v["network"].as_str().unwrap_or(""),
                    self.v["ledger_seq"]
                ))
            }
        };
        let shown = rel(&self.ctx.corpus, &object);
        let obj = match std::fs::read(&object) {
            Ok(o) => o,
            Err(e) => return vec![format!("lake object {shown}: {e}")],
        };
        let check = |p: &mut Vec<String>, what: &str, field: &str, bytes: &[u8]| {
            let got = xdrcheck_xdr::sha256_hex(bytes);
            if let Some(w) = src[format!("{field}_sha256")].as_str() {
                if w != got {
                    p.push(format!("{what}: sha256 is {got}, manifest says {w}"));
                }
            }
            if let Some(n) = src[format!("{field}_bytes")].as_u64() {
                if n != bytes.len() as u64 {
                    p.push(format!("{what}: {} bytes, manifest says {n}", bytes.len()));
                }
            }
        };
        check(&mut p, &format!("lake object {shown}"), "object", &obj);
        let dec = match xdrcheck_xdr::batch::decompress(&obj) {
            Ok(d) => d,
            Err(e) => {
                p.push(format!("lake object {shown}: does not decompress: {e}"));
                return p;
            }
        };
        check(&mut p, "decompressed object", "decompressed", &dec);
        let Ok(blob) = self.blob() else {
            return p; // reported by the blob check
        };
        // A slice carries its parent's source; its bytes sit `slice_of.byte_offset` into the
        // parent ledger.
        let slice_off = self.v["slice_of"]["byte_offset"]
            .as_u64()
            .map(|o| o as usize);
        if self.v["slice_of"].is_object() && slice_off.is_none() {
            p.push(
                "slice_of has no byte_offset; the slice cannot be located in the lake object"
                    .into(),
            );
            return p;
        }
        let within = slice_off.unwrap_or(0);
        if let Some(off) = src["blob_offset"].as_u64() {
            let off = off as usize + within;
            if dec.get(off..off + blob.len()) != Some(blob) {
                p.push(format!(
                    "decompressed object bytes [{off}, {}) are not the blob",
                    off + blob.len()
                ));
            }
        }
        match xdrcheck_xdr::split_batch(&dec, &self.ctx.limits, &self.ctx.gate) {
            Err(e) => p.push(format!("decompressed object is not a valid batch: {e}")),
            Ok(batch) => {
                let i = src["batch_index"].as_u64().unwrap_or(0) as usize;
                let ledger = batch.ledgers.get(i).map(Vec::as_slice);
                let got = match slice_off {
                    None => ledger,
                    Some(o) => ledger.and_then(|l| l.get(o..o + blob.len())),
                };
                if got != Some(blob) {
                    p.push(format!("ledger {i} of the batch is not the blob"));
                }
            }
        }
        p
    }

    /// For a variant listed in a chain index (same scenario, network and protocol), the index
    /// row for its ledger agrees with the blob (`docs/manifest.md` §11 item 6).
    fn chain_index_rows(&self, src: &Value, chains: &[(String, Value)]) -> Vec<String> {
        let mut p = Vec::new();
        for (name, c) in chains.iter().filter(|(_, c)| {
            c["scenario"] == src["scenario"]
                && c["network"] == self.v["network"]
                && c["protocol"] == self.v["protocol"]
        }) {
            let row = c["ledgers"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|r| r["seq"] == self.v["ledger_seq"]);
            let Some(row) = row else {
                p.push(format!(
                    "{name}: no row for ledger {}",
                    self.v["ledger_seq"]
                ));
                continue;
            };
            if row["blob_sha256"] != self.v["blob"]["sha256"] {
                p.push(format!(
                    "{name}: ledger {} blob_sha256 {} differs from the variant's {}",
                    row["seq"], row["blob_sha256"], self.v["blob"]["sha256"]
                ));
            }
            if row["bytes"] != self.v["blob"]["bytes"] {
                p.push(format!(
                    "{name}: ledger {} bytes {} differs from the variant's {}",
                    row["seq"], row["bytes"], self.v["blob"]["bytes"]
                ));
            }
            if let Ok(bytes) = self.blob() {
                match xdrcheck_xdr::ledger_info(bytes) {
                    Ok(info) if row["header_hash"] != hex::encode(info.header_hash) => {
                        p.push(format!(
                            "{name}: ledger {} header_hash {} is not the blob's {}",
                            row["seq"],
                            row["header_hash"],
                            hex::encode(info.header_hash)
                        ))
                    }
                    Ok(_) => {}
                    Err(e) => p.push(format!("blob header: {e}")),
                }
            }
        }
        p
    }

    /// Negative entries: the oracle must reject the bytes, for the declared reason class. The decode
    /// depth is `expect.reject.limits.depth` when the entry states one, else the oracle's default. A
    /// `record-marked` variant is a stream: every record mark must be well formed and record
    /// `frame_index` must hold exactly one value of `xdr_type`.
    fn reject(&self) -> Vec<String> {
        let reject = self
            .entry
            .json
            .as_ref()
            .ok()
            .map(|j| j["expect"]["reject"].clone())
            .unwrap_or(Value::Null);
        let Some(reason) = reject["reason"].as_str().map(str::to_string) else {
            return vec!["negative entry has no expect.reject.reason".into()];
        };
        let bytes = match self.blob() {
            Ok(b) => b,
            Err(e) => return vec![e],
        };
        let entry_depth = reject["limits"]["depth"]
            .as_u64()
            .map(|d| u32::try_from(d).unwrap_or(u32::MAX));
        let limits = xdrcheck_xdr::Limits {
            depth: entry_depth.unwrap_or(self.ctx.limits.depth),
            ..self.ctx.limits
        };
        let framed = self.v["framing"] == "record-marked";
        let outcome = if framed {
            match self.framed_decode(bytes, &limits) {
                Ok(r) => r,
                Err(problem) => return vec![problem],
            }
        } else {
            oracle_gate(self.ctx, self.xdr_type(), bytes)
                .and_then(|()| xdrcheck_xdr::roundtrip(self.xdr_type(), bytes, &limits))
        };
        let what = if framed {
            format!(
                "the record-marked stream (frame {}) as {}",
                self.frame_index(),
                self.xdr_type()
            )
        } else {
            format!("the bytes as {}", self.xdr_type())
        };
        match outcome {
            Ok(()) if entry_depth.is_some() => vec![format!(
                "the oracle accepts {what} at the entry's depth limit of {} units \
                 (expect.reject.limits.depth); expected rejection ({reason})",
                limits.depth
            )],
            Ok(()) if reason == "depth" => vec![format!(
                "the oracle accepts {what} at its default depth limit of {} units; to reject at a \
                 reader's boundary, state it as expect.reject.limits.depth",
                limits.depth
            )],
            Ok(()) => vec![format!(
                "the oracle accepts {what}; expected rejection ({reason})"
            )],
            Err(e) => {
                let classes = reason_classes(&e);
                if classes.contains(&reason.as_str()) {
                    vec![]
                } else {
                    vec![format!(
                        "rejected for another reason: {e} (class {}), expected {reason}",
                        classes.join("|")
                    )]
                }
            }
        }
    }

    /// `frame_index` of a record-marked variant (default 0).
    fn frame_index(&self) -> usize {
        self.v["frame_index"].as_u64().unwrap_or(0) as usize
    }

    /// Split a record-marked stream and check its frame. The inner result is the oracle's verdict
    /// on the input; the outer error is a manifest problem (no such frame).
    fn framed_decode(
        &self,
        stream: &[u8],
        limits: &xdrcheck_xdr::Limits,
    ) -> Result<Result<(), XdrError>, String> {
        let records = match xdrcheck_xdr::split(stream) {
            Ok(r) => r,
            Err(e) => return Ok(Err(e)),
        };
        let i = self.frame_index();
        let Some(r) = records.get(i) else {
            return Err(format!(
                "frame_index {i} is past the end of the stream ({} well-formed records)",
                records.len()
            ));
        };
        Ok(oracle_gate(self.ctx, self.xdr_type(), r.payload)
            .and_then(|()| xdrcheck_xdr::framing::check_record(self.xdr_type(), r, limits)))
    }

    fn pinpoints(&self) -> Vec<String> {
        let mut p = Vec::new();
        let Ok(j) = &self.entry.json else {
            return vec!["entry is unreadable".into()];
        };
        let derived = &self.v["derived"];
        // Every ${derived.*} token in expect (and api.input) resolves in this variant.
        let mut strings = Vec::new();
        collect_strings(&j["expect"], &mut strings);
        collect_strings(&j["api"]["input"], &mut strings);
        for s in strings {
            if let Err(e) = substitute(s, derived) {
                p.push(e);
            }
        }
        let sidecar = match self.read_sidecar() {
            Ok(s) => s,
            Err(e) => {
                p.push(e);
                return p;
            }
        };
        if let Some(fp) = self.v["focus"]["path"].as_str() {
            if sidecar.pointer(fp).is_none() {
                p.push(format!("focus.path {fp} does not resolve in the sidecar"));
            }
        }
        for item in j["expect"]["values"].as_array().into_iter().flatten() {
            let rel = item["path"].as_str().unwrap_or("");
            // A key-selected pinpoint: its path is relative to the element the key selects.
            let resolved = match item.get("select") {
                None => Ok(rel.to_string()),
                Some(sel) => subst_value(sel, derived).and_then(|sel| {
                    let limits = xdrcheck_xdr::Limits::default();
                    xdrcheck_xdr::from_json("LedgerKey", &sel["key"], &limits).map_err(|e| {
                        format!("select.key {} is not a LedgerKey: {e}", sel["key"])
                    })?;
                    super::select::resolve(&sidecar, &sel).map(|at| format!("{at}{rel}"))
                }),
            };
            let path = match resolved {
                Ok(p) => p,
                Err(e) => {
                    p.push(e);
                    continue;
                }
            };
            let path = path.as_str();
            let Some(got) = sidecar.pointer(path) else {
                p.push(format!("{path} does not resolve in the sidecar"));
                continue;
            };
            match subst_value(&item["equals"], derived) {
                Err(e) => p.push(e),
                Ok(want) if &want != got => {
                    p.push(format!("{path}: expected {want}, sidecar has {got}"))
                }
                Ok(_) => {}
            }
        }
        if self.entry.kind() == "ledger" && self.xdr_type() == "LedgerCloseMeta" {
            p.extend(self.ledger_facts(derived));
        }
        // The features the bytes need, and the object-layer values their focus implies.
        let xdr_type = self.xdr_type();
        let want = xdrcheck_xdr::with_stack(self.ctx.limits.stack_size, || {
            let w = xdrcheck_meta::derive::requires(xdr_type, &sidecar);
            drop(sidecar);
            w
        });
        p.extend(xdrcheck_meta::derive::compare_requires(
            &self.v["requires"],
            &want,
        ));
        if let Ok(bytes) = self.blob() {
            let passphrase = self.v["passphrase"].as_str().unwrap_or("");
            let ctx = self.ctx;
            match xdrcheck_meta::derive::l1(
                xdr_type,
                bytes,
                passphrase,
                &self.v["focus"],
                &ctx.limits,
                &ctx.gate,
            ) {
                Ok(w) => p.extend(xdrcheck_meta::derive::compare_l1(&derived["l1"], &w)),
                Err(e) => p.push(format!("derived.l1: {e}")),
            }
        }
        p
    }

    /// `derived.ledger_hash` is the header hash in the blob and every `derived.header` value the
    /// header's; transaction hashes recomputed from the envelopes under the variant's passphrase
    /// equal the result hashes, `derived.tx_hashes` and the focus transaction.
    fn ledger_facts(&self, derived: &Value) -> Vec<String> {
        let mut p = Vec::new();
        let Ok(bytes) = self.blob() else {
            return p;
        };
        match (xdrcheck_xdr::ledger_info(bytes), derived["ledger_hash"].as_str()) {
            (Ok(info), Some(want)) if hex::encode(info.header_hash) != want => p.push(format!(
                "derived.ledger_hash {want} is not the blob's header hash {}",
                hex::encode(info.header_hash)
            )),
            (Err(e), _) => p.push(format!("blob header: {e}")),
            _ => {}
        }
        let passphrase = self.v["passphrase"].as_str().unwrap_or("");
        let hashes = match tx_hashes(bytes, passphrase, &self.ctx.limits, &self.ctx.gate) {
            Ok(h) => h,
            Err(e) => {
                p.push(format!("transaction hashes: {e}"));
                return p;
            }
        };
        let hexes: Vec<String> = hashes.results.iter().map(hex::encode).collect();
        let (mut r, mut e) = (hashes.results.clone(), hashes.envelopes.clone());
        r.sort();
        e.sort();
        if r != e {
            p.push(format!(
                "envelope hashes under passphrase {passphrase:?} do not equal the result hashes ({} envelopes, {} results)",
                e.len(),
                r.len()
            ));
        }
        p.extend(transaction_meta_version_problems(
            &self.v["meta"]["transaction_meta_version"],
            &hashes.meta_versions,
            self.v["focus"]["tx_index"].as_u64(),
        ));
        p.extend(derived_header_problems(&derived["header"], &hashes.header));
        if let Some(want) = derived["tx_hashes"].as_array() {
            let want: Vec<&str> = want.iter().filter_map(Value::as_str).collect();
            if want != hexes {
                p.push("derived.tx_hashes differ from the result hashes in apply order".into());
            }
        }
        let focus = &self.v["focus"];
        if let Some(i) = focus["tx_index"].as_u64() {
            match hexes.get(i as usize) {
                None => p.push(format!("focus.tx_index {i} is past the last transaction")),
                Some(h) => {
                    for (what, val) in [
                        ("focus.tx_hash", &focus["tx_hash"]),
                        ("derived.tx_hash", &derived["tx_hash"]),
                    ] {
                        if let Some(w) = val.as_str() {
                            if w != h {
                                p.push(format!("{what} {w} is not transaction {i}'s hash {h}"));
                            }
                        }
                    }
                }
            }
        }
        p
    }

    /// AG-1: the blob is frame `frame_index` of the pinned golden file. A missing golden cache is
    /// a tool error (exit 2), not a failed check.
    fn ag1(&self) -> Result<Vec<String>> {
        let src = &self.v["source"];
        let tag = src["core_tag"].as_str().unwrap_or("");
        let file = src["file"].as_str().unwrap_or("");
        let path = self.ctx.goldens.join(tag).join(file);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => bail!(
                "ag1: golden file {} is not in the cache ({e}); run `xdrcheck-corpus fetch-goldens {tag}` or pass --goldens",
                path.display()
            ),
        };
        let mut p = Vec::new();
        let got = xdrcheck_xdr::sha256_hex(&data);
        if src["file_sha256"].as_str() != Some(got.as_str()) {
            p.push(format!(
                "golden {file}: sha256 is {got}, manifest says {}",
                src["file_sha256"]
            ));
        }
        let frame = src["frame_index"].as_u64().unwrap_or(u64::MAX) as usize;
        match xdrcheck_xdr::split(&data) {
            Err(e) => p.push(format!("golden {file}: {e}")),
            Ok(records) => match (records.get(frame), self.blob()) {
                (None, _) => p.push(format!(
                    "golden {file} has {} records, no frame {frame}",
                    records.len()
                )),
                (Some(_), Err(e)) => p.push(e),
                (Some(r), Ok(blob)) if r.payload != blob => {
                    p.push(format!("frame {frame} of golden {file} is not the blob"))
                }
                _ => {}
            },
        }
        Ok(p)
    }

    /// The reference extractor's facts agree with the entry's `expect`, resolved for this variant
    /// (`docs/manifest.md` §6.11; rules in `xdrcheck_meta::extract::agree`).
    fn extractor(&self) -> Vec<String> {
        use xdrcheck_meta::extract::{agree, extract, network_id};
        let Ok(j) = &self.entry.json else {
            return vec!["entry is unreadable".into()];
        };
        let bytes = match self.blob() {
            Ok(b) => b,
            Err(e) => return vec![e],
        };
        let passphrase = self.v["passphrase"].as_str().unwrap_or("");
        let expect = match agree::resolve_derived(&j["expect"], &self.v["derived"]) {
            Ok(x) => x,
            Err(e) => return vec![e],
        };
        let focus = self.v["focus"]["tx_index"].as_u64().unwrap_or(0) as usize;
        let ctx = self.ctx;
        xdrcheck_xdr::with_stack(ctx.limits.stack_size, || {
            let lcm = match xdrcheck_xdr::decode_ledger(bytes, &ctx.limits, &ctx.gate) {
                Ok(l) => l,
                Err(e) => return vec![e.to_string()],
            };
            match extract(&lcm, passphrase) {
                Ok(ext) => agree::check(&expect, &ext, focus, network_id(passphrase)),
                Err(e) => vec![format!("extractor: {e}")],
            }
        })
    }

    /// AG-3 on the curated tier: the golden blob decodes and re-encodes byte-exactly.
    fn ag3(&self) -> Vec<String> {
        match self.blob() {
            Err(e) => vec![e],
            Ok(bytes) => match xdrcheck_xdr::roundtrip(self.xdr_type(), bytes, &self.ctx.limits) {
                Ok(()) => vec![],
                Err(e) => vec![e.to_string()],
            },
        }
    }
}

/// `meta.transaction_meta_version` against the `TransactionMeta` arms in the blob (`arms`, apply
/// order): absent when the ledger has no transactions (there is no TransactionMeta to read), else
/// the focus transaction's arm, or the arm every transaction shares.
fn transaction_meta_version_problems(
    stated: &Value,
    arms: &[i32],
    focus: Option<u64>,
) -> Vec<String> {
    if arms.is_empty() {
        return match stated.is_null() {
            true => vec![],
            false => vec![format!(
                "meta.transaction_meta_version is {stated}, but the ledger has no transactions: \
                 there is no TransactionMeta to read it from; leave it out"
            )],
        };
    }
    let Some(stated) = stated.as_i64() else {
        return vec![]; // a missing value is reported by the schema check
    };
    let want: Vec<i32> = match focus.and_then(|i| arms.get(i as usize)) {
        Some(a) => vec![*a],
        None => {
            let mut a = arms.to_vec();
            a.sort_unstable();
            a.dedup();
            a
        }
    };
    if want == [stated as i32] {
        vec![]
    } else {
        vec![format!(
            "meta.transaction_meta_version is {stated}, but the blob's TransactionMeta is v{}",
            want.iter()
                .map(i32::to_string)
                .collect::<Vec<_>>()
                .join(", v")
        )]
    }
}

/// Decode under the oracle's limits; for `LedgerCloseMeta` check the gate first (typed
/// refusal). With `full`, also re-encode and JSON-round-trip and return the JSON.
pub fn oracle_decode(
    ctx: &Ctx,
    xdr_type: &str,
    bytes: &[u8],
    full: bool,
) -> Result<Value, XdrError> {
    oracle_gate(ctx, xdr_type, bytes)?;
    if full {
        xdrcheck_xdr::json_roundtrip(xdr_type, bytes, &ctx.limits)
    } else {
        xdrcheck_xdr::roundtrip(xdr_type, bytes, &ctx.limits).map(|()| Value::Null)
    }
}

/// The fail-closed gate, for `LedgerCloseMeta` only (a typed refusal before any decode).
fn oracle_gate(ctx: &Ctx, xdr_type: &str, bytes: &[u8]) -> Result<(), XdrError> {
    if xdr_type == "LedgerCloseMeta" {
        ctx.gate.check(&xdrcheck_xdr::ledger_info(bytes)?)?;
    }
    Ok(())
}

/// The `expect.reject.reason` values an oracle error is consistent with. The library reports
/// several malformations with one error (an undeclared enum value, union arm or optional flag
/// are all "invalid"), so some errors admit several reasons. The library reads a boolean
/// leniently (any value other than 1 is false), so a boolean out of range is rejected by the
/// byte-exact re-encode, not by the decoder.
pub fn reason_classes(e: &XdrError) -> Vec<&'static str> {
    use xdrcheck_xdr::xdr::Error as X;
    match e {
        XdrError::LimitExceeded {
            limit: LimitKind::Depth,
            ..
        } => vec!["depth"],
        XdrError::LimitExceeded {
            limit: LimitKind::Len,
            ..
        } => vec!["length_exceeds_input"],
        XdrError::Malformed { reason, .. } => match reason {
            Malformed::TrailingBytes { .. } => vec!["trailing_bytes"],
            Malformed::UnexpectedEof => vec!["length_exceeds_input"],
            Malformed::Invalid(m) if *m == X::NonZeroPadding.to_string() => {
                vec!["nonzero_padding"]
            }
            Malformed::Invalid(m) if *m == X::LengthExceedsMax.to_string() => {
                vec!["length_exceeds_max"]
            }
            Malformed::Invalid(m) if *m == X::Invalid.to_string() => vec![
                "optional_flag_range",
                "enum_undeclared",
                "union_arm_undeclared",
            ],
            _ => vec!["other"],
        },
        XdrError::RoundTrip { stage: "xdr", .. } => vec!["bool_range"],
        // Record-mark faults of a record-marked stream. A mark that declares more bytes than remain,
        // or fewer than its value needs, is also a length fault; one that declares more than the
        // value holds leaves trailing bytes in the record.
        XdrError::Framing(f) => match f {
            FramingError::Truncated { .. } => vec!["record_mark", "length_exceeds_input"],
            FramingError::LengthMismatch { detail, .. } if detail.starts_with("needs more") => {
                vec!["record_mark", "length_exceeds_input"]
            }
            FramingError::LengthMismatch { .. } => vec!["record_mark", "trailing_bytes"],
            FramingError::LastFragmentBitClear { .. } | FramingError::RecordTooLarge(_) => {
                vec!["record_mark"]
            }
        },
        XdrError::Refusal(Refusal::UnknownLedgerCloseMetaVersion { .. }) => {
            vec!["union_arm_undeclared"]
        }
        _ => vec!["other"],
    }
}

// ---------------------------------------------------------------------------------------------
// Helpers

fn rel(base: &Path, p: &Path) -> String {
    p.strip_prefix(base).unwrap_or(p).display().to_string()
}

fn collect_strings<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter().for_each(|x| collect_strings(x, out)),
        Value::Object(m) => m.values().for_each(|x| collect_strings(x, out)),
        _ => {}
    }
}

/// `derived.header` (optional) against the blob's ledger header: an object whose every key is a
/// header field verify knows and whose every value is that field's decimal string.
fn derived_header_problems(want: &Value, header: &xdrcheck_xdr::xdr::LedgerHeader) -> Vec<String> {
    let m = match want {
        Value::Null => return vec![],
        Value::Object(m) => m,
        other => return vec![format!("derived.header must be an object, not {other}")],
    };
    let mut p = Vec::new();
    for (k, v) in m {
        match (super::ledger::header_field(header, k), v.as_str()) {
            (None, _) => p.push(format!(
                "derived.header.{k} is not a ledger-header field verify checks"
            )),
            (Some(_), None) => p.push(format!(
                "derived.header.{k} must be a decimal string, not {v}"
            )),
            (Some(got), Some(w)) if got != w => p.push(format!(
                "derived.header.{k} {w} is not the blob's header value {got}"
            )),
            _ => {}
        }
    }
    p
}

/// Replace every `${derived.<path>}` in `s` (textual, single pass; `docs/manifest.md` §4.6).
pub fn substitute(s: &str, derived: &Value) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find("${derived.") {
        out.push_str(&rest[..start]);
        let after = &rest[start + "${derived.".len()..];
        let Some(end) = after.find('}') else {
            return Err(format!("unterminated token in {s:?}"));
        };
        let path = &after[..end];
        let mut cur = derived;
        for seg in path.split('.') {
            cur = match cur {
                Value::Object(m) => m.get(seg).unwrap_or(&Value::Null),
                Value::Array(a) => seg
                    .parse::<usize>()
                    .ok()
                    .and_then(|i| a.get(i))
                    .unwrap_or(&Value::Null),
                _ => &Value::Null,
            };
        }
        match cur {
            Value::Null => return Err(format!("${{derived.{path}}} has no value in this variant")),
            Value::String(v) => out.push_str(v),
            other => out.push_str(&other.to_string()),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn subst_value(v: &Value, derived: &Value) -> Result<Value, String> {
    Ok(match v {
        Value::String(s) => Value::String(substitute(s, derived)?),
        Value::Array(a) => Value::Array(
            a.iter()
                .map(|x| subst_value(x, derived))
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| Ok((k.clone(), subst_value(x, derived)?)))
                .collect::<Result<_, String>>()?,
        ),
        other => other.clone(),
    })
}

/// JSON Pointer of the first place two values differ.
fn first_difference(a: &Value, b: &Value, at: String) -> String {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for (k, va) in x {
                let p = format!("{at}/{}", k.replace('~', "~0").replace('/', "~1"));
                match y.get(k) {
                    None => return format!("{p} (missing in the fresh rendering)"),
                    Some(vb) if va != vb => return first_difference(va, vb, p),
                    _ => {}
                }
            }
            match y.keys().find(|k| !x.contains_key(*k)) {
                Some(k) => format!("{at}/{k} (missing in the sidecar)"),
                None => at,
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            for (i, (va, vb)) in x.iter().zip(y).enumerate() {
                if va != vb {
                    return first_difference(va, vb, format!("{at}/{i}"));
                }
            }
            format!("{at} (length {} vs {})", x.len(), y.len())
        }
        _ => {
            if at.is_empty() {
                "/".into()
            } else {
                at
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn substitution() {
        let d = json!({"contracts": {"sac": "CABC"}, "tx_hashes": ["aa", "bb"], "n": 5});
        assert_eq!(substitute("${derived.contracts.sac}", &d).unwrap(), "CABC");
        assert_eq!(substitute("x${derived.tx_hashes.1}y", &d).unwrap(), "xbby");
        assert_eq!(substitute("${derived.n}", &d).unwrap(), "5");
        assert!(substitute("${derived.missing}", &d).is_err());
        assert_eq!(substitute("plain", &d).unwrap(), "plain");
    }

    fn repo_corpus() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
    }

    fn entry(id: &str) -> Entry {
        let p = repo_corpus().join(format!("manifest/{id}.json"));
        Entry {
            id: id.into(),
            json: Ok(serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()),
        }
    }

    /// A ledger with no transactions has no TransactionMeta: `meta.transaction_meta_version` is
    /// left out there (and an error when stated), and required on every other ledger variant.
    #[test]
    fn transaction_meta_version_is_absent_without_transactions() {
        let schemas = Schemas::load(&repo_corpus()).unwrap();
        let tmv = |p: &[String]| p.iter().any(|x| x.contains("transaction_meta_version"));
        let mut e = entry("protocol-02/upgrade-ledger-empty-changes");
        let j = e.json.as_mut().unwrap();
        assert_eq!(j["expect"]["ledger"]["transactions"], 0);
        j["variants"][0]["meta"]
            .as_object_mut()
            .unwrap()
            .remove("transaction_meta_version");
        assert!(!tmv(&schema_problems(&e, &schemas)));
        e.json.as_mut().unwrap()["variants"][0]["meta"]["transaction_meta_version"] = json!(4);
        assert!(tmv(&schema_problems(&e, &schemas)));

        let mut e = entry("cap-0038/pool-issuers-order-by-bytes-not-strkey");
        assert!(!tmv(&schema_problems(&e, &schemas)));
        e.json.as_mut().unwrap()["variants"][0]["meta"]
            .as_object_mut()
            .unwrap()
            .remove("transaction_meta_version");
        assert!(tmv(&schema_problems(&e, &schemas)));

        // Against the bytes.
        let f = transaction_meta_version_problems;
        assert!(f(&Value::Null, &[], None).is_empty());
        assert!(!f(&json!(4), &[], None).is_empty());
        assert!(f(&json!(4), &[4, 4], None).is_empty());
        assert!(!f(&json!(3), &[4, 4], None).is_empty());
        assert!(!f(&json!(4), &[3, 4], None).is_empty());
        assert!(f(&json!(4), &[3, 4], Some(1)).is_empty());
    }

    /// `derived.header` pins the blob's ledger-header values, so an expectation shared by variants
    /// whose header differs (the fee pool after the Protocol 24 upgrade, per passphrase) can name
    /// them: a wrong value, a number instead of a decimal string, a field verify does not know and
    /// a non-object are each a problem.
    #[test]
    fn derived_header_is_checked_against_the_bytes() {
        let ctx = Ctx {
            corpus: repo_corpus(),
            overlay: None,
            limits: xdrcheck_xdr::Limits::default(),
            gate: xdrcheck_xdr::Gate::default(),
            goldens: repo_corpus().join("no-goldens"),
            corpus_json: None,
            write_mirrors: false,
        };
        let e = entry("cap-0076/fee-pool-adjustment-on-public-passphrase");
        let header = |v: &Value| -> Vec<String> {
            VariantCtx::new(&ctx, &e, v)
                .pinpoints()
                .into_iter()
                .filter(|p| p.contains("derived.header"))
                .collect()
        };
        let mut pools = Vec::new();
        for v in e.variants() {
            assert!(v["derived"]["header"].is_object(), "{}", v["network"]);
            assert!(header(v).is_empty(), "{:?}", header(v));
            pools.push(v["derived"]["header"]["fee_pool"].clone());
        }
        // One expectation, a different fee pool per passphrase.
        assert!(pools.len() >= 2 && pools[0] != pools[1], "{pools:?}");

        let v = &e.variants()[0];
        for (field, value) in [
            ("fee_pool", json!("1")),
            ("ledger_version", json!(24)),
            ("no_such_field", json!("1")),
        ] {
            let mut bad = v.clone();
            bad["derived"]["header"][field] = value;
            let p = header(&bad);
            assert!(p.iter().any(|x| x.contains(field)), "{field}: {p:?}");
        }
        let mut bad = v.clone();
        bad["derived"]["header"] = json!("24");
        assert!(!header(&bad).is_empty());
    }

    /// A scratch directory next to the test binary (inside the build's target directory).
    fn scratch(name: &str) -> PathBuf {
        let exe = std::env::current_exe().unwrap();
        let dir = exe
            .parent()
            .unwrap()
            .join("xdrcheck-test-scratch")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn copy_tree(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for e in std::fs::read_dir(from).unwrap() {
            let p = e.unwrap().path();
            let dest = to.join(p.file_name().unwrap());
            if p.is_dir() {
                copy_tree(&p, &dest);
            } else {
                std::fs::copy(&p, &dest).unwrap();
            }
        }
    }

    /// `hashes` on a `history-archive` variant checks the vendored archive object, the HAS and
    /// the record at `byte_offset`, and fails on any tampering.
    #[test]
    fn history_archive_objects_are_hash_checked() {
        let repo = repo_corpus();
        let ids = [
            "cap-0085/bucket-entry-with-executable-tag",
            "cap-0020/bucket-metaentry-first-record",
        ];
        let entries: Vec<Entry> = ids.iter().map(|id| entry(id)).collect();
        let dir = scratch("history-archive");
        let corpus = dir.join("corpus");
        let mut object_dir = None;
        for e in &entries {
            let v = &e.variants()[0];
            assert_eq!(v["source"]["kind"], "history-archive");
            for f in [&v["blob"]["path"], &v["decoded"]] {
                let f = f.as_str().unwrap();
                std::fs::create_dir_all(corpus.join(f).parent().unwrap()).unwrap();
                std::fs::copy(repo.join(f), corpus.join(f)).unwrap();
            }
            let net = v["network"].as_str().unwrap();
            for c in archive::captures(&repo, net) {
                let cj: Value = serde_json::from_slice(&std::fs::read(&c).unwrap()).unwrap();
                if cj["object"] == v["source"]["object"] {
                    let rel = c
                        .parent()
                        .unwrap()
                        .strip_prefix(&repo)
                        .unwrap()
                        .to_path_buf();
                    copy_tree(c.parent().unwrap(), &corpus.join(&rel));
                    object_dir = Some(corpus.join(rel));
                }
            }
        }
        let object_dir = object_dir.expect("a vendored history-archive object");
        let ctx = Ctx {
            corpus: corpus.clone(),
            overlay: None,
            limits: xdrcheck_xdr::Limits::default(),
            gate: xdrcheck_xdr::Gate::default(),
            goldens: dir.join("goldens"),
            corpus_json: None,
            write_mirrors: false,
        };
        let hashes = |e: &Entry, v: &Value| VariantCtx::new(&ctx, e, v).hashes(&[]);
        for e in &entries {
            let p = hashes(e, &e.variants()[0]);
            assert!(p.is_empty(), "{}: {p:?}", e.id);
        }

        // Another record offset is not the blob.
        let e = &entries[0];
        let mut v = e.variants()[0].clone();
        v["source"]["byte_offset"] = json!(0);
        assert!(!hashes(e, &v).is_empty());

        let file_of = |suffix: &str| {
            std::fs::read_dir(&object_dir)
                .unwrap()
                .map(|d| d.unwrap().path())
                .find(|p| {
                    let name = p.file_name().unwrap().to_string_lossy();
                    name.ends_with(suffix) && name != "capture.json"
                })
                .unwrap()
        };
        let tamper = |p: &Path, at: usize| {
            let mut b = std::fs::read(p).unwrap();
            let i = at.min(b.len() - 1);
            b[i] ^= 0x01;
            std::fs::write(p, b).unwrap();
        };
        // A changed HAS.
        let has = file_of(".json");
        let original = std::fs::read(&has).unwrap();
        tamper(&has, 40);
        assert!(hashes(e, &e.variants()[0])
            .iter()
            .any(|x| x.contains("HAS")));
        std::fs::write(&has, original).unwrap();
        // A changed bucket object (inside the compressed data).
        let obj = file_of(".xdr.gz");
        let original = std::fs::read(&obj).unwrap();
        tamper(&obj, original.len() / 2);
        assert!(!hashes(e, &e.variants()[0]).is_empty());
        std::fs::write(&obj, original).unwrap();
        // No vendored object at all.
        std::fs::remove_dir_all(&object_dir).unwrap();
        assert!(hashes(e, &e.variants()[0])
            .iter()
            .any(|x| x.contains("no vendored history-archive object")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn difference_pointer() {
        let a = json!({"a": [1, {"b": 2}]});
        let b = json!({"a": [1, {"b": 3}]});
        assert_eq!(first_difference(&a, &b, String::new()), "/a/1/b");
    }
}
