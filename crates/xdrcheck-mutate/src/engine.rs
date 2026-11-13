//! Sources, mutants and the deterministic plan.
//!
//! A **source** is one valid value from the corpus: a variant's blob (`LedgerCloseMeta`, `ScVal`,
//! `TransactionEnvelope`, …), or a value cut out of a ledger at its typed byte range (the first
//! envelopes and `SCVal`s of a ledger, so SDK value decoders see real values of every kind). A
//! **mutant** is a source with one or more mutations of one class applied.
//!
//! Determinism: the plan for (`seed`, `budget`, sources) is fixed, a mutation's argument is a
//! function of (entry, variant, seed, mutator, place), and building a mutant from its mutation
//! list is pure, so the same command gives byte-identical mutants.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use xdrcheck_xdr::{Gate, Limits};

use crate::mutate::{self, Class, Mutation, Origin};
use crate::oracle::{self, Reseal, Verdict};
use crate::schema::{Schema, Ty};
use crate::tree;

/// One value to mutate.
#[derive(Debug, Clone)]
pub struct Source {
    /// The source's ID: the entry ID, plus `#<path>` for a value cut out of a ledger.
    pub id: String,
    pub entry: String,
    pub variant: usize,
    pub xdr_type: String,
    pub bytes: Vec<u8>,
    pub passphrase: String,
    pub network: String,
    pub protocol: u64,
    /// The manifest entry (for a cut value: the ledger's entry).
    pub entry_json: Value,
    /// The variant.
    pub variant_json: Value,
    /// Where a cut value came from in the ledger.
    pub cut_from: Option<String>,
}

impl Source {
    pub fn is_ledger(&self) -> bool {
        self.xdr_type == "LedgerCloseMeta"
    }
    pub fn origin(&self, seed: u64) -> Origin<'_> {
        Origin {
            entry: &self.id,
            variant: self.variant,
            seed,
        }
    }
}

/// Options for listing sources.
#[derive(Debug, Clone)]
pub struct SourceOpts {
    /// Entry ID globs (`*` matches anything); empty selects every entry.
    pub entries: Vec<String>,
    /// Largest blob read, in bytes.
    pub max_bytes: usize,
    /// Every variant, not only the first of each entry.
    pub all_variants: bool,
    /// Cut envelopes and SCVals out of ledgers as sources of their own.
    pub cut_values: bool,
}

impl Default for SourceOpts {
    fn default() -> Self {
        SourceOpts {
            entries: Vec::new(),
            max_bytes: 256 << 10,
            all_variants: false,
            cut_values: true,
        }
    }
}

/// A `*` glob.
pub fn glob_match(glob: &str, s: &str) -> bool {
    let parts: Vec<&str> = glob.split('*').collect();
    if parts.len() == 1 {
        return glob == s;
    }
    let mut rest = s;
    for (i, p) in parts.iter().enumerate() {
        if i == 0 {
            match rest.strip_prefix(p) {
                Some(r) => rest = r,
                None => return false,
            }
        } else if i == parts.len() - 1 {
            return rest.ends_with(p);
        } else {
            match rest.find(p) {
                Some(at) => rest = &rest[at + p.len()..],
                None => return false,
            }
        }
    }
    true
}

fn walk_json(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut items: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .collect();
    items.sort();
    for p in items {
        if p.is_dir() {
            walk_json(&p, out)?;
        } else if p.extension().is_some_and(|x| x == "json") {
            out.push(p);
        }
    }
    Ok(())
}

/// The corpus gate (`corpus.json`), or the pinned default.
pub fn gate(corpus: &Path) -> Result<Gate> {
    Ok(Gate::from_corpus_json(&corpus.join("corpus.json"))?.unwrap_or_default())
}

/// Every valid source of the corpus, sorted by ID.
pub fn sources(corpus: &Path, s: &Schema, o: &SourceOpts) -> Result<Vec<Source>> {
    let mut files = Vec::new();
    walk_json(&corpus.join("manifest"), &mut files)?;
    let mut out = Vec::new();
    for f in files {
        let e: Value = serde_json::from_slice(&std::fs::read(&f)?)
            .with_context(|| format!("parsing {}", f.display()))?;
        let id = e["id"].as_str().unwrap_or_default().to_string();
        if !o.entries.is_empty() && !o.entries.iter().any(|g| glob_match(g, &id)) {
            continue;
        }
        if e["negative"].as_bool() == Some(true)
            || !matches!(e["kind"].as_str(), Some("ledger" | "xdr"))
        {
            continue;
        }
        let Some(vars) = e["variants"].as_array() else {
            continue;
        };
        for (vi, v) in vars.iter().enumerate() {
            if vi > 0 && !o.all_variants {
                break;
            }
            let (Some(path), Some(n)) = (v["blob"]["path"].as_str(), v["blob"]["bytes"].as_u64())
            else {
                continue;
            };
            if n as usize > o.max_bytes || v["framing"].as_str() == Some("record-marked") {
                continue;
            }
            let xdr_type = v["xdr_type"].as_str().unwrap_or_default().to_string();
            if !s.has(&xdr_type) {
                continue;
            }
            let bytes = std::fs::read(corpus.join(path))
                .with_context(|| format!("{id}: reading {path}"))?;
            out.push(Source {
                id: id.clone(),
                entry: id.clone(),
                variant: vi,
                xdr_type,
                bytes,
                passphrase: v["passphrase"].as_str().unwrap_or_default().to_string(),
                network: v["network"].as_str().unwrap_or("none").to_string(),
                protocol: v["protocol"].as_u64().unwrap_or(0),
                entry_json: e.clone(),
                variant_json: v.clone(),
                cut_from: None,
            });
        }
    }
    if o.cut_values {
        let mut cut = Vec::new();
        // Each ledger cuts its own values: a source ID never depends on which other ledgers are listed.
        for src in out.iter().filter(|x| x.is_ledger()) {
            cut.extend(cut_values(s, src)?);
        }
        out.extend(cut);
    }
    out.sort_by(|a, b| (a.id.as_str(), a.variant).cmp(&(b.id.as_str(), b.variant)));
    Ok(out)
}

/// Up to two envelopes and two SCVals of a ledger, each as a source (byte-identical values once).
fn cut_values(s: &Schema, src: &Source) -> Result<Vec<Source>> {
    let mut seen = BTreeSet::new();
    let root_ty = Ty::Ref("LedgerCloseMeta".into());
    let bytes = src.bytes.clone();
    let found: Vec<(String, String, u32, u32)> =
        xdrcheck_xdr::with_stack(Limits::default().stack_size, || -> Result<_> {
            let node = tree::decode(s, &root_ty, &bytes)?;
            let sites = tree::sites(s, &root_ty, &node)?;
            let mut want: BTreeMap<&str, usize> = [("TransactionEnvelope", 2usize), ("SCVal", 2)]
                .into_iter()
                .collect();
            let mut out = Vec::new();
            for st in &sites {
                let Some(t) = st.type_name.as_deref() else {
                    continue;
                };
                // An SCVal under another SCVal is part of the outer value; take outermost values.
                let Some(left) = want.get_mut(t) else {
                    continue;
                };
                if *left == 0 || st.end <= st.off {
                    continue;
                }
                if out
                    .iter()
                    .any(|(tn, _, o, e): &(String, String, u32, u32)| {
                        tn == t && st.off >= *o && st.end <= *e
                    })
                {
                    continue;
                }
                *left -= 1;
                out.push((t.to_string(), st.path.clone(), st.off, st.end));
            }
            drop(sites);
            drop(node);
            Ok(out)
        })?;
    let mut out = Vec::new();
    for (t, path, off, end) in found {
        let b = bytes[off as usize..end as usize].to_vec();
        if !seen.insert(xdrcheck_xdr::sha256_hex(&b)) {
            continue;
        }
        let xdr_type = if t == "SCVal" { "ScVal".to_string() } else { t };
        out.push(Source {
            id: format!("{}#{}", src.entry, path),
            entry: src.entry.clone(),
            variant: src.variant,
            xdr_type,
            bytes: b,
            passphrase: src.passphrase.clone(),
            network: src.network.clone(),
            protocol: src.protocol,
            entry_json: src.entry_json.clone(),
            variant_json: src.variant_json.clone(),
            cut_from: Some(path),
        });
    }
    Ok(out)
}

/// The XDR type expression of a source.
pub fn root_ty(s: &Schema, xdr_type: &str) -> Result<Ty> {
    let (k, _) = s
        .lookup(xdr_type)
        .ok_or_else(|| anyhow!("unknown XDR type {xdr_type}"))?;
    Ok(Ty::Ref(k.to_string()))
}

/// Every candidate mutation of a source for the given classes (the argument picked by the seed).
pub fn candidates(s: &Schema, src: &Source, seed: u64, classes: &[Class]) -> Result<Vec<Mutation>> {
    let t = root_ty(s, &src.xdr_type)?;
    let bytes = src.bytes.clone();
    let o = src.origin(seed);
    xdrcheck_xdr::with_stack(Limits::default().stack_size, || -> Result<_> {
        let node = tree::decode(s, &t, &bytes).with_context(|| {
            format!(
                "{}: the tree reader refuses a value the corpus holds",
                src.id
            )
        })?;
        let sites = tree::sites(s, &t, &node)?;
        let c = mutate::candidates(s, &sites, &node, &o, classes, src.is_ledger())?;
        drop(sites);
        drop(node);
        Ok(c)
    })
}

/// A built mutant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mutant {
    pub id: String,
    pub source: String,
    pub entry: String,
    pub variant: usize,
    pub seed: u64,
    pub class: Class,
    pub xdr_type: String,
    /// The mutations that changed the value, in order.
    pub mutations: Vec<Mutation>,
    #[serde(with = "hex_bytes")]
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub oracle: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reseal: Option<Reseal>,
    pub stale_hashes: bool,
    /// The protocol rule the mutant's value breaks although XDR admits it (see
    /// [`mutate::protocol_rule`]).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub protocol_rule: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub notes: Vec<String>,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

/// The ID of a mutant: a hash of its source, seed and mutation IDs.
pub fn mutant_id(src: &Source, seed: u64, muts: &[Mutation]) -> String {
    let mut h = Sha256::new();
    h.update(format!("{}\0{}\0{seed}", src.id, src.variant));
    for m in muts {
        h.update(b"\0");
        h.update(m.id.as_bytes());
    }
    format!("x{}", &hex::encode(h.finalize())[..16])
}

/// Build a mutant from mutations of one class. Mutations that change nothing (a place an earlier
/// mutation replaced) are dropped; `Ok(None)` when none changes anything.
pub fn build(
    s: &Schema,
    src: &Source,
    seed: u64,
    muts: &[Mutation],
    stale_hashes: bool,
    gate: &Gate,
) -> Result<Option<Mutant>> {
    let Some(class) = muts.first().map(|m| m.class) else {
        return Ok(None);
    };
    if muts.iter().any(|m| m.class != class) {
        bail!("a mutant's mutations are of one class");
    }
    let t = root_ty(s, &src.xdr_type)?;
    let src_bytes = src.bytes.clone();
    let mut notes = Vec::new();
    let built: Option<(Vec<u8>, Vec<Mutation>, Option<Reseal>)> =
        xdrcheck_xdr::with_stack(Limits::default().stack_size, || -> Result<_> {
            match class {
                Class::Valid => {
                    let mut node = tree::decode(s, &t, &src_bytes)?;
                    let mut applied = Vec::new();
                    for m in muts {
                        if mutate::apply_valid(s, &t, &mut node, m)? {
                            applied.push(m.clone());
                        }
                    }
                    if applied.is_empty() {
                        return Ok(None);
                    }
                    let mut bytes = tree::encode(s, &t, &node)?;
                    drop(node);
                    let mut reseal = None;
                    if src.is_ledger()
                        && !stale_hashes
                        && oracle::check(&src.xdr_type, &bytes).accepts
                    {
                        let orig = oracle::decode_ledger(&src_bytes, gate)?;
                        let mut lcm = oracle::decode_ledger(&bytes, gate)?;
                        reseal = Some(oracle::reseal(&mut lcm, &orig, &src.passphrase)?);
                        bytes = oracle::encode_ledger(lcm)?;
                    }
                    Ok(Some((bytes, applied, reseal)))
                }
                Class::Metamorphic => {
                    if !src.is_ledger() {
                        return Ok(None);
                    }
                    let mut lcm = oracle::decode_ledger(&src_bytes, gate)?;
                    let mut applied = Vec::new();
                    for m in muts {
                        let changed = match m.mutator.as_str() {
                            "change-permute" => {
                                let seed_of =
                                    u64::from_str_radix(&m.id[1..], 16).unwrap_or(0) ^ seed;
                                xdrcheck_meta::permute::permute_operation_changes(&mut lcm, seed_of)
                                    .permuted
                                    > 0
                            }
                            "timing" => {
                                let v = if m.arg == 0 { 0 } else { 0x0123_4567_89ab_cdef };
                                xdrcheck_meta::permute::set_timing(&mut lcm, v) > 0
                            }
                            other => bail!("{other} is not a metamorphic mutator"),
                        };
                        if changed {
                            applied.push(m.clone());
                        }
                    }
                    if applied.is_empty() {
                        return Ok(None);
                    }
                    Ok(Some((oracle::encode_ledger(lcm)?, applied, None)))
                }
                Class::Wire => {
                    let node = tree::decode(s, &t, &src_bytes)?;
                    let mut bytes = src_bytes.clone();
                    let mut applied = Vec::new();
                    for m in muts {
                        if mutate::apply_wire(&mut bytes, m, s, &t, &node)? {
                            applied.push(m.clone());
                        }
                    }
                    drop(node);
                    if applied.is_empty() || bytes == src_bytes {
                        return Ok(None);
                    }
                    Ok(Some((bytes, applied, None)))
                }
            }
        })?;
    let Some((bytes, applied, reseal)) = built else {
        return Ok(None);
    };
    if src.is_ledger() && class == Class::Valid && stale_hashes {
        notes.push("dependent hashes left stale".into());
    }
    let verdict = oracle::check(&src.xdr_type, &bytes);
    let mut rule = applied
        .iter()
        .find_map(mutate::protocol_rule)
        .map(str::to_string);
    if rule.is_none() && class == Class::Valid && verdict.accepts && src.is_ledger() {
        rule = ledger_rule(src, &bytes, gate)?;
    }
    Ok(Some(Mutant {
        id: mutant_id(src, seed, &applied),
        source: src.id.clone(),
        entry: src.entry.clone(),
        variant: src.variant,
        seed,
        class,
        xdr_type: src.xdr_type.clone(),
        sha256: xdrcheck_xdr::sha256_hex(&bytes),
        bytes,
        protocol_rule: rule,
        mutations: applied,
        oracle: verdict,
        reseal,
        stale_hashes: stale_hashes && class == Class::Valid && src.is_ledger(),
        notes,
    }))
}

/// The cross-structure rule a mutated ledger breaks that its source keeps ([`oracle::consistency`]).
fn ledger_rule(src: &Source, bytes: &[u8], gate: &Gate) -> Result<Option<String>> {
    xdrcheck_xdr::with_stack(Limits::default().stack_size, || {
        let m = oracle::decode_ledger(bytes, gate)?;
        let Some(r) = oracle::consistency(&m, &src.passphrase) else {
            return Ok(None);
        };
        let o = oracle::decode_ledger(&src.bytes, gate)?;
        Ok(oracle::consistency(&o, &src.passphrase)
            .is_none()
            .then(|| r.to_string()))
    })
}

/// Options for a plan.
#[derive(Debug, Clone)]
pub struct PlanOpts {
    pub seed: u64,
    pub budget: usize,
    pub classes: Vec<Class>,
    /// Mutator IDs; empty means every mutator of the classes.
    pub mutators: Vec<String>,
    /// Most valid-preserving mutations stacked in one mutant.
    pub max_stack: usize,
    pub stale_hashes: bool,
}

impl Default for PlanOpts {
    fn default() -> Self {
        PlanOpts {
            seed: 1,
            budget: 200,
            classes: vec![Class::Valid, Class::Metamorphic, Class::Wire],
            mutators: Vec::new(),
            max_stack: 3,
            stale_hashes: false,
        }
    }
}

/// The plan: `budget` mutants spread round-robin over the sources, each source's share built from
/// its candidates with a generator seeded by (seed, source). Within a source the classes rotate;
/// a mutator is picked uniformly among those with candidates, then a place uniformly.
pub fn plan(
    s: &Schema,
    srcs: &[Source],
    o: &PlanOpts,
    gate: &Gate,
    mut on_mutant: impl FnMut(&Source, Mutant) -> Result<()>,
) -> Result<usize> {
    if srcs.is_empty() || o.budget == 0 {
        return Ok(0);
    }
    let n = srcs.len();
    let mut made = 0;
    for (i, src) in srcs.iter().enumerate() {
        let share = o.budget / n + usize::from(i < o.budget % n);
        if share == 0 {
            continue;
        }
        let cands = candidates(s, src, o.seed, &o.classes)?;
        let mut by: BTreeMap<(Class, &str), Vec<&Mutation>> = BTreeMap::new();
        for c in &cands {
            if o.mutators.is_empty() || o.mutators.iter().any(|m| m == &c.mutator) {
                by.entry((c.class, c.mutator.as_str())).or_default().push(c);
            }
        }
        let classes: Vec<Class> = o
            .classes
            .iter()
            .copied()
            .filter(|c| by.keys().any(|(k, _)| k == c))
            .collect();
        if classes.is_empty() {
            continue;
        }
        let mut rng = xdrcheck_meta::permute::SplitMix(
            o.seed
                ^ u64::from_be_bytes(Sha256::digest(src.id.as_bytes())[..8].try_into().unwrap())
                ^ src.variant as u64,
        );
        let mut seen = BTreeSet::new();
        let mut got = 0;
        let mut tries = 0;
        let mut retry = 0;
        while got < share && tries < share * 8 {
            tries += 1;
            // Classes rotate across sources and within a source's share; a mutant that cannot be
            // built is retried in the same class first.
            let class = classes[(i + got + retry / 3) % classes.len()];
            retry += 1;
            let muts: Vec<&str> = by
                .keys()
                .filter(|(c, _)| *c == class)
                .map(|(_, m)| *m)
                .collect();
            let pick = |rng: &mut xdrcheck_meta::permute::SplitMix| -> Mutation {
                let m = muts[rng.below(muts.len())];
                let list = &by[&(class, m)];
                list[rng.below(list.len())].clone()
            };
            let mut chosen = vec![pick(&mut rng)];
            if class == Class::Valid && o.max_stack > 1 {
                let k = rng.below(o.max_stack);
                for _ in 0..k {
                    let m = pick(&mut rng);
                    // One deepening per mutant: two would compound past the nesting stellar-core admits.
                    if m.mutator == "deepen" && chosen.iter().any(|c| c.mutator == "deepen") {
                        continue;
                    }
                    chosen.push(m);
                }
            }
            chosen.dedup_by(|a, b| a.id == b.id);
            let Some(m) = build(s, src, o.seed, &chosen, o.stale_hashes, gate)? else {
                continue;
            };
            if !seen.insert(m.id.clone()) {
                continue;
            }
            retry = 0;
            got += 1;
            made += 1;
            on_mutant(src, m)?;
        }
    }
    Ok(made)
}

/// Find a source by ID (and variant).
pub fn find_source<'a>(srcs: &'a [Source], id: &str, variant: Option<usize>) -> Result<&'a Source> {
    srcs.iter()
        .find(|x| x.id == id && variant.is_none_or(|v| v == x.variant))
        .ok_or_else(|| anyhow!("no source {id}"))
}

/// Rebuild one mutant from its source, seed and mutation IDs (the candidates are listed again
/// and matched by ID).
pub fn rebuild(
    s: &Schema,
    src: &Source,
    seed: u64,
    ids: &[String],
    stale_hashes: bool,
    gate: &Gate,
) -> Result<Mutant> {
    let all = candidates(
        s,
        src,
        seed,
        &[Class::Valid, Class::Metamorphic, Class::Wire],
    )?;
    let mut muts = Vec::new();
    for id in ids {
        let m = all
            .iter()
            .find(|m| &m.id == id)
            .ok_or_else(|| anyhow!("{}: no mutation {id} under seed {seed}", src.id))?;
        muts.push(m.clone());
    }
    build(s, src, seed, &muts, stale_hashes, gate)?
        .ok_or_else(|| anyhow!("{}: the mutations change nothing", src.id))
}

// ----------------------------------------------------------------------------------------------
// The mutant corpus: what the conformance and replay runners read.
// ----------------------------------------------------------------------------------------------

fn blob_rel(sha: &str) -> String {
    format!("blobs/{}/{sha}.xdr", &sha[..2])
}

fn write_blob(root: &Path, bytes: &[u8]) -> Result<(String, String)> {
    let sha = xdrcheck_xdr::sha256_hex(bytes);
    let rel = blob_rel(&sha);
    let p = root.join(&rel);
    if !p.exists() {
        std::fs::create_dir_all(p.parent().unwrap())?;
        std::fs::write(&p, bytes)?;
    }
    Ok((sha, rel))
}

fn levels(entry: &Value, xdr_type: &str) -> Vec<String> {
    let have: Vec<String> = entry["conformance"]["levels"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_else(|| vec!["L0".into()]);
    let mut out = vec!["L0".to_string()];
    if (xdr_type == "LedgerCloseMeta" || xdr_type == "TransactionEnvelope")
        && (have.iter().any(|l| l == "L1") || xdr_type == "TransactionEnvelope")
    {
        out.push("L1".into());
    }
    out
}

/// The facts the oracle and the reference extractor give for a positive mutant (or a source),
/// as the variant's `derived` block and the entry's `expect` block.
fn positive_facts(
    src: &Source,
    bytes: &[u8],
    class: Class,
    gate: &Gate,
) -> Result<(Map<String, Value>, Value, Vec<String>)> {
    let mut derived = Map::new();
    let mut notes = Vec::new();
    let mut expect = json!({});
    let focus_tx = src.variant_json["focus"]["tx_index"].as_u64().unwrap_or(0) as usize;
    if class == Class::Metamorphic {
        // Facts must not change: the original's derived values and expectations stand.
        // Pinpointed values (`expect.values`) are read at level L2, which mutants do not run, and a
        // key-selected one needs a sidecar the mutant corpus does not carry.
        let d = src.variant_json["derived"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        let mut e = src.entry_json["expect"].clone();
        if let Some(o) = e.as_object_mut() {
            o.remove("values");
        }
        return Ok((d, e, notes));
    }
    let limits = Limits::default();
    if src.is_ledger() {
        let r = xdrcheck_xdr::with_stack(limits.stack_size, || -> Result<_> {
            let orig = oracle::decode_ledger(&src.bytes, gate)?;
            let lcm = oracle::decode_ledger(bytes, gate)?;
            let (hashes, header) = oracle::ledger_hashes(&lcm, &orig, &src.passphrase);
            let ex = oracle::expect_facts(&lcm, &src.passphrase, focus_tx);
            // A mutation of the transaction set can leave the processing list pointing at envelopes the
            // set no longer holds; such a ledger has no focus transaction to ask a reader about.
            let n = oracle::envelopes(&lcm).len();
            let focus_ok = n == hashes.len() && focus_tx < n;
            // A ledger whose parts no longer agree has no single right reading: only its XDR is judged.
            let consistent = oracle::consistency(&lcm, &src.passphrase).is_none()
                || oracle::consistency(&orig, &src.passphrase).is_some();
            Ok((hashes, header, ex, focus_ok, consistent))
        })?;
        let (hashes, header, ex, focus_ok, consistent) = r;
        derived.insert("ledger_hash".into(), json!(header));
        if !focus_ok || !consistent {
            derived.insert(NO_FOCUS.into(), json!(true));
        } else if let Some(h) = hashes.get(focus_tx) {
            if src.variant_json["focus"]["tx_index"].is_u64() {
                derived.insert("tx_hash".into(), json!(h));
            }
        }
        let ex = if consistent {
            ex
        } else {
            Err(anyhow!("the ledger's parts no longer agree"))
        };
        if consistent {
            derived.insert("tx_hashes".into(), json!(hashes));
        }
        match ex {
            Ok(ex) => {
                let mut e = Map::new();
                for k in ["ledger", "transactions"] {
                    if !ex[k].is_null() {
                        e.insert(k.into(), ex[k].clone());
                    }
                }
                expect = Value::Object(e);
            }
            Err(err) => notes.push(format!("the reference extractor gives no facts: {err}")),
        }
    } else if src.xdr_type == "TransactionEnvelope" && !src.passphrase.is_empty() {
        let env = xdrcheck_xdr::decode("TransactionEnvelope", bytes, &limits)?;
        if let stellar_xdr::Type::TransactionEnvelope(e) = env {
            if let Ok(h) = e.hash(oracle::network_id(&src.passphrase)) {
                derived.insert("tx_hash".into(), json!(hex::encode(h)));
            }
        }
    }
    let focus = if src.cut_from.is_some() || derived.contains_key(NO_FOCUS) {
        json!({})
    } else {
        src.variant_json["focus"].clone()
    };
    match xdrcheck_meta::derive::l1(&src.xdr_type, bytes, &src.passphrase, &focus, &limits, gate) {
        Ok(l1) if !l1.is_empty() => {
            derived.insert("l1".into(), Value::Object(l1));
        }
        Ok(_) => {}
        Err(e) => notes.push(format!("derived.l1: {e}")),
    }
    Ok((derived, expect, notes))
}

/// The XDR features (`requires`) the unmutated source value uses.
fn source_requires(src: &Source) -> Result<Value> {
    let limits = Limits::default();
    let json = xdrcheck_xdr::xdr_json(&src.xdr_type, &src.bytes, &limits)?;
    Ok(xdrcheck_xdr::with_stack(limits.stack_size, move || {
        let r: Vec<&str> = xdrcheck_meta::derive::requires(&src.xdr_type, &json)
            .into_iter()
            .collect();
        drop(json);
        json!(r)
    }))
}

/// The marker [`positive_facts`] leaves in `derived` for a ledger with no focus transaction left.
const NO_FOCUS: &str = "_no_focus";

fn variant_json(
    src: &Source,
    sha: &str,
    rel: &str,
    n: usize,
    derived: Option<Map<String, Value>>,
    reason: &str,
    focus_hash: Option<&str>,
) -> Value {
    let mut derived = derived;
    let no_focus = derived
        .as_mut()
        .is_some_and(|d| d.remove(NO_FOCUS).is_some());
    let mut v = Map::new();
    v.insert("network".into(), json!(src.network));
    v.insert("passphrase".into(), json!(src.passphrase));
    v.insert("protocol".into(), json!(src.protocol));
    if let Some(seq) = src
        .variant_json
        .get("ledger_seq")
        .filter(|_| src.is_ledger())
    {
        v.insert("ledger_seq".into(), seq.clone());
    }
    v.insert("xdr_type".into(), json!(src.xdr_type));
    v.insert(
        "blob".into(),
        json!({"sha256": sha, "bytes": n, "path": rel}),
    );
    v.insert(
        "source".into(),
        json!({"kind": "synthetic", "recipe": format!("xdrcheck mutate: {}", src.id), "base_entry": src.entry, "reason": reason}),
    );
    if src.cut_from.is_none() {
        if let Some(f) = src
            .variant_json
            .get("focus")
            .and_then(Value::as_object)
            .filter(|_| !no_focus)
        {
            let mut f = f.clone();
            if let Some(h) = focus_hash {
                f.insert("tx_hash".into(), json!(h));
            }
            v.insert("focus".into(), Value::Object(f));
        }
        if let Some(m) = src.variant_json.get("meta") {
            v.insert("meta".into(), m.clone());
        }
    }
    if let Some(d) = derived.filter(|d| !d.is_empty()) {
        v.insert("derived".into(), Value::Object(d));
    }
    Value::Object(v)
}

fn base_entry(
    id: &str,
    src: &Source,
    title: String,
    why: String,
    negative: bool,
) -> Map<String, Value> {
    let mut e = Map::new();
    e.insert("schema".into(), json!("xcc.manifest.entry/v1"));
    e.insert("id".into(), json!(id));
    e.insert("title".into(), json!(title));
    e.insert(
        "kind".into(),
        json!(if src.is_ledger() { "ledger" } else { "xdr" }),
    );
    e.insert("caps".into(), src.entry_json["caps"].clone());
    e.insert("protocol".into(), src.entry_json["protocol"].clone());
    e.insert("synthetic".into(), json!(true));
    if negative {
        e.insert("negative".into(), json!(true));
    }
    // A wire-class mutant's bytes must fail to decode; every other mutant decodes as a valid value.
    e.insert(
        "validity".into(),
        json!(if negative { "malformed" } else { "valid" }),
    );
    e.insert("why".into(), json!(why));
    e
}

/// The manifest entry of a mutant in the mutant corpus (ID `mut/<mutant>`), and its notes.
pub fn mutant_entry(src: &Source, m: &Mutant, root: &Path, gate: &Gate) -> Result<Value> {
    mutant_entry_as(src, m, root, gate, &format!("mut/{}", m.id))
}

/// [`mutant_entry`] under another entry ID.
pub fn mutant_entry_as(
    src: &Source,
    m: &Mutant,
    root: &Path,
    gate: &Gate,
    id: &str,
) -> Result<Value> {
    let (sha, rel) = write_blob(root, &m.bytes)?;
    let id = id.to_string();
    let first = &m.mutations[0];
    let title = format!("{} at {} of {}", first.mutator, first.path, src.id);
    let why = format!(
        "Class-{} mutant of {} (seed {}): {}.",
        m.class.number(),
        src.id,
        m.seed,
        m.mutations
            .iter()
            .map(|x| format!("{}@{}", x.mutator, x.path))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let negative = m.class == Class::Wire;
    let mut e = base_entry(&id, src, title, why, negative);
    let mut notes = m.notes.clone();
    if negative {
        let mut v = variant_json(
            src,
            &sha,
            &rel,
            m.bytes.len(),
            None,
            "wire-invalid mutant",
            None,
        );
        // A wire-invalid mutant has the unmutated value's structure: a column is beyond its reach only
        // when it lacks a feature the source uses, not because of the source's protocol number.
        v["requires"] = source_requires(src)?;
        e.insert("variants".into(), json!([v]));
        e.insert(
            "expect".into(),
            json!({"reject": {"reason": format!("mutation:{}", first.mutator)}}),
        );
        e.insert("conformance".into(), json!({"levels": ["L0"]}));
    } else {
        let (derived, expect, n) = if m.oracle.accepts {
            positive_facts(src, &m.bytes, m.class, gate)?
        } else {
            (
                Map::new(),
                json!({}),
                vec!["the oracle refuses this mutant".to_string()],
            )
        };
        notes.extend(n);
        let focus_hash = derived
            .get("tx_hash")
            .and_then(Value::as_str)
            .map(str::to_string);
        let mut v = variant_json(
            src,
            &sha,
            &rel,
            m.bytes.len(),
            Some(derived),
            "valid-preserving or metamorphic mutant",
            focus_hash.as_deref(),
        );
        // A metamorphic mutant has the source's structure; a valid-preserving one may hold arms of any
        // protocol, so its reach stays the protocol rule.
        if m.class == Class::Metamorphic {
            v["requires"] = source_requires(src)?;
        } else {
            // A sibling arm or kind may be of any protocol the definitions hold: a column whose schema
            // stops below that is judged on what it accepts, and its clean refusal of an arm it lacks is
            // beyond its reach.
            v["protocol"] = json!(src.protocol.max(gate.max_protocol as u64));
        }
        e.insert("variants".into(), json!([v]));
        e.insert("expect".into(), expect);
        e.insert(
            "conformance".into(),
            json!({"levels": levels(&src.entry_json, &src.xdr_type)}),
        );
    }
    if src.is_ledger() {
        let scope = src.entry_json["replay"]["indexer_scope"]
            .as_str()
            .unwrap_or("all");
        e.insert(
            "replay".into(),
            json!({"unit": "single", "indexer_scope": scope, "requires_prior_state": false}),
        );
    }
    if !notes.is_empty() {
        e.insert("notes".into(), json!(notes.join("; ")));
    }
    let v = Value::Object(e);
    let p = root.join("manifest").join(format!("{id}.json"));
    std::fs::create_dir_all(p.parent().unwrap())?;
    std::fs::write(&p, serde_json::to_vec_pretty(&v)?)?;
    Ok(v)
}

/// The control entry of a source (ID `mutctl/<source>/v<variant>`): the unmutated value, judged
/// like its mutants, so a reader that already fails the source is not charged with its mutants.
pub fn control_id(src: &Source) -> String {
    let slug: String = src
        .id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '/') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("mutctl/{}/v{}", slug.trim_matches('/'), src.variant)
}

pub fn control_entry(src: &Source, root: &Path, gate: &Gate, class: Class) -> Result<Value> {
    let (sha, rel) = write_blob(root, &src.bytes)?;
    let id = control_id(src);
    let p = root.join("manifest").join(format!("{id}.json"));
    let mut e = base_entry(
        &id,
        src,
        format!("Unmutated {}", src.id),
        format!("The control of the mutants of {}.", src.id),
        false,
    );
    let (derived, expect, notes) = if class == Class::Metamorphic {
        positive_facts(src, &src.bytes, Class::Metamorphic, gate)?
    } else {
        positive_facts(src, &src.bytes, Class::Valid, gate)?
    };
    let focus_hash = derived
        .get("tx_hash")
        .and_then(Value::as_str)
        .map(str::to_string);
    let v = variant_json(
        src,
        &sha,
        &rel,
        src.bytes.len(),
        Some(derived),
        "unmutated control",
        focus_hash.as_deref(),
    );
    e.insert("variants".into(), json!([v]));
    e.insert("expect".into(), expect);
    e.insert(
        "conformance".into(),
        json!({"levels": levels(&src.entry_json, &src.xdr_type)}),
    );
    if src.is_ledger() {
        let scope = src.entry_json["replay"]["indexer_scope"]
            .as_str()
            .unwrap_or("all");
        e.insert(
            "replay".into(),
            json!({"unit": "single", "indexer_scope": scope, "requires_prior_state": false}),
        );
    }
    if !notes.is_empty() {
        e.insert("notes".into(), json!(notes.join("; ")));
    }
    let v = Value::Object(e);
    std::fs::create_dir_all(p.parent().unwrap())?;
    std::fs::write(&p, serde_json::to_vec_pretty(&v)?)?;
    Ok(v)
}

/// Start a mutant corpus at `root`: its `corpus.json` is the source corpus's.
pub fn init_corpus(source_corpus: &Path, root: &Path) -> Result<()> {
    if root.join("manifest").exists() {
        std::fs::remove_dir_all(root.join("manifest"))?;
    }
    std::fs::create_dir_all(root.join("manifest"))?;
    std::fs::create_dir_all(root.join("blobs"))?;
    let cj = source_corpus.join("corpus.json");
    if cj.exists() {
        std::fs::copy(&cj, root.join("corpus.json"))?;
    }
    Ok(())
}
