//! `scan cut-slices`: cut transaction slices out of captured ledger entries of an overlay corpus.
//!
//! Per (ledger, apply index) it writes `xdr` entries of types every conformance column decodes:
//! `<group>/s-<seq>-<i>-env` (`TransactionEnvelope`, found in the set by hash), `-res`
//! (`TransactionResultPair`), `-meta` (`TransactionMeta`), and one `LedgerEntryChange` per fee change
//! (`-fee<k>`) and per post-apply fee change (`-postfee<k>`, LCM v2). Each slice is the re-encoding
//! of the sub-value and must occur byte for byte in the parent blob; the first offset is recorded.
//! The output is the same, file for file, as the pilot's Python cutter.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use xdrcheck_xdr::xdr::{
    GeneralizedTransactionSet, LedgerCloseMeta, LedgerEntryChange, Limits as XdrLimits,
    TransactionEnvelope, TransactionPhase, TxSetComponent, WriteXdr,
};
use xdrcheck_xdr::{Gate, Limits};

#[derive(clap::Args, Debug)]
pub struct CutArgs {
    /// Overlay corpus directory (holds manifest/<group>/l-<seq>.json)
    #[arg(long)]
    pub corpus: PathBuf,
    /// Lines `seq<TAB>tx_index` (apply order)
    #[arg(long)]
    pub pairs: PathBuf,
    /// Entry group
    #[arg(long, default_value = "scan")]
    pub group: String,
}

fn envelopes(lcm: &LedgerCloseMeta) -> Vec<(String, &TransactionEnvelope)> {
    let (v, set) = match lcm {
        LedgerCloseMeta::V0(m) => {
            return m
                .tx_set
                .txs
                .iter()
                .enumerate()
                .map(|(k, e)| (format!("/v0/tx_set/txs/{k}"), e))
                .collect();
        }
        LedgerCloseMeta::V1(m) => (1, &m.tx_set),
        LedgerCloseMeta::V2(m) => (2, &m.tx_set),
    };
    let GeneralizedTransactionSet::V1(s) = set;
    let base = format!("/v{v}/tx_set");
    let mut out = Vec::new();
    for (p, ph) in s.phases.iter().enumerate() {
        match ph {
            TransactionPhase::V0(cs) => {
                for (c, comp) in cs.iter().enumerate() {
                    let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) = comp;
                    for (k, e) in comp.txs.iter().enumerate() {
                        out.push((
                            format!("{base}/v1/phases/{p}/v0/{c}/txs_maybe_discounted_fee/txs/{k}"),
                            e,
                        ));
                    }
                }
            }
            TransactionPhase::V1(pp) => {
                for (st, stage) in pp.execution_stages.iter().enumerate() {
                    for (c, cl) in stage.0.iter().enumerate() {
                        for (k, e) in cl.0.iter().enumerate() {
                            out.push((
                                format!("{base}/v1/phases/{p}/v1/execution_stages/{st}/{c}/{k}"),
                                e,
                            ));
                        }
                    }
                }
            }
        }
    }
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        {
            let k = hay[i..hay.len() - needle.len() + 1]
                .iter()
                .position(|&b| b == first)?;
            i += k;
            if &hay[i..i + needle.len()] == needle {
                return Some(i);
            }
            i += 1;
        }
    }
    None
}

fn write_blob(corpus: &Path, raw: &[u8]) -> Result<Value> {
    let sha = hex::encode(Sha256::digest(raw));
    let rel = format!("blobs/{}/{sha}.xdr", &sha[..2]);
    let path = corpus.join(&rel);
    if !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap())?;
        let tmp = path.with_extension("xdr.tmp");
        std::fs::write(&tmp, raw)?;
        std::fs::rename(&tmp, &path)?;
    }
    Ok(json!({"sha256": sha, "bytes": raw.len(), "path": rel}))
}

/// JSON in the layout of Python's `json.dump(…, indent=1)`.
fn dump(v: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let f = serde_json::ser::PrettyFormatter::with_indent(b" ");
    let mut s = serde_json::Serializer::with_formatter(&mut out, f);
    serde::Serialize::serialize(v, &mut s)?;
    Ok(out)
}

/// One cut part of a transaction: its name (`env`, `res`, `meta`, `fee<k>`, `postfee<k>`), XDR type, JSON
/// path in the parent ledger, bytes (the re-encoding of the sub-value) and the first offset at which those
/// bytes occur in the parent ledger's XDR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    pub name: String,
    pub xdr_type: &'static str,
    pub path: String,
    pub bytes: Vec<u8>,
    pub offset: usize,
}

/// The parts of one transaction (apply order index) and its hash.
#[derive(Debug, Clone)]
pub struct TxParts {
    pub hash: [u8; 32],
    pub parts: Vec<Part>,
}

/// Transactions in `lcm` (its `tx_processing`).
pub fn tx_count(lcm: &LedgerCloseMeta) -> usize {
    match lcm {
        LedgerCloseMeta::V0(m) => m.tx_processing.len(),
        LedgerCloseMeta::V1(m) => m.tx_processing.len(),
        LedgerCloseMeta::V2(m) => m.tx_processing.len(),
    }
}

/// Cut the transactions `idxs` (apply order) of `lcm`, decoded from `blob`, into their parts, in the order
/// env, res, meta, fee<k>, postfee<k>. The envelope is found in the transaction set by its hash under
/// `network_id`. Each part's bytes must occur in `blob`, or this fails. An index past the last transaction
/// gives `None`. Must run on a large stack.
pub fn cut_parts(
    lcm: &LedgerCloseMeta,
    blob: &[u8],
    network_id: [u8; 32],
    idxs: &[usize],
) -> Result<Vec<(usize, Option<TxParts>)>> {
    let seq = match lcm {
        LedgerCloseMeta::V0(m) => m.ledger_header.header.ledger_seq,
        LedgerCloseMeta::V1(m) => m.ledger_header.header.ledger_seq,
        LedgerCloseMeta::V2(m) => m.ledger_header.header.ledger_seq,
    };
    let v = lcm.discriminant() as u32;
    struct P<'x> {
        hash: [u8; 32],
        result: Vec<u8>,
        meta: Vec<u8>,
        fee: &'x [LedgerEntryChange],
        post: Option<&'x [LedgerEntryChange]>,
    }
    let enc = |x: &dyn Fn() -> Result<Vec<u8>, xdrcheck_xdr::xdr::Error>| {
        x().map_err(anyhow::Error::from)
    };
    let procs: Vec<P> = match lcm {
        LedgerCloseMeta::V0(m) => m
            .tx_processing
            .iter()
            .map(|t| {
                Ok(P {
                    hash: t.result.transaction_hash.0,
                    result: enc(&|| t.result.to_xdr(XdrLimits::none()))?,
                    meta: enc(&|| t.tx_apply_processing.to_xdr(XdrLimits::none()))?,
                    fee: &t.fee_processing.0,
                    post: None,
                })
            })
            .collect::<Result<_>>()?,
        LedgerCloseMeta::V1(m) => m
            .tx_processing
            .iter()
            .map(|t| {
                Ok(P {
                    hash: t.result.transaction_hash.0,
                    result: enc(&|| t.result.to_xdr(XdrLimits::none()))?,
                    meta: enc(&|| t.tx_apply_processing.to_xdr(XdrLimits::none()))?,
                    fee: &t.fee_processing.0,
                    post: None,
                })
            })
            .collect::<Result<_>>()?,
        LedgerCloseMeta::V2(m) => m
            .tx_processing
            .iter()
            .map(|t| {
                Ok(P {
                    hash: t.result.transaction_hash.0,
                    result: enc(&|| t.result.to_xdr(XdrLimits::none()))?,
                    meta: enc(&|| t.tx_apply_processing.to_xdr(XdrLimits::none()))?,
                    fee: &t.fee_processing.0,
                    post: Some(&t.post_tx_apply_fee_processing.0[..]),
                })
            })
            .collect::<Result<_>>()?,
    };
    let need: std::collections::BTreeSet<[u8; 32]> = idxs
        .iter()
        .filter_map(|&i| procs.get(i).map(|p| p.hash))
        .collect();
    let mut by_hash: BTreeMap<[u8; 32], (String, Vec<u8>)> = BTreeMap::new();
    for (ptr, e) in envelopes(lcm) {
        let h = e.hash(network_id)?;
        if need.contains(&h) {
            by_hash.insert(h, (ptr, e.to_xdr(XdrLimits::none())?));
        }
    }
    let mut out = Vec::new();
    for &i in idxs {
        let Some(t) = procs.get(i) else {
            out.push((i, None));
            continue;
        };
        let tpp = format!("/v{v}/tx_processing/{i}");
        let (eptr, eb) = by_hash
            .get(&t.hash)
            .with_context(|| format!("{seq} {i}: no envelope"))?;
        let mut parts: Vec<(String, &'static str, String, Vec<u8>)> = vec![
            (
                "env".into(),
                "TransactionEnvelope",
                eptr.clone(),
                eb.clone(),
            ),
            (
                "res".into(),
                "TransactionResultPair",
                format!("{tpp}/result"),
                t.result.clone(),
            ),
            (
                "meta".into(),
                "TransactionMeta",
                format!("{tpp}/tx_apply_processing"),
                t.meta.clone(),
            ),
        ];
        for (k, ch) in t.fee.iter().enumerate() {
            parts.push((
                format!("fee{k}"),
                "LedgerEntryChange",
                format!("{tpp}/fee_processing/{k}"),
                ch.to_xdr(XdrLimits::none())?,
            ));
        }
        if let Some(post) = t.post {
            for (k, ch) in post.iter().enumerate() {
                parts.push((
                    format!("postfee{k}"),
                    "LedgerEntryChange",
                    format!("{tpp}/post_tx_apply_fee_processing/{k}"),
                    ch.to_xdr(XdrLimits::none())?,
                ));
            }
        }
        let mut cut = Vec::with_capacity(parts.len());
        for (name, xdr_type, path, bytes) in parts {
            let Some(offset) = find(blob, &bytes) else {
                bail!("{seq} {i} {name}: re-encoding does not occur in the parent blob");
            };
            cut.push(Part {
                name,
                xdr_type,
                path,
                bytes,
                offset,
            });
        }
        out.push((
            i,
            Some(TxParts {
                hash: t.hash,
                parts: cut,
            }),
        ));
    }
    Ok(out)
}

pub fn cut(a: CutArgs) -> Result<()> {
    let mut want: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for l in std::fs::read_to_string(&a.pairs)?.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let mut f = l.split('\t');
        let seq: u32 = f.next().context("seq")?.parse()?;
        let i: usize = f.next().context("tx_index")?.parse()?;
        want.entry(seq).or_default().push(i);
    }
    let (mut written, mut skipped) = (0usize, 0usize);
    let limits = Limits::default();
    let gate = Gate::default().reading_live();
    for (seq, idxs) in &want {
        let parent_id = format!("{}/l-{seq}", a.group);
        let parent: Value = serde_json::from_slice(&std::fs::read(
            a.corpus.join("manifest").join(format!("{parent_id}.json")),
        )?)?;
        let pv = &parent["variants"][0];
        let blob = std::fs::read(
            a.corpus
                .join(pv["blob"]["path"].as_str().context("blob path")?),
        )?;
        let pp = pv["passphrase"].as_str().context("passphrase")?;
        let network_id: [u8; 32] = Sha256::digest(pp.as_bytes()).into();
        let r: Result<(usize, usize)> = xdrcheck_xdr::with_stack(limits.stack_size, || {
            let lcm = xdrcheck_xdr::decode_ledger(&blob, &limits, &gate)?;
            let (mut w, mut sk) = (0usize, 0usize);
            for (i, got) in cut_parts(&lcm, &blob, network_id, idxs)? {
                let Some(tx) = got else {
                    eprintln!("skip {seq} {i}: ledger has {} transactions", tx_count(&lcm));
                    sk += 1;
                    continue;
                };
                for part in tx.parts {
                    let (suffix, typ, ptr, raw, off) =
                        (part.name, part.xdr_type, part.path, part.bytes, part.offset);
                    let eid = format!("{}/s-{seq}-{i}-{suffix}", a.group);
                    let mut var = Map::new();
                    for k in [
                        "network",
                        "passphrase",
                        "protocol",
                        "header_protocol",
                        "ledger_seq",
                    ] {
                        if let Some(x) = pv.get(k) {
                            var.insert(k.into(), x.clone());
                        }
                    }
                    var.insert("xdr_type".into(), json!(typ));
                    var.insert("xdr_definitions".into(), pv["xdr_definitions"].clone());
                    var.insert("blob".into(), write_blob(&a.corpus, &raw)?);
                    var.insert(
                        "slice_of".into(),
                        json!({"entry": parent_id, "path": ptr, "byte_offset": off}),
                    );
                    var.insert("source".into(), pv["source"].clone());
                    if suffix == "env" {
                        var.insert("derived".into(), json!({"tx_hash": hex::encode(tx.hash)}));
                    }
                    let entry = json!({
                        "schema": "xcc.manifest.entry/v1", "id": eid, "title": format!("pubnet {seq} tx {i} {typ}"),
                        "kind": "xdr", "caps": [], "caps_note": "mainnet scan", "protocol": {"introduced": 0},
                        "synthetic": false, "validity": "valid", "why": "mainnet scan transaction slice",
                        "variants": [Value::Object(var)], "expect": {}
                    });
                    let path = a.corpus.join("manifest").join(format!("{eid}.json"));
                    std::fs::create_dir_all(path.parent().unwrap())?;
                    std::fs::write(&path, dump(&entry)?)?;
                    w += 1;
                }
            }
            Ok((w, sk))
        });
        let (w, sk) = r?;
        written += w;
        skipped += sk;
    }
    eprintln!("cut-slices: {written} slice entries written, {skipped} transactions skipped");
    Ok(())
}
