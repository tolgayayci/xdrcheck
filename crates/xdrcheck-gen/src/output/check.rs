//! `gen --check`: compare a regeneration with a committed chain.
//!
//! Per ledger of the committed chain index: the regenerated ledger exists and has the same header
//! hash. For every ledger whose committed bytes are available — its blob in the corpus, which every
//! ledger that holds entries must have (a missing one is a difference), or else its record in the
//! chain's vendored meta stream (`chains/<id>.meta.xdr.zst`, checked against the index's sha256) —
//! the same transaction hashes in apply order, the same results, and byte-equal ledgers after
//! stellar-core's golden-comparison normalisation (`xdrcheck_meta::normalise`). Raw bytes are never
//! compared: they are not reproducible (diagnostic timings, change order). The `orders` a chain
//! records (the nonce and shape of each ordered ledger group) must be what the regeneration's search
//! chose.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use serde_json::Value;
use stellar_xdr::{Limits as XdrLimits, WriteXdr};
use xdrcheck_meta::normalise::normalise_ledger;
use xdrcheck_xdr::{Gate, Limits};

use super::chain::{chain_id, ledger_facts, stream_ledgers};
use super::run::RunRecord;
use super::sidecar::read_sidecar;
use super::write::blob_path;

/// What a check found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckOutcome {
    /// The chain checked.
    pub chain: String,
    /// Ledgers whose header hash was compared.
    pub ledgers: usize,
    /// Ledgers also compared by transactions, results and normalised bytes.
    pub blobs: usize,
    /// One line per difference; empty when the regeneration matches.
    pub differences: Vec<String>,
}

impl CheckOutcome {
    pub fn ok(&self) -> bool {
        self.differences.is_empty()
    }
}

/// Compare a regenerated run with the committed chain index `committed` and the corpus blobs.
pub fn check_run(
    corpus: &Path,
    committed: &Value,
    rec: &RunRecord,
    stream: &[u8],
) -> Result<CheckOutcome> {
    let chain = committed["id"].as_str().unwrap_or("?").to_string();
    let mut out = CheckOutcome {
        chain: chain.clone(),
        ..CheckOutcome::default()
    };
    let diff = |out: &mut CheckOutcome, s: String| out.differences.push(format!("{chain}: {s}"));
    if chain_id(rec) != chain {
        diff(&mut out, format!("regenerated chain is {}", chain_id(rec)));
    }
    // Ordered ledger groups: the search must choose the nonce and shape the chain records.
    let committed_orders = committed.get("orders").cloned().unwrap_or(Value::Null);
    let fresh_orders = if rec.orders.is_empty() {
        Value::Null
    } else {
        serde_json::to_value(&rec.orders)?
    };
    if committed_orders != fresh_orders {
        diff(
            &mut out,
            format!(
                "ordered ledger groups: the search chose {fresh_orders}, the chain records \
                 {committed_orders}"
            ),
        );
    }
    let committed_stream = committed_stream(corpus, committed, &mut out.differences)?;
    let fresh = stream_ledgers(stream)?;
    let rows = committed["ledgers"].as_array().cloned().unwrap_or_default();
    if rows.len() != fresh.len() {
        diff(
            &mut out,
            format!(
                "{} ledgers committed, {} regenerated",
                rows.len(),
                fresh.len()
            ),
        );
    }
    for row in &rows {
        let seq = row["seq"].as_u64().unwrap_or(0);
        let Some(l) = fresh.iter().find(|l| u64::from(l.info.sequence) == seq) else {
            diff(&mut out, format!("ledger {seq} was not regenerated"));
            continue;
        };
        out.ledgers += 1;
        let want = row["header_hash"].as_str().unwrap_or("");
        let got = hex::encode(l.info.header_hash);
        if want != got {
            diff(
                &mut out,
                format!(
                    "ledger {seq}: header hash {got}, committed {want} (close time {}, committed {})",
                    l.info.close_time,
                    row["close_time"].as_str().unwrap_or("?")
                ),
            );
        }
        let sha = row["blob_sha256"].as_str().unwrap_or("");
        let path = blob_path(corpus, sha);
        let holds_entries = row["entries"].as_array().is_some_and(|e| !e.is_empty());
        let blob = if path.is_file() {
            std::fs::read(&path)?
        } else if holds_entries {
            diff(
                &mut out,
                format!(
                    "ledger {seq}: blob {sha} of entries {} is not in the corpus",
                    row["entries"]
                ),
            );
            continue;
        } else if let Some(stream) = &committed_stream {
            match stream.get(&seq) {
                Some(bytes) if xdrcheck_xdr::sha256_hex(bytes) == sha => bytes.clone(),
                _ => {
                    diff(
                        &mut out,
                        format!("ledger {seq}: blob {sha} is not in the committed stream"),
                    );
                    continue;
                }
            }
        } else {
            continue;
        };
        out.blobs += 1;
        for d in compare_ledgers(&blob, l.bytes)? {
            diff(&mut out, format!("ledger {seq}: {d}"));
        }
    }
    Ok(out)
}

/// The committed chain's vendored meta stream (`stream.path` under `chains/`), as ledger sequence →
/// bytes, after checking its sha256 against the index. `None` when the index names no vendored
/// stream (the evidence chains); a named stream that is missing or wrong is a difference.
fn committed_stream(
    corpus: &Path,
    committed: &Value,
    differences: &mut Vec<String>,
) -> Result<Option<BTreeMap<u64, Vec<u8>>>> {
    let chain = committed["id"].as_str().unwrap_or("?");
    let Some(rel) = committed["stream"]["path"]
        .as_str()
        .filter(|p| p.starts_with("chains/"))
    else {
        return Ok(None);
    };
    let path = corpus.join(rel);
    if !path.is_file() {
        differences.push(format!("{chain}: the committed stream {rel} is missing"));
        return Ok(None);
    }
    let bytes = read_sidecar(&path)?;
    let want = committed["stream"]["sha256"].as_str().unwrap_or("");
    let got = xdrcheck_xdr::sha256_hex(&bytes);
    if got != want {
        differences.push(format!(
            "{chain}: the committed stream {rel} has sha256 {got}, the index says {want}"
        ));
        return Ok(None);
    }
    Ok(Some(
        stream_ledgers(&bytes)?
            .into_iter()
            .map(|l| (u64::from(l.info.sequence), l.bytes.to_vec()))
            .collect(),
    ))
}

/// Differences between a committed and a regenerated ledger: transaction hashes, results,
/// normalised bytes (with the first differing JSON path).
pub fn compare_ledgers(committed: &[u8], fresh: &[u8]) -> Result<Vec<String>> {
    let mut d = Vec::new();
    let (a, b) = (ledger_facts(committed)?, ledger_facts(fresh)?);
    let hashes = |f: &super::chain::LedgerFacts| -> Vec<String> {
        f.results
            .iter()
            .map(|r| hex::encode(r.transaction_hash.0))
            .collect()
    };
    if hashes(&a) != hashes(&b) {
        d.push(format!(
            "transaction hashes {:?}, committed {:?}",
            hashes(&b),
            hashes(&a)
        ));
    }
    for (i, (x, y)) in a.results.iter().zip(&b.results).enumerate() {
        let (x, y) = (
            x.result.to_xdr(XdrLimits::none())?,
            y.result.to_xdr(XdrLimits::none())?,
        );
        if x != y {
            d.push(format!("transaction {i}: result differs"));
        }
    }
    let limits = Limits::default();
    let gate = Gate::default();
    let (na, _) = normalise_ledger(committed, &limits, &gate)?;
    let (nb, _) = normalise_ledger(fresh, &limits, &gate)?;
    if na != nb {
        let ja = xdrcheck_xdr::json_roundtrip("LedgerCloseMeta", &na, &limits)?;
        let jb = xdrcheck_xdr::json_roundtrip("LedgerCloseMeta", &nb, &limits)?;
        d.push(format!(
            "normalised bytes differ; first difference at {}",
            first_difference(&ja, &jb, String::new())
        ));
    }
    Ok(d)
}

/// JSON Pointer of the first place two values differ.
pub fn first_difference(a: &Value, b: &Value, at: String) -> String {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for (k, v) in x {
                match y.get(k) {
                    Some(w) if w != v => return first_difference(v, w, format!("{at}/{k}")),
                    None => return format!("{at}/{k} (missing in the regeneration)"),
                    _ => {}
                }
            }
            match y.keys().find(|k| !x.contains_key(*k)) {
                Some(k) => format!("{at}/{k} (only in the regeneration)"),
                None => at,
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            for (i, (v, w)) in x.iter().zip(y).enumerate() {
                if v != w {
                    return first_difference(v, w, format!("{at}/{i}"));
                }
            }
            format!("{at} (length {} vs {})", x.len(), y.len())
        }
        _ => format!("{at} ({a} vs {b})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn first_difference_names_the_path() {
        let a = json!({"v2": {"tx": [1, {"fee": 100}], "x": 1}});
        let b = json!({"v2": {"tx": [1, {"fee": 200}], "x": 1}});
        assert_eq!(
            first_difference(&a, &b, String::new()),
            "/v2/tx/1/fee (100 vs 200)"
        );
        let c = json!({"v2": {"tx": [1], "x": 1}});
        assert_eq!(
            first_difference(&a, &c, String::new()),
            "/v2/tx (length 2 vs 1)"
        );
    }
}
