//! Chain indexes (`corpus/schema/chain-index.schema.json`) from a run directory.
//!
//! A chain is one run of one scenario on one passphrase at one target protocol under one flag
//! profile. Its ID is `<scenario>/p<NN>-<network>`, with `-<profile>` appended for any profile other
//! than `lake`; the file is `chains/<ID>.json`. Every ledger of the run is listed (from ledger 2),
//! with its blob hash and header hash; only the ledgers that hold an entry have their blob in the
//! corpus. The rest are served from the run's record-marked meta stream, which the corpus keeps
//! next to the index as `chains/<ID>.meta.xdr.zst` (one zstd frame at level 19 with the content
//! checksum, like sidecars); the index's `stream` names that path, and its `sha256` is of the
//! uncompressed stream.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use stellar_xdr::{
    LedgerCloseMeta, LedgerHeaderHistoryEntry, TransactionMeta, TransactionResultPair,
};
use xdrcheck_xdr::{Gate, Limits};

use super::run::{RunRecord, RUN_SCHEMA};

/// One ledger of a stream with the facts outputs and checks need.
#[derive(Debug, Clone)]
pub struct StreamLedger<'a> {
    pub info: xdrcheck_xdr::LedgerInfo,
    pub bytes: &'a [u8],
    /// Index of the record in the stream.
    pub index: usize,
}

/// Split a run's meta stream into ledgers.
pub fn stream_ledgers(stream: &[u8]) -> Result<Vec<StreamLedger<'_>>> {
    Ok(
        xdrcheck_xdr::split_ledger_stream(stream, &Limits::default(), &Gate::default())?
            .into_iter()
            .enumerate()
            .map(|(index, (info, bytes))| StreamLedger { info, bytes, index })
            .collect(),
    )
}

/// What a decoded ledger says beyond its header summary.
#[derive(Debug, Clone)]
pub struct LedgerFacts {
    pub header: LedgerHeaderHistoryEntry,
    /// Transaction hashes and results in apply order.
    pub results: Vec<TransactionResultPair>,
    /// The `TransactionMeta` arm of the first transaction, if any.
    pub transaction_meta_version: Option<u32>,
}

/// Decode a ledger and collect its [`LedgerFacts`].
pub fn ledger_facts(bytes: &[u8]) -> Result<LedgerFacts> {
    let lcm = xdrcheck_xdr::decode_ledger(bytes, &Limits::default(), &Gate::default())?;
    let (header, procs): (_, Vec<(TransactionResultPair, &TransactionMeta)>) = match &lcm {
        LedgerCloseMeta::V0(m) => (
            m.ledger_header.clone(),
            m.tx_processing
                .iter()
                .map(|t| (t.result.clone(), &t.tx_apply_processing))
                .collect(),
        ),
        LedgerCloseMeta::V1(m) => (
            m.ledger_header.clone(),
            m.tx_processing
                .iter()
                .map(|t| (t.result.clone(), &t.tx_apply_processing))
                .collect(),
        ),
        LedgerCloseMeta::V2(m) => (
            m.ledger_header.clone(),
            m.tx_processing
                .iter()
                .map(|t| (t.result.clone(), &t.tx_apply_processing))
                .collect(),
        ),
    };
    let transaction_meta_version = procs.first().map(|(_, m)| match m {
        TransactionMeta::V0(_) => 0,
        TransactionMeta::V1(_) => 1,
        TransactionMeta::V2(_) => 2,
        TransactionMeta::V3(_) => 3,
        TransactionMeta::V4(_) => 4,
    });
    Ok(LedgerFacts {
        header,
        results: procs.into_iter().map(|(r, _)| r).collect(),
        transaction_meta_version,
    })
}

/// `<scenario>/p<NN>-<network>[-<profile>]`.
pub fn chain_id(rec: &RunRecord) -> String {
    let mut id = format!("{}/p{}-{}", rec.scenario_name, rec.protocol, rec.network);
    if rec.profile != "lake" {
        id.push('-');
        id.push_str(&rec.profile);
    }
    id
}

/// `chains/<chain id>.json`, relative to the corpus root.
pub fn chain_index_path(rec: &RunRecord) -> PathBuf {
    PathBuf::from(format!("chains/{}.json", chain_id(rec)))
}

/// `chains/<chain id>.meta.xdr.zst`, relative to the corpus root: the vendored meta stream.
pub fn chain_stream_path(rec: &RunRecord) -> String {
    format!("chains/{}.meta.xdr.zst", chain_id(rec))
}

/// Write the run's meta stream to the corpus at [`chain_stream_path`], unless the file already holds
/// exactly this stream. Returns the path relative to the corpus root.
pub fn write_chain_stream(corpus: &Path, rec: &RunRecord, stream: &[u8]) -> Result<String> {
    let rel = chain_stream_path(rec);
    super::sidecar::write_sidecar(corpus, &rel, stream)?;
    Ok(rel)
}

/// The vendored meta stream of a committed chain index (uncompressed), when the index names one
/// under `chains/`, the file is there and it has the index's sha256; `None` otherwise.
pub fn vendored_stream(corpus: &Path, index: &Value) -> Result<Option<Vec<u8>>> {
    let Some(rel) = index["stream"]["path"]
        .as_str()
        .filter(|p| p.starts_with("chains/"))
    else {
        return Ok(None);
    };
    let path = corpus.join(rel);
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = super::sidecar::read_sidecar(&path)?;
    Ok(
        (Some(xdrcheck_xdr::sha256_hex(&bytes).as_str()) == index["stream"]["sha256"].as_str())
            .then_some(bytes),
    )
}

/// Read `run.json` and the meta stream of a kept run.
pub fn read_run_dir(run_dir: &Path) -> Result<(RunRecord, Vec<u8>)> {
    let path = run_dir.join("run.json");
    let rec: RunRecord = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("{} is not a generator run record", path.display()))?;
    if rec.schema != RUN_SCHEMA {
        bail!(
            "{}: schema {:?}, expected {RUN_SCHEMA}",
            path.display(),
            rec.schema
        );
    }
    let stream_path = run_dir.join(&rec.stream);
    let stream = std::fs::read(&stream_path)
        .with_context(|| format!("reading {}", stream_path.display()))?;
    Ok((rec, stream))
}

/// The chain index of a run.
pub fn chain_index(rec: &RunRecord, stream: &[u8]) -> Result<Value> {
    let ledgers = stream_ledgers(stream)?;
    if ledgers.len() != rec.ledgers.len() {
        bail!(
            "the meta stream holds {} ledgers, the run record {}",
            ledgers.len(),
            rec.ledgers.len()
        );
    }
    let mut rows = Vec::new();
    for (l, r) in ledgers.iter().zip(&rec.ledgers) {
        if l.info.sequence != r.seq {
            bail!(
                "stream record {} is ledger {}, the run record says {}",
                l.index,
                l.info.sequence,
                r.seq
            );
        }
        let facts = ledger_facts(l.bytes)?;
        let mut row = Map::new();
        row.insert("seq".into(), json!(r.seq));
        row.insert("blob_sha256".into(), json!(xdrcheck_xdr::sha256_hex(l.bytes)));
        row.insert("bytes".into(), json!(l.bytes.len()));
        row.insert("header_hash".into(), json!(hex::encode(l.info.header_hash)));
        row.insert(
            "previous_header_hash".into(),
            json!(hex::encode(facts.header.header.previous_ledger_hash.0)),
        );
        row.insert("close_time".into(), json!(l.info.close_time.to_string()));
        row.insert(
            "ledger_close_meta_version".into(),
            json!(l.info.ledger_close_meta_version),
        );
        if let Some(step) = &r.step {
            row.insert("step".into(), json!(step));
        }
        if !r.entries.is_empty() {
            row.insert("entries".into(), json!(r.entries));
        }
        rows.push(Value::Object(row));
    }
    let mut core = json!({
        "version": rec.core.version,
        "commit": rec.core.commit,
        "binary_sha256": rec.core.binary_sha256,
        "package": {"url": rec.core.package_url, "sha256": rec.core.package_sha256},
        "config_sha256": rec.core.config_sha256,
    });
    if rec.core.package_url.is_empty() {
        core.as_object_mut().expect("object").remove("package");
    }
    let mut index = json!({
        "schema": "xcc.chain.index/v1",
        "id": chain_id(rec),
        "scenario": rec.scenario,
        "scenario_sha256": rec.scenario_sha256,
        "network": rec.network,
        "passphrase": rec.passphrase,
        "protocol": rec.protocol,
        "profile": rec.profile,
        "core_meta_flags": rec.core_meta_flags,
        "core": core,
        "settings": rec.settings,
        "stream": {
            "path": chain_stream_path(rec),
            "sha256": xdrcheck_xdr::sha256_hex(stream),
            "records": ledgers.len(),
        },
        "first_ledger": rec.ledgers.first().map(|l| l.seq),
        "last_ledger": rec.ledgers.last().map(|l| l.seq),
        "ledgers": rows,
        "regenerate": regenerate_command(rec),
        "reproducibility": "normalised-identical",
    });
    if let Some(g) = &rec.golden_test {
        index["golden_test"] = g.clone();
    }
    // The nonce each ordered ledger group's search chose; `gen --check` compares it.
    if !rec.orders.is_empty() {
        index["orders"] = serde_json::to_value(&rec.orders)?;
    }
    Ok(index)
}

/// The command that regenerates (and checks) a run.
pub fn regenerate_command(rec: &RunRecord) -> String {
    let mut cmd = format!(
        "xdrcheck-corpus gen {} --network {} --protocol {}",
        rec.scenario, rec.network, rec.protocol
    );
    if rec.profile != "lake" {
        cmd.push_str(&format!(" --profile {}", rec.profile));
    }
    cmd
}
