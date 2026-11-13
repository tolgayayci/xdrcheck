//! `xdrcheck-corpus gen-lake` — run exploratory scenarios on a local stellar-core and write the closed
//! ledgers as a lake (SEP-54 layout, one zstd `LedgerCloseMetaBatch` per ledger) with a
//! `scenario.json` per scenario, for replays through indexers.
//!
//! ```text
//! xdrcheck-corpus gen-lake <scenario>… --out DIR [--network testnet|pubnet|core-test] [--protocol N]
//!                     [--annotations DIR]
//! xdrcheck-corpus gen-lake --stream meta.xdr --name NAME --passphrase P --out DIR [--annotations DIR]
//! ```
//!
//! Unlike `gen`, nothing is written into the corpus and outcomes are recorded, not asserted: a
//! submission core rejects is recorded with its result code, and a transaction core applies with
//! another result than the step expects is recorded with the result it got (`RunRequest::explore`).
//! Each scenario runs once, on one network (testnet by default) and one protocol (the scenario's
//! first unless `--protocol` is given).
//!
//! Output, per scenario `<out>/<scenario>/` (`<out>/<scenario>-p<NN>/` with `--protocol`):
//! - `.config.json` (the datastore manifest a SEP-54 reader expects) and one object per ledger at
//!   its SEP-54 key (`FFFFFFFD--0-63999/FFFFFFFD--2.xdr.zst`, …);
//! - `run/` (the kept run directory: `meta.xdr` as core streamed it, `run.json`, core's log);
//! - `scenario.json`: the network passphrase, the core build, per ledger its header hash, close
//!   time (and the millisecond close time from Protocol 30), `StellarValue` arm and transaction
//!   count, and per step the ledger, apply index, hash and result codes core gave (or the code it
//!   rejected the submission with); the step's `notes` as its property; and, when `--annotations`
//!   holds `<scenario>.json`, that object under `annotations`.
//!
//! Checks before anything is reported as written: every record of the stream decodes and
//! re-encodes byte-exactly with this repository's decoder; every object written is read back,
//! decompressed and decoded, and holds exactly the stream's bytes for its ledger; and
//! `stellar-core dump-xdr` of the stream exits 0 (its record count is recorded).
//!
//! `--stream` exports a meta stream produced elsewhere (for example by a node that closes ledgers
//! by itself) the same way, without a run.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use stellar_xdr::{LedgerCloseMeta, LedgerHeader, TransactionResultPair};
use xdrcheck_gen::core::{ClosePolicy, CoreBinary};
use xdrcheck_gen::output::results::{inner_code, op_codes, tx_code};
use xdrcheck_gen::output::{run as run_scenario, RunRecord, RunRequest};
use xdrcheck_xdr::{Gate, Limits};

use super::gen::{fresh_dir, load, networks, profile_for, protocols, target_role};
use super::intake::lake::object_key;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Scenario files (paths, or relative to the corpus root).
    pub scenarios: Vec<PathBuf>,
    /// Output directory; each scenario writes `<out>/<scenario>/`.
    #[arg(long)]
    pub out: PathBuf,
    /// testnet, pubnet or core-test.
    #[arg(long, default_value = "testnet")]
    pub network: String,
    /// Protocol to run (default: the scenario's first).
    #[arg(long)]
    pub protocol: Option<u32>,
    /// Directory of `<scenario>.json` objects copied into `scenario.json` as `annotations`.
    #[arg(long)]
    pub annotations: Option<PathBuf>,
    /// Export this meta stream instead of running scenarios (needs --name and --passphrase).
    #[arg(long)]
    pub stream: Option<PathBuf>,
    /// Scenario name for --stream.
    #[arg(long)]
    pub name: Option<String>,
    /// Network passphrase of the node that wrote --stream.
    #[arg(long)]
    pub passphrase: Option<String>,
    /// With --stream: a JSON array of the driver's steps (`id`, `property`, `tx_hash`, `submit`:
    /// core's answer to the submission); each is placed by its hash.
    #[arg(long)]
    pub steps: Option<PathBuf>,
}

pub fn run(corpus: &Path, args: Args) -> Result<ExitCode> {
    xdrcheck_xdr::with_stack(xdrcheck_xdr::DEFAULT_STACK_SIZE, || run_on_stack(corpus, args))
}

fn run_on_stack(corpus: &Path, args: Args) -> Result<ExitCode> {
    let binary = CoreBinary::locate()?.ok_or_else(|| {
        anyhow!(
            "no stellar-core binary: run scripts/fetch.d/stellar-core.sh, or set XDRCHECK_STELLAR_CORE"
        )
    })?;
    if let Some(stream) = &args.stream {
        let name = args
            .name
            .clone()
            .ok_or_else(|| anyhow!("--stream needs --name"))?;
        let passphrase = args
            .passphrase
            .clone()
            .ok_or_else(|| anyhow!("--stream needs --passphrase"))?;
        let dir = args.out.join(&name);
        std::fs::create_dir_all(&dir)?;
        let driver_steps: Option<Vec<Value>> = match &args.steps {
            Some(p) => Some(
                serde_json::from_slice(&std::fs::read(p)?)
                    .with_context(|| format!("{} is not a JSON array", p.display()))?,
            ),
            None => None,
        };
        let summary = export(
            &binary,
            &dir,
            stream,
            &passphrase,
            None,
            driver_steps.as_deref(),
            None,
            annotation(&args, &name)?,
            json!({"name": name, "source": "stream", "stream": stream.display().to_string()}),
        )?;
        println!("{name}: {summary}");
        return Ok(ExitCode::SUCCESS);
    }
    if args.scenarios.is_empty() {
        bail!("no scenario given");
    }
    let mut failed = false;
    for path in &args.scenarios {
        let t = load(corpus, path)?;
        if target_role(&t)? != xdrcheck_gen::core::binary::Role::Release {
            bail!("{}: gen-lake runs release-binary scenarios only", t.rel);
        }
        let protocol = match args.protocol {
            Some(p) => protocols(&t.scenario, &[p])?[0],
            None => *t
                .scenario
                .protocols
                .first()
                .ok_or_else(|| anyhow!("{}: no protocol", t.rel))?,
        };
        let network = networks(&t.scenario, &args.network)?[0];
        let (profile, golden) = profile_for(&t.scenario, None)?;
        // With --protocol the directory names the protocol, so one scenario can be written at
        // several protocols side by side.
        let dir = match args.protocol {
            Some(p) => args.out.join(format!("{}-p{p}", t.scenario.name)),
            None => args.out.join(&t.scenario.name),
        };
        fresh_dir(&dir)?;
        std::fs::create_dir_all(&dir)?;
        let run_dir = dir.join("run");
        eprintln!(
            "gen-lake: {} protocol {protocol} {} ...",
            t.rel,
            network.name()
        );
        let req = RunRequest {
            scenario: &t.scenario,
            scenario_path: t.rel.clone(),
            scenario_sha256: t.sha256.clone(),
            network,
            protocol,
            profile,
            golden_test: golden,
            close_policy: ClosePolicy::default(),
            run_dir: run_dir.clone(),
            corpus_root: corpus.to_path_buf(),
            explore: true,
        };
        let rec = match run_scenario(&binary, &req) {
            Ok(rec) => rec,
            Err(e) => {
                eprintln!("FAIL {}: {e:#} (run kept in {})", t.rel, run_dir.display());
                failed = true;
                continue;
            }
        };
        let summary = export(
            &binary,
            &dir,
            &run_dir.join(&rec.stream),
            &rec.passphrase,
            Some(&rec),
            None,
            Some(&t.scenario.document),
            annotation(&args, &t.scenario.name)?,
            json!({"name": t.scenario.name, "source": "scenario", "file": t.rel,
                   "file_sha256": t.sha256, "network": network.name()}),
        )?;
        println!("{}: {summary}", t.scenario.name);
    }
    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn annotation(args: &Args, name: &str) -> Result<Option<Value>> {
    let Some(dir) = &args.annotations else {
        return Ok(None);
    };
    let p = dir.join(format!("{name}.json"));
    if !p.is_file() {
        return Ok(None);
    }
    let v = serde_json::from_slice(&std::fs::read(&p)?)
        .with_context(|| format!("{} is not JSON", p.display()))?;
    Ok(Some(v))
}

/// Header and results of one decoded ledger.
fn parts(lcm: &LedgerCloseMeta) -> (&LedgerHeader, Vec<&TransactionResultPair>, usize) {
    match lcm {
        LedgerCloseMeta::V0(m) => (
            &m.ledger_header.header,
            m.tx_processing.iter().map(|t| &t.result).collect(),
            m.upgrades_processing.len(),
        ),
        LedgerCloseMeta::V1(m) => (
            &m.ledger_header.header,
            m.tx_processing.iter().map(|t| &t.result).collect(),
            m.upgrades_processing.len(),
        ),
        LedgerCloseMeta::V2(m) => (
            &m.ledger_header.header,
            m.tx_processing.iter().map(|t| &t.result).collect(),
            m.upgrades_processing.len(),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn export(
    binary: &CoreBinary,
    dir: &Path,
    stream_path: &Path,
    passphrase: &str,
    rec: Option<&RunRecord>,
    driver_steps: Option<&[Value]>,
    document: Option<&Value>,
    annotations: Option<Value>,
    about: Value,
) -> Result<String> {
    let stream =
        std::fs::read(stream_path).with_context(|| format!("reading {}", stream_path.display()))?;
    let limits = Limits::default();
    let gate = Gate::default();
    let records = xdrcheck_xdr::ledger::split_ledger_stream(&stream, &limits, &gate)
        .with_context(|| format!("{}: the stream does not decode", stream_path.display()))?;
    if records.is_empty() {
        bail!("{}: no ledgers in the stream", stream_path.display());
    }
    // Lake manifest, as the public lakes write it.
    std::fs::write(
        dir.join(".config.json"),
        serde_json::to_string(&json!({
            "networkPassphrase": passphrase,
            "version": "1.0",
            "compression": "zstd",
            "ledgersPerBatch": 1,
            "batchesPerPartition": 64000
        }))?,
    )?;
    let mut ledgers = Vec::new();
    // tx hash -> (ledger, apply index)
    let mut where_applied: BTreeMap<String, (u32, usize)> = BTreeMap::new();
    for (info, bytes) in &records {
        let key = object_key(info.sequence);
        let path = dir.join(&key);
        std::fs::create_dir_all(path.parent().expect("key has a partition"))?;
        let object =
            xdrcheck_xdr::batch::pack_object(&[bytes], &gate, xdrcheck_xdr::batch::DEFAULT_ZSTD_LEVEL)?;
        std::fs::write(&path, &object)?;
        // Read back what was written.
        let back = xdrcheck_xdr::batch::unpack_object(&std::fs::read(&path)?, &limits, &gate)
            .with_context(|| format!("{}: written object does not decode", path.display()))?;
        if back.ledgers.len() != 1
            || back.ledgers[0] != *bytes
            || back.start_sequence != info.sequence
        {
            bail!(
                "{}: object differs from the stream's ledger",
                path.display()
            );
        }
        let lcm = xdrcheck_xdr::ledger::decode_ledger(bytes, &limits, &gate)?;
        let (header, results, upgrades) = parts(&lcm);
        let ext = serde_json::to_value(&header.scp_value.ext)?;
        let (ext_arm, close_time_ms) = match &ext {
            Value::String(s) => (s.clone(), None),
            Value::Object(m) => {
                let (k, v) = m.iter().next().expect("one arm");
                (k.clone(), v.get("close_time_ms").cloned())
            }
            other => (other.to_string(), None),
        };
        let mut txs = Vec::new();
        for (i, r) in results.iter().enumerate() {
            let hash = hex::encode(r.transaction_hash.0);
            where_applied.insert(hash.clone(), (info.sequence, i));
            txs.push(json!({
                "index": i,
                "hash": hash,
                "result": tx_code(&r.result),
                "inner_result": inner_code(&r.result),
                "op_results": op_codes(&r.result),
                "fee_charged": r.result.fee_charged.to_string(),
            }));
        }
        ledgers.push(json!({
            "seq": info.sequence,
            "object": key,
            "object_sha256": xdrcheck_xdr::sha256_hex(&object),
            "header_hash": hex::encode(info.header_hash),
            "protocol": info.protocol,
            "ledger_close_meta": info.ledger_close_meta_version,
            "close_time": info.close_time,
            "stellar_value_ext": ext_arm,
            "close_time_ms": close_time_ms,
            "upgrades": upgrades,
            "transactions": txs,
        }));
    }
    // stellar-core's own decoder over the stream (its file-name rule wants `meta*.xdr`).
    let core_check = core_dump(binary, stream_path)?;
    if core_check["records"].as_u64() != Some(records.len() as u64) {
        bail!(
            "stellar-core dump-xdr printed {} ledgers, the stream holds {}",
            core_check["records"],
            records.len()
        );
    }
    let driver: Vec<Value> = driver_steps
        .unwrap_or_default()
        .iter()
        .map(|s| {
            let hash = s["tx_hash"].as_str().map(str::to_lowercase);
            let applied = hash.as_ref().and_then(|h| where_applied.get(h));
            let r = applied.and_then(|(l, i)| {
                ledgers
                    .iter()
                    .find(|x| x["seq"] == *l)
                    .map(|x| x["transactions"][*i].clone())
            });
            json!({
                "id": s["id"],
                "property": s["property"],
                "ledger": applied.map(|a| a.0),
                "tx_index": applied.map(|a| a.1),
                "tx_hash": hash,
                "result": r.as_ref().map(|r| r["result"].clone()),
                "op_results": r.as_ref().map(|r| r["op_results"].clone()),
                "fee_charged": r.as_ref().map(|r| r["fee_charged"].clone()),
                "core": match (applied, s["submit"].as_str()) {
                    (Some(_), _) => json!({"closed": true, "applied": true, "submit": s["submit"]}),
                    (None, Some("PENDING")) => json!({"closed": false, "submit": "PENDING", "note": "accepted but in no ledger of the stream"}),
                    (None, _) => json!({"closed": false, "rejected_by_core": s["submit"]}),
                },
            })
        })
        .collect();
    let steps: Vec<Value> = rec
        .map(|r| {
            r.steps
                .iter()
                .map(|s| {
                    let applied = s.tx_hash.as_ref().and_then(|h| where_applied.get(h));
                    let notes = document.and_then(|d| step_notes(d, &s.id));
                    json!({
                        "id": s.id,
                        "property": notes,
                        "ledger": s.ledger,
                        "tx_index": applied.map(|a| a.1),
                        "tx_hash": s.tx_hash,
                        "inner_tx_hash": s.inner_tx_hash,
                        "result": s.result,
                        "inner_result": s.inner_result,
                        "op_results": s.op_results,
                        "fee_charged": s.fee_charged,
                        "core": match (&s.submit_reject, &s.result) {
                            (Some(code), _) => match code.strip_prefix("simulation: ") {
                                // The host refused it while simulating; it was never submitted.
                                Some(e) => json!({"closed": false, "submitted": false, "host_simulation_error": e}),
                                None => json!({"closed": false, "rejected_by_core": code}),
                            },
                            (None, Some(_)) => json!({"closed": true, "applied": applied.is_some()}),
                            (None, None) => json!({"closed": s.ledger.is_some()}),
                        },
                        "soroban": s.soroban,
                        "simulated": s.simulated,
                    })
                })
                .collect()
        })
        .unwrap_or(driver);
    let n_ledgers = ledgers.len();
    let rejected = steps
        .iter()
        .filter(|s| s["core"]["rejected_by_core"].is_string())
        .count();
    let unsimulated = steps
        .iter()
        .filter(|s| s["core"]["host_simulation_error"].is_string())
        .count();
    let applied = steps.iter().filter(|s| s["tx_index"].is_number()).count();
    let doc = json!({
        "schema": "xcc.gen-lake/v1",
        "scenario": about,
        "network_passphrase": passphrase,
        "core": rec.map(|r| serde_json::to_value(&r.core).unwrap_or(Value::Null)),
        "protocol": rec.map(|r| r.protocol),
        "meta_flags": rec.map(|r| r.core_meta_flags.clone()),
        "settings": rec.map(|r| r.settings.clone()),
        "close_time_base": rec.map(|r| r.close_time_base),
        "close_time_stride": rec.map(|r| r.close_time_stride),
        "accounts": rec.map(|r| r.accounts.clone()),
        "contracts": rec.map(|r| r.contracts.clone()),
        "root": rec.and_then(|r| r.root.clone()),
        "annotations": annotations,
        "checks": {
            "repo_decoder": format!("{n_ledgers} ledgers decode and re-encode byte-exactly (rs-stellar-xdr); every object read back equal"),
            "stellar_core_dump_xdr": core_check,
        },
        "ledgers": ledgers,
        "steps": steps,
    });
    std::fs::write(
        dir.join("scenario.json"),
        serde_json::to_string_pretty(&doc)? + "\n",
    )?;
    Ok(format!(
        "{n_ledgers} ledgers ({}..{}), {applied} steps applied, {rejected} rejected by core, {unsimulated} refused in simulation -> {}",
        records[0].0.sequence,
        records[records.len() - 1].0.sequence,
        dir.display()
    ))
}

/// The `notes` of step `id` in the scenario document.
fn step_notes(doc: &Value, id: &str) -> Option<Value> {
    doc["steps"]
        .as_array()?
        .iter()
        .find(|s| s["id"] == id)
        .and_then(|s| s.get("notes").cloned())
}

/// Run `stellar-core dump-xdr` over the stream; the record count is the number of
/// `LedgerCloseMeta` values it printed (one `"ledgerHeader"` key each).
fn core_dump(binary: &CoreBinary, stream: &Path) -> Result<Value> {
    let name = stream
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    // dump-xdr picks the type from the file name: `meta…​.xdr` is a LedgerCloseMeta stream.
    let path = if name.starts_with("meta") && name.ends_with(".xdr") {
        stream.to_path_buf()
    } else {
        let p = stream.with_file_name("meta-stream.xdr");
        std::fs::copy(stream, &p)?;
        p
    };
    let out = binary
        .command()
        .arg("dump-xdr")
        .arg("--compact")
        .arg(&path)
        .output()
        .context("running stellar-core dump-xdr")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let records = stdout
        .lines()
        .filter(|l| l.trim_start().starts_with("\"ledgerHeader\""))
        .count();
    if !out.status.success() {
        bail!(
            "stellar-core dump-xdr {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(json!({"exit": 0, "records": records, "stdout_bytes": out.stdout.len()}))
}
