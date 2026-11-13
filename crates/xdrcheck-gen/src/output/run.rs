//! One scenario run on a local stellar-core: bring-up, setup, steps, checks of every result.
//!
//! The run directory ends up holding the node's files, `meta.xdr` (every ledger from 2 on, record
//! marked) and `run.json`, the [`RunRecord`] everything else is derived from.
//!
//! Soroban setup items run through [`crate::soroban`]: `deploy_sac` deploys from root in one ledger
//! ([`crate::soroban::run_deploy_sac`]); `deploy_contract` uploads the wasm (one ledger, skipped when
//! the code is on the ledger) and creates the contract (one ledger) through simulation
//! ([`crate::soroban::contract::run_deploy_contract`]), wasm paths relative to the corpus root. A
//! `simulate: true` step is simulated with the pinned host against the node's state before its
//! ledger ([`crate::soroban::sim::simulate_transaction`]), signed again, then submitted like any
//! other; its step record says `simulated` and `soroban_resources: simulated`.
//!
//! A ledger group whose first step has `order` is built for `${order_nonce}` = 0, 1, 2, … until the
//! model of core's transaction set ([`super::txset`]) applies its transactions in that order; the
//! nonce is recorded in [`RunRecord::orders`]. After the close the real apply order is checked. When
//! it differs, the model's guess of the set's shape was wrong: the shape core built is read from the
//! closed ledger and the whole run starts again from a fresh node with that shape for the group
//! (once per group). The chain index records each nonce and shape (`orders`); the search is
//! deterministic, and `gen --check` reports a different result as a difference.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stellar_xdr::TransactionEnvelope;

use super::results::{inner_code, op_codes, tx_code};
use super::txset::{self, ModelTx, Shape};
use super::Network;
use crate::core::{
    ClosePolicy, ClosedLedger, CoreBinary, Keypair, MetaProfile, Node, NodeOptions, SubmitStatus,
};
use crate::scenario::{BuiltStep, Interpreter, Item, Options, Scenario, SetupAction, Step};
use crate::soroban::sim::{check_applied, simulate_transaction, simulation_seed, Simulated};
use crate::soroban::TxOutcome;

/// `run.json` schema tag.
pub const RUN_SCHEMA: &str = "xcc.gen.run/v1";

/// Inclusion fee of the Soroban setup transactions the runner builds itself (deploys).
const SOROBAN_INCLUSION_FEE: u32 = 100;

/// A scenario result differed from what the scenario declares (a check failure, not a tool
/// failure).
#[derive(Debug)]
pub struct ExpectationFailed(pub String);

impl std::fmt::Display for ExpectationFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ExpectationFailed {}

fn expectation(msg: String) -> anyhow::Error {
    anyhow::Error::new(ExpectationFailed(msg))
}

/// The highest `${order_nonce}` tried before a group's `order` is declared unreachable.
pub const MAX_ORDER_NONCE: u64 = 20_000;

/// A ledger group applied in another order than the model predicted; the run starts again with the
/// shape core built.
#[derive(Debug)]
struct OrderRetry {
    group: String,
    shape: Shape,
    detail: String,
}

impl std::fmt::Display for OrderRetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "step group {}: {}", self.group, self.detail)
    }
}

impl std::error::Error for OrderRetry {}

/// How a ledger group with `order` got its apply order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderRecord {
    /// The `${order_nonce}` chosen.
    pub nonce: u64,
    /// `default` (the model's shape held) or `learned` (read from a first attempt's ledger).
    pub shape: String,
}

/// What to run.
#[derive(Debug, Clone)]
pub struct RunRequest<'a> {
    pub scenario: &'a Scenario,
    /// The scenario file relative to the corpus root (`scenarios/<file>.yaml`).
    pub scenario_path: String,
    /// sha256 of the scenario file.
    pub scenario_sha256: String,
    pub network: Network,
    pub protocol: u32,
    pub profile: MetaProfile,
    /// Required for the `golden-test` profile: `core_tag`, `test_name`, `flags_source`.
    pub golden_test: Option<Value>,
    pub close_policy: ClosePolicy,
    /// Must not exist or be empty.
    pub run_dir: PathBuf,
    /// The corpus root: `contracts.*.wasm` paths are relative to it.
    pub corpus_root: PathBuf,
    /// Record outcomes instead of asserting them: a rejected submission is recorded with its code
    /// whether or not the step declares `expect_submit_reject`, and results that differ from
    /// `expect_result`, `expect_op_results` or the step's simulation are recorded, not failed.
    /// For exploratory runs whose outcome is the thing measured (`xdrcheck-corpus gen-lake`).
    pub explore: bool,
}

/// The stellar-core build a run used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreRecord {
    pub version: String,
    pub commit: String,
    pub package_url: String,
    pub package_sha256: String,
    pub binary_sha256: String,
    pub config_sha256: String,
}

/// One closed ledger of the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerRecord {
    pub seq: u32,
    /// What the ledger did (`protocol 30`, `enable.xdr upload`, `setup[0] fund`, step IDs).
    pub label: String,
    /// The scenario step IDs that produced it, comma-separated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
    /// Entry IDs whose blob this ledger is.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<String>,
}

/// One scenario step that ran.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepRecord {
    pub id: String,
    pub entry: Option<String>,
    /// The ledger the step's transaction (or close) went into; `None` for a rejected submission.
    pub ledger: Option<u32>,
    pub close_time: u64,
    /// Hash of the submitted envelope (the outer hash of a fee bump).
    pub tx_hash: Option<String>,
    pub inner_tx_hash: Option<String>,
    /// The envelope's fee bid (the outer fee of a fee bump).
    pub fee_bid: Option<i64>,
    pub result: Option<String>,
    pub inner_result: Option<String>,
    #[serde(default)]
    pub op_results: Vec<String>,
    pub fee_charged: Option<String>,
    /// The code core rejected the submission with, for `expect_submit_reject` steps.
    pub submit_reject: Option<String>,
    pub soroban: bool,
    pub soroban_resources: Option<String>,
    /// Footprint, resources, resource fee and authorization came from simulation.
    #[serde(default)]
    pub simulated: bool,
    /// `expect_excluded`: submitted and queued, and left out of the ledger as expected.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub excluded: bool,
    /// `expect`, `fields`, `mirrors` with placeholders resolved.
    pub expect: Option<Value>,
    pub fields: Option<Value>,
    pub mirrors: Option<Value>,
}

/// `run.json`: everything about a run that the stream does not say.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunRecord {
    pub schema: String,
    /// Scenario file relative to the corpus root.
    pub scenario: String,
    pub scenario_name: String,
    pub scenario_sha256: String,
    pub network: String,
    pub passphrase: String,
    pub protocol: u32,
    pub profile: String,
    /// Meta flags that were on.
    pub core_meta_flags: Vec<String>,
    pub golden_test: Option<Value>,
    pub core: CoreRecord,
    /// The chain index `settings` object of the bring-up.
    pub settings: Value,
    /// The settings sets applied, as variant `source.inputs[]` (`name`, `sha256`, `origin`).
    pub inputs: Vec<Value>,
    pub close_time_base: u64,
    pub close_time_stride: u64,
    /// Meta stream file name inside the run directory.
    pub stream: String,
    pub ledgers: Vec<LedgerRecord>,
    pub steps: Vec<StepRecord>,
    /// Actor label → `G…` address.
    pub accounts: BTreeMap<String, String>,
    /// Network-dependent contract IDs of the scenario's assets (`sac_<asset>`) and contracts.
    pub contracts: BTreeMap<String, String>,
    /// The network's root account, when the scenario names it (`${acct.root}`, `{key: root}`):
    /// variants then carry it as `derived.accounts.root`. Not part of `accounts`, which twins share.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// Ledger groups with `order`, by first step ID: the nonce chosen.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub orders: BTreeMap<String, OrderRecord>,
}

impl RunRecord {
    pub fn network(&self) -> Result<Network> {
        Network::parse(&self.network)
    }
}

/// Run a scenario. On success the run directory holds `meta.xdr` and `run.json`; on failure it is
/// left as it is for inspection.
pub fn run(binary: &CoreBinary, req: &RunRequest<'_>) -> Result<RunRecord> {
    let mut shapes: BTreeMap<String, Shape> = BTreeMap::new();
    loop {
        match run_attempt(binary, req, &shapes) {
            Err(e) => {
                let Some(retry) = e.downcast_ref::<OrderRetry>() else {
                    return Err(e);
                };
                if shapes.contains_key(&retry.group) {
                    return Err(expectation(format!(
                        "{retry}, again with the shape read from core's ledger (the transaction-set \
                         model is wrong)"
                    )));
                }
                eprintln!("gen: {retry}; running again with the shape core built");
                shapes.insert(retry.group.clone(), retry.shape.clone());
                std::fs::remove_dir_all(&req.run_dir)
                    .with_context(|| format!("removing {}", req.run_dir.display()))?;
            }
            done => return done,
        }
    }
}

fn run_attempt(
    binary: &CoreBinary,
    req: &RunRequest<'_>,
    shapes: &BTreeMap<String, Shape>,
) -> Result<RunRecord> {
    let s = req.scenario;
    let pp = req.network.passphrase();
    if !s.protocols.contains(&req.protocol) {
        bail!(
            "scenario {} does not list protocol {} (it lists {:?})",
            s.name,
            req.protocol,
            s.protocols
        );
    }
    if req.profile.name() == "golden-test" && req.golden_test.is_none() {
        bail!("the golden-test profile needs the golden test (core_tag, test_name, flags_source)");
    }
    let mut options = NodeOptions::new(pp);
    options.profile = req.profile.clone();
    options.close_policy = req.close_policy;
    let mut node = Node::start(binary, &req.run_dir, options)?;
    let bring_up = crate::upgrade::bring_up(&mut node, req.protocol)
        .with_context(|| format!("bring-up to protocol {}", req.protocol))?;
    let mut ledgers: Vec<LedgerRecord> = bring_up
        .ledgers
        .iter()
        .map(|l| LedgerRecord {
            seq: l.ledger.sequence,
            label: l.step.clone(),
            step: None,
            entries: Vec::new(),
        })
        .collect();

    let root = Keypair::root(pp);
    let opts = Options {
        first_ledger: node.last_closed() + 1,
        close_time_base: req.close_policy.base,
        close_time_step: req.close_policy.stride,
        root_sequence: node
            .account_sequence(&root.account_id())?
            .context("the root account does not exist after bring-up")?,
        ..Options::default()
    };
    let mut it = Interpreter::new(s, pp, req.protocol, opts)?;
    let mut steps = Vec::new();
    let mut inputs: Vec<Value> = bring_up
        .settings
        .sets
        .iter()
        .map(
            |set| serde_json::json!({"name": set.file, "sha256": set.sha256, "origin": set.source}),
        )
        .collect();
    for b in s.bring_up.iter().filter(|b| b.runs_at(req.protocol)) {
        let l = bring_up_ledger(&bring_up, &b.ledger)?;
        let at = ledgers
            .iter()
            .position(|r| r.seq == l.sequence)
            .context("bring-up ledger missing")?;
        let e = it
            .resolve_entry(&b.annotation(), l.close_time)
            .map_err(|e| anyhow!("bring_up {}: {e}", b.ledger))?;
        steps.push(entry_step(
            &mut ledgers[at],
            format!("bring-up-{}", b.ledger),
            &e,
            l.close_time,
            None,
        ));
    }

    for (i, item) in s.setup.iter().enumerate() {
        sync(&mut it, &node)?;
        let built = match it.next_item().context("setup item missing")?? {
            Item::Setup(b) => b,
            Item::Step(_) => bail!("expected setup item {i}"),
        };
        let label = format!("setup[{i}] {}", item.kind());
        // The ledger a setup entry is committed as (an index into `ledgers`) and its transaction.
        let mut entry_at: Option<(usize, Option<SetupTx>)> = None;
        match built.action {
            SetupAction::Tx(tx) => {
                let hash = submit_pending(&mut node, &tx.envelope.envelope, &label)?;
                let l = node.close()?;
                let r = l.result_of(&hash)?.ok_or_else(|| {
                    anyhow!("{label}: transaction is not in ledger {}", l.sequence)
                })?;
                if tx_code(&r) != "tx_success" {
                    return Err(expectation(format!(
                        "{label}: {} in ledger {} (setup transactions must succeed): {:?}",
                        tx_code(&r),
                        l.sequence,
                        op_codes(&r)
                    )));
                }
                ledgers.push(ledger_record(&l, label, None, Vec::new()));
                entry_at = Some((
                    ledgers.len() - 1,
                    Some(SetupTx {
                        hash,
                        result: r,
                        fee_bid: Some(envelope_fee(&tx.envelope.envelope)),
                        soroban: matches!(&tx.transaction.ext, stellar_xdr::TransactionExt::V1(_)),
                    }),
                ));
            }
            SetupAction::Close(v) => {
                for k in 0..close_count(&v) {
                    let l = node.close()?;
                    ledgers.push(ledger_record(&l, label.clone(), None, Vec::new()));
                    if k == 0 {
                        entry_at = Some((ledgers.len() - 1, None));
                    }
                }
            }
            SetupAction::ConfigUpgrade {
                changes,
                salt_label,
            } => {
                let set = crate::upgrade::custom_upgrade_set(&mut node, &changes)
                    .with_context(|| label.clone())?;
                let (ls, _) = crate::upgrade::apply_upgrade_set(
                    &mut node,
                    &label,
                    &set,
                    crate::upgrade::upgrade_salt(&salt_label),
                )?;
                for l in ls {
                    ledgers.push(ledger_record(&l.ledger, l.step, None, Vec::new()));
                }
                entry_at = Some((ledgers.len() - 1, None));
                inputs.push(serde_json::json!({
                    "name": format!("{salt_label}.xdr"),
                    "sha256": xdrcheck_xdr::sha256_hex(&set),
                    "origin": format!("ConfigUpgradeSet of the scenario's {label}, from the settings the node held and the fields it changes"),
                }));
            }
            SetupAction::DeploySac { .. } => {
                let (_, out) = crate::soroban::run_deploy_sac(
                    &mut node,
                    &mut it,
                    &built.action,
                    SOROBAN_INCLUSION_FEE,
                )
                .with_context(|| label.clone())?;
                ledgers.push(LedgerRecord {
                    seq: out.ledger,
                    label,
                    step: None,
                    entries: Vec::new(),
                });
                entry_at = Some((ledgers.len() - 1, Some(SetupTx::of(&out))));
            }
            SetupAction::DeployContract { .. } => {
                let (_, outs) = crate::soroban::contract::run_deploy_contract(
                    &mut node,
                    &mut it,
                    &built.action,
                    &req.corpus_root,
                    SOROBAN_INCLUSION_FEE,
                )
                .with_context(|| label.clone())?;
                let parts: &[&str] = if outs.len() == 2 {
                    &["upload", "create"]
                } else {
                    &["create"]
                };
                for (out, part) in outs.iter().zip(parts) {
                    ledgers.push(LedgerRecord {
                        seq: out.ledger,
                        label: format!("{label} {part}"),
                        step: None,
                        entries: Vec::new(),
                    });
                    entry_at = Some((ledgers.len() - 1, Some(SetupTx::of(out))));
                }
            }
        }
        if let (Some(e), Some((at, tx))) = (&built.entry, entry_at) {
            steps.push(entry_step(
                &mut ledgers[at],
                format!("setup-{i}-{}", item.kind().replace('_', "-")),
                e,
                built.close_time,
                tx,
            ));
        }
        refresh_sequences(&mut it, &mut node)?;
    }

    let runnable: Vec<&Step> = s.steps_at(req.protocol).collect();
    let mut orders = BTreeMap::new();
    for group in ledger_groups(&runnable) {
        sync(&mut it, &node)?;
        let (built, sims, plan) = match &group[0].order {
            None => {
                let built = build_group(&mut it, &group)?;
                let (built, sims) = prepare_group(&mut node, &it, &group, built, req.explore)?;
                (built, sims, None)
            }
            Some(order) => {
                let learned = shapes.get(&group[0].id);
                let (built, sims, plan) = search_order(&mut node, &mut it, &group, order, learned)?;
                orders.insert(
                    group[0].id.clone(),
                    OrderRecord {
                        nonce: plan.nonce,
                        shape: if learned.is_some() {
                            "learned"
                        } else {
                            "default"
                        }
                        .into(),
                    },
                );
                (built, sims, Some(plan))
            }
        };
        steps.extend(run_group(
            &mut node,
            &group,
            built,
            sims,
            plan.as_ref(),
            &mut ledgers,
            req.explore,
        )?);
        refresh_sequences(&mut it, &mut node)?;
    }

    let accounts = it.accounts()?;
    let contracts = contracts(&it, s)?;
    let config_sha256 = node.config_sha256().to_string();
    node.stop()?;

    let pins = &binary.pins;
    let record = RunRecord {
        schema: RUN_SCHEMA.into(),
        scenario: req.scenario_path.clone(),
        scenario_name: s.name.clone(),
        scenario_sha256: req.scenario_sha256.clone(),
        network: req.network.name().into(),
        passphrase: pp.into(),
        protocol: req.protocol,
        profile: req.profile.name().into(),
        core_meta_flags: req
            .profile
            .flags()?
            .into_iter()
            .filter(|(_, on)| *on)
            .map(|(f, _)| f)
            .collect(),
        golden_test: req.golden_test.clone(),
        core: CoreRecord {
            version: pins.version.clone(),
            commit: pins.commit.clone(),
            package_url: pins.deb_url.clone(),
            package_sha256: pins.deb_sha256.clone(),
            binary_sha256: pins.binary_sha256.clone(),
            config_sha256,
        },
        settings: serde_json::to_value(bring_up.settings.chain_index())?,
        inputs,
        close_time_base: req.close_policy.base,
        close_time_stride: req.close_policy.stride,
        stream: "meta.xdr".into(),
        ledgers,
        steps,
        accounts,
        contracts,
        root: s.uses_root().then(|| root.address()),
        orders,
    };
    std::fs::write(
        req.run_dir.join("run.json"),
        serde_json::to_vec_pretty(&record)?,
    )?;
    Ok(record)
}

/// The transaction of a setup item whose ledger is an entry.
struct SetupTx {
    hash: [u8; 32],
    result: stellar_xdr::TransactionResult,
    fee_bid: Option<i64>,
    soroban: bool,
}

impl SetupTx {
    fn of(out: &TxOutcome) -> SetupTx {
        SetupTx {
            hash: out.hash,
            result: out.result.clone(),
            fee_bid: None,
            soroban: true,
        }
    }
}

/// Mark a bring-up or setup ledger as entry `e` and return the step record that describes it.
fn entry_step(
    ledger: &mut LedgerRecord,
    id: String,
    e: &crate::scenario::SetupEntry,
    close_time: u64,
    tx: Option<SetupTx>,
) -> StepRecord {
    if !ledger.entries.contains(&e.entry) {
        ledger.entries.push(e.entry.clone());
    }
    ledger.step = Some(match ledger.step.take() {
        Some(s) => format!("{s},{id}"),
        None => id.clone(),
    });
    StepRecord {
        id,
        entry: Some(e.entry.clone()),
        ledger: Some(ledger.seq),
        close_time,
        tx_hash: tx.as_ref().map(|t| hex::encode(t.hash)),
        inner_tx_hash: None,
        fee_bid: tx.as_ref().and_then(|t| t.fee_bid),
        result: tx.as_ref().map(|t| tx_code(&t.result)),
        inner_result: tx.as_ref().and_then(|t| inner_code(&t.result)),
        op_results: tx.as_ref().map(|t| op_codes(&t.result)).unwrap_or_default(),
        fee_charged: tx.as_ref().map(|t| t.result.fee_charged.to_string()),
        submit_reject: None,
        soroban: tx.as_ref().is_some_and(|t| t.soroban),
        soroban_resources: None,
        simulated: false,
        excluded: false,
        expect: e.expect.clone(),
        fields: e.fields.clone(),
        mirrors: None,
    }
}

/// The bring-up ledger named `name` (`upgrade`, `enable-applied`, `settings-applied`).
fn bring_up_ledger<'b>(b: &'b crate::upgrade::BringUp, name: &str) -> Result<&'b ClosedLedger> {
    let label = match name {
        "upgrade" => format!("protocol {}", b.protocol),
        "enable-applied" | "settings-applied" => {
            let set = if name == "enable-applied" {
                b.settings.sets.first()
            } else {
                b.settings.sets.last()
            };
            let set = set.ok_or_else(|| {
                expectation(format!(
                    "bring_up {name}: the bring-up to protocol {} applies no Soroban settings (limit \
                     the item with `protocols`)",
                    b.protocol
                ))
            })?;
            format!("{} arm", set.file)
        }
        other => bail!("unknown bring-up ledger {other}"),
    };
    b.ledgers
        .iter()
        .find(|l| l.step == label)
        .map(|l| &l.ledger)
        .ok_or_else(|| anyhow!("the bring-up has no ledger `{label}`"))
}

/// Tell the interpreter which ledger and close time the node will use next.
fn sync(it: &mut Interpreter<'_>, node: &Node) -> Result<()> {
    it.set_next_ledger(node.last_closed() + 1);
    it.set_next_close_time(node.next_close_time()?);
    Ok(())
}

/// Re-read every existing actor's (and root's) sequence number from the node.
fn refresh_sequences(it: &mut Interpreter<'_>, node: &mut Node) -> Result<()> {
    let labels: Vec<String> = it.keys().labels().map(str::to_string).collect();
    for label in labels {
        let id = Keypair::from_label(&label).account_id();
        if let Some(seq) = node.account_sequence(&id)? {
            it.set_sequence(&label, seq)?;
        }
    }
    let root = Keypair::root(node.passphrase()).account_id();
    if let Some(seq) = node.account_sequence(&root)? {
        it.set_root_sequence(seq);
    }
    Ok(())
}

fn submit_pending(node: &mut Node, env: &TransactionEnvelope, what: &str) -> Result<[u8; 32]> {
    let r = node.submit(env)?;
    if r.status != SubmitStatus::Pending {
        let code = r.error.as_ref().map(tx_code);
        return Err(expectation(format!(
            "{what}: submission {:?} {}",
            r.status,
            code.unwrap_or_default()
        )));
    }
    Ok(r.hash)
}

fn ledger_record(
    l: &ClosedLedger,
    label: String,
    step: Option<String>,
    entries: Vec<String>,
) -> LedgerRecord {
    LedgerRecord {
        seq: l.sequence,
        label,
        step,
        entries,
    }
}

fn close_count(close: &Value) -> u32 {
    close
        .get("ledgers")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(1)
        .max(1)
}

/// Steps in ledger groups: a step joins the current group when its `same_ledger_as` names a step of
/// that group.
pub fn ledger_groups<'s>(steps: &[&'s Step]) -> Vec<Vec<&'s Step>> {
    let mut groups: Vec<Vec<&Step>> = Vec::new();
    for s in steps {
        let joins = match (&s.same_ledger_as, groups.last()) {
            (Some(other), Some(g)) => g.iter().any(|x| &x.id == other),
            _ => false,
        };
        if joins {
            groups.last_mut().expect("checked").push(s);
        } else {
            groups.push(vec![s]);
        }
    }
    groups
}

/// Build the steps of one ledger group with the interpreter.
fn build_group(it: &mut Interpreter<'_>, group: &[&Step]) -> Result<Vec<BuiltStep>> {
    let mut built: Vec<BuiltStep> = Vec::new();
    for want in group {
        match it.next_item().context("step missing")?? {
            Item::Step(b) if b.id == want.id => built.push(*b),
            other => bail!(
                "interpreter out of step with the scenario at {}: {other:?}",
                want.id
            ),
        }
    }
    Ok(built)
}

/// The apply order a ledger group must get, and what the search chose.
#[derive(Debug, Clone)]
struct OrderPlan {
    group: String,
    nonce: u64,
    /// The group's applied transactions as the model saw them, in group order.
    txs: Vec<ModelTx>,
    /// Step index (in the group) of each model transaction.
    step_of: Vec<usize>,
    /// Model transactions in the wanted apply order.
    wanted: Vec<usize>,
    /// The set hash the model predicted.
    set_hash: [u8; 32],
}

/// The steps of a group whose transactions core applies (submitted and not refused).
fn applied_steps(group: &[&Step], built: &[BuiltStep]) -> Vec<usize> {
    (0..group.len())
        .filter(|i| {
            built[*i].tx.is_some()
                && group[*i].expect_submit_reject.is_none()
                && !group[*i].expect_excluded
        })
        .collect()
}

/// Build the group for `${order_nonce}` = 0, 1, … until the model applies its transactions in the
/// order the group's first step declares.
fn search_order(
    node: &mut Node,
    it: &mut Interpreter<'_>,
    group: &[&Step],
    order: &[String],
    learned: Option<&Shape>,
) -> Result<(Vec<BuiltStep>, Vec<Option<Simulated>>, OrderPlan)> {
    let leader = &group[0].id;
    let stream = std::fs::read(node.meta_path())?;
    let last = super::chain::stream_ledgers(&stream)?
        .pop()
        .context("the meta stream is empty")?;
    let previous = last.info.header_hash;
    let base_fee = i64::from(
        super::chain::ledger_facts(last.bytes)?
            .header
            .header
            .base_fee,
    );
    let base = it.clone();
    let mut first: Option<Vec<[u8; 32]>> = None;
    for nonce in 0..=MAX_ORDER_NONCE {
        let mut trial = base.clone();
        trial.set_order_nonce(nonce);
        let built = build_group(&mut trial, group)?;
        let (built, sims) = prepare_group(node, &trial, group, built, false)?;
        let applied = applied_steps(group, &built);
        let ids: Vec<&str> = applied.iter().map(|i| group[*i].id.as_str()).collect();
        let mut listed: Vec<&str> = order.iter().map(String::as_str).collect();
        let mut have = ids.clone();
        listed.sort_unstable();
        have.sort_unstable();
        if listed != have {
            bail!(
                "step group {leader}: `order` lists {order:?}; the transactions applied in its \
                 ledger at protocol {} are {ids:?}",
                trial.protocol()
            );
        }
        let txs = applied
            .iter()
            .map(|i| {
                ModelTx::new(
                    built[*i]
                        .tx
                        .as_ref()
                        .expect("applied")
                        .envelope
                        .envelope
                        .clone(),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let hashes: Vec<[u8; 32]> = txs.iter().map(|t| t.full_hash).collect();
        match &first {
            None => first = Some(hashes),
            Some(h) if *h == hashes => bail!(
                "step group {leader}: no transaction template of the group uses ${{order_nonce}}, so \
                 the search cannot change the order"
            ),
            Some(_) => {}
        }
        let shape = match learned {
            Some(s) => s.clone(),
            None => txset::default_shape(trial.protocol(), base_fee, &txs),
        };
        let pred = txset::predict(&shape, &txs, previous)?;
        txset::check_complete(&pred, txs.len())?;
        let wanted: Vec<usize> = order
            .iter()
            .map(|id| ids.iter().position(|x| x == id).expect("checked"))
            .collect();
        if pred.order == wanted {
            *it = trial;
            return Ok((
                built,
                sims,
                OrderPlan {
                    group: leader.clone(),
                    nonce,
                    txs,
                    step_of: applied,
                    wanted,
                    set_hash: pred.set_hash,
                },
            ));
        }
    }
    Err(expectation(format!(
        "step group {leader}: no ${{order_nonce}} up to {MAX_ORDER_NONCE} applies the transactions \
         in the order {order:?} (does a template use ${{order_nonce}}? transactions of one source \
         account apply in sequence-number order, classic ones before Soroban ones)"
    )))
}

/// Simulate the group's `simulate: true` steps against the state before its ledger and sign them
/// again.
fn prepare_group(
    node: &mut Node,
    it: &Interpreter<'_>,
    group: &[&Step],
    mut built: Vec<BuiltStep>,
    explore: bool,
) -> Result<(Vec<BuiltStep>, Vec<Option<Simulated>>)> {
    let mut sims: Vec<Option<Simulated>> = vec![None; built.len()];
    for (i, (step, b)) in group.iter().zip(built.iter_mut()).enumerate() {
        if !b.simulate {
            continue;
        }
        let draft =
            b.tx.as_ref()
                .with_context(|| format!("step {}: `simulate` without a transaction", b.id))?;
        let seed = simulation_seed(&format!("{}/{}", it.scenario().name, b.id));
        let (tx, sim) = match simulate_transaction(node, &draft.transaction, seed) {
            Ok(r) => r,
            Err(e) if explore => {
                b.sim_error = Some(format!("{e:#}"));
                b.tx = None;
                continue;
            }
            Err(e) => return Err(e.context(format!("step {}: simulation", b.id))),
        };
        sims[i] = Some(sim);
        b.tx = Some(
            it.sign_step(step, tx, b.close_time)
                .map_err(|e| anyhow!("step {}: signing the simulated transaction: {e}", b.id))?,
        );
        b.soroban_resources = Some("simulated".into());
    }
    Ok((built, sims))
}

/// Submit, close and check one ledger group (built and, for `simulate: true` steps, simulated by
/// [`prepare_group`]). With an order plan, the applied order is checked against it.
fn run_group(
    node: &mut Node,
    group: &[&Step],
    built: Vec<BuiltStep>,
    sims: Vec<Option<Simulated>>,
    plan: Option<&OrderPlan>,
    ledgers: &mut Vec<LedgerRecord>,
    explore: bool,
) -> Result<Vec<StepRecord>> {
    let built = built.as_slice();
    // Distinct fees within a ledger: ties are broken by pointer address in release builds.
    let mut fees = BTreeMap::new();
    for b in built.iter().filter(|b| b.expected.submit_reject.is_none()) {
        if let Some(tx) = &b.tx {
            let fee = envelope_fee(&tx.envelope.envelope);
            if let Some(other) = fees.insert(fee, b.id.clone()) {
                bail!(
                    "steps {other} and {} share ledger and fee {fee}; give each transaction in a \
                     ledger a distinct fee",
                    b.id
                );
            }
        }
    }
    let mut records: Vec<StepRecord> = Vec::new();
    let mut upgrades: Vec<(String, String)> = Vec::new();
    let mut closes = 1;
    let mut pending: Vec<(usize, [u8; 32])> = Vec::new();
    for (i, (step, b)) in group.iter().zip(built).enumerate() {
        let mut rec = StepRecord {
            id: b.id.clone(),
            entry: b.entry.clone(),
            ledger: None,
            close_time: b.close_time,
            tx_hash: None,
            inner_tx_hash: None,
            fee_bid: None,
            result: None,
            inner_result: None,
            op_results: Vec::new(),
            fee_charged: None,
            submit_reject: None,
            soroban: false,
            soroban_resources: b.soroban_resources.clone(),
            simulated: b.simulate,
            excluded: false,
            expect: b.expect.clone(),
            fields: b.fields.clone(),
            mirrors: b.mirrors.clone(),
        };
        if let Some(e) = &b.sim_error {
            rec.submit_reject = Some(format!("simulation: {e}"));
        }
        if let Some(u) = &b.upgrade {
            for (k, v) in u.as_object().into_iter().flatten() {
                let v = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                upgrades.push((k.clone(), v));
            }
        }
        if let Some(c) = &b.close {
            closes = closes.max(close_count(c));
        }
        if let Some(tx) = &b.tx {
            let env = &tx.envelope.envelope;
            rec.tx_hash = Some(hex::encode(tx.hash()));
            rec.inner_tx_hash = tx.inner_hash().map(hex::encode);
            rec.fee_bid = Some(envelope_fee(env));
            rec.soroban = matches!(&tx.transaction.ext, stellar_xdr::TransactionExt::V1(_));
            let reply = node.submit(env)?;
            if explore && step.expect_submit_reject.is_none() {
                match &reply.status {
                    SubmitStatus::Pending => pending.push((i, tx.hash())),
                    status => {
                        rec.submit_reject = Some(match reply.error.as_ref() {
                            Some(r) if !op_codes(r).is_empty() => {
                                format!("{}[{}]", tx_code(r), op_codes(r).join(","))
                            }
                            Some(r) => tx_code(r),
                            None => format!("{status:?}"),
                        });
                    }
                }
                records.push(rec);
                continue;
            }
            match (&step.expect_submit_reject, &reply.status) {
                (Some(want), SubmitStatus::Error) => {
                    let got = reply.error.as_ref().map(tx_code).unwrap_or_default();
                    if &got != want {
                        return Err(expectation(format!(
                            "step {}: submission rejected with {got}, the step expects {want}",
                            b.id
                        )));
                    }
                    rec.submit_reject = Some(got);
                }
                (Some(want), status) => {
                    return Err(expectation(format!(
                        "step {}: the step expects the submission to be rejected with {want}; core \
                         answered {status:?}",
                        b.id
                    )))
                }
                (None, SubmitStatus::Pending) => pending.push((i, tx.hash())),
                (None, status) => {
                    return Err(expectation(format!(
                        "step {}: submission {status:?} {}",
                        b.id,
                        reply.error.as_ref().map(tx_code).unwrap_or_default()
                    )))
                }
            }
        }
        records.push(rec);
    }
    let closes_ledger = !pending.is_empty()
        || !upgrades.is_empty()
        || group
            .iter()
            .any(|s| s.close.is_some() || s.upgrade.is_some());
    if !closes_ledger {
        return Ok(records);
    }
    if !upgrades.is_empty() {
        let params: Vec<(&str, String)> = upgrades
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        node.set_upgrades(&params)?;
    }
    let first = node.close()?;
    if let Some(plan) = plan {
        check_order(plan, built, &first)?;
    }
    for (i, hash) in &pending {
        let (step, rec) = (group[*i], &mut records[*i]);
        if step.expect_excluded {
            // Accepted into the queue, left out of the set (surge pricing).
            if let Some(r) = first.result_of(hash)? {
                return Err(expectation(format!(
                    "step {}: the step expects its transaction to be left out of ledger {}; core \
                     applied it ({})",
                    rec.id,
                    first.sequence,
                    tx_code(&r)
                )));
            }
            rec.excluded = true;
            continue;
        }
        let r = first.result_of(hash)?.ok_or_else(|| {
            expectation(format!(
                "step {}: transaction {} is not in ledger {}",
                rec.id,
                hex::encode(hash),
                first.sequence
            ))
        })?;
        rec.result = Some(tx_code(&r));
        rec.inner_result = inner_code(&r);
        rec.op_results = op_codes(&r);
        rec.fee_charged = Some(r.fee_charged.to_string());
        if explore {
            continue;
        }
        if let Some(want) = &step.expect_result {
            if rec.result.as_ref() != Some(want) {
                return Err(expectation(format!(
                    "step {}: result {} (operations {:?}) in ledger {}, the step expects {want}",
                    rec.id,
                    rec.result.as_deref().unwrap_or(""),
                    rec.op_results,
                    first.sequence
                )));
            }
        }
        if !step.expect_op_results.is_empty() && step.expect_op_results != rec.op_results {
            return Err(expectation(format!(
                "step {}: operation results {:?}, the step expects {:?}",
                rec.id, rec.op_results, step.expect_op_results
            )));
        }
        if let (Some(sim), Some("tx_success")) = (&sims[*i], rec.result.as_deref()) {
            let out = TxOutcome::read(&first, hash)?;
            check_applied(sim, &out).map_err(|e| {
                expectation(format!(
                    "step {}: the applied transaction differs from its simulation: {e:#}",
                    rec.id
                ))
            })?;
        }
    }
    let mut entries: Vec<String> = Vec::new();
    let mut ids: Vec<&str> = Vec::new();
    for rec in records.iter_mut().filter(|r| r.submit_reject.is_none()) {
        rec.ledger = Some(first.sequence);
        ids.push(&rec.id);
        if let Some(e) = &rec.entry {
            if !entries.contains(e) {
                entries.push(e.clone());
            }
        }
    }
    let label = ids.join(",");
    ledgers.push(ledger_record(
        &first,
        label.clone(),
        Some(label.clone()),
        entries,
    ));
    for _ in 1..closes {
        let l = node.close()?;
        ledgers.push(ledger_record(
            &l,
            format!("{label} (close)"),
            Some(label.clone()),
            Vec::new(),
        ));
    }
    Ok(records)
}

/// The closed ledger applied the plan's transactions in the wanted order, or the run is retried
/// with the shape core built ([`OrderRetry`]).
fn check_order(plan: &OrderPlan, built: &[BuiltStep], l: &ClosedLedger) -> Result<()> {
    let applied: Vec<[u8; 32]> = l
        .tx_results()?
        .iter()
        .map(|r| r.transaction_hash.0)
        .collect();
    let hash_of = |m: usize| built[plan.step_of[m]].tx.as_ref().expect("applied").hash();
    let mut got: Vec<usize> = (0..plan.txs.len()).collect();
    got.sort_by_key(|m| applied.iter().position(|h| *h == hash_of(*m)));
    if got == plan.wanted {
        return Ok(());
    }
    let lcm = l.decode()?;
    let actual_hash = txset::set_hash_of(&lcm)?;
    let shape = txset::learn_shape(&lcm, &plan.txs)?;
    let short =
        |o: &[usize]| -> Vec<String> { o.iter().map(|m| hex::encode(&hash_of(*m)[..4])).collect() };
    Err(anyhow::Error::new(OrderRetry {
        group: plan.group.clone(),
        shape,
        detail: format!(
            "ledger {} applied {:?}, the order wanted is {:?} (set hash {}, the model predicted {})",
            l.sequence,
            short(&got),
            short(&plan.wanted),
            hex::encode(actual_hash),
            hex::encode(plan.set_hash)
        ),
    }))
}

fn envelope_fee(env: &TransactionEnvelope) -> i64 {
    match env {
        TransactionEnvelope::TxV0(e) => i64::from(e.tx.fee),
        TransactionEnvelope::Tx(e) => i64::from(e.tx.fee),
        TransactionEnvelope::TxFeeBump(e) => e.tx.fee,
    }
}

/// `sac_<asset name, lower case>` for each scenario asset and the ID of each scenario contract the
/// interpreter can name.
fn contracts(it: &Interpreter<'_>, s: &Scenario) -> Result<BTreeMap<String, String>> {
    let resolver = it.resolver(None);
    let mut out = BTreeMap::new();
    for name in s.assets.keys() {
        let v = resolver.value(&crate::scenario::Placeholder::ContractSac(name.clone()))?;
        if let Some(c) = v.as_str() {
            out.insert(format!("sac_{}", name.to_lowercase()), c.to_string());
        }
    }
    for name in s.contracts.keys() {
        if let Ok(id) = resolver.contract_id(name) {
            out.insert(
                name.to_lowercase(),
                format!("{}", stellar_strkey::Contract(id)),
            );
        }
    }
    Ok(out)
}

/// The run directory a gen run uses under `runs`: `<scenario>/p<NN>-<network>[-<profile>]`.
pub fn run_dir_name(scenario: &str, protocol: u32, network: Network, profile: &str) -> PathBuf {
    let mut leaf = format!("p{protocol}-{}", network.name());
    if profile != "lake" {
        leaf.push('-');
        leaf.push_str(profile);
    }
    Path::new(scenario).join(leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_sharing_a_ledger_form_one_group() {
        let step = |id: &str, same: Option<&str>| {
            let mut v = serde_json::json!({"id": id, "close": {}, "entry": "probe/x"});
            if let Some(s) = same {
                v["same_ledger_as"] = s.into();
            }
            serde_json::from_value::<Step>(v).unwrap()
        };
        let steps = [
            step("a", None),
            step("b", Some("a")),
            step("c", Some("a")),
            step("d", None),
            step("e", Some("a")),
        ];
        let refs: Vec<&Step> = steps.iter().collect();
        let groups: Vec<Vec<&str>> = ledger_groups(&refs)
            .iter()
            .map(|g| g.iter().map(|s| s.id.as_str()).collect())
            .collect();
        // `e` names a step of an earlier ledger, so it opens its own.
        assert_eq!(groups, vec![vec!["a", "b", "c"], vec!["d"], vec!["e"]]);
    }

    #[test]
    fn run_directories() {
        assert_eq!(
            run_dir_name("fee-bumps", 28, Network::Pubnet, "lake"),
            Path::new("fee-bumps/p28-pubnet")
        );
        assert_eq!(
            run_dir_name("x", 30, Network::Testnet, "golden-test"),
            Path::new("x/p30-testnet-golden-test")
        );
    }
}
