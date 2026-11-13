//! Walking a scenario: setup items, then the steps that run at the chosen protocol.
//!
//! [`Interpreter`] keeps the state a run needs between items and lets the node side correct it:
//!
//! - **Sequence numbers.** An actor funded by a `fund` item starts at `ledger << 32` (core's
//!   `getStartingSequenceNumber`) for the ledger the interpreter planned for that item, unless a
//!   value was injected ([`Options::sequences`], [`Interpreter::set_sequence`]); injected values
//!   win. Root starts at [`Options::root_sequence`]. After each transaction the source account's
//!   sequence becomes the transaction's `seq_num` — except when the step declares
//!   `expect_submit_reject` or a result that core reports before consuming the sequence number
//!   (`tx_too_early`, `tx_too_late`; field VF-04).
//! - **Ledgers and close times.** Every setup item and every step takes one ledger (a `close`
//!   with `ledgers: n` takes n), starting at [`Options::first_ledger`] (13: after the protocol
//!   upgrade at ledger 2 and the two Soroban settings upgrades in ledgers 3–12); a
//!   `same_ledger_as` step shares its ledger. Ledger n closes at
//!   `close_time_base + (n − 2) · close_time_step` unless the node side overrides it
//!   ([`Interpreter::set_next_ledger`], [`Interpreter::set_next_close_time`]).
//! - **Derived values and contract IDs** for `${derived.…}` and `${contract.id(…)}`.
//! - **Transaction hashes per step** for `${signer.pre_auth_tx(STEP)}`. A reference to a later
//!   step is resolved by building ahead to it on a copy of the interpreter; when that step is then
//!   really built its hash must be the predicted one.
//! - **Deploys.** A `deploy_contract` item plans two ledgers (upload, create) the first time its
//!   wasm appears in the scenario and one ledger after that (the code is already on the ledger);
//!   its constructor arguments are resolved and parsed as `ScVal`s here. The node side executes it.
//! - **Simulated steps** (`simulate: true`): the template's `ext` defaults to `v0` and its
//!   `invoke_host_function.auth` to `[]`; the step is built and signed like any other, and the node
//!   side replaces `ext`, the authorization and the fee from a simulation and signs again with
//!   [`Interpreter::sign_step`].
//!
//! Templates are parsed as SEP-51 JSON of `Transaction`. The library's serde silently ignores
//! unknown fields, so after parsing the transaction is rendered back to JSON and every field of
//! the resolved template must still be there with the same value; a misspelt field is an error,
//! not a dropped operation.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};
use stellar_xdr::{
    FeeBumpTransaction, FeeBumpTransactionExt, FeeBumpTransactionInnerTx, MuxedAccount, ScVal,
    Transaction, TransactionEnvelope, Type,
};

use super::envelope::{
    envelope_v1, sign_envelope, sign_fee_bump, sign_hash_with, transaction_hash, BuiltTx,
};
use super::file::{parse_amount, Scenario, SetupEntry, SetupItem, SignerSpec, Step};
use super::ids::contract_salt;
use super::keys::{account_strkey, hash_x_preimage, network_id, Keys, NAMESPACE};
use super::placeholder::{pre_auth_steps, Resolver};
use super::{Error, Result};

/// First ledger after the bring-up (upgrade at 2, settings upgrades at 3–12).
pub const DEFAULT_FIRST_LEDGER: u32 = 13;
/// Close time of ledger 2 (`T0`).
pub const DEFAULT_CLOSE_TIME_BASE: u64 = 1_700_000_000;
/// Close time step per ledger (`Δ`).
pub const DEFAULT_CLOSE_TIME_STEP: u64 = 1_000_000;

const MAX_LIMIT: &str = "9223372036854775807";

/// Inputs the node side may inject.
#[derive(Debug, Clone)]
pub struct Options {
    /// Namespace of label-derived seeds and salts ([`NAMESPACE`]).
    pub namespace: String,
    pub first_ledger: u32,
    pub close_time_base: u64,
    pub close_time_step: u64,
    /// Root's sequence number before the first setup transaction (0 on a fresh genesis; the
    /// node side passes the value after its own bring-up transactions).
    pub root_sequence: i64,
    /// Starting sequence numbers per actor; these win over values implied by `fund`.
    pub sequences: BTreeMap<String, i64>,
    /// Contract IDs per `contracts` name, for `${contract.id(NAME)}`.
    pub contract_ids: BTreeMap<String, [u8; 32]>,
    /// Values for `${derived.NAME}`.
    pub derived: Map<String, Value>,
    /// Per-operation fee of the transactions the interpreter writes itself (fund, trust, pay).
    pub setup_fee_per_op: u32,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            namespace: NAMESPACE.to_string(),
            first_ledger: DEFAULT_FIRST_LEDGER,
            close_time_base: DEFAULT_CLOSE_TIME_BASE,
            close_time_step: DEFAULT_CLOSE_TIME_STEP,
            root_sequence: 0,
            sequences: BTreeMap::new(),
            contract_ids: BTreeMap::new(),
            derived: Map::new(),
            setup_fee_per_op: 100,
        }
    }
}

/// The expected outcome a step declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expected {
    /// `expect_result`, e.g. `tx_success`.
    pub result: Option<String>,
    /// `expect_op_results`.
    pub op_results: Vec<String>,
    /// `expect_submit_reject`: the code core must reject the submission with.
    pub submit_reject: Option<String>,
    /// `expect_excluded`: queued but left out of the ledger, so the sequence number stays unused.
    pub excluded: bool,
}

/// A built step.
#[derive(Debug, Clone)]
pub struct BuiltStep {
    pub id: String,
    pub entry: Option<String>,
    /// The planned ledger (the first one, for a multi-ledger close).
    pub ledger: u32,
    pub close_time: u64,
    pub same_ledger_as: Option<String>,
    /// The signed transaction, when the step has `tx`.
    pub tx: Option<BuiltTx>,
    /// `close` and `upgrade`, placeholders resolved.
    pub close: Option<Value>,
    pub upgrade: Option<Value>,
    pub expected: Expected,
    /// `expect`, `fields`, `mirrors` with placeholders resolved (unknown `${derived.…}` kept).
    pub expect: Option<Value>,
    pub fields: Option<Value>,
    pub mirrors: Option<Value>,
    pub precondition: Option<String>,
    pub soroban_resources: Option<String>,
    /// `simulate: true`: `tx` is a draft whose `ext`, authorization and fee the node side fills from
    /// a simulation before signing it again ([`Interpreter::sign_step`]).
    pub simulate: bool,
    pub notes: Option<String>,
    /// Explore runs only: the simulation of this `simulate: true` step failed, so nothing is
    /// submitted and the error is recorded instead.
    pub sim_error: Option<String>,
}

/// What a setup item asks for.
#[derive(Debug, Clone)]
pub enum SetupAction {
    /// A classic transaction the interpreter built and signed (`fund`, `trust`, `pay`, `tx`).
    Tx(Box<BuiltTx>),
    /// Deploy the Stellar Asset Contract of an asset (built by the node side).
    DeploySac {
        asset_name: String,
        /// SEP-51 JSON of the `Asset`.
        asset: Value,
        /// The `C…` ID the deployment will have.
        contract_id: String,
    },
    /// Upload and deploy a contract (built by the node side).
    DeployContract {
        name: String,
        wasm: String,
        wasm_sha256: Option<String>,
        deployer: Option<String>,
        /// The salt `${contract.id(NAME)}` assumes.
        salt: [u8; 32],
        /// The `C…` ID, when a deployer is named or an ID was injected.
        contract_id: Option<String>,
        /// The constructor arguments, placeholders resolved.
        constructor_args: Vec<ScVal>,
    },
    /// A `close` item, resolved.
    Close(Value),
    /// A `config_upgrade` item: the settings to change (placeholders resolved) and the label of
    /// its upgrade contract's salt, `<scenario>/setup-<index>`.
    ConfigUpgrade {
        changes: Map<String, Value>,
        salt_label: String,
    },
}

/// A built setup item.
#[derive(Debug, Clone)]
pub struct BuiltSetup {
    /// Position in the `setup` list.
    pub index: usize,
    /// The item's key (`fund`, `trust`, …).
    pub kind: &'static str,
    pub ledger: u32,
    pub close_time: u64,
    pub action: SetupAction,
    /// The entry the item's ledger is committed as, `expect` and `fields` resolved.
    pub entry: Option<SetupEntry>,
}

/// One item of the walk.
#[derive(Debug, Clone)]
pub enum Item {
    Setup(Box<BuiltSetup>),
    Step(Box<BuiltStep>),
}

/// Everything [`build`] produces.
#[derive(Debug, Clone)]
pub struct BuiltScenario {
    pub passphrase: String,
    pub network_id: [u8; 32],
    pub protocol: u32,
    /// Actor label → `G…` address.
    pub accounts: BTreeMap<String, String>,
    pub setup: Vec<BuiltSetup>,
    pub steps: Vec<BuiltStep>,
}

/// Build every item of `scenario` for one passphrase and protocol, with no feedback from a node.
pub fn build(
    scenario: &Scenario,
    passphrase: &str,
    protocol: u32,
    options: Options,
) -> Result<BuiltScenario> {
    let mut it = Interpreter::new(scenario, passphrase, protocol, options)?;
    let mut setup = Vec::new();
    let mut steps = Vec::new();
    while let Some(item) = it.next_item() {
        match item? {
            Item::Setup(s) => setup.push(*s),
            Item::Step(s) => steps.push(*s),
        }
    }
    Ok(BuiltScenario {
        passphrase: passphrase.to_string(),
        network_id: it.network_id,
        protocol,
        accounts: it.accounts()?,
        setup,
        steps,
    })
}

/// The stateful walk over one scenario on one network at one protocol.
#[derive(Debug, Clone)]
pub struct Interpreter<'s> {
    scenario: &'s Scenario,
    network_id: [u8; 32],
    protocol: u32,
    keys: Keys,
    options: Options,
    sequences: BTreeMap<String, i64>,
    root_sequence: i64,
    injected: BTreeSet<String>,
    next_ledger: u32,
    next_close_time: Option<u64>,
    setup_pos: usize,
    step_pos: usize,
    /// Built step ID → (ledger, close time).
    placed: BTreeMap<String, (u32, u64)>,
    /// Step ID → transaction hash, built or predicted.
    pre_auth: BTreeMap<String, [u8; 32]>,
    /// Steps whose hash in `pre_auth` is a prediction not yet checked.
    predicted: BTreeSet<String>,
    /// A copy building ahead for a prediction: unknown pre-auth hashes are zero, not predicted.
    lookahead: bool,
    /// The `${order_nonce}` of the current ledger group, when its first step has `order`.
    order_nonce: u64,
    /// Whether the ledger group being built has `order`.
    ordered_group: bool,
}

impl<'s> Interpreter<'s> {
    /// Start a walk. `protocol` must be one of the scenario's and at least 13 (envelopes are
    /// `ENVELOPE_TYPE_TX`, which core rejects before Protocol 13).
    pub fn new(
        scenario: &'s Scenario,
        passphrase: &str,
        protocol: u32,
        options: Options,
    ) -> Result<Self> {
        if !scenario.protocols.contains(&protocol) {
            return Err(Error::Invalid(format!(
                "protocol {protocol} is not one of the scenario's {:?}",
                scenario.protocols
            )));
        }
        if protocol < 13 {
            return Err(Error::Invalid(format!(
                "protocol {protocol}: ENVELOPE_TYPE_TX envelopes need Protocol 13 or later"
            )));
        }
        let keys = Keys::new(&options.namespace, passphrase, &scenario.actors);
        let injected: BTreeSet<String> = options.sequences.keys().cloned().collect();
        for label in &injected {
            keys.actor(label)?;
        }
        Ok(Interpreter {
            scenario,
            network_id: network_id(passphrase),
            protocol,
            sequences: options.sequences.clone(),
            root_sequence: options.root_sequence,
            next_ledger: options.first_ledger,
            keys,
            options,
            injected,
            next_close_time: None,
            setup_pos: 0,
            step_pos: 0,
            placed: BTreeMap::new(),
            pre_auth: BTreeMap::new(),
            predicted: BTreeSet::new(),
            lookahead: false,
            order_nonce: 0,
            ordered_group: false,
        })
    }

    /// The scenario being walked.
    pub fn scenario(&self) -> &'s Scenario {
        self.scenario
    }

    /// The scenario's keys on this network.
    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    pub fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    pub fn protocol(&self) -> u32 {
        self.protocol
    }

    /// Actor label → `G…` address.
    pub fn accounts(&self) -> Result<BTreeMap<String, String>> {
        self.scenario
            .actors
            .iter()
            .map(|l| Ok((l.clone(), self.keys.address(l)?)))
            .collect()
    }

    /// The current (last used) sequence number of an actor.
    pub fn sequence(&self, label: &str) -> Option<i64> {
        self.sequences.get(label).copied()
    }

    /// Set an actor's current sequence number (the next transaction uses `seq + 1`). A value set
    /// here is never overwritten by a later `fund`.
    pub fn set_sequence(&mut self, label: &str, seq: i64) -> Result<()> {
        self.keys.actor(label)?;
        self.sequences.insert(label.to_string(), seq);
        self.injected.insert(label.to_string());
        Ok(())
    }

    pub fn root_sequence(&self) -> i64 {
        self.root_sequence
    }

    pub fn set_root_sequence(&mut self, seq: i64) {
        self.root_sequence = seq;
    }

    /// The ledger the next item will be planned in.
    pub fn next_ledger(&self) -> u32 {
        self.next_ledger
    }

    pub fn set_next_ledger(&mut self, ledger: u32) {
        self.next_ledger = ledger;
    }

    /// Override the close time of the next item that opens a ledger.
    pub fn set_next_close_time(&mut self, close_time: u64) {
        self.next_close_time = Some(close_time);
    }

    /// The default close time of `ledger`.
    pub fn close_time_for(&self, ledger: u32) -> u64 {
        self.options.close_time_base
            + u64::from(ledger.saturating_sub(2)) * self.options.close_time_step
    }

    /// The `${order_nonce}` of the next ledger group with `order` (0 until set). The node side
    /// searches it so that the group's transactions apply in the declared order.
    pub fn set_order_nonce(&mut self, nonce: u64) {
        self.order_nonce = nonce;
    }

    pub fn order_nonce(&self) -> u64 {
        self.order_nonce
    }

    pub fn set_derived(&mut self, name: &str, value: Value) {
        self.options.derived.insert(name.to_string(), value);
    }

    pub fn set_contract_id(&mut self, name: &str, id: [u8; 32]) {
        self.options.contract_ids.insert(name.to_string(), id);
    }

    /// A resolver for the current state and the given close time.
    pub fn resolver(&self, close_time: Option<u64>) -> Resolver<'_> {
        Resolver {
            keys: &self.keys,
            namespace: &self.options.namespace,
            network_id: &self.network_id,
            assets: &self.scenario.assets,
            contracts: &self.scenario.contracts,
            sequences: &self.sequences,
            root_sequence: self.root_sequence,
            close_time,
            derived: &self.options.derived,
            contract_ids: &self.options.contract_ids,
            pre_auth: &self.pre_auth,
            order_nonce: self.ordered_group.then_some(self.order_nonce),
        }
    }

    /// Build the next setup item or step; `None` at the end.
    #[allow(clippy::should_implement_trait)]
    pub fn next_item(&mut self) -> Option<Result<Item>> {
        if let Some(item) = self.scenario.setup.get(self.setup_pos) {
            let index = self.setup_pos;
            let raw = &self.scenario.document["setup"][index];
            let built = self
                .predict_pre_auth(raw)
                .and_then(|()| {
                    self.setup_pos += 1;
                    self.build_setup(index, item)
                })
                .map(|s| Item::Setup(Box::new(s)))
                .map_err(|e| e.within(format!("setup[{index}] ({})", item.kind())));
            self.setup_pos = self.setup_pos.max(index + 1);
            return Some(built);
        }
        while let Some(step) = self.scenario.steps.get(self.step_pos) {
            let raw = &self.scenario.document["steps"][self.step_pos];
            if step.runs_at(self.protocol) {
                let built = self
                    .predict_pre_auth(raw)
                    .and_then(|()| {
                        self.step_pos += 1;
                        self.build_step(step)
                    })
                    .map(|s| Item::Step(Box::new(s)))
                    .map_err(|e| e.within(format!("step `{}`", step.id)));
                return Some(built);
            }
            self.step_pos += 1;
        }
        None
    }

    /// Before an item is built: make sure every step it names in `${signer.pre_auth_tx(…)}` has a
    /// hash, predicting the hashes of steps not built yet.
    fn predict_pre_auth(&mut self, raw: &Value) -> Result<()> {
        for target in pre_auth_steps(raw) {
            if self.pre_auth.contains_key(&target) {
                continue;
            }
            if self.lookahead {
                // Only the target's own hash matters to the copy; a chained reference is caught
                // when the real build checks its prediction.
                self.pre_auth.insert(target, [0; 32]);
                continue;
            }
            let hash = self.look_ahead(&target)?;
            self.pre_auth.insert(target.clone(), hash);
            self.predicted.insert(target);
        }
        Ok(())
    }

    /// The transaction hash step `target` will have, from building ahead on a copy.
    fn look_ahead(&self, target: &str) -> Result<[u8; 32]> {
        let at = format!("${{signer.pre_auth_tx({target})}}");
        let step = self
            .scenario
            .steps
            .iter()
            .find(|s| s.id == target)
            .ok_or_else(|| Error::placeholder(&at, "no step has that ID"))?;
        if step.simulate {
            return Err(Error::placeholder(
                &at,
                "the step is `simulate: true`; its hash is known only after simulation",
            ));
        }
        let mut copy = self.clone();
        copy.lookahead = true;
        while let Some(item) = copy.next_item() {
            let item = item.map_err(|e| e.within(format!("building ahead to step `{target}`")))?;
            if let Item::Step(s) = item {
                if s.id == target {
                    let tx = s
                        .tx
                        .as_ref()
                        .ok_or_else(|| Error::placeholder(&at, "the step has no transaction"))?;
                    return transaction_hash(&self.network_id, &tx.transaction);
                }
            }
        }
        Err(Error::placeholder(
            &at,
            format!(
                "the step is not built after this item at protocol {} (an earlier step without \
                 `tx`, or a step that does not run at this protocol)",
                self.protocol
            ),
        ))
    }

    /// Plan a new ledger span of `count` ledgers; returns (first ledger, close time).
    fn open_ledger(&mut self, count: u32) -> (u32, u64) {
        let ledger = self.next_ledger;
        let close_time = self
            .next_close_time
            .take()
            .unwrap_or_else(|| self.close_time_for(ledger));
        self.next_ledger += count.max(1);
        (ledger, close_time)
    }

    fn build_setup(&mut self, index: usize, item: &SetupItem) -> Result<BuiltSetup> {
        let count = match item {
            SetupItem::Close(v) => close_ledgers(v),
            SetupItem::DeployContract(name) if !self.code_deployed_before(index, name) => 2,
            SetupItem::ConfigUpgrade(_) => 5,
            _ => 1,
        };
        let (ledger, close_time) = self.open_ledger(count);
        let action = match item {
            SetupItem::Fund(pairs) => {
                let ops = pairs
                    .iter()
                    .map(|(label, amount)| {
                        Ok(json!({"source_account": null, "body": {"create_account": {
                            "destination": self.keys.address(label)?,
                            "starting_balance": parse_amount(amount).map_err(Error::Invalid)?.to_string(),
                        }}}))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let root = self.keys.root().clone();
                let template = self.classic_template(
                    &account_strkey(root.verifying_key().as_bytes()),
                    self.root_sequence + 1,
                    ops,
                );
                let tx = parse_transaction(&template)?;
                let hash = transaction_hash(&self.network_id, &tx)?;
                let sigs = sign_hash_with(&[&root], &hash)?;
                let built = BuiltTx {
                    transaction: tx.clone(),
                    envelope: envelope_v1(tx, hash, sigs, Vec::new())?,
                    inner: None,
                };
                self.root_sequence += 1;
                for (label, _) in pairs {
                    if !self.injected.contains(label) {
                        self.sequences
                            .insert(label.clone(), i64::from(ledger) << 32);
                    }
                }
                SetupAction::Tx(Box::new(built))
            }
            SetupItem::Trust(pairs) => {
                let source = pairs
                    .first()
                    .map(|(l, _)| l.clone())
                    .ok_or_else(|| Error::Invalid("empty `trust`".into()))?;
                let resolver = self.resolver(Some(close_time));
                let mut ops = Vec::new();
                let mut signers: Vec<SignerSpec> = Vec::new();
                for (label, asset) in pairs {
                    let op_source = if *label == source {
                        Value::Null
                    } else {
                        Value::String(self.keys.address(label)?)
                    };
                    ops.push(
                        json!({"source_account": op_source, "body": {"change_trust": {
                            "line": resolver.value(&super::Placeholder::Asset(asset.clone()))?,
                            "limit": MAX_LIMIT,
                        }}}),
                    );
                    let spec = SignerSpec::Key(label.clone());
                    if !signers.contains(&spec) {
                        signers.push(spec);
                    }
                }
                SetupAction::Tx(Box::new(self.classic_tx(&source, ops, &signers)?))
            }
            SetupItem::Pay {
                from,
                to,
                asset,
                amount,
            } => {
                let resolver = self.resolver(Some(close_time));
                let ops = vec![json!({"source_account": null, "body": {"payment": {
                    "destination": self.keys.address(to)?,
                    "asset": resolver.value(&super::Placeholder::Asset(asset.clone()))?,
                    "amount": parse_amount(amount).map_err(Error::Invalid)?.to_string(),
                }}})];
                SetupAction::Tx(Box::new(self.classic_tx(
                    from,
                    ops,
                    &[SignerSpec::Key(from.clone())],
                )?))
            }
            SetupItem::Tx(template) => {
                let resolved = self.resolver(Some(close_time)).resolve(template)?;
                let tx = parse_checked(&resolved)?;
                let signers = self.source_signers(&tx);
                let built = BuiltTx {
                    envelope: sign_envelope(&self.network_id, tx.clone(), &signers, &self.keys)?,
                    transaction: tx,
                    inner: None,
                };
                self.consume(&built.transaction, &Expected::default());
                SetupAction::Tx(Box::new(built))
            }
            SetupItem::DeploySac(name) => {
                let resolver = self.resolver(Some(close_time));
                SetupAction::DeploySac {
                    asset_name: name.clone(),
                    asset: resolver.value(&super::Placeholder::Asset(name.clone()))?,
                    contract_id: resolver
                        .value(&super::Placeholder::ContractSac(name.clone()))?
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                }
            }
            SetupItem::DeployContract(name) => {
                let spec = &self.scenario.contracts[name];
                let resolver = self.resolver(Some(close_time));
                let id = resolver.contract_id(name).ok();
                let constructor_args = spec
                    .constructor_args
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        parse_scval(&resolver.resolve(v)?).map_err(|e| {
                            e.within(format!("contracts.{name}.constructor_args[{i}]"))
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                SetupAction::DeployContract {
                    name: name.clone(),
                    wasm: spec.wasm.clone(),
                    wasm_sha256: spec.wasm_sha256.clone(),
                    deployer: spec.deployer.clone(),
                    salt: contract_salt(&self.options.namespace, name),
                    contract_id: id.map(|id| format!("{}", stellar_strkey::Contract(id))),
                    constructor_args,
                }
            }
            SetupItem::Close(v) => SetupAction::Close(self.resolver(Some(close_time)).resolve(v)?),
            SetupItem::ConfigUpgrade(changes) => {
                let resolved = self
                    .resolver(Some(close_time))
                    .resolve(&Value::Object(changes.clone()))?;
                SetupAction::ConfigUpgrade {
                    changes: resolved.as_object().cloned().unwrap_or_default(),
                    salt_label: format!("{}/setup-{index}", self.scenario.name),
                }
            }
        };
        let entry = match &self.scenario.setup_entries[index] {
            Some(e) => Some(self.resolve_entry(e, close_time)?),
            None => None,
        };
        Ok(BuiltSetup {
            index,
            kind: item.kind(),
            ledger,
            close_time,
            action,
            entry,
        })
    }

    /// An entry annotation with `expect` and `fields` resolved at `close_time` (unknown
    /// `${derived.…}` kept).
    pub fn resolve_entry(&self, e: &SetupEntry, close_time: u64) -> Result<SetupEntry> {
        let resolver = self.resolver(Some(close_time));
        let annotate = |v: &Option<Value>| -> Result<Option<Value>> {
            v.as_ref()
                .map(|v| resolver.resolve_annotation(v))
                .transpose()
        };
        Ok(SetupEntry {
            entry: e.entry.clone(),
            expect: annotate(&e.expect)?,
            fields: annotate(&e.fields)?,
            notes: e.notes.clone(),
        })
    }

    /// Whether an earlier `deploy_contract` item uploads the same code (same `wasm_sha256`, or the
    /// same path when no hash is given).
    fn code_deployed_before(&self, index: usize, name: &str) -> bool {
        let code = |n: &str| {
            let c = &self.scenario.contracts[n];
            c.wasm_sha256.clone().unwrap_or_else(|| c.wasm.clone())
        };
        let mine = code(name);
        self.scenario.setup[..index]
            .iter()
            .any(|i| matches!(i, SetupItem::DeployContract(n) if code(n) == mine))
    }

    fn classic_template(&self, source: &str, seq: i64, ops: Vec<Value>) -> Value {
        let n = u32::try_from(ops.len().max(1)).unwrap_or(u32::MAX);
        json!({
            "source_account": source,
            "fee": self.options.setup_fee_per_op.saturating_mul(n),
            "seq_num": seq.to_string(),
            "cond": "none",
            "memo": "none",
            "operations": ops,
            "ext": "v0",
        })
    }

    fn classic_tx(
        &mut self,
        source: &str,
        ops: Vec<Value>,
        signers: &[SignerSpec],
    ) -> Result<BuiltTx> {
        let seq = self.sequences.get(source).copied().ok_or_else(|| {
            Error::Invalid(format!("`{source}` has no sequence number (not funded?)"))
        })? + 1;
        let template = self.classic_template(&self.keys.address(source)?, seq, ops);
        let tx = parse_transaction(&template)?;
        let built = BuiltTx {
            envelope: sign_envelope(&self.network_id, tx.clone(), signers, &self.keys)?,
            transaction: tx,
            inner: None,
        };
        self.consume(&built.transaction, &Expected::default());
        Ok(built)
    }

    /// `{key: L}` for the transaction source and each operation source that is an actor.
    fn source_signers(&self, tx: &Transaction) -> Vec<SignerSpec> {
        let mut out: Vec<SignerSpec> = Vec::new();
        let sources = std::iter::once(&tx.source_account).chain(
            tx.operations
                .iter()
                .filter_map(|op| op.source_account.as_ref()),
        );
        for s in sources {
            if let Some(label) = self.keys.signer_label_of(&muxed_key(s)) {
                let spec = SignerSpec::Key(label.to_string());
                if !out.contains(&spec) {
                    out.push(spec);
                }
            }
        }
        out
    }

    /// Record that `tx` consumed its source's sequence number (unless `expected` says it won't).
    fn consume(&mut self, tx: &Transaction, expected: &Expected) {
        let skipped = expected.submit_reject.is_some()
            || expected.excluded
            || matches!(
                expected.result.as_deref(),
                Some("tx_too_early" | "tx_too_late")
            );
        if skipped {
            return;
        }
        let key = muxed_key(&tx.source_account);
        if let Some(label) = self.keys.label_of(&key) {
            self.sequences.insert(label.to_string(), tx.seq_num.0);
        } else if self.keys.root().verifying_key().as_bytes() == &key {
            self.root_sequence = tx.seq_num.0;
        }
    }

    fn build_step(&mut self, step: &Step) -> Result<BuiltStep> {
        if step.same_ledger_as.is_none() {
            self.ordered_group = step.order.is_some();
        }
        let (ledger, close_time) = match &step.same_ledger_as {
            Some(other) => *self.placed.get(other).ok_or_else(|| {
                Error::Invalid(format!(
                    "same_ledger_as `{other}`: that step does not run at protocol {}",
                    self.protocol
                ))
            })?,
            None => {
                let count = step.close.as_ref().map(close_ledgers).unwrap_or(1);
                self.open_ledger(count)
            }
        };
        let expected = Expected {
            result: step.expect_result.clone(),
            op_results: step.expect_op_results.clone(),
            submit_reject: step.expect_submit_reject.clone(),
            excluded: step.expect_excluded,
        };
        let resolver = self.resolver(Some(close_time));
        let annotate = |v: &Option<Value>| -> Result<Option<Value>> {
            v.as_ref()
                .map(|v| resolver.resolve_annotation(v))
                .transpose()
        };
        let expect = annotate(&step.expect)?;
        let fields = annotate(&step.fields)?;
        let mirrors = annotate(&step.mirrors)?;
        let close = step
            .close
            .as_ref()
            .map(|v| resolver.resolve(v))
            .transpose()?;
        let upgrade = step
            .upgrade
            .as_ref()
            .map(|v| resolver.resolve(v))
            .transpose()?;
        let tx = match &step.tx {
            Some(template) => Some(self.build_step_tx(step, template, close_time)?),
            None => None,
        };
        if let Some(built) = &tx {
            self.consume(&built.transaction, &expected);
            if !step.simulate {
                let hash = transaction_hash(&self.network_id, &built.transaction)?;
                if self.predicted.remove(&step.id) && self.pre_auth.get(&step.id) != Some(&hash) {
                    return Err(Error::Build(format!(
                        "the transaction differs from the one its `${{signer.pre_auth_tx({})}}` \
                         was computed for (it depends on another pre-auth hash or on a value only \
                         the node knows)",
                        step.id
                    )));
                }
                self.pre_auth.insert(step.id.clone(), hash);
            }
        }
        self.placed.insert(step.id.clone(), (ledger, close_time));
        Ok(BuiltStep {
            id: step.id.clone(),
            entry: step.entry.clone(),
            ledger,
            close_time,
            same_ledger_as: step.same_ledger_as.clone(),
            tx,
            close,
            upgrade,
            expected,
            expect,
            fields,
            mirrors,
            precondition: step.precondition.clone(),
            soroban_resources: step.soroban_resources.clone(),
            simulate: step.simulate,
            notes: step.notes.clone(),
            sim_error: None,
        })
    }

    fn build_step_tx(&self, step: &Step, template: &Value, close_time: u64) -> Result<BuiltTx> {
        let mut resolved = self.resolver(Some(close_time)).resolve(template)?;
        if step.simulate {
            simulation_draft(&mut resolved)?;
        }
        let tx = parse_checked(&resolved)?;
        self.sign_step(step, tx, close_time)
    }

    /// Sign `tx` as step `step` says (its `sign` list, and its `fee_bump` when it has one), with
    /// placeholders in `fee_bump` resolved at `close_time`. The node side calls this again for a
    /// `simulate: true` step once simulation has filled the transaction.
    pub fn sign_step(&self, step: &Step, tx: Transaction, close_time: u64) -> Result<BuiltTx> {
        let resolver = self.resolver(Some(close_time));
        let signers = self.signer_specs(step.sign.as_deref().unwrap_or_default());
        let inner = sign_envelope(&self.network_id, tx.clone(), &signers, &self.keys)?;
        let Some(fb) = &step.fee_bump else {
            return Ok(BuiltTx {
                transaction: tx,
                envelope: inner,
                inner: None,
            });
        };
        let fee_source_text = if fb.fee_source.contains("${") {
            resolver.resolve_string(&fb.fee_source)?
        } else {
            self.keys.address(&fb.fee_source)?
        };
        let fee_source: MuxedAccount = fee_source_text.parse().map_err(|_| {
            Error::Build(format!(
                "fee_bump.fee_source `{fee_source_text}` is not a G… or M… address"
            ))
        })?;
        let fee_text = resolver.resolve_string(&fb.fee)?;
        let fee: i64 = fee_text
            .parse()
            .map_err(|_| Error::Build(format!("fee_bump.fee `{fee_text}` is not an int64")))?;
        let fb_signers = match &fb.sign {
            Some(s) => self.signer_specs(s),
            None => {
                let label = self
                    .keys
                    .signer_label_of(&muxed_key(&fee_source))
                    .ok_or_else(|| {
                        Error::Build("fee_bump.fee_source is not an actor; give `sign`".into())
                    })?;
                vec![SignerSpec::Key(label.to_string())]
            }
        };
        let TransactionEnvelope::Tx(v1) = inner.envelope.clone() else {
            unreachable!("sign_envelope builds ENVELOPE_TYPE_TX")
        };
        let bump = FeeBumpTransaction {
            fee_source,
            fee,
            inner_tx: FeeBumpTransactionInnerTx::Tx(v1),
            ext: FeeBumpTransactionExt::V0,
        };
        let outer = sign_fee_bump(&self.network_id, bump, &fb_signers, &self.keys)?;
        Ok(BuiltTx {
            transaction: tx,
            envelope: outer,
            inner: Some(inner),
        })
    }

    /// The signer specifications with named hash-x preimages replaced by their bytes.
    fn signer_specs(&self, specs: &[SignerSpec]) -> Vec<SignerSpec> {
        specs
            .iter()
            .map(|s| match s {
                SignerSpec::HashXNamed(name) => {
                    SignerSpec::HashX(hash_x_preimage(&self.options.namespace, name).to_vec())
                }
                other => other.clone(),
            })
            .collect()
    }
}

/// Prepare a resolved `simulate: true` template: `ext` must be `v0` or absent (it becomes `v0`), the
/// transaction must have exactly one operation, an `invoke_host_function`, whose `auth` defaults to
/// `[]`.
fn simulation_draft(template: &mut Value) -> Result<()> {
    let bad = |m: &str| Err(Error::Build(format!("a `simulate: true` step: {m}")));
    let Some(tx) = template.as_object_mut() else {
        return bad("the template is not an object");
    };
    match tx.get("ext") {
        None => {
            tx.insert("ext".into(), Value::String("v0".into()));
        }
        Some(Value::String(s)) if s == "v0" => {}
        Some(_) => {
            return bad("`ext` is filled by simulation; write `ext: v0` or leave it out");
        }
    }
    let ops = tx.get_mut("operations").and_then(Value::as_array_mut);
    let Some([op]) = ops.map(|o| o.as_mut_slice()) else {
        return bad("the transaction must have exactly one operation");
    };
    let Some(ihf) = op
        .get_mut("body")
        .and_then(|b| b.get_mut("invoke_host_function"))
        .and_then(Value::as_object_mut)
    else {
        return bad("the operation must be `invoke_host_function`");
    };
    ihf.entry("auth")
        .or_insert_with(|| Value::Array(Vec::new()));
    Ok(())
}

/// Parse SEP-51 JSON of an `ScVal`, failing if the parser dropped or changed a field.
fn parse_scval(json: &Value) -> Result<ScVal> {
    let limits = xdrcheck_xdr::Limits::default();
    match xdrcheck_xdr::from_json("ScVal", json, &limits)? {
        Type::ScVal(v) => {
            let back = xdrcheck_xdr::to_json(&Type::ScVal(v.clone()), &limits)?;
            preserved(json, &back, &mut String::new())?;
            Ok(*v)
        }
        _ => unreachable!("from_json(\"ScVal\") returns an ScVal"),
    }
}

fn close_ledgers(close: &Value) -> u32 {
    close
        .get("ledgers")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(1)
}

/// The ed25519 key of a muxed or plain account.
fn muxed_key(account: &MuxedAccount) -> [u8; 32] {
    match account {
        MuxedAccount::Ed25519(k) => k.0,
        MuxedAccount::MuxedEd25519(m) => m.ed25519.0,
    }
}

fn parse_transaction(json: &Value) -> Result<Transaction> {
    match xdrcheck_xdr::from_json("Transaction", json, &xdrcheck_xdr::Limits::default())? {
        Type::Transaction(tx) => Ok(*tx),
        _ => unreachable!("from_json(\"Transaction\") returns a Transaction"),
    }
}

/// Parse a resolved template and fail if the parser dropped or changed any of its fields.
pub fn parse_checked(template: &Value) -> Result<Transaction> {
    let tx = parse_transaction(template)?;
    let back = xdrcheck_xdr::to_json(
        &Type::Transaction(Box::new(tx.clone())),
        &xdrcheck_xdr::Limits::default(),
    )?;
    preserved(template, &back, &mut String::new())?;
    Ok(tx)
}

fn preserved(template: &Value, parsed: &Value, path: &mut String) -> Result<()> {
    let differ = |path: &str, why: String| {
        Err(Error::Build(format!(
            "template field {} {why}",
            if path.is_empty() { "/" } else { path }
        )))
    };
    match (template, parsed) {
        (Value::Object(t), Value::Object(p)) => {
            for (k, tv) in t {
                let len = path.len();
                path.push('/');
                path.push_str(k);
                match p.get(k) {
                    Some(pv) => preserved(tv, pv, path)?,
                    None => {
                        return differ(
                            path,
                            "is not a field of the XDR type (the parser ignored it)".into(),
                        )
                    }
                }
                path.truncate(len);
            }
            Ok(())
        }
        (Value::Array(t), Value::Array(p)) => {
            if t.len() != p.len() {
                return differ(
                    path,
                    format!("has {} items but parsed to {}", t.len(), p.len()),
                );
            }
            for (i, (tv, pv)) in t.iter().zip(p).enumerate() {
                let len = path.len();
                path.push_str(&format!("/{i}"));
                preserved(tv, pv, path)?;
                path.truncate(len);
            }
            Ok(())
        }
        (t, p) => match (scalar(t), scalar(p)) {
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(&b) => Ok(()),
            _ => differ(path, format!("`{t}` parsed as `{p}`")),
        },
    }
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => Some("null".into()),
        _ => None,
    }
}
