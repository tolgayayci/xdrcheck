//! Loading and validating a scenario file.
//!
//! A file is YAML (any extension other than `.json`; merge keys `<<` are applied) or JSON. It is
//! validated against the frozen `corpus/schema/scenario.schema.json`, compiled once with the
//! manifest-entry schema registered under its `$id` so the step `expect` block is checked against
//! `urn:xcc:schema:manifest-entry:v1#/$defs/expect`. Validation runs on the file as written,
//! before any placeholder is resolved.
//!
//! After the schema, [`Scenario::from_value`] checks what the schema cannot express: unique step
//! IDs; `same_ledger_as` names an earlier step; step protocols are a subset of the scenario's;
//! every label in `sign`, `fund`, `trust`, `pay` and `contracts.*.deployer` is an actor; every
//! asset name in `trust`, `pay` and `deploy_sac` is defined; a step with `tx` has `sign`, and
//! `fee_bump` comes with `tx`; `simulate` comes with `tx`, not with `soroban_resources: declared`,
//! and only on steps that run at Protocol 29 or later; a scenario with `deploy_contract` lists no
//! protocol below 29 (contracts are uploaded and created through simulation, which has a host for
//! Protocols 29 and 30 only).
//!
//! The setup items `trust` and `pay` (see [`SetupItem`]):
//!
//! - `trust: {<label>: <asset name> | [<asset name>, …], …}` — one `change_trust` per pair with the
//!   maximum limit, all in one transaction.
//! - `pay: {from: <label>, to: <label>, asset: <asset name> | native, amount: "<decimal>"}`.
//!
//! Any setup item may also carry `entry` (with `expect`, `fields`, `notes`): its ledger is then
//! committed as that entry ([`SetupEntry`]). `bring_up` names entries on the bring-up's own
//! ledgers ([`BringUpEntry`]).
//!
//! `root` is the network's root account ([`super::keys::ROOT`]): `${acct.root}`, `${seq.root}`,
//! `sign: [{key: root}]` and `fee_bump.fee_source: root` use it. No actor may be called `root`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::{Map, Value};

use super::{Error, Result};

const SCENARIO_SCHEMA: &str = include_str!("../../../../corpus/schema/scenario.schema.json");
const MANIFEST_ENTRY_SCHEMA: &str =
    include_str!("../../../../corpus/schema/manifest-entry.schema.json");
const MANIFEST_ENTRY_ID: &str = "urn:xcc:schema:manifest-entry:v1";

/// A loaded, validated scenario.
#[derive(Debug, Clone)]
pub struct Scenario {
    /// `scenario`: the scenario name.
    pub name: String,
    pub caps: Vec<u32>,
    pub protocols: Vec<u32>,
    /// `networks`, defaulting to `testnet` and `pubnet` as the schema says.
    pub networks: Vec<String>,
    pub profile: String,
    pub profile_flags: BTreeMap<String, bool>,
    /// `binary`: the stellar-core binary the scenario runs on (`release`, `buildtests`, `vnext`).
    pub binary: String,
    /// `channel`: `stable`, or `next` (the advisory `-next` corpus; the only channel for protocols
    /// above the newest released one).
    pub channel: String,
    pub settings: BTreeMap<String, String>,
    pub actors: Vec<String>,
    /// `assets`: name → SEP-51 JSON of the `Asset`, placeholders unresolved.
    pub assets: Map<String, Value>,
    pub contracts: BTreeMap<String, ContractSpec>,
    pub setup: Vec<SetupItem>,
    /// Per setup item (same index): the entry its ledger is committed as, if any.
    pub setup_entries: Vec<Option<SetupEntry>>,
    /// Entries on bring-up ledgers.
    pub bring_up: Vec<BringUpEntry>,
    pub steps: Vec<Step>,
    /// The validated document as written.
    pub document: Value,
}

/// A `contracts` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct ContractSpec {
    pub wasm: String,
    pub wasm_sha256: Option<String>,
    /// Deployer label; used with [`super::contract_salt`] to derive `${contract.id(NAME)}`.
    pub deployer: Option<String>,
    /// Constructor arguments as SEP-51 JSON `ScVal`s, placeholders unresolved.
    #[serde(default)]
    pub constructor_args: Vec<Value>,
}

/// The entry a setup item's ledger (or a bring-up ledger) is committed as, with the annotations a
/// step would carry. For a setup item that closes more than one ledger it is the ledger of the
/// item's last transaction (the `create` of a `deploy_contract`), or the first one of a `close`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupEntry {
    pub entry: String,
    pub expect: Option<Value>,
    pub fields: Option<Value>,
    pub notes: Option<String>,
}

/// The bring-up ledgers an entry can name.
pub const BRING_UP_LEDGERS: [&str; 3] = ["upgrade", "enable-applied", "settings-applied"];

/// `bring_up[]`: an entry on one bring-up ledger — `upgrade` (ledger 2, the protocol upgrade from
/// genesis; `LedgerCloseMeta` v0), `enable-applied` (the ledger that applies the `enable` settings
/// set) or `settings-applied` (the ledger that applies the protocol's network settings set). The
/// settings ledgers exist only at protocols with Soroban settings (20 and later).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BringUpEntry {
    pub ledger: String,
    pub protocols: Option<Vec<u32>>,
    pub entry: String,
    pub expect: Option<Value>,
    pub fields: Option<Value>,
    pub notes: Option<String>,
}

impl BringUpEntry {
    pub fn runs_at(&self, protocol: u32) -> bool {
        self.protocols
            .as_ref()
            .is_none_or(|ps| ps.contains(&protocol))
    }

    /// As a [`SetupEntry`].
    pub fn annotation(&self) -> SetupEntry {
        SetupEntry {
            entry: self.entry.clone(),
            expect: self.expect.clone(),
            fields: self.fields.clone(),
            notes: self.notes.clone(),
        }
    }
}

/// The first protocol with Soroban (and its configuration settings).
pub const FIRST_SOROBAN_PROTOCOL: u32 = 20;

/// The first protocol with a simulation host, which `simulate` steps and `deploy_contract` need.
pub const FIRST_SIMULATION_PROTOCOL: u32 = 29;

/// One setup item (each is one ledger in the interpreter's plan).
#[derive(Debug, Clone)]
pub enum SetupItem {
    /// `fund`: label → starting balance in XLM (decimal, up to 7 places); one root transaction of
    /// `create_account` operations in file order.
    Fund(Vec<(String, String)>),
    /// `trust`: (label, asset name) pairs.
    Trust(Vec<(String, String)>),
    /// `pay`.
    Pay {
        from: String,
        to: String,
        asset: String,
        amount: String,
    },
    /// `deploy_sac`: asset name. Built by the node side (Soroban).
    DeploySac(String),
    /// `deploy_contract`: contract name. Built by the node side (Soroban).
    DeployContract(String),
    /// `tx`: a SEP-51 `Transaction` template.
    Tx(Value),
    /// `close`: passed through.
    Close(Value),
    /// `config_upgrade`: Soroban settings to change, by `ConfigSettingEntry` arm name (see
    /// [`crate::upgrade::custom_upgrade_set`]). Five ledgers: the four upgrade transactions and the
    /// ledger that applies the set.
    ConfigUpgrade(Map<String, Value>),
}

impl SetupItem {
    /// The item's key in the file.
    pub fn kind(&self) -> &'static str {
        match self {
            SetupItem::Fund(_) => "fund",
            SetupItem::Trust(_) => "trust",
            SetupItem::Pay { .. } => "pay",
            SetupItem::DeploySac(_) => "deploy_sac",
            SetupItem::DeployContract(_) => "deploy_contract",
            SetupItem::Tx(_) => "tx",
            SetupItem::Close(_) => "close",
            SetupItem::ConfigUpgrade(_) => "config_upgrade",
        }
    }
}

/// One step, as written (placeholders unresolved).
#[derive(Debug, Clone, Deserialize)]
pub struct Step {
    pub id: String,
    pub entry: Option<String>,
    pub protocols: Option<Vec<u32>>,
    pub same_ledger_as: Option<String>,
    /// On the first step of a ledger group: the group's transaction steps in the apply order wanted.
    pub order: Option<Vec<String>>,
    pub precondition: Option<String>,
    pub tx: Option<Value>,
    pub fee_bump: Option<FeeBumpSpec>,
    #[serde(default)]
    pub sign: Option<Vec<SignerSpec>>,
    pub soroban_resources: Option<String>,
    /// Fill footprint, resources, resource fee and authorization by simulation before signing.
    #[serde(default)]
    pub simulate: bool,
    pub close: Option<Value>,
    pub upgrade: Option<Value>,
    pub expect_result: Option<String>,
    #[serde(default)]
    pub expect_op_results: Vec<String>,
    pub expect: Option<Value>,
    pub fields: Option<Value>,
    pub mirrors: Option<Value>,
    pub notes: Option<String>,
    pub expect_submit_reject: Option<String>,
    /// The transaction is accepted into core's queue but left out of the ledger (surge pricing).
    #[serde(default)]
    pub expect_excluded: bool,
}

impl Step {
    /// Whether the step runs at `protocol`.
    pub fn runs_at(&self, protocol: u32) -> bool {
        self.protocols
            .as_ref()
            .is_none_or(|ps| ps.contains(&protocol))
    }
}

/// A step's `fee_bump` block.
#[derive(Debug, Clone, Deserialize)]
pub struct FeeBumpSpec {
    /// An actor label, or a placeholder giving a `G…`/`M…` address of an actor.
    pub fee_source: String,
    /// The outer fee in stroops (decimal int64; placeholders allowed).
    pub fee: String,
    /// Signers of the fee bump; absent means the fee source's key.
    pub sign: Option<Vec<SignerSpec>>,
}

/// A signer specification.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawSigner")]
pub enum SignerSpec {
    /// `{key: L}`: ed25519 signature of L over the transaction hash.
    Key(String),
    /// `{signed_payload: {key: L, payload_hex: H}}`: ed25519 signature of L over the payload bytes.
    SignedPayload { key: String, payload: Vec<u8> },
    /// `{hash_x: H}`: the preimage itself as the signature.
    HashX(Vec<u8>),
    /// `{hash_x: "${hash_x.preimage(NAME)}"}`: the named preimage
    /// ([`super::hash_x_preimage`]) as the signature.
    HashXNamed(String),
    /// `{pre_auth: true}`: no signature; the transaction hash is a pre-authorised signer.
    PreAuth,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum RawSigner {
    Key(String),
    SignedPayload { key: String, payload_hex: String },
    HashX(String),
    PreAuth(bool),
}

impl TryFrom<RawSigner> for SignerSpec {
    type Error = String;
    fn try_from(raw: RawSigner) -> Result<Self, String> {
        Ok(match raw {
            RawSigner::Key(k) => SignerSpec::Key(k),
            RawSigner::SignedPayload { key, payload_hex } => {
                let payload = hex::decode(&payload_hex)
                    .map_err(|e| format!("payload_hex `{payload_hex}`: {e}"))?;
                if payload.is_empty() || payload.len() > 64 {
                    return Err(format!("payload_hex `{payload_hex}`: 1 to 64 bytes"));
                }
                SignerSpec::SignedPayload { key, payload }
            }
            RawSigner::HashX(h) if h.starts_with("${") => {
                match super::Placeholder::parse(&h[2..h.len().saturating_sub(1)]) {
                    Ok(super::Placeholder::HashXPreimage(name)) if h.ends_with('}') => {
                        SignerSpec::HashXNamed(name)
                    }
                    _ => {
                        return Err(format!(
                            "hash_x `{h}`: a preimage in hex or ${{hash_x.preimage(NAME)}}"
                        ))
                    }
                }
            }
            RawSigner::HashX(h) => {
                let preimage = hex::decode(&h).map_err(|e| format!("hash_x `{h}`: {e}"))?;
                if preimage.len() > 64 {
                    return Err(format!("hash_x `{h}`: a preimage is at most 64 bytes"));
                }
                SignerSpec::HashX(preimage)
            }
            RawSigner::PreAuth(true) => SignerSpec::PreAuth,
            RawSigner::PreAuth(false) => return Err("`pre_auth: false` means nothing".into()),
        })
    }
}

impl SignerSpec {
    /// The actor label whose key signs, if any.
    pub fn label(&self) -> Option<&str> {
        match self {
            SignerSpec::Key(k) | SignerSpec::SignedPayload { key: k, .. } => Some(k),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct RawScenario {
    scenario: String,
    caps: Vec<u32>,
    protocols: Vec<u32>,
    networks: Option<Vec<String>>,
    profile: String,
    #[serde(default)]
    profile_flags: BTreeMap<String, bool>,
    binary: Option<String>,
    channel: Option<String>,
    #[serde(default)]
    settings: BTreeMap<String, String>,
    actors: Vec<String>,
    #[serde(default)]
    assets: Map<String, Value>,
    #[serde(default)]
    contracts: BTreeMap<String, ContractSpec>,
    #[serde(default)]
    setup: Vec<Map<String, Value>>,
    #[serde(default)]
    bring_up: Vec<BringUpEntry>,
    steps: Vec<Step>,
}

fn validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let scenario: Value =
            serde_json::from_str(SCENARIO_SCHEMA).expect("scenario schema is JSON");
        let manifest: Value =
            serde_json::from_str(MANIFEST_ENTRY_SCHEMA).expect("manifest-entry schema is JSON");
        let registry = jsonschema::Registry::new()
            .add(MANIFEST_ENTRY_ID, manifest)
            .and_then(|b| b.prepare())
            .expect("manifest-entry schema registers");
        jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .with_registry(&registry)
            .build(&scenario)
            .expect("scenario schema compiles")
    })
}

/// Validate a document against the scenario schema; every violation is reported.
pub fn validate_schema(document: &Value) -> Result<()> {
    let errors: Vec<String> = validator()
        .iter_errors(document)
        .map(|e| {
            let path = e.instance_path().to_string();
            format!("{}: {e}", if path.is_empty() { "/" } else { &path })
        })
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(Error::Schema(errors))
    }
}

/// Parse YAML text into a JSON value (merge keys applied).
pub fn yaml_to_json(text: &str) -> Result<Value, String> {
    let mut yaml: serde_yaml::Value = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
    yaml.apply_merge().map_err(|e| e.to_string())?;
    serde_yaml::from_value(yaml).map_err(|e| e.to_string())
}

/// Parse JSON text without serde_json's default nesting limit of 128. Call it on a large stack
/// ([`xdrcheck_xdr::with_stack`]): parsing, and later dropping, a deep value recurses.
pub fn json_unbounded(text: &str) -> Result<Value, String> {
    use serde::Deserialize;
    let mut de = serde_json::Deserializer::from_str(text);
    de.disable_recursion_limit();
    let v = Value::deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(v)
}

impl Scenario {
    /// Read, parse (YAML, or JSON for `.json`) and validate a scenario file. YAML nests at most 128
    /// levels (the parser's fixed limit); a scenario with deeper values is written as JSON. Running
    /// such a scenario (building its envelopes) also recurses: do it on a large stack.
    pub fn load(path: &Path) -> Result<Scenario> {
        let load_err = |message: String| Error::Load {
            path: path.display().to_string(),
            message,
        };
        let text = std::fs::read_to_string(path).map_err(|e| load_err(e.to_string()))?;
        if path.extension().is_some_and(|e| e == "json") {
            // JSON has no nesting limit here, so values deeper than YAML's fixed 128 levels can be
            // written; parsing and validating such a document recurses, hence the large stack.
            return xdrcheck_xdr::with_stack(xdrcheck_xdr::DEFAULT_STACK_SIZE, || {
                Scenario::from_value(json_unbounded(&text).map_err(load_err)?)
            });
        }
        Scenario::from_value(yaml_to_json(&text).map_err(load_err)?)
    }

    /// Parse and validate YAML (or JSON) text.
    pub fn from_yaml_str(text: &str) -> Result<Scenario> {
        let document = yaml_to_json(text).map_err(|message| Error::Load {
            path: "<text>".into(),
            message,
        })?;
        Scenario::from_value(document)
    }

    /// Validate a parsed document and build the scenario.
    pub fn from_value(document: Value) -> Result<Scenario> {
        validate_schema(&document)?;
        let raw: RawScenario = serde_json::from_value(document.clone())
            .map_err(|e| Error::Invalid(format!("after schema validation: {e}")))?;
        let (setup, setup_entries): (Vec<_>, Vec<_>) = raw
            .setup
            .iter()
            .map(parse_setup_item)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .unzip();
        let scenario = Scenario {
            name: raw.scenario,
            caps: raw.caps,
            protocols: raw.protocols,
            networks: raw
                .networks
                .unwrap_or_else(|| vec!["testnet".into(), "pubnet".into()]),
            profile: raw.profile,
            profile_flags: raw.profile_flags,
            binary: raw.binary.unwrap_or_else(|| "release".into()),
            channel: raw.channel.unwrap_or_else(|| "stable".into()),
            settings: raw.settings,
            actors: raw.actors,
            assets: raw.assets,
            contracts: raw.contracts,
            setup,
            setup_entries,
            bring_up: raw.bring_up,
            steps: raw.steps,
            document,
        };
        scenario.check()?;
        Ok(scenario)
    }

    /// Whether the scenario names the root account (`${acct.root}`, `${seq.root}`,
    /// `${muxed(root, …)}`, `{key: root}`, `fee_source: root`).
    pub fn uses_root(&self) -> bool {
        let text = self.document.to_string();
        [
            "acct.root}",
            "seq.root}",
            "(root,",
            "\"key\":\"root\"",
            "\"fee_source\":\"root\"",
        ]
        .iter()
        .any(|p| text.contains(p))
    }

    /// The steps that run at `protocol`, in file order.
    pub fn steps_at(&self, protocol: u32) -> impl Iterator<Item = &Step> {
        self.steps.iter().filter(move |s| s.runs_at(protocol))
    }

    fn check(&self) -> Result<()> {
        let invalid = |m: String| Err(Error::Invalid(m));
        if self.actors.iter().any(|a| a == super::keys::ROOT) {
            return invalid(format!(
                "actors: `{}` names the network's root account and cannot be an actor",
                super::keys::ROOT
            ));
        }
        let actors: BTreeSet<&str> = self.actors.iter().map(String::as_str).collect();
        let actor = |label: &str, at: &str| -> Result<()> {
            if actors.contains(label) {
                Ok(())
            } else {
                Err(Error::Invalid(format!("{at}: `{label}` is not an actor")))
            }
        };
        // Signers and fee sources may also be the root account.
        let signer = |label: &str, at: &str| -> Result<()> {
            if label == super::keys::ROOT {
                Ok(())
            } else {
                actor(label, at)
            }
        };
        for b in &self.bring_up {
            if !BRING_UP_LEDGERS.contains(&b.ledger.as_str()) {
                return invalid(format!(
                    "bring_up: `{}` is not a bring-up ledger ({BRING_UP_LEDGERS:?})",
                    b.ledger
                ));
            }
            if let Some(p) = b
                .protocols
                .iter()
                .flatten()
                .find(|p| !self.protocols.contains(p))
            {
                return invalid(format!(
                    "bring_up `{}`: protocol {p} is not a scenario protocol",
                    b.ledger
                ));
            }
        }
        let asset = |name: &str, at: &str| -> Result<()> {
            if name == "native" || self.assets.contains_key(name) {
                Ok(())
            } else {
                Err(Error::Invalid(format!(
                    "{at}: asset `{name}` is not defined"
                )))
            }
        };
        for (name, c) in &self.contracts {
            if let Some(d) = &c.deployer {
                actor(d, &format!("contracts.{name}.deployer"))?;
            }
        }
        for (i, item) in self.setup.iter().enumerate() {
            let at = format!("setup[{i}].{}", item.kind());
            match item {
                SetupItem::Fund(pairs) => {
                    for (l, _) in pairs {
                        actor(l, &at)?;
                    }
                }
                SetupItem::Trust(pairs) => {
                    for (l, a) in pairs {
                        actor(l, &at)?;
                        asset(a, &at)?;
                    }
                }
                SetupItem::Pay {
                    from, to, asset: a, ..
                } => {
                    actor(from, &at)?;
                    actor(to, &at)?;
                    asset(a, &at)?;
                }
                SetupItem::DeploySac(a) => asset(a, &at)?,
                SetupItem::ConfigUpgrade(_) => {
                    if let Some(p) = self.protocols.iter().find(|p| **p < FIRST_SOROBAN_PROTOCOL) {
                        return invalid(format!(
                            "{at}: Soroban settings exist from Protocol {FIRST_SOROBAN_PROTOCOL}; the \
                             scenario lists {p}"
                        ));
                    }
                }
                SetupItem::DeployContract(c) if !self.contracts.contains_key(c) => {
                    return invalid(format!("{at}: contract `{c}` is not defined"));
                }
                SetupItem::DeployContract(_) => {
                    if let Some(p) = self
                        .protocols
                        .iter()
                        .find(|p| **p < FIRST_SIMULATION_PROTOCOL)
                    {
                        return invalid(format!(
                            "{at}: contracts are deployed through simulation, which needs Protocol \
                             {FIRST_SIMULATION_PROTOCOL} or later; the scenario lists {p}"
                        ));
                    }
                }
                _ => {}
            }
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for step in &self.steps {
            let at = format!("step `{}`", step.id);
            if !seen.insert(&step.id) {
                return invalid(format!("{at}: duplicate step id"));
            }
            if let Some(ps) = &step.protocols {
                if let Some(p) = ps.iter().find(|p| !self.protocols.contains(p)) {
                    return invalid(format!("{at}: protocol {p} is not a scenario protocol"));
                }
            }
            if let Some(other) = &step.same_ledger_as {
                if other == &step.id || !seen.contains(other.as_str()) {
                    return invalid(format!(
                        "{at}: same_ledger_as `{other}` is not an earlier step"
                    ));
                }
            }
            if let Some(order) = &step.order {
                self.check_order(step, order)?;
            }
            match (&step.tx, &step.sign) {
                (Some(_), None) => return invalid(format!("{at}: a step with `tx` needs `sign`")),
                (None, Some(_)) => return invalid(format!("{at}: `sign` without `tx`")),
                _ => {}
            }
            if step.fee_bump.is_some() && step.tx.is_none() {
                return invalid(format!("{at}: `fee_bump` without `tx`"));
            }
            if step.expect_excluded {
                if step.tx.is_none() {
                    return invalid(format!("{at}: `expect_excluded` without `tx`"));
                }
                if step.expect_result.is_some()
                    || !step.expect_op_results.is_empty()
                    || step.expect_submit_reject.is_some()
                {
                    return invalid(format!(
                        "{at}: a step left out of its ledger has no result (`expect_excluded` with \
                         `expect_result`, `expect_op_results` or `expect_submit_reject`)"
                    ));
                }
            }
            if step.simulate {
                if step.tx.is_none() {
                    return invalid(format!("{at}: `simulate` without `tx`"));
                }
                if step.soroban_resources.as_deref() == Some("declared") {
                    return invalid(format!(
                        "{at}: `simulate: true` and `soroban_resources: declared` contradict"
                    ));
                }
                let protocols = step.protocols.as_ref().unwrap_or(&self.protocols);
                if let Some(p) = protocols.iter().find(|p| **p < FIRST_SIMULATION_PROTOCOL) {
                    return invalid(format!(
                        "{at}: simulation needs Protocol {FIRST_SIMULATION_PROTOCOL} or later, the \
                         step runs at {p} (limit it with `protocols`)"
                    ));
                }
            }
            let signers = step
                .sign
                .iter()
                .flatten()
                .chain(step.fee_bump.iter().flat_map(|f| f.sign.iter().flatten()));
            for s in signers {
                if let Some(l) = s.label() {
                    signer(l, &at)?;
                }
            }
            if let Some(fb) = &step.fee_bump {
                if !fb.fee_source.contains("${") {
                    signer(&fb.fee_source, &format!("{at}: fee_bump.fee_source"))?;
                }
            }
        }
        Ok(())
    }
}

impl Scenario {
    /// `order` is on a group's first step and lists that step and later steps that share its
    /// ledger, each once. Whether it lists every transaction of the group is checked per run (a
    /// step's `protocols` decide which steps run).
    fn check_order(&self, step: &Step, order: &[String]) -> Result<()> {
        let at = format!("step `{}`: order", step.id);
        if step.same_ledger_as.is_some() {
            return Err(Error::Invalid(format!(
                "{at}: `order` belongs on the first step of the ledger group, not on a step with \
                 `same_ledger_as`"
            )));
        }
        if order.len() < 2 {
            return Err(Error::Invalid(format!("{at}: lists fewer than two steps")));
        }
        let pos = self.steps.iter().position(|s| s.id == step.id).unwrap_or(0);
        let mut members: BTreeSet<&str> = BTreeSet::from([step.id.as_str()]);
        for s in &self.steps[pos + 1..] {
            match &s.same_ledger_as {
                Some(o) if members.contains(o.as_str()) => {
                    members.insert(&s.id);
                }
                _ => break,
            }
        }
        let mut seen = BTreeSet::new();
        for id in order {
            if !members.contains(id.as_str()) {
                return Err(Error::Invalid(format!(
                    "{at}: `{id}` is not a step of this ledger group"
                )));
            }
            if !seen.insert(id.as_str()) {
                return Err(Error::Invalid(format!("{at}: `{id}` is listed twice")));
            }
        }
        Ok(())
    }
}

/// The keys a setup item may carry besides its one action.
const SETUP_ANNOTATIONS: [&str; 4] = ["entry", "expect", "fields", "notes"];

fn parse_setup_item(item: &Map<String, Value>) -> Result<(SetupItem, Option<SetupEntry>)> {
    let annotations: Map<String, Value> = item
        .iter()
        .filter(|(k, _)| SETUP_ANNOTATIONS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let entry = if annotations.is_empty() {
        None
    } else {
        Some(
            serde_json::from_value::<SetupEntry>(Value::Object(annotations))
                .map_err(|e| Error::Invalid(format!("setup item: {e}")))?,
        )
    };
    let mut actions = item
        .iter()
        .filter(|(k, _)| !SETUP_ANNOTATIONS.contains(&k.as_str()));
    let (kind, value) = actions
        .next()
        .ok_or_else(|| Error::Invalid("a setup item without an action".into()))?;
    if let Some((other, _)) = actions.next() {
        return Err(Error::Invalid(format!(
            "setup item: one action per item (`{kind}` and `{other}`)"
        )));
    }
    Ok((parse_setup_action(kind, value)?, entry))
}

fn parse_setup_action(kind: &String, value: &Value) -> Result<SetupItem> {
    let bad = |m: &str| Error::Invalid(format!("setup `{kind}`: {m}"));
    let string = |v: &Value| {
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| bad("expected a string"))
    };
    Ok(match kind.as_str() {
        "fund" => SetupItem::Fund(
            value
                .as_object()
                .ok_or_else(|| bad("expected an object"))?
                .iter()
                .map(|(l, a)| Ok((l.clone(), string(a)?)))
                .collect::<Result<_>>()?,
        ),
        "trust" => {
            let mut pairs = Vec::new();
            for (l, a) in value.as_object().ok_or_else(|| bad("expected an object"))? {
                match a {
                    Value::Array(names) => {
                        for n in names {
                            pairs.push((l.clone(), string(n)?));
                        }
                    }
                    other => pairs.push((l.clone(), string(other)?)),
                }
            }
            SetupItem::Trust(pairs)
        }
        "pay" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Pay {
                from: String,
                to: String,
                asset: String,
                amount: String,
            }
            let p: Pay = serde_json::from_value(value.clone())
                .map_err(|e| bad(&format!("{e} (expected {{from, to, asset, amount}})")))?;
            parse_amount(&p.amount).map_err(|e| bad(&e))?;
            SetupItem::Pay {
                from: p.from,
                to: p.to,
                asset: p.asset,
                amount: p.amount,
            }
        }
        "deploy_sac" => SetupItem::DeploySac(string(value)?),
        "deploy_contract" => SetupItem::DeployContract(string(value)?),
        "tx" => SetupItem::Tx(value.clone()),
        "close" => SetupItem::Close(value.clone()),
        "config_upgrade" => SetupItem::ConfigUpgrade(
            value
                .as_object()
                .filter(|m| !m.is_empty())
                .ok_or_else(|| bad("expected an object of configuration settings"))?
                .clone(),
        ),
        other => return Err(Error::Invalid(format!("unknown setup item `{other}`"))),
    })
}

/// A decimal amount with up to 7 places ("10000", "0.5") in stroops.
pub fn parse_amount(text: &str) -> Result<i64, String> {
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    let ok = !whole.is_empty()
        && whole.bytes().all(|b| b.is_ascii_digit())
        && frac.len() <= 7
        && frac.bytes().all(|b| b.is_ascii_digit())
        && !(text.contains('.') && frac.is_empty());
    if !ok {
        return Err(format!(
            "amount `{text}`: expected a decimal with up to 7 places"
        ));
    }
    let padded = format!("{whole}{frac:0<7}");
    padded
        .parse::<i64>()
        .map_err(|_| format!("amount `{text}` does not fit int64 stroops"))
}
