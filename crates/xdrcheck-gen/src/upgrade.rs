//! Protocol bring-up: take a fresh node from genesis (protocol 0) to protocol N with usable
//! Soroban limits, reproducibly.
//!
//! | Ledger | Step |
//! |---|---|
//! | 2 | one upgrade 0 → N (`protocolversion=N&basereserve=5000000`, long expiration), then close; below Protocol 20 the bring-up ends here |
//! | 3–6 | settings set 1 (`enable`): restore, upload, create, invoke — one transaction per ledger |
//! | 7 | arm `configupgradesetkey` for set 1, close |
//! | 8–11 | settings set 2 (the protocol's network limits): same four transactions |
//! | 12 | arm set 2, close |
//!
//! Scenario steps start at ledger 13. The settings transactions are built natively ([`txs`]) with the fixed
//! salt `sha256("xcc/settings-upgrade-salt/<file>")` and signed by root, so every run of the same protocol
//! on the same passphrase gives the same header hash at every ledger. Every step is checked: the protocol
//! after ledger 2, `txSUCCESS` for each settings transaction, and the armed key in the next ledger's
//! `upgradesProcessing`.
//!
//! A scenario's own Soroban settings change (`config_upgrade`) goes through the same path
//! ([`apply_upgrade_set`], five ledgers) with its own fixed salt; [`custom_upgrade_set`] builds its
//! `ConfigUpgradeSet` from the settings the node holds and the fields the scenario changes.

pub mod settings;
pub mod txs;

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use stellar_xdr::{
    ConfigSettingEntry, ConfigUpgradeSet, LedgerCloseMeta, LedgerEntryData, LedgerUpgrade,
    TransactionResultResult, Type, WriteXdr,
};

pub use settings::{
    upgrade_contract_wasm, upgrade_salt, ChainIndexFile, ChainIndexSettings, ProtocolSettings,
    SettingsSet,
};
pub use txs::{
    contract_id, contract_id_from_address, contract_instance_key, settings_upgrade_txs,
    SettingsUpgradeTxs,
};

use crate::core::{ClosedLedger, Keypair, Node};

/// Base reserve set with the protocol upgrade (0.5 XLM, as quickstart and the probes did).
pub const BASE_RESERVE: u32 = 5_000_000;

/// The protocols a bring-up can target: every one before Soroban (no settings needed), and those
/// with a vendored network settings set (21 to 30; 28 borrows 27's). Protocol 20 has no upstream
/// set.
pub fn supported_protocol(protocol: u32) -> bool {
    (1..settings::FIRST_SOROBAN_PROTOCOL).contains(&protocol) || (21..=30).contains(&protocol)
}

/// One ledger closed during bring-up.
#[derive(Debug, Clone)]
pub struct BringUpLedger {
    /// What the ledger did, for example `protocol 30`, `enable.xdr upload`, `enable.xdr arm`.
    pub step: String,
    /// The transaction applied in it, if any.
    pub tx_hash: Option<[u8; 32]>,
    /// The ledger.
    pub ledger: ClosedLedger,
}

/// What [`bring_up`] did.
#[derive(Debug, Clone)]
pub struct BringUp {
    /// The target protocol.
    pub protocol: u32,
    /// The settings applied.
    pub settings: ProtocolSettings,
    /// Ledgers 2 to 12, in order.
    pub ledgers: Vec<BringUpLedger>,
    /// The upgrade contract of each set (contract ID), in order.
    pub upgrade_contracts: Vec<[u8; 32]>,
}

/// Bring a fresh node (last closed ledger 1) up to `protocol` with that protocol's Soroban settings.
pub fn bring_up(node: &mut Node, protocol: u32) -> Result<BringUp> {
    if !supported_protocol(protocol) {
        bail!(
            "bring-up supports protocols 1 to 19 and 21 to 30, not {protocol} (no Soroban settings \
             set is vendored for it)"
        );
    }
    if node.last_closed() != 1 {
        bail!(
            "bring-up needs a fresh node; ledger {} is already closed",
            node.last_closed()
        );
    }
    let settings = ProtocolSettings::for_protocol(protocol)?;
    let mut ledgers = Vec::new();

    node.set_upgrades(&[
        ("protocolversion", protocol.to_string()),
        ("basereserve", BASE_RESERVE.to_string()),
    ])?;
    let l = node.close()?;
    if l.protocol != protocol {
        bail!(
            "ledger {} is at protocol {} after the upgrade to {protocol}",
            l.sequence,
            l.protocol
        );
    }
    ledgers.push(BringUpLedger {
        step: format!("protocol {protocol}"),
        tx_hash: None,
        ledger: l,
    });

    let mut upgrade_contracts = Vec::new();
    for set in &settings.sets {
        let (ls, id) = apply_upgrade_set(node, &set.file, &set.upgrade_set, set.salt())?;
        ledgers.extend(ls);
        upgrade_contracts.push(id);
    }
    Ok(BringUp {
        protocol,
        settings,
        ledgers,
        upgrade_contracts,
    })
}

/// Write one `ConfigUpgradeSet` through its own upgrade contract (created by root with `salt`) and
/// arm it: restore, upload, create and invoke, one ledger each, then the ledger that applies the
/// set. Ledgers are labelled `<name> restore` … `<name> arm`. Returns them and the contract ID.
pub fn apply_upgrade_set(
    node: &mut Node,
    name: &str,
    upgrade_set: &[u8],
    salt: [u8; 32],
) -> Result<(Vec<BringUpLedger>, [u8; 32])> {
    let wasm = upgrade_contract_wasm()?;
    let root = Keypair::root(node.passphrase());
    let seq = node
        .account_sequence(&root.account_id())?
        .context("the root account does not exist")?;
    let txs = settings_upgrade_txs(node.passphrase(), &root, seq, wasm, upgrade_set, salt)?;
    let mut ledgers = Vec::new();
    for (step, env) in txs.in_order() {
        let hash = node.submit_pending(env)?;
        let l = node.close()?;
        match l.result_of(&hash)? {
            Some(r) if matches!(r.result, TransactionResultResult::TxSuccess(_)) => {}
            other => bail!(
                "{name} {step} (tx {}) in ledger {}: {other:?}",
                hex::encode(hash),
                l.sequence
            ),
        }
        ledgers.push(BringUpLedger {
            step: format!("{name} {step}"),
            tx_hash: Some(hash),
            ledger: l,
        });
    }
    node.set_upgrades(&[("configupgradesetkey", txs.key_base64()?)])?;
    let l = node.close()?;
    let applied = match l.decode()? {
        LedgerCloseMeta::V0(m) => m.upgrades_processing,
        LedgerCloseMeta::V1(m) => m.upgrades_processing,
        LedgerCloseMeta::V2(m) => m.upgrades_processing,
    }
    .iter()
    .any(|u| matches!(&u.upgrade, LedgerUpgrade::Config(k) if *k == txs.key));
    if !applied {
        bail!(
            "ledger {} did not apply the settings upgrade {name} (core refuses a set that fails its \
             validity checks; see the node log)",
            l.sequence
        );
    }
    ledgers.push(BringUpLedger {
        step: format!("{name} arm"),
        tx_hash: None,
        ledger: l,
    });
    Ok((ledgers, txs.contract_id))
}

/// The `ConfigUpgradeSet` (XDR) of a scenario's `config_upgrade`: one `ConfigSettingEntry` per key
/// of `changes` (a `ConfigSettingEntry` arm name, such as `state_archival`). An object value is
/// merged into the setting the node holds (only the fields given change; nested objects merge
/// too); any other value, or a setting the node does not hold (the `*_delta` arms), is taken as
/// written. In `frozen_ledger_keys` and `frozen_ledger_keys_delta` a key may be written as the
/// SEP-51 JSON of a `LedgerKey` instead of its XDR in hex. Entries are sorted by setting ID, as
/// core requires.
pub fn custom_upgrade_set(node: &mut Node, changes: &Map<String, Value>) -> Result<Vec<u8>> {
    let limits = xdrcheck_xdr::Limits::default();
    let mut entries: Vec<ConfigSettingEntry> = Vec::new();
    for (arm, change) in changes {
        let key_json = json!({"config_setting": {"config_setting_id": arm}});
        let key = match xdrcheck_xdr::from_json("LedgerKey", &key_json, &limits) {
            Ok(Type::LedgerKey(k)) => *k,
            _ => bail!("config_upgrade: `{arm}` is not a configuration setting"),
        };
        let current = node
            .ledger_entries(&[key])?
            .into_iter()
            .find_map(|e| match e.data {
                LedgerEntryData::ConfigSetting(c) => Some(c),
                _ => None,
            });
        let mut value = match (&current, change) {
            (Some(c), Value::Object(_)) => {
                let mut v =
                    xdrcheck_xdr::to_json(&Type::ConfigSettingEntry(Box::new(c.clone())), &limits)?;
                merge(&mut v[arm.as_str()], change);
                v
            }
            _ => json!({ arm.as_str(): change }),
        };
        if arm.starts_with("frozen_ledger_keys") {
            encode_keys(&mut value[arm.as_str()], &limits)?;
        }
        match xdrcheck_xdr::from_json("ConfigSettingEntry", &value, &limits) {
            Ok(Type::ConfigSettingEntry(e)) => entries.push(*e),
            Ok(_) => unreachable!("from_json(\"ConfigSettingEntry\")"),
            Err(e) => bail!("config_upgrade `{arm}`: {e}"),
        }
    }
    entries.sort_by_key(|e| e.discriminant() as i32);
    let set = ConfigUpgradeSet {
        updated_entry: entries.try_into()?,
    };
    Ok(set.to_xdr(stellar_xdr::Limits::none())?)
}

/// Merge `change` into `into`: objects key by key, anything else replaced.
fn merge(into: &mut Value, change: &Value) {
    match (into, change) {
        (Value::Object(a), Value::Object(b)) => {
            for (k, v) in b {
                merge(a.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (slot, v) => *slot = v.clone(),
    }
}

/// In a frozen-keys setting, every object inside a key list (a `LedgerKey` as SEP-51 JSON) becomes
/// its XDR in hex (`EncodedLedgerKey`).
fn encode_keys(v: &mut Value, limits: &xdrcheck_xdr::Limits) -> Result<()> {
    if let Value::Object(fields) = v {
        for list in fields.values_mut().filter_map(Value::as_array_mut) {
            for k in list.iter_mut().filter(|k| k.is_object()) {
                let t = xdrcheck_xdr::from_json("LedgerKey", k, limits)?;
                *k = Value::String(hex::encode(xdrcheck_xdr::encode(&t, limits)?));
            }
        }
    }
    Ok(())
}
