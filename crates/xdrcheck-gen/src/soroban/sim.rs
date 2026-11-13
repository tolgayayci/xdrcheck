//! Offline simulation of host-function calls against the running node's ledger state.
//!
//! The call runs in recording mode through `soroban-simulation`, on the host of the ledger's protocol:
//! `soroban-env-host` 30.0.0 (`pins.toml`) for Protocol 30 and 29.0.2 for Protocol 29. A production host
//! refuses ledgers older than its own protocol, and stellar-core 30.0.0 itself applies Protocol 29
//! ledgers with its 29.x host. The ledger snapshot is the node: every entry the host reads is fetched
//! from core's query server (`getledgerentryraw`) with its TTL entry, so the footprint, resources,
//! resource fee and (in recording mode) authorization entries come from the state the transaction then
//! applies to. No RPC is involved and nothing leaves the loopback.
//!
//! The simulated ledger is the next one: sequence `last closed + 1`, its scheduled close time, the
//! node's protocol and base reserve. The PRNG seed is the caller's, derived from a label per
//! simulation ([`simulation_seed`]), and resource adjustment is the one RPC applies, so a given state
//! and label always give the same transaction. [`check_applied`] holds the applied result to the
//! simulation (success, the same contract events, the same return value).
//!
//! The 29.x host speaks `stellar-xdr` 28.0.0; values cross between it and the oracle's 30.0.0 types as
//! XDR bytes.

use std::rc::Rc;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use stellar_xdr::{
    AccountId, ContractEvent, Hash, HostFunction, LedgerEntry, LedgerEntryData, LedgerKey,
    LedgerKeyTtl, Limits, MuxedAccount, OperationBody, PublicKey, ReadXdr, ScVal,
    SorobanAuthorizationEntry, SorobanTransactionData, Transaction, TransactionExt, WriteXdr,
};

use super::TxOutcome;
use crate::core::keys::sha256;
use crate::core::{http, Node};

/// What a simulation produced.
#[derive(Debug, Clone)]
pub struct Simulated {
    /// Footprint, resources and resource fee (with the default adjustment RPC applies).
    pub transaction_data: SorobanTransactionData,
    /// Authorization entries: recorded (unsigned) in recording mode, the given ones when enforcing.
    pub auth: Vec<SorobanAuthorizationEntry>,
    /// The call's return value.
    pub return_value: ScVal,
    /// Contract events the call emitted in simulation.
    pub contract_events: Vec<ContractEvent>,
    /// CPU instructions metered, before adjustment.
    pub instructions: u32,
}

/// How authorization is handled while simulating.
#[derive(Debug, Clone)]
pub enum AuthMode {
    /// Record what the call needs (the source account's own authorizations become
    /// `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT` entries).
    Record,
    /// Enforce these entries, exactly as the transaction will carry them.
    Enforce(Vec<SorobanAuthorizationEntry>),
}

/// The ledger the simulation pretends to apply in.
#[derive(Debug, Clone, Copy)]
struct NextLedger {
    protocol: u32,
    sequence: u32,
    close_time: u64,
    network_id: [u8; 32],
    base_reserve: u32,
}

/// A ledger snapshot read from core's query server.
struct QuerySnapshot {
    port: u16,
}

impl QuerySnapshot {
    fn fetch(&self, keys: &[LedgerKey]) -> Result<Vec<LedgerEntry>> {
        let mut body = Vec::new();
        for k in keys {
            body.push(format!(
                "key={}",
                http::encode(&k.to_xdr_base64(Limits::none())?)
            ));
        }
        let raw = http::post_form(self.port, "getledgerentryraw", &body.join("&"))?;
        let v: Value = serde_json::from_str(&raw).with_context(|| {
            format!("getledgerentryraw reply is not JSON: {}", http::short(&raw))
        })?;
        v.get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|e| {
                let b64 = e
                    .get("entry")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("entry without \"entry\": {e}"))?;
                Ok(LedgerEntry::from_xdr_base64(
                    b64,
                    Limits {
                        depth: 1000,
                        len: 64 << 20,
                    },
                )?)
            })
            .collect()
    }

    /// The live entry for `key` and, for Soroban entries, its `live_until` ledger.
    fn get_entry(&self, key: &LedgerKey) -> Result<Option<(LedgerEntry, Option<u32>)>> {
        let Some(entry) = self.fetch(std::slice::from_ref(key))?.into_iter().next() else {
            return Ok(None);
        };
        let live_until = match key {
            LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) => {
                let ttl_key = LedgerKey::Ttl(LedgerKeyTtl {
                    key_hash: Hash(sha256(&key.to_xdr(Limits::none())?)),
                });
                match self.fetch(&[ttl_key])?.into_iter().next() {
                    Some(LedgerEntry {
                        data: LedgerEntryData::Ttl(t),
                        ..
                    }) => Some(t.live_until_ledger_seq),
                    _ => bail!("no TTL entry for live Soroban entry {key:?}"),
                }
            }
            _ => None,
        };
        Ok(Some((entry, live_until)))
    }
}

/// One simulation path per host version. Both hosts have the same API over their own XDR types.
macro_rules! host_simulation {
    ($module:ident, $host:ident, $simulation:ident) => {
        mod $module {
            use super::*;
            use $host::e2e_invoke::RecordingInvocationAuthMode;
            use $host::xdr as hx;
            use $simulation::simulation::{
                simulate_invoke_host_function_op, SimulationAdjustmentConfig,
            };
            use $simulation::NetworkConfig;

            fn to_host<A: WriteXdr, B: hx::ReadXdr>(a: &A) -> Result<B> {
                let bytes = a.to_xdr(Limits::none())?;
                Ok(B::from_xdr(bytes, hx::Limits::none())?)
            }

            fn from_host<A: hx::WriteXdr, B: ReadXdr>(a: &A) -> Result<B> {
                let bytes = a.to_xdr(hx::Limits::none())?;
                Ok(B::from_xdr(
                    &bytes,
                    Limits {
                        depth: 1000,
                        len: bytes.len(),
                    },
                )?)
            }

            struct Snapshot(QuerySnapshot);

            impl $host::storage::SnapshotSource for Snapshot {
                fn get(
                    &self,
                    key: &Rc<hx::LedgerKey>,
                ) -> Result<Option<$host::storage::EntryWithLiveUntil>, $host::HostError> {
                    let found =
                        from_host(&**key).and_then(|k: LedgerKey| match self.0.get_entry(&k)? {
                            Some((e, live)) => Ok(Some((Rc::new(to_host(&e)?), live))),
                            None => Ok(None),
                        });
                    found.map_err(|e| {
                        eprintln!("simulation snapshot: {e:#}");
                        $host::Error::from_type_and_code(
                            hx::ScErrorType::Storage,
                            hx::ScErrorCode::InternalError,
                        )
                        .into()
                    })
                }
            }

            pub(super) fn run(
                snapshot: QuerySnapshot,
                next: NextLedger,
                source: &AccountId,
                host_function: &HostFunction,
                auth: &AuthMode,
                seed: [u8; 32],
            ) -> Result<Simulated> {
                let snapshot = Snapshot(snapshot);
                let network = NetworkConfig::load_from_snapshot(&snapshot)
                    .context("load the network's Soroban settings from the node")?;
                let mut ledger_info = $host::LedgerInfo {
                    protocol_version: next.protocol,
                    sequence_number: next.sequence,
                    timestamp: next.close_time,
                    network_id: next.network_id,
                    base_reserve: next.base_reserve,
                    ..Default::default()
                };
                network.fill_config_fields_in_ledger_info(&mut ledger_info);
                let auth_mode = match auth {
                    AuthMode::Record => RecordingInvocationAuthMode::recording(false, false),
                    AuthMode::Enforce(entries) => RecordingInvocationAuthMode::Enforcing(
                        entries.iter().map(to_host).collect::<Result<_>>()?,
                    ),
                };
                let r = simulate_invoke_host_function_op(
                    Rc::new(snapshot),
                    &network,
                    &SimulationAdjustmentConfig::default_adjustment(),
                    &ledger_info,
                    to_host(host_function)?,
                    auth_mode,
                    &to_host(source)?,
                    seed,
                    true,
                )?;
                let return_value = match &r.invoke_result {
                    Ok(v) => from_host(v)?,
                    Err(e) => {
                        let diagnostics: Vec<String> = r
                            .diagnostic_events
                            .iter()
                            .take(20)
                            .map(|d| format!("  {:?}", d.event.body))
                            .collect();
                        bail!("simulation failed: {e:?}\n{}", diagnostics.join("\n"))
                    }
                };
                let data = r
                    .transaction_data
                    .as_ref()
                    .ok_or_else(|| anyhow!("simulation returned no transaction data"))?;
                Ok(Simulated {
                    transaction_data: from_host(data)?,
                    auth: r.auth.iter().map(from_host).collect::<Result<_>>()?,
                    return_value,
                    contract_events: r
                        .contract_events
                        .iter()
                        .map(from_host)
                        .collect::<Result<_>>()?,
                    instructions: r.simulated_instructions,
                })
            }
        }
    };
}

host_simulation!(p30, soroban_env_host, soroban_simulation);
host_simulation!(p29, soroban_env_host_p29, soroban_simulation_p29);

/// The protocols [`simulate`] has a host for.
pub const SIMULATION_PROTOCOLS: std::ops::RangeInclusive<u32> = 29..=30;

/// Fill a drafted one-operation `invoke_host_function` transaction from a simulation on the node's
/// next ledger: `ext` becomes the simulated `SorobanTransactionData`, an empty authorization list
/// becomes the recorded entries (a non-empty one is enforced as written), and the fee becomes the
/// draft's fee (the inclusion fee) plus the resource fee. The source of the simulation is the
/// operation's source, else the transaction's (the account behind a muxed address).
pub fn simulate_transaction(
    node: &mut Node,
    draft: &Transaction,
    seed: [u8; 32],
) -> Result<(Transaction, Simulated)> {
    let [op] = draft.operations.as_slice() else {
        bail!("a simulated transaction has exactly one operation");
    };
    let OperationBody::InvokeHostFunction(ihf) = &op.body else {
        bail!("a simulated transaction's operation is invoke_host_function");
    };
    let source = op.source_account.as_ref().unwrap_or(&draft.source_account);
    let source = AccountId(PublicKey::PublicKeyTypeEd25519(match source {
        MuxedAccount::Ed25519(k) => k.clone(),
        MuxedAccount::MuxedEd25519(m) => m.ed25519.clone(),
    }));
    let auth = if ihf.auth.is_empty() {
        AuthMode::Record
    } else {
        AuthMode::Enforce(ihf.auth.to_vec())
    };
    let sim = simulate(node, &source, ihf.host_function.clone(), auth, seed)?;
    let mut tx = draft.clone();
    let fee = i64::from(draft.fee) + sim.transaction_data.resource_fee;
    tx.fee = u32::try_from(fee).with_context(|| {
        format!(
            "inclusion fee {} plus resource fee does not fit uint32",
            draft.fee
        )
    })?;
    if ihf.auth.is_empty() {
        let mut op = op.clone();
        if let OperationBody::InvokeHostFunction(o) = &mut op.body {
            o.auth = sim.auth.clone().try_into()?;
        }
        tx.operations = vec![op].try_into()?;
    }
    tx.ext = TransactionExt::V1(sim.transaction_data.clone());
    Ok((tx, sim))
}

/// The PRNG seed of one simulation: `sha256("xcc/simulation-seed/<label>")`. Callers label each
/// simulation distinctly (the scenario runner uses `<scenario>/<step id>`, deploys
/// `<scenario>/deploy_contract/<name>/upload|create`), so values the host draws from its PRNG, such
/// as recorded nonces, differ between steps and are the same on every run.
pub fn simulation_seed(label: &str) -> [u8; 32] {
    sha256(format!("xcc/simulation-seed/{label}").as_bytes())
}

/// Check an applied transaction against its simulation: it succeeded, its operation's contract
/// events are the simulated ones, and its return value is the simulated one.
pub fn check_applied(sim: &Simulated, out: &TxOutcome) -> Result<()> {
    if !out.succeeded() {
        bail!(
            "simulation succeeded but the transaction failed: {:?}",
            out.result.result
        );
    }
    let events = out.op_events(0);
    if events != sim.contract_events {
        bail!(
            "the applied transaction emitted {} contract events, simulation {} (or they differ): \
             applied {events:?}, simulated {:?}",
            events.len(),
            sim.contract_events.len(),
            sim.contract_events
        );
    }
    if let Some(v) = out.return_value() {
        if v != sim.return_value {
            bail!(
                "the applied return value {v:?} differs from the simulated {:?}",
                sim.return_value
            );
        }
    }
    Ok(())
}

/// Simulate `host_function` sourced by `source` on the node's next ledger, with PRNG `seed`
/// ([`simulation_seed`]).
pub fn simulate(
    node: &mut Node,
    source: &AccountId,
    host_function: HostFunction,
    auth: AuthMode,
    seed: [u8; 32],
) -> Result<Simulated> {
    let info = node.info()?;
    let ledger = |k: &str| {
        info.pointer(&format!("/info/ledger/{k}"))
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("info has no ledger.{k}"))
    };
    let next = NextLedger {
        protocol: u32::try_from(ledger("version")?)?,
        sequence: node.last_closed() + 1,
        close_time: node.next_close_time()?,
        network_id: node.network_id(),
        base_reserve: u32::try_from(ledger("baseReserve")?)?,
    };
    let snapshot = QuerySnapshot {
        port: node.query_port(),
    };
    match next.protocol {
        30 => p30::run(snapshot, next, source, &host_function, &auth, seed),
        29 => p29::run(snapshot, next, source, &host_function, &auth, seed),
        p => bail!(
            "no simulation host for protocol {p} (have {SIMULATION_PROTOCOLS:?}); declare the footprint instead"
        ),
    }
}
