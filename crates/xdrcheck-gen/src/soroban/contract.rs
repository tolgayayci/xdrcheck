//! Custom contracts: upload a wasm, deploy it with `CREATE_CONTRACT_V2` and constructor
//! arguments under a deterministic salt, and invoke it. Every transaction's footprint, resources and
//! resource fee come from offline simulation against the node ([`super::sim`]).
//!
//! - The salt of contract `<name>` is `sha256("xcc/contract-salt/<name>")`
//!   ([`crate::scenario::contract_salt`]); several instances of one wasm are several names.
//! - [`run_deploy_contract`] executes the scenario interpreter's `deploy_contract` setup item.
//! - [`delegated_auth`] builds a CAP-0071 `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` entry.

use std::path::Path;

use anyhow::{bail, Context, Result};
use stellar_xdr::{
    ContractExecutable, ContractId, ContractIdPreimage, ContractIdPreimageFromAddress,
    CreateContractArgsV2, Hash, HostFunction, InvokeContractArgs, LedgerKey, LedgerKeyContractCode,
    ScAddress, ScSymbol, ScVal, SorobanAddressCredentials, SorobanAddressCredentialsWithDelegates,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, SorobanDelegateSignature, Uint256,
};

use super::sim::{check_applied, simulate, simulation_seed, AuthMode, Simulated};
use super::{execute, host_function_tx, next_seq, Resources, TxOutcome};
use crate::core::keys::sha256;
use crate::core::{Keypair, Node};
use crate::scenario::{contract_salt, Interpreter, SetupAction, NAMESPACE};
use crate::upgrade::contract_id;

/// A wasm checked against its expected sha256.
#[derive(Debug, Clone)]
pub struct ContractWasm {
    /// The bytes.
    pub wasm: Vec<u8>,
    /// sha256 of the bytes (the contract code hash).
    pub hash: [u8; 32],
}

impl ContractWasm {
    /// Read `path`; when `expected_sha256` is given the file must have it.
    pub fn from_file(path: &Path, expected_sha256: Option<&str>) -> Result<ContractWasm> {
        let wasm = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let hash = sha256(&wasm);
        if let Some(want) = expected_sha256 {
            if hex::encode(hash) != want {
                bail!(
                    "{} has sha256 {}, expected {want}",
                    path.display(),
                    hex::encode(hash)
                );
            }
        }
        Ok(ContractWasm { wasm, hash })
    }

    /// The `ContractCode` key of this wasm.
    pub fn code_key(&self) -> LedgerKey {
        LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: Hash(self.hash),
        })
    }
}

/// A deployed contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployed {
    /// The contract ID.
    pub contract_id: [u8; 32],
    /// The salt it was created with.
    pub salt: [u8; 32],
}

impl Deployed {
    /// The contract address.
    pub fn address(&self) -> ScAddress {
        ScAddress::Contract(ContractId(Hash(self.contract_id)))
    }

    /// The `C…` strkey.
    pub fn strkey(&self) -> String {
        format!("{}", stellar_strkey::Contract(self.contract_id))
    }
}

/// Simulate `host_function` from `source` with PRNG `seed` ([`super::sim::simulation_seed`]), build
/// the transaction from the simulation (footprint, resources, resource fee, authorization), sign it
/// with `source`, submit, close and read the outcome. The applied transaction must have succeeded
/// with the simulated contract events and return value ([`check_applied`]); a failing call fails in
/// simulation already, so this is for calls meant to succeed.
pub fn simulate_and_execute(
    node: &mut Node,
    source: &Keypair,
    host_function: HostFunction,
    auth: AuthMode,
    inclusion_fee: u32,
    seed: [u8; 32],
) -> Result<(Simulated, TxOutcome)> {
    let sim = simulate(
        node,
        &source.account_id(),
        host_function.clone(),
        auth,
        seed,
    )?;
    let data = &sim.transaction_data;
    let resources = Resources {
        instructions: data.resources.instructions,
        disk_read_bytes: data.resources.disk_read_bytes,
        write_bytes: data.resources.write_bytes,
        resource_fee: data.resource_fee,
    };
    let seq = next_seq(node, source)?;
    let mut tx = host_function_tx(
        source.muxed_account(),
        seq,
        inclusion_fee,
        host_function,
        sim.auth.clone(),
        data.resources.footprint.clone(),
        resources,
    )?;
    // Keep the simulation's extension (it lists archived entries to restore, if any).
    tx.ext = stellar_xdr::TransactionExt::V1(data.clone());
    let (out, _) = execute(node, tx, &[source])?;
    check_applied(&sim, &out).with_context(|| {
        format!(
            "transaction {} in ledger {}",
            hex::encode(out.hash),
            out.ledger
        )
    })?;
    Ok((sim, out))
}

/// Upload `wasm` from `source` unless the code is already on the ledger. Returns the outcome when an
/// upload ran.
pub fn upload(
    node: &mut Node,
    source: &Keypair,
    wasm: &ContractWasm,
    inclusion_fee: u32,
    seed: [u8; 32],
) -> Result<Option<TxOutcome>> {
    if !node.ledger_entries(&[wasm.code_key()])?.is_empty() {
        return Ok(None);
    }
    let (_, out) = simulate_and_execute(
        node,
        source,
        HostFunction::UploadContractWasm(wasm.wasm.clone().try_into()?),
        AuthMode::Record,
        inclusion_fee,
        seed,
    )
    .with_context(|| format!("upload of wasm {}", hex::encode(wasm.hash)))?;
    Ok(Some(out))
}

/// Create contract `name` from `deployer` (also the transaction source) with `CREATE_CONTRACT_V2`,
/// salt `sha256("xcc/contract-salt/<name>")` and `constructor_args`. The code must be uploaded.
pub fn create(
    node: &mut Node,
    deployer: &Keypair,
    name: &str,
    wasm: &ContractWasm,
    constructor_args: Vec<ScVal>,
    inclusion_fee: u32,
    seed: [u8; 32],
) -> Result<(Deployed, TxOutcome)> {
    let salt = contract_salt(NAMESPACE, name);
    let preimage = ContractIdPreimage::Address(ContractIdPreimageFromAddress {
        address: ScAddress::Account(deployer.account_id()),
        salt: Uint256(salt),
    });
    let id = contract_id(node.passphrase(), preimage.clone())?;
    let (_, out) = simulate_and_execute(
        node,
        deployer,
        HostFunction::CreateContractV2(CreateContractArgsV2 {
            contract_id_preimage: preimage,
            executable: ContractExecutable::Wasm(Hash(wasm.hash)),
            constructor_args: constructor_args.try_into()?,
        }),
        AuthMode::Record,
        inclusion_fee,
        seed,
    )
    .with_context(|| format!("creating contract {name}"))?;
    Ok((
        Deployed {
            contract_id: id,
            salt,
        },
        out,
    ))
}

/// `contract.function(args)` from `source`, simulated with PRNG `seed` then executed; it must succeed
/// as simulated ([`simulate_and_execute`]).
#[allow(clippy::too_many_arguments)]
pub fn invoke(
    node: &mut Node,
    source: &Keypair,
    contract: &ScAddress,
    function: &str,
    args: Vec<ScVal>,
    auth: AuthMode,
    inclusion_fee: u32,
    seed: [u8; 32],
) -> Result<(Simulated, TxOutcome)> {
    simulate_and_execute(
        node,
        source,
        HostFunction::InvokeContract(invoke_args(contract, function, args)?),
        auth,
        inclusion_fee,
        seed,
    )
    .with_context(|| format!("calling {function}"))
}

/// `InvokeContractArgs` for a call.
pub fn invoke_args(
    contract: &ScAddress,
    function: &str,
    args: Vec<ScVal>,
) -> Result<InvokeContractArgs> {
    Ok(InvokeContractArgs {
        contract_address: contract.clone(),
        function_name: ScSymbol(
            function
                .try_into()
                .map_err(|_| anyhow::anyhow!("{function:?} is not a symbol"))?,
        ),
        args: args.try_into()?,
    })
}

/// One delegate of [`delegated_auth`]: its address, its signature value and its own delegates.
#[derive(Debug, Clone)]
pub struct Delegate {
    /// The delegate's address.
    pub address: ScAddress,
    /// Its signature (any value a custom account accepts).
    pub signature: ScVal,
    /// Delegates of this delegate.
    pub nested: Vec<Delegate>,
}

fn delegate_signature(d: &Delegate) -> Result<SorobanDelegateSignature> {
    Ok(SorobanDelegateSignature {
        address: d.address.clone(),
        signature: d.signature.clone(),
        nested_delegates: d
            .nested
            .iter()
            .map(delegate_signature)
            .collect::<Result<Vec<_>>>()?
            .try_into()?,
    })
}

/// A CAP-0071 authorization entry: `address` authorizes the root invocation `call` with `signature`
/// and forwards to `delegates`. `nonce` must be unused; the signature expires at
/// `signature_expiration_ledger`.
pub fn delegated_auth(
    address: ScAddress,
    nonce: i64,
    signature_expiration_ledger: u32,
    signature: ScVal,
    delegates: &[Delegate],
    call: InvokeContractArgs,
) -> Result<SorobanAuthorizationEntry> {
    Ok(SorobanAuthorizationEntry {
        credentials: SorobanCredentials::AddressWithDelegates(
            SorobanAddressCredentialsWithDelegates {
                address_credentials: SorobanAddressCredentials {
                    address,
                    nonce,
                    signature_expiration_ledger,
                    signature,
                },
                delegates: delegates
                    .iter()
                    .map(delegate_signature)
                    .collect::<Result<Vec<_>>>()?
                    .try_into()?,
            },
        ),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(call),
            sub_invocations: vec![].try_into()?,
        },
    })
}

/// Execute a scenario's `deploy_contract` setup item ([`SetupAction::DeployContract`]): read the wasm
/// (relative to `base_dir`, hash-checked when the scenario gives one), upload it unless the code is
/// already on the ledger, create the contract from its deployer (root when none is named) with the
/// item's constructor arguments, then tell the interpreter the contract ID, the deployer's sequence
/// number and the next ledger (an upload takes a ledger of its own). Root uploads the code. The
/// outcomes are in ledger order: the upload's (when one ran), then the create's.
pub fn run_deploy_contract(
    node: &mut Node,
    interpreter: &mut Interpreter<'_>,
    action: &SetupAction,
    base_dir: &Path,
    inclusion_fee: u32,
) -> Result<(Deployed, Vec<TxOutcome>)> {
    let SetupAction::DeployContract {
        name,
        wasm,
        wasm_sha256,
        deployer,
        salt,
        contract_id: expected,
        constructor_args,
    } = action
    else {
        bail!("run_deploy_contract takes a deploy_contract setup item, not {action:?}");
    };
    let code = ContractWasm::from_file(&base_dir.join(wasm), wasm_sha256.as_deref())?;
    let root = Keypair::root(node.passphrase());
    let deployer_key = match deployer {
        Some(label) => Keypair::from_seed(interpreter.keys().actor(label)?.to_bytes()),
        None => root.clone(),
    };
    let label = format!("{}/deploy_contract/{name}", interpreter.scenario().name);
    let mut outcomes = Vec::new();
    let upload_seed = simulation_seed(&format!("{label}/upload"));
    if let Some(out) = upload(node, &root, &code, inclusion_fee, upload_seed)? {
        outcomes.push(out);
    }
    let (deployed, out) = create(
        node,
        &deployer_key,
        name,
        &code,
        constructor_args.clone(),
        inclusion_fee,
        simulation_seed(&format!("{label}/create")),
    )?;
    outcomes.push(out);
    if deployed.salt != *salt {
        bail!("contract {name}: the interpreter's salt differs from the generator's");
    }
    if let Some(want) = expected {
        if deployed.strkey() != *want {
            bail!(
                "contract {name} deployed as {}, the scenario resolved {want}",
                deployed.strkey()
            );
        }
    }
    interpreter.set_contract_id(name, deployed.contract_id);
    interpreter.set_root_sequence(next_seq(node, &root)? - 1);
    if let Some(label) = deployer {
        interpreter.set_sequence(label, next_seq(node, &deployer_key)? - 1)?;
    }
    interpreter.set_next_ledger(node.last_closed() + 1);
    Ok((deployed, outcomes))
}
