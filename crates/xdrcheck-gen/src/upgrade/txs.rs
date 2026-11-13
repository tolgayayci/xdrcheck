//! The four Soroban settings-upgrade transactions, built natively with a fixed salt.
//!
//! This is stellar-core 30.0.0's `get-settings-upgrade-txs` (`src/main/SettingsUpgradeUtils.cpp`) field for
//! field — operations, footprints, resources, fees and sequence numbers — except that the upgrade contract's
//! salt is a parameter instead of `autocheck::generator<Hash>()`. A random salt gives the contract, and so
//! the bucket list and every later header hash, a different value on every run.
//!
//! 1. restore the upgrade contract's code (a no-op on a fresh network, kept for parity with core);
//! 2. upload the code;
//! 3. create the contract from the root account with the salt;
//! 4. invoke `write(ConfigUpgradeSet bytes)`, which stores the set in temporary contract data.
//!
//! The returned [`ConfigUpgradeSetKey`] (contract ID, sha256 of the set) is what `upgrades?mode=set&
//! configupgradesetkey=` arms.

use anyhow::{Context, Result};
use stellar_xdr::{
    ConfigUpgradeSet, ConfigUpgradeSetKey, ContractDataDurability, ContractExecutable, ContractId,
    ContractIdPreimage, ContractIdPreimageFromAddress, CreateContractArgs, ExtensionPoint, Hash,
    HashIdPreimage, HashIdPreimageContractId, HostFunction, InvokeContractArgs,
    InvokeHostFunctionOp, LedgerFootprint, LedgerKey, LedgerKeyContractCode, LedgerKeyContractData,
    Limits, Memo, Operation, OperationBody, Preconditions, ReadXdr, RestoreFootprintOp, ScAddress,
    ScBytes, ScSymbol, ScVal, SequenceNumber, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanResources, SorobanTransactionData,
    SorobanTransactionDataExt, Transaction, TransactionEnvelope, TransactionExt, Uint256, WriteXdr,
};

use crate::core::keys::{network_id, sha256, sign_transaction, Keypair};

/// The settings-upgrade transactions for one `ConfigUpgradeSet`.
#[derive(Debug, Clone)]
pub struct SettingsUpgradeTxs {
    /// Restore the contract code (sequence `seq + 1`).
    pub restore: TransactionEnvelope,
    /// Upload the contract code (`seq + 2`).
    pub upload: TransactionEnvelope,
    /// Create the upgrade contract (`seq + 3`).
    pub create: TransactionEnvelope,
    /// Write the upgrade set (`seq + 4`).
    pub invoke: TransactionEnvelope,
    /// What to arm with `configupgradesetkey`.
    pub key: ConfigUpgradeSetKey,
    /// The upgrade contract's ID.
    pub contract_id: [u8; 32],
    /// The salt used.
    pub salt: [u8; 32],
}

impl SettingsUpgradeTxs {
    /// The four envelopes in submission order, with step names.
    pub fn in_order(&self) -> [(&'static str, &TransactionEnvelope); 4] {
        [
            ("restore", &self.restore),
            ("upload", &self.upload),
            ("create", &self.create),
            ("invoke", &self.invoke),
        ]
    }

    /// The key as base64 XDR, the form the `upgrades` endpoint takes.
    pub fn key_base64(&self) -> Result<String> {
        Ok(self.key.to_xdr_base64(Limits::none())?)
    }
}

/// The contract ID of a contract created from `deployer` with `salt` on `passphrase`.
pub fn contract_id_from_address(
    passphrase: &str,
    deployer: &Keypair,
    salt: [u8; 32],
) -> Result<[u8; 32]> {
    contract_id(passphrase, from_address(deployer, salt))
}

/// `sha256(HashIdPreimage::ContractId{network ID, preimage})`.
pub fn contract_id(passphrase: &str, preimage: ContractIdPreimage) -> Result<[u8; 32]> {
    let full = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(network_id(passphrase)),
        contract_id_preimage: preimage,
    });
    Ok(sha256(&full.to_xdr(Limits::none())?))
}

fn from_address(deployer: &Keypair, salt: [u8; 32]) -> ContractIdPreimage {
    ContractIdPreimage::Address(ContractIdPreimageFromAddress {
        address: ScAddress::Account(deployer.account_id()),
        salt: Uint256(salt),
    })
}

/// The persistent instance key of contract `id`.
pub fn contract_instance_key(id: [u8; 32]) -> LedgerKey {
    LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(ContractId(Hash(id))),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    })
}

/// Resources and fees of one settings transaction, as core sets them.
struct Budget {
    instructions: u32,
    disk_read_bytes: u32,
    write_bytes: u32,
    resource_fee: i64,
    inclusion_fee: i64,
}

/// A Soroban transaction with core's field layout: one operation, no memo, no preconditions,
/// `fee = inclusion + resource fee`.
fn soroban_tx(
    root: &Keypair,
    seq: i64,
    body: OperationBody,
    read_only: Vec<LedgerKey>,
    read_write: Vec<LedgerKey>,
    b: Budget,
) -> Result<Transaction> {
    let fee = u32::try_from(b.inclusion_fee + b.resource_fee).context("fee fits u32")?;
    Ok(Transaction {
        source_account: root.muxed_account(),
        fee,
        seq_num: SequenceNumber(seq),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body,
        }]
        .try_into()?,
        ext: TransactionExt::V1(SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: read_only.try_into()?,
                    read_write: read_write.try_into()?,
                },
                instructions: b.instructions,
                disk_read_bytes: b.disk_read_bytes,
                write_bytes: b.write_bytes,
            },
            resource_fee: b.resource_fee,
        }),
    })
}

fn invoke(
    host_function: HostFunction,
    auth: Vec<SorobanAuthorizationEntry>,
) -> Result<OperationBody> {
    Ok(OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
        host_function,
        auth: auth.try_into()?,
    }))
}

/// Build and sign (by `root`) the four settings-upgrade transactions. `seq` is root's current sequence
/// number; the transactions use `seq + 1` to `seq + 4`. `wasm` is the upgrade contract
/// ([`super::settings::upgrade_contract_wasm`]); `upgrade_set` the XDR `ConfigUpgradeSet`.
pub fn settings_upgrade_txs(
    passphrase: &str,
    root: &Keypair,
    seq: i64,
    wasm: &[u8],
    upgrade_set: &[u8],
    salt: [u8; 32],
) -> Result<SettingsUpgradeTxs> {
    // Core decodes the set and re-encodes it; canonical XDR makes that the same bytes, which we check.
    let set = ConfigUpgradeSet::from_xdr(
        upgrade_set,
        stellar_xdr::Limits {
            depth: 100,
            len: upgrade_set.len(),
        },
    )
    .context("decode ConfigUpgradeSet")?;
    let set_bytes = set.to_xdr(Limits::none())?;
    anyhow::ensure!(
        set_bytes == upgrade_set,
        "ConfigUpgradeSet bytes are not canonical XDR"
    );

    let wasm_hash = sha256(wasm);
    let code_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: Hash(wasm_hash),
    });

    let restore = soroban_tx(
        root,
        seq + 1,
        OperationBody::RestoreFootprint(RestoreFootprintOp {
            ext: ExtensionPoint::V0,
        }),
        vec![],
        vec![code_key.clone()],
        Budget {
            instructions: 0,
            disk_read_bytes: 2000,
            write_bytes: 2000,
            resource_fee: 55_000_000,
            inclusion_fee: 100_000_000,
        },
    )?;

    let upload = soroban_tx(
        root,
        seq + 2,
        invoke(
            HostFunction::UploadContractWasm(wasm.to_vec().try_into()?),
            vec![],
        )?,
        vec![],
        vec![code_key.clone()],
        Budget {
            instructions: 2_000_000,
            disk_read_bytes: 2000,
            write_bytes: 2000,
            resource_fee: 55_000_000,
            inclusion_fee: 100_000_000,
        },
    )?;

    let preimage = from_address(root, salt);
    let id = contract_id(passphrase, preimage.clone())?;
    let instance_key = contract_instance_key(id);
    let create_args = CreateContractArgs {
        contract_id_preimage: preimage,
        executable: ContractExecutable::Wasm(Hash(wasm_hash)),
    };
    let auth = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::CreateContractHostFn(create_args.clone()),
            sub_invocations: vec![].try_into()?,
        },
    };
    let create = soroban_tx(
        root,
        seq + 3,
        invoke(HostFunction::CreateContract(create_args), vec![auth])?,
        vec![code_key.clone()],
        vec![instance_key.clone()],
        Budget {
            instructions: 2_000_000,
            disk_read_bytes: 2000,
            write_bytes: 120,
            resource_fee: 15_000_000,
            inclusion_fee: 25_000_000,
        },
    )?;

    let content_hash = sha256(&set_bytes);
    let contract = ScAddress::Contract(ContractId(Hash(id)));
    let upgrade_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: contract.clone(),
        key: ScVal::Bytes(ScBytes(content_hash.to_vec().try_into()?)),
        durability: ContractDataDurability::Temporary,
    });
    let write_bytes = u32::try_from(set_bytes.len() + 200).context("upgrade set size")?;
    let disk_read = u32::try_from(wasm.len() + 300).context("wasm size")?;
    let invoke_tx = soroban_tx(
        root,
        seq + 4,
        invoke(
            HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: contract,
                function_name: ScSymbol("write".try_into()?),
                args: vec![ScVal::Bytes(ScBytes(set_bytes.try_into()?))].try_into()?,
            }),
            vec![],
        )?,
        vec![instance_key, code_key],
        vec![upgrade_key],
        Budget {
            instructions: 2_000_000,
            disk_read_bytes: disk_read,
            write_bytes,
            resource_fee: 95_000_000,
            inclusion_fee: 100_000_000,
        },
    )?;

    let sign = |tx| sign_transaction(passphrase, tx, &[root]);
    Ok(SettingsUpgradeTxs {
        restore: sign(restore)?,
        upload: sign(upload)?,
        create: sign(create)?,
        invoke: sign(invoke_tx)?,
        key: ConfigUpgradeSetKey {
            contract_id: ContractId(Hash(id)),
            content_hash: Hash(content_hash),
        },
        contract_id: id,
        salt,
    })
}
