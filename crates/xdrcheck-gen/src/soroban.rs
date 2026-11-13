//! Soroban support, part 1: Stellar Asset Contract deploys and calls with declared footprints
//! and generous fixed resources — the route the local-core probes executed, with no simulation.
//!
//! - [`Sac`]: an asset's contract ID on a network and its storage layout: the instance key, the holder
//!   balance keys (an account's trustline, or the account itself for the native asset; a contract's
//!   persistent `Balance(Address)` entry), and the temporary `Allowance({from, spender})` entry.
//! - [`SacCall`] → [`Invocation`]: function name, arguments, the declared footprint, and a
//!   source-account authorization entry for the address that must authorize.
//! - [`host_function_tx`], [`invoke_tx`], [`deploy_sac_tx`]: unsigned transactions with
//!   [`Resources::GENEROUS`] by default. Resources are generator-chosen, not simulated; the surplus
//!   resource fee is refunded in the meta.
//! - [`TxOutcome`]: a transaction's result and `TransactionMeta` read back from a [`ClosedLedger`]
//!   (operation changes and events, transaction-level events, return value).
//! - [`execute`], [`deploy_sac`], [`call_sac`]: sign, submit, close and read the outcome in one call;
//!   [`run_deploy_sac`] executes a scenario's `deploy_sac` setup item for the interpreter.
//! - [`contract`] (part 2): wasm upload, `CREATE_CONTRACT_V2` deploys with constructor
//!   arguments under `sha256("xcc/contract-salt/<name>")`, custom-contract calls, CAP-0071 delegated
//!   authorization, and the `deploy_contract` setup item. Their footprints and resources come from
//!   [`sim`], offline simulation with the pinned host against the node's own ledger state.
//!
//! Footprints follow the probes: every SAC call reads the instance and (for an issued asset) the issuer
//! account; `trust` writes the trustline and the trusting account (its sub-entry count changes);
//! `mint` writes the recipient's balance; `transfer` writes both balances; `approve` writes the
//! allowance; `balance` reads the holder's balance. Muxed addresses (`M…`, `W…`) hold their balance in
//! the underlying account or contract.

pub mod contract;
pub mod sim;

use anyhow::{anyhow, bail, Context, Result};
use stellar_xdr::{
    AccountId, Asset, ContractDataDurability, ContractEvent, ContractExecutable, ContractId,
    ContractIdPreimage, CreateContractArgs, Hash, HostFunction, Int128Parts, InvokeContractArgs,
    InvokeHostFunctionOp, LedgerCloseMeta, LedgerEntryChange, LedgerFootprint, LedgerKey,
    LedgerKeyAccount, LedgerKeyContractData, LedgerKeyTrustLine, Memo, MuxedAccount, Operation,
    OperationBody, Preconditions, PublicKey, ScAddress, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec,
    SequenceNumber, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanResources, SorobanTransactionData,
    SorobanTransactionDataExt, Transaction, TransactionEvent, TransactionExt, TransactionMeta,
    TransactionResult, TransactionResultResult, TrustLineAsset, Uint256,
};

use crate::core::{sign_transaction, ClosedLedger, Keypair, Node};
use crate::scenario::{Interpreter, SetupAction};
use crate::upgrade::{contract_id, contract_instance_key};

/// Declared Soroban resources of one transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resources {
    /// CPU instructions.
    pub instructions: u32,
    /// Bytes read from disk.
    pub disk_read_bytes: u32,
    /// Bytes written.
    pub write_bytes: u32,
    /// Resource fee in stroops (the unused part is refunded).
    pub resource_fee: i64,
}

impl Resources {
    /// The probes' constants: 50,000,000 instructions, 20,000 bytes read and written, 5 XLM resource fee.
    /// Enough for every SAC call at Protocols 26–30 with the vendored settings.
    pub const GENEROUS: Resources = Resources {
        instructions: 50_000_000,
        disk_read_bytes: 20_000,
        write_bytes: 20_000,
        resource_fee: 50_000_000,
    };
}

impl Default for Resources {
    fn default() -> Self {
        Resources::GENEROUS
    }
}

/// `ScVal::I128`.
pub fn i128_val(n: i128) -> ScVal {
    ScVal::I128(Int128Parts {
        hi: (n >> 64) as i64,
        lo: n as u64,
    })
}

/// `ScVal::Symbol`.
pub fn symbol(s: &str) -> Result<ScVal> {
    Ok(ScVal::Symbol(ScSymbol(
        s.try_into().map_err(|_| anyhow!("{s:?} is not a symbol"))?,
    )))
}

/// The account (`G…`) address of a key.
pub fn account_address(key: &Keypair) -> ScAddress {
    ScAddress::Account(key.account_id())
}

/// The account a muxed or plain account address stands for, or `None` for contract addresses.
fn underlying_account(addr: &ScAddress) -> Option<AccountId> {
    match addr {
        ScAddress::Account(a) => Some(a.clone()),
        ScAddress::MuxedAccount(m) => Some(AccountId(PublicKey::PublicKeyTypeEd25519(
            m.ed25519.clone(),
        ))),
        _ => None,
    }
}

/// The contract a contract or muxed contract address stands for.
fn underlying_contract(addr: &ScAddress) -> Option<ContractId> {
    match addr {
        ScAddress::Contract(c) => Some(c.clone()),
        ScAddress::MuxedContract(m) => Some(m.contract_id.clone()),
        _ => None,
    }
}

fn account_key(account: AccountId) -> LedgerKey {
    LedgerKey::Account(LedgerKeyAccount {
        account_id: account,
    })
}

/// A Stellar Asset Contract on one network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sac {
    /// The asset.
    pub asset: Asset,
    /// `sha256(HashIdPreimage::ContractId{network ID, FromAsset(asset)})`.
    pub contract_id: [u8; 32],
}

/// A call to a SAC function.
#[derive(Debug, Clone)]
pub enum SacCall {
    /// `trust(addr)`: create `addr`'s trustline if it has none (CAP-0073). Authorized by `addr`.
    Trust {
        /// The account to trust the asset.
        addr: ScAddress,
    },
    /// `mint(to, amount)`. Authorized by the admin (the issuer).
    Mint {
        /// Recipient.
        to: ScAddress,
        /// Amount in stroops.
        amount: i128,
    },
    /// `transfer(from, to, amount)`; `to` may be muxed (`M…`, and `W…` from Protocol 30).
    Transfer {
        /// Sender; authorizes.
        from: ScAddress,
        /// Recipient.
        to: ScAddress,
        /// Amount in stroops.
        amount: i128,
    },
    /// `approve(from, spender, amount, live_until_ledger)`. Authorized by `from`.
    Approve {
        /// Owner of the balance.
        from: ScAddress,
        /// Who may spend it.
        spender: ScAddress,
        /// Allowance.
        amount: i128,
        /// Last ledger the allowance is live.
        live_until_ledger: u32,
    },
    /// `balance(id)`: read-only.
    Balance {
        /// Holder.
        id: ScAddress,
    },
}

/// A contract invocation ready to put into a transaction.
#[derive(Debug, Clone)]
pub struct Invocation {
    /// The contract.
    pub contract: ScAddress,
    /// Function name.
    pub function: String,
    /// Arguments.
    pub args: Vec<ScVal>,
    /// Declared footprint.
    pub footprint: LedgerFootprint,
    /// The address whose authorization the call needs, if any.
    pub authorizer: Option<ScAddress>,
}

impl Invocation {
    /// The authorized invocation tree of this call (root only, no sub-invocations).
    pub fn authorized_invocation(&self) -> Result<SorobanAuthorizedInvocation> {
        Ok(SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(self.contract_args()?),
            sub_invocations: vec![].try_into()?,
        })
    }

    /// Authorization entries when the authorizer is the transaction's source account: one
    /// `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT` entry, or none when no authorization is needed.
    pub fn source_account_auth(&self) -> Result<Vec<SorobanAuthorizationEntry>> {
        Ok(match self.authorizer {
            None => vec![],
            Some(_) => vec![SorobanAuthorizationEntry {
                credentials: SorobanCredentials::SourceAccount,
                root_invocation: self.authorized_invocation()?,
            }],
        })
    }

    /// The `InvokeContractArgs`.
    pub fn contract_args(&self) -> Result<InvokeContractArgs> {
        Ok(InvokeContractArgs {
            contract_address: self.contract.clone(),
            function_name: ScSymbol(
                self.function
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow!("{:?} is not a symbol", self.function))?,
            ),
            args: self.args.clone().try_into()?,
        })
    }
}

impl Sac {
    /// The SAC of `asset` on `passphrase`.
    pub fn new(passphrase: &str, asset: Asset) -> Result<Sac> {
        let contract_id = contract_id(passphrase, ContractIdPreimage::Asset(asset.clone()))?;
        Ok(Sac { asset, contract_id })
    }

    /// The SAC of an asset given as SEP-51 JSON (as the scenario interpreter resolves `${asset.NAME}`).
    pub fn from_asset_json(passphrase: &str, asset: &serde_json::Value) -> Result<Sac> {
        let asset: Asset = serde_json::from_value(asset.clone())
            .with_context(|| format!("not a SEP-51 Asset: {asset}"))?;
        Sac::new(passphrase, asset)
    }

    /// The contract address.
    pub fn address(&self) -> ScAddress {
        ScAddress::Contract(ContractId(Hash(self.contract_id)))
    }

    /// The `C…` strkey.
    pub fn strkey(&self) -> String {
        format!("{}", stellar_strkey::Contract(self.contract_id))
    }

    /// The persistent instance entry.
    pub fn instance_key(&self) -> LedgerKey {
        contract_instance_key(self.contract_id)
    }

    /// The issuer's account entry (`None` for the native asset).
    pub fn issuer_key(&self) -> Option<LedgerKey> {
        match &self.asset {
            Asset::Native => None,
            Asset::CreditAlphanum4(a) => Some(account_key(a.issuer.clone())),
            Asset::CreditAlphanum12(a) => Some(account_key(a.issuer.clone())),
        }
    }

    fn trustline_asset(&self) -> TrustLineAsset {
        match &self.asset {
            Asset::Native => TrustLineAsset::Native,
            Asset::CreditAlphanum4(a) => TrustLineAsset::CreditAlphanum4(a.clone()),
            Asset::CreditAlphanum12(a) => TrustLineAsset::CreditAlphanum12(a.clone()),
        }
    }

    /// The trustline of `account` for this asset.
    pub fn trustline_key(&self, account: AccountId) -> LedgerKey {
        LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: account,
            asset: self.trustline_asset(),
        })
    }

    /// Where `holder`'s balance lives: an account's trustline (its account entry for the native
    /// asset), or a contract's persistent `Balance(Address)` entry in this SAC. Muxed addresses use
    /// their underlying account or contract.
    pub fn balance_key(&self, holder: &ScAddress) -> Result<LedgerKey> {
        if let Some(account) = underlying_account(holder) {
            return Ok(match self.asset {
                Asset::Native => account_key(account),
                _ => self.trustline_key(account),
            });
        }
        let contract = underlying_contract(holder)
            .ok_or_else(|| anyhow!("a SAC balance cannot be held by {holder:?}"))?;
        self.data_key(
            ScVal::Vec(Some(ScVec(
                vec![
                    symbol("Balance")?,
                    ScVal::Address(ScAddress::Contract(contract)),
                ]
                .try_into()?,
            ))),
            ContractDataDurability::Persistent,
        )
    }

    /// The temporary `Allowance({from, spender})` entry.
    pub fn allowance_key(&self, from: &ScAddress, spender: &ScAddress) -> Result<LedgerKey> {
        // A `#[contracttype]` struct is a map keyed by field-name symbols, in sorted order.
        let map = ScMap(
            vec![
                ScMapEntry {
                    key: symbol("from")?,
                    val: ScVal::Address(from.clone()),
                },
                ScMapEntry {
                    key: symbol("spender")?,
                    val: ScVal::Address(spender.clone()),
                },
            ]
            .try_into()?,
        );
        self.data_key(
            ScVal::Vec(Some(ScVec(
                vec![symbol("Allowance")?, ScVal::Map(Some(map))].try_into()?,
            ))),
            ContractDataDurability::Temporary,
        )
    }

    fn data_key(&self, key: ScVal, durability: ContractDataDurability) -> Result<LedgerKey> {
        Ok(LedgerKey::ContractData(LedgerKeyContractData {
            contract: self.address(),
            key,
            durability,
        }))
    }

    /// The deploy footprint: reads the issuer, writes the instance.
    pub fn deploy_footprint(&self) -> Result<LedgerFootprint> {
        footprint(
            self.issuer_key().into_iter().collect(),
            vec![self.instance_key()],
        )
    }

    /// The invocation for `call`, with its declared footprint.
    pub fn invocation(&self, call: &SacCall) -> Result<Invocation> {
        let mut read_only = vec![self.instance_key()];
        read_only.extend(self.issuer_key());
        let addr = |a: &ScAddress| ScVal::Address(a.clone());
        let (function, args, read_write, authorizer) = match call {
            SacCall::Trust { addr: a } => {
                let account = underlying_account(a)
                    .ok_or_else(|| anyhow!("trust takes an account address, not {a:?}"))?;
                let rw = vec![self.balance_key(a)?, account_key(account)];
                ("trust", vec![addr(a)], rw, Some(a.clone()))
            }
            SacCall::Mint { to, amount } => {
                let admin = match &self.asset {
                    Asset::Native => bail!("the native asset cannot be minted"),
                    Asset::CreditAlphanum4(a) => a.issuer.clone(),
                    Asset::CreditAlphanum12(a) => a.issuer.clone(),
                };
                let rw = vec![self.balance_key(to)?];
                (
                    "mint",
                    vec![addr(to), i128_val(*amount)],
                    rw,
                    Some(ScAddress::Account(admin)),
                )
            }
            SacCall::Transfer { from, to, amount } => {
                let mut rw = vec![self.balance_key(from)?];
                let to_key = self.balance_key(to)?;
                if !rw.contains(&to_key) {
                    rw.push(to_key);
                }
                (
                    "transfer",
                    vec![addr(from), addr(to), i128_val(*amount)],
                    rw,
                    Some(from.clone()),
                )
            }
            SacCall::Approve {
                from,
                spender,
                amount,
                live_until_ledger,
            } => (
                "approve",
                vec![
                    addr(from),
                    addr(spender),
                    i128_val(*amount),
                    ScVal::U32(*live_until_ledger),
                ],
                vec![self.allowance_key(from, spender)?],
                Some(from.clone()),
            ),
            SacCall::Balance { id } => {
                read_only.push(self.balance_key(id)?);
                ("balance", vec![addr(id)], vec![], None)
            }
        };
        Ok(Invocation {
            contract: self.address(),
            function: function.to_string(),
            args,
            footprint: footprint(read_only, read_write)?,
            authorizer,
        })
    }
}

fn footprint(read_only: Vec<LedgerKey>, read_write: Vec<LedgerKey>) -> Result<LedgerFootprint> {
    Ok(LedgerFootprint {
        read_only: read_only.try_into()?,
        read_write: read_write.try_into()?,
    })
}

/// An unsigned one-operation `InvokeHostFunction` transaction: no memo, no preconditions,
/// `fee = inclusion_fee + resources.resource_fee`.
pub fn host_function_tx(
    source: MuxedAccount,
    seq: i64,
    inclusion_fee: u32,
    host_function: HostFunction,
    auth: Vec<SorobanAuthorizationEntry>,
    footprint: LedgerFootprint,
    resources: Resources,
) -> Result<Transaction> {
    let fee = u32::try_from(i64::from(inclusion_fee) + resources.resource_fee)
        .context("inclusion fee plus resource fee fits u32")?;
    Ok(Transaction {
        source_account: source,
        fee,
        seq_num: SequenceNumber(seq),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function,
                auth: auth.try_into()?,
            }),
        }]
        .try_into()?,
        ext: TransactionExt::V1(SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint,
                instructions: resources.instructions,
                disk_read_bytes: resources.disk_read_bytes,
                write_bytes: resources.write_bytes,
            },
            resource_fee: resources.resource_fee,
        }),
    })
}

/// An unsigned transaction invoking `invocation` with `auth` (for example
/// [`Invocation::source_account_auth`], or address credentials the caller signed).
pub fn invoke_tx(
    source: MuxedAccount,
    seq: i64,
    inclusion_fee: u32,
    invocation: &Invocation,
    auth: Vec<SorobanAuthorizationEntry>,
    resources: Resources,
) -> Result<Transaction> {
    host_function_tx(
        source,
        seq,
        inclusion_fee,
        HostFunction::InvokeContract(invocation.contract_args()?),
        auth,
        invocation.footprint.clone(),
        resources,
    )
}

/// An unsigned transaction deploying `sac` (no authorization needed for an asset preimage).
pub fn deploy_sac_tx(
    source: MuxedAccount,
    seq: i64,
    inclusion_fee: u32,
    sac: &Sac,
    resources: Resources,
) -> Result<Transaction> {
    host_function_tx(
        source,
        seq,
        inclusion_fee,
        HostFunction::CreateContract(CreateContractArgs {
            contract_id_preimage: ContractIdPreimage::Asset(sac.asset.clone()),
            executable: ContractExecutable::StellarAsset,
        }),
        vec![],
        sac.deploy_footprint()?,
        resources,
    )
}

/// A transaction's result and meta as one closed ledger recorded them.
#[derive(Debug, Clone)]
pub struct TxOutcome {
    /// Transaction hash.
    pub hash: [u8; 32],
    /// Ledger sequence.
    pub ledger: u32,
    /// The result.
    pub result: TransactionResult,
    /// The apply meta.
    pub meta: TransactionMeta,
}

impl TxOutcome {
    /// Find transaction `hash` in `ledger`.
    pub fn read(ledger: &ClosedLedger, hash: &[u8; 32]) -> Result<TxOutcome> {
        let pairs: Vec<_> = match ledger.decode()? {
            LedgerCloseMeta::V0(m) => m
                .tx_processing
                .iter()
                .map(|t| (t.result.clone(), t.tx_apply_processing.clone()))
                .collect(),
            LedgerCloseMeta::V1(m) => m
                .tx_processing
                .iter()
                .map(|t| (t.result.clone(), t.tx_apply_processing.clone()))
                .collect(),
            LedgerCloseMeta::V2(m) => m
                .tx_processing
                .iter()
                .map(|t| (t.result.clone(), t.tx_apply_processing.clone()))
                .collect(),
        };
        let (pair, meta) = pairs
            .into_iter()
            .find(|(p, _)| p.transaction_hash.0 == *hash)
            .ok_or_else(|| {
                anyhow!(
                    "transaction {} is not in ledger {}",
                    hex::encode(hash),
                    ledger.sequence
                )
            })?;
        Ok(TxOutcome {
            hash: *hash,
            ledger: ledger.sequence,
            result: pair.result,
            meta,
        })
    }

    /// `txSUCCESS`.
    pub fn succeeded(&self) -> bool {
        matches!(self.result.result, TransactionResultResult::TxSuccess(_))
    }

    /// The meta version (0–4).
    pub fn meta_version(&self) -> u32 {
        match self.meta {
            TransactionMeta::V0(_) => 0,
            TransactionMeta::V1(_) => 1,
            TransactionMeta::V2(_) => 2,
            TransactionMeta::V3(_) => 3,
            TransactionMeta::V4(_) => 4,
        }
    }

    /// Ledger entry changes of operation `op`.
    pub fn op_changes(&self, op: usize) -> Vec<LedgerEntryChange> {
        let changes = match &self.meta {
            TransactionMeta::V0(ops) => ops.get(op).map(|o| &o.changes),
            TransactionMeta::V1(m) => m.operations.get(op).map(|o| &o.changes),
            TransactionMeta::V2(m) => m.operations.get(op).map(|o| &o.changes),
            TransactionMeta::V3(m) => m.operations.get(op).map(|o| &o.changes),
            TransactionMeta::V4(m) => m.operations.get(op).map(|o| &o.changes),
        };
        changes.map(|c| c.0.to_vec()).unwrap_or_default()
    }

    /// Contract events of operation `op` (TransactionMeta v4 keeps them per operation; v3 keeps the
    /// Soroban operation's events in `soroban_meta`).
    pub fn op_events(&self, op: usize) -> Vec<ContractEvent> {
        match &self.meta {
            TransactionMeta::V4(m) => m
                .operations
                .get(op)
                .map(|o| o.events.to_vec())
                .unwrap_or_default(),
            TransactionMeta::V3(m) if op == 0 => m
                .soroban_meta
                .as_ref()
                .map(|s| s.events.to_vec())
                .unwrap_or_default(),
            _ => vec![],
        }
    }

    /// Transaction-level events (fee events; TransactionMeta v4 only).
    pub fn tx_events(&self) -> Vec<TransactionEvent> {
        match &self.meta {
            TransactionMeta::V4(m) => m.events.to_vec(),
            _ => vec![],
        }
    }

    /// The Soroban return value.
    pub fn return_value(&self) -> Option<ScVal> {
        match &self.meta {
            TransactionMeta::V4(m) => m.soroban_meta.as_ref().and_then(|s| s.return_value.clone()),
            TransactionMeta::V3(m) => m.soroban_meta.as_ref().map(|s| s.return_value.clone()),
            _ => None,
        }
    }
}

/// Sign `tx` with `signers`, submit it (it must be `PENDING`), close the ledger and read its outcome.
pub fn execute(
    node: &mut Node,
    tx: Transaction,
    signers: &[&Keypair],
) -> Result<(TxOutcome, ClosedLedger)> {
    let env = sign_transaction(node.passphrase(), tx, signers)?;
    let hash = node.submit_pending(&env)?;
    let ledger = node.close()?;
    Ok((TxOutcome::read(&ledger, &hash)?, ledger))
}

/// Deploy the SAC of `asset` from `source` (sequence read from the node) in its own ledger and require
/// success.
pub fn deploy_sac(
    node: &mut Node,
    source: &Keypair,
    asset: Asset,
    inclusion_fee: u32,
) -> Result<(Sac, TxOutcome)> {
    let sac = Sac::new(node.passphrase(), asset)?;
    let seq = next_seq(node, source)?;
    let tx = deploy_sac_tx(
        source.muxed_account(),
        seq,
        inclusion_fee,
        &sac,
        Resources::GENEROUS,
    )?;
    let (out, _) = execute(node, tx, &[source])?;
    if !out.succeeded() {
        bail!("deploying {} failed: {:?}", sac.strkey(), out.result.result);
    }
    Ok((sac, out))
}

/// Call `sac` from `source` (sequence read from the node), authorizing with source-account
/// credentials, in its own ledger. The outcome is returned whether or not it succeeded.
pub fn call_sac(
    node: &mut Node,
    source: &Keypair,
    sac: &Sac,
    call: &SacCall,
    inclusion_fee: u32,
) -> Result<TxOutcome> {
    let inv = sac.invocation(call)?;
    let seq = next_seq(node, source)?;
    let tx = invoke_tx(
        source.muxed_account(),
        seq,
        inclusion_fee,
        &inv,
        inv.source_account_auth()?,
        Resources::GENEROUS,
    )?;
    Ok(execute(node, tx, &[source])?.0)
}

/// Execute a scenario's `deploy_sac` setup item ([`SetupAction::DeploySac`]): deploy from root in the
/// ledger the interpreter planned, check the contract ID is the one the interpreter resolved for
/// `${contract.sac(NAME)}`, and hand root's new sequence number back to the interpreter.
pub fn run_deploy_sac(
    node: &mut Node,
    interpreter: &mut Interpreter<'_>,
    action: &SetupAction,
    inclusion_fee: u32,
) -> Result<(Sac, TxOutcome)> {
    let SetupAction::DeploySac {
        asset_name,
        asset,
        contract_id,
    } = action
    else {
        bail!("run_deploy_sac takes a deploy_sac setup item, not {action:?}");
    };
    let sac = Sac::from_asset_json(node.passphrase(), asset)?;
    if sac.strkey() != *contract_id {
        bail!(
            "the SAC of {asset_name} is {}, but the scenario resolved {contract_id}",
            sac.strkey()
        );
    }
    let root = Keypair::root(node.passphrase());
    let seq = next_seq(node, &root)?;
    let (sac, out) = deploy_sac(node, &root, sac.asset, inclusion_fee)?;
    interpreter.set_root_sequence(seq);
    Ok((sac, out))
}

/// `source`'s next sequence number, from the node.
pub fn next_seq(node: &mut Node, source: &Keypair) -> Result<i64> {
    let seq = node
        .account_sequence(&source.account_id())?
        .ok_or_else(|| anyhow!("account {} does not exist", source.address()))?;
    Ok(seq + 1)
}

/// The `MuxedEd25519Account` address `M…` of `key` with `id`.
pub fn muxed_account_address(key: &Keypair, id: u64) -> ScAddress {
    ScAddress::MuxedAccount(stellar_xdr::MuxedEd25519Account {
        id,
        ed25519: Uint256(key.public_key()),
    })
}

/// The muxed contract address `W…` of contract `contract_id` with `id` (Protocol 30, CAP-0084).
pub fn muxed_contract_address(contract_id: [u8; 32], id: u64) -> ScAddress {
    ScAddress::MuxedContract(stellar_xdr::MuxedContract {
        id,
        contract_id: ContractId(Hash(contract_id)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::TESTNET_PASSPHRASE;
    use stellar_xdr::{AlphaNum4, AssetCode4};

    fn usdc(issuer: &Keypair) -> Asset {
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USDC"),
            issuer: issuer.account_id(),
        })
    }

    #[test]
    fn native_sac_address_matches_the_known_testnet_one() {
        // The native SAC on testnet is CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC.
        let sac = Sac::new(TESTNET_PASSPHRASE, Asset::Native).unwrap();
        assert_eq!(
            sac.strkey(),
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"
        );
    }

    #[test]
    fn i128_round_trips_through_parts() {
        for n in [0i128, 1, -1, i128::MAX, i128::MIN, 1 << 64] {
            let ScVal::I128(p) = i128_val(n) else {
                panic!()
            };
            assert_eq!((i128::from(p.hi) << 64) | i128::from(p.lo), n);
        }
    }

    #[test]
    fn footprints_follow_the_sac_layout() {
        let issuer = Keypair::from_label("issuer");
        let b = Keypair::from_label("b");
        let sac = Sac::new(TESTNET_PASSPHRASE, usdc(&issuer)).unwrap();
        let trust = sac
            .invocation(&SacCall::Trust {
                addr: account_address(&b),
            })
            .unwrap();
        assert_eq!(trust.footprint.read_only.len(), 2);
        assert_eq!(
            trust.footprint.read_write.to_vec(),
            vec![
                sac.trustline_key(b.account_id()),
                account_key(b.account_id())
            ]
        );
        // A muxed destination's balance is its account's trustline; W… is the contract's Balance entry.
        let to = muxed_account_address(&b, 42);
        assert_eq!(
            sac.balance_key(&to).unwrap(),
            sac.trustline_key(b.account_id())
        );
        let w = muxed_contract_address([7; 32], 9);
        let LedgerKey::ContractData(k) = sac.balance_key(&w).unwrap() else {
            panic!()
        };
        assert_eq!(k.durability, ContractDataDurability::Persistent);
        assert_eq!(
            k.key,
            ScVal::Vec(Some(ScVec(
                vec![
                    symbol("Balance").unwrap(),
                    ScVal::Address(ScAddress::Contract(ContractId(Hash([7; 32]))))
                ]
                .try_into()
                .unwrap()
            )))
        );
        // Native balances are account entries; native cannot be minted.
        let native = Sac::new(TESTNET_PASSPHRASE, Asset::Native).unwrap();
        assert_eq!(
            native.balance_key(&account_address(&b)).unwrap(),
            account_key(b.account_id())
        );
        assert!(native
            .invocation(&SacCall::Mint {
                to: account_address(&b),
                amount: 1
            })
            .is_err());
    }
}
