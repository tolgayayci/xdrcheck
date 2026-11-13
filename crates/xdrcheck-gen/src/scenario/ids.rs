//! Contract IDs, computed as the host computes them: `sha256` of the XDR of
//! `HashIdPreimage::ContractId { network_id, contract_id_preimage }`.
//!
//! - Stellar Asset Contract: preimage `ContractIdPreimage::Asset(asset)`.
//! - Deployed contract: preimage `ContractIdPreimage::Address { address, salt }`, where the
//!   deployer address is an `ScAddress` and the salt 32 bytes. Scenarios name no salt, so the
//!   interpreter uses [`contract_salt`] — `sha256("<namespace>/contract-salt/<name>")` — which the
//!   deploying side must use too, or inject the real ID instead.

use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, Asset, ContractIdPreimage, ContractIdPreimageFromAddress, Hash, HashIdPreimage,
    HashIdPreimageContractId, PublicKey, ScAddress, Type, Uint256,
};

use super::Result;

fn contract_id(network_id: &[u8; 32], preimage: ContractIdPreimage) -> Result<[u8; 32]> {
    let value = Type::HashIdPreimage(Box::new(HashIdPreimage::ContractId(
        HashIdPreimageContractId {
            network_id: Hash(*network_id),
            contract_id_preimage: preimage,
        },
    )));
    let bytes = xdrcheck_xdr::encode(&value, &xdrcheck_xdr::Limits::default())?;
    Ok(Sha256::digest(&bytes).into())
}

/// The Stellar Asset Contract ID of `asset` on the network with this ID.
pub fn sac_contract_id(network_id: &[u8; 32], asset: &Asset) -> Result<[u8; 32]> {
    contract_id(network_id, ContractIdPreimage::Asset(asset.clone()))
}

/// The `C…` strkey of the Stellar Asset Contract of `asset`.
pub fn sac_contract_strkey(network_id: &[u8; 32], asset: &Asset) -> Result<String> {
    Ok(format!(
        "{}",
        stellar_strkey::Contract(sac_contract_id(network_id, asset)?)
    ))
}

/// The ID of a contract deployed by the account `deployer` (raw ed25519 key) with `salt`.
pub fn contract_id_from_address(
    network_id: &[u8; 32],
    deployer: &[u8; 32],
    salt: &[u8; 32],
) -> Result<[u8; 32]> {
    contract_id(
        network_id,
        ContractIdPreimage::Address(ContractIdPreimageFromAddress {
            address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                *deployer,
            )))),
            salt: Uint256(*salt),
        }),
    )
}

/// The deterministic deploy salt of contract `name`: `sha256("<namespace>/contract-salt/<name>")`.
pub fn contract_salt(namespace: &str, name: &str) -> [u8; 32] {
    Sha256::digest(format!("{namespace}/contract-salt/{name}").as_bytes()).into()
}
