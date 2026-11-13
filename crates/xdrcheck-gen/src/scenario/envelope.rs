//! Hashing, signing and wrapping transactions.
//!
//! The hash signed is `sha256(XDR(TransactionSignaturePayload { network_id, tagged_transaction }))`
//! (`ENVELOPE_TYPE_TX` for a transaction, `ENVELOPE_TYPE_TX_FEE_BUMP` for a fee bump). Each
//! signer specification becomes one `DecoratedSignature` the way stellar-core v30.0.0 checks it
//! (`src/transactions/SignatureUtils.cpp`; fields VF-07 and VF-08):
//!
//! | Spec | `signature` | `hint` |
//! |---|---|---|
//! | `{key: L}` | ed25519 of L over the hash | last 4 bytes of L's public key |
//! | `{signed_payload: {key: L, payload_hex: H}}` | ed25519 of L over the payload bytes | key hint XOR payload hint |
//! | `{hash_x: H}` | the preimage bytes (0–64) | last 4 bytes of `sha256(preimage)` |
//! | `{pre_auth: true}` | none — the hash itself is a pre-authorised signer | — |
//!
//! The payload hint is core's `getHint`: the last 4 bytes of the payload, or, for a payload
//! shorter than 4 bytes, its bytes at the start of a zeroed hint.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    BytesM, DecoratedSignature, FeeBumpTransaction, FeeBumpTransactionEnvelope, Signature,
    SignatureHint, Transaction, TransactionEnvelope, TransactionV1Envelope, Type, VecM, WriteXdr,
};

use super::file::SignerSpec;
use super::keys::Keys;
use super::{Error, Result};

/// A signed envelope ready to submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEnvelope {
    pub envelope: TransactionEnvelope,
    /// XDR bytes of the envelope.
    pub bytes: Vec<u8>,
    /// Base64 of [`Self::bytes`] (what core's HTTP `tx` endpoint takes).
    pub base64: String,
    /// The transaction hash under the passphrase (the fee-bump hash for a fee bump).
    pub hash: [u8; 32],
    /// `T…` signers the specifications declared pre-authorised (the hash itself).
    pub pre_authorised: Vec<String>,
}

impl SignedEnvelope {
    /// The hash as lowercase hex, as transaction hashes are usually written.
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash)
    }

    fn new(
        envelope: TransactionEnvelope,
        hash: [u8; 32],
        pre_authorised: Vec<String>,
    ) -> Result<Self> {
        let value = Type::TransactionEnvelope(Box::new(envelope.clone()));
        let bytes = xdrcheck_xdr::encode(&value, &xdrcheck_xdr::Limits::default())?;
        let base64 = envelope
            .to_xdr_base64(stellar_xdr::Limits {
                depth: xdrcheck_xdr::DEFAULT_DEPTH,
                len: usize::MAX,
            })
            .map_err(|e| Error::Build(format!("base64 of the envelope: {e}")))?;
        Ok(SignedEnvelope {
            envelope,
            bytes,
            base64,
            hash,
            pre_authorised,
        })
    }
}

/// One built transaction: the plain transaction and what is submitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltTx {
    /// The transaction built from the template (the inner transaction of a fee bump).
    pub transaction: Transaction,
    /// What is submitted: the fee-bump envelope when there is one, else the transaction's.
    pub envelope: SignedEnvelope,
    /// For a fee bump: the signed inner `ENVELOPE_TYPE_TX` envelope.
    pub inner: Option<SignedEnvelope>,
}

impl BuiltTx {
    /// The hash of the transaction as it appears in a ledger (outer hash for a fee bump).
    pub fn hash(&self) -> [u8; 32] {
        self.envelope.hash
    }

    /// The inner transaction hash of a fee bump.
    pub fn inner_hash(&self) -> Option<[u8; 32]> {
        self.inner.as_ref().map(|e| e.hash)
    }
}

/// Last 4 bytes of an ed25519 public key.
pub fn signature_hint(public: &[u8; 32]) -> [u8; 4] {
    last4(public)
}

fn last4(bytes: &[u8; 32]) -> [u8; 4] {
    [bytes[28], bytes[29], bytes[30], bytes[31]]
}

/// stellar-core's `getHint` of an arbitrary byte string.
fn bytes_hint(bytes: &[u8]) -> [u8; 4] {
    let mut hint = [0u8; 4];
    if bytes.len() < 4 {
        hint[..bytes.len()].copy_from_slice(bytes);
    } else {
        hint.copy_from_slice(&bytes[bytes.len() - 4..]);
    }
    hint
}

/// The hint of a signed-payload signature: key hint XOR payload hint (`getSignedPayloadHint`).
pub fn signed_payload_hint(public: &[u8; 32], payload: &[u8]) -> [u8; 4] {
    let k = last4(public);
    let p = bytes_hint(payload);
    [k[0] ^ p[0], k[1] ^ p[1], k[2] ^ p[2], k[3] ^ p[3]]
}

fn decorated(hint: [u8; 4], signature: Vec<u8>) -> Result<DecoratedSignature> {
    Ok(DecoratedSignature {
        hint: SignatureHint(hint),
        signature: Signature(
            BytesM::try_from(signature)
                .map_err(|_| Error::Build("a signature is longer than 64 bytes".into()))?,
        ),
    })
}

fn ed25519(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    key.sign(message).to_bytes().to_vec()
}

/// The signatures for `specs` over `hash`, plus the `T…` keys of `pre_auth` specs.
pub fn sign_hash(
    specs: &[SignerSpec],
    keys: &Keys,
    hash: &[u8; 32],
) -> Result<(Vec<DecoratedSignature>, Vec<String>)> {
    let mut sigs = Vec::new();
    let mut pre_auth = Vec::new();
    for spec in specs {
        match spec {
            SignerSpec::Key(label) => {
                let key = keys.actor(label)?;
                sigs.push(decorated(
                    signature_hint(key.verifying_key().as_bytes()),
                    ed25519(key, hash),
                )?);
            }
            SignerSpec::SignedPayload { key, payload } => {
                let k = keys.actor(key)?;
                sigs.push(decorated(
                    signed_payload_hint(k.verifying_key().as_bytes(), payload),
                    ed25519(k, payload),
                )?);
            }
            SignerSpec::HashX(preimage) => {
                let digest: [u8; 32] = Sha256::digest(preimage).into();
                sigs.push(decorated(last4(&digest), preimage.clone())?);
            }
            SignerSpec::HashXNamed(name) => {
                return Err(Error::Build(format!(
                    "hash_x preimage `{name}` must be replaced by its bytes before signing"
                )))
            }
            SignerSpec::PreAuth => pre_auth.push(format!("{}", stellar_strkey::PreAuthTx(*hash))),
        }
    }
    Ok((sigs, pre_auth))
}

/// Sign with raw keys (for transactions the scenario does not describe, such as root funding).
pub fn sign_hash_with(keys: &[&SigningKey], hash: &[u8; 32]) -> Result<Vec<DecoratedSignature>> {
    keys.iter()
        .map(|k| {
            decorated(
                signature_hint(k.verifying_key().as_bytes()),
                ed25519(k, hash),
            )
        })
        .collect()
}

fn sig_vec(sigs: Vec<DecoratedSignature>) -> Result<VecM<DecoratedSignature, 20>> {
    let n = sigs.len();
    VecM::try_from(sigs)
        .map_err(|_| Error::Build(format!("{n} signatures; an envelope holds at most 20")))
}

/// The transaction hash under the network ID.
pub fn transaction_hash(network_id: &[u8; 32], tx: &Transaction) -> Result<[u8; 32]> {
    tx.hash(*network_id)
        .map_err(|e| Error::Build(format!("transaction hash: {e}")))
}

/// The fee-bump hash under the network ID.
pub fn fee_bump_hash(network_id: &[u8; 32], tx: &FeeBumpTransaction) -> Result<[u8; 32]> {
    tx.hash(*network_id)
        .map_err(|e| Error::Build(format!("fee-bump hash: {e}")))
}

/// Wrap `tx` in an `ENVELOPE_TYPE_TX` envelope signed per `specs`.
pub fn sign_envelope(
    network_id: &[u8; 32],
    tx: Transaction,
    specs: &[SignerSpec],
    keys: &Keys,
) -> Result<SignedEnvelope> {
    let hash = transaction_hash(network_id, &tx)?;
    let (sigs, pre_auth) = sign_hash(specs, keys, &hash)?;
    envelope_v1(tx, hash, sigs, pre_auth)
}

/// Wrap `tx` in an `ENVELOPE_TYPE_TX` envelope with the given signatures.
pub fn envelope_v1(
    tx: Transaction,
    hash: [u8; 32],
    sigs: Vec<DecoratedSignature>,
    pre_auth: Vec<String>,
) -> Result<SignedEnvelope> {
    SignedEnvelope::new(
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: sig_vec(sigs)?,
        }),
        hash,
        pre_auth,
    )
}

/// Wrap a fee bump in an `ENVELOPE_TYPE_TX_FEE_BUMP` envelope signed per `specs`.
pub fn sign_fee_bump(
    network_id: &[u8; 32],
    tx: FeeBumpTransaction,
    specs: &[SignerSpec],
    keys: &Keys,
) -> Result<SignedEnvelope> {
    let hash = fee_bump_hash(network_id, &tx)?;
    let (sigs, pre_auth) = sign_hash(specs, keys, &hash)?;
    SignedEnvelope::new(
        TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx,
            signatures: sig_vec(sigs)?,
        }),
        hash,
        pre_auth,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_hint_follows_core_get_hint() {
        assert_eq!(bytes_hint(&[0x2a]), [0x2a, 0, 0, 0]);
        assert_eq!(bytes_hint(&[1, 2, 3]), [1, 2, 3, 0]);
        assert_eq!(bytes_hint(&[1, 2, 3, 4, 5]), [2, 3, 4, 5]);
        let mut key = [0u8; 32];
        key[28..].copy_from_slice(&[0xff, 0x0f, 0xf0, 0x00]);
        assert_eq!(signed_payload_hint(&key, &[0x2a]), [0xd5, 0x0f, 0xf0, 0x00]);
    }
}
