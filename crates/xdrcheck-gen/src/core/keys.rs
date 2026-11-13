//! Keys and signatures for transactions the generator signs itself.
//!
//! - The root key's ed25519 seed is the network ID, `sha256(passphrase)`: genesis gives it every lumen.
//! - Every other key's seed is `sha256("<KEY_NAMESPACE>/key/<label>")`. Labels and the namespace are public;
//!   no key ever holds real funds.
//! - A transaction hash is `sha256(TransactionSignaturePayload{network ID, tagged transaction})`; a signature
//!   is ed25519 over that hash, decorated with the last four bytes of the public key as its hint.

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, DecoratedSignature, MuxedAccount, PublicKey, Signature, SignatureHint, Transaction,
    TransactionEnvelope, TransactionV1Envelope, Uint256,
};

/// Public prefix of every derived seed and salt.
pub const KEY_NAMESPACE: &str = "xcc";

/// `"Test SDF Network ; September 2015"`.
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
/// `"Public Global Stellar Network ; September 2015"`.
pub const PUBNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// `sha256(passphrase)`.
pub fn network_id(passphrase: &str) -> [u8; 32] {
    sha256(passphrase.as_bytes())
}

/// sha256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// An ed25519 key pair.
#[derive(Clone)]
pub struct Keypair {
    signing: SigningKey,
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keypair({})", self.address())
    }
}

impl Keypair {
    /// The key whose ed25519 seed is `seed`.
    pub fn from_seed(seed: [u8; 32]) -> Keypair {
        Keypair {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// The network's root account key: seed = network ID.
    pub fn root(passphrase: &str) -> Keypair {
        Keypair::from_seed(network_id(passphrase))
    }

    /// The key for a public label: seed = `sha256("xcc/key/<label>")`. Independent of the network.
    pub fn from_label(label: &str) -> Keypair {
        Keypair::from_seed(sha256(format!("{KEY_NAMESPACE}/key/{label}").as_bytes()))
    }

    /// The raw ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// The account ID (`PublicKey::Ed25519`).
    pub fn account_id(&self) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(self.public_key())))
    }

    /// The account as an unmuxed `MuxedAccount`.
    pub fn muxed_account(&self) -> MuxedAccount {
        MuxedAccount::Ed25519(Uint256(self.public_key()))
    }

    /// The `G…` address.
    pub fn address(&self) -> String {
        format!("{}", stellar_strkey::ed25519::PublicKey(self.public_key()))
    }

    /// The `S…` secret seed (public by construction: every seed here is derived from public data).
    pub fn secret_seed(&self) -> String {
        let key = stellar_strkey::ed25519::PrivateKey(self.signing.to_bytes());
        format!("{}", key.as_unredacted())
    }

    /// The signature hint: the last four bytes of the public key.
    pub fn hint(&self) -> [u8; 4] {
        let pk = self.public_key();
        [pk[28], pk[29], pk[30], pk[31]]
    }

    /// ed25519 signature of `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// The decorated signature of a transaction hash.
    pub fn sign_decorated(&self, hash: &[u8; 32]) -> DecoratedSignature {
        DecoratedSignature {
            hint: SignatureHint(self.hint()),
            signature: Signature(
                self.sign(hash)
                    .to_vec()
                    .try_into()
                    .expect("64 bytes fit a signature"),
            ),
        }
    }
}

/// The hash of `tx` under `passphrase`.
pub fn tx_hash(passphrase: &str, tx: &Transaction) -> Result<[u8; 32]> {
    tx.hash(network_id(passphrase)).context("hash transaction")
}

/// Wrap `tx` in a v1 envelope signed by each of `signers`, in order.
pub fn sign_transaction(
    passphrase: &str,
    tx: Transaction,
    signers: &[&Keypair],
) -> Result<TransactionEnvelope> {
    let hash = tx_hash(passphrase, &tx)?;
    let signatures: Vec<DecoratedSignature> =
        signers.iter().map(|k| k.sign_decorated(&hash)).collect();
    Ok(TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: signatures.try_into().context("at most 20 signatures")?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_addresses_match_core() {
        // stellar-core logs these as "Root account" for the two real passphrases.
        assert_eq!(
            Keypair::root(TESTNET_PASSPHRASE).address(),
            "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H"
        );
        assert_eq!(
            Keypair::root(PUBNET_PASSPHRASE).address(),
            "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"
        );
    }

    #[test]
    fn label_keys_are_stable_and_distinct() {
        let a = Keypair::from_label("a");
        assert_eq!(a.public_key(), Keypair::from_label("a").public_key());
        assert_ne!(a.public_key(), Keypair::from_label("b").public_key());
        assert!(a.secret_seed().starts_with('S'));
    }
}
