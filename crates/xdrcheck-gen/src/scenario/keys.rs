//! Deterministic keys.
//!
//! - **Actor** `<label>`: ed25519 seed = `sha256("<namespace>/key/<label>")`, UTF-8, no
//!   terminator. With the default namespace [`NAMESPACE`] actor `A` has seed `sha256("xcc/key/A")`.
//!   The seed does not depend on the network, so an actor has the same `G…` address on every
//!   passphrase (twins share participants).
//! - **Hash-x preimage** `<name>`: `sha256("<namespace>/hashx/<name>")` ([`hash_x_preimage`]).
//! - **Root**: ed25519 seed = the network ID = `sha256(passphrase)`. stellar-core creates the
//!   genesis account from `SecretKey::fromSeed(networkID)` (`LedgerManagerImpl::startNewLedger`),
//!   so this is the key that holds the genesis balance of a fresh standalone node.
//!
//! The keys are public by construction; they must never hold real funds.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use super::{Error, Result};

/// The public namespace of every label-derived seed of this kit.
pub const NAMESPACE: &str = "xcc";

/// The label that names the network's root account in placeholders and signer lists
/// (`${acct.root}`, `{key: root}`); no actor may use it.
pub const ROOT: &str = "root";

/// `sha256(passphrase)`: the network ID that every transaction hash and contract ID commits to.
pub fn network_id(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase.as_bytes()).into()
}

/// The ed25519 seed of actor `label`: `sha256("<namespace>/key/<label>")`.
pub fn actor_seed(namespace: &str, label: &str) -> [u8; 32] {
    Sha256::digest(format!("{namespace}/key/{label}").as_bytes()).into()
}

/// The hash-x preimage named `name`: `sha256("<namespace>/hashx/<name>")`, 32 bytes. Its signer key
/// (`X…`) is the sha256 of these bytes.
pub fn hash_x_preimage(namespace: &str, name: &str) -> [u8; 32] {
    Sha256::digest(format!("{namespace}/hashx/{name}").as_bytes()).into()
}

/// The signing key of actor `label`.
pub fn actor_key(namespace: &str, label: &str) -> SigningKey {
    SigningKey::from_bytes(&actor_seed(namespace, label))
}

/// The root (genesis) key of the network with this passphrase.
pub fn root_key(passphrase: &str) -> SigningKey {
    SigningKey::from_bytes(&network_id(passphrase))
}

/// `G…` strkey of an ed25519 public key.
pub fn account_strkey(public: &[u8; 32]) -> String {
    format!("{}", stellar_strkey::ed25519::PublicKey(*public))
}

/// Every key a scenario can sign with: its actors and the network's root.
#[derive(Clone)]
pub struct Keys {
    actors: BTreeMap<String, SigningKey>,
    root: SigningKey,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Seeds are public, but printing them is never useful; show addresses.
        let mut m = f.debug_map();
        for (label, key) in &self.actors {
            m.entry(label, &account_strkey(key.verifying_key().as_bytes()));
        }
        m.entry(
            &"<root>",
            &account_strkey(self.root.verifying_key().as_bytes()),
        );
        m.finish()
    }
}

impl Keys {
    /// Derive the keys of `actors` under `namespace` and the root key of `passphrase`.
    pub fn new<'a>(
        namespace: &str,
        passphrase: &str,
        actors: impl IntoIterator<Item = &'a String>,
    ) -> Self {
        Keys {
            actors: actors
                .into_iter()
                .map(|label| (label.clone(), actor_key(namespace, label)))
                .collect(),
            root: root_key(passphrase),
        }
    }

    /// The signing key of an actor, or of the root account for [`ROOT`].
    pub fn actor(&self, label: &str) -> Result<&SigningKey> {
        if label == ROOT {
            return Ok(&self.root);
        }
        self.actors
            .get(label)
            .ok_or_else(|| Error::Invalid(format!("`{label}` is not an actor of the scenario")))
    }

    /// The root key.
    pub fn root(&self) -> &SigningKey {
        &self.root
    }

    /// The raw ed25519 public key of an actor.
    pub fn public(&self, label: &str) -> Result<[u8; 32]> {
        Ok(self.actor(label)?.verifying_key().to_bytes())
    }

    /// The `G…` address of an actor.
    pub fn address(&self, label: &str) -> Result<String> {
        Ok(account_strkey(&self.public(label)?))
    }

    /// The actor label owning this public key, or `None` (root is reported as `None` too).
    pub fn label_of(&self, public: &[u8; 32]) -> Option<&str> {
        self.actors
            .iter()
            .find(|(_, k)| k.verifying_key().as_bytes() == public)
            .map(|(l, _)| l.as_str())
    }

    /// The actor label owning this public key, or [`ROOT`] for the root account.
    pub fn signer_label_of(&self, public: &[u8; 32]) -> Option<&str> {
        if self.root.verifying_key().as_bytes() == public {
            return Some(ROOT);
        }
        self.label_of(public)
    }

    /// The signing key (actor or root) for this public key.
    pub fn signer_for(&self, public: &[u8; 32]) -> Option<&SigningKey> {
        if self.root.verifying_key().as_bytes() == public {
            return Some(&self.root);
        }
        self.actors
            .values()
            .find(|k| k.verifying_key().as_bytes() == public)
    }

    /// Actor labels in sorted order.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.actors.keys().map(String::as_str)
    }
}
