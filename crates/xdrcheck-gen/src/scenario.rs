//! The scenario interpreter: load a scenario file, derive its keys, resolve its
//! placeholders, and build and sign every transaction it describes for one network passphrase and
//! one protocol. Nothing here runs a node; the node side (`core`, `upgrade`, `soroban`) submits
//! what this module builds and feeds back what only the node knows (sequence numbers, ledger
//! numbers, close times, contract IDs, derived values).
//!
//! # Pieces
//!
//! - [`file`]: [`Scenario::load`] reads YAML or JSON, validates it against the frozen
//!   `corpus/schema/scenario.schema.json` (with the manifest-entry schema registered for the
//!   `expect` block), then checks what the schema cannot (unique step IDs, known labels, …).
//! - [`keys`]: deterministic keys. An actor's ed25519 seed is
//!   `sha256("<namespace>/key/<label>")` with the namespace [`NAMESPACE`] (`"xcc"`), so actor `A`
//!   has seed `sha256("xcc/key/A")`; addresses are the same on every network. The root key's seed
//!   is the network ID, `sha256(passphrase)`, exactly as stellar-core derives its genesis account.
//! - [`ids`]: contract IDs from `HashIdPreimage::ContractId` — the Stellar Asset Contract from an
//!   asset, a deployed contract from a deployer address and salt.
//! - [`placeholder`]: the `${…}` language of the scenario schema.
//! - [`envelope`]: transaction hashing and signing (ed25519, signed payload, hash-x, pre-auth) and
//!   fee-bump wrapping.
//! - [`interpreter`]: [`Interpreter`] walks setup items and steps in order, tracks sequence
//!   numbers and the planned ledger and close time, and returns [`BuiltSetup`] / [`BuiltStep`]
//!   values; [`build`] runs it to the end with no feedback from a node.

pub mod envelope;
pub mod file;
pub mod ids;
pub mod interpreter;
pub mod keys;
pub mod placeholder;

pub use envelope::{sign_envelope, signature_hint, signed_payload_hint, BuiltTx, SignedEnvelope};
pub use file::FIRST_SIMULATION_PROTOCOL;
pub use file::{BringUpEntry, FeeBumpSpec, Scenario, SetupEntry, SignerSpec, Step};
pub use ids::{contract_id_from_address, contract_salt, sac_contract_id, sac_contract_strkey};
pub use interpreter::{
    build, BuiltScenario, BuiltSetup, BuiltStep, Expected, Interpreter, Item, Options, SetupAction,
    DEFAULT_CLOSE_TIME_BASE, DEFAULT_CLOSE_TIME_STEP, DEFAULT_FIRST_LEDGER,
};
pub use keys::{
    actor_key, actor_seed, hash_x_preimage, network_id, root_key, Keys, NAMESPACE, ROOT,
};
pub use placeholder::{Placeholder, Resolver};

/// Errors of the scenario interpreter.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file could not be read or parsed as YAML/JSON.
    #[error("{path}: {message}")]
    Load { path: String, message: String },
    /// The file does not match `scenario.schema.json`; one line per violation.
    #[error("scenario does not match the schema:\n  {}", .0.join("\n  "))]
    Schema(Vec<String>),
    /// A rule the schema cannot express (duplicate step IDs, unknown labels, …).
    #[error("scenario: {0}")]
    Invalid(String),
    /// A placeholder that does not parse or cannot be resolved.
    #[error("placeholder `{placeholder}`: {message}")]
    Placeholder {
        placeholder: String,
        message: String,
    },
    /// A failure while building one setup item or step, with its ID.
    #[error("{item}: {source}")]
    Item {
        item: String,
        #[source]
        source: Box<Error>,
    },
    /// A transaction that cannot be built or signed.
    #[error("{0}")]
    Build(String),
    /// XDR or SEP-51 JSON failure from the oracle.
    #[error(transparent)]
    Xdr(#[from] xdrcheck_xdr::Error),
}

/// Result alias of this module.
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub(crate) fn placeholder(placeholder: &str, message: impl Into<String>) -> Self {
        Error::Placeholder {
            placeholder: placeholder.to_string(),
            message: message.into(),
        }
    }

    pub(crate) fn within(self, item: impl Into<String>) -> Self {
        Error::Item {
            item: item.into(),
            source: Box::new(self),
        }
    }
}
