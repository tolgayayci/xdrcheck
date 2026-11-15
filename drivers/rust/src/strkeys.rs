//! Strkey (SEP-23) decode and encode through the `stellar-strkey` version the column's `stellar-xdr` depends
//! on: 1.0.0 for `stellar-xdr` 30.0.0 (cargo feature `strkey-1`), 0.0.13 for the 28.x crates. The two APIs
//! differ (error variants, `SignedPayload` construction, `S…` handling, no muxed-contract kind before 1.0.0),
//! so each has its own implementation behind the same three functions.
//!
//! Payloads are the raw SEP-23 payload, the bytes between the version byte and the checksum:
//! `G`/`S`/`T`/`X`/`C`/`L` 32 bytes, `M` key ‖ id (big-endian u64), `W` contract ‖ id, `B` sub-version byte ‖
//! hash, `P` key ‖ inner length (u32) ‖ inner payload ‖ zero padding to a multiple of four.

use crate::outcome::Reason;

/// A strkey kind, named as in the manifest's `strkey.type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Account,
    MuxedAccount,
    SecretSeed,
    PreAuthTx,
    HashX,
    SignedPayload,
    Contract,
    MuxedContract,
    LiquidityPool,
    ClaimableBalance,
}

impl Kind {
    pub fn from_name(s: &str) -> Option<Kind> {
        Some(match s {
            "account" => Kind::Account,
            "muxed_account" => Kind::MuxedAccount,
            "secret_seed" => Kind::SecretSeed,
            "pre_auth_tx" => Kind::PreAuthTx,
            "hash_x" => Kind::HashX,
            "signed_payload" => Kind::SignedPayload,
            "contract" => Kind::Contract,
            "muxed_contract" => Kind::MuxedContract,
            "liquidity_pool" => Kind::LiquidityPool,
            "claimable_balance" => Kind::ClaimableBalance,
            _ => return None,
        })
    }

    // Only the 0.0.13 implementation names kinds in its messages.
    #[cfg_attr(feature = "strkey-1", allow(dead_code))]
    pub fn name(self) -> &'static str {
        match self {
            Kind::Account => "account",
            Kind::MuxedAccount => "muxed_account",
            Kind::SecretSeed => "secret_seed",
            Kind::PreAuthTx => "pre_auth_tx",
            Kind::HashX => "hash_x",
            Kind::SignedPayload => "signed_payload",
            Kind::Contract => "contract",
            Kind::MuxedContract => "muxed_contract",
            Kind::LiquidityPool => "liquidity_pool",
            Kind::ClaimableBalance => "claimable_balance",
        }
    }
}

/// A decoded strkey: its kind and raw payload.
pub struct Decoded {
    #[cfg_attr(feature = "strkey-1", allow(dead_code))]
    pub kind: Kind,
    pub payload: Vec<u8>,
}

/// The result of encoding a payload.
pub enum Encoded {
    /// The library produced this text.
    Text(String),
    /// The library refused (only `SignedPayload::new` of stellar-strkey 1.0.0 refuses at construction).
    #[cfg_attr(not(feature = "strkey-1"), allow(dead_code))]
    Refused(Reason),
    /// The payload cannot be held by the library's type for the kind (a length other than the fixed one, a
    /// claimable-balance sub-version other than V0, non-zero signed-payload padding): there is nothing an
    /// application could pass, so the cell is `n_a`.
    Unrepresentable(String),
    /// The library has no such kind (muxed contracts before stellar-strkey 1.0.0).
    #[cfg_attr(feature = "strkey-1", allow(dead_code))]
    Unsupported(String),
}

fn arr32(p: &[u8]) -> Option<[u8; 32]> {
    p.try_into().ok()
}

fn key_and_id(p: &[u8]) -> Option<([u8; 32], u64)> {
    if p.len() != 40 {
        return None;
    }
    Some((
        arr32(&p[..32])?,
        u64::from_be_bytes(p[32..].try_into().ok()?),
    ))
}

fn join(key: &[u8], id: u64) -> Vec<u8> {
    let mut v = key.to_vec();
    v.extend_from_slice(&id.to_be_bytes());
    v
}

/// The raw signed-payload layout: key ‖ u32 length ‖ inner ‖ zero padding.
fn signed_payload_raw(key: &[u8], inner: &[u8]) -> Vec<u8> {
    let mut v = key.to_vec();
    v.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    v.extend_from_slice(inner);
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    v
}

/// Splits a raw signed payload into key and inner payload, if it has exactly that layout with zero padding.
fn signed_payload_split(p: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    if p.len() < 36 {
        return None;
    }
    let key = arr32(&p[..32])?;
    let n = u32::from_be_bytes(p[32..36].try_into().ok()?) as usize;
    let rest = &p[36..];
    let padded = n.checked_add(3)? / 4 * 4;
    if rest.len() != padded || rest[n..].iter().any(|b| *b != 0) {
        return None;
    }
    Some((key, rest[..n].to_vec()))
}

fn reason(code: &'static str, class: String, message: String, entry_point: &str) -> Reason {
    Reason::new(code)
        .message(message)
        .class(class)
        .entry_point(entry_point)
}

#[cfg(feature = "strkey-1")]
mod imp {
    use super::*;
    use stellar_strkey::{
        ed25519, ClaimableBalance, Contract, DecodeError, HashX, LiquidityPool, MuxedContract,
        PreAuthTx, Strkey,
    };

    pub fn version() -> &'static str {
        stellar_strkey::VERSION.pkg
    }

    fn code(e: &DecodeError) -> &'static str {
        match e {
            DecodeError::ChecksumMismatch => "strkey_checksum",
            DecodeError::UnsupportedVersion | DecodeError::PrivateKey => "strkey_version",
            DecodeError::TooShort | DecodeError::TooLong | DecodeError::InvalidPayloadLength => {
                "strkey_length"
            }
            DecodeError::InvalidPadding => "strkey_padding",
            DecodeError::UnsupportedClaimableBalanceVersion => "strkey_payload",
            // Base32 failures (invalid symbol, encoded length, non-zero trailing bits, '=' padding) are one
            // variant; the driver does not guess which.
            _ => "decode_error",
        }
    }

    fn err(e: DecodeError, ep: &str) -> Reason {
        reason(
            code(&e),
            format!("stellar_strkey::DecodeError::{e:?}"),
            e.to_string(),
            ep,
        )
    }

    fn from_strkey(k: Strkey) -> Decoded {
        let (kind, payload) = match k {
            Strkey::PublicKeyEd25519(k) => (Kind::Account, k.0.to_vec()),
            Strkey::PreAuthTx(k) => (Kind::PreAuthTx, k.0.to_vec()),
            Strkey::HashX(k) => (Kind::HashX, k.0.to_vec()),
            Strkey::MuxedAccountEd25519(m) => (Kind::MuxedAccount, join(&m.ed25519, m.id)),
            Strkey::SignedPayloadEd25519(p) => (
                Kind::SignedPayload,
                signed_payload_raw(p.ed25519(), p.payload()),
            ),
            Strkey::Contract(k) => (Kind::Contract, k.0.to_vec()),
            Strkey::LiquidityPool(k) => (Kind::LiquidityPool, k.0.to_vec()),
            Strkey::ClaimableBalance(ClaimableBalance::V0(h)) => {
                let mut v = vec![0u8];
                v.extend_from_slice(&h);
                (Kind::ClaimableBalance, v)
            }
            Strkey::MuxedContract(m) => (Kind::MuxedContract, join(&m.contract_id, m.id)),
        };
        Decoded { kind, payload }
    }

    pub fn decode(s: &str, declared: Option<Kind>) -> Result<Decoded, Reason> {
        let d = |kind, payload: Vec<u8>| Decoded { kind, payload };
        match declared {
            None => match Strkey::from_string(s) {
                Ok(k) => Ok(from_strkey(k)),
                // The library routes S… to the private-key type explicitly.
                Err(DecodeError::PrivateKey) => ed25519::PrivateKey::from_string(s)
                    .map(|k| d(Kind::SecretSeed, k.0.to_vec()))
                    .map_err(|e| err(e, "stellar_strkey::ed25519::PrivateKey::from_string")),
                Err(e) => Err(err(e, "stellar_strkey::Strkey::from_string")),
            },
            Some(Kind::Account) => ed25519::PublicKey::from_string(s)
                .map(|k| d(Kind::Account, k.0.to_vec()))
                .map_err(|e| err(e, "stellar_strkey::ed25519::PublicKey::from_string")),
            Some(Kind::SecretSeed) => ed25519::PrivateKey::from_string(s)
                .map(|k| d(Kind::SecretSeed, k.0.to_vec()))
                .map_err(|e| err(e, "stellar_strkey::ed25519::PrivateKey::from_string")),
            Some(Kind::MuxedAccount) => ed25519::MuxedAccount::from_string(s)
                .map(|m| d(Kind::MuxedAccount, join(&m.ed25519, m.id)))
                .map_err(|e| err(e, "stellar_strkey::ed25519::MuxedAccount::from_string")),
            Some(Kind::SignedPayload) => ed25519::SignedPayload::from_string(s)
                .map(|p| {
                    d(
                        Kind::SignedPayload,
                        signed_payload_raw(p.ed25519(), p.payload()),
                    )
                })
                .map_err(|e| err(e, "stellar_strkey::ed25519::SignedPayload::from_string")),
            Some(Kind::PreAuthTx) => PreAuthTx::from_string(s)
                .map(|k| d(Kind::PreAuthTx, k.0.to_vec()))
                .map_err(|e| err(e, "stellar_strkey::PreAuthTx::from_string")),
            Some(Kind::HashX) => HashX::from_string(s)
                .map(|k| d(Kind::HashX, k.0.to_vec()))
                .map_err(|e| err(e, "stellar_strkey::HashX::from_string")),
            Some(Kind::Contract) => Contract::from_string(s)
                .map(|k| d(Kind::Contract, k.0.to_vec()))
                .map_err(|e| err(e, "stellar_strkey::Contract::from_string")),
            Some(Kind::LiquidityPool) => LiquidityPool::from_string(s)
                .map(|k| d(Kind::LiquidityPool, k.0.to_vec()))
                .map_err(|e| err(e, "stellar_strkey::LiquidityPool::from_string")),
            Some(Kind::ClaimableBalance) => ClaimableBalance::from_string(s)
                .map(|ClaimableBalance::V0(h)| {
                    let mut v = vec![0u8];
                    v.extend_from_slice(&h);
                    d(Kind::ClaimableBalance, v)
                })
                .map_err(|e| err(e, "stellar_strkey::ClaimableBalance::from_string")),
            Some(Kind::MuxedContract) => MuxedContract::from_string(s)
                .map(|m| d(Kind::MuxedContract, join(&m.contract_id, m.id)))
                .map_err(|e| err(e, "stellar_strkey::MuxedContract::from_string")),
        }
    }

    pub fn encode(kind: Kind, p: &[u8]) -> (Encoded, &'static str) {
        let bad = |what: &str| {
            Encoded::Unrepresentable(format!("a {}-byte payload cannot be {what}", p.len()))
        };
        match kind {
            Kind::Account => match arr32(p) {
                Some(a) => (
                    Encoded::Text(ed25519::PublicKey(a).to_string().to_string()),
                    "stellar_strkey::ed25519::PublicKey::to_string",
                ),
                None => (bad("an ed25519 public key"), ""),
            },
            Kind::SecretSeed => match arr32(p) {
                Some(a) => (
                    Encoded::Text(
                        ed25519::PrivateKey(a)
                            .as_unredacted()
                            .to_string()
                            .to_string(),
                    ),
                    "stellar_strkey::ed25519::PrivateKey::as_unredacted().to_string",
                ),
                None => (bad("an ed25519 private key"), ""),
            },
            Kind::PreAuthTx => match arr32(p) {
                Some(a) => (
                    Encoded::Text(PreAuthTx(a).to_string().to_string()),
                    "stellar_strkey::PreAuthTx::to_string",
                ),
                None => (bad("a pre-auth transaction hash"), ""),
            },
            Kind::HashX => match arr32(p) {
                Some(a) => (
                    Encoded::Text(HashX(a).to_string().to_string()),
                    "stellar_strkey::HashX::to_string",
                ),
                None => (bad("a hash-x"), ""),
            },
            Kind::Contract => match arr32(p) {
                Some(a) => (
                    Encoded::Text(Contract(a).to_string().to_string()),
                    "stellar_strkey::Contract::to_string",
                ),
                None => (bad("a contract ID"), ""),
            },
            Kind::LiquidityPool => match arr32(p) {
                Some(a) => (
                    Encoded::Text(LiquidityPool(a).to_string().to_string()),
                    "stellar_strkey::LiquidityPool::to_string",
                ),
                None => (bad("a liquidity pool ID"), ""),
            },
            Kind::MuxedAccount => match key_and_id(p) {
                Some((ed25519, id)) => (
                    Encoded::Text(
                        ed25519::MuxedAccount { ed25519, id }
                            .to_string()
                            .to_string(),
                    ),
                    "stellar_strkey::ed25519::MuxedAccount::to_string",
                ),
                None => (bad("a muxed account (key and id)"), ""),
            },
            Kind::MuxedContract => match key_and_id(p) {
                Some((contract_id, id)) => (
                    Encoded::Text(MuxedContract { contract_id, id }.to_string().to_string()),
                    "stellar_strkey::MuxedContract::to_string",
                ),
                None => (bad("a muxed contract (contract and id)"), ""),
            },
            Kind::ClaimableBalance => match (p.first(), p.get(1..).and_then(arr32)) {
                (Some(0), Some(h)) => (
                    Encoded::Text(ClaimableBalance::V0(h).to_string().to_string()),
                    "stellar_strkey::ClaimableBalance::to_string",
                ),
                _ => (bad("a V0 claimable balance ID"), ""),
            },
            Kind::SignedPayload => match signed_payload_split(p) {
                Some((key, inner)) => {
                    let ep = "stellar_strkey::ed25519::SignedPayload::new";
                    match ed25519::SignedPayload::new(key, &inner) {
                        Ok(sp) => (
                            Encoded::Text(sp.to_string().to_string()),
                            "stellar_strkey::ed25519::SignedPayload::to_string",
                        ),
                        Err(e) => (Encoded::Refused(err(e, ep)), ep),
                    }
                }
                None => (bad("a signed payload with zero padding"), ""),
            },
        }
    }
}

#[cfg(not(feature = "strkey-1"))]
mod imp {
    use super::*;
    use stellar_strkey::{
        ed25519, ClaimableBalance, Contract, DecodeError, HashX, LiquidityPool, PreAuthTx, Strkey,
    };

    pub fn version() -> &'static str {
        stellar_strkey::VERSION.pkg
    }

    // 0.0.13 has a single error variant, Invalid.
    fn err(e: DecodeError, ep: &str) -> Reason {
        reason(
            "decode_error",
            format!("stellar_strkey::DecodeError::{e:?}"),
            e.to_string(),
            ep,
        )
    }

    fn cb(h: [u8; 32]) -> Vec<u8> {
        let mut v = vec![0u8];
        v.extend_from_slice(&h);
        v
    }

    fn from_strkey(k: Strkey) -> Decoded {
        let (kind, payload) = match k {
            Strkey::PublicKeyEd25519(k) => (Kind::Account, k.0.to_vec()),
            Strkey::PrivateKeyEd25519(k) => (Kind::SecretSeed, k.0.to_vec()),
            Strkey::PreAuthTx(k) => (Kind::PreAuthTx, k.0.to_vec()),
            Strkey::HashX(k) => (Kind::HashX, k.0.to_vec()),
            Strkey::MuxedAccountEd25519(m) => (Kind::MuxedAccount, join(&m.ed25519, m.id)),
            Strkey::SignedPayloadEd25519(p) => (
                Kind::SignedPayload,
                signed_payload_raw(&p.ed25519, &p.payload),
            ),
            Strkey::Contract(k) => (Kind::Contract, k.0.to_vec()),
            Strkey::LiquidityPool(k) => (Kind::LiquidityPool, k.0.to_vec()),
            Strkey::ClaimableBalance(ClaimableBalance::V0(h)) => (Kind::ClaimableBalance, cb(h)),
        };
        Decoded { kind, payload }
    }

    pub fn decode(s: &str, declared: Option<Kind>) -> Result<Decoded, Reason> {
        let d = |kind, payload: Vec<u8>| Decoded { kind, payload };
        match declared {
            None | Some(Kind::MuxedContract) => {
                // 0.0.13 has no muxed-contract kind: a declared `W…` goes through the generic decoder, which
                // is what an application on this version has.
                let r = Strkey::from_string(s)
                    .map_err(|e| err(e, "stellar_strkey::Strkey::from_string"))?;
                let dec = from_strkey(r);
                if declared.is_some() {
                    return Err(Reason::new("strkey_version")
                        .message(format!(
                            "decoded as {}; this stellar-strkey has no muxed_contract kind",
                            dec.kind.name()
                        ))
                        .entry_point("stellar_strkey::Strkey::from_string"));
                }
                Ok(dec)
            }
            Some(Kind::Account) => ed25519::PublicKey::from_string(s)
                .map(|k| d(Kind::Account, k.0.to_vec()))
                .map_err(|e| err(e, "stellar_strkey::ed25519::PublicKey::from_string")),
            Some(Kind::SecretSeed) => ed25519::PrivateKey::from_string(s)
                .map(|k| d(Kind::SecretSeed, k.0.to_vec()))
                .map_err(|e| err(e, "stellar_strkey::ed25519::PrivateKey::from_string")),
            Some(Kind::MuxedAccount) => ed25519::MuxedAccount::from_string(s)
                .map(|m| d(Kind::MuxedAccount, join(&m.ed25519, m.id)))
                .map_err(|e| err(e, "stellar_strkey::ed25519::MuxedAccount::from_string")),
            Some(Kind::SignedPayload) => ed25519::SignedPayload::from_string(s)
                .map(|p| {
                    d(
                        Kind::SignedPayload,
                        signed_payload_raw(&p.ed25519, &p.payload),
                    )
                })
                .map_err(|e| err(e, "stellar_strkey::ed25519::SignedPayload::from_string")),
            Some(Kind::PreAuthTx) => PreAuthTx::from_string(s)
                .map(|k| d(Kind::PreAuthTx, k.0.to_vec()))
                .map_err(|e| err(e, "stellar_strkey::PreAuthTx::from_string")),
            Some(Kind::HashX) => HashX::from_string(s)
                .map(|k| d(Kind::HashX, k.0.to_vec()))
                .map_err(|e| err(e, "stellar_strkey::HashX::from_string")),
            Some(Kind::Contract) => Contract::from_string(s)
                .map(|k| d(Kind::Contract, k.0.to_vec()))
                .map_err(|e| err(e, "stellar_strkey::Contract::from_string")),
            Some(Kind::LiquidityPool) => LiquidityPool::from_string(s)
                .map(|k| d(Kind::LiquidityPool, k.0.to_vec()))
                .map_err(|e| err(e, "stellar_strkey::LiquidityPool::from_string")),
            Some(Kind::ClaimableBalance) => ClaimableBalance::from_string(s)
                .map(|ClaimableBalance::V0(h)| d(Kind::ClaimableBalance, cb(h)))
                .map_err(|e| err(e, "stellar_strkey::ClaimableBalance::from_string")),
        }
    }

    pub fn encode(kind: Kind, p: &[u8]) -> (Encoded, &'static str) {
        let bad = |what: &str| {
            Encoded::Unrepresentable(format!("a {}-byte payload cannot be {what}", p.len()))
        };
        match kind {
            Kind::Account => match arr32(p) {
                Some(a) => (
                    Encoded::Text(ed25519::PublicKey(a).to_string()),
                    "stellar_strkey::ed25519::PublicKey::to_string",
                ),
                None => (bad("an ed25519 public key"), ""),
            },
            Kind::SecretSeed => match arr32(p) {
                Some(a) => (
                    Encoded::Text(ed25519::PrivateKey(a).to_string()),
                    "stellar_strkey::ed25519::PrivateKey::to_string",
                ),
                None => (bad("an ed25519 private key"), ""),
            },
            Kind::PreAuthTx => match arr32(p) {
                Some(a) => (
                    Encoded::Text(PreAuthTx(a).to_string()),
                    "stellar_strkey::PreAuthTx::to_string",
                ),
                None => (bad("a pre-auth transaction hash"), ""),
            },
            Kind::HashX => match arr32(p) {
                Some(a) => (
                    Encoded::Text(HashX(a).to_string()),
                    "stellar_strkey::HashX::to_string",
                ),
                None => (bad("a hash-x"), ""),
            },
            Kind::Contract => match arr32(p) {
                Some(a) => (
                    Encoded::Text(Contract(a).to_string()),
                    "stellar_strkey::Contract::to_string",
                ),
                None => (bad("a contract ID"), ""),
            },
            Kind::LiquidityPool => match arr32(p) {
                Some(a) => (
                    Encoded::Text(LiquidityPool(a).to_string()),
                    "stellar_strkey::LiquidityPool::to_string",
                ),
                None => (bad("a liquidity pool ID"), ""),
            },
            Kind::MuxedAccount => match key_and_id(p) {
                Some((ed25519, id)) => (
                    Encoded::Text(ed25519::MuxedAccount { ed25519, id }.to_string()),
                    "stellar_strkey::ed25519::MuxedAccount::to_string",
                ),
                None => (bad("a muxed account (key and id)"), ""),
            },
            Kind::MuxedContract => (
                Encoded::Unsupported(format!(
                    "stellar-strkey {} has no muxed-contract (W) kind",
                    version()
                )),
                "",
            ),
            Kind::ClaimableBalance => match (p.first(), p.get(1..).and_then(arr32)) {
                (Some(0), Some(h)) => (
                    Encoded::Text(ClaimableBalance::V0(h).to_string()),
                    "stellar_strkey::ClaimableBalance::to_string",
                ),
                _ => (bad("a V0 claimable balance ID"), ""),
            },
            // 0.0.13 constructs a signed payload from its public fields without any check.
            Kind::SignedPayload => match signed_payload_split(p) {
                Some((ed25519, payload)) => (
                    Encoded::Text(ed25519::SignedPayload { ed25519, payload }.to_string()),
                    "stellar_strkey::ed25519::SignedPayload::to_string",
                ),
                None => (bad("a signed payload with zero padding"), ""),
            },
        }
    }
}

pub use imp::{decode, encode, version};
