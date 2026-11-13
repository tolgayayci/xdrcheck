//! Placeholders: `${…}` inside JSON strings of a scenario.
//!
//! | Placeholder | Value |
//! |---|---|
//! | `${acct.L}` | `G…` address of actor L; `${acct.root}` is the network's root account (in `expect`, `fields` and `mirrors` it stays a reference, `${derived.accounts.root}`: the root differs per passphrase) |
//! | `${muxed(L, id)}` | `M…` address of L with the decimal 64-bit ID |
//! | `${muxed_contract(NAME, id)}` | `W…` address of contract NAME (as `${contract.id(NAME)}`) with the decimal 64-bit ID |
//! | `${seq.L}` | L's next sequence number (current + 1), as a decimal string (`${seq.root}`: root's) |
//! | `${signer.payload(L, hex)}` | `P…` signed-payload signer of L's key and 1–64 payload bytes |
//! | `${signer.hash_x(NAME)}` | `X…` hash-x signer: sha256 of the preimage NAME |
//! | `${hash_x.preimage(NAME)}` | the preimage NAME in hex: `sha256("xcc/hashx/<NAME>")` ([`super::hash_x_preimage`]) |
//! | `${signer.pre_auth_tx(STEP)}` | `T…` pre-auth signer: the transaction hash (the inner one under a fee bump) of step STEP under this passphrase |
//! | `${asset.NAME}` | the SEP-51 JSON of asset NAME (its placeholders resolved) |
//! | `${contract.sac(NAME)}` | `C…` Stellar Asset Contract of asset NAME (or `native`) on this network |
//! | `${contract.id(NAME)}` | `C…` of contract NAME: injected, else derived from its deployer and [`super::contract_salt`] |
//! | `${close_time}` | this item's close time, as a decimal string |
//! | `${order_nonce}` | in a step of a ledger group with `order`: the nonce the generator chose so that the group's transactions apply in that order, as a decimal string |
//! | `${derived.NAME}` | an injected derived value; `NAME` may be a dotted path into nested objects |
//!
//! A string that is exactly one placeholder becomes the placeholder's JSON value (so
//! `"${asset.USDC}"` becomes an object). Placeholders inside a longer string are interpolated and
//! must resolve to a string or a number. In annotation blocks (`expect`, `fields`, `mirrors`) an
//! unresolvable `${derived.NAME}` stays verbatim: there it is a reference to the variant's
//! `derived` block of the manifest, filled only after a run.
//!
//! `${signer.pre_auth_tx(STEP)}` may name a later step (the usual case: add the pre-auth signer,
//! then submit the transaction it authorises). The interpreter then builds ahead to that step on a
//! copy of its state, and checks when the step is really built that its hash is the one it
//! predicted. The named step must not be `simulate: true` (its hash is known only after simulation).

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::Digest;
use stellar_xdr::Asset;

use super::file::ContractSpec;
use super::ids::{contract_id_from_address, contract_salt, sac_contract_id};
use super::keys::Keys;
use super::{Error, Result};

/// A parsed placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placeholder {
    Acct(String),
    Muxed(String, u64),
    MuxedContract(String, u64),
    Seq(String),
    SignerPayload(String, Vec<u8>),
    SignerHashX(String),
    HashXPreimage(String),
    PreAuthTx(String),
    Asset(String),
    ContractSac(String),
    ContractId(String),
    /// `${pool(A, B)}`: the `L…` ID of the constant-product pool of assets A and B (fee 30 bps), in
    /// the order written (core requires A < B).
    Pool(String, String),
    CloseTime,
    OrderNonce,
    Derived(String),
}

fn is_name(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A step ID as the schema writes it: `^[a-z0-9]+(-[a-z0-9]+)*$`.
fn is_step_id(s: &str) -> bool {
    !s.is_empty()
        && s.split('-').all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// The step IDs named by `${signer.pre_auth_tx(…)}` anywhere in `value`.
pub fn pre_auth_steps(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_pre_auth(value, &mut out);
    out
}

fn collect_pre_auth(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => {
            for (_, _, inner) in spans(s).unwrap_or_default() {
                if let Ok(Placeholder::PreAuthTx(step)) = Placeholder::parse(inner) {
                    if !out.contains(&step) {
                        out.push(step);
                    }
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|v| collect_pre_auth(v, out)),
        Value::Object(o) => o.values().for_each(|v| collect_pre_auth(v, out)),
        _ => {}
    }
}

impl Placeholder {
    /// Parse the text between `${` and `}`.
    pub fn parse(inner: &str) -> Result<Placeholder> {
        let text = inner.trim();
        let err = |m: &str| Error::placeholder(&format!("${{{inner}}}"), m);
        let name = |s: &str| -> Result<String> {
            let s = s.trim();
            if is_name(s) {
                Ok(s.to_string())
            } else {
                Err(err(&format!("`{s}` is not a valid name")))
            }
        };
        if text == "close_time" {
            return Ok(Placeholder::CloseTime);
        }
        if text == "order_nonce" {
            return Ok(Placeholder::OrderNonce);
        }
        if let Some(open) = text.find('(') {
            let func = text[..open].trim();
            let rest = &text[open + 1..];
            let args_text = rest
                .strip_suffix(')')
                .ok_or_else(|| err("missing closing parenthesis"))?;
            let args: Vec<&str> = args_text.split(',').map(str::trim).collect();
            let want = |n: usize| -> Result<()> {
                if args.len() == n {
                    Ok(())
                } else {
                    Err(err(&format!("`{func}` takes {n} argument(s)")))
                }
            };
            return match func {
                "muxed" | "muxed_contract" => {
                    want(2)?;
                    let id = Some(args[1])
                        .filter(|a| !a.is_empty() && a.bytes().all(|b| b.is_ascii_digit()))
                        .and_then(|a| a.parse::<u64>().ok())
                        .ok_or_else(|| err("the ID must be a decimal 64-bit unsigned integer"))?;
                    let label = name(args[0])?;
                    Ok(if func == "muxed" {
                        Placeholder::Muxed(label, id)
                    } else {
                        Placeholder::MuxedContract(label, id)
                    })
                }
                "signer.payload" => {
                    want(2)?;
                    let payload = hex::decode(args[1])
                        .map_err(|e| err(&format!("payload is not hex: {e}")))?;
                    if payload.is_empty() || payload.len() > 64 {
                        return Err(err("payload must be 1 to 64 bytes"));
                    }
                    Ok(Placeholder::SignerPayload(name(args[0])?, payload))
                }
                "signer.hash_x" => {
                    want(1)?;
                    Ok(Placeholder::SignerHashX(name(args[0])?))
                }
                "hash_x.preimage" => {
                    want(1)?;
                    Ok(Placeholder::HashXPreimage(name(args[0])?))
                }
                "signer.pre_auth_tx" => {
                    want(1)?;
                    if is_step_id(args[0]) {
                        Ok(Placeholder::PreAuthTx(args[0].to_string()))
                    } else {
                        Err(err(&format!("`{}` is not a step ID", args[0])))
                    }
                }
                "contract.sac" => {
                    want(1)?;
                    Ok(Placeholder::ContractSac(name(args[0])?))
                }
                "contract.id" => {
                    want(1)?;
                    Ok(Placeholder::ContractId(name(args[0])?))
                }
                "pool" => {
                    want(2)?;
                    Ok(Placeholder::Pool(name(args[0])?, name(args[1])?))
                }
                _ => Err(err(&format!("unknown function `{func}`"))),
            };
        }
        let (kind, arg) = text
            .split_once('.')
            .ok_or_else(|| err("unknown placeholder"))?;
        match kind {
            "acct" => Ok(Placeholder::Acct(name(arg)?)),
            "seq" => Ok(Placeholder::Seq(name(arg)?)),
            "asset" => Ok(Placeholder::Asset(name(arg)?)),
            "derived" if !arg.is_empty() && arg.split('.').all(|p| !p.is_empty()) => {
                Ok(Placeholder::Derived(arg.to_string()))
            }
            _ => Err(err("unknown placeholder")),
        }
    }
}

/// Everything a placeholder can resolve against, for one item on one network.
#[derive(Debug, Clone, Copy)]
pub struct Resolver<'a> {
    pub keys: &'a Keys,
    pub namespace: &'a str,
    pub network_id: &'a [u8; 32],
    pub assets: &'a Map<String, Value>,
    pub contracts: &'a BTreeMap<String, ContractSpec>,
    /// Current (last used) sequence number per actor.
    pub sequences: &'a BTreeMap<String, i64>,
    /// Root's current sequence number.
    pub root_sequence: i64,
    pub close_time: Option<u64>,
    pub derived: &'a Map<String, Value>,
    pub contract_ids: &'a BTreeMap<String, [u8; 32]>,
    /// Transaction hash per step ID, for `${signer.pre_auth_tx(STEP)}`.
    pub pre_auth: &'a BTreeMap<String, [u8; 32]>,
    /// `${order_nonce}`: set while the steps of a group with `order` are built.
    pub order_nonce: Option<u64>,
}

/// Where a value is being resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// A transaction template: every placeholder must resolve.
    Template,
    /// `expect`/`fields`/`mirrors`: unknown `${derived.…}` stays verbatim.
    Annotation,
}

impl<'a> Resolver<'a> {
    /// Resolve every placeholder in a transaction template (or any value that must be complete).
    pub fn resolve(&self, value: &Value) -> Result<Value> {
        self.walk(value, Mode::Template, 0)
    }

    /// Resolve an annotation block, keeping unknown `${derived.…}` references verbatim.
    pub fn resolve_annotation(&self, value: &Value) -> Result<Value> {
        self.walk(value, Mode::Annotation, 0)
    }

    /// Resolve one string to a string (interpolating every placeholder).
    pub fn resolve_string(&self, text: &str) -> Result<String> {
        match self.string(text, Mode::Template, 0)? {
            Value::String(s) => Ok(s),
            Value::Number(n) => Ok(n.to_string()),
            other => Err(Error::placeholder(
                text,
                format!("resolves to {other}, not a string"),
            )),
        }
    }

    /// The JSON value of one placeholder.
    pub fn value(&self, p: &Placeholder) -> Result<Value> {
        self.value_at(p, 0)
    }

    /// The `Asset` named `name` (`native` when not defined under that name).
    pub fn asset(&self, name: &str) -> Result<Asset> {
        let json = self.asset_json(name, 0)?;
        match xdrcheck_xdr::from_json("Asset", &json, &xdrcheck_xdr::Limits::default())? {
            stellar_xdr::Type::Asset(a) => Ok(*a),
            _ => unreachable!("from_json(\"Asset\") returns an Asset"),
        }
    }

    fn asset_json(&self, name: &str, depth: u32) -> Result<Value> {
        match self.assets.get(name) {
            Some(def) => self.walk(def, Mode::Template, depth + 1),
            None if name == "native" => Ok(Value::String("native".into())),
            None => Err(Error::placeholder(
                &format!("${{asset.{name}}}"),
                "asset is not defined",
            )),
        }
    }

    fn walk(&self, value: &Value, mode: Mode, depth: u32) -> Result<Value> {
        if depth > 8 {
            return Err(Error::Invalid(
                "placeholders nest too deeply (an asset refers to itself?)".into(),
            ));
        }
        Ok(match value {
            Value::String(s) => self.string(s, mode, depth)?,
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|v| self.walk(v, mode, depth))
                    .collect::<Result<_>>()?,
            ),
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| Ok((k.clone(), self.walk(v, mode, depth)?)))
                    .collect::<Result<_>>()?,
            ),
            other => other.clone(),
        })
    }

    fn string(&self, text: &str, mode: Mode, depth: u32) -> Result<Value> {
        let spans = spans(text)?;
        if spans.is_empty() {
            return Ok(Value::String(text.to_string()));
        }
        // A string that is exactly one placeholder takes the placeholder's JSON value.
        if let [(0, end, inner)] = spans.as_slice() {
            if *end == text.len() {
                let p = Placeholder::parse(inner)?;
                if let Some(r) = root_reference(&p, mode) {
                    return Ok(Value::String(r.into()));
                }
                return match self.value_at(&p, depth) {
                    Err(_) if keep_verbatim(&p, mode, self.derived) => {
                        Ok(Value::String(text.to_string()))
                    }
                    other => other,
                };
            }
        }
        let mut out = String::new();
        let mut last = 0;
        for (start, end, inner) in spans {
            out.push_str(&text[last..start]);
            let p = Placeholder::parse(inner)?;
            if let Some(r) = root_reference(&p, mode) {
                out.push_str(r);
                last = end;
                continue;
            }
            match self.value_at(&p, depth) {
                Ok(Value::String(s)) => out.push_str(&s),
                Ok(Value::Number(n)) => out.push_str(&n.to_string()),
                Ok(other) => {
                    return Err(Error::placeholder(
                        &text[start..end],
                        format!("cannot interpolate {other} into a string"),
                    ))
                }
                Err(_) if keep_verbatim(&p, mode, self.derived) => out.push_str(&text[start..end]),
                Err(e) => return Err(e),
            }
            last = end;
        }
        out.push_str(&text[last..]);
        Ok(Value::String(out))
    }

    fn value_at(&self, p: &Placeholder, depth: u32) -> Result<Value> {
        let s = |v: String| Ok(Value::String(v));
        match p {
            Placeholder::Acct(l) => s(self.keys.address(l)?),
            Placeholder::Muxed(l, id) => s(format!(
                "{}",
                stellar_strkey::ed25519::MuxedAccount {
                    ed25519: self.keys.public(l)?,
                    id: *id,
                }
            )),
            Placeholder::MuxedContract(name, id) => s(format!(
                "{}",
                stellar_strkey::MuxedContract {
                    contract_id: self.contract_id(name)?,
                    id: *id,
                }
            )),
            Placeholder::Seq(l) if l == super::keys::ROOT => s(self
                .root_sequence
                .checked_add(1)
                .ok_or_else(|| Error::placeholder("${seq.root}", "sequence number overflows"))?
                .to_string()),
            Placeholder::Seq(l) => {
                self.keys.actor(l)?;
                let current = self.sequences.get(l).ok_or_else(|| {
                    Error::placeholder(
                        &format!("${{seq.{l}}}"),
                        "no sequence number: the account is not funded in setup and none was injected",
                    )
                })?;
                let next = current.checked_add(1).ok_or_else(|| {
                    Error::placeholder(&format!("${{seq.{l}}}"), "sequence number overflows")
                })?;
                s(next.to_string())
            }
            Placeholder::SignerPayload(l, payload) => {
                let sp = stellar_strkey::ed25519::SignedPayload::new(self.keys.public(l)?, payload)
                    .map_err(|e| {
                        Error::placeholder(&format!("${{signer.payload({l}, …)}}"), e.to_string())
                    })?;
                s(format!("{sp}"))
            }
            Placeholder::SignerHashX(name) => {
                let preimage = super::keys::hash_x_preimage(self.namespace, name);
                let digest: [u8; 32] = sha2::Sha256::digest(preimage).into();
                s(format!("{}", stellar_strkey::HashX(digest)))
            }
            Placeholder::HashXPreimage(name) => s(hex::encode(super::keys::hash_x_preimage(
                self.namespace,
                name,
            ))),
            Placeholder::PreAuthTx(step) => match self.pre_auth.get(step) {
                Some(hash) => s(format!("{}", stellar_strkey::PreAuthTx(*hash))),
                None => Err(Error::placeholder(
                    &format!("${{signer.pre_auth_tx({step})}}"),
                    "no transaction hash for that step (is it a step with `tx` that runs at this protocol?)",
                )),
            },
            Placeholder::Asset(name) => self.asset_json(name, depth),
            Placeholder::ContractSac(name) => {
                let asset = self.asset(name)?;
                let id = sac_contract_id(self.network_id, &asset)?;
                s(format!("{}", stellar_strkey::Contract(id)))
            }
            Placeholder::ContractId(name) => s(format!(
                "{}",
                stellar_strkey::Contract(self.contract_id(name)?)
            )),
            Placeholder::Pool(a, b) => {
                use stellar_xdr::{
                    LiquidityPoolConstantProductParameters, LiquidityPoolParameters, WriteXdr,
                };
                let params = LiquidityPoolParameters::LiquidityPoolConstantProduct(
                    LiquidityPoolConstantProductParameters {
                        asset_a: self.asset(a)?,
                        asset_b: self.asset(b)?,
                        fee: 30,
                    },
                );
                let bytes = params
                    .to_xdr(stellar_xdr::Limits::none())
                    .map_err(|e| Error::placeholder("${pool(…)}", e.to_string()))?;
                let id: [u8; 32] = sha2::Sha256::digest(bytes).into();
                s(format!("{}", stellar_strkey::LiquidityPool(id)))
            }
            Placeholder::CloseTime => match self.close_time {
                Some(t) => s(t.to_string()),
                None => Err(Error::placeholder(
                    "${close_time}",
                    "no close time is known",
                )),
            },
            Placeholder::OrderNonce => match self.order_nonce {
                Some(n) => s(n.to_string()),
                None => Err(Error::placeholder(
                    "${order_nonce}",
                    "only a step of a ledger group with `order` has a nonce",
                )),
            },
            Placeholder::Derived(name) => lookup(self.derived, name).cloned().ok_or_else(|| {
                Error::placeholder(&format!("${{derived.{name}}}"), "no such derived value")
            }),
        }
    }

    /// The ID of contract `name`: injected, else derived from its deployer and salt.
    pub fn contract_id(&self, name: &str) -> Result<[u8; 32]> {
        if let Some(id) = self.contract_ids.get(name) {
            return Ok(*id);
        }
        let at = format!("${{contract.id({name})}}");
        let spec = self
            .contracts
            .get(name)
            .ok_or_else(|| Error::placeholder(&at, "contract is not defined"))?;
        let deployer = spec.deployer.as_deref().ok_or_else(|| {
            Error::placeholder(&at, "the contract names no deployer and no ID was injected")
        })?;
        contract_id_from_address(
            self.network_id,
            &self.keys.public(deployer)?,
            &contract_salt(self.namespace, name),
        )
    }
}

/// In an annotation, the root account is a reference to the variant's `derived.accounts.root`.
fn root_reference(p: &Placeholder, mode: Mode) -> Option<&'static str> {
    matches!((p, mode), (Placeholder::Acct(l), Mode::Annotation) if l == super::keys::ROOT)
        .then_some("${derived.accounts.root}")
}

fn keep_verbatim(p: &Placeholder, mode: Mode, derived: &Map<String, Value>) -> bool {
    matches!(p, Placeholder::Derived(name) if mode == Mode::Annotation && lookup(derived, name).is_none())
}

/// Look up `a.b.c`: first as a flat key, then as a path into nested objects.
fn lookup<'v>(derived: &'v Map<String, Value>, name: &str) -> Option<&'v Value> {
    if let Some(v) = derived.get(name) {
        return Some(v);
    }
    let mut parts = name.split('.');
    let mut cur = derived.get(parts.next()?)?;
    for part in parts {
        cur = cur.as_object()?.get(part)?;
    }
    Some(cur)
}

/// `(start, end, inner)` of every `${…}` in `text`; `end` is one past the closing brace.
fn spans(text: &str) -> Result<Vec<(usize, usize, &str)>> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = text[from..].find("${") {
        let start = from + rel;
        let close = text[start..]
            .find('}')
            .ok_or_else(|| Error::placeholder(&text[start..], "unterminated placeholder"))?;
        let end = start + close + 1;
        out.push((start, end, &text[start + 2..end - 1]));
        from = end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_form() {
        assert_eq!(
            Placeholder::parse("acct.A").unwrap(),
            Placeholder::Acct("A".into())
        );
        assert_eq!(
            Placeholder::parse("muxed(A, 18446744073709551615)").unwrap(),
            Placeholder::Muxed("A".into(), u64::MAX)
        );
        assert_eq!(
            Placeholder::parse("signer.payload(D, 2a)").unwrap(),
            Placeholder::SignerPayload("D".into(), vec![0x2a])
        );
        assert_eq!(
            Placeholder::parse("contract.sac(USDC)").unwrap(),
            Placeholder::ContractSac("USDC".into())
        );
        assert_eq!(
            Placeholder::parse("derived.accounts.owner").unwrap(),
            Placeholder::Derived("accounts.owner".into())
        );
        assert_eq!(
            Placeholder::parse("close_time").unwrap(),
            Placeholder::CloseTime
        );
        assert_eq!(
            Placeholder::parse("order_nonce").unwrap(),
            Placeholder::OrderNonce
        );
        assert_eq!(
            Placeholder::parse("signer.hash_x(gate)").unwrap(),
            Placeholder::SignerHashX("gate".into())
        );
        assert_eq!(
            Placeholder::parse("hash_x.preimage(gate)").unwrap(),
            Placeholder::HashXPreimage("gate".into())
        );
        assert_eq!(
            Placeholder::parse("signer.pre_auth_tx(pay-2)").unwrap(),
            Placeholder::PreAuthTx("pay-2".into())
        );
        for bad in [
            "acct.",
            "acct.1A",
            "muxed(A)",
            "muxed(A, -1)",
            "muxed(A, 18446744073709551616)",
            "signer.payload(D, 2)",
            "signer.payload(D, )",
            "nope.A",
            "contract.sac(USDC",
            "derived.",
            "signer.pre_auth_tx(Pay)",
            "signer.pre_auth_tx(a--b)",
            "signer.hash_x(1x)",
            "hash_x.preimage(a, b)",
        ] {
            assert!(Placeholder::parse(bad).is_err(), "{bad} should not parse");
        }
        let too_long = format!("signer.payload(D, {})", "00".repeat(65));
        assert!(Placeholder::parse(&too_long).is_err());
    }

    #[test]
    fn finds_spans() {
        let s = "USDC:${acct.I1} and ${close_time}";
        let sp = spans(s).unwrap();
        assert_eq!(sp.len(), 2);
        assert_eq!(sp[0].2, "acct.I1");
        assert_eq!(&s[sp[1].0..sp[1].1], "${close_time}");
        assert!(spans("${acct.A").is_err());
    }
}
