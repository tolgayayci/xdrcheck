//! L4: `strkey` entries and the `api` operations `stellar-xdr` and `stellar-strkey` have a function for.
//!
//! Arguments are the manifest entry's `api.input`, named exactly as the driver protocol's canonical api
//! vocabulary names them; there are no aliases. Bytes are `{"hex": "…"}` (optionally with
//! `"native": "bytes"`) or a plain lower-case hex string under a name ending `_hex`; numbers and IDs are
//! `{"native": "number" | "string" | "bigint", "value": "<decimal>"}`, and a bare string is a native string.
//!
//! | op | arguments (`[…]` optional) | `api` result |
//! |---|---|---|
//! | `strkey.decode` | `text`, [`type`] | `value`: the raw payload, hex |
//! | `strkey.encode` | `type`, `payload_hex` (raw SEP-23 payload) | `value`: the strkey; `self_decode` |
//! | `muxed_account.encode` | `account` (`G…`), `id` | `value`: the `M…` strkey, `xdr_hex`: the `MuxedAccount`; `self_decode` |
//! | `muxed_account.decode` | `text` (`M…`) | `value`: `{account, id}` with `id` a decimal string |
//! | `address.to_strkey` | `xdr_hex`, [`xdr_type`: `MuxedAccount` (default) or `AccountId`] | `value`: the strkey; `self_decode` |
//! | `address.from_sc_address` | `xdr_hex` (`ScAddress`) | as above |
//! | `signer_key.to_strkey` | `xdr_hex` (`SignerKey`) | as above |
//! | `transaction.hash` | `xdr_hex` (`TransactionEnvelope`), `passphrase` | `value`: the hash, hex |
//! | `memo.text_roundtrip` | `xdr_hex` (a text `Memo`) | `value`: hex of the native string's bytes, `xdr_hex`: its re-encoding; `self_decode` |
//! | `xdrjson.decode` | `xdr_type`, `json` (text, or a JSON value) | `xdr_hex`; `self_decode` |
//!
//! An argument that is missing, unknown, of the wrong JSON type or not well-formed is a protocol error: the
//! request does not say what to call. Every other operation is `n_a/op_not_supported`: the crate has no
//! builder, object, native-conversion or asset layer. An ID tagged with a native type whose value the
//! library's `u64` cannot hold is `n_a/value_not_representable`. A strkey payload whose length the library's
//! fixed-size key types cannot hold is refused (`strkey_payload`): the typed API takes nothing else.

use serde_json::{json, Map, Value};
use stellar_xdr::{
    Limits, Memo, MuxedAccount, MuxedAccountMed25519, TransactionEnvelope, Type, Uint256, WriteXdr,
};

use crate::codec::{self, Profile};
use crate::outcome::{Outcome, Reason};
use crate::strkeys::{self, Encoded, Kind};

/// The operations this driver implements (describe `api_ops`).
pub const OPS: &[&str] = &[
    "strkey.decode",
    "strkey.encode",
    "muxed_account.encode",
    "muxed_account.decode",
    "address.to_strkey",
    "address.from_sc_address",
    "signer_key.to_strkey",
    "transaction.hash",
    "memo.text_roundtrip",
    "xdrjson.decode",
];

/// The argument names each operation takes: (required, optional).
fn arg_names(op: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    Some(match op {
        "strkey.decode" => (&["text"], &["type"]),
        "strkey.encode" => (&["type", "payload_hex"], &[]),
        "muxed_account.encode" => (&["account", "id"], &[]),
        "muxed_account.decode" => (&["text"], &[]),
        "address.to_strkey" => (&["xdr_hex"], &["xdr_type"]),
        "address.from_sc_address" | "signer_key.to_strkey" | "memo.text_roundtrip" => {
            (&["xdr_hex"], &[])
        }
        "transaction.hash" => (&["xdr_hex"], &["passphrase"]),
        "xdrjson.decode" => (&["xdr_type", "json"], &[]),
        _ => return None,
    })
}

/// A request that does not say what to call: answered with a protocol error, not an SDK outcome.
type ArgResult<T> = Result<T, String>;

/// The arguments of one call, checked against the operation's names.
struct Args<'a> {
    m: &'a Map<String, Value>,
}

impl<'a> Args<'a> {
    fn new(op: &str, args: &'a Value) -> ArgResult<Args<'a>> {
        let Some(m) = args.as_object() else {
            return Err("args must be a JSON object".into());
        };
        let (req, opt) = arg_names(op).expect("a declared op has argument names");
        for k in m.keys() {
            if !req.contains(&k.as_str()) && !opt.contains(&k.as_str()) {
                return Err(format!(
                    "{op}: unknown argument {k:?} (takes {})",
                    req.iter()
                        .chain(opt.iter())
                        .copied()
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        for k in req {
            if !m.contains_key(*k) {
                return Err(format!("{op}: argument {k} is required"));
            }
        }
        Ok(Args { m })
    }

    fn get(&self, name: &str) -> Option<&'a Value> {
        self.m.get(name)
    }

    /// A string argument: a bare string, or `{"native": "string", "value": "…"}`.
    fn str_opt(&self, name: &str) -> ArgResult<Option<String>> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(Value::Object(o)) if o.get("native") == Some(&json!("string")) && o.len() == 2 => {
                match o.get("value") {
                    Some(Value::String(s)) => Ok(Some(s.clone())),
                    _ => Err(format!(
                        "argument {name}: the value of a native string must be a string"
                    )),
                }
            }
            Some(v) => Err(format!("argument {name}: want a string, got {v}")),
        }
    }

    fn str(&self, name: &str) -> ArgResult<String> {
        self.str_opt(name)?
            .ok_or_else(|| format!("argument {name} is required"))
    }

    /// A byte argument: a lower-case hex string, `{"hex": "…"}` or `{"native": "bytes", "hex": "…"}`.
    fn bytes(&self, name: &str) -> ArgResult<Vec<u8>> {
        let s = match self.get(name) {
            Some(Value::String(s)) => s.as_str(),
            Some(Value::Object(o)) => {
                let tagged = match o.get("native") {
                    None => o.len() == 1,
                    Some(t) => t == "bytes" && o.len() == 2,
                };
                match (tagged, o.get("hex")) {
                    (true, Some(Value::String(s))) => s.as_str(),
                    _ => {
                        return Err(format!(
                            "argument {name}: want {{\"hex\": \"…\"}} or a hex string"
                        ))
                    }
                }
            }
            Some(v) => return Err(format!("argument {name}: want hex bytes, got {v}")),
            None => return Err(format!("argument {name} is required")),
        };
        if s.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(format!("argument {name}: hex must be lower-case"));
        }
        hex::decode(s).map_err(|e| format!("argument {name} is not hex: {e}"))
    }

    /// An integer the library holds as `u64`. A tagged value it cannot hold is `value_not_representable`; an
    /// untagged one is a malformed argument.
    fn u64(&self, name: &str) -> ArgResult<Result<u64, Outcome>> {
        let (tag, text) = match self.get(name) {
            Some(Value::String(s)) => (None, s.clone()),
            Some(Value::Object(o)) => {
                let tag = match o.get("native") {
                    Some(Value::String(t)) if matches!(t.as_str(), "number" | "string" | "bigint") => {
                        t.clone()
                    }
                    _ => {
                        return Err(format!(
                            "argument {name}: want {{\"native\": \"number\" | \"string\" | \"bigint\", \"value\": \"<decimal>\"}}"
                        ))
                    }
                };
                match (o.len(), o.get("value")) {
                    (2, Some(Value::String(v))) => (Some(tag), v.clone()),
                    _ => {
                        return Err(format!(
                            "argument {name}: a tagged value needs exactly a string value"
                        ))
                    }
                }
            }
            Some(v) => return Err(format!("argument {name}: want an integer, got {v}")),
            None => return Err(format!("argument {name} is required")),
        };
        match (text.parse::<u64>(), tag) {
            (Ok(n), _) => Ok(Ok(n)),
            (Err(_), Some(tag)) => Ok(Err(Outcome::n_a(
                "value_not_representable",
                format!(
                    "argument {name}: the {tag} {text:?} is not representable as the u64 the library takes"
                ),
            ))),
            (Err(_), None) => Err(format!("argument {name}: {text:?} is not a decimal integer")),
        }
    }
}

fn api(m: Map<String, Value>) -> Outcome {
    Outcome::ok(Map::new()).actual("api", Value::Object(m))
}

/// Runs a strkey entry: decode `text`, typed by `declared_type` when given.
pub fn strkey_entry(text: &str, declared: Option<&str>) -> ArgResult<Outcome> {
    let kind = match declared {
        None => None,
        Some(d) => Some(Kind::from_name(d).ok_or_else(|| format!("unknown strkey type {d:?}"))?),
    };
    Ok(match strkeys::decode(text, kind) {
        Ok(d) => {
            let mut m = Map::new();
            m.insert("value".into(), json!(hex::encode(&d.payload)));
            api(m)
        }
        Err(r) => Outcome::reject(r),
    })
}

/// Runs an `api` operation. `Err` is a protocol error: the arguments do not say what to call.
pub fn run(
    op: &str,
    args: &Value,
    passphrase: Option<&str>,
    profile: Profile,
) -> ArgResult<Outcome> {
    if !OPS.contains(&op) {
        return Ok(Outcome::n_a(
            "op_not_supported",
            format!(
                "stellar-xdr {} has no API for {op}",
                stellar_xdr::VERSION.pkg
            ),
        ));
    }
    let a = Args::new(op, args)?;
    match op {
        "strkey.decode" => strkey_entry(&a.str("text")?, a.str_opt("type")?.as_deref()),
        "strkey.encode" => strkey_encode(&a),
        "muxed_account.encode" => muxed_encode(&a),
        "muxed_account.decode" => muxed_decode(&a),
        "address.to_strkey" => {
            let ty = a
                .str_opt("xdr_type")?
                .unwrap_or_else(|| "MuxedAccount".into());
            if ty != "MuxedAccount" && ty != "AccountId" {
                return Err(format!(
                    "address.to_strkey: xdr_type {ty:?} is not MuxedAccount or AccountId"
                ));
            }
            xdr_to_strkey(&a, &ty, profile)
        }
        "address.from_sc_address" => xdr_to_strkey(&a, "ScAddress", profile),
        "signer_key.to_strkey" => xdr_to_strkey(&a, "SignerKey", profile),
        "transaction.hash" => tx_hash(&a, passphrase, profile),
        "memo.text_roundtrip" => memo_roundtrip(&a, profile),
        "xdrjson.decode" => xdrjson_decode(&a, profile),
        _ => unreachable!("every declared op is dispatched"),
    }
}

/// `self_decode` of a strkey the library produced, and the outcome it implies.
fn with_self_decode(
    text: String,
    kind: Option<Kind>,
    entry_point: &str,
    extra: Map<String, Value>,
) -> Outcome {
    let mut m = extra;
    m.insert("value".into(), json!(text));
    match strkeys::decode(&text, kind) {
        Ok(_) => {
            m.insert("self_decode".into(), json!("accepted"));
            api(m)
        }
        Err(r) => {
            m.insert("self_decode".into(), json!("rejected"));
            let msg = format!(
                "{} produced {text}, which its own decoder rejects ({})",
                entry_point, r.code
            );
            own_output_rejected(m, msg, entry_point)
        }
    }
}

fn own_output_rejected(m: Map<String, Value>, msg: String, entry_point: &str) -> Outcome {
    let mut o = Outcome::diverge(
        Reason::new("own_output_rejected")
            .message(msg)
            .entry_point(entry_point),
    );
    o.actual.insert("api".into(), Value::Object(m));
    o
}

fn strkey_encode(a: &Args) -> ArgResult<Outcome> {
    let ty = a.str("type")?;
    let kind = Kind::from_name(&ty).ok_or_else(|| format!("unknown strkey type {ty:?}"))?;
    let payload = a.bytes("payload_hex")?;
    Ok(match strkeys::encode(kind, &payload) {
        (Encoded::Text(s), ep) => with_self_decode(s, Some(kind), ep, Map::new()),
        (Encoded::Refused(r), _) => Outcome::reject(r),
        (Encoded::Unrepresentable(m), _) => Outcome::reject(
            Reason::new("strkey_payload")
                .message(format!(
                    "{m}: the library's typed key for {ty} cannot be built from it"
                ))
                .entry_point("stellar_strkey typed constructor"),
        ),
        (Encoded::Unsupported(m), _) => Outcome::n_a("type_not_generated", m),
    })
}

fn muxed_encode(a: &Args) -> ArgResult<Outcome> {
    let g = a.str("account")?;
    let id = match a.u64("id")? {
        Ok(id) => id,
        Err(o) => return Ok(o),
    };
    let key = match strkeys::decode(&g, Some(Kind::Account)) {
        Ok(d) => d.payload,
        Err(r) => return Ok(Outcome::reject(r)),
    };
    let mut p = key.clone();
    p.extend_from_slice(&id.to_be_bytes());
    let (enc, ep) = strkeys::encode(Kind::MuxedAccount, &p);
    let Encoded::Text(text) = enc else {
        return Ok(Outcome::n_a(
            "type_not_generated",
            "the library cannot hold this muxed account",
        ));
    };
    let mut extra = Map::new();
    let ed25519: [u8; 32] = key.try_into().unwrap_or([0; 32]);
    let xdr = MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
        id,
        ed25519: Uint256(ed25519),
    });
    if let Ok(b) = xdr.to_xdr(Limits::none()) {
        extra.insert("xdr_hex".into(), json!(hex::encode(b)));
    }
    Ok(with_self_decode(text, Some(Kind::MuxedAccount), ep, extra))
}

fn muxed_decode(a: &Args) -> ArgResult<Outcome> {
    let t = a.str("text")?;
    Ok(match strkeys::decode(&t, Some(Kind::MuxedAccount)) {
        Ok(d) => {
            let (key, id) = d.payload.split_at(32);
            let account = match strkeys::encode(Kind::Account, key) {
                (Encoded::Text(s), _) => s,
                _ => {
                    return Ok(Outcome::reject(
                        Reason::new("strkey_payload")
                            .message("the account key cannot be rendered")
                            .entry_point("stellar_strkey::ed25519::PublicKey::to_string"),
                    ))
                }
            };
            let id = u64::from_be_bytes(id.try_into().unwrap_or([0; 8]));
            let mut m = Map::new();
            m.insert(
                "value".into(),
                json!({"account": account, "id": id.to_string()}),
            );
            api(m)
        }
        Err(r) => Outcome::reject(r),
    })
}

fn decode_arg(a: &Args, ty: &str, profile: Profile) -> ArgResult<Result<Type, Outcome>> {
    let bytes = a.bytes("xdr_hex")?;
    let Some(tv) = codec::type_variant(ty) else {
        return Ok(Err(Outcome::n_a(
            "type_not_generated",
            format!("stellar-xdr has no type {ty}"),
        )));
    };
    Ok(codec::decode(tv, &bytes, profile).map_err(|r| r.into_outcome("L4")))
}

/// Renders an XDR address-like value as a strkey through the crate's `Display`.
fn xdr_to_strkey(a: &Args, ty: &str, profile: Profile) -> ArgResult<Outcome> {
    let t = match decode_arg(a, ty, profile)? {
        Ok(t) => t,
        Err(o) => return Ok(o),
    };
    let (text, ep) = match &t {
        Type::MuxedAccount(v) => (v.to_string(), "stellar_xdr::MuxedAccount::to_string"),
        Type::AccountId(v) => (v.to_string(), "stellar_xdr::AccountId::to_string"),
        Type::SignerKey(v) => (v.to_string(), "stellar_xdr::SignerKey::to_string"),
        Type::ScAddress(v) => (v.to_string(), "stellar_xdr::ScAddress::to_string"),
        _ => unreachable!("only address-like types are decoded here"),
    };
    // Accept/reject of the text by the library's generic decoder.
    Ok(with_self_decode(text, None, ep, Map::new()))
}

fn tx_hash(a: &Args, passphrase: Option<&str>, profile: Profile) -> ArgResult<Outcome> {
    let pp = match a.str_opt("passphrase")? {
        Some(p) => p,
        None => passphrase
            .map(String::from)
            .ok_or("transaction.hash: argument passphrase is required")?,
    };
    let t = match decode_arg(a, "TransactionEnvelope", profile)? {
        Ok(t) => t,
        Err(o) => return Ok(o),
    };
    let Type::TransactionEnvelope(env) = t else {
        unreachable!("a TransactionEnvelope decodes to one")
    };
    let env: &TransactionEnvelope = &env;
    let network_id: [u8; 32] = sha2::Digest::finalize(
        <sha2::Sha256 as sha2::Digest>::new_with_prefix(pp.as_bytes()),
    )
    .into();
    Ok(match env.hash(network_id) {
        Ok(h) => {
            let mut m = Map::new();
            m.insert("value".into(), json!(hex::encode(h)));
            api(m)
        }
        Err(e) => Outcome::reject(codec::reason(&e, "stellar_xdr::TransactionEnvelope::hash")),
    })
}

fn memo_roundtrip(a: &Args, profile: Profile) -> ArgResult<Outcome> {
    let t = match decode_arg(a, "Memo", profile)? {
        Ok(t) => t,
        Err(o) => return Ok(o),
    };
    let Type::Memo(memo) = t else {
        unreachable!("a Memo decodes to one")
    };
    let Memo::Text(s) = *memo else {
        return Err("memo.text_roundtrip: xdr_hex is not a MEMO_TEXT value".into());
    };
    let native = match s.to_utf8_string() {
        Ok(n) => n,
        Err(e) => {
            return Ok(Outcome::reject(
                codec::reason(&e, "stellar_xdr::StringM::to_utf8_string").message(format!(
                    "{e}; the library has no lossless native string for these bytes"
                )),
            )
            .with_code("lossy_conversion_refused"))
        }
    };
    let back = match native.clone().try_into() {
        Ok(sm) => Memo::Text(sm),
        Err(e) => {
            return Ok(Outcome::reject(codec::reason(
                &e,
                "stellar_xdr::StringM::try_from",
            )))
        }
    };
    let bytes = match back.to_xdr(Limits::none()) {
        Ok(b) => b,
        Err(e) => {
            return Ok(Outcome::reject(codec::reason(
                &e,
                "stellar_xdr::WriteXdr::to_xdr",
            )))
        }
    };
    let mut m = Map::new();
    m.insert("value".into(), json!(hex::encode(native.as_bytes())));
    m.insert("xdr_hex".into(), json!(hex::encode(&bytes)));
    Ok(self_decoded(
        m,
        "Memo",
        &bytes,
        profile,
        "stellar_xdr::WriteXdr::to_xdr",
    ))
}

/// Adds `self_decode` for XDR bytes the library wrote, and the outcome it implies.
fn self_decoded(
    mut m: Map<String, Value>,
    ty: &str,
    bytes: &[u8],
    profile: Profile,
    entry_point: &str,
) -> Outcome {
    let tv = codec::type_variant(ty).expect("the type was just encoded");
    match codec::decode(tv, bytes, profile) {
        Ok(_) => {
            m.insert("self_decode".into(), json!("accepted"));
            api(m)
        }
        Err(r) => {
            m.insert("self_decode".into(), json!("rejected"));
            let msg = format!(
                "{entry_point} wrote bytes that {} rejects ({})",
                codec::ENTRY_POINT,
                r.reason.code
            );
            own_output_rejected(m, msg, entry_point)
        }
    }
}

fn xdrjson_decode(a: &Args, profile: Profile) -> ArgResult<Outcome> {
    let ty = a.str("xdr_type")?;
    let Some(tv) = codec::type_variant(&ty) else {
        return Ok(Outcome::n_a(
            "type_not_generated",
            format!("stellar-xdr has no type {ty}"),
        ));
    };
    let text = match a.get("json") {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => return Err("xdrjson.decode: argument json is required".into()),
    };
    let ep = "stellar_xdr::Type::from_json";
    let t = match Type::from_json(tv, text.as_bytes()) {
        Ok(t) => t,
        Err(e) => return Ok(Outcome::reject(codec::reason(&e, ep))),
    };
    let bytes = match t.to_xdr(Limits::none()) {
        Ok(b) => b,
        Err(e) => {
            return Ok(Outcome::diverge(
                codec::reason(&e, "stellar_xdr::WriteXdr::to_xdr")
                    .message(format!("the value parsed from JSON cannot be encoded: {e}")),
            )
            .with_code("own_output_rejected"))
        }
    };
    let mut m = Map::new();
    m.insert("xdr_hex".into(), json!(hex::encode(&bytes)));
    let ep_msg = format!("{ep} accepted the JSON and the encoder");
    Ok(self_decoded(m, tv.name(), &bytes, profile, &ep_msg).with_entry_point(ep))
}

impl Outcome {
    /// Replaces the reason code, keeping message, class and entry point.
    fn with_code(mut self, code: &'static str) -> Outcome {
        if let Some(r) = &mut self.reason {
            r.code = code;
        }
        self
    }

    /// Sets the reason's entry point, when there is a reason.
    fn with_entry_point(mut self, ep: &str) -> Outcome {
        if let Some(r) = self.reason.take() {
            self.reason = Some(Box::new((*r).entry_point(ep)));
        }
        self
    }
}
