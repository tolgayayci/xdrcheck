// Throwaway conformance probe for the stellar-xdr crate (+ stellar-strkey).
// Usage: probe <vectors.json> <limits|none> [vectorId ...]
//   limits = Limits{depth: 500, len: input.len()}  (soroban-env-host DEFAULT_XDR_RW_LIMITS depth, len = input as its comment says)
//   none   = Limits::none()
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use stellar_xdr::*;

#[cfg(feature = "p30")]
use stellar_strkey as sk;
#[cfg(not(feature = "p30"))]
use strkey_old as sk;

const XDR_VERSION: &str = env!("XDR_VERSION");
const SK_VERSION: &str = env!("SK_VERSION");

enum R {
    Ok(String, String),
    Na(String),
}
type Res = Result<R, String>;
fn ok(s: impl Into<String>) -> Res { Ok(R::Ok(s.into(), String::new())) }
fn okd(s: impl Into<String>, d: impl Into<String>) -> Res { Ok(R::Ok(s.into(), d.into())) }
fn na(s: &str) -> Res { Ok(R::Na(s.into())) }
fn e<E: std::fmt::Debug>(x: E) -> String { format!("{x:?}") }

fn p30() -> bool { ScAddressType::try_from(5i32).is_ok() && StellarValueType::try_from(3i32).is_ok() }

fn limits(mode: &str, n: usize) -> Limits {
    if mode == "none" { Limits::none() } else { Limits { depth: 500, len: n } }
}
fn sha(b: &[u8]) -> [u8; 32] { Sha256::digest(b).into() }

fn lp_hex(p: &LiquidityPoolParameters) -> String { hex::encode(sha(&p.to_xdr(Limits::none()).unwrap())) }

fn strkey_payload(s: &str) -> Result<String, String> {
    let c = ((s.chars().next().unwrap() as u32) & 0xff) as u8 as char;
    if c.to_ascii_uppercase() == 'S' {
        let k = sk::ed25519::PrivateKey::from_string(s).map_err(e)?;
        return Ok(hex::encode(k.0));
    }
    let k = sk::Strkey::from_string(s).map_err(e)?;
    Ok(match k {
        sk::Strkey::PublicKeyEd25519(k) => hex::encode(k.0),
        sk::Strkey::PreAuthTx(k) => hex::encode(k.0),
        sk::Strkey::HashX(k) => hex::encode(k.0),
        sk::Strkey::MuxedAccountEd25519(m) => format!("{}{:016x}", hex::encode(m.ed25519), m.id),
        sk::Strkey::SignedPayloadEd25519(p) => {
            #[cfg(feature = "p30")]
            let (key, pl) = (p.ed25519().to_vec(), p.payload().to_vec());
            #[cfg(not(feature = "p30"))]
            let (key, pl) = (p.ed25519.to_vec(), p.payload.clone());
            let mut v = key;
            v.extend_from_slice(&(pl.len() as u32).to_be_bytes());
            v.extend_from_slice(&pl);
            while (v.len() - 36) % 4 != 0 { v.push(0) }
            hex::encode(v)
        }
        sk::Strkey::Contract(k) => hex::encode(k.0),
        sk::Strkey::LiquidityPool(k) => hex::encode(k.0),
        sk::Strkey::ClaimableBalance(sk::ClaimableBalance::V0(h)) => format!("00{}", hex::encode(h)),
        #[cfg(feature = "p30")]
        sk::Strkey::MuxedContract(m) => format!("{}{:016x}", hex::encode(m.contract_id), m.id),
        #[allow(unreachable_patterns)]
        _ => return Err("other strkey kind".into()),
    })
}

fn run(v: &Value, mode: &str, dir: &std::path::Path) -> Res {
    let id = v["id"].as_str().unwrap();
    let g = v["group"].as_u64().unwrap();
    let p = &v["params"];
    let ps = |k: &str| p[k].as_str().unwrap_or("").to_string();
    let bytes = v["hex"].as_str().map(|h| hex::decode(h).unwrap()).unwrap_or_default();
    let lim = || limits(mode, bytes.len());
    match g {
        1 if id != "1c" => na("stellar-xdr has no asset/pool builder; LiquidityPoolParameters is a plain struct (order is not validated by the codec)"),
        1 | 3 => {
            let env = TransactionEnvelope::from_xdr(&bytes, lim()).map_err(e)?;
            let rt = env.to_xdr(Limits::none()).map_err(e)? == bytes;
            let TransactionEnvelope::Tx(t) = &env else { return Err("not v1".into()) };
            if id == "1c" {
                let h = env.hash(sha(ps("network").as_bytes())).map_err(e)?;
                let OperationBody::ChangeTrust(ct) = &t.tx.operations[2].body else { return Err("op2".into()) };
                let ChangeTrustAsset::PoolShare(lp) = &ct.line else { return Err("line".into()) };
                return okd(format!("hash={} pool={}", hex::encode(h), lp_hex(lp)), format!("roundtrip={rt}"));
            }
            let src = match &t.tx.source_account { MuxedAccount::MuxedEd25519(m) => m.id, _ => 0 };
            let OperationBody::ManageSellOffer(o) = &t.tx.operations[1].body else { return Err("op1".into()) };
            ok(format!("roundtrip={} src_id={} offer={}", rt, src, o.offer_id))
        }
        2 => na("no builder; MuxedAccountMed25519.id is u64 and offer_id is i64, out-of-range values are unrepresentable"),
        4 => na("stellar-xdr has no ScVal->native conversion (that lives in soroban-sdk/soroban-env)"),
        5 => {
            let mk = |s: &str| -> ScVal {
                let (t, x) = s.split_once(':').unwrap();
                match t {
                    "u32" => ScVal::U32(x.parse().unwrap()),
                    "bytes" => ScVal::Bytes(ScBytes(hex::decode(x).unwrap().try_into().unwrap())),
                    "symbol" => ScVal::Symbol(ScSymbol(x.try_into().unwrap())),
                    _ => ScVal::String(ScString(x.try_into().unwrap())),
                }
            };
            let keys: Vec<String> = p["keys"].as_array().unwrap().iter().map(|k| k.as_str().unwrap().to_string()).collect();
            let m = ScMap::sorted_from(keys.iter().map(|k| ScMapEntry { key: mk(k), val: ScVal::Void })).map_err(e)?;
            let s: Vec<String> = m.0.iter().map(|en| match &en.key {
                ScVal::U32(n) => format!("u32:{n}"),
                ScVal::Bytes(b) => format!("bytes:{}", hex::encode(b.as_slice())),
                ScVal::Symbol(s) => format!("symbol:{}", s.0),
                ScVal::String(s) => format!("string:{}", s.0),
                o => format!("{o:?}"),
            }).collect();
            okd(s.join(","), "ScMap::sorted_from (derived Ord on ScVal)")
        }
        6 | 8 => {
            let t = ps("type");
            let enc = match t.as_str() {
                "ScVal" => ScVal::from_xdr(&bytes, lim()).map_err(e)?.to_xdr(Limits::none()),
                "TransactionEnvelope" => TransactionEnvelope::from_xdr(&bytes, lim()).map_err(e)?.to_xdr(Limits::none()),
                "Memo" => Memo::from_xdr(&bytes, lim()).map_err(e)?.to_xdr(Limits::none()),
                _ => return na("type"),
            }.map_err(e)?;
            if g == 8 { return ok("decoded") }
            okd(hex::encode(&enc), if enc == bytes { "re-encode identical" } else { "re-encode DIFFERS" })
        }
        7 => {
            // native string = to_utf8_string(); escaped Display/FromStr reported in detail
            let (got, det) = match id {
                "7a" => {
                    let Memo::Text(s) = Memo::from_xdr(&bytes, lim()).map_err(e)? else { return Err("memo".into()) };
                    let disp = s.to_string();
                    let via_disp = Memo::Text(StringM::from_str(&disp).map_err(e)?).to_xdr(Limits::none()).map_err(e)?;
                    let det = format!("Display={disp:?} Display->FromStr re-encode identical={}", via_disp == bytes);
                    let native = s.to_utf8_string().map_err(|x| format!("to_utf8_string: {x:?}; {det}"))?;
                    (hex::encode(Memo::Text(native.try_into().map_err(e)?).to_xdr(Limits::none()).map_err(e)?), det)
                }
                "7b" => {
                    let op = Operation::from_xdr(&bytes, lim()).map_err(e)?;
                    (hex::encode(op.to_xdr(Limits::none()).map_err(e)?), "DataValue is BytesM (bytes)".to_string())
                }
                _ => {
                    let sv = ScVal::from_xdr(&bytes, lim()).map_err(e)?;
                    let sm = match &sv { ScVal::String(s) => s.0.clone(), ScVal::Symbol(s) => StringM::<{ u32::MAX }>::try_from(s.0.to_vec()).unwrap(), _ => return Err("t".into()) };
                    let disp = sm.to_string();
                    let det = format!("Display={disp:?}");
                    let native = sm.to_utf8_string().map_err(|x| format!("to_utf8_string: {x:?}; {det}"))?;
                    let back = if id == "7c" { ScVal::String(ScString(native.try_into().map_err(e)?)) } else { ScVal::Symbol(ScSymbol(native.try_into().map_err(e)?)) };
                    (hex::encode(back.to_xdr(Limits::none()).map_err(e)?), det)
                }
            };
            okd(got, det)
        }
        9 => match id {
            "9E1" => {
                #[cfg(feature = "p30")]
                {
                    let c: [u8; 32] = hex::decode(ps("contract")).unwrap().try_into().unwrap();
                    let m = sk::Strkey::MuxedContract(sk::MuxedContract { contract_id: c, id: ps("id").parse().unwrap() });
                    return ok(m.to_string().as_str());
                }
                #[cfg(not(feature = "p30"))]
                na("no MuxedContract in this stellar-strkey")
            }
            "9E2" => ok(ScAddress::from_xdr(&bytes, lim()).map_err(e)?.to_string()),
            "9E4" => ok(MuxedAccount::from_xdr(&bytes, lim()).map_err(e)?.to_string()),
            "9E3" => {
                let k: [u8; 32] = hex::decode(ps("key")).unwrap().try_into().unwrap();
                #[cfg(feature = "p30")]
                let sp = sk::ed25519::SignedPayload::new(k, &[]).map_err(e)?;
                #[cfg(not(feature = "p30"))]
                let sp = sk::ed25519::SignedPayload { ed25519: k, payload: vec![] };
                let s = sk::Strkey::SignedPayloadEd25519(sp).to_string();
                let back = sk::Strkey::from_string(s.as_ref()).map(|_| ()).map_err(e);
                okd(s.to_string(), format!("decode(own output)={back:?}"))
            }
            _ => ok(strkey_payload(&ps("s"))?),
        },
        10 => {
            let raw = std::fs::read(dir.join("..").join(ps("file"))).map_err(e)?;
            let b = LedgerCloseMetaBatch::from_xdr(&raw, limits(mode, raw.len())).map_err(e)?;
            let lcm = &b.ledger_close_metas[0];
            let (vn, h) = match lcm {
                LedgerCloseMeta::V0(m) => (0, &m.ledger_header.header),
                LedgerCloseMeta::V1(m) => (1, &m.ledger_header.header),
                LedgerCloseMeta::V2(m) => (2, &m.ledger_header.header),
            };
            let rt = b.to_xdr(Limits::none()).map_err(e)? == raw;
            ok(format!("lcm=v{} seq={} proto={} sv_ext={} roundtrip={}", vn, h.ledger_seq, h.ledger_version, h.scp_value.ext.name(), rt))
        }
        _ => na("not implemented"),
    }
}

fn judge(v: &Value, got: &str) -> &'static str {
    let mut acc = v["expect"]["accept"].clone();
    if acc == json!("p30") { acc = json!(p30()) }
    if acc == json!(false) { return "wrong" }
    if let Some(w) = v["expect"]["value"].as_str() { if w != got { return "wrong" } }
    "ok"
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let path = std::path::PathBuf::from(&a[1]);
    let mode = a[2].clone();
    let ids: Vec<String> = a[3..].to_vec();
    let vs: Vec<Value> = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let dir = path.parent().unwrap().to_path_buf();
    let lbl = if mode == "none" { "Limits::none()" } else { "Limits{depth:500,len:input}" };
    let ver = format!("stellar-xdr {XDR_VERSION} {lbl}; stellar-strkey {SK_VERSION}");
    for v in &vs {
        let id = v["id"].as_str().unwrap();
        if !ids.is_empty() && !ids.iter().any(|x| x == id) { continue }
        let r = std::panic::catch_unwind(|| run(v, &mode, &dir));
        let (outcome, got, detail) = match r {
            Err(p) => ("crash", None, format!("panic: {}", p.downcast_ref::<String>().cloned().or(p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default())),
            Ok(Err(x)) => ("reject", None, x),
            Ok(Ok(R::Na(x))) => ("n/a", None, x),
            Ok(Ok(R::Ok(g, d))) => (judge(v, &g), Some(g), d),
        };
        println!("{}", json!({"vector": id, "sdk": "rust", "version": ver, "p30": p30(), "outcome": outcome, "got": got, "detail": detail}));
    }
}
