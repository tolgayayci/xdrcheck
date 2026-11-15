//! xdrcheck-driver-soroban-spec: the conformance driver for the Rust `soroban-spec` crate, the contract-spec reader of
//! the Soroban Rust SDK and stellar-cli. One source serves every pinned version (drivers/soroban-spec/<version>/).
//!
//! It speaks the driver protocol xcc.driver/1 (corpus/schema/driver-protocol.schema.json) and answers the spec
//! level only: `soroban_spec::read::from_wasm` on a Wasm module, `soroban_spec::read::parse_raw` on a bare
//! SCSpecEntry stream, and the entries the crate returned in the neutral rendering of
//! docs/conformance-protocol.md (spec level). It never sees expected values.
use std::io::{BufRead, Write};

use serde_json::{json, Value};
use soroban_spec::read::{from_wasm, parse_raw, FromWasmError};
use stellar_xdr::{
    Limits, ReadXdr, ScAddressType, ScSpecEntry, ScSpecEventParamLocationV0, ScSpecTypeDef,
    ScSpecUdtUnionCaseV0, ScSymbol, StellarValueType, StringM,
};

const TAG: &str = "xcc.driver/1";

/// The bytes of a spec name (a string or a symbol).
trait Name {
    fn bytes(&self) -> &[u8];
}
impl<const N: u32> Name for StringM<N> {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }
}
impl Name for ScSymbol {
    fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

fn name_text(n: &impl Name) -> String {
    let b = n.bytes();
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => b
            .iter()
            .map(|&c| {
                if (0x20..0x7f).contains(&c) && c != b'\\' {
                    (c as char).to_string()
                } else {
                    format!("\\x{c:02x}")
                }
            })
            .collect(),
    }
}

fn type_text(t: &ScSpecTypeDef) -> String {
    use ScSpecTypeDef as T;
    match t {
        T::Val => "val".into(),
        T::Bool => "bool".into(),
        T::Void => "void".into(),
        T::Error => "error".into(),
        T::U32 => "u32".into(),
        T::I32 => "i32".into(),
        T::U64 => "u64".into(),
        T::I64 => "i64".into(),
        T::Timepoint => "timepoint".into(),
        T::Duration => "duration".into(),
        T::U128 => "u128".into(),
        T::I128 => "i128".into(),
        T::U256 => "u256".into(),
        T::I256 => "i256".into(),
        T::Bytes => "bytes".into(),
        T::String => "string".into(),
        T::Symbol => "symbol".into(),
        T::Address => "address".into(),
        T::MuxedAddress => "muxed_address".into(),
        T::Option(o) => format!("option<{}>", type_text(&o.value_type)),
        T::Result(r) => format!(
            "result<{},{}>",
            type_text(&r.ok_type),
            type_text(&r.error_type)
        ),
        T::Vec(v) => format!("vec<{}>", type_text(&v.element_type)),
        T::Map(m) => format!(
            "map<{},{}>",
            type_text(&m.key_type),
            type_text(&m.value_type)
        ),
        T::Tuple(t) => format!(
            "tuple<{}>",
            t.value_types
                .iter()
                .map(type_text)
                .collect::<Vec<_>>()
                .join(",")
        ),
        T::BytesN(b) => format!("bytes_n<{}>", b.n),
        T::Udt(u) => format!("udt:{}", name_text(&u.name)),
    }
}

fn arg(name: &impl Name, ty: String) -> Value {
    json!({"name": name_text(name), "type": ty})
}

fn entry_fact(e: &ScSpecEntry) -> Value {
    match e {
        ScSpecEntry::FunctionV0(f) => json!({
            "kind": "function", "name": name_text(&f.name),
            "args": f.inputs.iter().map(|i| arg(&i.name, type_text(&i.type_))).collect::<Vec<_>>(),
            "outputs": f.outputs.iter().map(type_text).collect::<Vec<_>>(),
        }),
        ScSpecEntry::UdtStructV0(s) => json!({
            "kind": "struct", "name": name_text(&s.name),
            "args": s.fields.iter().map(|f| arg(&f.name, type_text(&f.type_))).collect::<Vec<_>>(),
        }),
        ScSpecEntry::UdtUnionV0(u) => json!({
            "kind": "union", "name": name_text(&u.name),
            "args": u.cases.iter().map(|c| match c {
                ScSpecUdtUnionCaseV0::VoidV0(v) => arg(&v.name, "void".into()),
                ScSpecUdtUnionCaseV0::TupleV0(t) => arg(&t.name, format!("tuple<{}>", t.type_.iter().map(type_text).collect::<Vec<_>>().join(","))),
            }).collect::<Vec<_>>(),
        }),
        ScSpecEntry::UdtEnumV0(u) => json!({
            "kind": "enum", "name": name_text(&u.name),
            "args": u.cases.iter().map(|c| arg(&c.name, format!("={}", c.value))).collect::<Vec<_>>(),
        }),
        ScSpecEntry::UdtErrorEnumV0(u) => json!({
            "kind": "error_enum", "name": name_text(&u.name),
            "args": u.cases.iter().map(|c| arg(&c.name, format!("={}", c.value))).collect::<Vec<_>>(),
        }),
        ScSpecEntry::EventV0(ev) => json!({
            "kind": "event", "name": name_text(&ev.name),
            "args": ev.params.iter().map(|p| arg(&p.name, format!("{}@{}", type_text(&p.type_), match p.location {
                ScSpecEventParamLocationV0::Data => "data",
                ScSpecEventParamLocationV0::TopicList => "topic_list",
            }))).collect::<Vec<_>>(),
        }),
    }
}

/// The reason code of an XDR refusal, from the crate's error variant.
fn xdr_code(e: &stellar_xdr::Error) -> &'static str {
    use stellar_xdr::Error as E;
    match e {
        E::LengthExceedsMax => "length_exceeds_max",
        E::DepthLimitExceeded => "depth",
        E::Io(_) => "length_exceeds_input",
        E::NonZeroPadding => "nonzero_padding",
        E::Invalid => "union_arm_undeclared",
        _ => "decode_error",
    }
}

fn run_spec(input: &Value) -> Value {
    let container = input["container"].as_str().unwrap_or("");
    let Some(path) = input["path"].as_str() else {
        return json!({"protocol_error": "a spec input needs a path"});
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return json!({"protocol_error": format!("cannot read the input: {e}")}),
    };
    let (entry_point, res) = match container {
        "wasm" => (
            "soroban_spec::read::from_wasm",
            from_wasm(&bytes).map_err(|e| {
                let code = match &e {
                    FromWasmError::Parse(x) => xdr_code(x),
                    FromWasmError::Read(_) | FromWasmError::NotFound => "decode_error",
                };
                (
                    code,
                    format!("{e}: {e:?}"),
                    match e {
                        FromWasmError::NotFound => "NotFound",
                        FromWasmError::Read(_) => "Read",
                        FromWasmError::Parse(_) => "Parse",
                    },
                )
            }),
        ),
        "xdr-stream" => (
            "soroban_spec::read::parse_raw",
            parse_raw(&bytes)
                .map_err(|e| (xdr_code(&e), format!("{e}: {e:?}"), "stellar_xdr::Error")),
        ),
        other => return json!({"protocol_error": format!("unknown container {other:?}")}),
    };
    match res {
        Ok(entries) => json!({"outcome": "ok", "actual": {"spec": {
            "entries": entries.iter().map(entry_fact).collect::<Vec<_>>(),
            "entry_point": entry_point,
        }}}),
        Err((code, msg, class)) => json!({"outcome": "reject", "reason": {
            "code": code, "message": msg.chars().take(500).collect::<String>(), "error_class": class, "entry_point": entry_point,
        }}),
    }
}

fn checksums() -> Vec<(String, String, String)> {
    env!("XDRCHECK_LOCK_CHECKSUMS")
        .split(';')
        .filter_map(|s| {
            let mut p = s.split(' ');
            Some((
                p.next()?.to_string(),
                p.next()?.to_string(),
                p.next().unwrap_or("").to_string(),
            ))
        })
        .collect()
}

fn describe(id: &Value) -> Value {
    let sums = checksums();
    let find = |n: &str| sums.iter().find(|(name, _, _)| name == n).cloned();
    let (_, version, sum) = find("soroban-spec").unwrap_or_default();
    let mut sdk = json!({"ecosystem": "crates.io", "package": "soroban-spec", "version": version});
    if !sum.is_empty() {
        sdk["integrity"] = json!(format!("sha256:{sum}"));
    }
    if let Some((n, v, s)) = find("stellar-xdr") {
        sdk["dependencies"] =
            json!([{"package": n, "version": v, "integrity": format!("sha256:{s}")}]);
    }
    // The schema probes, read from the stellar-xdr version soroban-spec decodes with.
    let probes = json!({
        "sc_address_type_muxed_contract": ScAddressType::from_xdr([0u8, 0, 0, 5], Limits::none()).is_ok(),
        "stellar_value_signed_ms": StellarValueType::from_xdr([0u8, 0, 0, 3], Limits::none()).is_ok(),
    });
    json!({
        "xcc": TAG, "id": id, "op": "describe",
        "driver": {"name": "xdrcheck-driver-soroban-spec", "version": "0.1.0", "adapter": "soroban-spec"},
        "sdk": sdk,
        "runtime": {"name": "rustc", "version": env!("XDRCHECK_RUSTC_VERSION"), "os": std::env::consts::OS, "arch": std::env::consts::ARCH},
        "xdr_schema": {"probes": probes},
        "levels": ["spec"],
        "api_ops": [],
        "decode": {"entry_point": "soroban_spec::read::parse_raw", "default_depth": 500, "depth_configurable": false, "checks_consumed_length": true},
    })
}

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                let _ = writeln!(
                    out,
                    "{}",
                    json!({"xcc": TAG, "op": "protocol_error", "error": "the request is not JSON"})
                );
                continue;
            }
        };
        let id = req["id"].clone();
        let resp = match req["op"].as_str() {
            Some("describe") => describe(&id),
            Some("shutdown") => {
                let _ = writeln!(
                    out,
                    "{}",
                    json!({"xcc": TAG, "id": id, "op": "shutdown", "ok": true})
                );
                let _ = out.flush();
                return;
            }
            Some("run") => {
                let level = req["level"].as_str().unwrap_or("");
                let r = if level == "spec" && req["input"]["kind"] == "spec" {
                    run_spec(&req["input"])
                } else {
                    json!({"protocol_error": format!("{level}: this driver answers the spec level on spec inputs only")})
                };
                if let Some(e) = r.get("protocol_error") {
                    json!({"xcc": TAG, "id": id, "op": "protocol_error", "error": e})
                } else {
                    let mut m = json!({"xcc": TAG, "id": id, "op": "run", "entry": req["entry"], "level": level});
                    if let Some(v) = req.get("variant") {
                        m["variant"] = v.clone();
                    }
                    for (k, v) in r.as_object().into_iter().flatten() {
                        m[k] = v.clone();
                    }
                    m
                }
            }
            _ => json!({"xcc": TAG, "id": id, "op": "protocol_error", "error": "unknown op"}),
        };
        let _ = writeln!(out, "{resp}");
        let _ = out.flush();
    }
}
