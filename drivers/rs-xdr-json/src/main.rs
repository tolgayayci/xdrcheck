//! xdrcheck-driver-rs-xdr-json: the json-level conformance driver for the Rust `stellar-xdr` crate's XDR-JSON (SEP-51)
//! support, the converter stellar-cli, go-stellar-xdr-json and js-stellar-xdr-json are built on. One source serves
//! the pinned release and the pinned main commit (drivers/rs-xdr-json/<version>/).
//!
//! For each json request (an xdr input) it decodes the bytes as the named type (`Type::read_xdr_to_end` under the
//! limits the crate's own `stellar-xdr decode` uses, `Limits::none()`), writes the value's JSON with
//! `serde_json::to_string`, validates that JSON against the crate's own JSON Schema for the type
//! (`TypeVariant::json_schema` with the crate's draft 2019-09 settings, checked by the `jsonschema` crate), and reads
//! it back with `Type::from_json` and re-encodes it. It reports the canonical JSON's sha256, the schema verdict and
//! the round trip (docs/conformance-protocol.md §2a). It never sees expected values.
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{Limited, Limits, Type, TypeVariant, WriteXdr};

const TAG: &str = "xcc.driver/1";
const STACK: usize = 256 << 20;

/// Canonical JSON: object keys sorted by code point, no whitespace, strings escaping only `"`, `\` and control
/// characters (`\u00XX`), numbers as written.
fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null | Value::Bool(_) | Value::Number(_) => out.push_str(&v.to_string()),
        Value::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(&Value::String((*k).clone()), out);
                out.push(':');
                canonical(&m[*k], out);
            }
            out.push('}');
        }
    }
}

/// The crate's schemas name definitions after generic types (`StringM<32>`) and refer to them as
/// `#/definitions/StringM<32>`, which is not a URI reference (RFC 3986 has no `<`, `>` or space), so a strict
/// validator refuses to compile them. The JSON Pointer in a URI fragment must percent-encode those characters
/// (RFC 6901 §6); this rewrites every `$ref` that way, which points at the same definitions.
fn uri_safe_refs(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if k == "$ref" {
                    if let Value::String(s) = x {
                        let mut o = String::new();
                        for c in s.chars() {
                            match c {
                                '<' | '>' | ' ' | '"' | '{' | '}' | '|' | '\\' | '^' | '`' => {
                                    let mut buf = [0u8; 4];
                                    for b in c.encode_utf8(&mut buf).bytes() {
                                        o.push_str(&format!("%{b:02X}"));
                                    }
                                }
                                c => o.push(c),
                            }
                        }
                        *s = o;
                    }
                } else {
                    uri_safe_refs(x);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(uri_safe_refs),
        _ => {}
    }
}

/// A type's compiled schema, or why it does not compile.
type Compiled = Result<Arc<jsonschema::Validator>, String>;

/// The compiled schema of a type, built once per type.
fn validator(variant: TypeVariant) -> Compiled {
    static CACHE: OnceLock<Mutex<HashMap<String, Compiled>>> = OnceLock::new();
    let mut c = CACHE.get_or_init(Default::default).lock().expect("cache");
    c.entry(variant.name().to_string())
        .or_insert_with(|| {
            let mut schema = serde_json::to_value(
                variant.json_schema(stellar_xdr::schemars::settings_draft201909().into_generator()),
            )
            .expect("a schema is JSON");
            uri_safe_refs(&mut schema);
            jsonschema::validator_for(&schema)
                .map(Arc::new)
                .map_err(|e| e.to_string())
        })
        .clone()
}

fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn trim(s: String) -> String {
    s.chars().take(500).collect()
}

fn decode_code(e: &stellar_xdr::Error) -> &'static str {
    use stellar_xdr::Error as E;
    match e {
        E::LengthExceedsMax => "length_exceeds_max",
        E::DepthLimitExceeded => "depth",
        E::Io(_) => "length_exceeds_input",
        E::NonZeroPadding => "nonzero_padding",
        E::Invalid => "decode_error",
        _ => "decode_error",
    }
}

fn read_input(input: &Value) -> Result<Vec<u8>, String> {
    let mut b = match (input["path"].as_str(), input["xdr_hex"].as_str()) {
        (Some(p), _) => std::fs::read(p).map_err(|e| format!("cannot read the input: {e}"))?,
        (None, Some(h)) => hex::decode(h).map_err(|e| format!("bad xdr_hex: {e}"))?,
        _ => return Err("an xdr input needs path or xdr_hex".into()),
    };
    if input["framing"] == "record-marked" {
        let want = input["frame_index"].as_u64().unwrap_or(0) as usize;
        let (mut off, mut idx, mut cur) = (0usize, 0usize, Vec::new());
        loop {
            if off + 4 > b.len() {
                return Err("record mark truncated".into());
            }
            let h = u32::from_be_bytes(b[off..off + 4].try_into().unwrap());
            let n = (h & 0x7fff_ffff) as usize;
            off += 4;
            if off + n > b.len() {
                return Err("record fragment truncated".into());
            }
            cur.extend_from_slice(&b[off..off + n]);
            off += n;
            if h & 0x8000_0000 != 0 {
                if idx == want {
                    b = cur;
                    break;
                }
                idx += 1;
                cur = Vec::new();
            }
        }
    }
    Ok(b)
}

fn run_json(input: &Value) -> Value {
    let Some(name) = input["xdr_type"].as_str() else {
        return json!({"protocol_error": "an xdr input needs xdr_type"});
    };
    let bytes = match read_input(input) {
        Ok(b) => b,
        Err(e) => return json!({"protocol_error": e}),
    };
    let Ok(variant) = TypeVariant::from_str(name) else {
        return json!({"outcome": "n_a", "reason": {"code": "type_not_generated", "message": format!("no type {name}")}});
    };
    let limits = Limits::none();
    let value = match Type::read_xdr_to_end(
        variant,
        &mut Limited::new(std::io::Cursor::new(&bytes), limits),
    ) {
        Ok(v) => v,
        Err(e) => {
            return json!({"outcome": "reject", "reason": {"code": decode_code(&e), "message": trim(e.to_string()), "entry_point": "Type::read_xdr_to_end"}})
        }
    };
    let text = match serde_json::to_string(&value) {
        Ok(t) => t,
        Err(e) => {
            return json!({"outcome": "diverge", "reason": {"code": "own_output_rejected", "message": trim(e.to_string()), "entry_point": "serde_json::to_string"}})
        }
    };
    let mut de = serde_json::Deserializer::from_str(&text);
    de.disable_recursion_limit();
    let parsed: Value = match serde::Deserialize::deserialize(&mut de) {
        Ok(v) => v,
        Err(e) => {
            return json!({"outcome": "diverge", "reason": {"code": "own_output_rejected", "message": trim(format!("the JSON does not parse: {e}")), "entry_point": "serde_json::to_string"}})
        }
    };
    let mut canon = String::new();
    canonical(&parsed, &mut canon);
    let mut facts = json!({"json_sha256": sha(canon.as_bytes()), "json_bytes": text.len()});

    match validator(variant).as_deref() {
        Ok(v) => {
            let errs: Vec<String> = v
                .iter_errors(&parsed)
                .take(5)
                .map(|e| trim(format!("{} at {}", e, e.instance_path())))
                .collect();
            facts["schema"] = json!(if errs.is_empty() { "valid" } else { "invalid" });
            if !errs.is_empty() {
                facts["schema_errors"] = json!(errs);
            }
        }
        Err(e) => {
            facts["schema"] = json!("invalid");
            facts["schema_errors"] =
                json!([trim(format!("the crate's schema does not compile: {e}"))]);
        }
    }

    match Type::from_json(variant, text.as_bytes()) {
        Ok(back) => match back.to_xdr(Limits::none()) {
            Ok(b) => {
                facts["roundtrip"] = json!(if b == bytes { "identical" } else { "changed" });
                facts["roundtrip_sha256"] = json!(sha(&b));
            }
            Err(e) => {
                facts["roundtrip"] = json!("refused");
                facts["roundtrip_error"] = json!(trim(format!("re-encoding: {e}")));
            }
        },
        Err(e) => {
            facts["roundtrip"] = json!("refused");
            facts["roundtrip_error"] = json!(trim(format!("Type::from_json: {e}")));
        }
    }
    // The converter's own JSON at the request's pinpoints: the orchestrator compares each with the value the
    // manifest states there, exactly as JSON (docs/conformance-protocol.md, the json level's expected values).
    if let Some(pins) = input["pinpoints"].as_array() {
        let mut out = Vec::new();
        for p in pins {
            let Some(path) = p.as_str() else {
                return json!({"protocol_error": "pinpoints must be JSON Pointer strings"});
            };
            match parsed.pointer(path) {
                Some(v) => out.push(json!({"path": path, "found": true, "value": v})),
                None => out.push(json!({"path": path, "found": false})),
            }
        }
        facts["pinpoints"] = json!(out);
    }
    json!({"outcome": "ok", "actual": {"json": facts}})
}

/// The crate's version as the driver reports it: the crates.io version, or for a git dependency the first 12
/// characters of its commit as build metadata (`30.0.0+ebec5fb1c76e`), so version ranges treat it as that release (both read from the version directory's Cargo.lock at build time).
fn sdk_info() -> Value {
    let lock = env!("XDRCHECK_LOCK_XDR");
    let mut p = lock.split(' ');
    let (version, source, sum) = (
        p.next().unwrap_or(""),
        p.next().unwrap_or(""),
        p.next().unwrap_or(""),
    );
    let mut sdk = match source.split_once('#') {
        Some((_, commit)) => {
            json!({"ecosystem": "crates.io", "package": "stellar-xdr", "version": format!("{version}+{}", &commit[..12.min(commit.len())])})
        }
        None => json!({"ecosystem": "crates.io", "package": "stellar-xdr", "version": version}),
    };
    if !sum.is_empty() {
        sdk["integrity"] = json!(format!("sha256:{sum}"));
    }
    sdk["dependencies"] = json!([{"package": "stellar-xdr", "version": version}]);
    sdk
}

fn describe(id: &Value) -> Value {
    let probes = json!({
        "sc_address_type_muxed_contract": TypeVariant::from_str("ScAddressType").is_ok()
            && Type::read_xdr_to_end(TypeVariant::ScAddressType, &mut Limited::new(std::io::Cursor::new([0u8, 0, 0, 5]), Limits::none())).is_ok(),
        "stellar_value_signed_ms": Type::read_xdr_to_end(TypeVariant::StellarValueType, &mut Limited::new(std::io::Cursor::new([0u8, 0, 0, 3]), Limits::none())).is_ok(),
    });
    json!({
        "xcc": TAG, "id": id, "op": "describe",
        "driver": {"name": "xdrcheck-driver-rs-xdr-json", "version": "0.1.0", "adapter": "rs-xdr-json"},
        "sdk": sdk_info(),
        "runtime": {"name": "rustc", "version": env!("XDRCHECK_RUSTC_VERSION"), "os": std::env::consts::OS, "arch": std::env::consts::ARCH, "stack_bytes": STACK},
        "xdr_schema": {"probes": probes},
        "levels": ["json"],
        "api_ops": [],
        "decode": {"entry_point": "Type::read_xdr_to_end", "default_depth": null, "depth_configurable": false, "checks_consumed_length": true},
    })
}

fn serve() {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(req) = serde_json::from_str::<Value>(&line) else {
            let _ = writeln!(
                out,
                "{}",
                json!({"xcc": TAG, "op": "protocol_error", "error": "the request is not JSON"})
            );
            continue;
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
                let r = if level == "json" && req["input"]["kind"] == "xdr" {
                    run_json(&req["input"])
                } else {
                    json!({"protocol_error": format!("{level}: this driver answers the json level on xdr inputs only")})
                };
                if let Some(e) = r.get("protocol_error") {
                    json!({"xcc": TAG, "id": id, "op": "protocol_error", "error": e})
                } else {
                    let mut m = json!({"xcc": TAG, "id": id, "op": "run", "entry": req["entry"], "level": level});
                    for k in ["variant", "profile"] {
                        if let Some(v) = req.get(k) {
                            m[k] = v.clone();
                        }
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

fn main() {
    // Deep values recurse in the codec and in serde: serve on a large stack.
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(serve)
        .expect("spawn")
        .join()
        .expect("serve");
}
