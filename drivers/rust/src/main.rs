//! `xdrcheck-driver` for the Rust `stellar-xdr` crate: the conformance driver of the `rust@<version>` columns.
//!
//! It speaks the driver protocol `xcc.driver/1` (one JSON object per line on stdin and stdout; see
//! `drivers/README.md` and `corpus/schema/driver-protocol.schema.json`) and wraps exactly one `stellar-xdr`
//! version and the `stellar-strkey` version that crate depends on. The same source is compiled once per
//! crate version (`drivers/rust/<version>/`); the cargo feature `strkey-1` selects the `stellar-strkey` 1.x API.
//!
//! Levels:
//!
//! - **L0** decode by type name with `Type::from_xdr` under the request's decode profile, check that the whole
//!   input was consumed, re-encode and compare (`codec`).
//! - **L1** `n_a/no_object_layer`: the crate has no transaction object layer.
//! - **L2** the decoded value rendered as the crate's SEP-51 XDR-JSON, at the requested JSON Pointers or whole.
//! - **L3** `n_a/no_native_layer`: the crate has no native-value conversion.
//! - **L4** strkey entries and the `api` operations listed in `api`.
//!
//! Every run request is served on a fresh thread with a fixed stack ([`DECODE_STACK_BYTES`], reported as
//! `runtime.stack_bytes`). A panic there is reported as `crash/panic`; a stack overflow aborts the process,
//! which the orchestrator records as a crash. The driver never reads the manifest and never sees expected
//! values.

mod api;
mod codec;
mod outcome;
mod reach;
mod strkeys;

use std::io::{self, BufRead, Write};

use serde_json::{json, Map, Value};
use stellar_xdr::{ScAddressType, StellarValueType};

use codec::Profile;
use outcome::{Outcome, Reason};

const TAG: &str = "xcc.driver/1";

/// Stack size of the thread that serves a request: the size of Linux's default main-thread stack, on which
/// the `limits-none` stack-overflow boundary was measured. It is reported, never raised silently.
const DECODE_STACK_BYTES: usize = 8 << 20;

const LEVELS: [&str; 5] = ["L0", "L1", "L2", "L3", "L4"];

/// `name version sha256;…` from the crate's Cargo.lock, recorded by the build script.
const LOCK_CHECKSUMS: &str = env!("XDRCHECK_LOCK_CHECKSUMS");

fn lock_integrity(package: &str, version: &str) -> Option<String> {
    LOCK_CHECKSUMS.split(';').find_map(|l| {
        let mut f = l.split(' ');
        match (f.next(), f.next(), f.next()) {
            (Some(n), Some(v), Some(sum)) if n == package && v == version && !sum.is_empty() => {
                Some(format!("sha256:{sum}"))
            }
            _ => None,
        }
    })
}

fn describe(id: &Value) -> Value {
    let xdr_version = stellar_xdr::VERSION.pkg;
    let strkey_version = strkeys::version();
    let muxed_contract = ScAddressType::try_from(5i32).is_ok();
    let signed_ms = StellarValueType::try_from(3i32).is_ok();

    let mut sdk =
        json!({"ecosystem": "crates.io", "package": "stellar-xdr", "version": xdr_version});
    if let Some(i) = lock_integrity("stellar-xdr", xdr_version) {
        sdk["integrity"] = json!(i);
    }
    let mut strkey = json!({"package": "stellar-strkey", "version": strkey_version});
    if let Some(i) = lock_integrity("stellar-strkey", strkey_version) {
        strkey["integrity"] = json!(i);
    }
    sdk["dependencies"] = json!([strkey]);

    let mut schema = json!({"probes": {
        "sc_address_type_muxed_contract": muxed_contract,
        "stellar_value_signed_ms": signed_ms,
    }});
    let beyond = reach::beyond_known(reach::crate_values);
    if let Some(p) = reach::schema_protocol(&[(30, muxed_contract), (30, signed_ms)], &beyond) {
        schema["protocol"] = json!(p);
    }

    json!({
        "xcc": TAG,
        "id": id,
        "op": "describe",
        "driver": {"name": "xdrcheck-driver-rust", "version": env!("CARGO_PKG_VERSION")},
        "sdk": sdk,
        "runtime": {
            "name": "rustc",
            "version": env!("XDRCHECK_RUSTC_VERSION"),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "stack_bytes": DECODE_STACK_BYTES,
        },
        "xdr_schema": schema,
        "levels": LEVELS,
        "api_ops": api::OPS,
        "decode": {
            "entry_point": format!("{}(TypeVariant, bytes, Limits)", codec::ENTRY_POINT),
            // The crate has no default Limits; each profile states its own.
            "default_depth": null,
            "depth_configurable": true,
            "checks_consumed_length": true,
            "profiles": Profile::NAMES,
        },
    })
}

fn protocol_error(id: Option<&Value>, error: impl Into<String>) -> Value {
    let mut m = Map::new();
    m.insert("xcc".into(), json!(TAG));
    if let Some(id) = id {
        m.insert("id".into(), id.clone());
    }
    m.insert("op".into(), json!("protocol_error"));
    m.insert("error".into(), json!(error.into()));
    Value::Object(m)
}

/// A validated run request.
struct Run {
    level: String,
    profile: Profile,
    input: Value,
}

/// Reads the input bytes of an `xdr` input: a file or inline hex, then the requested record-marked frame.
fn input_bytes(input: &Value) -> Result<Result<Vec<u8>, Outcome>, String> {
    let raw = if let Some(p) = input.get("path").and_then(Value::as_str) {
        std::fs::read(p).map_err(|e| format!("cannot read input.path {p}: {e}"))?
    } else if let Some(h) = input.get("xdr_hex").and_then(Value::as_str) {
        hex::decode(h).map_err(|e| format!("input.xdr_hex is not hex: {e}"))?
    } else {
        return Err("an xdr input needs path or xdr_hex".into());
    };
    match input.get("framing").and_then(Value::as_str) {
        None | Some("none") => Ok(Ok(raw)),
        Some("record-marked") => {
            let i = input
                .get("frame_index")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            Ok(codec::frame(&raw, i).map(<[u8]>::to_vec).map_err(|m| {
                Outcome::reject(
                    Reason::new("decode_error")
                        .message(m)
                        .entry_point("record marks (driver)"),
                )
            }))
        }
        Some(f) => Err(format!("unknown input.framing {f}")),
    }
}

/// Serves one run request. A protocol problem is an `Err` with the message.
fn serve(run: Run) -> Result<Outcome, String> {
    let kind = run
        .input
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match run.level.as_str() {
        "L1" => {
            return Ok(Outcome::n_a(
                "no_object_layer",
                "stellar-xdr has no transaction object or other object layer above the codec",
            ))
        }
        "L3" => {
            return Ok(Outcome::n_a(
                "no_native_layer",
                "stellar-xdr has no conversion to native values (that lives in the Soroban SDK and host)",
            ))
        }
        "L4" => {
            return match kind {
                "strkey" => {
                    let text = run.input.get("text").and_then(Value::as_str).ok_or("strkey input without text")?;
                    api::strkey_entry(text, run.input.get("declared_type").and_then(Value::as_str))
                }
                "api" => {
                    let op = run.input.get("api_op").and_then(Value::as_str).ok_or("api input without api_op")?;
                    let args = run.input.get("args").cloned().unwrap_or(json!({}));
                    let pp = run.input.get("passphrase").and_then(Value::as_str);
                    api::run(op, &args, pp, run.profile)
                }
                _ => Err(format!("level L4 needs an api or strkey input, not {kind:?}")),
            }
        }
        _ => {}
    }
    if kind != "xdr" {
        return Err(format!(
            "level {} needs an xdr input, not {kind:?}",
            run.level
        ));
    }
    let ty = run
        .input
        .get("xdr_type")
        .and_then(Value::as_str)
        .ok_or("xdr input without xdr_type")?;
    let Some(tv) = codec::type_variant(ty) else {
        return Ok(Outcome::n_a(
            "type_not_generated",
            format!("stellar-xdr {} has no type {ty}", stellar_xdr::VERSION.pkg),
        ));
    };
    let bytes = match input_bytes(&run.input)? {
        Ok(b) => b,
        Err(o) => return Ok(o),
    };
    Ok(match run.level.as_str() {
        "L0" => codec::l0(tv, &bytes, run.profile),
        _ => {
            let pins = run
                .input
                .get("pinpoints")
                .and_then(Value::as_array)
                .map(Vec::as_slice);
            codec::l2(tv, &bytes, run.profile, pins)
        }
    })
}

/// Runs `serve` on a thread with the decode stack. A panic becomes `crash/panic`.
fn serve_on_thread(run: Run) -> Result<Outcome, String> {
    let handle = std::thread::Builder::new()
        .name("decode".into())
        .stack_size(DECODE_STACK_BYTES)
        .spawn(move || serve(run))
        .map_err(|e| format!("cannot start the decode thread: {e}"))?;
    match handle.join() {
        Ok(r) => r,
        Err(p) => {
            let msg = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "panic with a non-string payload".into());
            Ok(Outcome::with(
                "crash",
                Reason::new("panic").message(msg).class("panic"),
            ))
        }
    }
}

fn handle_run(req: &Map<String, Value>, id: &Value) -> Value {
    let entry = req.get("entry").and_then(Value::as_str);
    let level = req.get("level").and_then(Value::as_str);
    let (Some(entry), Some(level)) = (entry, level) else {
        return protocol_error(Some(id), "a run request needs entry and level");
    };
    if !LEVELS.contains(&level) {
        return protocol_error(Some(id), format!("unknown level {level}"));
    }
    let profile_name = req.get("profile").and_then(Value::as_str);
    let Some(profile) = Profile::parse(profile_name) else {
        return protocol_error(
            Some(id),
            format!("unknown profile {}", profile_name.unwrap_or_default()),
        );
    };
    let Some(input) = req.get("input").filter(|v| v.is_object()).cloned() else {
        return protocol_error(Some(id), "a run request needs an input object");
    };
    let outcome = match serve_on_thread(Run {
        level: level.to_string(),
        profile,
        input,
    }) {
        Ok(o) => o,
        Err(e) => return protocol_error(Some(id), e),
    };
    let mut resp = Map::new();
    resp.insert("xcc".into(), json!(TAG));
    resp.insert("id".into(), id.clone());
    resp.insert("op".into(), json!("run"));
    resp.insert("entry".into(), json!(entry));
    if let Some(v) = req.get("variant") {
        resp.insert("variant".into(), v.clone());
    }
    resp.insert("level".into(), json!(level));
    if let Some(p) = profile_name {
        resp.insert("profile".into(), json!(p));
    }
    outcome.fill(&mut resp);
    Value::Object(resp)
}

fn main() {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    let mut send = |v: &Value| {
        let mut line = serde_json::to_vec(v).expect("a JSON value serialises");
        line.push(b'\n');
        // The orchestrator went away: nothing left to do.
        if out.write_all(&line).and_then(|_| out.flush()).is_err() {
            std::process::exit(0);
        }
    };
    for line in stdin.lock().split(b'\n') {
        let Ok(line) = line else { break };
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let req: Value = match serde_json::from_slice(&line) {
            Ok(v) => v,
            Err(e) => {
                send(&protocol_error(None, format!("not a JSON object: {e}")));
                continue;
            }
        };
        let Some(obj) = req.as_object() else {
            send(&protocol_error(None, "not a JSON object"));
            continue;
        };
        let id = obj.get("id").filter(|v| v.as_u64().is_some_and(|n| n >= 1));
        if obj.get("xcc").and_then(Value::as_str) != Some(TAG) {
            send(&protocol_error(
                id,
                format!("unsupported protocol tag; this driver speaks {TAG}"),
            ));
            continue;
        }
        let Some(id) = id else {
            send(&protocol_error(None, "the request has no id"));
            continue;
        };
        match obj.get("op").and_then(Value::as_str) {
            Some("describe") => send(&describe(id)),
            Some("run") => send(&handle_run(obj, id)),
            Some("shutdown") => {
                send(&json!({"xcc": TAG, "id": id, "op": "shutdown", "ok": true}));
                return;
            }
            other => send(&protocol_error(
                Some(id),
                format!("unknown op {}", other.unwrap_or("(none)")),
            )),
        }
    }
}
