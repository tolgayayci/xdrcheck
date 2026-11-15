//! `xdrcheck-driver-selftest`: the Rust driver's own checks, run by `make test` after `make build`.
//!
//! ```text
//! xdrcheck-driver-selftest <driver> <stellar-xdr version> <repository root>
//! ```
//!
//! It drives the built `xdrcheck-driver` over the protocol, as the orchestrator does, and checks:
//!
//! 1. `describe`: the package, the version read from the library, both decode profiles, the schema probes.
//! 2. The executed cross-SDK probe in `evidence/sdk-matrix/`: every probe vector that maps onto a driver
//!    request is sent under both profiles, and the outcome class (and, where the probe recorded one, the
//!    value: re-encoded bytes, strkey payload, rendered address, transaction hash) must equal the probe's
//!    result for this crate version and limit setting. The result files are not committed: they are read from a
//!    local probe run, and from `$XDRCHECK_OVERLAY/evidence/sdk-matrix/results/` when it is set; with neither, the
//!    section is skipped. Vectors where the driver deliberately differs from the
//!    throwaway probe script are listed in [`DIFFERS`] with the reason, and checked against the driver's rule.
//! 3. Depth: under `limits-default` the driver decodes exactly the deepest `ScVec` nesting that
//!    `ScVal::from_xdr` decodes at the profile's depth, and refuses one level more for depth; 5,000
//!    decode under `limits-none`; 100,000 under `limits-none` abort the process on a stack overflow (in a
//!    fresh process, as the orchestrator isolates such entries) while `limits-default` refuses them cleanly.
//! 4. XDR-JSON: a vector one element longer than its declared maximum is accepted by 28.0.0's serde and
//!    written as bytes its own decoder rejects (rs-stellar-xdr#598), and refused from 28.0.1 on.
//! 5. L2 pinpoints over the vendored corpus entries (30.0.0, the oracle version): every `expect.values` path
//!    is found with the stated value, except where the manifest declares a known divergence for this version
//!    under `limits-default` (asserted instead) or the pending list acknowledges the cell.
//! 6. Protocol hygiene: L1/L3 typed `n_a`, unknown types, record-marked input, L0 evidence, protocol errors,
//!    shutdown.
//! 7. The api vocabulary: every declared operation answers a well-formed call with an SDK outcome (never
//!    `n_a/op_not_supported`), and with `self_decode` wherever it returns `xdr_hex` or a strkey; an unknown,
//!    missing or malformed argument is a protocol error; an ID the library's `u64` cannot hold is
//!    `n_a/value_not_representable` only when it carries a native tag.

mod reach;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const TAG: &str = "xcc.driver/1";
const PROFILES: [&str; 2] = ["limits-default", "limits-none"];

/// Probe vectors where the driver deliberately differs from the probe script: (vector, driver outcome,
/// reason). The driver follows its operation table (api.rs); the probe script predates it.
const DIFFERS: &[(&str, &str, &str)] = &[
    ("2m1", "ok", "muxed_account.encode maps onto Strkey::MuxedAccountEd25519; the u64 ID 2^53+1 is representable (the probe had no muxed-account operation)"),
    ("2m2", "ok", "as 2m1, ID 2^64-1"),
    ("5a", "n_a", "scval.sort_map is not mapped onto stellar-xdr in the operation table (the probe called ScMap::sorted_from)"),
    ("5b", "n_a", "as 5a"),
    ("5c", "n_a", "as 5a"),
    ("7b", "n_a", "operation.object_roundtrip needs an object layer stellar-xdr does not have (the probe re-encoded the codec value)"),
    ("7c", "n_a", "scval.native_roundtrip needs a native layer stellar-xdr does not have (the probe used StringM::to_utf8_string)"),
    ("7d", "n_a", "as 7c"),
];

struct Driver {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next: u64,
}

impl Driver {
    fn start(path: &Path) -> Driver {
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("cannot start {}: {e}", path.display()));
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Driver {
            child,
            stdin,
            stdout,
            next: 1,
        }
    }

    /// Sends a request (the id is filled in) and returns the response line, or None at end of output.
    fn call(&mut self, mut req: Value) -> Option<Value> {
        let id = self.next;
        self.next += 1;
        req["xcc"] = json!(TAG);
        req["id"] = json!(id);
        self.raw(&req.to_string())
    }

    fn raw(&mut self, line: &str) -> Option<Value> {
        writeln!(self.stdin, "{line}").ok()?;
        self.stdin.flush().ok()?;
        let mut out = String::new();
        match self.stdout.read_line(&mut out) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(
                serde_json::from_str(&out)
                    .unwrap_or_else(|e| panic!("driver wrote non-JSON {out:?}: {e}")),
            ),
        }
    }

    fn run(&mut self, level: &str, profile: &str, input: Value) -> Value {
        let req = json!({"op": "run", "entry": "selftest/x", "level": level, "profile": profile, "input": input});
        self.call(req).expect("the driver died")
    }

    /// Waits for the process and returns (signal or exit code, stderr).
    fn finish(mut self) -> (String, String) {
        drop(self.stdin);
        let status = self.child.wait().expect("wait");
        let mut err = String::new();
        if let Some(mut e) = self.child.stderr.take() {
            let _ = e.read_to_string(&mut err);
        }
        use std::os::unix::process::ExitStatusExt;
        let s = match status.signal() {
            Some(sig) => format!("signal {sig}"),
            None => format!("exit {}", status.code().unwrap_or(-1)),
        };
        (s, err)
    }
}

#[derive(Default)]
struct Tally {
    passed: usize,
    failed: Vec<String>,
}

impl Tally {
    fn check(&mut self, ok: bool, what: impl Into<String>) {
        if ok {
            self.passed += 1;
        } else {
            let w = what.into();
            println!("FAIL {w}");
            self.failed.push(w);
        }
    }
}

fn outcome(r: &Value) -> &str {
    r["outcome"].as_str().unwrap_or("?")
}

fn code(r: &Value) -> &str {
    r["reason"]["code"].as_str().unwrap_or("")
}

fn sha256_hex(h: &str) -> String {
    hex::encode(Sha256::digest(hex::decode(h).unwrap()))
}

fn nested_vec(levels: usize) -> String {
    let mut s = "000000100000000100000001".repeat(levels);
    s.push_str("00000001");
    s
}

/// The driver request for a probe vector: (level, input, how to compare the value).
enum Compare {
    None,
    Reencoded,
    Api,
    TxHash,
}

fn request_for(v: &Value) -> Option<(&'static str, Value, Compare)> {
    let id = v["id"].as_str()?;
    let p = &v["params"];
    let ps = |k: &str| p[k].as_str().unwrap_or("").to_string();
    let hexs = v["hex"].as_str().unwrap_or("");
    let api = |op: &str, args: Value| json!({"kind": "api", "api_op": op, "args": args});
    let xdr = |ty: &str| json!({"kind": "xdr", "xdr_type": ty, "xdr_hex": hexs});
    let group = v["group"].as_u64()?;
    Some(match (group, id) {
        (1, "1c") => (
            "L4",
            api(
                "transaction.hash",
                json!({"xdr_hex": {"hex": hexs}, "passphrase": ps("network")}),
            ),
            Compare::TxHash,
        ),
        (1, _) => (
            "L4",
            api(
                "liquidity_pool.id",
                json!({"asset_a": format!("{}:{}", ps("code"), ps("a")), "asset_b": format!("{}:{}", ps("code"), ps("b"))}),
            ),
            Compare::None,
        ),
        (2, _) if id.starts_with("2m") => (
            "L4",
            api(
                "muxed_account.encode",
                json!({"account": ps("g"), "id": {"native": ps("kind"), "value": ps("value")}}),
            ),
            Compare::None,
        ),
        (2, _) => (
            "L4",
            api(
                "offer.manage_sell",
                json!({"offer_id": {"native": ps("kind"), "value": ps("value")}}),
            ),
            Compare::None,
        ),
        (3, _) => ("L0", xdr("TransactionEnvelope"), Compare::None),
        (4, _) => ("L3", xdr("ScVal"), Compare::None),
        (5, _) => (
            "L4",
            api("scval.sort_map", json!({"keys": p["keys"]})),
            Compare::None,
        ),
        (6, _) => ("L0", xdr(&ps("type")), Compare::Reencoded),
        (7, "7a") => (
            "L4",
            api("memo.text_roundtrip", json!({"xdr_hex": {"hex": hexs}})),
            Compare::None,
        ),
        (7, "7b") => (
            "L4",
            api(
                "operation.object_roundtrip",
                json!({"xdr_hex": {"hex": hexs}}),
            ),
            Compare::None,
        ),
        (7, _) => (
            "L4",
            api("scval.native_roundtrip", json!({"xdr_hex": {"hex": hexs}})),
            Compare::None,
        ),
        (8, _) => ("L0", xdr("ScVal"), Compare::None),
        (9, "9E1") => {
            let id: u64 = ps("id").parse().ok()?;
            let payload = format!("{}{:016x}", ps("contract"), id);
            (
                "L4",
                api(
                    "strkey.encode",
                    json!({"type": "muxed_contract", "payload_hex": payload}),
                ),
                Compare::Api,
            )
        }
        (9, "9E2") => (
            "L4",
            api("address.from_sc_address", json!({"xdr_hex": {"hex": hexs}})),
            Compare::Api,
        ),
        (9, "9E3") => {
            let payload = format!("{}00000000{}", ps("key"), ps("payload"));
            (
                "L4",
                api(
                    "strkey.encode",
                    json!({"type": "signed_payload", "payload_hex": payload}),
                ),
                Compare::Api,
            )
        }
        (9, "9E4") => (
            "L4",
            api(
                "address.to_strkey",
                json!({"xdr_type": "MuxedAccount", "xdr_hex": hexs}),
            ),
            Compare::Api,
        ),
        (9, _) => (
            "L4",
            json!({"kind": "strkey", "text": ps("s")}),
            Compare::Api,
        ),
        // Group 10 reads ledger files the evidence directory does not vendor; the corpus entry for the same
        // ledger runs through the orchestrator.
        _ => return None,
    })
}

/// The driver outcome class the probe's result implies.
fn expected_outcome(probe: &Value) -> &'static str {
    let detail = probe["detail"].as_str().unwrap_or("");
    match probe["outcome"].as_str().unwrap_or("") {
        "n/a" => "n_a",
        "reject" => "reject",
        "crash" => "crash",
        // ok and wrong are both "accepted"; the driver names the self-evident mismatches.
        _ if detail.contains("re-encode DIFFERS") || detail.contains("decode(own output)=Err") => {
            "diverge"
        }
        _ => "ok",
    }
}

fn load_probe(path: &Path) -> BTreeMap<String, Value> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            (v["vector"].as_str().unwrap().to_string(), v)
        })
        .collect()
}

fn check_probe(t: &mut Tally, drv: &mut Driver, root: &Path, version: &str) {
    let dir = root.join("evidence/sdk-matrix");
    let vectors: Vec<Value> =
        serde_json::from_slice(&std::fs::read(dir.join("vectors/vectors.json")).unwrap()).unwrap();
    for (profile, label) in [
        ("limits-default", "Limits_500_len"),
        ("limits-none", "Limits_none"),
    ] {
        let file = format!("rust_{version}_{label}.jsonl");
        // A local probe run's file, and the overlay's file of the same name when XDRCHECK_OVERLAY names one.
        let mut probe = BTreeMap::new();
        let mut files = vec![dir.join("results").join(&file)];
        if let Some(ov) = std::env::var_os("XDRCHECK_OVERLAY").filter(|v| !v.is_empty()) {
            files.push(
                PathBuf::from(ov)
                    .join("evidence/sdk-matrix/results")
                    .join(&file),
            );
        }
        for f in files.iter().filter(|f| f.is_file()) {
            probe.extend(load_probe(f));
        }
        if probe.is_empty() {
            println!(
                "probe vectors under {profile}: no probe results (run evidence/sdk-matrix/run.sh, or set XDRCHECK_OVERLAY); skipped"
            );
            continue;
        }
        let mut n = 0;
        for v in &vectors {
            let id = v["id"].as_str().unwrap();
            let (Some((level, input, cmp)), Some(p)) = (request_for(v), probe.get(id)) else {
                continue;
            };
            n += 1;
            let r = drv.run(level, profile, input);
            let got = outcome(&r);
            let differs = DIFFERS.iter().find(|d| d.0 == id);
            let want = differs.map(|d| d.1).unwrap_or_else(|| expected_outcome(p));
            let what = format!(
                "probe {id} {profile}: driver {got} {} ({}), probe {} {:?}",
                code(&r),
                r["reason"]["message"].as_str().unwrap_or(""),
                p["outcome"],
                p["detail"]
            );
            t.check(got == want, what.clone());
            if differs.is_some() || got != want {
                continue;
            }
            let pgot = p["got"].as_str().unwrap_or("");
            match cmp {
                Compare::Reencoded if got == "ok" => t.check(
                    r["actual"]["reencoded_sha256"] == json!(sha256_hex(pgot)),
                    format!("{what}: re-encoding"),
                ),
                Compare::Reencoded if got == "diverge" => t.check(
                    r["actual"]["reencoded_hex"] == json!(pgot),
                    format!("{what}: re-encoding"),
                ),
                Compare::Api if got == "ok" || got == "diverge" => t.check(
                    r["actual"]["api"]["value"] == json!(pgot),
                    format!("{what}: value {}", r["actual"]["api"]["value"]),
                ),
                Compare::TxHash if got == "ok" => {
                    let h = pgot
                        .strip_prefix("hash=")
                        .and_then(|s| s.split(' ').next())
                        .unwrap_or("");
                    t.check(
                        r["actual"]["api"]["value"] == json!(h),
                        format!("{what}: hash"),
                    )
                }
                _ => {}
            }
        }
        println!("probe vectors under {profile}: {n} compared");
    }
}

/// The depth of the `limits-default` profile (`codec::DEFAULT_DEPTH` in the driver).
const LIMITS_DEFAULT_DEPTH: u32 = 500;

/// The deepest `ScVec` nesting the library itself decodes as an `ScVal` at `depth`, found by trying.
fn library_deepest_nested_vec(depth: u32) -> usize {
    use stellar_xdr::{Limits, ReadXdr, ScVal};
    let decodes = |n: usize| {
        let bytes = hex::decode(nested_vec(n)).expect("hex");
        ScVal::from_xdr(
            bytes,
            Limits {
                depth,
                len: usize::MAX,
            },
        )
        .is_ok()
    };
    let mut n = 0;
    while (n as u32) < depth && decodes(n + 1) {
        n += 1;
    }
    n
}

fn check_depth(t: &mut Tally, drv: &mut Driver, path: &Path) {
    let scval = |n: usize| json!({"kind": "xdr", "xdr_type": "ScVal", "xdr_hex": nested_vec(n)});
    // The driver spends one depth unit on `Type`'s dispatch level and adds it back, so it must draw the
    // line exactly where `ScVal::from_xdr` does at the same depth.
    let deepest = library_deepest_nested_vec(LIMITS_DEFAULT_DEPTH);
    t.check(
        deepest > 0,
        "ScVal::from_xdr decodes some nesting at the limits-default depth",
    );
    let r = drv.run("L0", "limits-default", scval(deepest));
    t.check(
        outcome(&r) == "ok",
        format!("the deepest nesting ScVal::from_xdr decodes, under limits-default: {r}"),
    );
    let r = drv.run("L0", "limits-default", scval(deepest + 1));
    t.check(
        outcome(&r) == "reject" && code(&r) == "depth",
        format!("one level past what ScVal::from_xdr decodes, under limits-default: {r}"),
    );
    let r = drv.run("L0", "limits-none", scval(5000));
    t.check(
        outcome(&r) == "ok",
        format!("5000 nested vectors under limits-none: {}", outcome(&r)),
    );
    let r = drv.run("L0", "limits-default", scval(100_000));
    t.check(
        outcome(&r) == "reject" && code(&r) == "depth",
        format!(
            "100000 nested vectors under limits-default: {}",
            outcome(&r)
        ),
    );

    // In a fresh process: the stack overflow aborts it, no response line is written.
    let mut fresh = Driver::start(path);
    let resp = fresh.call(json!({"op": "run", "entry": "selftest/deep", "level": "L0", "profile": "limits-none", "input": scval(100_000)}));
    let (status, stderr) = fresh.finish();
    t.check(
        resp.is_none() && status.starts_with("signal") && stderr.contains("overflowed its stack"),
        format!("100000 nested vectors under limits-none must abort on a stack overflow: response {resp:?}, {status}, stderr {stderr:?}"),
    );
}

fn check_xdrjson(t: &mut Tally, drv: &mut Driver, version: &str) {
    let call = |drv: &mut Driver, ty: &str, json_text: &str| {
        drv.run("L4", "limits-default", json!({"kind": "api", "api_op": "xdrjson.decode", "args": {"xdr_type": ty, "json": json_text}}))
    };
    let r = call(
        drv,
        "ClaimPredicate",
        r#"{"and":["unconditional","unconditional"]}"#,
    );
    t.check(
        outcome(&r) == "ok"
            && r["actual"]["api"]["xdr_hex"] == json!("00000001000000020000000000000000")
            && r["actual"]["api"]["self_decode"] == json!("accepted"),
        format!("xdrjson.decode of a two-predicate and: {r}"),
    );
    // ClaimPredicate.and is ClaimPredicate andPredicates<2>: three elements are one over the maximum.
    let r = call(
        drv,
        "ClaimPredicate",
        r#"{"and":["unconditional","unconditional","unconditional"]}"#,
    );
    if version == "28.0.0" {
        t.check(
            outcome(&r) == "diverge"
                && code(&r) == "own_output_rejected"
                && r["actual"]["api"]["self_decode"] == json!("rejected"),
            format!(
                "28.0.0 accepts an over-long vector in JSON and cannot decode its own bytes: {r}"
            ),
        );
    } else {
        t.check(
            outcome(&r) == "reject",
            format!("{version} refuses an over-long vector in JSON: {r}"),
        );
    }
    let r = call(drv, "Memo", &format!(r#"{{"text":"{}"}}"#, "a".repeat(29)));
    t.check(
        outcome(&r) == "reject",
        format!("a 29-byte string<28> in JSON is refused: {r}"),
    );
}

/// Replaces `${derived.<path>}` tokens with the variant's derived values (the manifest's convention): a
/// string that is one token becomes the value itself, a token inside a longer string is spliced in.
fn resolve(v: &Value, derived: &Value) -> Value {
    const OPEN: &str = "${derived.";
    let lookup = |path: &str| path.split('.').try_fold(derived, |d, k| d.get(k)).cloned();
    match v {
        Value::String(s) => {
            if let Some(path) = s.strip_prefix(OPEN).and_then(|r| r.strip_suffix('}')) {
                if !path.contains('}') {
                    return lookup(path).unwrap_or(Value::Null);
                }
            }
            let mut out = String::new();
            let mut rest = s.as_str();
            while let Some(i) = rest.find(OPEN) {
                out.push_str(&rest[..i]);
                let tail = &rest[i + OPEN.len()..];
                let Some(j) = tail.find('}') else { break };
                match lookup(&tail[..j]) {
                    Some(Value::String(x)) => out.push_str(&x),
                    Some(x) => out.push_str(&x.to_string()),
                    None => out.push_str(&rest[i..i + OPEN.len() + j + 1]),
                }
                rest = &tail[j + 1..];
            }
            out.push_str(rest);
            Value::String(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| resolve(x, derived)).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, x)| (k.clone(), resolve(x, derived)))
                .collect(),
        ),
        _ => v.clone(),
    }
}

/// The manifest's target name for this library (drivers/sets.toml).
const TARGET: &str = "stellar-xdr (crates.io)";
/// The decode profile the corpus pinpoints run under.
const CORPUS_PROFILE: &str = "limits-default";

/// A version as (MAJOR, MINOR, PATCH, prerelease); a release sorts after its prereleases.
fn parse_version(s: &str) -> (u64, u64, u64, Option<String>) {
    let s = s.trim().trim_start_matches('v');
    let s = s.split('+').next().unwrap_or("");
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p.to_string())),
        None => (s, None),
    };
    let mut n = core.split('.').map(|x| x.parse::<u64>().unwrap_or(0));
    let (a, b, c) = (
        n.next().unwrap_or(0),
        n.next().unwrap_or(0),
        n.next().unwrap_or(0),
    );
    (a, b, c, pre)
}

fn cmp_version(a: &str, b: &str) -> std::cmp::Ordering {
    let (x, y) = (parse_version(a), parse_version(b));
    (x.0, x.1, x.2)
        .cmp(&(y.0, y.1, y.2))
        .then_with(|| match (&x.3, &y.3) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(_), None) => std::cmp::Ordering::Less,
            (Some(p), Some(q)) => p.cmp(q),
        })
}

/// Whether `ver` satisfies a known divergence's range (docs/manifest.md): alternatives joined by `||`, each
/// `*`, a hyphen range `A - B`, or space-separated comparators.
fn in_range(ver: &str, range: &str) -> bool {
    use std::cmp::Ordering::{Greater, Less};
    range.split("||").map(str::trim).any(|alt| {
        if alt == "*" {
            return true;
        }
        if let Some((lo, hi)) = alt.split_once(" - ") {
            return cmp_version(ver, lo) != Less && cmp_version(ver, hi) != Greater;
        }
        alt.split_whitespace().all(|c| {
            let op = [">=", "<=", ">", "<", "="]
                .into_iter()
                .find(|o| c.starts_with(o))
                .unwrap_or("");
            let d = cmp_version(ver, &c[op.len()..]);
            match op {
                "<" => d == Less,
                "<=" => d != Greater,
                ">" => d == Greater,
                ">=" => d != Less,
                _ => d == std::cmp::Ordering::Equal,
            }
        })
    })
}

/// The report's variant key: the network, with `@protocol` when the entry's variants differ in protocol.
fn variant_key(e: &Value, var: &Value) -> String {
    let network = var["network"].as_str().unwrap_or("");
    let mixed = e["variants"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|o| o["protocol"] != var["protocol"]);
    if mixed {
        format!("{network}@{}", var["protocol"])
    } else {
        network.to_string()
    }
}

/// What a cell of this column is expected to do where it does not decode.
enum Expected {
    /// A known divergence the manifest declares for this target, version and profile at the level.
    Declared(Value),
    /// A divergence awaiting a finding, acknowledged without an asserted outcome: an item of the committed
    /// pending list (findings/pending/conformance.json) or a report row a finding record lists in
    /// `evidence.report_rows` (findings/, and the private overlay's findings/ when XDRCHECK_OVERLAY names one),
    /// as `xdrcheck conform check` reads them.
    Pending,
}

struct Expectations {
    version: String,
    column: String,
    pending: std::collections::BTreeSet<(String, String, String, String)>,
}

impl Expectations {
    fn load(root: &Path, version: &str) -> Expectations {
        let p = root.join("findings/pending/conformance.json");
        let doc: Value = serde_json::from_slice(
            &std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())),
        )
        .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        let s = |v: &Value| v.as_str().unwrap_or("").to_string();
        let mut pending: std::collections::BTreeSet<_> = doc["pending"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|x| {
                (
                    s(&x["entry"]),
                    s(&x["variant"]),
                    s(&x["column"]),
                    s(&x["level"]),
                )
            })
            .collect();
        let mut dirs = vec![root.join("findings")];
        if let Some(ov) = std::env::var_os("XDRCHECK_OVERLAY").filter(|v| !v.is_empty()) {
            dirs.push(PathBuf::from(ov).join("findings"));
        }
        for dir in dirs {
            for d in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let p = d.path().join("finding.json");
                let Ok(b) = std::fs::read(&p) else { continue };
                let rec: Value =
                    serde_json::from_slice(&b).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
                for row in rec["evidence"]["report_rows"]
                    .as_array()
                    .into_iter()
                    .flatten()
                {
                    // conform:<entry>:<variant or ->:<column>:<level>; a Rust column ID holds a colon itself.
                    let parts: Vec<&str> = row.as_str().unwrap_or("").split(':').collect();
                    if parts.len() < 5 || parts[0] != "conform" {
                        continue;
                    }
                    let variant = if parts[2] == "-" { "" } else { parts[2] };
                    pending.insert((
                        parts[1].to_string(),
                        variant.to_string(),
                        parts[3..parts.len() - 1].join(":"),
                        parts[parts.len() - 1].to_string(),
                    ));
                }
            }
        }
        Expectations {
            version: version.to_string(),
            column: format!("rust@{version}:{CORPUS_PROFILE}"),
            pending,
        }
    }

    fn at(&self, e: &Value, key: &str, level: &str) -> Option<Expected> {
        for k in e["conformance"]["known_divergences"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let level_ok = k["level"].as_str().is_none_or(|l| l == level);
            let profile_ok = k["profile"].as_str().is_none_or(|p| p == CORPUS_PROFILE);
            if k["target"] == json!(TARGET)
                && level_ok
                && profile_ok
                && k["versions"]
                    .as_str()
                    .is_some_and(|r| in_range(&self.version, r))
            {
                return Some(Expected::Declared(k.clone()));
            }
        }
        let id = e["id"].as_str().unwrap_or("").to_string();
        let cell = (id, key.to_string(), self.column.clone(), level.to_string());
        self.pending.contains(&cell).then_some(Expected::Pending)
    }
}

/// Checks a cell against its expected divergence; true when the divergence accounts for the cell, so the usual
/// checks are skipped: a declared one always, an acknowledged one at L2, and at L0 when the cell refuses.
fn held(t: &mut Tally, what: &str, r: &Value, exp: Option<Expected>) -> bool {
    match exp {
        None => false,
        Some(Expected::Pending) => !what.starts_with("L0 ") || outcome(r) != "ok",
        Some(Expected::Declared(k)) => {
            let want = k["match"]["reason"].as_str();
            t.check(
                k["outcome"].as_str() == Some(outcome(r)) && want.is_none_or(|w| w == code(r)),
                format!("{what}: the declared {} {}: {r}", k["outcome"], k["match"]),
            );
            true
        }
    }
}

/// L2 pinpoints over the corpus, under `limits-default`. A variant whose L0 or L2 cell the manifest declares a
/// known divergence for (this target, version and profile), or that the pending list acknowledges, is held to
/// that instead; a declared or acknowledged refusal at L0 leaves nothing to compare at L2, as in the
/// orchestrator.
fn check_corpus(t: &mut Tally, drv: &mut Driver, root: &Path, version: &str) {
    let expect = Expectations::load(root, version);
    let corpus = root.join("corpus");
    let mut files = Vec::new();
    let mut stack = vec![corpus.join("manifest")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "json") {
                files.push(p);
            }
        }
    }
    files.sort();
    let mut n = 0;
    for f in files {
        let e: Value = serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
        // Key-selected pinpoints (`select`) reach a driver only as plain pointers the orchestrator
        // resolved; this self-test sends the manifest's plain pointers.
        let Some(values) = e["expect"]["values"].as_array().map(|v| {
            v.iter()
                .filter(|x| x.get("select").is_none())
                .cloned()
                .collect::<Vec<_>>()
        }) else {
            continue;
        };
        let paths: Vec<Value> = values.iter().map(|v| v["path"].clone()).collect();
        for var in e["variants"].as_array().into_iter().flatten() {
            let Some(blob) = var["blob"]["path"].as_str() else {
                continue;
            };
            let id = e["id"].as_str().unwrap_or("?");
            let key = variant_key(&e, var);
            let input =
                json!({"kind": "xdr", "xdr_type": var["xdr_type"], "path": corpus.join(blob)});
            if let Some(exp) = expect.at(&e, &key, "L0") {
                let r = drv.run("L0", CORPUS_PROFILE, input.clone());
                if held(t, &format!("L0 {id} ({key})"), &r, Some(exp)) {
                    continue;
                }
            }
            let mut input = input;
            input["pinpoints"] = json!(paths);
            let r = drv.run("L2", CORPUS_PROFILE, input);
            if held(
                t,
                &format!("L2 {id} ({key})"),
                &r,
                expect.at(&e, &key, "L2"),
            ) {
                continue;
            }
            if outcome(&r) != "ok" {
                t.check(
                    false,
                    format!("L2 {id} ({}): {}", var["network"], outcome(&r)),
                );
                continue;
            }
            for (want, got) in values
                .iter()
                .zip(r["actual"]["pinpoints"].as_array().into_iter().flatten())
            {
                n += 1;
                let equals = resolve(&want["equals"], &var["derived"]);
                t.check(
                    got["found"] == json!(true) && got["value"] == equals,
                    format!("L2 {id} {}: got {got}, manifest {equals}", want["path"]),
                );
            }
        }
    }
    println!("corpus pinpoints compared: {n}");
}

fn check_protocol(t: &mut Tally, drv: &mut Driver) {
    let small = json!({"kind": "xdr", "xdr_type": "ScVal", "xdr_hex": "00000001"});
    for (level, c) in [("L1", "no_object_layer"), ("L3", "no_native_layer")] {
        let r = drv.run(level, "limits-default", small.clone());
        t.check(
            outcome(&r) == "n_a" && code(&r) == c,
            format!("{level} is n_a/{c}: {r}"),
        );
    }
    let r = drv.run(
        "L0",
        "limits-none",
        json!({"kind": "xdr", "xdr_type": "NoSuchType", "xdr_hex": "00"}),
    );
    t.check(
        outcome(&r) == "n_a" && code(&r) == "type_not_generated",
        format!("unknown type: {r}"),
    );
    t.check(
        r["profile"] == json!("limits-none") && r["entry"] == json!("selftest/x"),
        format!("echo: {r}"),
    );
    let r = drv.run(
        "L0",
        "limits-default",
        json!({"kind": "xdr", "xdr_type": "SCVal", "xdr_hex": "00000001"}),
    );
    t.check(
        outcome(&r) == "ok",
        format!("the XDR spelling SCVal resolves: {r}"),
    );
    t.check(
        r["actual"]["consumed_bytes"] == json!(4)
            && r["actual"]["reencoded_sha256"] == json!(sha256_hex("00000001")),
        format!("L0 ok carries consumed_bytes and reencoded_sha256: {r}"),
    );
    // Two frames, the second one selected.
    let framed = json!({"kind": "xdr", "xdr_type": "ScVal", "xdr_hex": "80000004000000018000000800000003000000ff", "framing": "record-marked", "frame_index": 1});
    let r = drv.run("L0", "limits-default", framed);
    t.check(
        outcome(&r) == "ok" && r["actual"]["consumed_bytes"] == json!(8),
        format!("record-marked frame 1: {r}"),
    );
    let r = drv.run(
        "L4",
        "limits-default",
        json!({"kind": "api", "api_op": "price.encode", "args": {}}),
    );
    t.check(
        outcome(&r) == "n_a" && code(&r) == "op_not_supported",
        format!("unimplemented op: {r}"),
    );
    let r = drv.raw("this is not JSON").expect("answer");
    t.check(
        r["op"] == json!("protocol_error"),
        format!("garbage line: {r}"),
    );
    let r = drv.call(json!({"op": "fly"})).expect("answer");
    t.check(
        r["op"] == json!("protocol_error") && r["id"].is_u64(),
        format!("unknown op: {r}"),
    );
}

/// An `api` input.
fn api_input(op: &str, args: Value) -> Value {
    json!({"kind": "api", "api_op": op, "args": args})
}

fn check_vocabulary(t: &mut Tally, drv: &mut Driver, root: &Path, declared: &[String]) {
    let key = "3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a";
    let g = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";
    let m = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ";
    let vectors: Vec<Value> = serde_json::from_slice(
        &std::fs::read(root.join("evidence/sdk-matrix/vectors/vectors.json")).unwrap(),
    )
    .unwrap();
    let envelope = vectors
        .iter()
        .find(|v| v["id"] == json!("1c"))
        .and_then(|v| v["hex"].as_str())
        .expect("probe vector 1c")
        .to_string();
    let memo_hi = "00000001000000026869".to_string() + "0000";
    // A well-formed call of every declared operation, and the argument that makes it malformed.
    let calls: Vec<(&str, Value, Value)> = vec![
        (
            "strkey.decode",
            json!({"text": g}),
            json!({"text": g, "strkey": g}),
        ),
        (
            "strkey.encode",
            json!({"type": "account", "payload_hex": key}),
            json!({"type": "account", "payload": key}),
        ),
        (
            "muxed_account.encode",
            json!({"account": g, "id": {"native": "string", "value": "5"}}),
            json!({"account_id": g, "id": {"native": "string", "value": "5"}}),
        ),
        (
            "muxed_account.decode",
            json!({"text": m}),
            json!({"address": m}),
        ),
        (
            "address.to_strkey",
            json!({"xdr_hex": format!("00000000{key}")}),
            json!({"xdr_hex": format!("00000000{key}"), "xdr_type": "SignerKey"}),
        ),
        (
            "address.from_sc_address",
            json!({"xdr_hex": format!("0000000000000000{key}")}),
            json!({"xdr": format!("0000000000000000{key}")}),
        ),
        (
            "signer_key.to_strkey",
            json!({"xdr_hex": {"hex": format!("00000000{key}")}}),
            json!({"xdr_hex": {"hex": format!("00000000{}", key.to_uppercase())}}),
        ),
        (
            "transaction.hash",
            json!({"xdr_hex": envelope, "passphrase": "Test SDF Network ; September 2015"}),
            json!({"xdr_hex": "zz", "passphrase": "Test SDF Network ; September 2015"}),
        ),
        (
            "memo.text_roundtrip",
            json!({"xdr_hex": memo_hi}),
            json!({"xdr_hex": "00000000"}),
        ),
        (
            "xdrjson.decode",
            json!({"xdr_type": "ClaimPredicate", "json": "\"unconditional\""}),
            json!({"type": "ClaimPredicate", "json": "\"unconditional\""}),
        ),
    ];
    let mut covered: Vec<&str> = Vec::new();
    for (op, good, bad) in &calls {
        covered.push(op);
        let r = drv.run("L4", "limits-default", api_input(op, good.clone()));
        let o = outcome(&r);
        t.check(
            matches!(o, "ok" | "reject" | "diverge"),
            format!("{op}: a well-formed call answers with an SDK outcome: {r}"),
        );
        let a = &r["actual"]["api"];
        if o == "ok" {
            t.check(
                !a["value"].is_null() || *op == "xdrjson.decode",
                format!("{op}: ok without a value: {r}"),
            );
            let strkey_op = matches!(
                *op,
                "strkey.encode"
                    | "muxed_account.encode"
                    | "address.to_strkey"
                    | "address.from_sc_address"
                    | "signer_key.to_strkey"
            );
            if !a["xdr_hex"].is_null() || strkey_op {
                t.check(
                    a["self_decode"].is_string(),
                    format!("{op}: ok without self_decode: {r}"),
                );
            }
        }
        let r = drv.run("L4", "limits-default", api_input(op, bad.clone()));
        t.check(
            r["op"] == json!("protocol_error") && r["id"].is_u64(),
            format!("{op}: a malformed call {bad} is a protocol error: {r}"),
        );
        let r = drv.run("L4", "limits-default", api_input(op, json!({})));
        t.check(
            r["op"] == json!("protocol_error"),
            format!("{op}: a call without its required arguments is a protocol error: {r}"),
        );
    }
    for d in declared {
        t.check(
            covered.contains(&d.as_str()),
            format!("declared op {d} has a vocabulary check"),
        );
    }
    // Values per the vocabulary.
    let r = drv.run(
        "L4",
        "limits-default",
        api_input("memo.text_roundtrip", json!({"xdr_hex": memo_hi})),
    );
    t.check(
        r["actual"]["api"]["value"] == json!("6869")
            && r["actual"]["api"]["xdr_hex"] == json!(memo_hi)
            && r["actual"]["api"]["self_decode"] == json!("accepted"),
        format!("memo.text_roundtrip value is the native text's bytes in hex: {r}"),
    );
    let r = drv.run(
        "L4",
        "limits-default",
        api_input("muxed_account.decode", json!({"text": m})),
    );
    t.check(
        r["actual"]["api"]["value"] == json!({"account": g, "id": "0"}),
        format!("muxed_account.decode value: {r}"),
    );
    // Tagged IDs the library's u64 cannot hold, and untagged ones that are not integers.
    for (tag, v) in [
        ("number", "-1"),
        ("string", "18446744073709551616"),
        ("bigint", "0x10"),
        ("string", ""),
    ] {
        let r = drv.run(
            "L4",
            "limits-default",
            api_input(
                "muxed_account.encode",
                json!({"account": g, "id": {"native": tag, "value": v}}),
            ),
        );
        t.check(
            outcome(&r) == "n_a" && code(&r) == "value_not_representable",
            format!("muxed ID {tag} {v:?} is not representable: {r}"),
        );
    }
    let r = drv.run(
        "L4",
        "limits-default",
        api_input("muxed_account.encode", json!({"account": g, "id": "abc"})),
    );
    t.check(
        r["op"] == json!("protocol_error"),
        format!("an untagged non-integer ID is malformed: {r}"),
    );
    let r = drv.run(
        "L4",
        "limits-default",
        api_input(
            "muxed_account.encode",
            json!({"account": g, "id": {"native": "bool", "value": "1"}}),
        ),
    );
    t.check(
        r["op"] == json!("protocol_error"),
        format!("an unknown native tag is malformed: {r}"),
    );
    // A payload no typed key can hold is refused by the typed API, not answered n_a.
    let r = drv.run(
        "L4",
        "limits-default",
        api_input(
            "strkey.encode",
            json!({"type": "account", "payload_hex": "00"}),
        ),
    );
    t.check(
        outcome(&r) == "reject" && code(&r) == "strkey_payload",
        format!("a one-byte account payload is refused: {r}"),
    );
    // A strkey entry with a type outside the vocabulary.
    let r = drv.run(
        "L4",
        "limits-default",
        json!({"kind": "strkey", "text": g, "declared_type": "public_key"}),
    );
    t.check(
        r["op"] == json!("protocol_error"),
        format!("unknown declared_type: {r}"),
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: xdrcheck-driver-selftest <driver> <stellar-xdr version> <repository root>");
        std::process::exit(2);
    }
    let path = PathBuf::from(&args[1]);
    let version = args[2].as_str();
    let root = PathBuf::from(&args[3]);
    let mut t = Tally::default();
    let mut drv = Driver::start(&path);

    let d = drv.call(json!({"op": "describe"})).expect("describe");
    let p30 = version == "30.0.0";
    t.check(
        d["sdk"]["package"] == json!("stellar-xdr") && d["sdk"]["ecosystem"] == json!("crates.io"),
        format!("describe sdk: {}", d["sdk"]),
    );
    t.check(
        d["sdk"]["version"] == json!(version),
        format!("describe sdk.version {} is {version}", d["sdk"]["version"]),
    );
    t.check(
        d["decode"]["profiles"] == json!(PROFILES),
        "describe profiles",
    );
    t.check(
        d["xdr_schema"]["probes"]
            == json!({"sc_address_type_muxed_contract": p30, "stellar_value_signed_ms": p30}),
        format!("describe probes: {}", d["xdr_schema"]),
    );
    // The reported protocol is the highest one the driver can prove: 30 with every Protocol 30
    // probe, 29 without one, none when the crate declares enum members above the Protocol 30
    // ceiling (src/reach.rs).
    t.check(
        d["xdr_schema"]["protocol"] == json!(if p30 { 30 } else { 29 }),
        format!("describe protocol: {}", d["xdr_schema"]),
    );
    t.check(
        reach::schema_protocol(&[(30, true), (30, true)], &[]) == Some(30)
            && reach::schema_protocol(&[(30, true), (30, false)], &[]) == Some(29)
            && reach::schema_protocol(&[(31, false), (30, true)], &[]) == Some(30)
            && reach::schema_protocol(&[(30, true)], &["ContractCostType 95".into()]).is_none(),
        "protocol from the probes and the ceiling",
    );
    t.check(
        reach::beyond_known(|e| {
            if e == "ScValType" {
                vec![0, 22, 23]
            } else {
                vec![0]
            }
        }) == ["ScValType 23"],
        "a member above the ceiling is found",
    );
    // A Protocol 30 crate declares each ceiling member itself, so the ceiling is not set too high
    // to notice a newer crate.
    for (e, max) in reach::CEILING {
        let vs = reach::crate_values(e);
        t.check(!p30 || vs.contains(&max), format!("{e} {max} is declared"));
        t.check(
            vs.iter().all(|v| *v <= max),
            format!("{e} has no member above {max}"),
        );
    }
    let strkey = if p30 { "1.0.0" } else { "0.0.13" };
    t.check(
        d["sdk"]["dependencies"][0]["version"] == json!(strkey),
        format!("stellar-strkey {strkey}: {}", d["sdk"]["dependencies"]),
    );

    check_probe(&mut t, &mut drv, &root, version);
    check_depth(&mut t, &mut drv, &path);
    check_xdrjson(&mut t, &mut drv, version);
    if p30 {
        check_corpus(&mut t, &mut drv, &root, version);
    }
    check_protocol(&mut t, &mut drv);
    let declared: Vec<String> = d["api_ops"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    check_vocabulary(&mut t, &mut drv, &root, &declared);

    let r = drv.call(json!({"op": "shutdown"}));
    t.check(
        r == Some(json!({"xcc": TAG, "id": drv.next - 1, "op": "shutdown", "ok": true})),
        format!("shutdown: {r:?}"),
    );
    let (status, _) = drv.finish();
    t.check(status == "exit 0", format!("exit after shutdown: {status}"));

    println!(
        "stellar-xdr {version}: {} checks passed, {} failed",
        t.passed,
        t.failed.len()
    );
    if !t.failed.is_empty() {
        std::process::exit(1);
    }
}
