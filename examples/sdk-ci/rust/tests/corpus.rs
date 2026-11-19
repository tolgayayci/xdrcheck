//! Puts the xdrcheck corpus through stellar-xdr at the byte level (conformance level L0).
//!
//! `XDRCHECK_CORPUS` names the corpus: a release archive `xdrcheck-<version>.tar.gz` or a directory. For every
//! entry outside the stress tier and every variant that holds one plain value of a named XDR type:
//!
//! - bytes the corpus says must be refused (validity `malformed` or `invalid`) conform when decoding fails;
//! - other bytes conform when they decode consuming every byte, re-encode to the same bytes, and the decoded
//!   value's SEP-51 JSON (`serde_json::to_value`) equals the corpus's expected JSON;
//! - a type the library does not generate is unread (`type_not_generated`); a panic is a failure (`crash`).
//!
//! The run must equal `expected-failures.txt` next to this crate (or the file `XDRCHECK_EXPECTED_FAILURES` names):
//! a new failure, a listed failure that now conforms, and a variant never read that the list does not name all
//! fail the test. `XDRCHECK_WRITE_EXPECTED_FAILURES=1` rewrites the file from the run instead; review it before
//! committing it.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use serde_json::Value;
use stellar_xdr::{Limits, Type, TypeVariant, WriteXdr};
use xdrcheck::{Corpus, ExpectedFailures, Results, Variant};

/// The decode limits: `Limits::none()`, what the crate's own command-line tool decodes with. This test judges
/// how the library reads bytes, not a caller's resource policy: the stress entries (nesting and length prefixes
/// built to exhaust a reader without limits) ship in the release's separate `stress/` root and are skipped below,
/// so every entry this test reads is safe to decode unbounded. A bounded depth (the Soroban host's 500, say)
/// would refuse valid ledgers whose authorization trees nest deeper than that from the `LedgerCloseMeta` root,
/// which says something about the limit, not about the library. A service decoding untrusted input should pass
/// its own `Limits`; to test those, change this function and list what they refuse in the expected failures.
fn limits(_input_len: usize) -> Limits {
    Limits::none()
}

const LEVEL: &str = "L0";

fn type_variant(name: &str) -> Option<TypeVariant> {
    name.parse::<TypeVariant>().ok()
}

/// The first place where two JSON values differ, as a JSON Pointer.
fn first_difference(got: &Value, want: &Value, at: &str) -> Option<String> {
    match (got, want) {
        (Value::Object(g), Value::Object(w)) => {
            for (k, wv) in w {
                let p = format!("{at}/{k}");
                match g.get(k) {
                    None => return Some(format!("{p} missing")),
                    Some(gv) => {
                        if let Some(d) = first_difference(gv, wv, &p) {
                            return Some(d);
                        }
                    }
                }
            }
            g.keys()
                .find(|k| !w.contains_key(*k))
                .map(|k| format!("{at}/{k} not expected"))
        }
        (Value::Array(g), Value::Array(w)) => {
            if g.len() != w.len() {
                return Some(format!("{at}: {} items, expected {}", g.len(), w.len()));
            }
            g.iter()
                .zip(w)
                .enumerate()
                .find_map(|(i, (gv, wv))| first_difference(gv, wv, &format!("{at}/{i}")))
        }
        _ if got == want => None,
        _ => Some(format!("{at}: {got}, expected {want}")),
    }
}

/// Judges one variant: Ok(()) when it conforms, Err(detail) otherwise.
fn judge(v: &Variant, tv: TypeVariant, bytes: &[u8]) -> Result<(), String> {
    let decoded = Type::from_xdr(tv, bytes, limits(bytes.len()));
    if v.must_refuse() {
        return match decoded {
            Err(_) => Ok(()),
            Ok(_) => Err("accepted invalid input".into()),
        };
    }
    let t = decoded.map_err(|e| format!("refused valid bytes: {e}"))?;
    let enc = t
        .to_xdr(Limits::none())
        .map_err(|e| format!("re-encoding failed: {e}"))?;
    if enc != bytes {
        return Err(format!(
            "re-encoding is {} bytes and differs from the {}-byte input",
            enc.len(),
            bytes.len()
        ));
    }
    let want = v
        .expected_json()
        .unwrap_or_else(|e| panic!("{e}"))
        .ok_or("the corpus has no expected JSON for valid bytes")?;
    let got = serde_json::to_value(&t).map_err(|e| format!("no SEP-51 JSON: {e}"))?;
    match first_difference(&got, &want, "") {
        None => Ok(()),
        Some(d) => Err(format!("SEP-51 JSON differs at {d}")),
    }
}

#[test]
fn corpus_conformance() {
    let path = std::env::var("XDRCHECK_CORPUS").expect(
        "set XDRCHECK_CORPUS to the corpus: a release archive xdrcheck-<version>.tar.gz or a corpus directory",
    );
    let corpus = Corpus::open(&path).unwrap_or_else(|e| panic!("{e}"));
    println!("corpus {} from {}", corpus.version(), corpus.source());
    println!("stellar-xdr {}", stellar_xdr::VERSION.pkg);

    let mut results = Results::new();
    let (mut pass, mut fail, mut unread) = (0, 0, 0);
    for entry in corpus.entries().iter().filter(|e| e.tier != "stress") {
        results.select(&entry.id);
        for v in entry.variants.iter().filter(|v| v.decodable()) {
            let Some(tv) = type_variant(&v.xdr_type) else {
                results.unread(&entry.id, &v.key, "type_not_generated");
                unread += 1;
                continue;
            };
            let bytes = v.blob().unwrap_or_else(|e| panic!("{e}"));
            let verdict =
                catch_unwind(AssertUnwindSafe(|| judge(v, tv, &bytes))).unwrap_or_else(|p| {
                    let msg = p
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                        .unwrap_or_default();
                    Err(format!("crash: {msg}"))
                });
            match verdict {
                Ok(()) => {
                    results.pass(&entry.id, &v.key, LEVEL);
                    pass += 1;
                }
                Err(detail) => {
                    println!("FAIL {} {} {}: {detail}", entry.id, v.key, v.xdr_type);
                    results.fail(&entry.id, &v.key, LEVEL, &detail);
                    fail += 1;
                }
            }
        }
    }
    println!("variants: {pass} conform, {fail} fail, {unread} unread");

    let list_path = std::env::var_os("XDRCHECK_EXPECTED_FAILURES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("expected-failures.txt"));
    if std::env::var("XDRCHECK_WRITE_EXPECTED_FAILURES").as_deref() == Ok("1") {
        let about = format!(
            "stellar-xdr {} (L0) against corpus {}",
            stellar_xdr::VERSION.pkg,
            corpus.version()
        );
        std::fs::write(&list_path, ExpectedFailures::write(&results, &about))
            .unwrap_or_else(|e| panic!("{}: {e}", list_path.display()));
        println!("wrote {}", list_path.display());
        return;
    }
    let list = ExpectedFailures::read(&list_path).unwrap_or_else(|e| panic!("{e}"));
    let cmp = results.compare(&list, true);
    print!("{}", cmp.to_text());
    assert!(cmp.passed(), "the run differs from {}", list_path.display());
}
