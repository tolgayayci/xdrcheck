//! `xdrcheck-corpus verify` on the vendored corpus and on doctored copies of it: each check passes on
//! the real corpus and fails on a copy with the defect it exists to catch.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A fresh copy of `corpus/` under the test temp directory.
fn copy_corpus(name: &str) -> PathBuf {
    fn copy(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for e in std::fs::read_dir(from).unwrap() {
            let p = e.unwrap().path();
            let dest = to.join(p.file_name().unwrap());
            if p.is_dir() {
                copy(&p, &dest);
            } else {
                std::fs::copy(&p, &dest).unwrap();
            }
        }
    }
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("verify")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    copy(&repo().join("corpus"), &dir.join("corpus"));
    std::fs::copy(repo().join("pins.toml"), dir.join("pins.toml")).unwrap();
    dir.join("corpus")
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    report: Option<Value>,
}

impl Run {
    /// Rows of `check` that failed, as (entry, variant, detail).
    fn failed(&self, check: &str) -> Vec<(String, String, String)> {
        let report = self.report.as_ref().expect("report written");
        report["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["corpus"]["check"] == check && r["corpus"]["ok"] == false)
            .map(|r| {
                (
                    r["entry"].as_str().unwrap().to_string(),
                    r["variant"].as_str().unwrap_or("").to_string(),
                    r["corpus"]["detail"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    fn rows(&self, check: &str) -> usize {
        let report = self.report.as_ref().expect("report written");
        report["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["corpus"]["check"] == check)
            .count()
    }
}

fn verify(corpus: &Path, args: &[&str]) -> Run {
    let report = corpus.parent().unwrap().join(format!(
        "report-{}.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let out = Command::new(env!("CARGO_BIN_EXE_xdrcheck-corpus"))
        .arg("--corpus")
        .arg(corpus)
        .arg("verify")
        .args(args)
        .arg("--report")
        .arg(&report)
        .arg("--pins")
        .arg(corpus.parent().unwrap().join("pins.toml"))
        .output()
        .unwrap();
    let report = std::fs::read(&report)
        .ok()
        .map(|b| serde_json::from_slice(&b).unwrap());
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        report,
    }
}

fn edit_json(path: &Path, f: impl FnOnce(&mut Value)) {
    let mut v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    f(&mut v);
    std::fs::write(path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
}

const CAP40: &str = "manifest/cap-0040/signed-payload-signer-added.json";
const CAP40_ID: &str = "cap-0040/signed-payload-signer-added";

fn cap40_blob(corpus: &Path) -> PathBuf {
    let m: Value = serde_json::from_slice(&std::fs::read(corpus.join(CAP40)).unwrap()).unwrap();
    corpus.join(m["variants"][0]["blob"]["path"].as_str().unwrap())
}

/// Validate a report against the frozen report schema.
fn assert_report_valid(report: &Value) {
    let schema: Value = serde_json::from_slice(
        &std::fs::read(repo().join("corpus/schema/report.schema.json")).unwrap(),
    )
    .unwrap();
    let v = jsonschema::draft202012::new(&schema).unwrap();
    let errors: Vec<String> = v.iter_errors(report).map(|e| e.to_string()).collect();
    assert!(errors.is_empty(), "report does not validate: {errors:?}");
}

/// (entries, variants) of the ledger/xdr entries in a corpus copy.
/// (entries, variants, variants of positive entries, variants of negative entries).
/// (manifest files, variants, positive variants, negative variants, spec variants); spec variants are in the
/// variant count only.
fn count_entries(corpus: &Path) -> (usize, usize, usize, usize, usize) {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out)
            } else {
                out.push(p)
            }
        }
    }
    let mut files = Vec::new();
    walk(&corpus.join("manifest"), &mut files);
    let (mut positive, mut negative, mut spec) = (0, 0, 0);
    for f in &files {
        let v: Value = serde_json::from_slice(&std::fs::read(f).unwrap()).unwrap();
        let n = v["variants"].as_array().map(Vec::len).unwrap_or(0);
        // A spec entry's variants get the hashes and spec checks only.
        if v["kind"] == "spec" {
            spec += n;
        } else if v["negative"] == true {
            negative += n;
        } else {
            positive += n;
        }
    }
    (
        files.len(),
        positive + negative + spec,
        positive,
        negative,
        spec,
    )
}

#[test]
fn vendored_corpus_passes_every_check() {
    let corpus = copy_corpus("pristine");
    let r = verify(&corpus, &[]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    let report = r.report.as_ref().unwrap();
    assert_report_valid(report);
    // entries x (schema, ids) + variants x (hashes, roundtrip, sidecar, pinpoints)
    // + chain indexes x schema + corpus.json x schema.
    let (entries, variants, positive, negative, spec) = count_entries(&corpus);
    let chains = std::fs::read_dir(corpus.join("chains"))
        .unwrap()
        .flat_map(|d| std::fs::read_dir(d.unwrap().path()).unwrap())
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|x| x == "json")
        })
        .count();
    assert_eq!(r.rows("schema"), entries + chains + 1);
    assert_eq!(r.rows("ids"), entries);
    assert_eq!(r.rows("hashes"), variants);
    for c in ["roundtrip", "sidecar", "pinpoints"] {
        assert_eq!(r.rows(c), positive, "{c}");
    }
    assert_eq!(r.rows("reject"), negative);
    assert_eq!(r.rows("spec"), spec);
    assert!(r.stdout.contains("result: PASS"), "{}", r.stdout);
    // The static subset as `make verify-static` runs it.
    let r = verify(&corpus, &["--checks", "schema,hashes,ids"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
}

#[test]
fn wrong_blob_byte_fails_hashes_and_roundtrip() {
    let corpus = copy_corpus("blob-byte");
    let blob = cap40_blob(&corpus);
    let mut bytes = std::fs::read(&blob).unwrap();
    let n = bytes.len();
    bytes[n - 1] ^= 0x01; // inside the last field of the ledger
    std::fs::write(&blob, bytes).unwrap();
    let r = verify(&corpus, &[]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    let f = r.failed("hashes");
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].0, CAP40_ID);
    assert!(f[0].2.contains("sha256 is"), "{f:?}");
    // The other entries still pass.
    assert!(r.failed("hashes").iter().all(|(e, _, _)| e == CAP40_ID));
}

#[test]
fn wrong_sha_in_manifest_fails_hashes() {
    let corpus = copy_corpus("manifest-sha");
    edit_json(&corpus.join(CAP40), |m| {
        m["variants"][0]["decoded_sha256"] = json!("0".repeat(64));
        m["variants"][0]["source"]["decompressed_sha256"] = json!("1".repeat(64));
    });
    let r = verify(&corpus, &["--checks", "hashes"]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    let f = r.failed("hashes");
    assert_eq!(f.len(), 1, "{f:?}");
    assert!(f[0].2.contains("sidecar"), "{f:?}");
    assert!(f[0].2.contains("decompressed object"), "{f:?}");

    // A chain-index row that disagrees with the variant's blob.
    let corpus = copy_corpus("chain-row");
    let (chain, seq) = trust_p28_chain(&corpus);
    edit_json(&corpus.join(&chain), |c| {
        let row = c["ledgers"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["seq"] == seq)
            .unwrap();
        row["header_hash"] = json!("00".repeat(32));
    });
    let r = verify(&corpus, &["--checks", "hashes"]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    // Every entry with a variant on that ledger fails (cap-0063/parallel-phase-single-cluster shares it).
    let f = r.failed("hashes");
    assert!(
        f.iter()
            .all(|x| x.1 == "testnet@28" && x.2.contains("header_hash")),
        "{f:?}"
    );
    assert!(
        f.iter()
            .any(|x| x.0 == "cap-0073/sac-trust-creates-trustline"),
        "{f:?}"
    );
}

#[test]
fn unknown_id_fails_ids() {
    let corpus = copy_corpus("unknown-id");
    let from = corpus.join(CAP40);
    let to = corpus.join("manifest/cap-0040/not-in-the-plan.json");
    std::fs::rename(&from, &to).unwrap();
    edit_json(&to, |m| m["id"] = json!("cap-0040/not-in-the-plan"));
    let r = verify(&corpus, &["--checks", "ids"]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    let f = r.failed("ids");
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].0, "cap-0040/not-in-the-plan");
    assert!(f[0].2.contains("not in plan.json"), "{f:?}");

    // A path that disagrees with the id fails too.
    let corpus = copy_corpus("path-id");
    edit_json(&corpus.join(CAP40), |m| {
        m["id"] = json!("cap-0073/sac-trust-creates-trustline")
    });
    let r = verify(&corpus, &["--checks", "ids"]);
    assert_eq!(r.code, 1);
    let f = r.failed("ids");
    assert!(
        f.iter()
            .any(|(_, _, d)| d.contains("does not match its path")),
        "{f:?}"
    );
    assert!(
        f.iter()
            .any(|(_, _, d)| d.contains("more than one manifest file")),
        "{f:?}"
    );
}

#[test]
fn wrong_pinpoint_value_fails_pinpoints() {
    let corpus = copy_corpus("pinpoint");
    edit_json(&corpus.join(CAP40), |m| {
        m["expect"]["values"][1]["equals"] = json!(2);
    });
    let r = verify(&corpus, &["--checks", "pinpoints"]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    let f = r.failed("pinpoints");
    assert_eq!(f.len(), 1, "{f:?}");
    assert!(f[0].2.contains("expected 2, sidecar has 1"), "{f:?}");

    // A token with no value in the variant, and a wrong derived ledger hash.
    let corpus = copy_corpus("pinpoint-derived");
    edit_json(&corpus.join(CAP40), |m| {
        m["expect"]["values"][0]["equals"] = json!("${derived.nothing_here}");
        m["variants"][0]["derived"]["ledger_hash"] = json!("ab".repeat(32));
        m["variants"][0]["derived"]["tx_hashes"][0] = json!("cd".repeat(32));
        m["variants"][0]["derived"]["tx_hash"] = json!("ef".repeat(32));
    });
    let r = verify(&corpus, &["--checks", "pinpoints"]);
    let f = r.failed("pinpoints");
    assert_eq!(f.len(), 1, "{f:?}");
    for want in [
        "${derived.nothing_here} has no value",
        "derived.ledger_hash",
        "derived.tx_hashes",
        "derived.tx_hash ",
    ] {
        assert!(f[0].2.contains(want), "{want}: {f:?}");
    }
}

#[test]
fn wrong_passphrase_fails_pinpoints() {
    let corpus = copy_corpus("passphrase");
    edit_json(&corpus.join(CAP40), |m| {
        m["variants"][0]["passphrase"] = json!("Public Global Stellar Network ; September 2015");
    });
    let r = verify(&corpus, &["--checks", "pinpoints"]);
    let f = r.failed("pinpoints");
    assert_eq!(f.len(), 1, "{f:?}");
    assert!(f[0].2.contains("envelope hashes under passphrase"), "{f:?}");
}

/// The cap-0040 variant's sidecar: its path and its uncompressed JSON.
fn cap40_sidecar(corpus: &Path) -> (PathBuf, Value) {
    let m: Value = serde_json::from_slice(&std::fs::read(corpus.join(CAP40)).unwrap()).unwrap();
    let path = corpus.join(m["variants"][0]["decoded"].as_str().unwrap());
    let text = zstd::stream::decode_all(std::fs::read(&path).unwrap().as_slice()).unwrap();
    (path, serde_json::from_slice(&text).unwrap())
}

/// Write a sidecar as `text` (compressed) and, with `rehash`, record its sha256 in the manifest.
fn write_sidecar(corpus: &Path, path: &Path, text: &[u8], rehash: bool) {
    std::fs::write(path, zstd::stream::encode_all(text, 3).unwrap()).unwrap();
    if rehash {
        let sha = xdrcheck_xdr::sha256_hex(text);
        edit_json(&corpus.join(CAP40), |m| {
            m["variants"][0]["decoded_sha256"] = json!(sha)
        });
    }
}

#[test]
fn edited_sidecar_fails_sidecar() {
    // Content edited, hash not updated: both checks see the hash mismatch.
    let corpus = copy_corpus("sidecar");
    let (path, mut d) = cap40_sidecar(&corpus);
    d["v2"]["ledger_header"]["header"]["ledger_seq"] = json!(1);
    write_sidecar(&corpus, &path, &serde_json::to_vec(&d).unwrap(), false);
    let r = verify(&corpus, &["--checks", "sidecar,hashes"]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    for c in ["sidecar", "hashes"] {
        let f = r.failed(c);
        assert_eq!(f.len(), 1, "{c}: {f:?}");
        assert!(f[0].2.contains("uncompressed sha256 is"), "{f:?}");
    }

    // Content edited and the hash updated to match: the content check still catches it.
    let corpus = copy_corpus("sidecar-rehashed");
    let (path, mut d) = cap40_sidecar(&corpus);
    d["v2"]["ledger_header"]["header"]["ledger_seq"] = json!(1);
    write_sidecar(&corpus, &path, &serde_json::to_vec(&d).unwrap(), true);
    let r = verify(&corpus, &["--checks", "sidecar,hashes"]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    let f = r.failed("sidecar");
    assert_eq!(f.len(), 1, "{f:?}");
    assert!(
        f[0].2.contains("/v2/ledger_header/header/ledger_seq"),
        "{f:?}"
    );
    assert!(r.failed("hashes").is_empty(), "{:?}", r.failed("hashes"));

    // Re-serialised (pretty, other zstd level) with the hash updated: the values are equal,
    // so `sidecar` passes.
    let corpus = copy_corpus("sidecar-reformat");
    let (path, d) = cap40_sidecar(&corpus);
    write_sidecar(
        &corpus,
        &path,
        &serde_json::to_vec_pretty(&d).unwrap(),
        true,
    );
    let r = verify(&corpus, &["--checks", "sidecar,hashes"]);
    assert_eq!(r.code, 0, "{}", r.stdout);

    // A sidecar that is not where the blob's hash puts it fails `hashes`.
    let corpus = copy_corpus("sidecar-path");
    let (path, _) = cap40_sidecar(&corpus);
    let moved = corpus.join("decoded/elsewhere.json.zst");
    std::fs::rename(&path, &moved).unwrap();
    edit_json(&corpus.join(CAP40), |m| {
        m["variants"][0]["decoded"] = json!("decoded/elsewhere.json.zst")
    });
    let r = verify(&corpus, &["--checks", "hashes"]);
    assert_eq!(r.code, 1);
    assert!(
        r.failed("hashes")[0].2.contains("one sidecar per blob"),
        "{}",
        r.stdout
    );
}

#[test]
fn schema_violation_fails_schema() {
    let corpus = copy_corpus("schema");
    edit_json(&corpus.join(CAP40), |m| {
        m["not_a_field"] = json!(true);
        m["variants"][0]["meta"]
            .as_object_mut()
            .unwrap()
            .remove("profile");
    });
    let (chain, _) = trust_p28_chain(&corpus);
    edit_json(&corpus.join(&chain), |c| {
        c["schema"] = json!("xcc.chain.index/v9");
    });
    let r = verify(&corpus, &["--checks", "schema"]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    let f = r.failed("schema");
    assert_eq!(f.len(), 2, "{f:?}");
    let entry = f.iter().find(|(e, _, _)| e == CAP40_ID).unwrap();
    assert!(entry.2.contains("not_a_field"), "{f:?}");
    assert!(entry.2.contains("meta.profile"), "{f:?}");
    assert!(f.iter().any(|(e, _, _)| *e == chain));
}

#[test]
fn unparsable_manifest_is_a_failed_check_not_a_crash() {
    let corpus = copy_corpus("unparsable");
    std::fs::write(corpus.join(CAP40), b"{ not json").unwrap();
    let r = verify(&corpus, &["--checks", "schema,ids,hashes"]);
    assert_eq!(r.code, 1, "{}{}", r.stdout, r.stderr);
    assert_eq!(r.failed("schema").len(), 1);
}

/// Write a blob into the corpus, returning its manifest `blob` object.
fn add_blob(corpus: &Path, bytes: &[u8]) -> Value {
    let sha = xdrcheck_xdr::sha256_hex(bytes);
    let rel = format!("blobs/{}/{sha}.xdr", &sha[..2]);
    std::fs::create_dir_all(corpus.join(&rel).parent().unwrap()).unwrap();
    std::fs::write(corpus.join(&rel), bytes).unwrap();
    json!({"sha256": sha, "bytes": bytes.len(), "path": rel})
}

fn negative_entry(id: &str, reason: &str, blob: Value) -> Value {
    let validity = match reason {
        "value_out_of_range" | "ordering" | "spec_sections" => "invalid",
        _ => "malformed",
    };
    json!({
        "schema": "xcc.manifest.entry/v1",
        "id": id,
        "title": "A synthetic negative ScVal for the reject check",
        "kind": "xdr",
        "caps": [],
        "caps_note": "A pure encoding rule of RFC 4506, not tied to a CAP.",
        "protocol": {"introduced": 20},
        "synthetic": true,
        "negative": true,
        "validity": validity,
        "flags": [reason.replace('_', "-")],
        "why": "A decoder that accepts this input accepts bytes stellar-core rejects.",
        "variants": [{
            "network": "none",
            "passphrase": "",
            "protocol": 30,
            "xdr_type": "ScVal",
            "requires": [],
            "blob": blob,
            "source": {"kind": "synthetic", "recipe": "hand-encoded in the verify test", "reason": "negative vector"}
        }],
        "expect": {"reject": {"reason": reason}}
    })
}

#[test]
fn negative_entries_must_be_rejected_for_their_reason() {
    let corpus = copy_corpus("negative");
    let (_, _, _, vendored_negative, _) = count_entries(&corpus);
    // SCV_VOID followed by four zero bytes: trailing bytes.
    let trailing = add_blob(&corpus, &[0, 0, 0, 1, 0, 0, 0, 0]);
    // SCV_BOOL with value 2.
    let bool2 = add_blob(&corpus, &[0, 0, 0, 0, 0, 0, 0, 2]);
    // A valid SCV_VOID.
    let valid = add_blob(&corpus, &[0, 0, 0, 1]);
    let dir = corpus.join("manifest/xdr-strict");
    std::fs::create_dir_all(&dir).unwrap();
    let write = |slug: &str, reason: &str, blob: &Value| {
        let id = format!("xdr-strict/{slug}");
        std::fs::write(
            dir.join(format!("{slug}.json")),
            serde_json::to_vec_pretty(&negative_entry(&id, reason, blob.clone())).unwrap(),
        )
        .unwrap();
    };
    // Entries the vendored corpus already holds are replaced, not added.
    let added = ["trailing-bytes", "bool-value-2"]
        .iter()
        .filter(|slug| !dir.join(format!("{slug}.json")).exists())
        .count();
    write("trailing-bytes", "trailing_bytes", &trailing);
    write("bool-value-2", "bool_range", &bool2);
    let r = verify(&corpus, &["--checks", "schema,ids,reject,hashes"]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.rows("reject"), vendored_negative + added);

    // Wrong reason class, and bytes the oracle accepts.
    write("trailing-bytes", "nonzero_padding", &trailing);
    write("bool-value-2", "bool_range", &valid);
    let r = verify(&corpus, &["--checks", "reject"]);
    assert_eq!(r.code, 1);
    let f = r.failed("reject");
    assert_eq!(f.len(), 2, "{f:?}");
    let by = |id: &str| f.iter().find(|(e, _, _)| e == id).unwrap().2.clone();
    assert!(
        by("xdr-strict/trailing-bytes").contains("another reason"),
        "{f:?}"
    );
    assert!(
        by("xdr-strict/bool-value-2").contains("accepts the bytes"),
        "{f:?}"
    );
}

/// The chain index (path relative to the corpus root) holding the cap-0073 sac-trust variant on the
/// testnet passphrase at Protocol 28, and that variant's ledger sequence.
fn trust_p28_chain(corpus: &Path) -> (String, u64) {
    let m: Value = serde_json::from_slice(
        &std::fs::read(corpus.join("manifest/cap-0073/sac-trust-creates-trustline.json")).unwrap(),
    )
    .unwrap();
    let v = m["variants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["network"] == "testnet" && v["protocol"] == 28)
        .unwrap();
    let blob = v["blob"]["sha256"].as_str().unwrap();
    for d in std::fs::read_dir(corpus.join("chains")).unwrap() {
        let d = d.unwrap().path();
        for f in std::fs::read_dir(&d).unwrap() {
            let f = f.unwrap().path();
            if f.extension().is_none_or(|x| x != "json") {
                continue;
            }
            let c: Value = serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
            if c["ledgers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["blob_sha256"] == blob)
            {
                let rel = f.strip_prefix(corpus).unwrap().display().to_string();
                return (rel, v["ledger_seq"].as_u64().unwrap());
            }
        }
    }
    panic!("no chain holds the sac-trust testnet@28 blob {blob}")
}

/// A golden cache holding one record-marked file whose frame 1 is the cap-0073 p28 testnet blob.
fn golden_fixture(corpus: &Path) -> (PathBuf, Value) {
    let m: Value = serde_json::from_slice(
        &std::fs::read(corpus.join("manifest/cap-0073/sac-trust-creates-trustline.json")).unwrap(),
    )
    .unwrap();
    let v = m["variants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["network"] == "testnet" && v["protocol"] == 28)
        .unwrap()
        .clone();
    let blob = std::fs::read(corpus.join(v["blob"]["path"].as_str().unwrap())).unwrap();
    let other = std::fs::read(cap40_blob(corpus)).unwrap();
    let stream = xdrcheck_xdr::frame([other.as_slice(), blob.as_slice()]).unwrap();
    let goldens = corpus.parent().unwrap().join("goldens");
    let file = "test-lcm-current/InvokeHostFunctionTests/0123456789abcdef.xdr";
    let path = goldens.join("v30.0.0").join(file);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &stream).unwrap();
    let mut gv = v.clone();
    gv["network"] = json!("core-test");
    gv["passphrase"] = json!("(V) (;,,;) (V)");
    gv["source"] = json!({
        "kind": "core-golden",
        "core_tag": "v30.0.0",
        "core_commit": "0e49751aa9ddf892302cca02cea7f3f5d97df9f1",
        "tier": "current",
        "file": file,
        "file_sha256": xdrcheck_xdr::sha256_hex(&stream),
        "frame_index": 1,
        "test_name": "a fixture test name"
    });
    (goldens, gv)
}

/// Drop the vendored core-golden variants (and entries left with none) so a test sees only its own
/// fixture golden and needs no golden cache.
fn without_vendored_goldens(corpus: &Path) {
    let mut stack = vec![corpus.join("manifest")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let mut m: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
            let Some(vs) = m["variants"].as_array_mut() else {
                continue; // api and strkey entries have no variants
            };
            let before = vs.len();
            vs.retain(|v| v["source"]["kind"] != "core-golden");
            if vs.is_empty() {
                std::fs::remove_file(&p).unwrap();
            } else if vs.len() != before {
                std::fs::write(&p, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
            }
        }
    }
}

#[test]
fn ag1_and_ag3_check_core_golden_variants() {
    let corpus = copy_corpus("ag1");
    without_vendored_goldens(&corpus);
    let (goldens, gv) = golden_fixture(&corpus);
    let manifest = corpus.join("manifest/cap-0073/sac-trust-creates-trustline.json");
    edit_json(&manifest, |m| {
        m["variants"].as_array_mut().unwrap().push(gv.clone())
    });
    let g = goldens.to_str().unwrap();
    let r = verify(&corpus, &["--checks", "ag1,ag3,schema", "--goldens", g]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.rows("ag1"), 1);
    assert_eq!(r.rows("ag3"), 1);

    // Wrong frame: AG-1 fails.
    edit_json(&manifest, |m| {
        let vs = m["variants"].as_array_mut().unwrap();
        vs.last_mut().unwrap()["source"]["frame_index"] = json!(0);
    });
    let r = verify(&corpus, &["--checks", "ag1", "--goldens", g]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(
        r.failed("ag1")[0].2.contains("frame 0"),
        "{:?}",
        r.failed("ag1")
    );

    // No golden cache: the tool cannot run.
    let r = verify(
        &corpus,
        &["--checks", "ag1", "--goldens", "/nonexistent-golden-cache"],
    );
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(r.stderr.contains("not in the cache"), "{}", r.stderr);
}

#[test]
fn bulk_tier_checks_every_golden_record() {
    let corpus = copy_corpus("bulk");
    // Two "golden files" made from probe meta streams.
    let goldens = corpus.parent().unwrap().join("goldens");
    let tier = goldens.join("v30.0.0").join("test-lcm-current");
    let mut index = String::new();
    for (name, src) in [
        (
            "A/1111111111111111.xdr",
            "evidence/local-core/out/testnet/run-1/meta.xdr",
        ),
        (
            "B/2222222222222222.xdr",
            "evidence/wallet-backend-731/out/p28-testnet/run-1/meta.xdr",
        ),
    ] {
        let data = std::fs::read(repo().join(src)).unwrap();
        std::fs::create_dir_all(tier.join(name).parent().unwrap()).unwrap();
        std::fs::write(tier.join(name), &data).unwrap();
        index.push_str(&format!(
            "{}  test-lcm-current/{name}\n",
            xdrcheck_xdr::sha256_hex(&data)
        ));
    }
    std::fs::create_dir_all(corpus.join("bulk")).unwrap();
    std::fs::write(corpus.join("bulk/core-v30.0.0-current.sha256"), &index).unwrap();
    std::fs::write(
        corpus.join("corpus.json"),
        serde_json::to_vec_pretty(&json!({
            "tiers": {"bulk": {"ref": "v30.0.0", "path": "test-lcm-current",
                               "file_index": "bulk/core-v30.0.0-current.sha256"}}
        }))
        .unwrap(),
    )
    .unwrap();
    let g = goldens.to_str().unwrap();
    let r = verify(&corpus, &["--tier", "bulk", "--goldens", g]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.rows("hashes"), 2);
    assert_eq!(r.rows("roundtrip"), 2);
    assert_report_valid(r.report.as_ref().unwrap());
    let r = verify(
        &corpus,
        &["--tier", "bulk", "--checks", "ag3", "--goldens", g],
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(r.stdout.contains("bulk_ledgers_ag3 53"), "{}", r.stdout);

    // A corrupted record mark in one file fails that file only.
    let f = tier.join("B/2222222222222222.xdr");
    let mut data = std::fs::read(&f).unwrap();
    data[3] = data[3].wrapping_add(4);
    std::fs::write(&f, data).unwrap();
    let r = verify(
        &corpus,
        &[
            "--tier",
            "bulk",
            "--checks",
            "hashes,roundtrip,ag3",
            "--goldens",
            g,
        ],
    );
    assert_eq!(r.code, 1);
    for c in ["hashes", "roundtrip", "ag3"] {
        let failed = r.failed(c);
        assert_eq!(failed.len(), 1, "{c}: {failed:?}");
        assert_eq!(failed[0].0, "bulk:test-lcm-current/B/2222222222222222.xdr");
    }
    assert!(
        r.failed("ag3")[0].2.contains("record 0"),
        "{:?}",
        r.failed("ag3")
    );
}

#[test]
fn tool_errors_exit_2() {
    let corpus = copy_corpus("tool-errors");
    for args in [
        &["--checks", "ag4", "--goldens", "/nonexistent-golden-cache"][..],
        &["--tier", "bulk", "--checks", "extractor"],
        &["--checks", "nonsense"],
        &["--entries", "no-such-group/*"],
    ] {
        let r = verify(&corpus, args);
        assert_eq!(r.code, 2, "{args:?}: {}", r.stderr);
        assert!(r.report.is_none());
    }
    let r = verify(
        &corpus,
        &["--checks", "ag4", "--goldens", "/nonexistent-golden-cache"],
    );
    assert!(r.stderr.contains("not in the cache"), "{}", r.stderr);
    // The bulk tier needs corpus.json; without it the tool cannot run.
    std::fs::remove_file(corpus.join("corpus.json")).unwrap();
    let r = verify(&corpus, &["--tier", "bulk"]);
    assert_eq!(r.code, 2, "bulk without corpus.json: {}", r.stderr);
    let r = verify(&corpus.join("nowhere"), &[]);
    assert_eq!(r.code, 2);
}

#[test]
fn entries_glob_selects_entries() {
    let corpus = copy_corpus("glob");
    let r = verify(&corpus, &["--entries", "cap-0040/*"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    // The entries and variants under manifest/cap-0040/ (the group grows with the corpus).
    let (mut entries, mut variants) = (0, 0);
    for f in std::fs::read_dir(corpus.join("manifest/cap-0040")).unwrap() {
        let m: Value = serde_json::from_slice(&std::fs::read(f.unwrap().path()).unwrap()).unwrap();
        entries += 1;
        variants += m["variants"].as_array().map_or(0, Vec::len);
    }
    assert!(entries >= 1);
    assert_eq!(r.rows("roundtrip"), variants);
    assert_eq!(r.rows("schema"), entries);
}

/// Write `entry` at its ID's path under `manifest/`.
fn write_entry(corpus: &Path, entry: &Value) {
    let id = entry["id"].as_str().unwrap();
    let path = corpus.join(format!("manifest/{id}.json"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec_pretty(entry).unwrap()).unwrap();
}

/// The detail of the failed `check` row of `id`, or `None` when it passed.
fn failure(r: &Run, check: &str, id: &str) -> Option<String> {
    let report = r.report.as_ref().expect("report written");
    let row = report["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["entry"] == id && x["corpus"]["check"] == check)
        .unwrap_or_else(|| panic!("no {check} row for {id}: {}", r.stdout));
    (row["corpus"]["ok"] == false).then(|| row["corpus"]["detail"].as_str().unwrap().to_string())
}

/// `n` nested one-element SCV_VEC values around SCV_VOID (four stellar-xdr depth units per level).
fn nested_vectors(n: usize) -> Vec<u8> {
    let mut b = Vec::new();
    for _ in 0..n {
        b.extend_from_slice(&[0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0, 1]);
    }
    b.extend_from_slice(&[0, 0, 0, 1]);
    b
}

#[test]
fn reject_uses_the_entrys_depth_limit() {
    let corpus = copy_corpus("reject-depth");
    // 600 levels: 2,400 units, below the oracle's default and above a 2,000-unit boundary.
    let blob = add_blob(&corpus, &nested_vectors(600));
    let id = "limits/test-depth-a";
    let mut e = negative_entry(id, "depth", blob);
    write_entry(&corpus, &e);
    let args = [
        "--checks",
        "schema,reject",
        "--entries",
        "limits/test-depth-*",
    ];
    let r = verify(&corpus, &args);
    let f = failure(&r, "reject", id).expect("accepted at the default depth");
    assert!(
        f.contains("default depth limit") && f.contains("expect.reject.limits.depth"),
        "{f}"
    );

    e["expect"]["reject"]["limits"] = json!({"depth": 2000});
    write_entry(&corpus, &e);
    let r = verify(&corpus, &args);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(failure(&r, "reject", id), None);

    e["expect"]["reject"]["limits"] = json!({"depth": 3000});
    write_entry(&corpus, &e);
    let r = verify(&corpus, &args);
    let f = failure(&r, "reject", id).expect("accepted at 3,000 units");
    assert!(f.contains("entry's depth limit of 3000"), "{f}");

    // stellar-core's decoder boundary in stellar-xdr units: 499 nested vectors decode at 2,000
    // units, 500 do not.
    for (n, accepted) in [(499, true), (500, false)] {
        let mut e = negative_entry(id, "depth", add_blob(&corpus, &nested_vectors(n)));
        e["expect"]["reject"]["limits"] = json!({"depth": 2000});
        write_entry(&corpus, &e);
        let f = failure(&verify(&corpus, &args), "reject", id);
        assert_eq!(f.is_some(), accepted, "{n} levels: {f:?}");
    }

    // The schema refuses a depth of zero.
    e["expect"]["reject"]["limits"] = json!({"depth": 0});
    write_entry(&corpus, &e);
    let r = verify(&corpus, &args);
    assert!(failure(&r, "schema", id).is_some());
}

#[test]
fn record_marked_negative_entries_are_split_before_decoding() {
    let corpus = copy_corpus("reject-framed");
    let void = [0u8, 0, 0, 1];
    let stream = |mark: u32, payload: &[u8]| {
        let mut b = mark.to_be_bytes().to_vec();
        b.extend_from_slice(payload);
        b
    };
    let cases: [(&str, Vec<u8>, &str, Option<&str>); 6] = [
        // Last-fragment bit clear.
        ("bit-clear", stream(4, &void), "record_mark", None),
        // The mark declares more bytes than the stream holds.
        ("longer", stream(0x8000_0008, &void), "record_mark", None),
        // The mark declares fewer bytes than the value: the rest misreads as the next mark.
        ("shorter", stream(0x8000_0002, &void), "record_mark", None),
        // The record holds the value and four more bytes.
        (
            "trailing",
            stream(0x8000_0008, &[0, 0, 0, 1, 0, 0, 0, 0]),
            "trailing_bytes",
            None,
        ),
        // A well-formed stream is accepted, so the entry fails.
        (
            "well-formed",
            stream(0x8000_0004, &void),
            "record_mark",
            Some("accepts the record-marked stream"),
        ),
        // A framing fault declared under the wrong reason.
        (
            "wrong-reason",
            stream(4, &void),
            "nonzero_padding",
            Some("another reason"),
        ),
    ];
    for (slug, bytes, reason, _) in &cases {
        let blob = add_blob(&corpus, bytes);
        let mut e = negative_entry(&format!("xdr-strict/test-framed-{slug}"), reason, blob);
        e["variants"][0]["framing"] = json!("record-marked");
        e["variants"][0]["frame_index"] = json!(0);
        write_entry(&corpus, &e);
    }
    let r = verify(
        &corpus,
        &[
            "--checks",
            "schema,reject",
            "--entries",
            "xdr-strict/test-framed-*",
        ],
    );
    for (slug, _, _, want) in &cases {
        let id = format!("xdr-strict/test-framed-{slug}");
        assert_eq!(failure(&r, "schema", &id), None, "{id}");
        match (failure(&r, "reject", &id), want) {
            (None, None) => {}
            (Some(f), Some(w)) => assert!(f.contains(w), "{id}: {f}"),
            (got, want) => panic!("{id}: reject failure {got:?}, expected {want:?}"),
        }
    }

    // A frame that does not exist is a manifest problem; framing on a positive entry is refused.
    let blob = add_blob(&corpus, &stream(0x8000_0004, &void));
    let mut e = negative_entry("xdr-strict/test-framed-no-frame", "record_mark", blob);
    e["variants"][0]["framing"] = json!("record-marked");
    e["variants"][0]["frame_index"] = json!(3);
    write_entry(&corpus, &e);
    e["id"] = json!("xdr-strict/test-framed-positive");
    e["negative"] = json!(false);
    write_entry(&corpus, &e);
    let r = verify(
        &corpus,
        &[
            "--checks",
            "schema,reject",
            "--entries",
            "xdr-strict/test-framed-*",
        ],
    );
    let f = failure(&r, "reject", "xdr-strict/test-framed-no-frame").unwrap();
    assert!(f.contains("past the end of the stream"), "{f}");
    assert!(failure(&r, "schema", "xdr-strict/test-framed-positive").is_some());
}

/// A positive SignerKey entry for the JSON round-trip tests, rendered by `xdrcheck-corpus render`.
fn signer_key_entry(corpus: &Path, id: &str, key: &stellar_xdr::SignerKey, exception: bool) {
    use stellar_xdr::WriteXdr;
    let bytes = key.to_xdr(stellar_xdr::Limits::none()).unwrap();
    let mut e = negative_entry(id, "depth", add_blob(corpus, &bytes));
    let o = e.as_object_mut().unwrap();
    o.remove("negative");
    o.remove("flags");
    o.insert("validity".into(), json!("valid"));
    o.remove("caps_note");
    o.insert("expect".into(), json!({}));
    o.insert("caps".into(), json!([40]));
    o.insert(
        "title".into(),
        json!("A signer key for the JSON round-trip tests"),
    );
    e["variants"][0]["xdr_type"] = json!("SignerKey");
    if exception {
        e["variants"][0]["json_roundtrip"] =
            json!({"skip": true, "reason": "the strkey of an empty payload does not parse back"});
    }
    write_entry(corpus, &e);
    let out = Command::new(env!("CARGO_BIN_EXE_xdrcheck-corpus"))
        .arg("--corpus")
        .arg(corpus)
        .args(["render", id])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "render {id}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn json_roundtrip_exception_skips_only_the_json_half() {
    use stellar_xdr::{SignerKey, SignerKeyEd25519SignedPayload, Uint256};
    let corpus = copy_corpus("json-exception");
    let empty = SignerKey::Ed25519SignedPayload(SignerKeyEd25519SignedPayload {
        ed25519: Uint256([9; 32]),
        payload: Vec::new().try_into().unwrap(),
    });
    let id = "cap-0040/test-json-empty-payload";
    signer_key_entry(&corpus, id, &empty, true);
    let args = [
        "--checks",
        "schema,roundtrip,sidecar,hashes",
        "--entries",
        "cap-0040/test-json-*",
    ];
    let r = verify(&corpus, &args);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);

    // Without the declaration the JSON half fails, and the message names the field.
    edit_json(&corpus.join(format!("manifest/{id}.json")), |e| {
        e["variants"][0]
            .as_object_mut()
            .unwrap()
            .remove("json_roundtrip");
    });
    let r = verify(&corpus, &args);
    let f = failure(&r, "roundtrip", id).unwrap();
    assert!(f.contains("variants[].json_roundtrip"), "{f}");

    // A declaration on bytes whose JSON does round-trip is stale.
    let stale = "cap-0040/test-json-stale";
    signer_key_entry(&corpus, stale, &SignerKey::Ed25519(Uint256([7; 32])), true);
    let r = verify(&corpus, &args);
    let f = failure(&r, "roundtrip", stale).unwrap();
    assert!(f.contains("stale"), "{f}");
    assert_eq!(failure(&r, "sidecar", stale), None);
}

#[test]
fn requires_and_l1_must_equal_what_the_oracle_derives() {
    let corpus = copy_corpus("derived-l1");
    let args = ["--checks", "pinpoints", "--entries", CAP40_ID];
    let r = verify(&corpus, &args);
    assert_eq!(failure(&r, "pinpoints", CAP40_ID), None);
    // A feature the bytes do not use.
    edit_json(&corpus.join(CAP40), |e| {
        e["variants"][0]["requires"] = json!(["stellar_value_signed_ms"])
    });
    let f = failure(&verify(&corpus, &args), "pinpoints", CAP40_ID).unwrap();
    assert!(f.contains("expected requires = []"), "{f}");
    // A wrong, a missing and an unimplied derived.l1 key.
    edit_json(&corpus.join(CAP40), |e| {
        e["variants"][0].as_object_mut().unwrap().remove("requires");
        e["variants"][0]["derived"]["l1"] = json!({"operation_type": "payment", "offer_id": "1"});
    });
    let f = failure(&verify(&corpus, &args), "pinpoints", CAP40_ID).unwrap();
    for want in [
        "derived.l1.operation_type is \"payment\", the oracle derives \"set_options\"",
        "derived.l1.memo_type is implied by the focus and missing",
        "derived.l1.offer_id is not implied by the focus",
        "expected derived.l1 = {\"memo_type\":\"none\",\"operation_type\":\"set_options\"}",
    ] {
        assert!(f.contains(want), "{want}: {f}");
    }
}

#[test]
fn unparsable_divergence_range_fails_schema() {
    let corpus = copy_corpus("ranges");
    edit_json(&corpus.join(CAP40), |e| {
        e["conformance"]["known_divergences"][0]["versions"] = json!("^1.2.3")
    });
    let r = verify(&corpus, &["--checks", "schema", "--entries", CAP40_ID]);
    let f = failure(&r, "schema", CAP40_ID).unwrap();
    assert!(f.contains("known_divergences[0].versions"), "{f}");
}

#[test]
fn divergence_match_and_mandatory_requires() {
    let corpus = copy_corpus("match");
    let args = ["--checks", "schema", "--entries", CAP40_ID];
    let set = |m: Value| {
        edit_json(&corpus.join(CAP40), |e| {
            let d = &mut e["conformance"]["known_divergences"][0];
            d["level"] = json!("L1");
            d["outcome"] = json!("reject");
            d["match"] = m;
        })
    };
    // Twelve transactions: index 11 exists, 12 does not; the reason is a driver reason code.
    set(json!({"reason": "decode_error", "rejected_tx_index": 11, "envelopes_parsed": 11}));
    assert_eq!(failure(&verify(&corpus, &args), "schema", CAP40_ID), None);
    set(json!({"reason": "no_such_code", "rejected_tx_index": 12}));
    let f = failure(&verify(&corpus, &args), "schema", CAP40_ID).unwrap();
    assert!(f.contains("not a driver protocol reason code"), "{f}");
    assert!(f.contains("rejected_tx_index 12 is past"), "{f}");
    edit_json(&corpus.join(CAP40), |e| {
        e["conformance"]["known_divergences"][0]["match"] = json!({"rejected_tx_index": 0});
        e["conformance"]["known_divergences"][0]["outcome"] = json!("crash");
    });
    let f = failure(&verify(&corpus, &args), "schema", CAP40_ID).unwrap();
    assert!(f.contains("needs outcome reject"), "{f}");

    // `requires` is mandatory: the schema and the pinpoints check both refuse its absence.
    edit_json(&corpus.join(CAP40), |e| {
        e["conformance"]["known_divergences"][0]
            .as_object_mut()
            .unwrap()
            .remove("match");
        e["variants"][0].as_object_mut().unwrap().remove("requires");
    });
    let r = verify(
        &corpus,
        &["--checks", "schema,pinpoints", "--entries", CAP40_ID],
    );
    assert!(failure(&r, "schema", CAP40_ID).is_some());
    let f = failure(&r, "pinpoints", CAP40_ID).unwrap();
    assert!(f.contains("requires is missing"), "{f}");
}

#[test]
fn extractor_disagreement_fails_and_unverified_excuses_it() {
    let corpus = copy_corpus("extractor");
    let args = ["--checks", "extractor", "--entries", CAP40_ID];
    assert_eq!(
        failure(&verify(&corpus, &args), "extractor", CAP40_ID),
        None
    );
    // A muxed ID the bytes do not carry.
    edit_json(&corpus.join(CAP40), |e| {
        e["expect"]["participants"]["must_include"][0]["muxed_id"] = json!("7")
    });
    let f = failure(&verify(&corpus, &args), "extractor", CAP40_ID).unwrap();
    assert!(
        f.contains("muxed_id 7 is stated but the extractor derives none"),
        "{f}"
    );
    edit_json(&corpus.join(CAP40), |e| {
        e["expect"]["participants"]["must_include"][0]["unverified"] =
            json!("held by the reader from the envelope only")
    });
    assert_eq!(
        failure(&verify(&corpus, &args), "extractor", CAP40_ID),
        None
    );
}

#[test]
fn orphan_files_fail_a_whole_corpus_run() {
    let corpus = copy_corpus("orphans");
    let checks = ["--checks", "orphans"];
    let r = verify(&corpus, &checks);
    assert_eq!(r.code, 0, "{}", r.stdout);
    add_blob(&corpus, &[0, 0, 0, 1, 0, 0, 0, 1]);
    std::fs::create_dir_all(corpus.join("chains/left-over")).unwrap();
    let r = verify(&corpus, &checks);
    assert_eq!(r.code, 1);
    assert!(failure(&r, "orphans", "blobs")
        .unwrap()
        .contains("referenced by no manifest entry"));
    assert!(failure(&r, "orphans", "chains")
        .unwrap()
        .contains("chains/left-over/ holds no chain index"));
    assert_eq!(failure(&r, "orphans", "decoded"), None);
    // An entry-filtered run does not look at the whole corpus.
    let r = verify(&corpus, &["--checks", "orphans", "--entries", CAP40_ID]);
    assert_eq!(r.rows("orphans"), 0);
}

/// Key-selected pinpoints (`expect.values[].select`): the element of a change list is found by its
/// ledger key, so the pinpoint holds wherever core put the change.
#[test]
fn key_selected_pinpoints_resolve_by_ledger_key() {
    const ID: &str = "cap-0001/bump-sequence-noop-updates-seq-time";
    // The bumped account (label-derived, the same on every passphrase).
    const ACCOUNT: &str = "GCLI5BBS3Z7RSEGAK2SKKEEV7BHXQX4C5WHXG4PYZQFX7GUMYVSBD5TV";
    let path = format!("manifest/{ID}.json");
    let corpus = copy_corpus("select");
    let changes = "/v2/tx_processing/0/tx_apply_processing/v4/operations/0/changes";
    let mut rewritten = 0;
    edit_json(&corpus.join(&path), |m| {
        // Every positional change pinpoint becomes a key-selected one.
        for v in m["expect"]["values"].as_array_mut().unwrap() {
            let p = v["path"].as_str().unwrap().to_string();
            let Some(rest) = p.strip_prefix(&format!("{changes}/")) else {
                continue;
            };
            let (_, rel) = rest.split_once('/').unwrap();
            let arm = rel.split('/').next().unwrap().to_string();
            v["select"] =
                json!({"in": changes, "key": {"account": {"account_id": ACCOUNT}}, "change": arm});
            v["path"] = json!(format!("/{rel}"));
            rewritten += 1;
        }
    });
    assert!(rewritten >= 2, "the entry has change pinpoints");
    let args = ["--checks", "schema,pinpoints", "--entries", ID];
    let r = verify(&corpus, &args);
    assert_eq!(r.code, 0, "{}", r.stdout);

    // Without `change` the key matches both the state and the updated entry.
    edit_json(&corpus.join(&path), |m| {
        m["expect"]["values"][0]["select"]
            .as_object_mut()
            .unwrap()
            .remove("change");
    });
    let r = verify(&corpus, &args);
    let f = failure(&r, "pinpoints", ID).expect("an ambiguous selection fails");
    assert!(f.contains("add `change`"), "{f}");

    // A key no change has, and a key that is not a LedgerKey.
    edit_json(&corpus.join(&path), |m| {
        m["expect"]["values"][0]["select"]["key"] = json!({"account": {"account_id":
            "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"}});
        m["expect"]["values"][1]["select"]["key"] = json!({"account": {"id": ACCOUNT}});
    });
    let r = verify(&corpus, &args);
    let f = failure(&r, "pinpoints", ID).expect("wrong keys fail");
    assert!(f.contains("no element of"), "{f}");
    assert!(f.contains("is not a LedgerKey"), "{f}");

    // The schema rejects an unknown change type.
    edit_json(&corpus.join(&path), |m| {
        m["expect"]["values"][0]["select"]["change"] = json!("modified");
    });
    let r = verify(&corpus, &args);
    assert!(failure(&r, "schema", ID).is_some(), "{}", r.stdout);
}

/// `--overlay DIR` verifies the public corpus merged with `DIR/corpus`: an overlay entry whose blob
/// is only in the overlay and whose ID only the overlay's `plan-rows.json` plans passes; without the
/// plan rows its ID is unknown; an overlay blob no entry reaches is an orphan; an ID in both corpora
/// is a tool error.
#[test]
fn overlay_corpus_is_merged_with_the_public_corpus() {
    let corpus = copy_corpus("overlay");
    let overlay = corpus.parent().unwrap().join("private-overlay");
    let ov = overlay.join("corpus");
    let _ = std::fs::remove_dir_all(&overlay);
    std::fs::create_dir_all(&ov).unwrap();
    // SCV_BOOL with value 7: a fictional probe the public corpus does not hold.
    let blob = add_blob(&ov, &[0, 0, 0, 0, 0, 0, 0, 7]);
    let id = "xdr-strict/fictional-overlay-probe";
    write_entry(&ov, &negative_entry(id, "bool_range", blob));
    let plan_rows = |rows: Value| {
        std::fs::write(
            ov.join("plan-rows.json"),
            serde_json::to_vec_pretty(&json!({"rows": rows, "members": {}})).unwrap(),
        )
        .unwrap();
    };
    plan_rows(json!([{"id": id, "members": []}]));
    let ovs = overlay.to_str().unwrap().to_string();
    let with = |extra: &[&str]| {
        let mut a = vec!["--checks", "schema,ids,hashes,reject,orphans"];
        a.extend_from_slice(extra);
        verify(&corpus, &a)
    };

    let r = with(&["--overlay", &ovs]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(failure(&r, "reject", id), None);
    assert_eq!(failure(&r, "ids", id), None);
    assert_eq!(
        r.report.as_ref().unwrap()["header"]["mode"]["overlay"],
        true
    );

    // The public corpus alone does not hold the entry.
    let r = with(&[]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(
        r.rows("reject") + 1,
        with(&["--overlay", &ovs]).rows("reject")
    );

    // Without the overlay plan row the ID is not canonical.
    plan_rows(json!([]));
    let r = with(&["--overlay", &ovs]);
    assert_eq!(r.code, 1);
    assert!(failure(&r, "ids", id).is_some());
    plan_rows(json!([{"id": id, "members": []}]));

    // An overlay blob nothing reaches is an orphan.
    add_blob(&ov, &[0, 0, 0, 0, 0, 0, 0, 9]);
    let r = with(&["--overlay", &ovs]);
    assert_eq!(r.code, 1);
    let f = r.failed("orphans");
    assert!(
        f.iter().any(|(_, _, d)| d.contains("overlay:blobs/")),
        "{f:?}"
    );

    // An entry in both corpora is a tool error.
    let public = add_blob(&corpus, &[0, 0, 0, 0, 0, 0, 0, 7]);
    write_entry(&corpus, &negative_entry(id, "bool_range", public));
    let r = with(&["--overlay", &ovs]);
    assert_eq!(r.code, 2, "{}\n{}", r.stdout, r.stderr);
    assert!(r.stderr.contains("both"), "{}", r.stderr);
}
