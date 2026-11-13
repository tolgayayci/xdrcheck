//! `xdrcheck-corpus render`: sidecars are one compressed file per blob; re-rendering the vendored
//! corpus changes no bytes; drift (an edited sidecar, an old-style per-entry sidecar, a stray
//! file) is reported by `--check` and repaired by `render`; `--print` shows the JSON.

mod common;

use std::path::{Path, PathBuf};

use common::{copy_corpus, read_json, run, snapshot};
use serde_json::{json, Value};

const CAP40: &str = "cap-0040/signed-payload-signer-added";

fn manifests(corpus: &Path) -> Vec<Value> {
    snapshot(&corpus.join("manifest"))
        .into_iter()
        .map(|(_, b)| serde_json::from_slice(&b).unwrap())
        .collect()
}

fn unzstd(path: &Path) -> Vec<u8> {
    zstd::stream::decode_all(std::fs::read(path).unwrap().as_slice()).unwrap()
}

fn cap40_sidecar(corpus: &Path) -> PathBuf {
    let m = read_json(&corpus.join(format!("manifest/{CAP40}.json")));
    corpus.join(m["variants"][0]["decoded"].as_str().unwrap())
}

#[test]
fn every_variant_uses_the_shared_sidecar_of_its_blob() {
    let corpus = copy_corpus("render", "layout");
    let mut variants = 0;
    let mut files = std::collections::HashSet::new();
    for m in manifests(&corpus) {
        for v in m["variants"].as_array().into_iter().flatten() {
            // Negative entries have no sidecar.
            let Some(rel) = v["decoded"].as_str() else {
                continue;
            };
            variants += 1;
            let sha = v["blob"]["sha256"].as_str().unwrap();
            assert_eq!(rel, format!("decoded/{}/{sha}.json.zst", &sha[..2]));
            let text = unzstd(&corpus.join(rel));
            assert_eq!(
                xdrcheck_xdr::sha256_hex(&text),
                v["decoded_sha256"].as_str().unwrap()
            );
            // Compact JSON with a trailing newline.
            assert!(text.ends_with(b"\n"));
            assert_eq!(text.iter().filter(|&&b| b == b'\n').count(), 1, "{rel}");
            files.insert(rel.to_string());
        }
    }
    // Some vendored entries share a ledger blob, and share its sidecar.
    assert!(
        files.len() < variants,
        "{} files for {variants} variants",
        files.len()
    );
    assert_eq!(snapshot(&corpus.join("decoded")).len(), files.len());
}

#[test]
fn rerendering_the_vendored_corpus_changes_no_bytes() {
    let corpus = copy_corpus("render", "stable");
    let before = snapshot(&corpus);
    let r = run(&corpus, &["render", "--all", "--check"]);
    assert_eq!(r.code, 0, "{}{}", r.stdout, r.stderr);
    assert!(!r.stdout.contains("DRIFT"), "{}", r.stdout);
    let r = run(&corpus, &["render", "--all"]);
    assert_eq!(r.code, 0, "{}{}", r.stdout, r.stderr);
    assert!(!r.stdout.contains("rendered "), "{}", r.stdout);
    assert!(!r.stdout.contains("removed "), "{}", r.stdout);
    assert_eq!(snapshot(&corpus), before, "render --all changed bytes");
}

#[test]
fn edited_sidecar_is_reported_and_restored() {
    let corpus = copy_corpus("render", "edited");
    let path = cap40_sidecar(&corpus);
    let original = std::fs::read(&path).unwrap();
    let mut v: Value = serde_json::from_slice(&unzstd(&path)).unwrap();
    v["v2"]["ledger_header"]["header"]["ledger_seq"] = json!(1);
    let edited = zstd::stream::encode_all(serde_json::to_vec(&v).unwrap().as_slice(), 3).unwrap();
    std::fs::write(&path, &edited).unwrap();

    let r = run(&corpus, &["verify", "--checks", "sidecar"]);
    assert_eq!(r.code, 1, "{}{}", r.stdout, r.stderr);
    let r = run(&corpus, &["render", CAP40, "--check"]);
    assert_eq!(r.code, 1, "{}{}", r.stdout, r.stderr);
    assert!(r.stdout.contains("DRIFT decoded/"), "{}", r.stdout);
    assert_eq!(std::fs::read(&path).unwrap(), edited, "--check wrote");

    let r = run(&corpus, &["render", CAP40]);
    assert_eq!(r.code, 0, "{}{}", r.stdout, r.stderr);
    // Same zstd build, same settings: the very same bytes come back.
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let r = run(&corpus, &["verify"]);
    assert_eq!(r.code, 0, "{}{}", r.stdout, r.stderr);
}

#[test]
fn old_per_entry_sidecars_are_migrated_and_removed() {
    let corpus = copy_corpus("render", "migrate");
    let manifest = corpus.join(format!("manifest/{CAP40}.json"));
    let manifest_before = std::fs::read(&manifest).unwrap();
    let new_path = cap40_sidecar(&corpus);
    let new_before = std::fs::read(&new_path).unwrap();
    // Put the variant back into the previous form: a pretty per-entry JSON file.
    let value: Value = serde_json::from_slice(&unzstd(&new_path)).unwrap();
    let old_rel = "decoded/cap-0040/signed-payload-signer-added.testnet.json";
    let old_text = serde_json::to_string_pretty(&value).unwrap() + "\n";
    std::fs::create_dir_all(corpus.join("decoded/cap-0040")).unwrap();
    std::fs::write(corpus.join(old_rel), &old_text).unwrap();
    std::fs::remove_file(&new_path).unwrap();
    let mut m = read_json(&manifest);
    m["variants"][0]["decoded"] = json!(old_rel);
    m["variants"][0]["decoded_sha256"] = json!(xdrcheck_xdr::sha256_hex(old_text.as_bytes()));
    std::fs::write(&manifest, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    // A stray file nobody references.
    std::fs::write(corpus.join("decoded/stray.json"), b"{}\n").unwrap();

    let r = run(&corpus, &["render", "--all", "--check"]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    for want in [
        "DRIFT decoded/",
        "DRIFT manifest/cap-0040",
        "DRIFT decoded/stray.json",
    ] {
        assert!(r.stdout.contains(want), "{want}: {}", r.stdout);
    }

    let r = run(&corpus, &["render", "--all"]);
    assert_eq!(r.code, 0, "{}{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains(&format!("removed {old_rel}")),
        "{}",
        r.stdout
    );
    assert!(!corpus.join(old_rel).exists());
    assert!(!corpus.join("decoded/stray.json").exists());
    assert!(
        !corpus.join("decoded/cap-0040").exists(),
        "empty directory left behind"
    );
    assert_eq!(std::fs::read(&new_path).unwrap(), new_before);
    assert_eq!(std::fs::read(&manifest).unwrap(), manifest_before);
    let r = run(&corpus, &["render", "--all", "--check"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
}

#[test]
fn missing_sidecar_and_fields_are_recreated_in_place() {
    let corpus = copy_corpus("render", "missing");
    let manifest = corpus.join(format!("manifest/{CAP40}.json"));
    let manifest_before = std::fs::read(&manifest).unwrap();
    let path = cap40_sidecar(&corpus);
    let sidecar_before = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let mut m = read_json(&manifest);
    let v = m["variants"][0].as_object_mut().unwrap();
    for f in ["decoded", "decoded_sha256", "decoded_by"] {
        v.shift_remove(f);
    }
    std::fs::write(&manifest, serde_json::to_vec_pretty(&m).unwrap()).unwrap();

    let r = run(&corpus, &["render", CAP40]);
    assert_eq!(r.code, 0, "{}{}", r.stdout, r.stderr);
    assert_eq!(std::fs::read(&path).unwrap(), sidecar_before);
    assert_eq!(std::fs::read(&manifest).unwrap(), manifest_before);
}

#[test]
fn print_shows_the_decoded_json() {
    let corpus = copy_corpus("render", "print");
    let text = unzstd(&cap40_sidecar(&corpus));
    let r = run(&corpus, &["render", "--print", CAP40]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout.as_bytes(), text.as_slice());
    let r = run(
        &corpus,
        &[
            "render",
            "--print",
            CAP40,
            "--variant",
            "testnet",
            "--pretty",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.starts_with("{\n  \"v2\": {"),
        "{}",
        &r.stdout[..40]
    );
    let a: Value = serde_json::from_str(&r.stdout).unwrap();
    let b: Value = serde_json::from_slice(&text).unwrap();
    assert_eq!(a, b);
    let r = run(
        &corpus,
        &["render", "--print", CAP40, "--variant", "pubnet"],
    );
    assert_eq!(r.code, 2, "{}", r.stderr);
}

#[test]
fn unknown_entry_is_a_tool_error() {
    let corpus = copy_corpus("render", "unknown");
    let r = run(&corpus, &["render", "cap-0040/no-such-entry"]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    let r = run(&corpus, &["render"]);
    assert_eq!(r.code, 2, "{}", r.stderr);
}

#[test]
fn a_blob_that_does_not_round_trip_fails_the_entry() {
    let corpus = copy_corpus("render", "bad-blob");
    let m = read_json(&corpus.join(format!("manifest/{CAP40}.json")));
    let blob = corpus.join(m["variants"][0]["blob"]["path"].as_str().unwrap());
    let mut bytes = std::fs::read(&blob).unwrap();
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    std::fs::write(&blob, bytes).unwrap();
    let before = snapshot(&corpus.join("decoded"));
    let r = run(&corpus, &["render", "--all"]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(r.stdout.contains(&format!("FAIL {CAP40}")), "{}", r.stdout);
    assert!(r.stdout.contains("trailing bytes"), "{}", r.stdout);
    // The failing entry's sidecar is still referenced, so nothing was removed.
    assert_eq!(snapshot(&corpus.join("decoded")), before);
}
