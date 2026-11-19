//! Tests against the repository's own corpus (counts derived from its index.json), and against small corpora
//! and archives built from it in the target directory.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use xdrcheck::{Corpus, ExpectedFailures, Results};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn index() -> Value {
    serde_json::from_slice(&std::fs::read(corpus_dir().join("index.json")).unwrap()).unwrap()
}

fn index_rows() -> Vec<Value> {
    index()["entries"].as_array().unwrap().clone()
}

/// A fresh directory under the target directory.
fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

#[test]
fn opens_the_repository_corpus() {
    let c = Corpus::open(corpus_dir()).unwrap();
    let rows = index_rows();
    assert_eq!(c.entries().len(), rows.len());
    for (e, r) in c.entries().iter().zip(&rows) {
        assert_eq!(e.id, r["id"].as_str().unwrap());
        assert_eq!(e.variants.len(), r["variants"].as_array().unwrap().len());
        assert_eq!(e.manifest()["id"], r["id"]);
    }
    let cj: Value =
        serde_json::from_slice(&std::fs::read(corpus_dir().join("corpus.json")).unwrap()).unwrap();
    assert_eq!(c.version(), cj["corpus_version"].as_str().unwrap());
    let first = rows[0]["id"].as_str().unwrap();
    assert_eq!(c.entry(first).unwrap().id, first);
    assert!(c.entry("no-such/entry").is_none());
}

#[test]
fn every_blob_and_sidecar_of_every_non_stress_entry_verifies() {
    let c = Corpus::open(corpus_dir()).unwrap();
    let want: usize = index_rows()
        .iter()
        .filter(|r| r["tier"] != "stress")
        .map(|r| r["variants"].as_array().unwrap().len())
        .sum();
    let mut blobs = 0;
    let mut sidecars = 0;
    for e in c.entries().iter().filter(|e| e.tier != "stress") {
        for v in &e.variants {
            let b = v.blob().unwrap_or_else(|err| panic!("{err}"));
            assert_eq!(b.len() as u64, v.bytes);
            blobs += 1;
            if v.expected_json()
                .unwrap_or_else(|err| panic!("{err}"))
                .is_some()
            {
                sidecars += 1;
            }
            assert_eq!(v.decoded_path.is_some(), v.decoded_sha256.is_some());
        }
    }
    assert_eq!(blobs, want);
    assert!(sidecars > 0);
}

#[test]
fn expected_json_of_a_ledger_entry_parses_and_its_focus_resolves() {
    let c = Corpus::open(corpus_dir()).unwrap();
    let e = c.entry("cap-0001/account-merge-seqnum-too-far").unwrap();
    assert_eq!(e.kind, "ledger");
    for v in &e.variants {
        assert_eq!(v.xdr_type, "LedgerCloseMeta");
        assert!(v.decodable() && !v.must_refuse());
        let j = v.expected_json().unwrap().unwrap();
        let raw = v.expected_json_bytes().unwrap().unwrap();
        assert_eq!(sha256_hex(&raw), v.decoded_sha256.clone().unwrap());
        assert_eq!(
            j["v2"]["ledger_header"]["header"]["ledger_version"],
            json!(v.protocol)
        );
        let mv = e.manifest()["variants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["network"] == json!(v.network) && m["protocol"] == json!(v.protocol))
            .unwrap();
        let path = mv["focus"]["path"].as_str().unwrap();
        assert!(j.pointer(path).is_some(), "{path}");
    }
}

#[test]
fn variant_key_rule() {
    let c = Corpus::open(corpus_dir()).unwrap();
    let mut multi = 0;
    let mut single = 0;
    for e in c.entries() {
        let protocols: BTreeSet<u32> = e.variants.iter().map(|v| v.protocol).collect();
        for v in &e.variants {
            if protocols.len() > 1 {
                assert_eq!(v.key, format!("{}@{}", v.network, v.protocol));
                multi += 1;
            } else {
                assert_eq!(v.key, v.network);
                single += 1;
            }
            assert!(
                std::ptr::eq(e.variant(&v.key).unwrap(), v),
                "key {} not unique",
                v.key
            );
        }
    }
    assert!(multi > 0 && single > 0);
}

#[test]
fn negative_entries_and_helpers() {
    let c = Corpus::open(corpus_dir()).unwrap();
    for e in c.entries() {
        for v in &e.variants {
            assert_eq!(
                v.must_refuse(),
                v.validity == "malformed" || v.validity == "invalid"
            );
            if v.must_refuse() {
                assert!(v.decoded_path.is_none(), "{} {}", e.id, v.key);
            }
            assert_eq!(
                v.decodable(),
                (e.kind == "ledger" || e.kind == "xdr") && v.framing == "none"
            );
        }
        let reason = e
            .manifest()
            .pointer("/expect/reject/reason")
            .and_then(Value::as_str);
        assert_eq!(e.expect_reject_reason(), reason);
        if e.validity == "malformed" && (e.kind == "xdr") {
            assert!(e.expect_reject_reason().is_some(), "{}", e.id);
        }
    }
}

/// A corpus directory holding only the named entries' files, under `dir`.
fn copy_entries(dir: &Path, ids: &[&str], with_sums: bool) -> Vec<Value> {
    let src = corpus_dir();
    let rows: Vec<Value> = index_rows()
        .into_iter()
        .filter(|r| ids.contains(&r["id"].as_str().unwrap()))
        .collect();
    assert_eq!(rows.len(), ids.len());
    let copy = |rel: &str| {
        let to = dir.join(rel);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(src.join(rel), to).unwrap();
    };
    copy("corpus.json");
    let mut sums = String::new();
    for r in &rows {
        let m = r["manifest"].as_str().unwrap();
        copy(m);
        sums.push_str(&format!(
            "{}  {m}\n",
            sha256_hex(&std::fs::read(src.join(m)).unwrap())
        ));
        for v in r["variants"].as_array().unwrap() {
            copy(v["blob"].as_str().unwrap());
            if let Some(d) = v["decoded"].as_str() {
                copy(d);
            }
        }
    }
    if with_sums {
        std::fs::write(dir.join("manifest.sha256"), sums).unwrap();
    }
    let idx = json!({"schema": "xcc.index/v1", "entries": rows});
    std::fs::write(dir.join("index.json"), serde_json::to_vec(&idx).unwrap()).unwrap();
    rows
}

const LEDGER: &str = "cap-0001/account-merge-seqnum-too-far";

#[test]
fn a_tampered_blob_sidecar_or_manifest_is_refused() {
    let dir = scratch("tampered");
    let rows = copy_entries(&dir, &[LEDGER], true);
    let c = Corpus::open(&dir).unwrap();
    let v = &c.entry(LEDGER).unwrap().variants[0];
    v.blob().unwrap();
    v.expected_json().unwrap().unwrap();

    // One flipped byte in the blob.
    let blob = dir.join(rows[0]["variants"][0]["blob"].as_str().unwrap());
    let mut b = std::fs::read(&blob).unwrap();
    b[10] ^= 1;
    std::fs::write(&blob, &b).unwrap();
    let err = v.blob().unwrap_err().to_string();
    assert!(err.contains("but the index says"), "{err}");
    // A truncated blob.
    b[10] ^= 1;
    std::fs::write(&blob, &b[..b.len() - 4]).unwrap();
    assert!(v.blob().is_err());

    // A sidecar that is valid zstd of other JSON.
    let side = dir.join(rows[0]["variants"][0]["decoded"].as_str().unwrap());
    std::fs::write(&side, zstd::encode_all(&b"{\"v2\":{}}\n"[..], 3).unwrap()).unwrap();
    let err = v.expected_json().unwrap_err().to_string();
    assert!(err.contains("uncompressed sha256"), "{err}");
    // A sidecar that is not zstd.
    std::fs::write(&side, b"{}").unwrap();
    assert!(v
        .expected_json()
        .unwrap_err()
        .to_string()
        .contains("not zstd"));

    // A manifest that differs from manifest.sha256.
    let m = dir.join(rows[0]["manifest"].as_str().unwrap());
    let mut mb = std::fs::read(&m).unwrap();
    mb.push(b'\n');
    std::fs::write(&m, mb).unwrap();
    let err = Corpus::open(&dir).unwrap_err().to_string();
    assert!(err.contains("manifest.sha256"), "{err}");
}

/// A ustar header for a regular file (prefix/name split for long paths).
fn tar_header(path: &str, size: usize) -> [u8; 512] {
    let mut h = [0u8; 512];
    let (prefix, name) = if path.len() <= 100 {
        ("", path)
    } else {
        let cut = path[..=155.min(path.len() - 1)].rfind('/').unwrap();
        (&path[..cut], &path[cut + 1..])
    };
    assert!(name.len() <= 100 && prefix.len() <= 155);
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0");
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

fn tar_gz(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut tar = Vec::new();
    for (p, b) in files {
        tar.extend_from_slice(&tar_header(p, b.len()));
        tar.extend_from_slice(b);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.resize(tar.len() + 1024, 0);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

/// Every file under `dir`, keyed `<prefix>/<relative path>`.
fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let key = format!("{prefix}/{}", p.file_name().unwrap().to_str().unwrap());
        if p.is_dir() {
            walk(&p, &key, out);
        } else {
            out.insert(key, std::fs::read(&p).unwrap());
        }
    }
}

#[test]
fn opens_a_release_archive_and_an_extracted_release() {
    let stress_id = index_rows()
        .iter()
        .find(|r| {
            r["tier"] == "stress"
                && r["variants"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v["decoded"].is_string())
        })
        .map(|r| r["id"].as_str().unwrap().to_string())
        .expect("a stress entry with a sidecar");
    let work = scratch("release");
    let top = "xdrcheck-30.0.0";
    let rel = work.join(top);
    // corpus/ holds the index (both rows) and the curated entry's files; stress/ the stress entry's.
    let stress_dir = rel.join("stress");
    std::fs::create_dir_all(&stress_dir).unwrap();
    let srows = copy_entries(&stress_dir, &[&stress_id], true);
    std::fs::remove_file(stress_dir.join("index.json")).unwrap();
    let corpus = rel.join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();
    let mut crows = copy_entries(&corpus, &[LEDGER], true);
    crows.extend(srows);
    let idx = json!({"schema": "xcc.index/v1", "entries": crows});
    std::fs::write(corpus.join("index.json"), serde_json::to_vec(&idx).unwrap()).unwrap();
    std::fs::write(
        rel.join("PROVENANCE.json"),
        br#"{"schema":"xcc.release/v1","version":"30.0.0"}"#,
    )
    .unwrap();

    let check = |c: &Corpus| {
        assert_eq!(c.version(), "30.0.0");
        assert_eq!(c.entries().len(), 2);
        for e in c.entries() {
            for v in &e.variants {
                v.blob().unwrap_or_else(|err| panic!("{err}"));
                assert!(v.expected_json().unwrap().is_some());
            }
        }
        assert_eq!(c.entry(&stress_id).unwrap().tier, "stress");
    };

    // Layout 2: the extracted release.
    check(&Corpus::open(&rel).unwrap());

    // Layout 1: the archive, with and without its sha256.
    let mut files = BTreeMap::new();
    walk(&rel, top, &mut files);
    let gz = tar_gz(&files);
    let archive = work.join(format!("{top}.tar.gz"));
    std::fs::write(&archive, &gz).unwrap();
    let c = Corpus::open(&archive).unwrap();
    check(&c);
    assert!(c.source().contains(&sha256_hex(&gz)));
    check(&Corpus::open_verified(&archive, Some(&sha256_hex(&gz))).unwrap());
    let err = Corpus::open_verified(&archive, Some(&"0".repeat(64)))
        .unwrap_err()
        .to_string();
    assert!(err.contains("was expected"), "{err}");

    // A stress entry is read from stress/, not corpus/: an archive without the stress blob fails there.
    let sblob = format!(
        "{top}/stress/{}",
        crows[1]["variants"][0]["blob"].as_str().unwrap()
    );
    let mut cut = files.clone();
    cut.remove(&sblob).unwrap();
    let a2 = work.join("cut.tar.gz");
    std::fs::write(&a2, tar_gz(&cut)).unwrap();
    let c2 = Corpus::open(&a2).unwrap();
    let err = c2.entry(&stress_id).unwrap().variants[0]
        .blob()
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("/stress/blobs/") && err.contains("no such file"),
        "{err}"
    );

    // A tampered manifest in the archive is refused by its root's manifest.sha256.
    let mpath = format!("{top}/corpus/{}", crows[0]["manifest"].as_str().unwrap());
    let mut bad = files.clone();
    bad.get_mut(&mpath).unwrap().push(b' ');
    let a3 = work.join("bad.tar.gz");
    std::fs::write(&a3, tar_gz(&bad)).unwrap();
    assert!(Corpus::open(&a3)
        .unwrap_err()
        .to_string()
        .contains("manifest.sha256"));
}

/// A release archive built by `make release`, when the environment names one.
#[test]
fn opens_a_real_release_archive_when_given() {
    let Ok(path) = std::env::var("XDRCHECK_TEST_ARCHIVE") else {
        return;
    };
    let c = Corpus::open(&path).unwrap();
    for e in c.entries().iter().filter(|e| e.tier != "stress") {
        for v in &e.variants {
            v.blob().unwrap_or_else(|err| panic!("{err}"));
            v.expected_json().unwrap_or_else(|err| panic!("{err}"));
        }
    }
}

#[test]
fn expected_failure_list_parse() {
    let text = "# header\n\na/b testnet L0  # comment\nc/d - unread\n   \n";
    let l = ExpectedFailures::parse(text, "list.txt").unwrap();
    assert_eq!(l.items.len(), 2);
    assert_eq!(l.items[0].line, 3);
    assert_eq!(l.items[1].to_string(), "c/d - unread");
    let err = ExpectedFailures::parse("a/b testnet\n", "list.txt").unwrap_err();
    assert!(err.to_string().starts_with("list.txt:1: want"), "{err}");
    let err = ExpectedFailures::parse("a b L0\n#x\na b L0 # again\n", "list.txt").unwrap_err();
    assert_eq!(
        err.to_string(),
        "list.txt:3: a b L0 is already listed on line 1"
    );
}

#[test]
fn expected_failure_compare_all_outcomes() {
    let list = ExpectedFailures::parse(
        "\
e/still-fails testnet L0
e/fixed testnet L0
e/now-read none unread
e/still-unread none unread
e/selected testnet L0
e/not-selected testnet L0
",
        "ef.txt",
    )
    .unwrap();
    let mut r = Results::new();
    r.fail("e/still-fails", "testnet", "L0", "refused");
    r.fail("e/new", "pubnet", "L0", "accepted invalid input");
    r.pass("e/fixed", "testnet", "L0");
    r.pass("e/now-read", "none", "L0");
    r.unread("e/still-unread", "none", "type_not_generated");
    r.unread("e/new-unread", "none", "type_not_generated");
    r.select("e/selected");

    let c = r.compare(&list, true);
    assert!(!c.passed());
    let text = c.to_text();
    let want = "\
NEW-FAILURE   e/new pubnet L0: accepted invalid input
UNEXPECTED-PASS e/fixed testnet L0: listed as failing but now conforms; remove the line from ef.txt
UNEXPECTED-PASS e/now-read none unread: listed as unread but the column now reads it; remove the line from ef.txt
NEW-UNREAD    e/new-unread none: never read (type_not_generated)
NOT-RUN       e/selected testnet L0 (ef.txt line 5): the run has no such cell; remove the line or fix its spelling
expected failures ef.txt: 2 still as listed, 1 new failures, 1 new unread, 2 unexpected passes, 1 listed but not run
";
    assert_eq!(text, want);

    // Without require_all_read an unlisted unread variant is not a difference.
    let c = r.compare(&list, false);
    assert!(c.new_unread.is_empty());
    assert_eq!(c.new_failures.len(), 1);

    // A list written from the run compares clean with it.
    let written = ExpectedFailures::write(&r, "an SDK against corpus 30.0.0");
    let l2 = ExpectedFailures::parse(&written, "w.txt").unwrap();
    let c = r.compare(&l2, true);
    assert!(c.passed(), "{}", c.to_text());
    assert_eq!(c.matched, 4);
    assert_eq!(
        c.to_text(),
        "expected failures w.txt: 4 still as listed, 0 new failures, 0 new unread, 0 unexpected passes, 0 listed but not run\n"
    );
    let body: Vec<&str> = written.lines().filter(|l| !l.starts_with('#')).collect();
    assert_eq!(
        body,
        [
            "e/new pubnet L0  # accepted invalid input",
            "e/new-unread none unread  # never read: type_not_generated",
            "e/still-fails testnet L0  # refused",
            "e/still-unread none unread  # never read: type_not_generated",
        ]
    );
}
