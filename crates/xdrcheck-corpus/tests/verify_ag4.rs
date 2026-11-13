//! `verify --checks ag4`: the golden mirror computed on the corpus's own bytes.
//!
//! The hermetic tests use a small golden set: a golden cache whose files are record-marked copies
//! of corpus ledgers (one is a local-core variant's own ledger, so it is that variant's golden
//! counterpart; another is a ledger of a different shape), listed in a test `file_index`. They
//! check that `--write-mirrors` finds the counterpart and lists the rest, that the check then
//! passes, that a wrong or stale `mirrors.json` fails, that zero AG-4 rows fail the floor, and
//! that a missing cache is a tool error. The last test runs the check on the repository corpus
//! against the full golden cache when `make fetch` has filled it.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The local-core entry and variant whose ledger serves as its own golden counterpart.
const ENTRY: &str = "cap-0054/contract-code-entry-with-cost-inputs";
const VARIANT: (&str, u64) = ("testnet", 30);
/// An entry whose ledger has a different shape (the second golden file).
const OTHER: &str = "classic/set-options-thresholds-and-master-weight";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let t = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &t);
        } else {
            std::fs::copy(e.path(), t).unwrap();
        }
    }
}

fn read_json(p: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn write_json(p: &Path, v: &Value) {
    std::fs::write(p, serde_json::to_string_pretty(v).unwrap() + "\n").unwrap();
}

/// The blob of an entry's first variant matching `pick`.
fn blob(corpus: &Path, entry: &str, pick: impl Fn(&Value) -> bool) -> Vec<u8> {
    let m = read_json(&corpus.join(format!("manifest/{entry}.json")));
    let v = m["variants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| pick(v))
        .unwrap()
        .clone();
    std::fs::read(corpus.join(v["blob"]["path"].as_str().unwrap())).unwrap()
}

fn record_marked(payload: &[u8]) -> Vec<u8> {
    let mut out = ((payload.len() as u32) | 0x8000_0000)
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(payload);
    out
}

/// A corpus copy whose golden set is two files in a private cache; returns (corpus, cache).
fn fixture(name: &str) -> (PathBuf, PathBuf) {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("ag4")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    let corpus = dir.join("corpus");
    copy_dir(&repo().join("corpus"), &corpus);
    std::fs::copy(repo().join("pins.toml"), dir.join("pins.toml")).unwrap();
    let _ = std::fs::remove_file(corpus.join("mirrors.json"));

    let cache = dir.join("goldens");
    let golden_dir = cache.join("v30.0.0/test-lcm-current/TestSet");
    std::fs::create_dir_all(&golden_dir).unwrap();
    let files = [
        (
            "a.xdr",
            blob(&corpus, ENTRY, |v| {
                v["network"] == VARIANT.0 && v["protocol"] == VARIANT.1
            }),
        ),
        (
            "b.xdr",
            blob(&corpus, OTHER, |v| v["source"]["kind"] == "local-core"),
        ),
    ];
    let mut index = String::new();
    // The other shape first, so the search must go past a non-matching file.
    for (name, bytes) in files.iter().rev() {
        let data = record_marked(bytes);
        std::fs::write(golden_dir.join(name), &data).unwrap();
        index.push_str(&format!(
            "{}  test-lcm-current/TestSet/{name}\n",
            hex::encode(Sha256::digest(&data))
        ));
    }
    std::fs::create_dir_all(corpus.join("bulk")).unwrap();
    std::fs::write(corpus.join("bulk/ag4-test.sha256"), index).unwrap();
    let mut cj = read_json(&corpus.join("corpus.json"));
    cj["tiers"]["bulk"]["file_index"] = json!("bulk/ag4-test.sha256");
    cj["tiers"]["bulk"]["ref"] = json!("v30.0.0");
    cj["tiers"]["bulk"]["path"] = json!("test-lcm-current");
    write_json(&corpus.join("corpus.json"), &cj);
    (corpus, cache)
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn ag4(corpus: &Path, goldens: &Path, extra: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_xdrcheck-corpus"))
        .arg("--corpus")
        .arg(corpus)
        .args(["verify", "--checks", "ag4", "--goldens"])
        .arg(goldens)
        .args(extra)
        .output()
        .unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The local-core variant keys of an entry.
fn local_keys(corpus: &Path, entry: &str) -> Vec<String> {
    let m = read_json(&corpus.join(format!("manifest/{entry}.json")));
    let vs = m["variants"].as_array().unwrap();
    let several = vs
        .iter()
        .map(|v| v["protocol"].to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        > 1;
    vs.iter()
        .filter(|v| v["source"]["kind"] == "local-core")
        .map(|v| {
            let net = v["network"].as_str().unwrap();
            if several {
                format!("{net}@{}", v["protocol"])
            } else {
                net.to_string()
            }
        })
        .collect()
}

#[test]
fn write_mirrors_maps_the_counterpart_and_the_check_passes() {
    let (corpus, cache) = fixture("pass");
    let r = ag4(&corpus, &cache, &["--write-mirrors"]);
    assert_eq!(r.code, 0, "{}{}", r.stdout, r.stderr);
    let m = read_json(&corpus.join("mirrors.json"));
    let mapped = m["mapped"].as_array().unwrap();
    let ours = mapped
        .iter()
        .find(|e| e["entry"] == ENTRY)
        .expect("the entry is mapped");
    let key = format!("{}@{}", VARIANT.0, VARIANT.1);
    assert_eq!(
        ours["variants"][&key]["file"],
        "test-lcm-current/TestSet/a.xdr"
    );
    assert_eq!(ours["variants"][&key]["frame_index"], 0);
    // Every local-core entry is listed exactly once.
    let locals: usize = std::fs::read_dir(corpus.join("manifest"))
        .unwrap()
        .flat_map(|g| std::fs::read_dir(g.unwrap().path()).unwrap())
        .filter(|f| {
            let m = read_json(&f.as_ref().unwrap().path());
            m["variants"]
                .as_array()
                .is_some_and(|vs| vs.iter().any(|v| v["source"]["kind"] == "local-core"))
        })
        .count();
    assert_eq!(
        mapped.len() + m["unmapped"].as_array().unwrap().len(),
        locals
    );
    assert!(m["unmapped"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["reason"] == "no golden covers this shape"));

    let r = ag4(&corpus, &cache, &[]);
    assert_eq!(r.code, 0, "{}{}", r.stdout, r.stderr);
    // One row per mapped variant and per variant of the operation tier, plus the list and the
    // floor rows.
    let variants = |list: &str| {
        m[list]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["variants"].as_object().unwrap().len())
            .sum::<usize>()
    };
    let rows: usize = variants("mapped") + variants("operations") + 2;
    assert!(
        r.stdout
            .contains(&format!("  {:<10} {:>5} pass {:>5} fail", "ag4", rows, 0)),
        "{}",
        r.stdout
    );
}

#[test]
fn a_counterpart_of_another_shape_fails() {
    let (corpus, cache) = fixture("wrong-golden");
    assert_eq!(ag4(&corpus, &cache, &["--write-mirrors"]).code, 0);
    let p = corpus.join("mirrors.json");
    let mut m = read_json(&p);
    for e in m["mapped"].as_array_mut().unwrap() {
        if e["entry"] == ENTRY {
            for (_, g) in e["variants"].as_object_mut().unwrap() {
                g["file"] = json!("test-lcm-current/TestSet/b.xdr");
            }
        }
    }
    write_json(&p, &m);
    let r = ag4(&corpus, &cache, &[]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(
        r.stdout
            .contains("differs from golden test-lcm-current/TestSet/b.xdr"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("FAIL ag4 floor:ag4"), "{}", r.stdout);
}

#[test]
fn a_stale_list_and_zero_rows_fail() {
    let (corpus, cache) = fixture("stale");
    assert_eq!(ag4(&corpus, &cache, &["--write-mirrors"]).code, 0);
    let p = corpus.join("mirrors.json");
    let mut m = read_json(&p);
    // Forget every mapped entry: the list is stale and no AG-4 variant row is left.
    m["mapped"] = json!([]);
    write_json(&p, &m);
    let r = ag4(&corpus, &cache, &[]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    // The variants the list forgot are found again ...
    for k in local_keys(&corpus, ENTRY) {
        if k == format!("{}@{}", VARIANT.0, VARIANT.1) {
            assert!(
                r.stdout.contains(&format!(
                    "FAIL ag4 {ENTRY} [{k}]: the profile-free skeleton equals golden"
                )),
                "{}",
                r.stdout
            );
        }
    }
    // ... the entry is missing from the list, and no AG-4 variant row is left.
    assert!(
        r.stdout
            .contains(&format!("local-core entry {ENTRY} is not listed")),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout
            .contains("no AG-4 row: no local-core variant is compared"),
        "{}",
        r.stdout
    );
}

#[test]
fn a_missing_golden_cache_exits_2() {
    let (corpus, _) = fixture("no-cache");
    let r = ag4(&corpus, &corpus.join("no-such-cache"), &[]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(r.stderr.contains("not in the cache"), "{}", r.stderr);
    assert!(r.stderr.contains("fetch-goldens v30.0.0"), "{}", r.stderr);
}

/// The repository corpus against the full golden cache (filled by `make fetch`); skipped with a
/// banner when the cache is absent.
#[test]
fn the_repository_corpus_passes_against_the_golden_set() {
    let cache = std::env::var_os("XDRCHECK_GOLDENS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cache/xdrcheck/goldens")
        });
    if !cache.join("v30.0.0").is_dir() {
        eprintln!(
            "SKIPPED: no golden cache at {} (make fetch)",
            cache.display()
        );
        return;
    }
    let r = ag4(&repo().join("corpus"), &cache, &[]);
    assert_eq!(r.code, 0, "{}{}", r.stdout, r.stderr);
    let m = read_json(&repo().join("corpus/mirrors.json"));
    assert!(!m["mapped"].as_array().unwrap().is_empty());
}
