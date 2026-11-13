//! `xdrcheck-corpus mainnet build|fetch|check` on a fixture of four real pubnet transactions
//! (`tests/data/mainnet/`: their lake objects, a four-row cover and the occurrences of their tokens), one per
//! `LedgerCloseMeta` arm and two of arm 0. The fixture tier holds the tokens of these four transactions only.
mod common;

use std::path::{Path, PathBuf};

use common::{copy_dir, repo, run};
use serde_json::Value;

fn data() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/mainnet")
}

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("mainnet")
        .join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// A copy of the fixture tier and a cache filled from the fixture objects.
fn setup(name: &str) -> (PathBuf, PathBuf) {
    let d = scratch(name);
    let tier = d.join("tier");
    copy_dir(&data().join("tier"), &tier);
    let cache = d.join("cache");
    let o = run(
        &repo().join("corpus"),
        &[
            "mainnet",
            "fetch",
            "--tier",
            s(&tier),
            "--cache",
            s(&cache),
            "--from",
            s(&data().join("objects")),
        ],
    );
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    (tier, cache)
}

fn check(tier: &Path, cache: &Path) -> common::Out {
    run(
        &repo().join("corpus"),
        &["mainnet", "check", "--tier", s(tier), "--cache", s(cache)],
    )
}

/// Rewrite one line of the tier with `f` and record the new sha256 in the header, so only the change is tested.
fn tamper(tier: &Path, line: usize, f: impl Fn(&mut Value)) {
    let p = tier.join("tier.jsonl");
    let text = std::fs::read_to_string(&p).unwrap();
    let mut out = String::new();
    for (n, l) in text.lines().enumerate() {
        if n == line {
            let mut v: Value = serde_json::from_str(l).unwrap();
            f(&mut v);
            out.push_str(&serde_json::to_string(&v).unwrap());
        } else {
            out.push_str(l);
        }
        out.push('\n');
    }
    std::fs::write(&p, &out).unwrap();
    let hp = tier.join("tier.json");
    let mut h: Value = serde_json::from_slice(&std::fs::read(&hp).unwrap()).unwrap();
    h["lines"]["sha256"] = Value::from(xdrcheck_xdr::sha256_hex(out.as_bytes()));
    std::fs::write(&hp, serde_json::to_vec_pretty(&h).unwrap()).unwrap();
}

#[test]
fn build_reproduces_the_fixture_tier() {
    let d = scratch("build");
    let o = run(
        &repo().join("corpus"),
        &[
            "mainnet",
            "build",
            "--tier",
            s(&d),
            "--cover",
            s(&data().join("cover.tsv")),
            "--token-table",
            s(&data().join("token-occurrences.tsv")),
            "--objects",
            s(&data().join("objects")),
        ],
    );
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    for f in ["tier.json", "tier.jsonl"] {
        assert_eq!(
            std::fs::read(d.join(f)).unwrap(),
            std::fs::read(data().join("tier").join(f)).unwrap(),
            "{f} differs from the fixture"
        );
    }
}

#[test]
fn build_refuses_a_cover_count_that_the_walk_does_not_give() {
    let d = scratch("build-bad");
    let cover = d.join("cover.tsv");
    let text = std::fs::read_to_string(data().join("cover.tsv")).unwrap();
    // 7863 tx 0 newly covers 23 tokens in the fixture's order; claim 22.
    std::fs::write(&cover, text.replace("7863\t0\t23\t", "7863\t0\t22\t")).unwrap();
    let o = run(
        &repo().join("corpus"),
        &[
            "mainnet",
            "build",
            "--tier",
            s(&d.join("t")),
            "--cover",
            s(&cover),
            "--token-table",
            s(&data().join("token-occurrences.tsv")),
            "--objects",
            s(&data().join("objects")),
        ],
    );
    assert_eq!(o.code, 2, "{}{}", o.stdout, o.stderr);
    assert!(o.stderr.contains("the cover says 22"), "{}", o.stderr);
}

#[test]
fn fetch_fills_the_cache_then_needs_no_source() {
    let (tier, cache) = setup("fetch");
    // A second run finds every object in the cache: the lake URL points nowhere and is never asked.
    let o = run(
        &repo().join("corpus"),
        &[
            "mainnet",
            "fetch",
            "--tier",
            s(&tier),
            "--cache",
            s(&cache),
            "--lake-url",
            "http://127.0.0.1:9/none",
        ],
    );
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("cached: 4 objects"), "{}", o.stdout);
    assert!(o.stdout.contains("0 failed"), "{}", o.stdout);
}

#[test]
fn fetch_reports_drift_and_keeps_the_object_aside() {
    let d = scratch("drift");
    let tier = d.join("tier");
    copy_dir(&data().join("tier"), &tier);
    let from = d.join("lake");
    copy_dir(&data().join("objects"), &from);
    let key = "FFFFFFFF--0-63999/FFFFE148--7863.xdr.zst";
    let mut b = std::fs::read(from.join(key)).unwrap();
    let n = b.len();
    b[n - 1] ^= 1;
    std::fs::write(from.join(key), &b).unwrap();
    let cache = d.join("cache");
    let o = run(
        &repo().join("corpus"),
        &[
            "mainnet",
            "fetch",
            "--tier",
            s(&tier),
            "--cache",
            s(&cache),
            "--from",
            s(&from),
        ],
    );
    assert_eq!(o.code, 1, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("drift"), "{}", o.stdout);
    let obj = cache.join("mainnet/objects").join(key);
    assert!(!obj.exists());
    assert!(obj.with_extension("zst.drift").exists());
}

#[test]
fn check_passes_on_the_fixture() {
    let (tier, cache) = setup("pass");
    let o = check(&tier, &cache);
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    assert!(
        o.stdout.contains("4 transactions, 4 ledgers, 22 parts")
            && o.stdout
                .contains("502 tokens listed, 502 walked; 0 lines failed, 0 totals failed"),
        "{}",
        o.stdout
    );
}

#[test]
fn check_fails_without_the_objects() {
    let d = scratch("empty");
    let tier = d.join("tier");
    copy_dir(&data().join("tier"), &tier);
    let o = check(&tier, &d.join("cache"));
    assert_eq!(o.code, 1, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("not in the cache"), "{}", o.stdout);
}

#[test]
fn check_fails_on_a_changed_object() {
    let (tier, cache) = setup("object");
    let p = cache
        .join("mainnet/objects")
        .join("FFF34DFF--832000-895999/FFF3034C--851123.xdr.zst");
    let mut b = std::fs::read(&p).unwrap();
    b[20] ^= 1;
    std::fs::write(&p, &b).unwrap();
    let o = check(&tier, &cache);
    assert_eq!(o.code, 1, "{}{}", o.stdout, o.stderr);
    assert!(
        o.stdout.contains("FAIL 851123-0: lake object"),
        "{}",
        o.stdout
    );
}

#[test]
fn check_fails_on_a_shifted_offset() {
    let (tier, cache) = setup("offset");
    tamper(&tier, 0, |v| {
        let o = v["parts"][0][3].as_u64().unwrap();
        v["parts"][0][3] = Value::from(o + 4);
    });
    let o = check(&tier, &cache);
    assert_eq!(o.code, 1, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("do not have sha256"), "{}", o.stdout);
    assert!(
        o.stdout.contains("parts cut from the ledger differ"),
        "{}",
        o.stdout
    );
}

#[test]
fn check_fails_on_a_changed_part_hash() {
    let (tier, cache) = setup("sha");
    tamper(&tier, 2, |v| {
        v["parts"][1][5] = Value::from("00".repeat(32));
    });
    let o = check(&tier, &cache);
    assert_eq!(o.code, 1, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("res: bytes at"), "{}", o.stdout);
}

#[test]
fn check_fails_on_a_dropped_token() {
    let (tier, cache) = setup("token");
    tamper(&tier, 3, |v| {
        v["tokens"].as_array_mut().unwrap().pop();
    });
    let o = check(&tier, &cache);
    assert_eq!(o.code, 1, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("no earlier line holds"), "{}", o.stdout);
    assert!(
        o.stdout.contains("tokens, tier.json says 502"),
        "{}",
        o.stdout
    );
}

#[test]
fn check_fails_on_a_foreign_token() {
    let (tier, cache) = setup("foreign");
    tamper(&tier, 0, |v| {
        v["tokens"]
            .as_array_mut()
            .unwrap()
            .push(Value::from("ff".repeat(16)));
    });
    let o = check(&tier, &cache);
    assert_eq!(o.code, 1, "{}{}", o.stdout, o.stderr);
    assert!(
        o.stdout.contains("is not among the transaction's tokens"),
        "{}",
        o.stdout
    );
}

#[test]
fn check_refuses_a_tier_whose_header_hash_differs() {
    let (tier, cache) = setup("header");
    let p = tier.join("tier.jsonl");
    let mut t = std::fs::read_to_string(&p).unwrap();
    t.push('\n');
    std::fs::write(&p, t).unwrap();
    let o = check(&tier, &cache);
    assert_eq!(o.code, 2, "{}{}", o.stdout, o.stderr);
    assert!(o.stderr.contains("tier.json says"), "{}", o.stderr);
}

#[test]
fn coverage_states_the_tier_and_the_curated_count_and_checks_it() {
    let d = scratch("coverage");
    let out = d.join("mainnet-coverage.json");
    let corpus = repo().join("corpus");
    let tier = data().join("tier");
    let args = ["mainnet", "coverage", "--tier", s(&tier), "--out", s(&out)];
    let o = run(&corpus, &args);
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    let v: Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(v["schema"], "xdrcheck.results.mainnet-coverage/v1");
    assert_eq!(v["tokens"], 502);
    assert_eq!(v["mainnet_tier"]["tokens_held"], 502);
    let curated = v["curated"]["tokens_held"].as_u64().unwrap();
    assert!(curated > 0 && curated <= 502, "{v}");
    assert!(v["statement"]
        .as_str()
        .unwrap()
        .starts_with("mainnet transaction-level token coverage: 502 of 502 in the mainnet tier; "));
    let mut check = args.to_vec();
    check.push("--check");
    assert_eq!(run(&corpus, &check).code, 0);
    let text = std::fs::read_to_string(&out).unwrap();
    std::fs::write(&out, text.replace("\"tokens_held\": 502", "\"tokens_held\": 501")).unwrap();
    let o = run(&corpus, &check);
    assert_eq!(o.code, 1, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("differs from a fresh generation"), "{}", o.stdout);
}
