//! Golden fetch and import: tree fetch from git, the bulk index, test-name
//! resolution, import, and the AG-1 and AG-3 checks.
//!
//! Offline tests use a small golden tree built here (two ledgers derived from a corpus blob with
//! their transactions removed, so they hash under any passphrase) and a throwaway git repository.
//! The tests marked `#[ignore]` need the real tree at v30.0.0 in the cache: run
//! `xdrcheck-corpus fetch-goldens v30.0.0` first, then
//! `cargo test --release -p xdrcheck-corpus --test intake_golden -- --ignored --nocapture`.

#[allow(dead_code)]
#[path = "../src/cmd/intake/mod.rs"]
mod intake;

use std::path::{Path, PathBuf};
use std::process::Command;

use intake::golden::{self, Ag1Failure, GoldenSource, Origin, Tree};
use intake::util::read_json;
use serde_json::{json, Value};
use stellar_xdr::{
    GeneralizedTransactionSet, LedgerCloseMeta, Limits as XdrLimits, VecM, WriteXdr,
};
use xdrcheck_xdr::{Gate, Limits};

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    if d.exists() {
        std::fs::remove_dir_all(&d).unwrap();
    }
    std::fs::create_dir_all(&d).unwrap();
    d
}

const NAME: &str = "Fake ledgers|protocol version 30|two ledgers";

/// Two `LedgerCloseMeta` values with no transactions, derived from a corpus blob (sequences 28, 29).
fn ledgers() -> Vec<Vec<u8>> {
    let entry: serde_json::Value = serde_json::from_slice(
        &std::fs::read(corpus().join("manifest/cap-0073/sac-trust-creates-trustline.json"))
            .unwrap(),
    )
    .unwrap();
    let v = entry["variants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["network"] == "testnet" && v["protocol"] == 30)
        .unwrap();
    let blob = std::fs::read(corpus().join(v["blob"]["path"].as_str().unwrap())).unwrap();
    xdrcheck_xdr::with_stack(256 << 20, || {
        let lcm = xdrcheck_xdr::decode_ledger(&blob, &Limits::default(), &Gate::default()).unwrap();
        let LedgerCloseMeta::V2(mut m) = lcm else {
            panic!("not v2")
        };
        let GeneralizedTransactionSet::V1(ref mut set) = m.tx_set;
        set.phases = VecM::default();
        m.tx_processing = VecM::default();
        (0..2)
            .map(|i| {
                let mut m = m.clone();
                m.ledger_header.header.ledger_seq = 28 + i;
                LedgerCloseMeta::V2(m).to_xdr(XdrLimits::none()).unwrap()
            })
            .collect()
    })
}

/// A golden tree laid out like stellar-core's, at `root`: one directory, one test, two frames.
fn write_tree(root: &Path) -> String {
    let file = format!("test-lcm-current/FakeTests/{}.xdr", golden::hash16(NAME));
    let ls = ledgers();
    let stream = xdrcheck_xdr::frame(ls.iter().map(Vec::as_slice)).unwrap();
    std::fs::create_dir_all(root.join("test-lcm-current/FakeTests")).unwrap();
    std::fs::write(root.join(&file), stream).unwrap();
    let mut idx = json!({"!cfg protocol version": 30, "!rng seed": 12345});
    idx[golden::hash16(NAME)] = json!(NAME);
    std::fs::write(
        root.join("test-lcm-current/FakeTests/index.json"),
        serde_json::to_vec_pretty(&idx).unwrap(),
    )
    .unwrap();
    file
}

/// A fetched tree in the cache layout: `<cache>/goldens/vtest/`.
fn fake_cache(name: &str) -> (PathBuf, Tree, String) {
    let cache = scratch(name);
    let root = cache.join("goldens/vtest");
    let file = write_tree(&root);
    std::fs::write(
        root.join(golden::FETCHED),
        serde_json::to_vec(&json!({"tag": "vtest", "commit": "c".repeat(40)})).unwrap(),
    )
    .unwrap();
    (cache, Tree::open(&root).unwrap(), file)
}

fn sha_index(root: &Path) -> std::collections::BTreeMap<String, String> {
    golden::tier_files(root, "current")
        .unwrap()
        .into_iter()
        .map(|f| {
            let sha = xdrcheck_xdr::sha256_file(&root.join(&f)).unwrap();
            (f, sha)
        })
        .collect()
}

#[test]
fn names_resolve_through_the_index() {
    let (_, tree, file) = fake_cache("golden-names");
    let r = golden::resolve(&tree.root, NAME, None).unwrap();
    assert_eq!(
        (r.file.as_str(), r.tier.as_str(), r.rng_seed),
        (file.as_str(), "current", Some(12345))
    );
    let loose = golden::resolve(&tree.root, "Fake ledgers|two ledgers", None).unwrap();
    assert_eq!(loose.test_name, NAME);
    assert!(golden::resolve(&tree.root, "Fake ledgers|three ledgers", None).is_err());
    assert_eq!(
        golden::strip_protocol_section(NAME),
        "Fake ledgers|two ledgers"
    );
    assert_eq!(
        golden::hash16("sponsor future reserves|protocol version 30|success"),
        "1c7fb8566ea79e53"
    );
}

#[test]
fn import_takes_the_named_frame_and_ag1_detects_every_kind_of_change() {
    let (_, tree, file) = fake_cache("golden-ag1");
    let index = sha_index(&tree.root);
    let gate = Gate::default();
    assert!(
        golden::import(&tree, NAME, None, Some(&index), &gate).is_err(),
        "--frame required"
    );
    let im = golden::import(&tree, NAME, Some(1), Some(&index), &gate).unwrap();
    assert_eq!(im.blob, ledgers()[1]);
    assert_eq!((im.frames, im.ledger.ledger_seq), (2, 29));
    let v = im.variant(&tree);
    assert_eq!(v["network"], "core-test");
    assert_eq!(v["source"]["file"], file.as_str());
    assert_eq!(v["source"]["rng_seed"], 12345);
    let src = GoldenSource::from_json(&v["source"]).unwrap();
    assert_eq!(golden::ag1(&tree, &src, &im.blob).unwrap(), Ok(()));

    let mut changed = im.blob.clone();
    changed[100] ^= 1;
    assert!(matches!(
        golden::ag1(&tree, &src, &changed).unwrap(),
        Err(Ag1Failure::BytesDiffer {
            first_difference: 100,
            ..
        })
    ));
    let other_frame = GoldenSource {
        frame_index: 0,
        ..src.clone()
    };
    assert!(matches!(
        golden::ag1(&tree, &other_frame, &im.blob).unwrap(),
        Err(Ag1Failure::BytesDiffer { .. })
    ));
    let past_end = GoldenSource {
        frame_index: 2,
        ..src.clone()
    };
    assert_eq!(
        golden::ag1(&tree, &past_end, &im.blob).unwrap(),
        Err(Ag1Failure::NoFrame { frames: 2 })
    );
    let wrong_sha = GoldenSource {
        file_sha256: "0".repeat(64),
        ..src.clone()
    };
    assert!(matches!(
        golden::ag1(&tree, &wrong_sha, &im.blob).unwrap(),
        Err(Ag1Failure::FileHash { .. })
    ));
    let wrong_name = GoldenSource {
        test_name: "Fake ledgers|other".into(),
        ..src.clone()
    };
    assert!(matches!(
        golden::ag1(&tree, &wrong_name, &im.blob).unwrap(),
        Err(Ag1Failure::NameMismatch { .. })
    ));
    let wrong_tag = GoldenSource {
        core_tag: "v0".into(),
        ..src.clone()
    };
    assert!(matches!(
        golden::ag1(&tree, &wrong_tag, &im.blob).unwrap(),
        Err(Ag1Failure::WrongTree { .. })
    ));

    let mut bad_index = index.clone();
    bad_index.insert(file.clone(), "0".repeat(64));
    assert!(golden::import(&tree, NAME, Some(1), Some(&bad_index), &gate).is_err());
}

#[test]
fn ag3_counts_ledgers_and_reports_a_corrupt_file() {
    let (_, tree, file) = fake_cache("golden-ag3");
    let r = golden::ag3(&tree, "current", &Limits::default(), &Gate::default(), 2).unwrap();
    assert!(r.ok(), "{:?}", r.failures);
    assert_eq!((r.files, r.ledgers), (1, 2));
    let p = tree.root.join(&file);
    let mut bytes = std::fs::read(&p).unwrap();
    bytes.truncate(bytes.len() - 1);
    std::fs::write(&p, bytes).unwrap();
    let r = golden::ag3(&tree, "current", &Limits::default(), &Gate::default(), 2).unwrap();
    assert_eq!(r.failures.len(), 1);
    assert_eq!(r.failures[0].0, file);
}

#[test]
fn verify_tree_finds_missing_changed_and_unlisted_files() {
    let (_, tree, file) = fake_cache("golden-verify");
    let index = sha_index(&tree.root);
    let c = golden::verify_tree(&tree.root, "current", &index).unwrap();
    assert!(c.ok() && c.verified == 1 && c.listed == 1);
    std::fs::write(
        tree.root
            .join("test-lcm-current/FakeTests/0000000000000000.xdr"),
        b"x",
    )
    .unwrap();
    let mut index2 = index.clone();
    index2.insert(
        "test-lcm-current/FakeTests/ffffffffffffffff.xdr".into(),
        "0".repeat(64),
    );
    index2.insert(file.clone(), "1".repeat(64));
    let c = golden::verify_tree(&tree.root, "current", &index2).unwrap();
    assert_eq!(c.mismatched, vec![file]);
    assert_eq!(
        c.missing,
        vec!["test-lcm-current/FakeTests/ffffffffffffffff.xdr".to_string()]
    );
    assert_eq!(
        c.unlisted,
        vec!["test-lcm-current/FakeTests/0000000000000000.xdr".to_string()]
    );
    // The index format is sha256sum's.
    let text = "aa".repeat(32) + "  test-lcm-current/A/b.xdr\n";
    let p = scratch("golden-index").join("i.sha256");
    std::fs::write(&p, text).unwrap();
    assert_eq!(
        golden::read_index(&p).unwrap()["test-lcm-current/A/b.xdr"],
        "aa".repeat(32)
    );
}

/// Run git in a throwaway fixture repository, with the user's own git configuration and a fixed fixture identity
/// (a CI runner has no git identity configured).
fn git(repo: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_AUTHOR_NAME", "fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?}");
}

/// Fetch from a local clone (the `XDRCHECK_STELLAR_CORE_REPO` path): the tree is written from the tag's
/// commit, the pinned tag must resolve to the pinned commit, and a second fetch keeps the cache.
#[test]
fn fetch_from_a_local_clone_and_keep_the_cache() {
    let base = scratch("golden-fetch");
    let repo = base.join("core");
    write_tree(&repo);
    std::fs::write(repo.join("README"), "not golden").unwrap();
    git(&repo, &["init", "--quiet"]);
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "--quiet", "-m", "fixture"]);
    git(&repo, &["tag", "vtest"]);
    let pins = intake::pins::Pins::load(&corpus()).unwrap();
    let dest = base.join("cache/goldens/vtest");
    let origin = Origin::Local(repo.clone());
    let f = golden::fetch_tree("vtest", &dest, &origin, &pins).unwrap();
    assert_eq!(f.written.len(), 1);
    assert_eq!(f.written[0].1, 1);
    assert!(!dest.join("README").exists());
    let c = golden::verify_tree(&dest, "current", &sha_index(&repo)).unwrap();
    assert!(c.ok() && c.verified == 1);
    let again = golden::fetch_tree("vtest", &dest, &origin, &pins).unwrap();
    assert!(again.written.is_empty());
    assert_eq!(again.tree, f.tree);
    // The fixture has no v30.0.0 tag; a tag that is the pinned one must resolve to the pinned commit.
    git(&repo, &["tag", &pins.core_tag()]);
    let e = golden::fetch_tree(
        &pins.core_tag(),
        &base.join("cache/goldens/pinned"),
        &origin,
        &pins,
    )
    .unwrap_err();
    assert!(format!("{e:#}").contains("pins.toml pins"), "{e:#}");
}

/// `import-golden` end to end: the binary reads the cached tree, writes the blob and adds the
/// `core-golden` variant to an entry.
#[test]
fn import_golden_command_adds_a_core_golden_variant() {
    let (cache, tree, _) = fake_cache("golden-cmd");
    let root = scratch("golden-cmd-corpus").join("corpus");
    let id = "cap-0073/sac-trust-creates-trustline";
    std::fs::create_dir_all(root.join("manifest/cap-0073")).unwrap();
    std::fs::copy(
        corpus().join(format!("manifest/{id}.json")),
        root.join(format!("manifest/{id}.json")),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_xdrcheck-corpus"))
        .env("XDRCHECK_CACHE_DIR", &cache)
        .arg("--corpus")
        .arg(&root)
        .args([
            "import-golden",
            "vtest",
            "Fake ledgers|two ledgers",
            "--frame",
            "0",
            "--entry",
            id,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let e = read_json(&root.join(format!("manifest/{id}.json"))).unwrap();
    let v: &Value = e["variants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["network"] == "core-test")
        .unwrap();
    assert_eq!(v["source"]["frame_index"], 0);
    let blob = std::fs::read(root.join(v["blob"]["path"].as_str().unwrap())).unwrap();
    let src = GoldenSource::from_json(&v["source"]).unwrap();
    assert_eq!(golden::ag1(&tree, &src, &blob).unwrap(), Ok(()));
}

// --- The real tree (needs `fetch-goldens v30.0.0` first) ---

fn real_tree() -> Tree {
    Tree::open_tag("v30.0.0").expect("run `xdrcheck-corpus fetch-goldens v30.0.0` first")
}

/// Done-condition: the committed bulk index lists 866 files per tier and the fetched tree matches it.
#[test]
#[ignore = "needs the fetched golden tree at v30.0.0"]
fn bulk_index_lists_866_files_per_tier_and_the_tree_verifies() {
    let tree = real_tree();
    assert_eq!(tree.commit, "0e49751aa9ddf892302cca02cea7f3f5d97df9f1");
    for tier in golden::TIERS {
        let index = golden::read_index(&golden::index_path(&corpus(), "v30.0.0", tier)).unwrap();
        assert_eq!(index.len(), 866, "{tier}");
        let c = golden::verify_tree(&tree.root, tier, &index).unwrap();
        assert!(c.ok(), "{tier}: {c:?}");
        assert_eq!(c.verified, 866);
    }
}

/// Done-condition: AG-3 over the whole current tier — 866 files, 15,306 ledgers, all byte-exact.
#[test]
#[ignore = "needs the fetched golden tree at v30.0.0"]
fn ag3_over_the_whole_current_tier() {
    let tree = real_tree();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let r = golden::ag3(
        &tree,
        "current",
        &Limits::default(),
        &Gate::default(),
        threads,
    )
    .unwrap();
    println!(
        "AG-3 test-lcm-current: {} files, {} ledgers, {} bytes, {} failures, {:.2} s on {threads} threads",
        r.files,
        r.ledgers,
        r.bytes,
        r.failures.len(),
        r.elapsed.as_secs_f64()
    );
    assert!(r.ok(), "{:?}", r.failures);
    assert_eq!((r.files, r.ledgers), (866, 15_306));
}

/// Done-condition: importing the SAC `trust` golden (golden-mirror spike: test "Trustline stellar
/// asset contract|protocol version 30", file 4c437318f87437c5, frame 42, ledger 44, transaction
/// eab3ffad…) yields that frame's bytes, and AG-1 fails when one byte of the blob changes.
#[test]
#[ignore = "needs the fetched golden tree at v30.0.0"]
fn sac_trust_golden_imports_byte_exact_and_ag1_catches_one_byte() {
    let tree = real_tree();
    let index = golden::read_index(&golden::index_path(&corpus(), "v30.0.0", "current")).unwrap();
    let name = "Trustline stellar asset contract|protocol version 30";
    let im = golden::import(&tree, name, Some(42), Some(&index), &Gate::default()).unwrap();
    assert_eq!(
        im.resolved.file,
        "test-lcm-current/InvokeHostFunctionTests/4c437318f87437c5.xdr"
    );
    assert_eq!(
        im.file_sha256,
        "20624d6db29bb4546312a1aafcc72c978c1781b40b90a4828ab0dc7166fefeda"
    );
    assert_eq!((im.frames, im.ledger.ledger_seq), (44, 44));
    assert_eq!(
        im.ledger.tx_hashes,
        ["eab3ffad35f024566020f85092cfccba8a11e496ef14d2625c8c8418322e5cfe"]
    );

    // The frame read independently: walk the record marks by hand.
    let file = std::fs::read(tree.root.join(&im.resolved.file)).unwrap();
    let mut pos = 0;
    let mut frame = &file[..0];
    for i in 0..=42 {
        let mark = u32::from_be_bytes(file[pos..pos + 4].try_into().unwrap());
        assert_ne!(mark & 0x8000_0000, 0);
        let len = (mark & 0x7fff_ffff) as usize;
        if i == 42 {
            frame = &file[pos + 4..pos + 4 + len];
        }
        pos += 4 + len;
    }
    assert_eq!(im.blob, frame);

    let src = GoldenSource::from_json(&im.variant(&tree)["source"]).unwrap();
    assert_eq!(golden::ag1(&tree, &src, &im.blob).unwrap(), Ok(()));
    for at in [0, im.blob.len() / 2, im.blob.len() - 1] {
        let mut changed = im.blob.clone();
        changed[at] ^= 0x01;
        assert_eq!(
            golden::ag1(&tree, &src, &changed).unwrap(),
            Err(Ag1Failure::BytesDiffer {
                blob_len: 4504,
                frame_len: 4504,
                first_difference: at
            })
        );
    }
}
