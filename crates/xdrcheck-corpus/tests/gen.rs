//! `xdrcheck-corpus gen` end to end on the pinned stellar-core: the two probe scenarios
//! (`corpus/scenarios/s02-signed-payload-and-signers.yaml`, `s03-fee-bumps.yaml`) run at Protocols
//! 28 and 30 on both passphrases into a scratch corpus; the entries pass `verify`; `gen --check`
//! passes three times in a row with the network unreachable; a changed close-time stride fails the
//! check; a wrong expected result fails the run and writes nothing; `chain-index` on a kept run
//! reproduces the chain index `gen` wrote.
//!
//! Needs the pinned binary (`scripts/fetch.d/stellar-core.sh` or `XDRCHECK_STELLAR_CORE`); without it the
//! test prints a loud `SKIPPED` banner and passes, or fails when `XDRCHECK_REQUIRE_CORE=1`. The checks run
//! under `scripts/offline-run.sh` when the host allows unprivileged user namespaces.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_xdrcheck-corpus");

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let p = e.path();
        if p.is_dir() {
            copy_dir(&p, &to.join(e.file_name()));
        } else {
            std::fs::copy(&p, to.join(e.file_name())).unwrap();
        }
    }
}

/// A corpus root with the schemas, the ID registry, the field table, the index and the scenarios,
/// and no entries.
fn scratch_corpus(name: &str) -> PathBuf {
    let root =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let corpus = root.join("corpus");
    let src = repo().join("corpus");
    copy_dir(&src.join("schema"), &corpus.join("schema"));
    copy_dir(&src.join("scenarios"), &corpus.join("scenarios"));
    for f in ["plan.json", "fields.yaml", "corpus.json"] {
        std::fs::copy(src.join(f), corpus.join(f)).unwrap();
    }
    std::fs::create_dir_all(corpus.join("manifest")).unwrap();
    corpus
}

/// `xdrcheck-corpus --corpus <corpus> <args>`, under `scripts/offline-run.sh` when `offline` and the host
/// supports it.
fn xdrcheck(corpus: &Path, args: &[&str], offline: bool) -> Output {
    let runs = corpus.parent().unwrap().join("runs");
    let mut full: Vec<String> = vec!["--corpus".into(), corpus.display().to_string()];
    full.extend(args.iter().map(|s| s.to_string()));
    if args.first() == Some(&"gen") {
        full.extend(["--runs".into(), runs.display().to_string()]);
    }
    let out = if offline && offline_available() {
        Command::new(repo().join("scripts/offline-run.sh"))
            .arg(BIN)
            .args(&full)
            .output()
            .unwrap()
    } else {
        Command::new(BIN).args(&full).output().unwrap()
    };
    eprintln!(
        "$ xdrcheck-corpus {}\n{}{}",
        full.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn offline_available() -> bool {
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--mount", "true"])
        .status()
        .is_ok_and(|s| s.success())
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

/// Whether the pinned binary is present; without it the test is skipped with a loud banner, or
/// fails when `XDRCHECK_REQUIRE_CORE=1` (CI sets it).
fn have_core() -> bool {
    match xdrcheck_gen::core::CoreBinary::locate()
        .expect("a stellar-core binary is present but is not the pinned one")
    {
        Some(_) => true,
        None => {
            let why =
                "gen end to end: no stellar-core binary (run scripts/fetch.d/stellar-core.sh)";
            if std::env::var("XDRCHECK_REQUIRE_CORE").is_ok_and(|v| v == "1") {
                panic!("XDRCHECK_REQUIRE_CORE=1 and {why}");
            }
            eprintln!("\n{}\nSKIPPED {why}\n{}\n", "=".repeat(78), "=".repeat(78));
            println!("SKIPPED {why}");
            false
        }
    }
}

const S02: &str = "scenarios/s02-signed-payload-and-signers.yaml";
const S03: &str = "scenarios/s03-fee-bumps.yaml";

#[test]
fn probe_scenarios_end_to_end() {
    if !have_core() {
        return;
    }
    let corpus = scratch_corpus("gen-e2e");

    // Generate: 2 scenarios × Protocols 28, 30 × testnet, pubnet.
    let out = xdrcheck(&corpus, &["gen", S02, S03], true);
    assert_eq!(code(&out), 0, "gen failed");
    let entries = [
        "cap-0040/signed-payload-signers-1-byte-and-64-byte",
        "cap-0040/tx-authorised-by-signed-payload-signature",
        "cap-0040/extra-signer-signed-payload-local",
        "cap-0015/fee-bump-muxed-fee-source-inner-failed",
    ];
    for id in entries {
        let e: serde_json::Value = serde_json::from_slice(
            &std::fs::read(corpus.join(format!("manifest/{id}.json"))).unwrap(),
        )
        .unwrap();
        let keys: Vec<(String, u64)> = e["variants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                (
                    v["network"].as_str().unwrap().to_string(),
                    v["protocol"].as_u64().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            keys,
            [
                ("testnet", 30),
                ("pubnet", 30),
                ("testnet", 28),
                ("pubnet", 28)
            ]
            .map(|(n, p)| (n.to_string(), p))
            .to_vec(),
            "{id}"
        );
        for v in e["variants"].as_array().unwrap() {
            // One sidecar per blob, named by the blob's hash.
            let sha = v["blob"]["sha256"].as_str().unwrap();
            let dec = v["decoded"].as_str().unwrap();
            assert_eq!(dec, format!("decoded/{}/{sha}.json.zst", &sha[..2]));
            assert!(corpus.join(dec).is_file(), "{dec}");
            assert_eq!(v["source"]["reproducibility"], "normalised-identical");
        }
    }
    for chain in ["signed-payload-and-signers", "fee-bumps"] {
        for leaf in ["p28-testnet", "p28-pubnet", "p30-testnet", "p30-pubnet"] {
            assert!(corpus.join(format!("chains/{chain}/{leaf}.json")).is_file());
        }
    }

    // The oracle gate passes on everything generated.
    let pins = repo().join("pins.toml");
    let out = xdrcheck(
        &corpus,
        &["verify", "--pins", pins.to_str().unwrap()],
        false,
    );
    assert_eq!(code(&out), 0, "verify failed");
    assert!(String::from_utf8_lossy(&out.stdout).contains("result: PASS"));

    // Three regenerations in a row, offline, all equal.
    // Only the two scenarios generated here (the repository's pr.list names more).
    let list = corpus.join("scenarios/e2e.list");
    std::fs::write(
        &list,
        "s02-signed-payload-and-signers.yaml\ns03-fee-bumps.yaml\n",
    )
    .unwrap();
    for i in 0..3 {
        let out = xdrcheck(
            &corpus,
            &["gen", "--check", "--list", list.to_str().unwrap()],
            true,
        );
        assert_eq!(code(&out), 0, "gen --check run {i} found differences");
        assert!(String::from_utf8_lossy(&out.stdout).contains("8 chains, 0 differences"));
    }

    // A changed close-time stride changes every header hash from ledger 3 on.
    let out = xdrcheck(
        &corpus,
        &[
            "gen",
            "--check",
            S03,
            "--network",
            "pubnet",
            "--protocol",
            "28",
            "--close-time-stride",
            "2000000",
        ],
        true,
    );
    assert_eq!(
        code(&out),
        1,
        "a changed close-time stride must fail the check"
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("FAIL fee-bumps/p28-pubnet: ledger 3: header hash"),
        "{text}"
    );

    // A result that differs from the scenario fails the run and writes nothing.
    let manifest = corpus.join("manifest/cap-0015/fee-bump-muxed-fee-source-inner-failed.json");
    let before = std::fs::read(&manifest).unwrap();
    let bad = corpus.join("scenarios/s03-wrong-result.yaml");
    std::fs::write(
        &bad,
        std::fs::read_to_string(corpus.join(S03)).unwrap().replace(
            "expect_result: tx_fee_bump_inner_failed",
            "expect_result: tx_fee_bump_inner_success",
        ),
    )
    .unwrap();
    let out = xdrcheck(
        &corpus,
        &[
            "gen",
            bad.to_str().unwrap(),
            "--network",
            "testnet",
            "--protocol",
            "30",
        ],
        true,
    );
    assert_eq!(code(&out), 1);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("the step expects tx_fee_bump_inner_success")
    );
    assert_eq!(
        std::fs::read(&manifest).unwrap(),
        before,
        "nothing is written"
    );
    std::fs::remove_file(&bad).unwrap();

    // chain-index on a kept run gives the index gen writes.
    let out = xdrcheck(
        &corpus,
        &[
            "gen",
            S03,
            "--network",
            "testnet",
            "--protocol",
            "28",
            "--keep",
        ],
        true,
    );
    assert_eq!(code(&out), 0);
    let run_dir = corpus.parent().unwrap().join("runs/fee-bumps/p28-testnet");
    let out_file = corpus.parent().unwrap().join("chain-from-run.json");
    let out = xdrcheck(
        &corpus,
        &[
            "chain-index",
            run_dir.to_str().unwrap(),
            "--out",
            out_file.to_str().unwrap(),
        ],
        false,
    );
    assert_eq!(code(&out), 0);
    assert_eq!(
        std::fs::read(&out_file).unwrap(),
        std::fs::read(corpus.join("chains/fee-bumps/p28-testnet.json")).unwrap()
    );
}
