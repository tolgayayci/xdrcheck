//! `xdrcheck-corpus gen` with Soroban in the scenario, end to end on the pinned stellar-core: a scenario
//! that deploys a Stellar Asset Contract and the shape-emitter contract (constructor argument
//! `Symbol("xcc")`), makes a SAC transfer with a declared footprint (Protocol 29) or simulated
//! (Protocol 30), and a simulated shape-emitter call, runs at Protocols 29 and 30 on both passphrases
//! into a scratch corpus. Then: the run records mark the simulated steps; each chain's meta stream is
//! vendored next to its index and matches it; `verify` passes; `gen --check` passes; generating
//! again changes no file; and `gen --check` fails when a declared chain, an entry blob or a
//! variant's chain is missing.
//!
//! Needs the pinned binary; without it the test prints a loud `SKIPPED` banner and passes, or fails
//! when `XDRCHECK_REQUIRE_CORE=1`. Runs under `scripts/offline-run.sh` when the host allows it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_xdrcheck-corpus");

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let p = e.unwrap().path();
        let dest = to.join(p.file_name().unwrap());
        if p.is_dir() {
            copy_dir(&p, &dest);
        } else {
            std::fs::copy(&p, &dest).unwrap();
        }
    }
}

const SCENARIO_FILE: &str = "scenarios/soroban-in-runs.yaml";

/// The scenario under test; the syntax content authors copy.
const SCENARIO: &str = r#"
scenario: soroban-in-runs
caps: [46, 67]
protocols: [29, 30]
profile: lake
actors: [A, B, I]
assets:
  USDC: {credit_alphanum4: {asset_code: USDC, issuer: "${acct.I}"}}
contracts:
  emitter:
    wasm: contracts/shape-emitter.wasm
    wasm_sha256: b53305d9913b679f137ae4d44f1ea2d32f57502f1b12aaa26406168ef4daaed8
    deployer: A
    constructor_args: [{symbol: xcc}]
setup:
  - fund: {A: "10000", B: "10000", I: "10000"}
  - trust: {A: USDC, B: USDC}
  - pay: {from: I, to: A, asset: USDC, amount: "1000"}
  - deploy_sac: USDC
  - deploy_contract: emitter
steps:
  - id: sac-transfer-declared
    entry: cap-0067/sac-transfer-to-muxed-account
    protocols: [29]
    tx:
      source_account: "${acct.A}"
      fee: 50001000
      seq_num: "${seq.A}"
      cond: none
      memo: none
      operations:
        - source_account: null
          body:
            invoke_host_function:
              host_function:
                invoke_contract:
                  contract_address: "${contract.sac(USDC)}"
                  function_name: transfer
                  args: [{address: "${acct.A}"}, {address: "${muxed(B, 7)}"}, {i128: "100000000"}]
              auth:
                - credentials: source_account
                  root_invocation:
                    function:
                      contract_fn:
                        contract_address: "${contract.sac(USDC)}"
                        function_name: transfer
                        args: [{address: "${acct.A}"}, {address: "${muxed(B, 7)}"}, {i128: "100000000"}]
                    sub_invocations: []
      ext:
        v1:
          ext: v0
          resources:
            footprint:
              read_only:
                - contract_data: {contract: "${contract.sac(USDC)}", key: ledger_key_contract_instance, durability: persistent}
                - account: {account_id: "${acct.I}"}
              read_write:
                - trustline: {account_id: "${acct.A}", asset: "${asset.USDC}"}
                - trustline: {account_id: "${acct.B}", asset: "${asset.USDC}"}
            instructions: 50000000
            disk_read_bytes: 20000
            write_bytes: 20000
          resource_fee: "50000000"
    soroban_resources: declared
    sign: [{key: A}]
    expect_result: tx_success

  - id: sac-transfer-simulated
    entry: cap-0067/sac-transfer-to-muxed-account
    protocols: [30]
    tx:
      source_account: "${acct.A}"
      fee: 1000
      seq_num: "${seq.A}"
      cond: none
      memo: none
      operations:
        - source_account: null
          body:
            invoke_host_function:
              host_function:
                invoke_contract:
                  contract_address: "${contract.sac(USDC)}"
                  function_name: transfer
                  args: [{address: "${acct.A}"}, {address: "${muxed(B, 7)}"}, {i128: "100000000"}]
    simulate: true
    sign: [{key: A}]
    expect_result: tx_success

  - id: emitter-colliding-keys
    entry: cap-0046/event-data-map-with-colliding-keys
    tx:
      source_account: "${acct.B}"
      fee: 1000
      seq_num: "${seq.B}"
      cond: none
      memo: none
      operations:
        - source_account: null
          body:
            invoke_host_function:
              host_function:
                invoke_contract: {contract_address: "${contract.id(emitter)}", function_name: colliding_keys, args: []}
    simulate: true
    sign: [{key: B}]
    expect_result: tx_success
    expect_op_results: [invoke_host_function.success]
"#;

/// A corpus root with the schemas, the ID registry, the field table, the index, the contracts and
/// this test's scenario, and no entries.
fn scratch_corpus() -> PathBuf {
    let root =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("gen-soroban-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let corpus = root.join("corpus");
    let src = repo().join("corpus");
    copy_dir(&src.join("schema"), &corpus.join("schema"));
    copy_dir(&src.join("contracts"), &corpus.join("contracts"));
    for f in ["plan.json", "fields.yaml", "corpus.json"] {
        std::fs::copy(src.join(f), corpus.join(f)).unwrap();
    }
    std::fs::create_dir_all(corpus.join("manifest")).unwrap();
    std::fs::create_dir_all(corpus.join("scenarios")).unwrap();
    std::fs::write(corpus.join(SCENARIO_FILE), SCENARIO).unwrap();
    corpus
}

fn offline_available() -> bool {
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--mount", "true"])
        .status()
        .is_ok_and(|s| s.success())
}

/// `xdrcheck-corpus --corpus <corpus> <args>`, offline when the host supports it.
fn xdrcheck(corpus: &Path, args: &[&str]) -> Output {
    let runs = corpus.parent().unwrap().join("runs");
    let mut full: Vec<String> = vec!["--corpus".into(), corpus.display().to_string()];
    full.extend(args.iter().map(|s| s.to_string()));
    if args.first() == Some(&"gen") {
        full.extend(["--runs".into(), runs.display().to_string()]);
    }
    let out = if args.first() == Some(&"gen") && offline_available() {
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

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn have_core() -> bool {
    match xdrcheck_gen::core::CoreBinary::locate()
        .expect("a stellar-core binary is present but is not the pinned one")
    {
        Some(_) => true,
        None => {
            let why =
                "gen with Soroban: no stellar-core binary (run scripts/fetch.d/stellar-core.sh)";
            if std::env::var("XDRCHECK_REQUIRE_CORE").is_ok_and(|v| v == "1") {
                panic!("XDRCHECK_REQUIRE_CORE=1 and {why}");
            }
            eprintln!("\n{}\nSKIPPED {why}\n{}\n", "=".repeat(78), "=".repeat(78));
            println!("SKIPPED {why}");
            false
        }
    }
}

fn json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// Relative path → sha256 of every file under `dir`.
fn snapshot(dir: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                todo.push(p);
            } else {
                let rel = p.strip_prefix(dir).unwrap().display().to_string();
                out.insert(rel, xdrcheck_xdr::sha256_hex(&std::fs::read(&p).unwrap()));
            }
        }
    }
    out
}

const SAC: &str = "cap-0067/sac-transfer-to-muxed-account";
const EMITTER: &str = "cap-0046/event-data-map-with-colliding-keys";
const CHAINS: [&str; 4] = ["p30-testnet", "p30-pubnet", "p29-testnet", "p29-pubnet"];

#[test]
fn soroban_scenario_end_to_end() {
    if !have_core() {
        return;
    }
    let corpus = scratch_corpus();

    let out = xdrcheck(&corpus, &["gen", SCENARIO_FILE, "--keep"]);
    assert_eq!(code(&out), 0, "gen failed");

    // The run record says which steps were simulated.
    let runs = corpus.parent().unwrap().join("runs/soroban-in-runs");
    for (leaf, simulated) in [
        ("p29-testnet", vec![false, true]),
        ("p30-pubnet", vec![true, true]),
    ] {
        let rec = json(&runs.join(leaf).join("run.json"));
        let got: Vec<bool> = rec["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["simulated"].as_bool().unwrap())
            .collect();
        assert_eq!(got, simulated, "{leaf}");
        let labels: Vec<&str> = rec["ledgers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["label"].as_str().unwrap())
            .collect();
        for want in [
            "setup[3] deploy_sac",
            "setup[4] deploy_contract upload",
            "setup[4] deploy_contract create",
        ] {
            assert!(labels.contains(&want), "{leaf}: {labels:?}");
        }
    }

    // Variants: both protocols on both passphrases, with the resources' origin recorded.
    for (id, by_protocol) in [
        (SAC, [("29", "declared"), ("30", "simulated")]),
        (EMITTER, [("29", "simulated"), ("30", "simulated")]),
    ] {
        let e = json(&corpus.join(format!("manifest/{id}.json")));
        let variants = e["variants"].as_array().unwrap();
        assert_eq!(variants.len(), 4, "{id}");
        for v in variants {
            let p = v["protocol"].to_string();
            let want = by_protocol.iter().find(|(q, _)| *q == p).unwrap().1;
            assert_eq!(v["source"]["soroban_resources"], want, "{id} p{p}");
            // Every actor's address, so a shared expect can say `${derived.accounts.<label>}`.
            let accounts = v["derived"]["accounts"].as_object().unwrap();
            assert_eq!(
                accounts.keys().collect::<Vec<_>>(),
                ["A", "B", "I"],
                "{id} p{p}"
            );
            assert!(accounts
                .values()
                .all(|a| a.as_str().unwrap().starts_with('G')));
        }
    }

    // Each chain's meta stream is in the corpus next to its index and is the stream it describes.
    for leaf in CHAINS {
        let index = json(&corpus.join(format!("chains/soroban-in-runs/{leaf}.json")));
        let rel = index["stream"]["path"].as_str().unwrap();
        assert_eq!(rel, format!("chains/soroban-in-runs/{leaf}.meta.xdr.zst"));
        let raw = std::fs::read(corpus.join(rel)).unwrap();
        assert_eq!(&raw[..4], &[0x28, 0xb5, 0x2f, 0xfd], "zstd");
        assert_ne!(raw[4] & 0x04, 0, "content checksum flag");
        let stream = zstd::stream::decode_all(raw.as_slice()).unwrap();
        assert_eq!(index["stream"]["sha256"], xdrcheck_xdr::sha256_hex(&stream));
        let records = xdrcheck_xdr::split_ledger_stream(
            &stream,
            &xdrcheck_xdr::Limits::default(),
            &xdrcheck_xdr::Gate::default(),
        )
        .unwrap();
        let ledgers = index["ledgers"].as_array().unwrap();
        assert_eq!(records.len(), ledgers.len());
        for ((_, bytes), row) in records.iter().zip(ledgers) {
            assert_eq!(row["blob_sha256"], xdrcheck_xdr::sha256_hex(bytes));
        }
    }

    let pins = repo().join("pins.toml");
    let out = xdrcheck(&corpus, &["verify", "--pins", pins.to_str().unwrap()]);
    assert_eq!(code(&out), 0, "verify failed");
    assert!(stdout(&out).contains("result: PASS"));

    let out = xdrcheck(&corpus, &["gen", "--check", SCENARIO_FILE]);
    assert_eq!(code(&out), 0, "gen --check found differences");
    assert!(stdout(&out).contains("4 chains, 0 differences"));

    // Generating again keeps every committed byte.
    let before = snapshot(&corpus);
    let out = xdrcheck(&corpus, &["gen", SCENARIO_FILE]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("bytes kept"), "{}", stdout(&out));
    let after = snapshot(&corpus);
    let changed: Vec<&String> = after
        .iter()
        .filter(|(k, v)| before.get(*k) != Some(*v))
        .map(|(k, _)| k)
        .collect();
    assert!(changed.is_empty(), "a second gen changed {changed:?}");
    assert_eq!(before.len(), after.len());

    // A declared chain that is not committed fails the check, and so does the variant it carried.
    let chain = corpus.join("chains/soroban-in-runs/p29-pubnet.json");
    let saved = std::fs::read(&chain).unwrap();
    std::fs::remove_file(&chain).unwrap();
    let out = xdrcheck(
        &corpus,
        &[
            "gen",
            "--check",
            SCENARIO_FILE,
            "--network",
            "pubnet",
            "--protocol",
            "29",
        ],
    );
    assert_eq!(code(&out), 1);
    let text = stdout(&out);
    assert!(
        text.contains("no committed chain index chains/soroban-in-runs/p29-pubnet.json"),
        "{text}"
    );
    assert!(text.contains("is on no committed chain"), "{text}");
    std::fs::write(&chain, saved).unwrap();

    // A missing entry blob fails the check.
    let e = json(&corpus.join(format!("manifest/{EMITTER}.json")));
    let v = e["variants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["network"] == "testnet" && v["protocol"] == 29)
        .unwrap();
    let blob = corpus.join(v["blob"]["path"].as_str().unwrap());
    let saved = std::fs::read(&blob).unwrap();
    std::fs::remove_file(&blob).unwrap();
    let out = xdrcheck(
        &corpus,
        &[
            "gen",
            "--check",
            SCENARIO_FILE,
            "--network",
            "testnet",
            "--protocol",
            "29",
        ],
    );
    assert_eq!(code(&out), 1);
    assert!(
        stdout(&out).contains("is not in the corpus"),
        "{}",
        stdout(&out)
    );
    std::fs::write(&blob, saved).unwrap();

    // A variant whose blob is on none of the scenario's chains fails the check.
    let path = corpus.join(format!("manifest/{EMITTER}.json"));
    let original = std::fs::read(&path).unwrap();
    let mut e: Value = serde_json::from_slice(&original).unwrap();
    for v in e["variants"].as_array_mut().unwrap() {
        if v["network"] == "testnet" && v["protocol"] == 29 {
            v["blob"]["sha256"] = "00".repeat(32).into();
        }
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&e).unwrap()).unwrap();
    let out = xdrcheck(
        &corpus,
        &[
            "gen",
            "--check",
            SCENARIO_FILE,
            "--network",
            "testnet",
            "--protocol",
            "29",
        ],
    );
    assert_eq!(code(&out), 1);
    assert!(
        stdout(&out).contains("is on no committed chain"),
        "{}",
        stdout(&out)
    );
    std::fs::write(&path, original).unwrap();

    // Restored, the check passes again.
    let out = xdrcheck(
        &corpus,
        &[
            "gen",
            "--check",
            SCENARIO_FILE,
            "--network",
            "testnet",
            "--protocol",
            "29",
        ],
    );
    assert_eq!(code(&out), 0);
    std::fs::remove_dir_all(corpus.parent().unwrap()).ok();
}
