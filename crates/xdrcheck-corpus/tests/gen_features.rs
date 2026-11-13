//! `xdrcheck-corpus gen` end to end for the generator features that content rows wait on, each with its
//! own test scenario under `tests/data/`: the scenario is generated into a scratch corpus on both
//! passphrases, the entries it writes pass `verify`, and `gen --check` reproduces every chain.
//!
//! Needs the pinned binary (`scripts/fetch.d/stellar-core.sh` or `XDRCHECK_STELLAR_CORE`); without it a
//! test prints a loud `SKIPPED` banner and passes, or fails when `XDRCHECK_REQUIRE_CORE=1`. `gen` runs
//! under `scripts/offline-run.sh` when the host allows unprivileged user namespaces.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};

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

/// A corpus root with the schemas, the ID registry (plus `extra_ids` as probe rows), the field
/// table, the index and the named test scenario, and no entries. Returns the corpus root and the
/// scenario path relative to it.
fn scratch_corpus(scenario: &str, extra_ids: &[&str]) -> (PathBuf, String) {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("gen-features-{scenario}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let corpus = root.join("corpus");
    let src = repo().join("corpus");
    copy_dir(&src.join("schema"), &corpus.join("schema"));
    for f in ["fields.yaml", "corpus.json"] {
        std::fs::copy(src.join(f), corpus.join(f)).unwrap();
    }
    let mut plan: Value =
        serde_json::from_slice(&std::fs::read(src.join("plan.json")).unwrap()).unwrap();
    let template = plan[0].clone();
    for id in extra_ids {
        let mut row = template.clone();
        row["id"] = json!(id);
        row["kind"] = json!("ledger");
        row["caps"] = json!([]);
        row["shape"] = json!(format!("Test row {id} for a generator feature"));
        plan.as_array_mut().unwrap().push(row);
    }
    std::fs::write(
        corpus.join("plan.json"),
        serde_json::to_vec_pretty(&plan).unwrap(),
    )
    .unwrap();
    std::fs::create_dir_all(corpus.join("manifest")).unwrap();
    std::fs::create_dir_all(corpus.join("scenarios")).unwrap();
    let rel = format!("scenarios/{scenario}.yaml");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/data/{scenario}.yaml")),
        corpus.join(&rel),
    )
    .unwrap();
    std::fs::copy(repo().join("pins.toml"), root.join("pins.toml")).unwrap();
    (corpus, rel)
}

fn offline_available() -> bool {
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--mount", "true"])
        .status()
        .is_ok_and(|s| s.success())
}

/// `xdrcheck-corpus --corpus <corpus> <args>`; `gen` offline when the host supports it.
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

fn have_core(test: &str) -> bool {
    match xdrcheck_gen::core::CoreBinary::locate()
        .expect("a stellar-core binary is present but is not the pinned one")
    {
        Some(_) => true,
        None => {
            let why =
                format!("{test}: no stellar-core binary (run scripts/fetch.d/stellar-core.sh)");
            if std::env::var("XDRCHECK_REQUIRE_CORE").is_ok_and(|v| v == "1") {
                panic!("XDRCHECK_REQUIRE_CORE=1 and {why}");
            }
            eprintln!("\n{}\nSKIPPED {why}\n{}\n", "=".repeat(78), "=".repeat(78));
            println!("SKIPPED {why}");
            false
        }
    }
}

fn entry(corpus: &Path, id: &str) -> Value {
    serde_json::from_slice(&std::fs::read(corpus.join(format!("manifest/{id}.json"))).unwrap())
        .unwrap()
}

/// Generate `rel` (with extra `gen` arguments), verify the entries `ids` and check every chain.
fn generate_verify_check(corpus: &Path, rel: &str, gen_args: &[&str], ids: &[&str]) {
    let mut args = vec!["gen", rel];
    args.extend(gen_args);
    let out = xdrcheck(corpus, &args);
    assert_eq!(code(&out), 0, "gen failed");
    let pins = corpus.parent().unwrap().join("pins.toml");
    for id in ids {
        let out = xdrcheck(
            corpus,
            &["verify", "--pins", pins.to_str().unwrap(), "--entries", id],
        );
        assert_eq!(code(&out), 0, "verify {id} failed");
    }
    // Every chain index the run wrote matches its schema.
    let out = xdrcheck(
        corpus,
        &[
            "verify",
            "--pins",
            pins.to_str().unwrap(),
            "--checks",
            "schema",
        ],
    );
    assert_eq!(code(&out), 0, "verify --checks schema failed");
    let mut args = vec!["gen", "--check", rel];
    args.extend(gen_args);
    let out = xdrcheck(corpus, &args);
    assert_eq!(code(&out), 0, "gen --check found differences");
    assert!(stdout(&out).contains(" 0 differences"), "{}", stdout(&out));
}

/// Bring-up ledgers, a setup item and a root-signed step become entries.
#[test]
fn bring_up_setup_and_root_entries() {
    if !have_core("bring_up_setup_and_root_entries") {
        return;
    }
    let (corpus, rel) = scratch_corpus("bring-up-entries", &["probe/setup-entry"]);
    let upgrade = "ledger/standalone-upgrade-0-to-30-lcm-v0";
    let settings = "ledger/config-upgrade-set-applied";
    let setup = "probe/setup-entry";
    let root = "classic/create-account-funded-from-root";
    generate_verify_check(&corpus, &rel, &[], &[upgrade, settings, setup, root]);

    let e = entry(&corpus, upgrade);
    for v in e["variants"].as_array().unwrap() {
        assert_eq!(v["ledger_seq"], 2, "the protocol upgrade from genesis");
        assert_eq!(v["meta"]["ledger_close_meta_version"], 0);
        assert_eq!(v["source"]["step"], "bring-up-upgrade");
    }
    let e = entry(&corpus, settings);
    assert_eq!(
        e["variants"][0]["source"]["step"],
        "bring-up-settings-applied"
    );
    let e = entry(&corpus, setup);
    let v = &e["variants"][0];
    assert_eq!(v["source"]["step"], "setup-0-fund");
    assert_eq!(
        v["focus"]["tx_index"], 0,
        "the setup transaction is the focus"
    );

    // The root account is the source; the expectation names it through the variant's derived
    // accounts, which differ between the twins.
    let e = entry(&corpus, root);
    assert_eq!(
        e["expect"]["values"][0]["equals"],
        "${derived.accounts.root}"
    );
    let roots: Vec<&str> = e["variants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["derived"]["accounts"]["root"].as_str().unwrap())
        .collect();
    assert_eq!(roots.len(), 2);
    assert_ne!(
        roots[0], roots[1],
        "the root account differs per passphrase"
    );
}

/// Bring-up below Protocol 26: 13 and 19 without Soroban settings, 22 and 23 with the vendored
/// quickstart sets, an ordered ledger on each (the legacy transaction set before 20), and a
/// stepwise upgrade from 23 to 24.
#[test]
fn older_protocols() {
    if !have_core("older_protocols") {
        return;
    }
    let payments = "probe/older-protocol-payments";
    let upgrade = "probe/upgrade-23-to-24";
    let (corpus, rel) = scratch_corpus("older-protocols", &[payments, upgrade]);
    generate_verify_check(&corpus, &rel, &[], &[payments, upgrade]);

    let e = entry(&corpus, payments);
    let mut seen = Vec::new();
    for v in e["variants"].as_array().unwrap() {
        let p = v["protocol"].as_u64().unwrap();
        seen.push(p);
        // a-pays-b is the focus and applies second, as `order` asks.
        assert_eq!(v["focus"]["tx_index"], 1, "protocol {p}");
        let lcm = v["meta"]["ledger_close_meta_version"].as_u64().unwrap();
        assert_eq!(
            lcm,
            if p < 20 {
                0
            } else if p < 23 {
                1
            } else {
                2
            }
        );
        let doc = sidecar(&corpus, v);
        assert_eq!(
            doc[format!("v{lcm}")]["ledger_header"]["header"]["ledger_version"],
            p
        );
    }
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen, [13, 19, 22, 23]);
    // The chain at 13 applied no Soroban settings.
    let chain: Value = serde_json::from_slice(
        &std::fs::read(corpus.join("chains/older-protocols/p13-testnet.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(chain["settings"]["files"], json!([]));
    assert!(chain["settings"]["source"]
        .as_str()
        .unwrap()
        .starts_with("none"));
    // Each chain records the nonce its ordered group's search chose, and `gen --check` holds the
    // search to it.
    let path = corpus.join("chains/older-protocols/p19-pubnet.json");
    let mut chain: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let nonce = chain["orders"]["a-pays-b"]["nonce"].as_u64().unwrap();
    assert_eq!(chain["orders"]["a-pays-b"]["shape"], "default");
    chain["orders"]["a-pays-b"]["nonce"] = json!(nonce + 1);
    std::fs::write(&path, serde_json::to_vec_pretty(&chain).unwrap()).unwrap();
    let out = xdrcheck(
        &corpus,
        &[
            "gen",
            "--check",
            &rel,
            "--protocol",
            "19",
            "--network",
            "pubnet",
        ],
    );
    assert_eq!(code(&out), 1);
    assert!(
        stdout(&out).contains("ordered ledger groups: the search chose"),
        "{}",
        stdout(&out)
    );

    let e = entry(&corpus, upgrade);
    for v in e["variants"].as_array().unwrap() {
        assert_eq!(v["protocol"], 23);
        let doc = sidecar(&corpus, v);
        assert_eq!(doc["v2"]["ledger_header"]["header"]["ledger_version"], 24);
    }
}

/// Surge pricing: a step expected to be left out of its ledger, the discounted base fee of the set,
/// and the apply order of the included transactions under it (the transaction-set model learns the
/// surge-priced shape from a first attempt when its default guess is wrong).
#[test]
fn surge_pricing_leaves_a_transaction_out() {
    if !have_core("surge_pricing_leaves_a_transaction_out") {
        return;
    }
    let limit = "probe/max-tx-set-size-two";
    let surge = "probe/surge-priced-set";
    let after = "probe/after-surge";
    let (corpus, rel) = scratch_corpus("surge-pricing", &[limit, surge, after]);
    generate_verify_check(&corpus, &rel, &[], &[limit, surge, after]);

    let e = entry(&corpus, surge);
    for v in e["variants"].as_array().unwrap() {
        assert_eq!(v["source"]["step"], "bid-300, bid-200, bid-100");
        assert_eq!(v["focus"]["tx_index"], 0);
        assert_eq!(v["derived"]["fee_charged"], "200");
        assert_eq!(v["derived"]["tx_hashes"].as_array().unwrap().len(), 2);
    }
    // The left-out transaction appears in no later ledger.
    let e = entry(&corpus, after);
    for v in e["variants"].as_array().unwrap() {
        assert_eq!(v["derived"]["tx_hashes"], json!([]));
    }
}

/// The uncompressed sidecar of a variant.
fn sidecar(corpus: &Path, v: &Value) -> Value {
    let path = corpus.join(v["decoded"].as_str().unwrap());
    serde_json::from_slice(&xdrcheck_gen::output::sidecar::read_sidecar(&path).unwrap()).unwrap()
}

/// A scenario's own Soroban settings changes go through the fixed-salt upgrade path.
#[test]
fn custom_config_upgrades() {
    if !have_core("custom_config_upgrades") {
        return;
    }
    let archival = "probe/archival-settings-applied";
    let frozen = "probe/frozen-key-applied";
    let after = "probe/after-config-upgrades";
    let (corpus, rel) = scratch_corpus("config-upgrade", &[archival, frozen, after]);
    generate_verify_check(&corpus, &rel, &[], &[archival, frozen, after]);

    // Each set is a pinned input of the variants after it.
    let e = entry(&corpus, after);
    let inputs = e["variants"][0]["source"]["inputs"].as_array().unwrap();
    let names: Vec<&str> = inputs.iter().map(|i| i["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"config-upgrade/setup-1.xdr"), "{names:?}");
    assert!(names.contains(&"config-upgrade/setup-2.xdr"), "{names:?}");

    // Only the fields given changed: the rest of the archival settings are the network set's.
    let e = entry(&corpus, archival);
    let doc = sidecar(&corpus, &e["variants"][0]);
    let changes = doc["v2"]["upgrades_processing"][0]["changes"]
        .as_array()
        .unwrap();
    let updated = changes
        .iter()
        .find_map(|c| c["updated"]["data"]["config_setting"]["state_archival"].as_object())
        .expect("the archival settings changed");
    assert_eq!(updated["starting_eviction_scan_level"], 1);
    assert_eq!(
        updated["eviction_scan_size"], 500000,
        "kept from the network set"
    );

    // The frozen key is F's account key, encoded from the LedgerKey JSON.
    let f = e["variants"][0]["derived"]["accounts"]["F"]
        .as_str()
        .unwrap()
        .to_string();
    let limits = xdrcheck_xdr::Limits::default();
    let key =
        xdrcheck_xdr::from_json("LedgerKey", &json!({"account": {"account_id": f}}), &limits).unwrap();
    let hex_key = hex::encode(xdrcheck_xdr::encode(&key, &limits).unwrap());
    let e = entry(&corpus, frozen);
    let doc = sidecar(&corpus, &e["variants"][0]);
    let text = doc["v2"]["upgrades_processing"].to_string();
    assert!(text.contains(&hex_key), "{text}");
}
