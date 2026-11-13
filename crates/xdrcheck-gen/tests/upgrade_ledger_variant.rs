//! A scenario that upgrades the protocol on a running chain, written into a scratch corpus on both
//! passphrases: the upgrade ledger's variant keeps the protocol its transactions were applied at and
//! records the header's protocol as `header_protocol`; a ledger after the upgrade is applied at the
//! new protocol; and every variant carries the ledger header's values under `derived.header`, so a
//! shared `expect` can pin a header field that differs per passphrase (the Protocol 24 fee-pool
//! adjustment happens on the public passphrase only).
//!
//! Needs the pinned binary (`scripts/fetch.d/stellar-core.sh`, or `XDRCHECK_STELLAR_CORE`); see
//! `common::core_or_skip`.

mod common;

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use xdrcheck_gen::core::ClosePolicy;
use xdrcheck_gen::core::MetaProfile;
use xdrcheck_gen::output::{run, write_run, Network, RunRequest};
use xdrcheck_gen::scenario::Scenario;

const SCENARIO: &str = r#"
scenario: upgrade-variant
caps: [76]
protocols: [23]
networks: [testnet, pubnet]
profile: lake
actors: [A, B]
setup:
  - fund: {A: "100", B: "100"}
steps:
  - id: upgrade-to-24
    entry: probe/upgrade-ledger
    upgrade: {protocolversion: 24}
    expect:
      values:
        - path: /v2/ledger_header/header/fee_pool
          equals: "${derived.header.fee_pool}"
  - id: pay-at-24
    entry: probe/after-upgrade
    tx:
      source_account: "${acct.A}"
      fee: 1000
      seq_num: "${seq.A}"
      cond: none
      memo: none
      operations:
        - source_account: null
          body: {payment: {destination: "${acct.B}", asset: native, amount: "10000000"}}
      ext: v0
    sign: [{key: A}]
    expect_result: tx_success
    expect_op_results: [payment.success]
"#;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A corpus root with the index and two empty probe entries.
fn scratch_corpus() -> PathBuf {
    let root = common::run_dir("upgrade-variant-corpus");
    std::fs::create_dir_all(root.join("manifest/probe")).unwrap();
    std::fs::copy(repo().join("corpus/corpus.json"), root.join("corpus.json")).unwrap();
    for id in ["probe/upgrade-ledger", "probe/after-upgrade"] {
        let e = json!({"id": id, "variants": [], "expect": {}});
        std::fs::write(
            root.join(format!("manifest/{id}.json")),
            serde_json::to_vec_pretty(&e).unwrap(),
        )
        .unwrap();
    }
    root
}

fn variant(corpus: &Path, id: &str, network: &str) -> Value {
    let e: Value =
        serde_json::from_slice(&std::fs::read(corpus.join(format!("manifest/{id}.json"))).unwrap())
            .unwrap();
    e["variants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["network"] == network)
        .unwrap_or_else(|| panic!("{id} has no {network} variant: {e}"))
        .clone()
}

#[test]
fn upgrade_ledger_variant_has_applied_and_header_protocol() {
    let Some(bin) = common::core_or_skip("upgrade_ledger_variant_has_applied_and_header_protocol")
    else {
        return;
    };
    let scenario = Scenario::from_yaml_str(SCENARIO).unwrap();
    let corpus = scratch_corpus();
    for network in [Network::Testnet, Network::Pubnet] {
        let dir = common::run_dir(&format!("upgrade-variant-{}", network.name()));
        let req = RunRequest {
            scenario: &scenario,
            scenario_path: "scenarios/upgrade-variant.yaml".into(),
            scenario_sha256: "0".repeat(64),
            network,
            protocol: 23,
            profile: MetaProfile::Lake,
            golden_test: None,
            close_policy: ClosePolicy::default(),
            run_dir: dir.clone(),
            corpus_root: repo().join("corpus"),
            explore: false,
        };
        let rec = run(&bin, &req).unwrap();
        let stream = std::fs::read(dir.join(&rec.stream)).unwrap();
        write_run(&corpus, &rec, &stream).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    let mut fee_pools = Vec::new();
    for network in ["testnet", "pubnet"] {
        // The upgrade ledger: applied at 23, header at 24.
        let v = variant(&corpus, "probe/upgrade-ledger", network);
        assert_eq!(v["protocol"], 23, "{network}");
        assert_eq!(v["header_protocol"], 24, "{network}");
        let h = &v["derived"]["header"];
        assert_eq!(h["ledger_version"], "24", "{network}: {h}");
        assert_eq!(h["base_reserve"], "5000000", "{network}: {h}");
        fee_pools.push(h["fee_pool"].as_str().unwrap().parse::<i64>().unwrap());
        for f in ["total_coins", "base_fee", "max_tx_set_size"] {
            assert!(
                h[f].as_str()
                    .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())),
                "{network}: derived.header.{f} is not a decimal string: {h}"
            );
        }

        // The next ledger runs at the new protocol; its header agrees.
        let v = variant(&corpus, "probe/after-upgrade", network);
        assert_eq!(v["protocol"], 24, "{network}");
        assert!(v.get("header_protocol").is_none(), "{network}: {v}");
        assert_eq!(v["derived"]["header"]["ledger_version"], "24");
    }
    // The same fees were charged on both chains; on the public passphrase the Protocol 24 upgrade
    // adds 31,879,035 stroops to the fee pool.
    assert_eq!(fee_pools[1] - fee_pools[0], 31_879_035, "{fee_pools:?}");
    // The shared expectation keeps the token; each variant resolves it to its own fee pool.
    let e: Value = serde_json::from_slice(
        &std::fs::read(corpus.join("manifest/probe/upgrade-ledger.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        e["expect"]["values"][0]["equals"],
        "${derived.header.fee_pool}"
    );
    std::fs::remove_dir_all(&corpus).unwrap();
}
