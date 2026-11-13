//! Controlled apply order on the pinned stellar-core: each ledger group with `order` applies its
//! transactions in the declared order on both passphrases, the chosen `${order_nonce}` is recorded
//! in the run record, and a second run finds the same nonce and the same header hashes. Classic
//! transactions (`tests/data/apply-order.yaml`, one with an apply-time failure that depends on the
//! order) and Soroban transactions in the parallel phase (`tests/data/apply-order-soroban.yaml`).

mod common;

use std::path::Path;

use xdrcheck_gen::core::{ClosePolicy, MetaProfile};
use xdrcheck_gen::output::chain::{ledger_facts, stream_ledgers};
use xdrcheck_gen::output::{run, Network, RunRecord, RunRequest};
use xdrcheck_gen::scenario::Scenario;

fn scenario(file: &str) -> Scenario {
    Scenario::load(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data")
            .join(file),
    )
    .unwrap()
}

fn run_on(
    binary: &xdrcheck_gen::core::CoreBinary,
    s: &Scenario,
    network: Network,
) -> (RunRecord, Vec<u8>) {
    let dir = common::run_dir(&format!("{}-{}", s.name, network.name()));
    let req = RunRequest {
        scenario: s,
        scenario_path: "tests/data/apply-order.yaml".into(),
        scenario_sha256: "0".repeat(64),
        network,
        protocol: 30,
        profile: MetaProfile::Lake,
        golden_test: None,
        close_policy: ClosePolicy::default(),
        run_dir: dir.clone(),
        corpus_root: dir.clone(),
        explore: false,
    };
    let rec = run(binary, &req).unwrap();
    let stream = std::fs::read(dir.join(&rec.stream)).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    (rec, stream)
}

/// Step IDs of a ledger's transactions in apply order.
fn applied(rec: &RunRecord, stream: &[u8], seq: u32) -> Vec<String> {
    let ledgers = stream_ledgers(stream).unwrap();
    let l = ledgers.iter().find(|l| l.info.sequence == seq).unwrap();
    ledger_facts(l.bytes)
        .unwrap()
        .results
        .iter()
        .map(|r| {
            let h = hex::encode(r.transaction_hash.0);
            rec.steps
                .iter()
                .find(|s| s.tx_hash.as_deref() == Some(&h))
                .map(|s| s.id.clone())
                .unwrap_or(h)
        })
        .collect()
}

#[test]
fn ordered_groups_apply_in_the_declared_order() {
    let Some(binary) = common::core_or_skip("ordered_groups_apply_in_the_declared_order") else {
        return;
    };
    let _ = check(
        &binary,
        &scenario("apply-order.yaml"),
        &[
            ("a-pays-b", vec!["a-pays-b", "b-pays-c"]),
            ("b-pays-c-first", vec!["b-pays-c-first", "a-pays-b-second"]),
        ],
    );
}

#[test]
fn ordered_soroban_group_applies_in_the_declared_order() {
    let Some(binary) = common::core_or_skip("ordered_soroban_group_applies_in_the_declared_order")
    else {
        return;
    };
    let _ = check(
        &binary,
        &scenario("apply-order-soroban.yaml"),
        &[("a-pays-x", vec!["c-pays-z", "a-pays-x", "b-pays-y"])],
    );
}

#[test]
fn ordered_group_under_surge_pricing_learns_the_shape() {
    let Some(binary) = common::core_or_skip("ordered_group_under_surge_pricing_learns_the_shape")
    else {
        return;
    };
    let s = scenario("apply-order-surge.yaml");
    let runs = check(
        &binary,
        &s,
        &[("bid-400", vec!["bid-200", "bid-400", "bid-300"])],
    );
    for (rec, _) in &runs {
        let left_out = rec.steps.iter().find(|x| x.id == "bid-100").unwrap();
        assert!(left_out.excluded && left_out.result.is_none());
        let charged: Vec<&str> = rec
            .steps
            .iter()
            .filter(|x| x.id != "bid-100")
            .filter_map(|x| x.fee_charged.as_deref())
            .collect();
        assert_eq!(charged, ["200", "200", "200"], "the discounted base fee");
    }
    // The default shape (the ledger's base fee) is wrong under surge pricing: at least one network
    // needed the shape read back from core (the outcome is deterministic).
    assert!(
        runs.iter()
            .any(|(r, _)| r.orders["bid-400"].shape == "learned"),
        "{:?}",
        runs.iter().map(|(r, _)| &r.orders).collect::<Vec<_>>()
    );
}

fn check(
    binary: &xdrcheck_gen::core::CoreBinary,
    s: &Scenario,
    groups: &[(&str, Vec<&str>)],
) -> Vec<(RunRecord, Vec<u8>)> {
    let mut runs = Vec::new();
    for network in [Network::Testnet, Network::Pubnet, Network::Testnet] {
        let (rec, stream) = run_on(binary, s, network);
        for (leader, want) in groups {
            assert!(rec.orders.contains_key(*leader), "{:?}", rec.orders);
            let seq = rec
                .steps
                .iter()
                .find(|x| x.id == *leader)
                .unwrap()
                .ledger
                .unwrap();
            assert_eq!(
                &applied(&rec, &stream, seq),
                want,
                "{} {leader}",
                network.name()
            );
        }
        runs.push((rec, stream));
    }
    // The second testnet run chose the same nonces and closed the same ledgers.
    let (a, b) = (&runs[0], &runs[2]);
    assert_eq!(a.0.orders, b.0.orders);
    let hashes = |s: &[u8]| -> Vec<[u8; 32]> {
        stream_ledgers(s)
            .unwrap()
            .iter()
            .map(|l| l.info.header_hash)
            .collect()
    };
    assert_eq!(hashes(&a.1), hashes(&b.1));
    println!(
        "orders: testnet {:?}, pubnet {:?}",
        a.0.orders, runs[1].0.orders
    );
    runs
}
