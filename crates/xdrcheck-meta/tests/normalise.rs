//! stellar-core's golden-comparison normalisation.
//!
//! Always-run part: `tests/data/` holds ledger 15 of a Protocol 28 local-core chain from two runs on
//! the testnet passphrase (raw bytes differ: change order and timing diagnostics) and from a run on
//! the public passphrase (a different ledger: other keys, hashes and state). The two testnet runs
//! must be byte-identical after normalisation; the public one must stay different.
//!
//! Probe part: with `XDRCHECK_PROBE_DIR` set to the directory that holds the saved research probe runs
//! (`local-core/out/…`, `wallet-backend-731/out/…`, `golden-mirror/out/…`), every ledger of every
//! saved repeated run is compared; the test is skipped when the variable is unset or the directory is
//! absent.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use stellar_xdr::{
    LedgerCloseMeta, LedgerEntryChange, LedgerEntryData, ScVal, TransactionMeta, Type,
};
use xdrcheck_meta::normalise::{self, looks_record_marked, normalise_ledger, normalise_stream};
use xdrcheck_xdr::{Gate, Limits};

fn data(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data")
            .join(name),
    )
    .unwrap()
}

fn norm(bytes: &[u8]) -> Vec<u8> {
    normalise_ledger(bytes, &Limits::default(), &Gate::default())
        .unwrap()
        .0
}

fn decode(bytes: &[u8]) -> LedgerCloseMeta {
    xdrcheck_xdr::decode_ledger(bytes, &Limits::default(), &Gate::default()).unwrap()
}

fn encode(lcm: LedgerCloseMeta) -> Vec<u8> {
    xdrcheck_xdr::encode(&Type::LedgerCloseMeta(Box::new(lcm)), &Limits::default()).unwrap()
}

#[test]
fn differing_runs_of_one_ledger_normalise_to_identical_bytes() {
    let run1 = data("p28-testnet-l15-run1.xdr");
    let run2 = data("p28-testnet-l15-run2.xdr");
    let info1 = xdrcheck_xdr::ledger_info(&run1).unwrap();
    let info2 = xdrcheck_xdr::ledger_info(&run2).unwrap();
    assert_eq!(
        info1.header_hash, info2.header_hash,
        "same state transition"
    );
    assert_ne!(run1, run2, "raw bytes differ between the runs");

    let (n1, s1) = normalise_ledger(&run1, &Limits::default(), &Gate::default()).unwrap();
    let (n2, s2) = normalise_ledger(&run2, &Limits::default(), &Gate::default()).unwrap();
    assert_eq!(n1, n2, "normalised bytes are identical");
    assert!(s1.timing_events > 0 && s2.timing_events > 0);
    // Normalisation is idempotent.
    assert_eq!(norm(&n1), n1);
}

#[test]
fn ledgers_that_differ_in_state_stay_different() {
    let testnet = data("p28-testnet-l15-run1.xdr");
    let pubnet = data("p28-pubnet-l15-run1.xdr");
    assert_ne!(
        xdrcheck_xdr::ledger_info(&testnet).unwrap().header_hash,
        xdrcheck_xdr::ledger_info(&pubnet).unwrap().header_hash
    );
    assert_ne!(norm(&testnet), norm(&pubnet));

    // One balance changed by one stroop: a state difference that no normalisation may remove.
    let mut lcm = decode(&testnet);
    let LedgerCloseMeta::V2(v) = &mut lcm else {
        panic!("v2 ledger")
    };
    let mut edited = false;
    for c in v
        .tx_processing
        .iter_mut()
        .next()
        .unwrap()
        .fee_processing
        .0
        .iter_mut()
    {
        if let LedgerEntryChange::Updated(e) = c {
            if let LedgerEntryData::Account(a) = &mut e.data {
                a.balance += 1;
                edited = true;
            }
        }
    }
    assert!(edited);
    assert_ne!(norm(&encode(lcm)), norm(&testnet));
}

#[test]
fn post_apply_fee_processing_is_not_sorted_but_fee_processing_is() {
    // Synthetic test value: put the fee-processing pair (state, updated) into both vectors in
    // reverse order. Core sorts the first and leaves the second as emitted.
    let mut lcm = decode(&data("p28-testnet-l15-run1.xdr"));
    let LedgerCloseMeta::V2(v) = &mut lcm else {
        panic!("v2 ledger")
    };
    let tx = v.tx_processing.iter_mut().next().unwrap();
    let mut pair = tx.fee_processing.0.to_vec();
    assert_eq!(pair.len(), 2);
    pair.reverse();
    tx.fee_processing.0 = pair.clone().try_into().unwrap();
    tx.post_tx_apply_fee_processing.0 = pair.clone().try_into().unwrap();
    let normalised = decode(&norm(&encode(lcm)));
    let LedgerCloseMeta::V2(v) = normalised else {
        panic!("v2 ledger")
    };
    let tx = &v.tx_processing[0];
    assert!(matches!(
        tx.fee_processing.0[0],
        LedgerEntryChange::State(_)
    ));
    assert!(matches!(
        tx.fee_processing.0[1],
        LedgerEntryChange::Updated(_)
    ));
    assert_eq!(tx.post_tx_apply_fee_processing.0.to_vec(), pair);
}

#[test]
fn timing_values_are_zeroed_and_nothing_else() {
    let lcm = decode(&data("p28-testnet-l15-run1.xdr"));
    let normalised = decode(&norm(&data("p28-testnet-l15-run1.xdr")));
    let events = |l: &LedgerCloseMeta| match l {
        LedgerCloseMeta::V2(v) => match &v.tx_processing[0].tx_apply_processing {
            TransactionMeta::V4(m) => m.diagnostic_events.to_vec(),
            _ => panic!("v4 meta"),
        },
        _ => panic!("v2 ledger"),
    };
    let (before, after) = (events(&lcm), events(&normalised));
    assert_eq!(before.len(), after.len());
    let mut timing = 0;
    for (b, a) in before.iter().zip(&after) {
        if normalise::is_timing_event(b) {
            timing += 1;
            let stellar_xdr::ContractEventBody::V0(body) = &a.event.body;
            assert_eq!(body.data, ScVal::U64(0));
        } else {
            assert_eq!(a, b, "other diagnostic events are untouched");
        }
    }
    assert!(timing > 0);
}

#[test]
fn rank_order_is_state_created_updated_removed_restored() {
    let lcm = decode(&data("p28-testnet-l15-run1.xdr"));
    let LedgerCloseMeta::V2(v) = &lcm else {
        panic!("v2 ledger")
    };
    let entry = match &v.tx_processing[0].fee_processing.0[0] {
        LedgerEntryChange::State(e) | LedgerEntryChange::Updated(e) => e.clone(),
        _ => panic!("account entry"),
    };
    let key = entry.to_key();
    let changes = [
        LedgerEntryChange::Restored(entry.clone()),
        LedgerEntryChange::Removed(key),
        LedgerEntryChange::Updated(entry.clone()),
        LedgerEntryChange::Created(entry.clone()),
        LedgerEntryChange::State(entry),
    ];
    let mut sorted = changes.to_vec();
    sorted.sort_by(normalise::compare_changes);
    let names: Vec<_> = sorted.iter().map(|c| c.name()).collect();
    assert_eq!(
        names,
        ["State", "Created", "Updated", "Removed", "Restored"]
    );
}

#[test]
fn stream_in_stream_out() {
    let a = data("p28-testnet-l15-run1.xdr");
    let b = data("p28-pubnet-l15-run1.xdr");
    let stream = xdrcheck_xdr::frame([a.as_slice(), b.as_slice()]).unwrap();
    assert!(looks_record_marked(&stream));
    assert!(!looks_record_marked(&a));
    let (out, _) = normalise_stream(&stream, &Limits::default(), &Gate::default()).unwrap();
    assert_eq!(
        out,
        xdrcheck_xdr::frame([norm(&a).as_slice(), norm(&b).as_slice()]).unwrap()
    );
}

#[test]
fn every_corpus_blob_normalises_idempotently() {
    // Every LedgerCloseMeta blob the manifest names (xdr entries hold other types).
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
    let mut blobs = std::collections::BTreeSet::new();
    let mut stack = vec![corpus.join("manifest")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let m: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
            for v in m["variants"].as_array().into_iter().flatten() {
                if let (Some("LedgerCloseMeta"), Some(rel)) =
                    (v["xdr_type"].as_str(), v["blob"]["path"].as_str())
                {
                    blobs.insert(corpus.join(rel));
                }
            }
        }
    }
    let mut n = 0;
    for path in blobs {
        let bytes = std::fs::read(path).unwrap();
        let once = norm(&bytes);
        assert_eq!(norm(&once), once);
        n += 1;
    }
    assert!(n >= 6);
}

// --- Saved research probe runs (skipped unless XDRCHECK_PROBE_DIR points at them). ---

fn probe_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("XDRCHECK_PROBE_DIR")?);
    dir.is_dir().then_some(dir)
}

/// One ledger of one run: sequence → (header hash, raw bytes).
type Run = BTreeMap<u32, ([u8; 32], Vec<u8>)>;

fn load_run(meta: &Path) -> Run {
    let stream = std::fs::read(meta).unwrap();
    xdrcheck_xdr::split_ledger_stream(&stream, &Limits::default(), &Gate::default())
        .unwrap()
        .into_iter()
        .map(|(info, payload)| (info.sequence, (info.header_hash, payload.to_vec())))
        .collect()
}

/// Groups of saved runs that repeated one scenario on one passphrase.
fn run_sets(dir: &Path) -> Vec<(String, Vec<PathBuf>)> {
    let mut sets = Vec::new();
    for net in ["testnet", "mainnet"] {
        sets.push((
            format!("local-core {net}"),
            (1..=3)
                .map(|n| dir.join(format!("local-core/out/{net}/run-{n}/meta.xdr")))
                .collect(),
        ));
        sets.push((
            format!("wallet-backend-731 p28-{net}"),
            (1..=3)
                .map(|n| dir.join(format!("wallet-backend-731/out/p28-{net}/run-{n}/meta.xdr")))
                .collect(),
        ));
    }
    sets.push((
        "golden-mirror trust testnet".into(),
        vec![
            dir.join("golden-mirror/out/trust/testnet-golden-trust/meta.xdr"),
            dir.join("golden-mirror/out/repeat/trust-testnet-golden-trust-run2/meta.xdr"),
            dir.join("golden-mirror/out/repeat/trust-testnet-golden-trust-run3/meta.xdr"),
        ],
    ));
    sets
}

#[test]
fn saved_probe_runs_normalise_to_identical_bytes() {
    let Some(dir) = probe_dir() else {
        eprintln!("skipped: XDRCHECK_PROBE_DIR is not set or not a directory");
        return;
    };
    let mut compared_sets = 0;
    for (name, paths) in run_sets(&dir) {
        let present: Vec<&PathBuf> = paths.iter().filter(|p| p.exists()).collect();
        let missing = paths.len() - present.len();
        if present.len() < 2 {
            // The probe kept only run 1's stream; runs 2 and 3 survive as per-ledger hashes in their
            // analysis.json. Check those say "same state, different raw bytes" for the ledgers we have.
            let Some(first) = present.first() else {
                continue;
            };
            let run = load_run(first);
            let mut raw_differ = 0;
            for p in paths.iter().filter(|p| !p.exists()) {
                let Ok(text) = std::fs::read(p.with_file_name("analysis.json")) else {
                    continue;
                };
                let analysis: serde_json::Value = serde_json::from_slice(&text).unwrap();
                for l in analysis["ledgers"].as_array().unwrap() {
                    let seq = l["ledger"].as_u64().unwrap() as u32;
                    let (hash, bytes) = &run[&seq];
                    assert_eq!(l["header_hash"].as_str().unwrap(), hex::encode(hash));
                    if l["raw_sha256"].as_str().unwrap() != xdrcheck_xdr::sha256_hex(bytes) {
                        raw_differ += 1;
                    }
                }
            }
            eprintln!(
                "{name}: {} saved stream(s), {missing} run(s) kept as hashes only: same header hashes, \
                 {raw_differ} raw ledger differences against run 1 (not normalisable without the bytes)",
                present.len()
            );
            continue;
        }
        let runs: Vec<Run> = present.iter().map(|p| load_run(p)).collect();
        let (mut raw_differ, mut ledgers) = (0, 0);
        for (seq, (hash, bytes)) in &runs[0] {
            let normalised = norm(bytes);
            assert_eq!(norm(&normalised), normalised, "{name} L{seq}: idempotent");
            let mut differs = false;
            for other in &runs[1..] {
                let (h, b) = &other[seq];
                assert_eq!(h, hash, "{name} L{seq}: header hashes equal across runs");
                differs |= b != bytes;
                assert_eq!(norm(b), normalised, "{name} L{seq}: normalised bytes equal");
            }
            raw_differ += usize::from(differs);
            ledgers += 1;
        }
        eprintln!(
            "{name}: {} runs, {ledgers} ledgers, raw bytes differ in {raw_differ}, normalised identical in all",
            runs.len()
        );
        assert!(raw_differ > 0, "{name}: the runs differ raw");
        compared_sets += 1;
    }
    assert!(compared_sets > 0, "no saved run set had two streams");

    // Twins: the same sequence on the other passphrase is a different ledger and must stay different.
    for pair in [
        (
            "local-core/out/testnet/run-1",
            "local-core/out/mainnet/run-1",
        ),
        (
            "wallet-backend-731/out/p28-testnet/run-1",
            "wallet-backend-731/out/p28-mainnet/run-1",
        ),
    ] {
        let (a, b) = (
            dir.join(pair.0).join("meta.xdr"),
            dir.join(pair.1).join("meta.xdr"),
        );
        if !(a.exists() && b.exists()) {
            continue;
        }
        let (a, b) = (load_run(&a), load_run(&b));
        for (seq, (hash, bytes)) in &a {
            let (h, other) = &b[seq];
            assert_ne!(h, hash);
            assert_ne!(norm(other), norm(bytes), "{} L{seq}: twins differ", pair.0);
        }
        eprintln!(
            "{} vs {}: {} twin ledgers stay different",
            pair.0,
            pair.1,
            a.len()
        );
    }
}
