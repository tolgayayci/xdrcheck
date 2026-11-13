//! The structural skeleton reproduces the golden-mirror spike's recorded skeleton hashes.
//!
//! Always-run part: the golden files vendored under `evidence/golden-mirror/golden/` and the three
//! saved `golden-trust` mirror runs under `evidence/golden-mirror/out/trust/`. Probe part: with
//! `XDRCHECK_PROBE_DIR` set to the directory holding the spike's saved runs (`golden-mirror/out/…`), every
//! row of the spike's `summary.tsv` (40 run × ledger rows, ordered skeletons) is recomputed;
//! skipped when the variable is unset.

use std::path::{Path, PathBuf};

use stellar_xdr::LedgerCloseMeta;
use xdrcheck_meta::skeleton::{self, diff, ledger_skeleton, tx_skeleton, Skeleton};
use xdrcheck_xdr::{Gate, Limits};

/// The spike's recorded golden skeleton hashes (`out/summary.tsv`).
const TRUST: &str = "14603d361d2bbd845938a02cb0d02af648a44b371949f4caf6b8a1862017c125";
const REPEAT: &str = "bc12323110472d0dab61dc4c672834bc420ecd5cf878ef55f8ddfeb18301f1a2";
const MUXED: &str = "54292e6543145033047e00eeddb6f74674f3f2fb18d4b194d408c0c6e8bea20f";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Ledgers of a record-marked stream, by sequence.
fn ledgers(path: &Path) -> Vec<(u32, LedgerCloseMeta)> {
    let stream = std::fs::read(path).unwrap();
    xdrcheck_xdr::split_ledger_stream(&stream, &Limits::default(), &Gate::default())
        .unwrap()
        .into_iter()
        .map(|(info, bytes)| {
            (
                info.sequence,
                xdrcheck_xdr::decode_ledger(bytes, &Limits::default(), &Gate::default()).unwrap(),
            )
        })
        .collect()
}

fn frame(path: &Path, index: usize) -> LedgerCloseMeta {
    ledgers(path).swap_remove(index).1
}

fn ledger_seq(path: &Path, seq: u32) -> LedgerCloseMeta {
    ledgers(path)
        .into_iter()
        .find(|(s, _)| *s == seq)
        .unwrap_or_else(|| panic!("{} has no ledger {seq}", path.display()))
        .1
}

fn skel(lcm: &LedgerCloseMeta) -> Skeleton {
    xdrcheck_xdr::with_stack(Limits::default().stack_size, || {
        tx_skeleton(lcm, 0, None).unwrap()
    })
}

fn golden(name: &str) -> PathBuf {
    repo().join("evidence/golden-mirror/golden").join(name)
}

#[test]
fn golden_frames_reproduce_the_spike_hashes() {
    let g = golden("4c437318f87437c5.xdr");
    assert_eq!(skel(&frame(&g, 42)).hash, TRUST);
    assert_eq!(skel(&frame(&g, 43)).hash, REPEAT);
    assert_eq!(
        skel(&frame(&golden("f9e9d669f79493b3.xdr"), 11)).hash,
        MUXED
    );
}

#[test]
fn negative_control_frame_42_against_43_differs_in_six_paths() {
    let g = golden("4c437318f87437c5.xdr");
    let d = diff(&skel(&frame(&g, 42)), &skel(&frame(&g, 43)));
    for x in &d {
        eprintln!(
            "- {}\n    A: {}\n    B: {}",
            x.path,
            skeleton::canon(&x.a),
            skeleton::canon(&x.b)
        );
    }
    assert_eq!(d.len(), 6);
}

#[test]
fn saved_golden_trust_mirror_runs_equal_the_golden() {
    for net in ["coretest", "testnet", "mainnet"] {
        let run = repo().join(format!(
            "evidence/golden-mirror/out/trust/{net}-golden-trust/meta.xdr"
        ));
        assert_eq!(skel(&ledger_seq(&run, 18)).hash, TRUST, "{net} L18");
        assert_eq!(skel(&ledger_seq(&run, 19)).hash, REPEAT, "{net} L19");
    }
}

#[test]
fn skeleton_ignores_values_but_not_shape() {
    let g = golden("4c437318f87437c5.xdr");
    let lcm = frame(&g, 42);
    let a = skel(&lcm);
    // Renormalising is a no-op; the ledger scope also works.
    assert_eq!(skel(&lcm).hash, a.hash);
    let l = xdrcheck_xdr::with_stack(Limits::default().stack_size, || {
        ledger_skeleton(&lcm).unwrap()
    });
    assert_eq!(l.sections.len(), 1);
    // Changing a value (the fee charged) keeps the skeleton; changing an arm does not.
    let edit = |f: &dyn Fn(&mut stellar_xdr::TransactionResultMetaV1)| {
        let mut v = lcm.clone();
        let LedgerCloseMeta::V2(x) = &mut v else {
            panic!("v2")
        };
        f(x.tx_processing.iter_mut().next().unwrap());
        skel(&v).hash
    };
    assert_eq!(edit(&|tx| tx.result.result.fee_charged += 1), a.hash);
    assert_ne!(
        edit(&|tx| tx.result.result.result = stellar_xdr::TransactionResultResult::TxTooLate),
        a.hash
    );
    // Two transactions need the passphrase to pair envelopes.
    let mut two = lcm.clone();
    let LedgerCloseMeta::V2(x) = &mut two else {
        panic!("v2")
    };
    let mut list = x.tx_processing.to_vec();
    list.push(list[0].clone());
    x.tx_processing = list.try_into().unwrap();
    let r = xdrcheck_xdr::with_stack(Limits::default().stack_size, || tx_skeleton(&two, 0, None));
    assert!(r.is_err());
    let r = xdrcheck_xdr::with_stack(Limits::default().stack_size, || {
        tx_skeleton(&two, 0, Some("(V) (;,,;) (V)"))
    });
    assert_eq!(r.unwrap().hash, a.hash);
}

/// Every row of the spike's summary.tsv, from its saved runs.
#[test]
fn every_saved_spike_run_reproduces_its_recorded_hash() {
    let Some(dir) = std::env::var_os("XDRCHECK_PROBE_DIR").map(PathBuf::from) else {
        eprintln!("skipped: XDRCHECK_PROBE_DIR is not set");
        return;
    };
    let gm = dir.join("golden-mirror");
    let tsv = std::fs::read_to_string(gm.join("out/summary.tsv")).unwrap();
    let mut rows = 0;
    for line in tsv.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        let (pattern, run, ledger, ordered) = (f[0], f[1], f[2], f[4]);
        let seq: u32 = ledger.trim_start_matches('L').parse().unwrap();
        let path = gm.join(format!("out/{pattern}/{run}/meta.xdr"));
        let got = skel(&ledger_seq(&path, seq)).hash;
        assert_eq!(got, ordered, "{pattern} {run} {ledger}");
        rows += 1;
    }
    // The two repeat runs of the trust chain.
    for r in ["run2", "run3"] {
        let p = gm.join(format!(
            "out/repeat/trust-testnet-golden-trust-{r}/meta.xdr"
        ));
        assert_eq!(skel(&ledger_seq(&p, 18)).hash, TRUST, "repeat {r}");
    }
    eprintln!("{rows} summary rows and 2 repeat runs reproduced");
    assert_eq!(rows, 40);
}

/// The entry's own lake-profile variants are not mirrors: against the golden they differ exactly
/// as the spike measured for the unmirrored entries (7 paths at Protocol 30, 4 at Protocol 28).
#[test]
fn lake_variants_differ_from_the_golden_as_measured() {
    let g = skel(&frame(&golden("4c437318f87437c5.xdr"), 42));
    // The spike measured the research-probe ledgers, vendored with their runs under evidence/.
    let p30 = ledger_seq(
        &repo().join("evidence/local-core/out/testnet/run-1/meta.xdr"),
        28,
    );
    let bytes = std::fs::read(
        repo().join("evidence/wallet-backend-731/out/p28-testnet/run-1/ledgers/15.xdr"),
    )
    .unwrap();
    assert_eq!(
        xdrcheck_xdr::sha256_hex(&bytes),
        "fe7ebd94df50cff714681207f98699c4e5d86a0eeca9175f96a38358b28dfb75"
    );
    let p28 = xdrcheck_xdr::decode_ledger(&bytes, &Limits::default(), &Gate::default()).unwrap();
    assert_eq!(diff(&g, &skel(&p30)).len(), 7);
    assert_eq!(diff(&g, &skel(&p28)).len(), 4);
}
