//! The engine's own guarantees, over real corpus entries:
//!
//! - determinism: the same seed builds byte-identical mutants (same IDs, same hashes), twice;
//! - validity: every valid-preserving and metamorphic mutant round-trips in the oracle and is
//!   accepted by stellar-core's own decoder (the `drivers/core` column), and every wire-invalid
//!   mutant is refused by both — except a bool of 2, which stellar-core reads as TRUE (the
//!   documented oracle question of `xdr-strict/bool-value-2`);
//! - metamorphism: permuting every operation's change list of the CAP-38 ledgers, or rewriting their
//!   timing diagnostics, leaves the reference extractor's facts exactly as they were.
//!
//! The stellar-core part needs the core driver built (`xdrcheck conform build --columns 'core@*'`); without
//! it that part is skipped with a note, the rest still runs.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use xdrcheck_mutate::engine::{self, Mutant, PlanOpts, Source, SourceOpts};
use xdrcheck_mutate::mutate::Class;
use xdrcheck_mutate::oracle;
use xdrcheck_mutate::schema::Schema;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn corpus() -> PathBuf {
    root().join("corpus")
}

fn sources(globs: &[&str]) -> Vec<Source> {
    let s = Schema::load().unwrap();
    let o = SourceOpts {
        entries: globs.iter().map(|g| g.to_string()).collect(),
        ..SourceOpts::default()
    };
    let v = engine::sources(&corpus(), &s, &o).unwrap();
    assert!(!v.is_empty(), "no sources for {globs:?}");
    v
}

fn plan(srcs: &[Source], o: &PlanOpts) -> Vec<(Source, Mutant)> {
    let s = Schema::load().unwrap();
    let gate = engine::gate(&corpus()).unwrap();
    let mut out = Vec::new();
    engine::plan(&s, srcs, o, &gate, |src, m| {
        out.push((src.clone(), m));
        Ok(())
    })
    .unwrap();
    out
}

const SET: &[&str] = &[
    "cap-0038/*",
    "cap-0046/scval-map-keys-collide-*",
    "classic/muxed-id-max-and-offer-id-max-roundtrip",
];

#[test]
fn same_seed_same_mutants() {
    let srcs = sources(SET);
    let o = PlanOpts {
        seed: 7,
        budget: 150,
        ..PlanOpts::default()
    };
    let a: Vec<(String, String)> = plan(&srcs, &o)
        .into_iter()
        .map(|(_, m)| (m.id, m.sha256))
        .collect();
    let b: Vec<(String, String)> = plan(&srcs, &o)
        .into_iter()
        .map(|(_, m)| (m.id, m.sha256))
        .collect();
    assert_eq!(a.len(), 150);
    assert_eq!(a, b, "two runs with seed 7 built different mutants");
    let c: Vec<(String, String)> = plan(
        &srcs,
        &PlanOpts {
            seed: 8,
            ..o.clone()
        },
    )
    .into_iter()
    .map(|(_, m)| (m.id, m.sha256))
    .collect();
    assert_ne!(a, c, "seed 8 built the same mutants as seed 7");
    // A mutant rebuilds from its source, seed and mutation IDs alone.
    let s = Schema::load().unwrap();
    let gate = engine::gate(&corpus()).unwrap();
    for (src, m) in plan(&srcs, &o).iter().step_by(10) {
        let ids: Vec<String> = m.mutations.iter().map(|x| x.id.clone()).collect();
        let r = engine::rebuild(&s, src, m.seed, &ids, m.stale_hashes, &gate).unwrap();
        assert_eq!(
            (r.id.as_str(), r.sha256.as_str()),
            (m.id.as_str(), m.sha256.as_str())
        );
    }
}

/// A running driver (the protocol of drivers/README.md).
struct Driver {
    child: std::process::Child,
    out: BufReader<std::process::ChildStdout>,
    id: u64,
}

impl Driver {
    fn start(dir: &Path, column: &str) -> Option<Driver> {
        let bin = dir.join("bin/xdrcheck-driver");
        if !bin.exists() {
            return None;
        }
        let cache = std::env::var("XDRCHECK_CACHE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| Path::new(&std::env::var("HOME").unwrap()).join(".cache/xdrcheck"));
        let rel = dir
            .strip_prefix(root())
            .unwrap()
            .to_string_lossy()
            .replace('/', "-");
        let mut child = Command::new(&bin)
            .current_dir(dir)
            .env("XDRCHECK_COLUMN", column)
            .env("XDRCHECK_CACHE_DIR", cache.join("conform").join(rel))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let out = BufReader::new(child.stdout.take().unwrap());
        let mut d = Driver { child, out, id: 0 };
        d.call(json!({"op": "describe"}))?;
        Some(d)
    }

    fn call(&mut self, mut req: Value) -> Option<Value> {
        self.id += 1;
        req["xcc"] = json!("xcc.driver/1");
        req["id"] = json!(self.id);
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{req}").ok()?;
        stdin.flush().ok()?;
        let mut line = String::new();
        self.out.read_line(&mut line).ok()?;
        serde_json::from_str(&line).ok()
    }

    fn l0(&mut self, entry: &str, xdr_type: &str, path: &Path) -> String {
        let r = self
            .call(json!({"op": "run", "entry": entry, "level": "L0",
                         "input": {"kind": "xdr", "xdr_type": xdr_type, "path": path.to_string_lossy()}}))
            .expect("the driver answers");
        r["outcome"].as_str().unwrap_or("none").to_string()
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let _ = self.call(json!({"op": "shutdown"}));
        let _ = self.child.wait();
    }
}

#[test]
fn every_mutant_is_what_its_class_says() {
    let srcs = sources(SET);
    let muts = plan(
        &srcs,
        &PlanOpts {
            seed: 3,
            budget: 240,
            ..PlanOpts::default()
        },
    );
    let mut by_class = std::collections::BTreeMap::new();
    for (_, m) in &muts {
        *by_class.entry(m.class).or_insert(0) += 1;
        let v = oracle::check(&m.xdr_type, &m.bytes);
        match m.class {
            Class::Valid | Class::Metamorphic => {
                assert!(
                    v.accepts,
                    "{} ({:?}, {}): the oracle refuses a {:?} mutant: {:?}",
                    m.id, m.mutations[0].mutator, m.source, m.class, v.reason
                )
            }
            Class::Wire => assert!(
                !v.accepts,
                "{} ({}): the oracle accepts a wire-invalid mutant",
                m.id, m.mutations[0].mutator
            ),
        }
        assert_eq!(v, m.oracle, "{}: the recorded oracle answer is stale", m.id);
    }
    for c in [Class::Valid, Class::Metamorphic, Class::Wire] {
        assert!(
            by_class.get(&c).copied().unwrap_or(0) > 0,
            "no {c:?} mutant in the plan"
        );
    }

    let dir = root().join("drivers/core");
    let Some(mut core) = Driver::start(&dir, "core@30.0.0") else {
        eprintln!("skipped the stellar-core half: drivers/core is not built");
        return;
    };
    let tmp = std::env::temp_dir().join(format!("xdrcheck-mutate-validity-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let mut wrong = Vec::new();
    for (_, m) in &muts {
        let p = tmp.join(format!("{}.xdr", m.id));
        std::fs::write(&p, &m.bytes).unwrap();
        let outcome = core.l0(&format!("mut/{}", m.id), &m.xdr_type, &p);
        // stellar-core's decoder reads a bool of 2 as TRUE (evidence/core-print-xdr/out/bool-2.txt) and
        // does not check an enum outside a union discriminant against its members
        // (evidence/core-print-xdr/out/enum-undeclared-durability.txt): there the oracle and core disagree,
        // and the run quarantines the mutant as an oracle question.
        let core_lenient = m
            .mutations
            .iter()
            .any(|x| x.mutator == "bool-2" || x.mutator == "enum-range");
        let want = match m.class {
            Class::Wire if core_lenient => "ok",
            Class::Wire => "reject",
            _ => "ok",
        };
        if outcome != "n_a" && outcome != want {
            wrong.push(format!(
                "{} {:?} {}@{} ({}): core says {outcome}",
                m.id, m.class, m.mutations[0].mutator, m.mutations[0].path, m.source
            ));
        }
    }
    std::fs::remove_dir_all(&tmp).ok();
    assert!(
        wrong.is_empty(),
        "stellar-core disagrees with the mutant class:\n{}",
        wrong.join("\n")
    );
}

/// The extractor lists a transaction's participants, state changes and movements in the order it
/// meets them; as facts they are sets. Every list under `txs[]` except a participant's own (sorted)
/// roles is compared as a multiset.
fn as_facts(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(txs) = v["txs"].as_array_mut() {
        for tx in txs {
            for k in [
                "participants",
                "must_not_include",
                "state_changes",
                "movements",
                "proposed_must_not_movements",
                "named_by_contract",
                "flags",
            ] {
                if let Some(a) = tx[k].as_array_mut() {
                    a.sort_by_key(|x| x.to_string());
                }
            }
        }
    }
    v
}

#[test]
fn reordered_changes_keep_the_facts() {
    let srcs: Vec<Source> = sources(&["cap-0038/*"])
        .into_iter()
        .filter(|s| s.is_ledger())
        .collect();
    let gate = engine::gate(&corpus()).unwrap();
    let mut permuted = 0;
    for src in &srcs {
        let orig = oracle::decode_ledger(&src.bytes, &gate).unwrap();
        let want = as_facts(&oracle::facts(&orig, &src.passphrase).unwrap());
        for seed in [1u64, 2, 3] {
            let mut lcm = orig.clone();
            let st = xdrcheck_meta::permute::permute_operation_changes(&mut lcm, seed);
            let bytes = oracle::encode_ledger(lcm).unwrap();
            assert!(oracle::check("LedgerCloseMeta", &bytes).accepts);
            if st.permuted == 0 {
                continue;
            }
            permuted += 1;
            assert_ne!(bytes, src.bytes);
            let got = as_facts(
                &oracle::facts(
                    &oracle::decode_ledger(&bytes, &gate).unwrap(),
                    &src.passphrase,
                )
                .unwrap(),
            );
            assert_eq!(
                got, want,
                "{} seed {seed}: the facts changed when the change order did",
                src.id
            );
        }
        let mut lcm = orig.clone();
        xdrcheck_meta::permute::set_timing(&mut lcm, 0x0123_4567_89ab_cdef);
        let got = as_facts(&oracle::facts(&lcm, &src.passphrase).unwrap());
        assert_eq!(
            got, want,
            "{}: the facts changed with the timing diagnostics",
            src.id
        );
    }
    assert!(
        permuted > 0,
        "no CAP-38 ledger has an operation with two change units"
    );
}
