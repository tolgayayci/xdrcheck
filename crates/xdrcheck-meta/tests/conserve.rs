//! The conservation check holds on every variant of the corpus: for each transaction, holder and
//! asset, the expected movements net to the balance delta of the operations' entry changes.

use std::path::{Path, PathBuf};

use xdrcheck_meta::extract::{conserve, entry, extract};
use xdrcheck_xdr::{Gate, Limits};

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn all_entries() -> Vec<String> {
    let root = corpus().join("manifest");
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if let Some(rel) = p.strip_prefix(&root).unwrap().to_str() {
                out.push(rel.trim_end_matches(".json").to_string());
            }
        }
    }
    out.sort();
    out
}

#[test]
fn movements_conserve_balances_on_every_variant() {
    let mut bad = Vec::new();
    let (mut ledgers, mut ambiguous) = (0, Vec::new());
    for id in all_entries() {
        let e = entry::load_entry(&corpus(), &id).unwrap();
        for v in &e.variants {
            if v.blob.is_empty() {
                continue;
            }
            let Ok(bytes) = std::fs::read(corpus().join(&v.blob)) else {
                continue;
            };
            let Ok(lcm) = xdrcheck_xdr::decode_ledger(&bytes, &Limits::default(), &Gate::default())
            else {
                continue;
            };
            let pass = v.passphrase.clone();
            let (ext, violations) = xdrcheck_xdr::with_stack(Limits::default().stack_size, move || {
                let ext = extract(&lcm, &pass).unwrap();
                let vs = conserve::check(&lcm, &pass, &ext);
                (ext, vs)
            });
            ledgers += 1;
            for viol in violations {
                bad.push(format!("{id} {}: {viol}", v.label));
            }
            for t in &ext.txs {
                for f in t
                    .flags
                    .iter()
                    .filter(|f| f.kind == "balance_delta_ambiguous")
                {
                    ambiguous.push(format!("{id} {} tx {}: {}", v.label, t.index, f.detail));
                }
            }
        }
    }
    ambiguous.sort();
    ambiguous.dedup();
    eprintln!(
        "{} balance_delta_ambiguous flag(s):\n  {}",
        ambiguous.len(),
        ambiguous.join("\n  ")
    );
    assert!(ledgers > 100, "{ledgers} ledgers");
    assert!(
        bad.is_empty(),
        "{} violation(s):\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// The check is not vacuous: on every variant whose transactions have a transfer of a classic asset
/// between two holders, raising its amount by one is a violation, and so is dropping it.
#[test]
fn a_wrong_or_missing_movement_is_a_violation() {
    let mut mutated = 0;
    for id in all_entries() {
        let e = entry::load_entry(&corpus(), &id).unwrap();
        for v in &e.variants {
            let Ok(bytes) = std::fs::read(corpus().join(&v.blob)) else {
                continue;
            };
            let Ok(lcm) = xdrcheck_xdr::decode_ledger(&bytes, &Limits::default(), &Gate::default())
            else {
                continue;
            };
            let pass = v.passphrase.clone();
            let caught = xdrcheck_xdr::with_stack(Limits::default().stack_size, move || {
                let ext = extract(&lcm, &pass).unwrap();
                let (t, m) = ext.txs.iter().enumerate().find_map(|(t, tx)| {
                    tx.movements
                        .iter()
                        .position(|m| {
                            m.kind == "transfer"
                                && !m.asset.starts_with('C')
                                && m.from != m.to
                                && m.amount != "0"
                        })
                        .map(|m| (t, m))
                })?;
                let mut raised = ext.clone();
                let mv = &mut raised.txs[t].movements[m];
                mv.amount = (mv.amount.parse::<i128>().unwrap() + 1).to_string();
                let mut dropped = ext.clone();
                dropped.txs[t].movements.remove(m);
                Some(
                    !conserve::check(&lcm, &pass, &raised).is_empty()
                        && !conserve::check(&lcm, &pass, &dropped).is_empty(),
                )
            });
            match caught {
                Some(true) => mutated += 1,
                Some(false) => panic!("{id} {}: a mutated movement passed the check", v.label),
                None => {}
            }
        }
    }
    assert!(mutated > 20, "{mutated} variants mutated");
}
