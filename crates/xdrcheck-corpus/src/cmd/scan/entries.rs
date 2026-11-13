//! `entry-tokens`: the shape tokens of every corpus entry, walked with the scan's own emitter.
//!
//! Each `LedgerCloseMeta` variant of `corpus/index.json` is decoded and cut into components exactly as
//! `scan run` cuts a mainnet ledger ([`Ctx::ledger`], rules `scan-rules-v1.toml`). For a variant whose focus is a
//! transaction (`focus.tx_index`), the tokens of that transaction's components (E, A, R, F, M and every O) are
//! written; for a ledger-level focus, the tokens of the ledger component L. A variant of another XDR type is
//! listed once with the kind `-` and no token: the scan has no component of that type.
//!
//! The transaction join needs the network passphrase the ledger was closed under. The variant's network names
//! it (pubnet, testnet); for a ledger closed by a local stellar-core under another network, the passphrases of
//! stellar-core's test and standalone networks are tried as well, and the first that joins every transaction is
//! used.
//!
//! Output (TSV, sorted): entry, variant (network@protocol, or network@protocol#ledger when an entry has more than
//! one variant with the same network and protocol), component kind, token. A variant that cannot be walked is
//! written with kind `!` and the reason in the token column.
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use xdrcheck_xdr::{Gate, Limits};

use super::shape::{Ctx, Rules, RULES_V1};
use crate::cmd::coverage::walk::Defs;

#[derive(clap::Args, Debug)]
pub struct EntryTokensArgs {
    /// The corpus directory (holds index.json and blobs/)
    #[arg(long, default_value = "corpus")]
    pub corpus: PathBuf,
    /// Output TSV (default: stdout)
    #[arg(long)]
    pub out: Option<PathBuf>,
}

const PASSPHRASES: &[(&str, &str)] = &[
    ("pubnet", "Public Global Stellar Network ; September 2015"),
    ("testnet", "Test SDF Network ; September 2015"),
    ("core-test", "(V) (;,,;) (V)"),
    ("standalone", "Standalone Network ; February 2017"),
];

pub fn run(a: EntryTokensArgs) -> Result<()> {
    let rows = walk(&a.corpus)?;
    let mut w: Box<dyn Write> = match &a.out {
        Some(p) => Box::new(std::io::BufWriter::new(std::fs::File::create(p)?)),
        None => Box::new(std::io::BufWriter::new(std::io::stdout().lock())),
    };
    writeln!(w, "entry\tvariant\tkind\ttoken")?;
    for (e, v, k, t) in rows {
        writeln!(w, "{e}\t{v}\t{k}\t{t}")?;
    }
    w.flush()?;
    Ok(())
}

/// The rows `entry-tokens` writes, for the corpus at `corpus`: (entry, variant, component kind, token).
pub fn walk(corpus: &std::path::Path) -> Result<BTreeSet<(String, String, String, String)>> {
    let defs = Defs::pinned();
    let rules = Rules::parse(RULES_V1, defs)?;
    let index_path = corpus.join("index.json");
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&index_path).with_context(|| index_path.display().to_string())?,
    )?;
    let limits = Limits::default();
    let gate = Gate::default().reading_live();
    let mut rows: BTreeSet<(String, String, String, String)> = BTreeSet::new();
    for e in index["entries"].as_array().context("index.json: no entries")? {
        let id = e["id"].as_str().context("entry without id")?.to_string();
        let vars = e["variants"].as_array().cloned().unwrap_or_default();
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for v in &vars {
            *seen
                .entry(format!("{}@{}", v["network"].as_str().unwrap_or("none"), v["protocol"]))
                .or_default() += 1;
        }
        for v in &vars {
            let net = v["network"].as_str().unwrap_or("none").to_string();
            let base = format!("{net}@{}", v["protocol"]);
            let label = if seen[&base] > 1 {
                format!("{base}#{}", v["ledger_seq"])
            } else {
                base
            };
            if v["xdr_type"] != "LedgerCloseMeta" {
                rows.insert((id.clone(), label, "-".into(), String::new()));
                continue;
            }
            let blob_path = corpus.join(v["blob"].as_str().context("variant without blob")?);
            let blob = std::fs::read(&blob_path).with_context(|| blob_path.display().to_string())?;
            let focus = v["focus"]["tx_index"].as_u64();
            let mut order: Vec<&str> = PASSPHRASES
                .iter()
                .filter(|(n, _)| *n == net)
                .map(|(_, p)| *p)
                .collect();
            order.extend(PASSPHRASES.iter().filter(|(n, _)| *n != net).map(|(_, p)| *p));
            let got = xdrcheck_xdr::with_stack(limits.stack_size, || -> Result<Vec<(char, String)>> {
                let lcm = xdrcheck_xdr::decode_ledger(&blob, &limits, &gate)?;
                let mut last = None;
                for pass in &order {
                    let ctx = Ctx {
                        defs,
                        rules: &rules,
                        network_id: Sha256::digest(pass.as_bytes()).into(),
                    };
                    let sh = ctx.ledger(&lcm, &blob)?;
                    if sh.tx_hash_mismatches > 0 {
                        last = Some(sh.tx_hash_mismatches);
                        continue;
                    }
                    let mut out = Vec::new();
                    match focus {
                        None => {
                            for t in &sh.ledger.tokens {
                                out.push(('L', t.clone()));
                            }
                        }
                        Some(i) => {
                            let tx = sh.txs.get(i as usize).with_context(|| {
                                format!("focus tx_index {i} not among {} transactions", sh.txs.len())
                            })?;
                            let mut ids = vec![&tx.e, &tx.r, &tx.f, &tx.m];
                            if let Some(a) = &tx.a {
                                ids.push(a);
                            }
                            for (o, _) in &tx.ops {
                                ids.push(o);
                            }
                            for cid in ids {
                                let c = sh.components.get(cid).context("component missing")?;
                                for t in &c.tokens {
                                    out.push((c.kind, t.clone()));
                                }
                            }
                        }
                    }
                    return Ok(out);
                }
                anyhow::bail!(
                    "no known network passphrase joins every transaction ({} unjoined)",
                    last.unwrap_or(0)
                )
            });
            match got {
                Ok(toks) => {
                    for (k, t) in toks {
                        rows.insert((id.clone(), label.clone(), k.to_string(), t));
                    }
                }
                Err(err) => {
                    let msg = format!("{err:#}").replace(['\t', '\n'], " ");
                    rows.insert((id.clone(), label, "!".into(), msg));
                }
            }
        }
    }
    Ok(rows)
}
