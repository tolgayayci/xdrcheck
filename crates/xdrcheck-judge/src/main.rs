//! `xdrcheck-judge`: facts from ledgers, conservation self-check, verdicts on indexer rows.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use xdrcheck_judge::conserve::{self, Tally};
use xdrcheck_judge::facts::{judge_ledger, Options};
use xdrcheck_judge::{lake, verdict};

#[derive(Parser)]
#[command(
    name = "xdrcheck-judge",
    about = "Ground truth from LedgerCloseMeta, and verdicts on indexer rows"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compute facts (JSONL) for ledgers; optionally run the conservation self-check.
    Facts {
        /// Ledger files (zstd LedgerCloseMetaBatch or raw XDR), processed in the order given.
        files: Vec<PathBuf>,
        /// A lake-layout directory with `index.tsv` (seq, path, size).
        #[arg(long)]
        root: Option<PathBuf>,
        /// Ledger sequences to take from --root (first column of each line; `#`/non-numeric skipped).
        #[arg(long)]
        list: Option<PathBuf>,
        #[arg(long, default_value = xdrcheck_judge::read::MAINNET)]
        network: String,
        /// Extra SAC candidates: one asset string (`native`, `CODE:ISSUER`) per line.
        #[arg(long)]
        sac_registry: Option<PathBuf>,
        /// Facts output (`-` = stdout). Omit to write none.
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Write `residuals.jsonl` and `summary.json` of the conservation check here.
        #[arg(long)]
        conserve: Option<PathBuf>,
        #[arg(short = 'j', long, default_value_t = 4)]
        jobs: usize,
    },
    /// Compare an indexer's rows with facts and emit verdicts.
    Verdict {
        #[arg(long)]
        facts: PathBuf,
        #[arg(long)]
        rows: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
        /// `net`: rows carry fees too; `nofee`: rows exclude fee and refund changes.
        #[arg(long, default_value = "net")]
        balance_scope: String,
        /// Kinds to compare (default: every kind present in the rows).
        #[arg(long, value_delimiter = ',')]
        kinds: Vec<String>,
        /// Participant roles that count (default: all).
        #[arg(long, value_delimiter = ',')]
        roles: Vec<String>,
        /// The target's scope file (TOML): kinds, comparison modes, out-of-scope rules.
        #[arg(long)]
        scope: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Facts {
            files,
            root,
            list,
            network,
            sac_registry,
            out,
            conserve,
            jobs,
        } => {
            let mut opts = Options::new(&network);
            if let Some(r) = sac_registry {
                opts.sac_registry = std::fs::read_to_string(r)?
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect();
            }
            let mut inputs = files;
            if let Some(root) = root {
                inputs.extend(from_index(&root, list.as_deref())?);
            }
            run_facts(
                &inputs,
                &opts,
                out.as_deref(),
                conserve.as_deref(),
                jobs.max(1),
            )
        }
        Cmd::Verdict {
            facts,
            rows,
            out,
            balance_scope,
            kinds,
            roles,
            scope,
        } => {
            let cfg = verdict::Config {
                nofee: balance_scope == "nofee",
                kinds: kinds.into_iter().collect(),
                roles: roles.into_iter().collect(),
                scope: scope.map(|p| xdrcheck_judge::scope::load(&p)).transpose()?,
            };
            let s = verdict::run(&facts, &rows, &out, &cfg)?;
            eprintln!("{}", serde_json::to_string(&s)?);
            Ok(())
        }
    }
}

fn from_index(root: &Path, list: Option<&Path>) -> Result<Vec<PathBuf>> {
    let idx = BufReader::new(File::open(root.join("index.tsv")).context("index.tsv")?);
    let mut by_seq: HashMap<u32, String> = HashMap::new();
    let mut order: Vec<u32> = Vec::new();
    for l in idx.lines() {
        let l = l?;
        let mut it = l.split('\t');
        let (Some(s), Some(p)) = (it.next(), it.next()) else {
            continue;
        };
        if let Ok(s) = s.parse::<u32>() {
            by_seq.insert(s, p.to_string());
            order.push(s);
        }
    }
    let seqs: Vec<u32> = match list {
        Some(l) => {
            let mut v = Vec::new();
            for line in BufReader::new(File::open(l)?).lines() {
                let line = line?;
                let first = line.split(['\t', ' ', ',']).next().unwrap_or("");
                if let Ok(s) = first.trim().parse::<u32>() {
                    v.push(s);
                }
            }
            v
        }
        None => order,
    };
    let mut out = Vec::new();
    for s in seqs {
        match by_seq.get(&s) {
            Some(p) => out.push(root.join(p)),
            None => anyhow::bail!("ledger {s} not in index"),
        }
    }
    Ok(out)
}

/// Process inputs in chunks; each chunk is split over `jobs` threads and written in input order.
/// Memory is bounded by one chunk.
fn run_facts(
    inputs: &[PathBuf],
    opts: &Options,
    out: Option<&Path>,
    conserve_dir: Option<&Path>,
    jobs: usize,
) -> Result<()> {
    let mut w: Option<Box<dyn Write>> = match out {
        None => None,
        Some(p) if p == Path::new("-") => Some(Box::new(BufWriter::new(std::io::stdout()))),
        Some(p) => Some(Box::new(BufWriter::new(File::create(p)?))),
    };
    let mut rw = match conserve_dir {
        Some(d) => {
            std::fs::create_dir_all(d)?;
            Some(BufWriter::new(File::create(d.join("residuals.jsonl"))?))
        }
        None => None,
    };
    let mut tally = Tally::default();
    let mut errors: Vec<String> = Vec::new();
    let t0 = Instant::now();
    let chunk = jobs * 16;
    let mut done = 0usize;
    for group in inputs.chunks(chunk) {
        let per = group.len().div_ceil(jobs);
        let results: Vec<Vec<FileOut>> = std::thread::scope(|s| {
            let hs: Vec<_> = group
                .chunks(per.max(1))
                .map(|part| {
                    s.spawn(move || {
                        part.iter()
                            .map(|p| one_file(p, opts, conserve_dir.is_some()))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().expect("worker")).collect()
        });
        for (facts, res, t, errs) in results.into_iter().flatten() {
            if let Some(w) = w.as_mut() {
                w.write_all(facts.as_bytes())?;
            }
            if let Some(r) = rw.as_mut() {
                r.write_all(res.as_bytes())?;
            }
            tally.merge(&t);
            errors.extend(errs);
        }
        done += group.len();
        if done % (chunk * 64) < chunk {
            eprintln!(
                "{done}/{} files, {:.0} ledgers/s",
                inputs.len(),
                tally.ledgers as f64 / t0.elapsed().as_secs_f64()
            );
        }
    }
    if let Some(w) = w.as_mut() {
        w.flush()?;
    }
    let secs = t0.elapsed().as_secs_f64();
    let summary = serde_json::json!({
        "files": inputs.len(),
        "ledgers": tally.ledgers,
        "seconds": (secs * 10.0).round() / 10.0,
        "ledgers_per_second": (tally.ledgers as f64 / secs).round(),
        "jobs": jobs,
        "errors": errors,
        "tally": tally,
    });
    if let Some(d) = conserve_dir {
        rw.as_mut().unwrap().flush()?;
        std::fs::write(
            d.join("summary.json"),
            serde_json::to_string_pretty(&summary)? + "\n",
        )?;
    }
    eprintln!("{}", serde_json::to_string(&summary["tally"]["residual"])?);
    eprintln!(
        "ledgers {} in {:.1}s = {:.0}/s, errors {}",
        tally.ledgers,
        secs,
        tally.ledgers as f64 / secs,
        errors.len()
    );
    Ok(())
}

/// Facts text, residuals text, tally and errors of one input file.
type FileOut = (String, String, Tally, Vec<String>);

fn one_file(p: &Path, opts: &Options, conserve: bool) -> FileOut {
    let mut facts_s = String::new();
    let mut res_s = String::new();
    let mut tally = Tally::default();
    let mut errs = Vec::new();
    let lcms = match lake::read_file(p) {
        Ok(l) => l,
        Err(e) => {
            errs.push(format!("{}: {e:#}", p.display()));
            return (facts_s, res_s, tally, errs);
        }
    };
    for lcm in &lcms {
        match judge_ledger(lcm, opts) {
            Ok(facts) => {
                for f in &facts {
                    facts_s.push_str(&serde_json::to_string(f).expect("serialise"));
                    facts_s.push('\n');
                }
                if !conserve {
                    tally.ledgers += 1;
                } else {
                    for r in conserve::check(&facts, &mut tally) {
                        res_s.push_str(&serde_json::to_string(&r).expect("serialise"));
                        res_s.push('\n');
                    }
                }
            }
            Err(e) => errs.push(format!("{}: {e:#}", p.display())),
        }
    }
    (facts_s, res_s, tally, errs)
}
