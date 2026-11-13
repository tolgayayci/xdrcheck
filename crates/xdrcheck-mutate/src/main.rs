//! `xdrcheck-mutate`: the mutation and oracle half of `xdrcheck mutate`.
//!
//! - `gen`: list the corpus's sources, build the plan's mutants, write them as a mutant corpus
//!   (`<out>/corpus`, entries `mut/<mutant>` and `mutctl/<source>/v<variant>`) and one JSON line per
//!   mutant in `<out>/mutants.ndjson`.
//! - `build`: rebuild one mutant from (source, variant, seed, mutation IDs) into its own mutant
//!   corpus; prints the mutant's record.
//! - `candidates`: list a source's candidate mutations under a seed.
//! - `promote`: write a mutant as a synthetic-tier corpus entry with expectations.
//! - `mutators`: the mutator table.
//!
//! Exit codes: 0 done, 2 error.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use xdrcheck_mutate::engine::{self, Mutant, PlanOpts, SourceOpts};
use xdrcheck_mutate::mutate::{Class, MUTATORS};
use xdrcheck_mutate::schema::Schema;

#[derive(Parser)]
#[command(
    name = "xdrcheck-mutate",
    about = "structure-aware mutation of corpus values"
)]
struct Cli {
    /// The corpus the sources come from.
    #[arg(long, default_value = "corpus", global = true)]
    corpus: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args, Clone)]
struct Select {
    /// Entry ID globs, comma-separated.
    #[arg(long, default_value = "")]
    entries: String,
    /// Largest blob used as a source, in bytes.
    #[arg(long, default_value_t = 256 << 10)]
    max_bytes: usize,
    /// Every variant, not only the first of each entry.
    #[arg(long)]
    all_variants: bool,
    /// Do not cut envelopes and SCVals out of ledgers.
    #[arg(long)]
    no_cut: bool,
}

impl Select {
    fn opts(&self) -> SourceOpts {
        SourceOpts {
            entries: self
                .entries
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            max_bytes: self.max_bytes,
            all_variants: self.all_variants,
            cut_values: !self.no_cut,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Build the plan's mutants into a mutant corpus.
    Gen {
        #[command(flatten)]
        select: Select,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, default_value_t = 200)]
        budget: usize,
        /// valid, metamorphic, wire-invalid (comma-separated).
        #[arg(long, default_value = "valid,metamorphic,wire-invalid")]
        classes: String,
        /// Mutator IDs (comma-separated); empty: all.
        #[arg(long, default_value = "")]
        mutators: String,
        #[arg(long, default_value_t = 3)]
        max_stack: usize,
        /// Leave ledger hashes stale after a valid-preserving mutation.
        #[arg(long)]
        stale_hashes: bool,
    },
    /// Rebuild one mutant.
    Build {
        #[command(flatten)]
        select: Select,
        #[arg(long)]
        out: PathBuf,
        /// The source ID (an entry ID, or `<entry>#<path>` for a value cut from a ledger).
        #[arg(long)]
        source: String,
        #[arg(long, default_value_t = 0)]
        variant: usize,
        #[arg(long)]
        seed: u64,
        /// Mutation IDs, comma-separated, in order.
        #[arg(long)]
        mutation: String,
        #[arg(long)]
        stale_hashes: bool,
    },
    /// List a source's candidate mutations.
    Candidates {
        #[command(flatten)]
        select: Select,
        #[arg(long)]
        source: String,
        #[arg(long, default_value_t = 0)]
        variant: usize,
        #[arg(long)]
        seed: u64,
    },
    /// Write a mutant as a synthetic-tier corpus entry.
    Promote {
        #[command(flatten)]
        select: Select,
        /// The corpus root the entry is written into.
        #[arg(long)]
        into: PathBuf,
        /// The new entry's ID.
        #[arg(long)]
        id: String,
        #[arg(long)]
        source: String,
        #[arg(long, default_value_t = 0)]
        variant: usize,
        #[arg(long)]
        seed: u64,
        #[arg(long)]
        mutation: String,
        #[arg(long)]
        stale_hashes: bool,
    },
    /// The mutator table.
    Mutators,
}

fn classes(s: &str) -> Result<Vec<Class>> {
    s.split(',')
        .filter(|x| !x.is_empty())
        .map(|x| match x {
            "valid" | "1" => Ok(Class::Valid),
            "metamorphic" | "2" => Ok(Class::Metamorphic),
            "wire-invalid" | "wire" | "3" => Ok(Class::Wire),
            other => bail!("unknown class {other}"),
        })
        .collect()
}

/// A mutant's line in `mutants.ndjson`: the record without its bytes (they are in the corpus).
fn record(m: &Mutant, entry_id: &str) -> Value {
    let mut v = serde_json::to_value(m).expect("a mutant serialises");
    v.as_object_mut().unwrap().remove("bytes");
    v["entry_id"] = json!(entry_id);
    v["bytes_len"] = json!(m.bytes.len());
    v["replay"] = json!(xdrcheck_mutate::promote::replay_command(m));
    v
}

fn run(cli: Cli) -> Result<()> {
    let schema = Schema::load()?;
    let gate = engine::gate(&cli.corpus)?;
    match cli.cmd {
        Cmd::Mutators => {
            for m in MUTATORS {
                println!("{:<20} class {}  {}", m.id, m.class.number(), m.about);
            }
        }
        Cmd::Gen {
            select,
            out,
            seed,
            budget,
            classes: cls,
            mutators,
            max_stack,
            stale_hashes,
        } => {
            let srcs = engine::sources(&cli.corpus, &schema, &select.opts())?;
            let root = out.join("corpus");
            engine::init_corpus(&cli.corpus, &root)?;
            let mut lines =
                std::io::BufWriter::new(std::fs::File::create(out.join("mutants.ndjson"))?);
            let o = PlanOpts {
                seed,
                budget,
                classes: classes(&cls)?,
                mutators: mutators
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
                max_stack,
                stale_hashes,
            };
            let mut controls = std::collections::BTreeSet::new();
            let n = engine::plan(&schema, &srcs, &o, &gate, |src, m| {
                let e = engine::mutant_entry(src, &m, &root, &gate)?;
                let ctl = engine::control_id(src);
                if m.class != Class::Wire
                    && controls.insert((ctl.clone(), m.class == Class::Metamorphic))
                {
                    if m.class == Class::Metamorphic {
                        engine::control_entry(src, &root, &gate, Class::Metamorphic)?;
                    } else if !root.join("manifest").join(format!("{ctl}.json")).exists() {
                        engine::control_entry(src, &root, &gate, Class::Valid)?;
                    }
                }
                let mut r = record(&m, e["id"].as_str().unwrap_or_default());
                r["control"] = json!(if m.class == Class::Wire {
                    Value::Null
                } else {
                    json!(ctl)
                });
                serde_json::to_writer(&mut lines, &r)?;
                lines.write_all(b"\n")?;
                Ok(())
            })?;
            lines.flush()?;
            let summary =
                json!({"sources": srcs.len(), "mutants": n, "seed": seed, "budget": budget});
            std::fs::write(out.join("gen.json"), serde_json::to_vec_pretty(&summary)?)?;
            println!("{summary}");
        }
        Cmd::Build {
            select,
            out,
            source,
            variant,
            seed,
            mutation,
            stale_hashes,
        } => {
            let srcs = engine::sources(&cli.corpus, &schema, &select.opts())?;
            let src = engine::find_source(&srcs, &source, Some(variant))?;
            let ids: Vec<String> = mutation
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            let m = engine::rebuild(&schema, src, seed, &ids, stale_hashes, &gate)?;
            let root = out.join("corpus");
            engine::init_corpus(&cli.corpus, &root)?;
            let e = engine::mutant_entry(src, &m, &root, &gate)?;
            let ctl = engine::control_id(src);
            if m.class != Class::Wire {
                engine::control_entry(src, &root, &gate, m.class)?;
            }
            let mut r = record(&m, e["id"].as_str().unwrap_or_default());
            r["control"] = json!(if m.class == Class::Wire {
                Value::Null
            } else {
                json!(ctl)
            });
            std::fs::write(out.join("mutants.ndjson"), format!("{r}\n"))?;
            println!("{r}");
        }
        Cmd::Candidates {
            select,
            source,
            variant,
            seed,
        } => {
            let srcs = engine::sources(&cli.corpus, &schema, &select.opts())?;
            let src = engine::find_source(&srcs, &source, Some(variant))?;
            for c in engine::candidates(
                &schema,
                src,
                seed,
                &[Class::Valid, Class::Metamorphic, Class::Wire],
            )? {
                println!("{}", serde_json::to_string(&c)?);
            }
        }
        Cmd::Promote {
            select,
            into,
            id,
            source,
            variant,
            seed,
            mutation,
            stale_hashes,
        } => {
            let srcs = engine::sources(&cli.corpus, &schema, &select.opts())?;
            let src = engine::find_source(&srcs, &source, Some(variant))?;
            let ids: Vec<String> = mutation
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            let m = engine::rebuild(&schema, src, seed, &ids, stale_hashes, &gate)?;
            std::fs::create_dir_all(into.join("manifest"))
                .with_context(|| format!("creating {}", into.display()))?;
            let e = xdrcheck_mutate::promote::promote(src, &m, &into, &id, &gate)?;
            println!(
                "{}",
                serde_json::to_string(
                    &json!({"id": e["id"], "mutant": m.id, "blob": e["variants"][0]["blob"]})
                )?
            );
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    // Settings exported under the earlier name (XCC_*) still apply; before parsing, as flags read the environment.
    xdrcheck_xdr::userdir::legacy_env();
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xdrcheck-mutate: {e:#}");
            ExitCode::from(2)
        }
    }
}
