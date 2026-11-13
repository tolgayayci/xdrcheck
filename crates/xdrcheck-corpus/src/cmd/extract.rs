//! `xdrcheck-corpus extract <entry ID>… [--variant NETWORK[.pNN]]`: run the reference
//! extractor (`xdrcheck_meta::extract`) on each selected variant and print, as JSON, the focus
//! transaction's participants, state changes and movements in the manifest's `expect` vocabulary,
//! with the whole-ledger counts and transaction list, the extractor's notes, and its disagreements
//! with the entry's hand-written `expect`. Exit 1 when any variant disagrees.
use std::path::Path;
use std::process::ExitCode;

use serde_json::Value;
use xdrcheck_meta::extract::entry::{load_entry, run_variant};
use xdrcheck_xdr::Gate;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Entry IDs (`<group>/<slug>`).
    #[arg(required = true)]
    pub entries: Vec<String>,
    /// Only this variant: `testnet`, `pubnet`, `testnet.p28`, …
    #[arg(long)]
    pub variant: Option<String>,
}

pub fn run(corpus: &Path, args: Args) -> anyhow::Result<ExitCode> {
    let gate = Gate::from_corpus_json(&corpus.join("corpus.json"))?.unwrap_or_default();
    let mut out = Vec::new();
    let mut disagree = false;
    for id in &args.entries {
        let entry = load_entry(corpus, id)?;
        for v in entry.select(args.variant.as_deref())? {
            let run = run_variant(corpus, &entry, v, &gate)?;
            if !run.disagreements.is_empty() {
                disagree = true;
                for d in &run.disagreements {
                    eprintln!("{id} {}: {d}", v.label);
                }
            }
            out.push(run.output);
        }
    }
    println!("{}", serde_json::to_string_pretty(&Value::Array(out))?);
    Ok(if disagree {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}
