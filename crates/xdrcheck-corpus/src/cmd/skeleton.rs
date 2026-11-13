//! `xdrcheck-corpus skeleton <entry> [--variant NETWORK[.pNN]] [--scope tx|ledger]`: print
//! the structural skeleton (`xdrcheck_meta::skeleton`) of each selected variant — of its focus
//! transaction (`--scope tx`, the default and the AG-4 scope) or of the whole ledger — as JSON with
//! the section hashes and the overall sha256. The last line of each variant on stderr is
//! `<entry> <variant> <scope> <sha256>`.
use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use serde_json::{json, Value};
use xdrcheck_meta::extract::entry::load_entry;
use xdrcheck_meta::skeleton::{ledger_skeleton, tx_skeleton};
use xdrcheck_xdr::{Gate, Limits};

/// What to take the skeleton of.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The variant's focus transaction.
    Tx,
    /// The whole ledger.
    Ledger,
}

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Entry ID (`<group>/<slug>`).
    pub entry: String,
    /// Only this variant: `testnet`, `pubnet`, `testnet.p28`, …
    #[arg(long)]
    pub variant: Option<String>,
    /// Scope of the skeleton.
    #[arg(long, value_enum, default_value = "tx")]
    pub scope: Scope,
}

pub fn run(corpus: &Path, args: Args) -> anyhow::Result<ExitCode> {
    let gate = Gate::from_corpus_json(&corpus.join("corpus.json"))?.unwrap_or_default();
    let limits = Limits::default();
    let entry = load_entry(corpus, &args.entry)?;
    let mut out = Vec::new();
    for v in entry.select(args.variant.as_deref())? {
        let path = corpus.join(&v.blob);
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let skel = xdrcheck_xdr::with_stack(limits.stack_size, || -> anyhow::Result<_> {
            let lcm = xdrcheck_xdr::decode_ledger(&bytes, &limits, &gate)?;
            Ok(match args.scope {
                Scope::Tx => tx_skeleton(&lcm, v.focus_tx, Some(&v.passphrase))?,
                Scope::Ledger => ledger_skeleton(&lcm)?,
            })
        })?;
        let scope = match args.scope {
            Scope::Tx => "tx",
            Scope::Ledger => "ledger",
        };
        eprintln!("{} {} {scope} {}", entry.id, v.label, skel.hash);
        let mut doc = json!({"entry": entry.id, "variant": v.label, "scope": scope});
        if let (Value::Object(d), Value::Object(s)) = (&mut doc, skel.to_json()) {
            d.extend(s);
        }
        out.push(doc);
    }
    println!("{}", serde_json::to_string_pretty(&Value::Array(out))?);
    Ok(ExitCode::SUCCESS)
}
