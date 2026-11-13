//! `xdrcheck-corpus normalise <file> [--out FILE]`: apply stellar-core's golden-comparison
//! normalisation (`xdrcheck_meta::normalise`) to one `LedgerCloseMeta` or to a record-marked stream of
//! them. A stream in gives a record-marked stream out; a single ledger gives a single ledger. The
//! normalised bytes go to stdout or `--out`; a one-line summary goes to stderr. Normalised bytes are
//! for comparison only and never become corpus bytes.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use xdrcheck_meta::normalise::{looks_record_marked, normalise_ledger, normalise_stream};
use xdrcheck_xdr::{Gate, Limits};

#[derive(clap::Args, Debug)]
pub struct Args {
    /// A `LedgerCloseMeta` blob or a record-marked meta stream (golden file, core meta stream).
    pub file: PathBuf,
    /// Write the normalised bytes here instead of stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn run(corpus: &Path, args: Args) -> anyhow::Result<ExitCode> {
    let gate = Gate::from_corpus_json(&corpus.join("corpus.json"))?.unwrap_or_default();
    let limits = Limits::default();
    let input =
        std::fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    let (out, stats, what) = if looks_record_marked(&input) {
        let (o, s) = normalise_stream(&input, &limits, &gate)?;
        (o, s, "stream")
    } else {
        let (o, s) = normalise_ledger(&input, &limits, &gate)?;
        (o, s, "ledger")
    };
    match &args.out {
        Some(p) => std::fs::write(p, &out).with_context(|| format!("writing {}", p.display()))?,
        None => std::io::stdout().lock().write_all(&out)?,
    }
    eprintln!(
        "normalised {what}: {} change vectors sorted ({} reordered), {} timing events ({} zeroed), sha256 {}",
        stats.vectors_sorted,
        stats.vectors_reordered,
        stats.timing_events,
        stats.timing_values_zeroed,
        xdrcheck_xdr::sha256_hex(&out)
    );
    Ok(ExitCode::SUCCESS)
}
