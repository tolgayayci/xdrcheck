//! `xdrcheck-corpus chain-index <run dir> [--out FILE]` — write the chain index of a kept generator run
//! (`xdrcheck-corpus gen --keep`): the run's `run.json` and meta stream give every ledger's sequence, blob
//! hash and header hash. The index goes to `<corpus>/chains/<scenario>/p<NN>-<network>.json`, with the
//! run's meta stream vendored next to it as `p<NN>-<network>.meta.xdr.zst` (the path the index
//! names), unless `--out` names another file for the index; then only the index is written. Exit 0
//! on success, 2 if the run directory cannot be read.
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use xdrcheck_gen::output::{chain_index, chain_index_path, read_run_dir, write_chain_stream};

#[derive(clap::Args, Debug)]
pub struct Args {
    /// A run directory kept by `gen --keep` (holds run.json and meta.xdr).
    pub run_dir: PathBuf,
    /// Write here instead of the corpus's chains/ directory.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn run(corpus: &Path, args: Args) -> anyhow::Result<ExitCode> {
    let (rec, stream) = read_run_dir(&args.run_dir)?;
    let index = chain_index(&rec, &stream)?;
    let out = match args.out {
        Some(out) => out,
        None => {
            let stream_rel = write_chain_stream(corpus, &rec, &stream)?;
            println!("{}", corpus.join(stream_rel).display());
            corpus.join(chain_index_path(&rec))
        }
    };
    xdrcheck_gen::output::write::write_json(&out, &index)?;
    println!("{}", out.display());
    Ok(ExitCode::SUCCESS)
}
