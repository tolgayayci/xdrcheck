//! `xdrcheck-corpus`: the corpus toolchain command. Each subcommand lives in its own module under `cmd/`;
//! the command surface is documented in `docs/cli.md`. Exit codes: 0 success, 1 a check failed, 2 the
//! tool could not run. The global `--corpus` flag (default `corpus`) selects the corpus root.
use clap::{Parser, Subcommand};

mod cmd;

#[derive(Parser)]
#[command(
    name = "xdrcheck-corpus",
    version,
    about = "Corpus toolchain: oracle, generator, intake, coverage"
)]
struct Cli {
    /// Corpus root (directory holding corpus.json, manifest/, blobs/).
    #[arg(long, global = true, default_value = "corpus")]
    corpus: std::path::PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// The oracle gate: schema, ids, hashes, roundtrip, reject, sidecar, pinpoints, ag1, ag3, ag4, extractor
    Verify(cmd::verify::Args),
    /// Write SEP-51 decoded sidecars
    Render(cmd::render::Args),
    /// Reference extractor: participants, state changes, movements
    Extract(cmd::extract::Args),
    /// stellar-core golden-comparison normalisation
    Normalise(cmd::normalise::Args),
    /// Structural skeleton and hash
    Skeleton(cmd::skeleton::Args),
    /// Run scenarios on a local stellar-core; --check regenerates and compares
    Gen(cmd::gen::Args),
    /// Run exploratory scenarios on a local stellar-core and write the ledgers as a lake
    GenLake(cmd::gen_lake::Args),
    /// Write a chain index for a kept scenario run
    ChainIndex(cmd::chain_index::Args),
    /// Fetch one public-lake object verbatim with provenance
    Capture(cmd::capture::Args),
    /// Stream public-lake objects and keep only ledgers with wanted shapes
    Mine(cmd::mine::Args),
    /// Re-fetch every history entry and compare hashes
    Refetch(cmd::refetch::Args),
    /// Fetch the golden tree at a stellar-core tag
    FetchGoldens(cmd::fetch_goldens::Args),
    /// Import one golden ledger as a core-golden variant
    ImportGolden(cmd::import_golden::Args),
    /// Build synthetic, api or strkey entries from a recipe
    Synth(cmd::synth::Args),
    /// Cut an xdr entry out of a ledger entry
    Slice(cmd::slice::Args),
    /// Generate coverage.json and COVERAGE.md; --check fails on unexplained gaps
    Coverage(cmd::coverage::Args),
    /// Generate corpus/index.json, one row per entry; --check fails on drift
    Index(cmd::index::Args),
    /// Generate the guide's field table; --check fails on drift
    GuideTable(cmd::guide_table::Args),
    /// Check the guide's claim-to-source map
    GuideClaims(cmd::guide_claims::Args),
    /// The mainnet tier: fetch its lake objects, check it, build it from the scan
    Mainnet(cmd::mainnet::Args),
    /// Mainnet scan pilot: shape records and the offline tools over them
    Scan(cmd::scan::Args),
}

fn main() -> std::process::ExitCode {
    // Settings exported under the earlier name (XCC_*) still apply; before parsing, as flags read the environment.
    xdrcheck_xdr::userdir::legacy_env();
    let cli = Cli::parse();
    let r = match cli.command {
        Command::Verify(a) => cmd::verify::run(&cli.corpus, a),
        Command::Render(a) => cmd::render::run(&cli.corpus, a),
        Command::Extract(a) => cmd::extract::run(&cli.corpus, a),
        Command::Normalise(a) => cmd::normalise::run(&cli.corpus, a),
        Command::Skeleton(a) => cmd::skeleton::run(&cli.corpus, a),
        Command::Gen(a) => cmd::gen::run(&cli.corpus, a),
        Command::GenLake(a) => cmd::gen_lake::run(&cli.corpus, a),
        Command::ChainIndex(a) => cmd::chain_index::run(&cli.corpus, a),
        Command::Capture(a) => cmd::capture::run(&cli.corpus, a),
        Command::Mine(a) => cmd::mine::run(&cli.corpus, a),
        Command::Refetch(a) => cmd::refetch::run(&cli.corpus, a),
        Command::FetchGoldens(a) => cmd::fetch_goldens::run(&cli.corpus, a),
        Command::ImportGolden(a) => cmd::import_golden::run(&cli.corpus, a),
        Command::Synth(a) => cmd::synth::run(&cli.corpus, a),
        Command::Slice(a) => cmd::slice::run(&cli.corpus, a),
        Command::Coverage(a) => cmd::coverage::run(&cli.corpus, a),
        Command::Index(a) => cmd::index::run(&cli.corpus, a),
        Command::GuideTable(a) => cmd::guide_table::run(&cli.corpus, a),
        Command::GuideClaims(a) => cmd::guide_claims::run(&cli.corpus, a),
        Command::Mainnet(a) => cmd::mainnet::run(&cli.corpus, a),
        Command::Scan(a) => cmd::scan::run(&cli.corpus, a),
    };
    match r {
        Ok(code) => code,
        Err(e) => {
            eprintln!("xdrcheck-corpus: {e:#}");
            std::process::ExitCode::from(2)
        }
    }
}
