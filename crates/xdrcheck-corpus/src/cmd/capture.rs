//! `xdrcheck-corpus capture <network> <ledger> [--tx HASH] [--entry ID]` (network step):
//! fetch one public-lake object anonymously, keep it verbatim under
//! `corpus/objects/<network>/<seq>/` with its provenance in `capture.json`, and with `--entry` add
//! or update that entry's `history` variant (blob written to `corpus/blobs/`, focus on `--tx`).
//!
//! Re-capturing a vendored ledger checks the lake still serves the same bytes; if it does not,
//! nothing is overwritten and the command fails as a check (exit 1). See [`intake::lake`].
//!
//! A ledger above the corpus gate (`corpus.json` `max_protocol`: the network upgraded before the
//! pins moved) is captured with a warning when the pinned definitions still decode it, refused with
//! `--entry`, and, when it does not decode, kept under `<cache>/beyond-gate/` with an error naming
//! the unknown shape (exit 1).
//!
//! The shared intake code lives in `cmd/intake/` and is declared here, because the command
//! dispatch (`cmd/mod.rs`) is frozen; `refetch`, `fetch-goldens` and `import-golden` use it as
//! `super::intake`.
use std::path::Path;
use std::process::ExitCode;

use anyhow::Result;

use super::intake::lake::{self, Fetch, Network};
use super::intake::util::{exit_code, CheckFailed};

#[derive(clap::Args, Debug)]
pub struct Args {
    /// `pubnet` or `testnet` (the current testnet epoch pinned in pins.toml)
    pub network: String,
    /// Ledger sequence
    pub ledger: u32,
    /// Focus transaction (hash, hex); must be in the ledger
    #[arg(long)]
    pub tx: Option<String>,
    /// Manifest entry ID whose history variant to add or update
    #[arg(long)]
    pub entry: Option<String>,
}

pub fn run(corpus: &Path, args: Args) -> Result<ExitCode> {
    exit_code("capture", capture(corpus, &args))
}

fn capture(corpus: &Path, args: &Args) -> Result<bool> {
    let network = Network::parse(&args.network)?;
    let pins = super::intake::pins::Pins::load(corpus)?;
    let gate = xdrcheck_xdr::Gate::from_corpus_json(&corpus.join("corpus.json"))?.unwrap_or_default();
    let loc = lake::locate(&pins, network, args.ledger)?;
    eprintln!("fetching {}", loc.url);
    let fetched = match lake::fetch(&loc)? {
        Fetch::Found(f) => f,
        Fetch::Gone(status) => {
            return Err(CheckFailed(format!(
            "{} ledger {} is not in the lake (HTTP {status}): past the tip, or gone after a reset",
            network.name(),
            args.ledger
        ))
            .into())
        }
    };
    let out = match lake::capture_fetched(
        corpus,
        &pins,
        &gate,
        network,
        args.ledger,
        &fetched,
        args.tx.as_deref(),
        args.entry.as_deref(),
    ) {
        Ok(out) => out,
        Err(e) => return Err(beyond_gate(network, args.ledger, &gate, &fetched.object, e)),
    };
    let r = &out.record;
    println!(
        "{} {}: object {} ({} bytes, {}), decompressed {}, blob {} at offset {} ({} bytes)",
        r.network,
        r.ledger_seq,
        r.object_sha256,
        r.object_bytes,
        if out.object_unchanged {
            "identical to the vendored copy"
        } else {
            "new"
        },
        r.decompressed_sha256,
        r.blob_sha256,
        r.blob_offset,
        r.blob_bytes
    );
    println!(
        "protocol {}, {} transactions, written by {}, regenerated {}",
        r.ledger.protocol, r.ledger.tx_count, r.written_by, r.regenerated
    );
    if let Some(i) = out.tx_index {
        println!(
            "focus: transaction {} at apply index {i}",
            args.tx.as_deref().unwrap_or("")
        );
    }
    if let (Some(id), Some(u)) = (&args.entry, out.upsert) {
        println!("entry {id}: history variant {u:?}");
    }
    for w in &out.warnings {
        eprintln!("warning: {w}");
    }
    Ok(true)
}

/// A capture that failed on a ledger above the corpus gate: the network has a shape the pinned
/// definitions do not know. The object is kept, as served, under `<cache>/beyond-gate/` (a testnet
/// upgrade ledger does not stay available), and the error names the unknown shape. Any other
/// failure is returned as it was.
fn beyond_gate(
    network: Network,
    seq: u32,
    gate: &xdrcheck_xdr::Gate,
    object: &[u8],
    e: anyhow::Error,
) -> anyhow::Error {
    let Some(protocol) = lake::object_protocol(object).filter(|&p| gate.above_max(p).is_some())
    else {
        return e;
    };
    let unknown = super::mine::unknown_shapes(object);
    let kept = super::intake::golden::cache_root().and_then(|root| {
        let path = root
            .join("beyond-gate")
            .join(network.name())
            .join(seq.to_string())
            .join(
                lake::object_key(seq)
                    .rsplit('/')
                    .next()
                    .unwrap_or("object.xdr.zst"),
            );
        std::fs::create_dir_all(path.parent().expect("a parent"))?;
        super::intake::util::write_atomic(&path, object)?;
        Ok(path)
    });
    let kept = match kept {
        Ok(p) => format!("the object is kept at {}", p.display()),
        Err(k) => format!("the object could not be kept: {k:#}"),
    };
    CheckFailed(format!(
        "{} ledger {seq} has protocol {protocol}, above the corpus gate {}, and does not decode with \
         the pinned definitions ({unknown}); {kept}. The upgrade changed XDR shapes: follow the \
         upgrade procedure in docs/maintenance.md, section 5 (oracle error: {e:#})",
        network.name(),
        gate.max_protocol
    ))
    .into()
}
