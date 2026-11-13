//! `xdrcheck-corpus verify` — the oracle gate (`docs/manifest.md` §11).
//!
//! `verify [--tier curated|bulk] [--checks LIST] [--entries GLOB] [--report FILE] [--overlay DIR]`
//!
//! With `--overlay DIR` (a private overlay, `docs/conformance-protocol.md`), the curated tier is
//! the public corpus merged with `DIR/corpus`: its manifests, blobs and sidecars, with the ID
//! registry `plan.json` extended by `DIR/corpus/plan-rows.json`. An entry or plan row in both is a
//! tool error.
//!
//! Curated tier: every manifest entry under `<corpus>/manifest/` is checked; one result row per
//! entry × variant × check (entry-level checks have no variant). Checks:
//!
//! | check | applies to | what |
//! |---|---|---|
//! | `schema` | every entry, chain index, `corpus.json` | JSON Schema 2020-12 against `corpus/schema/`, plus the structural rules a schema cannot state (unique variant keys, `meta` on ledger variants, sidecars on positive variants, `expect.reject` and no sidecar on negative entries, `validity` on every entry with the flag of its reject reason and `core-lenient` exactly when stellar-core accepts, `protocol.introduced` ≤ variant protocol) |
//! | `ids` | every entry | path equals `id`; `id` is canonical in `plan.json`; unique; cited entry IDs canonical |
//! | `hashes` | `ledger`, `xdr`, `spec` variants | blob name, sha256 and length; sidecar `decoded_sha256`; `history`: vendored lake object → decompressed → blob at `blob_offset`; `history-archive`: HAS lists the bucket, object → gunzipped sha256 = bucket hash → record mark at `byte_offset` frames the blob; `local-core`: chain-index row agrees with the blob |
//! | `roundtrip` | `ledger`, positive `xdr` | decode with explicit limits, byte-exact re-encode, SEP-51 JSON → XDR byte-exact; a variant with `json_roundtrip.skip` keeps the byte round trip and skips JSON → XDR, which must still fail (else the exception is stale) |
//! | `reject` | negative `xdr` | the oracle must reject the bytes, with the reason class of `expect.reject.reason` where the oracle can tell; at `expect.reject.limits.depth` when stated; a `record-marked` variant is split into records first (record-mark faults are class `record_mark`) and record `frame_index` is decoded |
//! | `sidecar` | positive `ledger`, `xdr` | the sidecar equals a fresh rendering, compared as JSON values |
//! | `pinpoints` | positive `ledger`, `xdr` | `focus.path` and every `expect.values` path resolve in the sidecar and equal after `${derived.*}` substitution (a key-selected pinpoint, `select`, first resolves to the one array element with its ledger key: `verify/select.rs`); every token resolves; for ledgers, `derived.ledger_hash` is the header hash in the blob and transaction hashes are recomputed from the envelopes under the variant's passphrase; `meta.transaction_meta_version` equals the bytes (absent when there are no transactions) |
//! | `ag1` | `core-golden` variants | the blob equals frame `frame_index` of the golden file, whose sha256 is `file_sha256` |
//! | `ag3` | `core-golden` variants | the golden decodes and re-encodes byte-exactly in the oracle |
//! | `ag4` | `local-core` variants | the profile-free skeleton and the reduced shape tokens of the variant's own focus transaction equal those of its golden counterpart in `mirrors.json` (`mapped`), or every operation's reduced shape equals that of its golden operation (`operations`), recomputed from both sets of bytes; the list and the reverse coverage are complete and current; at least one row and every listed entry passing (`verify/ag4.rs`, `verify/ag4_shape.rs`); not in the default set: it needs the golden cache |
//! | `extractor` | positive `LedgerCloseMeta` variants | the reference extractor's facts agree with `expect` (participants, state changes, movements, whole-ledger receipts): a stated value it cannot derive fails unless the item carries `unverified` |
//! | `orphans` | the corpus (whole-corpus runs only) | every blob, sidecar and chain index is reached from a manifest entry |
//! | `spec` | `spec` variants | the corpus's own section reader (`xdrcheck_xdr::spec`) re-reads the blob (a Wasm module's `contractspecv0` sections, or a bare `SCSpecEntry` stream) and its facts equal `expect.spec`; a negative entry's bytes must not be a clean single-section spec |
//!
//! `pinpoints` also compares `variants[].requires` with the XDR features derived from the sidecar
//! and `variants[].derived.l1` with the values the focus implies (`xdrcheck_meta::derive`); `schema`
//! also parses every known-divergence version range (`verify/ranges.rs`).
//!
//! Bulk tier (`corpus.json` `tiers.bulk`): every golden file listed in the `file_index` is read from
//! the golden cache. `hashes` checks each file's sha256, `roundtrip` decodes, re-encodes and
//! JSON-round-trips every record, `ag3` decodes and re-encodes every record. Default: `hashes`,
//! `roundtrip`.
//!
//! Golden cache: `--goldens DIR`, else `$XDRCHECK_GOLDENS`, else `$HOME/.cache/xdrcheck/goldens`. A golden file
//! named `file` (a path inside the stellar-core repository) at tag `T` is read from
//! `<DIR>/<T>/<file>`.
//!
//! Exit codes: 0 every check passed, 1 a check failed, 2 the tool could not run.

mod ag4;
pub(crate) mod ag4_shape;
mod bulk;
mod checks;
mod ledger;
pub(crate) mod load;
mod model;
mod orphans;
mod ranges;
pub(crate) mod report;
mod select;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};

use model::{Check, Ctx, Row};

/// Which tier to verify.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// The in-repository corpus (`manifest/`, `blobs/`, `decoded/`).
    Curated,
    /// The golden set listed in `corpus.json` `tiers.bulk`, read from the golden cache.
    Bulk,
    /// The next-protocol golden set listed in `corpus.json` `tiers.bulk-next`, read from the golden
    /// cache under the protocol gate `--max-protocol` lifts it to.
    BulkNext,
}

impl Tier {
    fn name(self) -> &'static str {
        match self {
            Tier::Curated => "curated",
            Tier::Bulk => "bulk",
            Tier::BulkNext => "bulk-next",
        }
    }

    /// A golden tier (bulk or bulk-next), read from the golden cache.
    fn is_golden(self) -> bool {
        matches!(self, Tier::Bulk | Tier::BulkNext)
    }
}

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Tier to verify.
    #[arg(long, value_enum, default_value = "curated")]
    pub tier: Tier,
    /// Comma-separated checks: schema, hashes, ids, roundtrip, reject, sidecar, pinpoints, ag1,
    /// ag3, ag4, extractor, orphans, spec. Default: every check that applies to the tier except ag4.
    #[arg(long, value_delimiter = ',')]
    pub checks: Option<Vec<String>>,
    /// Only entries whose ID matches this glob (`*` and `?`); on the bulk tier, golden file paths.
    #[arg(long)]
    pub entries: Option<String>,
    /// Write an `xcc.report/v1` report to this file.
    #[arg(long)]
    pub report: Option<PathBuf>,
    /// The pins file (only read for the report header).
    #[arg(long, default_value = "pins.toml")]
    pub pins: PathBuf,
    /// Golden cache root (default `$XDRCHECK_GOLDENS`, else `$HOME/.cache/xdrcheck/goldens`).
    #[arg(long)]
    pub goldens: Option<PathBuf>,
    /// With `ag4` on a whole-corpus run: search the golden set again and rewrite
    /// `<corpus>/mirrors.json` (the local-core entries' golden counterparts) before checking.
    #[arg(long)]
    pub write_mirrors: bool,
    /// Private overlay directory: verify the public corpus merged with `DIR/corpus` (manifests,
    /// blobs, sidecars; `DIR/corpus/plan-rows.json` adds to `plan.json`). Curated tier only.
    #[arg(long)]
    pub overlay: Option<PathBuf>,
    /// With --tier bulk-next (and only with it, where it is required): the protocol of the next-protocol
    /// goldens. The oracle's protocol gate is raised to N for this run only, to see what the pinned
    /// definitions fail on; corpus.json can never raise it.
    #[arg(long, value_name = "N")]
    pub max_protocol: Option<u32>,
}

pub fn run(corpus: &Path, args: Args) -> Result<ExitCode> {
    if !corpus.join("manifest").is_dir() && args.tier == Tier::Curated {
        bail!(
            "{}: not a corpus root (no manifest/ directory)",
            corpus.display()
        );
    }
    let checks = select_checks(args.tier, args.checks.as_deref())?;
    if args.write_mirrors && !checks.contains(&Check::Ag4) {
        bail!("--write-mirrors needs the ag4 check (--checks ag4)");
    }
    match (args.tier, args.max_protocol) {
        (Tier::BulkNext, None) => bail!("--tier bulk-next needs --max-protocol N"),
        (Tier::Curated | Tier::Bulk, Some(_)) => {
            bail!("--max-protocol applies to --tier bulk-next only")
        }
        _ => {}
    }
    let mut ctx = Ctx::new(corpus, goldens_root(args.goldens))?;
    if let Some(n) = args.max_protocol {
        ctx.gate.max_protocol = n;
    }
    ctx.write_mirrors = args.write_mirrors;
    if let Some(ov) = &args.overlay {
        if args.tier != Tier::Curated {
            bail!("--overlay applies to the curated tier only");
        }
        if args.write_mirrors {
            bail!("--write-mirrors rewrites the public mirrors.json; run it without --overlay");
        }
        let dir = ov.join("corpus");
        if !dir.join("manifest").is_dir() {
            bail!(
                "--overlay {}: no corpus/manifest/ directory in the overlay",
                ov.display()
            );
        }
        ctx.overlay = Some(dir);
    }

    let started = std::time::Instant::now();
    let (rows, counts) = match args.tier {
        Tier::Curated => checks::run_curated(&ctx, &checks, args.entries.as_deref())?,
        Tier::Bulk | Tier::BulkNext => {
            bulk::run_bulk(&ctx, &checks, args.entries.as_deref(), args.tier.name())?
        }
    };

    report::print_summary(args.tier, &checks, &rows, &counts);
    if let Some(path) = &args.report {
        let pins = find_pins(corpus, &args.pins)?;
        report::write_report(
            &ctx,
            args.tier,
            &rows,
            &counts,
            &pins,
            path,
            started.elapsed(),
        )
        .with_context(|| format!("writing report {}", path.display()))?;
    }
    let failed = rows.iter().any(|r: &Row| !r.ok);
    Ok(ExitCode::from(if failed { 1 } else { 0 }))
}

/// Parse `--checks`, or choose the default for the tier. Unknown names and checks that are not
/// built are tool errors.
fn select_checks(tier: Tier, requested: Option<&[String]>) -> Result<Vec<Check>> {
    let Some(names) = requested else {
        return Ok(match tier {
            Tier::Curated => vec![
                Check::Schema,
                Check::Ids,
                Check::Hashes,
                Check::Roundtrip,
                Check::Reject,
                Check::Sidecar,
                Check::Pinpoints,
                Check::Ag1,
                Check::Ag3,
                Check::Extractor,
                Check::Orphans,
                Check::Spec,
            ],
            Tier::Bulk | Tier::BulkNext => vec![Check::Hashes, Check::Roundtrip],
        });
    };
    let mut out = Vec::new();
    for n in names.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let c = Check::parse(n).with_context(|| format!("unknown check {n:?}"))?;
        if tier.is_golden() && !matches!(c, Check::Hashes | Check::Roundtrip | Check::Ag3) {
            bail!(
                "check {} does not apply to the bulk tier (hashes, roundtrip, ag3 do)",
                c.name()
            );
        }
        if !out.contains(&c) {
            out.push(c);
        }
    }
    if out.is_empty() {
        bail!("--checks is empty");
    }
    Ok(out)
}

fn goldens_root(flag: Option<PathBuf>) -> PathBuf {
    if let Some(p) = flag {
        return p;
    }
    if let Some(p) = std::env::var_os("XDRCHECK_GOLDENS").filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    xdrcheck_xdr::userdir::home_cache()
        .unwrap_or_else(|| PathBuf::from(".cache/xdrcheck"))
        .join("goldens")
}

/// The pins file: as given, else next to the corpus root (`<corpus>/../pins.toml`).
fn find_pins(corpus: &Path, flag: &Path) -> Result<PathBuf> {
    if flag.is_file() {
        return Ok(flag.to_path_buf());
    }
    if flag == Path::new("pins.toml") {
        let alt = corpus.join("..").join("pins.toml");
        if alt.is_file() {
            return Ok(alt);
        }
    }
    bail!(
        "pins file {} not found (needed for the report header)",
        flag.display()
    )
}
