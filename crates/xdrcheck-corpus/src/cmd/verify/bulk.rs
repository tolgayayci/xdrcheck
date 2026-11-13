//! The bulk tier: stellar-core's golden files at the pinned tag, listed in `corpus.json`
//! `tiers.bulk.file_index` (a `sha256sum`-format file, paths relative to the stellar-core
//! repository root) and read from `<goldens>/<tiers.bulk.ref>/<path>`. One row per file × check. The
//! next-protocol tier `bulk-next` reads `tiers.bulk-next` the same way.

use anyhow::{bail, Context, Result};

use super::load;
use super::model::{Check, Counts, Ctx, Row};

pub fn run_bulk(
    ctx: &Ctx,
    checks: &[Check],
    glob: Option<&str>,
    tier: &str,
) -> Result<(Vec<Row>, Counts)> {
    let Some(bulk) = ctx.corpus_json.as_ref().map(|c| &c["tiers"][tier]) else {
        bail!("the {tier} tier needs corpus.json with tiers.{tier}; there is no corpus.json");
    };
    let (Some(tag), Some(index)) = (bulk["ref"].as_str(), bulk["file_index"].as_str()) else {
        bail!("corpus.json tiers.{tier} needs `ref` and `file_index`");
    };
    let index_path = ctx.corpus.join(index);
    let text = std::fs::read_to_string(&index_path)
        .with_context(|| format!("reading the bulk file index {}", index_path.display()))?;
    let root = ctx.goldens.join(tag);
    if !root.is_dir() {
        bail!(
            "golden cache {} does not exist; run `xdrcheck-corpus fetch-goldens {tag}` or pass --goldens",
            root.display()
        );
    }
    let mut rows = Vec::new();
    let mut counts = Counts::default();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((sha, file)) = line.split_once("  ") else {
            bail!("{}:{}: not `<sha256>  <path>`", index_path.display(), n + 1);
        };
        let file = file.trim_start_matches('*');
        // Index paths are relative to the stellar-core repository root; an index written
        // relative to the tier directory (`tiers.bulk.path`) is accepted too.
        let file = match bulk["path"].as_str() {
            Some(dir) if !file.starts_with(&format!("{dir}/")) => format!("{dir}/{file}"),
            _ => file.to_string(),
        };
        let file = file.as_str();
        if glob.is_some_and(|g| !load::glob_match(g, file)) {
            continue;
        }
        counts.add("bulk_files", 1);
        let subject = format!("bulk:{file}");
        let data = std::fs::read(root.join(file));
        for &c in checks {
            let problems = match (&data, c) {
                (Err(e), _) => vec![format!("{file}: {e}")],
                (Ok(d), Check::Hashes) => {
                    let got = xdrcheck_xdr::sha256_hex(d);
                    if got == sha {
                        vec![]
                    } else {
                        vec![format!("sha256 is {got}, index says {sha}")]
                    }
                }
                (Ok(d), Check::Roundtrip) => records(ctx, d, true, &mut counts),
                (Ok(d), Check::Ag3) => records(ctx, d, false, &mut counts),
                _ => continue,
            };
            rows.push(Row::new(c, &subject, Some("core-test"), problems));
        }
    }
    Ok((rows, counts))
}

/// Split a golden file and check every record: decode and re-encode byte-exactly, and with
/// `json` also the SEP-51 JSON round trip. Problems name the record index.
fn records(ctx: &Ctx, data: &[u8], json: bool, counts: &mut Counts) -> Vec<String> {
    let mut problems = Vec::new();
    let mut n = 0;
    // Records are checked as they are split, so a bad mark is reported at its own record.
    for r in xdrcheck_xdr::records(data) {
        let r = match r {
            Ok(r) => r,
            Err(e) => {
                problems.push(e.to_string());
                break;
            }
        };
        n += 1;
        let res =
            xdrcheck_xdr::framing::check_record("LedgerCloseMeta", &r, &ctx.limits).and_then(|()| {
                if json {
                    super::checks::oracle_decode(ctx, "LedgerCloseMeta", r.payload, true)
                        .map(|_| ())
                } else {
                    Ok(())
                }
            });
        if let Err(e) = res {
            let framing = matches!(e, xdrcheck_xdr::Error::Framing(_));
            problems.push(format!("record {}: {e}", r.index));
            // After a framing fault the following marks are misaligned; stop there.
            if framing || problems.len() >= 10 {
                break;
            }
        }
    }
    counts.add(
        if json {
            "bulk_ledgers_roundtrip"
        } else {
            "bulk_ledgers_ag3"
        },
        n,
    );
    problems
}
