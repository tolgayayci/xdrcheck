//! `xdrcheck-corpus slice <entry> <json-pointer> --id <new id> --type <XdrType>` — cut a contiguous
//! sub-value of a ledger entry's blob out as an `xdr` entry.
//!
//! 1. The parent variant's blob is rendered by the oracle (gate, limits, full round trip).
//! 2. The JSON at `<json-pointer>` is encoded as `--type`.
//! 3. Those bytes must occur in the parent blob: exactly once, or at `--offset`. The slice is
//!    therefore byte-identical to a range of the parent, and it must decode and re-encode to
//!    exactly that range.
//! 4. The slice is written as a blob, a sidecar and a variant with `slice_of {entry, path,
//!    byte_offset}`. The variant copies the parent's network, passphrase, protocol, ledger
//!    sequence and `source` (the bytes come from the same place). The manifest entry is updated if
//!    it exists, else a skeleton is written from the new ID's `plan.json` row (see `synth`).
//!
//! Exit codes: 0 written, 1 the slice cannot be cut, 2 tool error.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use super::render::{self, Oracle};
use super::synth;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Parent entry ID (a `ledger` or `xdr` entry).
    pub entry: String,
    /// JSON Pointer into the parent's decoded form.
    pub path: String,
    /// ID of the new `xdr` entry (must exist in `plan.json`).
    #[arg(long)]
    pub id: String,
    /// XDR type of the value at the pointer, e.g. `TransactionEnvelope`.
    #[arg(long = "type")]
    pub xdr_type: String,
    /// Parent variant (`network` or `network@protocol`); default: the first.
    #[arg(long)]
    pub variant: Option<String>,
    /// Byte offset of the slice in the parent blob, when the bytes occur more than once.
    #[arg(long)]
    pub offset: Option<usize>,
}

pub fn run(corpus: &Path, args: Args) -> Result<ExitCode> {
    let oracle = Oracle::new(corpus)?;
    xdrcheck_xdr::type_variant(&args.xdr_type)?;
    let parent_path = render::manifest_path(corpus, &args.entry);
    let parent: Value = serde_json::from_slice(
        &std::fs::read(&parent_path).with_context(|| format!("no parent entry {}", args.entry))?,
    )?;
    let row = synth::plan_row(corpus, &args.id)?;
    if row.kind != "xdr" {
        bail!(
            "plan.json says {} is a {} entry; a slice is an xdr entry",
            args.id,
            row.kind
        );
    }
    match cut(corpus, &oracle, &args, &parent, &row) {
        Ok(lines) => {
            lines.iter().for_each(|l| println!("{l}"));
            for line in render::collect_garbage(corpus, false)? {
                println!("{line}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            println!("FAIL slice {} {}: {e:#}", args.entry, args.path);
            Ok(ExitCode::from(1))
        }
    }
}

fn cut(
    corpus: &Path,
    oracle: &Oracle,
    args: &Args,
    parent: &Value,
    row: &synth::PlanRow,
) -> Result<Vec<String>> {
    let pv = synth::select_variant(parent, args.variant.as_deref())?;
    let parent_type = pv["xdr_type"].as_str().unwrap_or_default();
    let parent_blob = std::fs::read(render::blob_path(corpus, pv))?;
    let decoded = oracle.render(parent_type, &parent_blob)?;
    let Some(sub) = decoded.pointer(&args.path) else {
        bail!(
            "{} does not resolve in the parent's decoded form",
            args.path
        );
    };
    let bytes = xdrcheck_xdr::json_to_xdr(&args.xdr_type, sub, &oracle.limits)
        .with_context(|| format!("the value at {} is not a {}", args.path, args.xdr_type))?;
    let offset = locate(&parent_blob, &bytes, args.offset)?;
    // The slice must decode and re-encode to exactly the parent's byte range.
    let range = &parent_blob[offset..offset + bytes.len()];
    xdrcheck_xdr::roundtrip(&args.xdr_type, range, &oracle.limits)?;

    let mut lines = Vec::new();
    let blob = synth::write_blob(corpus, range)?;
    lines.push(format!(
        "slice of {} at bytes [{offset}, {}) -> {}",
        args.entry,
        offset + bytes.len(),
        blob["path"].as_str().unwrap_or("")
    ));
    let mut variant = serde_json::Map::new();
    for k in [
        "network",
        "passphrase",
        "protocol",
        "header_protocol",
        "ledger_seq",
    ] {
        if !pv[k].is_null() {
            variant.insert(k.into(), pv[k].clone());
        }
    }
    variant.insert("xdr_type".into(), json!(args.xdr_type));
    variant.insert(
        "xdr_definitions".into(),
        json!(synth::xdr_definitions(corpus)),
    );
    variant.insert("blob".into(), blob);
    variant.insert(
        "slice_of".into(),
        json!({ "entry": args.entry, "path": args.path, "byte_offset": offset }),
    );
    variant.insert("source".into(), pv["source"].clone());

    let manifest = render::manifest_path(corpus, &args.id);
    let mut entry = match std::fs::read(&manifest) {
        Ok(b) => serde_json::from_slice(&b)?,
        Err(_) => {
            lines.push(format!(
                "skeleton manifest/{}.json: author title, why and expect",
                args.id
            ));
            let mut s = synth::skeleton(&args.id, row, &format!("a slice of {}", args.entry));
            s["synthetic"] = parent["synthetic"].clone();
            s
        }
    };
    synth::upsert_variant(&mut entry, Value::Object(variant))?;
    synth::write_sidecars(corpus, oracle, &mut entry, range, &mut lines)?;
    std::fs::create_dir_all(manifest.parent().expect("manifest has a parent"))?;
    std::fs::write(&manifest, render::manifest_text(&entry))?;
    lines.push(format!("wrote manifest/{}.json", args.id));
    Ok(lines)
}

/// Where `needle` sits in `hay`: at `want` if given, else its only occurrence.
fn locate(hay: &[u8], needle: &[u8], want: Option<usize>) -> Result<usize> {
    if needle.is_empty() {
        bail!("the value encodes to no bytes");
    }
    if let Some(at) = want {
        if hay.get(at..at + needle.len()) == Some(needle) {
            return Ok(at);
        }
        bail!("the encoded value is not at offset {at} of the parent blob");
    }
    let hits: Vec<usize> = hay
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i)
        .take(10)
        .collect();
    match hits.as_slice() {
        [one] => Ok(*one),
        [] => bail!(
            "the encoded value does not occur in the parent blob (not a contiguous sub-value)"
        ),
        many => {
            bail!("the encoded value occurs at several offsets {many:?}; choose one with --offset")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locating() {
        let hay = [1, 2, 3, 1, 2];
        assert_eq!(locate(&hay, &[2, 3], None).unwrap(), 1);
        assert!(locate(&hay, &[1, 2], None).is_err());
        assert_eq!(locate(&hay, &[1, 2], Some(3)).unwrap(), 3);
        assert!(locate(&hay, &[9], None).is_err());
    }
}
