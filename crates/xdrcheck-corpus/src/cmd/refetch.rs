//! `xdrcheck-corpus refetch [--network testnet|pubnet]` (network step, run nightly):
//! re-fetch every vendored lake object (`corpus/objects/*/*/capture.json`) and every `history`
//! variant's object that is not vendored, and compare each hash with the recorded one.
//!
//! Each object is reported `present` (same bytes), `CHANGED` (both hashes printed), `gone` (a
//! perishable testnet object whose source has disappeared: reported, not failed) or `GONE` (a
//! non-perishable object is missing). The vendored object and blob stay canonical in every case;
//! nothing is written. Exit 1 if anything changed or a non-perishable object is gone.
use std::collections::BTreeSet;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result};
use serde_json::Value;

use super::intake::lake::{self, Fetch, Network};
use super::intake::pins::Pins;
use super::intake::util::{exit_code, read_json};

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Only this network (`testnet` or `pubnet`)
    #[arg(long)]
    pub network: Option<String>,
}

/// One object to re-fetch.
struct Target {
    what: String,
    store: String,
    key: String,
    url: String,
    sha256: String,
    perishable: bool,
}

pub fn run(corpus: &Path, args: Args) -> Result<ExitCode> {
    exit_code("refetch", refetch(corpus, &args))
}

fn refetch(corpus: &Path, args: &Args) -> Result<bool> {
    let only = args.network.as_deref().map(Network::parse).transpose()?;
    let pins = Pins::load(corpus)?;
    let targets = targets(corpus, &pins, only)?;
    let (mut present, mut changed, mut gone, mut lost, mut errors) = (0, 0, 0, 0, 0);
    for t in &targets {
        match lake::get(&t.url) {
            Ok(Fetch::Found(bytes)) => {
                let sha = xdrcheck_xdr::sha256_hex(&bytes);
                if sha == t.sha256 {
                    present += 1;
                    println!("present  {}  {}", t.what, t.sha256);
                } else {
                    changed += 1;
                    println!("CHANGED  {}  recorded {}  lake {sha}", t.what, t.sha256);
                }
            }
            Ok(Fetch::Gone(status)) if t.perishable => {
                gone += 1;
                println!(
                    "gone     {}  HTTP {status}; perishable, the vendored copy is the only one",
                    t.what
                );
            }
            Ok(Fetch::Gone(status)) => {
                lost += 1;
                println!("GONE     {}  HTTP {status}  {}/{}", t.what, t.store, t.key);
            }
            Err(e) => {
                errors += 1;
                println!("ERROR    {}  {e:#}", t.what);
            }
        }
    }
    println!(
        "refetch: {} objects: {present} present, {changed} changed, {gone} gone (perishable), {lost} gone (not perishable), {errors} could not be fetched",
        targets.len()
    );
    anyhow::ensure!(errors == 0, "{errors} objects could not be fetched");
    Ok(changed == 0 && lost == 0)
}

/// Vendored captures first, then history variants whose object is not vendored.
fn targets(corpus: &Path, pins: &Pins, only: Option<Network>) -> Result<Vec<Target>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for network in [Network::Pubnet, Network::Testnet] {
        if only.is_some_and(|o| o != network) {
            continue;
        }
        let dir = corpus.join("objects").join(network.name());
        if !dir.is_dir() {
            continue;
        }
        let mut seqs: Vec<u32> = std::fs::read_dir(&dir)?
            .filter_map(|d| d.ok()?.file_name().to_str()?.parse().ok())
            .collect();
        seqs.sort_unstable();
        for seq in seqs {
            let record = lake::capture_dir(corpus, network, seq).join("capture.json");
            if !record.is_file() {
                continue;
            }
            let prior = lake::load_prior(&record)?;
            let v = read_json(&record)?;
            let loc = match (
                v.get("store").and_then(Value::as_str),
                v.get("key").and_then(Value::as_str),
            ) {
                (Some(store), Some(key)) => lake::Location {
                    url: lake::https_url(store, key)?,
                    store: store.to_string(),
                    key: key.to_string(),
                },
                _ => lake::locate(pins, network, seq)?,
            };
            seen.insert((loc.store.clone(), loc.key.clone()));
            out.push(Target {
                what: format!("{} {seq}", network.name()),
                store: loc.store,
                key: loc.key,
                url: loc.url,
                sha256: prior.object_sha256,
                perishable: network.perishable(),
            });
        }
    }
    for (id, v) in history_variants(corpus)? {
        let s = &v["source"];
        let field = |k: &str| {
            s.get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .with_context(|| format!("{id}: history source has no {k}"))
        };
        let (store, key) = (field("store")?, field("key")?);
        let network = v.get("network").and_then(Value::as_str).unwrap_or("");
        if only.is_some_and(|o| o.name() != network) || seen.contains(&(store.clone(), key.clone()))
        {
            continue;
        }
        seen.insert((store.clone(), key.clone()));
        out.push(Target {
            what: format!("{id} ({network})"),
            url: lake::https_url(&store, &key)?,
            store,
            key,
            sha256: field("object_sha256")?,
            perishable: s
                .get("perishable")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        });
    }
    Ok(out)
}

/// `(entry id, variant)` for every `history` variant in the manifest.
fn history_variants(corpus: &Path) -> Result<Vec<(String, Value)>> {
    let mut out = Vec::new();
    let root = corpus.join("manifest");
    if !root.is_dir() {
        return Ok(out);
    }
    let mut groups: Vec<_> = std::fs::read_dir(&root)?.filter_map(|d| d.ok()).collect();
    groups.sort_by_key(|d| d.file_name());
    for g in groups.iter().filter(|g| g.path().is_dir()) {
        let mut files: Vec<_> = std::fs::read_dir(g.path())?
            .filter_map(|d| d.ok())
            .collect();
        files.sort_by_key(|d| d.file_name());
        for f in files {
            let name = f.file_name().to_string_lossy().to_string();
            let Some(slug) = name.strip_suffix(".json") else {
                continue;
            };
            let id = format!("{}/{slug}", g.file_name().to_string_lossy());
            let e = read_json(&f.path())?;
            for v in e
                .get("variants")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if v["source"]["kind"] == "history" {
                    out.push((id.clone(), v.clone()));
                }
            }
        }
    }
    Ok(out)
}
