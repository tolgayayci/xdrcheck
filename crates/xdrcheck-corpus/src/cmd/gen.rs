//! `xdrcheck-corpus gen` — run scenarios on a local stellar-core and write corpus entries; `--check`
//! regenerates and compares with what is committed.
//!
//! ```text
//! xdrcheck-corpus gen <scenario>… [--network testnet|pubnet|core-test|both] [--protocol N,…]
//!                [--profile lake|golden-test|custom] [--runs DIR] [--keep]
//! xdrcheck-corpus gen --check (<scenario>… | --list FILE | --all) [--network …] [--protocol …]
//! ```
//!
//! A scenario argument is a path, or a path relative to the corpus root; the file must lie inside
//! the corpus root (entries cite it relative to the root). Without `--protocol` every protocol the
//! scenario lists runs; `--network both` (the default) runs testnet and pubnet, limited to the
//! scenario's `networks`.
//!
//! **Generate.** Every (scenario, protocol, network) runs in `<runs>/<scenario>/p<NN>-<network>`
//! (default `target/xdrcheck-runs`; an earlier run there is removed first). If any run's results differ
//! from the scenario's expectations, or testnet and pubnet twins disagree on a
//! passphrase-independent value, nothing is written and the exit code is 1. Otherwise each run's
//! blobs, sidecars, manifest variants, chain index and meta stream (`chains/<id>.meta.xdr.zst`) are
//! written into the corpus. When the chain is already committed and the fresh run passes the check
//! below against it, the committed stream's bytes are written again instead of the fresh ones (raw
//! meta bytes are not reproducible), so gen on an unchanged scenario changes nothing; a kept run
//! directory then holds the committed stream too. Run directories are removed unless `--keep` is
//! given (`xdrcheck-corpus chain-index <run dir>` works on a kept one). Last, blobs that no manifest
//! variant or chain index references any more (a replaced variant's old bytes) and sidecars that no
//! variant references are removed.
//!
//! **Check.** Every chain the scenario declares (its protocols × networks, filtered by `--network`
//! and `--protocol`) must have a committed index, and every `local-core` variant in the manifest
//! whose `source.scenario` is the scenario must have its blob on one of those chains; anything
//! missing is a difference. Each committed chain (`chains/<scenario>/*.json`, same filters) is
//! regenerated in a scratch directory under `<runs>` and compared: per ledger equal header hashes;
//! for every ledger with committed bytes (its blob, required for ledgers that hold entries, or its
//! record in the vendored stream) equal transaction hashes, equal results and byte-equal ledgers
//! after normalisation. Every difference is printed; exit 1 if there is one. `--list FILE` reads
//! scenario paths, one per line (`#` comments, paths relative to the list file); `--all` checks
//! every `scenarios/*.yaml`.
//!
//! **Binary.** A scenario's `binary:` picks the stellar-core it runs on: `release` (default; the pinned
//! release, or `XDRCHECK_STELLAR_CORE` / `XDRCHECK_STELLAR_CORE_MANIFEST`), `buildtests` or `vnext`, each resolved from
//! `pins.toml` and checked by sha256 ([`CoreBinary::locate_role`]). Only the binaries the given scenarios
//! name are looked up. **Channel gate:** a `vnext` scenario must declare `channel: next`, and a `next`
//! scenario must run on `vnext`; the schema already allows a protocol above the newest released one only
//! under `channel: next`.
//!
//! Run it with the network unreachable: `scripts/offline-run.sh xdrcheck-corpus gen …`. Exit codes: 0
//! success, 1 a result or check differs, 2 the tool could not run.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use xdrcheck_gen::core::binary::Role;
use xdrcheck_gen::core::{ClosePolicy, CoreBinary, MetaProfile};
use xdrcheck_gen::output::{
    chain_index_path, check_run, compare_twins, run as run_scenario, vendored_stream, write_run,
    ExpectationFailed, Network, RunRecord, RunRequest,
};
use xdrcheck_gen::scenario::Scenario;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Scenario files (paths, or relative to the corpus root).
    pub scenarios: Vec<PathBuf>,
    /// testnet, pubnet, core-test, or both (testnet and pubnet).
    #[arg(long, default_value = "both")]
    pub network: String,
    /// Protocols to run (default: the scenario's).
    #[arg(long, value_delimiter = ',')]
    pub protocol: Vec<u32>,
    /// Meta flag profile (default: the scenario's).
    #[arg(long)]
    pub profile: Option<String>,
    /// Regenerate and compare with the committed chains instead of writing.
    #[arg(long)]
    pub check: bool,
    /// File listing scenario paths, one per line (with --check).
    #[arg(long)]
    pub list: Option<PathBuf>,
    /// Every scenario under <corpus>/scenarios (with --check).
    #[arg(long)]
    pub all: bool,
    /// Directory for run directories.
    #[arg(long, default_value = "target/xdrcheck-runs")]
    pub runs: PathBuf,
    /// Keep the run directories.
    #[arg(long)]
    pub keep: bool,
    /// Close-time stride in seconds (default 1000000); changing it changes every header hash.
    #[arg(long, hide = true)]
    pub close_time_stride: Option<u64>,
}

/// One scenario to run, resolved.
pub(crate) struct Target {
    pub(crate) scenario: Scenario,
    /// Relative to the corpus root.
    pub(crate) rel: String,
    pub(crate) sha256: String,
}

pub fn run(corpus: &Path, args: Args) -> Result<ExitCode> {
    // A JSON scenario may nest values far deeper than the main thread's stack allows to walk
    // (placeholder resolution, template checks, conversion to XDR all recurse).
    xdrcheck_xdr::with_stack(xdrcheck_xdr::DEFAULT_STACK_SIZE, || run_on_stack(corpus, args))
}

fn run_on_stack(corpus: &Path, args: Args) -> Result<ExitCode> {
    let paths = scenario_paths(corpus, &args)?;
    if paths.is_empty() {
        bail!("no scenario given (pass files, --list FILE or --all)");
    }
    let targets = paths
        .iter()
        .map(|p| load(corpus, p))
        .collect::<Result<Vec<_>>>()?;
    let mut binaries = Binaries::new();
    for t in &targets {
        let role = target_role(t)?;
        if binaries.contains_key(&role) {
            continue;
        }
        let binary = CoreBinary::locate_role(role)?.ok_or_else(|| match role {
            Role::Release => anyhow!(
                "no stellar-core binary: run scripts/fetch.d/stellar-core.sh, or set XDRCHECK_STELLAR_CORE \
                 to the pinned binary"
            ),
            _ => anyhow!(
                "no {} stellar-core binary in the cache (pins.toml [{}]); fetch it first",
                role.name(),
                role.table()
            ),
        })?;
        binaries.insert(role, binary);
    }
    let mut policy = ClosePolicy::default();
    if let Some(s) = args.close_time_stride {
        policy.stride = s;
    }
    if args.check {
        check(corpus, &args, &binaries, policy, &targets)
    } else {
        generate(corpus, &args, &binaries, policy, &targets)
    }
}

/// The located binary of each role the scenarios name.
type Binaries = BTreeMap<Role, CoreBinary>;

/// The binary role a scenario runs on, after the channel gate: `vnext` only with `channel: next`, and
/// `channel: next` only on `vnext`.
pub(crate) fn target_role(t: &Target) -> Result<Role> {
    let role = Role::parse(&t.scenario.binary).map_err(|e| anyhow!("{}: {e}", t.rel))?;
    match (role, t.scenario.channel.as_str()) {
        (Role::Vnext, "next") | (Role::Release | Role::Buildtests, "stable") => Ok(role),
        (Role::Vnext, c) => bail!("{}: binary vnext needs channel: next (it says {c})", t.rel),
        (_, c) => bail!(
            "{}: channel {c} needs binary: vnext (it says {})",
            t.rel,
            role.name()
        ),
    }
}

/// The binary of a target, located by `run_on_stack`.
fn binary_for<'b>(binaries: &'b Binaries, t: &Target) -> Result<&'b CoreBinary> {
    let role = target_role(t)?;
    binaries
        .get(&role)
        .ok_or_else(|| anyhow!("{}: no {} binary was located", t.rel, role.name()))
}

fn generate(
    corpus: &Path,
    args: &Args,
    binaries: &Binaries,
    policy: ClosePolicy,
    targets: &[Target],
) -> Result<ExitCode> {
    let mut done: Vec<(RunRecord, Vec<u8>, PathBuf)> = Vec::new();
    let mut failed = false;
    for t in targets {
        let binary = binary_for(binaries, t)?;
        let (profile, golden) = profile_for(&t.scenario, args.profile.as_deref())?;
        for protocol in protocols(&t.scenario, &args.protocol)? {
            for network in networks(&t.scenario, &args.network)? {
                let dir = args.runs.join(xdrcheck_gen::output::run::run_dir_name(
                    &t.scenario.name,
                    protocol,
                    network,
                    profile.name(),
                ));
                fresh_dir(&dir)?;
                eprintln!("gen: {} protocol {protocol} {} ...", t.rel, network.name());
                let req = RunRequest {
                    scenario: &t.scenario,
                    scenario_path: t.rel.clone(),
                    scenario_sha256: t.sha256.clone(),
                    network,
                    protocol,
                    profile: profile.clone(),
                    golden_test: golden.clone(),
                    close_policy: policy,
                    run_dir: dir.clone(),
                    corpus_root: corpus.to_path_buf(),
                    explore: false,
                };
                match run_scenario(binary, &req) {
                    Ok(rec) => {
                        let stream = std::fs::read(dir.join(&rec.stream))?;
                        done.push((rec, stream, dir));
                    }
                    Err(e) if e.downcast_ref::<ExpectationFailed>().is_some() => {
                        eprintln!(
                            "FAIL {} protocol {protocol} {}: {e:#} (run kept in {})",
                            t.rel,
                            network.name(),
                            dir.display()
                        );
                        failed = true;
                    }
                    Err(e) => {
                        return Err(e.context(format!(
                            "{} protocol {protocol} {} (run kept in {})",
                            t.rel,
                            network.name(),
                            dir.display()
                        )))
                    }
                }
            }
        }
    }
    if failed {
        eprintln!("gen: nothing written");
        return Ok(ExitCode::from(1));
    }
    // Twins: testnet and pubnet runs of one scenario, protocol and profile.
    let mut by_key: BTreeMap<(String, u32, String), Vec<usize>> = BTreeMap::new();
    for (i, (rec, _, _)) in done.iter().enumerate() {
        by_key
            .entry((rec.scenario.clone(), rec.protocol, rec.profile.clone()))
            .or_default()
            .push(i);
    }
    let mut twin_diffs = Vec::new();
    for idx in by_key.values() {
        let find = |n: &str| idx.iter().find(|i| done[**i].0.network == n).copied();
        if let (Some(t), Some(p)) = (find("testnet"), find("pubnet")) {
            twin_diffs.extend(compare_twins(
                &done[t].0, &done[t].1, &done[p].0, &done[p].1,
            )?);
        }
    }
    if !twin_diffs.is_empty() {
        for d in &twin_diffs {
            eprintln!("FAIL twins: {d}");
        }
        eprintln!("gen: nothing written");
        return Ok(ExitCode::from(1));
    }
    for (rec, stream, dir) in &done {
        // A regeneration that `gen --check` would accept keeps the committed bytes, so running gen
        // twice on an unchanged scenario changes nothing.
        let committed = committed_equivalent(corpus, rec, stream)?;
        let s = write_run(corpus, rec, committed.as_deref().unwrap_or(stream))?;
        println!(
            "{} p{} {}: {} entries ({} new), {} blobs, {}{}",
            rec.scenario_name,
            rec.protocol,
            rec.network,
            s.entries.len(),
            s.created.len(),
            s.blobs.len(),
            s.chain,
            if committed.is_some() {
                " (bytes kept: normalised-identical to the committed chain)"
            } else {
                ""
            }
        );
        if !args.keep {
            std::fs::remove_dir_all(dir).ok();
        } else if let Some(kept) = &committed {
            // The kept run directory describes what the corpus holds, so `chain-index` on it gives
            // the index gen wrote.
            std::fs::write(dir.join(&rec.stream), kept)?;
        }
    }
    for line in collect_garbage(corpus)? {
        println!("{line}");
    }
    Ok(ExitCode::SUCCESS)
}

/// A replaced variant may leave its old blob and sidecar unreferenced: remove every blob no
/// manifest variant or chain index references, then every sidecar no variant references.
fn collect_garbage(corpus: &Path) -> Result<Vec<String>> {
    let mut lines = super::render::collect_blob_garbage(corpus, false)?;
    lines.extend(super::render::collect_garbage(corpus, false)?);
    Ok(lines)
}

/// The committed stream of this run's chain, when the chain is committed with a vendored stream and
/// the fresh run matches it as `gen --check` compares.
fn committed_equivalent(corpus: &Path, rec: &RunRecord, stream: &[u8]) -> Result<Option<Vec<u8>>> {
    let path = corpus.join(chain_index_path(rec));
    if !path.is_file() {
        return Ok(None);
    }
    let index: Value = serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("{} is not JSON", path.display()))?;
    let Some(old) = vendored_stream(corpus, &index)? else {
        return Ok(None);
    };
    Ok(check_run(corpus, &index, rec, stream)?.ok().then_some(old))
}

fn check(
    corpus: &Path,
    args: &Args,
    binaries: &Binaries,
    policy: ClosePolicy,
    targets: &[Target],
) -> Result<ExitCode> {
    let scratch = args.runs.join(format!("check-{}", std::process::id()));
    let mut differences = 0usize;
    let mut chains = 0usize;
    let variants = local_core_variants(corpus)?;
    for t in targets {
        let binary = binary_for(binaries, t)?;
        let committed = committed_chains(corpus, t, args)?;
        // Every chain the scenario declares (protocols × networks, as filtered) must be committed.
        let profile = args.profile.as_deref().unwrap_or(&t.scenario.profile);
        for protocol in protocols(&t.scenario, &args.protocol)? {
            for network in networks(&t.scenario, &args.network).unwrap_or_default() {
                let leaf = xdrcheck_gen::output::run::run_dir_name(
                    &t.scenario.name,
                    protocol,
                    network,
                    profile,
                );
                let id = leaf.to_string_lossy().replace('\\', "/");
                if !committed.iter().any(|(_, v)| v["id"] == id.as_str()) {
                    println!(
                        "FAIL {}: no committed chain index chains/{id}.json for protocol \
                         {protocol} {}",
                        t.rel,
                        network.name()
                    );
                    differences += 1;
                }
            }
        }
        // Every local-core variant generated from this scenario must lie on a chain that is checked.
        let reached: BTreeSet<&str> = committed
            .iter()
            .flat_map(|(_, v)| v["ledgers"].as_array().into_iter().flatten())
            .filter_map(|l| l["blob_sha256"].as_str())
            .collect();
        for v in variants.iter().filter(|v| v.scenario == t.rel) {
            let selected = (args.network == "both" || args.network == v.network)
                && (args.protocol.is_empty() || args.protocol.contains(&v.protocol));
            if selected && !reached.contains(v.blob.as_str()) {
                println!(
                    "FAIL {}: variant {}@{} of {} (blob {}) is on no committed chain of the scenario",
                    t.rel, v.network, v.protocol, v.entry, v.blob
                );
                differences += 1;
            }
        }
        for (path, index) in committed {
            chains += 1;
            let network = Network::parse(index["network"].as_str().unwrap_or(""))?;
            let protocol = index["protocol"]
                .as_u64()
                .and_then(|p| u32::try_from(p).ok())
                .ok_or_else(|| anyhow!("{}: no protocol", path.display()))?;
            let profile_name = index["profile"].as_str().unwrap_or("lake");
            let (profile, golden) = profile_for(&t.scenario, Some(profile_name))?;
            let dir = scratch.join(xdrcheck_gen::output::run::run_dir_name(
                &t.scenario.name,
                protocol,
                network,
                profile_name,
            ));
            fresh_dir(&dir)?;
            let req = RunRequest {
                scenario: &t.scenario,
                scenario_path: t.rel.clone(),
                scenario_sha256: t.sha256.clone(),
                network,
                protocol,
                profile,
                golden_test: golden,
                close_policy: policy,
                run_dir: dir.clone(),
                corpus_root: corpus.to_path_buf(),
                explore: false,
            };
            let id = index["id"].as_str().unwrap_or("?").to_string();
            let rec = match run_scenario(binary, &req) {
                Ok(rec) => rec,
                Err(e) if e.downcast_ref::<ExpectationFailed>().is_some() => {
                    println!("FAIL {id}: the regeneration does not meet the scenario: {e:#}");
                    differences += 1;
                    continue;
                }
                Err(e) => return Err(e.context(format!("regenerating {id}"))),
            };
            if rec.scenario_sha256 != index["scenario_sha256"].as_str().unwrap_or("") {
                println!("note {id}: the scenario file changed since the chain was committed");
            }
            let stream = std::fs::read(dir.join(&rec.stream))?;
            let outcome = check_run(corpus, &index, &rec, &stream)?;
            if outcome.ok() {
                println!(
                    "ok {id}: {} header hashes equal; {} ledgers equal in transactions, results and normalised bytes",
                    outcome.ledgers, outcome.blobs
                );
            } else {
                for d in &outcome.differences {
                    println!("FAIL {d}");
                }
                differences += outcome.differences.len();
            }
        }
    }
    if !args.keep {
        std::fs::remove_dir_all(&scratch).ok();
    }
    println!("gen --check: {chains} chains, {differences} differences");
    Ok(ExitCode::from(if differences == 0 { 0 } else { 1 }))
}

/// One `local-core` variant of a manifest entry.
struct LocalVariant {
    entry: String,
    scenario: String,
    network: String,
    protocol: u32,
    blob: String,
}

/// Every `local-core` variant in `manifest/`.
fn local_core_variants(corpus: &Path) -> Result<Vec<LocalVariant>> {
    let mut out = Vec::new();
    let mut dirs = vec![corpus.join("manifest")];
    while let Some(dir) = dirs.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd {
            let p = e?.path();
            if p.is_dir() {
                dirs.push(p);
                continue;
            }
            if p.extension().is_none_or(|x| x != "json") {
                continue;
            }
            let entry: Value = serde_json::from_slice(&std::fs::read(&p)?)
                .with_context(|| format!("{} is not JSON", p.display()))?;
            for v in entry["variants"].as_array().into_iter().flatten() {
                let src = &v["source"];
                if src["kind"] != "local-core" {
                    continue;
                }
                out.push(LocalVariant {
                    entry: entry["id"].as_str().unwrap_or("?").to_string(),
                    scenario: src["scenario"].as_str().unwrap_or("").to_string(),
                    network: v["network"].as_str().unwrap_or("").to_string(),
                    protocol: v["protocol"]
                        .as_u64()
                        .and_then(|p| u32::try_from(p).ok())
                        .unwrap_or(0),
                    blob: v["blob"]["sha256"].as_str().unwrap_or("").to_string(),
                });
            }
        }
    }
    Ok(out)
}

/// The committed chain indexes of a scenario, filtered by the command line.
fn committed_chains(corpus: &Path, t: &Target, args: &Args) -> Result<Vec<(PathBuf, Value)>> {
    let dir = corpus.join("chains").join(&t.scenario.name);
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    let nets: Vec<&str> = match args.network.as_str() {
        "both" => vec!["testnet", "pubnet", "core-test"],
        n => vec![n],
    };
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    for p in files {
        let v: Value = serde_json::from_slice(&std::fs::read(&p)?)
            .with_context(|| format!("{} is not JSON", p.display()))?;
        if v["scenario"] != t.rel.as_str() {
            continue;
        }
        if !nets.contains(&v["network"].as_str().unwrap_or("")) {
            continue;
        }
        let proto = v["protocol"].as_u64().unwrap_or(0);
        if !args.protocol.is_empty() && !args.protocol.iter().any(|p| u64::from(*p) == proto) {
            continue;
        }
        out.push((p, v));
    }
    Ok(out)
}

fn scenario_paths(corpus: &Path, args: &Args) -> Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = args.scenarios.clone();
    if let Some(list) = &args.list {
        let text =
            std::fs::read_to_string(list).with_context(|| format!("reading {}", list.display()))?;
        let base = list.parent().unwrap_or(Path::new("."));
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if !line.is_empty() {
                out.push(base.join(line));
            }
        }
    }
    if args.all {
        let dir = corpus.join("scenarios");
        let mut all: Vec<PathBuf> = std::fs::read_dir(&dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension()
                    .is_some_and(|e| e == "yaml" || e == "yml" || e == "json")
            })
            .collect();
        all.sort();
        out.extend(all);
    }
    Ok(out)
}

pub(crate) fn load(corpus: &Path, path: &Path) -> Result<Target> {
    let file = if path.is_file() {
        path.to_path_buf()
    } else {
        corpus.join(path)
    };
    let abs = file
        .canonicalize()
        .with_context(|| format!("scenario {} not found", path.display()))?;
    let root = corpus
        .canonicalize()
        .with_context(|| format!("corpus root {} not found", corpus.display()))?;
    let rel = abs
        .strip_prefix(&root)
        .map_err(|_| {
            anyhow!(
                "scenario {} is not inside the corpus root {}",
                abs.display(),
                root.display()
            )
        })?
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/");
    let bytes = std::fs::read(&abs)?;
    let scenario = Scenario::load(&abs).map_err(|e| anyhow!("{rel}: {e}"))?;
    Ok(Target {
        scenario,
        rel,
        sha256: xdrcheck_xdr::sha256_hex(&bytes),
    })
}

pub(crate) fn protocols(s: &Scenario, requested: &[u32]) -> Result<Vec<u32>> {
    if requested.is_empty() {
        return Ok(s.protocols.clone());
    }
    for p in requested {
        if !s.protocols.contains(p) {
            bail!("scenario {} does not list protocol {p}", s.name);
        }
    }
    Ok(requested.to_vec())
}

pub(crate) fn networks(s: &Scenario, requested: &str) -> Result<Vec<Network>> {
    let want: Vec<Network> = match requested {
        "both" => vec![Network::Testnet, Network::Pubnet],
        n => vec![Network::parse(n)?],
    };
    let out: Vec<Network> = want
        .into_iter()
        .filter(|n| s.networks.iter().any(|x| x == n.name()))
        .collect();
    if out.is_empty() {
        bail!(
            "scenario {} runs on {:?}, not on {requested}",
            s.name,
            s.networks
        );
    }
    Ok(out)
}

/// The meta profile and, for `golden-test`, the golden test it copies (from the first step's
/// `mirrors`: `core_golden.core_tag`, `core_golden.test_name`, `flags_source`).
pub(crate) fn profile_for(
    s: &Scenario,
    requested: Option<&str>,
) -> Result<(MetaProfile, Option<Value>)> {
    let flags: BTreeMap<String, bool> = s.profile_flags.clone();
    match requested.unwrap_or(&s.profile) {
        "lake" => Ok((MetaProfile::Lake, None)),
        "custom" if !flags.is_empty() => Ok((MetaProfile::Custom(flags), None)),
        "golden-test" if !flags.is_empty() => {
            let m = s
                .steps
                .iter()
                .find_map(|st| st.mirrors.clone())
                .ok_or_else(|| {
                    anyhow!(
                        "{}: the golden-test profile needs a step with mirrors",
                        s.name
                    )
                })?;
            let g = serde_json::json!({
                "core_tag": m["core_golden"]["core_tag"],
                "test_name": m["core_golden"]["test_name"],
                "flags_source": m["flags_source"],
            });
            if g.as_object()
                .is_some_and(|o| o.values().any(|v| !v.is_string()))
            {
                bail!(
                    "{}: mirrors must give core_golden.core_tag, core_golden.test_name and \
                     flags_source",
                    s.name
                );
            }
            Ok((MetaProfile::GoldenTest(flags), Some(g)))
        }
        "custom" | "golden-test" => {
            bail!("{}: profile_flags are required for that profile", s.name)
        }
        other => bail!("unknown profile {other:?} (lake, golden-test, custom)"),
    }
}

/// Remove an earlier run directory and create its parent.
pub(crate) fn fresh_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    if let Some(p) = dir.parent() {
        std::fs::create_dir_all(p)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A scratch corpus next to the test binary (inside the build's target directory).
    fn scratch(name: &str) -> PathBuf {
        let exe = std::env::current_exe().unwrap();
        let dir = exe
            .parent()
            .unwrap()
            .join("xdrcheck-test-scratch")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn put(corpus: &Path, rel: &str, bytes: &[u8]) {
        let p = corpus.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    fn blob(sha: &str) -> String {
        format!("blobs/{}/{sha}.xdr", &sha[..2])
    }

    fn sidecar(sha: &str) -> String {
        format!("decoded/{}/{sha}.json.zst", &sha[..2])
    }

    /// After a regeneration replaced a variant's blob, the old blob and its sidecar go; a blob a
    /// variant names, a blob only a chain index names, and files that are not blobs stay. An
    /// unreadable chain index keeps every blob.
    #[test]
    fn garbage_collection_removes_replaced_blobs() {
        let corpus = scratch("gen-gc").join("corpus");
        let (kept, chained, replaced) = ("aa".repeat(32), "bb".repeat(32), "cc".repeat(32));
        let variant = json!({"blob": {"sha256": kept, "bytes": 1, "path": blob(&kept)}, "decoded": sidecar(&kept)});
        put(
            &corpus,
            "manifest/group-x/entry.json",
            json!({"variants": [variant]}).to_string().as_bytes(),
        );
        put(
            &corpus,
            "chains/s/p1-testnet.json",
            json!({"ledgers": [{"seq": 2, "blob_sha256": chained}]})
                .to_string()
                .as_bytes(),
        );
        for sha in [&kept, &chained, &replaced] {
            put(&corpus, &blob(sha), b"x");
        }
        for sha in [&kept, &replaced] {
            put(&corpus, &sidecar(sha), b"x");
        }
        put(&corpus, "blobs/README", b"not a blob");

        let lines = collect_garbage(&corpus).unwrap();
        assert!(!corpus.join(blob(&replaced)).exists(), "{lines:?}");
        assert!(!corpus.join(sidecar(&replaced)).exists());
        assert!(!corpus.join("blobs/cc").exists(), "empty directory left");
        for f in [
            blob(&kept),
            blob(&chained),
            sidecar(&kept),
            "blobs/README".into(),
        ] {
            assert!(corpus.join(&f).exists(), "{f} removed");
        }
        assert!(lines
            .iter()
            .any(|l| l == &format!("removed {}", blob(&replaced))));

        // An unreadable chain index keeps every blob.
        put(&corpus, &blob(&replaced), b"x");
        put(&corpus, "chains/s/p2-testnet.json", b"{not json");
        collect_garbage(&corpus).unwrap();
        assert!(corpus.join(blob(&replaced)).exists());
        let _ = std::fs::remove_dir_all(corpus.parent().unwrap());

        // On the vendored corpus every blob is referenced (checked without writing).
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
        let stray = super::super::render::collect_blob_garbage(&repo, true).unwrap();
        assert!(stray.is_empty(), "{stray:?}");
    }
}
