//! Range plans for a scan: ledger segments cut into units at lake-partition boundaries (and, with
//! `--max-unit-ledgers`, inside partitions), each weighted by its compressed bytes plus a fixed
//! per-ledger cost, listed newest → oldest. Units are dealt to `N` workers by a deterministic
//! largest-first rule, so N machines or processes given the same plan agree on who scans what
//! without a coordinator. Each unit is one output directory with its own journal, so a unit resumes
//! on its own. Bytes come from the lake listing (`list-lake`) when given, else from a sampled size
//! model. `verify` proves, partition directory by partition directory (bounded memory), that run
//! directories hold every planned ledger exactly once.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::record::Field;

const PART: u32 = 64_000;

/// One unit of a plan.
#[derive(Debug, Clone, PartialEq)]
pub struct Unit {
    pub partition: String,
    pub first: u32,
    pub last: u32,
    pub est_bytes: u64,
    pub weight: u64,
}

impl Unit {
    /// The output directory name: the lake partition's name when the unit is the whole partition,
    /// else `<partition>~<first>-<last>`.
    pub fn name(&self) -> String {
        let p = self.first / PART * PART;
        if self.first == p && self.last == p + PART - 1 {
            self.partition.clone()
        } else {
            format!("{}~{}-{}", self.partition, self.first, self.last)
        }
    }
}

#[derive(clap::Args, Debug)]
pub struct PlanArgs {
    /// First ledger (with --tip; or give --segment)
    #[arg(long)]
    pub first: Option<u32>,
    /// Fixed tip (last ledger)
    #[arg(long)]
    pub tip: Option<u32>,
    /// A segment `A-B` (inclusive); repeatable, instead of --first/--tip
    #[arg(long = "segment")]
    pub segments: Vec<String>,
    /// Largest unit, in ledgers (default: a whole lake partition)
    #[arg(long, default_value_t = PART)]
    pub max_unit_ledgers: u32,
    /// Runs whose `ledgers.parquet` give a sampled size model (object bytes of sampled ledgers)
    #[arg(long = "size-run")]
    pub size_runs: Vec<PathBuf>,
    /// Lake listing directory (`scan list-lake`): exact object sizes; preferred over --size-run
    #[arg(long)]
    pub listing: Option<PathBuf>,
    /// Fixed cost of one ledger, in bytes-equivalents
    #[arg(long, default_value_t = 150_000)]
    pub fixed_cost_bytes: u64,
    /// Output plan file
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct VerifyArgs {
    /// Range plan
    #[arg(long)]
    pub ranges: PathBuf,
    /// Run directories (all workers' outputs, or one worker's with --worker)
    #[arg(long = "run", required = true)]
    pub runs: Vec<PathBuf>,
    /// Check only the units of this worker (with --workers)
    #[arg(long)]
    pub worker: Option<usize>,
    #[arg(long, default_value_t = 1)]
    pub workers: usize,
    /// Units left to another machine (`scan run --skip-units`): not expected here
    #[arg(long)]
    pub skip_units: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct MergeArgs {
    /// Range plan
    #[arg(long)]
    pub ranges: PathBuf,
    /// Run directories to merge
    #[arg(long = "run", required = true)]
    pub runs: Vec<PathBuf>,
    /// Merged run directory (unit directories are hard-linked or copied)
    #[arg(long)]
    pub into: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct ListArgs {
    /// First ledger
    #[arg(long)]
    pub first: u32,
    /// Last ledger
    #[arg(long)]
    pub tip: u32,
    /// Bucket endpoint
    #[arg(
        long,
        default_value = "https://aws-public-blockchain.s3.us-east-2.amazonaws.com"
    )]
    pub endpoint: String,
    /// Key prefix of the pubnet ledgers
    #[arg(long, default_value = "v1.1/stellar/ledgers/pubnet")]
    pub prefix: String,
    /// Parallel list calls (at most 8)
    #[arg(long, default_value_t = 8)]
    pub parallel: usize,
    /// Output directory: one `<partition>.tsv` per partition (an existing file is skipped: resumable)
    #[arg(long)]
    pub out: PathBuf,
}

fn partition_name(p: u32) -> String {
    format!("{:08X}--{}-{}", u32::MAX - p, p, p + PART - 1)
}

/// Object bytes of every ledger in the runs' `ledgers.parquet` files.
pub fn ledger_sizes(runs: &[PathBuf]) -> Result<BTreeMap<u32, u64>> {
    let mut m = BTreeMap::new();
    for run in runs {
        for p in super::store::partitions(run)? {
            let r = SerializedFileReader::new(File::open(p.join("ledgers.parquet"))?)?;
            for row in r.get_row_iter(None)? {
                let row = row?;
                let f: Vec<&Field> = row.get_column_iter().map(|(_, f)| f).collect();
                if let (Field::Int(s), Field::Long(b)) = (f[0], f[1]) {
                    m.insert(*s as u32, *b as u64);
                }
            }
        }
    }
    Ok(m)
}

/// Object sizes from a listing directory, for the partitions of `[lo, hi]`.
fn listing_sizes(dir: &Path, lo: u32, hi: u32) -> Result<BTreeMap<u32, u64>> {
    let mut m = BTreeMap::new();
    for p in lo / PART..=hi / PART {
        let f = dir.join(format!("{}.tsv", partition_name(p * PART)));
        let t = std::fs::read_to_string(&f).with_context(|| format!("listing {}", f.display()))?;
        for l in t.lines().skip(1) {
            let c: Vec<&str> = l.split('\t').collect();
            if c.len() >= 3 {
                m.insert(c[0].parse()?, c[2].parse()?);
            }
        }
    }
    Ok(m)
}

fn segments(a: &PlanArgs) -> Result<Vec<(u32, u32)>> {
    let mut v = Vec::new();
    if let (Some(f), Some(t)) = (a.first, a.tip) {
        v.push((f, t));
    }
    for s in &a.segments {
        let (x, y) = s.split_once('-').context("segment is A-B")?;
        v.push((x.parse()?, y.parse()?));
    }
    ensure!(!v.is_empty(), "give --first/--tip or --segment");
    v.sort();
    for w in v.windows(2) {
        ensure!(w[0].1 < w[1].0, "segments overlap");
    }
    for (x, y) in &v {
        ensure!(x <= y, "segment {x}-{y} is empty");
    }
    Ok(v)
}

pub fn plan(a: PlanArgs) -> Result<()> {
    let segs = segments(&a)?;
    let (lo, hi) = (segs[0].0, segs.last().unwrap().1);
    let (model, sizes) = if let Some(d) = &a.listing {
        let s = listing_sizes(d, lo, hi)?;
        (
            format!("lake listing {} ({} objects)", d.display(), s.len()),
            s,
        )
    } else {
        ensure!(!a.size_runs.is_empty(), "give --listing or --size-run");
        let s = ledger_sizes(&a.size_runs)?;
        (format!("mean object bytes of {} sampled ledgers per lake partition (nearest-neighbour fill)", s.len()), s)
    };
    ensure!(!sizes.is_empty(), "the size model holds no ledgers");
    let exact = a.listing.is_some();
    let mut per: BTreeMap<u32, (u64, u64)> = BTreeMap::new();
    for (s, b) in &sizes {
        let e = per.entry(s / PART).or_default();
        e.0 += b;
        e.1 += 1;
    }
    let mean = |p: u32| -> f64 {
        if let Some((b, n)) = per.get(&p) {
            return *b as f64 / *n as f64;
        }
        let x = per
            .range(..p)
            .next_back()
            .map(|(_, (b, n))| *b as f64 / *n as f64);
        let y = per
            .range(p..)
            .next()
            .map(|(_, (b, n))| *b as f64 / *n as f64);
        match (x, y) {
            (Some(x), Some(y)) => (x + y) / 2.0,
            (Some(x), None) | (None, Some(x)) => x,
            _ => 0.0,
        }
    };
    let mut units = Vec::new();
    let mut unlisted = 0u64;
    for &(first, tip) in segs.iter().rev() {
        for p in (first / PART..=tip / PART).rev() {
            let plo = (p * PART).max(first);
            let phi = (p * PART + PART - 1).min(tip);
            // Split the partition into pieces of at most max_unit_ledgers, newest piece first.
            let step = a.max_unit_ledgers.clamp(1, PART);
            let mut pieces = Vec::new();
            let mut s = plo;
            loop {
                let e = s.saturating_add(step - 1).min(phi);
                pieces.push((s, e));
                if e == phi {
                    break;
                }
                s = e + 1;
            }
            for (ulo, uhi) in pieces.into_iter().rev() {
                let n = (uhi - ulo + 1) as u64;
                let est = if exact {
                    let got: u64 = sizes.range(ulo..=uhi).map(|(_, b)| *b).sum();
                    unlisted += n - sizes.range(ulo..=uhi).count() as u64;
                    got
                } else {
                    (mean(p) * n as f64) as u64
                };
                units.push(Unit {
                    partition: partition_name(p * PART),
                    first: ulo,
                    last: uhi,
                    est_bytes: est,
                    weight: est + n * a.fixed_cost_bytes,
                });
            }
        }
    }
    let segtext: Vec<String> = segs.iter().map(|(x, y)| format!("{x}-{y}")).collect();
    let mut t = format!(
        "# xdrcheck scan range plan\n# segments={}\n# max_unit_ledgers={}\n# fixed_cost_bytes={}\n# size_model={model}\nunit\tpartition\tfirst\tlast\tledgers\test_bytes\tweight\n",
        segtext.join(","),
        a.max_unit_ledgers,
        a.fixed_cost_bytes
    );
    for (i, u) in units.iter().enumerate() {
        t.push_str(&format!(
            "{i}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            u.partition,
            u.first,
            u.last,
            u.last - u.first + 1,
            u.est_bytes,
            u.weight
        ));
    }
    super::store::write_atomic(&a.out, t.as_bytes())?;
    let total: u64 = units.iter().map(|u| u.weight).sum();
    let ledgers: u64 = segs.iter().map(|(x, y)| (y - x + 1) as u64).sum();
    eprintln!(
        "{} units, {ledgers} ledgers, est. {:.2} GB objects, weight {total}{}",
        units.len(),
        units.iter().map(|u| u.est_bytes).sum::<u64>() as f64 / 1e9,
        if exact {
            format!("; {unlisted} planned ledgers have no listed object")
        } else {
            String::new()
        }
    );
    Ok(())
}

pub fn read(path: &Path) -> Result<(Vec<Unit>, String)> {
    let text = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
    let mut units = Vec::new();
    for l in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with("unit\t") && !l.trim().is_empty())
    {
        let f: Vec<&str> = l.split('\t').collect();
        ensure!(f.len() == 7, "bad plan line {l}");
        units.push(Unit {
            partition: f[1].to_string(),
            first: f[2].parse()?,
            last: f[3].parse()?,
            est_bytes: f[5].parse()?,
            weight: f[6].parse()?,
        });
    }
    Ok((units, xdrcheck_xdr::sha256_hex(text.as_bytes())))
}

/// Static assignment: units by weight (largest first, then name) to the least-loaded worker (lowest id
/// on ties). Returns the unit indexes of `worker`.
pub fn assign(units: &[Unit], workers: usize, worker: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..units.len()).collect();
    order.sort_by(|&a, &b| {
        units[b]
            .weight
            .cmp(&units[a].weight)
            .then(units[a].name().cmp(&units[b].name()))
    });
    let mut load = vec![0u64; workers.max(1)];
    let mut mine = Vec::new();
    for i in order {
        let w = (0..load.len()).min_by_key(|&w| (load[w], w)).unwrap();
        load[w] += units[i].weight;
        if w == worker {
            mine.push(i);
        }
    }
    mine.sort();
    mine
}

/// The ledgers of the units `worker` of `workers` scans.
pub fn assigned_seqs(path: &Path, workers: usize, worker: usize) -> Result<(Vec<u32>, String)> {
    ensure!(worker < workers.max(1), "worker {worker} of {workers}");
    let (units, sha) = read(path)?;
    let mut seqs = Vec::new();
    for i in assign(&units, workers, worker) {
        seqs.extend(units[i].first..=units[i].last);
    }
    Ok((seqs, sha))
}

/// Ledgers and refusals of one finished unit directory.
fn unit_seqs(dir: &Path) -> Result<Vec<u32>> {
    let mut v = Vec::new();
    for name in ["ledgers.parquet", "refusals.parquet"] {
        let p = dir.join(name);
        if !p.exists() {
            continue;
        }
        let r = SerializedFileReader::new(File::open(p)?)?;
        for row in r.get_row_iter(None)? {
            let row = row?;
            if let Some((_, Field::Int(s))) = row.get_column_iter().next() {
                v.push(*s as u32);
            }
        }
    }
    Ok(v)
}

/// Unit names from a file, one per line; a `w<i>/` prefix (as in a moved-units list) is ignored.
pub fn read_skip(path: &Path) -> Result<BTreeSet<String>> {
    let t = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
    Ok(t.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.rsplit('/').next().unwrap_or(l).to_string())
        .collect())
}

/// Every expected unit present once, each holding exactly its ledgers. Memory: one unit at a time.
pub fn verify(a: VerifyArgs) -> Result<bool> {
    let (units, _) = read(&a.ranges)?;
    let expected: BTreeMap<String, (u32, u32)> = match a.worker {
        Some(w) => assign(&units, a.workers, w)
            .into_iter()
            .map(|i| (units[i].name(), (units[i].first, units[i].last)))
            .collect(),
        None => units
            .iter()
            .map(|u| (u.name(), (u.first, u.last)))
            .collect(),
    };
    let mut expected = expected;
    if let Some(f) = &a.skip_units {
        let skip = read_skip(f)?;
        expected.retain(|k, _| !skip.contains(k));
    }
    let all: BTreeSet<String> = units.iter().map(|u| u.name()).collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let (mut found, mut missing, mut dup, mut extra) = (0u64, 0u64, 0u64, 0u64);
    let mut bad = Vec::new();
    for run in &a.runs {
        for p in super::store::partitions(run)? {
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            let Some(&(lo, hi)) = expected.get(&name) else {
                bad.push(format!(
                    "{}: {}",
                    p.display(),
                    if all.contains(&name) {
                        "another worker's unit"
                    } else {
                        "not in the plan"
                    }
                ));
                continue;
            };
            if !seen.insert(name.clone()) {
                bad.push(format!("{}: unit present twice", p.display()));
                continue;
            }
            if !super::store::verify_partition(&p)? {
                bad.push(format!("{}: manifest does not verify", p.display()));
                continue;
            }
            let mut s = unit_seqs(&p)?;
            s.sort_unstable();
            let n = s.len();
            s.dedup();
            dup += (n - s.len()) as u64;
            extra += s.iter().filter(|x| **x < lo || **x > hi).count() as u64;
            let inside = s.iter().filter(|x| **x >= lo && **x <= hi).count() as u64;
            found += inside;
            missing += (hi - lo + 1) as u64 - inside;
        }
    }
    let absent: Vec<&String> = expected.keys().filter(|k| !seen.contains(*k)).collect();
    for k in &absent {
        let (lo, hi) = expected[*k];
        missing += (hi - lo + 1) as u64;
    }
    let planned: u64 = expected.values().map(|(lo, hi)| (hi - lo + 1) as u64).sum();
    println!(
        "units expected {}; present {}; absent {} {:?}; ledgers planned {planned}; found {found}; missing {missing}; duplicated {dup}; outside their unit {extra}; problems {}",
        expected.len(),
        seen.len(),
        absent.len(),
        absent.iter().take(5).collect::<Vec<_>>(),
        bad.len()
    );
    for b in &bad {
        println!("{b}");
    }
    Ok(missing == 0 && dup == 0 && extra == 0 && bad.is_empty())
}

pub fn merge(a: MergeArgs) -> Result<()> {
    std::fs::create_dir_all(&a.into)?;
    let (units, sha) = read(&a.ranges)?;
    let names: BTreeSet<String> = units.iter().map(|u| u.name()).collect();
    let mut n = 0;
    for run in &a.runs {
        for p in super::store::partitions(run)? {
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            ensure!(names.contains(&name), "{name} is not in the plan");
            let dst = a.into.join(&name);
            if dst.exists() {
                bail!("{name} is in more than one run");
            }
            std::fs::create_dir_all(&dst)?;
            for e in std::fs::read_dir(&p)? {
                let e = e?.path();
                let t = dst.join(e.file_name().unwrap());
                if std::fs::hard_link(&e, &t).is_err() {
                    std::fs::copy(&e, &t)?;
                }
            }
            n += 1;
        }
    }
    let mut sums = String::new();
    for p in super::store::partitions(&a.into)? {
        let m = p.join("MANIFEST.json");
        sums.push_str(&format!(
            "{}  {}/MANIFEST.json\n",
            xdrcheck_xdr::sha256_file(&m)?,
            p.file_name().unwrap().to_string_lossy()
        ));
    }
    super::store::write_atomic(&a.into.join("SHA256SUMS"), sums.as_bytes())?;
    super::store::write_atomic(&a.into.join("ranges.sha256"), format!("{sha}\n").as_bytes())?;
    eprintln!("merged {n} unit directories into {}", a.into.display());
    Ok(())
}

// ---------- lake listing ----------

fn pct(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

fn tag<'a>(x: &'a str, t: &str) -> Option<&'a str> {
    let (o, c) = (format!("<{t}>"), format!("</{t}>"));
    let i = x.find(&o)? + o.len();
    let j = x[i..].find(&c)? + i;
    Some(&x[i..j])
}

/// List one partition (paged ListObjectsV2, anonymous); returns `seq, key, size, etag, last_modified` rows.
fn list_partition(
    agent: &ureq::Agent,
    endpoint: &str,
    prefix: &str,
    part: &str,
) -> Result<(String, u32)> {
    let mut rows = String::from("seq\tkey\tsize\tetag\tlast_modified\n");
    let mut token: Option<String> = None;
    let mut calls = 0u32;
    loop {
        let mut url = format!(
            "{endpoint}/?list-type=2&max-keys=1000&prefix={}",
            pct(&format!("{prefix}/{part}/"))
        );
        if let Some(t) = &token {
            url.push_str(&format!("&continuation-token={}", pct(t)));
        }
        let mut attempt = 0u32;
        let body = loop {
            attempt += 1;
            calls += 1;
            match agent.get(&url).call() {
                Ok(mut r) if r.status().as_u16() == 200 => break r.body_mut().read_to_string()?,
                Ok(r) if attempt < 8 && matches!(r.status().as_u16(), 429 | 500..=599) => {}
                Ok(r) => bail!("{url}: HTTP {}", r.status()),
                Err(e) if attempt < 8 => eprintln!("{part}: {e}; retrying"),
                Err(e) => bail!("{url}: {e}"),
            }
            std::thread::sleep(std::time::Duration::from_millis(
                (500u64 << attempt.min(7)).min(60_000),
            ));
        };
        let mut rest = body.as_str();
        while let Some(i) = rest.find("<Contents>") {
            let j = rest[i..]
                .find("</Contents>")
                .context("unterminated Contents")?
                + i;
            let c = &rest[i..j];
            let key = tag(c, "Key").context("Key")?;
            let size = tag(c, "Size").context("Size")?;
            let etag = tag(c, "ETag")
                .unwrap_or("")
                .replace("&quot;", "")
                .replace('"', "");
            let lm = tag(c, "LastModified").unwrap_or("");
            let seq = key
                .rsplit("--")
                .next()
                .and_then(|s| s.split('.').next())
                .and_then(|s| s.parse::<u32>().ok());
            if let Some(seq) = seq {
                rows.push_str(&format!("{seq}\t{key}\t{size}\t{etag}\t{lm}\n"));
            }
            rest = &rest[j..];
        }
        if tag(&body, "IsTruncated") == Some("true") {
            token = Some(
                tag(&body, "NextContinuationToken")
                    .context("no continuation token")?
                    .replace("&amp;", "&"),
            );
        } else {
            return Ok((rows, calls));
        }
    }
}

pub fn list_lake(a: ListArgs) -> Result<()> {
    std::fs::create_dir_all(&a.out)?;
    let parts: Vec<String> = (a.first / PART..=a.tip / PART)
        .rev()
        .map(|p| partition_name(p * PART))
        .collect();
    let todo: Vec<&String> = parts
        .iter()
        .filter(|p| !a.out.join(format!("{p}.tsv")).exists())
        .collect();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(120)))
        .http_status_as_error(false)
        .user_agent("xdrcheck-corpus-scan")
        .build()
        .into();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let calls = std::sync::atomic::AtomicU64::new(0);
    let errs = std::sync::Mutex::new(Vec::new());
    let t0 = std::time::Instant::now();
    std::thread::scope(|sc| {
        for _ in 0..a.parallel.clamp(1, 8) {
            sc.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let Some(p) = todo.get(i) else { break };
                match list_partition(
                    &agent,
                    a.endpoint.trim_end_matches('/'),
                    a.prefix.trim_matches('/'),
                    p,
                ) {
                    Ok((rows, c)) => {
                        calls.fetch_add(c as u64, std::sync::atomic::Ordering::Relaxed);
                        if let Err(e) = super::store::write_atomic(
                            &a.out.join(format!("{p}.tsv")),
                            rows.as_bytes(),
                        ) {
                            errs.lock().unwrap().push(format!("{p}: {e:#}"));
                        }
                    }
                    Err(e) => errs.lock().unwrap().push(format!("{p}: {e:#}")),
                }
            });
        }
    });
    let e = errs.into_inner().unwrap();
    for x in &e {
        eprintln!("error: {x}");
    }
    let secs = t0.elapsed().as_secs_f64();
    println!(
        "listed {} partitions ({} already present) with {} calls in {secs:.1} s = {:.1} calls/s; errors {}",
        todo.len(),
        parts.len() - todo.len(),
        calls.load(std::sync::atomic::Ordering::Relaxed),
        calls.load(std::sync::atomic::Ordering::Relaxed) as f64 / secs.max(0.001),
        e.len()
    );
    ensure!(e.is_empty(), "listing incomplete; rerun to resume");
    Ok(())
}
