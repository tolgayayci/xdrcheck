//! Shared pieces of the streaming whole-run tools (`cover-stream`, `token-census`, `chain-check`):
//! the run's units in ledger order with completeness checks, parallel loops over units, zstd TSV
//! output, and readers of the census files.
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

use anyhow::{bail, ensure, Context, Result};

use super::shape::Id;

/// One unit (a partition directory) of a merged run.
#[derive(Clone, Debug)]
pub struct Unit {
    pub first: u32,
    pub last: u32,
    pub dir: PathBuf,
}

impl Unit {
    pub fn name(&self) -> String {
        self.dir.file_name().unwrap().to_string_lossy().to_string()
    }
}

/// `first` and `last` ledger of a unit from its directory name (`<partition>~<first>-<last>`).
pub fn range_of(dir: &Path) -> Result<(u32, u32)> {
    let n = dir.file_name().context("unit name")?.to_string_lossy();
    let (_, r) = n
        .rsplit_once('~')
        .with_context(|| format!("{n}: not a unit name"))?;
    let (a, b) = r
        .split_once('-')
        .with_context(|| format!("{n}: not a unit name"))?;
    Ok((a.parse()?, b.parse()?))
}

/// The units of `run` (or the ones listed in `units_from`) sorted by first ledger. Fails when two
/// units overlap, when a unit directory has no manifest (a copy in progress), or, unless
/// `allow_gaps`, when the units do not follow each other without a gap.
pub fn list(run: &Path, units_from: Option<&Path>, allow_gaps: bool) -> Result<Vec<Unit>> {
    let dirs: Vec<PathBuf> = match units_from {
        None => {
            let mut all = 0usize;
            for e in fs::read_dir(run).with_context(|| run.display().to_string())? {
                let p = e?.path();
                if p.is_dir() && p.file_name().unwrap().to_string_lossy().contains('~') {
                    all += 1;
                }
            }
            let v = super::store::partitions(run)?;
            ensure!(
                v.len() == all,
                "{}: {} unit directories but {} manifests (a copy in progress?)",
                run.display(),
                all,
                v.len()
            );
            v
        }
        Some(f) => {
            let mut v = Vec::new();
            for l in fs::read_to_string(f)?.lines() {
                let l = l.trim();
                if l.is_empty() || l.starts_with('#') {
                    continue;
                }
                let p = run.join(Path::new(l).file_name().context("unit name")?);
                ensure!(
                    p.join("MANIFEST.json").exists(),
                    "{}: not a unit of the run",
                    p.display()
                );
                v.push(p);
            }
            v
        }
    };
    let mut units = Vec::with_capacity(dirs.len());
    for d in dirs {
        let (first, last) = range_of(&d)?;
        ensure!(first <= last, "{}: empty range", d.display());
        units.push(Unit {
            first,
            last,
            dir: d,
        });
    }
    units.sort_by_key(|u| (u.first, u.last));
    units.dedup_by(|a, b| a.dir == b.dir);
    ensure!(!units.is_empty(), "{}: no units", run.display());
    for w in units.windows(2) {
        ensure!(
            w[1].first > w[0].last,
            "units {} and {} overlap",
            w[0].name(),
            w[1].name()
        );
        if !allow_gaps && w[1].first != w[0].last + 1 {
            bail!(
                "gap between units {} and {} (give --allow-gaps for a partial view)",
                w[0].name(),
                w[1].name()
            );
        }
    }
    Ok(units)
}

/// Every file the unit's manifest lists exists with the listed size (catches a unit copied half way).
pub fn check_manifest(dir: &Path) -> Result<()> {
    let m: serde_json::Value = serde_json::from_slice(&fs::read(dir.join("MANIFEST.json"))?)?;
    for (n, f) in m["files"].as_object().context("manifest without files")? {
        let want = f["bytes"].as_u64().context("manifest bytes")?;
        let got = fs::metadata(dir.join(n))
            .with_context(|| format!("{}: {n}", dir.display()))?
            .len();
        ensure!(
            got == want,
            "{}: {n} has {got} bytes, the manifest says {want}",
            dir.display()
        );
    }
    Ok(())
}

/// Run `f` on every item, `jobs` at a time, in any order; the first error stops the loop.
pub fn par_each<T: Sync>(
    items: &[T],
    jobs: usize,
    f: impl Fn(usize, &T) -> Result<()> + Sync,
) -> Result<()> {
    let next = AtomicUsize::new(0);
    let errs: Mutex<Vec<String>> = Mutex::new(Vec::new());
    std::thread::scope(|sc| {
        for _ in 0..jobs.max(1) {
            sc.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= items.len() || !errs.lock().unwrap().is_empty() {
                    return;
                }
                if let Err(e) = f(i, &items[i]) {
                    errs.lock().unwrap().push(format!("{e:#}"));
                }
            });
        }
    });
    let errs = errs.into_inner().unwrap();
    if !errs.is_empty() {
        bail!("{}", errs.join("; "));
    }
    Ok(())
}

/// Run `work` on every item, `jobs` at a time and at most `window` items ahead of the consumer,
/// and hand the results to `consume` in item order.
pub fn par_ordered<T: Sync, R: Send>(
    items: &[T],
    jobs: usize,
    window: usize,
    work: impl Fn(&T) -> Result<R> + Sync,
    mut consume: impl FnMut(usize, R) -> Result<()>,
) -> Result<()> {
    struct St<R> {
        next: usize,
        consumed: usize,
        stop: bool,
        ready: BTreeMap<usize, Result<R>>,
    }
    let window = window.max(1);
    let st = Mutex::new(St {
        next: 0,
        consumed: 0,
        stop: false,
        ready: BTreeMap::new(),
    });
    let cv = Condvar::new();
    std::thread::scope(|sc| -> Result<()> {
        for _ in 0..jobs.max(1) {
            sc.spawn(|| loop {
                let i = {
                    let mut g = st.lock().unwrap();
                    while !g.stop && g.next < items.len() && g.next >= g.consumed + window {
                        g = cv.wait(g).unwrap();
                    }
                    if g.stop || g.next >= items.len() {
                        return;
                    }
                    g.next += 1;
                    g.next - 1
                };
                let r = work(&items[i]);
                let mut g = st.lock().unwrap();
                if r.is_err() {
                    g.stop = true;
                }
                g.ready.insert(i, r);
                cv.notify_all();
            });
        }
        let mut out = Ok(());
        for i in 0..items.len() {
            let r = {
                let mut g = st.lock().unwrap();
                loop {
                    if let Some(r) = g.ready.remove(&i) {
                        break Some(r);
                    }
                    if g.stop && i >= g.next {
                        break None;
                    }
                    g = cv.wait(g).unwrap();
                }
            };
            let res = match r {
                Some(Ok(v)) => consume(i, v),
                Some(Err(e)) => Err(e),
                None => Err(anyhow::anyhow!("stopped before item {i}")),
            };
            let mut g = st.lock().unwrap();
            g.consumed = i + 1;
            if res.is_err() {
                g.stop = true;
            }
            cv.notify_all();
            drop(g);
            if let Err(e) = res {
                out = Err(e);
                break;
            }
        }
        st.lock().unwrap().stop = true;
        cv.notify_all();
        out
    })
}

pub fn tmp_of(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

pub fn write_atomic(p: &Path, b: &[u8]) -> Result<()> {
    fs::write(tmp_of(p), b)?;
    fs::rename(tmp_of(p), p)?;
    Ok(())
}

/// A zstd TSV written as `<dst>.tmp` and renamed when finished.
pub struct ZOut {
    pub enc: zstd::Encoder<'static, BufWriter<File>>,
    dst: PathBuf,
}

impl ZOut {
    pub fn create(dst: PathBuf, header: &str) -> Result<ZOut> {
        let f = File::create(tmp_of(&dst)).with_context(|| dst.display().to_string())?;
        let mut enc = zstd::Encoder::new(BufWriter::with_capacity(1 << 20, f), 3)?;
        enc.write_all(header.as_bytes())?;
        enc.write_all(b"\n")?;
        Ok(ZOut { enc, dst })
    }
    pub fn finish(self) -> Result<()> {
        let f = self
            .enc
            .finish()?
            .into_inner()
            .map_err(|e| e.into_error())?;
        f.sync_all()?;
        drop(f);
        fs::rename(tmp_of(&self.dst), &self.dst)?;
        Ok(())
    }
}

/// Lines of a zstd TSV after its header, split on tabs.
pub fn each_tsv_zst(path: &Path, mut f: impl FnMut(&[&str]) -> Result<()>) -> Result<()> {
    let r = BufReader::with_capacity(
        1 << 20,
        zstd::Decoder::new(File::open(path).with_context(|| path.display().to_string())?)?,
    );
    for (n, l) in r.lines().enumerate() {
        let l = l?;
        if n == 0 || l.is_empty() {
            continue;
        }
        let cols: Vec<&str> = l.split('\t').collect();
        f(&cols).with_context(|| format!("{}: line {}", path.display(), n + 1))?;
    }
    Ok(())
}

pub fn unhex16(s: &str) -> Result<Id> {
    let v = hex::decode(s)?;
    v.try_into()
        .map_err(|_| anyhow::anyhow!("{s}: not a 16-byte id"))
}

/// Component kinds of the census files, tx-level first.
pub const COMP_KINDS: [char; 7] = ['A', 'E', 'F', 'M', 'O', 'R', 'L'];

/// Read `shapes-<level>-<kind>.tsv.zst` of a census directory: (id, occurrences, first, last).
pub fn each_census(
    dir: &Path,
    level: &str,
    kind: char,
    mut f: impl FnMut(Id, u64, u32, u32) -> Result<()>,
) -> Result<()> {
    each_tsv_zst(&dir.join(format!("shapes-{level}-{kind}.tsv.zst")), |c| {
        ensure!(c.len() >= 4, "short line");
        f(unhex16(c[0])?, c[1].parse()?, c[2].parse()?, c[3].parse()?)
    })
}

/// 5,000,000-ledger era of a ledger.
pub const ERA: u32 = 5_000_000;
