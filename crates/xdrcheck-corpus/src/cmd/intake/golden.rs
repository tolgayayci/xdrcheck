//! stellar-core's golden `LedgerCloseMeta` tree (the `core-golden` source, `docs/architecture.md`).
//!
//! **Layout** at a core tag: `test-lcm-{current,next}/<TestFileStem>/<hash16>.xdr` with one
//! `index.json` per directory mapping `hash16` to the human test name (`"<test case>|<section>|…"`,
//! `hash16` = first 16 hex characters of sha256 of the name) plus header keys `!rng seed`, `!cfg
//! protocol version`, …. A file is a record-marked stream of every ledger the test closed.
//! Entries name tests by human name, never by `hash16` (it changes at every protocol).
//!
//! **Fetch** ([`fetch_tree`]): the tree is read out of git at the tag — from a local clone when
//! `XDRCHECK_STELLAR_CORE_REPO` names one, otherwise from a shallow fetch of the tag from GitHub kept
//! in the cache — and written to `<cache>/goldens/<tag>/` with `FETCHED.json` (tag, commit,
//! origin). At the tag pinned in `pins.toml` the commit must be the pinned one. `<cache>` is
//! `XDRCHECK_CACHE_DIR`, default `$HOME/.cache/xdrcheck`.
//!
//! **Bulk index**: `corpus/bulk/core-<tag>-<tier>.sha256`, `sha256sum` format (`<sha256>␠␠<path>`,
//! paths relative to the tree root, sorted), one line per `.xdr` file. [`verify_tree`] checks a
//! fetched tier against it: every listed file present with its hash, no unlisted `.xdr` file.
//!
//! **Checks** called by `verify`:
//! - AG-1 ([`ag1`]): a `core-golden` variant's blob equals frame `frame_index` of the named file,
//!   whose sha256 is the recorded one, and the test name resolves to that file at the tag.
//! - AG-3 ([`ag3`]): every golden of a tier decodes (gate, explicit limits) and re-encodes byte-exactly.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use xdrcheck_xdr::{Gate, Limits};

use super::ledger::LedgerSummary;
use super::manifest::blob_rel_path;
use super::pins::Pins;
use super::util::{now_rfc3339, read_json, write_json};

/// stellar-core's hard-coded unit-test passphrase.
pub const PASSPHRASE: &str = "(V) (;,,;) (V)";
/// The two golden tiers (`pins.toml` `[stellar_core] golden_tiers`).
pub const TIERS: [&str; 2] = ["current", "next"];
/// The upstream repository fetched when no local clone is named.
pub const UPSTREAM: &str = "https://github.com/stellar/stellar-core.git";
/// Marker file written into a fetched tree.
pub const FETCHED: &str = "FETCHED.json";

/// The cache root: `XDRCHECK_CACHE_DIR`, default `$HOME/.cache/xdrcheck`.
pub fn cache_root() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("XDRCHECK_CACHE_DIR") {
        return Ok(PathBuf::from(d));
    }
    xdrcheck_xdr::userdir::home_cache().context("neither XDRCHECK_CACHE_DIR nor HOME is set")
}

/// Where the tree of `tag` is kept: `<cache>/goldens/<tag>`.
pub fn tree_dir(tag: &str) -> Result<PathBuf> {
    Ok(cache_root()?.join("goldens").join(tag))
}

/// Directory name of a tier: `test-lcm-<tier>`.
pub fn tier_dir(tier: &str) -> String {
    format!("test-lcm-{tier}")
}

/// The bulk index of `tag` and `tier`: `corpus/bulk/core-<tag>-<tier>.sha256`.
pub fn index_path(corpus: &Path, tag: &str, tier: &str) -> PathBuf {
    corpus
        .join("bulk")
        .join(format!("core-{tag}-{tier}.sha256"))
}

/// A fetched golden tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    /// Its root directory (holds `test-lcm-*/`).
    pub root: PathBuf,
    /// The core tag.
    pub tag: String,
    /// The commit the tag resolved to.
    pub commit: String,
}

impl Tree {
    /// Open a fetched tree (reads `FETCHED.json`).
    pub fn open(root: &Path) -> Result<Tree> {
        let f = root.join(FETCHED);
        ensure!(
            f.is_file(),
            "no golden tree at {} (run `xdrcheck-corpus fetch-goldens <tag>` first)",
            root.display()
        );
        let v = read_json(&f)?;
        let s = |k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .with_context(|| format!("{}: {k} missing", f.display()))
        };
        Ok(Tree {
            root: root.to_path_buf(),
            tag: s("tag")?,
            commit: s("commit")?,
        })
    }

    /// Open the cached tree of `tag`.
    pub fn open_tag(tag: &str) -> Result<Tree> {
        let t = Tree::open(&tree_dir(tag)?)?;
        ensure!(
            t.tag == tag,
            "{} holds tag {}, not {tag}",
            t.root.display(),
            t.tag
        );
        Ok(t)
    }
}

// --- Fetching from git ---

fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .context("run git (is it installed?)")?;
    ensure!(
        out.status.success(),
        "git {} in {}: {}",
        args.join(" "),
        repo.display(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(out.stdout)
}

/// Where the tree's bytes come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// A local clone that already has the tag.
    Local(PathBuf),
    /// A shallow fetch of the tag from [`UPSTREAM`] into this bare repository.
    Upstream(PathBuf),
}

impl Origin {
    /// `XDRCHECK_STELLAR_CORE_REPO` if set, else a bare repository in the cache.
    pub fn from_env() -> Result<Origin> {
        match std::env::var_os("XDRCHECK_STELLAR_CORE_REPO") {
            Some(p) => Ok(Origin::Local(PathBuf::from(p))),
            None => Ok(Origin::Upstream(
                cache_root()?.join("goldens").join(".stellar-core.git"),
            )),
        }
    }

    fn describe(&self) -> String {
        match self {
            Origin::Local(_) => "local clone (XDRCHECK_STELLAR_CORE_REPO)".into(),
            Origin::Upstream(_) => format!("shallow fetch of {UPSTREAM}"),
        }
    }

    /// Make the tag available and return (repository, commit).
    fn resolve(&self, tag: &str) -> Result<(PathBuf, String)> {
        let rev = format!("refs/tags/{tag}^{{commit}}");
        let repo = match self {
            Origin::Local(p) => p.clone(),
            Origin::Upstream(p) => {
                if !p.join("HEAD").exists() {
                    std::fs::create_dir_all(p)?;
                    git(p, &["init", "--bare", "--quiet"])?;
                }
                // A tag fetched once is not fetched again, so later runs are offline; the pinned
                // commit and the bulk index still check what it points to.
                if git(p, &["rev-parse", "--verify", "--quiet", &rev]).is_err() {
                    let refspec = format!("+refs/tags/{tag}:refs/tags/{tag}");
                    let args = ["fetch", "--quiet", "--depth", "1", "--no-tags", UPSTREAM];
                    git(p, &[&args[..], &[refspec.as_str()]].concat())?;
                }
                p.clone()
            }
        };
        let commit = String::from_utf8(git(&repo, &["rev-parse", "--verify", &rev])?)?
            .trim()
            .to_string();
        Ok((repo, commit))
    }
}

/// One file of a tier as git lists it.
struct TreeFile {
    oid: String,
    path: String,
}

fn list_tier(repo: &Path, commit: &str, tier: &str) -> Result<Vec<TreeFile>> {
    let out = git(
        repo,
        &["ls-tree", "-r", "-z", commit, "--", &tier_dir(tier)],
    )?;
    let mut files = Vec::new();
    for rec in out.split(|&b| b == 0).filter(|r| !r.is_empty()) {
        let rec = String::from_utf8_lossy(rec);
        let (meta, path) = rec.split_once('\t').context("unreadable ls-tree line")?;
        let parts: Vec<&str> = meta.split_whitespace().collect();
        ensure!(
            parts.len() == 3 && parts[1] == "blob",
            "unexpected tree entry {rec:?}"
        );
        files.push(TreeFile {
            oid: parts[2].to_string(),
            path: path.to_string(),
        });
    }
    Ok(files)
}

/// Write the blobs of `files` under `dest` with one `git cat-file --batch`.
fn extract(repo: &Path, files: &[TreeFile], dest: &Path) -> Result<u64> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("run git cat-file")?;
    let mut stdin = child.stdin.take().context("stdin")?;
    let oids: Vec<String> = files.iter().map(|f| f.oid.clone()).collect();
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        for oid in oids {
            writeln!(stdin, "{oid}")?;
        }
        Ok(())
    });
    let mut out = BufReader::new(child.stdout.take().context("stdout")?);
    let mut total = 0u64;
    for f in files {
        let mut header = String::new();
        out.read_line(&mut header)?;
        let parts: Vec<&str> = header.split_whitespace().collect();
        ensure!(
            parts.len() == 3 && parts[0] == f.oid && parts[1] == "blob",
            "git cat-file: unexpected header {header:?} for {}",
            f.path
        );
        let size: usize = parts[2].parse()?;
        let mut buf = vec![0u8; size + 1];
        out.read_exact(&mut buf)?;
        buf.pop();
        let path = dest.join(&f.path);
        std::fs::create_dir_all(path.parent().context("path")?)?;
        std::fs::write(&path, &buf)?;
        total += size as u64;
    }
    writer.join().expect("writer thread")?;
    ensure!(child.wait()?.success(), "git cat-file failed");
    Ok(total)
}

/// Per-tier counts of a fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The tree.
    pub tree: Tree,
    /// `(tier, files, bytes)` written, empty when the cached tree was already complete.
    pub written: Vec<(String, usize, u64)>,
}

/// Fetch the golden tree of `tag` into `dest` (see the module documentation). A complete tree
/// already there for the same commit is kept. At the pinned tag the commit must be the pinned one.
pub fn fetch_tree(tag: &str, dest: &Path, origin: &Origin, pins: &Pins) -> Result<Fetched> {
    let (repo, commit) = origin.resolve(tag)?;
    if tag == pins.core_tag() {
        ensure!(
            commit == pins.core_commit,
            "tag {tag} resolves to {commit}, but pins.toml pins {}",
            pins.core_commit
        );
    }
    if let Ok(t) = Tree::open(dest) {
        if t.tag == tag && t.commit == commit {
            return Ok(Fetched {
                tree: t,
                written: Vec::new(),
            });
        }
    }
    let parent = dest.parent().context("destination has no parent")?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        dest.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    if tmp.exists() {
        std::fs::remove_dir_all(&tmp)?;
    }
    let mut written = Vec::new();
    let mut tiers = serde_json::Map::new();
    for tier in TIERS {
        let files = list_tier(&repo, &commit, tier)?;
        if files.is_empty() {
            continue;
        }
        let bytes = extract(&repo, &files, &tmp)?;
        let xdr = files.iter().filter(|f| f.path.ends_with(".xdr")).count();
        tiers.insert(
            tier.into(),
            json!({"xdr_files": xdr, "files": files.len(), "bytes": bytes}),
        );
        written.push((tier.to_string(), xdr, bytes));
    }
    ensure!(!written.is_empty(), "tag {tag} has no test-lcm-* tree");
    write_json(
        &tmp.join(FETCHED),
        &json!({
            "tag": tag,
            "commit": commit,
            "origin": origin.describe(),
            "fetched_at": now_rfc3339(),
            "tiers": tiers,
        }),
    )?;
    if dest.exists() {
        std::fs::remove_dir_all(dest)?;
    }
    std::fs::rename(&tmp, dest)?;
    Ok(Fetched {
        tree: Tree::open(dest)?,
        written,
    })
}

// --- Bulk index ---

/// Read a `sha256sum`-format index into `path → sha256`.
pub fn read_index(path: &Path) -> Result<BTreeMap<String, String>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut out = BTreeMap::new();
    for (n, line) in text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
    {
        let (sha, file) = line
            .split_once("  ")
            .with_context(|| format!("{}:{}: not `<sha256>  <path>`", path.display(), n + 1))?;
        ensure!(
            sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
            "{}:{}: bad sha256",
            path.display(),
            n + 1
        );
        ensure!(
            out.insert(file.to_string(), sha.to_ascii_lowercase())
                .is_none(),
            "{}:{}: {file} listed twice",
            path.display(),
            n + 1
        );
    }
    Ok(out)
}

/// Every `.xdr` file of a tier in a fetched tree, as tree-relative paths, sorted.
pub fn tier_files(root: &Path, tier: &str) -> Result<Vec<String>> {
    let base = root.join(tier_dir(tier));
    let mut out = Vec::new();
    for d in std::fs::read_dir(&base).with_context(|| format!("read {}", base.display()))? {
        let d = d?;
        if !d.file_type()?.is_dir() {
            continue;
        }
        for f in std::fs::read_dir(d.path())? {
            let name = f?.file_name().to_string_lossy().to_string();
            if name.ends_with(".xdr") {
                out.push(format!(
                    "{}/{}/{name}",
                    tier_dir(tier),
                    d.file_name().to_string_lossy()
                ));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Result of checking one tier against its bulk index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TierCheck {
    /// Files the index lists.
    pub listed: usize,
    /// Listed files present with the listed hash.
    pub verified: usize,
    /// Listed files that are absent.
    pub missing: Vec<String>,
    /// Listed files whose hash differs.
    pub mismatched: Vec<String>,
    /// `.xdr` files in the tree the index does not list.
    pub unlisted: Vec<String>,
}

impl TierCheck {
    /// No problem found.
    pub fn ok(&self) -> bool {
        self.missing.is_empty() && self.mismatched.is_empty() && self.unlisted.is_empty()
    }
}

/// Check a tier of a fetched tree against an index.
pub fn verify_tree(root: &Path, tier: &str, index: &BTreeMap<String, String>) -> Result<TierCheck> {
    let mut c = TierCheck {
        listed: index.len(),
        ..TierCheck::default()
    };
    for (file, sha) in index {
        let p = root.join(file);
        if !p.is_file() {
            c.missing.push(file.clone());
        } else if xdrcheck_xdr::sha256_file(&p)? != *sha {
            c.mismatched.push(file.clone());
        } else {
            c.verified += 1;
        }
    }
    c.unlisted = tier_files(root, tier)?
        .into_iter()
        .filter(|f| !index.contains_key(f))
        .collect();
    Ok(c)
}

// --- Names and frames ---

/// A test name resolved to its golden file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Tier.
    pub tier: String,
    /// Tree-relative path, `test-lcm-<tier>/<Dir>/<hash16>.xdr`.
    pub file: String,
    /// The human test name exactly as in `index.json`.
    pub test_name: String,
    /// `!rng seed` of the directory's index.
    pub rng_seed: Option<i64>,
}

/// The `index.json` files of a tier: `(directory name, parsed index)`.
fn indexes(root: &Path, tier: &str) -> Result<Vec<(String, Value)>> {
    let base = root.join(tier_dir(tier));
    let mut out = Vec::new();
    if !base.is_dir() {
        return Ok(out);
    }
    for d in std::fs::read_dir(&base)? {
        let d = d?;
        let idx = d.path().join("index.json");
        if idx.is_file() {
            out.push((
                d.file_name().to_string_lossy().to_string(),
                read_json(&idx)?,
            ));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// The name without its `protocol version N` section, which changes at every protocol bump.
pub fn strip_protocol_section(name: &str) -> String {
    name.split('|')
        .filter(|s| !s.starts_with("protocol version "))
        .collect::<Vec<_>>()
        .join("|")
}

/// `hash16` of a human test name: the first 16 hex characters of its sha256.
pub fn hash16(name: &str) -> String {
    xdrcheck_xdr::sha256_hex(name.as_bytes())[..16].to_string()
}

/// Resolve a human test name to its file. Tiers are searched in [`TIERS`] order (or only `tier`).
/// An exact name wins; otherwise a name equal after dropping the `protocol version N` section
/// must match exactly one test in the first tier where it matches at all.
pub fn resolve(root: &Path, test_name: &str, tier: Option<&str>) -> Result<Resolved> {
    let tiers: Vec<&str> = match tier {
        Some(t) => vec![t],
        None => TIERS.to_vec(),
    };
    let wanted = strip_protocol_section(test_name);
    let mut loose: Option<Vec<Resolved>> = None;
    for tier in tiers {
        let mut matches = Vec::new();
        for (dir, idx) in indexes(root, tier)? {
            let seed = idx.get("!rng seed").and_then(Value::as_i64);
            for (h, name) in idx.as_object().into_iter().flatten() {
                let Some(name) = name.as_str() else { continue };
                if h.starts_with('!') {
                    continue;
                }
                let r = Resolved {
                    tier: tier.to_string(),
                    file: format!("{}/{dir}/{h}.xdr", tier_dir(tier)),
                    test_name: name.to_string(),
                    rng_seed: seed,
                };
                if name == test_name {
                    ensure!(
                        hash16(name) == *h,
                        "{}: {h} is not the hash of {name:?}",
                        r.file
                    );
                    return Ok(r);
                }
                if strip_protocol_section(name) == wanted {
                    matches.push(r);
                }
            }
        }
        if loose.is_none() && !matches.is_empty() {
            loose = Some(matches);
        }
    }
    match loose {
        Some(mut m) if m.len() == 1 => Ok(m.remove(0)),
        Some(m) => bail!(
            "test name {test_name:?} is ambiguous without its protocol section: {}",
            m.iter()
                .map(|r| r.test_name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        None => bail!("no golden test named {test_name:?} at this tag"),
    }
}

/// The payload of record `index` of a record-marked file, and the number of records.
pub fn frame(file: &[u8], index: usize) -> Result<(Option<&[u8]>, usize)> {
    let mut found = None;
    let mut n = 0;
    for r in xdrcheck_xdr::records(file) {
        let r = r?;
        if r.index == index {
            found = Some(r.payload);
        }
        n += 1;
    }
    Ok((found, n))
}

// --- AG-1 ---

/// The `source` block of a `core-golden` variant, as AG-1 reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoldenSource {
    /// `core_tag`.
    pub core_tag: String,
    /// `core_commit`.
    pub core_commit: String,
    /// `tier`.
    pub tier: String,
    /// `file`, path inside the stellar-core repository.
    pub file: String,
    /// `file_sha256`.
    pub file_sha256: String,
    /// `frame_index`.
    pub frame_index: usize,
    /// `test_name`.
    pub test_name: String,
}

impl GoldenSource {
    /// Read the fields from a variant's `source` JSON (`kind` must be `core-golden`).
    pub fn from_json(source: &Value) -> Result<GoldenSource> {
        ensure!(
            source.get("kind").and_then(Value::as_str) == Some("core-golden"),
            "source kind is not core-golden"
        );
        let s = |k: &str| {
            source
                .get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .with_context(|| format!("core-golden source has no {k}"))
        };
        Ok(GoldenSource {
            core_tag: s("core_tag")?,
            core_commit: s("core_commit")?,
            tier: s("tier")?,
            file: s("file")?,
            file_sha256: s("file_sha256")?,
            frame_index: source
                .get("frame_index")
                .and_then(Value::as_u64)
                .context("core-golden source has no frame_index")?
                as usize,
            test_name: s("test_name")?,
        })
    }
}

/// Why AG-1 failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ag1Failure {
    /// The tree is of another tag or commit.
    WrongTree {
        /// What the variant names.
        want: String,
        /// What the tree is.
        have: String,
    },
    /// The test name no longer resolves to the named file.
    NameMismatch {
        /// File the name resolves to, or the resolution error.
        resolves_to: String,
    },
    /// The named file is not in the tree.
    FileMissing,
    /// The file's sha256 is not the recorded one.
    FileHash {
        /// Recorded.
        want: String,
        /// Actual.
        have: String,
    },
    /// The file is not a well-framed record stream.
    Framing(String),
    /// The file has fewer frames.
    NoFrame {
        /// Frames in the file.
        frames: usize,
    },
    /// The blob is not the frame's bytes.
    BytesDiffer {
        /// Blob length.
        blob_len: usize,
        /// Frame length.
        frame_len: usize,
        /// First differing offset.
        first_difference: usize,
    },
}

impl std::fmt::Display for Ag1Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ag1Failure::WrongTree { want, have } => write!(f, "golden tree is {have}, the variant names {want}"),
            Ag1Failure::NameMismatch { resolves_to } => write!(f, "test name resolves to {resolves_to}, not the named file"),
            Ag1Failure::FileMissing => write!(f, "named golden file is not in the tree"),
            Ag1Failure::FileHash { want, have } => write!(f, "golden file sha256 is {have}, the variant records {want}"),
            Ag1Failure::Framing(e) => write!(f, "golden file framing: {e}"),
            Ag1Failure::NoFrame { frames } => write!(f, "golden file has only {frames} frames"),
            Ag1Failure::BytesDiffer { blob_len, frame_len, first_difference } => write!(
                f,
                "blob ({blob_len} bytes) differs from the frame ({frame_len} bytes) at byte {first_difference}"
            ),
        }
    }
}

/// AG-1 (pinned import,): `blob` equals frame `src.frame_index` of `src.file` in `tree`,
/// the file's sha256 is `src.file_sha256`, the tree is `src.core_tag` at `src.core_commit`, and
/// `src.test_name` resolves to `src.file` in `src.tier`. `Ok(Err(_))` is a failed check; `Err(_)`
/// means the check could not run (unreadable file).
pub fn ag1(tree: &Tree, src: &GoldenSource, blob: &[u8]) -> Result<Result<(), Ag1Failure>> {
    if tree.tag != src.core_tag || tree.commit != src.core_commit {
        return Ok(Err(Ag1Failure::WrongTree {
            want: format!("{} at {}", src.core_tag, src.core_commit),
            have: format!("{} at {}", tree.tag, tree.commit),
        }));
    }
    match resolve(&tree.root, &src.test_name, Some(&src.tier)) {
        Ok(r) if r.file == src.file && r.test_name == src.test_name => {}
        Ok(r) => {
            return Ok(Err(Ag1Failure::NameMismatch {
                resolves_to: format!("{} ({:?})", r.file, r.test_name),
            }))
        }
        Err(e) => {
            return Ok(Err(Ag1Failure::NameMismatch {
                resolves_to: format!("nothing: {e}"),
            }))
        }
    }
    let path = tree.root.join(&src.file);
    if !path.is_file() {
        return Ok(Err(Ag1Failure::FileMissing));
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let have = xdrcheck_xdr::sha256_hex(&bytes);
    if have != src.file_sha256 {
        return Ok(Err(Ag1Failure::FileHash {
            want: src.file_sha256.clone(),
            have,
        }));
    }
    let (found, frames) = match frame(&bytes, src.frame_index) {
        Ok(x) => x,
        Err(e) => return Ok(Err(Ag1Failure::Framing(e.to_string()))),
    };
    let Some(payload) = found else {
        return Ok(Err(Ag1Failure::NoFrame { frames }));
    };
    if payload != blob {
        let first_difference = payload
            .iter()
            .zip(blob)
            .position(|(a, b)| a != b)
            .unwrap_or(payload.len().min(blob.len()));
        return Ok(Err(Ag1Failure::BytesDiffer {
            blob_len: blob.len(),
            frame_len: payload.len(),
            first_difference,
        }));
    }
    Ok(Ok(()))
}

// --- AG-3 ---

/// Result of AG-3 over one tier.
#[allow(dead_code)] // used by `verify --checks ag3`
#[derive(Debug, Clone, Default)]
pub struct Ag3Report {
    /// Files checked.
    pub files: usize,
    /// Ledgers (records) that decoded and re-encoded byte-exactly.
    pub ledgers: usize,
    /// Bytes read.
    pub bytes: u64,
    /// Wall time.
    pub elapsed: Duration,
    /// `(file, error)` for every file that failed; a file stops at its first bad record.
    pub failures: Vec<(String, String)>,
}

#[allow(dead_code)] // used by `verify --checks ag3`
impl Ag3Report {
    /// Every file passed.
    pub fn ok(&self) -> bool {
        self.failures.is_empty() && self.files > 0
    }
}

/// AG-3 (decoder consistency,): every record of every `.xdr` file of `tier` in `tree`
/// passes the gate, decodes under `limits` as exactly one `LedgerCloseMeta` and re-encodes to the
/// same bytes. Files are checked on `threads` worker threads (at least one).
#[allow(dead_code)] // called by `verify --checks ag3`
pub fn ag3(
    tree: &Tree,
    tier: &str,
    limits: &Limits,
    gate: &Gate,
    threads: usize,
) -> Result<Ag3Report> {
    let start = Instant::now();
    let files = tier_files(&tree.root, tier)?;
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..threads.max(1) {
            s.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(f) = files.get(i) else { break };
                let r = std::fs::read(tree.root.join(f))
                    .map_err(anyhow::Error::from)
                    .and_then(|bytes| {
                        let n = xdrcheck_xdr::split_ledger_stream(&bytes, limits, gate)?.len();
                        Ok((n, bytes.len() as u64))
                    });
                results.lock().expect("lock").push((f.clone(), r));
            });
        }
    });
    let mut report = Ag3Report {
        files: files.len(),
        ..Ag3Report::default()
    };
    let mut results = results.into_inner().expect("lock");
    results.sort_by(|a, b| a.0.cmp(&b.0));
    for (f, r) in results {
        match r {
            Ok((n, b)) => {
                report.ledgers += n;
                report.bytes += b;
            }
            Err(e) => report.failures.push((f, format!("{e:#}"))),
        }
    }
    report.elapsed = start.elapsed();
    Ok(report)
}

// --- Import ---

/// One imported golden frame.
#[derive(Debug, Clone)]
pub struct Imported {
    /// The resolved test.
    pub resolved: Resolved,
    /// Its file's sha256.
    pub file_sha256: String,
    /// Frame index.
    pub frame_index: usize,
    /// Frames in the file.
    pub frames: usize,
    /// The frame's bytes (the blob).
    pub blob: Vec<u8>,
    /// What the ledger says.
    pub ledger: LedgerSummary,
}

/// Resolve `test_name` in `tree`, check the file against the bulk index when one is given, and
/// take frame `frame_index` (required when the test closed more than one ledger). The frame must
/// pass the gate, round-trip, and have its transaction hashes recomputed under [`PASSPHRASE`].
pub fn import(
    tree: &Tree,
    test_name: &str,
    frame_index: Option<usize>,
    index: Option<&BTreeMap<String, String>>,
    gate: &Gate,
) -> Result<Imported> {
    let resolved = resolve(&tree.root, test_name, None)?;
    let bytes = std::fs::read(tree.root.join(&resolved.file))?;
    let file_sha256 = xdrcheck_xdr::sha256_hex(&bytes);
    if let Some(index) = index {
        match index.get(&resolved.file) {
            Some(want) => ensure!(
                *want == file_sha256,
                "{} has sha256 {file_sha256}, the bulk index lists {want}",
                resolved.file
            ),
            None => bail!("{} is not in the bulk index", resolved.file),
        }
    }
    let limits = Limits::default();
    let frames = xdrcheck_xdr::split_ledger_stream(&bytes, &limits, gate)
        .with_context(|| format!("split {}", resolved.file))?;
    let frame_index = match frame_index {
        Some(i) => i,
        None if frames.len() == 1 => 0,
        None => bail!(
            "{:?} closed {} ledgers (sequences {}..={}); choose one with --frame N (0-based)",
            resolved.test_name,
            frames.len(),
            frames.first().map_or(0, |f| f.0.sequence),
            frames.last().map_or(0, |f| f.0.sequence)
        ),
    };
    let (_, payload) = frames.get(frame_index).with_context(|| {
        format!(
            "{} has {} frames, no frame {frame_index}",
            resolved.file,
            frames.len()
        )
    })?;
    let blob = payload.to_vec();
    let ledger = super::ledger::summarise(&blob, PASSPHRASE, &limits, gate)?;
    Ok(Imported {
        resolved,
        file_sha256,
        frame_index,
        frames: frames.len(),
        blob,
        ledger,
    })
}

impl Imported {
    /// The `core-golden` variant (`docs/manifest.md` §4.4). `meta.profile` is left to the author: it
    /// needs the test's `flags_source`, read from the test's code.
    pub fn variant(&self, tree: &Tree) -> Value {
        let sha = xdrcheck_xdr::sha256_hex(&self.blob);
        let mut source = json!({
            "kind": "core-golden",
            "core_tag": tree.tag,
            "core_commit": tree.commit,
            "tier": self.resolved.tier,
            "file": self.resolved.file,
            "file_sha256": self.file_sha256,
            "frame_index": self.frame_index,
            "test_name": self.resolved.test_name,
        });
        if let Some(seed) = self.resolved.rng_seed {
            source["rng_seed"] = json!(seed);
        }
        let mut meta = json!({"ledger_close_meta_version": self.ledger.ledger_close_meta_version});
        if let Some(t) = self.ledger.meta_version(None) {
            meta["transaction_meta_version"] = json!(t);
        }
        json!({
            "network": "core-test",
            "passphrase": PASSPHRASE,
            "protocol": self.ledger.protocol,
            "ledger_seq": self.ledger.ledger_seq,
            "xdr_type": "LedgerCloseMeta",
            "xdr_definitions": super::XDR_DEFINITIONS,
            "blob": {"sha256": sha, "bytes": self.blob.len(), "path": blob_rel_path(&sha)},
            "source": source,
            "meta": meta,
            "derived": {"ledger_hash": self.ledger.header_hash, "tx_hashes": self.ledger.tx_hashes},
        })
    }
}
