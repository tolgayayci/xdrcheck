//! Reads the xdrcheck corpus and keeps an SDK's expected-failure list.
//!
//! An SDK's own CI puts the corpus's bytes through its XDR types. This crate does the reading: it opens the
//! corpus, finds every entry and variant through the entry index `corpus/index.json` (docs/manifest.md §3.1),
//! returns each variant's blob and expected SEP-51 JSON after checking them against their sha256, and compares
//! the run's results with a committed expected-failure list (docs/use-in-sdk-ci.md §7).
//!
//! # Corpus layouts
//!
//! [`Corpus::open`] takes any of:
//!
//! 1. a release archive `xdrcheck-<version>.tar.gz` (docs/release.md): read into memory, never
//!    extracted; [`Corpus::open_verified`] also checks the archive's sha256;
//! 2. an extracted release: a directory holding `corpus/` and `stress/`;
//! 3. a corpus directory holding `index.json` (the repository's own `corpus/`).
//!
//! In a release a stress entry's files are under `stress/` and every other entry's under `corpus/`; in a
//! corpus directory everything is under the one directory. Every manifest is read when the corpus is opened
//! (and checked against the root's `manifest.sha256` when the root has one), so an extracted release needs both
//! roots.
//!
//! # Example
//!
//! ```no_run
//! use xdrcheck::{Corpus, ExpectedFailures, Results};
//!
//! let corpus = Corpus::open(std::env::var("XDRCHECK_CORPUS").unwrap())?;
//! let mut results = Results::new();
//! for entry in corpus.entries().iter().filter(|e| e.tier != "stress") {
//!     for v in entry.variants.iter().filter(|v| v.decodable()) {
//!         let bytes = v.blob()?;
//!         // decode `bytes` as `v.xdr_type` with the SDK under test, then:
//!         results.pass(&entry.id, &v.key, "L0");
//!     }
//! }
//! let list = ExpectedFailures::read("expected-failures.txt")?;
//! let cmp = results.compare(&list, true);
//! cmp.print(&mut std::io::stdout()).unwrap();
//! assert!(cmp.passed());
//! # Ok::<(), xdrcheck::Error>(())
//! ```
//!
//! The crate does no network access, writes nothing and keeps no global state. It is one source file, so an SDK
//! may vendor it.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Every error of this crate: what file and what is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl Error {
    fn new(msg: impl Into<String>) -> Error {
        Error(msg.into())
    }

    /// The message.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// Parses JSON without serde_json's nesting limit: sidecars of deeply nested values exceed it.
fn parse_json(bytes: &[u8], what: &str) -> Result<Value> {
    use serde::Deserialize;
    let mut de = serde_json::Deserializer::from_slice(bytes);
    de.disable_recursion_limit();
    let v =
        Value::deserialize(&mut de).map_err(|e| Error::new(format!("{what}: not JSON: {e}")))?;
    de.end()
        .map_err(|e| Error::new(format!("{what}: not JSON: {e}")))?;
    Ok(v)
}

// ---------------------------------------------------------------------------------------------------------------
// Storage: a directory or an in-memory archive, with two corpus roots.

/// The two corpus roots of a release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Root {
    Corpus,
    Stress,
}

impl Root {
    fn name(self) -> &'static str {
        match self {
            Root::Corpus => "corpus",
            Root::Stress => "stress",
        }
    }
}

enum Files {
    /// Root directories; in a corpus directory both are the same.
    Dir { corpus: PathBuf, stress: PathBuf },
    /// Archive members by path; `top` is the top-level directory.
    Archive {
        files: HashMap<String, Vec<u8>>,
        top: String,
    },
}

struct Store {
    files: Files,
    /// manifest.sha256 of each root that has one: path relative to the root -> sha256.
    manifest_sums: HashMap<&'static str, HashMap<String, String>>,
}

impl Store {
    /// A file of a root, or None when it is not there.
    fn get(&self, root: Root, rel: &str) -> Result<Option<Cow<'_, [u8]>>> {
        match &self.files {
            Files::Dir { corpus, stress } => {
                let p = match root {
                    Root::Corpus => corpus.join(rel),
                    Root::Stress => stress.join(rel),
                };
                match std::fs::read(&p) {
                    Ok(b) => Ok(Some(Cow::Owned(b))),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(Error::new(format!("{}: {e}", p.display()))),
                }
            }
            Files::Archive { files, top } => Ok(files
                .get(&format!("{top}/{}/{rel}", root.name()))
                .map(|b| Cow::Borrowed(b.as_slice()))),
        }
    }

    fn read(&self, root: Root, rel: &str) -> Result<Cow<'_, [u8]>> {
        self.get(root, rel)?
            .ok_or_else(|| Error::new(format!("{}: no such file", self.describe(root, rel))))
    }

    /// The file's name for messages.
    fn describe(&self, root: Root, rel: &str) -> String {
        match &self.files {
            Files::Dir { corpus, stress } => match root {
                Root::Corpus => corpus.join(rel).display().to_string(),
                Root::Stress => stress.join(rel).display().to_string(),
            },
            Files::Archive { top, .. } => format!("archive member {top}/{}/{rel}", root.name()),
        }
    }

    fn same_roots(&self) -> bool {
        matches!(&self.files, Files::Dir { corpus, stress } if corpus == stress)
    }
}

/// Files of a ustar (or GNU tar) stream by path; directories are left out.
fn untar(buf: &[u8]) -> Result<HashMap<String, Vec<u8>>> {
    fn cstr(b: &[u8]) -> String {
        let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
        String::from_utf8_lossy(&b[..end]).into_owned()
    }
    fn size(field: &[u8]) -> Result<usize> {
        if field[0] & 0x80 != 0 {
            // GNU base-256
            let mut n: u64 = u64::from(field[0] & 0x7f);
            for &b in &field[1..] {
                n = n
                    .checked_mul(256)
                    .and_then(|n| n.checked_add(u64::from(b)))
                    .ok_or_else(|| Error::new("tar member size overflows"))?;
            }
            return usize::try_from(n).map_err(|_| Error::new("tar member size overflows"));
        }
        let s = cstr(field);
        let s = s.trim();
        if s.is_empty() {
            return Ok(0);
        }
        usize::from_str_radix(s, 8).map_err(|_| Error::new(format!("bad tar size field {s:?}")))
    }
    fn pax_path(data: &[u8]) -> Option<String> {
        let mut rest = data;
        while !rest.is_empty() {
            let sp = rest.iter().position(|&b| b == b' ')?;
            let len: usize = std::str::from_utf8(&rest[..sp]).ok()?.parse().ok()?;
            if len <= sp || len > rest.len() {
                return None;
            }
            let rec = &rest[sp + 1..len];
            let rec = rec.strip_suffix(b"\n").unwrap_or(rec);
            if let Some(v) = rec.strip_prefix(b"path=") {
                return Some(String::from_utf8_lossy(v).into_owned());
            }
            rest = &rest[len..];
        }
        None
    }

    let mut files = HashMap::new();
    let mut long_name: Option<String> = None;
    let mut off = 0usize;
    while off + 512 <= buf.len() {
        let h = &buf[off..off + 512];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let n = size(&h[124..136])?;
        let typ = if h[156] == 0 { b'0' } else { h[156] };
        let prefix = cstr(&h[345..500]);
        let base = cstr(&h[0..100]);
        let name = long_name.take().unwrap_or(if prefix.is_empty() {
            base
        } else {
            format!("{prefix}/{base}")
        });
        let start = off + 512;
        let end = start
            .checked_add(n)
            .filter(|&e| e <= buf.len())
            .ok_or_else(|| Error::new(format!("tar member {name}: truncated")))?;
        let data = &buf[start..end];
        off = start + n.div_ceil(512) * 512;
        match typ {
            b'L' => long_name = Some(cstr(data)),
            b'x' => long_name = pax_path(data),
            b'0' | b'7' => {
                files.insert(name, data.to_vec());
            }
            b'5' | b'g' => {}
            t => {
                return Err(Error::new(format!(
                    "tar member {name}: unsupported entry type {:?}",
                    t as char
                )))
            }
        }
    }
    Ok(files)
}

// ---------------------------------------------------------------------------------------------------------------
// The corpus.

/// An opened corpus.
pub struct Corpus {
    version: String,
    source: String,
    entries: Vec<Entry>,
    by_id: HashMap<String, usize>,
}

impl fmt::Debug for Corpus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Corpus")
            .field("version", &self.version)
            .field("source", &self.source)
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl Corpus {
    /// Opens a release archive, an extracted release or a corpus directory.
    pub fn open(path: impl AsRef<Path>) -> Result<Corpus> {
        Self::open_verified(path, None)
    }

    /// Like [`Corpus::open`]; when `archive_sha256` is given, `path` must be an archive with that sha256.
    pub fn open_verified(path: impl AsRef<Path>, archive_sha256: Option<&str>) -> Result<Corpus> {
        let path = path.as_ref();
        let shown = path.display().to_string();
        let meta =
            std::fs::metadata(path).map_err(|e| Error::new(format!("corpus {shown}: {e}")))?;
        let (files, source, provenance) = if meta.is_dir() {
            if archive_sha256.is_some() {
                return Err(Error::new(format!(
                    "corpus {shown}: an archive sha256 was given, but this is a directory"
                )));
            }
            if path.join("index.json").is_file() {
                let p = path.to_path_buf();
                (
                    Files::Dir {
                        corpus: p.clone(),
                        stress: p,
                    },
                    shown,
                    None,
                )
            } else if path.join("corpus").join("index.json").is_file() {
                let prov = match std::fs::read(path.join("PROVENANCE.json")) {
                    Ok(b) => Some(b),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => return Err(Error::new(format!("{shown}/PROVENANCE.json: {e}"))),
                };
                (
                    Files::Dir {
                        corpus: path.join("corpus"),
                        stress: path.join("stress"),
                    },
                    shown,
                    prov,
                )
            } else {
                return Err(Error::new(format!(
                    "corpus {shown}: neither index.json nor corpus/index.json is in this directory"
                )));
            }
        } else {
            let gz = std::fs::read(path).map_err(|e| Error::new(format!("{shown}: {e}")))?;
            let got = sha256_hex(&gz);
            if let Some(want) = archive_sha256 {
                if !got.eq_ignore_ascii_case(want.trim()) {
                    return Err(Error::new(format!(
                        "{shown}: sha256 {got}, but {} was expected",
                        want.trim()
                    )));
                }
            }
            let mut tar = Vec::new();
            flate2::read::MultiGzDecoder::new(gz.as_slice())
                .read_to_end(&mut tar)
                .map_err(|e| Error::new(format!("{shown}: not a gzip file: {e}")))?;
            let files = untar(&tar).map_err(|e| Error::new(format!("{shown}: {e}")))?;
            let mut tops: BTreeSet<&str> = BTreeSet::new();
            for k in files.keys() {
                tops.insert(k.split('/').next().unwrap_or(""));
            }
            if tops.len() != 1 {
                return Err(Error::new(format!(
                    "{shown}: want one top-level directory, found {}",
                    tops.len()
                )));
            }
            let top = tops.into_iter().next().unwrap_or_default().to_string();
            if !files.contains_key(&format!("{top}/corpus/index.json")) {
                return Err(Error::new(format!(
                    "{shown}: {top}/corpus/index.json is not in the archive"
                )));
            }
            let prov = files.get(&format!("{top}/PROVENANCE.json")).cloned();
            (
                Files::Archive { files, top },
                format!("{shown} (sha256 {got})"),
                prov,
            )
        };

        let mut store = Store {
            files,
            manifest_sums: HashMap::new(),
        };
        let roots: &[Root] = if store.same_roots() {
            &[Root::Corpus]
        } else {
            &[Root::Corpus, Root::Stress]
        };
        for &root in roots {
            if let Some(b) = store.get(root, "manifest.sha256")? {
                let what = store.describe(root, "manifest.sha256");
                let sums = parse_sums(&b, &what)?;
                store.manifest_sums.insert(root.name(), sums);
            }
        }

        let version = match provenance {
            Some(b) => {
                let v = parse_json(&b, "PROVENANCE.json")?;
                v.get("version")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::new("PROVENANCE.json: no version"))?
                    .to_string()
            }
            None => {
                let what = store.describe(Root::Corpus, "corpus.json");
                let v = parse_json(&store.read(Root::Corpus, "corpus.json")?, &what)?;
                v.get("corpus_version")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::new(format!("{what}: no corpus_version")))?
                    .to_string()
            }
        };

        let what = store.describe(Root::Corpus, "index.json");
        let index = parse_json(&store.read(Root::Corpus, "index.json")?, &what)?;
        if index.get("schema").and_then(Value::as_str) != Some("xcc.index/v1") {
            return Err(Error::new(format!("{what}: schema is not xcc.index/v1")));
        }
        let rows = index
            .get("entries")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::new(format!("{what}: no entries array")))?;
        let store = Arc::new(store);
        let mut entries = Vec::with_capacity(rows.len());
        let mut by_id = HashMap::new();
        for row in rows {
            let e = Entry::from_row(row, &store, &what)?;
            if by_id.insert(e.id.clone(), entries.len()).is_some() {
                return Err(Error::new(format!(
                    "{what}: entry {} is listed twice",
                    e.id
                )));
            }
            entries.push(e);
        }
        Ok(Corpus {
            version,
            source,
            entries,
            by_id,
        })
    }

    /// The corpus version: the release's PROVENANCE.json version, else corpus.json corpus_version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Where the corpus was read from, for logs.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Every entry of the index, stress entries included, in index order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The entry with this ID.
    pub fn entry(&self, id: &str) -> Option<&Entry> {
        self.by_id.get(id).map(|&i| &self.entries[i])
    }
}

/// A sha256sum-format file: path -> sha256.
fn parse_sums(b: &[u8], what: &str) -> Result<HashMap<String, String>> {
    let text = std::str::from_utf8(b).map_err(|_| Error::new(format!("{what}: not UTF-8")))?;
    let mut out = HashMap::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let (sum, path) = line
            .split_once(' ')
            .ok_or_else(|| Error::new(format!("{what}:{}: not `<sha256>  <path>`", i + 1)))?;
        let path = path.trim_start_matches(' ').trim_start_matches('*');
        out.insert(path.to_string(), sum.to_ascii_lowercase());
    }
    Ok(out)
}

fn field_str(row: &Value, key: &str, what: &str) -> Result<String> {
    row.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::new(format!("{what}: field {key} is missing or not a string")))
}

fn field_opt_str(row: &Value, key: &str) -> Option<String> {
    row.get(key).and_then(Value::as_str).map(str::to_string)
}

fn field_u64(row: &Value, key: &str, what: &str) -> Result<u64> {
    row.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::new(format!("{what}: field {key} is missing or not an integer")))
}

fn field_strs(row: &Value, key: &str, what: &str) -> Result<Vec<String>> {
    row.get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new(format!("{what}: field {key} is missing or not an array")))?
        .iter()
        .map(|x| {
            x.as_str()
                .map(str::to_string)
                .ok_or_else(|| Error::new(format!("{what}: {key} holds a non-string")))
        })
        .collect()
}

/// One entry: its index row, and its manifest.
pub struct Entry {
    pub id: String,
    pub title: String,
    /// `ledger`, `xdr`, `api`, `strkey` or `spec`.
    pub kind: String,
    pub caps: Vec<u32>,
    pub rows: Vec<String>,
    pub protocol_introduced: u32,
    pub synthetic: bool,
    /// `valid`, `malformed`, `invalid` or `acceptable` (docs/manifest.md §9.5).
    pub validity: String,
    pub flags: Vec<String>,
    pub sources: Vec<String>,
    /// `curated`, or `stress` for an entry a release ships under `stress/`.
    pub tier: String,
    /// The manifest file, relative to the entry's corpus root.
    pub manifest_path: String,
    pub variants: Vec<Variant>,
    manifest: Value,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("validity", &self.validity)
            .field("tier", &self.tier)
            .field("variants", &self.variants)
            .finish()
    }
}

impl Entry {
    fn from_row(row: &Value, store: &Arc<Store>, index: &str) -> Result<Entry> {
        let id = field_str(row, "id", index)?;
        let what = format!("{index}: entry {id}");
        let tier = field_str(row, "tier", &what)?;
        let root = if tier == "stress" {
            Root::Stress
        } else {
            Root::Corpus
        };
        let manifest_path = field_str(row, "manifest", &what)?;
        let mwhat = store.describe(root, &manifest_path);
        let mbytes = store.read(root, &manifest_path)?;
        if let Some(sums) = store.manifest_sums.get(root.name()) {
            let want = sums.get(&manifest_path).ok_or_else(|| {
                Error::new(format!("{mwhat}: not listed in the root's manifest.sha256"))
            })?;
            let got = sha256_hex(&mbytes);
            if &got != want {
                return Err(Error::new(format!(
                    "{mwhat}: sha256 {got}, but manifest.sha256 says {want}"
                )));
            }
        }
        let manifest = parse_json(&mbytes, &mwhat)?;
        let kind = field_str(row, "kind", &what)?;
        let caps = row
            .get("caps")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::new(format!("{what}: field caps is missing")))?
            .iter()
            .map(|c| {
                c.as_u64()
                    .and_then(|c| u32::try_from(c).ok())
                    .ok_or_else(|| Error::new(format!("{what}: caps holds a non-integer")))
            })
            .collect::<Result<Vec<u32>>>()?;
        let protocol_introduced = row
            .get("protocol")
            .and_then(|p| p.get("introduced"))
            .and_then(Value::as_u64)
            .and_then(|p| u32::try_from(p).ok())
            .ok_or_else(|| Error::new(format!("{what}: protocol.introduced is missing")))?;
        let synthetic = row
            .get("synthetic")
            .and_then(Value::as_bool)
            .ok_or_else(|| Error::new(format!("{what}: field synthetic is missing")))?;

        let rows_v = row
            .get("variants")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::new(format!("{what}: field variants is missing")))?;
        let protocols: HashSet<u64> = rows_v
            .iter()
            .filter_map(|v| v.get("protocol").and_then(Value::as_u64))
            .collect();
        let manifest_variants = manifest
            .get("variants")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let mut variants = Vec::with_capacity(rows_v.len());
        for v in rows_v {
            let network = field_str(v, "network", &what)?;
            let protocol = field_u64(v, "protocol", &what)?;
            let vwhat = format!("{what} variant {network}@{protocol}");
            let key = if protocols.len() > 1 {
                format!("{network}@{protocol}")
            } else {
                network.clone()
            };
            let mv = manifest_variants
                .iter()
                .find(|m| {
                    m.get("network").and_then(Value::as_str) == Some(network.as_str())
                        && m.get("protocol").and_then(Value::as_u64) == Some(protocol)
                })
                .ok_or_else(|| Error::new(format!("{mwhat}: no variant {network}@{protocol}")))?;
            let framing = field_opt_str(mv, "framing").unwrap_or_else(|| "none".into());
            let frame_index = mv.get("frame_index").and_then(Value::as_u64).unwrap_or(0);
            variants.push(Variant {
                entry_id: id.clone(),
                entry_kind: kind.clone(),
                key,
                network,
                protocol: u32::try_from(protocol)
                    .map_err(|_| Error::new(format!("{vwhat}: protocol out of range")))?,
                ledger_seq: v.get("ledger_seq").and_then(Value::as_u64),
                xdr_type: field_str(v, "xdr_type", &vwhat)?,
                validity: field_str(v, "validity", &vwhat)?,
                blob_path: field_opt_str(v, "blob"),
                sha256: field_str(v, "sha256", &vwhat)?,
                bytes: field_u64(v, "bytes", &vwhat)?,
                decoded_path: field_opt_str(v, "decoded"),
                decoded_sha256: field_opt_str(v, "decoded_sha256"),
                framing,
                frame_index: usize::try_from(frame_index)
                    .map_err(|_| Error::new(format!("{vwhat}: frame_index out of range")))?,
                root,
                store: Arc::clone(store),
            });
        }
        Ok(Entry {
            title: field_str(row, "title", &what)?,
            kind,
            caps,
            rows: field_strs(row, "rows", &what)?,
            protocol_introduced,
            synthetic,
            validity: field_str(row, "validity", &what)?,
            flags: field_strs(row, "flags", &what)?,
            sources: field_strs(row, "sources", &what)?,
            tier,
            manifest_path,
            variants,
            manifest,
            id,
        })
    }

    /// The manifest entry, parsed (checked against the root's manifest.sha256 when it has one).
    pub fn manifest(&self) -> &Value {
        &self.manifest
    }

    /// The manifest's `expect.reject.reason`, for a negative entry.
    pub fn expect_reject_reason(&self) -> Option<&str> {
        self.manifest
            .pointer("/expect/reject/reason")
            .and_then(Value::as_str)
    }

    /// The variant with this report key.
    pub fn variant(&self, key: &str) -> Option<&Variant> {
        self.variants.iter().find(|v| v.key == key)
    }
}

/// One variant: the entry's bytes on one network at one protocol.
pub struct Variant {
    /// The entry's ID.
    pub entry_id: String,
    /// The entry's kind.
    pub entry_kind: String,
    /// The report key: `network`, or `network@protocol` when the entry's variants span several protocols.
    pub key: String,
    pub network: String,
    pub protocol: u32,
    pub ledger_seq: Option<u64>,
    /// The type name in the pinned XDR definitions (`LedgerCloseMeta`, `ScVal`, ...).
    pub xdr_type: String,
    /// The variant's validity (its own, else the entry's).
    pub validity: String,
    /// The blob's path relative to the corpus root; None for a bulk-tier variant fetched by hash.
    pub blob_path: Option<String>,
    pub sha256: String,
    pub bytes: u64,
    /// The sidecar's path; None when the bytes do not decode.
    pub decoded_path: Option<String>,
    /// sha256 of the sidecar's uncompressed JSON.
    pub decoded_sha256: Option<String>,
    /// `none`: the blob is one value; `record-marked`: an RFC 5531 record-marked stream.
    pub framing: String,
    /// With `record-marked`: the record that holds the value.
    pub frame_index: usize,
    root: Root,
    store: Arc<Store>,
}

impl fmt::Debug for Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Variant")
            .field("key", &self.key)
            .field("xdr_type", &self.xdr_type)
            .field("validity", &self.validity)
            .field("blob_path", &self.blob_path)
            .finish()
    }
}

impl Variant {
    /// The blob, checked: its sha256 and length must equal the index.
    pub fn blob(&self) -> Result<Vec<u8>> {
        let path = self.blob_path.as_deref().ok_or_else(|| {
            Error::new(format!(
                "{} {}: the blob is not in the corpus (bulk tier, fetched by hash {})",
                self.entry_id, self.key, self.sha256
            ))
        })?;
        let b = self.store.read(self.root, path)?;
        let got = sha256_hex(&b);
        if got != self.sha256 || b.len() as u64 != self.bytes {
            return Err(Error::new(format!(
                "{}: sha256 {got} and {} bytes, but the index says {} and {} bytes",
                self.store.describe(self.root, path),
                b.len(),
                self.sha256,
                self.bytes
            )));
        }
        Ok(b.into_owned())
    }

    /// The sidecar's uncompressed JSON text, checked against `decoded_sha256`; None when the bytes do not decode.
    pub fn expected_json_bytes(&self) -> Result<Option<Vec<u8>>> {
        let Some(path) = self.decoded_path.as_deref() else {
            return Ok(None);
        };
        let what = self.store.describe(self.root, path);
        let want = self
            .decoded_sha256
            .as_deref()
            .ok_or_else(|| Error::new(format!("{what}: the index gives no decoded_sha256")))?;
        let z = self.store.read(self.root, path)?;
        let json = zstd::stream::decode_all(&z[..])
            .map_err(|e| Error::new(format!("{what}: not zstd: {e}")))?;
        let got = sha256_hex(&json);
        if got != want {
            return Err(Error::new(format!(
                "{what}: uncompressed sha256 {got}, but the index says {want}"
            )));
        }
        Ok(Some(json))
    }

    /// The expected SEP-51 JSON value of the bytes; None when the bytes do not decode.
    pub fn expected_json(&self) -> Result<Option<Value>> {
        match self.expected_json_bytes()? {
            None => Ok(None),
            Some(b) => {
                let what = self
                    .store
                    .describe(self.root, self.decoded_path.as_deref().unwrap_or_default());
                parse_json(&b, &what).map(Some)
            }
        }
    }

    /// An L0 byte decoder must refuse these bytes: validity `malformed` or `invalid`.
    pub fn must_refuse(&self) -> bool {
        matches!(self.validity.as_str(), "malformed" | "invalid")
    }

    /// One value of `xdr_type` to decode: an entry of kind `ledger` or `xdr` whose blob is not record-marked.
    pub fn decodable(&self) -> bool {
        matches!(self.entry_kind.as_str(), "ledger" | "xdr") && self.framing == "none"
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Expected-failure lists.

/// The level of a list line naming an entry variant the run never reads.
pub const UNREAD: &str = "unread";

fn dash(v: &str) -> &str {
    if v.is_empty() {
        "-"
    } else {
        v
    }
}

fn row_key(entry: &str, variant: &str, level: &str) -> String {
    format!("{entry} {} {level}", dash(variant))
}

/// One line of an expected-failure list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedFailure {
    pub entry: String,
    /// `-` for an entry without variants.
    pub variant: String,
    /// A level (`L0`, ...) or [`UNREAD`].
    pub level: String,
    /// The line number in the file.
    pub line: usize,
}

impl fmt::Display for ExpectedFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.entry, dash(&self.variant), self.level)
    }
}

/// An expected-failure list: one item per line, `<entry> <variant or -> <level or unread>`, `#` starts a comment
/// to the end of the line, blank lines are ignored (the format of `xdrcheck conform --expected-failures`).
#[derive(Debug, Clone, Default)]
pub struct ExpectedFailures {
    /// The file's name, used in messages.
    pub name: String,
    pub items: Vec<ExpectedFailure>,
}

impl ExpectedFailures {
    /// Parses a list; a line that is not three fields, or an item listed twice, is an error.
    pub fn parse(text: &str, name: &str) -> Result<ExpectedFailures> {
        let mut items = Vec::new();
        let mut seen: HashMap<String, usize> = HashMap::new();
        for (i, raw) in text.lines().enumerate() {
            let n = i + 1;
            let line = raw.split('#').next().unwrap_or("");
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.is_empty() {
                continue;
            }
            if fields.len() != 3 {
                return Err(Error::new(format!(
                    "{name}:{n}: want `<entry> <variant or -> <level or unread>`, got {:?}",
                    line.trim()
                )));
            }
            let f = ExpectedFailure {
                entry: fields[0].to_string(),
                variant: fields[1].to_string(),
                level: fields[2].to_string(),
                line: n,
            };
            let k = row_key(&f.entry, &f.variant, &f.level);
            if let Some(prev) = seen.insert(k, n) {
                return Err(Error::new(format!(
                    "{name}:{n}: {f} is already listed on line {prev}"
                )));
            }
            items.push(f);
        }
        Ok(ExpectedFailures {
            name: name.to_string(),
            items,
        })
    }

    /// Reads and parses a list file.
    pub fn read(path: impl AsRef<Path>) -> Result<ExpectedFailures> {
        let path = path.as_ref();
        let name = path.display().to_string();
        let text = std::fs::read_to_string(path).map_err(|e| Error::new(format!("{name}: {e}")))?;
        Self::parse(&text, &name)
    }

    /// A list file of the run's failures and unread variants: header comment lines naming `about` (the SDK
    /// and corpus), then the sorted lines `<entry> <variant> <level>  # <detail>`.
    pub fn write(results: &Results, about: &str) -> String {
        let mut lines: Vec<(String, String)> = Vec::new();
        for c in results.cells.iter().filter(|c| c.failed) {
            lines.push((
                row_key(&c.entry, &c.variant, &c.level),
                format!(
                    "{} {} {}  # {}",
                    c.entry,
                    dash(&c.variant),
                    c.level,
                    one_line(&c.detail, 400)
                ),
            ));
        }
        for u in &results.unread {
            lines.push((
                row_key(&u.entry, &u.variant, UNREAD),
                format!(
                    "{} {} {UNREAD}  # never read: {}",
                    u.entry,
                    dash(&u.variant),
                    one_line(&u.reason, 400)
                ),
            ));
        }
        lines.sort();
        lines.dedup_by(|a, b| a.0 == b.0);
        let mut out = String::new();
        out.push_str(&format!("# Expected failures of {about}.\n"));
        out.push_str("# The run passes only when its failures are exactly these lines: a new failure fails, and so does a\n");
        out.push_str("# listed cell that passes (remove its line when a bug is fixed).\n");
        out.push_str("# <entry> <variant or -> <level>  # what the SDK did\n");
        out.push_str("# <entry> <variant or -> unread   # an entry variant the SDK never reads\n");
        for (_, l) in lines {
            out.push_str(&l);
            out.push('\n');
        }
        out
    }
}

fn one_line(s: &str, max: usize) -> String {
    let s: String = s
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    if s.chars().count() <= max {
        return s;
    }
    let mut t: String = s.chars().take(max).collect();
    t.push('…');
    t
}

/// One judged cell of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub entry: String,
    pub variant: String,
    pub level: String,
    pub failed: bool,
    pub detail: String,
}

/// An entry variant the run never read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unread {
    pub entry: String,
    pub variant: String,
    pub reason: String,
}

/// What a run found, cell by cell.
#[derive(Debug, Clone, Default)]
pub struct Results {
    pub cells: Vec<Cell>,
    pub unread: Vec<Unread>,
    selected: BTreeSet<String>,
}

impl Results {
    pub fn new() -> Results {
        Results::default()
    }

    /// A cell that does not conform; `detail` says what the SDK did.
    pub fn fail(&mut self, entry: &str, variant: &str, level: &str, detail: &str) {
        self.record(entry, variant, level, true, detail);
    }

    /// A cell that conforms.
    pub fn pass(&mut self, entry: &str, variant: &str, level: &str) {
        self.record(entry, variant, level, false, "");
    }

    /// An entry variant the run could not read at all.
    pub fn unread(&mut self, entry: &str, variant: &str, reason: &str) {
        self.selected.insert(entry.to_string());
        self.unread.push(Unread {
            entry: entry.to_string(),
            variant: dash(variant).to_string(),
            reason: reason.to_string(),
        });
    }

    /// Marks an entry as selected by the run without recording a cell for it, so a listed line of it that the
    /// run does not have is NOT-RUN rather than ignored.
    pub fn select(&mut self, entry: &str) {
        self.selected.insert(entry.to_string());
    }

    fn record(&mut self, entry: &str, variant: &str, level: &str, failed: bool, detail: &str) {
        self.selected.insert(entry.to_string());
        self.cells.push(Cell {
            entry: entry.to_string(),
            variant: dash(variant).to_string(),
            level: level.to_string(),
            failed,
            detail: detail.to_string(),
        });
    }

    /// Compares the run with a list. `require_all_read` makes an unread variant the list does not name a
    /// difference (NEW-UNREAD). Listed lines of entries the run did not select are ignored.
    pub fn compare(&self, list: &ExpectedFailures, require_all_read: bool) -> Comparison {
        let listed: HashSet<String> = list
            .items
            .iter()
            .map(|f| row_key(&f.entry, &f.variant, &f.level))
            .collect();
        let mut c = Comparison {
            name: list.name.clone(),
            ..Comparison::default()
        };
        let mut present: HashSet<String> = HashSet::new();
        for cell in &self.cells {
            let k = row_key(&cell.entry, &cell.variant, &cell.level);
            present.insert(k.clone());
            present.insert(row_key(&cell.entry, &cell.variant, UNREAD));
            match (cell.failed, listed.contains(&k)) {
                (true, true) => c.matched += 1,
                (true, false) => c.new_failures.push(cell.clone()),
                (false, true) => c.now_passing.push(cell.clone()),
                (false, false) => {}
            }
        }
        let mut unread: HashSet<String> = HashSet::new();
        for u in &self.unread {
            let k = row_key(&u.entry, &u.variant, UNREAD);
            present.insert(k.clone());
            unread.insert(k.clone());
            if listed.contains(&k) {
                c.matched += 1;
            } else if require_all_read {
                c.new_unread.push(u.clone());
            }
        }
        for f in &list.items {
            let k = row_key(&f.entry, &f.variant, &f.level);
            if !present.contains(&k) {
                if self.selected.contains(&f.entry) {
                    c.not_run.push(f.clone());
                }
            } else if f.level == UNREAD && !unread.contains(&k) {
                c.now_read.push(f.clone());
            }
        }
        c
    }
}

/// A run compared with an expected-failure list.
#[derive(Debug, Clone, Default)]
pub struct Comparison {
    /// The list's name.
    pub name: String,
    /// Listed cells that still fail, and listed variants still unread.
    pub matched: usize,
    /// Failing cells the list does not name.
    pub new_failures: Vec<Cell>,
    /// Listed cells that now conform.
    pub now_passing: Vec<Cell>,
    /// Listed as unread, but the run read them.
    pub now_read: Vec<ExpectedFailure>,
    /// Unread variants the list does not name (only under `require_all_read`).
    pub new_unread: Vec<Unread>,
    /// Listed items of selected entries that the run does not have.
    pub not_run: Vec<ExpectedFailure>,
}

impl Comparison {
    /// The run's failures and unread variants are exactly the list.
    pub fn passed(&self) -> bool {
        self.new_failures.is_empty()
            && self.now_passing.is_empty()
            && self.now_read.is_empty()
            && self.new_unread.is_empty()
            && self.not_run.is_empty()
    }

    /// Writes every difference with what to do, then a summary line, as `xdrcheck conform` does.
    pub fn print(&self, w: &mut dyn Write) -> std::io::Result<()> {
        let file = &self.name;
        for c in &self.new_failures {
            writeln!(
                w,
                "NEW-FAILURE   {} {} {}: {}",
                c.entry, c.variant, c.level, c.detail
            )?;
        }
        for c in &self.now_passing {
            writeln!(
                w,
                "UNEXPECTED-PASS {} {} {}: listed as failing but now conforms; remove the line from {file}",
                c.entry, c.variant, c.level
            )?;
        }
        for f in &self.now_read {
            writeln!(
                w,
                "UNEXPECTED-PASS {} {} {UNREAD}: listed as unread but the column now reads it; remove the line from {file}",
                f.entry,
                dash(&f.variant)
            )?;
        }
        for u in &self.new_unread {
            writeln!(
                w,
                "NEW-UNREAD    {} {}: never read ({})",
                u.entry, u.variant, u.reason
            )?;
        }
        for f in &self.not_run {
            writeln!(
                w,
                "NOT-RUN       {f} ({file} line {}): the run has no such cell; remove the line or fix its spelling",
                f.line
            )?;
        }
        writeln!(
            w,
            "expected failures {file}: {} still as listed, {} new failures, {} new unread, {} unexpected passes, {} listed but not run",
            self.matched,
            self.new_failures.len(),
            self.new_unread.len(),
            self.now_passing.len() + self.now_read.len(),
            self.not_run.len()
        )
    }

    /// [`Comparison::print`] into a string.
    pub fn to_text(&self) -> String {
        let mut b = Vec::new();
        self.print(&mut b).expect("writing to a Vec does not fail");
        String::from_utf8_lossy(&b).into_owned()
    }
}
