//! History capture from the public Stellar data lake (the `history` source, `docs/manifest.md` §4.4).
//!
//! **Where.** The lake is the SEP-54 store on AWS Open Data, one ledger per object and 64,000
//! objects per partition. The key of ledger `s` is
//! `%08X--%d-%d/%08X--%d.xdr.zst` of `(0xFFFFFFFF − p, p, p + 63999, 0xFFFFFFFF − s, s)` with
//! `p = s / 64000 * 64000` ([`object_key`]). The stores are `[public_lake]` in `pins.toml`: pubnet,
//! and the current testnet epoch.
//!
//! **How (pinned transport).** Anonymous HTTPS through the `curl` command against the bucket's
//! regional endpoint [`HTTPS_ENDPOINT`]: a `HEAD` for the object's user metadata (`x-amz-meta-*`:
//! `core-version`, exporter `version`, `protocol-version`, `network-passphrase`, …),
//! `Last-Modified` and `ETag`, then a `GET` of the bytes. No credentials, no SDK; any reviewer can
//! repeat it with the `refetch` command recorded per capture.
//!
//! **What is kept.** The object exactly as served, at `corpus/objects/<network>/<seq>/<basename of
//! the key>`, and `capture.json` beside it ([`CaptureRecord`], format documented in
//! `corpus/objects/README.md`). The chain object → blob is: `object_sha256` → zstd decompress →
//! `decompressed_sha256` → the `LedgerCloseMetaBatch` → bytes `[blob_offset, blob_offset +
//! blob_bytes)` → `blob_sha256`. With one ledger per batch the blob starts at offset 12.
//!
//! **Writer and `regenerated`.** `written_by` is the object's `core-version` and exporter
//! `version` metadata. `regenerated` ([`is_regenerated`]) says the object was written by a core
//! newer than the ledger's protocol era, so its meta is not what a node emitted when the ledger
//! closed.
//!
//! Two older `capture.json` layouts (written before this tool existed) are read by
//! [`load_prior`] so a re-capture keeps their first capture time and research notes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use xdrcheck_xdr::{Gate, Limits};

use super::ledger::{summarise, LedgerSummary};
use super::manifest::{blob_rel_path, upsert_variant, write_blob, Upsert};
use super::pins::Pins;
use super::util::{
    now_rfc3339, parse_http_date, parse_rfc3339, read_json, rfc3339, write_atomic, write_json,
    CheckFailed,
};

/// Regional HTTPS endpoint of the `aws-public-blockchain` bucket (virtual-hosted style).
pub const HTTPS_ENDPOINT: &str = "https://aws-public-blockchain.s3.us-east-2.amazonaws.com";
/// The bucket as an `s3://` URL; `[public_lake] bucket` in `pins.toml` must start with it.
pub const S3_BUCKET: &str = "s3://aws-public-blockchain";
/// Ledgers per object in the public lake.
pub const LEDGERS_PER_BATCH: u32 = 1;
/// Objects per partition in the public lake.
pub const BATCHES_PER_PARTITION: u32 = 64_000;
/// `schema` value of a normalised `capture.json`.
pub const CAPTURE_SCHEMA: &str = "xcc.capture/v1";
/// An object written more than this long after its ledger closed was written by a later export,
/// not by the node that closed the ledger.
pub const LIVE_WRITE_WINDOW_SECS: i64 = 86_400;

/// A network with a public lake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// The public network.
    Pubnet,
    /// The test network (resets; its objects are perishable).
    Testnet,
}

impl Network {
    /// Parse `pubnet` or `testnet`.
    pub fn parse(s: &str) -> Result<Network> {
        match s {
            "pubnet" => Ok(Network::Pubnet),
            "testnet" => Ok(Network::Testnet),
            _ => bail!("network must be pubnet or testnet, not {s:?}"),
        }
    }

    /// `pubnet` or `testnet`.
    pub fn name(self) -> &'static str {
        match self {
            Network::Pubnet => "pubnet",
            Network::Testnet => "testnet",
        }
    }

    /// The network passphrase.
    pub fn passphrase(self) -> &'static str {
        match self {
            Network::Pubnet => "Public Global Stellar Network ; September 2015",
            Network::Testnet => "Test SDF Network ; September 2015",
        }
    }

    /// Whether the public source will disappear (testnet resets).
    pub fn perishable(self) -> bool {
        self == Network::Testnet
    }
}

/// The SEP-54 key of ledger `seq` in a store with [`LEDGERS_PER_BATCH`] = 1 and
/// [`BATCHES_PER_PARTITION`] = 64,000.
pub fn object_key(seq: u32) -> String {
    let size = LEDGERS_PER_BATCH * BATCHES_PER_PARTITION;
    let p = seq / size * size;
    let end = p.saturating_add(size - 1);
    format!(
        "{:08X}--{p}-{end}/{:08X}--{seq}.xdr.zst",
        u32::MAX - p,
        u32::MAX - seq
    )
}

/// Where one ledger's object lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// `s3://…` store root, as manifests record it.
    pub store: String,
    /// Key under the store.
    pub key: String,
    /// HTTPS URL of the object.
    pub url: String,
}

impl Location {
    /// Base name of the object (the vendored file name).
    pub fn file_name(&self) -> &str {
        self.key.rsplit('/').next().unwrap_or(&self.key)
    }

    /// The command a reviewer runs to fetch the same bytes.
    pub fn refetch_command(&self) -> String {
        format!("curl -fsS -o {} {}", self.file_name(), self.url)
    }
}

/// The location of `seq` on `network` under the pinned stores.
pub fn locate(pins: &Pins, network: Network, seq: u32) -> Result<Location> {
    let prefix = match network {
        Network::Pubnet => &pins.lake_pubnet,
        Network::Testnet => &pins.lake_testnet,
    };
    let store = format!("{}/{prefix}", pins.lake_bucket.trim_end_matches('/'));
    let key = object_key(seq);
    Ok(Location {
        url: https_url(&store, &key)?,
        store,
        key,
    })
}

/// The HTTPS URL of `key` in an `s3://aws-public-blockchain/…` store.
pub fn https_url(store: &str, key: &str) -> Result<String> {
    let path = store
        .strip_prefix(S3_BUCKET)
        .and_then(|p| p.strip_prefix('/'))
        .with_context(|| format!("store {store} is not under {S3_BUCKET}"))?;
    Ok(format!(
        "{HTTPS_ENDPOINT}/{}/{key}",
        path.trim_end_matches('/')
    ))
}

// --- Fetching ---

/// Result of a request: the object, or the HTTP status that says it is not there.
#[derive(Debug)]
pub enum Fetch<T> {
    /// 200.
    Found(T),
    /// 404 (or 403, which S3 returns for a missing key when listing is not allowed).
    Gone(u16),
}

/// What a `HEAD` returns that capture keeps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Head {
    /// User metadata (`x-amz-meta-*` without the prefix), as served.
    pub metadata: BTreeMap<String, String>,
    /// `Last-Modified` as `YYYY-MM-DDTHH:MM:SSZ`.
    pub last_modified: Option<String>,
    /// `ETag`, quotes included.
    pub etag: Option<String>,
    /// `Content-Length`.
    pub content_length: Option<u64>,
}

/// One fetched object.
#[derive(Debug, Clone)]
pub struct Fetched {
    /// The object bytes as served.
    pub object: Vec<u8>,
    /// Its `HEAD` response.
    pub head: Head,
    /// The transport, e.g. `curl 8.14.1`.
    pub fetched_with: String,
}

fn curl(args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("curl")
        .args([
            "-sS",
            "--retry",
            "3",
            "--retry-delay",
            "2",
            "--max-time",
            "300",
        ])
        .args(args)
        .output()
        .context("run curl (is it installed?)")?;
    if !out.status.success() {
        bail!(
            "curl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

/// `curl <version>` of the installed curl.
pub fn curl_version() -> String {
    Command::new("curl")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            let first = text
                .lines()
                .next()?
                .split_whitespace()
                .take(2)
                .collect::<Vec<_>>();
            Some(first.join(" "))
        })
        .unwrap_or_else(|| "curl".to_string())
}

/// `HEAD` an object anonymously.
pub fn head(url: &str) -> Result<Fetch<Head>> {
    let text = String::from_utf8_lossy(&curl(&["-I", url])?).to_string();
    parse_head(&text)
}

/// Parse the header block(s) curl prints for `-I`; the last block is the object's.
pub fn parse_head(text: &str) -> Result<Fetch<Head>> {
    let block = text
        .split("\r\n\r\n")
        .flat_map(|b| b.split("\n\n"))
        .filter(|b| b.trim_start().starts_with("HTTP/"))
        .last()
        .context("no HTTP status line in the HEAD response")?;
    let mut lines = block.lines();
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .context("unreadable HTTP status line")?;
    match status {
        200 => {}
        403 | 404 => return Ok(Fetch::Gone(status)),
        _ => bail!("HEAD returned HTTP {status}"),
    }
    let mut h = Head::default();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim().to_string());
        if let Some(meta) = name.strip_prefix("x-amz-meta-") {
            h.metadata.insert(meta.to_string(), value);
        } else if name == "last-modified" {
            h.last_modified = Some(rfc3339(parse_http_date(&value)?));
        } else if name == "etag" {
            h.etag = Some(value);
        } else if name == "content-length" {
            h.content_length = value.parse().ok();
        }
    }
    Ok(Fetch::Found(h))
}

/// `GET` an object anonymously.
pub fn get(url: &str) -> Result<Fetch<Vec<u8>>> {
    let mut out = curl(&["-w", "\n%{http_code}", url])?;
    let nl = out
        .iter()
        .rposition(|&b| b == b'\n')
        .context("no status from curl")?;
    let status: u16 = String::from_utf8_lossy(&out[nl + 1..])
        .trim()
        .parse()
        .context("unreadable HTTP status from curl")?;
    out.truncate(nl);
    match status {
        200 => Ok(Fetch::Found(out)),
        403 | 404 => Ok(Fetch::Gone(status)),
        _ => bail!("GET returned HTTP {status}"),
    }
}

/// `HEAD` then `GET` one object.
pub fn fetch(loc: &Location) -> Result<Fetch<Fetched>> {
    let head = match head(&loc.url)? {
        Fetch::Found(h) => h,
        Fetch::Gone(s) => return Ok(Fetch::Gone(s)),
    };
    let object = match get(&loc.url)? {
        Fetch::Found(b) => b,
        Fetch::Gone(s) => return Ok(Fetch::Gone(s)),
    };
    if let Some(n) = head.content_length {
        ensure!(
            n == object.len() as u64,
            "{}: HEAD says {n} bytes, GET returned {}",
            loc.url,
            object.len()
        );
    }
    Ok(Fetch::Found(Fetched {
        object,
        head,
        fetched_with: curl_version(),
    }))
}

// --- The object → blob chain ---

/// What the object's bytes say.
#[derive(Debug, Clone)]
pub struct ObjectFacts {
    /// sha256 of the object as served.
    pub object_sha256: String,
    /// Its length.
    pub object_bytes: u64,
    /// sha256 of the decompressed `LedgerCloseMetaBatch`.
    pub decompressed_sha256: String,
    /// Its length.
    pub decompressed_bytes: u64,
    /// Index of the ledger in the batch.
    pub batch_index: u32,
    /// Offset of the ledger's bytes in the decompressed object.
    pub blob_offset: u64,
    /// The ledger's bytes (the blob).
    pub blob: Vec<u8>,
    /// sha256 of the blob.
    pub blob_sha256: String,
    /// What the ledger says.
    pub ledger: LedgerSummary,
}

/// Decompress the object, split its batch (gate, limits, byte-exact re-encode), cut ledger `seq`
/// out of it and summarise that ledger under `network`'s passphrase.
pub fn analyse(object: &[u8], network: Network, seq: u32, gate: &Gate) -> Result<ObjectFacts> {
    let limits = Limits::default();
    let xdr = xdrcheck_xdr::batch::decompress(object).context("decompress the lake object")?;
    let batch =
        xdrcheck_xdr::split_batch(&xdr, &limits, gate).context("split the LedgerCloseMetaBatch")?;
    let i = batch
        .infos
        .iter()
        .position(|info| info.sequence == seq)
        .with_context(|| {
            format!(
                "ledger {seq} is not in the batch {}..={}",
                batch.start_sequence, batch.end_sequence
            )
        })?;
    let offset = 12 + batch.ledgers[..i].iter().map(Vec::len).sum::<usize>();
    let blob = &xdr[offset..offset + batch.ledgers[i].len()];
    ensure!(
        blob == batch.ledgers[i].as_slice(),
        "batch split disagrees with the offset"
    );
    let ledger = summarise(blob, network.passphrase(), &limits, gate)?;
    ensure!(
        ledger.ledger_seq == seq,
        "blob is ledger {}, not {seq}",
        ledger.ledger_seq
    );
    Ok(ObjectFacts {
        object_sha256: xdrcheck_xdr::sha256_hex(object),
        object_bytes: object.len() as u64,
        decompressed_sha256: xdrcheck_xdr::sha256_hex(&xdr),
        decompressed_bytes: xdr.len() as u64,
        batch_index: i as u32,
        blob_offset: offset as u64,
        blob_sha256: xdrcheck_xdr::sha256_hex(blob),
        blob: blob.to_vec(),
        ledger,
    })
}

/// `written_by` from the object metadata: `<core-version>; exporter <version>`.
pub fn written_by(metadata: &BTreeMap<String, String>) -> Result<String> {
    let core = metadata
        .get("core-version")
        .context("object metadata has no core-version, so written_by cannot be recorded")?;
    Ok(match metadata.get("version") {
        Some(v) => format!("{core}; exporter {v}"),
        None => core.clone(),
    })
}

/// Major version of a `core-version` value such as `stellar-core 23.0.1 (050eacf…)`.
pub fn core_major(core_version: &str) -> Option<u32> {
    let v = core_version.split_whitespace().find(|w| {
        w.trim_start_matches('v')
            .starts_with(|c: char| c.is_ascii_digit())
    })?;
    v.trim_start_matches('v').split('.').next()?.parse().ok()
}

/// Whether a lake object for a ledger at `protocol` written by a core of major version
/// `writer_major`, `lag_secs` after the ledger closed, is regenerated (not the meta a node
/// emitted when the ledger closed).
///
/// A core of major version N implements protocols up to N, and a network at protocol P runs cores
/// P and, before the vote to P + 1, P + 1. So:
/// - `writer_major > protocol + 1`: the writer is newer than any core of the ledger's era —
///   regenerated (the pubnet lake's Protocol 1–21 ledgers, written by core 23.0.1);
/// - `writer_major == protocol + 1`: either a node that had already upgraded wrote it live, or a
///   later export did; it is regenerated when the object was written more than
///   [`LIVE_WRITE_WINDOW_SECS`] after the ledger closed (the Protocol 22 ledgers written by core
///   23.0.1 months later), or when that time is unknown;
/// - `writer_major <= protocol`: a core of the ledger's own era wrote it — not regenerated.
pub fn is_regenerated(writer_major: u32, protocol: u32, lag_secs: Option<i64>) -> bool {
    if writer_major > protocol + 1 {
        return true;
    }
    if writer_major == protocol + 1 {
        return lag_secs.is_none_or(|lag| lag > LIVE_WRITE_WINDOW_SECS);
    }
    false
}

// --- capture.json ---

/// Facts about the captured ledger, recorded in `capture.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerFacts {
    /// Header protocol.
    pub protocol: u32,
    /// New protocol of a protocol-version upgrade in this ledger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_upgrade: Option<u32>,
    /// `LedgerCloseMeta` arm.
    pub ledger_close_meta_version: i32,
    /// Header hash in the meta.
    pub header_hash: String,
    /// Close time, Unix seconds.
    pub close_time: u64,
    /// Close time, UTC.
    pub close_time_utc: String,
    /// Number of transactions.
    pub tx_count: usize,
    /// Count of transactions per `TransactionMeta` arm (`v2`, `v3`, `v4`, …).
    pub transaction_meta_versions: BTreeMap<String, usize>,
    /// Every transaction hash was recomputed from its envelope under the passphrase.
    pub tx_hashes_recomputed: bool,
}

impl LedgerFacts {
    fn of(s: &LedgerSummary) -> LedgerFacts {
        let mut versions = BTreeMap::new();
        for v in &s.transaction_meta_versions {
            *versions.entry(format!("v{v}")).or_insert(0) += 1;
        }
        LedgerFacts {
            protocol: s.protocol,
            protocol_upgrade: s.protocol_upgrade,
            ledger_close_meta_version: s.ledger_close_meta_version,
            header_hash: s.header_hash.clone(),
            close_time: s.close_time,
            close_time_utc: rfc3339(s.close_time as i64),
            tx_count: s.tx_hashes.len(),
            transaction_meta_versions: versions,
            tx_hashes_recomputed: true,
        }
    }
}

/// A normalised `capture.json` (schema [`CAPTURE_SCHEMA`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaptureRecord {
    /// [`CAPTURE_SCHEMA`].
    pub schema: String,
    /// `pubnet` or `testnet`.
    pub network: String,
    /// Network passphrase.
    pub passphrase: String,
    /// Ledger sequence.
    pub ledger_seq: u32,
    /// `s3://` store root.
    pub store: String,
    /// Key under the store.
    pub key: String,
    /// HTTPS URL.
    pub url: String,
    /// File name of the vendored object in this directory.
    pub object_file: String,
    /// sha256 of the object as served.
    pub object_sha256: String,
    /// Its length.
    pub object_bytes: u64,
    /// sha256 after zstd decompression.
    pub decompressed_sha256: String,
    /// Its length.
    pub decompressed_bytes: u64,
    /// Index of the ledger in the batch.
    pub batch_index: u32,
    /// Offset of the blob in the decompressed bytes.
    pub blob_offset: u64,
    /// sha256 of the blob (the ledger's `LedgerCloseMeta`).
    pub blob_sha256: String,
    /// Its length.
    pub blob_bytes: u64,
    /// Core and exporter versions from the object metadata.
    pub written_by: String,
    /// See [`is_regenerated`].
    pub regenerated: bool,
    /// The public source will disappear (testnet).
    pub perishable: bool,
    /// User metadata as served.
    pub object_metadata: BTreeMap<String, String>,
    /// `Last-Modified` of the object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_last_modified: Option<String>,
    /// `ETag` of the object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_etag: Option<String>,
    /// What the ledger says.
    pub ledger: LedgerFacts,
    /// When the vendored object was first downloaded.
    pub captured_at: String,
    /// How it was first downloaded.
    pub captured_with: String,
    /// When a capture last confirmed the lake still serves the same bytes.
    pub verified_at: String,
    /// Command that fetches the same object.
    pub refetch: String,
    /// Research notes on shapes found in this ledger, carried over verbatim from the first capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shapes: Option<Value>,
    /// How to read `shapes`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shapes_note: Option<String>,
}

/// What an earlier `capture.json` (any layout) contributes to a re-capture.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Prior {
    /// Object hash recorded then.
    pub object_sha256: String,
    /// First download time.
    pub captured_at: String,
    /// First download method.
    pub captured_with: String,
    /// Metadata recorded then, if any.
    pub metadata: Option<BTreeMap<String, String>>,
    /// `Last-Modified` recorded then.
    pub last_modified: Option<String>,
    /// `ETag` recorded then.
    pub etag: Option<String>,
    /// Research notes.
    pub shapes: Option<Value>,
    /// How to read them.
    pub shapes_note: Option<String>,
}

const AWS_CLI: &str = "aws s3 cp --no-sign-request (aws-cli)";

/// Read a `capture.json` in any of the three layouts: normalised ([`CAPTURE_SCHEMA`]); the first
/// research layout (`sha256_compressed`, `downloaded_utc`, `s3_head_object`, `shapes`,
/// `schema_note`); or the locator-verification layout (`object_sha256`, `captured_at`,
/// `captured_by`, `shapes`, no metadata).
pub fn load_prior(path: &Path) -> Result<Prior> {
    let v = read_json(path)?;
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    if s("schema").as_deref() == Some(CAPTURE_SCHEMA) {
        let r: CaptureRecord = serde_json::from_value(v.clone())
            .with_context(|| format!("parse {}", path.display()))?;
        return Ok(Prior {
            object_sha256: r.object_sha256,
            captured_at: r.captured_at,
            captured_with: r.captured_with,
            metadata: Some(r.object_metadata),
            last_modified: r.object_last_modified,
            etag: r.object_etag,
            shapes: r.shapes,
            shapes_note: r.shapes_note,
        });
    }
    if let Some(sha) = s("sha256_compressed") {
        let head = v.get("s3_head_object").cloned().unwrap_or(Value::Null);
        let metadata = head.get("Metadata").and_then(Value::as_object).map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                .collect()
        });
        let last_modified = match head.get("LastModified").and_then(Value::as_str) {
            Some(t) => Some(rfc3339(parse_rfc3339(t)?)),
            None => None,
        };
        return Ok(Prior {
            object_sha256: sha,
            captured_at: s("downloaded_utc").context("downloaded_utc missing")?,
            captured_with: AWS_CLI.into(),
            metadata,
            last_modified,
            etag: head.get("ETag").and_then(Value::as_str).map(str::to_string),
            shapes: v.get("shapes").cloned(),
            shapes_note: s("schema_note"),
        });
    }
    if let Some(sha) = s("object_sha256") {
        return Ok(Prior {
            object_sha256: sha,
            captured_at: s("captured_at").context("captured_at missing")?,
            captured_with: AWS_CLI.into(),
            shapes: v.get("shapes").cloned(),
            ..Prior::default()
        });
    }
    bail!("{}: unknown capture.json layout", path.display())
}

/// Directory of a capture: `corpus/objects/<network>/<seq>`.
pub fn capture_dir(corpus: &Path, network: Network, seq: u32) -> PathBuf {
    corpus
        .join("objects")
        .join(network.name())
        .join(seq.to_string())
}

/// Build the normalised record from the location, the object facts, its metadata and any prior
/// record. Checks the metadata against the bytes: passphrase, ledger range, protocol.
pub fn build_record(
    network: Network,
    loc: &Location,
    facts: &ObjectFacts,
    head: &Head,
    prior: Option<&Prior>,
    captured_with: &str,
    now: &str,
) -> Result<CaptureRecord> {
    let meta = &head.metadata;
    let seq = facts.ledger.ledger_seq;
    if let Some(p) = meta.get("network-passphrase") {
        ensure!(
            p == network.passphrase(),
            "object metadata passphrase {p:?} is not {}'s",
            network.name()
        );
    }
    for k in ["start-ledger", "end-ledger"] {
        if let Some(v) = meta.get(k) {
            ensure!(
                *v == seq.to_string(),
                "object metadata {k} is {v}, not {seq}"
            );
        }
    }
    if let Some(v) = meta.get("protocol-version") {
        ensure!(
            *v == facts.ledger.protocol.to_string(),
            "object metadata protocol-version is {v}, the header says {}",
            facts.ledger.protocol
        );
    }
    let written_by = written_by(meta)?;
    let major = core_major(&written_by)
        .with_context(|| format!("no core major version in {written_by:?}"))?;
    let lag = match &head.last_modified {
        Some(t) => Some(parse_rfc3339(t)? - facts.ledger.close_time as i64),
        None => None,
    };
    Ok(CaptureRecord {
        schema: CAPTURE_SCHEMA.into(),
        network: network.name().into(),
        passphrase: network.passphrase().into(),
        ledger_seq: seq,
        store: loc.store.clone(),
        key: loc.key.clone(),
        url: loc.url.clone(),
        object_file: loc.file_name().into(),
        object_sha256: facts.object_sha256.clone(),
        object_bytes: facts.object_bytes,
        decompressed_sha256: facts.decompressed_sha256.clone(),
        decompressed_bytes: facts.decompressed_bytes,
        batch_index: facts.batch_index,
        blob_offset: facts.blob_offset,
        blob_sha256: facts.blob_sha256.clone(),
        blob_bytes: facts.blob.len() as u64,
        regenerated: is_regenerated(major, facts.ledger.protocol, lag),
        written_by,
        perishable: network.perishable(),
        object_metadata: meta.clone(),
        object_last_modified: head.last_modified.clone(),
        object_etag: head.etag.clone(),
        ledger: LedgerFacts::of(&facts.ledger),
        captured_at: prior.map_or_else(|| now.to_string(), |p| p.captured_at.clone()),
        captured_with: prior.map_or_else(|| captured_with.to_string(), |p| p.captured_with.clone()),
        verified_at: now.into(),
        refetch: loc.refetch_command(),
        shapes: prior.and_then(|p| p.shapes.clone()),
        shapes_note: prior.and_then(|p| p.shapes_note.clone()),
    })
}

/// The `history` variant of a capture (`manifest.md` §4.2–§4.4). `tx_index` sets the focus.
pub fn history_variant(
    corpus_rel_object: &str,
    r: &CaptureRecord,
    s: &LedgerSummary,
    tx_index: Option<usize>,
) -> Value {
    let mut v = json!({
        "network": r.network,
        "passphrase": r.passphrase,
        "protocol": s.protocol,
        "ledger_seq": r.ledger_seq,
        "xdr_type": "LedgerCloseMeta",
        "xdr_definitions": super::XDR_DEFINITIONS,
        "blob": {"sha256": r.blob_sha256, "bytes": r.blob_bytes, "path": blob_rel_path(&r.blob_sha256)},
        "source": {
            "kind": "history",
            "store": r.store,
            "key": r.key,
            "object_sha256": r.object_sha256,
            "object_bytes": r.object_bytes,
            "decompressed_sha256": r.decompressed_sha256,
            "decompressed_bytes": r.decompressed_bytes,
            "batch_index": r.batch_index,
            "blob_offset": r.blob_offset,
            "captured_at": r.captured_at,
            "written_by": r.written_by,
            "object_metadata": r.object_metadata,
            "refetch": r.refetch,
            "perishable": r.perishable,
            "regenerated": r.regenerated,
            "object_path": corpus_rel_object,
        },
    });
    if let Some(i) = tx_index {
        v["focus"] = json!({"tx_index": i, "tx_hash": s.tx_hashes[i]});
    }
    let mut meta = json!({"ledger_close_meta_version": s.ledger_close_meta_version});
    if let Some(t) = s.meta_version(tx_index) {
        meta["transaction_meta_version"] = json!(t);
    }
    meta["profile"] = json!("lake");
    v["meta"] = meta;
    let mut derived = json!({"ledger_hash": s.header_hash, "tx_hashes": s.tx_hashes});
    if let Some(i) = tx_index {
        derived["tx_hash"] = json!(s.tx_hashes[i]);
    }
    v["derived"] = derived;
    v
}

/// What [`capture_fetched`] did.
#[derive(Debug)]
pub struct CaptureOutcome {
    /// The record written.
    pub record: CaptureRecord,
    /// The vendored object was already present with the same bytes.
    pub object_unchanged: bool,
    /// Apply-order index of `--tx`.
    pub tx_index: Option<usize>,
    /// What happened to the manifest entry, with `--entry`.
    pub upsert: Option<Upsert>,
    /// Things the author must look at.
    pub warnings: Vec<String>,
}

/// The protocol of the first ledger in a lake object, read from the batch and ledger headers alone
/// (no full decode); `None` when the object does not decompress or its header does not read.
pub fn object_protocol(object: &[u8]) -> Option<u32> {
    let xdr = xdrcheck_xdr::batch::decompress(object).ok()?;
    xdrcheck_xdr::ledger_info(xdr.get(12..)?)
        .ok()
        .map(|info| info.protocol)
}

/// Capture one fetched object into the corpus: check it, keep it verbatim (an existing vendored
/// object must have the same bytes, or this fails as a check and nothing is written), write
/// `capture.json`, and with `entry` write the blob and add or update the entry's `history`
/// variant (focus on `tx` when given).
///
/// `gate` is the corpus gate. A ledger above its `max_protocol` is still read, with the protocol
/// ceiling lifted ([`Gate::reading_live`]): the object is kept and a warning says so, because a
/// network can upgrade with little notice and a testnet upgrade ledger does not stay available.
/// With `entry` such a ledger is refused before anything is written: the corpus gate would refuse
/// the entry.
#[allow(clippy::too_many_arguments)]
pub fn capture_fetched(
    corpus: &Path,
    pins: &Pins,
    gate: &Gate,
    network: Network,
    seq: u32,
    fetched: &Fetched,
    tx: Option<&str>,
    entry: Option<&str>,
) -> Result<CaptureOutcome> {
    let loc = locate(pins, network, seq)?;
    let protocol = object_protocol(&fetched.object);
    let above = protocol.and_then(|p| gate.above_max(p));
    if let (Some(_), Some(id)) = (&above, entry) {
        return Err(CheckFailed(format!(
            "{} ledger {seq}: protocol {} is above the corpus gate {}, so it cannot become a variant \
             of {id}; capture it without --entry to keep the object, and add the entry once the gate \
             is raised (docs/maintenance.md, section 5.2)",
            network.name(),
            protocol.unwrap_or_default(),
            gate.max_protocol
        ))
        .into());
    }
    let facts = analyse(&fetched.object, network, seq, &gate.reading_live())?;
    let tx_index = match tx {
        None => None,
        Some(h) => Some(facts.ledger.tx_index(h).ok_or_else(|| {
            CheckFailed(format!(
                "transaction {h} is not in {} ledger {seq} ({} transactions)",
                network.name(),
                facts.ledger.tx_hashes.len()
            ))
        })?),
    };
    let dir = capture_dir(corpus, network, seq);
    let record_path = dir.join("capture.json");
    let prior = if record_path.exists() {
        Some(load_prior(&record_path)?)
    } else {
        None
    };
    let object_path = dir.join(loc.file_name());
    let mut unchanged = false;
    if let Some(p) = &prior {
        if p.object_sha256 != facts.object_sha256 {
            return Err(CheckFailed(format!(
                "lake object changed: vendored {} has sha256 {}, the lake now serves {}; the vendored copy is kept",
                object_path.display(),
                p.object_sha256,
                facts.object_sha256
            ))
            .into());
        }
    }
    if object_path.exists() {
        let have = xdrcheck_xdr::sha256_file(&object_path)?;
        if have != facts.object_sha256 {
            return Err(CheckFailed(format!(
                "lake object changed: vendored {} has sha256 {have}, the lake now serves {}; the vendored copy is kept",
                object_path.display(),
                facts.object_sha256
            ))
            .into());
        }
        unchanged = true;
    }
    if dir.exists() {
        for f in std::fs::read_dir(&dir)? {
            let name = f?.file_name().to_string_lossy().to_string();
            if name.ends_with(".xdr.zst") && name != loc.file_name() {
                bail!("{} holds another object, {name}", dir.display());
            }
        }
    }
    let now = now_rfc3339();
    let record = build_record(
        network,
        &loc,
        &facts,
        &fetched.head,
        prior.as_ref(),
        &fetched.fetched_with,
        &now,
    )?;
    if !unchanged {
        write_atomic(&object_path, &fetched.object)?;
    }
    write_json(&record_path, &serde_json::to_value(&record)?)?;

    let mut warnings: Vec<String> = above.into_iter().collect();
    if let Some(v) = facts.ledger.protocol_upgrade {
        warnings.push(format!(
            "ledger {seq} upgrades the protocol to {v}: the header protocol is {}, but its transactions were applied at the previous protocol; set the variant's protocol and header_protocol by hand",
            facts.ledger.protocol
        ));
    }
    let upsert = match entry {
        None => None,
        Some(id) => {
            write_blob(corpus, &facts.blob)?;
            let rel_object = object_path
                .strip_prefix(corpus)
                .unwrap_or(&object_path)
                .to_string_lossy()
                .to_string();
            let variant = history_variant(&rel_object, &record, &facts.ledger, tx_index);
            Some(upsert_variant(corpus, id, variant)?)
        }
    };
    Ok(CaptureOutcome {
        record,
        object_unchanged: unchanged,
        tx_index,
        upsert,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        assert_eq!(object_key(2), "FFFFFFFF--0-63999/FFFFFFFD--2.xdr.zst");
        assert_eq!(
            object_key(63999),
            "FFFFFFFF--0-63999/FFFF0600--63999.xdr.zst"
        );
        assert_eq!(
            object_key(64000),
            "FFFF05FF--64000-127999/FFFF05FF--64000.xdr.zst"
        );
        assert_eq!(
            object_key(65_437_981),
            "FC19F3FF--65408000-65471999/FC197EE2--65437981.xdr.zst"
        );
    }

    #[test]
    fn regenerated_rule() {
        assert!(is_regenerated(23, 1, Some(10 * 365 * 86_400)));
        assert!(is_regenerated(23, 22, Some(200 * 86_400)));
        assert!(!is_regenerated(30, 29, Some(2)));
        assert!(!is_regenerated(28, 28, Some(2)));
        assert!(!is_regenerated(27, 27, Some(6 * 86_400)));
        assert!(is_regenerated(30, 29, None));
    }

    #[test]
    fn majors() {
        assert_eq!(core_major("stellar-core 23.0.1 (050eacf1)"), Some(23));
        assert_eq!(
            core_major("stellar-core 30.0.0 (0e49751a); exporter 4d89b44"),
            Some(30)
        );
        assert_eq!(core_major("v28.0.1"), Some(28));
    }

    #[test]
    fn head_parsing() {
        let text = "HTTP/1.1 200 OK\r\nLast-Modified: Sat, 20 Sep 2025 05:41:56 GMT\r\nETag: \"c2be\"\r\nx-amz-meta-core-version: stellar-core 23.0.1 (050e)\r\nContent-Length: 756\r\n\r\n";
        let Fetch::Found(h) = parse_head(text).unwrap() else {
            panic!("not found")
        };
        assert_eq!(h.last_modified.as_deref(), Some("2025-09-20T05:41:56Z"));
        assert_eq!(h.content_length, Some(756));
        assert_eq!(h.metadata["core-version"], "stellar-core 23.0.1 (050e)");
        assert!(matches!(
            parse_head("HTTP/1.1 404 Not Found\r\n\r\n").unwrap(),
            Fetch::Gone(404)
        ));
    }
}
