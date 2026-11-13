//! The `hashes` check of a `history-archive` source: the vendored archive object proves the blob
//! (`corpus/objects/README.md`, "History-archive objects"). The chain is: the object's sha256 and
//! size → gzip decompress → sha256 = the bucket hash (named in the object's file name and listed in
//! the vendored History Archive State at the recorded level and slot) → the record mark at
//! `source.byte_offset` frames exactly the blob.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// The capture format of a vendored history-archive object.
const CAPTURE_SCHEMA: &str = "xcc.capture.history-archive/v1";

/// Largest decompressed bucket the check reads.
const MAX_BUCKET: usize = 1 << 30;

/// Every `objects/<network>/history-archive/<checkpoint>/capture.json`, sorted.
pub fn captures(corpus: &Path, network: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> =
        std::fs::read_dir(corpus.join("objects").join(network).join("history-archive"))
            .into_iter()
            .flatten()
            .flatten()
            .map(|d| d.path().join("capture.json"))
            .filter(|p| p.is_file())
            .collect();
    out.sort();
    out
}

/// Problems with the vendored archive object behind one variant. `entry` is the manifest entry
/// ID, `blob` the variant's bytes (`Err` when the blob check already failed).
pub fn check(corpus: &Path, entry: &str, v: &Value, blob: Result<&[u8], String>) -> Vec<String> {
    let src = &v["source"];
    let object = src["object"].as_str().unwrap_or("");
    let network = v["network"].as_str().unwrap_or("");
    let found = captures(corpus, network).into_iter().find_map(|p| {
        let c: Value = serde_json::from_slice(&std::fs::read(&p).ok()?).ok()?;
        (c["object"] == object).then_some((p, c))
    });
    let Some((capture_path, c)) = found else {
        return vec![format!(
            "no vendored history-archive object: no objects/{network}/history-archive/*/capture.json \
             has object {object:?}"
        )];
    };
    let dir = capture_path.parent().unwrap_or(corpus).to_path_buf();
    let shown = |p: &Path| p.strip_prefix(corpus).unwrap_or(p).display().to_string();
    let cap = shown(&capture_path);
    let mut p = Vec::new();
    if c["schema"] != CAPTURE_SCHEMA {
        p.push(format!(
            "{cap}: schema is {}, not {CAPTURE_SCHEMA}",
            c["schema"]
        ));
    }
    if c["store"] != src["store"] {
        p.push(format!(
            "{cap}: store {} is not source.store {}",
            c["store"], src["store"]
        ));
    }

    // The History Archive State names the bucket.
    let has = &c["has"];
    let bucket_hash = c["bucket_hash"].as_str().unwrap_or("");
    match has["file"].as_str().map(|f| dir.join(f)) {
        None => p.push(format!("{cap}: has.file is missing")),
        Some(hp) => match std::fs::read(&hp) {
            Err(e) => p.push(format!("HAS {}: {e}", shown(&hp))),
            Ok(bytes) => {
                let what = format!("HAS {}", shown(&hp));
                p.extend(sized(&what, &bytes, &has["sha256"], &has["bytes"]));
                p.extend(has_lists_bucket(&what, &bytes, &c, bucket_hash));
            }
        },
    }

    // The object as served.
    let file = c["object_file"].as_str().unwrap_or("");
    if object.rsplit('/').next() != Some(file) {
        p.push(format!(
            "{cap}: object_file {file:?} is not the base name of {object:?}"
        ));
    }
    if src["object_sha256"] != c["object_sha256"] {
        p.push(format!(
            "source.object_sha256 {} differs from {cap} object_sha256 {}",
            src["object_sha256"], c["object_sha256"]
        ));
    }
    if file
        .strip_prefix("bucket-")
        .and_then(|f| f.strip_suffix(".xdr.gz"))
        != Some(bucket_hash)
    {
        p.push(format!(
            "{cap}: object_file {file:?} is not named by bucket_hash {bucket_hash}"
        ));
    }
    let op = dir.join(file);
    let obj = match std::fs::read(&op) {
        Ok(o) => o,
        Err(e) => {
            p.push(format!("archive object {}: {e}", shown(&op)));
            return p;
        }
    };
    let obj_shown = format!("archive object {}", shown(&op));
    p.extend(sized(
        &obj_shown,
        &obj,
        &c["object_sha256"],
        &c["object_bytes"],
    ));

    // Decompressed: the bucket, whose sha256 is its hash.
    let dec = match super::gzip::gunzip(&obj, MAX_BUCKET) {
        Ok(d) => d,
        Err(e) => {
            p.push(format!("{obj_shown}: does not gunzip: {e}"));
            return p;
        }
    };
    p.extend(sized(
        "gunzipped object",
        &dec,
        &c["decompressed_sha256"],
        &c["decompressed_bytes"],
    ));
    let got = xdrcheck_xdr::sha256_hex(&dec);
    if got != bucket_hash {
        p.push(format!(
            "gunzipped object: sha256 is {got}, not the bucket hash {bucket_hash}"
        ));
    }

    // The record at byte_offset is the blob.
    let Some(off) = src["byte_offset"].as_u64().map(|o| o as usize) else {
        p.push("source.byte_offset is missing".into());
        return p;
    };
    let Some(mark) = dec.get(off..off + 4) else {
        p.push(format!(
            "source.byte_offset {off} is past the end of the bucket ({} bytes)",
            dec.len()
        ));
        return p;
    };
    let mark = u32::from_be_bytes([mark[0], mark[1], mark[2], mark[3]]);
    if mark & 0x8000_0000 == 0 {
        p.push(format!(
            "record mark {mark:08x} at byte {off} does not have the last-fragment bit"
        ));
    }
    let len = (mark & 0x7fff_ffff) as usize;
    let body = dec.get(off + 4..off + 4 + len);
    if let Ok(blob) = blob {
        if body != Some(blob) {
            p.push(format!(
                "the record at byte {off} (mark {mark:08x}, {len} bytes) is not the blob ({} bytes)",
                blob.len()
            ));
        }
    }

    // The capture's row for this entry agrees.
    let row = c["records"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["entry"] == entry);
    match row {
        None => p.push(format!("{cap}: records[] has no row for {entry}")),
        Some(r) => {
            let want = [
                ("byte_offset", Value::from(off)),
                ("blob_offset", Value::from(off + 4)),
                ("blob_bytes", v["blob"]["bytes"].clone()),
                ("blob_sha256", v["blob"]["sha256"].clone()),
                ("record_mark", Value::from(format!("{mark:08x}"))),
            ];
            for (k, w) in want {
                if r[k] != w {
                    p.push(format!(
                        "{cap}: records[{entry}].{k} is {}, expected {w}",
                        r[k]
                    ));
                }
            }
        }
    }
    p
}

/// sha256 and size of `bytes` against the recorded values (when recorded).
fn sized(what: &str, bytes: &[u8], sha: &Value, size: &Value) -> Vec<String> {
    let mut p = Vec::new();
    let got = xdrcheck_xdr::sha256_hex(bytes);
    match sha.as_str() {
        Some(w) if w != got => p.push(format!("{what}: sha256 is {got}, recorded {w}")),
        Some(_) => {}
        None => p.push(format!("{what}: no recorded sha256")),
    }
    if let Some(n) = size.as_u64() {
        if n != bytes.len() as u64 {
            p.push(format!("{what}: {} bytes, recorded {n}", bytes.len()));
        }
    }
    p
}

/// The HAS lists `bucket` at the capture's `bucket_level` / `bucket_slot`, and its
/// `currentLedger` is the capture's checkpoint.
fn has_lists_bucket(what: &str, bytes: &[u8], c: &Value, bucket: &str) -> Vec<String> {
    let Ok(has) = serde_json::from_slice::<Value>(bytes) else {
        return vec![format!("{what}: not JSON")];
    };
    let mut p = Vec::new();
    if has["currentLedger"] != c["checkpoint"] {
        p.push(format!(
            "{what}: currentLedger {} is not the checkpoint {}",
            has["currentLedger"], c["checkpoint"]
        ));
    }
    let level = c["bucket_level"].as_u64().unwrap_or(u64::MAX) as usize;
    let slot = c["bucket_slot"].as_str().unwrap_or("");
    let listed = &has["currentBuckets"][level][slot];
    if listed != bucket {
        p.push(format!(
            "{what}: currentBuckets[{level}].{slot} is {listed}, not the bucket {bucket}"
        ));
    }
    p
}
