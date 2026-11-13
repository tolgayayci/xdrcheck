//! The decoded sidecar: the SEP-51 XDR-JSON of a blob, as the corpus stores it (`docs/manifest.md` §2).
//!
//! Content: the oracle's JSON (`xdrcheck_xdr::json_roundtrip`, which also proves decode → re-encode and
//! JSON → re-encode are byte-exact) serialised compactly in the library's field order, followed by
//! one newline. `decoded_sha256` is the sha256 of that content.
//!
//! Storage: one file per blob, `decoded/<aa>/<blob sha256>.json.zst`, one zstd frame at level
//! [`ZSTD_LEVEL`] with the content checksum. A file is rewritten only when its content differs, so a
//! different zstd build causes no churn. `xdrcheck-corpus render` and the generator both use these
//! functions, so there is one serialisation and one layout.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

/// zstd level for sidecars.
pub const ZSTD_LEVEL: i32 = 19;

/// The sidecar content for a blob of `xdr_type`.
pub fn sidecar_bytes(xdr_type: &str, blob: &[u8]) -> Result<Vec<u8>> {
    let json = xdrcheck_xdr::json_roundtrip(xdr_type, blob, &xdrcheck_xdr::Limits::default())?;
    Ok(sidecar_text(&json).into_bytes())
}

/// Sidecar content for an already decoded value: compact JSON and a trailing newline. Serialising a
/// deep value recurses, so it runs on the large stack.
pub fn sidecar_text(v: &serde_json::Value) -> String {
    let mut s = xdrcheck_xdr::with_stack(xdrcheck_xdr::DEFAULT_STACK_SIZE, || {
        serde_json::to_string(v).expect("a JSON value serialises")
    });
    s.push('\n');
    s
}

/// The `decoded_by` string of a variant whose sidecar this module wrote, from the pins in `corpus.json`
/// (`Value::Null` when there is none). `render` and the generator both use it, so a variant's provenance does
/// not depend on which command wrote the sidecar. The crates share the workspace version.
pub fn decoded_by(corpus_json: &serde_json::Value) -> String {
    let pin = |p: &str, default: &str| {
        corpus_json
            .pointer(p)
            .and_then(serde_json::Value::as_str)
            .unwrap_or(default)
            .to_string()
    };
    format!(
        "rs-stellar-xdr {} ({}), xdrcheck-corpus render {}, XDR definitions {}",
        pin("/pins/oracle/version", "30.0.0"),
        pin(
            "/pins/oracle/commit",
            "3c2aa43d2ab54d429ae44aa5143d805bf5dba7e2"
        ),
        env!("CARGO_PKG_VERSION"),
        pin(
            "/pins/xdr_definitions/commit",
            "4f524bbac80c781c06e4fb5fc93a2d0d331d6705"
        ),
    )
}

/// Corpus-relative path of the sidecar of the blob with sha256 `blob_sha`.
pub fn sidecar_rel(blob_sha: &str) -> String {
    format!(
        "decoded/{}/{blob_sha}.json.zst",
        blob_sha.get(..2).unwrap_or("")
    )
}

/// One zstd frame at [`ZSTD_LEVEL`], with the content checksum.
pub fn compress_sidecar(content: &[u8]) -> Result<Vec<u8>> {
    let mut enc = zstd::stream::Encoder::new(Vec::new(), ZSTD_LEVEL)?;
    enc.include_checksum(true)?;
    enc.write_all(content)?;
    Ok(enc.finish()?)
}

/// The most a sidecar or vendored chain stream may decompress to (256 MiB); a larger output is an
/// error, not an allocation.
pub const MAX_DECOMPRESSED: u64 = 256 << 20;

/// The uncompressed content of a sidecar file (at most [`MAX_DECOMPRESSED`] bytes).
pub fn read_sidecar(path: &Path) -> Result<Vec<u8>> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    decompress_bounded(&data, MAX_DECOMPRESSED)
        .with_context(|| format!("{} is not a zstd frame", path.display()))
}

/// Decompress zstd `data`, failing if the output exceeds `max` bytes ([`xdrcheck_xdr::batch::decompress_bounded`]).
pub fn decompress_bounded(data: &[u8], max: u64) -> Result<Vec<u8>> {
    Ok(xdrcheck_xdr::batch::decompress_bounded(data, max)?)
}

/// Write the sidecar at `corpus/rel` unless the file already holds exactly `content`. Returns
/// whether it wrote.
pub fn write_sidecar(corpus: &Path, rel: &str, content: &[u8]) -> Result<bool> {
    let path = corpus.join(rel);
    if read_sidecar(&path).ok().as_deref() == Some(content) {
        return Ok(false);
    }
    std::fs::create_dir_all(path.parent().context("sidecar has a parent")?)?;
    std::fs::write(&path, compress_sidecar(content)?)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Every vendored sidecar is reproduced byte for byte from its blob, at its blob's path.
    #[test]
    fn reproduces_the_vendored_sidecars() {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
        let mut n = 0;
        for group in std::fs::read_dir(corpus.join("manifest")).unwrap() {
            for f in std::fs::read_dir(group.unwrap().path()).unwrap() {
                let e: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(f.unwrap().path()).unwrap()).unwrap();
                for v in e["variants"].as_array().into_iter().flatten() {
                    let Some(dec) = v["decoded"].as_str() else {
                        continue;
                    };
                    let blob =
                        std::fs::read(corpus.join(v["blob"]["path"].as_str().unwrap())).unwrap();
                    assert_eq!(dec, sidecar_rel(v["blob"]["sha256"].as_str().unwrap()));
                    let want = read_sidecar(&corpus.join(dec)).unwrap();
                    let xdr_type = v["xdr_type"].as_str().unwrap();
                    // A declared JSON round-trip exception is rendered without JSON → XDR.
                    let got = if v["json_roundtrip"]["skip"] == true {
                        let json = xdrcheck_xdr::xdr_json(xdr_type, &blob, &xdrcheck_xdr::Limits::default())
                            .unwrap();
                        sidecar_text(&json).into_bytes()
                    } else {
                        sidecar_bytes(xdr_type, &blob).unwrap()
                    };
                    assert!(got == want, "{dec} is not reproduced");
                    assert_eq!(
                        xdrcheck_xdr::sha256_hex(&got),
                        v["decoded_sha256"].as_str().unwrap()
                    );
                    n += 1;
                }
            }
        }
        assert!(n >= 6, "checked {n} sidecars");
    }

    #[test]
    fn writes_one_checksummed_frame_and_skips_identical_content() {
        let dir = std::env::temp_dir().join(format!("xdrcheck-gen-sidecar-{}", std::process::id()));
        let rel = sidecar_rel("ab12");
        assert_eq!(rel, "decoded/ab/ab12.json.zst");
        assert!(write_sidecar(&dir, &rel, b"{}\n").unwrap());
        let raw = std::fs::read(dir.join(&rel)).unwrap();
        assert_eq!(&raw[..4], &[0x28, 0xb5, 0x2f, 0xfd]);
        assert_ne!(raw[4] & 0x04, 0, "content checksum flag");
        assert_eq!(read_sidecar(&dir.join(&rel)).unwrap(), b"{}\n");
        assert!(!write_sidecar(&dir, &rel, b"{}\n").unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decompression_is_bounded() {
        let big = compress_sidecar(&vec![b'x'; 4096]).unwrap();
        assert_eq!(decompress_bounded(&big, 4096).unwrap().len(), 4096);
        let e = decompress_bounded(&big, 4095).unwrap_err();
        assert!(e.to_string().contains("more than 4095 bytes"), "{e}");
    }
}
