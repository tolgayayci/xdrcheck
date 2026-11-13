//! `xdrcheck-corpus index`: the committed `corpus/index.json` is current, has one row per manifest
//! entry with the entry's own validity, and `--check` fails on a stale copy.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn index(root: &Path, check: bool) -> (i32, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_xdrcheck-corpus"));
    c.arg("--corpus").arg(root).arg("index");
    if check {
        c.arg("--check");
    }
    let out = c.output().unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    (out.status.code().unwrap_or(-1), text)
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dest);
        } else {
            std::fs::copy(e.path(), dest).unwrap();
        }
    }
}

#[test]
fn committed_index_is_current_and_lists_every_entry() {
    let (code, out) = index(&corpus(), true);
    assert_eq!(code, 0, "{out}");
    let ix: Value =
        serde_json::from_slice(&std::fs::read(corpus().join("index.json")).unwrap()).unwrap();
    let rows = ix["entries"].as_array().unwrap();
    let manifests = xdrcheck_files(&corpus().join("manifest"));
    assert_eq!(rows.len(), manifests.len());
    for r in rows {
        let id = r["id"].as_str().unwrap();
        let m: Value = serde_json::from_slice(
            &std::fs::read(corpus().join(r["manifest"].as_str().unwrap())).unwrap(),
        )
        .unwrap();
        assert_eq!(m["id"], id);
        assert_eq!(r["validity"], m["validity"], "{id}");
        assert_eq!(r["caps"], m["caps"], "{id}");
        let variants = m["variants"].as_array().map_or(0, Vec::len);
        assert_eq!(r["variants"].as_array().unwrap().len(), variants, "{id}");
        // Every entry counts under at least one coverage row.
        assert!(!r["rows"].as_array().unwrap().is_empty(), "{id}");
    }
    // The limits/ group ships in the release archive's stress root.
    assert!(rows
        .iter()
        .filter(|r| r["id"].as_str().unwrap().starts_with("limits/"))
        .all(|r| r["tier"] == "stress"));
}

#[test]
fn stale_index_fails_and_regenerates() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("index-stale")
        .join("corpus");
    if root.exists() {
        std::fs::remove_dir_all(&root).unwrap();
    }
    for sub in ["manifest", "schema"] {
        copy_dir(&corpus().join(sub), &root.join(sub));
    }
    for f in ["caps.toml", "index.json"] {
        std::fs::copy(corpus().join(f), root.join(f)).unwrap();
    }
    assert_eq!(index(&root, true).0, 0);
    // A manifest change the index does not follow.
    let m = root.join("manifest/cap-0027/muxed-source-id-zero.json");
    let text = std::fs::read_to_string(&m).unwrap();
    std::fs::write(
        &m,
        text.replacen(
            "\"title\": \"Transaction whose source",
            "\"title\": \"Changed: transaction whose source",
            1,
        ),
    )
    .unwrap();
    let (code, out) = index(&root, true);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("differs from a fresh generation"), "{out}");
    assert_eq!(index(&root, false).0, 0);
    assert_eq!(index(&root, true).0, 0);
}

fn xdrcheck_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(xdrcheck_files(&p));
        } else if p.extension().is_some_and(|x| x == "json") {
            out.push(p);
        }
    }
    out
}
