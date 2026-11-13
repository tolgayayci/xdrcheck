//! `xdrcheck-corpus coverage`: the committed files are current, generation is stable, and
//! every failing condition of `--check` fails on a doctored copy of the corpus.

use std::path::{Path, PathBuf};
use std::process::Command;

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
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

/// A copy of the parts of the corpus that coverage reads.
fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(name)
        .join("corpus");
    if d.exists() {
        std::fs::remove_dir_all(&d).unwrap();
    }
    for sub in ["manifest", "schema"] {
        copy_dir(&corpus().join(sub), &d.join(sub));
    }
    // The arm walk of COVERAGE.md reads every blob, chain stream and lake object; the tests never
    // change them, so they are linked, not copied.
    for sub in ["blobs", "chains", "objects"] {
        std::os::unix::fs::symlink(corpus().join(sub).canonicalize().unwrap(), d.join(sub))
            .unwrap();
    }
    for f in [
        "arms.toml",
        "caps.toml",
        "plan.json",
        "corpus.json",
        "coverage.json",
        "COVERAGE.md",
        "mirrors.json",
    ] {
        std::fs::copy(corpus().join(f), d.join(f)).unwrap();
    }
    d
}

fn coverage(root: &Path, check: bool) -> (i32, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_xdrcheck-corpus"));
    c.arg("--corpus").arg(root).arg("coverage");
    if check {
        c.arg("--check");
    }
    let out = c.output().unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    (out.status.code().unwrap_or(-1), text)
}

fn edit(path: &Path, from: &str, to: &str) {
    let text = std::fs::read_to_string(path).unwrap();
    assert!(text.contains(from), "{from:?} not in {}", path.display());
    std::fs::write(path, text.replacen(from, to, 1)).unwrap();
}

#[test]
fn committed_coverage_is_current_and_accounts_for_every_cap_file() {
    let (code, out) = coverage(&corpus(), true);
    assert_eq!(code, 0, "{out}");
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(corpus().join("coverage.json")).unwrap()).unwrap();
    assert_eq!(v["totals"]["cap_files"], 102);
    let t = &v["totals"];
    assert_eq!(
        t["cap_files_reader_visible"].as_u64().unwrap()
            + t["cap_files_implemented_not_reader_visible"]
                .as_u64()
                .unwrap()
            + t["cap_files_not_implemented"].as_u64().unwrap(),
        102
    );
}

#[test]
fn generation_is_stable() {
    let root = scratch("coverage-stable");
    let before = std::fs::read(root.join("coverage.json")).unwrap();
    assert_eq!(coverage(&root, false).0, 0);
    assert_eq!(coverage(&root, false).0, 0);
    assert_eq!(std::fs::read(root.join("coverage.json")).unwrap(), before);
    assert_eq!(coverage(&root, true).0, 0);
}

#[test]
fn stale_committed_files_fail() {
    for f in ["coverage.json", "COVERAGE.md"] {
        let root = scratch(&format!("coverage-stale-{f}"));
        let p = root.join(f);
        let mut text = std::fs::read_to_string(&p).unwrap();
        text.push(' ');
        std::fs::write(&p, text).unwrap();
        let (code, out) = coverage(&root, true);
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("differs from a fresh generation"), "{out}");
    }
}

#[test]
fn reader_visible_row_without_entry_plan_or_reason_fails() {
    let root = scratch("coverage-no-reason");
    let p = root.join("caps.toml");
    let text: String = std::fs::read_to_string(&p)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("gap_reason = \"an ordinary union arm"))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&p, text).unwrap();
    let (code, out) = coverage(&root, true);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("cap-0006: reader-visible, but no entry, no planned row and no gap_reason"),
        "{out}"
    );
}

#[test]
fn row_without_twins_plan_or_reason_fails() {
    let root = scratch("coverage-no-twins");
    let p = root.join("caps.toml");
    let text: String = std::fs::read_to_string(&p)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("twins_reason = \"needs validators that drop"))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&p, text).unwrap();
    let (code, out) = coverage(&root, true);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("cap-0083: no entry with testnet and pubnet variants, no planned twin row"),
        "{out}"
    );
}

#[test]
fn every_cap_file_must_be_accounted_for_once() {
    let root = scratch("coverage-cap-missing");
    edit(
        &root.join("caps.toml"),
        "[[cap]]\nfile = \"cap-0002.md\"",
        "[[cap]]\nfile = \"cap-0004.md\"",
    );
    let (code, out) = coverage(&root, true);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("cap-0004.md is listed twice"), "{out}");
    assert!(
        out.contains("101 CAP files listed, 102 at stellar-protocol"),
        "{out}"
    );

    let root = scratch("coverage-cap-no-reason");
    edit(
        &root.join("caps.toml"),
        "reason = \"signature-check ordering only; no XDR or meta shape\"\n",
        "",
    );
    let (code, out) = coverage(&root, true);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("cap-0002.md is not reader-visible and gives no reason"),
        "{out}"
    );
}

#[test]
fn entry_that_counts_under_no_row_fails() {
    let root = scratch("coverage-stray-entry");
    let src = root.join("manifest/cap-0040/signed-payload-signer-added.json");
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&src).unwrap()).unwrap();
    v["id"] = "cap-0002/stray".into();
    v["caps"] = serde_json::json!([2]);
    std::fs::create_dir_all(root.join("manifest/cap-0002")).unwrap();
    std::fs::write(
        root.join("manifest/cap-0002/stray.json"),
        serde_json::to_vec(&v).unwrap(),
    )
    .unwrap();
    let (code, out) = coverage(&root, true);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("entry cap-0002/stray counts under no coverage row"),
        "{out}"
    );
    assert!(
        out.contains("cites CAP 2, which caps.toml does not list as reader-visible"),
        "{out}"
    );
}

#[test]
fn a_local_core_entry_missing_from_the_mirror_list_fails() {
    // An entry added without `verify --checks ag4 --write-mirrors` must fail without the golden cache.
    let root = scratch("coverage-mirrors-unlisted");
    let p = root.join("mirrors.json");
    let mut m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    let list = m["unmapped"].as_array_mut().unwrap();
    let gone = list.remove(0)["entry"].as_str().unwrap().to_string();
    std::fs::write(&p, serde_json::to_string_pretty(&m).unwrap()).unwrap();
    let (code, out) = coverage(&root, true);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains(&format!(
            "corpus/mirrors.json does not list the local-core entry {gone}"
        )),
        "{out}"
    );
}
