//! `xdrcheck-corpus guide-table` and `guide-claims`: both run clean on the committed tree,
//! generation is stable, and each failing condition fails on a doctored copy. Where the Python
//! check (`scripts/py/check_guide_claims.py`) can run, `guide-claims` must report the same.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
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

/// A copy of what the two commands read: `<root>/corpus/{manifest,blobs,plan.json,fields.yaml}` and
/// `<root>/guide/`. Returns the corpus root.
fn scratch(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    if root.exists() {
        std::fs::remove_dir_all(&root).unwrap();
    }
    for sub in ["corpus/manifest", "corpus/blobs", "guide"] {
        copy_dir(&repo().join(sub), &root.join(sub));
    }
    for f in ["corpus/plan.json", "corpus/fields.yaml"] {
        std::fs::copy(repo().join(f), root.join(f)).unwrap();
    }
    root.join("corpus")
}

fn run(corpus: &Path, args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_xdrcheck-corpus"))
        .arg("--corpus")
        .arg(corpus)
        .args(args)
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    (out.status.code().unwrap_or(-1), text)
}

fn edit(path: &Path, from: &str, to: &str) {
    let text = std::fs::read_to_string(path).unwrap();
    assert!(text.contains(from), "{from:?} not in {}", path.display());
    std::fs::write(path, text.replacen(from, to, 1)).unwrap();
}

fn page(corpus: &Path) -> PathBuf {
    corpus.parent().unwrap().join("guide/indexer-hardening.mdx")
}

const ENTRY: &str = "manifest/cap-0040/signed-payload-signer-added.json";

#[test]
fn both_commands_run_clean_on_the_committed_tree() {
    let corpus = repo().join("corpus");
    let (code, out) = run(&corpus, &["guide-table", "--check"]);
    assert_eq!(code, 0, "{out}");
    let (code, out) = run(&corpus, &["guide-claims", "--check"]);
    assert_eq!(code, 0, "{out}");
}

#[test]
fn generation_is_stable() {
    let c = scratch("guide-stable");
    let before = std::fs::read(page(&c)).unwrap();
    assert_eq!(run(&c, &["guide-table"]).0, 0);
    assert_eq!(run(&c, &["guide-table"]).0, 0);
    assert_eq!(std::fs::read(page(&c)).unwrap(), before);
}

#[test]
fn condition_1_unknown_row_cited() {
    let c = scratch("guide-c1");
    edit(&c.join(ENTRY), "\"VF-29\"", "\"VF-99\"");
    let (code, out) = run(&c, &["guide-table", "--check"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("condition 1: cap-0040/signed-payload-signer-added cites VF-99"),
        "{out}"
    );
}

#[test]
fn condition_2_row_cited_under_the_wrong_status() {
    let c = scratch("guide-c2");
    edit(&c.join(ENTRY), "\"validated\": [", "\"passed_through\": [");
    let (code, out) = run(&c, &["guide-table", "--check"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains(
            "condition 2: cap-0040/signed-payload-signer-added cites VF-29 under passed_through"
        ),
        "{out}"
    );
}

#[test]
fn condition_3_published_row_without_a_demonstration() {
    let c = scratch("guide-c3");
    // Every entry citing VF-29 loses its bytes.
    let mut stack = vec![c.join("manifest")];
    let mut cited = 0;
    while let Some(d) = stack.pop() {
        for f in std::fs::read_dir(&d).unwrap() {
            let p = f.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let text = std::fs::read_to_string(&p).unwrap();
            if !text.contains("\"VF-29\"") {
                continue;
            }
            cited += 1;
            let e: serde_json::Value = serde_json::from_str(&text).unwrap();
            for v in e["variants"].as_array().into_iter().flatten() {
                if let Some(b) = v["blob"]["path"].as_str() {
                    let _ = std::fs::remove_file(c.join(b));
                }
            }
        }
    }
    assert!(cited > 0);
    let (code, out) = run(&c, &["guide-table", "--check"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("condition 3: guide/indexer-hardening.mdx: VF-29 is published but no corpus entry with bytes"), "{out}");
}

#[test]
fn condition_4_non_canonical_entry_ids() {
    let c = scratch("guide-c4-fields");
    edit(
        &c.join("fields.yaml"),
        "demonstrated_by: [\"protocol-13/upgrade-ledger-header-13-envelopes-v0\"]",
        "demonstrated_by: [\"protocol-13/no-such-entry\"]",
    );
    let (code, out) = run(&c, &["guide-table", "--check"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains(
            "condition 4: fields.yaml VF-01: demonstrated_by \"protocol-13/no-such-entry\""
        ),
        "{out}"
    );

    let c = scratch("guide-c4-page");
    edit(
        &page(&c),
        "Two rules carry most of this page.",
        "Two rules carry most of this page (`cap-0040/no-such-entry`).",
    );
    let (code, out) = run(&c, &["guide-table", "--check"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("condition 4: guide/indexer-hardening.mdx: \"cap-0040/no-such-entry\""),
        "{out}"
    );
}

#[test]
fn condition_5_committed_table_differs() {
    let c = scratch("guide-c5");
    edit(&page(&c), "| VF-29 | ", "| VF-29 | edited ");
    let (code, out) = run(&c, &["guide-table", "--check"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("condition 5: guide/indexer-hardening.mdx: block fields operations differs"),
        "{out}"
    );
    // Without --check the block is rewritten and the page is clean again.
    assert_eq!(run(&c, &["guide-table"]).0, 0);
    assert_eq!(run(&c, &["guide-table", "--check"]).0, 0);
}

#[test]
fn condition_6_unverified_part_published() {
    let c = scratch("guide-c6");
    edit(
        &c.join("fields.yaml"),
        "{id: VF-02b, aspect: \"The muxed ID\", status: passed_through, verification: executed}",
        "{id: VF-02b, aspect: \"The muxed ID\", status: passed_through, verification: unverified}",
    );
    let (code, out) = run(&c, &["guide-table", "--check"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains(
            "condition 6: guide/indexer-hardening.mdx: VF-02b is published but not yet established"
        ),
        "{out}"
    );
    // Regenerated, VF-02b moves to the "not in this table" list.
    assert_eq!(run(&c, &["guide-table"]).0, 0);
    let text = std::fs::read_to_string(page(&c)).unwrap();
    assert!(!text.contains("| VF-02b |"));
    assert!(text.contains("- VF-02b Transaction.sourceAccount, The muxed ID: not yet established"));
}

#[test]
fn missing_marker_block_fails() {
    let c = scratch("guide-markers");
    edit(&page(&c), "{/* BEGIN GENERATED: fields memo */}", "");
    let (code, out) = run(&c, &["guide-table", "--check"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("no block for fields memo"), "{out}");
    let (code, out) = run(&c, &["guide-claims", "--check"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("unpaired BEGIN GENERATED / END GENERATED markers"),
        "{out}"
    );
}

/// Failure and summary lines, with quote characters made equal (Python prints `repr`, Rust `{:?}`).
fn fails(out: &str) -> Vec<String> {
    let mut v: Vec<String> = out
        .lines()
        .filter(|l| l.starts_with("FAIL") || l.starts_with("guide:"))
        .map(|l| l.replace(['\'', '"'], "\u{0}"))
        .collect();
    v.sort();
    v
}

/// The Python check, when its virtualenv exists, on the copy at `corpus`.
fn python(corpus: &Path) -> Option<String> {
    let py = repo().join(".venv/bin/python");
    if !py.is_file() {
        eprintln!("skipping the Python comparison: no .venv");
        return None;
    }
    let script = corpus
        .parent()
        .unwrap()
        .join("scripts/py/check_guide_claims.py");
    std::fs::create_dir_all(script.parent().unwrap()).unwrap();
    std::fs::copy(repo().join("scripts/py/check_guide_claims.py"), &script).unwrap();
    let out = Command::new(py).arg(&script).output().unwrap();
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

#[test]
fn guide_claims_failures_match_the_python_check() {
    let c = scratch("guide-claims");
    let p = page(&c);
    // An untagged normative sentence, a wrong sentence, a padded CAP number, a duplicate tag.
    edit(&p, " {/* claim: C-6103 */}", "");
    edit(
        &p,
        "Two rules carry most of this page.",
        "Two rules carry most of this page. Readers should check CAP-0067.",
    );
    edit(
        &p,
        "A closed ledger is final: a transaction",
        "A closed ledger is final: one transaction",
    );
    edit(
        &p,
        "{/* claim: C-6104 */}",
        "{/* claim: C-6104 */} {/* claim: C-6101 */}",
    );
    let (code, out) = run(&c, &["guide-claims", "--check"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("normative sentence without a claim tag"),
        "{out}"
    );
    assert!(out.contains("C-6104 sentence differs"), "{out}");
    assert!(out.contains("write CAP-0067 without zero padding"), "{out}");
    assert!(out.contains("C-6101 is tagged twice"), "{out}");
    if let Some(py) = python(&c) {
        assert_eq!(fails(&out), fails(&py), "rust:\n{out}\npython:\n{py}");
    }
    // And on the clean tree, the same summary line.
    let clean = scratch("guide-claims-clean");
    let (_, out) = run(&clean, &["guide-claims", "--check"]);
    if let Some(py) = python(&clean) {
        assert_eq!(fails(&out), fails(&py));
    }
}
