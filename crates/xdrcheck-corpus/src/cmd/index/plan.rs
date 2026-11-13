//! `xdrcheck-corpus index --plan [--check]`: merge the plan fragments `corpus/plan.d/*.json` into the entry-ID
//! registry `corpus/plan.json`.
//!
//! Each fragment is a JSON array of plan rows (the shape of `plan.json`'s rows), so a task adds the rows it
//! plans in its own file and never edits `plan.json` itself. Fragments are read in name order; a row whose ID
//! `plan.json` already holds must equal that row (it was merged before), any other row is appended after the
//! existing rows, in fragment order. A row planned twice across fragments with different content is an error.
//! With no fragment, or nothing new, `plan.json` is left exactly as it is. `--check` writes nothing and fails
//! (exit 1) when a fragment row is not in `plan.json` yet.
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::Value;

/// The fragments directory, relative to the corpus root.
pub const PLAN_DIR: &str = "plan.d";

/// `plan.json` as written: one-space indent, a final newline.
pub fn render(rows: &[Value]) -> Result<String> {
    let mut out = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b" ");
    let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
    rows.serialize(&mut ser)?;
    out.push(b'\n');
    Ok(String::from_utf8(out)?)
}

fn fragments(corpus: &Path) -> Result<Vec<PathBuf>> {
    let dir = corpus.join(PLAN_DIR);
    let mut files = Vec::new();
    match std::fs::read_dir(&dir) {
        Ok(rd) => {
            for e in rd {
                let p = e?.path();
                if p.extension().is_some_and(|x| x == "json") {
                    files.push(p);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("read {}", dir.display())),
    }
    files.sort();
    Ok(files)
}

/// The merged rows and how many are new.
pub fn merge(corpus: &Path) -> Result<(Vec<Value>, usize)> {
    let path = corpus.join("plan.json");
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let plan: Value =
        serde_json::from_str(&text).with_context(|| format!("{} is not JSON", path.display()))?;
    let Some(rows) = plan.as_array() else {
        bail!("{}: not an array of rows", path.display());
    };
    let mut rows = rows.clone();
    let mut new = 0;
    for f in fragments(corpus)? {
        let v: Value = serde_json::from_slice(
            &std::fs::read(&f).with_context(|| format!("read {}", f.display()))?,
        )
        .with_context(|| format!("{} is not JSON", f.display()))?;
        let Some(frag) = v.as_array() else {
            bail!("{}: not an array of plan rows", f.display());
        };
        for r in frag {
            let Some(id) = r["id"].as_str() else {
                bail!("{}: a row has no id", f.display());
            };
            match rows.iter().find(|have| have["id"] == id) {
                Some(have) if have == r => {}
                Some(_) => bail!(
                    "{}: row {id} is already planned with other content (in plan.json or an earlier fragment)",
                    f.display()
                ),
                None => {
                    rows.push(r.clone());
                    new += 1;
                }
            }
        }
    }
    Ok((rows, new))
}

pub fn run(corpus: &Path, check: bool) -> Result<ExitCode> {
    let (rows, new) = merge(corpus)?;
    let path = corpus.join("plan.json");
    if check {
        if new > 0 {
            println!("FAIL plan: {new} fragment row(s) of {PLAN_DIR}/ are not in plan.json; run `xdrcheck-corpus index --plan`");
            return Ok(ExitCode::from(1));
        }
        println!(
            "plan: {} rows; every fragment row is in plan.json",
            rows.len()
        );
        return Ok(ExitCode::SUCCESS);
    }
    if new > 0 {
        std::fs::write(&path, render(&rows)?)
            .with_context(|| format!("write {}", path.display()))?;
    }
    println!("plan: {} rows, {new} added from {PLAN_DIR}/", rows.len());
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("xdrcheck-plan-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(PLAN_DIR)).unwrap();
        d
    }

    /// The committed plan.json is exactly what `render` writes, so a merge that adds rows changes only them.
    #[test]
    fn render_reproduces_the_committed_plan() {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
        let text = std::fs::read_to_string(corpus.join("plan.json")).unwrap();
        let v: Vec<Value> = serde_json::from_str(&text).unwrap();
        assert!(
            render(&v).unwrap() == text,
            "plan.json is not in render's format"
        );
    }

    #[test]
    fn fragments_append_in_name_order_and_empty_changes_nothing() {
        let d = scratch("merge");
        let base = r#"[{"id": "a/one", "kind": "xdr"}]"#;
        std::fs::write(d.join("plan.json"), base).unwrap();
        // No fragment: nothing new, plan.json untouched.
        assert_eq!(merge(&d).unwrap().1, 0);
        run(&d, false).unwrap();
        assert_eq!(std::fs::read_to_string(d.join("plan.json")).unwrap(), base);
        std::fs::write(
            d.join(PLAN_DIR).join("20-b.json"),
            r#"[{"id": "c/three", "kind": "xdr"}]"#,
        )
        .unwrap();
        std::fs::write(
            d.join(PLAN_DIR).join("10-a.json"),
            r#"[{"id": "a/one", "kind": "xdr"}, {"id": "b/two", "kind": "ledger"}]"#,
        )
        .unwrap();
        assert_eq!(run(&d, true).unwrap(), ExitCode::from(1));
        run(&d, false).unwrap();
        let rows: Vec<Value> =
            serde_json::from_str(&std::fs::read_to_string(d.join("plan.json")).unwrap()).unwrap();
        let ids: Vec<&str> = rows.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["a/one", "b/two", "c/three"]);
        assert_eq!(run(&d, true).unwrap(), ExitCode::SUCCESS);
        // The same ID with other content is refused.
        std::fs::write(
            d.join(PLAN_DIR).join("30-c.json"),
            r#"[{"id": "b/two", "kind": "xdr"}]"#,
        )
        .unwrap();
        assert!(merge(&d).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
