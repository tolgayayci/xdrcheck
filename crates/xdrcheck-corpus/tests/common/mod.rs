//! Helpers shared by the `render`, `synth` and `slice` tests: a scratch copy of the corpus and a
//! runner for the binary.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A fresh copy of `corpus/` at `<tmp>/<suite>/<name>/corpus`.
pub fn copy_corpus(suite: &str, name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(suite)
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&repo().join("corpus"), &dir.join("corpus"));
    dir.join("corpus")
}

pub fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let p = e.unwrap().path();
        let dest = to.join(p.file_name().unwrap());
        if p.is_dir() {
            copy_dir(&p, &dest);
        } else {
            std::fs::copy(&p, &dest).unwrap();
        }
    }
}

pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run `xdrcheck-corpus --corpus <corpus> <args…>`.
pub fn run(corpus: &Path, args: &[&str]) -> Out {
    let out = Command::new(env!("CARGO_BIN_EXE_xdrcheck-corpus"))
        .arg("--corpus")
        .arg(corpus)
        .args(args)
        .output()
        .unwrap();
    Out {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

pub fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// Every file under `dir` with its bytes, sorted by path.
pub fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push((p.clone(), std::fs::read(&p).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}
