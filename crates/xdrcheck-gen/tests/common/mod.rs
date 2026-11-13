//! Shared helpers for the tests that run a real stellar-core.
//!
//! These tests need the pinned binary (`scripts/fetch.d/stellar-core.sh`, or `XDRCHECK_STELLAR_CORE`). Without
//! it they print a loud `SKIPPED` banner and pass, unless `XDRCHECK_REQUIRE_CORE=1` is set (CI sets it):
//! then a missing binary fails the test. Run them with the network unreachable:
//! `scripts/offline-run.sh cargo test -p xdrcheck-gen --offline`.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use xdrcheck_gen::core::CoreBinary;

/// The pinned binary, or `None` after printing why the calling test is skipped. With
/// `XDRCHECK_REQUIRE_CORE=1` a missing binary panics instead.
pub fn core_or_skip(test: &str) -> Option<CoreBinary> {
    match CoreBinary::locate().expect("a stellar-core binary is present but is not the pinned one")
    {
        Some(b) => Some(b),
        None => {
            let why = format!(
                "{test}: no stellar-core binary. Run scripts/fetch.d/stellar-core.sh (or set \
                 XDRCHECK_STELLAR_CORE to the pinned binary) to run it."
            );
            if std::env::var("XDRCHECK_REQUIRE_CORE").is_ok_and(|v| v == "1") {
                panic!("XDRCHECK_REQUIRE_CORE=1 and {why}");
            }
            eprintln!("\n{}\nSKIPPED {why}\n{}\n", "=".repeat(78), "=".repeat(78));
            println!("SKIPPED {test}: no stellar-core binary");
            None
        }
    }
}

/// A fresh run directory under the cargo target directory, unique to this process and call.
pub fn run_dir(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("xdrcheck-gen-runs")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// `pgrep -a -f <dir>`: processes whose command line names `dir` (a node's `--conf <dir>/core.cfg`).
pub fn processes_in(dir: &Path) -> Vec<String> {
    let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    let out = Command::new("pgrep")
        .arg("-a")
        .arg("-f")
        .arg(dir.as_os_str())
        .output()
        .expect("run pgrep");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}
