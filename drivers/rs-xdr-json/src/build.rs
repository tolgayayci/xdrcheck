//! Build script of the rs-xdr-json driver: records `version source checksum` of the `stellar-xdr` package from the
//! version directory's Cargo.lock (a crates.io release carries its sha256; a git dependency its commit in the
//! source), and the compiler's version.
use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let lock_path = dir.join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock_path.display());
    let lock = fs::read_to_string(&lock_path).unwrap_or_default();
    let mut out = String::new();
    for block in lock.split("[[package]]") {
        let field = |key: &str| {
            block.lines().find_map(|l| {
                l.trim()
                    .strip_prefix(key)
                    .and_then(|r| r.trim_start().strip_prefix('='))
                    .map(|v| v.trim().trim_matches('"').to_string())
            })
        };
        if field("name").as_deref() == Some("stellar-xdr") {
            out = format!(
                "{} {} {}",
                field("version").unwrap_or_default(),
                field("source").unwrap_or_default(),
                field("checksum").unwrap_or_default()
            );
        }
    }
    println!("cargo:rustc-env=XDRCHECK_LOCK_XDR={out}");
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let v = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    println!(
        "cargo:rustc-env=XDRCHECK_RUSTC_VERSION={}",
        v.split_whitespace().nth(1).unwrap_or("unknown")
    );
}
