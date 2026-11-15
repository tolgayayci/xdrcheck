//! Build script shared by every version crate of the Rust conformance driver.
//!
//! It records two facts the driver reports in `describe` and cannot read from the libraries themselves:
//!
//! - `XDRCHECK_LOCK_CHECKSUMS`: `name version sha256` for the packages whose behaviour decides decoding
//!   (`stellar-xdr`, `stellar-strkey`), taken from the crate's `Cargo.lock`. Cargo refuses a downloaded
//!   `.crate` whose sha256 differs from the lock, so these are the integrity values of the compiled artefacts.
//! - `XDRCHECK_RUSTC_VERSION`: the compiler's version line.
//!
//! The library versions themselves are read at run time from the libraries' own `VERSION` constants.

use std::{env, fs, path::PathBuf, process::Command};

const PACKAGES: &[&str] = &["stellar-xdr", "stellar-strkey"];

fn main() {
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let lock_path = dir.join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock_path.display());
    let lock = fs::read_to_string(&lock_path).unwrap_or_default();

    let mut out = Vec::new();
    for block in lock.split("[[package]]") {
        let field = |key: &str| {
            block.lines().find_map(|l| {
                let l = l.trim();
                l.strip_prefix(key)
                    .and_then(|r| r.trim_start().strip_prefix('='))
                    .map(|v| v.trim().trim_matches('"').to_string())
            })
        };
        let (Some(name), Some(version)) = (field("name"), field("version")) else {
            continue;
        };
        if PACKAGES.contains(&name.as_str()) {
            let sum = field("checksum").unwrap_or_default();
            out.push(format!("{name} {version} {sum}"));
        }
    }
    println!("cargo:rustc-env=XDRCHECK_LOCK_CHECKSUMS={}", out.join(";"));

    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    // "rustc 1.98.1 (hash date)" -> "1.98.1"
    let short = version
        .split_whitespace()
        .nth(1)
        .unwrap_or("unknown")
        .to_string();
    println!("cargo:rustc-env=XDRCHECK_RUSTC_VERSION={short}");
}
