//! Build script of the soroban-spec driver: records `name version sha256` of the crates that decide what the
//! driver reports (`soroban-spec`, `stellar-xdr`), from the version directory's `Cargo.lock` (cargo refuses a
//! downloaded crate whose sha256 differs from the lock), and the compiler's version.
use std::{env, fs, path::PathBuf, process::Command};

const PACKAGES: &[&str] = &["soroban-spec", "stellar-xdr"];

fn main() {
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let lock_path = dir.join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock_path.display());
    let lock = fs::read_to_string(&lock_path).unwrap_or_default();
    let mut out = Vec::new();
    for block in lock.split("[[package]]") {
        let field = |key: &str| {
            block.lines().find_map(|l| {
                l.trim()
                    .strip_prefix(key)
                    .and_then(|r| r.trim_start().strip_prefix('='))
                    .map(|v| v.trim().trim_matches('"').to_string())
            })
        };
        if let (Some(name), Some(version)) = (field("name"), field("version")) {
            if PACKAGES.contains(&name.as_str()) {
                out.push(format!(
                    "{name} {version} {}",
                    field("checksum").unwrap_or_default()
                ));
            }
        }
    }
    println!("cargo:rustc-env=XDRCHECK_LOCK_CHECKSUMS={}", out.join(";"));
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
