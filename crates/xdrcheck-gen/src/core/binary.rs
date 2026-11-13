//! Finding the pinned stellar-core binary.
//!
//! `scripts/fetch.d/stellar-core.sh` unpacks the release package and its runtime libraries into
//! `${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/stellar-core/<version>/pkg/`. `XDRCHECK_STELLAR_CORE` names another binary
//! instead; its libraries are taken from `<binary dir>/../lib/x86_64-linux-gnu` when that exists. Either
//! way the binary's sha256 must equal `pins.toml` `[stellar_core] binary_sha256`: anything else is an error,
//! never a silent fallback.
//!
//! `XDRCHECK_STELLAR_CORE_MANIFEST` names the `manifest.json` of a next-protocol build
//! (`scripts/nightly/vnext-core.sh`, docs/maintenance.md): the binary is then checked against that
//! manifest's `binary_sha256` instead, it defaults to `<manifest dir>/pkg/usr/bin/stellar-core`, and the
//! chains it produces record the build's commit and hash. Entries from such a binary belong to the `-next`
//! channel only.
//!
//! A scenario names its binary with `binary:` ([`Role`]): `release` (the above), `buildtests` (a build with test
//! hooks, pinned by `pins.toml` `[stellar_core_buildtests]`) or `vnext` (the pinned next-protocol build,
//! `[stellar_core_next]`). Each is found under the fetch cache at
//! `stellar-core-<role>/<version>/pkg/usr/bin/stellar-core` and checked against its pin's `binary_sha256`; a
//! role whose table `pins.toml` does not have is an error, never a fallback to another binary.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// `pins.toml`, embedded at build time so the pins travel with the binary.
const PINS: &str = include_str!("../../../../pins.toml");

/// The `[stellar_core]` table of `pins.toml` (the fields the generator uses).
#[derive(Debug, Clone, Deserialize)]
pub struct CorePins {
    /// Release version, for example `30.0.0`.
    pub version: String,
    /// Source commit of the release.
    pub commit: String,
    /// URL of the release package.
    pub deb_url: String,
    /// sha256 of the release package.
    pub deb_sha256: String,
    /// sha256 of `usr/bin/stellar-core` inside the package.
    pub binary_sha256: String,
}

/// Which stellar-core binary a scenario runs on (its `binary:` key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    /// The pinned release (`[stellar_core]`).
    Release,
    /// A build with test hooks (`[stellar_core_buildtests]`).
    Buildtests,
    /// The pinned next-protocol build (`[stellar_core_next]`).
    Vnext,
}

impl Role {
    /// The role a scenario's `binary:` value names.
    pub fn parse(s: &str) -> Result<Role> {
        Ok(match s {
            "release" => Role::Release,
            "buildtests" => Role::Buildtests,
            "vnext" => Role::Vnext,
            other => bail!("binary {other:?} is not release, buildtests or vnext"),
        })
    }

    /// The name scenarios and manifests use (`local-core` `core_role`).
    pub fn name(self) -> &'static str {
        match self {
            Role::Release => "release",
            Role::Buildtests => "buildtests",
            Role::Vnext => "vnext",
        }
    }

    /// The `pins.toml` table that pins this role's binary.
    pub fn table(self) -> &'static str {
        match self {
            Role::Release => "stellar_core",
            Role::Buildtests => "stellar_core_buildtests",
            Role::Vnext => "stellar_core_next",
        }
    }
}

/// A non-release binary's pin: `[stellar_core_buildtests]` or `[stellar_core_next]` in `pins.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct BuildPin {
    /// A version label, for example `30.0.0-buildtests` or `31.0.0-next`; names the cache directory.
    pub version: String,
    /// The stellar-core commit it was built from.
    pub commit: String,
    /// sha256 of the built `stellar-core` binary.
    pub binary_sha256: String,
}

/// The pins of `role` from a `pins.toml` text: `Ok(None)` when the file has no table for it.
pub fn role_pins(role: Role, pins_toml: &str) -> Result<Option<CorePins>> {
    if role == Role::Release {
        return Ok(Some(core_pins()));
    }
    let doc: toml::Table = toml::from_str(pins_toml).context("pins.toml does not parse")?;
    let Some(table) = doc.get(role.table()) else {
        return Ok(None);
    };
    let pin: BuildPin = table
        .clone()
        .try_into()
        .with_context(|| format!("pins.toml [{}]", role.table()))?;
    if pin.binary_sha256.len() != 64 || !pin.binary_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("pins.toml [{}] binary_sha256 is not a sha256", role.table());
    }
    Ok(Some(CorePins {
        version: pin.version,
        commit: pin.commit,
        deb_url: String::new(),
        deb_sha256: String::new(),
        binary_sha256: pin.binary_sha256,
    }))
}

/// The pinned stellar-core, from the embedded `pins.toml`.
pub fn core_pins() -> CorePins {
    #[derive(Deserialize)]
    struct Pins {
        stellar_core: CorePins,
    }
    toml::from_str::<Pins>(PINS)
        .expect("pins.toml has a [stellar_core] table")
        .stellar_core
}

/// A located, hash-checked stellar-core binary.
#[derive(Debug, Clone)]
pub struct CoreBinary {
    /// The executable.
    pub path: PathBuf,
    /// Directory for `LD_LIBRARY_PATH` (the unpacked runtime libraries), if any.
    pub lib_dir: Option<PathBuf>,
    /// The pins it was checked against.
    pub pins: CorePins,
}

impl CoreBinary {
    /// Locate the binary: `XDRCHECK_STELLAR_CORE` if set, otherwise the fetch cache. `Ok(None)` when no binary is
    /// there (callers that are tests skip); an error when one is there but its hash is not the pinned one.
    pub fn locate() -> Result<Option<CoreBinary>> {
        let manifest = std::env::var_os("XDRCHECK_STELLAR_CORE_MANIFEST").map(PathBuf::from);
        let pins = match &manifest {
            Some(m) => vnext_pins(m)?,
            None => core_pins(),
        };
        let path = match std::env::var_os("XDRCHECK_STELLAR_CORE") {
            Some(p) => {
                let p = PathBuf::from(p);
                if !p.is_file() {
                    bail!("XDRCHECK_STELLAR_CORE={} is not a file", p.display());
                }
                p
            }
            None if manifest.is_some() => {
                let dir = manifest
                    .as_deref()
                    .and_then(Path::parent)
                    .unwrap_or(Path::new("."));
                let p = dir.join("pkg/usr/bin/stellar-core");
                if !p.is_file() {
                    bail!(
                        "XDRCHECK_STELLAR_CORE_MANIFEST is set but {} is not a file",
                        p.display()
                    );
                }
                p
            }
            None => {
                let p = cache_dir()?
                    .join("stellar-core")
                    .join(&pins.version)
                    .join("pkg/usr/bin/stellar-core");
                if !p.is_file() {
                    return Ok(None);
                }
                p
            }
        };
        CoreBinary::at(&path, pins).map(Some)
    }

    /// Locate the binary of `role`: [`CoreBinary::locate`] for the release; otherwise the role's pin in the
    /// embedded `pins.toml` and the binary at `stellar-core-<role>/<version>/pkg/usr/bin/stellar-core` under
    /// the cache, hash-checked. `Ok(None)` when the binary is not there; an error when `pins.toml` does not pin
    /// the role or the binary's hash is not the pinned one.
    pub fn locate_role(role: Role) -> Result<Option<CoreBinary>> {
        if role == Role::Release {
            return CoreBinary::locate();
        }
        let pins = role_pins(role, PINS)?.ok_or_else(|| {
            anyhow::anyhow!(
                "binary: {} needs a [{}] table in pins.toml, and it has none",
                role.name(),
                role.table()
            )
        })?;
        let p = cache_dir()?
            .join(format!("stellar-core-{}", role.name()))
            .join(&pins.version)
            .join("pkg/usr/bin/stellar-core");
        if !p.is_file() {
            return Ok(None);
        }
        CoreBinary::at(&p, pins).map(Some)
    }

    /// Check the binary at `path` against `pins`.
    pub fn at(path: &Path, pins: CorePins) -> Result<CoreBinary> {
        let have =
            xdrcheck_xdr::sha256_file(path).with_context(|| format!("hash {}", path.display()))?;
        if have != pins.binary_sha256 {
            bail!(
                "{} has sha256 {have}, but pins.toml pins stellar-core {} as {}",
                path.display(),
                pins.version,
                pins.binary_sha256
            );
        }
        let lib_dir = path
            .parent()
            .and_then(Path::parent)
            .map(|usr| usr.join("lib/x86_64-linux-gnu"))
            .filter(|d| d.is_dir());
        Ok(CoreBinary {
            path: path.to_path_buf(),
            lib_dir,
            pins,
        })
    }

    /// A command for this binary with the library path set.
    pub fn command(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new(&self.path);
        if let Some(lib) = &self.lib_dir {
            let mut paths = vec![lib.clone()];
            if let Some(old) = std::env::var_os("LD_LIBRARY_PATH") {
                paths.extend(std::env::split_paths(&old));
            }
            cmd.env(
                "LD_LIBRARY_PATH",
                std::env::join_paths(paths).expect("library paths join"),
            );
        }
        cmd
    }
}

/// The pins of a next-protocol build, from its `manifest.json` (`commit`, `binary_sha256`). There is no
/// release package, so the package fields are empty and the version names the commit.
pub fn vnext_pins(manifest: &Path) -> Result<CorePins> {
    #[derive(Deserialize)]
    struct Manifest {
        commit: String,
        binary_sha256: String,
    }
    let text = std::fs::read_to_string(manifest)
        .with_context(|| format!("read {}", manifest.display()))?;
    let m: Manifest = serde_json::from_str(&text)
        .with_context(|| format!("{}: not a next-protocol build manifest", manifest.display()))?;
    if m.binary_sha256.len() != 64 || m.commit.len() < 7 {
        bail!(
            "{}: binary_sha256 or commit is malformed",
            manifest.display()
        );
    }
    Ok(CorePins {
        version: format!("vnext-{}", &m.commit[..12.min(m.commit.len())]),
        commit: m.commit,
        deb_url: String::new(),
        deb_sha256: String::new(),
        binary_sha256: m.binary_sha256,
    })
}

/// `$XDRCHECK_CACHE`, or `$HOME/.cache/xdrcheck`.
pub fn cache_dir() -> Result<PathBuf> {
    if let Some(c) = std::env::var_os("XDRCHECK_CACHE") {
        return Ok(PathBuf::from(c));
    }
    xdrcheck_xdr::userdir::home_cache().context("neither XDRCHECK_CACHE nor HOME is set")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vnext_manifest_pins() {
        let dir = std::env::temp_dir().join(format!("xdrcheck-vnext-pins-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let m = dir.join("manifest.json");
        let sha = "ab".repeat(32);
        std::fs::write(
            &m,
            format!(r#"{{"commit":"0123456789abcdef0123","binary_sha256":"{sha}","ledger_protocol":31}}"#),
        )
        .unwrap();
        let p = vnext_pins(&m).unwrap();
        assert_eq!(p.version, "vnext-0123456789ab");
        assert_eq!(p.binary_sha256, sha);
        std::fs::write(&m, r#"{"commit":"x","binary_sha256":"short"}"#).unwrap();
        assert!(vnext_pins(&m).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn role_pins_read_their_tables_only() {
        let sha = "cd".repeat(32);
        let text = format!(
            "[stellar_core_next]\nversion = \"31.0.0-next\"\ncommit = \"0123456789abcdef\"\nbinary_sha256 = \"{sha}\"\n"
        );
        let p = role_pins(Role::Vnext, &text).unwrap().unwrap();
        assert_eq!(
            (p.version.as_str(), p.binary_sha256.as_str()),
            ("31.0.0-next", sha.as_str())
        );
        assert!(role_pins(Role::Buildtests, &text).unwrap().is_none());
        assert!(role_pins(
            Role::Vnext,
            "[stellar_core_next]\nversion = \"x\"\ncommit = \"y\"\nbinary_sha256 = \"short\"\n"
        )
        .is_err());
        // The repository's pins.toml has no next or buildtests table yet: those roles are an error, not the release.
        if role_pins(Role::Vnext, PINS).unwrap().is_none() {
            assert!(CoreBinary::locate_role(Role::Vnext).is_err());
        }
        for r in [Role::Release, Role::Buildtests, Role::Vnext] {
            assert_eq!(Role::parse(r.name()).unwrap(), r);
        }
        assert!(Role::parse("debug").is_err());
    }

    #[test]
    fn pins_parse() {
        let p = core_pins();
        assert!(!p.version.is_empty());
        assert_eq!(p.binary_sha256.len(), 64);
    }
}
