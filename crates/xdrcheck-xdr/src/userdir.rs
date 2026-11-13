//! The kit's per-user cache directory, `$HOME/.cache/xdrcheck`. The kit had another name before, and a cache made
//! under that name is still read: when `$HOME/.cache/xdrcheck` does not exist and the old directory does, the old
//! one is used, so existing caches keep working. Nothing is moved. Environment variables of the earlier name
//! (`XCC_<NAME>`) are read the same way: [`legacy_env`] copies them to `XDRCHECK_<NAME>` when that is not set.

use std::path::{Path, PathBuf};

/// The directory name the kit creates.
pub const NAME: &str = "xdrcheck";
/// The directory name earlier versions created; only read.
const LEGACY: &str = "xcc";

/// `base/xdrcheck`, or `base/<legacy name>` when only that one exists as a directory.
pub fn under(base: &Path) -> PathBuf {
    let cur = base.join(NAME);
    if cur.exists() {
        return cur;
    }
    let old = base.join(LEGACY);
    if old.is_dir() {
        return old;
    }
    cur
}

/// `$HOME/.cache/xdrcheck` (or the legacy directory there); `None` when `HOME` is not set.
pub fn home_cache() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| under(&PathBuf::from(h).join(".cache")))
}

/// The prefix of the kit's environment variables.
pub const ENV_PREFIX: &str = "XDRCHECK_";
/// The prefix earlier versions read; only read.
const LEGACY_ENV_PREFIX: &str = "XCC_";

/// Copies every variable of the earlier name (`XCC_<NAME>`) to `XDRCHECK_<NAME>` when `XDRCHECK_<NAME>` is not
/// set, so settings exported under the old name still apply to this process and to every program it starts. A
/// variable set under the new name always wins. Returns the names it set. Binaries call it first thing in
/// `main`, before parsing arguments (some flags default from the environment) and before starting threads.
pub fn legacy_env() -> Vec<String> {
    let mut set = Vec::new();
    for (k, v) in std::env::vars_os() {
        let Some(k) = k.to_str() else { continue };
        let Some(rest) = k.strip_prefix(LEGACY_ENV_PREFIX) else { continue };
        if rest.is_empty() {
            continue;
        }
        let name = format!("{ENV_PREFIX}{rest}");
        if std::env::var_os(&name).is_none() {
            std::env::set_var(&name, v);
            set.push(name);
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_env_copies_old_names_and_keeps_new_ones() {
        let id = std::process::id();
        let only_old = format!("USERDIR_TEST_OLD_ONLY_{id}");
        let both = format!("USERDIR_TEST_BOTH_{id}");
        std::env::set_var(format!("XCC_{only_old}"), "old");
        std::env::set_var(format!("XCC_{both}"), "old");
        std::env::set_var(format!("XDRCHECK_{both}"), "new");
        let set = legacy_env();
        assert_eq!(std::env::var(format!("XDRCHECK_{only_old}")).unwrap(), "old");
        assert_eq!(std::env::var(format!("XDRCHECK_{both}")).unwrap(), "new");
        assert!(set.contains(&format!("XDRCHECK_{only_old}")));
        assert!(!set.contains(&format!("XDRCHECK_{both}")));
        for n in [format!("XCC_{only_old}"), format!("XCC_{both}"), format!("XDRCHECK_{only_old}"), format!("XDRCHECK_{both}")] {
            std::env::remove_var(n);
        }
    }

    #[test]
    fn prefers_new_then_legacy_then_new() {
        let t = std::env::temp_dir().join(format!("xdrcheck-userdir-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        assert_eq!(under(&t), t.join(NAME));
        std::fs::create_dir_all(t.join(LEGACY)).unwrap();
        assert_eq!(under(&t), t.join(LEGACY));
        std::fs::create_dir_all(t.join(NAME)).unwrap();
        assert_eq!(under(&t), t.join(NAME));
        std::fs::remove_dir_all(&t).unwrap();
    }
}
