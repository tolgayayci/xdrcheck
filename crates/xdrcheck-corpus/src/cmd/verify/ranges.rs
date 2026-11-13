//! The grammar of `conformance.known_divergences[].versions` (`docs/manifest.md` §7), checked so
//! that a range no consumer can parse fails verify instead of silently matching nothing. It is
//! the grammar the conformance runner evaluates:
//!
//! - a commit range for repositories without tags: `A..B` or `..B`, each side 7 to 40 lower-case
//!   hex digits;
//! - otherwise a semver range: alternatives joined by `||`, each `*`, a hyphen range `A - B`, or
//!   a space-separated list of comparators (`=`, `<`, `<=`, `>`, `>=`, or a bare version). A
//!   version is `MAJOR[.MINOR[.PATCH]]` with an optional leading `v`, optional `-prerelease` and
//!   optional `+build`.

/// Why `range` does not parse, or `None` when it does.
pub fn problem(range: &str) -> Option<String> {
    let r = range.trim();
    if r.is_empty() {
        return Some("an empty version range".into());
    }
    if r.contains("..") {
        return commit_range(r).err();
    }
    for alt in r.split("||") {
        if let Err(e) = alternative(alt.trim()) {
            return Some(format!("{range:?}: {e}"));
        }
    }
    None
}

fn commit_range(r: &str) -> Result<(), String> {
    let hex = |s: &str| {
        (7..=40).contains(&s.len()) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    match r.split_once("..") {
        Some((a, b)) if (a.is_empty() || hex(a)) && hex(b) => Ok(()),
        _ => Err(format!(
            "{r:?} is not a commit range A..B or ..B of 7 to 40 lower-case hex digits"
        )),
    }
}

fn alternative(set: &str) -> Result<(), String> {
    if set.is_empty() || set == "*" {
        return Ok(());
    }
    if let Some((lo, hi)) = set.split_once(" - ") {
        version(lo)?;
        return version(hi);
    }
    for c in set.split_whitespace() {
        let v = [">=", "<=", ">", "<", "="]
            .iter()
            .find_map(|op| c.strip_prefix(op))
            .unwrap_or(c);
        version(v)?;
    }
    Ok(())
}

fn version(s: &str) -> Result<(), String> {
    let s = s.trim();
    let s = s.strip_prefix('v').unwrap_or(s);
    let s = s.split_once('+').map_or(s, |(a, _)| a);
    let core = s.split_once('-').map_or(s, |(a, _)| a);
    let parts: Vec<&str> = core.split('.').collect();
    let ok = !core.is_empty()
        && parts.len() <= 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    if ok {
        Ok(())
    } else {
        Err(format!("version {s:?} is not MAJOR.MINOR.PATCH"))
    }
}

#[cfg(test)]
mod tests {
    use super::problem;

    #[test]
    fn accepts_what_the_runner_evaluates() {
        for r in [
            ">=0.7.0 <0.7.2",
            "<0.6.1",
            ">=16.0.0 <17.2.0 || >=17.3.0",
            "1.2.3 - 1.4.0",
            "*",
            "=v0.8.0",
            "17.2.0-rc.1",
            "..764a4f5bcbff5abb0949d93da37f769063013ea0",
            "c152783c..e967ce8b",
        ] {
            assert_eq!(problem(r), None, "{r}");
        }
    }

    #[test]
    fn refuses_what_it_cannot_parse() {
        for r in [
            "", "^1.2.3", "~1.2", ">=1.x", "1.2.3.4", "abc..", "..XYZ", "latest", ">= 1.0.0",
        ] {
            assert!(problem(r).is_some(), "{r}");
        }
    }
}
