//! Small helpers: atomic writes, pretty JSON files, UTC time stamps and date parsing (RFC 3339 and
//! the HTTP date format), without a date-time dependency.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

/// A check failed (exit code 1), as opposed to the tool being unable to run (exit code 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckFailed(pub String);

impl std::fmt::Display for CheckFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CheckFailed {}

/// Map a command's result to its exit code: a [`CheckFailed`] is printed and exits 1; any other
/// error is returned (exit 2 in `main`).
pub fn exit_code(cmd: &str, r: Result<bool>) -> Result<std::process::ExitCode> {
    match r {
        Ok(true) => Ok(std::process::ExitCode::SUCCESS),
        Ok(false) => Ok(std::process::ExitCode::from(1)),
        Err(e) => match e.downcast_ref::<CheckFailed>() {
            Some(c) => {
                eprintln!("xdrcheck-corpus {cmd}: {c}");
                Ok(std::process::ExitCode::from(1))
            }
            None => Err(e),
        },
    }
}

/// Write `bytes` to `path` through a temporary file in the same directory and a rename, creating
/// the parent directory.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .with_context(|| format!("{} has no parent", path.display()))?;
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    std::fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}

/// Write a JSON value pretty-printed (two-space indent, key order kept) with a final newline.
pub fn write_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    write_atomic(path, text.as_bytes())
}

/// Read and parse a JSON file.
pub fn read_json(path: &Path) -> Result<serde_json::Value> {
    let text = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&text).with_context(|| format!("parse {}", path.display()))
}

/// Seconds since the Unix epoch, now.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Now as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn now_rfc3339() -> String {
    rfc3339(now_unix())
}

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn rfc3339(unix: i64) -> String {
    let (days, secs) = (unix.div_euclid(86_400), unix.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Parse `YYYY-MM-DDTHH:MM:SS` followed by `Z` or `+00:00` (UTC only) into Unix seconds.
pub fn parse_rfc3339(s: &str) -> Result<i64> {
    let (date, time) = s.split_once('T').context("no 'T'")?;
    let time = time
        .strip_suffix('Z')
        .or_else(|| time.strip_suffix("+00:00"))
        .with_context(|| format!("{s:?} is not UTC"))?;
    let num = |p: &str| -> Result<i64> { p.parse::<i64>().with_context(|| format!("{s:?}")) };
    let d: Vec<&str> = date.split('-').collect();
    let t: Vec<&str> = time.split(':').collect();
    if d.len() != 3 || t.len() != 3 {
        bail!("{s:?} is not YYYY-MM-DDTHH:MM:SS");
    }
    let days = days_from_civil(num(d[0])?, num(d[1])?, num(d[2])?);
    Ok(days * 86_400 + num(t[0])? * 3600 + num(t[1])? * 60 + num(t[2])?)
}

/// Parse an HTTP date (`Sat, 20 Sep 2025 05:41:56 GMT`, RFC 9110 IMF-fixdate) into Unix seconds.
pub fn parse_http_date(s: &str) -> Result<i64> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 6 || parts[5] != "GMT" {
        bail!("{s:?} is not an HTTP date");
    }
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month = MONTHS
        .iter()
        .position(|m| *m == parts[2])
        .with_context(|| format!("{s:?}: month"))? as i64
        + 1;
    let day: i64 = parts[1].parse()?;
    let year: i64 = parts[3].parse()?;
    let t: Vec<i64> = parts[4]
        .split(':')
        .map(|x| x.parse::<i64>())
        .collect::<Result<_, _>>()?;
    if t.len() != 3 {
        bail!("{s:?}: time");
    }
    Ok(days_from_civil(year, month, day) * 86_400 + t[0] * 3600 + t[1] * 60 + t[2])
}

// Howard Hinnant's civil-date algorithms (proleptic Gregorian calendar).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(rfc3339(1_443_633_354), "2015-09-30T17:15:54Z");
        assert_eq!(
            parse_rfc3339("2015-09-30T17:15:54Z").unwrap(),
            1_443_633_354
        );
        assert_eq!(
            parse_rfc3339("2025-09-20T05:41:56+00:00").unwrap(),
            parse_http_date("Sat, 20 Sep 2025 05:41:56 GMT").unwrap()
        );
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
    }
}
