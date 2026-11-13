//! `xdrcheck-corpus guide-claims --check`: check the guide page
//! (`guide/indexer-hardening.mdx`, beside the corpus root) against its claim map
//! (`guide/claims.yaml`). The same checks as `scripts/py/check_guide_claims.py`; keep the two in step.
//!
//! A normative sentence is tagged by an MDX comment placed right after it:
//! `sentence. {/* claim: C-0123 */}`. Each of these is a failure:
//! - a claim tag names no claim in `claims.yaml`, or a claim is tagged twice;
//! - a sentence containing "must", "never", "should" or "do not" (outside code) has no claim tag;
//! - a tagged claim's `sentence` differs from the tagged sentence of the page (links reduced to
//!   their text, bold markers removed), or its `guide_anchor` is not the anchor of the section the
//!   sentence sits in;
//! - a corpus entry ID mentioned in the page is not canonical (a row or `<row>.<member>` of
//!   `corpus/plan.json`);
//! - generated-table markers are unpaired, a CAP or SEP number is zero-padded in prose, or the page
//!   names an internal working file.
//!
//! Sentences are split per paragraph line and list item; a table row is one statement, cells joined
//! with " | ". Fenced code blocks, front matter, other MDX comments and the generated field tables
//! (between `BEGIN GENERATED` and `END GENERATED`, checked by `guide-table` against `fields.yaml`)
//! are not split into sentences. Exit 1 on any failure.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;

use super::coverage::data;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Check the page against the claim map (the command only checks; the flag is accepted for the
    /// documented spelling `guide-claims --check`)
    #[arg(long)]
    pub check: bool,
}

/// The page, relative to the repository root.
pub const PAGE: &str = "guide/indexer-hardening.mdx";

fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid regex")
}

static TAG_RE: LazyLock<Regex> = LazyLock::new(|| re(r"\{/\*\s*claim:\s*(C-[0-9]{3,4})\s*\*/\}"));
static COMMENT_RE: LazyLock<Regex> = LazyLock::new(|| re(r"\{/\*.*?\*/\}"));
static MARK_RE: LazyLock<Regex> = LazyLock::new(|| re("\x00(\\d+)\x00"));
static LEAD_MARKS_RE: LazyLock<Regex> = LazyLock::new(|| re("^(\\s*\x00\\d+\x00\\s*)+"));
static TRIGGER_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\b(must|never|should|do not)\b"));
static ANCHOR_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^#{2,6}\s.*\{#([a-z0-9-]+)\}\s*$"));
static ENTRY_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"([a-z0-9]+(?:-[a-z0-9]+)*)/([a-z0-9]+(?:[.-][a-z0-9]+)*)"));
static BANNED: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (re(r"\bADR[- ]?\d"), "ADR number"),
        (
            re(r"\d{4}-\d{2}-\d{2}\.md|-2026-\d\d-\d\d"),
            "research note name",
        ),
        (
            re(r"fields\.yaml|claims\.yaml|plan\.json|draft\.yaml"),
            "internal file name",
        ),
    ]
});
static PADDED_RE: LazyLock<Regex> = LazyLock::new(|| re(r"\b(CAP|SEP)-0\d+"));
static LINK_RE: LazyLock<Regex> = LazyLock::new(|| re(r"\[([^\]]*)\]\([^)]*\)"));
static SPACES_RE: LazyLock<Regex> = LazyLock::new(|| re(r"\s+"));
static ITEM_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^(?:[-*]|\d+\.)\s+"));
static DELIM_ROW_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^\|[\s:|-]+\|$"));
static CODE_SPAN_RE: LazyLock<Regex> = LazyLock::new(|| re(r"`[^`]*`"));
static FENCE_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)```.*?```"));
static PROSE_STRIP_RE: LazyLock<Regex> = LazyLock::new(|| re(r"`[^`]*`|\([^)\s]*\)|https?://\S+"));

/// Sentence text as `claims.yaml` stores it: links reduced to their text, bold removed, spaces
/// collapsed.
pub fn clean(text: &str) -> String {
    let t = LINK_RE.replace_all(text, "$1").replace("**", "");
    SPACES_RE.replace_all(&t, " ").trim().to_string()
}

/// `(line number, anchor, text)` for each paragraph line, list item and table row of the page.
/// Table rows are marked with a leading `\x01`.
fn segments(text: &str) -> Vec<(usize, String, String)> {
    let mut out = Vec::new();
    let (mut anchor, mut in_code, mut in_front, mut in_generated) =
        (String::new(), false, false, false);
    for (i, line) in text.split('\n').enumerate() {
        let n = i + 1;
        let s = line.trim();
        if n == 1 && s == "---" {
            in_front = true;
            continue;
        }
        if in_front {
            in_front = s != "---";
            continue;
        }
        if s.starts_with("```") {
            in_code = !in_code;
            continue;
        }
        if in_code || s.is_empty() {
            continue;
        }
        if s.contains("BEGIN GENERATED:") {
            in_generated = true;
            continue;
        }
        if s.contains("END GENERATED") {
            in_generated = false;
            continue;
        }
        if in_generated {
            continue;
        }
        if let Some(c) = ANCHOR_RE.captures(s) {
            anchor = format!("#{}", &c[1]);
        }
        if s.starts_with('|') {
            if DELIM_ROW_RE.is_match(s) {
                continue;
            }
            let cells: Vec<&str> = s.trim_matches('|').split('|').map(str::trim).collect();
            out.push((n, anchor.clone(), format!("\x01{}", cells.join(" | "))));
        } else if s.starts_with('<') && !TAG_RE.find(s).is_some_and(|m| m.start() == 0) {
            continue;
        } else {
            out.push((n, anchor.clone(), ITEM_RE.replace(s, "").into_owned()));
        }
    }
    out
}

/// Split at whitespace runs that follow `.`, `!` or `?` (Python `(?<=[.!?])\s+`).
fn split_sentences(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut prev, mut chars) = (0, None::<char>, text.char_indices().peekable());
    while let Some((i, c)) = chars.next() {
        if c.is_whitespace() && matches!(prev, Some('.' | '!' | '?')) {
            out.push(&text[start..i]);
            let mut end = i + c.len_utf8();
            while let Some(&(j, d)) = chars.peek() {
                if !d.is_whitespace() {
                    break;
                }
                end = j + d.len_utf8();
                chars.next();
            }
            start = end;
            prev = None;
            continue;
        }
        prev = Some(c);
    }
    out.push(&text[start..]);
    out
}

/// Split one segment into `(sentence, claim IDs)`; a tag belongs to the sentence before it. A table
/// row is a single statement whose tags cover the row.
fn sentences(text: &str) -> Vec<(String, Vec<String>)> {
    let row = text.starts_with('\x01');
    let mut tags: Vec<String> = Vec::new();
    let marked = TAG_RE.replace_all(text.trim_start_matches('\x01'), |c: &regex::Captures| {
        tags.push(c[1].to_string());
        format!(" \x00{}\x00 ", tags.len() - 1)
    });
    let text = COMMENT_RE.replace_all(&marked, " ").into_owned();
    let ids_in = |s: &str| -> Vec<String> {
        MARK_RE
            .captures_iter(s)
            .map(|c| tags[c[1].parse::<usize>().expect("index")].clone())
            .collect()
    };
    if row {
        return vec![(clean(&MARK_RE.replace_all(&text, " ")), ids_in(&text))];
    }
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for piece in split_sentences(&text) {
        let mut piece = piece;
        if let Some(lead) = LEAD_MARKS_RE.find(piece) {
            let ids = ids_in(lead.as_str());
            match out.last_mut() {
                Some(last) => last.1.extend(ids),
                None => out.push((String::new(), ids)),
            }
            piece = &piece[lead.end()..];
        }
        if piece.trim().is_empty() {
            continue;
        }
        out.push((clean(&MARK_RE.replace_all(piece, " ")), ids_in(piece)));
    }
    out
}

/// `(line, anchor, sentence, claim IDs)` for the whole page.
pub fn tagged_sentences(page: &str) -> Vec<(usize, String, String, Vec<String>)> {
    let mut out = Vec::new();
    for (n, anchor, seg) in segments(page) {
        for (s, ids) in sentences(&seg) {
            out.push((n, anchor.clone(), s, ids));
        }
    }
    out
}

/// Every `group/slug` corpus-ID-shaped string in `text` whose group is in `groups` (Python
/// `(?<![\w/.-])…`: the match must not follow a word character, `/`, `.` or `-`).
pub fn entry_ids<'a>(text: &'a str, groups: &BTreeSet<String>) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(c) = ENTRY_RE.captures_at(text, at) {
        let m = c.get(0).expect("match");
        let ok_before = text[..m.start()]
            .chars()
            .next_back()
            .is_none_or(|p| !(p.is_alphanumeric() || p == '_' || p == '/' || p == '.' || p == '-'));
        if !ok_before {
            // Try again one character later, as a look-behind would.
            at = m.start() + text[m.start()..].chars().next().map_or(1, char::len_utf8);
            continue;
        }
        if groups.contains(&c[1]) {
            out.push(m.as_str());
        }
        at = m.end();
    }
    out
}

#[derive(Debug, Deserialize)]
struct ClaimsFile {
    claims: Vec<Claim>,
}

#[derive(Debug, Deserialize)]
struct Claim {
    claim_id: String,
    guide_anchor: String,
    sentence: String,
}

/// Repository root of a corpus root (its parent).
pub fn repo_root(corpus: &Path) -> PathBuf {
    let c = corpus
        .canonicalize()
        .unwrap_or_else(|_| corpus.to_path_buf());
    c.parent().map(Path::to_path_buf).unwrap_or(c)
}

/// Run every check; returns `(summary, failures)`.
pub fn check(corpus: &Path) -> Result<(String, Vec<String>)> {
    let root = repo_root(corpus);
    let page_path = root.join(PAGE);
    let raw = std::fs::read_to_string(&page_path)
        .with_context(|| format!("read {}", page_path.display()))?;
    let claims_path = root.join("guide/claims.yaml");
    let claims: ClaimsFile = serde_yaml::from_str(
        &std::fs::read_to_string(&claims_path)
            .with_context(|| format!("read {}", claims_path.display()))?,
    )
    .with_context(|| format!("parse {}", claims_path.display()))?;
    let claims: BTreeMap<String, Claim> = claims
        .claims
        .into_iter()
        .map(|c| (c.claim_id.clone(), c))
        .collect();
    let canon = data::canonical_ids(corpus)?;
    let groups: BTreeSet<String> = canon
        .iter()
        .filter_map(|i| i.split('/').next().map(str::to_string))
        .collect();

    let mut bad = Vec::new();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let (mut n_sent, mut n_norm) = (0, 0);
    for (line, anchor, sent, ids) in tagged_sentences(&raw) {
        n_sent += 1;
        if TRIGGER_RE.is_match(&CODE_SPAN_RE.replace_all(&sent, "")) {
            n_norm += 1;
            if ids.is_empty() {
                let short: String = sent.chars().take(120).collect();
                bad.push(format!(
                    "{PAGE}:{line}: normative sentence without a claim tag: {short:?}"
                ));
            }
        }
        for cid in ids {
            if let Some(first) = seen.get(&cid) {
                bad.push(format!(
                    "{PAGE}:{line}: {cid} is tagged twice (first on line {first})"
                ));
            }
            seen.insert(cid.clone(), line);
            let Some(c) = claims.get(&cid) else {
                bad.push(format!("{PAGE}:{line}: {cid} is not in guide/claims.yaml"));
                continue;
            };
            if c.sentence != sent {
                bad.push(format!(
                    "{PAGE}:{line}: {cid} sentence differs from claims.yaml:\n    page:   {sent:?}\n    claims: {:?}",
                    c.sentence
                ));
            }
            if c.guide_anchor != anchor {
                bad.push(format!(
                    "{PAGE}:{line}: {cid} guide_anchor {:?} but the section is {anchor:?}",
                    c.guide_anchor
                ));
            }
        }
    }

    let body = FENCE_RE.replace_all(&raw, "");
    let named: BTreeSet<&str> = entry_ids(&body, &groups).into_iter().collect();
    for id in entry_ids(&body, &groups) {
        if !canon.contains(id) {
            bad.push(format!("{PAGE}: {id:?} is not a canonical corpus entry ID"));
        }
    }
    if raw.matches("BEGIN GENERATED:").count() != raw.matches("END GENERATED").count() {
        bad.push(format!(
            "{PAGE}: unpaired BEGIN GENERATED / END GENERATED markers"
        ));
    }
    let prose = PROSE_STRIP_RE.replace_all(&body, "");
    for m in PADDED_RE.find_iter(&prose) {
        bad.push(format!(
            "{PAGE}: write {} without zero padding in prose",
            m.as_str()
        ));
    }
    for (rx, why) in BANNED.iter() {
        for m in rx.find_iter(&raw) {
            bad.push(format!("{PAGE}: {why}: {:?}", m.as_str()));
        }
    }
    let summary = format!(
        "guide: {n_sent} sentences, {n_norm} normative, {} claim tags, {} corpus entries named",
        seen.len(),
        named.len()
    );
    Ok((summary, bad))
}

pub fn run(corpus: &Path, _args: Args) -> Result<ExitCode> {
    let (summary, bad) = check(corpus)?;
    println!("{summary}");
    for b in &bad {
        println!("FAIL {b}");
    }
    Ok(if bad.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_like_the_python_check() {
        assert_eq!(
            split_sentences("One. Two!  Three? x.y"),
            vec!["One.", "Two!", "Three?", "x.y"]
        );
        let s = sentences(
            "First rule. {/* claim: C-6001 */} Second, see [x](http://y). {/* claim: C-6002 */}",
        );
        assert_eq!(
            s,
            vec![
                ("First rule.".to_string(), vec!["C-6001".to_string()]),
                ("Second, see x.".to_string(), vec!["C-6002".to_string()]),
            ]
        );
        let groups: BTreeSet<String> = ["cap-0073".to_string()].into();
        assert_eq!(
            entry_ids("see `cap-0073/sac-trust` and x/cap-0073/no", &groups),
            vec!["cap-0073/sac-trust"]
        );
    }
}
