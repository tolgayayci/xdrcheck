//! Reading the corpus: manifest entries, chain indexes, the ID registry and the frozen schemas.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// One manifest file.
pub struct Entry {
    /// ID derived from the file path (`manifest/<id>.json`).
    pub id: String,
    /// The parsed file, or why it could not be parsed.
    pub json: Result<Value, String>,
}

impl Entry {
    pub fn kind(&self) -> &str {
        self.json
            .as_ref()
            .ok()
            .and_then(|j| j["kind"].as_str())
            .unwrap_or("")
    }

    pub fn negative(&self) -> bool {
        self.json
            .as_ref()
            .ok()
            .and_then(|j| j["negative"].as_bool())
            .unwrap_or(false)
    }

    pub fn variants(&self) -> &[Value] {
        self.json
            .as_ref()
            .ok()
            .and_then(|j| j["variants"].as_array())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn caps(&self) -> Vec<i64> {
        self.json
            .as_ref()
            .ok()
            .and_then(|j| j["caps"].as_array())
            .map(|a| a.iter().filter_map(Value::as_i64).collect())
            .unwrap_or_default()
    }

    /// Variant key: the network, or `network@protocol` when the entry has several protocols.
    pub fn variant_key(&self, v: &Value) -> String {
        let net = v["network"].as_str().unwrap_or("?");
        let protocols: HashSet<String> = self
            .variants()
            .iter()
            .map(|v| v["protocol"].to_string())
            .collect();
        if protocols.len() > 1 {
            format!("{net}@{}", v["protocol"])
        } else {
            net.to_string()
        }
    }
}

/// Every JSON file under `dir`, recursively, sorted, as (path relative to `dir` without `.json`,
/// full path).
pub fn json_files(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<()> {
        for e in std::fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
            let p = e?.path();
            if p.is_dir() {
                walk(base, &p, out)?;
            } else if p.extension().is_some_and(|x| x == "json") {
                let rel = p.strip_prefix(base).expect("under base").with_extension("");
                let rel = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((rel, p));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    if dir.is_dir() {
        walk(dir, dir, &mut out)?;
    }
    out.sort();
    Ok(out)
}

/// Load every manifest entry, keeping parse failures as data (the `schema` check reports them).
/// With an overlay corpus, its `manifest/` is read too; an entry ID in both is a tool error.
pub fn entries(corpus: &Path, overlay: Option<&Path>) -> Result<Vec<Entry>> {
    let mut files = json_files(&corpus.join("manifest"))?;
    if let Some(ov) = overlay {
        let public: HashSet<String> = files.iter().map(|(id, _)| id.clone()).collect();
        let mut both = Vec::new();
        for (id, p) in json_files(&ov.join("manifest"))? {
            if public.contains(&id) {
                both.push(id);
            } else {
                files.push((id, p));
            }
        }
        if !both.is_empty() {
            bail!(
                "entries in both the public corpus and the overlay corpus {}: {}",
                ov.display(),
                both.join(", ")
            );
        }
        files.sort();
    }
    Ok(files
        .into_iter()
        .map(|(id, path)| {
            let json = std::fs::read(&path)
                .map_err(|e| e.to_string())
                .and_then(|b| serde_json::from_slice(&b).map_err(|e| format!("not JSON: {e}")));
            Entry { id, json }
        })
        .collect())
}

/// Canonical entry IDs from `plan.json`: every row ID and `<row id>.<member>`. With an overlay
/// corpus, its `plan-rows.json` (`{"rows": [plan rows], "members": {row id: [member]}}`) adds
/// rows and members to public rows; a row ID in both is a tool error.
pub fn canonical_ids(corpus: &Path, overlay: Option<&Path>) -> Result<HashSet<String>> {
    let read = |path: &Path| -> Result<Value> {
        serde_json::from_slice(
            &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        )
        .with_context(|| format!("{} is not JSON", path.display()))
    };
    let path = corpus.join("plan.json");
    let plan = read(&path)?;
    let Some(rows) = plan.as_array() else {
        bail!("{}: not an array of rows", path.display());
    };
    let mut ids = HashSet::new();
    let add_rows = |rows: &[Value], path: &Path, ids: &mut HashSet<String>| -> Result<()> {
        for r in rows {
            let Some(id) = r["id"].as_str() else {
                bail!("{}: a row has no id", path.display());
            };
            if !ids.insert(id.to_string()) {
                bail!("{}: row {id} is planned twice", path.display());
            }
            for m in r["members"].as_array().into_iter().flatten() {
                if let Some(m) = m.as_str() {
                    ids.insert(format!("{id}.{m}"));
                }
            }
        }
        Ok(())
    };
    add_rows(rows, &path, &mut ids)?;
    if let Some(ov) = overlay {
        let path = ov.join("plan-rows.json");
        if path.is_file() {
            let extra = read(&path)?;
            let rows = extra["rows"].as_array().map(Vec::as_slice).unwrap_or(&[]);
            add_rows(rows, &path, &mut ids)?;
            for (row, members) in extra["members"].as_object().into_iter().flatten() {
                if !ids.contains(row) {
                    bail!(
                        "{}: members of {row}, which no plan row has",
                        path.display()
                    );
                }
                for m in members.as_array().into_iter().flatten() {
                    if let Some(m) = m.as_str() {
                        ids.insert(format!("{row}.{m}"));
                    }
                }
            }
        }
    }
    Ok(ids)
}

/// Whether `s` has the shape of an entry ID: `group/slug[/…]`, lower-case alphanumerics, the
/// group joined by `-`, slugs by `-` or `.` (as `scripts/py/check_ids.py`).
pub fn looks_like_id(s: &str) -> bool {
    fn word_run(s: &str, seps: &[char]) -> bool {
        !s.is_empty()
            && s.split(|c| seps.contains(&c)).all(|w| {
                !w.is_empty()
                    && w.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            })
    }
    let mut parts = s.split('/');
    let group = parts.next().unwrap_or("");
    let rest: Vec<&str> = parts.collect();
    word_run(group, &['-']) && !rest.is_empty() && rest.iter().all(|p| word_run(p, &['-', '.']))
}

/// Simple glob: `*` matches any run of characters (including `/`), `?` one character.
pub fn glob_match(pattern: &str, s: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), s.chars().collect());
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// The frozen schemas, by file stem (`manifest-entry`, `chain-index`, …), with a validator per
/// schema that resolves cross-schema `$ref`s through their `$id`s.
pub struct Schemas {
    validators: BTreeMap<String, jsonschema::Validator>,
    /// The driver protocol's reason codes (`runResponse.reason.code`), which a known divergence's
    /// `match.reason` must be one of.
    pub driver_reasons: Vec<String>,
}

impl Schemas {
    pub fn load(corpus: &Path) -> Result<Schemas> {
        let dir = corpus.join("schema");
        let mut docs = Vec::new();
        for e in std::fs::read_dir(&dir).with_context(|| format!("listing {}", dir.display()))? {
            let p = e?.path();
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            if let Some(stem) = name.strip_suffix(".schema.json") {
                let v: Value = serde_json::from_slice(&std::fs::read(&p)?)
                    .with_context(|| format!("{} is not JSON", p.display()))?;
                docs.push((stem.to_string(), v));
            }
        }
        let mut builder = jsonschema::Registry::new();
        for (stem, doc) in &docs {
            let Some(id) = doc["$id"].as_str() else {
                bail!("schema {stem} has no $id");
            };
            builder = builder
                .add(id, doc)
                .with_context(|| format!("registering schema {stem}"))?;
        }
        let registry = builder.prepare().context("preparing the schema registry")?;
        let driver_reasons = docs
            .iter()
            .find(|(stem, _)| stem == "driver-protocol")
            .and_then(|(_, d)| {
                d.pointer("/$defs/runResponse/properties/reason/properties/code/enum")
                    .and_then(Value::as_array)
            })
            .into_iter()
            .flatten()
            .filter_map(|c| c.as_str().map(str::to_string))
            .collect();
        let mut validators = BTreeMap::new();
        for (stem, doc) in &docs {
            let v = jsonschema::draft202012::options()
                .with_registry(&registry)
                .should_validate_formats(true)
                .build(doc)
                .map_err(|e| anyhow::anyhow!("schema {stem} does not compile: {e}"))?;
            validators.insert(stem.clone(), v);
        }
        Ok(Schemas {
            validators,
            driver_reasons,
        })
    }

    /// Validation errors of `instance` against schema `name` (at most `limit`, as
    /// `at <pointer>: <message>`).
    pub fn errors(&self, name: &str, instance: &Value, limit: usize) -> Vec<String> {
        let Some(v) = self.validators.get(name) else {
            return vec![format!("schema {name} is not in corpus/schema/")];
        };
        v.iter_errors(instance)
            .take(limit)
            .map(|e| {
                let mut msg = e.to_string();
                if msg.len() > 200 {
                    let mut cut = 200;
                    while !msg.is_char_boundary(cut) {
                        cut -= 1;
                    }
                    msg.truncate(cut);
                    msg.push('…');
                }
                format!(
                    "at {}: {msg}",
                    if e.instance_path().as_str().is_empty() {
                        "/"
                    } else {
                        e.instance_path().as_str()
                    }
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Rust validator agrees with the reference Python check (`scripts/py/check_schemas.py`)
    /// on every schema example: valid examples validate, invalid ones do not.
    #[test]
    fn schema_examples_agree_with_reference() {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
        let schemas = Schemas::load(&corpus).unwrap();
        let mut n = 0;
        for (rel, path) in json_files(&corpus.join("schema/examples")).unwrap() {
            let (name, file) = rel.split_once('/').unwrap();
            let v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            let errors = schemas.errors(name, &v, 3);
            if file.starts_with("valid-") {
                assert!(errors.is_empty(), "{rel} should be valid: {errors:?}");
            } else {
                assert!(!errors.is_empty(), "{rel} should be invalid");
            }
            n += 1;
        }
        assert!(n >= 28, "{n} examples");
    }

    #[test]
    fn glob() {
        assert!(glob_match(
            "cap-0040/*",
            "cap-0040/signed-payload-signer-added"
        ));
        assert!(glob_match("*", "a/b"));
        assert!(glob_match("cap-00??/*", "cap-0073/x"));
        assert!(!glob_match("cap-0040/*", "cap-0073/x"));
        assert!(glob_match(
            "*signer*",
            "cap-0040/signed-payload-signer-added"
        ));
    }

    #[test]
    fn id_shape() {
        assert!(looks_like_id("cap-0040/signed-payload-signer-added"));
        assert!(looks_like_id("strkey/sep-0023.valid-01"));
        assert!(!looks_like_id("Cap-0040/x"));
        assert!(!looks_like_id("cap-0040"));
        assert!(!looks_like_id("https://example.com/x"));
        assert!(!looks_like_id("cap-0040/a..b"));
    }
}
