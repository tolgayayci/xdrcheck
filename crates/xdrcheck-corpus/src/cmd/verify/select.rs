//! Key-selected pinpoints: `expect.values[].select` (`docs/manifest.md`, the pinpoints).
//!
//! stellar-core writes an operation's ledger-entry changes from an unordered map, so where one
//! entry's change sits in a change list differs between runs and passphrases. A pinpoint with
//! `select: {in, key, change?}` names the element of the array at the JSON Pointer `in` by its
//! ledger key — `key` is the SEP-51 JSON of a `LedgerKey` — and its `path` is a JSON Pointer
//! relative to that element. An element matches when it is
//!
//! - a `LedgerEntryChange` (`{created|updated|state|restored: LedgerEntry}` or `{removed:
//!   LedgerKey}`) whose entry has the key (or whose removed key equals it), and whose arm is
//!   `change` when one is given;
//! - a `LedgerEntry` with the key (only without `change`);
//! - a `LedgerKey` equal to `key` (only without `change`).
//!
//! An entry has a key when the key's arm names the entry's `data` arm and every field of the key
//! is a field of the entry with the same value (a `LedgerKey` arm's fields are a subset of its
//! entry's, under the same names); a `config_setting` key matches the entry whose union arm is
//! its `config_setting_id`. Exactly one element must match. The Go loader
//! (`go/internal/manifest`) applies the same rules, so both resolve a selection to the same
//! pointer.

use serde_json::Value;

/// The `LedgerEntryChange` arms.
pub const CHANGE_ARMS: [&str; 5] = ["created", "updated", "removed", "state", "restored"];

/// Resolve a selection (tokens already substituted) in `doc` to the JSON Pointer of the one
/// matching element.
pub fn resolve(doc: &Value, select: &Value) -> Result<String, String> {
    let at = select["in"].as_str().ok_or("select.in is not a string")?;
    let key = &select["key"];
    if !key.as_object().is_some_and(|k| k.len() == 1) {
        return Err(format!("select.key {key} is not a ledger key"));
    }
    let change = match &select["change"] {
        Value::Null => None,
        Value::String(c) if CHANGE_ARMS.contains(&c.as_str()) => Some(c.as_str()),
        other => return Err(format!("select.change {other} is not a change type")),
    };
    let items = doc
        .pointer(at)
        .ok_or_else(|| format!("select.in {at} does not resolve in the sidecar"))?
        .as_array()
        .ok_or_else(|| format!("select.in {at} is not an array"))?;
    let hits: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, el)| element_matches(el, key, change))
        .map(|(i, _)| i)
        .collect();
    let what = || match change {
        Some(c) => format!("a `{c}` change of {key}"),
        None => format!("{key}"),
    };
    match hits.as_slice() {
        [i] => Ok(format!("{at}/{i}")),
        [] => Err(format!(
            "select: no element of {at} is {} ({} elements)",
            what(),
            items.len()
        )),
        many => Err(format!(
            "select: elements {many:?} of {at} are all {}; add `change` or a narrower `in`",
            what()
        )),
    }
}

/// Whether one array element is the selected key (and change type).
pub fn element_matches(el: &Value, key: &Value, change: Option<&str>) -> bool {
    if let Some(o) = el.as_object() {
        if let Some((arm, v)) = single(o) {
            if CHANGE_ARMS.contains(&arm.as_str()) {
                if change.is_some_and(|c| c != arm) {
                    return false;
                }
                return if arm == "removed" {
                    v == key
                } else {
                    data_has_key(&v["data"], key)
                };
            }
        }
        if o.contains_key("data") && o.contains_key("last_modified_ledger_seq") {
            return change.is_none() && data_has_key(&o["data"], key);
        }
    }
    change.is_none() && el == key
}

/// Whether a `LedgerEntry`'s `data` has ledger key `key`.
pub fn data_has_key(data: &Value, key: &Value) -> bool {
    let (Some((d_arm, d)), Some((k_arm, k))) = (
        data.as_object().and_then(single),
        key.as_object().and_then(single),
    ) else {
        return false;
    };
    if d_arm != k_arm {
        return false;
    }
    if k_arm == "config_setting" {
        let id = k.get("config_setting_id").and_then(Value::as_str);
        return match (id, d.as_object().and_then(single)) {
            (Some(id), Some((arm, _))) => arm == id,
            _ => false,
        };
    }
    match (k.as_object(), d.as_object()) {
        (Some(kf), Some(df)) => !kf.is_empty() && kf.iter().all(|(f, v)| df.get(f) == Some(v)),
        _ => false,
    }
}

fn single(o: &serde_json::Map<String, Value>) -> Option<(&String, &Value)> {
    (o.len() == 1).then(|| o.iter().next()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn account(id: &str, balance: &str) -> Value {
        json!({"last_modified_ledger_seq": 5, "data": {"account": {"account_id": id, "balance": balance}}, "ext": "v0"})
    }

    #[test]
    fn selects_by_key_and_change() {
        let doc = json!({"changes": [
            {"state": account("GB", "1")},
            {"state": account("GA", "2")},
            {"updated": account("GA", "3")},
            {"updated": account("GB", "4")},
            {"removed": {"trustline": {"account_id": "GA", "asset": "native"}}},
            {"created": {"last_modified_ledger_seq": 5, "data": {"config_setting": {"contract_max_size_bytes": 1}}, "ext": "v0"}},
        ]});
        let a = json!({"account": {"account_id": "GA"}});
        let sel = |key: &Value, change: Option<&str>| {
            let mut s = json!({"in": "/changes", "key": key});
            if let Some(c) = change {
                s["change"] = json!(c);
            }
            resolve(&doc, &s)
        };
        assert_eq!(sel(&a, Some("updated")).unwrap(), "/changes/2");
        assert_eq!(sel(&a, Some("state")).unwrap(), "/changes/1");
        assert!(sel(&a, None).unwrap_err().contains("[1, 2]"));
        assert!(sel(&a, Some("created")).unwrap_err().contains("no element"));
        let tl = json!({"trustline": {"account_id": "GA", "asset": "native"}});
        assert_eq!(sel(&tl, None).unwrap(), "/changes/4");
        let cs = json!({"config_setting": {"config_setting_id": "contract_max_size_bytes"}});
        assert_eq!(sel(&cs, Some("created")).unwrap(), "/changes/5");
        assert!(resolve(&doc, &json!({"in": "/nope", "key": a})).is_err());
    }

    #[test]
    fn keys_and_entries_in_plain_arrays() {
        let doc = json!({"keys": [{"ttl": {"key_hash": "aa"}}, {"ttl": {"key_hash": "bb"}}],
                         "entries": [account("GA", "1"), account("GB", "2")]});
        let k = json!({"ttl": {"key_hash": "bb"}});
        assert_eq!(
            resolve(&doc, &json!({"in": "/keys", "key": k})).unwrap(),
            "/keys/1"
        );
        let b = json!({"account": {"account_id": "GB"}});
        assert_eq!(
            resolve(&doc, &json!({"in": "/entries", "key": b})).unwrap(),
            "/entries/1"
        );
        // A change type selects only changes.
        assert!(resolve(
            &doc,
            &json!({"in": "/entries", "key": b, "change": "updated"})
        )
        .is_err());
    }
}
