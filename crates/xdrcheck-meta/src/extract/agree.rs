//! Agreement between the extractor's output and a hand-written `expect` block (`docs/manifest.md`
//! §6.11; matching rules of §6.3–§6.7). This is not the replay harness's matcher: it
//! checks only what the extractor derives — whole-ledger counts, transaction results, participants,
//! state changes, movements — with must-include, must-not-include and exactness within scope.
//! `values`, `addresses`, `native` and `reject` are other checks' business (`verify`'s pinpoints,
//! the oracle) and are ignored here.
//!
//! Rules applied:
//! - scope: an item belongs to its `tx_index`, else the focus transaction;
//! - P-1/P-2: each `must_include` base address is a participant; a stated `muxed_id` or
//!   `on_chain_form` must equal ours, and one we do not derive is a disagreement; roles are not
//!   compared (P-4 makes them advisory);
//! - P-5: no `must_not_include` address appears anywhere in the extractor's facts for the
//!   transaction. P-5's one exception (M-7: a reader's record matching a listed movement that
//!   states the forbidden address exactly as its endpoint) concerns readers; the extractor records
//!   no movement for a forged asset claim, so a hit in its own facts is always a disagreement;
//!   P-6: with `exact`, the participant set equals `must_include`;
//! - S-1…S-3: kind, transaction, base account and asset (either form: a classic asset and its
//!   Stellar Asset Contract address under the variant's network are the same asset); `signer`
//!   compared in full; every stated `detail` key must be one we derive, with the same value;
//!   `cause` is not matched; an `only_if: initial_authorization_separate` item is confirmed against
//!   the trustline the transaction created (same account and asset, its flags, `initial: true`);
//! - S-5: with `state_changes_exact`, every operation-level change of the focus transaction other
//!   than the ambient kinds (`balance_changed`, `sequence_bumped`, `ttl_extended`) must match a
//!   listed item;
//! - M-1…M-6: kind, asset (either form), amount, base `from` / `to`, exactly `count` (default 1)
//!   records; a stated `op_index` counts only that operation's records (identical movements of
//!   several operations are one item each, as `xdrcheck-corpus extract` writes them); a stated
//!   `muxed_id` of `from` / `to` must equal ours; `routing` absent and void are the same;
//!   `count: 0` is a must-not;
//! - with `movements_exact`, every non-fee movement of the focus transaction must match an item.
//!
//! A stated value the extractor cannot confirm is a disagreement. An item that carries
//! `unverified: "<reason>"` (a participant, state change or movement) is the author's explicit
//! exception: it is not required here (the replay harness scores it `not_applicable`), but it
//! still accounts for the facts it describes under the exactness flags.

use serde_json::{Map, Value};

use super::{contract_strkey, parse_asset, sac_contract_id, Extraction};

/// Replace every `${derived.<path>}` token in the strings of `v` with the variant's value
/// (textual, single pass, strings only). A token with no value is an error.
pub fn resolve_derived(v: &Value, derived: &Value) -> Result<Value, String> {
    Ok(match v {
        Value::String(s) => Value::String(resolve_str(s, derived)?),
        Value::Array(a) => Value::Array(
            a.iter()
                .map(|x| resolve_derived(x, derived))
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| Ok((k.clone(), resolve_derived(x, derived)?)))
                .collect::<Result<Map<_, _>, String>>()?,
        ),
        other => other.clone(),
    })
}

fn resolve_str(s: &str, derived: &Value) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find("${derived.") {
        out.push_str(&rest[..start]);
        let after = &rest[start + "${derived.".len()..];
        let end = after
            .find('}')
            .ok_or_else(|| format!("unterminated token in {s:?}"))?;
        let mut cur = derived;
        for part in after[..end].split('.') {
            cur = match cur {
                Value::Array(a) => part.parse::<usize>().ok().and_then(|i| a.get(i)),
                Value::Object(m) => m.get(part),
                _ => None,
            }
            .ok_or_else(|| format!("no derived value for ${{derived.{}}}", &after[..end]))?;
        }
        match cur {
            Value::String(x) => out.push_str(x),
            Value::Number(n) => out.push_str(&n.to_string()),
            other => return Err(format!("derived value is not a scalar: {other}")),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Whether two asset strings name the same asset under `network_id`.
pub fn same_asset(a: &str, b: &str, network_id: [u8; 32]) -> bool {
    if a == b {
        return true;
    }
    let sac = |classic: &str| {
        parse_asset(classic).map(|x| contract_strkey(sac_contract_id(&x, network_id)))
    };
    sac(a).as_deref() == Some(b) || sac(b).as_deref() == Some(a)
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}

fn addr(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|a| s(a, "address"))
}

fn tx_of(item: &Value, focus: usize) -> usize {
    item.get("tx_index")
        .and_then(Value::as_u64)
        .map_or(focus, |n| n as usize)
}

/// Compare an `expect` block (already resolved with [`resolve_derived`]) with the extractor's
/// output. Returns one line per disagreement; empty means agreement.
pub fn check(expect: &Value, ext: &Extraction, focus: usize, network_id: [u8; 32]) -> Vec<String> {
    let mut bad = Vec::new();
    let out = serde_json::to_value(ext).expect("extraction serialises");
    let txs = out["txs"].as_array().cloned().unwrap_or_default();
    let tx = |i: usize| txs.get(i).cloned().unwrap_or(Value::Null);

    // Whole-ledger counts and transaction results.
    if let Some(l) = expect.get("ledger").and_then(Value::as_object) {
        for (k, v) in l {
            if out["ledger"].get(k) != Some(v) {
                bad.push(format!(
                    "ledger.{k}: expected {v}, extractor {}",
                    out["ledger"][k]
                ));
            }
        }
    }
    for t in expect["transactions"].as_array().into_iter().flatten() {
        let i = t["index"].as_u64().unwrap_or(0) as usize;
        let Some(ours) = out["transactions"].get(i) else {
            bad.push(format!("transactions[{i}]: no such transaction"));
            continue;
        };
        for (k, v) in t.as_object().into_iter().flatten() {
            if ours.get(k) != Some(v) {
                bad.push(format!(
                    "transactions[{i}].{k}: expected {v}, extractor {}",
                    ours[k]
                ));
            }
        }
    }

    // Participants.
    let p = &expect["participants"];
    for item in p["must_include"].as_array().into_iter().flatten() {
        if item.get("unverified").is_some() {
            continue;
        }
        let t = tx(tx_of(item, focus));
        let want = s(item, "address").unwrap_or_default();
        let Some(ours) = t["participants"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|x| s(x, "address").as_deref() == Some(&want))
        else {
            bad.push(format!("participant {want}: missing"));
            continue;
        };
        for key in ["muxed_id", "on_chain_form"] {
            match (s(item, key), s(ours, key)) {
                (Some(m), Some(o)) if m != o => bad.push(format!(
                    "participant {want}: {key} {m} expected, extractor {o}"
                )),
                (Some(m), None) => bad.push(format!(
                    "participant {want}: {key} {m} is stated but the extractor derives none{UNVERIFIED}"
                )),
                _ => {}
            }
        }
        // Roles are advisory (manifest rule P-4): readers and authors label the same participant differently
        // (`destination` for a payment recipient versus only for a created account), so they never fail
        // agreement. Identity, muxed ID and must-not facts do.
        let _ = ours;
    }
    let t_focus = tx(focus);
    for item in p["must_not_include"].as_array().into_iter().flatten() {
        let a = s(item, "address").unwrap_or_default();
        if mentions(&t_focus, &a) {
            bad.push(format!(
                "must_not_include {a}: present in the extractor's facts"
            ));
        }
    }
    if p["exact"].as_bool() == Some(true) {
        let want: Vec<String> = p["must_include"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| s(x, "address"))
            .collect();
        for x in t_focus["participants"].as_array().into_iter().flatten() {
            let a = s(x, "address").unwrap_or_default();
            if !want.contains(&a) {
                bad.push(format!("participants.exact: extra participant {a}"));
            }
        }
    }

    // State changes.
    let expected_sc: Vec<&Value> = expect["state_changes"]
        .as_array()
        .into_iter()
        .flatten()
        .collect();
    let sc_matches = |item: &Value, ours: &Value| -> bool {
        ours["kind"] == item["kind"]
            && ours["tx_index"].as_u64() == Some(tx_of(item, focus) as u64)
            && addr(ours, "account") == addr(item, "account")
            && match (s(item, "asset"), s(ours, "asset")) {
                (Some(a), Some(b)) => same_asset(&a, &b, network_id),
                (Some(_), None) => false,
                (None, _) => true,
            }
    };
    let all_sc: Vec<Value> = txs
        .iter()
        .flat_map(|t| t["state_changes"].as_array().cloned().unwrap_or_default())
        .collect();
    for item in &expected_sc {
        if item.get("unverified").is_some() {
            continue;
        }
        if let Some(choice) = item.get("only_if") {
            if let Some(problem) = confirm_only_if(item, choice, &all_sc, focus, network_id) {
                bad.push(problem);
            }
            continue;
        }
        let cands: Vec<&Value> = all_sc.iter().filter(|o| sc_matches(item, o)).collect();
        let full = cands.iter().find(|o| {
            let signer_ok = match item.get("signer") {
                Some(sig) => o.get("signer") == Some(sig),
                None => true,
            };
            let detail_ok = item["detail"]
                .as_object()
                .into_iter()
                .flatten()
                .all(|(k, v)| o["detail"].get(k) == Some(v));
            signer_ok && detail_ok
        });
        if full.is_none() {
            let what = format!(
                "{} {} {}",
                item["kind"],
                addr(item, "account").unwrap_or_default(),
                s(item, "asset").unwrap_or_default()
            );
            match cands.first() {
                None => bad.push(format!("state change {what}: missing")),
                Some(o) => bad.push(format!(
                    "state change {what}: signer or detail differs or is not derived: expected {}, \
                     extractor {}{UNVERIFIED}",
                    item, o
                )),
            }
        }
    }
    if expect["state_changes_exact"].as_bool() == Some(true) {
        for o in t_focus["state_changes"].as_array().into_iter().flatten() {
            let kind = o["kind"].as_str().unwrap_or("");
            if matches!(kind, "balance_changed" | "sequence_bumped" | "ttl_extended")
                || o.get("op_index").is_none()
            {
                continue;
            }
            if !expected_sc.iter().any(|item| sc_matches(item, o)) {
                bad.push(format!("state_changes_exact: extra {o}"));
            }
        }
    }

    // Movements.
    let all_mv: Vec<Value> = txs
        .iter()
        .flat_map(|t| t["movements"].as_array().cloned().unwrap_or_default())
        .collect();
    let mv_matches = |item: &Value, o: &Value| -> bool {
        o["kind"] == item["kind"]
            && o["tx_index"].as_u64() == Some(tx_of(item, focus) as u64)
            && (item.get("op_index").is_none() || o["op_index"] == item["op_index"])
            && same_asset(
                item["asset"].as_str().unwrap_or(""),
                o["asset"].as_str().unwrap_or(""),
                network_id,
            )
            && o["amount"] == item["amount"]
            && addr(o, "from") == addr(item, "from")
            && addr(o, "to") == addr(item, "to")
            && muxed_ok(item, o, "from")
            && muxed_ok(item, o, "to")
            && routing_ok(item.get("routing"), o.get("routing"))
    };
    let expected_mv: Vec<&Value> = expect["movements"]
        .as_array()
        .into_iter()
        .flatten()
        .collect();
    for item in &expected_mv {
        if item.get("unverified").is_some() {
            continue;
        }
        let count = item["count"].as_u64().unwrap_or(1) as usize;
        let n = all_mv.iter().filter(|o| mv_matches(item, o)).count();
        if n != count {
            bad.push(format!(
                "movement {item}: expected {count} record(s), extractor {n}"
            ));
        }
    }
    if expect["movements_exact"].as_bool() == Some(true) {
        for o in t_focus["movements"].as_array().into_iter().flatten() {
            if matches!(o["kind"].as_str(), Some("fee" | "fee_refund")) {
                continue;
            }
            if !expected_mv.iter().any(|item| mv_matches(item, o)) {
                bad.push(format!("movements_exact: extra {o}"));
            }
        }
    }
    bad
}

/// Appended to a disagreement the author may resolve with an explicit marker.
const UNVERIFIED: &str =
    "; correct it, or mark the item `unverified` with the reason it cannot be derived from the bytes";

/// A stated `muxed_id` of a movement endpoint must equal the extractor's.
fn muxed_ok(item: &Value, o: &Value, k: &str) -> bool {
    match item.get(k).and_then(|a| s(a, "muxed_id")) {
        Some(m) => o.get(k).and_then(|a| s(a, "muxed_id")).as_deref() == Some(m.as_str()),
        None => true,
    }
}

/// Confirm an `only_if` item. `initial_authorization_separate` states the authorisation a
/// trustline was created with as its own `trustline_flags_changed`: it is confirmed by the
/// `trustline_created` of the same transaction, account and asset, whose flag keys it must repeat,
/// with `initial: true`. Returns the disagreement, if any.
fn confirm_only_if(
    item: &Value,
    choice: &Value,
    all_sc: &[Value],
    focus: usize,
    network_id: [u8; 32],
) -> Option<String> {
    let what = format!(
        "only_if {choice} item {} {}",
        item["kind"],
        addr(item, "account").unwrap_or_default()
    );
    if choice != "initial_authorization_separate" || item["kind"] != "trustline_flags_changed" {
        return Some(format!(
            "{what}: the extractor cannot confirm it{UNVERIFIED}"
        ));
    }
    let created = all_sc.iter().find(|o| {
        o["kind"] == "trustline_created"
            && o["tx_index"].as_u64() == Some(tx_of(item, focus) as u64)
            && addr(o, "account") == addr(item, "account")
            && match (s(item, "asset"), s(o, "asset")) {
                (Some(a), Some(b)) => same_asset(&a, &b, network_id),
                (Some(_), None) => false,
                (None, _) => true,
            }
    });
    let Some(created) = created else {
        return Some(format!(
            "{what}: no trustline_created to confirm it against"
        ));
    };
    for (k, v) in item["detail"].as_object().into_iter().flatten() {
        let ok = match k.as_str() {
            "initial" => v == true,
            "flags" | "authorized" | "authorized_to_maintain_liabilities" | "clawback_enabled" => {
                created["detail"].get(k) == Some(v)
            }
            _ => false,
        };
        if !ok {
            return Some(format!(
                "{what}: detail {k} = {v} does not match the created trustline {}{UNVERIFIED}",
                created["detail"]
            ));
        }
    }
    None
}

fn routing_ok(want: Option<&Value>, got: Option<&Value>) -> bool {
    let none =
        |r: Option<&Value>| r.is_none_or(|r| matches!(r["type"].as_str(), Some("absent" | "void")));
    match want {
        None => true,
        Some(w) if none(Some(w)) => none(got),
        Some(w) => got == Some(w),
    }
}

/// Whether a transaction's facts mention a base address anywhere (participants, state-change
/// accounts, movement endpoints).
fn mentions(tx: &Value, a: &str) -> bool {
    let hit = |list: &Value, keys: &[&str]| {
        list.as_array().into_iter().flatten().any(|x| {
            keys.iter().any(|k| {
                if *k == "address" {
                    s(x, "address").as_deref() == Some(a)
                } else {
                    addr(x, k).as_deref() == Some(a)
                }
            })
        })
    };
    hit(&tx["participants"], &["address"])
        || hit(&tx["state_changes"], &["account"])
        || hit(&tx["movements"], &["from", "to"])
}
