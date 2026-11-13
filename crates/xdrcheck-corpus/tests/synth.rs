//! `xdrcheck-corpus synth`: the recipes under `corpus/recipes/` rebuild the executed probe's
//! hand-encoded vectors byte for byte, positive entries pass the oracle, negative entries are
//! rejected once their reason is authored, and every construction kind works.

mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use common::{copy_corpus, read_json, repo, run};
use serde_json::{json, Value};

/// Every recipe file under `corpus/recipes/` of `corpus`.
fn recipes(corpus: &Path) -> Vec<PathBuf> {
    common::snapshot(&corpus.join("recipes"))
        .into_iter()
        .map(|(p, _)| p)
        .collect()
}

/// The probe's vectors by ID, as `evidence/sdk-matrix/vectors/gen_vectors.py` wrote them.
fn probe_vectors() -> HashMap<String, String> {
    let v = read_json(&repo().join("evidence/sdk-matrix/vectors/vectors.json"));
    v.as_array()
        .unwrap()
        .iter()
        .filter_map(|x| {
            Some((
                x["id"].as_str()?.to_string(),
                x["hex"].as_str()?.to_string(),
            ))
        })
        .collect()
}

fn blob_of(corpus: &Path, id: &str) -> Vec<u8> {
    let m = read_json(&corpus.join(format!("manifest/{id}.json")));
    let v = &m["variants"][0];
    std::fs::read(corpus.join(v["blob"]["path"].as_str().unwrap())).unwrap()
}

/// `n` nested SCV_VEC around SCV_VOID, hand-encoded from the XDR definitions
/// (SCV_VEC = 16, optional present = 1, length 1; SCV_VOID = 1).
fn vec_nest(n: usize) -> Vec<u8> {
    let mut out = [0u8, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0, 1].repeat(n);
    out.extend_from_slice(&[0, 0, 0, 1]);
    out
}

fn synth_all(name: &str) -> PathBuf {
    let corpus = copy_corpus("synth", name);
    let paths = recipes(&corpus);
    let mut args = vec!["synth".to_string()];
    args.extend(paths.iter().map(|p| p.to_string_lossy().into_owned()));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = run(&corpus, &args);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    corpus
}

#[test]
fn recipes_rebuild_the_probe_vectors_byte_for_byte() {
    let corpus = synth_all("probe");
    let probe = probe_vectors();
    let mut compared = Vec::new();
    for path in recipes(&corpus) {
        let recipe = read_json(&path);
        if recipe["kind"] != "xdr" {
            continue; // api and strkey recipes build no bytes
        }
        let id = recipe["entry"].as_str().unwrap();
        let bytes = blob_of(&corpus, id);
        let origin = recipe["origin"].as_str().unwrap_or("");
        if let Some(vid) = origin.strip_prefix("evidence/sdk-matrix/vectors/vectors.json ") {
            let want = probe
                .get(vid)
                .unwrap_or_else(|| panic!("no probe vector {vid}"));
            assert_eq!(hex::encode(&bytes), *want, "{id} vs probe vector {vid}");
            compared.push(vid.to_string());
        }
        if let Some(depth) = recipe["construction"]["nest"]["depth"].as_u64() {
            assert_eq!(bytes, vec_nest(depth as usize), "{id}");
        }
    }
    // The probe vectors behind the corpus's strictness negatives and nesting entries are all covered.
    for vid in ["6f", "6g", "6h", "6h2", "6h3", "6h4", "8n99", "8n100"] {
        assert!(
            compared.iter().any(|c| c == vid),
            "probe vector {vid} not reproduced"
        );
    }
    // Re-running synth over the same recipes changes nothing.
    let before = common::snapshot(&corpus);
    let mut args = vec!["synth".to_string()];
    args.extend(
        recipes(&corpus)
            .iter()
            .map(|p| p.to_string_lossy().into_owned()),
    );
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    assert_eq!(run(&corpus, &args).code, 0);
    assert_eq!(common::snapshot(&corpus), before);
}

#[test]
fn positive_entries_pass_the_oracle_and_negatives_have_no_sidecar() {
    let corpus = copy_corpus("synth", "oracle");
    // A recipe for a planned entry with no manifest file yet: synth writes a skeleton.
    write_recipe(
        &corpus,
        "skeleton",
        json!({
            "entry": "limits/scvec-nesting-66", "kind": "xdr", "xdr_type": "ScVal",
            "construction": {"nest": {"leaf": "void", "wrapper": "scv_map", "depth": 374}},
            "reason": "built by the test: a planned entry with no manifest file"
        }),
    );
    let paths = recipes(&corpus);
    let mut args = vec!["synth".to_string()];
    args.extend(paths.iter().map(|p| p.to_string_lossy().into_owned()));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = run(&corpus, &args);
    assert_eq!(
        r.code, 0,
        "{}
{}",
        r.stdout, r.stderr
    );
    // The skeleton fails `schema` on purpose (TODO title and why); the byte checks pass.
    let r = run(
        &corpus,
        &[
            "verify",
            "--checks",
            "hashes,roundtrip,sidecar,pinpoints,ids",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    let positive_xdr = common::snapshot(&corpus.join("manifest"))
        .into_iter()
        .filter(|(p, _)| {
            let m = read_json(p);
            m["kind"] == "xdr" && m["negative"] != true
        })
        .count();
    assert!(
        r.stdout.contains(&format!("xdr {positive_xdr},")),
        "{}",
        r.stdout
    );
    let r = run(&corpus, &["verify", "--checks", "schema"]);
    assert_eq!(r.code, 1);
    assert!(
        r.stdout.contains("\"TODO\" is shorter than 8 characters"),
        "{}",
        r.stdout
    );

    let m = read_json(&corpus.join("manifest/xdr-strict/length-prefix-exceeds-input.6h.json"));
    assert_eq!(m["negative"], true);
    assert!(m["variants"][0]["decoded"].is_null());
    assert_eq!(
        m["variants"][0]["source"]["recipe"],
        "recipes/xdr-strict/length-prefix-exceeds-input.6h.json"
    );
    let m = read_json(&corpus.join("manifest/limits/scvec-nesting-66.json"));
    let sidecar = corpus.join(m["variants"][0]["decoded"].as_str().unwrap());
    // A 374-level sidecar is stored compact and compressed, so it stays small.
    assert!(sidecar.to_string_lossy().ends_with(".json.zst"));
    assert!(std::fs::metadata(sidecar).unwrap().len() < 4_000);
}

/// Fill in what an author writes, keeping everything synth wrote.
fn author(corpus: &Path, id: &str, reason: Option<&str>) {
    let path = corpus.join(format!("manifest/{id}.json"));
    let mut m = read_json(&path);
    m["title"] = json!(format!("Authored title for {id}"));
    m["why"] = json!("An authored explanation of why this trips readers.");
    m["caps_note"] = json!("A pure encoding rule, not tied to a CAP.");
    if let Some(r) = reason {
        m["expect"] = json!({"reject": {"reason": r}});
        let flag = json!(r.replace('_', "-"));
        let mut flags = m["flags"].as_array().cloned().unwrap_or_default();
        if !flags.contains(&flag) {
            flags.push(flag);
        }
        m["flags"] = json!(flags);
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
}

#[test]
fn authored_negatives_are_rejected_for_their_reason() {
    let corpus = copy_corpus("synth", "authored");
    // The corpus's own strictness negatives, and one test-built negative (under a planned ID with no
    // manifest file) for each other reason the oracle names.
    let built = [
        (
            "xdr-strict/optional-flag-2",
            "ScVal",
            "000000100000000300000000",
            "optional_flag_range",
        ),
        (
            "xdr-strict/nonzero-padding.string",
            "ScVal",
            "0000000e0000000162000007",
            "nonzero_padding",
        ),
        (
            "xdr-strict/nonzero-padding.opaque",
            "ScVal",
            "0000000d0000000101000100",
            "nonzero_padding",
        ),
        (
            "xdr-strict/trailing-bytes.scval",
            "ScVal",
            "000000030000000700000000",
            "trailing_bytes",
        ),
        (
            "xdr-strict/enum-value-undeclared",
            "ScVal",
            "000000020000000100000064",
            "enum_undeclared",
        ),
        (
            "xdr-strict/vector-one-over-declared-max.memo-text-29",
            "Memo",
            "000000010000001d6262626262626262626262626262626262626262626262626262626262000000",
            "length_exceeds_max",
        ),
    ];
    let mut paths = recipes(&corpus);
    for (i, (id, ty, hex, _)) in built.iter().enumerate() {
        paths.push(PathBuf::from(write_recipe(
            &corpus,
            &format!("negative-{i}"),
            json!({"entry": id, "kind": "xdr", "xdr_type": ty, "construction": {"hex": hex},
                   "reason": "built by the test: one negative per reject reason"}),
        )));
    }
    paths.push(PathBuf::from(write_recipe(
        &corpus,
        "depth",
        json!({"entry": "xdr-strict/scval-nesting-beyond-core-limit", "kind": "xdr", "xdr_type": "ScVal",
               "construction": {"nest": {"leaf": "void", "wrapper": "scv_vec", "depth": 500}},
               "reason": "built by the test: one level past stellar-core's decoder limit"}),
    )));
    let mut args = vec!["synth".to_string()];
    args.extend(paths.iter().map(|p| p.to_string_lossy().into_owned()));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = run(&corpus, &args);
    assert_eq!(
        r.code, 0,
        "{}
{}",
        r.stdout, r.stderr
    );
    let mut cases = vec![
        (
            "xdr-strict/union-discriminant-undeclared.no-arm",
            "union_arm_undeclared",
        ),
        (
            "xdr-strict/union-discriminant-undeclared.scaddress-type-6",
            "union_arm_undeclared",
        ),
        (
            "xdr-strict/length-prefix-exceeds-input.6h",
            "length_exceeds_input",
        ),
        (
            "xdr-strict/length-prefix-exceeds-input.6h2",
            "length_exceeds_input",
        ),
        (
            "xdr-strict/length-prefix-exceeds-input.6h3",
            "length_exceeds_input",
        ),
        (
            "xdr-strict/length-prefix-exceeds-input.6h4",
            "length_exceeds_input",
        ),
        ("xdr-strict/bool-value-2", "bool_range"),
    ];
    cases.extend(built.iter().map(|(id, _, _, reason)| (*id, *reason)));
    for (id, reason) in cases {
        author(&corpus, id, Some(reason));
    }
    let r = run(
        &corpus,
        &[
            "verify",
            "--checks",
            "schema,ids,reject",
            "--entries",
            "xdr-strict/*",
        ],
    );
    // Everything passes except the depth entry, which the oracle rejects only at an entry depth
    // limit; its failure names the field.
    let fails: Vec<&str> = r.stdout.lines().filter(|l| l.starts_with("FAIL")).collect();
    assert!(
        fails
            .iter()
            .all(|l| l.contains("scval-nesting-beyond-core-limit")),
        "{}",
        r.stdout
    );
    author(
        &corpus,
        "xdr-strict/scval-nesting-beyond-core-limit",
        Some("depth"),
    );
    let r = run(
        &corpus,
        &[
            "verify",
            "--checks",
            "reject",
            "--entries",
            "xdr-strict/scval-*",
        ],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stdout.contains("expect.reject.limits.depth"),
        "{}",
        r.stdout
    );
    // At stellar-core's decoder boundary (499 nested vectors decode, 500 do not; four
    // stellar-xdr units per level, four more for the value itself: 2,000 units) the oracle
    // rejects it too.
    let path = corpus.join("manifest/xdr-strict/scval-nesting-beyond-core-limit.json");
    let mut m = read_json(&path);
    m["expect"]["reject"]["limits"] = json!({"depth": 2000});
    std::fs::write(&path, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    let r = run(
        &corpus,
        &[
            "verify",
            "--checks",
            "schema,reject",
            "--entries",
            "xdr-strict/scval-*",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stdout);

    // Re-running synth keeps the authored fields.
    let recipe = corpus.join("recipes/test/negative-0.json");
    let r = run(&corpus, &["synth", recipe.to_str().unwrap()]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    let m = read_json(&corpus.join("manifest/xdr-strict/optional-flag-2.json"));
    assert_eq!(m["expect"]["reject"]["reason"], "optional_flag_range");
    assert!(m["title"].as_str().unwrap().starts_with("Authored"));
}

fn write_recipe(corpus: &Path, name: &str, recipe: Value) -> String {
    let p = corpus.join("recipes/test").join(format!("{name}.json"));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, serde_json::to_vec_pretty(&recipe).unwrap()).unwrap();
    p.to_string_lossy().into_owned()
}

#[test]
fn json_edit_nest_api_and_strkey_constructions() {
    let corpus = copy_corpus("synth", "constructions");
    let reason = "built by the test to exercise one construction";
    // json
    let r1 = write_recipe(
        &corpus,
        "json",
        json!({
            "entry": "limits/scvec-nesting-66", "kind": "xdr", "xdr_type": "ScVal",
            "construction": {"json": {"vec": [{"u32": 7}]}}, "reason": reason
        }),
    );
    // edit of the entry just built: append four zero bytes (a trailing-bytes negative)
    let r2 = write_recipe(
        &corpus,
        "edit",
        json!({
            "entry": "xdr-strict/trailing-bytes.scval", "kind": "xdr", "xdr_type": "ScVal",
            "construction": {"edit": {"base_entry": "limits/scvec-nesting-66",
                                      "ops": [{"at": 16, "op": "replace", "hex": "00000009"},
                                              {"at": 20, "op": "append", "hex": "00000000"}]}},
            "reason": reason
        }),
    );
    // nest with map wrapper: the shape stellar-core's decoder admits to 374 levels
    let r3 = write_recipe(
        &corpus,
        "map",
        json!({
            "entry": "limits/scvec-nesting-374", "kind": "xdr", "xdr_type": "ScVal",
            "construction": {"nest": {"leaf": "void", "wrapper": "scv_map", "depth": 374}},
            "reason": reason
        }),
    );
    let r4 = write_recipe(
        &corpus,
        "api",
        json!({
            "entry": "cap-0038/api-liquidity-pool-issuer-ordering.reversed-order", "kind": "api",
            "construction": {"api": {"op": "liquidity_pool.id", "input": {"a": "x", "b": "y"}, "expect_reject": true}},
            "reason": reason
        }),
    );
    let r5 = write_recipe(
        &corpus,
        "strkey",
        json!({
            "entry": "strkey/truncated-muxed-address-56-chars", "kind": "strkey",
            "construction": {"strkey": {"text": "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAPG", "type": "muxed_account"}},
            "reason": reason
        }),
    );
    let r = run(&corpus, &["synth", &r1, &r2, &r3, &r4, &r5]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);

    // json: ScVal Vec[U32 7].
    assert_eq!(
        hex::encode(blob_of(&corpus, "limits/scvec-nesting-66")),
        "0000001000000001000000010000000300000007"
    );
    // edit: 7 -> 9, then four trailing bytes; the base entry is recorded.
    assert_eq!(
        hex::encode(blob_of(&corpus, "xdr-strict/trailing-bytes.scval")),
        "000000100000000100000001000000030000000900000000"
    );
    let m = read_json(&corpus.join("manifest/xdr-strict/trailing-bytes.scval.json"));
    assert_eq!(
        m["variants"][0]["source"]["base_entry"],
        "limits/scvec-nesting-66"
    );
    assert!(r.stdout.contains("the oracle rejects"), "{}", r.stdout);
    // nest scv_map: byte-equal to `map_nest` of evidence/core-print-xdr/cases.py
    // (SCV_MAP = 17, present, one entry, key SCV_VOID; innermost SCV_VOID).
    let mut want = [0u8, 0, 0, 17, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1].repeat(374);
    want.extend_from_slice(&[0, 0, 0, 1]);
    assert_eq!(blob_of(&corpus, "limits/scvec-nesting-374"), want);
    // api and strkey: the block is written, there are no bytes.
    let m = read_json(
        &corpus.join("manifest/cap-0038/api-liquidity-pool-issuer-ordering.reversed-order.json"),
    );
    assert_eq!(m["kind"], "api");
    assert_eq!(m["api"]["op"], "liquidity_pool.id");
    assert!(m["variants"].is_null());
    let m = read_json(&corpus.join("manifest/strkey/truncated-muxed-address-56-chars.json"));
    assert_eq!(m["negative"], true);
    assert_eq!(m["strkey"]["type"], "muxed_account");
    let r = run(
        &corpus,
        &[
            "verify",
            "--checks",
            "hashes,roundtrip,sidecar",
            "--entries",
            "limits/*",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
}

#[test]
fn bad_recipes_fail() {
    let corpus = copy_corpus("synth", "bad");
    let not_planned = write_recipe(
        &corpus,
        "unplanned",
        json!({
            "entry": "xdr-strict/not-in-the-plan", "kind": "xdr", "xdr_type": "ScVal",
            "construction": {"hex": "00000001"}, "reason": "a recipe whose ID is not planned"
        }),
    );
    let invalid = write_recipe(
        &corpus,
        "invalid",
        json!({
            "entry": "xdr-strict/bool-value-2", "kind": "xdr",
            "construction": {"hex": "00000001"}, "reason": "no xdr_type"
        }),
    );
    let positive_bad = write_recipe(
        &corpus,
        "positive-bad",
        json!({
            "entry": "limits/scvec-nesting-67", "kind": "xdr", "xdr_type": "ScVal",
            "construction": {"hex": "0000000100000000"}, "reason": "a positive entry whose bytes do not decode"
        }),
    );
    for (recipe, want) in [
        (&not_planned, "not in plan.json"),
        (&invalid, "not a valid recipe"),
        (&positive_bad, "a positive entry must pass the oracle"),
    ] {
        let r = run(&corpus, &["synth", recipe]);
        assert_eq!(r.code, 1, "{}", r.stdout);
        assert!(r.stdout.contains(want), "{want}: {}", r.stdout);
    }
}
