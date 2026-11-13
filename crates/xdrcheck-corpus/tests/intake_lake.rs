//! History capture: the SEP-54 object → blob chain and `capture.json` provenance.
//!
//! Offline tests re-derive every vendored capture from its object and run a whole capture into a
//! scratch corpus from a vendored object. The two tests marked `#[ignore]` need the network (the
//! public lake): run them with `cargo test -p xdrcheck-corpus --test intake_lake -- --ignored`.

#[allow(dead_code)]
#[path = "../src/cmd/intake/mod.rs"]
mod intake;

use std::path::{Path, PathBuf};
use std::process::Command;

use intake::lake::{self, CaptureRecord, Fetched, Head, Network};
use intake::util::{read_json, CheckFailed};
use serde_json::Value;
use xdrcheck_xdr::Gate;

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    if d.exists() {
        std::fs::remove_dir_all(&d).unwrap();
    }
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dest);
        } else {
            std::fs::copy(e.path(), dest).unwrap();
        }
    }
}

/// Every vendored capture directory: (network, sequence, record path).
fn captures() -> Vec<(Network, u32, PathBuf)> {
    let mut out = Vec::new();
    for net in [Network::Pubnet, Network::Testnet] {
        for d in std::fs::read_dir(corpus().join("objects").join(net.name())).unwrap() {
            let d = d.unwrap();
            if let Ok(seq) = d.file_name().to_string_lossy().parse::<u32>() {
                out.push((net, seq, d.path().join("capture.json")));
            }
        }
    }
    out.sort_by_key(|c| (c.0.name(), c.1));
    out
}

fn head_of(r: &CaptureRecord) -> Head {
    Head {
        metadata: r.object_metadata.clone(),
        last_modified: r.object_last_modified.clone(),
        etag: r.object_etag.clone(),
        content_length: Some(r.object_bytes),
    }
}

fn record(path: &Path) -> CaptureRecord {
    serde_json::from_value(read_json(path).unwrap()).unwrap()
}

/// History variants of the manifest: (entry id, variant).
fn history_variants() -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for g in std::fs::read_dir(corpus().join("manifest")).unwrap() {
        let g = g.unwrap();
        for f in std::fs::read_dir(g.path()).unwrap() {
            let f = f.unwrap();
            let e = read_json(&f.path()).unwrap();
            for v in e["variants"].as_array().into_iter().flatten() {
                // A value cut out of a captured ledger (`xdrcheck-corpus slice`) keeps its parent's
                // `history` source and names the cut in `slice_of`; its blob is the slice, not the
                // ledger, so it is checked by `history_slices_cut_from_the_captured_ledger`.
                if v["source"]["kind"] == "history" && v["slice_of"].is_null() {
                    out.push((e["id"].as_str().unwrap().to_string(), v.clone()));
                }
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn key_formula_matches_listed_lake_keys() {
    assert_eq!(lake::object_key(2), "FFFFFFFF--0-63999/FFFFFFFD--2.xdr.zst");
    assert_eq!(
        lake::object_key(64000),
        "FFFF05FF--64000-127999/FFFF05FF--64000.xdr.zst"
    );
    for (net, seq, path) in captures() {
        let r = record(&path);
        assert_eq!(r.key, lake::object_key(seq), "{} {seq}", net.name());
        let loc = lake::locate(&intake::pins::Pins::load(&corpus()).unwrap(), net, seq).unwrap();
        assert_eq!((loc.store, loc.key, loc.url), (r.store, r.key, r.url));
    }
}

/// Every vendored object reproduces its normalised record: hashes, sizes, offset, ledger facts,
/// `written_by` and `regenerated` — all re-derived offline from the bytes and the recorded metadata.
#[test]
fn every_vendored_object_reproduces_its_capture_record() {
    let caps = captures();
    // One per vendored object directory (the corpus grows; never fewer than the first capture batch).
    assert!(caps.len() >= 38, "vendored captures: {}", caps.len());
    let gate = Gate::default();
    for (net, seq, path) in caps {
        let r = record(&path);
        assert_eq!(r.schema, lake::CAPTURE_SCHEMA);
        let object = std::fs::read(path.parent().unwrap().join(&r.object_file)).unwrap();
        let facts = lake::analyse(&object, net, seq, &gate).unwrap();
        let loc = lake::Location {
            store: r.store.clone(),
            key: r.key.clone(),
            url: r.url.clone(),
        };
        let prior = lake::load_prior(&path).unwrap();
        let again = lake::build_record(
            net,
            &loc,
            &facts,
            &head_of(&r),
            Some(&prior),
            "-",
            &r.verified_at,
        )
        .unwrap();
        assert_eq!(again, r, "{} {seq}", net.name());
        assert_eq!(facts.blob_offset, 12);
        assert_eq!(facts.blob.len() as u64 + 12, facts.decompressed_bytes);
    }
}

/// The `history` variants in the manifest chain object → decompressed → blob with the vendored
/// object, and the blob file has the recorded hash.
#[test]
fn history_variants_chain_object_to_blob() {
    let vs = history_variants();
    assert!(vs.len() >= 2);
    for (id, v) in vs {
        let s = &v["source"];
        let net = Network::parse(v["network"].as_str().unwrap()).unwrap();
        let seq = v["ledger_seq"].as_u64().unwrap() as u32;
        let dir = lake::capture_dir(&corpus(), net, seq);
        let object =
            std::fs::read(dir.join(lake::object_key(seq).rsplit('/').next().unwrap())).unwrap();
        let facts = lake::analyse(&object, net, seq, &Gate::default()).unwrap();
        assert_eq!(facts.object_sha256, s["object_sha256"], "{id}");
        assert_eq!(facts.decompressed_sha256, s["decompressed_sha256"], "{id}");
        assert_eq!(
            facts.blob_offset,
            s["blob_offset"].as_u64().unwrap(),
            "{id}"
        );
        assert_eq!(facts.blob_sha256, v["blob"]["sha256"], "{id}");
        let blob = std::fs::read(corpus().join(v["blob"]["path"].as_str().unwrap())).unwrap();
        assert_eq!(blob, facts.blob, "{id}");
        if let Some(h) = v["focus"]["tx_hash"].as_str() {
            assert_eq!(
                facts.ledger.tx_index(h),
                Some(v["focus"]["tx_index"].as_u64().unwrap() as usize),
                "{id}"
            );
        }
    }
}

/// Every `history` variant with `slice_of` is a contiguous range of the ledger its source names: the
/// vendored object chains to that ledger (as for a capture), the range at `byte_offset` is the slice's blob
/// byte for byte, and the parent entry's variant for the same ledger holds that ledger as its blob.
#[test]
fn history_slices_cut_from_the_captured_ledger() {
    let mut n = 0;
    for g in std::fs::read_dir(corpus().join("manifest")).unwrap() {
        for f in std::fs::read_dir(g.unwrap().path()).unwrap() {
            let e = read_json(&f.unwrap().path()).unwrap();
            let id = e["id"].as_str().unwrap().to_string();
            for v in e["variants"].as_array().into_iter().flatten() {
                if v["source"]["kind"] != "history" || v["slice_of"].is_null() {
                    continue;
                }
                n += 1;
                let s = &v["source"];
                let net = Network::parse(v["network"].as_str().unwrap()).unwrap();
                let seq = v["ledger_seq"].as_u64().unwrap() as u32;
                let dir = lake::capture_dir(&corpus(), net, seq);
                let object =
                    std::fs::read(dir.join(lake::object_key(seq).rsplit('/').next().unwrap()))
                        .unwrap();
                let facts = lake::analyse(&object, net, seq, &Gate::default()).unwrap();
                assert_eq!(facts.object_sha256, s["object_sha256"], "{id}");
                assert_eq!(facts.decompressed_sha256, s["decompressed_sha256"], "{id}");
                let blob =
                    std::fs::read(corpus().join(v["blob"]["path"].as_str().unwrap())).unwrap();
                let at = v["slice_of"]["byte_offset"].as_u64().unwrap() as usize;
                assert_eq!(
                    &facts.blob[at..at + blob.len()],
                    &blob[..],
                    "{id}: the slice at {at}"
                );
                let parent = read_json(&corpus().join(format!(
                    "manifest/{}.json",
                    v["slice_of"]["entry"].as_str().unwrap()
                )))
                .unwrap();
                assert!(
                    parent["variants"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|p| p["source"]["kind"] == "history"
                            && p["ledger_seq"] == v["ledger_seq"]
                            && p["network"] == v["network"]
                            && p["blob"]["sha256"] == facts.blob_sha256),
                    "{id}: the parent holds the captured ledger"
                );
            }
        }
    }
    assert!(n >= 2, "the corpus has history slices");
}

/// A scratch corpus holding the two history entries, their vendored objects and the registry.
fn scratch_corpus(name: &str) -> PathBuf {
    let root = scratch(name).join("corpus");
    for (id, v) in history_variants() {
        let rel = format!("manifest/{id}.json");
        std::fs::create_dir_all(root.join(&rel).parent().unwrap()).unwrap();
        std::fs::copy(corpus().join(&rel), root.join(&rel)).unwrap();
        let dir = format!(
            "objects/{}/{}",
            v["network"].as_str().unwrap(),
            v["ledger_seq"]
        );
        copy_dir(&corpus().join(&dir), &root.join(&dir));
    }
    copy_dir(
        &corpus().join("objects/pubnet/3"),
        &root.join("objects/pubnet/3"),
    );
    std::fs::copy(corpus().join("plan.json"), root.join("plan.json")).unwrap();
    root
}

/// The variant a re-capture writes must reproduce the authored variant's bytes and provenance.
fn assert_same_history_variant(id: &str, new: &Value, old: &Value) {
    assert_eq!(new["blob"], old["blob"], "{id}: blob");
    for k in [
        "store",
        "key",
        "object_sha256",
        "object_bytes",
        "decompressed_sha256",
        "decompressed_bytes",
        "batch_index",
        "blob_offset",
        "written_by",
        "object_metadata",
        "regenerated",
        "captured_at",
    ] {
        assert_eq!(new["source"][k], old["source"][k], "{id}: source.{k}");
    }
    // `perishable` is optional in an authored entry; absent means false.
    let perishable = |v: &Value| v["source"]["perishable"].as_bool().unwrap_or(false);
    assert_eq!(perishable(new), perishable(old), "{id}: source.perishable");
    for k in [
        "focus",
        "derived",
        "meta",
        "decoded",
        "decoded_sha256",
        "notes",
        "protocol",
        "ledger_seq",
    ] {
        assert_eq!(new[k], old[k], "{id}: {k}");
    }
}

fn variant_of(corpus: &Path, id: &str, v: &Value) -> Value {
    let e = read_json(&corpus.join(format!("manifest/{id}.json"))).unwrap();
    e["variants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["network"] == v["network"] && x["protocol"] == v["protocol"])
        .cloned()
        .unwrap()
}

/// A whole capture with `--entry` and `--tx` into a scratch corpus, from the vendored objects and
/// recorded metadata instead of the network: the updated variants equal the authored ones.
#[test]
fn capture_into_entry_reproduces_the_authored_variants() {
    let root = scratch_corpus("capture-offline");
    let pins = intake::pins::Pins::load(&root).unwrap();
    for (id, old) in history_variants() {
        let net = Network::parse(old["network"].as_str().unwrap()).unwrap();
        let seq = old["ledger_seq"].as_u64().unwrap() as u32;
        let dir = lake::capture_dir(&root, net, seq);
        let r = record(&dir.join("capture.json"));
        let fetched = Fetched {
            object: std::fs::read(dir.join(&r.object_file)).unwrap(),
            head: head_of(&r),
            fetched_with: "test".into(),
        };
        let tx = old["focus"]["tx_hash"].as_str();
        let out = lake::capture_fetched(
            &root,
            &pins,
            &Gate::default(),
            net,
            seq,
            &fetched,
            tx,
            Some(&id),
        )
        .unwrap();
        assert!(out.object_unchanged);
        if old["header_protocol"].is_u64() {
            // A protocol-upgrade ledger: capture records the header protocol and asks the author to
            // set `protocol` (the applied one) by hand, so it adds a variant under the header
            // protocol; its bytes and provenance must still be the authored ones.
            assert_eq!(out.upsert, Some(intake::manifest::Upsert::Added), "{id}");
            assert!(!out.warnings.is_empty(), "{id}");
            let mut header = old.clone();
            header["protocol"] = old["header_protocol"].clone();
            let new = variant_of(&root, &id, &header);
            assert_eq!(new["blob"], old["blob"], "{id}");
            assert_eq!(
                new["source"]["object_sha256"], old["source"]["object_sha256"],
                "{id}"
            );
            continue;
        }
        assert_eq!(out.upsert, Some(intake::manifest::Upsert::Updated), "{id}");
        let new = variant_of(&root, &id, &old);
        assert_same_history_variant(&id, &new, &old);
        assert_eq!(
            new["source"]["object_path"],
            format!("objects/{}/{seq}/{}", net.name(), r.object_file)
        );
        assert!(root.join(new["blob"]["path"].as_str().unwrap()).is_file());
    }
}

/// A vendored object that no longer matches what the lake serves is a failed check, and nothing
/// is overwritten. A focus transaction that is not in the ledger is a failed check too.
#[test]
fn changed_object_and_missing_transaction_fail_as_checks() {
    let root = scratch_corpus("capture-changed");
    let pins = intake::pins::Pins::load(&root).unwrap();
    let dir = lake::capture_dir(&root, Network::Pubnet, 3);
    let r = record(&dir.join("capture.json"));
    let fetched = Fetched {
        object: std::fs::read(dir.join(&r.object_file)).unwrap(),
        head: head_of(&r),
        fetched_with: "test".into(),
    };
    let missing = "00".repeat(32);
    let e = lake::capture_fetched(
        &root,
        &pins,
        &Gate::default(),
        Network::Pubnet,
        3,
        &fetched,
        Some(&missing),
        None,
    )
    .unwrap_err();
    assert!(e.downcast_ref::<CheckFailed>().is_some(), "{e:#}");

    let vendored = dir.join(&r.object_file);
    let mut bytes = std::fs::read(&vendored).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&vendored, &bytes).unwrap();
    let before = std::fs::read(dir.join("capture.json")).unwrap();
    let e = lake::capture_fetched(
        &root,
        &pins,
        &Gate::default(),
        Network::Pubnet,
        3,
        &fetched,
        None,
        None,
    )
    .unwrap_err();
    assert!(e.downcast_ref::<CheckFailed>().is_some(), "{e:#}");
    assert_eq!(
        std::fs::read(&vendored).unwrap(),
        bytes,
        "vendored object kept"
    );
    assert_eq!(
        std::fs::read(dir.join("capture.json")).unwrap(),
        before,
        "record kept"
    );
}

/// `--entry <row>.<member>` for a member whose file does not exist yet starts the member's entry
/// from its family row; a member the row does not list is refused and nothing is written.
#[test]
fn capture_into_new_family_member_starts_it_from_the_family_row() {
    let root = scratch("capture-member").join("corpus");
    copy_dir(
        &corpus().join("objects/pubnet/3"),
        &root.join("objects/pubnet/3"),
    );
    let plan = serde_json::json!([{
        "id": "protocol-01/family-row",
        "kind": "ledger",
        "caps": [],
        "protocol_min": 1,
        "shape": "a family row with one listed member",
        "members": ["pubnet-3"],
    }]);
    std::fs::write(root.join("plan.json"), plan.to_string()).unwrap();
    let pins = intake::pins::Pins::load(&root).unwrap();
    let dir = lake::capture_dir(&root, Network::Pubnet, 3);
    let r = record(&dir.join("capture.json"));
    let fetched = Fetched {
        object: std::fs::read(dir.join(&r.object_file)).unwrap(),
        head: head_of(&r),
        fetched_with: "test".into(),
    };
    let capture = |id: &str| {
        lake::capture_fetched(
            &root,
            &pins,
            &Gate::default(),
            Network::Pubnet,
            3,
            &fetched,
            None,
            Some(id),
        )
    };

    let id = "protocol-01/family-row.pubnet-3";
    let out = capture(id).unwrap();
    assert_eq!(out.upsert, Some(intake::manifest::Upsert::CreatedEntry));
    let e = read_json(&root.join(format!("manifest/{id}.json"))).unwrap();
    assert_eq!(e["id"], id);
    assert_eq!(e["title"], "a family row with one listed member");
    assert_eq!(e["variants"][0]["ledger_seq"], 3);
    assert_eq!(e["variants"][0]["source"]["kind"], "history");

    let unlisted = "protocol-01/family-row.pubnet-4";
    let err = capture(unlisted).unwrap_err();
    assert!(format!("{err:#}").contains("not a member"), "{err:#}");
    assert!(!root.join(format!("manifest/{unlisted}.json")).exists());
    assert!(capture("protocol-01/no-such-row.pubnet-3").is_err());
}

fn xdrcheck_corpus(root: &Path, args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_xdrcheck-corpus"))
        .arg("--corpus")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    (out.status.code().unwrap_or(-1), text)
}

/// Network test, part 1: re-capturing one pubnet and two testnet vendored
/// ledgers from the lake reproduces their object hashes, and for the two testnet ledgers with
/// manifest entries the blob hashes and the whole provenance of the authored variants.
#[test]
#[ignore = "needs the network (public data lake)"]
fn recapture_three_vendored_ledgers_from_the_lake() {
    let root = scratch_corpus("capture-network");
    let (code, out) = xdrcheck_corpus(&root, &["capture", "pubnet", "3"]);
    assert_eq!(code, 0, "{out}");
    let r = record(&root.join("objects/pubnet/3/capture.json"));
    let vendored = record(&corpus().join("objects/pubnet/3/capture.json"));
    assert_eq!(
        (&r.object_sha256, &r.blob_sha256),
        (&vendored.object_sha256, &vendored.blob_sha256)
    );
    let mut testnet = 0;
    // The two testnet history entries the corpus started with.
    let first = [
        "cap-0038/pool-issuers-order-by-bytes-not-strkey",
        "cap-0040/signed-payload-signer-added",
    ];
    for (id, old) in history_variants()
        .into_iter()
        .filter(|(id, _)| first.contains(&id.as_str()))
    {
        let seq = old["ledger_seq"].to_string();
        let tx = old["focus"]["tx_hash"].as_str().unwrap();
        let net = old["network"].as_str().unwrap();
        let (code, out) =
            xdrcheck_corpus(&root, &["capture", net, &seq, "--tx", tx, "--entry", &id]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("identical to the vendored copy"), "{out}");
        assert_same_history_variant(&id, &variant_of(&root, &id, &old), &old);
        testnet += usize::from(net == "testnet");
    }
    assert_eq!(testnet, 2);
}

/// Network test, part 2: `refetch` over the committed corpus finds all 38
/// vendored objects present with their recorded hashes.
#[test]
#[ignore = "needs the network (public data lake)"]
fn refetch_reports_every_vendored_object_present() {
    let (code, out) = xdrcheck_corpus(&corpus(), &["refetch"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("refetch: 38 objects: 38 present, 0 changed"),
        "{out}"
    );
}

/// A vendored object rewritten one protocol above the corpus gate (header protocol raised, stored
/// header hash recomputed), as a network that upgraded before the pins moved would serve it.
fn above_gate_object(object: &[u8], protocol: u32) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    use xdrcheck_xdr::xdr::{Hash, LedgerCloseMeta, Limits, ReadXdr, WriteXdr};
    let xdr = xdrcheck_xdr::batch::decompress(object).unwrap();
    let mut lcm = LedgerCloseMeta::from_xdr(&xdr[12..], Limits::none()).unwrap();
    let h = match &mut lcm {
        LedgerCloseMeta::V0(m) => &mut m.ledger_header,
        LedgerCloseMeta::V1(m) => &mut m.ledger_header,
        LedgerCloseMeta::V2(m) => &mut m.ledger_header,
    };
    h.header.ledger_version = protocol;
    h.hash = Hash(Sha256::digest(h.header.to_xdr(Limits::none()).unwrap()).into());
    let mut batch = xdr[..12].to_vec();
    batch.extend_from_slice(&lcm.to_xdr(Limits::none()).unwrap());
    xdrcheck_xdr::batch::compress(&batch, 3).unwrap()
}

/// A ledger above the corpus gate that the pinned definitions still decode (a protocol upgrade
/// that changed no XDR) is captured with a warning, not refused; with `--entry` it is refused before
/// anything is written, because the corpus gate would refuse the entry.
#[test]
fn capture_above_the_gate_warns_and_refuses_an_entry() {
    let root = scratch_corpus("capture-above-gate");
    let pins = intake::pins::Pins::load(&root).unwrap();
    let gate = Gate::default();
    let next = gate.max_protocol + 1;
    let dir = lake::capture_dir(&root, Network::Pubnet, 3);
    let r = record(&dir.join("capture.json"));
    let object = above_gate_object(&std::fs::read(dir.join(&r.object_file)).unwrap(), next);
    assert_eq!(lake::object_protocol(&object), Some(next));
    std::fs::remove_dir_all(&dir).unwrap();
    // The exporter states the protocol it wrote, and the bytes changed.
    let mut head = head_of(&r);
    head.metadata
        .insert("protocol-version".into(), next.to_string());
    head.content_length = Some(object.len() as u64);
    head.etag = None;
    let fetched = Fetched {
        object,
        head,
        fetched_with: "test".into(),
    };
    let capture = |entry: Option<&str>| {
        lake::capture_fetched(
            &root,
            &pins,
            &gate,
            Network::Pubnet,
            3,
            &fetched,
            None,
            entry,
        )
    };
    let e = capture(Some("protocol-01/anything")).unwrap_err();
    assert!(e.downcast_ref::<CheckFailed>().is_some(), "{e:#}");
    assert!(format!("{e:#}").contains("without --entry"), "{e:#}");
    assert!(!dir.exists(), "nothing written");

    let out = capture(None).unwrap();
    assert_eq!(out.record.ledger.protocol, next);
    assert!(
        out.warnings.iter().any(|w| w.contains(&format!(
            "ledger protocol {next} is above the supported maximum"
        ))),
        "{:?}",
        out.warnings
    );
    assert!(dir.join(&r.object_file).is_file());
}
