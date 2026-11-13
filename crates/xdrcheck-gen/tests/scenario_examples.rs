//! The two worked scenario examples (CAP-0040 signed payloads, CAP-0073 SAC `trust`), written as
//! complete files under `tests/data/`, load, validate and resolve on both passphrases at both of
//! their protocols; and the Stellar Asset Contract ID derivation reproduces the IDs recorded in
//! the vendored manifest entry `cap-0073/sac-trust-creates-trustline` (taken from the ledgers
//! stellar-core produced).

use std::path::{Path, PathBuf};

use serde_json::Value;
use stellar_xdr::{
    AlphaNum4, Asset, AssetCode4, HostFunction, LedgerKey, OperationBody, ScAddress,
    TransactionEnvelope, TransactionExt, TrustLineAsset,
};
use xdrcheck_gen::scenario::{build, network_id, sac_contract_strkey, Options, Scenario, SetupAction};

const TESTNET: &str = "Test SDF Network ; September 2015";
const PUBNET: &str = "Public Global Stellar Network ; September 2015";

fn data(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

/// Every `${…}` left in a resolved annotation must be a `${derived.…}` reference.
fn assert_only_derived_left(v: &Value, at: &str) {
    match v {
        Value::String(s) => {
            let mut rest = s.as_str();
            while let Some(i) = rest.find("${") {
                assert!(
                    rest[i..].starts_with("${derived."),
                    "{at}: unresolved placeholder in `{s}`"
                );
                rest = &rest[i + 2..];
            }
        }
        Value::Array(a) => a.iter().for_each(|x| assert_only_derived_left(x, at)),
        Value::Object(o) => o.values().for_each(|x| assert_only_derived_left(x, at)),
        _ => {}
    }
}

fn credit4(code: &str, issuer: &str) -> Asset {
    let mut c = [0u8; 4];
    c[..code.len()].copy_from_slice(code.as_bytes());
    Asset::CreditAlphanum4(AlphaNum4 {
        asset_code: AssetCode4(c),
        issuer: issuer.parse().unwrap(),
    })
}

#[test]
fn worked_examples_load_and_resolve() {
    for file in ["cap-0040-signed-payload.yaml", "cap-0073-sac-trust.yaml"] {
        let scenario = Scenario::load(&data(file)).unwrap();
        assert_eq!(scenario.protocols, vec![28, 30]);
        for pp in [TESTNET, PUBNET] {
            for &p in &scenario.protocols {
                let built = build(&scenario, pp, p, Options::default())
                    .unwrap_or_else(|e| panic!("{file} at {p}: {e}"));
                assert_eq!(built.steps.len(), scenario.steps.len());
                for s in &built.steps {
                    let tx = s.tx.as_ref().expect("every example step has a transaction");
                    let back = xdrcheck_xdr::decode(
                        "TransactionEnvelope",
                        &tx.envelope.bytes,
                        &xdrcheck_xdr::Limits::default(),
                    )
                    .unwrap();
                    assert_eq!(
                        back,
                        stellar_xdr::Type::TransactionEnvelope(Box::new(
                            tx.envelope.envelope.clone()
                        ))
                    );
                    for block in [&s.expect, &s.fields, &s.mirrors].into_iter().flatten() {
                        assert_only_derived_left(block, &format!("{file} {}", s.id));
                    }
                    assert_eq!(s.expected.result.as_deref(), Some("tx_success"));
                    assert!(s.entry.is_some());
                }
            }
        }
    }
}

#[test]
fn example_1_resolves_signers_and_expectations() {
    let scenario = Scenario::load(&data("cap-0040-signed-payload.yaml")).unwrap();
    let built = build(&scenario, TESTNET, 30, Options::default()).unwrap();
    let first = &built.steps[0];
    let expect = first.expect.as_ref().unwrap();
    let signer_key = expect["state_changes"][0]["signer"]["key"]
        .as_str()
        .unwrap();
    assert!(signer_key.starts_with('P'));
    let parsed: stellar_strkey::ed25519::SignedPayload = signer_key.parse().unwrap();
    assert_eq!(parsed.payload(), &[0x2a]);
    assert_eq!(
        format!("{}", stellar_strkey::ed25519::PublicKey(*parsed.ed25519())),
        built.accounts["D"]
    );
    assert_eq!(
        expect["participants"]["must_include"][0]["address"],
        built.accounts["A"].as_str()
    );
    assert_eq!(
        expect["participants"]["must_not_include"][0]["address"],
        built.accounts["D"].as_str()
    );
    assert_eq!(expect["addresses"][0]["strkey"], signer_key);
    assert_eq!(first.fields.as_ref().unwrap()["validated"][0], "VF-29");
    assert_eq!(built.steps[1].ledger, first.ledger, "same_ledger_as");
}

#[test]
fn example_2_uses_the_sac_of_the_asset_on_each_network() {
    let scenario = Scenario::load(&data("cap-0073-sac-trust.yaml")).unwrap();
    let mut ids = Vec::new();
    for pp in [TESTNET, PUBNET] {
        for p in [28, 30] {
            let built = build(&scenario, pp, p, Options::default()).unwrap();
            let usdc = credit4("USDC", &built.accounts["I1"]);
            let want = sac_contract_strkey(&network_id(pp), &usdc).unwrap();
            let SetupAction::DeploySac {
                asset_name,
                contract_id,
                asset,
            } = &built.setup[1].action
            else {
                panic!("setup[1] is deploy_sac")
            };
            assert_eq!(asset_name, "USDC");
            assert_eq!(contract_id, &want);
            assert_eq!(
                asset["credit_alphanum4"]["issuer"],
                built.accounts["I1"].as_str()
            );

            let s = &built.steps[0];
            assert_eq!(s.ledger, 15, "fund at 13, deploy_sac at 14");
            let TransactionEnvelope::Tx(e) = &s.tx.as_ref().unwrap().envelope.envelope else {
                panic!("v1")
            };
            let OperationBody::InvokeHostFunction(op) = &e.tx.operations[0].body else {
                panic!("invoke_host_function")
            };
            let HostFunction::InvokeContract(args) = &op.host_function else {
                panic!("invoke_contract")
            };
            let ScAddress::Contract(c) = &args.contract_address else {
                panic!("contract address")
            };
            assert_eq!(format!("{}", stellar_strkey::Contract(c.0 .0)), want);
            assert_eq!(args.function_name.to_string(), "trust");
            let TransactionExt::V1(sd) = &e.tx.ext else {
                panic!("soroban data")
            };
            assert_eq!(sd.resource_fee, 50_000_000);
            let rw = &sd.resources.footprint.read_write;
            let LedgerKey::Trustline(tl) = &rw[0] else {
                panic!("trustline key")
            };
            assert_eq!(
                format!("{}", tl.account_id),
                built.accounts["B"],
                "trustline of B"
            );
            let TrustLineAsset::CreditAlphanum4(a) = &tl.asset else {
                panic!("credit asset")
            };
            assert_eq!(format!("{}", a.issuer), built.accounts["I1"]);
            ids.push(want);
        }
    }
    assert_eq!(
        ids[0], ids[1],
        "same network, same contract at both protocols"
    );
    assert_ne!(ids[0], ids[2], "the SAC ID depends on the network");
}

#[test]
fn sac_ids_match_the_vendored_manifest_entry() {
    let path = repo("corpus/manifest/cap-0073/sac-trust-creates-trustline.json");
    let entry: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    // The scenario's own variants; a core-golden variant uses the core test's asset, not ours.
    let variants: Vec<&Value> = entry["variants"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["source"]["kind"] == "local-core")
        .collect();
    assert_eq!(variants.len(), 4);
    for v in variants {
        let pp = v["passphrase"].as_str().unwrap();
        let derived = &v["derived"];
        // The scenario's issuer actor is `issuer`; its asset is USDC.
        let (code, issuer) = ("USDC", derived["accounts"]["issuer"].as_str().unwrap());
        let nid = network_id(pp);
        assert_eq!(
            sac_contract_strkey(&nid, &credit4(code, issuer)).unwrap(),
            derived["contracts"]["sac_usdc"].as_str().unwrap(),
            "{pp} protocol {}",
            v["protocol"]
        );

        // The same ID through the placeholder, with the recorded issuer as a literal address.
        let yaml = format!(
            r#"
scenario: sac-id
caps: [73]
protocols: [30]
profile: lake
actors: [B]
assets:
  USDC: {{credit_alphanum4: {{asset_code: {code}, issuer: "{issuer}"}}}}
steps:
  - id: s
    entry: probe/sac-id
    close: {{}}
    expect:
      values:
        - {{path: /a, equals: "${{contract.sac(USDC)}}"}}
        - {{path: /b, equals: "${{contract.sac(native)}}"}}
"#
        );
        let scenario = Scenario::from_yaml_str(&yaml).unwrap();
        let built = build(&scenario, pp, 30, Options::default()).unwrap();
        let values = &built.steps[0].expect.as_ref().unwrap()["values"];
        assert_eq!(values[0]["equals"], derived["contracts"]["sac_usdc"]);
        assert_eq!(
            values[1]["equals"],
            sac_contract_strkey(&nid, &Asset::Native).unwrap()
        );
    }
}
