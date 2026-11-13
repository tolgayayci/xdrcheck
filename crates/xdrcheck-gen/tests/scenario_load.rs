//! Loading, validation and resolution rules of the scenario interpreter, including what it must
//! refuse.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use xdrcheck_gen::scenario::{
    actor_seed, build, contract_id_from_address, contract_salt, network_id, root_key, Error,
    Options, Scenario, NAMESPACE,
};

const TESTNET: &str = "Test SDF Network ; September 2015";

fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

/// A minimal scenario around one step's YAML (indented as a list item under `steps:`).
fn scenario_with(step: &str) -> String {
    format!(
        r#"
scenario: rules
caps: [40]
protocols: [28, 30]
profile: lake
actors: [A, B]
contracts:
  emitter: {{wasm: corpus/contracts/shape-emitter.wasm, deployer: B}}
setup:
  - fund: {{A: "100", B: "100.5"}}
steps:
{step}
"#
    )
}

const PAYMENT: &str = r#"
  - id: pay
    entry: probe/pay
    tx:
      source_account: "${acct.A}"
      fee: 100
      seq_num: "${seq.A}"
      cond: none
      memo: none
      operations:
        - source_account: null
          body: {payment: {destination: "${acct.B}", asset: native, amount: "1"}}
      ext: v0
    sign: [{key: A}]
    expect_result: tx_success
"#;

fn err(yaml: &str) -> String {
    match Scenario::from_yaml_str(yaml) {
        Err(e) => e.to_string(),
        Ok(s) => match build(&s, TESTNET, 30, Options::default()) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected an error for:\n{yaml}"),
        },
    }
}

#[test]
fn schema_examples_are_accepted_and_rejected_as_labelled() {
    let valid = Scenario::load(&repo("corpus/schema/examples/scenario/valid-01.json")).unwrap();
    assert_eq!(valid.name, "cap-0073-sac-trust");
    assert_eq!(valid.networks, vec!["testnet", "pubnet"], "schema default");
    // Its template is only a sketch (one field), so it cannot be built.
    let e = build(&valid, TESTNET, 30, Options::default()).unwrap_err();
    assert!(e.to_string().contains("sac-trust"), "{e}");

    // The generator features: bring-up and setup entries, root, config_upgrade, order, left out.
    let features = Scenario::load(&repo("corpus/schema/examples/scenario/valid-03.json")).unwrap();
    assert_eq!(features.bring_up.len(), 2);
    build(&features, TESTNET, 30, Options::default()).unwrap();
    assert!(matches!(
        Scenario::load(&repo("corpus/schema/examples/scenario/invalid-04.json")),
        Err(Error::Schema(_))
    ));

    let invalid = Scenario::load(&repo("corpus/schema/examples/scenario/invalid-01.json"));
    let Err(Error::Schema(errors)) = invalid else {
        panic!("invalid-01 must fail the schema: {invalid:?}")
    };
    assert!(
        errors.iter().any(|e| e.starts_with("/profile")),
        "{errors:?}"
    );
}

#[test]
fn expect_blocks_are_checked_against_the_manifest_schema() {
    // A transaction expectation without `successful`, which the manifest-entry schema requires.
    let yaml = scenario_with(&format!(
        "{PAYMENT}    expect:\n      transactions:\n        - {{index: 0, fee_charged: \"${{derived.fee_charged}}\"}}\n"
    ));
    let Err(Error::Schema(errors)) = Scenario::from_yaml_str(&yaml) else {
        panic!("expected a schema error")
    };
    assert!(
        errors
            .iter()
            .any(|e| e.contains("/steps/0/expect/transactions/0")),
        "{errors:?}"
    );
    let ok = yaml.replace("{index: 0,", "{index: 0, successful: true,");
    Scenario::from_yaml_str(&ok).unwrap();
}

#[test]
fn misspelt_template_fields_are_errors_not_silently_dropped() {
    let yaml = scenario_with(&PAYMENT.replace("operations:", "operatons:"));
    let e = err(&yaml);
    assert!(e.contains("step `pay`"), "{e}");
    let yaml = scenario_with(&PAYMENT.replace("amount: \"1\"", "amount: \"1\", amoutn: \"2\""));
    let e = err(&yaml);
    assert!(e.contains("amoutn") && e.contains("not a field"), "{e}");
}

#[test]
fn rejected_inputs() {
    let cases = [
        (
            PAYMENT.replace("${acct.B}", "${acct.Z}"),
            "`Z` is not an actor",
        ),
        (
            PAYMENT.replace("${acct.B}", "${account.B}"),
            "unknown placeholder",
        ),
        (
            PAYMENT.replace("${acct.B}", "${derived.nope}"),
            "no such derived value",
        ),
        (
            PAYMENT.replace("${acct.B}", "${contract.id(other)}"),
            "contract is not defined",
        ),
        (
            PAYMENT.replace("{key: A}", "{key: Q}"),
            "`Q` is not an actor",
        ),
        (
            PAYMENT.replace("    sign: [{key: A}]\n", ""),
            "a step with `tx` needs `sign`",
        ),
        (format!("{PAYMENT}{PAYMENT}"), "duplicate step id"),
        (
            PAYMENT.replace(
                "entry: probe/pay",
                "entry: probe/pay\n    same_ledger_as: later",
            ),
            "not an earlier step",
        ),
        (
            PAYMENT.replace("entry: probe/pay", "entry: probe/pay\n    protocols: [29]"),
            "protocol 29 is not a scenario protocol",
        ),
        (
            PAYMENT.replace("{key: A}", "{signed_payload: {key: A, payload_hex: \"\"}}"),
            "does not match the schema",
        ),
        // A left-out transaction has no result.
        (
            PAYMENT.replace(
                "    expect_result: tx_success\n",
                "    expect_result: tx_success\n    expect_excluded: true\n",
            ),
            "a step left out of its ledger has no result",
        ),
        // `${order_nonce}` outside a group with `order`; `order` naming a step of another ledger.
        (
            PAYMENT.replace("memo: none", "memo: {id: \"${order_nonce}\"}"),
            "only a step of a ledger group with `order`",
        ),
        (
            format!(
                "{}{}",
                PAYMENT.replace(
                    "entry: probe/pay",
                    "entry: probe/pay\n    order: [pay, pay-2]"
                ),
                PAYMENT.replace("id: pay", "id: pay-2")
            ),
            "`pay-2` is not a step of this ledger group",
        ),
    ];
    for (step, want) in cases {
        let e = err(&scenario_with(&step));
        assert!(e.contains(want), "want `{want}` in: {e}");
    }
    // An actor that is never funded has no sequence number unless one is injected.
    let unfunded =
        scenario_with(PAYMENT).replace("setup:\n  - fund: {A: \"100\", B: \"100.5\"}\n", "");
    assert!(
        err(&unfunded).contains("no sequence number"),
        "{}",
        err(&unfunded)
    );
    let s = Scenario::from_yaml_str(&unfunded).unwrap();
    let mut options = Options::default();
    options.sequences.insert("A".into(), 5);
    let built = build(&s, TESTNET, 30, options).unwrap();
    assert_eq!(built.steps[0].tx.as_ref().unwrap().transaction.seq_num.0, 6);
    // A protocol the scenario does not list.
    let s = Scenario::from_yaml_str(&scenario_with(PAYMENT)).unwrap();
    assert!(build(&s, TESTNET, 29, Options::default()).is_err());
}

#[test]
fn root_account_and_setup_entries() {
    let root_pay = PAYMENT
        .replace("\"${acct.A}\"", "\"${acct.root}\"")
        .replace("${seq.A}", "${seq.root}")
        .replace("{key: A}", "{key: root}")
        .replace(
            "    expect_result: tx_success\n",
            "    expect_result: tx_success\n    expect:\n      values: [{path: /x, equals: \"${acct.root}\"}]\n",
        );
    let yaml = scenario_with(&root_pay).replace(
        "  - fund: {A: \"100\", B: \"100.5\"}",
        "  - fund: {A: \"100\", B: \"100.5\"}\n    entry: probe/fund\n    expect: {values: [{path: /y, equals: \"${acct.A}\"}]}",
    );
    let s = Scenario::from_yaml_str(&yaml).unwrap();
    assert!(s.uses_root());
    assert_eq!(s.setup_entries[0].as_ref().unwrap().entry, "probe/fund");
    let built = build(&s, TESTNET, 30, Options::default()).unwrap();
    // The fund transaction used root's sequence 1; the step uses 2 and root's signature.
    let tx = built.steps[0].tx.as_ref().unwrap();
    assert_eq!(tx.transaction.seq_num.0, 2);
    let root = root_key(TESTNET).verifying_key().to_bytes();
    let stellar_xdr::TransactionEnvelope::Tx(env) = &tx.envelope.envelope else {
        panic!("a v1 envelope")
    };
    assert_eq!(env.signatures[0].hint.0, root[28..]);
    // In annotations the root account is a reference to the variant's derived accounts.
    assert_eq!(
        built.steps[0].expect.as_ref().unwrap()["values"][0]["equals"],
        "${derived.accounts.root}"
    );
    let e = built.setup[0].entry.as_ref().unwrap();
    assert_eq!(
        e.expect.as_ref().unwrap()["values"][0]["equals"],
        built.accounts["A"].as_str()
    );

    // `root` cannot be an actor; a setup item has one action.
    let e = err(&yaml.replace("actors: [A, B]", "actors: [A, B, root]"));
    assert!(e.contains("cannot be an actor"), "{e}");
    let e = err(&yaml.replace("    entry: probe/fund\n", "    close: {}\n"));
    assert!(e.contains("does not match the schema"), "{e}");
}

#[test]
fn step_protocols_filter_steps() {
    let only30 = PAYMENT.replace("entry: probe/pay", "entry: probe/pay\n    protocols: [30]");
    let s = Scenario::from_yaml_str(&scenario_with(&only30)).unwrap();
    assert_eq!(
        build(&s, TESTNET, 30, Options::default())
            .unwrap()
            .steps
            .len(),
        1
    );
    assert_eq!(
        build(&s, TESTNET, 28, Options::default())
            .unwrap()
            .steps
            .len(),
        0
    );
}

#[test]
fn derived_values_and_contract_ids() {
    let step = format!(
        "{}    expect:\n      values:\n        - {{path: /a, equals: \"${{derived.fee_charged}}\"}}\n        - {{path: /b, equals: \"owner ${{derived.accounts.owner}}\"}}\n        - {{path: /c, equals: \"${{contract.id(emitter)}}\"}}\n        - {{path: /d, equals: \"${{close_time}}\"}}\n",
        PAYMENT.replace("amount: \"1\"", "amount: \"${derived.amount}\"")
    );
    let s = Scenario::from_yaml_str(&scenario_with(&step)).unwrap();
    // Without the derived amount the template cannot be built.
    assert!(build(&s, TESTNET, 30, Options::default())
        .unwrap_err()
        .to_string()
        .contains("derived.amount"));
    let options = Options {
        derived: serde_json::json!({"amount": "77", "accounts": {"owner": "G-owner"}})
            .as_object()
            .unwrap()
            .clone(),
        ..Options::default()
    };
    let built = build(&s, TESTNET, 30, options).unwrap();
    let st = &built.steps[0];
    let values = &st.expect.as_ref().unwrap()["values"];
    assert_eq!(
        values[0]["equals"], "${derived.fee_charged}",
        "kept for the manifest"
    );
    assert_eq!(values[1]["equals"], "owner G-owner");
    let b = xdrcheck_gen::scenario::actor_key(NAMESPACE, "B")
        .verifying_key()
        .to_bytes();
    let id = contract_id_from_address(
        &network_id(TESTNET),
        &b,
        &contract_salt(NAMESPACE, "emitter"),
    )
    .unwrap();
    assert_eq!(
        values[2]["equals"],
        format!("{}", stellar_strkey::Contract(id))
    );
    assert_eq!(values[3]["equals"], st.close_time.to_string());
    let stellar_xdr::OperationBody::Payment(p) =
        &st.tx.as_ref().unwrap().transaction.operations[0].body
    else {
        panic!()
    };
    assert_eq!(p.amount, 77);
    // Funded balances: "100" and "100.5" XLM.
    let xdrcheck_gen::scenario::SetupAction::Tx(fund) = &built.setup[0].action else {
        panic!()
    };
    let balances: Vec<i64> = fund
        .transaction
        .operations
        .iter()
        .map(|op| match &op.body {
            stellar_xdr::OperationBody::CreateAccount(c) => c.starting_balance,
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(balances, vec![1_000_000_000, 1_005_000_000]);
}

#[test]
fn trust_and_pay_setup_items() {
    let yaml = scenario_with(PAYMENT).replace(
        "setup:\n",
        "assets:\n  USDC: {credit_alphanum4: {asset_code: USDC, issuer: \"${acct.B}\"}}\nsetup:\n",
    ) + "";
    let yaml = yaml.replace(
        "  - fund: {A: \"100\", B: \"100.5\"}\n",
        "  - fund: {A: \"100\", B: \"100.5\"}\n  - trust: {A: USDC}\n  - pay: {from: B, to: A, asset: USDC, amount: \"5\"}\n",
    );
    let s = Scenario::from_yaml_str(&yaml).unwrap();
    let built = build(&s, TESTNET, 30, Options::default()).unwrap();
    let txs: Vec<_> = built
        .setup
        .iter()
        .map(|i| match &i.action {
            xdrcheck_gen::scenario::SetupAction::Tx(t) => t.transaction.clone(),
            other => panic!("{other:?}"),
        })
        .collect();
    let start = 13i64 << 32;
    let stellar_xdr::OperationBody::ChangeTrust(ct) = &txs[1].operations[0].body else {
        panic!()
    };
    assert_eq!(ct.limit, i64::MAX);
    assert_eq!(txs[1].seq_num.0, start + 1, "A trusts");
    let stellar_xdr::OperationBody::Payment(p) = &txs[2].operations[0].body else {
        panic!()
    };
    assert_eq!(
        (p.amount, txs[2].seq_num.0),
        (50_000_000, start + 1),
        "B pays"
    );
    assert_eq!(built.setup[2].ledger, 15);
    // The step after setup: A's second transaction, in ledger 16.
    let st = &built.steps[0];
    assert_eq!(
        (st.ledger, st.tx.as_ref().unwrap().transaction.seq_num.0),
        (16, start + 2)
    );
}

#[test]
fn key_derivation_is_the_documented_one() {
    let want: [u8; 32] = Sha256::digest(b"xcc/key/A").into();
    assert_eq!(actor_seed(NAMESPACE, "A"), want);
    let want_root: [u8; 32] = Sha256::digest(TESTNET.as_bytes()).into();
    assert_eq!(root_key(TESTNET).to_bytes(), want_root);
    assert_eq!(network_id(TESTNET), want_root);
}
