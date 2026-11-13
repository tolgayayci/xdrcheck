//! Scenario rules added for Soroban runs and signer keys, checked without a node: contract
//! constructor arguments and deploy ledger planning, `simulate: true` drafts, the typed `trust` and
//! `pay` setup items, the strict `mirrors` block, and the hash-x and pre-auth-tx signer placeholders.

use sha2::{Digest, Sha256};
use stellar_xdr::{OperationBody, ScSymbol, ScVal, SignerKey, TransactionEnvelope, TransactionExt};
use xdrcheck_gen::scenario::{
    build, hash_x_preimage, network_id, Error, Options, Scenario, SetupAction, NAMESPACE,
};

const TESTNET: &str = "Test SDF Network ; September 2015";

fn err(yaml: &str, protocol: u32) -> String {
    match Scenario::from_yaml_str(yaml) {
        Err(e) => e.to_string(),
        Ok(s) => match build(&s, TESTNET, protocol, Options::default()) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected an error for:\n{yaml}"),
        },
    }
}

const SET_OPTIONS: &str = "inflation_dest: null, clear_flags: null, set_flags: null, master_weight: null, low_threshold: null, med_threshold: null, high_threshold: null, home_domain: null";

fn payment(id: &str, sign: &str) -> String {
    format!(
        r#"
  - id: {id}
    entry: probe/pay
    tx:
      source_account: "${{acct.A}}"
      fee: 100
      seq_num: "${{seq.A}}"
      cond: none
      memo: none
      operations:
        - source_account: null
          body: {{payment: {{destination: "${{acct.B}}", asset: native, amount: "1"}}}}
      ext: v0
    sign: [{sign}]
"#
    )
}

fn signers_scenario(later: &str) -> String {
    format!(
        r#"
scenario: signer-keys
caps: [21]
protocols: [28, 30]
profile: lake
actors: [A, B]
setup:
  - fund: {{A: "100", B: "100"}}
steps:
  - id: add-signers
    entry: probe/signers
    tx:
      source_account: "${{acct.A}}"
      fee: 200
      seq_num: "${{seq.A}}"
      cond: none
      memo: none
      operations:
        - source_account: null
          body: {{set_options: {{{SET_OPTIONS}, signer: {{key: "${{signer.pre_auth_tx(pre-authorised)}}", weight: 1}}}}}}
        - source_account: null
          body: {{set_options: {{{SET_OPTIONS}, signer: {{key: "${{signer.hash_x(gate)}}", weight: 1}}}}}}
      ext: v0
    sign: [{{key: A}}]
    expect:
      addresses:
        - {{strkey: "${{signer.pre_auth_tx(pre-authorised)}}", type: pre_auth_tx}}
        - {{strkey: "${{signer.hash_x(gate)}}", type: hash_x}}
{later}"#
    )
}

#[test]
fn hash_x_and_pre_auth_signer_keys() {
    let later = payment("pre-authorised", "{pre_auth: true}")
        + &payment("by-hash-x", "{hash_x: \"${hash_x.preimage(gate)}\"}");
    let s = Scenario::from_yaml_str(&signers_scenario(&later)).unwrap();
    for protocol in [28, 30] {
        let built = build(&s, TESTNET, protocol, Options::default()).unwrap();
        let [add, pre, hx] = built.steps.as_slice() else {
            panic!("three steps")
        };
        // The pre-auth key is the hash of the later step's transaction under this passphrase.
        let pre_tx = pre.tx.as_ref().unwrap();
        let pre_hash = pre_tx.transaction.hash(network_id(TESTNET)).unwrap();
        let t_key = format!("{}", stellar_strkey::PreAuthTx(pre_hash));
        assert_eq!(pre_tx.envelope.pre_authorised, vec![t_key.clone()]);
        let TransactionEnvelope::Tx(e) = &pre_tx.envelope.envelope else {
            panic!()
        };
        assert!(
            e.signatures.is_empty(),
            "a pre-authorised transaction carries no signature"
        );
        // The hash-x key is sha256 of the named preimage, sha256("xcc/hashx/gate").
        let preimage: [u8; 32] = Sha256::digest(b"xcc/hashx/gate").into();
        assert_eq!(hash_x_preimage(NAMESPACE, "gate"), preimage);
        let x_key = format!("{}", stellar_strkey::HashX(Sha256::digest(preimage).into()));
        let keys: Vec<String> = add
            .tx
            .as_ref()
            .unwrap()
            .transaction
            .operations
            .iter()
            .map(|op| match &op.body {
                OperationBody::SetOptions(o) => match &o.signer.as_ref().unwrap().key {
                    SignerKey::PreAuthTx(k) => format!("{}", stellar_strkey::PreAuthTx(k.0)),
                    SignerKey::HashX(k) => format!("{}", stellar_strkey::HashX(k.0)),
                    other => panic!("{other:?}"),
                },
                _ => panic!(),
            })
            .collect();
        assert_eq!(keys, vec![t_key.clone(), x_key.clone()]);
        let addresses = &add.expect.as_ref().unwrap()["addresses"];
        assert_eq!(addresses[0]["strkey"], t_key.as_str());
        assert_eq!(addresses[1]["strkey"], x_key.as_str());
        // The hash-x signature is the preimage itself.
        let TransactionEnvelope::Tx(e) = &hx.tx.as_ref().unwrap().envelope.envelope else {
            panic!()
        };
        assert_eq!(e.signatures.len(), 1);
        assert_eq!(e.signatures[0].signature.as_slice(), preimage.as_slice());
    }
}

#[test]
fn pre_auth_references_that_cannot_be_predicted_are_refused() {
    // A pre-authorised step whose own template names a later pre-auth hash: the prediction made
    // without that hash differs from the real build.
    let chained = payment("pre-authorised", "{pre_auth: true}").replace(
        "amount: \"1\"",
        "amount: \"1\"}}\n        - source_account: null\n          body: {set_options: {inflation_dest: null, clear_flags: null, set_flags: null, master_weight: null, low_threshold: null, med_threshold: null, high_threshold: null, home_domain: null, signer: {key: \"${signer.pre_auth_tx(last)}\", weight: 1}",
    ) + &payment("last", "{pre_auth: true}");
    let e = err(&signers_scenario(&chained), 30);
    assert!(e.contains("differs from the one its"), "{e}");
    // A step that does not exist, or has no transaction.
    let e = err(&signers_scenario(&payment("other", "{key: A}")), 30);
    assert!(e.contains("no step has that ID"), "{e}");
    // A bad hash_x signer value is a schema error.
    let bad = signers_scenario(&payment("pre-authorised", "{hash_x: \"${acct.A}\"}"));
    assert!(matches!(
        Scenario::from_yaml_str(&bad),
        Err(Error::Schema(_))
    ));
}

const CONTRACTS: &str = r#"
scenario: deploys
caps: [46]
protocols: [29, 30]
profile: lake
actors: [A, D]
assets:
  USDC: {credit_alphanum4: {asset_code: USDC, issuer: "${acct.A}"}}
contracts:
  emitter: {wasm: contracts/shape-emitter.wasm, deployer: D, constructor_args: [{symbol: xcc}, {address: "${acct.A}"}, {u32: 7}]}
  account_1: {wasm: contracts/custom-account.wasm, deployer: D}
  account_2: {wasm: contracts/custom-account.wasm, deployer: D}
setup:
  - fund: {A: "100", D: "100"}
  - deploy_sac: USDC
  - deploy_contract: emitter
  - deploy_contract: account_1
  - deploy_contract: account_2
steps:
  - id: call
    entry: probe/call
    tx:
      source_account: "${acct.A}"
      fee: 100
      seq_num: "${seq.A}"
      cond: none
      memo: none
      operations:
        - source_account: null
          body:
            invoke_host_function:
              host_function:
                invoke_contract: {contract_address: "${contract.id(emitter)}", function_name: colliding_keys, args: []}
    simulate: true
    sign: [{key: A}]
    expect_result: tx_success
"#;

#[test]
fn deploys_plan_their_ledgers_and_parse_constructor_args() {
    let s = Scenario::from_yaml_str(CONTRACTS).unwrap();
    let built = build(&s, TESTNET, 30, Options::default()).unwrap();
    // fund 13, deploy_sac 14, emitter upload+create 15-16, account_1 upload+create 17-18,
    // account_2 create only (same code) 19, the step 20.
    let ledgers: Vec<u32> = built.setup.iter().map(|i| i.ledger).collect();
    assert_eq!(ledgers, vec![13, 14, 15, 17, 19]);
    assert_eq!(built.steps[0].ledger, 20);
    let SetupAction::DeployContract {
        constructor_args, ..
    } = &built.setup[2].action
    else {
        panic!()
    };
    assert_eq!(constructor_args.len(), 3);
    assert_eq!(
        constructor_args[0],
        ScVal::Symbol(ScSymbol("xcc".try_into().unwrap()))
    );
    assert_eq!(constructor_args[2], ScVal::U32(7));
    // A simulated step is a draft: ext v0 and an empty authorization list until simulation.
    let st = &built.steps[0];
    assert!(st.simulate);
    let tx = &st.tx.as_ref().unwrap().transaction;
    assert!(matches!(tx.ext, TransactionExt::V0));
    let OperationBody::InvokeHostFunction(op) = &tx.operations[0].body else {
        panic!()
    };
    assert!(op.auth.is_empty());

    // A misspelt constructor argument is an error, not a dropped value.
    let e = err(&CONTRACTS.replace("{u32: 7}", "{u33: 7}"), 30);
    assert!(e.contains("constructor_args[2]"), "{e}");
}

#[test]
fn soroban_rules_the_schema_cannot_express() {
    let cases = [
        (
            CONTRACTS.replace("protocols: [29, 30]", "protocols: [28, 30]"),
            "needs Protocol 29 or later; the scenario lists 28",
        ),
        (
            CONTRACTS.replace("    simulate: true\n", "    simulate: true\n    soroban_resources: declared\n"),
            "contradict",
        ),
        (
            CONTRACTS
                .replace("protocols: [29, 30]", "protocols: [28, 29, 30]")
                .replace("  - deploy_contract: emitter\n  - deploy_contract: account_1\n  - deploy_contract: account_2\n", "")
                .replace("${contract.id(emitter)}", "${contract.sac(USDC)}"),
            "the step runs at 28",
        ),
        (
            CONTRACTS.replace("      ext: v0\n", "").replace(
                "    simulate: true\n",
                "      ext: {v1: {ext: v0, resources: {footprint: {read_only: [], read_write: []}, instructions: 1, disk_read_bytes: 1, write_bytes: 1}, resource_fee: \"1\"}}\n    simulate: true\n",
            ),
            "`ext` is filled by simulation",
        ),
    ];
    for (yaml, want) in cases {
        let e = err(&yaml, 30);
        assert!(e.contains(want), "want `{want}` in: {e}");
    }
    // With `protocols: [29, 30]` the step is allowed, and at 28 it does not run.
    let ok = CONTRACTS
        .replace("protocols: [29, 30]", "protocols: [28, 29, 30]")
        .replace("  - deploy_contract: emitter\n  - deploy_contract: account_1\n  - deploy_contract: account_2\n", "")
        .replace("${contract.id(emitter)}", "${contract.sac(USDC)}")
        .replace("    simulate: true\n", "    simulate: true\n    protocols: [29, 30]\n");
    let s = Scenario::from_yaml_str(&ok).unwrap();
    assert!(build(&s, TESTNET, 28, Options::default())
        .unwrap()
        .steps
        .is_empty());
}

#[test]
fn new_schema_examples_are_accepted_and_rejected_as_labelled() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/schema/examples/scenario");
    let valid = Scenario::load(&dir.join("valid-02.json")).unwrap();
    assert!(valid.steps[2].simulate);
    assert_eq!(valid.contracts["emitter"].constructor_args.len(), 1);
    for (file, at) in [
        ("invalid-02.json", "/steps/0/mirrors"),
        ("invalid-03.json", "/setup/1/pay"),
    ] {
        let Err(Error::Schema(errors)) = Scenario::load(&dir.join(file)) else {
            panic!("{file} must fail the schema")
        };
        assert!(
            errors.iter().any(|e| e.starts_with(at)),
            "{file}: {errors:?}"
        );
    }
}

#[test]
fn typed_setup_items_and_strict_mirrors() {
    let base = |setup: &str, step_extra: &str| {
        format!(
            r#"
scenario: typed
caps: [1]
protocols: [30]
profile: lake
actors: [A, B]
assets:
  USDC: {{credit_alphanum4: {{asset_code: USDC, issuer: "${{acct.B}}"}}}}
setup:
  - fund: {{A: "100", B: "100"}}
{setup}
steps:
  - id: settle
    entry: probe/settle
    close: {{ledgers: 1}}
{step_extra}"#
        )
    };
    let good = base(
        "  - trust: {A: [USDC]}\n  - pay: {from: B, to: A, asset: USDC, amount: \"1.5\"}",
        "",
    );
    Scenario::from_yaml_str(&good).unwrap();
    for (setup, at) in [
        ("  - trust: {A: 5}", "/setup/1/trust/A"),
        ("  - trust: {A: []}", "/setup/1/trust/A"),
        ("  - pay: {from: B, to: A, asset: USDC}", "/setup/1/pay"),
        (
            "  - pay: {from: B, to: A, asset: USDC, amount: \"1\", memo: x}",
            "/setup/1/pay",
        ),
        (
            "  - pay: {from: B, to: A, asset: USDC, amount: \"1.12345678\"}",
            "/setup/1/pay/amount",
        ),
    ] {
        let Err(Error::Schema(errors)) = Scenario::from_yaml_str(&base(setup, "")) else {
            panic!("{setup} must fail the schema")
        };
        assert!(
            errors.iter().any(|e| e.starts_with(at)),
            "{setup}: {errors:?}"
        );
    }
    // `mirrors` is the manifest entry's definition: the old free-form shape is refused.
    let old = base(
        "",
        "    mirrors: {core_golden: {tag: v30.0.0, test_name: t, frame: 1, tx: 0}, flags_from: x}\n",
    );
    let Err(Error::Schema(errors)) = Scenario::from_yaml_str(&old) else {
        panic!("free-form mirrors must fail the schema")
    };
    assert!(
        errors.iter().any(|e| e.starts_with("/steps/0/mirrors")),
        "{errors:?}"
    );
    let strict = base(
        "",
        "    mirrors:\n      core_golden: {core_tag: v30.0.0, file: f.xdr, file_sha256: 20624d6db29bb4546312a1aafcc72c978c1781b40b90a4828ab0dc7166fefeda, test_name: t, frame_index: 1, tx_index: 0}\n      flags: [EMIT_CLASSIC_EVENTS]\n      flags_source: \"src/test/test.cpp:1\"\n      state: planned\n",
    );
    Scenario::from_yaml_str(&strict).unwrap();
}
