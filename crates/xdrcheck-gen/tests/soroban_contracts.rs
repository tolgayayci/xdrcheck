//! On fresh Protocol 29 and 30 nodes, on each passphrase, deploy the shape-emitter
//! and custom-account test contracts (through the scenario interpreter's `deploy_contract` items), call
//! shape-emitter functions emitting the colliding-key maps, a vector nested 99 levels, a token-shaped
//! `transfer` event with `to_muxed_id` Void and a forged SAC-shaped event, and make a call authorized
//! through custom-account with nested delegates (CAP-0071). Every transaction's footprint and resources
//! come from offline simulation against the node. All `tx_success`, events as emitted, and two runs give
//! identical header hashes.
//!
//! The contracts declare interface protocol 29 (soroban-sdk 29.0.1), so the host refuses them at 28.
//! Expected event shapes come from the contracts' source, not from a reader.

mod common;

use std::path::Path;

use stellar_xdr::{
    ContractEvent, ContractEventBody, ContractId, Hash, ScAddress, ScString, ScSymbol, ScVal,
    ScVec, SorobanCredentials, TransactionEnvelope,
};
use xdrcheck_gen::core::{Keypair, Node, NodeOptions, PUBNET_PASSPHRASE, TESTNET_PASSPHRASE};
use xdrcheck_gen::scenario::{Interpreter, Item, Options, Scenario, SetupAction};
use xdrcheck_gen::soroban::contract::{
    delegated_auth, invoke, invoke_args, run_deploy_contract, Delegate, Deployed,
};
use xdrcheck_gen::soroban::sim::{simulation_seed, AuthMode};
use xdrcheck_gen::soroban::{account_address, i128_val, symbol, TxOutcome};
use xdrcheck_gen::upgrade::bring_up;

const SCENARIO: &str = r#"
scenario: r18-contract-calls
caps: [46, 67, 71]
protocols: [29, 30]
profile: lake
actors: [deployer, A, B, I]
contracts:
  emitter: {wasm: corpus/contracts/shape-emitter.wasm, wasm_sha256: b53305d9913b679f137ae4d44f1ea2d32f57502f1b12aaa26406168ef4daaed8, deployer: deployer, constructor_args: [{symbol: xcc}]}
  account: {wasm: corpus/contracts/custom-account.wasm, wasm_sha256: 0a4d4597cbf11959d7e27d795ed4e5d00e2fb8ff59f8a402bf4aefadda9c0999, deployer: deployer}
  delegate_1: {wasm: corpus/contracts/custom-account.wasm, wasm_sha256: 0a4d4597cbf11959d7e27d795ed4e5d00e2fb8ff59f8a402bf4aefadda9c0999, deployer: deployer}
  delegate_2: {wasm: corpus/contracts/custom-account.wasm, wasm_sha256: 0a4d4597cbf11959d7e27d795ed4e5d00e2fb8ff59f8a402bf4aefadda9c0999, deployer: deployer}
setup:
  - fund: {deployer: "10000", A: "10000", B: "10000", I: "10000"}
  - deploy_contract: emitter
  - deploy_contract: account
  - deploy_contract: delegate_1
  - deploy_contract: delegate_2
steps:
  - id: settle
    entry: cap-0046/event-data-map-with-colliding-keys
    close: {ledgers: 1}
"#;

fn repo() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

fn body(e: &ContractEvent) -> (Vec<ScVal>, ScVal) {
    let ContractEventBody::V0(b) = &e.body;
    (b.topics.to_vec(), b.data.clone())
}

fn map_keys(v: &ScVal) -> Vec<ScVal> {
    let ScVal::Map(Some(m)) = v else {
        panic!("not a map: {v:?}")
    };
    m.iter().map(|e| e.key.clone()).collect()
}

fn string(s: &str) -> ScVal {
    ScVal::String(ScString(s.try_into().unwrap()))
}

fn submit_close(node: &mut Node, env: &TransactionEnvelope) -> TxOutcome {
    let hash = node.submit_pending(env).unwrap();
    let ledger = node.close().unwrap();
    TxOutcome::read(&ledger, &hash).unwrap()
}

/// The op events of a successful call, checked against what simulation said the call emits.
fn events(out: &TxOutcome, simulated: &[ContractEvent], what: &str) -> Vec<ContractEvent> {
    assert!(out.succeeded(), "{what}: {:?}", out.result);
    let ev = out.op_events(0);
    assert_eq!(
        ev, simulated,
        "{what}: ledger events differ from the simulated ones"
    );
    ev
}

fn chain(bin: &xdrcheck_gen::core::CoreBinary, passphrase: &str, protocol: u32) -> Vec<[u8; 32]> {
    let dir = common::run_dir(&format!("contracts-p{protocol}"));
    let mut node = Node::start(bin, &dir, NodeOptions::new(passphrase)).unwrap();
    bring_up(&mut node, protocol).unwrap();
    let root = Keypair::root(passphrase);
    let scenario = Scenario::from_yaml_str(SCENARIO).unwrap();
    let options = Options {
        root_sequence: node.account_sequence(&root.account_id()).unwrap().unwrap(),
        ..Options::default()
    };
    let mut it = Interpreter::new(&scenario, passphrase, protocol, options).unwrap();
    let mut deployed: Vec<(String, Deployed)> = Vec::new();
    while let Some(item) = it.next_item() {
        match item.unwrap() {
            Item::Setup(s) => {
                assert_eq!(s.ledger, node.last_closed() + 1, "setup[{}]", s.index);
                match &s.action {
                    SetupAction::Tx(b) => {
                        let out = submit_close(&mut node, &b.envelope.envelope);
                        assert!(out.succeeded(), "{}: {:?}", s.kind, out.result);
                    }
                    SetupAction::DeployContract { name, .. } => {
                        let (d, outs) =
                            run_deploy_contract(&mut node, &mut it, &s.action, repo(), 100)
                                .unwrap();
                        assert!(outs.iter().all(TxOutcome::succeeded));
                        if name == "emitter" {
                            // The constructor ran in the create transaction: its `init` event.
                            let (t, data) = body(&outs.last().unwrap().op_events(0)[0]);
                            assert_eq!(t, vec![symbol("init").unwrap()]);
                            assert_eq!(data, symbol("xcc").unwrap());
                        }
                        deployed.push((name.clone(), d));
                    }
                    other => panic!("unexpected setup item {other:?}"),
                }
            }
            Item::Step(st) => {
                assert_eq!(st.ledger, node.last_closed() + 1);
                assert!(st.tx.is_none());
                node.close().unwrap();
            }
        }
    }
    let addr = |n: &str| deployed.iter().find(|(k, _)| k == n).unwrap().1.address();
    let emitter = addr("emitter");
    let ScAddress::Contract(emitter_id) = &emitter else {
        panic!()
    };
    let (a, b, i) = (
        Keypair::from_label("A"),
        Keypair::from_label("B"),
        Keypair::from_label("I"),
    );

    // colliding_keys(): two events, maps whose keys collide after native conversion.
    let (sim, out) = invoke(
        &mut node,
        &a,
        &emitter,
        "colliding_keys",
        vec![],
        AuthMode::Record,
        100,
        simulation_seed("r18-contract-calls/colliding_keys"),
    )
    .unwrap();
    let ev = events(&out, &sim.contract_events, "colliding_keys");
    assert_eq!(ev.len(), 2);
    let (t0, d0) = body(&ev[0]);
    let (_, d1) = body(&ev[1]);
    assert_eq!(t0, vec![symbol("colliding").unwrap()]);
    let mut k0 = map_keys(&d0);
    k0.sort();
    let mut want0 = vec![ScVal::U32(1), string("1"), symbol("1").unwrap()];
    want0.sort();
    assert_eq!(k0, want0);
    let mut k1 = map_keys(&d1);
    k1.sort();
    let mut want1 = vec![ScVal::Bool(true), ScVal::U32(1), ScVal::I32(1)];
    want1.sort();
    assert_eq!(k1, want1);

    // nested_vec(99): event data is Void wrapped in 99 vectors.
    let (sim, out) = invoke(
        &mut node,
        &a,
        &emitter,
        "nested_vec",
        vec![ScVal::U32(99)],
        AuthMode::Record,
        100,
        simulation_seed("r18-contract-calls/nested_vec"),
    )
    .unwrap();
    let ev = events(&out, &sim.contract_events, "nested_vec");
    let (t, mut v) = body(&ev[0]);
    assert_eq!(t, vec![symbol("nested").unwrap()]);
    let mut depth = 0;
    while let ScVal::Vec(Some(ScVec(inner))) = v {
        assert_eq!(inner.len(), 1);
        v = inner[0].clone();
        depth += 1;
    }
    assert_eq!((depth, v), (99, ScVal::Void));

    // transfer(A, B, 1000, with_muxed = true, to_muxed_id = Void): a token-shaped event whose
    // to_muxed_id is Void.
    let (aa, ba) = (
        ScVal::Address(account_address(&a)),
        ScVal::Address(account_address(&b)),
    );
    let args = vec![
        aa.clone(),
        ba.clone(),
        i128_val(1000),
        ScVal::Bool(true),
        ScVal::Void,
    ];
    let (sim, out) = invoke(
        &mut node,
        &a,
        &emitter,
        "transfer",
        args,
        AuthMode::Record,
        100,
        simulation_seed("r18-contract-calls/transfer"),
    )
    .unwrap();
    let ev = events(&out, &sim.contract_events, "transfer");
    let (t, data) = body(&ev[0]);
    assert_eq!(t, vec![symbol("transfer").unwrap(), aa.clone(), ba.clone()]);
    let ScVal::Map(Some(m)) = &data else {
        panic!("{data:?}")
    };
    let entries: Vec<_> = m.iter().map(|e| (e.key.clone(), e.val.clone())).collect();
    assert_eq!(
        entries,
        vec![
            (symbol("amount").unwrap(), i128_val(1000)),
            (symbol("to_muxed_id").unwrap(), ScVal::Void)
        ]
    );

    // forged_sac_event(transfer, [A, B], "USDC:<I>", 1000): SAC layout from a contract that is not
    // that asset's SAC.
    let asset = format!("USDC:{}", i.address());
    let args = vec![
        symbol("transfer").unwrap(),
        ScVal::Vec(Some(ScVec(
            vec![aa.clone(), ba.clone()].try_into().unwrap(),
        ))),
        string(&asset),
        i128_val(1000),
    ];
    let (sim, out) = invoke(
        &mut node,
        &a,
        &emitter,
        "forged_sac_event",
        args,
        AuthMode::Record,
        100,
        simulation_seed("r18-contract-calls/forged_sac_event"),
    )
    .unwrap();
    let ev = events(&out, &sim.contract_events, "forged_sac_event");
    let (t, data) = body(&ev[0]);
    assert_eq!(t, vec![symbol("transfer").unwrap(), aa, ba, string(&asset)]);
    assert_eq!(data, i128_val(1000));
    assert_eq!(ev[0].contract_id.as_ref(), Some(emitter_id));
    let sac = xdrcheck_gen::soroban::Sac::new(
        passphrase,
        stellar_xdr::Asset::CreditAlphanum4(stellar_xdr::AlphaNum4 {
            asset_code: stellar_xdr::AssetCode4(*b"USDC"),
            issuer: i.account_id(),
        }),
    )
    .unwrap();
    assert_ne!(ev[0].contract_id, Some(ContractId(Hash(sac.contract_id))));

    // auth_nested(account, []) authorized by custom-account `account` with delegate_1, which has its
    // own delegate delegate_2 (CAP-0071), all signatures arbitrary values.
    let account = addr("account");
    let call_args = vec![
        ScVal::Address(account.clone()),
        ScVal::Vec(Some(ScVec::default())),
    ];
    let entry = delegated_auth(
        account.clone(),
        71,
        node.last_closed() + 100,
        ScVal::Void,
        &[Delegate {
            address: addr("delegate_1"),
            signature: ScVal::U32(1),
            nested: vec![Delegate {
                address: addr("delegate_2"),
                signature: ScVal::U32(2),
                nested: vec![],
            }],
        }],
        invoke_args(&emitter, "auth_nested", call_args.clone()).unwrap(),
    )
    .unwrap();
    let (sim, out) = invoke(
        &mut node,
        &a,
        &emitter,
        "auth_nested",
        call_args,
        AuthMode::Enforce(vec![entry]),
        100,
        simulation_seed("r18-contract-calls/auth_nested"),
    )
    .unwrap();
    assert!(matches!(
        sim.auth[0].credentials,
        SorobanCredentials::AddressWithDelegates(_)
    ));
    let ev = events(&out, &sim.contract_events, "auth_nested");
    let checks: Vec<(Option<ContractId>, ScVal)> = ev
        .iter()
        .filter(|e| body(e).0 == vec![ScVal::Symbol(ScSymbol("check_auth".try_into().unwrap()))])
        .map(|e| (e.contract_id.clone(), body(e).1))
        .collect();
    let id = |n: &str| match addr(n) {
        ScAddress::Contract(c) => Some(c),
        _ => None,
    };
    for (who, delegates) in [("account", 1), ("delegate_1", 1), ("delegate_2", 0)] {
        assert!(
            checks.contains(&(id(who), ScVal::U32(delegates))),
            "{who} ran __check_auth with {delegates} delegates: {checks:?}"
        );
    }

    node.close().unwrap();
    node.stop().unwrap();
    assert!(common::processes_in(&dir).is_empty());
    let stream = std::fs::read(dir.join("meta.xdr")).unwrap();
    let hashes = xdrcheck_xdr::split_ledger_stream(
        &stream,
        &xdrcheck_xdr::Limits::default(),
        &xdrcheck_xdr::Gate::default(),
    )
    .unwrap()
    .iter()
    .map(|(info, _)| info.header_hash)
    .collect();
    std::fs::remove_dir_all(&dir).unwrap();
    hashes
}

fn reproducible(protocol: u32) {
    let Some(bin) = common::core_or_skip(&format!("contract_calls_p{protocol}")) else {
        return;
    };
    for passphrase in [TESTNET_PASSPHRASE, PUBNET_PASSPHRASE] {
        let a = chain(&bin, passphrase, protocol);
        let b = chain(&bin, passphrase, protocol);
        assert_eq!(a.len(), b.len());
        for (k, (x, y)) in a.iter().zip(&b).enumerate() {
            assert_eq!(
                hex::encode(x),
                hex::encode(y),
                "protocol {protocol} {passphrase:?}: ledger {} differs between runs",
                k + 2
            );
        }
        eprintln!(
            "protocol {protocol} {passphrase:?}: {} ledgers identical across two runs, last header {}",
            a.len(),
            hex::encode(a.last().unwrap())
        );
    }
}

#[test]
fn contract_calls_p29() {
    reproducible(29);
}

#[test]
fn contract_calls_p30() {
    reproducible(30);
}
