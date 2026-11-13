//! On a fresh Protocol 28 and Protocol 30 node, on each passphrase, issue an asset,
//! deploy its Stellar Asset Contract, `trust(B)` for an account with no trustline, `mint` to B, `transfer`
//! to a muxed account (and at Protocol 30 to a muxed contract `W…`), `approve` and `balance` — all with
//! declared footprints and fixed resources, all `tx_success` — and regenerate with identical header
//! hashes.
//!
//! The setup (fund, classic trustline, SAC deploy) and the `trust` step run through the scenario
//! interpreter, so the scenario route (`SetupAction::DeploySac`, SEP-51 step templates) is exercised;
//! the remaining calls use the `soroban` API directly. Expected values come from the calls' intent and
//! CAP-0067/0073/0084, never from a reader.

mod common;

use stellar_xdr::{
    ContractEvent, ContractEventBody, ContractId, Hash, LedgerEntryChange, LedgerEntryData,
    ScAddress, ScVal, TransactionEnvelope, TrustLineAsset,
};
use xdrcheck_gen::core::{Keypair, Node, NodeOptions, PUBNET_PASSPHRASE, TESTNET_PASSPHRASE};
use xdrcheck_gen::scenario::{Interpreter, Item, Options, Scenario, SetupAction};
use xdrcheck_gen::soroban::{
    account_address, call_sac, i128_val, muxed_account_address, muxed_contract_address,
    run_deploy_sac, symbol, Sac, SacCall, TxOutcome,
};
use xdrcheck_gen::upgrade::bring_up;

const SCENARIO: &str = r#"
scenario: r10-sac-calls
caps: [73, 67, 84]
protocols: [28, 30]
profile: lake
actors: [I, A, B]
assets:
  USDC: {credit_alphanum4: {asset_code: USDC, issuer: "${acct.I}"}}
setup:
  - fund: {I: "10000", A: "10000", B: "10000"}
  - trust: {A: USDC}
  - deploy_sac: USDC
steps:
  - id: sac-trust
    entry: cap-0073/sac-trust-creates-trustline
    tx:
      source_account: "${acct.B}"
      fee: 50001016
      seq_num: "${seq.B}"
      cond: none
      memo: none
      operations:
        - source_account: null
          body:
            invoke_host_function:
              host_function:
                invoke_contract:
                  contract_address: "${contract.sac(USDC)}"
                  function_name: trust
                  args: [{address: "${acct.B}"}]
              auth:
                - credentials: source_account
                  root_invocation:
                    function:
                      contract_fn:
                        contract_address: "${contract.sac(USDC)}"
                        function_name: trust
                        args: [{address: "${acct.B}"}]
                    sub_invocations: []
      ext:
        v1:
          ext: v0
          resources:
            footprint:
              read_only:
                - contract_data: {contract: "${contract.sac(USDC)}", key: ledger_key_contract_instance, durability: persistent}
                - account: {account_id: "${acct.I}"}
              read_write:
                - trustline: {account_id: "${acct.B}", asset: "${asset.USDC}"}
                - account: {account_id: "${acct.B}"}
            instructions: 50000000
            disk_read_bytes: 20000
            write_bytes: 20000
          resource_fee: "50000000"
    soroban_resources: declared
    sign: [{key: B}]
    expect_result: tx_success
"#;

fn op_event(out: &TxOutcome, n: usize) -> (Vec<ScVal>, ScVal) {
    let events: Vec<ContractEvent> = out.op_events(0);
    let ContractEventBody::V0(e) = &events[n].body;
    (e.topics.to_vec(), e.data.clone())
}

fn map_get(data: &ScVal, key: &str) -> Option<ScVal> {
    let ScVal::Map(Some(m)) = data else {
        return None;
    };
    m.iter()
        .find(|e| e.key == symbol(key).unwrap())
        .map(|e| e.val.clone())
}

/// One chain; returns every ledger header hash after bring-up.
fn chain(bin: &xdrcheck_gen::core::CoreBinary, passphrase: &str, protocol: u32) -> Vec<[u8; 32]> {
    let dir = common::run_dir(&format!("sac-p{protocol}"));
    let mut node = Node::start(bin, &dir, NodeOptions::new(passphrase)).unwrap();
    bring_up(&mut node, protocol).unwrap();
    let root = Keypair::root(passphrase);
    let scenario = Scenario::from_yaml_str(SCENARIO).unwrap();
    let options = Options {
        root_sequence: node.account_sequence(&root.account_id()).unwrap().unwrap(),
        ..Options::default()
    };
    let mut it = Interpreter::new(&scenario, passphrase, protocol, options).unwrap();
    let mut sac: Option<Sac> = None;
    let mut trust: Option<TxOutcome> = None;
    while let Some(item) = it.next_item() {
        let item = item.unwrap();
        match item {
            Item::Setup(s) => {
                assert_eq!(
                    s.ledger,
                    node.last_closed() + 1,
                    "setup[{}] planned ledger",
                    s.index
                );
                match &s.action {
                    SetupAction::Tx(b) => {
                        let out = submit_close(&mut node, &b.envelope.envelope);
                        assert!(out.succeeded(), "setup {}: {:?}", s.kind, out.result);
                    }
                    SetupAction::DeploySac { .. } => {
                        let (deployed, out) =
                            run_deploy_sac(&mut node, &mut it, &s.action, 100).unwrap();
                        assert!(out.succeeded());
                        sac = Some(deployed);
                    }
                    other => panic!("unexpected setup item {other:?}"),
                }
            }
            Item::Step(st) => {
                assert_eq!(st.ledger, node.last_closed() + 1);
                let out = submit_close(&mut node, &st.tx.as_ref().unwrap().envelope.envelope);
                assert_eq!(st.expected.result.as_deref(), Some("tx_success"));
                assert!(out.succeeded(), "{}: {:?}", st.id, out.result);
                trust = Some(out);
            }
        }
    }
    let sac = sac.unwrap();
    let (i, a, b) = (
        Keypair::from_label("I"),
        Keypair::from_label("A"),
        Keypair::from_label("B"),
    );
    assert_eq!(
        it.keys().address("B").unwrap(),
        b.address(),
        "one key derivation"
    );

    // trust(B): a created trustline (balance 0, limit i64::MAX, flags 1 = authorized), no contract
    // event for the trust itself, TransactionMeta v4.
    let trust = trust.unwrap();
    assert_eq!(trust.meta_version(), 4);
    assert!(
        trust.op_events(0).is_empty(),
        "trust emits no contract event"
    );
    let created: Vec<_> = trust
        .op_changes(0)
        .into_iter()
        .filter_map(|c| match c {
            LedgerEntryChange::Created(e) => match e.data {
                LedgerEntryData::Trustline(t) => Some(t),
                _ => None,
            },
            _ => None,
        })
        .collect();
    assert_eq!(created.len(), 1, "one trustline created");
    let tl = &created[0];
    assert_eq!(tl.account_id, b.account_id());
    assert!(matches!(&tl.asset, TrustLineAsset::CreditAlphanum4(x) if x.asset_code.0 == *b"USDC"));
    assert_eq!((tl.balance, tl.limit, tl.flags), (0, i64::MAX, 1));

    // mint(B) by the issuer.
    let minted = 10_000_000;
    let out = call_sac(
        &mut node,
        &i,
        &sac,
        &SacCall::Mint {
            to: account_address(&b),
            amount: minted,
        },
        100,
    )
    .unwrap();
    assert!(out.succeeded(), "mint: {:?}", out.result);
    let (topics, data) = op_event(&out, 0);
    assert_eq!(topics[0], symbol("mint").unwrap());
    assert_eq!(data, i128_val(minted));

    // transfer(B → M(A, 42)): the event names A's G address and carries to_muxed_id (CAP-0067).
    let out = call_sac(
        &mut node,
        &b,
        &sac,
        &SacCall::Transfer {
            from: account_address(&b),
            to: muxed_account_address(&a, 42),
            amount: 1234,
        },
        100,
    )
    .unwrap();
    assert!(out.succeeded(), "transfer to M: {:?}", out.result);
    let (topics, data) = op_event(&out, 0);
    assert_eq!(topics[0], symbol("transfer").unwrap());
    assert_eq!(topics[2], ScVal::Address(account_address(&a)));
    assert_eq!(map_get(&data, "to_muxed_id"), Some(ScVal::U64(42)));
    assert_eq!(map_get(&data, "amount"), Some(i128_val(1234)));
    let mut spent = 1234;

    // Protocol 30: transfer(B → W(dest, 2^63)) (CAP-0084). The destination contract need not exist:
    // the SAC writes its Balance entry without reading the destination.
    if protocol >= 30 {
        let dest = xdrcheck_gen::core::keys::sha256(b"xcc/test/dest-contract");
        let out = call_sac(
            &mut node,
            &b,
            &sac,
            &SacCall::Transfer {
                from: account_address(&b),
                to: muxed_contract_address(dest, 1 << 63),
                amount: 777,
            },
            100,
        )
        .unwrap();
        assert!(out.succeeded(), "transfer to W: {:?}", out.result);
        let (topics, data) = op_event(&out, 0);
        assert_eq!(topics[0], symbol("transfer").unwrap());
        assert_eq!(
            topics[2],
            ScVal::Address(ScAddress::Contract(ContractId(Hash(dest))))
        );
        assert_eq!(map_get(&data, "to_muxed_id"), Some(ScVal::U64(1 << 63)));
        spent += 777;
    }

    // approve(B, A, 500, live until 1000 ledgers ahead): a temporary allowance entry.
    let live_until = node.last_closed() + 1000;
    let out = call_sac(
        &mut node,
        &b,
        &sac,
        &SacCall::Approve {
            from: account_address(&b),
            spender: account_address(&a),
            amount: 500,
            live_until_ledger: live_until,
        },
        100,
    )
    .unwrap();
    assert!(out.succeeded(), "approve: {:?}", out.result);
    assert_eq!(op_event(&out, 0).0[0], symbol("approve").unwrap());
    assert!(out.op_changes(0).iter().any(|c| matches!(c,
        LedgerEntryChange::Created(e) if matches!(&e.data, LedgerEntryData::ContractData(_)))));

    // balance(B), read-only, called by A: minted minus what B sent.
    let out = call_sac(
        &mut node,
        &a,
        &sac,
        &SacCall::Balance {
            id: account_address(&b),
        },
        100,
    )
    .unwrap();
    assert!(out.succeeded(), "balance: {:?}", out.result);
    assert_eq!(out.return_value(), Some(i128_val(minted - spent)));

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

fn submit_close(node: &mut Node, env: &TransactionEnvelope) -> TxOutcome {
    let hash = node.submit_pending(env).unwrap();
    let ledger = node.close().unwrap();
    TxOutcome::read(&ledger, &hash).unwrap()
}

fn reproducible(protocol: u32) {
    let Some(bin) = common::core_or_skip(&format!("sac_calls_p{protocol}")) else {
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
fn sac_calls_p28() {
    reproducible(28);
}

#[test]
fn sac_calls_p30() {
    reproducible(30);
}
