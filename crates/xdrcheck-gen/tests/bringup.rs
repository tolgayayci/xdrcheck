//! Bring-up to every supported protocol (1–19 without Soroban settings, 21–30 with the vendored
//! sets) with the natively built, fixed-salt settings upgrade gives identical header hashes for
//! every ledger across two runs on each passphrase, and from Protocol 21 the resulting network
//! accepts a Stellar Asset Contract deploy. Also: the native transactions are
//! exactly what stellar-core's own `get-settings-upgrade-txs` builds, once its random salt is replaced.

mod common;

use stellar_xdr::{
    Asset, ContractExecutable, ContractIdPreimage, CreateContractArgs, HostFunction,
    InvokeHostFunctionOp, LedgerCloseMeta, LedgerEntryChange, LedgerEntryData, LedgerFootprint,
    Limits, Memo, Operation, OperationBody, Preconditions, ReadXdr, SequenceNumber,
    SorobanResources, SorobanTransactionData, SorobanTransactionDataExt, Transaction,
    TransactionEnvelope, TransactionExt, TransactionMeta, TransactionResultResult, WriteXdr,
};
use xdrcheck_gen::core::{
    sign_transaction, CoreBinary, Keypair, Node, NodeOptions, PUBNET_PASSPHRASE, TESTNET_PASSPHRASE,
};
use xdrcheck_gen::upgrade::{
    bring_up, contract_id, contract_instance_key, settings_upgrade_txs, upgrade_contract_wasm,
    ProtocolSettings,
};

/// Deploy the native asset's Stellar Asset Contract from root; the minimal Soroban transaction.
fn deploy_native_sac(node: &mut Node) -> [u8; 32] {
    let pp = node.passphrase().to_string();
    let root = Keypair::root(&pp);
    let seq = node.account_sequence(&root.account_id()).unwrap().unwrap();
    let preimage = ContractIdPreimage::Asset(Asset::Native);
    let id = contract_id(&pp, preimage.clone()).unwrap();
    let resource_fee = 10_000_000;
    let tx = Transaction {
        source_account: root.muxed_account(),
        fee: 1_000 + resource_fee as u32,
        seq_num: SequenceNumber(seq + 1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::CreateContract(CreateContractArgs {
                    contract_id_preimage: preimage,
                    executable: ContractExecutable::StellarAsset,
                }),
                auth: vec![].try_into().unwrap(),
            }),
        }]
        .try_into()
        .unwrap(),
        ext: TransactionExt::V1(SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: vec![].try_into().unwrap(),
                    read_write: vec![contract_instance_key(id)].try_into().unwrap(),
                },
                instructions: 10_000_000,
                disk_read_bytes: 10_000,
                write_bytes: 10_000,
            },
            resource_fee,
        }),
    };
    let env = sign_transaction(&pp, tx, &[&root]).unwrap();
    let hash = node.submit_pending(&env).unwrap();
    let l = node.close().unwrap();
    let r = l
        .result_of(&hash)
        .unwrap()
        .expect("deploy is in the ledger");
    assert!(
        matches!(r.result, TransactionResultResult::TxSuccess(_)),
        "SAC deploy on {pp}: {r:?}"
    );
    // The deploy wrote the contract instance.
    let operations = match l.decode().unwrap() {
        LedgerCloseMeta::V0(m) => m.tx_processing[0].tx_apply_processing.clone(),
        LedgerCloseMeta::V1(m) => m.tx_processing[0].tx_apply_processing.clone(),
        LedgerCloseMeta::V2(m) => m.tx_processing[0].tx_apply_processing.clone(),
    };
    let changes: Vec<LedgerEntryChange> = match operations {
        TransactionMeta::V3(m) => m.operations[0].changes.to_vec(),
        TransactionMeta::V4(m) => m.operations[0].changes.to_vec(),
        other => panic!("TransactionMeta {other:?} after a Soroban deploy"),
    };
    let created_instance = changes.iter().any(|c| {
        matches!(c, LedgerEntryChange::Created(e) if matches!(&e.data, LedgerEntryData::ContractData(_)))
    });
    assert!(created_instance, "the deploy created the instance entry");
    id
}

/// One chain: bring-up to `protocol`, a SAC deploy, one empty close. Returns every header hash.
fn chain(bin: &CoreBinary, passphrase: &str, protocol: u32) -> Vec<(u32, [u8; 32])> {
    let dir = common::run_dir(&format!("p{protocol}"));
    let mut node = Node::start(bin, &dir, NodeOptions::new(passphrase)).unwrap();
    let b = bring_up(&mut node, protocol).unwrap();
    let soroban = protocol >= 20;
    assert_eq!(b.ledgers.len(), if soroban { 11 } else { 1 });
    for (k, l) in b.ledgers.iter().enumerate() {
        assert_eq!(l.ledger.sequence, 2 + k as u32);
        assert_eq!(l.ledger.protocol, protocol);
    }
    // The upgrade ledger is v0 (meta follows the pre-upgrade protocol); the rest are v1 from
    // Protocol 20 and v2 from Protocol 23.
    assert_eq!(b.ledgers[0].ledger.ledger_close_meta_version, 0);
    let later = if protocol >= 23 { 2 } else { 1 };
    assert!(b.ledgers[1..]
        .iter()
        .all(|l| l.ledger.ledger_close_meta_version == later));
    if soroban {
        deploy_native_sac(&mut node);
    } else {
        node.close().unwrap();
    }
    node.close().unwrap();
    node.stop().unwrap();
    assert!(common::processes_in(&dir).is_empty());

    let stream = std::fs::read(dir.join("meta.xdr")).unwrap();
    let ledgers = xdrcheck_xdr::split_ledger_stream(
        &stream,
        &xdrcheck_xdr::Limits::default(),
        &xdrcheck_xdr::Gate::default(),
    )
    .unwrap();
    assert_eq!(ledgers.len(), b.ledgers.len() + 2);
    std::fs::remove_dir_all(&dir).unwrap();
    ledgers
        .iter()
        .map(|(i, _)| (i.sequence, i.header_hash))
        .collect()
}

fn reproducible(protocol: u32) {
    let Some(bin) = common::core_or_skip(&format!("bring_up_p{protocol}")) else {
        return;
    };
    let mut twins = Vec::new();
    for passphrase in [TESTNET_PASSPHRASE, PUBNET_PASSPHRASE] {
        let a = chain(&bin, passphrase, protocol);
        let b = chain(&bin, passphrase, protocol);
        for ((sa, ha), (sb, hb)) in a.iter().zip(&b) {
            assert_eq!(sa, sb);
            assert_eq!(
                hex::encode(ha),
                hex::encode(hb),
                "protocol {protocol} {passphrase:?}: ledger {sa} header hash differs between runs"
            );
        }
        eprintln!(
            "protocol {protocol} {passphrase:?}: {} ledgers identical across two runs, last header {}",
            a.len(),
            hex::encode(a.last().unwrap().1)
        );
        twins.push(a);
    }
    assert_ne!(twins[0].last(), twins[1].last(), "passphrase twins differ");
}

#[test]
fn bring_up_p13() {
    reproducible(13);
}

#[test]
fn bring_up_p19() {
    reproducible(19);
}

#[test]
fn bring_up_p21() {
    reproducible(21);
}

#[test]
fn bring_up_p22() {
    reproducible(22);
}

#[test]
fn bring_up_p23() {
    reproducible(23);
}

#[test]
fn bring_up_p24() {
    reproducible(24);
}

#[test]
fn bring_up_p25() {
    reproducible(25);
}

#[test]
fn protocol_20_is_refused() {
    assert!(!xdrcheck_gen::upgrade::supported_protocol(20));
    assert!(xdrcheck_gen::upgrade::supported_protocol(13));
}

#[test]
fn bring_up_p26() {
    reproducible(26);
}

#[test]
fn bring_up_p27() {
    reproducible(27);
}

#[test]
fn bring_up_p28() {
    reproducible(28);
}

#[test]
fn bring_up_p29() {
    reproducible(29);
}

#[test]
fn bring_up_p30() {
    reproducible(30);
}

/// Our transactions equal stellar-core's `get-settings-upgrade-txs` output byte for byte once the helper's
/// random salt is put into ours: restore and upload directly, create, invoke and the key with its salt.
#[test]
fn native_txs_match_core_helper() {
    let Some(bin) = common::core_or_skip("native_txs_match_core_helper") else {
        return;
    };
    let wasm = upgrade_contract_wasm().unwrap();
    for passphrase in [TESTNET_PASSPHRASE, PUBNET_PASSPHRASE] {
        let root = Keypair::root(passphrase);
        for set in &ProtocolSettings::for_protocol(30).unwrap().sets {
            let seq = 12345;
            let b64 = set.decode().unwrap().to_xdr_base64(Limits::none()).unwrap();
            let mut child = bin
                .command()
                .arg("get-settings-upgrade-txs")
                .arg(root.address())
                .arg(seq.to_string())
                .arg(passphrase)
                .arg("--xdr")
                .arg(&b64)
                .arg("--signtxs")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            use std::io::Write;
            writeln!(child.stdin.take().unwrap(), "{}", root.secret_seed()).unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success());
            let lines: Vec<String> = String::from_utf8(out.stdout)
                .unwrap()
                .lines()
                .map(str::to_string)
                .collect();
            assert_eq!(lines.len(), 9, "{lines:?}");
            let env =
                |i: usize| TransactionEnvelope::from_xdr_base64(&lines[i], Limits::none()).unwrap();
            // The helper's salt, read from its create transaction.
            let TransactionEnvelope::Tx(create) = env(4) else {
                panic!()
            };
            let OperationBody::InvokeHostFunction(op) = &create.tx.operations[0].body else {
                panic!()
            };
            let HostFunction::CreateContract(args) = &op.host_function else {
                panic!()
            };
            let ContractIdPreimage::Address(a) = &args.contract_id_preimage else {
                panic!()
            };
            let ours =
                settings_upgrade_txs(passphrase, &root, seq, wasm, &set.upgrade_set, a.salt.0)
                    .unwrap();
            for (i, (name, e)) in ours.in_order().iter().enumerate() {
                assert_eq!(
                    e.to_xdr_base64(Limits::none()).unwrap(),
                    lines[2 * i],
                    "{} {name} on {passphrase:?}",
                    set.file
                );
                assert_eq!(
                    hex::encode(e.hash(xdrcheck_gen::core::network_id(passphrase)).unwrap()),
                    lines[2 * i + 1],
                    "{} {name} tx id",
                    set.file
                );
            }
            assert_eq!(ours.key_base64().unwrap(), lines[8], "{} key", set.file);
        }
    }
}
