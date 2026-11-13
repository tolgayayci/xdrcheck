//! Entry attributes, claimants, amount-less events, token-event fields and target scope: facts from
//! hand-built ledgers, then verdicts on rows derived from them, each with a planted bug.
#![allow(dead_code, clippy::type_complexity)]

use stellar_xdr::*;
use xdrcheck_judge::facts::{judge_ledger, Fact, Options};
use xdrcheck_judge::read::{contract_strkey, network_id, sac_contract_id, MAINNET};
use xdrcheck_judge::verdict;

fn acct(n: u8) -> AccountId {
    AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([n; 32])))
}

fn account(n: u8, balance: i64) -> LedgerEntry {
    LedgerEntry {
        last_modified_ledger_seq: 1,
        data: LedgerEntryData::Account(AccountEntry {
            account_id: acct(n),
            balance,
            ..Default::default()
        }),
        ext: LedgerEntryExt::V0,
    }
}

fn usdc() -> Asset {
    Asset::CreditAlphanum4(AlphaNum4 {
        asset_code: AssetCode4(*b"USDC"),
        issuer: acct(9),
    })
}

fn i128v(n: i128) -> ScVal {
    ScVal::I128(Int128Parts {
        hi: (n >> 64) as i64,
        lo: n as u64,
    })
}

fn sym(s: &str) -> ScVal {
    ScVal::Symbol(ScSymbol(s.try_into().unwrap()))
}

fn contract_addr(id: [u8; 32]) -> ScAddress {
    ScAddress::Contract(ContractId(Hash(id)))
}

/// A `[Balance, holder]` entry of contract `cid` with a SAC-shaped value.
fn balance_entry(cid: [u8; 32], holder: ScAddress, amount: i128) -> LedgerEntry {
    let val = ScVal::Map(Some(
        vec![
            ScMapEntry {
                key: sym("amount"),
                val: i128v(amount),
            },
            ScMapEntry {
                key: sym("authorized"),
                val: ScVal::Bool(true),
            },
            ScMapEntry {
                key: sym("clawback"),
                val: ScVal::Bool(false),
            },
        ]
        .try_into()
        .unwrap(),
    ));
    LedgerEntry {
        last_modified_ledger_seq: 1,
        data: LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: contract_addr(cid),
            key: ScVal::Vec(Some(
                vec![sym("Balance"), ScVal::Address(holder)]
                    .try_into()
                    .unwrap(),
            )),
            durability: ContractDataDurability::Persistent,
            val,
        }),
        ext: LedgerEntryExt::V0,
    }
}

fn event(cid: [u8; 32], topics: Vec<ScVal>, data: ScVal) -> ContractEvent {
    ContractEvent {
        ext: ExtensionPoint::V0,
        contract_id: Some(ContractId(Hash(cid))),
        type_: ContractEventType::Contract,
        body: ContractEventBody::V0(ContractEventV0 {
            topics: topics.try_into().unwrap(),
            data,
        }),
    }
}

fn changes(v: Vec<LedgerEntryChange>) -> LedgerEntryChanges {
    LedgerEntryChanges(v.try_into().unwrap())
}

struct Tx {
    source: MuxedAccount,
    ops: Vec<Operation>,
    success: bool,
    fee_charged: i64,
    fee: Vec<LedgerEntryChange>,
    ops_meta: Vec<(Vec<LedgerEntryChange>, Vec<ContractEvent>)>,
    refund: Vec<LedgerEntryChange>,
}

fn payment_op(to: MuxedAccount, amount: i64) -> Operation {
    Operation {
        source_account: None,
        body: OperationBody::Payment(PaymentOp {
            destination: to,
            asset: Asset::Native,
            amount,
        }),
    }
}

fn ledger(protocol: u32, txs: Vec<Tx>) -> LedgerCloseMeta {
    let nid = network_id(MAINNET);
    let mut envs = Vec::new();
    let mut metas = Vec::new();
    for (i, t) in txs.into_iter().enumerate() {
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: Transaction {
                source_account: t.source,
                fee: 100,
                seq_num: SequenceNumber(i as i64 + 1),
                operations: t.ops.try_into().unwrap(),
                ..Default::default()
            },
            signatures: VecM::default(),
        });
        let hash = env.hash(nid).unwrap();
        let ops_n = t.ops_meta.len();
        let op_results: Vec<OperationResult> = (0..ops_n)
            .map(|_| OperationResult::OpInner(OperationResultTr::Payment(PaymentResult::Success)))
            .collect();
        let result = TransactionResult {
            fee_charged: t.fee_charged,
            result: if t.success {
                TransactionResultResult::TxSuccess(op_results.try_into().unwrap())
            } else {
                TransactionResultResult::TxFailed(op_results.try_into().unwrap())
            },
            ext: TransactionResultExt::V0,
        };
        let meta = TransactionMeta::V4(TransactionMetaV4 {
            ext: ExtensionPoint::V0,
            tx_changes_before: changes(vec![]),
            operations: t
                .ops_meta
                .into_iter()
                .map(|(c, e)| OperationMetaV2 {
                    ext: ExtensionPoint::V0,
                    changes: changes(c),
                    events: e.try_into().unwrap(),
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            tx_changes_after: changes(vec![]),
            soroban_meta: None,
            events: VecM::default(),
            diagnostic_events: VecM::default(),
        });
        metas.push(TransactionResultMetaV1 {
            ext: ExtensionPoint::V0,
            result: TransactionResultPair {
                transaction_hash: Hash(hash),
                result,
            },
            fee_processing: changes(t.fee),
            tx_apply_processing: meta,
            post_tx_apply_fee_processing: changes(t.refund),
        });
        envs.push(env);
    }
    let mut v2 = LedgerCloseMetaV2::default();
    v2.ledger_header.header.ledger_seq = 1000;
    v2.ledger_header.header.ledger_version = protocol;
    v2.tx_set = GeneralizedTransactionSet::V1(TransactionSetV1 {
        previous_ledger_hash: Hash([0; 32]),
        phases: vec![TransactionPhase::V0(
            vec![TxSetComponent::TxsetCompTxsMaybeDiscountedFee(
                TxSetComponentTxsMaybeDiscountedFee {
                    base_fee: None,
                    txs: envs.try_into().unwrap(),
                },
            )]
            .try_into()
            .unwrap(),
        )]
        .try_into()
        .unwrap(),
    });
    v2.tx_processing = metas.try_into().unwrap();
    LedgerCloseMeta::V2(v2)
}

fn upd(pre: LedgerEntry, post: LedgerEntry) -> Vec<LedgerEntryChange> {
    vec![
        LedgerEntryChange::State(pre),
        LedgerEntryChange::Updated(post),
    ]
}

fn g(n: u8) -> String {
    acct(n).to_string()
}

fn nop() -> Operation {
    Operation {
        source_account: None,
        body: OperationBody::BumpSequence(BumpSequenceOp {
            bump_to: SequenceNumber(0),
        }),
    }
}

fn signed_payload() -> SignerKey {
    SignerKey::Ed25519SignedPayload(SignerKeyEd25519SignedPayload {
        ed25519: Uint256([7; 32]),
        payload: vec![1u8, 2, 3, 4, 5].try_into().unwrap(),
    })
}

fn with_signers(
    n: u8,
    master: u8,
    signers: Vec<(SignerKey, u32)>,
    flags: u32,
    home: &str,
) -> LedgerEntry {
    let mut e = account(n, 1000);
    if let LedgerEntryData::Account(a) = &mut e.data {
        a.thresholds = Thresholds([master, 1, 2, 3]);
        a.signers = signers
            .into_iter()
            .map(|(key, weight)| Signer { key, weight })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        a.flags = flags;
        a.home_domain = String32(home.as_bytes().try_into().unwrap());
    }
    e
}

fn trustline(n: u8, flags: u32, limit: i64) -> LedgerEntry {
    LedgerEntry {
        last_modified_ledger_seq: 1,
        data: LedgerEntryData::Trustline(TrustLineEntry {
            account_id: acct(n),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"USDC"),
                issuer: acct(9),
            }),
            balance: 0,
            limit,
            flags,
            ext: TrustLineEntryExt::V0,
        }),
        ext: LedgerEntryExt::V0,
    }
}

fn data_entry(n: u8, name: &str, value: &[u8]) -> LedgerEntry {
    LedgerEntry {
        last_modified_ledger_seq: 1,
        data: LedgerEntryData::Data(DataEntry {
            account_id: acct(n),
            data_name: String64(name.as_bytes().try_into().unwrap()),
            data_value: DataValue(value.to_vec().try_into().unwrap()),
            ext: DataEntryExt::V0,
        }),
        ext: LedgerEntryExt::V0,
    }
}

/// One ledger, one transaction: op 0 sets signers of every type, thresholds, flags and home domain on
/// account 1; op 1 creates a trustline (authorized) and a data entry for account 2; op 2 moves the trustline
/// from authorized to authorized-to-maintain-liabilities and removes the data entry.
fn state_ledger() -> Vec<Fact> {
    let before = with_signers(1, 1, vec![], 0, "");
    let after = with_signers(
        1,
        0,
        vec![
            (SignerKey::Ed25519(Uint256([2; 32])), 2),
            (SignerKey::PreAuthTx(Uint256([3; 32])), 3),
            (SignerKey::HashX(Uint256([4; 32])), 4),
            (signed_payload(), 5),
        ],
        3,
        "x.org",
    );
    let mut after = after;
    if let LedgerEntryData::Account(a) = &mut after.data {
        a.thresholds.0[2] = 5; // medium 2 -> 5
    }
    let l = ledger(
        23,
        vec![Tx {
            source: MuxedAccount::Ed25519(Uint256([1; 32])),
            ops: vec![nop(), nop(), nop()],
            success: true,
            fee_charged: 0,
            fee: vec![],
            ops_meta: vec![
                (upd(before, after), vec![]),
                (
                    vec![
                        LedgerEntryChange::Created(trustline(2, 1, 100)),
                        LedgerEntryChange::Created(data_entry(2, "k", b"v1")),
                    ],
                    vec![],
                ),
                (
                    {
                        let mut c = upd(trustline(2, 1, 100), trustline(2, 2, 100));
                        c.push(LedgerEntryChange::State(data_entry(2, "k", b"v1")));
                        c.push(LedgerEntryChange::Removed(
                            data_entry(2, "k", b"v1").to_key(),
                        ));
                        c
                    },
                    vec![],
                ),
            ],
            refund: vec![],
        }],
    );
    judge_ledger(&l, &Options::mainnet()).unwrap()
}

fn fields(f: &[Fact]) -> Vec<(Option<u32>, String, String, Option<String>, Option<String>)> {
    f.iter()
        .filter_map(|x| match x {
            Fact::EntryField(e) => Some((
                e.op_index,
                e.subject.clone(),
                e.field.clone(),
                e.old.clone(),
                e.new.clone(),
            )),
            _ => None,
        })
        .collect()
}

fn s(v: &str) -> Option<String> {
    Some(v.to_string())
}

#[test]
fn entry_fields_carry_full_signer_keys_of_every_type_and_trustline_auth() {
    let f = state_ledger();
    let got = fields(&f);
    let a = format!("account:{}", g(1));
    let master = format!("signer:30{}", hex::encode([1u8; 32]));
    let p_key = format!(
        "signer:78{}{}{}",
        hex::encode([7u8; 32]),
        "00000005",
        "0102030405000000"
    );
    let want_op0 = vec![
        (Some(0), a.clone(), "flags".to_string(), s("0"), s("3")),
        (
            Some(0),
            a.clone(),
            "home_domain".to_string(),
            s(""),
            s(&hex::encode("x.org")),
        ),
        (Some(0), a.clone(), master, s("1"), None),
        (
            Some(0),
            a.clone(),
            format!("signer:30{}", hex::encode([2u8; 32])),
            None,
            s("2"),
        ),
        (Some(0), a.clone(), p_key, None, s("5")),
        (
            Some(0),
            a.clone(),
            format!("signer:98{}", hex::encode([3u8; 32])),
            None,
            s("3"),
        ),
        (
            Some(0),
            a.clone(),
            format!("signer:b8{}", hex::encode([4u8; 32])),
            None,
            s("4"),
        ),
        (
            Some(0),
            a.clone(),
            "threshold:med".to_string(),
            s("2"),
            s("5"),
        ),
    ];
    let op0: Vec<_> = got.iter().filter(|x| x.0 == Some(0)).cloned().collect();
    assert_eq!(op0, want_op0);
    let t = format!("trustline:{}:USDC:{}", g(2), g(9));
    let d = format!("data:{}:{}", g(2), hex::encode("k"));
    let op12: Vec<_> = got.iter().filter(|x| x.0 != Some(0)).cloned().collect();
    assert_eq!(
        op12,
        vec![
            (Some(1), t.clone(), "flags".into(), None, s("1")),
            (Some(1), t.clone(), "limit".into(), None, s("100")),
            (
                Some(1),
                d.clone(),
                "value".into(),
                None,
                s(&hex::encode("v1"))
            ),
            (Some(2), t.clone(), "flags".into(), s("1"), s("2")),
        ]
    );
    // The trustline's entry facts name the asset's SAC id.
    let nid = network_id(MAINNET);
    let c = contract_strkey(&sac_contract_id(&usdc(), nid));
    assert!(f.iter().any(|x| matches!(x, Fact::EntryChange(e)
        if e.subject == t && e.asset_contract.as_deref() == Some(c.as_str()))));
}

// ---- verdicts ----

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("xdrcheck-judge-test-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

fn run(
    tag: &str,
    facts: &[Fact],
    rows: &[serde_json::Value],
    scope: Option<&str>,
) -> (Vec<serde_json::Value>, verdict::Summary) {
    let fp = tmp(&format!("{tag}.facts.jsonl"));
    let rp = tmp(&format!("{tag}.rows.jsonl"));
    let op = tmp(&format!("{tag}.verdicts.jsonl"));
    let mut fs = String::new();
    for f in facts {
        fs.push_str(&serde_json::to_string(f).unwrap());
        fs.push('\n');
    }
    std::fs::write(&fp, fs).unwrap();
    let mut rs = String::new();
    for r in rows {
        rs.push_str(&serde_json::to_string(r).unwrap());
        rs.push('\n');
    }
    std::fs::write(&rp, rs).unwrap();
    let scope = scope.map(|t| {
        let p = tmp(&format!("{tag}.scope.toml"));
        std::fs::write(&p, t).unwrap();
        xdrcheck_judge::scope::load(&p).unwrap()
    });
    let cfg = verdict::Config {
        scope,
        ..Default::default()
    };
    let sum = verdict::run(&fp, &rp, &op, &cfg).unwrap();
    let out = std::fs::read_to_string(&op)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    (out, sum)
}

fn classes(v: &[serde_json::Value]) -> Vec<String> {
    let mut c: Vec<String> = v
        .iter()
        .filter(|x| x["verdict"] != "ok")
        .map(|x| {
            format!(
                "{} {}",
                x["verdict"].as_str().unwrap(),
                x["class"].as_str().unwrap()
            )
        })
        .collect();
    c.sort();
    c
}

const ENTRY_SCOPE: &str = r#"
target = "toy"
[kinds.entry_change]
lifecycle = ["account:created", "account:removed", "trustline:created", "trustline:removed",
             "data:created", "data:removed"]
fields = ["account:signer", "account:threshold", "account:flags", "account:home_domain",
          "trustline:limit", "trustline:flags", "data:value"]
"#;

/// The rows a correct state-change exporter writes for `state_ledger` (wallet-backend style).
fn entry_rows() -> Vec<serde_json::Value> {
    use serde_json::json;
    let a = g(1);
    let row = |op: u32, v: serde_json::Value| {
        let mut r = json!({"kind": "entry_change", "ledger": 1000, "tx_index": 0, "op_index": op});
        r.as_object_mut()
            .unwrap()
            .extend(v.as_object().unwrap().clone());
        r
    };
    let nid = network_id(MAINNET);
    let token = contract_strkey(&sac_contract_id(&usdc(), nid));
    vec![
        row(
            0,
            json!({"entry_type": "account", "account": a, "field": format!("signer:30{}", hex::encode([2u8; 32])), "new": "2"}),
        ),
        row(
            0,
            json!({"entry_type": "account", "account": a, "field": format!("signer:98{}", hex::encode([3u8; 32])), "new": "3"}),
        ),
        row(
            0,
            json!({"entry_type": "account", "account": a, "field": format!("signer:b8{}", hex::encode([4u8; 32])), "new": "4"}),
        ),
        row(
            0,
            json!({"entry_type": "account", "account": a, "field": format!("signer:78{}000000050102030405000000", hex::encode([7u8; 32])), "new": "5"}),
        ),
        row(
            0,
            json!({"entry_type": "account", "account": a, "field": format!("signer:30{}", hex::encode([1u8; 32])), "old": "1"}),
        ),
        row(
            0,
            json!({"entry_type": "account", "account": a, "field": "flags:set", "new": "3"}),
        ),
        row(
            0,
            json!({"entry_type": "account", "account": a, "field": "home_domain", "new": hex::encode("x.org")}),
        ),
        row(
            1,
            json!({"entry_type": "trustline", "account": g(2), "token": token, "change": "created"}),
        ),
        row(
            1,
            json!({"entry_type": "trustline", "account": g(2), "token": token, "field": "limit", "new": "100"}),
        ),
        row(
            1,
            json!({"entry_type": "trustline", "account": g(2), "token": token, "field": "flags:set", "new": "1"}),
        ),
        row(
            1,
            json!({"entry_type": "data", "account": g(2), "data_name": "k", "change": "created"}),
        ),
        row(
            1,
            json!({"entry_type": "data", "account": g(2), "data_name": "k", "field": "value", "new": hex::encode("v1")}),
        ),
        row(
            2,
            json!({"entry_type": "trustline", "account": g(2), "token": token, "field": "flags:set", "new": "2"}),
        ),
        row(
            2,
            json!({"entry_type": "trustline", "account": g(2), "token": token, "field": "flags:clear", "new": "1"}),
        ),
        row(
            2,
            json!({"entry_type": "data", "account": g(2), "data_name": "k", "change": "removed"}),
        ),
        row(
            0,
            json!({"entry_type": "account", "account": a, "field": "threshold:med", "old": "2", "new": "5"}),
        ),
    ]
}

#[test]
fn entry_rows_of_a_correct_exporter_are_ok() {
    let f = state_ledger();
    let (v, sum) = run("entry_ok", &f, &entry_rows(), Some(ENTRY_SCOPE));
    assert_eq!(classes(&v), Vec::<String>::new());
    assert_eq!(sum.txs, 1);
}

#[test]
fn planted_entry_bugs_are_each_caught() {
    use serde_json::json;
    let f = state_ledger();
    // (description, mutation, expected class)
    let plants: Vec<(&str, Box<dyn Fn(&mut Vec<serde_json::Value>)>, &str)> = vec![
        (
            "signed-payload signer stored truncated to 32 bytes",
            Box::new(|r: &mut Vec<serde_json::Value>| {
                r[3]["field"] = json!(format!("signer:78{}", hex::encode([7u8; 32])));
            }),
            "wrong_value entry_change:wrong_value:account:signer_key",
        ),
        (
            "signer weight wrong",
            Box::new(|r: &mut Vec<serde_json::Value>| {
                r[0]["new"] = json!("9");
            }),
            "wrong_value entry_change:wrong_value:account:signer",
        ),
        (
            "trustline creation dropped",
            Box::new(|r: &mut Vec<serde_json::Value>| {
                r.remove(7);
            }),
            "missing entry_change:missing:trustline:created",
        ),
        (
            "authorization row dropped",
            Box::new(|r: &mut Vec<serde_json::Value>| {
                r.remove(9);
            }),
            "missing entry_change:missing_on_create:trustline:flags",
        ),
        (
            "an empty flags row before the right one",
            Box::new(|r: &mut Vec<serde_json::Value>| {
                let mut x = r[9].clone();
                x["new"] = json!("0");
                r.insert(9, x);
            }),
            "extra entry_change:extra:noop_on_create:trustline:flags",
        ),
        (
            "a limit restated on an entry whose limit stayed",
            Box::new(|r: &mut Vec<serde_json::Value>| {
                let mut x = r[8].clone();
                x["op_index"] = json!(2);
                r.push(x);
            }),
            "extra entry_change:extra:noop:trustline:limit",
        ),
        (
            "a value said gone from a removed entry is no verdict, a value set on it is",
            Box::new(|r: &mut Vec<serde_json::Value>| {
                let mut x = r[14].clone();
                x["field"] = json!("value");
                x["old"] = json!(hex::encode("v1"));
                r.push(x.clone());
                x["new"] = json!("00");
                r.push(x);
            }),
            "extra entry_change:extra:data:value",
        ),
        (
            "a threshold restated beside one that changed",
            Box::new(|r: &mut Vec<serde_json::Value>| {
                let mut x = r[6].clone();
                x["field"] = json!("threshold:low");
                x["new"] = json!("1");
                r.push(x);
            }),
            "extra entry_change:extra:noop:account:threshold",
        ),
        (
            "cleared bits restated beyond the change",
            Box::new(|r: &mut Vec<serde_json::Value>| {
                r[13]["new"] = json!("5");
            }),
            "wrong_value entry_change:wrong_value:restated_bits:trustline:flags",
        ),
        (
            "cleared bits wrong",
            Box::new(|r: &mut Vec<serde_json::Value>| {
                r[13]["new"] = json!("2");
            }),
            "wrong_value entry_change:wrong_value:trustline:flags",
        ),
        (
            "an extra clear of a flag that was not set",
            Box::new(|r: &mut Vec<serde_json::Value>| {
                let mut x = r[13].clone();
                x["new"] = json!("4");
                r.push(x);
            }),
            "extra entry_change:extra:noop:trustline:flags",
        ),
        (
            "trustline removed with no entry change",
            Box::new(|r: &mut Vec<serde_json::Value>| {
                let mut x = r[7].clone();
                x["change"] = json!("removed");
                x["op_index"] = json!(2);
                r.push(x);
            }),
            "extra entry_change:extra:trustline:removed",
        ),
        (
            "unchanged threshold written as a change",
            Box::new(|r: &mut Vec<serde_json::Value>| {
                let mut x = r[0].clone();
                x["field"] = json!("threshold:low");
                x["old"] = json!("1");
                x["new"] = json!("1");
                r.push(x);
            }),
            "extra entry_change:extra:noop:account:threshold",
        ),
        (
            "account creation with no entry change",
            Box::new(|r: &mut Vec<serde_json::Value>| {
                r.push(
                    json!({"kind": "entry_change", "ledger": 1000, "tx_index": 0, "op_index": 1,
                          "entry_type": "account", "account": g(5), "change": "created"}),
                );
            }),
            "extra entry_change:extra:account:created",
        ),
        (
            "wrong operation",
            Box::new(|r: &mut Vec<serde_json::Value>| {
                r[10]["op_index"] = json!(0);
            }),
            "wrong_value entry_change:wrong_value:op_index",
        ),
    ];
    for (what, plant, want) in plants {
        let mut rows = entry_rows();
        plant(&mut rows);
        let (v, _) = run("entry_plant", &f, &rows, Some(ENTRY_SCOPE));
        assert_eq!(classes(&v), vec![want.to_string()], "{what}");
    }
}

#[test]
fn claimants_are_their_own_role_and_scope_rules_move_verdicts_out_of_scope() {
    use serde_json::json;
    let op = Operation {
        source_account: None,
        body: OperationBody::CreateClaimableBalance(CreateClaimableBalanceOp {
            asset: Asset::Native,
            amount: 1,
            claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
                destination: acct(4),
                predicate: ClaimPredicate::Unconditional,
            })]
            .try_into()
            .unwrap(),
        }),
    };
    let l = ledger(
        23,
        vec![Tx {
            source: MuxedAccount::Ed25519(Uint256([1; 32])),
            ops: vec![op],
            success: true,
            fee_charged: 0,
            fee: vec![],
            ops_meta: vec![(vec![], vec![])],
            refund: vec![],
        }],
    );
    let f = judge_ledger(&l, &Options::mainnet()).unwrap();
    assert!(f.iter().any(|x| matches!(x, Fact::Participant(p)
        if p.address == g(4) && p.roles == vec!["claimant".to_string()])));
    let part =
        |a: String| json!({"kind": "participant", "ledger": 1000, "tx_index": 0, "holder": a});
    // No row for the claimant: ok. A row: extra:claimant, in scope without a rule.
    let (v, _) = run("cl0", &f, &[part(g(1))], None);
    assert_eq!(classes(&v), Vec::<String>::new());
    let (v, _) = run("cl1", &f, &[part(g(1)), part(g(4))], None);
    assert_eq!(
        classes(&v),
        vec!["extra participant:extra:claimant".to_string()]
    );
    let scope = r#"
target = "toy"
[kinds.participant]
[[rule]]
id = "claimants"
reason = "claimants are participants"
cite = "toy.go:1"
kinds = ["participant"]
class_prefix = ["participant:extra:claimant"]
"#;
    let (v, sum) = run("cl2", &f, &[part(g(1)), part(g(4))], Some(scope));
    assert_eq!(
        classes(&v),
        vec!["out_of_scope participant:extra:claimant".to_string()]
    );
    assert_eq!(v.iter().filter(|x| x["verdict"] == "ok").count(), 1);
    assert_eq!(sum.out_of_scope["claimants"], 1);
    // The planted bug the rule must not hide: a dropped source is still in scope.
    let (v, _) = run("cl3", &f, &[part(g(4))], Some(scope));
    assert!(classes(&v).contains(&"missing participant:missing:fee_payer+source".to_string()));
}

fn sac_event_ledger(data: ScVal, muxed: Option<ScVal>) -> Vec<Fact> {
    let nid = network_id(MAINNET);
    let sac = sac_contract_id(&usdc(), nid);
    let usdc_str = "USDC:".to_string() + &g(9);
    let data = if let Some(muxed) = muxed {
        ScVal::Map(Some(
            vec![
                ScMapEntry {
                    key: sym("amount"),
                    val: data,
                },
                ScMapEntry {
                    key: sym("to_muxed_id"),
                    val: muxed,
                },
            ]
            .try_into()
            .unwrap(),
        ))
    } else {
        data
    };
    let ev = event(
        sac,
        vec![
            sym("transfer"),
            ScVal::Address(ScAddress::Account(acct(1))),
            ScVal::Address(ScAddress::Account(acct(2))),
            ScVal::String(ScString(usdc_str.as_str().try_into().unwrap())),
        ],
        data,
    );
    let l = ledger(
        23,
        vec![Tx {
            source: MuxedAccount::Ed25519(Uint256([1; 32])),
            ops: vec![nop()],
            success: true,
            fee_charged: 0,
            fee: vec![],
            ops_meta: vec![(vec![], vec![ev])],
            refund: vec![],
        }],
    );
    judge_ledger(&l, &Options::mainnet()).unwrap()
}

fn transfer_row(amount: &str) -> serde_json::Value {
    let nid = network_id(MAINNET);
    serde_json::json!({"kind": "token_event", "ledger": 1000, "tx_index": 0, "op_index": 0,
        "contract": contract_strkey(&sac_contract_id(&usdc(), nid)), "event": "transfer",
        "from": g(1), "to": g(2), "amount": amount})
}

#[test]
fn an_event_without_an_amount_is_not_a_token_movement() {
    let f = sac_event_ledger(ScVal::U32(5), None);
    assert!(f.iter().any(|x| matches!(x, Fact::EventWithoutAmount(_))));
    assert!(!f.iter().any(|x| matches!(x, Fact::TokenEvent(_))));
    let scope = "target = \"toy\"\n[kinds.token_event]\n";
    let (v, _) = run("noamt0", &f, &[], Some(scope));
    assert_eq!(classes(&v), Vec::<String>::new());
    // Planted: an exporter that books it as a transfer of 0.
    let (v, _) = run("noamt1", &f, &[transfer_row("0")], Some(scope));
    assert_eq!(classes(&v), vec!["extra token_event:extra".to_string()]);
}

#[test]
fn to_muxed_id_is_compared_on_token_events() {
    use serde_json::json;
    let scope = "target = \"toy\"\n[kinds.token_event]\n";
    let plain = sac_event_ledger(i128v(10), None);
    let (v, _) = run("mx0", &plain, &[transfer_row("10")], Some(scope));
    assert_eq!(classes(&v), Vec::<String>::new());
    // Planted: a fabricated id where the event has none.
    let mut r = transfer_row("10");
    r["to_muxed_id"] = json!("0");
    let (v, _) = run("mx1", &plain, &[r], Some(scope));
    assert_eq!(
        classes(&v),
        vec!["wrong_value token_event:wrong_value:to_muxed_id".to_string()]
    );
    let muxed = sac_event_ledger(i128v(10), Some(ScVal::U64(77)));
    let mut r = transfer_row("10");
    r["to_muxed_id"] = json!("77");
    let (v, _) = run("mx2", &muxed, &[r], Some(scope));
    assert_eq!(classes(&v), Vec::<String>::new());
    // A Void id is no id: a row without one is right.
    let void = sac_event_ledger(i128v(10), Some(ScVal::Void));
    let (v, _) = run("mx4", &void, &[transfer_row("10")], Some(scope));
    assert_eq!(classes(&v), Vec::<String>::new());
    // Planted: the id dropped.
    let (v, _) = run("mx3", &muxed, &[transfer_row("10")], Some(scope));
    assert_eq!(
        classes(&v),
        vec!["wrong_value token_event:wrong_value:to_muxed_id_absent".to_string()]
    );
}

#[test]
fn extra_only_kinds_check_what_was_written_and_count_the_rest() {
    let scope = "target = \"toy\"\n[kinds.token_event]\nmode = \"extra_only\"\n";
    let f = sac_event_ledger(i128v(10), None);
    let (v, sum) = run("xo0", &f, &[], Some(scope));
    assert_eq!(classes(&v), Vec::<String>::new());
    assert_eq!(sum.not_compared["token_event:extra_only"], 1);
    // Planted: a wrong amount is still caught.
    let (v, _) = run("xo1", &f, &[transfer_row("11")], Some(scope));
    assert_eq!(
        classes(&v),
        vec!["wrong_value token_event:wrong_value:small_diff".to_string()]
    );
    // A kind with another name compared as token events (an operation's asset balance changes).
    let scope2 = "target = \"toy\"\n[kinds.op_token_event]\ncompare = \"token_event\"\nmode = \"extra_only\"\n";
    let mut r = transfer_row("10");
    r["kind"] = serde_json::json!("op_token_event");
    let (v, _) = run("xo2", &f, &[r.clone()], Some(scope2));
    assert_eq!(classes(&v), Vec::<String>::new());
    r["amount"] = serde_json::json!("12");
    let (v, _) = run("xo3", &f, &[r], Some(scope2));
    assert_eq!(
        classes(&v),
        vec!["wrong_value op_token_event:wrong_value:small_diff".to_string()]
    );
}

#[test]
fn shipped_scope_files_load_and_every_rule_cites_its_source() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scopes");
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().and_then(|x| x.to_str()) != Some("toml") {
            continue;
        }
        let s = xdrcheck_judge::scope::load(&p).unwrap();
        assert!(!s.at.is_empty(), "{}: no version", p.display());
        for (k, ks) in &s.kinds {
            assert!(
                !ks.cite.is_empty(),
                "{}: kind {k} cites nothing",
                p.display()
            );
        }
        n += 1;
    }
    assert_eq!(n, 3);
}

#[test]
fn sponsors_of_entries_are_attributes() {
    use serde_json::json;
    let sponsored = |n: u8, by: Option<u8>| {
        let mut e = account(n, 1000);
        e.ext = LedgerEntryExt::V1(LedgerEntryExtensionV1 {
            sponsoring_id: SponsorshipDescriptor(by.map(acct)),
            ext: LedgerEntryExtensionV1Ext::V0,
        });
        e
    };
    let l = ledger(
        23,
        vec![Tx {
            source: MuxedAccount::Ed25519(Uint256([1; 32])),
            ops: vec![nop(), nop()],
            success: true,
            fee_charged: 0,
            fee: vec![],
            ops_meta: vec![
                (
                    vec![LedgerEntryChange::Created(sponsored(5, Some(6)))],
                    vec![],
                ),
                (upd(sponsored(5, Some(6)), sponsored(5, None)), vec![]),
            ],
            refund: vec![],
        }],
    );
    let f = judge_ledger(&l, &Options::mainnet()).unwrap();
    let a = format!("account:{}", g(5));
    let sp: Vec<_> = fields(&f)
        .into_iter()
        .filter(|x| x.2 == "sponsor")
        .collect();
    assert_eq!(
        sp,
        vec![
            (Some(0), a.clone(), "sponsor".to_string(), None, s(&g(6))),
            (Some(1), a.clone(), "sponsor".to_string(), s(&g(6)), None),
        ]
    );
    let scope = "target = \"toy\"\n[kinds.entry_change]\nlifecycle = [\"account:created\"]\nfields = [\"account:sponsor\", \"account:signer\"]\n";
    let row = |op: u32, v: serde_json::Value| {
        let mut r = json!({"kind": "entry_change", "ledger": 1000, "tx_index": 0, "op_index": op, "entry_type": "account", "account": g(5)});
        r.as_object_mut()
            .unwrap()
            .extend(v.as_object().unwrap().clone());
        r
    };
    let master = format!("signer:30{}", hex::encode([5u8; 32]));
    let good = vec![
        row(0, json!({"change": "created"})),
        row(0, json!({"field": master, "new": "0"})),
        row(0, json!({"field": "sponsor", "new": g(6)})),
        row(1, json!({"field": "sponsor", "old": g(6)})),
    ];
    // The account helper has master weight 0: no master signer fact; drop that row.
    let good: Vec<_> = good
        .into_iter()
        .filter(|r| r.get("field") != Some(&json!(master)))
        .collect();
    let (v, _) = run("sp0", &f, &good, Some(scope));
    assert_eq!(classes(&v), Vec::<String>::new());
    // Planted: the sponsor named wrong.
    let mut bad = good.clone();
    bad[1]["new"] = json!(g(7));
    let (v, _) = run("sp1", &f, &bad, Some(scope));
    assert_eq!(
        classes(&v),
        vec!["wrong_value entry_change:wrong_value:account:sponsor".to_string()]
    );
    // Planted: the sponsorship removal dropped.
    let (v, _) = run("sp2", &f, &good[..2], Some(scope));
    assert_eq!(
        classes(&v),
        vec!["missing entry_change:missing:account:sponsor".to_string()]
    );
}
