//! Hand-built ledgers: each test builds a `LedgerCloseMeta` v2 with one or more transactions and
//! checks the facts the judge derives from it.

use stellar_xdr::*;
use xdrcheck_judge::facts::{judge_ledger, BalanceFact, Fact, Options};
use xdrcheck_judge::read::{contract_strkey, network_id, sac_contract_id, MAINNET};

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

fn balances(f: &[Fact]) -> Vec<&BalanceFact> {
    f.iter()
        .filter_map(|x| match x {
            Fact::BalanceChange(b) => Some(b),
            _ => None,
        })
        .collect()
}

fn bal<'a>(f: &'a [Fact], holder: &str, asset: &str) -> Option<&'a BalanceFact> {
    balances(f)
        .into_iter()
        .find(|b| b.holder == holder && b.asset == asset)
}

fn g(n: u8) -> String {
    acct(n).to_string()
}

#[test]
fn payment_with_fee_and_refund_nets_per_holder() {
    let mut fee = upd(account(1, 1000), account(1, 900));
    fee.extend(vec![]);
    let mut ops = upd(account(1, 900), account(1, 600));
    ops.extend(upd(account(2, 50), account(2, 350)));
    let l = ledger(
        23,
        vec![Tx {
            source: MuxedAccount::Ed25519(Uint256([1; 32])),
            ops: vec![payment_op(MuxedAccount::Ed25519(Uint256([2; 32])), 300)],
            success: true,
            fee_charged: 70,
            fee,
            ops_meta: vec![(ops, vec![])],
            refund: upd(account(1, 600), account(1, 630)),
        }],
    );
    let f = judge_ledger(&l, &Options::mainnet()).unwrap();
    let a = bal(&f, &g(1), "native").unwrap();
    assert_eq!(a.amount, "-370");
    assert_eq!(a.parts["fee"], "-100");
    assert_eq!(a.parts["op:0"], "-300");
    assert_eq!(a.parts["refund"], "30");
    assert_eq!(bal(&f, &g(2), "native").unwrap().amount, "300");
    let mut tally = Default::default();
    assert!(xdrcheck_judge::conserve::check(&f, &mut tally).is_empty());
}

#[test]
fn custom_token_named_usdc_is_not_a_balance_but_the_real_sac_is() {
    let nid = network_id(MAINNET);
    let real = sac_contract_id(&usdc(), nid);
    let fake = [7u8; 32];
    let holder = contract_addr([3; 32]);
    let usdc_str = "USDC:".to_string() + &g(9);
    let ev = |cid| {
        event(
            cid,
            vec![
                sym("mint"),
                ScVal::Address(holder.clone()),
                ScVal::String(ScString(usdc_str.as_str().try_into().unwrap())),
            ],
            i128v(5),
        )
    };
    let l = ledger(
        23,
        vec![Tx {
            source: MuxedAccount::Ed25519(Uint256([1; 32])),
            ops: vec![payment_op(MuxedAccount::Ed25519(Uint256([2; 32])), 1)],
            success: true,
            fee_charged: 0,
            fee: vec![],
            ops_meta: vec![(
                vec![
                    LedgerEntryChange::Created(balance_entry(fake, holder.clone(), 1_000_000)),
                    LedgerEntryChange::Created(balance_entry(real, holder.clone(), 5)),
                ],
                vec![ev(fake), ev(real)],
            )],
            refund: vec![],
        }],
    );
    let f = judge_ledger(&l, &Options::mainnet()).unwrap();
    let h = holder.to_string();
    let b = bal(&f, &h, &usdc_str).unwrap();
    assert_eq!(b.amount, "5");
    assert_eq!(b.contract, contract_strkey(&real));
    assert_eq!(
        balances(&f).len(),
        1,
        "the fake contract's entry is not a balance"
    );
    assert!(f
        .iter()
        .any(|x| matches!(x, Fact::NonsacBalance(n) if n.contract == contract_strkey(&fake))));
    let evs: Vec<_> = f
        .iter()
        .filter_map(|x| match x {
            Fact::TokenEvent(e) => Some((e.contract.clone(), e.sac)),
            _ => None,
        })
        .collect();
    assert_eq!(
        evs,
        vec![
            (contract_strkey(&fake), false),
            (contract_strkey(&real), true)
        ]
    );
}

#[test]
fn update_without_prior_state_is_unknown_not_zero() {
    let l = ledger(
        23,
        vec![Tx {
            source: MuxedAccount::Ed25519(Uint256([1; 32])),
            ops: vec![payment_op(MuxedAccount::Ed25519(Uint256([2; 32])), 1)],
            success: true,
            fee_charged: 0,
            fee: vec![],
            ops_meta: vec![(vec![LedgerEntryChange::Updated(account(2, 77))], vec![])],
            refund: vec![],
        }],
    );
    let f = judge_ledger(&l, &Options::mainnet()).unwrap();
    let b = bal(&f, &g(2), "native").unwrap();
    assert!(!b.complete);
    assert!(f
        .iter()
        .any(|x| matches!(x, Fact::Unknown(u) if u.class == "updated_without_prior_state")));
}

#[test]
fn prior_state_from_an_earlier_list_of_the_ledger_is_used() {
    // The fee list gives account 2's value; the op list then updates it without a STATE.
    let l = ledger(
        23,
        vec![Tx {
            source: MuxedAccount::Ed25519(Uint256([2; 32])),
            ops: vec![payment_op(MuxedAccount::Ed25519(Uint256([2; 32])), 1)],
            success: true,
            fee_charged: 10,
            fee: upd(account(2, 100), account(2, 90)),
            ops_meta: vec![(vec![LedgerEntryChange::Updated(account(2, 95))], vec![])],
            refund: vec![],
        }],
    );
    let f = judge_ledger(&l, &Options::mainnet()).unwrap();
    let b = bal(&f, &g(2), "native").unwrap();
    assert!(b.complete);
    assert_eq!(b.amount, "-5");
}

#[test]
fn p23_reconciliation_counts_only_the_leading_matching_event() {
    let nid = network_id(MAINNET);
    let sac = sac_contract_id(&usdc(), nid);
    let holder = contract_addr([4; 32]);
    let usdc_str = "USDC:".to_string() + &g(9);
    let asset_topic = ScVal::String(ScString(usdc_str.as_str().try_into().unwrap()));
    let mint = |n| {
        event(
            sac,
            vec![
                sym("mint"),
                ScVal::Address(holder.clone()),
                asset_topic.clone(),
            ],
            i128v(n),
        )
    };
    let restored = balance_entry(sac, holder.clone(), 1000);
    let mut ops = vec![LedgerEntryChange::Restored(restored.clone())];
    ops.extend(upd(restored, balance_entry(sac, holder.clone(), 1007)));
    let ihf = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::UploadContractWasm(BytesM::default()),
            auth: VecM::default(),
        }),
    };
    let mk_with = |protocol, events: Vec<ContractEvent>| {
        ledger(
            protocol,
            vec![Tx {
                source: MuxedAccount::Ed25519(Uint256([1; 32])),
                ops: vec![ihf.clone()],
                success: true,
                fee_charged: 0,
                fee: vec![],
                ops_meta: vec![(ops.clone(), events)],
                refund: vec![],
            }],
        )
    };
    // Reconciliation mint of 400 first, then a genuine mint of 7.
    let mk = |protocol| mk_with(protocol, vec![mint(400), mint(7)]);
    let f = judge_ledger(&mk(23), &Options::mainnet()).unwrap();
    let b = bal(&f, &holder.to_string(), &usdc_str).unwrap();
    assert_eq!(b.parts["op:0"], "7");
    assert_eq!(b.parts["reconcile:0"], "400");
    assert_eq!(b.amount, "407");
    let rec: Vec<bool> = f
        .iter()
        .filter_map(|x| match x {
            Fact::TokenEvent(e) => Some(e.reconciliation),
            _ => None,
        })
        .collect();
    assert_eq!(rec, vec![true, false]);
    let mut t = Default::default();
    assert!(xdrcheck_judge::conserve::check(&f, &mut t).is_empty());
    // A lone genuine mint on a restored balance is not a reconciliation: it shows in the delta.
    let f = judge_ledger(&mk_with(23, vec![mint(7)]), &Options::mainnet()).unwrap();
    let b = bal(&f, &holder.to_string(), &usdc_str).unwrap();
    assert_eq!(b.amount, "7");
    assert!(!b.parts.contains_key("reconcile:0"));
    // Outside protocol 23 there is no reconciliation.
    let f = judge_ledger(&mk(24), &Options::mainnet()).unwrap();
    let b = bal(&f, &holder.to_string(), &usdc_str).unwrap();
    assert_eq!(b.amount, "7");
}

#[test]
fn muxed_destination_keeps_its_id_and_wide_amounts_are_exact() {
    let nid = network_id(MAINNET);
    let sac = sac_contract_id(&usdc(), nid);
    let holder = contract_addr([5; 32]);
    let wide: i128 = (1i128 << 64) + 12345;
    let dest = MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
        id: u64::MAX,
        ed25519: Uint256([2; 32]),
    });
    let usdc_str = "USDC:".to_string() + &g(9);
    let ev = event(
        sac,
        vec![
            sym("mint"),
            ScVal::Address(holder.clone()),
            ScVal::String(ScString(usdc_str.as_str().try_into().unwrap())),
        ],
        i128v(wide),
    );
    let l = ledger(
        23,
        vec![Tx {
            source: MuxedAccount::Ed25519(Uint256([1; 32])),
            ops: vec![payment_op(dest, 1)],
            success: true,
            fee_charged: 0,
            fee: vec![],
            ops_meta: vec![(
                vec![LedgerEntryChange::Created(balance_entry(
                    sac,
                    holder.clone(),
                    wide,
                ))],
                vec![ev],
            )],
            refund: vec![],
        }],
    );
    let f = judge_ledger(&l, &Options::mainnet()).unwrap();
    assert_eq!(
        bal(&f, &holder.to_string(), &usdc_str).unwrap().amount,
        wide.to_string()
    );
    let p = f
        .iter()
        .find_map(|x| match x {
            Fact::Participant(p) if p.address == g(2) => Some(p),
            _ => None,
        })
        .unwrap();
    assert_eq!(p.muxed_ids, vec![u64::MAX.to_string()]);
    assert!(p.roles.contains(&"counterparty".to_string()));
}

#[test]
fn failed_transaction_has_only_fee_changes() {
    let l = ledger(
        23,
        vec![Tx {
            source: MuxedAccount::Ed25519(Uint256([1; 32])),
            ops: vec![payment_op(MuxedAccount::Ed25519(Uint256([2; 32])), 5)],
            success: false,
            fee_charged: 100,
            fee: upd(account(1, 1000), account(1, 900)),
            ops_meta: vec![(vec![], vec![])],
            refund: vec![],
        }],
    );
    let f = judge_ledger(&l, &Options::mainnet()).unwrap();
    assert_eq!(balances(&f).len(), 1);
    assert_eq!(bal(&f, &g(1), "native").unwrap().amount, "-100");
    assert!(f.iter().any(|x| matches!(x, Fact::Tx(t) if !t.success)));
}

#[test]
fn output_is_deterministic() {
    let mk = || {
        ledger(
            23,
            vec![Tx {
                source: MuxedAccount::Ed25519(Uint256([1; 32])),
                ops: vec![payment_op(MuxedAccount::Ed25519(Uint256([2; 32])), 300)],
                success: true,
                fee_charged: 100,
                fee: upd(account(1, 1000), account(1, 900)),
                ops_meta: vec![(
                    {
                        let mut v = upd(account(1, 900), account(1, 600));
                        v.extend(upd(account(2, 0), account(2, 300)));
                        v
                    },
                    vec![],
                )],
                refund: vec![],
            }],
        )
    };
    let a = serde_json::to_string(&judge_ledger(&mk(), &Options::mainnet()).unwrap()).unwrap();
    let b = serde_json::to_string(&judge_ledger(&mk(), &Options::mainnet()).unwrap()).unwrap();
    assert_eq!(a, b);
}

/// One transaction in an older ledger form: LCM v0 with meta v1, or LCM v1 with meta v3.
fn old_ledger(
    lcm: u32,
    protocol: u32,
    tx: Tx,
    before: Vec<LedgerEntryChange>,
    after: Vec<LedgerEntryChange>,
) -> LedgerCloseMeta {
    let nid = network_id(MAINNET);
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: tx.source,
            fee: 100,
            seq_num: SequenceNumber(1),
            operations: tx.ops.try_into().unwrap(),
            ..Default::default()
        },
        signatures: VecM::default(),
    });
    let hash = env.hash(nid).unwrap();
    let ops: Vec<OperationResult> = tx
        .ops_meta
        .iter()
        .map(|_| OperationResult::OpInner(OperationResultTr::Payment(PaymentResult::Success)))
        .collect();
    let result = TransactionResultPair {
        transaction_hash: Hash(hash),
        result: TransactionResult {
            fee_charged: tx.fee_charged,
            result: TransactionResultResult::TxSuccess(ops.try_into().unwrap()),
            ext: TransactionResultExt::V0,
        },
    };
    let events: Vec<ContractEvent> = tx.ops_meta.iter().flat_map(|(_, e)| e.clone()).collect();
    let op_metas: Vec<OperationMeta> = tx
        .ops_meta
        .into_iter()
        .map(|(c, _)| OperationMeta {
            changes: changes(c),
        })
        .collect();
    let meta = if lcm == 0 {
        TransactionMeta::V1(TransactionMetaV1 {
            tx_changes: changes(before),
            operations: op_metas.try_into().unwrap(),
        })
    } else {
        TransactionMeta::V3(TransactionMetaV3 {
            ext: ExtensionPoint::V0,
            tx_changes_before: changes(before),
            operations: op_metas.try_into().unwrap(),
            tx_changes_after: changes(after),
            soroban_meta: Some(SorobanTransactionMeta {
                ext: SorobanTransactionMetaExt::V0,
                events: events.try_into().unwrap(),
                return_value: ScVal::Void,
                diagnostic_events: VecM::default(),
            }),
        })
    };
    let trm = TransactionResultMeta {
        result,
        fee_processing: changes(tx.fee),
        tx_apply_processing: meta,
    };
    if lcm == 0 {
        let mut v = LedgerCloseMetaV0::default();
        v.ledger_header.header.ledger_seq = 1000;
        v.ledger_header.header.ledger_version = protocol;
        v.tx_set.txs = vec![env].try_into().unwrap();
        v.tx_processing = vec![trm].try_into().unwrap();
        LedgerCloseMeta::V0(v)
    } else {
        let mut v = LedgerCloseMetaV1::default();
        v.ledger_header.header.ledger_seq = 1000;
        v.ledger_header.header.ledger_version = protocol;
        v.tx_set = GeneralizedTransactionSet::V1(TransactionSetV1 {
            previous_ledger_hash: Hash([0; 32]),
            phases: vec![TransactionPhase::V0(
                vec![TxSetComponent::TxsetCompTxsMaybeDiscountedFee(
                    TxSetComponentTxsMaybeDiscountedFee {
                        base_fee: None,
                        txs: vec![env].try_into().unwrap(),
                    },
                )]
                .try_into()
                .unwrap(),
            )]
            .try_into()
            .unwrap(),
        });
        v.tx_processing = vec![trm].try_into().unwrap();
        LedgerCloseMeta::V1(v)
    }
}

#[test]
fn lcm_v0_meta_v1_payment() {
    let mut ops = upd(account(1, 900), account(1, 600));
    ops.extend(upd(account(2, 50), account(2, 350)));
    let l = old_ledger(
        0,
        9,
        Tx {
            source: MuxedAccount::Ed25519(Uint256([1; 32])),
            ops: vec![payment_op(MuxedAccount::Ed25519(Uint256([2; 32])), 300)],
            success: true,
            fee_charged: 100,
            fee: upd(account(1, 1000), account(1, 900)),
            ops_meta: vec![(ops, vec![])],
            refund: vec![],
        },
        vec![],
        vec![],
    );
    let f = judge_ledger(&l, &Options::mainnet()).unwrap();
    assert_eq!(bal(&f, &g(1), "native").unwrap().amount, "-400");
    assert_eq!(bal(&f, &g(2), "native").unwrap().amount, "300");
    assert!(f
        .iter()
        .any(|x| matches!(x, Fact::Tx(t) if t.meta_version == 1)));
    let mut t = Default::default();
    assert!(xdrcheck_judge::conserve::check(&f, &mut t).is_empty());
}

#[test]
fn lcm_v1_meta_v3_soroban_refund_in_tx_changes_after_and_events_from_soroban_meta() {
    let nid = network_id(MAINNET);
    let native = sac_contract_id(&Asset::Native, nid);
    let holder = contract_addr([6; 32]);
    let ev = event(
        native,
        vec![
            sym("transfer"),
            ScVal::Address(ScAddress::Account(acct(1))),
            ScVal::Address(holder.clone()),
            ScVal::String(ScString("native".try_into().unwrap())),
        ],
        i128v(250),
    );
    let mut ops = upd(account(1, 900), account(1, 650));
    ops.push(LedgerEntryChange::Created(balance_entry(
        native,
        holder.clone(),
        250,
    )));
    let l = old_ledger(
        1,
        21,
        Tx {
            source: MuxedAccount::Ed25519(Uint256([1; 32])),
            ops: vec![payment_op(MuxedAccount::Ed25519(Uint256([2; 32])), 1)],
            success: true,
            fee_charged: 70,
            fee: upd(account(1, 1000), account(1, 900)),
            ops_meta: vec![(ops, vec![ev])],
            refund: vec![],
        },
        vec![],
        upd(account(1, 650), account(1, 680)),
    );
    let f = judge_ledger(&l, &Options::mainnet()).unwrap();
    let a = bal(&f, &g(1), "native").unwrap();
    assert_eq!(a.amount, "-320");
    assert_eq!(a.parts["after"], "30");
    assert_eq!(
        bal(&f, &holder.to_string(), "native").unwrap().amount,
        "250"
    );
    assert!(f
        .iter()
        .any(|x| matches!(x, Fact::TokenEvent(e) if e.sac && e.op_index == Some(0))));
    let mut t = Default::default();
    assert!(xdrcheck_judge::conserve::check(&f, &mut t).is_empty());
}
