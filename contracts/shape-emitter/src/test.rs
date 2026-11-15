//! Unit tests: every emitted shape, checked as XDR, against both the native
//! contract and the vendored wasm (`corpus/contracts/shape-emitter.wasm`).
//!
//! Calls go through `Host::invoke_function` with `ScVal` arguments, the same
//! XDR path stellar-core uses, so argument conversion limits apply as on a
//! real ledger. The testutils host is soroban-env-host 29.0.1 at ledger
//! protocol 29.
extern crate std;

use std::{format, vec, vec::Vec as StdVec};

use soroban_sdk::{
    testutils::{EnvTestConfig, HostError, Ledger as _},
    xdr::{
        AccountId, ClaimableBalanceId, ContractEvent, ContractEventBody, ContractEventType,
        ContractExecutable, ContractId, ContractIdPreimage, ContractIdPreimageFromAddress,
        CreateContractArgsV2, Hash, HostFunction, Int128Parts, Int256Parts, InvokeContractArgs,
        MuxedEd25519Account, PoolId, PublicKey, ScAddress, ScBytes, ScMap, ScMapEntry, ScString,
        ScSymbol, ScVal, ScVec, UInt128Parts, UInt256Parts, Uint256,
    },
    Address, Env,
};
use stellar_strkey::{ed25519, ClaimableBalance, Contract, LiquidityPool, MuxedContract, Strkey};

use crate::ShapeEmitter;

const WASM: &[u8] = include_bytes!("../../../corpus/contracts/shape-emitter.wasm");

fn env() -> Env {
    Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    })
}

fn tag() -> ScVal {
    ScVal::Symbol(ScSymbol("t".try_into().unwrap()))
}

/// The contract registered twice: natively and from the vendored wasm.
fn both(env: &Env) -> [Address; 2] {
    let t = soroban_sdk::Symbol::new(env, "t");
    [
        env.register(ShapeEmitter, (t.clone(),)),
        env.register(WASM, (t,)),
    ]
}

fn wasm_only(env: &Env) -> Address {
    env.register(WASM, (soroban_sdk::Symbol::new(env, "t"),))
}

/// Why a call did not succeed: the host error, or `None` when the testutils
/// host panicked instead of returning one.
#[derive(Debug)]
struct Failure {
    error: Option<soroban_sdk::Error>,
}

/// Invokes `f` with XDR arguments under a fresh default budget.
///
/// The default budget matters: on this testutils host (soroban-env-host
/// 29.0.1) a call that fails on an over-deep value or a muxed storage key does
/// not return under an unlimited budget, and under the default budget its
/// failure can surface as a panic from testutils auth bookkeeping. Both are
/// reported as a `Failure` here, so tests assert on "did not succeed".
fn invoke(env: &Env, id: &Address, f: &str, args: StdVec<ScVal>) -> Result<ScVal, Failure> {
    env.cost_estimate().budget().reset_default();
    let call = || -> Result<ScVal, HostError> {
        env.host()
            .invoke_function(HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: ScAddress::from(id),
                function_name: ScSymbol(f.try_into().unwrap()),
                args: args.clone().try_into().unwrap(),
            }))
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(call)) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(Failure {
            error: Some(e.error),
        }),
        Err(_) => Err(Failure { error: None }),
    }
}

/// Contract events recorded by the host so far (successful and failed calls).
fn events(env: &Env) -> StdVec<(ContractEvent, bool)> {
    env.host()
        .get_events()
        .unwrap()
        .0
        .into_iter()
        .filter(|e| e.event.type_ == ContractEventType::Contract)
        .map(|e| (e.event, e.failed_call))
        .collect()
}

fn last(env: &Env) -> (StdVec<ScVal>, ScVal) {
    let (e, _) = events(env).pop().expect("no contract event");
    let ContractEventBody::V0(b) = e.body;
    (b.topics.to_vec(), b.data)
}

fn sym(s: &str) -> ScVal {
    ScVal::Symbol(ScSymbol(s.try_into().unwrap()))
}
fn string(b: &[u8]) -> ScVal {
    ScVal::String(ScString(b.try_into().unwrap()))
}
fn bytes(b: &[u8]) -> ScVal {
    ScVal::Bytes(ScBytes(b.try_into().unwrap()))
}
fn i128v(v: i128) -> ScVal {
    ScVal::I128(Int128Parts {
        hi: (v >> 64) as i64,
        lo: v as u64,
    })
}
fn vecv(items: StdVec<ScVal>) -> ScVal {
    ScVal::Vec(Some(ScVec(items.try_into().unwrap())))
}
fn map(entries: StdVec<(ScVal, ScVal)>) -> ScVal {
    ScVal::Map(Some(ScMap(
        entries
            .into_iter()
            .map(|(key, val)| ScMapEntry { key, val })
            .collect::<StdVec<_>>()
            .try_into()
            .unwrap(),
    )))
}
fn account(n: u8) -> ScAddress {
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([n; 32]))))
}
fn addr(a: ScAddress) -> ScVal {
    ScVal::Address(a)
}
fn nested(depth: u32) -> ScVal {
    let mut v = ScVal::Void;
    for _ in 0..depth {
        v = vecv(vec![v]);
    }
    v
}

// --- the wasm artifact itself ---------------------------------------------

#[test]
fn wasm_uploads_at_protocol_29() {
    let env = env();
    let hash = env
        .host()
        .invoke_function(HostFunction::UploadContractWasm(WASM.try_into().unwrap()));
    assert!(matches!(hash, Ok(ScVal::Bytes(_))), "{hash:?}");
}

#[test]
fn wasm_rejected_at_protocol_28() {
    // soroban-sdk 29.0.1 stamps interface protocol 29 into contractenvmetav0;
    // a host at ledger protocol 28 refuses a contract built for a later
    // protocol, so this wasm cannot be uploaded on a Protocol 28 chain.
    let env = env();
    env.ledger().set_protocol_version(28);
    let r = env
        .host()
        .invoke_function(HostFunction::UploadContractWasm(WASM.try_into().unwrap()));
    assert!(r.is_err(), "{r:?}");
}

// --- constructor (cap-0058/create-contract-v2-with-constructor) -----------

#[test]
fn constructor_stores_tag() {
    let env = env();
    for id in both(&env) {
        let stored = invoke(&env, &id, "get", vec![ScVal::U32(2), sym("tag")]).unwrap();
        assert_eq!(stored, tag());
    }
}

#[test]
fn create_contract_v2_runs_constructor_and_emits_its_event() {
    // The route the generator takes: upload the wasm, then
    // HOST_FUNCTION_TYPE_CREATE_CONTRACT_V2 with a constructor argument.
    let env = env();
    env.mock_all_auths();
    let hash = match env
        .host()
        .invoke_function(HostFunction::UploadContractWasm(WASM.try_into().unwrap()))
        .unwrap()
    {
        ScVal::Bytes(b) => Hash(b.as_slice().try_into().unwrap()),
        other => panic!("upload returned {other:?}"),
    };
    let deployer = addr(account(20));
    let ScVal::Address(deployer) = deployer else {
        unreachable!()
    };
    let created = env
        .host()
        .invoke_function(HostFunction::CreateContractV2(CreateContractArgsV2 {
            contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
                address: deployer,
                salt: Uint256([1; 32]),
            }),
            executable: ContractExecutable::Wasm(hash),
            constructor_args: vec![tag()].try_into().unwrap(),
        }))
        .unwrap();
    let ScVal::Address(ScAddress::Contract(cid)) = created else {
        panic!("create returned {created:?}");
    };
    let (e, failed) = events(&env).pop().expect("constructor event");
    assert!(!failed);
    assert_eq!(e.contract_id, Some(cid));
    let ContractEventBody::V0(b) = e.body;
    assert_eq!(b.topics.to_vec(), vec![sym("init")]);
    assert_eq!(b.data, tag());
}

// --- cap-0046/event-data-map-with-colliding-keys --------------------------

#[test]
fn colliding_keys_are_host_ordered_by_type() {
    let env = env();
    let a = map(vec![
        (ScVal::U32(1), ScVal::U32(10)),
        (string(b"1"), ScVal::U32(20)),
        (sym("1"), ScVal::U32(30)),
    ]);
    let b = map(vec![
        (ScVal::Bool(true), ScVal::U32(1)),
        (ScVal::U32(1), ScVal::U32(2)),
        (ScVal::I32(1), ScVal::U32(3)),
    ]);
    for id in both(&env) {
        let ret = invoke(&env, &id, "colliding_keys", vec![]).unwrap();
        assert_eq!(ret, vecv(vec![a.clone(), b.clone()]));
        let evs = events(&env);
        let n = evs.len();
        for (i, want) in [(n - 2, &a), (n - 1, &b)] {
            let ContractEventBody::V0(body) = &evs[i].0.body;
            assert_eq!(body.topics.to_vec(), vec![sym("colliding")]);
            assert_eq!(&body.data, want);
        }
    }
}

// --- cap-0046/scval-nested-vec-99-in-event, nested arguments --------------

/// Deepest `nested_vec(depth)` the host completes in 90..=110 (bounded scan).
fn max_emitted_depth(env: &Env, id: &Address) -> u32 {
    let mut max = 0;
    for d in 90..=110 {
        if invoke(env, id, "nested_vec", vec![ScVal::U32(d)]).is_ok() {
            max = d;
        }
    }
    max
}

#[test]
fn nested_vec_at_the_host_limit() {
    let env = env();
    let id = wasm_only(&env);
    let max = max_emitted_depth(&env, &id);
    // Measured: the host converts at most this many SCV_VEC levels around an
    // innermost Void into event data and the return value (limit 100).
    assert_eq!(max, MAX_EMITTED_DEPTH);
    let ret = invoke(&env, &id, "nested_vec", vec![ScVal::U32(max)]).unwrap();
    assert_eq!(ret, nested(max));
    let (topics, data) = last(&env);
    assert_eq!(topics, vec![sym("nested")]);
    assert_eq!(data, nested(max));
}
const MAX_EMITTED_DEPTH: u32 = 99;

#[test]
fn argument_nested_beyond_the_host_limit_fails() {
    let env = env();
    let id = wasm_only(&env);
    let mut ok = 0;
    for d in 90..=110 {
        if invoke(&env, &id, "echo", vec![nested(d)]).is_ok() {
            ok = d;
        }
    }
    assert_eq!(ok, MAX_ARGUMENT_DEPTH);
    assert!(invoke(&env, &id, "echo", vec![nested(MAX_ARGUMENT_DEPTH + 1)]).is_err());
}
const MAX_ARGUMENT_DEPTH: u32 = 99;

// --- cap-0046/scvec-null-pointer-versus-empty -----------------------------

#[test]
fn null_vec_and_map_bodies_are_refused_empty_ones_pass() {
    // SCV_VEC / SCV_MAP with an absent body is valid XDR but the host refuses
    // to convert it; the empty forms pass. So only the synthetic row can carry
    // the null form.
    let env = env();
    for id in both(&env) {
        for null in [ScVal::Vec(None), ScVal::Map(None)] {
            assert!(
                invoke(&env, &id, "echo", vec![null.clone()]).is_err(),
                "{null:?}"
            );
        }
        let empty_vec = ScVal::Vec(Some(Default::default()));
        let empty_map = ScVal::Map(Some(Default::default()));
        assert_eq!(
            invoke(&env, &id, "echo", vec![empty_vec.clone()]).unwrap(),
            empty_vec
        );
        assert_eq!(
            invoke(&env, &id, "echo", vec![empty_map.clone()]).unwrap(),
            empty_map
        );
    }
}

// --- cap-0046/scstring-and-scsymbol-non-utf8 ------------------------------

#[test]
fn non_utf8_string_is_emitted_verbatim() {
    let env = env();
    for id in both(&env) {
        let ret = invoke(&env, &id, "raw_string", vec![bytes(&[0xff, 0xfe])]).unwrap();
        assert_eq!(ret, string(&[0xff, 0xfe]));
        let (topics, data) = last(&env);
        assert_eq!(topics, vec![sym("raw_string"), string(&[0xff, 0xfe])]);
        assert_eq!(data, string(&[0xff, 0xfe]));
        // The same bytes also pass through as an argument.
        let echo = invoke(
            &env,
            &id,
            "echo",
            vec![string(&[0xff, 0xfe, 0x00, 0xed, 0xa0, 0x80])],
        );
        assert_eq!(echo.unwrap(), string(&[0xff, 0xfe, 0x00, 0xed, 0xa0, 0x80]));
    }
}

#[test]
fn symbol_outside_the_charset_is_rejected() {
    // ScSymbol is XDR `string<32>`, but the host accepts only [A-Za-z0-9_]:
    // a non-UTF-8 (or any other) symbol cannot reach a ledger from a contract.
    let env = env();
    for id in both(&env) {
        for bad in [&[0xffu8][..], b"a b", b"\xc3\xa9"] {
            let v = ScVal::Symbol(ScSymbol(bad.try_into().unwrap()));
            assert!(invoke(&env, &id, "echo", vec![v]).is_err(), "{bad:?}");
        }
        assert_eq!(
            invoke(&env, &id, "echo", vec![sym("ok_1")]).unwrap(),
            sym("ok_1")
        );
    }
}

// --- cap-0046/event-topic-count-extremes ----------------------------------

#[test]
fn topic_counts_zero_one_four_and_beyond() {
    let env = env();
    for id in both(&env) {
        for n in [0u32, 1, 4, 5, 16] {
            invoke(&env, &id, "topic_count", vec![ScVal::U32(n)]).unwrap();
            let (topics, data) = last(&env);
            let want: StdVec<ScVal> = (0..n).map(ScVal::U32).collect();
            assert_eq!(topics, want);
            assert_eq!(data, ScVal::U32(n));
        }
    }
}

#[test]
fn non_token_transfer_symbol() {
    let env = env();
    for id in both(&env) {
        invoke(&env, &id, "transfer_lookalike", vec![]).unwrap();
        let (topics, data) = last(&env);
        assert_eq!(topics, vec![sym("transfer")]);
        assert_eq!(data, string(b"not a token transfer"));
    }
}

// --- cap-0067 token-shaped events -----------------------------------------

#[test]
fn transfer_with_every_to_muxed_id_form() {
    let env = env();
    let (from, to) = (addr(account(1)), addr(account(2)));
    let forms = [
        ScVal::Void,
        ScVal::U64(u64::MAX),
        bytes(&[1, 2, 3, 4]),
        bytes(&[7; 40]),
        string(b"memo text"),
        ScVal::I32(5),
    ];
    for id in both(&env) {
        // absent: bare i128
        invoke(
            &env,
            &id,
            "transfer",
            vec![
                from.clone(),
                to.clone(),
                i128v(100),
                ScVal::Bool(false),
                ScVal::Void,
            ],
        )
        .unwrap();
        let (topics, data) = last(&env);
        assert_eq!(topics, vec![sym("transfer"), from.clone(), to.clone()]);
        assert_eq!(data, i128v(100));
        for f in &forms {
            invoke(
                &env,
                &id,
                "transfer",
                vec![
                    from.clone(),
                    to.clone(),
                    i128v(100),
                    ScVal::Bool(true),
                    f.clone(),
                ],
            )
            .unwrap();
            let (_, data) = last(&env);
            assert_eq!(
                data,
                map(vec![
                    (sym("amount"), i128v(100)),
                    (sym("to_muxed_id"), f.clone())
                ])
            );
        }
    }
}

#[test]
fn mint_legacy_and_current_layouts() {
    let env = env();
    let (admin, to) = (addr(account(3)), addr(account(4)));
    for id in both(&env) {
        let base = |a: ScVal| vec![a, to.clone(), i128v(5), ScVal::Bool(false), ScVal::Void];
        invoke(&env, &id, "mint", base(admin.clone())).unwrap();
        assert_eq!(last(&env).0, vec![sym("mint"), admin.clone(), to.clone()]);
        invoke(&env, &id, "mint", base(ScVal::Void)).unwrap();
        assert_eq!(last(&env).0, vec![sym("mint"), to.clone()]);
        assert_eq!(last(&env).1, i128v(5));
    }
}

#[test]
fn sep41_burn_clawback_approve_map_forms() {
    let env = env();
    let (a, b) = (addr(account(5)), addr(account(6)));
    for id in both(&env) {
        invoke(
            &env,
            &id,
            "burn",
            vec![a.clone(), i128v(7), ScVal::Bool(true)],
        )
        .unwrap();
        assert_eq!(
            last(&env),
            (
                vec![sym("burn"), a.clone()],
                map(vec![(sym("amount"), i128v(7))])
            )
        );
        invoke(
            &env,
            &id,
            "burn",
            vec![a.clone(), i128v(7), ScVal::Bool(false)],
        )
        .unwrap();
        assert_eq!(last(&env).1, i128v(7));

        invoke(
            &env,
            &id,
            "clawback",
            vec![b.clone(), a.clone(), i128v(8), ScVal::Bool(true)],
        )
        .unwrap();
        assert_eq!(
            last(&env),
            (
                vec![sym("clawback"), b.clone(), a.clone()],
                map(vec![(sym("amount"), i128v(8))])
            )
        );
        invoke(
            &env,
            &id,
            "clawback",
            vec![ScVal::Void, a.clone(), i128v(8), ScVal::Bool(false)],
        )
        .unwrap();
        assert_eq!(last(&env), (vec![sym("clawback"), a.clone()], i128v(8)));

        let approve = |m: bool| {
            vec![
                a.clone(),
                b.clone(),
                i128v(9),
                ScVal::U32(1000),
                ScVal::Bool(m),
            ]
        };
        invoke(&env, &id, "approve", approve(true)).unwrap();
        assert_eq!(
            last(&env),
            (
                vec![sym("approve"), a.clone(), b.clone()],
                map(vec![
                    (sym("amount"), i128v(9)),
                    (sym("live_until_ledger"), ScVal::U32(1000))
                ])
            )
        );
        invoke(&env, &id, "approve", approve(false)).unwrap();
        assert_eq!(last(&env).1, vecv(vec![i128v(9), ScVal::U32(1000)]));
    }
}

// --- cap-0067/forged-token-event-from-unrelated-contract ------------------

#[test]
fn forged_sac_shaped_transfer() {
    let env = env();
    let issuer = Strkey::PublicKeyEd25519(ed25519::PublicKey([9; 32])).to_string();
    let asset = format!("USD:{issuer}");
    let (from, victim) = (addr(account(10)), addr(account(11)));
    for id in both(&env) {
        invoke(
            &env,
            &id,
            "forged_sac_event",
            vec![
                sym("transfer"),
                vecv(vec![from.clone(), victim.clone()]),
                string(asset.as_bytes()),
                i128v(1_000_000_000),
            ],
        )
        .unwrap();
        let (e, failed) = events(&env).pop().unwrap();
        assert!(!failed);
        // The emitting contract is this one, not the asset's SAC.
        assert_eq!(
            e.contract_id,
            Some(ScAddress::from(&id).try_into_contract_id())
        );
        let ContractEventBody::V0(b) = e.body;
        assert_eq!(
            b.topics.to_vec(),
            vec![
                sym("transfer"),
                from.clone(),
                victim.clone(),
                string(asset.as_bytes())
            ]
        );
        assert_eq!(b.data, i128v(1_000_000_000));
    }
}

trait ContractIdOf {
    fn try_into_contract_id(self) -> ContractId;
}
impl ContractIdOf for ScAddress {
    fn try_into_contract_id(self) -> ContractId {
        match self {
            ScAddress::Contract(c) => c,
            other => panic!("not a contract address: {other:?}"),
        }
    }
}

// --- ScAddress kinds -------------------------------------------------------

#[test]
fn address_kinds_a_contract_can_construct() {
    let env = env();
    let g = Strkey::PublicKeyEd25519(ed25519::PublicKey([1; 32])).to_string();
    let c = Strkey::Contract(Contract([2; 32])).to_string();
    let m = Strkey::MuxedAccountEd25519(ed25519::MuxedAccount {
        ed25519: [3; 32],
        id: 42,
    })
    .to_string();
    let muxed = ScAddress::MuxedAccount(MuxedEd25519Account {
        id: 42,
        ed25519: Uint256([3; 32]),
    });
    for id in both(&env) {
        for (s, want) in [
            (&g, account(1)),
            (&c, ScAddress::Contract(ContractId(Hash([2; 32])))),
            // A muxed account is allowed in topics, data and return values.
            (&m, muxed.clone()),
        ] {
            let ret = invoke(&env, &id, "address_from_strkey", vec![string(s.as_bytes())]);
            assert_eq!(ret.unwrap(), addr(want.clone()));
            let (topics, data) = last(&env);
            assert_eq!(topics, vec![sym("address"), addr(want.clone())]);
            assert_eq!(data, addr(want));
        }
    }
}

#[test]
fn address_kinds_the_host_refuses() {
    let env = env();
    let b = Strkey::ClaimableBalance(ClaimableBalance::V0([4; 32])).to_string();
    let l = Strkey::LiquidityPool(LiquidityPool([5; 32])).to_string();
    // W (muxed contract) is Protocol 30; this testutils host is Protocol 29.
    let w = Strkey::MuxedContract(MuxedContract {
        contract_id: [6; 32],
        id: 7,
    })
    .to_string();
    for id in both(&env) {
        for s in [&b, &l, &w] {
            let r = invoke(&env, &id, "address_from_strkey", vec![string(s.as_bytes())]);
            assert!(r.is_err(), "{s} was accepted: {r:?}");
        }
        // The same kinds given directly as ScVal arguments.
        for a in [
            ScAddress::ClaimableBalance(ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(
                [4; 32],
            ))),
            ScAddress::LiquidityPool(PoolId(Hash([5; 32]))),
        ] {
            assert!(
                invoke(&env, &id, "echo", vec![addr(a.clone())]).is_err(),
                "{a:?}"
            );
        }
    }
}

#[test]
fn address_echo_includes_own_address_and_muxed_argument() {
    let env = env();
    let muxed = addr(ScAddress::MuxedAccount(MuxedEd25519Account {
        id: u64::MAX,
        ed25519: Uint256([8; 32]),
    }));
    for id in both(&env) {
        let own = addr(ScAddress::from(&id));
        let ret = invoke(&env, &id, "address_echo", vec![muxed.clone()]).unwrap();
        assert_eq!(ret, vecv(vec![own.clone(), muxed.clone()]));
        assert_eq!(
            last(&env),
            (vec![sym("address"), own, muxed.clone()], muxed.clone())
        );
    }
}

// --- cap-0046/scval-integer-extremes --------------------------------------

#[test]
fn integer_extremes() {
    let env = env();
    let want = vecv(vec![
        i128v(i128::MIN),
        i128v(i128::MAX),
        i128v(-1),
        ScVal::U128(UInt128Parts {
            hi: u64::MAX,
            lo: u64::MAX,
        }),
        ScVal::U256(UInt256Parts {
            hi_hi: u64::MAX,
            hi_lo: u64::MAX,
            lo_hi: u64::MAX,
            lo_lo: u64::MAX,
        }),
        ScVal::I256(Int256Parts {
            hi_hi: i64::MIN,
            hi_lo: 0,
            lo_hi: 0,
            lo_lo: 0,
        }),
        ScVal::I256(Int256Parts {
            hi_hi: i64::MAX,
            hi_lo: u64::MAX,
            lo_hi: u64::MAX,
            lo_lo: u64::MAX,
        }),
        ScVal::I256(Int256Parts {
            hi_hi: -1,
            hi_lo: u64::MAX,
            lo_hi: u64::MAX,
            lo_lo: u64::MAX,
        }),
        ScVal::U64(u64::MAX),
        ScVal::I64(i64::MIN),
    ]);
    for id in both(&env) {
        assert_eq!(invoke(&env, &id, "int_extremes", vec![]).unwrap(), want);
        assert_eq!(last(&env), (vec![sym("int_extremes")], want.clone()));
    }
}

// --- storage (S19) ---------------------------------------------------------

#[test]
fn storage_round_trip_in_every_durability() {
    let env = env();
    let key = map(vec![(sym("k"), vecv(vec![ScVal::U32(1)]))]);
    for id in both(&env) {
        for kind in 0u32..3 {
            let val = string(&[0xff, kind as u8]);
            invoke(
                &env,
                &id,
                "put",
                vec![ScVal::U32(kind), key.clone(), val.clone()],
            )
            .unwrap();
            let got = invoke(&env, &id, "get", vec![ScVal::U32(kind), key.clone()]).unwrap();
            assert_eq!(got, val);
        }
        assert!(invoke(
            &env,
            &id,
            "put",
            vec![ScVal::U32(3), key.clone(), ScVal::Void]
        )
        .is_err());
    }
}

#[test]
fn muxed_address_allowed_as_stored_value_but_not_as_key() {
    let env = env();
    let muxed = addr(ScAddress::MuxedAccount(MuxedEd25519Account {
        id: 1,
        ed25519: Uint256([12; 32]),
    }));
    for id in both(&env) {
        invoke(
            &env,
            &id,
            "put",
            vec![ScVal::U32(1), sym("m"), muxed.clone()],
        )
        .unwrap();
        let got = invoke(&env, &id, "get", vec![ScVal::U32(1), sym("m")]).unwrap();
        assert_eq!(got, muxed);

        // As a key the call must not succeed. Observed on this testutils host
        // (soroban-env-host 29.0.1): it ends in Error(Budget, ExceededLimit),
        // raised as a panic from testutils auth bookkeeping after the call,
        // at well under the default budget. The host source rejects a muxed
        // address in a storage key with (Storage, InvalidInput); which error
        // core reports is not established here. Only "not stored" is asserted.
        let as_key = invoke(
            &env,
            &id,
            "put",
            vec![ScVal::U32(1), muxed.clone(), ScVal::Void],
        );
        assert!(as_key.is_err(), "muxed key accepted");
    }
}

// --- cap-0087/ml-dsa-sized-byte-arguments ---------------------------------

#[test]
fn ml_dsa_sized_byte_arguments() {
    let env = env();
    for id in both(&env) {
        for n in [2592usize, 4627] {
            let r = invoke(&env, &id, "bytes_len", vec![bytes(&vec![0xab; n])]).unwrap();
            assert_eq!(r, ScVal::U32(n as u32));
        }
    }
}

// --- failure after emitting ------------------------------------------------

#[test]
fn fail_after_emit_leaves_a_failed_call_event() {
    let env = env();
    for id in both(&env) {
        let r = invoke(&env, &id, "fail_after_emit", vec![ScVal::U32(7)]);
        let err = r
            .expect_err("call must fail")
            .error
            .expect("a host error, not a panic");
        assert!(
            err.is_type(soroban_sdk::xdr::ScErrorType::Contract),
            "{err:?}"
        );
        assert_eq!(err.get_code(), 7);
        let (e, failed) = events(&env).pop().unwrap();
        assert!(failed, "event of a failed call must be marked failed");
        let ContractEventBody::V0(b) = e.body;
        assert_eq!(b.topics.to_vec(), vec![sym("before_fail")]);
        assert_eq!(b.data, ScVal::U32(7));
    }
}

// --- matched nested authorization -----------------------------------------

#[test]
fn auth_nested_requires_a_tree_of_chain_length_plus_one() {
    let env = env();
    let ids: StdVec<Address> = (0..4).map(|_| wasm_only(&env)).collect();
    let client = crate::ShapeEmitterClient::new(&env, &ids[0]);
    let who = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
    let chain = soroban_sdk::Vec::from_slice(&env, &ids[1..]);
    env.mock_all_auths();
    client.auth_nested(&who, &chain);
    let auths = env.auths();
    assert_eq!(auths.len(), 1);
    let mut depth = 0;
    let mut inv = &auths[0].1;
    while let Some(next) = inv.sub_invocations.first() {
        depth += 1;
        inv = next;
    }
    assert_eq!(depth, 3);
}

#[test]
fn auth_nested_cannot_reenter_the_same_contract() {
    // The host forbids re-entry: a chain that names the calling contract fails
    // even when every authorization is granted.
    let env = env();
    let id = wasm_only(&env);
    env.mock_all_auths();
    let r = invoke(
        &env,
        &id,
        "auth_nested",
        vec![addr(account(14)), vecv(vec![addr(ScAddress::from(&id))])],
    );
    assert!(r.is_err());
}

#[test]
fn auth_nested_fails_without_authorization() {
    let env = env();
    let id = wasm_only(&env);
    let who = addr(account(13));
    let r = invoke(&env, &id, "auth_nested", vec![who, vecv(vec![])]);
    assert!(r.is_err());
}
