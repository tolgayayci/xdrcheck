//! Unit tests for `custom-account`, run against the vendored wasm
//! (`corpus/contracts/custom-account.wasm`), with the vendored
//! `shape-emitter` wasm as the protected contract.
//!
//! The delegate tests build `SorobanAuthorizationEntry` values by hand with
//! `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` (CAP-0071), the shape S07 needs.
extern crate std;

use std::{vec, vec::Vec as StdVec};

use soroban_sdk::{
    testutils::{EnvTestConfig, HostError, Ledger as _},
    xdr::{
        ContractEventBody, ContractEventType, HostFunction, InvokeContractArgs, ScAddress,
        ScSymbol, ScVal, SorobanAddressCredentials, SorobanAddressCredentialsWithDelegates,
        SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
        SorobanCredentials, SorobanDelegateSignature,
    },
    Address, Env,
};

use crate::CustomAccount;

const WASM: &[u8] = include_bytes!("../../../corpus/contracts/custom-account.wasm");
const EMITTER: &[u8] = include_bytes!("../../../corpus/contracts/shape-emitter.wasm");

fn env() -> Env {
    Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    })
}

fn sym(s: &str) -> ScVal {
    ScVal::Symbol(ScSymbol(s.try_into().unwrap()))
}

fn emitter(env: &Env) -> Address {
    env.register(EMITTER, (soroban_sdk::Symbol::new(env, "t"),))
}

/// `auth_nested(account, [])` on the emitter, authorized by one entry with
/// the given credentials.
fn call_protected(
    env: &Env,
    emitter: &Address,
    account: &Address,
    credentials: SorobanCredentials,
) -> Result<ScVal, HostError> {
    let args: StdVec<ScVal> = vec![
        ScVal::Address(ScAddress::from(account)),
        ScVal::Vec(Some(Default::default())),
    ];
    let invoke = InvokeContractArgs {
        contract_address: ScAddress::from(emitter),
        function_name: ScSymbol("auth_nested".try_into().unwrap()),
        args: args.clone().try_into().unwrap(),
    };
    let entry = SorobanAuthorizationEntry {
        credentials,
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
            sub_invocations: Default::default(),
        },
    };
    env.cost_estimate().budget().reset_default();
    env.host().set_authorization_entries(vec![entry])?;
    env.host()
        .invoke_function(HostFunction::InvokeContract(invoke))
}

fn address_credentials(
    account: &Address,
    nonce: i64,
    signature: ScVal,
) -> SorobanAddressCredentials {
    SorobanAddressCredentials {
        address: ScAddress::from(account),
        nonce,
        signature_expiration_ledger: 1000,
        signature,
    }
}

/// `check_auth` events, in order, as (emitting contract, delegate count).
fn checks(env: &Env) -> StdVec<(ScAddress, ScVal)> {
    env.host()
        .get_events()
        .unwrap()
        .0
        .into_iter()
        .filter(|e| e.event.type_ == ContractEventType::Contract && !e.failed_call)
        .filter_map(|e| {
            let ContractEventBody::V0(b) = e.event.body;
            (b.topics.to_vec() == vec![sym("check_auth")])
                .then(|| (ScAddress::Contract(e.event.contract_id.unwrap()), b.data))
        })
        .collect()
}

#[test]
fn wasm_uploads_at_protocol_29_and_not_at_28() {
    let env = env();
    let up = |e: &Env| {
        e.host()
            .invoke_function(HostFunction::UploadContractWasm(WASM.try_into().unwrap()))
    };
    assert!(up(&env).is_ok());
    let env28 = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env28.ledger().set_protocol_version(28);
    assert!(up(&env28).is_err());
}

#[test]
fn native_registration_accepts_any_signature() {
    let env = env();
    env.ledger().set_sequence_number(10);
    let account = env.register(CustomAccount, ());
    let em = emitter(&env);
    for (nonce, signature) in [
        (1, ScVal::Void),
        (2, ScVal::Vec(Some(Default::default()))),
        (3, ScVal::Bytes(vec![0xff; 64].try_into().unwrap())),
    ] {
        let creds = SorobanCredentials::Address(address_credentials(&account, nonce, signature));
        call_protected(&env, &em, &account, creds).unwrap();
    }
}

#[test]
fn any_signature_value_is_accepted() {
    let env = env();
    env.ledger().set_sequence_number(10);
    let account = env.register(WASM, ());
    let em = emitter(&env);
    for (nonce, signature) in [
        (1, ScVal::Void),
        (2, ScVal::Vec(Some(Default::default()))),
        (3, ScVal::Map(Some(Default::default()))),
        (4, ScVal::String(vec![0xff, 0xfe].try_into().unwrap())),
        (5, ScVal::Bytes(vec![0xab; 4627].try_into().unwrap())),
    ] {
        let creds = SorobanCredentials::Address(address_credentials(&account, nonce, signature));
        call_protected(&env, &em, &account, creds).unwrap();
        assert_eq!(
            checks(&env).last(),
            Some(&(ScAddress::from(&account), ScVal::U32(0)))
        );
    }
}

#[test]
fn null_vec_or_map_signature_is_refused_by_the_host() {
    // SCV_VEC / SCV_MAP with an absent (null) body is valid XDR, but the host
    // refuses to convert it, so it cannot be a signature on a ledger.
    let env = env();
    env.ledger().set_sequence_number(10);
    let account = env.register(WASM, ());
    let em = emitter(&env);
    for (nonce, signature) in [(1, ScVal::Vec(None)), (2, ScVal::Map(None))] {
        let creds = SorobanCredentials::Address(address_credentials(&account, nonce, signature));
        let r = call_protected(&env, &em, &account, creds);
        let err = r.expect_err("null body accepted").error;
        assert!(err.is_type(soroban_sdk::xdr::ScErrorType::Value), "{err:?}");
    }
}

#[test]
fn nested_delegates_each_run_check_auth() {
    let env = env();
    env.ledger().set_sequence_number(10);
    let root = env.register(WASM, ());
    let d1 = env.register(WASM, ());
    let d2 = env.register(WASM, ());
    let em = emitter(&env);
    // root -> d1 -> d2: a delegate with a nested delegate (second recursion).
    let creds = SorobanCredentials::AddressWithDelegates(SorobanAddressCredentialsWithDelegates {
        address_credentials: address_credentials(&root, 1, ScVal::Void),
        delegates: vec![SorobanDelegateSignature {
            address: ScAddress::from(&d1),
            signature: ScVal::U32(1),
            nested_delegates: vec![SorobanDelegateSignature {
                address: ScAddress::from(&d2),
                signature: ScVal::U32(2),
                nested_delegates: Default::default(),
            }]
            .try_into()
            .unwrap(),
        }]
        .try_into()
        .unwrap(),
    });
    call_protected(&env, &em, &root, creds).unwrap();
    let ran = checks(&env);
    let find = |a: &Address| ran.iter().find(|(c, _)| *c == ScAddress::from(a)).cloned();
    assert_eq!(find(&root).map(|x| x.1), Some(ScVal::U32(1)));
    assert_eq!(find(&d1).map(|x| x.1), Some(ScVal::U32(1)));
    assert_eq!(find(&d2).map(|x| x.1), Some(ScVal::U32(0)));
}
