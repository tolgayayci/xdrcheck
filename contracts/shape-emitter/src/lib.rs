//! `shape-emitter`: a test contract whose only job is to put rare-but-valid
//! shapes into ledger meta — as contract events, return values and contract
//! data — so local-core scenarios S07, S15 and S19 can emit them on both
//! passphrases.
//!
//! Public functions name the corpus entry IDs (from `corpus/plan.json`) they
//! serve. Functions take and return built-in types only (`Val`, `Vec`,
//! `Map`, `Bytes`, `String`, `Address`, integers), so the contract spec holds
//! function entries and nothing else; the generator writes arguments as XDR.
//!
//! Event topics and data are published with the raw `Events::publish` call
//! rather than `#[contractevent]` types, because the point is to choose the
//! topic count and layout freely, including layouts no typed event allows.
//!
//! What the host does not let a contract emit (each covered by a unit test
//! that shows the rejection):
//! - an `SCV_SYMBOL` outside `[A-Za-z0-9_]`, so no non-UTF-8 symbol;
//! - `ScAddress` of kind claimable balance or liquidity pool;
//! - a muxed address inside a contract-data key;
//! - a value nested beyond the host depth limit (100).
#![no_std]
#![allow(deprecated)] // `Events::publish` is deprecated in favour of typed events.

use soroban_sdk::{
    contract, contractimpl, panic_with_error, Address, Bytes, Env, Error, IntoVal, Map,
    MuxedAddress, String, Symbol, Val, Vec, I256, U256,
};

#[contract]
pub struct ShapeEmitter;

/// Storage kind selector for [`ShapeEmitter::put`] and [`ShapeEmitter::get`].
pub const TEMPORARY: u32 = 0;
pub const PERSISTENT: u32 = 1;
pub const INSTANCE: u32 = 2;

fn sym(env: &Env, s: &str) -> Val {
    Symbol::new(env, s).to_val()
}

fn topics(env: &Env, items: &[Val]) -> Vec<Val> {
    Vec::from_slice(env, items)
}

/// `{amount: i128, to_muxed_id: <v>}`; keys are symbols, so host order is lexical.
fn amount_map(env: &Env, amount: i128, muxed: Option<Val>) -> Val {
    let mut m: Map<Symbol, Val> = Map::new(env);
    m.set(Symbol::new(env, "amount"), amount.into_val(env));
    if let Some(v) = muxed {
        m.set(Symbol::new(env, "to_muxed_id"), v);
    }
    m.to_val()
}

#[contractimpl]
impl ShapeEmitter {
    /// Constructor with an argument that emits an event and writes instance
    /// storage. Serves `cap-0058/create-contract-v2-with-constructor`
    /// (`CREATE_CONTRACT_V2` with constructor arguments; constructor events in
    /// the same transaction). Uploading this wasm serves
    /// `cap-0054/contract-code-entry-with-cost-inputs`.
    pub fn __constructor(env: Env, tag: Val) {
        env.storage().instance().set(&sym(&env, "tag"), &tag);
        env.events()
            .publish(topics(&env, &[sym(&env, "init")]), tag);
    }

    /// Emits an event with caller-supplied topics and data, verbatim.
    /// The general route for any shape the caller can encode as arguments.
    pub fn emit(env: Env, topics: Vec<Val>, data: Val) {
        env.events().publish(topics, data);
    }

    /// Returns its argument unchanged. An argument nested beyond the host depth
    /// limit fails at argument conversion.
    pub fn echo(_env: Env, v: Val) -> Val {
        v
    }

    /// Emits and returns two maps whose keys collide after native conversion:
    /// `{U32(1), String("1"), Symbol("1")}` and `{Bool(true), U32(1), I32(1)}`.
    /// The host orders keys by type, then value. Serves
    /// `cap-0046/event-data-map-with-colliding-keys`, and gives the synthetic
    /// `cap-0046/scval-map-keys-collide-three-types` a core-emitted twin.
    pub fn colliding_keys(env: Env) -> Vec<Val> {
        let mut a: Map<Val, Val> = Map::new(&env);
        a.set(1u32.into_val(&env), 10u32.into_val(&env));
        a.set(String::from_str(&env, "1").to_val(), 20u32.into_val(&env));
        a.set(sym(&env, "1"), 30u32.into_val(&env));
        let mut b: Map<Val, Val> = Map::new(&env);
        b.set(true.into_val(&env), 1u32.into_val(&env));
        b.set(1u32.into_val(&env), 2u32.into_val(&env));
        b.set(1i32.into_val(&env), 3u32.into_val(&env));
        let both = Vec::from_slice(&env, &[a.to_val(), b.to_val()]);
        env.events()
            .publish(topics(&env, &[sym(&env, "colliding")]), a.to_val());
        env.events()
            .publish(topics(&env, &[sym(&env, "colliding")]), b.to_val());
        both
    }

    /// Builds a vector nested `depth` levels around `Void`, emits it as event
    /// data and returns it. Used to measure the host maximum. Serves
    /// `cap-0046/scval-nested-vec-99-in-event`.
    pub fn nested_vec(env: Env, depth: u32) -> Val {
        let mut v: Val = ().into_val(&env);
        for _ in 0..depth {
            v = Vec::from_slice(&env, &[v]).to_val();
        }
        env.events()
            .publish(topics(&env, &[sym(&env, "nested")]), v);
        v
    }

    /// Emits a `String` holding the given bytes (no UTF-8 check is made by the
    /// host) as both a topic and the data, and returns it. With `ff fe` it
    /// serves the `string` member of `cap-0046/scstring-and-scsymbol-non-utf8`.
    /// The `symbol` member cannot be emitted: the host rejects symbol bytes
    /// outside `[A-Za-z0-9_]`.
    pub fn raw_string(env: Env, bytes: Bytes) -> String {
        let mut buf = [0u8; 256];
        let n = bytes.len() as usize;
        if n > buf.len() {
            panic_with_error!(&env, Error::from_contract_error(1));
        }
        bytes.copy_into_slice(&mut buf[..n]);
        let s = String::from_bytes(&env, &buf[..n]);
        env.events().publish(
            topics(&env, &[sym(&env, "raw_string"), s.to_val()]),
            s.to_val(),
        );
        s
    }

    /// Emits one event with `n` topics `U32(0)..U32(n-1)` and data `U32(n)`.
    /// Serves the `zero-topics` and `four-topics` members of
    /// `cap-0046/event-topic-count-extremes`. The host enforces no topic count
    /// itself (see the unit tests); only the events size limit applies.
    pub fn topic_count(env: Env, n: u32) {
        let mut t: Vec<Val> = Vec::new(&env);
        for i in 0..n {
            t.push_back(i.into_val(&env));
        }
        env.events().publish(t, n);
    }

    /// A non-token event whose first topic is the symbol `transfer`: one topic,
    /// string data. Serves the `non-token-transfer-symbol` member of
    /// `cap-0046/event-topic-count-extremes`.
    pub fn transfer_lookalike(env: Env) {
        env.events().publish(
            topics(&env, &[sym(&env, "transfer")]),
            String::from_str(&env, "not a token transfer"),
        );
    }

    /// Custom-token `transfer` event `[transfer, from, to]`. With
    /// `with_muxed = false` the data is a bare `i128` (`to_muxed_id` absent);
    /// otherwise `{amount, to_muxed_id: <to_muxed_id>}` with any value the
    /// caller supplies (Void, u64, bytes, string, or a wrong type).
    /// Serves `cap-0067/token-events-bytes-and-bad-type-muxed-id` (members
    /// `bytes-4`, `bytes-40`, `i32`) and gives local twins to
    /// `cap-0067/to-muxed-id-void-custom-token`.
    pub fn transfer(
        env: Env,
        from: Address,
        to: Address,
        amount: i128,
        with_muxed: bool,
        to_muxed_id: Val,
    ) {
        let data = if with_muxed {
            amount_map(&env, amount, Some(to_muxed_id))
        } else {
            amount.into_val(&env)
        };
        env.events().publish(
            topics(&env, &[sym(&env, "transfer"), from.to_val(), to.to_val()]),
            data,
        );
    }

    /// Custom-token `mint`: legacy layout `[mint, admin, to]` when `admin` is
    /// given, otherwise `[mint, to]`. Data as in [`Self::transfer`]. Gives
    /// local twins to `cap-0067/legacy-layout-mint-with-admin-topic`.
    pub fn mint(
        env: Env,
        admin: Option<Address>,
        to: Address,
        amount: i128,
        with_muxed: bool,
        to_muxed_id: Val,
    ) {
        let mut t = topics(&env, &[sym(&env, "mint")]);
        if let Some(a) = admin {
            t.push_back(a.to_val());
        }
        t.push_back(to.to_val());
        let data = if with_muxed {
            amount_map(&env, amount, Some(to_muxed_id))
        } else {
            amount.into_val(&env)
        };
        env.events().publish(t, data);
    }

    /// SEP-41 `burn` `[burn, from]`; data `{amount}` when `map_form`, else
    /// `i128`. Serves `cap-0067/sep41-map-form-burn-approve-events`.
    pub fn burn(env: Env, from: Address, amount: i128, map_form: bool) {
        let data = if map_form {
            amount_map(&env, amount, None)
        } else {
            amount.into_val(&env)
        };
        env.events()
            .publish(topics(&env, &[sym(&env, "burn"), from.to_val()]), data);
    }

    /// `clawback`: `[clawback, admin, from]` when `admin` is given, else
    /// `[clawback, from]`; data `{amount}` when `map_form`, else `i128`.
    /// Serves `cap-0067/sep41-map-form-burn-approve-events`.
    pub fn clawback(env: Env, admin: Option<Address>, from: Address, amount: i128, map_form: bool) {
        let mut t = topics(&env, &[sym(&env, "clawback")]);
        if let Some(a) = admin {
            t.push_back(a.to_val());
        }
        t.push_back(from.to_val());
        let data = if map_form {
            amount_map(&env, amount, None)
        } else {
            amount.into_val(&env)
        };
        env.events().publish(t, data);
    }

    /// SEP-41 `approve` `[approve, from, spender]`; data
    /// `{amount, live_until_ledger}` when `map_form`, else the vector
    /// `[amount, live_until_ledger]`. Serves
    /// `cap-0067/sep41-map-form-burn-approve-events`.
    pub fn approve(
        env: Env,
        from: Address,
        spender: Address,
        amount: i128,
        live_until_ledger: u32,
        map_form: bool,
    ) {
        let data = if map_form {
            let mut m: Map<Symbol, Val> = Map::new(&env);
            m.set(Symbol::new(&env, "amount"), amount.into_val(&env));
            m.set(
                Symbol::new(&env, "live_until_ledger"),
                live_until_ledger.into_val(&env),
            );
            m.to_val()
        } else {
            let pair: [Val; 2] = [amount.into_val(&env), live_until_ledger.into_val(&env)];
            Vec::from_slice(&env, &pair).to_val()
        };
        env.events().publish(
            topics(
                &env,
                &[sym(&env, "approve"), from.to_val(), spender.to_val()],
            ),
            data,
        );
    }

    /// An event laid out exactly like a Stellar Asset Contract event:
    /// `[name, <addresses...>, "<CODE>:<ISSUER>"]` with `i128` data. This
    /// contract is not that asset's SAC, so no balance moves. With
    /// `name = transfer` and two addresses it serves
    /// `cap-0067/forged-token-event-from-unrelated-contract`.
    pub fn forged_sac_event(
        env: Env,
        name: Symbol,
        addresses: Vec<Address>,
        asset: String,
        amount: i128,
    ) {
        let mut t = topics(&env, &[name.to_val()]);
        for a in addresses.iter() {
            t.push_back(a.to_val());
        }
        t.push_back(asset.to_val());
        env.events().publish(t, amount);
    }

    /// Parses a strkey with the host and emits the address as a topic and as
    /// the data, then returns it. 56-character strkeys (`G…`, `C…`) become an
    /// `Address`; 69-character ones (`M…`, and `W…` on a Protocol 30 host)
    /// become a `MuxedAddress`, which the host does allow in topics and data.
    /// `B…` and `L…` strkeys are rejected by the host. No plan row of its own:
    /// it backs the "every `ScAddress` kind" requirement of S15.
    pub fn address_from_strkey(env: Env, strkey: String) -> Val {
        let v = if strkey.len() == 56 {
            Address::from_string(&strkey).to_val()
        } else {
            MuxedAddress::from_string(&strkey).to_val()
        };
        env.events()
            .publish(topics(&env, &[sym(&env, "address"), v]), v);
        v
    }

    /// Emits and returns this contract's own address and an address received
    /// as an argument (any kind the host accepts in arguments).
    pub fn address_echo(env: Env, a: Val) -> Vec<Val> {
        let own = env.current_contract_address().to_val();
        env.events()
            .publish(topics(&env, &[sym(&env, "address"), own, a]), a);
        Vec::from_slice(&env, &[own, a])
    }

    /// Emits and returns integer extremes: i128 min/max/−1, u128 max,
    /// u256 max, i256 min/max/−1, u64 max, i64 min. Gives core-emitted twins
    /// to the synthetic `cap-0046/scval-integer-extremes`.
    pub fn int_extremes(env: Env) -> Vec<Val> {
        let v = Vec::from_slice(
            &env,
            &[
                i128::MIN.into_val(&env),
                i128::MAX.into_val(&env),
                (-1i128).into_val(&env),
                u128::MAX.into_val(&env),
                U256::from_parts(&env, u64::MAX, u64::MAX, u64::MAX, u64::MAX).to_val(),
                I256::from_parts(&env, i64::MIN, 0, 0, 0).to_val(),
                I256::from_parts(&env, i64::MAX, u64::MAX, u64::MAX, u64::MAX).to_val(),
                I256::from_parts(&env, -1, u64::MAX, u64::MAX, u64::MAX).to_val(),
                u64::MAX.into_val(&env),
                i64::MIN.into_val(&env),
            ],
        );
        env.events()
            .publish(topics(&env, &[sym(&env, "int_extremes")]), v.to_val());
        v
    }

    /// Stores `val` under `key` in temporary (0), persistent (1) or instance
    /// (2) storage. Serves `cap-0062/eviction-on-local-chain`,
    /// `cap-0066/autorestore-on-local-chain` and
    /// `cap-0077/frozen-key-access-on-local-chain` (S19).
    pub fn put(env: Env, kind: u32, key: Val, val: Val) {
        match kind {
            TEMPORARY => env.storage().temporary().set(&key, &val),
            PERSISTENT => env.storage().persistent().set(&key, &val),
            INSTANCE => env.storage().instance().set(&key, &val),
            _ => panic_with_error!(&env, Error::from_contract_error(2)),
        }
    }

    /// Reads `key` from the selected storage; reading an archived persistent
    /// entry is what auto-restores it (`cap-0066/autorestore-on-local-chain`).
    pub fn get(env: Env, kind: u32, key: Val) -> Option<Val> {
        match kind {
            TEMPORARY => env.storage().temporary().get(&key),
            PERSISTENT => env.storage().persistent().get(&key),
            INSTANCE => env.storage().instance().get(&key),
            _ => panic_with_error!(&env, Error::from_contract_error(2)),
        }
    }

    /// Accepts any `Bytes` and returns its length. Serves
    /// `cap-0087/ml-dsa-sized-byte-arguments` (2592 and 4627 bytes).
    pub fn bytes_len(_env: Env, b: Bytes) -> u32 {
        b.len()
    }

    /// Emits an event, then fails with contract error `code`: a failed
    /// transaction whose events survive only as diagnostics.
    pub fn fail_after_emit(env: Env, code: u32) {
        env.events()
            .publish(topics(&env, &[sym(&env, "before_fail")]), code);
        panic_with_error!(&env, Error::from_contract_error(code));
    }

    /// Calls `require_auth` on `addr`, then calls `auth_nested(addr, rest)` on
    /// the first contract of `chain`, so a matched authorization tree
    /// `chain.len() + 1` invocations deep is needed. The host forbids contract
    /// re-entry, so `chain` must name distinct contracts (for example several
    /// instances of this wasm), none of them this one. With `addr` a
    /// `custom-account` instance and an empty chain it is the protected call
    /// of `cap-0071/credentials-with-nested-delegates` (S07).
    pub fn auth_nested(env: Env, addr: Address, chain: Vec<Address>) {
        addr.require_auth();
        if let Some(next) = chain.first() {
            let rest = chain.slice(1..);
            env.invoke_contract::<()>(
                &next,
                &Symbol::new(&env, "auth_nested"),
                Vec::from_slice(&env, &[addr.to_val(), rest.to_val()]),
            );
        }
    }
}

#[cfg(test)]
mod test;
