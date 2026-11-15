//! `token-shape`: a token-shaped test contract for local-core scenarios.
//!
//! It implements the SEP-41 interface (`balance`, `transfer`, `transfer_from`, `approve`,
//! `allowance`, `burn`, `burn_from`, `decimals`, `name`, `symbol`) over its own storage, so an
//! indexer that recognises tokens by interface or by event shape treats it as a token. What it adds:
//!
//! - metadata whose `name` and `symbol` are caller-chosen bytes (`String` holds bytes; the host
//!   checks no encoding), stored in instance storage under `METADATA` in the layout the token SDK
//!   uses (`{decimal: u32, name: String, symbol: String}`) and returned by `name` / `symbol`;
//! - `mint` by the admin with any `i128` amount the caller gives, including zero and negative
//!   values (a real token rejects those; here the balance arithmetic is checked only for overflow);
//! - `emit_many`: `n` small events in one invocation, for event-count limits;
//! - functions whose events and storage disagree, for testing readers that trust either one:
//!   `fake_transfer` / `fake_mint` (event, no storage change), `silent_set` (storage, no event),
//!   `skewed_transfer` (storage moves one amount, the event states another), and
//!   `transfer_tagged` (an honest transfer whose event carries a fourth topic, an SCString of
//!   caller-chosen bytes, as Stellar Asset Contract events do).
//!
//! The interface matches the SEP-41 signature set exactly (parameter names included, e.g.
//! `approve(from, spender, amount, expiration_ledger)`), so spec-based classifiers accept it.
//!
//! Events follow the SEP-41 / CAP-67 layouts: `[transfer, from, to]`, `[mint, to]`, `[burn, from]`,
//! `[approve, from, spender]` with `[amount, live_until_ledger]`, data `i128` otherwise.
#![no_std]
#![allow(deprecated)] // `Events::publish` is deprecated in favour of typed events.

use soroban_sdk::{
    contract, contractimpl, panic_with_error, Address, Bytes, Env, Error, IntoVal, Map, String,
    Symbol, Val, Vec,
};

#[contract]
pub struct TokenShape;

fn sym(env: &Env, s: &str) -> Symbol {
    Symbol::new(env, s)
}

fn admin(env: &Env) -> Address {
    env.storage().instance().get(&sym(env, "ADMIN")).unwrap()
}

fn meta_field(env: &Env, field: &str) -> Val {
    let m: Map<Symbol, Val> = env.storage().instance().get(&sym(env, "METADATA")).unwrap();
    m.get(sym(env, field)).unwrap()
}

fn bal_key(env: &Env, id: &Address) -> Vec<Val> {
    Vec::from_slice(env, &[sym(env, "Balance").to_val(), id.to_val()])
}

fn read_bal(env: &Env, id: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&bal_key(env, id))
        .unwrap_or(0)
}

fn write_bal(env: &Env, id: &Address, v: i128) {
    env.storage().persistent().set(&bal_key(env, id), &v);
}

fn add(env: &Env, id: &Address, d: i128) {
    let v = read_bal(env, id)
        .checked_add(d)
        .unwrap_or_else(|| panic_with_error!(env, Error::from_contract_error(1)));
    write_bal(env, id, v);
}

fn publish(env: &Env, name: &str, addrs: &[&Address], data: Val) {
    let mut t: Vec<Val> = Vec::new(env);
    t.push_back(sym(env, name).to_val());
    for a in addrs {
        t.push_back(a.to_val());
    }
    env.events().publish(t, data);
}

#[contractimpl]
impl TokenShape {
    /// Stores the admin and the metadata; `name` and `symbol` are taken as raw bytes.
    pub fn __constructor(env: Env, admin: Address, decimal: u32, name: Bytes, symbol: Bytes) {
        let mut buf = [0u8; 1024];
        let s = |b: &Bytes, buf: &mut [u8; 1024]| {
            let n = b.len() as usize;
            if n > buf.len() {
                panic_with_error!(&env, Error::from_contract_error(2));
            }
            b.copy_into_slice(&mut buf[..n]);
            String::from_bytes(&env, &buf[..n])
        };
        let name = s(&name, &mut buf);
        let symbol = s(&symbol, &mut buf);
        let mut m: Map<Symbol, Val> = Map::new(&env);
        m.set(sym(&env, "decimal"), decimal.into_val(&env));
        m.set(sym(&env, "name"), name.to_val());
        m.set(sym(&env, "symbol"), symbol.to_val());
        env.storage().instance().set(&sym(&env, "METADATA"), &m);
        env.storage().instance().set(&sym(&env, "ADMIN"), &admin);
    }

    pub fn decimals(env: Env) -> u32 {
        meta_field(&env, "decimal").into_val(&env)
    }

    pub fn name(env: Env) -> String {
        meta_field(&env, "name").into_val(&env)
    }

    pub fn symbol(env: Env) -> String {
        meta_field(&env, "symbol").into_val(&env)
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        read_bal(&env, &id)
    }

    /// Admin mint of any amount (zero and negative included).
    pub fn mint(env: Env, to: Address, amount: i128) {
        admin(&env).require_auth();
        add(&env, &to, amount);
        publish(&env, "mint", &[&to], amount.into_val(&env));
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        add(&env, &from, amount.checked_neg().unwrap_or(0));
        add(&env, &to, amount);
        publish(&env, "transfer", &[&from, &to], amount.into_val(&env));
    }

    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        add(&env, &from, amount.checked_neg().unwrap_or(0));
        add(&env, &to, amount);
        publish(&env, "transfer", &[&from, &to], amount.into_val(&env));
    }

    pub fn approve(
        env: Env,
        from: Address,
        spender: Address,
        amount: i128,
        expiration_ledger: u32,
    ) {
        from.require_auth();
        let k = Vec::from_slice(
            &env,
            &[
                sym(&env, "Allowance").to_val(),
                from.to_val(),
                spender.to_val(),
            ],
        );
        env.storage().temporary().set(&k, &amount);
        let pair: [Val; 2] = [amount.into_val(&env), expiration_ledger.into_val(&env)];
        publish(
            &env,
            "approve",
            &[&from, &spender],
            Vec::from_slice(&env, &pair).to_val(),
        );
    }

    pub fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        let k = Vec::from_slice(
            &env,
            &[
                sym(&env, "Allowance").to_val(),
                from.to_val(),
                spender.to_val(),
            ],
        );
        env.storage().temporary().get(&k).unwrap_or(0)
    }

    pub fn burn(env: Env, from: Address, amount: i128) {
        from.require_auth();
        add(&env, &from, amount.checked_neg().unwrap_or(0));
        publish(&env, "burn", &[&from], amount.into_val(&env));
    }

    pub fn burn_from(env: Env, spender: Address, from: Address, amount: i128) {
        spender.require_auth();
        add(&env, &from, amount.checked_neg().unwrap_or(0));
        publish(&env, "burn", &[&from], amount.into_val(&env));
    }

    /// A `transfer` event with no authorization and no storage change.
    pub fn fake_transfer(env: Env, from: Address, to: Address, amount: i128) {
        publish(&env, "transfer", &[&from, &to], amount.into_val(&env));
    }

    /// A `mint` event with no storage change.
    pub fn fake_mint(env: Env, to: Address, amount: i128) {
        publish(&env, "mint", &[&to], amount.into_val(&env));
    }

    /// Admin sets a balance directly: storage changes, no event.
    pub fn silent_set(env: Env, id: Address, amount: i128) {
        admin(&env).require_auth();
        write_bal(&env, &id, amount);
    }

    /// Moves `amount` in storage and emits a transfer event stating `event_amount`.
    pub fn skewed_transfer(env: Env, from: Address, to: Address, amount: i128, event_amount: i128) {
        from.require_auth();
        add(&env, &from, amount.checked_neg().unwrap_or(0));
        add(&env, &to, amount);
        publish(&env, "transfer", &[&from, &to], event_amount.into_val(&env));
    }

    /// An honest transfer whose event is `[transfer, from, to, String(tag)]`.
    pub fn transfer_tagged(env: Env, from: Address, to: Address, amount: i128, tag: Bytes) {
        from.require_auth();
        add(&env, &from, amount.checked_neg().unwrap_or(0));
        add(&env, &to, amount);
        let mut buf = [0u8; 1024];
        let n = tag.len() as usize;
        if n > buf.len() {
            panic_with_error!(&env, Error::from_contract_error(2));
        }
        tag.copy_into_slice(&mut buf[..n]);
        let t = Vec::from_slice(
            &env,
            &[
                sym(&env, "transfer").to_val(),
                from.to_val(),
                to.to_val(),
                String::from_bytes(&env, &buf[..n]).to_val(),
            ],
        );
        env.events().publish(t, amount);
    }

    /// Emits `n` events `[n, i]` with data `i` (`u32`).
    pub fn emit_many(env: Env, n: u32) {
        for i in 0..n {
            let t = Vec::from_slice(&env, &[sym(&env, "n").to_val(), i.into_val(&env)]);
            env.events().publish(t, i);
        }
    }
}
