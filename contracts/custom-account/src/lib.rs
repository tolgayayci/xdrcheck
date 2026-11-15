//! `custom-account`: the smallest custom account contract scenario S07 needs.
//!
//! `__check_auth` accepts any signature value (an arbitrary `ScVal`, as
//! CAP-0046-11 allows) and forwards the authorization to every delegated
//! signer attached to the auth entry (CAP-0071
//! `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES`). A delegate that is itself an
//! instance of this contract forwards again to its own nested delegates, so
//! the `SorobanDelegateSignature.nestedDelegates` recursion can be made as
//! deep as the host allows. Serves `cap-0071/credentials-with-nested-delegates`.
//!
//! It also emits one event per check, `[check_auth]` with data
//! `U32(<number of delegates>)`, so a ledger shows which accounts ran.
//!
//! This contract authorizes everything. It exists for local test chains only.
#![no_std]
#![allow(deprecated)] // `Events::publish` is deprecated in favour of typed events.

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    Env, Error, Symbol, Val, Vec,
};

#[contract]
pub struct CustomAccount;

#[contractimpl]
impl CustomAccountInterface for CustomAccount {
    type Signature = Val;
    type Error = Error;

    fn __check_auth(
        env: Env,
        _signature_payload: Hash<32>,
        _signature: Val,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let delegates = env.custom_account().get_delegated_signers();
        for d in delegates.iter() {
            env.custom_account().delegate_auth(&d);
        }
        env.events().publish(
            Vec::<Val>::from_slice(&env, &[Symbol::new(&env, "check_auth").to_val()]),
            delegates.len(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod test;
