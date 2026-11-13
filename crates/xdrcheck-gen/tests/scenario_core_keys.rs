//! The scenario interpreter and the node side derive the same keys, network IDs, transaction
//! hashes and signatures: actor seed `sha256("xcc/key/<label>")`, root seed = network ID.

use std::path::Path;

use stellar_xdr::TransactionEnvelope;
use xdrcheck_gen::core::keys::{self as core_keys, Keypair, KEY_NAMESPACE};
use xdrcheck_gen::scenario::{self, build, Options, Scenario, SignerSpec, NAMESPACE};

const PASSPHRASES: [&str; 2] = [core_keys::TESTNET_PASSPHRASE, core_keys::PUBNET_PASSPHRASE];

#[test]
fn same_namespace_keys_and_network_ids() {
    assert_eq!(NAMESPACE, KEY_NAMESPACE);
    for label in ["A", "B", "C", "D", "I1", "core-node", "issuer_2"] {
        let ours = scenario::actor_key(NAMESPACE, label);
        let theirs = Keypair::from_label(label);
        assert_eq!(
            ours.verifying_key().to_bytes(),
            theirs.public_key(),
            "{label}"
        );
        assert_eq!(
            scenario::keys::account_strkey(&ours.verifying_key().to_bytes()),
            theirs.address()
        );
        assert_eq!(
            scenario::signature_hint(&theirs.public_key()),
            theirs.hint()
        );
    }
    for pp in PASSPHRASES {
        assert_eq!(scenario::network_id(pp), core_keys::network_id(pp));
        assert_eq!(
            scenario::root_key(pp).verifying_key().to_bytes(),
            Keypair::root(pp).public_key()
        );
    }
}

#[test]
fn same_hashes_and_signatures_for_every_built_transaction() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/probe-transactions.yaml");
    let s = Scenario::load(&path).unwrap();
    let mut compared = 0;
    for pp in PASSPHRASES {
        let built = build(&s, pp, 30, Options::default()).unwrap();
        for step in &built.steps {
            let tx = step.tx.as_ref().unwrap();
            let inner_hash = tx.inner_hash().unwrap_or(tx.hash());
            assert_eq!(
                core_keys::tx_hash(pp, &tx.transaction).unwrap(),
                inner_hash,
                "{}",
                step.id
            );
            // Steps signed by ed25519 keys only: the node side's signer gives the same envelope
            // (ed25519 signatures are deterministic).
            let spec = s.steps.iter().find(|x| x.id == step.id).unwrap();
            let labels: Option<Vec<&str>> = spec
                .sign
                .iter()
                .flatten()
                .map(|x| match x {
                    SignerSpec::Key(l) => Some(l.as_str()),
                    _ => None,
                })
                .collect();
            let Some(labels) = labels else { continue };
            let keys: Vec<Keypair> = labels.iter().map(|l| Keypair::from_label(l)).collect();
            let refs: Vec<&Keypair> = keys.iter().collect();
            let theirs = core_keys::sign_transaction(pp, tx.transaction.clone(), &refs).unwrap();
            let ours: &TransactionEnvelope = match &tx.inner {
                Some(inner) => &inner.envelope,
                None => &tx.envelope.envelope,
            };
            assert_eq!(&theirs, ours, "{}", step.id);
            compared += 1;
        }
        // The root-signed funding transaction too.
        let scenario::SetupAction::Tx(fund) = &built.setup[0].action else {
            panic!("fund")
        };
        let theirs =
            core_keys::sign_transaction(pp, fund.transaction.clone(), &[&Keypair::root(pp)])
                .unwrap();
        assert_eq!(theirs, fund.envelope.envelope);
    }
    assert!(compared >= 10, "compared {compared} envelopes");
}
