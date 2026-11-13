//! The probe transactions of `tests/data/probe-transactions.yaml` are built
//! and signed on the testnet and the public passphrase at Protocols 28 and 30; each envelope
//! decodes back to the intended operations, every signature verifies against the right key over
//! the right bytes, and every hash equals an independent computation.
//!
//! "Independent" here means: the network ID, the actor keys (from the documented derivation
//! `sha256("xcc/key/<label>")`), the signature payload framing, the hints and the signature checks
//! are all recomputed in this file with `sha2` and `ed25519-dalek`, not taken from the
//! interpreter.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature as EdSignature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    DecoratedSignature, FeeBumpTransactionInnerTx, Limits, Memo, MuxedAccount, OperationBody,
    Preconditions, ReadXdr, SignerKey, Transaction, TransactionEnvelope, WriteXdr,
};
use xdrcheck_gen::scenario::{build, BuiltScenario, BuiltStep, Interpreter, Item, Options, Scenario};

const TESTNET: &str = "Test SDF Network ; September 2015";
const PUBNET: &str = "Public Global Stellar Network ; September 2015";
const PASSPHRASES: [&str; 2] = [TESTNET, PUBNET];
const PROTOCOLS: [u32; 2] = [28, 30];

const ENVELOPE_TYPE_TX: [u8; 4] = [0, 0, 0, 2];
const ENVELOPE_TYPE_TX_FEE_BUMP: [u8; 4] = [0, 0, 0, 5];
const FIRST_LEDGER: i64 = 13;

fn data(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn network_id(passphrase: &str) -> [u8; 32] {
    sha256(passphrase.as_bytes())
}

fn key(label: &str) -> VerifyingKey {
    SigningKey::from_bytes(&sha256(format!("xcc/key/{label}").as_bytes())).verifying_key()
}

fn pk(label: &str) -> [u8; 32] {
    key(label).to_bytes()
}

fn xdr<T: WriteXdr>(v: &T) -> Vec<u8> {
    v.to_xdr(Limits::none()).unwrap()
}

fn tx_hash(passphrase: &str, tx: &Transaction) -> [u8; 32] {
    let mut buf = network_id(passphrase).to_vec();
    buf.extend_from_slice(&ENVELOPE_TYPE_TX);
    buf.extend_from_slice(&xdr(tx));
    sha256(&buf)
}

fn hint_of(public: &[u8; 32]) -> [u8; 4] {
    public[28..].try_into().unwrap()
}

/// Verify `sig` as `label`'s ed25519 signature over `message` with the plain key hint.
fn assert_key_sig(sig: &DecoratedSignature, label: &str, message: &[u8]) {
    assert_eq!(sig.hint.0, hint_of(&pk(label)), "hint of {label}");
    let bytes: [u8; 64] = sig
        .signature
        .0
        .as_slice()
        .try_into()
        .expect("64-byte signature");
    key(label)
        .verify_strict(message, &EdSignature::from_bytes(&bytes))
        .unwrap_or_else(|e| panic!("signature of {label}: {e}"));
}

/// Verify a signed-payload signature: over the payload, hint = key hint XOR payload hint.
fn assert_payload_sig(sig: &DecoratedSignature, label: &str, payload: &[u8], tx_hash: &[u8; 32]) {
    let k = hint_of(&pk(label));
    let mut p = [0u8; 4];
    if payload.len() >= 4 {
        p.copy_from_slice(&payload[payload.len() - 4..]);
    } else {
        p[..payload.len()].copy_from_slice(payload);
    }
    let want = [k[0] ^ p[0], k[1] ^ p[1], k[2] ^ p[2], k[3] ^ p[3]];
    assert_eq!(sig.hint.0, want, "signed-payload hint of {label}");
    let bytes: [u8; 64] = sig.signature.0.as_slice().try_into().unwrap();
    let ed = EdSignature::from_bytes(&bytes);
    key(label)
        .verify_strict(payload, &ed)
        .unwrap_or_else(|e| panic!("signed-payload signature of {label}: {e}"));
    assert!(
        key(label).verify_strict(tx_hash, &ed).is_err(),
        "a signed-payload signature is over the payload, not the hash"
    );
}

fn muxed(label: &str, id: u64) -> MuxedAccount {
    MuxedAccount::MuxedEd25519(stellar_xdr::MuxedAccountMed25519 {
        id,
        ed25519: stellar_xdr::Uint256(pk(label)),
    })
}

fn plain(label: &str) -> MuxedAccount {
    MuxedAccount::Ed25519(stellar_xdr::Uint256(pk(label)))
}

fn signed_payload(label: &str, payload: &[u8]) -> SignerKey {
    SignerKey::Ed25519SignedPayload(stellar_xdr::SignerKeyEd25519SignedPayload {
        ed25519: stellar_xdr::Uint256(pk(label)),
        payload: payload.to_vec().try_into().unwrap(),
    })
}

fn step<'a>(built: &'a BuiltScenario, id: &str) -> &'a BuiltStep {
    built.steps.iter().find(|s| s.id == id).unwrap()
}

/// The step's envelope decoded back from its bytes and from its base64; both must equal the
/// envelope the interpreter built. Returns the decoded envelope.
fn decoded(step: &BuiltStep) -> TransactionEnvelope {
    let built = step.tx.as_ref().expect("step has a transaction");
    let from_bytes = match xdrcheck_xdr::decode(
        "TransactionEnvelope",
        &built.envelope.bytes,
        &xdrcheck_xdr::Limits::default(),
    )
    .unwrap()
    {
        stellar_xdr::Type::TransactionEnvelope(e) => *e,
        _ => unreachable!(),
    };
    let from_b64 =
        TransactionEnvelope::from_xdr_base64(&built.envelope.base64, Limits::none()).unwrap();
    assert_eq!(from_bytes, built.envelope.envelope);
    assert_eq!(from_b64, from_bytes);
    from_bytes
}

/// A v1 envelope's transaction and signatures; the hash is checked independently.
fn v1(step: &BuiltStep, passphrase: &str) -> (Transaction, Vec<DecoratedSignature>, [u8; 32]) {
    let TransactionEnvelope::Tx(e) = decoded(step) else {
        panic!("{}: expected ENVELOPE_TYPE_TX", step.id)
    };
    let hash = tx_hash(passphrase, &e.tx);
    assert_eq!(
        step.tx.as_ref().unwrap().envelope.hash,
        hash,
        "{}: hash",
        step.id
    );
    (e.tx, e.signatures.to_vec(), hash)
}

fn only_op(tx: &Transaction) -> &OperationBody {
    assert_eq!(tx.operations.len(), 1);
    assert!(tx.operations[0].source_account.is_none());
    &tx.operations[0].body
}

fn seq(n: i64) -> i64 {
    (FIRST_LEDGER << 32) + n
}

fn load() -> Scenario {
    Scenario::load(&data("probe-transactions.yaml")).unwrap()
}

#[test]
fn muxed_payment_from_max_id_to_2_pow_53_plus_1() {
    let scenario = load();
    for pp in PASSPHRASES {
        for p in PROTOCOLS {
            let built = build(&scenario, pp, p, Options::default()).unwrap();
            let s = step(&built, "muxed-payment");
            let (tx, sigs, hash) = v1(s, pp);
            assert_eq!(tx.source_account, muxed("A", u64::MAX));
            assert_eq!(tx.seq_num.0, seq(1), "A was funded at ledger 13");
            assert_eq!(tx.fee, 1000);
            let OperationBody::Payment(pay) = only_op(&tx) else {
                panic!("payment")
            };
            assert_eq!(pay.destination, muxed("B", (1u64 << 53) + 1));
            assert_eq!(pay.amount, 12_345_678);
            assert_eq!(pay.asset, stellar_xdr::Asset::Native);
            assert_eq!(sigs.len(), 1);
            assert_key_sig(&sigs[0], "A", &hash);
            // Annotations: placeholders resolved, derived reference kept for the manifest.
            let values = &s.expect.as_ref().unwrap()["values"];
            assert_eq!(
                values[0]["equals"],
                "MAZ2HQB7GBW5KKURD7LMCBY4YU4BKCN6I3H2UL2BTZ3E5I6PCPKTJ7777777777777HGO"
            );
            assert_eq!(values[1]["equals"], seq(1).to_string());
            assert_eq!(values[2]["equals"], "${derived.fee_charged}");
            assert_eq!(s.ledger, 14);
            assert_eq!(s.close_time, 1_700_000_000 + 12 * 1_000_000);
        }
    }
}

#[test]
fn set_options_adds_signed_payload_signers_of_1_and_64_bytes() {
    let scenario = load();
    let payload64: Vec<u8> = (0u8..64).collect();
    for pp in PASSPHRASES {
        for p in PROTOCOLS {
            let built = build(&scenario, pp, p, Options::default()).unwrap();
            for (id, label, payload, fee, n) in [
                ("add-signer-1-byte", "D", vec![0x2a], 1000, 2),
                ("add-signer-64-bytes", "C", payload64.clone(), 1001, 3),
            ] {
                let s = step(&built, id);
                let (tx, sigs, hash) = v1(s, pp);
                assert_eq!(tx.source_account, plain("A"));
                assert_eq!(tx.seq_num.0, seq(n));
                assert_eq!(tx.fee, fee);
                let OperationBody::SetOptions(so) = only_op(&tx) else {
                    panic!("set_options")
                };
                let signer = so.signer.as_ref().unwrap();
                assert_eq!(signer.key, signed_payload(label, &payload));
                assert_eq!(signer.weight, 1);
                assert!(so.master_weight.is_none() && so.home_domain.is_none());
                assert_eq!(sigs.len(), 1);
                assert_key_sig(&sigs[0], "A", &hash);
            }
            let (a, b) = (
                step(&built, "add-signer-1-byte"),
                step(&built, "add-signer-64-bytes"),
            );
            assert_eq!((a.ledger, a.close_time), (b.ledger, b.close_time));
            assert_eq!(b.same_ledger_as.as_deref(), Some("add-signer-1-byte"));
        }
    }
}

#[test]
fn payment_authorised_only_by_a_signed_payload_signature() {
    let scenario = load();
    for pp in PASSPHRASES {
        for p in PROTOCOLS {
            let built = build(&scenario, pp, p, Options::default()).unwrap();
            let (tx, sigs, hash) = v1(step(&built, "authorised-by-signed-payload-only"), pp);
            assert_eq!(tx.source_account, plain("A"));
            assert_eq!(tx.seq_num.0, seq(4));
            let OperationBody::Payment(pay) = only_op(&tx) else {
                panic!("payment")
            };
            assert_eq!(pay.destination, plain("C"));
            assert_eq!(pay.amount, 10_000_000);
            assert_eq!(sigs.len(), 1, "A's own key does not sign");
            assert_payload_sig(&sigs[0], "D", &[0x2a], &hash);
            assert_ne!(sigs[0].hint.0, hint_of(&pk("A")));
        }
    }
}

#[test]
fn extra_signers_precondition() {
    let scenario = load();
    let payload =
        hex::decode("5ca1ab1e00000000000000000000000000000000000000000000000000000001").unwrap();
    for pp in PASSPHRASES {
        for p in PROTOCOLS {
            let built = build(&scenario, pp, p, Options::default()).unwrap();
            let (tx, sigs, hash) = v1(step(&built, "extra-signer-in-preconditions"), pp);
            assert_eq!(tx.source_account, plain("B"));
            assert_eq!(tx.seq_num.0, seq(1));
            let Preconditions::V2(v2) = &tx.cond else {
                panic!("PRECOND_V2")
            };
            assert_eq!(
                v2.extra_signers.to_vec(),
                vec![signed_payload("D", &payload)]
            );
            let tb = v2.time_bounds.as_ref().unwrap();
            assert_eq!((tb.min_time.0, tb.max_time.0), (0, 0));
            assert!(v2.ledger_bounds.is_none() && v2.min_seq_num.is_none());
            assert_eq!(sigs.len(), 2);
            assert_key_sig(&sigs[0], "B", &hash);
            assert_payload_sig(&sigs[1], "D", &payload, &hash);
        }
    }
}

#[test]
fn fee_bump_wraps_the_signed_inner_transaction() {
    let scenario = load();
    for pp in PASSPHRASES {
        for p in PROTOCOLS {
            let built = build(&scenario, pp, p, Options::default()).unwrap();
            for (id, inner_source, fee_source, fee_label, fee, inner_seq) in [
                (
                    "fee-bump-muxed-fee-source",
                    "A",
                    muxed("C", 7),
                    "C",
                    4000,
                    seq(5),
                ),
                ("fee-bump-failed-inner", "B", plain("D"), "D", 5000, seq(2)),
            ] {
                let s = step(&built, id);
                let built_tx = s.tx.as_ref().unwrap();
                let TransactionEnvelope::TxFeeBump(outer) = decoded(s) else {
                    panic!("{id}: expected ENVELOPE_TYPE_TX_FEE_BUMP")
                };
                assert_eq!(outer.tx.fee_source, fee_source);
                assert_eq!(outer.tx.fee, fee);
                let FeeBumpTransactionInnerTx::Tx(inner) = &outer.tx.inner_tx;
                assert_eq!(inner.tx, built_tx.transaction);
                assert_eq!(inner.tx.source_account, plain(inner_source));
                assert_eq!(inner.tx.seq_num.0, inner_seq);
                let OperationBody::Payment(pay) = only_op(&inner.tx) else {
                    panic!("payment")
                };
                assert_eq!(pay.destination, plain("D"));
                // Inner: hash and signature independent of the outer envelope.
                let inner_hash = tx_hash(pp, &inner.tx);
                assert_eq!(built_tx.inner_hash(), Some(inner_hash));
                assert_eq!(inner.signatures.len(), 1);
                assert_key_sig(&inner.signatures[0], inner_source, &inner_hash);
                let inner_env = built_tx.inner.as_ref().unwrap();
                assert_eq!(inner_env.envelope, TransactionEnvelope::Tx(inner.clone()));
                // Outer: hash over ENVELOPE_TYPE_TX_FEE_BUMP, signed by the fee source.
                let mut buf = network_id(pp).to_vec();
                buf.extend_from_slice(&ENVELOPE_TYPE_TX_FEE_BUMP);
                buf.extend_from_slice(&xdr(&outer.tx));
                let outer_hash = sha256(&buf);
                assert_eq!(built_tx.hash(), outer_hash);
                assert_ne!(outer_hash, inner_hash);
                assert_eq!(outer.signatures.len(), 1);
                assert_key_sig(&outer.signatures[0], fee_label, &outer_hash);
            }
            assert_eq!(
                step(&built, "fee-bump-failed-inner")
                    .expected
                    .result
                    .as_deref(),
                Some("tx_fee_bump_inner_failed")
            );
        }
    }
}

#[test]
fn hash_x_preimages_and_pre_auth() {
    let scenario = load();
    let preimage: Vec<u8> = (0u8..64).collect();
    for pp in PASSPHRASES {
        let built = build(&scenario, pp, 30, Options::default()).unwrap();
        let s = step(&built, "hash-x-and-pre-auth");
        let (tx, sigs, hash) = v1(s, pp);
        assert_eq!(tx.source_account, plain("C"));
        assert_eq!(tx.seq_num.0, seq(1));
        let Memo::Text(text) = &tx.memo else {
            panic!("memo text")
        };
        assert_eq!(text.to_string(), format!("close {}", s.close_time));
        assert_eq!(sigs.len(), 3, "pre_auth adds no signature");
        assert_key_sig(&sigs[0], "C", &hash);
        for (sig, pre) in [(&sigs[1], &[][..]), (&sigs[2], &preimage[..])] {
            assert_eq!(
                sig.signature.0.as_slice(),
                pre,
                "the preimage is the signature"
            );
            assert_eq!(
                sig.hint.0,
                sha256(pre)[28..],
                "hint: last 4 bytes of sha256(preimage)"
            );
        }
        let pre_auth = &s.tx.as_ref().unwrap().envelope.pre_authorised;
        assert_eq!(
            pre_auth,
            &vec![format!("{}", stellar_strkey::PreAuthTx(hash))]
        );
        assert_eq!(
            s.expected.submit_reject.as_deref(),
            Some("tx_bad_auth_extra")
        );
        assert!(s.entry.is_none());
    }
}

#[test]
fn twins_share_addresses_and_differ_in_hashes() {
    let scenario = load();
    let t = build(&scenario, TESTNET, 30, Options::default()).unwrap();
    let m = build(&scenario, PUBNET, 30, Options::default()).unwrap();
    assert_eq!(t.accounts, m.accounts);
    for label in ["A", "B", "C", "D"] {
        assert_eq!(
            t.accounts[label],
            format!("{}", stellar_strkey::ed25519::PublicKey(pk(label)))
        );
    }
    for (a, b) in t.steps.iter().zip(&m.steps) {
        let (ta, tb) = (a.tx.as_ref().unwrap(), b.tx.as_ref().unwrap());
        assert_eq!(ta.transaction, tb.transaction, "{}: same transaction", a.id);
        assert_ne!(
            ta.hash(),
            tb.hash(),
            "{}: the hash commits to the network",
            a.id
        );
        assert_eq!((a.ledger, a.close_time), (b.ledger, b.close_time));
    }
}

#[test]
fn root_funds_the_actors_on_each_network() {
    let scenario = load();
    for (pp, prefix, suffix) in [(TESTNET, "GBRPYHIL", "OX2H"), (PUBNET, "GAAZI4TC", "CWN7")] {
        let built = build(&scenario, pp, 30, Options::default()).unwrap();
        let fund = &built.setup[0];
        assert_eq!((fund.kind, fund.ledger), ("fund", 13));
        let xdrcheck_gen::scenario::SetupAction::Tx(tx) = &fund.action else {
            panic!("fund is a transaction")
        };
        let root = SigningKey::from_bytes(&network_id(pp)).verifying_key();
        let root_addr = format!("{}", stellar_strkey::ed25519::PublicKey(root.to_bytes()));
        assert!(
            root_addr.starts_with(prefix) && root_addr.ends_with(suffix),
            "{root_addr}"
        );
        let TransactionEnvelope::Tx(e) = &tx.envelope.envelope else {
            panic!("v1")
        };
        assert_eq!(
            e.tx.source_account,
            MuxedAccount::Ed25519(stellar_xdr::Uint256(root.to_bytes()))
        );
        assert_eq!(e.tx.seq_num.0, 1, "root starts at 0 unless injected");
        let hash = tx_hash(pp, &e.tx);
        assert_eq!(tx.envelope.hash, hash);
        assert_eq!(e.signatures[0].hint.0, hint_of(&root.to_bytes()));
        let sig: [u8; 64] = e.signatures[0].signature.0.as_slice().try_into().unwrap();
        root.verify_strict(&hash, &EdSignature::from_bytes(&sig))
            .unwrap();
        let created: Vec<_> = e
            .tx
            .operations
            .iter()
            .map(|op| match &op.body {
                OperationBody::CreateAccount(c) => (c.destination.0.clone(), c.starting_balance),
                other => panic!("{other:?}"),
            })
            .collect();
        let want: Vec<_> = ["A", "B", "C", "D"]
            .iter()
            .map(|l| {
                (
                    stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(pk(l))),
                    10_000 * 10_000_000,
                )
            })
            .collect();
        assert_eq!(created, want);
    }
}

#[test]
fn sequences_are_injectable() {
    let scenario = load();
    let mut options = Options::default();
    options.sequences.insert("A".into(), 1000);
    options.root_sequence = 41;
    let built = build(&scenario, TESTNET, 30, options).unwrap();
    let a = |id: &str| step(&built, id).tx.as_ref().unwrap().transaction.seq_num.0;
    assert_eq!(
        a("muxed-payment"),
        1001,
        "injected value wins over the fund"
    );
    assert_eq!(a("add-signer-1-byte"), 1002);
    assert_eq!(
        a("extra-signer-in-preconditions"),
        seq(1),
        "B still from the fund"
    );
    let xdrcheck_gen::scenario::SetupAction::Tx(fund) = &built.setup[0].action else {
        panic!()
    };
    assert_eq!(fund.transaction.seq_num.0, 42);

    // Driven item by item, as the node side does: correct B's sequence and the ledger mid-way.
    let mut it = Interpreter::new(&scenario, TESTNET, 30, Options::default()).unwrap();
    let mut seen = Vec::new();
    while let Some(item) = it.next_item() {
        match item.unwrap() {
            Item::Setup(_) => {
                it.set_sequence("B", 7 << 32).unwrap();
                it.set_next_ledger(40);
                it.set_next_close_time(1_800_000_000);
            }
            Item::Step(s) => seen.push(*s),
        }
    }
    let first = &seen[0];
    assert_eq!((first.ledger, first.close_time), (40, 1_800_000_000));
    assert_eq!(seen[1].ledger, 41);
    assert_eq!(seen[1].close_time, 1_700_000_000 + 39 * 1_000_000);
    let b = seen
        .iter()
        .find(|s| s.id == "extra-signer-in-preconditions")
        .unwrap();
    assert_eq!(b.tx.as_ref().unwrap().transaction.seq_num.0, (7 << 32) + 1);
    // A submission-time rejection does not consume C's sequence number.
    assert_eq!(it.sequence("C"), Some(FIRST_LEDGER << 32));
    assert_eq!(it.sequence("B"), Some((7 << 32) + 2));
}
