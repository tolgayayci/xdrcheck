//! Two scenario features checked without a node: a `.json` scenario may nest a value far deeper
//! than YAML's fixed 128 levels (it loads, validates and builds its envelope), and
//! `${muxed_contract(NAME, id)}` gives the `W…` address of a scenario contract.

use serde_json::{json, Value};
use stellar_xdr::{OperationBody, ScAddress, ScVal};
use xdrcheck_gen::scenario::{build, contract_id_from_address, contract_salt, Options, Scenario};

const TESTNET: &str = "Test SDF Network ; September 2015";

fn invoke(args: Value) -> Value {
    json!({
        "source_account": "${acct.A}",
        "fee": 50001000,
        "seq_num": "${seq.A}",
        "cond": "none",
        "memo": "none",
        "operations": [{
            "source_account": null,
            "body": {"invoke_host_function": {
                "host_function": {"invoke_contract": {
                    "contract_address": "${contract.id(emitter)}",
                    "function_name": "echo",
                    "args": args
                }},
                "auth": []
            }}
        }],
        "ext": "v0"
    })
}

fn scenario(args: Value) -> Value {
    json!({
        "scenario": "deep-and-muxed",
        "caps": [46],
        "protocols": [30],
        "profile": "lake",
        "actors": ["A"],
        "contracts": {"emitter": {"wasm": "contracts/shape-emitter.wasm", "deployer": "A"}},
        "setup": [{"fund": {"A": "10000"}}],
        "steps": [{"id": "call", "entry": "probe/call", "tx": invoke(args), "sign": [{"key": "A"}]}]
    })
}

fn first_arg_depth(v: &ScVal) -> usize {
    let mut depth = 0;
    let mut cur = v;
    while let ScVal::Vec(Some(items)) = cur {
        depth += 1;
        match items.first() {
            Some(next) => cur = next,
            None => break,
        }
    }
    depth
}

#[test]
fn json_scenario_nests_900_levels() {
    const LEVELS: usize = 900;
    let dir = std::env::temp_dir().join(format!("xdrcheck-deep-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("deep.json");
    // Built as text: a serde_json::Value this deep cannot be serialised on a test thread's stack.
    let arg = format!(
        "{}\"void\"{}",
        "{\"vec\": [".repeat(LEVELS),
        "]}".repeat(LEVELS)
    );
    let text = serde_json::to_string(&scenario(json!(["@ARG@"])))
        .unwrap()
        .replace("\"@ARG@\"", &arg);
    std::fs::write(&path, text).unwrap();

    // YAML cannot hold it: the same document as YAML stops at the parser's recursion limit.
    let Err(yaml_err) = Scenario::from_yaml_str(&std::fs::read_to_string(&path).unwrap()) else {
        panic!("YAML stops at 128 levels")
    };
    let yaml_err = yaml_err.to_string();
    assert!(yaml_err.contains("recursion limit"), "{yaml_err}");

    let depth = xdrcheck_xdr::with_stack(xdrcheck_xdr::DEFAULT_STACK_SIZE, || {
        let s = Scenario::load(&path).unwrap();
        let built = build(&s, TESTNET, 30, Options::default()).unwrap();
        let tx = built.steps[0].tx.as_ref().unwrap();
        assert!(!tx.envelope.bytes.is_empty());
        let OperationBody::InvokeHostFunction(op) = &tx.transaction.operations[0].body else {
            panic!("not an invoke_host_function")
        };
        let stellar_xdr::HostFunction::InvokeContract(call) = &op.host_function else {
            panic!("not invoke_contract")
        };
        first_arg_depth(&call.args[0])
    });
    assert_eq!(depth, LEVELS);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn muxed_contract_placeholder_names_a_contract_with_an_id() {
    let doc = scenario(json!([
        {"address": "${contract.id(emitter)}"},
        {"address": "${muxed_contract(emitter, 9223372036854775808)}"},
        {"address": "${muxed_contract(emitter, 18446744073709551615)}"}
    ]));
    let s = Scenario::from_value(doc).unwrap();
    let built = build(&s, TESTNET, 30, Options::default()).unwrap();
    let tx = &built.steps[0].tx.as_ref().unwrap().transaction;
    let OperationBody::InvokeHostFunction(op) = &tx.operations[0].body else {
        panic!()
    };
    let stellar_xdr::HostFunction::InvokeContract(call) = &op.host_function else {
        panic!()
    };
    let ScVal::Address(ScAddress::Contract(plain)) = &call.args[0] else {
        panic!("{:?}", call.args[0])
    };
    // The contract is A's deploy with the salt of its name, as `${contract.id(emitter)}` says.
    let actors = vec!["A".to_string()];
    let keys = xdrcheck_gen::scenario::Keys::new(xdrcheck_gen::scenario::NAMESPACE, TESTNET, &actors);
    let expected = contract_id_from_address(
        &xdrcheck_gen::scenario::network_id(TESTNET),
        &keys.public("A").unwrap(),
        &contract_salt(xdrcheck_gen::scenario::NAMESPACE, "emitter"),
    )
    .unwrap();
    assert_eq!(plain.0 .0, expected);
    for (arg, id) in call.args[1..].iter().zip([1u64 << 63, u64::MAX]) {
        let ScVal::Address(ScAddress::MuxedContract(m)) = arg else {
            panic!("{arg:?}")
        };
        assert_eq!(m.contract_id, *plain);
        assert_eq!(m.id, id);
    }
    let strkey = stellar_strkey::MuxedContract {
        contract_id: expected,
        id: u64::MAX,
    }
    .to_string();
    assert!(strkey.starts_with('W'), "{strkey}");
}
