//! The scenario keys `binary` and `channel`: defaults, and the schema's gate that a protocol above the newest
//! released one runs only under `channel: next`.

use xdrcheck_gen::scenario::{Error, Scenario};

fn example(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/schema/examples/scenario")
        .join(name)
}

#[test]
fn binary_and_channel_default_to_the_release() {
    let s = Scenario::load(&example("valid-01.json")).unwrap();
    assert_eq!(
        (s.binary.as_str(), s.channel.as_str()),
        ("release", "stable")
    );
}

#[test]
fn next_protocols_only_under_the_next_channel() {
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(example("valid-04.json")).unwrap()).unwrap();
    xdrcheck_gen::scenario::file::validate_schema(&doc)
        .expect("protocol 31 under channel: next is valid");
    for (file, at) in [("invalid-05.json", ""), ("invalid-06.json", "/binary")] {
        let Err(Error::Schema(errors)) = Scenario::load(&example(file)) else {
            panic!("{file} must fail the schema")
        };
        assert!(
            errors.iter().any(|e| e.starts_with(at)),
            "{file}: {errors:?}"
        );
    }
}
