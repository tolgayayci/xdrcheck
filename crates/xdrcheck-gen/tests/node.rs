//! A standalone node on each real passphrase closes ten empty ledgers at fixed close
//! times, the ledgers read back from the meta stream with the right sequences and protocol, and no
//! stellar-core process is left behind — after a clean stop, a panic, or a failed close.

mod common;

use std::panic::{catch_unwind, AssertUnwindSafe};

use stellar_xdr::LedgerCloseMeta;
use xdrcheck_gen::core::{ClosePolicy, Node, NodeOptions, PUBNET_PASSPHRASE, TESTNET_PASSPHRASE};
use xdrcheck_xdr::{split_ledger_stream, Gate, Limits};

#[test]
fn ten_empty_ledgers_on_both_passphrases() {
    let Some(bin) = common::core_or_skip("ten_empty_ledgers_on_both_passphrases") else {
        return;
    };
    let mut last_hashes = Vec::new();
    for passphrase in [TESTNET_PASSPHRASE, PUBNET_PASSPHRASE] {
        let dir = common::run_dir("empty");
        let mut node = Node::start(&bin, &dir, NodeOptions::new(passphrase)).unwrap();
        assert_eq!(
            common::processes_in(&dir).len(),
            1,
            "pgrep sees the running node"
        );
        let info = node.info().unwrap();
        assert_eq!(info["info"]["network"], passphrase);

        let closed: Vec<_> = (0..10).map(|_| node.close().unwrap()).collect();
        node.stop().unwrap();
        assert_eq!(
            common::processes_in(&dir),
            Vec::<String>::new(),
            "no process left in {dir:?}"
        );

        // Read the whole stream back independently of the incremental reader.
        let stream = std::fs::read(dir.join("meta.xdr")).unwrap();
        let ledgers = split_ledger_stream(&stream, &Limits::default(), &Gate::default()).unwrap();
        assert_eq!(ledgers.len(), 10);
        let mut previous: Option<[u8; 32]> = None;
        for (k, (l, (info, payload))) in closed.iter().zip(&ledgers).enumerate() {
            let seq = 2 + k as u32;
            let t = 1_700_000_000 + k as u64 * 1_000_000;
            assert_eq!((l.sequence, info.sequence), (seq, seq));
            assert_eq!((l.close_time, info.close_time), (t, t));
            // No upgrade was armed: the node stays at the genesis protocol, whose meta is v0.
            assert_eq!((l.protocol, info.protocol), (0, 0));
            assert_eq!(l.ledger_close_meta_version, 0);
            assert_eq!(l.bytes, *payload);
            assert_eq!(l.header_hash, info.header_hash);
            let LedgerCloseMeta::V0(m) = l.decode().unwrap() else {
                panic!("ledger {seq} is not LedgerCloseMeta v0");
            };
            assert!(m.tx_set.txs.is_empty(), "ledger {seq} is empty");
            if let Some(p) = previous {
                assert_eq!(
                    m.ledger_header.header.previous_ledger_hash.0, p,
                    "chain at {seq}"
                );
            }
            previous = Some(l.header_hash);
        }
        last_hashes.push(previous.unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }
    assert_ne!(
        last_hashes[0], last_hashes[1],
        "the passphrase twins differ"
    );
}

#[test]
fn panic_while_running_leaves_no_process() {
    let Some(bin) = common::core_or_skip("panic_while_running_leaves_no_process") else {
        return;
    };
    let dir = common::run_dir("panic");
    let r = catch_unwind(AssertUnwindSafe(|| {
        let mut node = Node::start(&bin, &dir, NodeOptions::new(TESTNET_PASSPHRASE)).unwrap();
        node.close().unwrap();
        assert_eq!(common::processes_in(&dir).len(), 1);
        panic!("scenario step failed");
    }));
    assert!(r.is_err());
    assert_eq!(common::processes_in(&dir), Vec::<String>::new());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn close_time_behind_the_node_fails_and_leaves_no_process() {
    let Some(bin) = common::core_or_skip("close_time_behind_the_node_fails_and_leaves_no_process")
    else {
        return;
    };
    let dir = common::run_dir("too-early");
    let mut opts = NodeOptions::new(TESTNET_PASSPHRASE);
    // Ledger 2 would close at 0: before genesis' close time, so core must refuse it.
    opts.close_policy = ClosePolicy {
        base: 0,
        stride: 1_000_000,
    };
    {
        let mut node = Node::start(&bin, &dir, opts).unwrap();
        let err = node.close().unwrap_err().to_string();
        assert!(err.contains("too early"), "{err}");
        assert_eq!(node.last_closed(), 1);
    }
    assert_eq!(common::processes_in(&dir), Vec::<String>::new());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn port_taken_before_core_binds_it_is_retried_on_fresh_ports() {
    let Some(bin) =
        common::core_or_skip("port_taken_before_core_binds_it_is_retried_on_fresh_ports")
    else {
        return;
    };
    // Another process holds the command port the first attempt is told to use, as when a free port is
    // taken between choosing it and core binding it.
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken = squatter.local_addr().unwrap().port();
    let spare = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let query = spare.local_addr().unwrap().port();
    drop(spare);
    let dir = common::run_dir("port-race");
    let mut opts = NodeOptions::new(TESTNET_PASSPHRASE);
    opts.first_ports = Some((taken, query));
    let mut node = Node::start(&bin, &dir, opts).unwrap();
    assert_ne!(node.http_port(), taken);
    let attempts = std::fs::read_to_string(dir.join("start-attempts.log")).unwrap();
    assert_eq!(attempts.lines().count(), 1, "{attempts}");
    assert!(
        attempts.contains(&format!("attempt 1/3 on ports {taken} and {query}")),
        "{attempts}"
    );
    assert!(dir.join("core.attempt-1.log").is_file());
    assert_eq!(node.close().unwrap().sequence, 2);
    node.stop().unwrap();
    drop(squatter);
    assert_eq!(common::processes_in(&dir), Vec::<String>::new());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The flaky start-up seen under load: two nodes started at the same moment chose the same free
/// command port. The second core exits on "bind: Address already in use", but the first answers
/// `info` on that port as a fresh node on the same passphrase, so the second start must neither take
/// that reply for its own node nor give up: it starts again on fresh ports.
#[test]
fn command_port_held_by_another_core_is_retried_on_fresh_ports() {
    let Some(bin) =
        common::core_or_skip("command_port_held_by_another_core_is_retried_on_fresh_ports")
    else {
        return;
    };
    let dir_a = common::run_dir("holder");
    let mut holder = Node::start(&bin, &dir_a, NodeOptions::new(TESTNET_PASSPHRASE)).unwrap();
    let spare = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let query = spare.local_addr().unwrap().port();
    drop(spare);
    let dir = common::run_dir("port-race-core");
    let mut opts = NodeOptions::new(TESTNET_PASSPHRASE);
    opts.first_ports = Some((holder.http_port(), query));
    let mut node = Node::start(&bin, &dir, opts).unwrap();
    assert_ne!(node.http_port(), holder.http_port());
    let attempts = std::fs::read_to_string(dir.join("start-attempts.log")).unwrap();
    assert_eq!(attempts.lines().count(), 1, "{attempts}");
    assert!(attempts.contains("Address already in use"), "{attempts}");
    // Each node closes its own ledgers.
    assert_eq!(node.close().unwrap().sequence, 2);
    assert_eq!(holder.info().unwrap()["info"]["ledger"]["num"], 1);
    assert_eq!(holder.close().unwrap().sequence, 2);
    node.stop().unwrap();
    holder.stop().unwrap();
    for d in [&dir, &dir_a] {
        assert_eq!(common::processes_in(d), Vec::<String>::new());
        std::fs::remove_dir_all(d).unwrap();
    }
}

/// Many nodes starting at once, several rounds: every start succeeds, and each node closes a ledger
/// on its own ports. `XDRCHECK_STRESS_ROUNDS` runs more rounds.
#[test]
fn many_nodes_start_in_parallel() {
    const NODES: usize = 16;
    let rounds: usize = std::env::var("XDRCHECK_STRESS_ROUNDS")
        .ok()
        .and_then(|r| r.parse().ok())
        .unwrap_or(5);
    let Some(bin) = common::core_or_skip("many_nodes_start_in_parallel") else {
        return;
    };
    for round in 0..rounds {
        let handles: Vec<_> = (0..NODES)
            .map(|i| {
                let bin = bin.clone();
                std::thread::spawn(move || -> Result<(), String> {
                    let dir = common::run_dir(&format!("parallel-{round}-{i}"));
                    let mut node = Node::start(&bin, &dir, NodeOptions::new(TESTNET_PASSPHRASE))
                        .map_err(|e| format!("node {i}: {e:#}"))?;
                    let l = node.close().map_err(|e| format!("node {i}: {e:#}"))?;
                    if l.sequence != 2 {
                        return Err(format!("node {i} closed ledger {}", l.sequence));
                    }
                    node.stop().map_err(|e| format!("node {i}: {e:#}"))?;
                    std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
                    Ok(())
                })
            })
            .collect();
        let failures: Vec<String> = handles
            .into_iter()
            .filter_map(|h| h.join().unwrap().err())
            .collect();
        assert!(failures.is_empty(), "round {round}: {failures:#?}");
    }
}
