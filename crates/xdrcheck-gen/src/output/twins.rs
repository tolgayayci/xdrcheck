//! Twins: the testnet and public-passphrase runs of one scenario at one protocol must agree on every
//! passphrase-independent value — label-derived addresses, ledger sequences, close times, result
//! codes, operation results, fees charged, transaction counts and entry blob lengths. Hashes,
//! signatures and contract IDs differ by construction and are not compared.

use super::chain::{ledger_facts, stream_ledgers};
use super::run::RunRecord;
use anyhow::Result;

/// The differences between two runs (empty when they agree).
pub fn compare_twins(
    a: &RunRecord,
    a_stream: &[u8],
    b: &RunRecord,
    b_stream: &[u8],
) -> Result<Vec<String>> {
    let mut d = Vec::new();
    let what = format!(
        "{} p{} {} vs {}",
        a.scenario_name, a.protocol, a.network, b.network
    );
    if a.accounts != b.accounts {
        d.push(format!("{what}: label-derived accounts differ"));
    }
    if a.steps.len() != b.steps.len() {
        d.push(format!(
            "{what}: {} steps vs {}",
            a.steps.len(),
            b.steps.len()
        ));
    }
    for (x, y) in a.steps.iter().zip(&b.steps) {
        let pairs = [
            (
                "ledger",
                format!("{:?}", x.ledger),
                format!("{:?}", y.ledger),
            ),
            (
                "close time",
                x.close_time.to_string(),
                y.close_time.to_string(),
            ),
            (
                "result",
                format!("{:?}", x.result),
                format!("{:?}", y.result),
            ),
            (
                "inner result",
                format!("{:?}", x.inner_result),
                format!("{:?}", y.inner_result),
            ),
            (
                "operation results",
                format!("{:?}", x.op_results),
                format!("{:?}", y.op_results),
            ),
            (
                "fee charged",
                format!("{:?}", x.fee_charged),
                format!("{:?}", y.fee_charged),
            ),
            (
                "submission rejection",
                format!("{:?}", x.submit_reject),
                format!("{:?}", y.submit_reject),
            ),
        ];
        for (name, p, q) in pairs {
            if p != q {
                d.push(format!("{what}: step {} {name} {p} vs {q}", x.id));
            }
        }
    }
    let (la, lb) = (stream_ledgers(a_stream)?, stream_ledgers(b_stream)?);
    if la.len() != lb.len() {
        d.push(format!("{what}: {} ledgers vs {}", la.len(), lb.len()));
    }
    for ((x, y), r) in la.iter().zip(&lb).zip(&a.ledgers) {
        if x.info.close_time != y.info.close_time {
            d.push(format!("{what}: ledger {} close time differs", r.seq));
        }
        if r.entries.is_empty() {
            continue;
        }
        if x.bytes.len() != y.bytes.len() {
            d.push(format!(
                "{what}: ledger {} ({}) is {} bytes vs {}",
                r.seq,
                r.label,
                x.bytes.len(),
                y.bytes.len()
            ));
        }
        let (fx, fy) = (ledger_facts(x.bytes)?, ledger_facts(y.bytes)?);
        if fx.results.len() != fy.results.len() {
            d.push(format!(
                "{what}: ledger {} has {} transactions vs {}",
                r.seq,
                fx.results.len(),
                fy.results.len()
            ));
        }
    }
    Ok(d)
}
