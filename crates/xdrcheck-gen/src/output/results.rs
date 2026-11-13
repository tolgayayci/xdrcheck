//! Result codes as scenarios and manifests name them: the SEP-51 (XDR-JSON) arm names.
//!
//! - Transaction: the `TransactionResultResult` arm, for example `tx_success`, `tx_failed`,
//!   `tx_fee_bump_inner_failed`, `tx_bad_auth_extra`.
//! - Operation: `<operation>.<code>` for an `op_inner` result (`set_options.success`,
//!   `payment.no_destination`), else the outer code (`op_bad_auth`). For a fee bump the operation
//!   results are the inner transaction's.

use serde_json::Value;
use stellar_xdr::{
    InnerTransactionResultResult, OperationResult, TransactionResult, TransactionResultResult,
};

/// The name of a union arm in SEP-51 JSON: a bare string, or the single key of an object.
fn arm(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Object(m) if m.len() == 1 => m.keys().next().cloned().unwrap_or_default(),
        other => other.to_string(),
    }
}

/// The transaction result code, e.g. `tx_success`.
pub fn tx_code(r: &TransactionResult) -> String {
    arm(&serde_json::to_value(&r.result).unwrap_or(Value::Null))
}

/// `<operation>.<code>` or the outer operation code.
pub fn op_code(r: &OperationResult) -> String {
    let v = serde_json::to_value(r).unwrap_or(Value::Null);
    match v.get("op_inner") {
        Some(Value::Object(inner)) if inner.len() == 1 => {
            let (op, code) = inner.iter().next().expect("one key");
            format!("{op}.{}", arm(code))
        }
        _ => arm(&v),
    }
}

/// The operation result codes of a transaction (of the inner transaction for a fee bump); empty
/// when the result carries none (for example `tx_bad_seq`).
pub fn op_codes(r: &TransactionResult) -> Vec<String> {
    let ops: &[OperationResult] = match &r.result {
        TransactionResultResult::TxSuccess(ops) | TransactionResultResult::TxFailed(ops) => ops,
        TransactionResultResult::TxFeeBumpInnerSuccess(p)
        | TransactionResultResult::TxFeeBumpInnerFailed(p) => match &p.result.result {
            InnerTransactionResultResult::TxSuccess(ops)
            | InnerTransactionResultResult::TxFailed(ops) => ops,
            _ => &[],
        },
        _ => &[],
    };
    ops.iter().map(op_code).collect()
}

/// The inner transaction's result code of a fee bump.
pub fn inner_code(r: &TransactionResult) -> Option<String> {
    match &r.result {
        TransactionResultResult::TxFeeBumpInnerSuccess(p)
        | TransactionResultResult::TxFeeBumpInnerFailed(p) => Some(arm(&serde_json::to_value(
            &p.result.result,
        )
        .unwrap_or(Value::Null))),
        _ => None,
    }
}
