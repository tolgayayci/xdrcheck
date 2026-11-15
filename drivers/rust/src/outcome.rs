//! What one `run` request produced: an outcome (`ok`, `diverge`, `reject`, `crash`, `n_a`), a typed reason,
//! and the `actual` facts, rendered as the driver protocol's response fields.

use serde_json::{json, Map, Value};

/// The longest `reason.message` the protocol allows, in characters.
const MAX_MESSAGE: usize = 500;

/// A typed reason. `code` is from the protocol's closed enum; the rest is for the report.
#[derive(Clone, Debug)]
pub struct Reason {
    pub code: &'static str,
    message: Option<String>,
    class: Option<String>,
    entry_point: Option<String>,
}

impl Reason {
    pub fn new(code: &'static str) -> Reason {
        Reason {
            code,
            message: None,
            class: None,
            entry_point: None,
        }
    }

    pub fn message(mut self, m: impl Into<String>) -> Reason {
        let m: String = m.into();
        self.message = Some(m.chars().take(MAX_MESSAGE).collect());
        self
    }

    pub fn class(mut self, c: impl Into<String>) -> Reason {
        self.class = Some(c.into());
        self
    }

    pub fn entry_point(mut self, e: impl Into<String>) -> Reason {
        let e: String = e.into();
        if !e.is_empty() {
            self.entry_point = Some(e);
        }
        self
    }

    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("code".into(), json!(self.code));
        if let Some(x) = &self.message {
            m.insert("message".into(), json!(x));
        }
        if let Some(x) = &self.class {
            m.insert("error_class".into(), json!(x));
        }
        if let Some(x) = &self.entry_point {
            m.insert("entry_point".into(), json!(x));
        }
        Value::Object(m)
    }
}

/// The result of a run request.
#[derive(Debug)]
pub struct Outcome {
    pub outcome: &'static str,
    pub reason: Option<Box<Reason>>,
    pub actual: Map<String, Value>,
}

impl Outcome {
    pub fn ok(actual: Map<String, Value>) -> Outcome {
        Outcome {
            outcome: "ok",
            reason: None,
            actual,
        }
    }

    pub fn with(outcome: &'static str, reason: Reason) -> Outcome {
        Outcome {
            outcome,
            reason: Some(Box::new(reason)),
            actual: Map::new(),
        }
    }

    pub fn reject(reason: Reason) -> Outcome {
        Outcome::with("reject", reason)
    }

    pub fn diverge(reason: Reason) -> Outcome {
        Outcome::with("diverge", reason)
    }

    pub fn n_a(code: &'static str, message: impl Into<String>) -> Outcome {
        Outcome::with("n_a", Reason::new(code).message(message))
    }

    pub fn actual(mut self, key: &str, v: Value) -> Outcome {
        self.actual.insert(key.into(), v);
        self
    }

    /// Writes outcome, reason and actual into a response object.
    pub fn fill(&self, resp: &mut Map<String, Value>) {
        resp.insert("outcome".into(), json!(self.outcome));
        if let Some(r) = &self.reason {
            resp.insert("reason".into(), r.to_json());
        }
        if !self.actual.is_empty() {
            resp.insert("actual".into(), Value::Object(self.actual.clone()));
        }
    }
}
