//! `promote`: a minimised mutant becomes a synthetic-tier corpus entry with expectations.
//!
//! The entry is written into a corpus root (by default the private overlay's corpus, never the
//! public tree unless asked): `manifest/<id>.json`, the blob, and for a positive mutant its SEP-51
//! sidecar. Its source is `synthetic`, naming the command that rebuilds the bytes. A
//! wire-invalid mutant is a negative entry expecting a refusal; a valid-preserving one expects the
//! oracle's and the reference extractor's facts on the mutant; a metamorphic one keeps the
//! original's expectations.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use xdrcheck_xdr::{Gate, Limits};

use crate::engine::{self, Mutant, Source};

/// The command that rebuilds a mutant.
pub fn replay_command(m: &Mutant) -> String {
    let ids: Vec<&str> = m.mutations.iter().map(|x| x.id.as_str()).collect();
    format!(
        "xdrcheck mutate replay --entry '{}' --variant {} --seed {} --mutation {}{}",
        m.source,
        m.variant,
        m.seed,
        ids.join(","),
        if m.stale_hashes {
            " --stale-hashes"
        } else {
            ""
        }
    )
}

/// Write the entry `id` for mutant `m` of `src` into the corpus at `into`.
pub fn promote(src: &Source, m: &Mutant, into: &Path, id: &str, gate: &Gate) -> Result<Value> {
    let mut e = engine::mutant_entry_as(src, m, into, gate, id)?;
    let v = &mut e["variants"][0];
    v["source"] = json!({
        "kind": "synthetic",
        "recipe": replay_command(m),
        "base_entry": src.entry,
        "reason": format!(
            "{} mutation{} of the corpus value {}: {}",
            match m.class.number() { 1 => "valid-preserving", 2 => "metamorphic", _ => "wire-invalid" },
            if m.mutations.len() == 1 { "" } else { "s" },
            src.id,
            m.mutations.iter().map(|x| format!("{} at {}", x.mutator, x.path)).collect::<Vec<_>>().join(", ")
        ),
    });
    if m.oracle.accepts {
        let json = xdrcheck_xdr::xdr_json(&m.xdr_type, &m.bytes, &Limits::default())?;
        let mut text = serde_json::to_vec(&json)?;
        text.push(b'\n');
        let dsha = xdrcheck_xdr::sha256_hex(&text);
        let rel = format!("decoded/{}/{}.json.zst", &m.sha256[..2], m.sha256);
        let p = into.join(&rel);
        std::fs::create_dir_all(p.parent().unwrap())?;
        let mut enc = zstd::Encoder::new(Vec::new(), 19)?;
        enc.write_all(&text)?;
        std::fs::write(&p, enc.finish()?).with_context(|| format!("writing {}", p.display()))?;
        v["decoded"] = json!(rel);
        v["decoded_sha256"] = json!(dsha);
        v["decoded_by"] = json!(format!(
            "rs-stellar-xdr 30.0.0, xdrcheck-mutate promote {}",
            env!("CARGO_PKG_VERSION")
        ));
    }
    let p = into.join("manifest").join(format!("{id}.json"));
    std::fs::write(&p, serde_json::to_vec_pretty(&e)?)?;
    Ok(e)
}
