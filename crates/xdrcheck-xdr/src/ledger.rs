//! `LedgerCloseMeta` helpers: the fail-closed gate (typed refusals for meta versions and
//! protocols above the configured maximum) and a cheap read of a ledger's version, protocol and
//! sequence that decodes only the ledger header.

use std::io::Cursor;
use std::path::Path;

use stellar_xdr::{
    LedgerCloseMeta, LedgerCloseMetaExt, LedgerHeaderHistoryEntry, Limited, ReadXdr, Type,
    TypeVariant,
};

use crate::codec::{self, Limits};
use crate::error::{Error, Refusal, Result};
use crate::framing;

/// Highest `LedgerCloseMeta` arm the pinned `stellar-xdr` 30.0.0 defines (`v0`, `v1`, `v2`).
pub const KNOWN_MAX_LEDGER_CLOSE_META_VERSION: u32 = 2;

/// Highest protocol the toolchain is pinned to (`pins.toml` `[protocol] max_supported`), used when
/// no `corpus.json` is available. It is also the ceiling: a `corpus.json` may lower the gate, never
/// raise it above this (`xdrcheck pins check` keeps the two equal).
pub const DEFAULT_MAX_PROTOCOL: u32 = 30;

/// The fail-closed gate: ledgers above these are refused, not guessed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    /// Highest ledger protocol (`LedgerHeader::ledger_version`) accepted.
    pub max_protocol: u32,
    /// Highest `LedgerCloseMeta` arm accepted. Values above
    /// [`KNOWN_MAX_LEDGER_CLOSE_META_VERSION`] are clamped to it: the library cannot decode them.
    pub max_ledger_close_meta_version: u32,
}

impl Default for Gate {
    fn default() -> Self {
        Gate {
            max_protocol: DEFAULT_MAX_PROTOCOL,
            max_ledger_close_meta_version: KNOWN_MAX_LEDGER_CLOSE_META_VERSION,
        }
    }
}

impl Gate {
    /// Read `max_protocol` and `max_ledger_close_meta_version` from a `corpus.json`. Returns
    /// `Ok(None)` when the file does not exist; missing fields take the defaults. A `max_protocol`
    /// above [`DEFAULT_MAX_PROTOCOL`] is an error: the library this crate is built against decodes
    /// nothing newer, so raising the gate takes a new pin and a new build, not an edited number
    /// (docs/maintenance.md, sections 4 and 5).
    pub fn from_corpus_json(path: &Path) -> Result<Option<Gate>> {
        let text = match std::fs::read(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let v: serde_json::Value = serde_json::from_slice(&text).map_err(|e| Error::Json {
            type_name: "corpus.json".into(),
            message: e.to_string(),
        })?;
        let field = |name: &str, default: u32| -> Result<u32> {
            match v.get(name) {
                None => Ok(default),
                Some(x) => x
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| Error::Json {
                        type_name: "corpus.json".into(),
                        message: format!("{name} is not a u32"),
                    }),
            }
        };
        let d = Gate::default();
        let max_protocol = field("max_protocol", d.max_protocol)?;
        // Only `xdrcheck-corpus verify --tier bulk-next --max-protocol N` reads above the ceiling, for one
        // run; corpus.json never raises it.
        if max_protocol > DEFAULT_MAX_PROTOCOL {
            return Err(Error::Json {
                type_name: "corpus.json".into(),
                message: format!(
                    "max_protocol {max_protocol} is above {DEFAULT_MAX_PROTOCOL}, the highest \
                     protocol this build supports (pins.toml protocol.max_supported); raising \
                     the gate is the protocol upgrade procedure in docs/maintenance.md"
                ),
            });
        }
        Ok(Some(Gate {
            max_protocol,
            max_ledger_close_meta_version: field(
                "max_ledger_close_meta_version",
                d.max_ledger_close_meta_version,
            )?,
        }))
    }

    fn max_version(&self) -> u32 {
        self.max_ledger_close_meta_version
            .min(KNOWN_MAX_LEDGER_CLOSE_META_VERSION)
    }

    /// The gate for tools that read live network data (`capture`, `mine`): the protocol ceiling is
    /// lifted and the meta-version gate kept. A network can move to a new protocol with little or no
    /// notice, and an upgrade that changes no XDR (a number-only upgrade) leaves every ledger
    /// decodable by the pinned definitions; refusing those ledgers would stop capture on the day it
    /// matters most. A shape the definitions do not know still fails the decode. Callers report every
    /// ledger above `max_protocol` with [`Gate::above_max`] and never make a corpus entry from it; the
    /// corpus itself keeps the strict gate.
    pub fn reading_live(&self) -> Gate {
        Gate {
            max_protocol: u32::MAX,
            ..*self
        }
    }

    /// `Some(warning)` when `protocol` is above `max_protocol`: the text says what was done and what
    /// to do about it.
    pub fn above_max(&self, protocol: u32) -> Option<String> {
        (protocol > self.max_protocol).then(|| {
            format!(
                "ledger protocol {protocol} is above the supported maximum {} (pins.toml \
                 protocol.max_supported): read with the protocol {} definitions, so a shape the new \
                 protocol added fails to decode and is reported as unknown; no corpus entry is made \
                 from it until the gate is raised (docs/maintenance.md, section 5.2)",
                self.max_protocol, self.max_protocol
            )
        })
    }

    /// Refuse a ledger described by `info` if it is above the gate.
    pub fn check(&self, info: &LedgerInfo) -> Result<()> {
        if info.ledger_close_meta_version < 0
            || info.ledger_close_meta_version as u32 > self.max_version()
        {
            return Err(Refusal::UnknownLedgerCloseMetaVersion {
                version: info.ledger_close_meta_version,
                max: self.max_version(),
            }
            .into());
        }
        if info.protocol > self.max_protocol {
            return Err(Refusal::ProtocolAboveMax {
                protocol: info.protocol,
                max: self.max_protocol,
            }
            .into());
        }
        Ok(())
    }
}

/// What can be read from a `LedgerCloseMeta` by decoding only its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerInfo {
    /// The `LedgerCloseMeta` union arm (0, 1 or 2).
    pub ledger_close_meta_version: i32,
    /// `LedgerHeader::ledger_version`.
    pub protocol: u32,
    /// `LedgerHeader::ledger_seq`.
    pub sequence: u32,
    /// The header hash stored in the meta (`LedgerHeaderHistoryEntry::hash`), not recomputed.
    pub header_hash: [u8; 32],
    /// `LedgerHeader::scp_value.close_time` in seconds.
    pub close_time: u64,
}

/// Read a `LedgerCloseMeta`'s version, protocol, sequence, header hash and close time without
/// decoding the transaction set or meta. Unknown arms are a refusal. Only a prefix of `bytes` is
/// read; use [`decode_ledger`] to validate the whole value.
pub fn ledger_info(bytes: &[u8]) -> Result<LedgerInfo> {
    codec::check_ledger_close_meta_arm(bytes, KNOWN_MAX_LEDGER_CLOSE_META_VERSION)?;
    let name = "LedgerCloseMeta";
    // The header is shallow, so the default stack and depth are ample.
    let limits = Limits::default().xdr(bytes.len());
    let mut r = Limited::new(Cursor::new(bytes), limits);
    let err = |e| Error::from_xdr_read(name, e, bytes.len(), bytes.len());
    let version = i32::read_xdr(&mut r).map_err(err)?;
    if version != 0 {
        LedgerCloseMetaExt::read_xdr(&mut r).map_err(err)?;
    }
    let h = LedgerHeaderHistoryEntry::read_xdr(&mut r).map_err(err)?;
    Ok(LedgerInfo {
        ledger_close_meta_version: version,
        protocol: h.header.ledger_version,
        sequence: h.header.ledger_seq,
        header_hash: h.hash.0,
        close_time: h.header.scp_value.close_time.0,
    })
}

/// Decode `bytes` as a `LedgerCloseMeta` after checking it against `gate`.
pub fn decode_ledger(bytes: &[u8], limits: &Limits, gate: &Gate) -> Result<LedgerCloseMeta> {
    gate.check(&ledger_info(bytes)?)?;
    let value = codec::decode("LedgerCloseMeta", bytes, limits)?;
    match value {
        Type::LedgerCloseMeta(v) => Ok(*v),
        _ => unreachable!("decoded as {:?}", TypeVariant::LedgerCloseMeta),
    }
}

/// Split a record-marked stellar-core meta stream into ledgers. Each record is checked against
/// `gate`, must hold exactly one `LedgerCloseMeta` (a mark whose length disagrees with the value
/// is a [`crate::FramingError::LengthMismatch`]) and must re-encode byte-exactly. Returns each
/// ledger's header information and payload (borrowed from `stream`). Stops at the first error.
pub fn split_ledger_stream<'a>(
    stream: &'a [u8],
    limits: &Limits,
    gate: &Gate,
) -> Result<Vec<(LedgerInfo, &'a [u8])>> {
    let mut out = Vec::new();
    for r in framing::records(stream) {
        let r = r?;
        let info = match ledger_info(r.payload) {
            Ok(info) => info,
            // The header itself is cut short or invalid: let the full check classify it (a
            // record too short for its value is a framing fault, not a malformed ledger).
            Err(e @ Error::Malformed { .. }) => {
                framing::check_record("LedgerCloseMeta", &r, limits)?;
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        gate.check(&info)?;
        framing::check_record("LedgerCloseMeta", &r, limits)?;
        out.push((info, r.payload));
    }
    Ok(out)
}

/// Check `bytes` against `gate`, then decode and re-encode it byte-exactly.
pub fn roundtrip_ledger(bytes: &[u8], limits: &Limits, gate: &Gate) -> Result<()> {
    gate.check(&ledger_info(bytes)?)?;
    codec::roundtrip("LedgerCloseMeta", bytes, limits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate_of(name: &str, json: &str) -> Result<Option<Gate>> {
        let dir =
            std::env::temp_dir().join(format!("xdrcheck-xdr-gate-cap-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("corpus.json");
        std::fs::write(&path, json).unwrap();
        let g = Gate::from_corpus_json(&path);
        std::fs::remove_dir_all(&dir).unwrap();
        g
    }

    /// `corpus.json` may lower the protocol gate, never raise it above the built-in maximum.
    #[test]
    fn corpus_json_cannot_raise_the_protocol_gate() {
        let at = format!(r#"{{"max_protocol": {DEFAULT_MAX_PROTOCOL}}}"#);
        assert_eq!(gate_of("at", &at).unwrap(), Some(Gate::default()));
        let lower = format!(r#"{{"max_protocol": {}}}"#, DEFAULT_MAX_PROTOCOL - 1);
        assert_eq!(
            gate_of("lower", &lower).unwrap().unwrap().max_protocol,
            DEFAULT_MAX_PROTOCOL - 1
        );
        let above = format!(r#"{{"max_protocol": {}}}"#, DEFAULT_MAX_PROTOCOL + 1);
        // The live-reading gate lifts the protocol ceiling only; the meta-version gate stays.
        let live = Gate::default().reading_live();
        let info = |protocol, version| LedgerInfo {
            ledger_close_meta_version: version,
            protocol,
            sequence: 1,
            header_hash: [0; 32],
            close_time: 0,
        };
        assert!(Gate::default()
            .check(&info(DEFAULT_MAX_PROTOCOL + 1, 1))
            .is_err());
        assert!(live.check(&info(DEFAULT_MAX_PROTOCOL + 1, 1)).is_ok());
        assert!(live
            .check(&info(
                DEFAULT_MAX_PROTOCOL + 1,
                KNOWN_MAX_LEDGER_CLOSE_META_VERSION as i32 + 1
            ))
            .is_err());
        assert!(Gate::default().above_max(DEFAULT_MAX_PROTOCOL).is_none());
        assert!(Gate::default()
            .above_max(DEFAULT_MAX_PROTOCOL + 1)
            .unwrap()
            .contains(&format!(
                "above the supported maximum {DEFAULT_MAX_PROTOCOL}"
            )));
        let e = gate_of("above", &above).unwrap_err().to_string();
        assert!(
            e.contains(&format!("max_protocol {}", DEFAULT_MAX_PROTOCOL + 1))
                && e.contains(&format!("above {DEFAULT_MAX_PROTOCOL}")),
            "{e}"
        );
    }
}
