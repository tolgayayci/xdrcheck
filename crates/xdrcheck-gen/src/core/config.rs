//! The standalone node configuration (as executed in the `evidence/local-core/` run).
//!
//! One template for every run. Paths and ports are filled in per run; the template with placeholders in
//! their place is hashed ([`NodeConfig::config_sha256`]) so the hash is stable across machines and runs.
//! The meta flags come from a [`MetaProfile`]: `lake` (all seven Galexie flags on, the default),
//! `golden-test` (exactly the flags a named stellar-core test sets) or `custom`.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Result};

use super::keys::Keypair;

/// The seven meta-affecting flags, in the order they are written. Under `lake` all are true; under the
/// other profiles each is written explicitly, `false` unless the profile's map sets it.
pub const META_FLAGS: [&str; 7] = [
    "ENABLE_SOROBAN_DIAGNOSTIC_EVENTS",
    "ENABLE_DIAGNOSTICS_FOR_TX_SUBMISSION",
    "EMIT_SOROBAN_TRANSACTION_META_EXT_V1",
    "EMIT_LEDGER_CLOSE_META_EXT_V1",
    "EMIT_CLASSIC_EVENTS",
    "BACKFILL_STELLAR_ASSET_EVENTS",
    "BACKFILL_RESTORE_META",
];

/// The label of the node's own key (`NODE_SEED`); it signs every `StellarValue`.
pub const NODE_SEED_LABEL: &str = "core-node";

/// Which meta flags the node runs with.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum MetaProfile {
    /// What Galexie-written lake objects look like: all of [`META_FLAGS`] true.
    #[default]
    Lake,
    /// A golden-mirror run: exactly the flags the named stellar-core test sets (others false).
    GoldenTest(BTreeMap<String, bool>),
    /// Any other explicit flag set (others false).
    Custom(BTreeMap<String, bool>),
}

impl MetaProfile {
    /// The profile name as the manifest and scenario files spell it.
    pub fn name(&self) -> &'static str {
        match self {
            MetaProfile::Lake => "lake",
            MetaProfile::GoldenTest(_) => "golden-test",
            MetaProfile::Custom(_) => "custom",
        }
    }

    /// Every flag this profile writes, with its value: the seven meta flags first, then any other key the
    /// profile's map names (sorted).
    pub fn flags(&self) -> Result<Vec<(String, bool)>> {
        let map = match self {
            MetaProfile::Lake => {
                return Ok(META_FLAGS.iter().map(|f| (f.to_string(), true)).collect())
            }
            MetaProfile::GoldenTest(m) | MetaProfile::Custom(m) => m,
        };
        for k in map.keys() {
            if k.is_empty()
                || !k
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            {
                bail!("meta flag {k:?} is not a stellar-core configuration key");
            }
        }
        let mut out: Vec<(String, bool)> = META_FLAGS
            .iter()
            .map(|f| (f.to_string(), map.get(*f).copied().unwrap_or(false)))
            .collect();
        out.extend(
            map.iter()
                .filter(|(k, _)| !META_FLAGS.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), *v)),
        );
        Ok(out)
    }
}

/// Everything that goes into `core.cfg` except paths and ports.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// `NETWORK_PASSPHRASE`.
    pub passphrase: String,
    /// Meta flag profile.
    pub profile: MetaProfile,
}

const RUN_DIR: &str = "@RUN_DIR@";
const HTTP_PORT: &str = "@HTTP_PORT@";
const QUERY_PORT: &str = "@QUERY_PORT@";

impl NodeConfig {
    /// The configuration with placeholders for the run directory and the two ports.
    pub fn template(&self) -> Result<String> {
        if self.passphrase.contains(['"', '\\', '\n']) {
            bail!(
                "passphrase {:?} cannot be written into core.cfg",
                self.passphrase
            );
        }
        let seed = Keypair::from_label(NODE_SEED_LABEL).secret_seed();
        let mut s = String::new();
        let mut line = |l: String| {
            s.push_str(&l);
            s.push('\n');
        };
        line(format!("NETWORK_PASSPHRASE=\"{}\"", self.passphrase));
        line("RUN_STANDALONE=true".into());
        line("MANUAL_CLOSE=true".into());
        line("NODE_IS_VALIDATOR=true".into());
        line(format!("NODE_SEED=\"{seed} self\""));
        line("UNSAFE_QUORUM=true".into());
        line("FAILURE_SAFETY=0".into());
        line("KNOWN_PEERS=[]".into());
        line("PREFERRED_PEERS=[]".into());
        line(format!("DATABASE=\"sqlite3://{RUN_DIR}/core.db\""));
        line(format!("BUCKET_DIR_PATH=\"{RUN_DIR}/buckets\""));
        line(format!("HTTP_PORT={HTTP_PORT}"));
        line("PUBLIC_HTTP_PORT=false".into());
        line(format!("HTTP_QUERY_PORT={QUERY_PORT}"));
        line(format!("METADATA_OUTPUT_STREAM=\"{RUN_DIR}/meta.xdr\""));
        line("NTP_DRIFT_CHECK_SERVER=\"\"".into());
        line("AUTOMATIC_SELF_CHECK_PERIOD=0".into());
        // Logs go to stdout, which the node captures in <run dir>/core.log.
        line("LOG_FILE_PATH=\"\"".into());
        line(format!("# profile \"{}\"", self.profile.name()));
        for (k, v) in self.profile.flags()? {
            line(format!("{k}={v}"));
        }
        line("[QUORUM_SET]".into());
        line("THRESHOLD_PERCENT=100".into());
        line("VALIDATORS=[\"$self\"]".into());
        Ok(s)
    }

    /// sha256 of [`NodeConfig::template`]: the `config_sha256` a chain index records.
    pub fn config_sha256(&self) -> Result<String> {
        Ok(xdrcheck_xdr::sha256_hex(self.template()?.as_bytes()))
    }

    /// The configuration for a run directory and two ports.
    pub fn render(&self, run_dir: &Path, http_port: u16, query_port: u16) -> Result<String> {
        let dir = run_dir.to_str().unwrap_or("");
        if dir.is_empty() || dir.contains(['"', '\\', '\n', '@']) {
            bail!(
                "run directory {} cannot be written into core.cfg",
                run_dir.display()
            );
        }
        Ok(self
            .template()?
            .replace(RUN_DIR, dir)
            .replace(HTTP_PORT, &http_port.to_string())
            .replace(QUERY_PORT, &query_port.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::keys::TESTNET_PASSPHRASE;

    fn cfg(profile: MetaProfile) -> NodeConfig {
        NodeConfig {
            passphrase: TESTNET_PASSPHRASE.into(),
            profile,
        }
    }

    #[test]
    fn lake_has_all_seven_flags_on() {
        let t = cfg(MetaProfile::Lake).template().unwrap();
        for f in META_FLAGS {
            assert!(t.contains(&format!("\n{f}=true\n")), "{f}");
        }
        assert!(t.contains("RUN_STANDALONE=true"));
        assert!(t.contains("MANUAL_CLOSE=true"));
        assert!(t.contains("METADATA_OUTPUT_STREAM=\"@RUN_DIR@/meta.xdr\""));
    }

    #[test]
    fn golden_test_writes_exactly_its_flags() {
        let m = BTreeMap::from([
            ("ENABLE_SOROBAN_DIAGNOSTIC_EVENTS".to_string(), true),
            ("EMIT_CLASSIC_EVENTS".to_string(), true),
            (
                "TESTING_MINIMUM_PERSISTENT_ENTRY_LIFETIME".to_string(),
                false,
            ),
        ]);
        let t = cfg(MetaProfile::GoldenTest(m)).template().unwrap();
        assert!(t.contains("\nENABLE_SOROBAN_DIAGNOSTIC_EVENTS=true\n"));
        assert!(t.contains("\nEMIT_CLASSIC_EVENTS=true\n"));
        assert!(t.contains("\nEMIT_LEDGER_CLOSE_META_EXT_V1=false\n"));
        assert!(t.contains("\nTESTING_MINIMUM_PERSISTENT_ENTRY_LIFETIME=false\n"));
        assert!(cfg(MetaProfile::Custom(BTreeMap::from([(
            "bad key".to_string(),
            true
        )])))
        .template()
        .is_err());
    }

    #[test]
    fn hash_ignores_paths_and_ports() {
        let c = cfg(MetaProfile::Lake);
        let a = c.render(Path::new("/x/run-a"), 1000, 1001).unwrap();
        let b = c.render(Path::new("/y/run-b"), 2000, 2001).unwrap();
        assert_ne!(a, b);
        assert_eq!(c.config_sha256().unwrap(), c.config_sha256().unwrap());
        assert_ne!(
            c.config_sha256().unwrap(),
            cfg(MetaProfile::Custom(BTreeMap::new()))
                .config_sha256()
                .unwrap()
        );
    }
}
