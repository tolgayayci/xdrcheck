//! One standalone stellar-core process in its own run directory.
//!
//! Lifecycle: [`Node::start`] writes `core.cfg`, runs `new-db`, starts `run` on two reserved loopback
//! ports and waits until the node answers `info` as a fresh ledger-1 node on the expected passphrase.
//! The caller then submits transactions ([`Node::submit`]), arms upgrades ([`Node::set_upgrades`])
//! and closes ledgers ([`Node::close`]), each close returning that ledger's `LedgerCloseMeta` bytes
//! from the meta stream.
//! [`Node::stop`] stops the process; dropping a `Node` (including during a panic) kills it. The child also
//! gets `PR_SET_PDEATHSIG = SIGKILL`, so it dies with the thread that started it even if this process is
//! killed outright: keep a `Node` on the thread that started it.
//!
//! **Ports.** A port chosen by binding port 0 and closing the socket again can be chosen by another
//! process — another node started at the same moment — before core binds it. Core then logs
//! `bind: Address already in use` and exits, and the node that holds the port answers `info` in its
//! place: a fresh ledger-1 node on the same passphrase looks exactly like the one just started. So:
//!
//! - ports are *reserved* ([`reserve_port`]): the socket that chose the port is left in TIME_WAIT on
//!   it, which keeps the kernel from handing the port to any other `bind` to port 0 or outgoing
//!   connection for about a minute, while core, which binds with `SO_REUSEADDR`, can still bind it;
//! - the node counts as started only once its own log says the query server is listening
//!   ([`listening_line`]): core binds the command port before the query port and exits if either
//!   fails, so from then on whatever answers on the command port is this process;
//! - if core exits during start-up because a port was taken after all (its log says
//!   `Address already in use`), it is started again on freshly reserved ports, up to
//!   [`START_ATTEMPTS`] times in all; any other exit during start-up fails at once with core's reason.
//!
//! Close times follow a fixed schedule ([`ClosePolicy`]): ledger `n` closes at `base + (n − 2)·stride`.
//! The node's virtual clock runs ahead while it is idle (about 3×10⁵ virtual seconds per wall second),
//! and core refuses a close time behind it ("too early"). The stride is therefore large, the next close is
//! issued promptly, and a refusal fails the run: the generator never retries with another close time.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use stellar_xdr::{
    AccountId, LedgerCloseMeta, LedgerEntry, LedgerEntryData, LedgerKey, LedgerKeyAccount, ReadXdr,
    TransactionEnvelope, TransactionResult, TransactionResultPair, WriteXdr,
};
use xdrcheck_xdr::{Gate, Limits};

use super::binary::CoreBinary;
use super::config::{MetaProfile, NodeConfig};
use super::http;
use super::keys::network_id;
use super::meta::MetaReader;

/// How many times [`Node::start`] starts core before giving up when a port it was given is taken.
pub const START_ATTEMPTS: u32 = 3;

/// What stellar-core logs when it cannot bind a port.
const PORT_TAKEN: &str = "Address already in use";

/// Timeout of one `info` poll while waiting for start-up (a port taken by another listener may
/// accept and never answer).
const READY_POLL_TIMEOUT: Duration = Duration::from_secs(2);

/// Close times after this are refused by core (first second of the year 2200).
pub const MAX_CLOSE_TIME: u64 = 7_258_118_400;

/// Limits for decoding XDR that the node itself returns (ledger entries, results).
const NODE_XDR_LIMITS: stellar_xdr::Limits = stellar_xdr::Limits {
    depth: 1000,
    len: 64 << 20,
};

/// The close-time schedule: ledger `n` closes at `base + (n − 2)·stride` seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosePolicy {
    /// Close time of ledger 2.
    pub base: u64,
    /// Seconds between consecutive ledgers; at least 10⁶ (the virtual clock jumps ahead when idle).
    pub stride: u64,
}

impl Default for ClosePolicy {
    /// `base` 1,700,000,000 and `stride` 1,000,000, as in every executed probe chain.
    fn default() -> Self {
        ClosePolicy {
            base: 1_700_000_000,
            stride: 1_000_000,
        }
    }
}

impl ClosePolicy {
    /// The close time of ledger `seq` (≥ 2).
    pub fn close_time(&self, seq: u32) -> Result<u64> {
        if seq < 2 {
            bail!("ledger {seq} is not closed by the generator (genesis is ledger 1)");
        }
        if self.stride < 1_000_000 {
            bail!("close-time stride {} is below 10^6 seconds", self.stride);
        }
        let t = u64::from(seq - 2)
            .checked_mul(self.stride)
            .and_then(|d| d.checked_add(self.base))
            .filter(|t| *t <= MAX_CLOSE_TIME)
            .ok_or_else(|| {
                anyhow!("ledger {seq} would close after the year 2200 under {self:?}")
            })?;
        Ok(t)
    }
}

/// How to start a node.
#[derive(Debug, Clone)]
pub struct NodeOptions {
    /// `NETWORK_PASSPHRASE`.
    pub passphrase: String,
    /// Meta flag profile.
    pub profile: MetaProfile,
    /// Close-time schedule.
    pub close_policy: ClosePolicy,
    /// How long the node may take to answer `info` after start.
    pub startup_timeout: Duration,
    /// How long a closed ledger may take to appear in the meta stream.
    pub ledger_timeout: Duration,
    /// Ports (command, query) for the first start attempt instead of free ones; tests use it to force
    /// a collision. Later attempts always pick free ports.
    pub first_ports: Option<(u16, u16)>,
}

impl NodeOptions {
    /// Defaults (`lake` profile, default schedule) for `passphrase`.
    pub fn new(passphrase: &str) -> NodeOptions {
        NodeOptions {
            passphrase: passphrase.to_string(),
            profile: MetaProfile::Lake,
            close_policy: ClosePolicy::default(),
            startup_timeout: Duration::from_secs(60),
            ledger_timeout: Duration::from_secs(60),
            first_ports: None,
        }
    }
}

/// The `status` of a `tx` submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitStatus {
    /// Accepted into the queue; it goes into the next ledger.
    Pending,
    /// Already in the queue.
    Duplicate,
    /// Rejected; [`SubmitReply::error`] holds the result.
    Error,
    /// The source account already has a transaction queued; close first.
    TryAgainLater,
    /// Filtered by the node.
    Filtered,
    /// Anything else core answered.
    Other(String),
}

/// Core's reply to `tx?blob=`.
#[derive(Debug, Clone)]
pub struct SubmitReply {
    /// The transaction hash under the node's passphrase.
    pub hash: [u8; 32],
    /// Submission status.
    pub status: SubmitStatus,
    /// For [`SubmitStatus::Error`]: the `TransactionResult` core returned.
    pub error: Option<TransactionResult>,
    /// For rejected Soroban transactions: base64 XDR of the diagnostic events, when core sends them.
    pub diagnostic_events: Option<String>,
    /// The raw JSON reply.
    pub raw: String,
}

/// One closed ledger.
#[derive(Debug, Clone)]
pub struct ClosedLedger {
    /// Ledger sequence.
    pub sequence: u32,
    /// `LedgerHeader::ledger_version` after the close.
    pub protocol: u32,
    /// `scp_value.close_time`.
    pub close_time: u64,
    /// The header hash stored in the meta.
    pub header_hash: [u8; 32],
    /// The `LedgerCloseMeta` arm (0, 1 or 2).
    pub ledger_close_meta_version: i32,
    /// Index of this ledger's record in the meta stream, from 0.
    pub stream_index: usize,
    /// The `LedgerCloseMeta` bytes as core emitted them.
    pub bytes: Vec<u8>,
}

impl ClosedLedger {
    /// Decode the ledger through the oracle (explicit limits, fail-closed gate).
    pub fn decode(&self) -> Result<LedgerCloseMeta> {
        Ok(xdrcheck_xdr::decode_ledger(
            &self.bytes,
            &Limits::default(),
            &Gate::default(),
        )?)
    }

    /// Every transaction's hash and result, in apply order.
    pub fn tx_results(&self) -> Result<Vec<TransactionResultPair>> {
        Ok(match self.decode()? {
            LedgerCloseMeta::V0(m) => m.tx_processing.iter().map(|t| t.result.clone()).collect(),
            LedgerCloseMeta::V1(m) => m.tx_processing.iter().map(|t| t.result.clone()).collect(),
            LedgerCloseMeta::V2(m) => m.tx_processing.iter().map(|t| t.result.clone()).collect(),
        })
    }

    /// The result of the transaction with `hash`, if it is in this ledger.
    pub fn result_of(&self, hash: &[u8; 32]) -> Result<Option<TransactionResult>> {
        Ok(self
            .tx_results()?
            .into_iter()
            .find(|p| p.transaction_hash.0 == *hash)
            .map(|p| p.result))
    }
}

/// A running standalone stellar-core.
#[derive(Debug)]
pub struct Node {
    child: Option<Child>,
    run_dir: PathBuf,
    http_port: u16,
    query_port: u16,
    options: NodeOptions,
    network_id: [u8; 32],
    config_sha256: String,
    meta: MetaReader,
    last_closed: u32,
}

impl Node {
    /// Start a node in `run_dir`, which must not exist or be empty. Returns once the node answers as a
    /// fresh ledger-1 node on `options.passphrase`.
    pub fn start(binary: &CoreBinary, run_dir: &Path, options: NodeOptions) -> Result<Node> {
        if run_dir.exists() && std::fs::read_dir(run_dir)?.next().is_some() {
            bail!("run directory {} is not empty", run_dir.display());
        }
        std::fs::create_dir_all(run_dir)
            .with_context(|| format!("create {}", run_dir.display()))?;
        let run_dir = run_dir.canonicalize()?;
        let config = NodeConfig {
            passphrase: options.passphrase.clone(),
            profile: options.profile.clone(),
        };
        let cfg_path = run_dir.join("core.cfg");
        let mut ports = match options.first_ports {
            Some(p) => p,
            None => reserve_ports()?,
        };
        std::fs::write(&cfg_path, config.render(&run_dir, ports.0, ports.1)?)?;

        let newdb_log = run_dir.join("new-db.log");
        let status = binary
            .command()
            .arg("new-db")
            .arg("--conf")
            .arg(&cfg_path)
            .current_dir(&run_dir)
            .stdin(Stdio::null())
            .stdout(File::create(&newdb_log)?)
            .stderr(File::create(run_dir.join("new-db.err"))?)
            .status()
            .with_context(|| format!("run {} new-db", binary.path.display()))?;
        if !status.success() {
            bail!(
                "stellar-core new-db failed ({status}): {}{}",
                tail(&run_dir.join("new-db.err")),
                tail(&newdb_log)
            );
        }

        let mut node = Node {
            child: None,
            meta: MetaReader::new(&run_dir.join("meta.xdr")),
            run_dir,
            http_port: ports.0,
            query_port: ports.1,
            network_id: network_id(&options.passphrase),
            config_sha256: config.config_sha256()?,
            options,
            last_closed: 1,
        };
        // A port can still be taken between choosing it and core binding it (see the module
        // documentation); core then exits saying so. Try again on fresh ports, a bounded number of times.
        for attempt in 1..=START_ATTEMPTS {
            if attempt > 1 {
                ports = reserve_ports()?;
                std::fs::write(&cfg_path, config.render(&node.run_dir, ports.0, ports.1)?)?;
            }
            node.http_port = ports.0;
            node.query_port = ports.1;
            node.spawn(binary, &cfg_path)?;
            match node.wait_ready()? {
                None => return Ok(node),
                Some(why) => {
                    let kept = node.run_dir.join(format!("core.attempt-{attempt}.log"));
                    std::fs::rename(node.run_dir.join("core.log"), &kept)?;
                    let line = format!(
                        "stellar-core start attempt {attempt}/{START_ATTEMPTS} on ports {} and {} \
                         failed: {why} (log kept in {})",
                        ports.0,
                        ports.1,
                        kept.display()
                    );
                    eprintln!("{line}");
                    let mut f = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(node.run_dir.join("start-attempts.log"))?;
                    writeln!(f, "{line}")?;
                }
            }
        }
        bail!(
            "stellar-core found a port taken {START_ATTEMPTS} times; see {}",
            node.run_dir.join("start-attempts.log").display()
        )
    }

    fn spawn(&mut self, binary: &CoreBinary, cfg_path: &Path) -> Result<()> {
        let log = File::create(self.run_dir.join("core.log"))?;
        let mut cmd = binary.command();
        cmd.arg("run")
            .arg("--conf")
            .arg(cfg_path)
            .current_dir(&self.run_dir)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        // SAFETY: prctl is async-signal-safe and touches no memory of this process. Linux only: elsewhere the
        // node is stopped by its Drop.
        #[cfg(target_os = "linux")]
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        self.child = Some(
            cmd.spawn()
                .with_context(|| format!("start {}", binary.path.display()))?,
        );
        Ok(())
    }

    /// Wait until the node has bound both ports and answers `info`. `Ok(None)` when it is ready and
    /// is the fresh node just started; `Ok(Some(reason))` when core exited during start-up because a
    /// port was taken (the caller may retry on other ports); an error for anything else, including
    /// any other exit during start-up.
    fn wait_ready(&mut self) -> Result<Option<String>> {
        let deadline = Instant::now() + self.options.startup_timeout;
        let log_path = self.run_dir.join("core.log");
        let bound = listening_line(self.query_port);
        let mut listening = false;
        let info = loop {
            let child = self.child.as_mut().expect("spawned");
            if let Some(status) = child.try_wait()? {
                self.child = None;
                let log = std::fs::read_to_string(&log_path).unwrap_or_default();
                // The first fatal line names the cause.
                let cause = log
                    .lines()
                    .find(|l| l.contains("FATAL"))
                    .or_else(|| log.lines().last())
                    .unwrap_or("")
                    .to_string();
                if cause.contains(PORT_TAKEN) {
                    return Ok(Some(format!("exited ({status}): {cause}")));
                }
                bail!(
                    "stellar-core exited during start-up ({status}): {cause}; last log lines:\n{}",
                    tail(&log_path)
                );
            }
            // Until core says its query server is listening, another process may hold the command
            // port: an answer there is not this node's.
            if !listening {
                listening = std::fs::read_to_string(&log_path)
                    .is_ok_and(|log| log.lines().any(|l| l.ends_with(&bound)));
            }
            if listening {
                if let Ok(body) = http::get_with_timeout(self.http_port, "info", READY_POLL_TIMEOUT)
                {
                    if let Ok(v) = serde_json::from_str::<Value>(&body) {
                        if v.pointer("/info/state").is_some() {
                            break v;
                        }
                    }
                }
            }
            if Instant::now() > deadline {
                bail!(
                    "stellar-core did not become ready within {:?} ({}); last log lines:\n{}",
                    self.options.startup_timeout,
                    if listening {
                        "its ports are bound, but it does not answer info"
                    } else {
                        "its log never said the query server is listening"
                    },
                    tail(&log_path)
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        // The process that answered must be ours: alive, on our passphrase, at genesis.
        self.check_alive()?;
        let network = info.pointer("/info/network").and_then(Value::as_str);
        let ledger = info.pointer("/info/ledger/num").and_then(Value::as_u64);
        if network != Some(self.options.passphrase.as_str()) || ledger != Some(1) {
            bail!(
                "the node on port {} is not the fresh node just started (network {network:?}, ledger {ledger:?})",
                self.http_port
            );
        }
        Ok(None)
    }

    /// The node's passphrase.
    pub fn passphrase(&self) -> &str {
        &self.options.passphrase
    }

    /// `sha256(passphrase)`.
    pub fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    /// The run directory (absolute).
    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    /// The meta stream file.
    pub fn meta_path(&self) -> &Path {
        self.meta.path()
    }

    /// The options the node was started with.
    pub fn options(&self) -> &NodeOptions {
        &self.options
    }

    /// sha256 of the configuration template (paths and ports as placeholders).
    pub fn config_sha256(&self) -> &str {
        &self.config_sha256
    }

    /// The command port.
    pub fn http_port(&self) -> u16 {
        self.http_port
    }

    /// The query port (`getledgerentryraw`).
    pub fn query_port(&self) -> u16 {
        self.query_port
    }

    /// The sequence of the last ledger closed (1 right after start).
    pub fn last_closed(&self) -> u32 {
        self.last_closed
    }

    /// The close time the next [`Node::close`] will use.
    pub fn next_close_time(&self) -> Result<u64> {
        self.options.close_policy.close_time(self.last_closed + 1)
    }

    /// Core's `info` reply.
    pub fn info(&mut self) -> Result<Value> {
        let body = self.command("info")?;
        Ok(serde_json::from_str(&body)?)
    }

    /// Submit an envelope through `tx?blob=`. Any status is returned, not only `PENDING`.
    pub fn submit(&mut self, envelope: &TransactionEnvelope) -> Result<SubmitReply> {
        let hash = envelope.hash(self.network_id)?;
        let blob = envelope.to_xdr_base64(stellar_xdr::Limits::none())?;
        let raw = self.command(&format!("tx?blob={}", http::encode(&blob)))?;
        let v: Value = serde_json::from_str(&raw)
            .with_context(|| format!("tx reply is not JSON: {}", http::short(&raw)))?;
        if let Some(e) = v.get("exception") {
            bail!("stellar-core refused the tx command: {e}");
        }
        let status = match v.get("status").and_then(Value::as_str) {
            Some("PENDING") => SubmitStatus::Pending,
            Some("DUPLICATE") => SubmitStatus::Duplicate,
            Some("ERROR") => SubmitStatus::Error,
            Some("TRY_AGAIN_LATER") => SubmitStatus::TryAgainLater,
            Some("FILTERED") => SubmitStatus::Filtered,
            other => SubmitStatus::Other(other.unwrap_or("").to_string()),
        };
        let error = match v.get("error").and_then(Value::as_str) {
            Some(b64) => Some(TransactionResult::from_xdr_base64(b64, NODE_XDR_LIMITS)?),
            None => None,
        };
        let diagnostic_events = v
            .get("diagnostic_events")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(SubmitReply {
            hash,
            status,
            error,
            diagnostic_events,
            raw,
        })
    }

    /// Submit and require `PENDING`; returns the transaction hash.
    pub fn submit_pending(&mut self, envelope: &TransactionEnvelope) -> Result<[u8; 32]> {
        let r = self.submit(envelope)?;
        if r.status != SubmitStatus::Pending {
            bail!(
                "transaction {} was not accepted: {:?} {:?} ({})",
                hex::encode(r.hash),
                r.status,
                r.error,
                http::short(&r.raw)
            );
        }
        Ok(r.hash)
    }

    /// Arm ledger upgrades for the next close: `upgrades?mode=set&upgradetime=1970-01-01T00:00:00Z&
    /// expirationminutes=100000000&<params>`. The long expiration keeps the upgrade armed however far the
    /// close-time schedule is from the epoch. `params` are `name=value` pairs; values are percent-encoded.
    pub fn set_upgrades(&mut self, params: &[(&str, String)]) -> Result<()> {
        let mut q = String::from(
            "upgrades?mode=set&upgradetime=1970-01-01T00:00:00Z&expirationminutes=100000000",
        );
        for (k, v) in params {
            q.push_str(&format!("&{k}={}", http::encode(v)));
        }
        let reply = self.command(&q)?;
        if !reply.trim().is_empty() {
            bail!(
                "stellar-core refused the upgrade {params:?}: {}",
                http::short(&reply)
            );
        }
        Ok(())
    }

    /// Close the next ledger at its scheduled close time and return it from the meta stream.
    pub fn close(&mut self) -> Result<ClosedLedger> {
        let seq = self.last_closed + 1;
        let t = self.options.close_policy.close_time(seq)?;
        let reply = self.command(&format!("manualclose?closeTime={t}"))?;
        if !reply.contains(&format!("sequence number {seq} and closeTime {t}")) {
            let hint = if reply.contains("too early") {
                " (the node's virtual clock ran past the close-time schedule while it was idle; the run \
                 fails rather than retry with another close time)"
            } else {
                ""
            };
            bail!(
                "manualclose of ledger {seq} at {t} failed: {}{hint}",
                http::short(&reply)
            );
        }
        let deadline = Instant::now() + self.options.ledger_timeout;
        let rec = loop {
            if let Some(r) = self.meta.try_next()? {
                break r;
            }
            self.check_alive()?;
            if Instant::now() > deadline {
                bail!(
                    "ledger {seq} did not appear in {} within {:?}",
                    self.meta.path().display(),
                    self.options.ledger_timeout
                );
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        if rec.info.sequence != seq || rec.info.close_time != t {
            bail!(
                "meta stream record {} is ledger {} closed at {}, expected ledger {seq} at {t}",
                rec.index,
                rec.info.sequence,
                rec.info.close_time
            );
        }
        self.last_closed = seq;
        Ok(ClosedLedger {
            sequence: seq,
            protocol: rec.info.protocol,
            close_time: rec.info.close_time,
            header_hash: rec.info.header_hash,
            ledger_close_meta_version: rec.info.ledger_close_meta_version,
            stream_index: rec.index,
            bytes: rec.bytes,
        })
    }

    /// Live ledger entries for `keys` from the query server (missing keys are left out).
    pub fn ledger_entries(&mut self, keys: &[LedgerKey]) -> Result<Vec<LedgerEntry>> {
        self.check_alive()?;
        let mut body = Vec::new();
        for k in keys {
            body.push(format!(
                "key={}",
                http::encode(&k.to_xdr_base64(stellar_xdr::Limits::none())?)
            ));
        }
        let raw = http::post_form(self.query_port, "getledgerentryraw", &body.join("&"))?;
        let v: Value = serde_json::from_str(&raw).with_context(|| {
            format!("getledgerentryraw reply is not JSON: {}", http::short(&raw))
        })?;
        let mut out = Vec::new();
        for e in v
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let b64 = e
                .get("entry")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("getledgerentryraw entry without \"entry\": {e}"))?;
            out.push(LedgerEntry::from_xdr_base64(b64, NODE_XDR_LIMITS)?);
        }
        Ok(out)
    }

    /// The sequence number of `account`, or `None` if it does not exist.
    pub fn account_sequence(&mut self, account: &AccountId) -> Result<Option<i64>> {
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: account.clone(),
        });
        Ok(self
            .ledger_entries(&[key])?
            .into_iter()
            .find_map(|e| match e.data {
                LedgerEntryData::Account(a) if a.account_id == *account => Some(a.seq_num.0),
                _ => None,
            }))
    }

    /// Stop the node: SIGINT, then SIGKILL after ten seconds. Returns its exit status.
    pub fn stop(mut self) -> Result<ExitStatus> {
        let mut child = self.child.take().expect("child present until stop or drop");
        stop_child(&mut child, Duration::from_secs(10))
    }

    /// A command-port request, after checking the process is still ours and alive.
    fn command(&mut self, path_and_query: &str) -> Result<String> {
        self.check_alive()?;
        http::get(self.http_port, path_and_query)
    }

    fn check_alive(&mut self) -> Result<()> {
        let child = self
            .child
            .as_mut()
            .expect("child present until stop or drop");
        if let Some(status) = child.try_wait()? {
            bail!(
                "stellar-core exited ({status}); last log lines:\n{}",
                tail(&self.run_dir.join("core.log"))
            );
        }
        Ok(())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn stop_child(child: &mut Child, grace: Duration) -> Result<ExitStatus> {
    if let Some(s) = child.try_wait()? {
        return Ok(s);
    }
    let pid = libc::pid_t::try_from(child.id()).context("pid out of range")?;
    // SAFETY: plain syscall on our own child's pid, which has not been reaped (try_wait returned None).
    unsafe {
        libc::kill(pid, libc::SIGINT);
    }
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if let Some(s) = child.try_wait()? {
            return Ok(s);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.kill()?;
    Ok(child.wait()?)
}

/// The line stellar-core logs once its query server on `port` is bound. Core binds the command port
/// first and exits if either bind fails, so after this line both ports are its own.
fn listening_line(query_port: u16) -> String {
    format!("Listening on 127.0.0.1:{query_port} for Query requests")
}

/// Two distinct reserved TCP ports on 127.0.0.1 for core's command and query servers.
fn reserve_ports() -> Result<(u16, u16)> {
    let a = reserve_port()?;
    // `a` is reserved now, so the kernel does not hand it out again.
    let b = reserve_port()?;
    if a == b {
        bail!("the kernel handed out reserved port {a} twice");
    }
    Ok((a, b))
}

/// A free TCP port on 127.0.0.1, reserved for about a minute (the TIME_WAIT interval). The port is
/// bound, a connection to it is accepted, and the accepted side closes first, so its socket stays
/// in TIME_WAIT on the port after everything is closed. Until that ends the kernel hands the port to
/// no other `bind` to port 0 and to no outgoing connection, but a server that binds it explicitly
/// with `SO_REUSEADDR`, as stellar-core's command and query servers do, gets it.
fn reserve_port() -> Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("bind a free port")?;
    let port = listener.local_addr()?.port();
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .with_context(|| format!("connect to the reserved port {port}"))?;
    let (accepted, _) = listener.accept().context("accept on the reserved port")?;
    drop(accepted);
    // The accepted side's FIN has arrived once the client reads end-of-stream; closing the client
    // then completes the accepted side's close into TIME_WAIT.
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = [0u8; 1];
    let n = client
        .read(&mut buf)
        .with_context(|| format!("close the reserved port {port}"))?;
    if n != 0 {
        bail!("the reserved port {port} sent data");
    }
    drop(client);
    drop(listener);
    Ok(port)
}

/// The last 20 lines of a log file.
fn tail(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(20)..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule() {
        let p = ClosePolicy::default();
        assert_eq!(p.close_time(2).unwrap(), 1_700_000_000);
        // The probes closed ledger 28 at 1726000000 on both networks.
        assert_eq!(p.close_time(28).unwrap(), 1_726_000_000);
        assert!(p.close_time(1).is_err());
        assert!(p.close_time(10_000).is_err(), "past the year 2200");
        assert!(ClosePolicy {
            base: 0,
            stride: 10
        }
        .close_time(3)
        .is_err());
    }

    /// Bind 127.0.0.1:`port` without `SO_REUSEADDR`; whether it succeeded.
    fn binds_without_reuse(port: u16) -> bool {
        // SAFETY: plain socket calls on a descriptor this function owns and closes.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            assert!(fd >= 0);
            let addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: port.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(Ipv4Addr::LOCALHOST).to_be(),
                },
                sin_zero: [0; 8],
            };
            let r = libc::bind(
                fd,
                std::ptr::addr_of!(addr).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            libc::close(fd);
            r == 0
        }
    }

    /// A reserved port stays held — a plain bind fails, so neither port 0 nor an outgoing
    /// connection gets it — while a server binding it with `SO_REUSEADDR`, as core does, gets it.
    #[test]
    fn reserved_ports_are_held_but_core_can_bind_them() {
        let (a, b) = reserve_ports().unwrap();
        assert_ne!(a, b);
        for p in [a, b] {
            assert!(!binds_without_reuse(p), "port {p} is not held");
            // std sets SO_REUSEADDR on a listener, as asio does for core's servers.
            let l = TcpListener::bind((Ipv4Addr::LOCALHOST, p)).unwrap();
            assert_eq!(l.local_addr().unwrap().port(), p);
        }
        assert_eq!(
            listening_line(a),
            format!("Listening on 127.0.0.1:{a} for Query requests")
        );
    }
}
