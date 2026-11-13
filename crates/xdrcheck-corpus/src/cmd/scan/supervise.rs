//! `scan supervise`: run N `scan run` workers of one range plan as child processes on this machine.
//!
//! - A worker that exits 3 (the lake answered 429 / 503 / `SlowDown`) is restarted after an
//!   exponential, capped, jittered backoff, and every later (re)start uses half the parallel GETs
//!   (at least 4; halved at most once per backoff base), for the running workers too; after 10
//!   quiet minutes the rate climbs back by doubling.
//! - A worker that exits otherwise non-zero is restarted the same way at most `--max-crashes` times.
//! - Every 30 s a heartbeat line (ledgers done, GETs/s, MB/s, retries, throttles, per-worker RSS,
//!   disk free, write MB/s) is appended to `<out>/heartbeat.jsonl` and `<out>/heartbeat.json` is
//!   replaced.
//! - The live GET cap is written to `<out>/gets_limit`; every worker re-reads it every 10 s.
//! - Watchdog: no ledger progress for `--stall-minutes`, or `--wall-hours` passed → the workers are
//!   killed and the supervisor exits 2 (stall) or 4 (wall clock). A worker over its crash budget is
//!   given up while the others finish; then exit 5. All workers done → exit 0.
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{json, Value};

#[derive(clap::Args, Debug)]
pub struct SuperviseArgs {
    /// Range plan
    #[arg(long)]
    pub ranges: PathBuf,
    /// Workers (one child process each)
    #[arg(long)]
    pub workers: usize,
    /// Run directory; worker i writes to `<out>/w<i>`
    #[arg(long)]
    pub out: PathBuf,
    /// Lake base URL
    #[arg(long)]
    pub http: String,
    /// Most parallel GETs per worker (threads and window; at most 64)
    #[arg(long, default_value_t = 64)]
    pub gets_per_worker: usize,
    /// The machine's GETs per second over all workers (0 = no cap). Change it while running by
    /// writing a number to `<out>/gets_rate`; workers re-read it every 10 s.
    #[arg(long, default_value_t = 0.0)]
    pub max_gets_per_sec: f64,
    /// Parallel GETs per worker at the start (default: --gets-per-worker). Raise it while running
    /// by writing a number to `<out>/gets_limit` (capped by --gets-per-worker).
    #[arg(long)]
    pub start_gets: Option<usize>,
    /// Restarts allowed per worker after non-throttle failures
    #[arg(long, default_value_t = 3)]
    pub max_crashes: u32,
    /// Backoff base and cap, seconds
    #[arg(long, default_value_t = 30)]
    pub backoff_base: u64,
    #[arg(long, default_value_t = 900)]
    pub backoff_cap: u64,
    /// Exit 2 when no ledger progress for this many minutes
    #[arg(long, default_value_t = 20.0)]
    pub stall_minutes: f64,
    /// Exit 4 after this many hours (0 = no limit)
    #[arg(long, default_value_t = 0.0)]
    pub wall_hours: f64,
    /// Heartbeat interval, seconds
    #[arg(long, default_value_t = 30)]
    pub heartbeat_secs: u64,
    /// Scanner binary (default: this one)
    #[arg(long)]
    pub bin: Option<PathBuf>,
    /// Extra arguments for every `scan run` (after `--`)
    #[arg(last = true)]
    pub extra: Vec<String>,
}

struct Worker {
    child: Option<Child>,
    restart_at: Option<Instant>,
    throttles: u32,
    crashes: u32,
    done: bool,
    last_ledgers: u64,
    last_write: u64,
}

fn jitter(secs: u64) -> Duration {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let f = 0.5 + (n % 1000) as f64 / 1000.0; // 0.5 .. 1.5
    Duration::from_secs_f64(secs as f64 * f)
}

fn proc_kb(pid: u32, file: &str, key: &str) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/{file}"))
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with(key))
                .map(|l| l.to_string())
        })
        .and_then(|l| l.split_whitespace().nth(1).and_then(|x| x.parse().ok()))
        .unwrap_or(0)
}

fn free_bytes(dir: &Path) -> u64 {
    Command::new("df")
        .args(["-B1", "--output=avail"])
        .arg(dir)
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .nth(1)
                .and_then(|l| l.trim().parse().ok())
        })
        .unwrap_or(0)
}

fn read_progress(dir: &Path) -> Value {
    std::fs::read(dir.join("progress.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(json!({}))
}

pub fn run(a: SuperviseArgs) -> Result<ExitCode> {
    std::fs::create_dir_all(&a.out)?;
    let bin = match &a.bin {
        Some(b) => b.clone(),
        None => std::env::current_exe()?,
    };
    let max_gets = a.gets_per_worker.clamp(4, 64);
    let mut gets = a.start_gets.unwrap_or(max_gets).clamp(4, max_gets);
    // The operator may have changed the live cap by hand: start from what the file says.
    let live = |g: usize| -> usize {
        std::fs::read_to_string(a.out.join("gets_limit"))
            .ok()
            .and_then(|t| t.trim().parse::<usize>().ok())
            .map(|v| v.clamp(4, max_gets))
            .unwrap_or(g)
    };
    let mut last_throttle: Option<Instant> = None;
    let mut ws: Vec<Worker> = (0..a.workers)
        .map(|_| Worker {
            child: None,
            restart_at: Some(Instant::now()),
            throttles: 0,
            crashes: 0,
            done: false,
            last_ledgers: 0,
            last_write: 0,
        })
        .collect();
    let t0 = Instant::now();
    let mut last_progress = Instant::now();
    let mut last_beat = Instant::now() - Duration::from_secs(a.heartbeat_secs);
    let mut prev_totals = (0u64, 0u64, 0u64, Instant::now());
    let mut best_ledgers = 0u64;
    // Counters (ledgers, object bytes, GETs, retries, refusals) of worker processes that have exited.
    let mut carried = [0u64; 7];
    const KEYS: [&str; 7] = [
        "ledgers",
        "object_bytes",
        "gets",
        "retries",
        "refusals",
        "http_throttled",
        "throttle_retries",
    ];
    let rate_file = a.out.join("gets_rate");
    super::store::write_atomic(&rate_file, format!("{}\n", a.max_gets_per_sec).as_bytes())?;
    // The live GET cap every worker re-reads every 10 s: a throttle slows all running workers.
    let limit_file = a.out.join("gets_limit");
    super::store::write_atomic(&limit_file, format!("{gets}\n").as_bytes())?;
    let spawn = |i: usize| -> Result<Child> {
        let dir = a.out.join(format!("w{i}"));
        std::fs::create_dir_all(&dir)?;
        let _ = std::fs::remove_file(dir.join("progress.json"));
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(a.out.join(format!("w{i}.log")))?;
        let mut c = Command::new(&bin);
        c.args(["scan", "run", "--ranges"])
            .arg(&a.ranges)
            .args([
                "--workers",
                &a.workers.to_string(),
                "--worker",
                &i.to_string(),
                "--jobs",
                "1",
            ])
            .args([
                "--http",
                &a.http,
                "--max-inflight",
                &max_gets.to_string(),
                "--fetch-jobs",
                &max_gets.to_string(),
                "--window",
                &max_gets.to_string(),
            ])
            .arg("--gets-limit-file")
            .arg(&limit_file)
            .arg("--gets-rate-file")
            .arg(&rate_file)
            .arg("--out")
            .arg(&dir)
            .args(&a.extra)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log));
        c.spawn().with_context(|| format!("start worker {i}"))
    };
    let code = loop {
        // Children: exits, restarts.
        for (i, w) in ws.iter_mut().enumerate() {
            if let Some(c) = &mut w.child {
                if let Some(st) = c.try_wait()? {
                    let p = read_progress(&a.out.join(format!("w{i}")));
                    for (c, k) in carried.iter_mut().zip(KEYS) {
                        *c += p[k].as_u64().unwrap_or(0);
                    }
                    w.child = None;
                    w.last_ledgers = 0;
                    match st.code() {
                        Some(0) => w.done = true,
                        Some(3) => {
                            w.throttles += 1;
                            // Halve at most once per backoff base, so many workers throttled together
                            // count as one slow-down signal.
                            if last_throttle
                                .is_none_or(|t| t.elapsed() >= Duration::from_secs(a.backoff_base))
                            {
                                gets = (live(gets) / 2).max(4);
                                super::store::write_atomic(
                                    &limit_file,
                                    format!("{gets}\n").as_bytes(),
                                )?;
                            }
                            last_throttle = Some(Instant::now());
                            let b = (a.backoff_base << w.throttles.min(10)).min(a.backoff_cap);
                            w.restart_at = Some(Instant::now() + jitter(b));
                            eprintln!("supervise: worker {i} throttled ({}); restart in ~{b}s at {gets} GETs", w.throttles);
                        }
                        other => {
                            w.crashes += 1;
                            if w.crashes > a.max_crashes {
                                // Give up on this worker only; the others keep going.
                                eprintln!("supervise: worker {i} failed {} times (last exit {other:?}); giving up on it, the others continue", w.crashes);
                                w.done = true;
                                continue;
                            }
                            let b = (a.backoff_base << w.crashes.min(10)).min(a.backoff_cap);
                            w.restart_at = Some(Instant::now() + jitter(b));
                            eprintln!(
                                "supervise: worker {i} exited {other:?}; restart {} of {} in ~{b}s",
                                w.crashes, a.max_crashes
                            );
                        }
                    }
                }
            }
        }
        // Climb back after 10 quiet minutes.
        if last_throttle.is_some_and(|t| t.elapsed() > Duration::from_secs(600)) && gets < max_gets
        {
            gets = (live(gets) * 2).min(max_gets);
            super::store::write_atomic(&limit_file, format!("{gets}\n").as_bytes())?;
            last_throttle = Some(Instant::now());
        }
        for (i, w) in ws.iter_mut().enumerate() {
            if !w.done && w.child.is_none() && w.restart_at.is_some_and(|t| Instant::now() >= t) {
                w.child = Some(spawn(i)?);
                w.restart_at = None;
            }
        }
        if ws.iter().all(|w| w.done) {
            break if ws.iter().any(|w| w.crashes > a.max_crashes) {
                5
            } else {
                0
            };
        }
        // Heartbeat and watchdog.
        if last_beat.elapsed() >= Duration::from_secs(a.heartbeat_secs) {
            last_beat = Instant::now();
            let [mut ledgers, mut bytes, mut gets_n, mut retries, mut refusals, mut http_throttled, mut throttle_retries] =
                carried;
            let mut factor_min = 1.0f64;
            let mut workers = Vec::new();
            let mut write_bytes = 0u64;
            for (i, w) in ws.iter_mut().enumerate() {
                // Only a running child's counters: an exited one's are in `carried`.
                let p = if w.child.is_some() {
                    read_progress(&a.out.join(format!("w{i}")))
                } else {
                    json!({})
                };
                let l = p["ledgers"].as_u64().unwrap_or(0);
                ledgers += l;
                bytes += p["object_bytes"].as_u64().unwrap_or(0);
                gets_n += p["gets"].as_u64().unwrap_or(0);
                retries += p["retries"].as_u64().unwrap_or(0);
                refusals += p["refusals"].as_u64().unwrap_or(0);
                http_throttled += p["http_throttled"].as_u64().unwrap_or(0);
                throttle_retries += p["throttle_retries"].as_u64().unwrap_or(0);
                if let Some(f) = p["rate_factor"].as_f64() {
                    factor_min = factor_min.min(f);
                }
                let (rss, wb) = match &w.child {
                    Some(c) => (
                        proc_kb(c.id(), "status", "VmRSS:"),
                        proc_kb(c.id(), "io", "write_bytes:"),
                    ),
                    None => (0, 0),
                };
                if wb >= w.last_write {
                    write_bytes += wb - w.last_write;
                }
                w.last_write = wb;
                w.last_ledgers = l;
                workers.push(json!({"worker": i, "running": w.child.is_some(), "done": w.done, "ledgers": l, "rss_kib": rss, "throttles": w.throttles, "crashes": w.crashes}));
            }
            let dt = prev_totals.3.elapsed().as_secs_f64().max(1.0);
            let beat = json!({
                "unix_s": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
                "elapsed_s": t0.elapsed().as_secs(),
                "ledgers_done": ledgers,
                "workers_done": ws.iter().filter(|w| w.done).count(),
                "gets_per_s": (gets_n.saturating_sub(prev_totals.1)) as f64 / dt,
                "mb_per_s": (bytes.saturating_sub(prev_totals.2)) as f64 / 1e6 / dt,
                "ledgers_per_s": (ledgers.saturating_sub(prev_totals.0)) as f64 / dt,
                "retries": retries,
                "refusals": refusals,
                "http_throttled": http_throttled,
                "throttle_retries": throttle_retries,
                "rate_factor_min": factor_min,
                "gets_rate_cap": std::fs::read_to_string(&rate_file).ok().and_then(|t| t.trim().parse::<f64>().ok()),
                "throttles": ws.iter().map(|w| w.throttles).sum::<u32>(),
                "gets_per_worker": gets,
                "rss_total_kib": workers.iter().map(|w| w["rss_kib"].as_u64().unwrap_or(0)).sum::<u64>(),
                "disk_free_bytes": free_bytes(&a.out),
                "write_mb_per_s": write_bytes as f64 / 1e6 / dt,
                "workers": workers,
            });
            prev_totals = (ledgers, gets_n, bytes, Instant::now());
            // Progress = more ledgers journaled than ever before (restarts and re-fetches do not count).
            if ledgers > best_ledgers {
                best_ledgers = ledgers;
                last_progress = Instant::now();
            }
            let line = format!("{beat}\n");
            use std::io::Write;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(a.out.join("heartbeat.jsonl"))?
                .write_all(line.as_bytes())?;
            super::store::write_atomic(&a.out.join("heartbeat.json"), line.as_bytes())?;
            if last_progress.elapsed() > Duration::from_secs_f64(a.stall_minutes * 60.0) {
                eprintln!(
                    "supervise: no ledger progress for {} minutes; stopping",
                    a.stall_minutes
                );
                break 2;
            }
        }
        if a.wall_hours > 0.0 && t0.elapsed() > Duration::from_secs_f64(a.wall_hours * 3600.0) {
            eprintln!(
                "supervise: wall-clock limit of {} h reached; stopping",
                a.wall_hours
            );
            break 4;
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    for w in ws.iter_mut() {
        if let Some(c) = &mut w.child {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
    eprintln!(
        "supervise: exit {code} after {:.0} s",
        t0.elapsed().as_secs_f64()
    );
    Ok(ExitCode::from(code))
}
