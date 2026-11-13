//! Where scan objects come from: local packs (one `objects.pack` + `objects.idx.tsv` per lake
//! partition), a local directory laid out like the lake (`DIR/<key>`), or the public lake over
//! HTTPS through one pooled client (keep-alive connections, retries with backoff).
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::cmd::intake::lake;
use crate::cmd::mine::{MAX_RETRIES, MAX_RETRY_WAIT};

/// Back-pressure towards the lake, process-wide.
///
/// - A `429` / `503` / `SlowDown` answer is retried for that request after an exponential, jittered
///   wait (0.5 s doubling to 30 s), up to [`pace::THROTTLE_RETRIES`] times; only then does the GET
///   fail with [`Throttled`] (and the worker stops, exit 3).
/// - Every GET (retries included) waits for its turn under a rate cap of `RATE_MILLI / 1000` GETs/s
///   (0 = none), times the back-pressure factor.
/// - AIMD: over the last 30 s, when more than `AIMD_SHARE_PPM` of the answers were throttled
///   (and at least 50 answers were seen), the factor drops to 70% (at most once per 10 s, never
///   below 10%); after 30 s with no throttled answer it climbs by 5 points back to 100%. The
///   factor scales both the rate cap and the parallel-GET cap.
pub mod pace {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    pub static THROTTLE_RETRIES: AtomicU32 = AtomicU32::new(10);
    pub static RATE_MILLI: AtomicU64 = AtomicU64::new(0);
    pub static FACTOR_MILLI: AtomicU64 = AtomicU64::new(1000);
    pub static AIMD_SHARE_PPM: AtomicU64 = AtomicU64::new(50_000);
    pub static THROTTLED_ANSWERS: AtomicU64 = AtomicU64::new(0);
    pub static THROTTLE_RETRIED: AtomicU64 = AtomicU64::new(0);
    static SEED: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

    static NEXT: Mutex<Option<Instant>> = Mutex::new(None);
    struct Win {
        seen: VecDeque<(Instant, bool)>,
        changed: Option<Instant>,
        last_bad: Option<Instant>,
    }
    static WIN: Mutex<Win> = Mutex::new(Win {
        seen: VecDeque::new(),
        changed: None,
        last_bad: None,
    });

    pub fn factor() -> f64 {
        FACTOR_MILLI.load(Relaxed) as f64 / 1000.0
    }

    /// Wait for this GET's turn under the rate cap.
    pub fn turn() {
        let r = RATE_MILLI.load(Relaxed) as f64 / 1000.0 * factor();
        if r <= 0.0 {
            return;
        }
        let gap = Duration::from_secs_f64(1.0 / r);
        let at = {
            let mut n = NEXT.lock().unwrap();
            let now = Instant::now();
            let at = match *n {
                Some(t) if t > now => t,
                _ => now,
            };
            *n = Some(at + gap);
            at
        };
        let now = Instant::now();
        if at > now {
            std::thread::sleep(at - now);
        }
    }

    /// Record one answer (throttled or not) and adjust the factor.
    pub fn observe(throttled: bool) {
        let now = Instant::now();
        let mut w = WIN.lock().unwrap();
        w.seen.push_back((now, throttled));
        if throttled {
            THROTTLED_ANSWERS.fetch_add(1, Relaxed);
            w.last_bad = Some(now);
        }
        while w
            .seen
            .front()
            .is_some_and(|(t, _)| now - *t > Duration::from_secs(30))
        {
            w.seen.pop_front();
        }
        if w.changed.is_some_and(|t| now - t < Duration::from_secs(10)) {
            return;
        }
        let n = w.seen.len() as u64;
        let bad = w.seen.iter().filter(|(_, b)| *b).count() as u64;
        let f = FACTOR_MILLI.load(Relaxed);
        if n >= 50 && bad * 1_000_000 > n * AIMD_SHARE_PPM.load(Relaxed) {
            FACTOR_MILLI.store((f * 7 / 10).max(100), Relaxed);
            w.changed = Some(now);
        } else if f < 1000
            && w.last_bad
                .is_none_or(|t| now - t >= Duration::from_secs(30))
            && w.changed.is_none_or(|t| now - t >= Duration::from_secs(30))
        {
            FACTOR_MILLI.store((f + 50).min(1000), Relaxed);
            w.changed = Some(now);
        }
    }

    /// 0.5 s doubling to 30 s, times a jitter in [0.5, 1.5).
    pub fn wait(attempt: u32) -> Duration {
        let base = (0.5 * f64::from(1u32 << attempt.saturating_sub(1).min(6))).min(30.0);
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let mut x = SEED.fetch_add(0x9E37_79B9_7F4A_7C15, Relaxed) ^ u64::from(n);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        Duration::from_secs_f64(base * (0.5 + (x % 1000) as f64 / 1000.0))
    }
}

/// The lake partition directory of `seq` (`FC2899FF--64448000-64511999`).
pub fn partition_of(seq: u32) -> String {
    lake::object_key(seq)
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

/// One fetched object and what came with it.
#[derive(Debug, Clone, Default)]
pub struct Fetched {
    pub bytes: Option<Vec<u8>>,
    pub status: u16,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub meta: BTreeMap<String, String>,
    pub tries: u32,
    pub us: u64,
    /// A problem the source found (sha256 against the pack index).
    pub problem: Option<String>,
}

pub struct PackEntry {
    offset: u64,
    bytes: u64,
    sha256: String,
    etag: Option<String>,
    last_modified: Option<String>,
    meta: BTreeMap<String, String>,
}

/// Process-wide cap on parallel GETs that may change while running (0 = only `--max-inflight`).
pub static GET_LIMIT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub enum Source {
    Packs {
        root: PathBuf,
        idx: Mutex<HashMap<String, Arc<HashMap<u32, PackEntry>>>>,
    },
    Dir(PathBuf),
    Http {
        base: String,
        agent: ureq::Agent,
        inflight: Arc<(Mutex<usize>, std::sync::Condvar)>,
        max: usize,
    },
}

impl Source {
    pub fn packs(root: PathBuf) -> Source {
        Source::Packs {
            root,
            idx: Mutex::new(HashMap::new()),
        }
    }
    pub fn http(base: String, max_inflight: usize) -> Source {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(300)))
            .http_status_as_error(false)
            .max_idle_connections_per_host(64)
            .user_agent("xdrcheck-corpus-scan")
            .build()
            .into();
        Source::Http {
            base,
            agent,
            inflight: Arc::new((Mutex::new(0), std::sync::Condvar::new())),
            max: max_inflight,
        }
    }

    pub fn name(&self) -> String {
        match self {
            Source::Packs { root, .. } => format!("packs:{}", root.display()),
            Source::Dir(d) => format!("dir:{}", d.display()),
            Source::Http { base, .. } => base.clone(),
        }
    }

    fn pack_index(&self, part: &str) -> Result<Arc<HashMap<u32, PackEntry>>> {
        let Source::Packs { root, idx } = self else {
            unreachable!()
        };
        // Held while the index is built: concurrent fetchers of one partition must not each parse
        // (and hold) their own copy of a 64,000-line index.
        let mut cache = idx.lock().unwrap();
        if let Some(i) = cache.get(part) {
            return Ok(i.clone());
        }
        let path = root.join(part).join("objects.idx.tsv");
        let mut m = HashMap::new();
        if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            let mut lines = text.lines();
            let head: Vec<&str> = lines.next().unwrap_or("").split('\t').collect();
            let col = |n: &str| head.iter().position(|h| *h == n);
            let (cs, co, cb, ch) = (col("seq"), col("offset"), col("bytes"), col("sha256"));
            let (ce, cl, cm) = (col("etag"), col("last_modified"), col("meta_json"));
            for l in lines {
                let f: Vec<&str> = l.split('\t').collect();
                let g = |c: Option<usize>| c.and_then(|i| f.get(i)).copied().unwrap_or("");
                let seq: u32 = g(cs).parse().context("idx seq")?;
                let meta: BTreeMap<String, String> =
                    serde_json::from_str::<serde_json::Value>(g(cm))
                        .ok()
                        .and_then(|v| v.as_object().cloned())
                        .map(|o| {
                            o.into_iter()
                                .map(|(k, v)| (k, v.as_str().unwrap_or("").to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                let opt = |s: &str| (!s.is_empty()).then(|| s.to_string());
                m.insert(
                    seq,
                    PackEntry {
                        offset: g(co).parse()?,
                        bytes: g(cb).parse()?,
                        sha256: g(ch).to_string(),
                        etag: opt(g(ce)),
                        last_modified: opt(g(cl)),
                        meta,
                    },
                );
            }
        }
        let a = Arc::new(m);
        cache.insert(part.to_string(), a.clone());
        Ok(a)
    }

    /// Fetch ledger `seq`. `again` asks for a fresh copy (the refusal classifier's second fetch).
    pub fn get(&self, seq: u32, again: bool) -> Result<Fetched> {
        let t0 = Instant::now();
        let mut out = match self {
            Source::Packs { root, .. } => {
                let part = partition_of(seq);
                let idx = self.pack_index(&part)?;
                match idx.get(&seq) {
                    None => Fetched {
                        status: 404,
                        ..Default::default()
                    },
                    Some(e) => {
                        let f = File::open(root.join(&part).join("objects.pack"))?;
                        let mut b = vec![0u8; e.bytes as usize];
                        f.read_exact_at(&mut b, e.offset)?;
                        let problem = (xdrcheck_xdr::sha256_hex(&b) != e.sha256).then(|| {
                            format!("object sha256 differs from the pack index ({})", e.sha256)
                        });
                        Fetched {
                            bytes: Some(b),
                            status: 200,
                            etag: e.etag.clone(),
                            last_modified: e.last_modified.clone(),
                            meta: e.meta.clone(),
                            tries: 1,
                            problem,
                            ..Default::default()
                        }
                    }
                }
            }
            Source::Dir(d) => {
                let key = lake::object_key(seq);
                let second = d.join(format!("{key}.second"));
                let p = if again && second.exists() {
                    second
                } else {
                    d.join(&key)
                };
                match std::fs::read(&p) {
                    Ok(b) => Fetched {
                        bytes: Some(b),
                        status: 200,
                        tries: 1,
                        ..Default::default()
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Fetched {
                        status: 404,
                        tries: 1,
                        ..Default::default()
                    },
                    Err(e) => return Err(e.into()),
                }
            }
            Source::Http {
                base,
                agent,
                inflight,
                max,
            } => {
                let url = format!("{base}/{}", lake::object_key(seq));
                let (lock, cv) = &**inflight;
                {
                    let mut n = lock.lock().unwrap();
                    // A live limit (set by `scan supervise` through --gets-limit-file) can lower the cap.
                    loop {
                        let live = GET_LIMIT.load(std::sync::atomic::Ordering::Relaxed);
                        let cap = if live == 0 { *max } else { live.min(*max) };
                        let cap = ((cap as f64 * pace::factor()) as usize).max(1);
                        if *n < cap {
                            break;
                        }
                        n = cv.wait_timeout(n, Duration::from_secs(1)).unwrap().0;
                    }
                    *n += 1;
                }
                let r = http_get(agent, &url);
                {
                    *lock.lock().unwrap() -= 1;
                    cv.notify_one();
                }
                r?
            }
        };
        out.us = t0.elapsed().as_micros() as u64;
        Ok(out)
    }
}

/// The lake answered `429`, `503` or `SlowDown`: the run stops instead of retrying.
#[derive(Debug)]
pub struct Throttled(pub String);

impl std::fmt::Display for Throttled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "throttled by the lake ({}); stopping, resume later",
            self.0
        )
    }
}

impl std::error::Error for Throttled {}

/// GET with retries: transport errors and `5xx` other than `503` back off (honouring `Retry-After`);
/// `429` / `503` (S3 `SlowDown`) return [`Throttled`].
pub fn http_get(agent: &ureq::Agent, url: &str) -> Result<Fetched> {
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let wait = |a: u32| Duration::from_millis((1000u64 << a.min(6)).min(MAX_RETRY_WAIT * 1000));
        pace::turn();
        let throttled = |what: String, attempt: u32| -> Option<anyhow::Error> {
            pace::observe(true);
            if attempt > pace::THROTTLE_RETRIES.load(std::sync::atomic::Ordering::Relaxed) {
                return Some(anyhow::Error::new(Throttled(format!(
                    "{what} (after {attempt} attempts)"
                ))));
            }
            pace::THROTTLE_RETRIED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::thread::sleep(pace::wait(attempt));
            None
        };
        match agent.get(url).call() {
            Ok(mut resp) => {
                let status = resp.status().as_u16();
                let h = |n: &str| {
                    resp.headers()
                        .get(n)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string())
                };
                let etag = h("etag").map(|s| s.trim_matches('"').to_string());
                let last_modified = h("last-modified");
                let retry_after = h("retry-after").and_then(|s| s.parse::<u64>().ok());
                let meta: BTreeMap<String, String> = resp
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| {
                        let k = k.as_str().to_ascii_lowercase();
                        k.strip_prefix("x-amz-meta-")
                            .map(|m| (m.to_string(), v.to_str().unwrap_or("").to_string()))
                    })
                    .collect();
                match status {
                    200 => {
                        let body = resp.body_mut().with_config().limit(1 << 30).read_to_vec();
                        if let Ok(b) = &body {
                            if b.len() < 1024
                                && String::from_utf8_lossy(b).contains("<Code>SlowDown</Code>")
                            {
                                match throttled(format!("{url}: SlowDown"), attempt) {
                                    Some(e) => return Err(e),
                                    None => continue,
                                }
                            }
                        }
                        pace::observe(false);
                        match body {
                            Ok(b) => {
                                return Ok(Fetched {
                                    bytes: Some(b),
                                    status,
                                    etag,
                                    last_modified,
                                    meta,
                                    tries: attempt,
                                    ..Default::default()
                                })
                            }
                            Err(e) if attempt <= MAX_RETRIES => {
                                eprintln!("{url}: body: {e}; retrying");
                                std::thread::sleep(wait(attempt));
                            }
                            Err(e) => bail!("{url}: body: {e}"),
                        }
                    }
                    403 | 404 => {
                        pace::observe(false);
                        return Ok(Fetched {
                            status,
                            tries: attempt,
                            ..Default::default()
                        });
                    }
                    // The lake asks us to slow down: wait and retry this request; stop the run (it
                    // resumes from its journals) only when the retries are used up.
                    429 | 503 => match throttled(format!("{url}: HTTP {status}"), attempt) {
                        Some(e) => return Err(e),
                        None => continue,
                    },
                    500..=599 if attempt <= MAX_RETRIES => {
                        let w = retry_after
                            .map(|s| Duration::from_secs(s.min(MAX_RETRY_WAIT)))
                            .unwrap_or(wait(attempt));
                        eprintln!("{url}: HTTP {status}; retrying in {w:?}");
                        std::thread::sleep(w);
                    }
                    s => bail!("{url}: HTTP {s}"),
                }
            }
            Err(e) if attempt <= MAX_RETRIES => {
                eprintln!("{url}: {e}; retrying");
                std::thread::sleep(wait(attempt));
            }
            Err(e) => bail!("{url}: {e}"),
        }
    }
}
