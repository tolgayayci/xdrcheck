//! `scan run` and `scan supervise` against fake lakes: one that always answers 503 `SlowDown`, one
//! that accepts connections and never answers.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    if d.exists() {
        std::fs::remove_dir_all(&d).unwrap();
    }
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A lake on 127.0.0.1: `slow` answers every request 503 SlowDown; otherwise it never answers.
fn fake_lake(slow: bool) -> String {
    fake_lake_status(if slow { 503 } else { 0 })
}

/// 503 = SlowDown to everything; 404 = every object missing; 1503 = alternately 503 and 404
/// (counted over all connections); 0 = never answer.
static SEEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn fake_lake_status(status: u16) -> String {
    let slow = status != 0;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            if !slow {
                held.push(s);
                continue;
            }
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];

                let body = "<?xml version=\"1.0\"?><Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error>";
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let k = SEEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    // 1503: every other answer is 503 SlowDown, the rest 404.
                    let r = if status == 404 || (status == 1503 && k.is_multiple_of(2)) {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
                    } else {
                        format!(
                            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                    };
                    if s.write_all(r.as_bytes()).is_err() {
                        break;
                    }
                }
            });
        }
    });
    format!("http://127.0.0.1:{port}/v1.1/stellar/ledgers/pubnet")
}

fn plan(dir: &Path) -> PathBuf {
    let p = dir.join("ranges.tsv");
    std::fs::write(
        &p,
        "# xdrcheck scan range plan\nunit\tpartition\tfirst\tlast\tledgers\test_bytes\tweight\n\
         0\tFFFFFFFF--0-63999\t3\t6\t4\t4000\t4000\n1\tFFFFFFFF--0-63999\t1\t2\t2\t2000\t2000\n",
    )
    .unwrap();
    p
}

// Every scan below passes `--min-free 0`: the scans write a few files, and the default free-space floor (sized
// for a full scan) would stop them on a small disk such as a CI runner's.
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_xdrcheck-corpus")
}

fn supervise(dir: &Path, lake: &str, extra: &[&str]) -> (i32, Duration) {
    let t = Instant::now();
    let st = Command::new(bin())
        .args(["scan", "supervise", "--ranges"])
        .arg(plan(dir))
        .args(["--workers", "2", "--out"])
        .arg(dir.join("run"))
        .args([
            "--http",
            lake,
            "--gets-per-worker",
            "16",
            "--backoff-base",
            "1",
            "--backoff-cap",
            "1",
        ])
        .args(["--heartbeat-secs", "1"])
        .args(extra)
        .args([
            "--",
            "--offline",
            "--min-free",
            "0",
            "--throttle-retries",
            "0",
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    (st.code().unwrap(), t.elapsed())
}

#[test]
fn a_throttled_worker_exits_3() {
    let d = scratch("scan-throttle-exit");
    let st = Command::new(bin())
        .args(["scan", "run", "--ranges"])
        .arg(plan(&d))
        .args([
            "--workers",
            "1",
            "--worker",
            "0",
            "--offline",
            "--min-free",
            "0",
            "--throttle-retries",
            "0",
            "--http",
            &fake_lake(true),
            "--out",
        ])
        .arg(d.join("w0"))
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(3));
    let p: serde_json::Value =
        serde_json::from_slice(&std::fs::read(d.join("w0/progress.json")).unwrap()).unwrap();
    assert_eq!(p["done"], true);
    assert_eq!(p["ledgers"], 0);
}

#[test]
fn endless_throttling_trips_the_stall_watchdog_and_slows_every_worker() {
    let d = scratch("scan-supervise-stall");
    let (code, took) = supervise(&d, &fake_lake(true), &["--stall-minutes", "0.1"]);
    assert_eq!(code, 2, "stall exit");
    assert!(took < Duration::from_secs(60), "{took:?}");
    let limit = std::fs::read_to_string(d.join("run/gets_limit")).unwrap();
    assert_eq!(limit.trim(), "4", "the live cap fell to its floor");
    let beat: serde_json::Value =
        serde_json::from_slice(&std::fs::read(d.join("run/heartbeat.json")).unwrap()).unwrap();
    assert!(beat["throttles"].as_u64().unwrap() >= 2);
    assert_eq!(beat["ledgers_done"], 0);
}

#[test]
fn the_wall_clock_limit_exits_4() {
    let d = scratch("scan-supervise-wall");
    let (code, took) = supervise(
        &d,
        &fake_lake(false),
        &["--wall-hours", "0.0015", "--stall-minutes", "10"],
    );
    assert_eq!(code, 4);
    assert!(took < Duration::from_secs(30), "{took:?}");
}

#[test]
fn a_worker_over_its_crash_budget_exits_5() {
    let d = scratch("scan-supervise-crash");
    let (code, _) = supervise(
        &d,
        &fake_lake(true),
        &["--bin", "/bin/false", "--max-crashes", "1"],
    );
    assert_eq!(code, 5);
}

fn refusals(run: &Path) -> String {
    let o = Command::new(bin())
        .args(["scan", "refusals", "--run"])
        .arg(run)
        .output()
        .unwrap();
    String::from_utf8(o.stdout).unwrap()
}

#[test]
fn a_panic_on_one_ledger_is_recorded_and_the_share_goes_on() {
    let d = scratch("scan-poison-ledger");
    std::fs::write(d.join("q.txt"), "5\n").unwrap();
    let st = Command::new(bin())
        .args(["scan", "run", "--ranges"])
        .arg(plan(&d))
        .args([
            "--workers",
            "1",
            "--worker",
            "0",
            "--offline",
            "--min-free",
            "0",
            "--http",
            &fake_lake_status(404),
            "--out",
        ])
        .arg(d.join("w0"))
        .arg("--quarantine")
        .arg(d.join("q.txt"))
        .env("XDRCHECK_SCAN_PANIC_SEQ", "3")
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(0));
    let r = refusals(&d.join("w0"));
    let stage = |seq: &str| {
        r.lines()
            .find(|l| l.starts_with(&format!("{seq}\t")))
            .map(|l| l.split('\t').nth(1).unwrap().to_string())
    };
    assert_eq!(stage("3").as_deref(), Some("panic"), "{r}");
    assert_eq!(stage("5").as_deref(), Some("quarantine"), "{r}");
    assert_eq!(stage("4").as_deref(), Some("fetch"), "{r}");
    assert_eq!(r.lines().count(), 7, "{r}");
}

#[test]
fn a_failing_worker_is_given_up_while_the_others_finish() {
    let d = scratch("scan-supervise-give-up");
    let script = d.join("flaky.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ncase \"$*\" in *\"--worker 1 \"*) exit 1;; esac\nexec {} \"$@\"\n",
            bin()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let lake = fake_lake_status(404);
    let (code, _) = supervise(
        &d,
        &lake,
        &["--bin", script.to_str().unwrap(), "--max-crashes", "1"],
    );
    assert_eq!(code, 5);
    let p: serde_json::Value =
        serde_json::from_slice(&std::fs::read(d.join("run/w0/progress.json")).unwrap()).unwrap();
    assert_eq!(p["done"], true);
    assert!(
        p["ledgers"].as_u64().unwrap() > 0,
        "worker 0 finished its share"
    );
}

#[test]
fn the_start_cap_can_sit_below_the_thread_cap() {
    let d = scratch("scan-supervise-start-gets");
    let (code, _) = supervise(
        &d,
        &fake_lake(false),
        &[
            "--wall-hours",
            "0.0006",
            "--stall-minutes",
            "10",
            "--start-gets",
            "8",
        ],
    );
    assert_eq!(code, 4);
    assert_eq!(
        std::fs::read_to_string(d.join("run/gets_limit"))
            .unwrap()
            .trim(),
        "8"
    );
}

#[test]
fn skipped_units_are_left_alone_and_a_started_one_is_refused() {
    let d = scratch("scan-skip-units");
    let lake = fake_lake_status(404);
    let run = |extra: &[&str]| {
        Command::new(bin())
            .args(["scan", "run", "--ranges"])
            .arg(plan(&d))
            .args([
                "--workers",
                "1",
                "--worker",
                "0",
                "--offline",
                "--min-free",
                "0",
                "--http",
                &lake,
                "--out",
            ])
            .arg(d.join("w0"))
            .args(extra)
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .code()
    };
    std::fs::write(d.join("skip.txt"), "w0/FFFFFFFF--0-63999~1-2\n").unwrap();
    let skip = d.join("skip.txt");
    assert_eq!(run(&["--skip-units", skip.to_str().unwrap()]), Some(0));
    assert!(d.join("w0/FFFFFFFF--0-63999~3-6/MANIFEST.json").exists());
    assert!(!d.join("w0/FFFFFFFF--0-63999~1-2").exists());
    let verify = |extra: &[&str]| {
        Command::new(bin())
            .args(["scan", "verify", "--ranges"])
            .arg(d.join("ranges.tsv"))
            .arg("--run")
            .arg(d.join("w0"))
            .args(extra)
            .status()
            .unwrap()
            .code()
    };
    assert_eq!(verify(&["--skip-units", skip.to_str().unwrap()]), Some(0));
    assert_ne!(
        verify(&[]),
        Some(0),
        "without the list the left unit is missing"
    );
    // A unit this worker has started may not be skipped.
    std::fs::write(d.join("skip2.txt"), "FFFFFFFF--0-63999~3-6\n").unwrap();
    assert_eq!(
        run(&["--skip-units", d.join("skip2.txt").to_str().unwrap()]),
        Some(2)
    );
}

#[test]
fn a_503_is_retried_for_that_request_and_the_worker_goes_on() {
    let d = scratch("scan-503-retry");
    let st = Command::new(bin())
        .args(["scan", "run", "--ranges"])
        .arg(plan(&d))
        .args([
            "--workers",
            "1",
            "--worker",
            "0",
            "--offline",
            "--min-free",
            "0",
            "--http",
            &fake_lake_status(1503),
            "--out",
        ])
        .arg(d.join("w0"))
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(0));
    let p: serde_json::Value =
        serde_json::from_slice(&std::fs::read(d.join("w0/progress.json")).unwrap()).unwrap();
    assert_eq!(p["ledgers"], 6);
    assert!(p["http_throttled"].as_u64().unwrap() >= 1, "{p}");
    assert_eq!(p["http_throttled"], p["throttle_retries"]);
}
