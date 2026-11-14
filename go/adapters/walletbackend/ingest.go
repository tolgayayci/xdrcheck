package walletbackend

// ingest: seed the cursor, launch live ingestion with every flag explicit, poll the cursor, stop the process,
// and report the facts behind the status.
//
// How the status is chosen (the ingest statuses of corpus/schema/adapter-protocol.schema.json), from machine-observable facts only:
//
//   - completed: the cursor `latest_ingest_ledger` reached the range end (≥: with a contiguous source the
//     indexer can run past the end between two polls). wallet-backend never exits after the last ledger, so
//     the adapter sends SIGTERM; it exits 0.
//   - crashed: the process died of a signal, or of an uncaught runtime fault, with the cursor behind.
//   - halted: the process exited on its own with the cursor behind. This is how every returned error ends,
//     including a retry ladder that gives up.
//   - timeout: still running at the deadline with the cursor behind; the adapter stops it.
//
// Telling a runtime fault from a returned error: before commit db43b388 (2026-10-01) cmd.Execute wraps every
// returned error in panic(…), so every error exits 2 as `panic: executing root command: …` from goroutine 1.
// There a single panic with that prefix is a returned error, and any other panic is a runtime fault. From
// db43b388 on, a returned error exits 1 and a panic keeps exit 2. When the adapter cannot tell it reports
// runtime_panic null and halted. Log text never decides a status; the phase and attempt count read from the
// log are secondary evidence for the report.

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
	"github.com/tolgayayci/xdrcheck/go/internal/proc"
)

// exitCodeChange is the commit from which a returned error exits 1 instead of panicking (exit 2).
const exitCodeChange = "db43b388bc53790c87506e3b0c80e669d1e4f678"

// runMigrate runs `migrate up` against a database.
func runMigrate(ctx context.Context, bin, url string) (string, error) {
	res, err := proc.Run(ctx, proc.Spec{Path: bin, Args: []string{"migrate", "up", "--database-url", url},
		Env: baseEnv(), Name: "wallet-backend-migrate", Limits: proc.Limits{Deadline: 2 * time.Minute}, TailBytes: 8 << 10})
	if err != nil {
		return "", err
	}
	out := string(res.Stdout.Data) + string(res.Stderr.Data)
	if res.ExitCode != 0 || res.TimedOut {
		return out, fmt.Errorf("exit %d", res.ExitCode)
	}
	return out, nil
}

// baseEnv is the scrubbed environment wallet-backend runs with.
func baseEnv() []string {
	return []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "AWS_EC2_METADATA_DISABLED=true"}
}

// ingestArgs builds the ingest command line from the commit's flag table. Every endpoint is explicit: the
// defaults are online (the public data lake, SDF's history archive), and the archive is never contacted when
// the cursor is seeded.
func ingestArgs(flags map[string]bool, in adapterkit.Input, network adapterkit.Network, dbURL string, port int) ([]string, []string, error) {
	args := []string{"ingest"}
	var missing []string
	set := func(name, value string, required bool) {
		if flags[name] {
			args = append(args, "--"+name, value)
		} else if required {
			missing = append(missing, name)
		}
	}
	set("database-url", dbURL, true)
	set("network-passphrase", network.Passphrase, true)
	netName := "testnet"
	if network.Name == "pubnet" {
		netName = "pubnet"
	}
	set("network", netName, false)
	set("stellar-environment", "xdrcheck", false) // the one flag with no default at the older commits
	set("ingestion-mode", "live", true)
	set("archive-url", "http://127.0.0.1:1/", true)
	set("ingest-server-port", strconv.Itoa(port), true)
	set("log-level", "INFO", false)
	set("blend-price-interval", "0", false) // the price snapshot task calls the RPC URL even on the datastore input
	env := baseEnv()
	switch in.Kind {
	case "sep54-s3":
		set("ledger-backend-type", "datastore", true)
		set("rpc-url", "http://127.0.0.1:1", true)
		set("datastore-bucket-path", in.BucketPath, true)
		set("datastore-region", in.Region, true)
		set("datastore-endpoint-url", in.EndpointURL, true)
		set("datastore-buffer-size", "1", false)
		set("datastore-num-workers", "1", false)
		set("datastore-retry-limit", "1", false)
		set("datastore-retry-wait", "1s", false)
		// Dummy static credentials for the local endpoint: without them the AWS client probes the
		// instance-metadata address for 5 s.
		env = append(env, "AWS_ACCESS_KEY_ID="+in.AccessKeyID, "AWS_SECRET_ACCESS_KEY="+in.SecretAccessKey, "AWS_REGION="+in.Region)
	case "rpc":
		set("ledger-backend-type", "rpc", true)
		set("rpc-url", in.URL, true)
		set("get-ledgers-limit", "1", false)
	}
	if len(missing) > 0 {
		return nil, nil, fmt.Errorf("this commit's ingest command lacks the flags %s", strings.Join(missing, ", "))
	}
	return args, env, nil
}

func (s *server) cursor(ctx context.Context, db string) (*int64, error) {
	out, err := s.db.Query(ctx, db, "SELECT value FROM ingest_store WHERE key = 'latest_ingest_ledger'")
	if err != nil {
		return nil, err
	}
	if out == "" {
		return nil, nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("cursor %q: %v", out, err)
	}
	return &n, nil
}

func (s *server) ingest(ctx context.Context, p adapterkit.IngestParams) (any, error) {
	ss, err := s.session(p.Session)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(Inputs, p.Input.Kind) {
		return nil, fail("unsupported_input", "this indexer cannot read input kind %s; supported: %s", p.Input.Kind, strings.Join(Inputs, ", "))
	}
	if p.Unit != "" && !slices.Contains(Units, p.Unit) {
		return nil, fail("unsupported_unit", "unit %s is not supported; supported: %s", p.Unit, strings.Join(Units, ", "))
	}
	if p.Range.Start < 2 || p.Range.End < p.Range.Start {
		return nil, fail("invalid_params", "range %d..%d", p.Range.Start, p.Range.End)
	}
	if s.db == nil {
		return nil, fail("environment", "%v", errNoDatabase)
	}
	network := p.Network
	if network.Passphrase == "" {
		network = ss.network
	}

	// Seed the cursor: live mode then starts at range.start and skips the history-archive bootstrap.
	seed := fmt.Sprintf("DELETE FROM ingest_store WHERE key IN ('latest_ingest_ledger', 'oldest_ingest_ledger');\n"+
		"INSERT INTO ingest_store (key, value) VALUES ('latest_ingest_ledger', '%d'), ('oldest_ingest_ledger', '%d');", p.Range.Start-1, p.Range.Start)
	if err := s.db.Exec(ctx, ss.db, seed); err != nil {
		return nil, fail("environment", "seeding the cursor: %v", err)
	}
	before, err := s.cursor(ctx, ss.db)
	if err != nil {
		return nil, fail("environment", "%v", err)
	}

	port, err := ingestPort(ss.ports)
	if err != nil {
		return nil, fail("environment", "%v", err)
	}
	args, env, err := ingestArgs(ss.bin.Flags, p.Input, network, s.db.URL(ss.db), port)
	if err != nil {
		return nil, fail("unsupported_target_version", "%v", err)
	}
	logFile, err := os.Create(filepath.Join(ss.workdir, "wallet-backend.log"))
	if err != nil {
		return nil, fail("environment", "%v", err)
	}
	defer logFile.Close()
	fmt.Fprintf(logFile, "$ %s %s\n", filepath.Base(ss.bin.Path), strings.Join(args, " "))
	logs := io.MultiWriter(logFile, s.log)

	deadline := time.Duration(p.DeadlineMS) * time.Millisecond
	deadline -= min(2*time.Second, deadline/10) // answer before the harness's own deadline
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	start := time.Now()
	child, err := proc.Start(runCtx, proc.Spec{Path: ss.bin.Path, Args: args, Env: env, Dir: ss.workdir, Name: "wallet-backend",
		Stdout: logs, Stderr: logs, Grace: 5 * time.Second, TailBytes: 16 << 10})
	if err != nil {
		return nil, fail("environment", "starting wallet-backend: %v", err)
	}

	var after *int64
	reached, timedOut := false, false
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
poll:
	for {
		select {
		case <-child.Done():
			break poll
		case <-tick.C:
		}
		c, err := s.cursor(ctx, ss.db)
		if err == nil && c != nil {
			after = c
			if *c >= p.Range.End {
				reached = true
				break poll
			}
		}
		if time.Since(start) >= deadline {
			timedOut = true
			break poll
		}
	}
	stopped := false
	select {
	case <-child.Done():
	default:
		stopped = true
		stop() // SIGTERM, then SIGKILL after the grace period
	}
	res := child.Wait()
	wall := time.Since(start)
	if c, err := s.cursor(ctx, ss.db); err == nil && c != nil {
		after = c
	}
	if after != nil && *after >= p.Range.End {
		reached = true
	}
	ancestor, _ := s.repo.isAncestor(ctx, exitCodeChange, ss.commit)
	out := ingestResult(p, res, before, after, reached, timedOut, stopped, ancestor, wall)
	if out.Status != adapterkit.StatusCompleted {
		failing, _ := out.Signals.FailingLedger.Get()
		rows, err := s.rowsFor(ctx, ss.db, failing)
		if err == nil {
			out.Signals.RowsForFailingLedger = adapterkit.Some(rows)
		}
	}
	return out, nil
}

// rowsFor counts the rows wallet-backend holds for one ledger.
func (s *server) rowsFor(ctx context.Context, db string, seq int64) (int64, error) {
	q := fmt.Sprintf("SELECT (SELECT count(*) FROM transactions WHERE ledger_number = %d) + (SELECT count(*) FROM operations WHERE ledger_number = %d) + (SELECT count(*) FROM state_changes WHERE ledger_number = %d)", seq, seq, seq)
	out, err := s.db.Query(ctx, db, q)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(out), 10, 64)
}

var (
	attemptsRe = regexp.MustCompile(`failed after (\d+) attempts`)
	panicRe    = regexp.MustCompile(`(?m)^panic: `)
	goroutRe   = regexp.MustCompile(`(?m)^goroutine (\d+) \[`)
)

// runtimePanic decides from the process's output and exit whether it ended in an uncaught runtime fault. ok is
// false when it cannot tell.
func runtimePanic(stderr string, exitCode int, afterExitCodeChange bool) (panicked, ok bool) {
	panics := panicRe.FindAllStringIndex(stderr, -1)
	if afterExitCodeChange {
		switch {
		case exitCode == 1:
			return false, true
		case exitCode == 2 && len(panics) > 0:
			return true, true
		case exitCode == 0:
			return false, true
		}
		return false, false
	}
	if exitCode == 0 {
		return false, true
	}
	if exitCode != 2 {
		return false, false
	}
	if len(panics) == 0 {
		return false, false
	}
	if len(panics) == 1 && strings.HasPrefix(stderr[panics[0][0]:], "panic: executing root command:") {
		g := goroutRe.FindStringSubmatch(stderr[panics[0][0]:])
		if g == nil || g[1] == "1" {
			return false, true
		}
		return true, true
	}
	return true, true
}

// phaseOf reads where the indexer stopped from the stable prefixes of its error chain, as secondary evidence.
func phaseOf(text string, ledger int64) string {
	l := strconv.FormatInt(ledger, 10)
	switch {
	case strings.Contains(text, "fetching ledger "+l+":"):
		if strings.Contains(text, "decod") || strings.Contains(text, "unmarshal") {
			return "decode"
		}
		return "fetch"
	case strings.Contains(text, "processing ledger "+l+":"):
		if strings.Contains(text, "ingesting processed data") || strings.Contains(text, "inserting") || strings.Contains(text, "persist") {
			return "persist"
		}
		return "process"
	}
	return ""
}

func ingestResult(p adapterkit.IngestParams, res proc.Result, before, after *int64, reached, timedOut, stopped, afterExitCodeChange bool, wall time.Duration) adapterkit.IngestResult {
	text := string(res.Stdout.Data) + "\n" + string(res.Stderr.Data)
	sig := adapterkit.Signals{CursorBefore: before, CursorAfter: after, ProcessExited: !stopped, WallMS: wall.Milliseconds(),
		StoppedByAdapter: &stopped, StderrTail: adapterkit.Some(tailText(text, 3000))}
	if res.Signal != 0 && !stopped {
		sig.ExitCode, sig.TermSignal = adapterkit.Null[int64](), adapterkit.Some(signalName(res.Signal))
	} else {
		sig.ExitCode, sig.TermSignal = adapterkit.Some(int64(res.ExitCode)), adapterkit.Null[string]()
	}
	out := adapterkit.IngestResult{LastLedger: after, Signals: sig}
	if reached {
		out.Status = adapterkit.StatusCompleted
		sig.FailingLedger, sig.Phase, sig.RowsForFailingLedger, sig.Attempts = adapterkit.Null[int64](), adapterkit.Null[string](), adapterkit.Null[int64](), adapterkit.Null[int64]()
		sig.RuntimePanic = adapterkit.Some(false)
		out.Signals = sig
		return out
	}
	failing := p.Range.Start
	if after != nil && *after+1 > failing {
		failing = *after + 1
	}
	sig.FailingLedger = adapterkit.Some(failing)
	sig.RowsForFailingLedger = adapterkit.Some(int64(0))
	if ph := phaseOf(text, failing); ph != "" {
		sig.Phase = adapterkit.Some(ph)
	} else {
		sig.Phase = adapterkit.Null[string]()
	}
	sig.Attempts = adapterkit.Null[int64]()
	if m := attemptsRe.FindAllStringSubmatch(text, -1); len(m) > 0 {
		n, _ := strconv.ParseInt(m[len(m)-1][1], 10, 64)
		sig.Attempts = adapterkit.Some(n)
	}
	switch {
	case timedOut || (stopped && !reached):
		out.Status = adapterkit.StatusTimeout
		sig.RuntimePanic = adapterkit.Some(false)
	case res.Signal != 0:
		out.Status = adapterkit.StatusCrashed
		sig.RuntimePanic = adapterkit.Some(false)
	default:
		panicked, ok := runtimePanic(string(res.Stderr.Data), res.ExitCode, afterExitCodeChange)
		switch {
		case !ok:
			sig.RuntimePanic = adapterkit.Null[bool]()
			out.Status = adapterkit.StatusHalted
		case panicked:
			sig.RuntimePanic = adapterkit.Some(true)
			out.Status = adapterkit.StatusCrashed
		default:
			sig.RuntimePanic = adapterkit.Some(false)
			out.Status = adapterkit.StatusHalted
		}
	}
	out.Signals = sig
	return out
}

var usageLineRe = regexp.MustCompile(`^(\s*(-\w, )?--[a-z0-9-]+ |Usage:|Flags:|Global Flags:|\s+wallet-backend \S+ \[flags\]|Use ".*--help"|\s*$)`)

// tailText keeps the end of the process output for the report, without the command's usage text (cobra prints
// it before every returned error), so the error line itself survives.
func tailText(s string, n int) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if !usageLineRe.MatchString(l) {
			keep = append(keep, l)
		}
	}
	s = strings.TrimSpace(strings.Join(keep, "\n"))
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}

func signalName(s syscall.Signal) string {
	switch s {
	case syscall.SIGKILL:
		return "SIGKILL"
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGSEGV:
		return "SIGSEGV"
	case syscall.SIGABRT:
		return "SIGABRT"
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGBUS:
		return "SIGBUS"
	}
	return fmt.Sprintf("SIG%d", int(s))
}

// ingestPort picks the port of wallet-backend's ingest server: the first port of the session's range that is
// free right now on every interface (wallet-backend binds ":port"), else any free port. A port reserved by the
// harness can be taken by another process between its check and the launch; a taken port makes wallet-backend
// exit before it reads a ledger, which would be an adapter fault, not an indexer result.
func ingestPort(r *adapterkit.PortRange) (int, error) {
	if r != nil {
		for p := r.First; p < r.First+r.Count; p++ {
			if l, err := net.Listen("tcp", ":"+strconv.Itoa(p)); err == nil {
				l.Close()
				return p, nil
			}
		}
	}
	return freePort()
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
