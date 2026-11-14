// Package stellaretl is the replay adapter for stellar-etl (github.com/stellar/stellar-etl): the protocol
// `xcc.adapter/1` over stdio around an unmodified stellar-etl binary built at the version under test.
//
// stellar-etl is a batch tool: one command exports a ledger range to JSON Lines files and exits. It reads
// ledgers only from a GCS datastore in the SEP-54 (Galexie) layout; the datastore type is hard-coded at
// v2.8.34. The adapter therefore takes the harness's `sep54-dir` input and serves that directory through a
// GCS-compatible emulator on loopback (gcs.go), which stellar-etl reaches through STORAGE_EMULATOR_HOST
// without credentials. For each session:
//
//   - `prepare` resolves the target (tag or commit) in a clone of stellar-etl, builds the binary once per
//     commit with the Go toolchain its go.mod names (build.go), and answers the commit ranges of known
//     divergences;
//   - `ingest` runs the export commands (exportCommands) over the range, one after the other, each writing to
//     its own folder; the status rests on exit codes and on which ledgers the ledgers export holds, never on
//     log text;
//   - `observe` reads the JSON Lines back and maps them onto the neutral vocabulary (observe.go);
//   - `teardown` removes the session's folder.
package stellaretl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
	"github.com/tolgayayci/xdrcheck/go/internal/proc"
	"github.com/tolgayayci/xdrcheck/go/internal/userdir"
)

// Version is the adapter's version.
const Version = "0.1.0"

// TargetName is the target string the corpus's known divergences use for stellar-etl.
const TargetName = "stellar/stellar-etl"

// Inputs and units the adapter declares. Only one ledger range per command, and no state is carried between
// ledgers, so a single ledger is always enough; a chain is the same command over a longer range.
var (
	Inputs = []string{"sep54-dir"}
	Units  = []string{"single", "chain"}
)

// networks maps a passphrase to stellar-etl's network flag and the datastore suffix it appends.
var networks = map[string]struct{ flag, suffix string }{
	"Public Global Stellar Network ; September 2015": {"", "pubnet"},
	"Test SDF Network ; September 2015":              {"--testnet", "testnet"},
	"Test SDF Future Network ; October 2022":         {"--futurenet", "futurenet"},
}

// Options are the adapter's command-line options.
type Options struct {
	CacheRoot string // the harness's cachedir when prepare names none; the adapter uses <root>/stellar-etl
	Repo      string // an existing stellar-etl clone instead of <cache>/repo.git
	Binary    string // a prebuilt stellar-etl used for every target instead of building one
	Offline   bool   // never clone, fetch or build
	// HaltOracle, when set, is a file the adapter appends one JSON line to per export per ledger of every ingest
	// (haltoracle.go): how that export ended on that ledger.
	HaltOracle string
	// ExportMemoryMax caps each export command's memory (bytes; 0: no cap). A command killed at the cap is a
	// crash.
	ExportMemoryMax int64
}

// Describe is the describe result for a target version; envelope is computed by the caller.
func Describe(target string, env adapterkit.Envelope) adapterkit.DescribeResult {
	kind := "tag"
	if fullCommit.MatchString(target) {
		kind = "commit"
	}
	parallel := 4
	perLedger, prepareCold := int64(20000), int64(300000)
	return adapterkit.DescribeResult{
		Adapter:         adapterkit.NameVersion{Name: "stellar-etl", Version: Version},
		Target:          adapterkit.Target{Name: TargetName, Version: target, VersionKind: kind},
		ProtocolVersion: adapterkit.Protocol,
		Inputs:          Inputs,
		Units:           Units,
		Envelope:        env,
		Observations: adapterkit.Observations{
			Receipts:     adapterkit.Capability{Supported: true, Subkinds: []string{"transactions", "operations", "events"}},
			Transactions: adapterkit.Capability{Supported: true},
			Participants: adapterkit.Capability{Supported: true, Muxed: "base_and_alias"},
			StateChanges: adapterkit.Capability{Supported: true, Subkinds: StateChangeKinds},
			Movements:    adapterkit.Capability{Supported: true, Subkinds: MovementKinds},
			Addresses: adapterkit.Capability{Supported: false,
				Reason: "stellar-etl keeps most addresses inside per-type detail columns; this adapter version reports addresses only as participants, state changes and movements"},
		},
		Concurrency:  &adapterkit.Concurrency{MaxParallelSessions: &parallel},
		Requirements: &adapterkit.Requirements{Network: "none", Tools: []string{"git", "go (the toolchain the target's go.mod names)", "a C compiler (cgo)"}},
		Timing:       &adapterkit.Timing{PrepareColdMS: &prepareCold, IngestPerLedgerMS: &perLedger, SlowestFailureMS: map[string]int64{"sep54-dir": 30000}},
	}
}

// envelopeFor reads the target's go.mod from the clone: the go-stellar-sdk it pins bounds what it can decode.
// Without a clone, or for an SDK the table does not classify, nothing is declared.
func envelopeFor(ctx context.Context, c *cache, target string) adapterkit.Envelope {
	none := func(why string) adapterkit.Envelope { return adapterkit.Envelope{Enforcement: "none", Basis: why} }
	if target == "" || !c.haveRepo() {
		return none("no envelope declared: the target's go.mod is read from a local stellar-etl clone, and there is none yet")
	}
	commit, err := c.git(ctx, "rev-parse", "--verify", "--quiet", target+"^{commit}")
	if err != nil {
		return none("no envelope declared: " + target + " is not in the local clone")
	}
	gomod, err := c.goMod(ctx, commit)
	if err != nil {
		return none("no envelope declared: " + err.Error())
	}
	sdk := sdkVersionOf(gomod)
	maxP := sdkMaxProtocol(sdk)
	if maxP == 0 {
		return none("no envelope declared: go.mod pins go-stellar-sdk " + sdk + ", which the adapter does not classify")
	}
	return adapterkit.Envelope{Enforcement: "sdk_limit", MaxProtocol: &maxP, LedgerCloseMetaVersions: []int{0, 1, 2},
		Basis: fmt.Sprintf("go.mod at %s pins go-stellar-sdk %s; stellar-etl has no protocol gate of its own", commit[:12], sdk)}
}

// Main runs the adapter. It returns the exit code.
func Main(args []string) int {
	fs := flag.NewFlagSet("stellaretl", flag.ContinueOnError)
	var o Options
	fs.StringVar(&o.CacheRoot, "cache-dir", "", "cache root when prepare names none (default: the user cache directory's xdrcheck/adapters)")
	fs.StringVar(&o.Repo, "repo", "", "an existing stellar-etl clone (default: <cache>/stellar-etl/repo.git, cloned on first use)")
	fs.StringVar(&o.Binary, "etl-binary", "", "a prebuilt stellar-etl used for every target (tests and CI); the target is not built")
	fs.BoolVar(&o.Offline, "offline", false, "never clone, fetch or build; use what the cache holds")
	fs.StringVar(&o.HaltOracle, "halt-oracle", "", "append one JSON line per export per ledger of every ingest to this file")
	fs.Int64Var(&o.ExportMemoryMax, "export-memory-max", 0, "memory cap per export command in bytes (0: none); a command killed at the cap is a crash")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if o.CacheRoot == "" {
		if d, err := userdir.UserCache(); err == nil {
			o.CacheRoot = filepath.Join(d, "adapters")
		}
	}
	s := &server{opts: o, sessions: map[string]*session{}, out: bufio.NewWriter(os.Stdout), log: os.Stderr}
	return s.serve(os.Stdin)
}

// ---- the protocol server ----

type session struct {
	workdir string
	out     string // <workdir>/out: one folder per export command
	logs    string // <workdir>/logs: each command's output
	binary  string
	port    int
	network adapterkit.Network
}

type server struct {
	opts     Options
	sessions map[string]*session
	out      *bufio.Writer
	log      io.Writer
	quit     bool
	desc     *adapterkit.DescribeResult
}

type request struct {
	XDRCHECK string          `json:"xcc"`
	ID       int64           `json:"id"`
	Method   string          `json:"method"`
	Params   json.RawMessage `json:"params"`
}

type response struct {
	XDRCHECK string                `json:"xcc"`
	ID       int64                 `json:"id"`
	Method   string                `json:"method"`
	Result   any                   `json:"result,omitempty"`
	Error    *adapterkit.ErrorBody `json:"error,omitempty"`
}

type protoError struct{ code, msg string }

func (e *protoError) Error() string { return e.code + ": " + e.msg }

func fail(code, format string, a ...any) error { return &protoError{code, fmt.Sprintf(format, a...)} }

func (s *server) cacheFor(cachedir string) *cache {
	root := cachedir
	if root == "" {
		root = s.opts.CacheRoot
	}
	c := &cache{dir: filepath.Join(root, "stellar-etl"), binary: s.opts.Binary, offline: s.opts.Offline}
	c.repo = filepath.Join(c.dir, "repo.git")
	if s.opts.Repo != "" {
		c.repo = s.opts.Repo
		if _, err := os.Stat(filepath.Join(c.repo, ".git")); err == nil {
			c.repo = filepath.Join(c.repo, ".git")
		}
	}
	return c
}

// serve answers one request per line until stdin closes, then stops what it started and exits 0.
func (s *server) serve(in io.Reader) int {
	r := bufio.NewReaderSize(in, 1<<20)
	for !s.quit {
		line, err := r.ReadBytes('\n')
		if len(strings.TrimSpace(string(line))) > 0 {
			s.handle(line)
		}
		if err != nil {
			break
		}
	}
	for id, ss := range s.sessions {
		os.RemoveAll(ss.workdir)
		delete(s.sessions, id)
	}
	return 0
}

func (s *server) handle(line []byte) {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		fmt.Fprintln(s.log, "stellaretl: unreadable request:", err)
		return
	}
	res, err := s.dispatch(req)
	resp := response{XDRCHECK: adapterkit.Protocol, ID: req.ID, Method: req.Method}
	if err != nil {
		var pe *protoError
		if !errors.As(err, &pe) {
			pe = &protoError{"internal", err.Error()}
		}
		no := false
		resp.Error = &adapterkit.ErrorBody{Code: pe.code, Message: pe.msg, Retryable: &no}
	} else {
		resp.Result = res
	}
	b, merr := json.Marshal(resp)
	if merr != nil {
		b, _ = json.Marshal(response{XDRCHECK: adapterkit.Protocol, ID: req.ID, Method: req.Method,
			Error: &adapterkit.ErrorBody{Code: "internal", Message: merr.Error()}})
	}
	s.out.Write(b)
	s.out.WriteByte('\n')
	s.out.Flush()
}

func params(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return fail("invalid_params", "params are required")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fail("invalid_params", "%v", err)
	}
	return nil
}

func (s *server) dispatch(req request) (any, error) {
	ctx := context.Background()
	switch req.Method {
	case adapterkit.MethodDescribe:
		var p adapterkit.DescribeParams
		if err := params(req.Params, &p); err != nil {
			return nil, err
		}
		if !slices.Contains(p.ProtocolVersions, adapterkit.Protocol) {
			s.quit = true
			return nil, fail("unsupported_protocol_version", "this adapter speaks %s only", adapterkit.Protocol)
		}
		d := Describe(p.TargetVersion, envelopeFor(ctx, s.cacheFor(""), p.TargetVersion))
		s.desc = &d
		return d, nil
	case adapterkit.MethodPrepare:
		var p adapterkit.PrepareParams
		if err := params(req.Params, &p); err != nil {
			return nil, err
		}
		return s.prepare(ctx, p)
	case adapterkit.MethodIngest:
		var p adapterkit.IngestParams
		if err := params(req.Params, &p); err != nil {
			return nil, err
		}
		return s.ingest(ctx, p)
	case adapterkit.MethodObserve:
		var p adapterkit.ObserveParams
		if err := params(req.Params, &p); err != nil {
			return nil, err
		}
		return s.observe(p)
	case adapterkit.MethodTeardown:
		var p adapterkit.TeardownParams
		if err := params(req.Params, &p); err != nil {
			return nil, err
		}
		return s.teardown(p)
	}
	return nil, fail("unknown_method", "unknown method %q", req.Method)
}

func (s *server) prepare(ctx context.Context, p adapterkit.PrepareParams) (any, error) {
	if p.Session == "" || p.Workdir == "" || p.TargetVersion == "" {
		return nil, fail("invalid_params", "session, workdir and target_version are required")
	}
	if _, dup := s.sessions[p.Session]; dup {
		return nil, fail("invalid_params", "session %q is already prepared", p.Session)
	}
	out := filepath.Join(p.Workdir, "out")
	if entries, err := os.ReadDir(out); err == nil && len(entries) > 0 {
		return nil, fail("prepare_failed", "%s already holds data this session did not create; refusing to use it", out)
	}
	c := s.cacheFor(p.Cachedir)
	commit := p.TargetVersion
	var notes []string
	if c.binary == "" || len(p.ResolveRanges) > 0 || !fullCommit.MatchString(commit) {
		if err := c.ensureRepo(ctx); err != nil {
			return nil, fail("prepare_failed", "%v", err)
		}
		r, err := c.resolve(ctx, p.TargetVersion)
		if err != nil {
			return nil, fail("unsupported_target_version", "%v", err)
		}
		commit = r
		if commit != p.TargetVersion {
			notes = append(notes, p.TargetVersion+" is commit "+commit)
		}
	}
	var answers []adapterkit.RangeAnswer
	for _, rng := range p.ResolveRanges {
		in, err := c.inRange(ctx, rng, commit)
		if err != nil {
			return nil, fail("prepare_failed", "resolve range %s: %v", rng, err)
		}
		answers = append(answers, adapterkit.RangeAnswer{Range: rng, Contains: in})
	}
	b, err := c.build(ctx, commit, s.log)
	if err != nil {
		return nil, fail("prepare_failed", "%v", err)
	}
	notes = append(notes, b.notes...)
	for _, d := range []string{out, filepath.Join(p.Workdir, "logs")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fail("prepare_failed", "%v", err)
		}
	}
	port := 0
	if p.PortRange != nil && p.PortRange.Count > 0 {
		port = p.PortRange.First
	}
	s.sessions[p.Session] = &session{workdir: p.Workdir, out: out, logs: filepath.Join(p.Workdir, "logs"), binary: b.binary, port: port, network: p.Network}
	cached, wall := b.cached, b.wall.Milliseconds()
	return adapterkit.PrepareResult{Ready: true, TargetVersion: p.TargetVersion, Build: &adapterkit.Build{Cached: &cached, ArtifactSHA256: b.sha256, WallMS: &wall},
		State: "clean", Notes: notes, Ranges: answers}, nil
}

func (s *server) session(id string) (*session, error) {
	ss, ok := s.sessions[id]
	if !ok {
		return nil, fail("unknown_session", "session %q was not prepared", id)
	}
	return ss, nil
}

// commandRun is what one export command did.
type commandRun struct {
	name string
	res  proc.Result
}

// ingest serves the layout through the emulator and runs every export over the range.
func (s *server) ingest(ctx context.Context, p adapterkit.IngestParams) (any, error) {
	ss, err := s.session(p.Session)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(Inputs, p.Input.Kind) {
		return nil, fail("unsupported_input", "stellar-etl reads only a GCS datastore; this adapter serves it from input kind sep54-dir, not %s", p.Input.Kind)
	}
	if p.Unit != "" && !slices.Contains(Units, p.Unit) {
		return nil, fail("unsupported_unit", "unit %s is not supported; supported: %s", p.Unit, strings.Join(Units, ", "))
	}
	passphrase := p.Network.Passphrase
	if passphrase == "" {
		passphrase = ss.network.Passphrase
	}
	nw, ok := networks[passphrase]
	if !ok {
		return nil, fail("unsupported_input", "stellar-etl knows only the pubnet, testnet and futurenet passphrases, not %q", passphrase)
	}
	if p.Range.Start <= 0 || p.Range.End < p.Range.Start {
		return nil, fail("invalid_params", "range %d..%d", p.Range.Start, p.Range.End)
	}
	emu, err := startEmulator(p.Input.Path, nw.suffix, listenAddr(ss.port))
	if err != nil {
		return nil, fail("environment", "start the GCS emulator: %v", err)
	}
	defer emu.close()

	start := time.Now()
	deadline := start.Add(time.Duration(p.DeadlineMS) * time.Millisecond)
	deadline = deadline.Add(-min(time.Second, time.Duration(p.DeadlineMS)*time.Millisecond/10))
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + ss.workdir, "STORAGE_EMULATOR_HOST=" + emu.host}
	// runExport runs one export command over from..to, writing its rows under dir and its output to logf.
	runExport := func(cmd string, from, to int64, dir string, logf *os.File, left time.Duration) (proc.Result, error) {
		args := []string{cmd, "-s", strconv.FormatInt(from, 10), "-e", strconv.FormatInt(to, 10),
			"-o", dir + string(filepath.Separator), "--datastore-path", datastoreArg}
		if nw.flag != "" {
			args = append(args, nw.flag)
		}
		return proc.Run(ctx, proc.Spec{Path: ss.binary, Args: args, Env: env, Dir: ss.workdir, Stdout: logf, Stderr: logf,
			Name: "stellar-etl", Limits: proc.Limits{Deadline: left, MemoryMax: s.opts.ExportMemoryMax}, Grace: time.Second, TailBytes: 4 << 10})
	}
	var runs []commandRun
	timedOut := false
	for _, cmd := range exportCommands {
		left := time.Until(deadline)
		if left <= 0 {
			timedOut = true
			break
		}
		dir := filepath.Join(ss.out, cmd)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fail("internal", "%v", err)
		}
		logf, err := os.Create(filepath.Join(ss.logs, cmd+".log"))
		if err != nil {
			return nil, fail("internal", "%v", err)
		}
		res, err := runExport(cmd, p.Range.Start, p.Range.End, dir, logf, left)
		logf.Close()
		if err != nil {
			return nil, fail("environment", "start stellar-etl: %v", err)
		}
		runs = append(runs, commandRun{cmd, res})
		fmt.Fprintf(s.log, "stellaretl: %s %s exit %d in %d ms\n", p.Session, cmd, res.ExitCode, res.Wall.Milliseconds())
		if res.TimedOut {
			timedOut = true
		}
		// A failed export does not stop the others: each one's ending is judged on every ledger.
	}
	served := emu.servedLedgers()
	fmt.Fprintf(s.log, "stellaretl: %s emulator served %d ledger object(s) %v in %d request(s)\n", p.Session, len(served), served, len(emu.requests()))
	ex, err := readExports(ss.out)
	if err != nil {
		return nil, fail("internal", "read the exports: %v", err)
	}
	wall := time.Since(start) // the probe below is the oracle's, not the ingest's
	if s.opts.HaltOracle != "" {
		// The probe reruns a failed export alone on one ledger (rows in a scratch directory, output appended to
		// logs/<export>.probe.log) within what is left of the deadline, so the oracle can name the ledger it fails
		// on even where the export writes no rows.
		probe := func(cmd string, ledger int64) (failed, ran bool) {
			left := time.Until(deadline)
			if left <= 0 {
				return false, false
			}
			dir, err := os.MkdirTemp(ss.workdir, "probe-")
			if err != nil {
				return false, false
			}
			defer os.RemoveAll(dir)
			logf, err := os.OpenFile(filepath.Join(ss.logs, cmd+".probe.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
			if err != nil {
				return false, false
			}
			defer logf.Close()
			fmt.Fprintf(logf, "== probe %s on ledger %d\n", cmd, ledger)
			res, err := runExport(cmd, ledger, ledger, dir, logf, left)
			if err != nil || res.TimedOut {
				return false, false
			}
			return res.ExitCode != 0 || res.Signal != 0, true
		}
		if err := appendHaltOracle(s.opts.HaltOracle, p, filepath.Base(ss.binary), runs, ex, probe); err != nil {
			fmt.Fprintln(s.log, "stellaretl: halt oracle:", err)
		}
	}
	return ingestResult(p, runs, timedOut, wall, ex), nil
}

// ingestResult turns the command runs into the protocol's status and signals. stellar-etl has no cursor; the
// adapter's progress marker is the highest ledger the ledgers export holds once every command has succeeded.
func ingestResult(p adapterkit.IngestParams, runs []commandRun, timedOut bool, wall time.Duration, ex *exports) adapterkit.IngestResult {
	allOK := !timedOut && len(runs) == len(exportCommands)
	var failed *commandRun
	for i := range runs {
		r := &runs[i]
		if r.res.TimedOut || r.res.ExitCode != 0 || r.res.Signal != 0 {
			allOK, failed = false, r
			break
		}
	}
	sig := adapterkit.Signals{ProcessExited: true, WallMS: wall.Milliseconds(), Attempts: adapterkit.Some(int64(1))}
	stopped := timedOut
	sig.StoppedByAdapter = &stopped
	last := ex.lastLedger()
	if allOK && last != nil && *last >= p.Range.End {
		sig.CursorAfter = last
		sig.ExitCode, sig.TermSignal = adapterkit.Some(int64(0)), adapterkit.Null[string]()
		sig.FailingLedger, sig.Phase, sig.RowsForFailingLedger = adapterkit.Null[int64](), adapterkit.Null[string](), adapterkit.Null[int64]()
		sig.RuntimePanic = adapterkit.Some(false)
		if n := len(runs); n > 0 {
			sig.StderrTail = adapterkit.Some(stderrTail(string(runs[n-1].res.Stderr.Data)))
		}
		return adapterkit.IngestResult{Status: adapterkit.StatusCompleted, LastLedger: last, Signals: sig}
	}

	// Stopped before the end. A command that failed or was cut off stopped at the ledger after the last one it
	// wrote rows for; the ledgers before it count as done only if every earlier command finished them too.
	failing := p.Range.Start
	if failed != nil {
		if hi := ex.highestLedgerOf(failed.name, p.Range); hi != nil && *hi+1 <= p.Range.End {
			failing = *hi + 1
		}
	} else if last != nil && *last+1 <= p.Range.End && *last >= p.Range.Start {
		failing = *last + 1
	}
	after := failing - 1
	sig.CursorAfter = &after
	sig.FailingLedger = adapterkit.Some(failing)
	sig.RowsForFailingLedger = adapterkit.Some(ex.rowsForLedger(failing))
	sig.Phase = adapterkit.Null[string]()
	out := adapterkit.IngestResult{LastLedger: &after}
	var res proc.Result
	if failed != nil {
		res = failed.res
	} else if n := len(runs); n > 0 {
		res = runs[n-1].res
	}
	stderr := strings.TrimSpace(string(res.Stderr.Data))
	sig.StderrTail = adapterkit.Some(stderrTail(stderr))
	panicked := res.ExitCode == 2 && strings.Contains(stderr, "panic:") && strings.Contains(stderr, "goroutine ")
	sig.RuntimePanic = adapterkit.Some(panicked)
	if res.Signal != 0 && !res.TimedOut {
		sig.ExitCode, sig.TermSignal = adapterkit.Null[int64](), adapterkit.Some(signalName(res.Signal))
	} else {
		sig.ExitCode, sig.TermSignal = adapterkit.Some(int64(res.ExitCode)), adapterkit.Null[string]()
	}
	switch {
	case timedOut:
		out.Status = adapterkit.StatusTimeout
	case res.Signal != 0 || panicked:
		out.Status = adapterkit.StatusCrashed
	default:
		out.Status = adapterkit.StatusHalted
	}
	out.Signals = sig
	return out
}

// highestLedgerOf is the highest ledger in the range a command's export wrote rows for.
func (e *exports) highestLedgerOf(cmd string, r adapterkit.Range) *int64 {
	var hi *int64
	for _, s := range e.rowLedger[cmd] {
		if s >= r.Start && s <= r.End && (hi == nil || s > *hi) {
			v := s
			hi = &v
		}
	}
	return hi
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

func (s *server) observe(p adapterkit.ObserveParams) (any, error) {
	ss, err := s.session(p.Session)
	if err != nil {
		return nil, err
	}
	ex, err := readExports(ss.out)
	if err != nil {
		return nil, fail("internal", "read the exports: %v", err)
	}
	d := s.desc
	if d == nil {
		x := Describe("", adapterkit.Envelope{Enforcement: "none"})
		d = &x
	}
	return observation(ex, p, *d), nil
}

func (s *server) teardown(p adapterkit.TeardownParams) (any, error) {
	ss, err := s.session(p.Session)
	if err != nil {
		return nil, err
	}
	delete(s.sessions, p.Session)
	if p.KeepState != nil && *p.KeepState {
		return adapterkit.TeardownResult{OK: true, LeftBehind: []string{ss.out, ss.logs}}, nil
	}
	for _, d := range []string{ss.out, ss.logs} {
		if err := os.RemoveAll(d); err != nil {
			return nil, fail("internal", "%v", err)
		}
	}
	os.Remove(ss.workdir) // the session directory too, when nothing else is in it
	return adapterkit.TeardownResult{OK: true}, nil
}

// stderrTail is the end of a stderr capture, short enough for the protocol's 4000-character stderr_tail.
func stderrTail(s string) string {
	s = strings.TrimSpace(s)
	const max = 3000
	if len(s) <= max {
		return s
	}
	cut := len(s) - max
	for cut < len(s) && !utf8.RuneStart(s[cut]) {
		cut++
	}
	return s[cut:]
}
