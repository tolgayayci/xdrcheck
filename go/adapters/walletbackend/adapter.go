// Package walletbackend is the reference adapter for stellar/wallet-backend: the replay protocol
// `xcc.adapter/1` over stdio (corpus/schema/adapter-protocol.schema.json), driving unmodified wallet-backend built from source at
// the commit under test, as a black box.
//
// Per session it gives the indexer a fresh database cloned from a per-commit template, seeds its ingest cursor
// to the range start minus one, runs its live ingestion against the harness's ledger server (the SEP-54 layout
// behind an S3 endpoint, or the mock RPC), polls the cursor, stops the process with SIGTERM once the cursor is
// at or past the range end, and reads the rows back with SQL. It patches nothing and links nothing of
// wallet-backend. The executed reproductions this follows are in evidence/wallet-backend-replay and
// evidence/wallet-backend-731.
//
// wallet-backend has no deliberate gate on protocol or meta versions: a ledger its SDK cannot decode looks
// exactly like a ledger that trips a bug (exit, cursor behind, no rows). So the adapter never reports
// `refused`; it declares an `sdk_limit` envelope computed from the commit's go.mod instead (the highest protocol
// the pinned go-stellar-sdk decodes), and the harness does not run ledgers outside it.
//
// One binary has two jobs: `wallet-backend-adapter [flags]` is the adapter; `wallet-backend-adapter fetch`
// is the one networked step (clone the repository, build the pinned commits, check the database image).
package walletbackend

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
	"strings"
	"time"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
	"github.com/tolgayayci/xdrcheck/go/internal/pins"
	"github.com/tolgayayci/xdrcheck/go/internal/userdir"
)

// Version is the adapter's version.
const Version = "0.1.0"

// TargetName is the target the corpus's known divergences name.
const TargetName = "stellar/wallet-backend"

// Inputs and units the adapter declares. wallet-backend's datastore source is hard-coded to S3, and it has no
// filesystem or captive-core source.
var (
	Inputs = []string{"sep54-s3", "rpc"}
	Units  = []string{"single", "chain"}
)

// StateChangeKinds are the neutral kinds the row mapping produces.
var StateChangeKinds = []string{
	"signer_added", "signer_removed", "signer_changed", "trustline_created", "trustline_removed",
	"trustline_flags_changed", "balance_changed", "account_created", "account_removed", "thresholds_changed",
	"contract_deployed",
}

// config is the adapter's configuration.
type config struct {
	pins       *pins.Pins
	cacheDir   string // <cachedir>/wallet-backend
	namePrefix string // docker names and labels
}

// Main runs the adapter, or `fetch`. It returns the exit code.
func Main(args []string) int {
	if len(args) > 0 && args[0] == "fetch" {
		return fetchMain(args[1:])
	}
	fs := flag.NewFlagSet("wallet-backend-adapter", flag.ContinueOnError)
	pinsPath := fs.String("pins", "", "pins.toml (default: found upwards from the working directory and the executable)")
	cache := fs.String("cachedir", "", "cache root (default: prepare's cachedir, else <user cache>/xdrcheck/adapters)")
	prefix := fs.String("name-prefix", envOr("XDRCHECK_WB_NAME_PREFIX", "xdrcheck-wb"), "prefix of docker container names and labels")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*pinsPath, *cache, *prefix)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wallet-backend-adapter:", err)
		return 2
	}
	s := &server{cfg: cfg, cacheFlag: *cache != "", sessions: map[string]*session{}, out: bufio.NewWriter(os.Stdout), log: os.Stderr}
	code := s.serve(os.Stdin)
	s.shutdown()
	return code
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadConfig(pinsPath, cache, prefix string) (*config, error) {
	if pinsPath == "" {
		pinsPath = findPins()
		if pinsPath == "" {
			return nil, errors.New("pins.toml not found; pass --pins")
		}
	}
	p, err := pins.Load(pinsPath)
	if err != nil {
		return nil, err
	}
	if cache == "" {
		base, err := userdir.UserCache()
		if err != nil {
			return nil, err
		}
		cache = filepath.Join(base, "adapters")
	}
	return &config{pins: p, cacheDir: filepath.Join(cache, "wallet-backend"), namePrefix: prefix}, nil
}

// findPins looks for pins.toml in the working directory, the executable's directory and their parents.
func findPins() string {
	var starts []string
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	if exe, err := os.Executable(); err == nil {
		starts = append(starts, filepath.Dir(exe))
	}
	for _, d := range starts {
		for {
			p := filepath.Join(d, "pins.toml")
			if _, err := os.Stat(p); err == nil {
				return p
			}
			parent := filepath.Dir(d)
			if parent == d {
				break
			}
			d = parent
		}
	}
	return ""
}

func (c *config) repo(online bool) *repo {
	return &repo{dir: c.cacheDir, toolchain: c.pins.Pipelines.WalletBackend.GoToolchain, online: online}
}

// ---- the protocol server ----

type session struct {
	id      string
	commit  string
	workdir string
	db      string
	bin     *buildResult
	network adapterkit.Network
	ports   *adapterkit.PortRange
	cols    *schemaCols
}

type server struct {
	cfg       *config
	cacheFlag bool // --cachedir given: prepare's cachedir does not override it
	sessions  map[string]*session
	out       *bufio.Writer
	log       io.Writer
	quit      bool

	db     *dbServer
	dbErr  error
	repo   *repo
	target string // full commit described
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

func (s *server) logf(format string, a ...any) {
	fmt.Fprintf(s.log, "wallet-backend-adapter: "+format+"\n", a...)
}

// serve answers one request per line until stdin closes.
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
	return 0
}

// shutdown stops every session's leftovers and the database server.
func (s *server) shutdown() {
	for id := range s.sessions {
		s.teardown(adapterkit.TeardownParams{Session: id})
	}
	if s.db != nil {
		if err := s.db.Close(); err != nil {
			s.logf("removing the database container: %v", err)
		}
		s.db = nil
	}
}

func (s *server) handle(line []byte) {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		s.logf("unreadable request: %v", err)
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
		s.logf("%s %d: %s", req.Method, req.ID, pe.Error())
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
		return s.describe(ctx, p)
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
		return s.observe(ctx, p)
	case adapterkit.MethodTeardown:
		var p adapterkit.TeardownParams
		if err := params(req.Params, &p); err != nil {
			return nil, err
		}
		return s.teardown(p)
	}
	return nil, fail("unknown_method", "unknown method %q", req.Method)
}

// useCache switches to prepare's cache directory unless --cachedir was given.
func (s *server) useCache(cachedir string) {
	if s.cacheFlag || cachedir == "" {
		return
	}
	dir := filepath.Join(cachedir, "wallet-backend")
	if dir != s.cfg.cacheDir {
		s.cfg.cacheDir = dir
		s.repo = nil
	}
}

func (s *server) getRepo() (*repo, error) {
	if s.repo == nil {
		r := s.cfg.repo(false)
		if !r.present() {
			return nil, fail("environment", "no wallet-backend clone at %s; run `wallet-backend-adapter fetch` first (the only networked step)", r.gitDir())
		}
		s.repo = r
	}
	return s.repo, nil
}

// envelopeFor computes the declared envelope of a commit from its go.mod: the highest protocol its pinned
// go-stellar-sdk decodes. Releases from v0.8.0 decode the newest protocol the kit supports; older ones were
// generated from Protocol 28 XDR (Protocol 29 changed no XDR), the value pins.toml records.
func (s *server) envelopeFor(ctx context.Context, commit string) (adapterkit.Envelope, error) {
	r, err := s.getRepo()
	if err != nil {
		return adapterkit.Envelope{}, err
	}
	gomod, err := r.file(ctx, commit, "go.mod")
	if err != nil {
		return adapterkit.Envelope{}, fail("environment", "reading go.mod at %s: %v", commit, err)
	}
	mod, ver := sdkVersion(gomod)
	maxP := s.cfg.pins.Pipelines.WalletBackend.MaxDecodableProtocolBeforeA9bac8d2
	if mod == "github.com/stellar/go-stellar-sdk" && semverAtLeast(ver, 0, 8, 0) {
		maxP = s.cfg.pins.Protocol.MaxSupported
	}
	minTx := 10
	basis := fmt.Sprintf("go.mod at %s requires %s %s, which decodes up to Protocol %d; wallet-backend has no protocol or meta-version gate of its own", commit[:12], mod, ver, maxP)
	if mod == "" {
		basis = fmt.Sprintf("go.mod at %s names no Stellar Go SDK; assumed to decode up to Protocol %d", commit[:12], maxP)
	}
	return adapterkit.Envelope{Enforcement: "sdk_limit", MaxProtocol: &maxP, MinProtocolWithTransactions: &minTx,
		LedgerCloseMetaVersions: []int{0, 1, 2}, Basis: basis}, nil
}

func (s *server) describe(ctx context.Context, p adapterkit.DescribeParams) (any, error) {
	r, err := s.getRepo()
	if err != nil {
		return nil, err
	}
	name := p.TargetVersion
	if name == "" || name == "unknown" {
		name = s.cfg.pins.Pipelines.WalletBackend.Current
	}
	commit, err := r.resolve(ctx, name)
	if err != nil {
		return nil, fail("unsupported_target_version", "%v", err)
	}
	env, err := s.envelopeFor(ctx, commit)
	if err != nil {
		return nil, err
	}
	s.target = commit
	parallel := 4
	ingestMS, prepMS := int64(300), int64(60000)
	obs := adapterkit.Observations{
		Receipts:     adapterkit.Capability{Supported: true, Subkinds: []string{"transactions", "operations"}},
		Transactions: adapterkit.Capability{Supported: true},
		Participants: adapterkit.Capability{Supported: true, Muxed: "base_only"},
		StateChanges: adapterkit.Capability{Supported: true, Subkinds: StateChangeKinds, Modelling: []string{"initial_authorization_separate"}},
		Movements:    adapterkit.Capability{Supported: false, Reason: "the adapter maps state changes only; balance movements are not read from wallet-backend's tables"},
		Addresses:    adapterkit.Capability{Supported: true, AddressEncoding: "version_byte_payload_hex"},
	}
	// The declared scope was read in wallet-backend's own source and documentation at one commit. Another commit
	// declares it only when every file the rules cite is byte-identical there, so a fact is never excused at a
	// commit whose statements nobody read.
	held, err := scopeHolds(ctx, commit, func(c, path string) (string, error) { return r.file(ctx, c, path) })
	if err != nil {
		return nil, err
	}
	if held {
		obs.Participants = withScope(obs.Participants, ParticipantScope)
		obs.Addresses = withScope(obs.Addresses, AddressScope)
		obs.StateChanges = withScope(obs.StateChanges, StateChangeScope)
	}
	return adapterkit.DescribeResult{
		Adapter:         adapterkit.NameVersion{Name: "wallet-backend", Version: Version},
		Target:          adapterkit.Target{Name: TargetName, Version: commit, VersionKind: "commit"},
		ProtocolVersion: adapterkit.Protocol,
		Inputs:          Inputs,
		Units:           Units,
		Envelope:        env,
		Observations:    obs,
		Concurrency:     &adapterkit.Concurrency{MaxParallelSessions: &parallel},
		Requirements: &adapterkit.Requirements{Network: "none", Services: []string{s.cfg.pins.Images["timescaledb"]},
			Tools: []string{"go (toolchain go" + s.cfg.pins.Pipelines.WalletBackend.GoToolchain + " in the module cache)", "git", "docker"}},
		Timing: &adapterkit.Timing{PrepareColdMS: &prepMS, IngestPerLedgerMS: &ingestMS,
			// The slowest failure seen inside the envelope: the five-attempt persist retry ladder (15.4 s) on
			// either input, plus headroom. A ledger the SDK cannot decode takes 151 s of retries on the RPC
			// input, but such ledgers are outside the declared envelope and are not run.
			SlowestFailureMS: map[string]int64{"sep54-s3": 20000, "rpc": 20000}},
	}, nil
}

// database returns the server, starting it on first use.
func (s *server) database(ctx context.Context, limits *adapterkit.Limits) (*dbServer, error) {
	if s.db != nil {
		return s.db, nil
	}
	if s.dbErr != nil {
		return nil, s.dbErr
	}
	o := dbOptions{Image: s.cfg.pins.Images["timescaledb"], NamePrefix: s.cfg.namePrefix, RunDir: shortRunDir(s.cfg.cacheDir)}
	if limits != nil {
		if limits.MemoryMaxBytes != nil {
			o.MemoryMax = *limits.MemoryMaxBytes
		}
		if limits.PidsMax != nil {
			o.PidsMax = *limits.PidsMax
		}
	}
	start := time.Now()
	db, err := startDB(ctx, o)
	if err != nil {
		s.dbErr = fail("environment", "starting the database: %v", err)
		return nil, s.dbErr
	}
	s.logf("database ready in %s (%s)", time.Since(start).Round(time.Millisecond), db.Container)
	s.db = db
	return db, nil
}

// template returns the migrated template database of a commit, making it on first use.
func (s *server) template(ctx context.Context, db *dbServer, commit, bin string) (string, []string, error) {
	if t, ok := db.templates[commit]; ok {
		return t, nil, nil
	}
	name := "tmpl_" + commit[:12]
	start := time.Now()
	if err := db.Drop(ctx, name); err != nil {
		return "", nil, err
	}
	if err := db.Exec(ctx, "postgres", "CREATE DATABASE "+quoteIdent(name)); err != nil {
		return "", nil, err
	}
	out, err := runMigrate(ctx, bin, db.URL(name))
	if err != nil {
		return "", nil, fmt.Errorf("migrate up at %s: %v: %s", commit[:12], err, lastLines(out, 10))
	}
	if err := db.MakeTemplate(ctx, name); err != nil {
		return "", nil, err
	}
	db.templates[commit] = name
	return name, []string{fmt.Sprintf("template %s migrated in %s", name, time.Since(start).Round(time.Millisecond))}, nil
}

func (s *server) prepare(ctx context.Context, p adapterkit.PrepareParams) (any, error) {
	if p.Session == "" || p.Workdir == "" {
		return nil, fail("invalid_params", "session and workdir are required")
	}
	if _, dup := s.sessions[p.Session]; dup {
		return nil, fail("invalid_params", "session %q is already prepared", p.Session)
	}
	s.useCache(p.Cachedir)
	r, err := s.getRepo()
	if err != nil {
		return nil, err
	}
	commit, err := r.resolve(ctx, p.TargetVersion)
	if err != nil {
		return nil, fail("unsupported_target_version", "%v", err)
	}
	res := adapterkit.PrepareResult{Ready: true, TargetVersion: commit, State: "clean"}
	for _, rng := range p.ResolveRanges {
		in, err := r.contains(ctx, rng, commit)
		if err != nil {
			return nil, fail("prepare_failed", "resolving %s: %v", rng, err)
		}
		res.Ranges = append(res.Ranges, adapterkit.RangeAnswer{Range: rng, Contains: in})
	}

	b, err := r.build(ctx, commit, s.log)
	if err != nil {
		return nil, fail("prepare_failed", "%v", err)
	}
	wall := b.Wall.Milliseconds()
	cached := b.Cached
	res.Build = &adapterkit.Build{Cached: &cached, ArtifactSHA256: b.SHA256, WallMS: &wall}

	db, err := s.database(ctx, p.Limits)
	if err != nil {
		return nil, err
	}
	res.Notes = append(res.Notes, db.Notes...)
	tmpl, notes, err := s.template(ctx, db, commit, b.Path)
	if err != nil {
		return nil, fail("prepare_failed", "%v", err)
	}
	res.Notes = append(res.Notes, notes...)

	name := sanitizeDBName("run_", p.Session)
	if exists, err := db.Exists(ctx, name); err != nil {
		return nil, fail("environment", "%v", err)
	} else if exists {
		return nil, fail("prepare_failed", "database %s already exists and was not created by this session; refusing to use it", name)
	}
	start := time.Now()
	if err := db.CreateFrom(ctx, name, tmpl); err != nil {
		return nil, fail("prepare_failed", "creating the session database: %v", err)
	}
	res.Notes = append(res.Notes, fmt.Sprintf("database %s cloned from %s in %s", name, tmpl, time.Since(start).Round(time.Millisecond)))
	if err := os.MkdirAll(p.Workdir, 0o755); err != nil {
		db.Drop(ctx, name)
		return nil, fail("prepare_failed", "%v", err)
	}
	s.sessions[p.Session] = &session{id: p.Session, commit: commit, workdir: p.Workdir, db: name, bin: b, network: p.Network, ports: p.PortRange}
	return res, nil
}

func (s *server) session(id string) (*session, error) {
	ss, ok := s.sessions[id]
	if !ok {
		return nil, fail("unknown_session", "session %q was not prepared", id)
	}
	return ss, nil
}

func (s *server) teardown(p adapterkit.TeardownParams) (any, error) {
	ss, err := s.session(p.Session)
	if err != nil {
		return nil, err
	}
	delete(s.sessions, p.Session)
	if p.KeepState != nil && *p.KeepState {
		left := []string{ss.workdir}
		if s.db != nil {
			left = append(left, "database "+ss.db+" in container "+s.db.Container+" (removed when the adapter exits)")
		}
		return adapterkit.TeardownResult{OK: true, LeftBehind: left}, nil
	}
	if s.db != nil {
		if err := s.db.Drop(context.Background(), ss.db); err != nil {
			return nil, fail("internal", "dropping %s: %v", ss.db, err)
		}
	}
	os.RemoveAll(filepath.Join(ss.workdir, "wallet-backend.log"))
	os.Remove(ss.workdir)
	return adapterkit.TeardownResult{OK: true}, nil
}
