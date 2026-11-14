// Package baseline is the baseline indexer's adapter: the replay protocol `xcc.adapter/1` over stdio
// (docs/adapter-protocol.md), around the indexer in ./indexer, built on the public package adapterkit. It is the
// full reference adapter; the template to copy is ../minimal (docs/adapter-protocol.md §8). `describe` is a
// constant; `prepare` makes the session's store directory; `ingest` runs the indexer as a child process and
// reads its exit record and cursor — never its log text; `observe` reads the stored ledger documents back;
// `teardown` removes the directory.
//
// One binary does both jobs: `baseline [flags]` is the adapter; `baseline index …` is the indexer the adapter
// starts. The gate flags lower the indexer's declared limits for testing, and describe declares exactly what the
// indexer enforces. `--bug NAME` switches on one seeded bug (./bugs) for the harness's self-test; the target is
// then named `xdrcheck/NAME`.
package baseline

import (
	"bytes"
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
	"time"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
	"github.com/tolgayayci/xdrcheck/go/adapters/baseline/bugs"
	"github.com/tolgayayci/xdrcheck/go/adapters/baseline/indexer"
)

// Version is the adapter's and the indexer's version.
const Version = "0.1.0"

// Inputs and units the baseline declares.
var (
	Inputs = []string{"sep54-dir", "sep54-s3", "rpc"}
	Units  = []string{"single", "chain", "stream"}
)

// StateChangeKinds are the state-change kinds the indexer derives (every kind but entry_evicted, which is a
// ledger-level fact with no transaction).
var StateChangeKinds = []string{
	"account_created", "account_removed", "balance_changed", "trustline_created", "trustline_removed",
	"trustline_flags_changed", "trustline_limit_changed", "signer_added", "signer_removed", "signer_changed",
	"sponsorship_changed", "offer_changed", "liquidity_pool_created", "liquidity_pool_removed",
	"liquidity_pool_changed", "claimable_balance_created", "claimable_balance_claimed", "contract_data_changed",
	"contract_deployed", "entry_restored", "data_entry_changed", "thresholds_changed", "sequence_bumped",
	"account_flags_changed", "home_domain_changed", "inflation_destination_changed", "ttl_extended",
	"contract_code_created",
}

// Describe is the constant describe result for the given gates.
func Describe(g indexer.Gates) adapterkit.DescribeResult {
	maxP, minTx := int(g.MaxProtocol), int(g.MinProtocolWithTransactions)
	var lcm []int
	for v := 0; v <= int(g.MaxLedgerCloseMetaVersion); v++ {
		lcm = append(lcm, v)
	}
	parallel := 8
	return adapterkit.DescribeResult{
		Adapter:         adapterkit.NameVersion{Name: "baseline", Version: Version},
		Target:          adapterkit.Target{Name: "xdrcheck baseline indexer", Version: Version, VersionKind: "tag"},
		ProtocolVersion: adapterkit.Protocol,
		Inputs:          Inputs,
		Units:           Units,
		Envelope: adapterkit.Envelope{Enforcement: "indexer_gate", MaxProtocol: &maxP, MinProtocolWithTransactions: &minTx,
			LedgerCloseMetaVersions: lcm,
			Basis:                   "the baseline indexer's own gates (adapters/baseline/indexer, Gates), checked before anything is written for a ledger"},
		Observations: adapterkit.Observations{
			Receipts:     adapterkit.Capability{Supported: true, Subkinds: []string{"transactions", "operations", "events", "entry_changes"}},
			Transactions: adapterkit.Capability{Supported: true},
			Participants: adapterkit.Capability{Supported: true, Muxed: "base_and_alias"},
			StateChanges: adapterkit.Capability{Supported: true, Subkinds: StateChangeKinds},
			Movements:    adapterkit.Capability{Supported: true, Subkinds: []string{"transfer", "mint", "burn", "clawback", "fee", "fee_refund"}},
			Addresses:    adapterkit.Capability{Supported: true, AddressEncoding: "strkey_text"},
		},
		Concurrency:  &adapterkit.Concurrency{MaxParallelSessions: &parallel},
		Requirements: &adapterkit.Requirements{Network: "none"},
	}
}

// Main runs the adapter, or the indexer when the first argument is "index". It returns the exit code.
func Main(args []string) int {
	if len(args) > 0 && args[0] == "index" {
		return indexMain(args[1:])
	}
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	g := gateFlags(fs)
	bugName := fs.String("bug", "", "switch on one seeded bug for the harness's self-test")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	bug, err := bugs.Lookup(*bugName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "baseline:", err)
		return 2
	}
	if bug != nil && bug.Gates != nil {
		bug.Gates(g)
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "baseline:", err)
		return 2
	}
	return adapterkit.Main(&server{gates: *g, bug: bug, self: self, sessions: map[string]*session{}})
}

func gateFlags(fs *flag.FlagSet) *indexer.Gates {
	g := indexer.DefaultGates
	fs.Func("max-protocol", "highest protocol the indexer accepts (default 30)", func(v string) error {
		n, err := strconv.ParseUint(v, 10, 32)
		g.MaxProtocol = uint32(n)
		return err
	})
	fs.Func("max-lcm-version", "highest LedgerCloseMeta version (default 2)", func(v string) error {
		n, err := strconv.ParseInt(v, 10, 32)
		g.MaxLedgerCloseMetaVersion = int32(n)
		return err
	})
	fs.Func("min-protocol-with-transactions", "lowest protocol whose ledgers may carry transactions (default 10)", func(v string) error {
		n, err := strconv.ParseUint(v, 10, 32)
		g.MinProtocolWithTransactions = uint32(n)
		return err
	})
	return &g
}

// indexMain is `baseline index`: one ingest run of the indexer.
func indexMain(args []string) int {
	fs := flag.NewFlagSet("baseline index", flag.ContinueOnError)
	var cfg indexer.Config
	g := gateFlags(fs)
	fs.StringVar(&cfg.Input.Kind, "input", "", "sep54-dir, sep54-s3 or rpc")
	fs.StringVar(&cfg.Input.Path, "path", "", "sep54-dir: the layout directory")
	fs.StringVar(&cfg.Input.Endpoint, "endpoint", "", "sep54-s3: endpoint URL")
	fs.StringVar(&cfg.Input.BucketPath, "bucket-path", "", "sep54-s3: bucket/prefix")
	fs.StringVar(&cfg.Input.Region, "region", "", "sep54-s3: region")
	fs.StringVar(&cfg.Input.URL, "url", "", "rpc: endpoint URL")
	start := fs.Uint("start", 0, "first ledger")
	end := fs.Uint("end", 0, "last ledger")
	fs.StringVar(&cfg.Passphrase, "passphrase", "", "network passphrase")
	fs.StringVar(&cfg.Out, "out", "", "store directory")
	bugName := fs.String("bug", "", "the seeded bug the adapter switched on")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	bug, err := bugs.Lookup(*bugName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "baseline index:", err)
		return 2
	}
	if bug != nil && bug.Seed != nil {
		cfg.Seed = bug.Seed()
	}
	cfg.Start, cfg.End, cfg.Gates = uint32(*start), uint32(*end), *g
	if cfg.Out == "" || cfg.Passphrase == "" || cfg.Start == 0 || cfg.End < cfg.Start {
		fmt.Fprintln(os.Stderr, "baseline index: --out, --passphrase and --start ≤ --end are required")
		return 2
	}
	return indexer.Run(context.Background(), cfg)
}

// ---- the protocol handler (adapterkit.Serve does the framing and the input and unit checks) ----

type session struct {
	workdir string
	store   string
	network adapterkit.Network
}

type server struct {
	gates    indexer.Gates
	bug      *bugs.Bug // nil for the baseline
	self     string
	sessions map[string]*session
}

// Describe is the constant describe result, with the seeded bug's declarations when one is switched on.
func (s *server) Describe(adapterkit.DescribeParams) (adapterkit.DescribeResult, error) {
	d := Describe(s.gates)
	if s.bug != nil {
		d.Target.Name = "xdrcheck/" + s.bug.Name
		if s.bug.Describe != nil {
			s.bug.Describe(&d)
		}
	}
	return d, nil
}

func (s *server) Prepare(p adapterkit.PrepareParams) (adapterkit.PrepareResult, error) {
	if p.Session == "" || p.Workdir == "" {
		return adapterkit.PrepareResult{}, adapterkit.Errorf(adapterkit.CodeInvalidParams, "session and workdir are required")
	}
	store := filepath.Join(p.Workdir, "store")
	if entries, err := os.ReadDir(store); err == nil && len(entries) > 0 {
		return adapterkit.PrepareResult{}, adapterkit.Errorf(adapterkit.CodePrepareFailed, "%s already holds data this session did not create; refusing to use it", store)
	}
	if err := os.MkdirAll(store, 0o755); err != nil {
		return adapterkit.PrepareResult{}, adapterkit.Errorf(adapterkit.CodePrepareFailed, "%v", err)
	}
	s.sessions[p.Session] = &session{workdir: p.Workdir, store: store, network: p.Network}
	return adapterkit.PrepareResult{Ready: true, TargetVersion: Version, State: "clean"}, nil
}

func (s *server) session(id string) (*session, error) {
	ss, ok := s.sessions[id]
	if !ok {
		return nil, adapterkit.Errorf(adapterkit.CodeUnknownSession, "session %q was not prepared", id)
	}
	return ss, nil
}

// Ingest runs the indexer over the range and reports the facts behind its status.
func (s *server) Ingest(p adapterkit.IngestParams) (adapterkit.IngestResult, error) {
	ss, err := s.session(p.Session)
	if err != nil {
		return adapterkit.IngestResult{}, err
	}
	passphrase := p.Network.Passphrase
	if passphrase == "" {
		passphrase = ss.network.Passphrase
	}
	args := []string{"index", "--input", p.Input.Kind, "--start", strconv.FormatInt(p.Range.Start, 10), "--end", strconv.FormatInt(p.Range.End, 10),
		"--passphrase", passphrase, "--out", ss.store,
		"--max-protocol", strconv.FormatUint(uint64(s.gates.MaxProtocol), 10),
		"--max-lcm-version", strconv.FormatInt(int64(s.gates.MaxLedgerCloseMetaVersion), 10),
		"--min-protocol-with-transactions", strconv.FormatUint(uint64(s.gates.MinProtocolWithTransactions), 10)}
	if s.bug != nil {
		args = append(args, "--bug", s.bug.Name)
	}
	// A scrubbed environment: the XDRCHECK_ variables and PATH, plus the dummy object-store credentials of the request.
	env := []string{"AWS_EC2_METADATA_DISABLED=true"}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "XDRCHECK_") || strings.HasPrefix(kv, "PATH=") {
			env = append(env, kv)
		}
	}
	switch p.Input.Kind {
	case "sep54-dir":
		args = append(args, "--path", p.Input.Path)
	case "sep54-s3":
		args = append(args, "--endpoint", p.Input.EndpointURL, "--bucket-path", p.Input.BucketPath, "--region", p.Input.Region)
		env = append(env, "AWS_ACCESS_KEY_ID="+p.Input.AccessKeyID, "AWS_SECRET_ACCESS_KEY="+p.Input.SecretAccessKey, "AWS_REGION="+p.Input.Region)
	case "rpc":
		args = append(args, "--url", p.Input.URL)
	}

	var before *int64
	if c, ok := indexer.Cursor(ss.store); ok {
		before = adapterkit.Int64(int64(c))
	}
	deadline := time.Duration(p.DeadlineMS) * time.Millisecond
	margin := min(time.Second, deadline/10)
	res, err := adapterkit.RunChild(context.Background(), adapterkit.ChildSpec{Path: s.self, Args: args, Env: env, Dir: ss.store,
		Deadline: deadline - margin})
	if err != nil {
		return adapterkit.IngestResult{}, adapterkit.Errorf(adapterkit.CodeEnvironment, "start the indexer: %v", err)
	}
	return ingestResult(p, res, before, ss.store), nil
}

func ingestResult(p adapterkit.IngestParams, res adapterkit.ChildResult, before *int64, store string) adapterkit.IngestResult {
	var after *int64
	if c, ok := indexer.Cursor(store); ok {
		after = adapterkit.Int64(int64(c))
	}
	reached := after != nil && *after >= p.Range.End
	rec, hasRec := indexer.ReadExit(store)
	stderr := strings.TrimSpace(res.Stderr)
	panicked := res.ExitCode == 2 && (strings.Contains(stderr, "panic:") || strings.Contains(stderr, "goroutine "))

	sig := adapterkit.Signals{
		CursorBefore: before, CursorAfter: after, ProcessExited: true, WallMS: res.Wall.Milliseconds(),
		RuntimePanic: adapterkit.Some(panicked), Attempts: adapterkit.Some(int64(1)), StderrTail: adapterkit.Some(stderr),
	}
	if res.Signal != 0 {
		sig.ExitCode, sig.TermSignal = adapterkit.Null[int64](), adapterkit.Some(res.TermSignal())
	} else {
		sig.ExitCode, sig.TermSignal = adapterkit.Some(int64(res.ExitCode)), adapterkit.Null[string]()
	}
	stopped := res.TimedOut
	sig.StoppedByAdapter = &stopped
	out := adapterkit.IngestResult{LastLedger: after, Signals: sig}

	if reached && res.ExitCode == 0 && !res.TimedOut {
		out.Status = adapterkit.StatusCompleted
		sig.FailingLedger, sig.Phase, sig.RowsForFailingLedger = adapterkit.Null[int64](), adapterkit.Null[string](), adapterkit.Null[int64]()
		out.Signals = sig
		return out
	}
	failing := p.Range.Start
	if after != nil {
		failing = *after + 1
	}
	if hasRec && rec.Ledger != 0 {
		failing = int64(rec.Ledger)
	}
	rows := int64(0)
	if _, err := os.Stat(indexer.DocPath(store, uint32(failing))); err == nil {
		rows = 1
	}
	sig.FailingLedger, sig.RowsForFailingLedger = adapterkit.Some(failing), adapterkit.Some(rows)
	sig.Phase = adapterkit.Null[string]()
	if hasRec {
		sig.Phase = adapterkit.Some(rec.Phase)
	}
	out.Signals = sig
	switch {
	case res.TimedOut:
		out.Status = adapterkit.StatusTimeout
	case res.Signal != 0 || panicked:
		out.Status = adapterkit.StatusCrashed
	case res.ExitCode == indexer.ExitRefused && hasRec && rec.Status == "refused":
		out.Status = adapterkit.StatusRefused
		observed, _ := json.Marshal(rec.Observed)
		out.Refusal = &adapterkit.Refusal{Gate: rec.Gate, Reason: rec.Message, Ledger: int64(rec.Ledger), Observed: observed}
	default:
		out.Status = adapterkit.StatusHalted
	}
	return out
}

// observation is an observe result written as it is read: the stored documents of the range, one ledger at a
// time, so the adapter's memory does not grow with the range (a stream unit of any length).
type observation struct {
	head    adapterkit.Observation // schema, range, kinds and errors; Ledgers stays empty
	store   string
	txs     []string
	written int
}

// ObserveStream checks the session and says what the observation set will hold; the ledgers are read while
// the response is written (observation.WriteResult).
func (s *server) ObserveStream(p adapterkit.ObserveParams) (adapterkit.ResultWriter, error) {
	ss, err := s.session(p.Session)
	if err != nil {
		return nil, err
	}
	d, _ := s.Describe(adapterkit.DescribeParams{})
	o := &observation{head: adapterkit.Observation{Schema: adapterkit.ObservationSchema, Range: p.Range,
		Kinds: adapterkit.ProvidedKinds(d.Observations, p.Kinds)}, store: ss.store, txs: p.TxHashes}
	if rec, ok := indexer.ReadExit(ss.store); ok && rec.Status == "error" && int64(rec.Ledger) >= p.Range.Start && int64(rec.Ledger) <= p.Range.End {
		o.head.Errors = []adapterkit.ObsError{{LedgerSeq: int64(rec.Ledger), Code: rec.Phase, Message: rec.Message}}
	}
	return o, nil
}

// Observe is ObserveStream held in memory; adapterkit.Serve calls ObserveStream.
func (s *server) Observe(p adapterkit.ObserveParams) (adapterkit.Observation, error) {
	rw, err := s.ObserveStream(p)
	if err != nil {
		return adapterkit.Observation{}, err
	}
	var buf bytes.Buffer
	if err := rw.WriteResult(&buf); err != nil {
		return adapterkit.Observation{}, err
	}
	var o adapterkit.Observation
	err = json.Unmarshal(buf.Bytes(), &o)
	return o, err
}

// WriteResult writes the observation set as JSON: the fixed members, then the ledgers one by one as each
// document is read back.
func (o *observation) WriteResult(w io.Writer) error {
	for _, part := range []struct {
		name string
		v    any
	}{{`{"schema":`, o.head.Schema}, {`,"range":`, o.head.Range}, {`,"kinds":`, o.head.Kinds}} {
		b, err := json.Marshal(part.v)
		if err != nil {
			return err
		}
		io.WriteString(w, part.name)
		w.Write(b)
	}
	io.WriteString(w, `,"ledgers":[`)
	r := o.head.Range
	for seq := r.Start; seq <= r.End; seq++ {
		l, ok, err := o.ledger(uint32(seq))
		if err != nil {
			return err
		}
		if ok { // a ledger missing from `ledgers` was not seen
			b, err := json.Marshal(l)
			if err != nil {
				return err
			}
			if o.written > 0 {
				io.WriteString(w, ",")
			}
			w.Write(b)
			o.written++
		}
		if seq == r.End {
			break
		}
	}
	io.WriteString(w, "]")
	if len(o.head.Errors) > 0 {
		b, err := json.Marshal(o.head.Errors)
		if err != nil {
			return err
		}
		io.WriteString(w, `,"errors":`)
		w.Write(b)
	}
	_, err := io.WriteString(w, "}")
	return err
}

// ledger reads one stored ledger document back as an observed ledger; false when the indexer stored none.
func (o *observation) ledger(seq uint32) (adapterkit.Ledger, bool, error) {
	raw, err := os.ReadFile(indexer.DocPath(o.store, seq))
	if errors.Is(err, os.ErrNotExist) {
		return adapterkit.Ledger{}, false, nil
	}
	if err != nil {
		return adapterkit.Ledger{}, false, err
	}
	var doc indexer.Doc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return adapterkit.Ledger{}, false, fmt.Errorf("ledger %d document: %v", seq, err)
	}
	k := o.head.Kinds
	keep := func(loc adapterkit.Locator) bool { return len(o.txs) == 0 || slices.Contains(o.txs, loc.TxHash) }
	l := doc.Facts
	out := adapterkit.Ledger{LedgerSeq: l.LedgerSeq, LedgerHash: l.LedgerHash}
	if k.Provided(adapterkit.KindReceipts) {
		out.Receipt = l.Receipt
	}
	if k.Provided(adapterkit.KindTransactions) {
		out.Transactions = l.Transactions
	}
	if k.Provided(adapterkit.KindParticipants) {
		out.Participants = filter(l.Participants, func(x adapterkit.ObsParticipant) bool { return keep(x.Locator) })
	}
	if k.Provided(adapterkit.KindStateChanges) {
		out.StateChanges = filter(l.StateChanges, func(x adapterkit.ObsStateChange) bool { return keep(x.Locator) })
	}
	if k.Provided(adapterkit.KindMovements) {
		out.Movements = filter(l.Movements, func(x adapterkit.ObsMovement) bool { return keep(x.Locator) })
	}
	if k.Provided(adapterkit.KindAddresses) {
		out.Addresses = filter(l.Addresses, func(x adapterkit.ObsAddress) bool { return keep(x.Locator) })
	}
	adapterkit.SortFacts(&out)
	return out, true, nil
}

func filter[T any](xs []T, keep func(T) bool) []T {
	var out []T
	for _, x := range xs {
		if keep(x) {
			out = append(out, x)
		}
	}
	return out
}

func (s *server) Teardown(p adapterkit.TeardownParams) (adapterkit.TeardownResult, error) {
	ss, err := s.session(p.Session)
	if err != nil {
		return adapterkit.TeardownResult{}, err
	}
	delete(s.sessions, p.Session)
	if p.KeepState != nil && *p.KeepState {
		return adapterkit.TeardownResult{OK: true, LeftBehind: []string{ss.store}}, nil
	}
	if err := os.RemoveAll(ss.store); err != nil {
		return adapterkit.TeardownResult{}, adapterkit.Errorf(adapterkit.CodeInternal, "%v", err)
	}
	os.Remove(ss.workdir) // the session directory too, when nothing else is in it
	return adapterkit.TeardownResult{OK: true}, nil
}
