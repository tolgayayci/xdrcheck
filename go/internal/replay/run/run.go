// Package run is the replay harness's runner (replay-harness.md §5): it starts the adapter, reads its describe
// declarations, plans the corpus with them (internal/replay/plan), and then for every unit serves the unit's
// ledgers, drives one adapter session — prepare → ingest → observe (always, whatever ingest returned) →
// teardown — matches every scored entry's variant (internal/match), classifies it (internal/classify), judges
// it against the manifest's known divergences, and streams one xcc.report/v1 row per entry variant.
//
// Isolation is per unit: a fresh session, a fresh ledger view (its own SEP-54 directory, its own mock RPC
// server or its own prefix in the shared object store) and its own delivery evidence. Each worker has its own
// adapter process; an adapter that breaks the protocol, does not answer or dies is killed and a fresh one is
// started for the next unit.
//
// Memory is bounded independently of a unit's length (`make verify-memory` checks it): after ingest a unit is
// observed in windows of consecutive ledgers (ObserveWindowBytes of served ledger bytes each), and
// each window's entries are matched, classified and written before the next window is asked for, so the
// harness holds one window's observation set at a time. An adapter response line is capped at
// DefaultMaxResponseBytes. When the adapter's group loses a process to its memory cap during ingest (the
// kernel's out-of-memory kill of the indexer the adapter started) and ingest is reported crashed, the crash is
// noted as a memory crash.
//
// Inputs: sep54-dir (a layout on disk; reads are not observed), rpc (the mock getLedgers; its request log is
// the delivery evidence) and sep54-s3 (SeaweedFS by the pinned digest behind the logging proxy, whose request
// log is the delivery evidence). sep54-gcs is not built. Without --input the first of sep54-s3, sep54-dir, rpc
// that the adapter declares is used; sep54-s3 only when the pinned store image is present locally.
package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/classify"
	"github.com/tolgayayci/xdrcheck/go/internal/lake"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/match"
	"github.com/tolgayayci/xdrcheck/go/internal/objstore"
	"github.com/tolgayayci/xdrcheck/go/internal/proc"
	"github.com/tolgayayci/xdrcheck/go/internal/replay/plan"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

// Options configure a run.
type Options struct {
	Corpus         *manifest.Corpus
	Adapter        adapter.Config // Argv, Env, Mechanism; Limits are set from MemoryMax and PidsMax
	HarnessVersion string
	TargetVersion  string

	Networks      []string
	Entries       []string
	Caps          []int
	Input         string // "" chooses
	Unit          string // "", single, chain, stream
	Repeat        int
	OutOfEnvelope string // probe (default), skip
	AssertKnown   bool
	Confirm       int
	Parallel      int
	Deadline      time.Duration // per-unit ingest deadline; 0 sizes it from describe.timing
	MemoryMax     int64
	PidsMax       int
	KeepGoing     bool
	KeepState     bool

	// ObserveWindowBytes bounds one observe call: consecutive ledgers whose served bytes add up to at most this
	// (always at least one ledger). 0 means DefaultObserveWindowBytes; a negative value observes every unit in
	// one call, which makes the harness's memory grow with the unit (kept for the memory test's negative
	// control).
	ObserveWindowBytes int64

	WorkDir    string // sessions, layouts, adapter workdirs; required
	CacheDir   string // passed to prepare
	LogDir     string // adapter logs and delivery logs; default WorkDir/logs
	StoreImage string // the pinned SeaweedFS image, for sep54-s3

	Report *report.Writer // rows; nil writes none
	// Pending marks an unexpected row that a committed pending list names as pending finding review
	// (report.ExpectationPending) and reports whether it did; nil marks none.
	Pending func(*report.Row) bool
	Out     io.Writer // one line per row; nil for none
	Log     io.Writer // progress; nil for none
}

// Result sums a run up.
type Result struct {
	Describe   *adapter.DescribeResult
	Target     report.Target
	Input      string
	Rows       int
	Unexpected int
	Faults     int // harness_fault rows plus failed teardowns: the run could not do everything it was asked
	ByResult   map[string]int
	Notes      []string
	Stopped    bool // stopped early at a harness fault (no --keep-going)
}

// ExitCode follows the kit's convention: 2 harness fault, 1 an unexpected result, 0 otherwise.
func (r *Result) ExitCode() int {
	switch {
	case r.Faults > 0:
		return 2
	case r.Unexpected > 0:
		return 1
	}
	return 0
}

const (
	// DefaultObserveWindowBytes is the served ledger bytes one observe call covers, and maxWindowLedgers the
	// number of ledgers.
	DefaultObserveWindowBytes = 256 << 10
	maxWindowLedgers          = 64
	// ObserveWindowEnv overrides it when Options.ObserveWindowBytes is 0: a byte count, or "unit" to observe
	// every unit whole (the memory test's negative control switches streaming off with it).
	ObserveWindowEnv = "XDRCHECK_REPLAY_OBSERVE_WINDOW"
	// runtimeShare of the memory group the harness runs in is its Go soft memory limit (proc.FitRuntimeToGroup).
	runtimeShare = 0.875
	// DefaultMaxResponseBytes caps one adapter response line (the memory-bound test's T-mem-2): a longer line is
	// a protocol violation of the unit and is never read whole.
	DefaultMaxResponseBytes = 64 << 20

	defaultObjectStoreBase = 30 * time.Second
	defaultRPCBase         = 180 * time.Second
	failureMargin          = 5 * time.Second
	defaultPerLedger       = time.Second
	maxFacts               = 25
)

type runner struct {
	o        Options
	desc     *adapter.DescribeResult
	target   report.Target
	input    string
	ranges   map[string]bool // commit ranges as the adapter answered them
	resolved bool
	plan     *plan.Plan
	nonce    string

	sessions atomic.Int64
	procs    atomic.Int64

	storeMu   sync.Mutex
	store     *objstore.Store
	storeLog  *lake.DeliveryLog
	storeErr  error
	storeOnce bool

	mu     sync.Mutex
	res    *Result
	stop   bool
	cancel context.CancelFunc
}

// Run runs the replay. An error means the run could not start (bad options, no adapter, a plan that cannot be
// built): exit 2.
func Run(ctx context.Context, o Options) (*Result, error) {
	if o.Corpus == nil || len(o.Adapter.Argv) == 0 || o.WorkDir == "" {
		return nil, errors.New("run: corpus, adapter command and work directory are required")
	}
	if o.TargetVersion == "" {
		return nil, errors.New("run: --target-version is required")
	}
	if o.LogDir == "" {
		o.LogDir = filepath.Join(o.WorkDir, "logs")
	}
	if err := os.MkdirAll(o.LogDir, 0o755); err != nil {
		return nil, err
	}
	if o.Parallel <= 0 {
		o.Parallel = 1
	}
	o.Adapter.Limits = proc.Limits{MemoryMax: o.MemoryMax, TasksMax: o.PidsMax}
	if o.Adapter.MaxLineBytes <= 0 {
		o.Adapter.MaxLineBytes = DefaultMaxResponseBytes
	}
	if o.ObserveWindowBytes == 0 {
		o.ObserveWindowBytes = DefaultObserveWindowBytes
		switch v := os.Getenv(ObserveWindowEnv); {
		case v == "unit":
			o.ObserveWindowBytes = -1
		case v != "":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("%s=%q: want a byte count or \"unit\"", ObserveWindowEnv, v)
			}
			o.ObserveWindowBytes = n
		}
	}
	r := &runner{o: o, res: &Result{ByResult: map[string]int{}}, ranges: map[string]bool{}, nonce: strconv.FormatUint(rand.Uint64(), 16)}
	if l := proc.FitRuntimeToGroup(runtimeShare); l > 0 {
		heapCeiling.Store(l)
		r.logf("memory: the harness's own group allows %d bytes; Go soft limit set to %d", int64(float64(l)/runtimeShare), l)
	}
	ctx, r.cancel = context.WithCancel(ctx)
	defer r.cancel()
	defer r.closeStore()

	// Describe on a first adapter process, which becomes worker 0's.
	first, err := r.startAdapter(ctx)
	if err != nil {
		return nil, err
	}
	r.desc = first.desc
	r.res.Describe = first.desc
	r.target = report.Target{Name: first.desc.Target.Name, Version: o.TargetVersion, Kind: targetKind(first.desc.Target.Name)}
	if err := r.chooseInput(); err != nil {
		first.c.Kill("run aborted")
		return nil, err
	}
	r.res.Input = r.input

	p, err := r.buildPlan()
	if err != nil {
		first.c.Kill("run aborted")
		return nil, err
	}
	r.plan = p

	// Commit ranges of the known divergences are answered by the adapter, which holds the repository.
	if err := r.resolveRanges(ctx, first); err != nil {
		first.c.Kill("run aborted")
		return nil, err
	}
	r.res.Target = r.target

	// Planned not_applicable items first.
	ranOf := map[string]bool{}
	for _, it := range p.Items {
		if it.Status == plan.StatusRun {
			ranOf[it.Entry] = true
		}
	}
	for _, it := range p.Items {
		if it.Status != plan.StatusRun {
			r.naRow(it)
		}
	}

	var units []*plan.Unit
	for _, pass := range p.Passes {
		units = append(units, pass.Units...)
	}
	work := make(chan *plan.Unit)
	var wg sync.WaitGroup
	workers := min(o.Parallel, max(1, len(units)))
	if c := r.desc.Concurrency; c != nil && c.MaxParallelSessions != nil {
		workers = min(workers, *c.MaxParallelSessions)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		var a *adapterProc
		if i == 0 {
			a = first
		}
		go func(a *adapterProc) {
			defer wg.Done()
			w := &worker{r: r, a: a}
			for u := range work {
				w.unit(ctx, u)
			}
			if w.a != nil {
				w.a.close()
			}
		}(a)
	}
	for _, u := range units {
		if r.stopped() {
			break
		}
		select {
		case work <- u:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(work)
	wg.Wait()
	if err := ctx.Err(); err != nil && !r.stopped() {
		return r.res, err
	}
	return r.res, nil
}

func targetKind(name string) string {
	if strings.HasPrefix(name, "xdrcheck/") || strings.HasPrefix(name, "xdrcheck-") {
		return "selftest"
	}
	return "pipeline"
}

func (r *runner) logf(format string, a ...any) {
	if r.o.Log != nil {
		fmt.Fprintf(r.o.Log, format+"\n", a...)
	}
}

func (r *runner) stopped() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stop
}

// ---- adapter processes ----

type adapterProc struct {
	c    *adapter.Client
	desc *adapter.DescribeResult
	log  *os.File
	name string
}

func (a *adapterProc) close() {
	if a == nil || a.c == nil {
		return
	}
	a.c.Close()
	if a.log != nil {
		a.log.Close()
	}
	a.c = nil
}

func (a *adapterProc) kill(reason string) {
	if a == nil || a.c == nil {
		return
	}
	a.c.Kill(reason)
	if a.log != nil {
		a.log.Close()
	}
	a.c = nil
}

func (r *runner) startAdapter(ctx context.Context) (*adapterProc, error) {
	n := r.procs.Add(1)
	name := fmt.Sprintf("adapter-%d.log", n)
	lf, err := os.Create(filepath.Join(r.o.LogDir, name))
	if err != nil {
		return nil, err
	}
	cfg := r.o.Adapter
	cfg.Stderr = lf
	cfg.Name = "adapter"
	c, err := adapter.Start(ctx, cfg)
	if err != nil {
		lf.Close()
		return nil, fmt.Errorf("starting the adapter: %w", err)
	}
	d, err := c.Describe(ctx, adapter.DescribeParams{HarnessVersion: r.o.HarnessVersion, ProtocolVersions: []string{adapter.Protocol}, TargetVersion: r.o.TargetVersion})
	if err != nil {
		c.Kill("describe failed")
		lf.Close()
		return nil, fmt.Errorf("adapter describe: %w (log %s)", err, lf.Name())
	}
	if r.desc != nil && (d.Adapter != r.desc.Adapter || d.Target.Name != r.desc.Target.Name) {
		c.Kill("describe changed")
		lf.Close()
		return nil, fmt.Errorf("adapter describe changed between processes: %+v, then %+v", r.desc.Adapter, d.Adapter)
	}
	return &adapterProc{c: c, desc: d, log: lf, name: name}, nil
}

// ---- planning ----

func (r *runner) chooseInput() error {
	declared := r.desc.Inputs
	if in := r.o.Input; in != "" {
		switch in {
		case "sep54-gcs":
			return errors.New("--input sep54-gcs: the GCS view is not built (replay-harness.md §2.2)")
		case "sep54-dir", "sep54-s3", "rpc":
		default:
			return fmt.Errorf("--input %q: want sep54-s3, sep54-gcs, sep54-dir or rpc", in)
		}
		if !slices.Contains(declared, in) {
			return fmt.Errorf("--input %s: the adapter declares only %v", in, declared)
		}
		if in == "sep54-s3" {
			if err := objstore.Available(r.o.StoreImage); err != nil {
				return fmt.Errorf("--input sep54-s3: %v", err)
			}
		}
		r.input = in
		return nil
	}
	for _, in := range []string{"sep54-s3", "sep54-dir", "rpc"} {
		if !slices.Contains(declared, in) {
			continue
		}
		if in == "sep54-s3" {
			if err := objstore.Available(r.o.StoreImage); err != nil {
				r.res.Notes = append(r.res.Notes, "sep54-s3 not used: "+err.Error())
				continue
			}
		}
		r.input = in
		return nil
	}
	return fmt.Errorf("the adapter declares inputs %v; the harness serves sep54-s3, sep54-dir and rpc", declared)
}

func (r *runner) buildPlan() (*plan.Plan, error) {
	e := r.desc.Envelope
	env := &plan.Envelope{
		MinProtocol: e.MinProtocol, MaxProtocol: e.MaxProtocol, MinProtocolWithTransactions: e.MinProtocolWithTransactions,
		LedgerCloseMetaVersions: e.LedgerCloseMetaVersions, TransactionMetaVersions: e.TransactionMetaVersions,
		OperationTypes: e.OperationTypes, Enforcement: e.Enforcement, Basis: e.Basis,
	}
	po := plan.Options{
		Networks: r.o.Networks, Entries: r.o.Entries, Caps: r.o.Caps, Unit: r.o.Unit, Units: r.desc.Units,
		Envelope: env, OutOfEnvelope: r.o.OutOfEnvelope, Repeat: r.o.Repeat,
	}
	if r.o.AssertKnown {
		ids := []string{}
		for _, en := range r.o.Corpus.Entries {
			if classify.HasReplayDivergence(en, r.target.Name) && r.selectedByFilters(en) {
				ids = append(ids, en.ID)
			}
		}
		if len(ids) == 0 {
			return nil, fmt.Errorf("--assert-known: no entry has a replay divergence for %s", r.target.Name)
		}
		po.Entries = ids
	}
	return plan.Build(r.o.Corpus, po)
}

func (r *runner) selectedByFilters(e *manifest.Entry) bool {
	if len(r.o.Entries) > 0 {
		ok := false
		for _, g := range r.o.Entries {
			if m, _ := filepath.Match(g, e.ID); m || g == e.ID {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.o.Caps) > 0 {
		for _, c := range r.o.Caps {
			if slices.Contains(e.Caps, c) {
				return true
			}
		}
		return false
	}
	return true
}

// commitRanges lists the planned entries' commit ranges (A..B, ..B) for the target, which only the adapter
// can evaluate.
func (r *runner) commitRanges() []string {
	seen := map[string]bool{}
	var out []string
	for _, it := range r.plan.Items {
		e := r.o.Corpus.Entry(it.Entry)
		if e == nil || e.Conformance == nil {
			continue
		}
		for _, d := range e.Conformance.KnownDivergences {
			if d.Target == r.target.Name && d.Level == "replay" && strings.Contains(d.Versions, "..") && !seen[d.Versions] {
				seen[d.Versions] = true
				out = append(out, d.Versions)
			}
		}
	}
	sort.Strings(out)
	return out
}

// resolveRanges asks the adapter, in a prepare/teardown of its own, whether the target version lies in each
// commit range, and records the resolved version.
func (r *runner) resolveRanges(ctx context.Context, a *adapterProc) error {
	rs := r.commitRanges()
	if len(rs) == 0 {
		r.resolved = true
		return nil
	}
	session := r.newSession()
	dir := filepath.Join(r.o.WorkDir, session)
	pr, err := a.c.Prepare(ctx, adapter.PrepareParams{Session: session, TargetVersion: r.o.TargetVersion, Network: r.someNetwork(),
		Workdir: filepath.Join(dir, "adapter"), Cachedir: r.o.CacheDir, Limits: r.limits(), ResolveRanges: rs})
	if err != nil {
		return fmt.Errorf("prepare to resolve the known divergences' commit ranges: %w", err)
	}
	if _, err := a.c.Teardown(ctx, adapter.TeardownParams{Session: session}); err != nil {
		return fmt.Errorf("teardown after resolving ranges: %w", err)
	}
	if !r.o.KeepState {
		os.RemoveAll(dir)
	}
	r.applyPrepare(pr)
	return nil
}

func (r *runner) applyPrepare(pr *adapter.PrepareResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n := resolvedNote(r.o.TargetVersion, pr.TargetVersion); n != "" && !slices.Contains(r.res.Notes, n) {
		r.res.Notes = append(r.res.Notes, n)
	}
	for _, a := range pr.Ranges {
		if _, ok := r.ranges[a.Range]; !ok {
			r.ranges[a.Range] = a.Contains
		}
	}
	r.resolved = true
}

// resolvedNote is the run note for an adapter that resolved the requested target version to another one (a
// branch or short commit to a full commit, or an adapter that runs one fixed version), or "" when they are the
// same. The report's target and its row IDs always carry the requested --target-version, so the note names both.
func resolvedNote(requested, resolved string) string {
	if resolved == "" || resolved == requested {
		return ""
	}
	return fmt.Sprintf("adapter resolved the requested target version %s to %s; the report and its row IDs keep %s (--target-version)",
		requested, resolved, requested)
}

func (r *runner) someNetwork() adapter.Network {
	for _, p := range r.plan.Passes {
		return adapter.Network{Name: p.Network, Passphrase: p.Passphrase}
	}
	for _, e := range r.o.Corpus.Entries {
		for _, v := range e.Variants {
			if v.Network != "none" {
				return adapter.Network{Name: v.Network, Passphrase: v.Passphrase}
			}
		}
	}
	return adapter.Network{Name: "testnet", Passphrase: "Test SDF Network ; September 2015"}
}

func (r *runner) limits() *adapter.Limits {
	if r.o.MemoryMax <= 0 && r.o.PidsMax <= 0 {
		return nil
	}
	l := &adapter.Limits{}
	if r.o.MemoryMax > 0 {
		l.MemoryMaxBytes = &r.o.MemoryMax
	}
	if r.o.PidsMax > 0 {
		l.PidsMax = &r.o.PidsMax
	}
	return l
}

func (r *runner) newSession() string { return fmt.Sprintf("s-%04d", r.sessions.Add(1)) }

// inRange evaluates one divergence range for the version under test.
func (r *runner) inRange(versions string) (bool, bool) {
	if strings.Contains(versions, "..") {
		r.mu.Lock()
		defer r.mu.Unlock()
		v, ok := r.ranges[versions]
		return v, ok
	}
	return classify.SemverContains(versions, r.o.TargetVersion)
}

// ---- the object store ----

func (r *runner) objectStore(ctx context.Context) (*objstore.Store, *lake.DeliveryLog, error) {
	r.storeMu.Lock()
	defer r.storeMu.Unlock()
	if !r.storeOnce {
		r.storeOnce = true
		f, err := os.Create(filepath.Join(r.o.LogDir, "delivery-s3.ndjson"))
		if err != nil {
			r.storeErr = err
		} else {
			r.storeLog = lake.NewDeliveryLog(f)
			r.store, r.storeErr = objstore.Launch(ctx, objstore.Options{Image: r.o.StoreImage, NamePrefix: "xdrcheck-replay", Log: r.storeLog})
			if r.store != nil {
				for _, n := range r.store.Notes {
					r.logf("object store: %s", n)
				}
			}
		}
	}
	return r.store, r.storeLog, r.storeErr
}

func (r *runner) closeStore() {
	r.storeMu.Lock()
	defer r.storeMu.Unlock()
	if r.store != nil {
		r.store.Close()
		r.store = nil
	}
}

// ---- one unit ----

type worker struct {
	r *runner
	a *adapterProc
}

// view is one unit's served ledgers.
type view struct {
	input    adapter.Input
	delivery string
	served   func(seq uint32) bool
	close    func()
	evidence string // what the delivery evidence is
}

func (w *worker) serve(ctx context.Context, u *plan.Unit, dir string) (*view, error) {
	r := w.r
	schemaOf := func(l *lake.Layout) *adapter.SEP54Schema {
		return &adapter.SEP54Schema{LedgersPerBatch: int(l.Config.LedgersPerBatch), BatchesPerPartition: int(l.Config.BatchesPerPartition), Compression: "zstd"}
	}
	switch r.input {
	case "sep54-dir":
		l, err := writeLayout(u, filepath.Join(dir, "lake"))
		if err != nil {
			return nil, err
		}
		abs, _ := filepath.Abs(l.Dir)
		return &view{input: adapter.Input{Kind: "sep54-dir", Path: abs, Schema: schemaOf(l)}, delivery: classify.DeliveryNone,
			served: func(uint32) bool { return false }, close: func() {}, evidence: "filesystem layout; reads are not observed"}, nil
	case "rpc":
		f, err := os.Create(filepath.Join(r.o.LogDir, "delivery-"+filepath.Base(dir)+".ndjson"))
		if err != nil {
			return nil, err
		}
		dlog := lake.NewDeliveryLog(f)
		srv, err := u.RPCServer(r.nonce, dlog)
		if err != nil {
			f.Close()
			return nil, err
		}
		hs, url, err := srv.Listen("127.0.0.1:0")
		if err != nil {
			f.Close()
			return nil, err
		}
		return &view{input: adapter.Input{Kind: "rpc", URL: url}, delivery: classify.DeliveryExact, served: dlog.Served,
			close: func() { hs.Close(); f.Close() }, evidence: "mock RPC request log logs/" + filepath.Base(f.Name())}, nil
	case "sep54-s3":
		l, err := u.WriteLayout(filepath.Join(dir, "lake"))
		if err != nil {
			return nil, err
		}
		st, dlog, err := r.objectStore(ctx)
		if err != nil {
			return nil, fmt.Errorf("object store: %w", err)
		}
		prefix := filepath.Base(dir) + "-" + u.ID
		if err := st.Upload(ctx, prefix, l); err != nil {
			return nil, err
		}
		if err := st.ReadBack(ctx, prefix, l); err != nil {
			return nil, err
		}
		served := func(seq uint32) bool {
			for _, d := range dlog.Records() {
				if strings.HasPrefix(d.Key, prefix+"/") && (d.Status == "200" || d.Status == "ok") && slices.Contains(d.Ledgers, seq) {
					return true
				}
			}
			return false
		}
		return &view{input: adapter.Input{Kind: "sep54-s3", EndpointURL: st.Endpoint, BucketPath: st.Bucket + "/" + prefix, Region: objstore.Region,
			AccessKeyID: objstore.AccessKey, SecretAccessKey: objstore.SecretKey, Schema: schemaOf(l)},
			delivery: classify.DeliveryExact, served: served, close: func() {}, evidence: "object-store logging proxy, logs/delivery-s3.ndjson (read-back checked)"}, nil
	}
	return nil, fmt.Errorf("input %q is not served", r.input)
}

const (
	// layoutSlice is how many ledgers writeLayout hands lake.Write at a time.
	layoutSlice = 32
	// largeLedger is the size from which a ledger is written, and observed, on its own: decoding a ledger of
	// megabytes takes tens of times its size for a moment, and that moment should start from the live set, not
	// from the garbage of the ledgers before it.
	largeLedger = 1 << 20
)

// Bounding the harness's own memory between slices of work. Renumbering, compressing and matching allocate many
// times the bytes they handle, and when and how far the collector lets the heap grow over the live set depends on
// its pacing and on the CPU it gets; over a long stream the process would keep the highest of those moments.
// Before each slice of work (a slice of the layout, a window of observations) the harness collects, returns the
// free memory to the system and sets the Go runtime's soft memory limit to what it uses then plus room for the
// slice: heapHeadroom and roomPerByte times the slice's ledger bytes, at most maxRoom, never above the limit taken
// from its own memory group. After the unit's work the limit goes back to that ceiling. With --parallel the room
// is shared.
//
// maxRoom matters for a ledger of megabytes: without it the room (64 times 6 MiB) is above the ceiling, and the
// heap of a long stream of such ledgers grows to the ceiling, whose 12.5 % share left to the rest of the process
// is less than the binary's own mapped code (about 37 MiB resident), so the process's peak resident set crossed
// its 256 MiB group in the memory test (make verify-memory). Its decoded ledger and buffers live at once are
// about seven times its bytes; 64 MiB above what the harness holds between slices is room for those and the
// collector's slack. The collector runs more often on such a stream, but the stream still ends sooner than one
// whose heap is pressed against the ceiling.
const (
	heapHeadroom = 16 << 20
	roomPerByte  = 64
	maxRoom      = 64 << 20
)

var heapCeiling atomic.Int64 // the soft memory limit from the harness's own group; 0 for none

// release returns the memory finished work left behind and bounds the Go runtime's memory for the next slice of
// work, which handles ledgers of next bytes.
func release(next int64) {
	debug.FreeOSMemory()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	limit := int64(ms.Sys-ms.HeapReleased) + min(heapHeadroom+roomPerByte*next, maxRoom)
	if c := heapCeiling.Load(); c > 0 && limit > c {
		limit = c
	}
	debug.SetMemoryLimit(limit)
}

// unbound lifts release's bound back to the ceiling.
func unbound() {
	c := heapCeiling.Load()
	if c <= 0 {
		c = math.MaxInt64
	}
	debug.SetMemoryLimit(c)
}

// writeLayout writes the unit as a SEP-54 layout on disk like plan.Unit.WriteLayout, a slice of ledgers at a
// time (a large ledger alone) under release's bound, so that neither the per-object records lake.Write keeps nor
// the garbage of renumbering ever exist for a whole long unit at once. The layout it returns has no Objects.
func writeLayout(u *plan.Unit, dir string) (*lake.Layout, error) {
	cfg := lake.NewConfig(u.Passphrase)
	out := &lake.Layout{Dir: dir, Config: cfg, First: u.First(), Last: u.Last()}
	defer unbound()
	var ls []lake.Ledger
	var bytes int64
	write := func() error {
		if len(ls) == 0 {
			return nil
		}
		release(bytes)
		_, err := lake.Write(dir, cfg, ls)
		ls, bytes = ls[:0], 0
		return err
	}
	for _, l := range u.Ledgers {
		if l.Bytes >= largeLedger {
			if err := write(); err != nil {
				return nil, err
			}
		}
		ls = append(ls, lake.Ledger{Seq: l.Seq, Load: l.Load, Original: l.Original})
		bytes += l.Bytes
		if len(ls) == layoutSlice || l.Bytes >= largeLedger {
			if err := write(); err != nil {
				return nil, err
			}
		}
	}
	if err := write(); err != nil {
		return nil, err
	}
	return out, nil
}

// session is what one unit's adapter session produced.
type session struct {
	id         string
	fault      string
	ingest     *adapter.IngestResult
	harness    classify.HarnessIngest
	memKills   int // processes of the adapter's group killed for its memory cap during ingest
	teardown   string
	view       *view
	lastServed uint32
	adapterLg  string
	wallMS     int64
}

// runSession runs one unit's adapter session and hands every scored entry of the unit to emit, in unit order
// and exactly once: window by window as each window of ledgers is observed and matched, or all at once with the
// session's fault when nothing could be observed.
func (w *worker) runSession(ctx context.Context, u *plan.Unit, emit func(*session, []entryRun)) *session {
	r := w.r
	s := &session{id: r.newSession()}
	next := 0 // u.Entries[:next] have been emitted
	start := time.Now()
	flush := func(obs *adapter.Observation, through uint32) {
		end := next
		for end < len(u.Entries) && u.Entries[end].Seq <= through {
			end++
		}
		if end > next {
			s.wallMS = time.Since(start).Milliseconds()
			emit(s, w.score(u, s, obs, u.Entries[next:end]))
			next = end
		}
	}
	// However the session ends, every entry not yet scored is scored now.
	defer flush(nil, ^uint32(0))
	dir := filepath.Join(r.o.WorkDir, s.id)
	defer func() {
		if !r.o.KeepState {
			os.RemoveAll(dir)
		}
	}()
	if w.a == nil || w.a.c == nil || w.a.c.Err() != nil {
		w.a.kill("replaced")
		a, err := r.startAdapter(ctx)
		if err != nil {
			s.fault = err.Error()
			return s
		}
		w.a = a
	}
	s.adapterLg = "logs/" + w.a.name
	v, err := w.serve(ctx, u, dir)
	if err != nil {
		s.fault = "serving the unit: " + err.Error()
		return s
	}
	defer v.close()
	s.view = v
	c := w.a.c
	start = time.Now()

	pr, err := c.Prepare(ctx, adapter.PrepareParams{Session: s.id, TargetVersion: r.o.TargetVersion,
		Network: adapter.Network{Name: u.Network, Passphrase: u.Passphrase}, Workdir: filepath.Join(dir, "adapter"),
		Cachedir: r.o.CacheDir, PortRange: freePortRange(4), Limits: r.limits(), ResolveRanges: r.commitRanges()})
	if err != nil {
		s.fault = "prepare: " + err.Error()
		w.afterError()
		return s
	}
	r.applyPrepare(pr)

	oomBefore, _ := proc.OOMKills(c.Pid())
	ing, err := c.Ingest(ctx, adapter.IngestParams{Session: s.id, Input: v.input, Range: adapter.Range{Start: int64(u.First()), End: int64(u.Last())},
		Network: adapter.Network{Name: u.Network, Passphrase: u.Passphrase}, Unit: u.Kind, DeadlineMS: r.deadline(u).Milliseconds()})
	var te *adapter.TimeoutError
	var xe *adapter.ExitError
	switch {
	case err == nil:
		s.ingest = ing
	case errors.As(err, &te):
		s.harness.TimedOut = true
	case errors.As(err, &xe) && xe.Result.MemoryCapHit:
		s.harness.MemoryCap = true
	default:
		s.fault = "ingest: " + err.Error()
	}
	if n, ok := proc.OOMKills(c.Pid()); ok {
		s.memKills = n - oomBefore
	} else if xe != nil {
		s.memKills = xe.Result.OOMKills - oomBefore
	}
	s.lastServed = lastServed(u, v)
	if c.Err() == nil && s.fault == "" {
		kinds := []string{}
		for _, k := range adapter.AllKinds {
			if w.a.desc.Observations.Kind(k).Supported {
				kinds = append(kinds, k)
			}
		}
		if len(kinds) == 0 {
			kinds = adapter.AllKinds
		}
		for _, win := range windows(u, r.o.ObserveWindowBytes) {
			release(windowBytes(u, win))
			obs, err := c.Observe(ctx, adapter.ObserveParams{Session: s.id, Range: adapter.Range{Start: int64(win[0]), End: int64(win[1])}, Kinds: kinds})
			if err != nil {
				s.fault = "observe: " + err.Error()
				break
			}
			flush(obs, win[1])
		}
		unbound()
	}
	if c.Err() == nil {
		keep := r.o.KeepState
		if _, err := c.Teardown(ctx, adapter.TeardownParams{Session: s.id, KeepState: &keep}); err != nil {
			s.teardown = err.Error()
		}
	}
	w.afterError()
	return s
}

// windows splits a unit's served range into observe windows: consecutive ledgers whose served bytes add up to
// at most budget and number at most maxWindowLedgers, at least one ledger each; one window for the whole unit
// when budget is negative.
func windows(u *plan.Unit, budget int64) [][2]uint32 {
	if budget < 0 {
		return [][2]uint32{{u.First(), u.Last()}}
	}
	var out [][2]uint32
	var cur [2]uint32
	var size int64
	n := 0
	for _, l := range u.Ledgers {
		b := max(l.Bytes, 1)
		if n > 0 && (size+b > budget || n == maxWindowLedgers) {
			out = append(out, cur)
			size, n = 0, 0
		}
		if n == 0 {
			cur[0] = l.Seq
		}
		cur[1] = l.Seq
		size += b
		n++
	}
	return append(out, cur)
}

// windowBytes is the served bytes of a window's ledgers (a unit's ledgers are consecutive).
func windowBytes(u *plan.Unit, win [2]uint32) int64 {
	var n int64
	for _, l := range u.Ledgers {
		if l.Seq >= win[0] && l.Seq <= win[1] {
			n += l.Bytes
		}
	}
	return n
}

// afterError drops an adapter process that can no longer be used.
func (w *worker) afterError() {
	if w.a != nil && w.a.c != nil && w.a.c.Err() != nil {
		w.a.kill("unusable after " + w.a.c.Err().Error())
	}
}

func (r *runner) deadline(u *plan.Unit) time.Duration {
	if r.o.Deadline > 0 {
		return r.o.Deadline
	}
	base := defaultObjectStoreBase
	if r.input == "rpc" {
		base = defaultRPCBase
	}
	per := defaultPerLedger
	if t := r.desc.Timing; t != nil {
		if ms, ok := t.SlowestFailureMS[r.input]; ok {
			base = time.Duration(ms)*time.Millisecond + failureMargin
		}
		if t.IngestPerLedgerMS != nil {
			per = time.Duration(*t.IngestPerLedgerMS) * time.Millisecond
		}
	}
	return base + per*time.Duration(len(u.Ledgers))
}

func freePortRange(count int) *adapter.PortRange {
	for attempt := 0; attempt < 64; attempt++ {
		first := 20000 + rand.IntN(40000-count)
		ok := true
		var held []net.Listener
		for p := first; p < first+count; p++ {
			ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
			if err != nil {
				ok = false
				break
			}
			held = append(held, ln)
		}
		for _, ln := range held {
			ln.Close()
		}
		if ok {
			return &adapter.PortRange{First: first, Count: count}
		}
	}
	return nil
}

// entryRun is one scored entry's outcome in one session.
type entryRun struct {
	sc      plan.Scored
	entry   *manifest.Entry
	variant *manifest.Variant
	outcome classify.Outcome
	match   *match.Result
}

// score matches and classifies entries of the unit against one window's observation set (nil when nothing was
// observed).
func (w *worker) score(u *plan.Unit, s *session, obs *adapter.Observation, entries []plan.Scored) []entryRun {
	r := w.r
	out := make([]entryRun, 0, len(entries))
	for _, sc := range entries {
		er := entryRun{sc: sc, entry: r.o.Corpus.Entry(sc.Entry)}
		in := classify.Input{Fault: s.fault, Seq: sc.Seq, UnitFirst: u.First(), UnitLast: u.Last(), UnitKind: u.Kind, Network: u.Network,
			Envelope: &w.r.desc.Envelope, Ingest: s.ingest, Harness: s.harness, Observed: obs}
		if er.entry != nil {
			for _, v := range er.entry.Variants {
				if er.entry.VariantKey(v) == sc.Variant && v.Network == u.Network {
					er.variant = v
				}
			}
		}
		if er.variant == nil && in.Fault == "" {
			in.Fault = fmt.Sprintf("entry %s variant %s is not in the corpus", sc.Entry, sc.Variant)
		}
		if s.view != nil {
			in.Delivery, in.Served = s.view.delivery, s.view.served(sc.Seq)
			in.LastServed = s.lastServed
		}
		if er.variant != nil {
			in.Variant, in.Expect = er.variant, er.variant.Resolved
			if obs != nil && in.Fault == "" {
				mi := match.Input{Expect: er.variant.Resolved, LedgerSeq: int64(sc.Seq), Passphrase: u.Passphrase, Declared: &w.r.desc.Observations, Observation: obs}
				if f := er.variant.Focus; f != nil {
					mi.FocusTxHash, mi.FocusTxIndex = f.TxHash, f.TxIndex
				}
				m, err := match.Match(mi)
				if err != nil {
					in.MatchError = err.Error()
				}
				er.match, in.Match = m, m
			}
		}
		er.outcome = classify.Classify(in)
		if er.outcome.Class == classify.Mishandled && er.outcome.Qualifier == classify.Crash && s.memKills > 0 && !s.harness.MemoryCap {
			er.outcome.Notes = append(er.outcome.Notes, fmt.Sprintf("memory: %d process(es) of the adapter's group were killed at its memory cap (%d bytes) during ingest", s.memKills, r.o.MemoryMax))
		}
		if u.Transformed {
			er.outcome.Notes = append(er.outcome.Notes, fmt.Sprintf("transformed: stream unit, served as ledger %d (corpus ledger %d); never acceptance evidence or a finding", sc.Seq, sc.OriginalSeq))
		}
		out = append(out, er)
	}
	return out
}

// lastServed is the highest ledger of the unit the view's delivery log shows delivered, 0 for none or when
// reads are not observed. It locates a stop the harness observed itself (a deadline or a memory kill).
func lastServed(u *plan.Unit, v *view) uint32 {
	if v.delivery != classify.DeliveryExact {
		return 0
	}
	var last uint32
	for _, l := range u.Ledgers {
		if l.Seq > last && v.served(l.Seq) {
			last = l.Seq
		}
	}
	return last
}

func (w *worker) unit(ctx context.Context, u *plan.Unit) {
	r := w.r
	if r.stopped() || ctx.Err() != nil {
		return
	}
	r.logf("unit %s: %d ledger(s) %d..%d, %d entr(ies), input %s", u.ID, len(u.Ledgers), u.First(), u.Last(), len(u.Entries), r.input)
	if r.o.Confirm == 0 {
		// Rows are written as each window is scored; nothing of the unit is held.
		s := w.runSession(ctx, u, func(s *session, ers []entryRun) {
			for _, er := range ers {
				r.writeRun(u, s, er)
			}
		})
		r.teardownNote(u, s)
		return
	}
	var runs []entryRun
	s := w.runSession(ctx, u, func(_ *session, ers []entryRun) { runs = append(runs, ers...) })

	// --confirm K: re-run a unit with a non-pass result; an entry whose result changes is flaky.
	if anyNonPass(runs) {
		seen := make([]map[string]bool, len(runs))
		for i, er := range runs {
			seen[i] = map[string]bool{er.outcome.String(): true}
		}
		for k := 0; k < r.o.Confirm && ctx.Err() == nil; k++ {
			i := 0
			w.runSession(ctx, u, func(_ *session, ers []entryRun) {
				for _, er := range ers {
					seen[i][er.outcome.String()] = true
					i++
				}
			})
		}
		for i := range runs {
			if len(seen[i]) > 1 {
				var all []string
				for k := range seen[i] {
					all = append(all, k)
				}
				sort.Strings(all)
				runs[i].outcome = classify.Outcome{Class: classify.Flaky, Notes: []string{"results differ between runs: " + strings.Join(all, ", ")}}
			}
		}
	}

	for _, er := range runs {
		r.writeRun(u, s, er)
	}
	r.teardownNote(u, s)
}

func (r *runner) teardownNote(u *plan.Unit, s *session) {
	if s.teardown != "" {
		r.mu.Lock()
		r.res.Faults++
		r.res.Notes = append(r.res.Notes, fmt.Sprintf("unit %s: teardown failed: %s", u.ID, s.teardown))
		r.mu.Unlock()
	}
}

func anyNonPass(runs []entryRun) bool {
	for _, er := range runs {
		switch er.outcome.Class {
		case classify.Pass, classify.NotApplicable:
		default:
			return true
		}
	}
	return false
}

// ---- rows ----

func (r *runner) rowID(entry, variant, unit string) string {
	return fmt.Sprintf("replay:%s@%s:%s:%s:%s", r.target.Name, r.target.Version, entry, variant, unit)
}

func (r *runner) naRow(it plan.Item) {
	e := r.o.Corpus.Entry(it.Entry)
	o := classify.Outcome{Class: classify.NotApplicable, Row: 1, Notes: []string{it.Qualifier + ": " + it.Detail}}
	unit := it.UnitKind
	if unit == "" {
		unit = plan.Single
	}
	ev := map[string]any{"planned": map[string]any{"status": it.Status, "qualifier": it.Qualifier, "detail": it.Detail}}
	r.emit(e, it.Variant, unit, nil, o, ev)
}

func (r *runner) writeRun(u *plan.Unit, s *session, er entryRun) {
	ev := map[string]any{"session": s.id}
	if s.ingest != nil {
		ev["ingest"] = s.ingest
	}
	if s.harness.TimedOut || s.harness.MemoryCap {
		ev["harness_ingest"] = s.harness
		if s.view != nil && s.view.delivery == classify.DeliveryExact {
			ev["last_served"] = s.lastServed
		}
	}
	if s.memKills > 0 {
		ev["memory_kills"] = s.memKills
	}
	if s.fault != "" {
		ev["fault"] = s.fault
	}
	if s.view != nil {
		ev["delivered"] = s.view.served(er.sc.Seq)
		ev["delivery_evidence"] = s.view.evidence
	}
	if er.sc.Seq != er.sc.OriginalSeq {
		ev["served_as"] = er.sc.Seq
		ev["corpus_ledger"] = er.sc.OriginalSeq
	}
	// Fact results are evidence only where they decided the class (the entry's ledger was ingested).
	if m := er.match; m != nil && er.outcome.Row >= 7 {
		var facts []match.Fact
		var other int
		for _, f := range m.Facts {
			if f.Status != match.Missing && f.Status != match.Wrong {
				continue
			}
			if len(facts) < maxFacts {
				facts = append(facts, f)
			} else {
				other++
			}
		}
		var extras []match.Extra
		for _, x := range m.Extras {
			if x.Status != match.Ignored && len(extras) < maxFacts {
				extras = append(extras, x)
			}
		}
		sum := m.Summary()
		fe := map[string]any{"matched": sum.Matched, "missing": sum.Missing, "wrong": sum.Wrong, "not_applicable": sum.NotApplicable,
			"extra_in_scope": sum.ExtraInScope, "forbidden": sum.Forbidden, "ledger_observed": m.LedgerObserved, "focus_tx": m.FocusTxSeen}
		if len(facts) > 0 {
			fe["missing_or_wrong"], fe["beyond_cap"] = facts, other
		}
		if len(extras) > 0 {
			fe["extras"] = extras
		}
		ev["facts"] = fe
	}
	if s.adapterLg != "" {
		ev["logs"] = s.adapterLg
	}
	ev["wall_ms"] = s.wallMS
	variant := er.sc.Variant
	r.emit(er.entry, variant, u.Kind, &report.Range{Start: int64(u.First()), End: int64(u.Last())}, er.outcome, ev)
}

// expectationWords is the console's last column: how the row stands against what the corpus expects, in plain
// words (report.json keeps the expectation field itself).
func expectationWords(row *report.Row) string {
	switch {
	case row.Expectation == "unexpected":
		return "UNEXPECTED"
	case row.Expectation == report.ExpectationPending:
		return "found before, awaiting review"
	case row.KnownDivergence != nil && row.Replay != nil && row.Replay.Class != "pass":
		return "known issue " + row.KnownDivergence.Reference
	}
	return "as expected"
}

func (r *runner) emit(e *manifest.Entry, variant, unit string, rng *report.Range, o classify.Outcome, ev map[string]any) {
	entryID := ""
	var caps []int
	x := classify.Expectation{}
	if e != nil {
		entryID, caps = e.ID, e.Caps
		x = classify.ForEntry(e, r.target.Name, r.inRange)
	}
	v := classify.Judge(x, o, r.o.AssertKnown)
	r.mu.Lock()
	defer r.mu.Unlock()
	row := report.Row{
		RowID: r.rowID(entryID, variant, unit), Tool: "replay", Entry: entryID, Variant: variant, Target: r.target,
		Failure: report.ReplayFailure(o.Class, o.Qualifier), Caps: caps,
		Expected: &report.Expected{Source: x.Source(), Result: x.Want()},
		Replay:   &report.ReplayResult{Unit: unit, Class: o.Class, Qualifier: o.Qualifier, Range: rng},
	}
	if rng != nil {
		row.Replay.Input = r.input
	}
	row.Expectation = "unexpected"
	if v.Expected {
		row.Expectation = "expected"
	}
	d := v.Divergence
	if d == nil && len(x.InRange) > 0 {
		d = x.InRange[0]
	}
	if d != nil {
		row.KnownDivergence = &report.DivergenceMatch{Reference: d.Reference, Status: d.Status, InRange: true, FixedIn: d.FixedIn}
		if v.Divergence != nil && d.Finding != "" {
			f := d.Finding
			row.Finding = &f
		}
	}
	row.Notes = append(row.Notes, o.Notes...)
	if v.Note != "" {
		row.Notes = append(row.Notes, v.Note)
	}
	ev["class_row"] = o.Row
	if b, err := json.Marshal(ev); err == nil {
		row.Evidence = b
	}
	if r.o.Pending != nil {
		r.o.Pending(&row)
	}
	r.res.Rows++
	if row.Expectation == "unexpected" {
		r.res.Unexpected++
	}
	if o.Class == classify.HarnessFault {
		r.res.Faults++
		if !r.o.KeepGoing && !r.stop {
			r.stop = true
			r.res.Stopped = true
			r.res.Notes = append(r.res.Notes, "stopped at the first harness fault ("+entryID+"); --keep-going runs on")
		}
	}
	r.res.ByResult[report.ResultKey(&row)]++
	if r.o.Report != nil {
		if err := r.o.Report.Write(row); err != nil {
			r.res.Faults++
			r.res.Notes = append(r.res.Notes, "report write: "+err.Error())
		}
	}
	if r.o.Out != nil {
		fmt.Fprintf(r.o.Out, "%-58s %-12s %-7s %-26s %s\n", entryID, variant, unit, o.String(), expectationWords(&row))
	}
}
