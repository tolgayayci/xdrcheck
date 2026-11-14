// Package conform is the conformance orchestrator: it runs corpus entries through one driver program per SDK
// column (the driver protocol, xcc.driver/1, NDJSON over stdio), under per-run time, memory and address-space
// limits, and records what each driver reported (docs/driver-protocol.md, docs/conformance-protocol.md §4).
//
// Process model: each column has one long-lived driver process, started under internal/proc and asked for its
// describe first. Cells of a column run serially on it; columns run in parallel up to Options.Jobs. A cell
// whose entry is isolated (Isolated) gets a fresh process of its own. When a process dies on a request, or is
// killed at the request timeout or at its memory cap, that cell is recorded as crash and the next cell starts a
// fresh process. Every response is validated strictly against the driver protocol schema; a response that
// breaks it is never trusted: the cell is recorded as a protocol error, the process is replaced, and the run
// exits 2.
//
// Verdicts are not decided here. Each observation is handed to a Judge (judge.go), the hook the verdict engine
// implements; until it exists, ObservedJudge records the outcome class as a provisional verdict.
package conform

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// Options configure a run.
type Options struct {
	Sets    *Sets
	Columns []*Column
	Corpus  *manifest.Corpus
	Entries Globs
	Levels  map[string]bool // nil means every level
	Jobs    int             // concurrent columns; default the number of CPUs
	Limits  Limits
	// ColumnAddressSpace overrides Limits.AddressSpaceMax for the columns it names (by column ID; 0 = none).
	// An entry's own sandbox still wins over both.
	ColumnAddressSpace map[string]int64
	Validator          *Validator
	Log                io.Writer // progress and problems; nil discards
}

// ColumnRun is one column's run: its describe and its problems.
type ColumnRun struct {
	Column      *Column
	Describe    *Describe
	DescribeRaw json.RawMessage
	Processes   int
	Errors      []string // infrastructure problems: start, describe, protocol, shutdown
}

// Result is a whole run.
type Result struct {
	Observations []*Observation // in report order
	Columns      []*ColumnRun   // sorted by column ID
	Started      time.Time
	Wall         time.Duration
}

// InfraErrors returns every infrastructure problem of the run, column by column.
func (r *Result) InfraErrors() []string {
	var out []string
	for _, c := range r.Columns {
		for _, e := range c.Errors {
			out = append(out, c.Column.ID+": "+e)
		}
	}
	return out
}

// Run plans the cells and runs them.
func Run(ctx context.Context, o Options) (*Result, error) {
	if o.Validator == nil || o.Validator.APIOps == nil {
		return nil, fmt.Errorf("conform: a validator with the api operation list is required")
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	jobs := o.Jobs
	if jobs <= 0 {
		jobs = runtime.NumCPU()
	}
	cells := Plan(o.Corpus, o.Columns, o.Entries, o.Levels)
	byCol := map[string][]*Cell{}
	for _, c := range cells {
		byCol[c.Column.ID] = append(byCol[c.Column.ID], c)
	}
	// No core files from drivers that abort: the limit is inherited by every child.
	syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
	res := &Result{Started: time.Now()}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, jobs)
		obs []*Observation
	)
	for _, col := range o.Columns {
		col := col
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cr, colObs := runColumn(ctx, &o, col, byCol[col.ID])
			mu.Lock()
			res.Columns = append(res.Columns, cr)
			obs = append(obs, colObs...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.SliceStable(obs, func(i, j int) bool { return obs[i].Cell.less(obs[j].Cell) })
	sort.Slice(res.Columns, func(i, j int) bool { return res.Columns[i].Column.ID < res.Columns[j].Column.ID })
	res.Observations = obs
	res.Wall = time.Since(res.Started)
	return res, ctx.Err()
}

// runColumn runs one column's cells serially.
func runColumn(ctx context.Context, o *Options, col *Column, cells []*Cell) (*ColumnRun, []*Observation) {
	cr := &ColumnRun{Column: col}
	out := make([]*Observation, 0, len(cells))
	var batch *driverProc
	fail := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		cr.Errors = append(cr.Errors, msg)
		fmt.Fprintf(o.Log, "conform: %s: %s\n", col.ID, msg)
	}
	start := func(cell *Cell) (*driverProc, error) {
		cr.Processes++
		limits := o.Limits
		if as, ok := o.ColumnAddressSpace[col.ID]; ok {
			limits.AddressSpaceMax = as
		}
		if cell.AddressSpaceMax > 0 {
			limits.AddressSpaceMax = cell.AddressSpaceMax
		}
		d, err := startDriver(ctx, o.Sets, col, limits, o.Validator, cr.Processes)
		if err != nil {
			return nil, err
		}
		if cr.Describe == nil {
			cr.Describe, cr.DescribeRaw = d.Describe, d.DescribeRaw
		}
		return d, nil
	}
	stop := func(d *driverProc) {
		if err := d.shutdown(ctx); err != nil && ctx.Err() == nil {
			fail("process %d: shutdown: %v", d.seq, err)
		}
	}
	broken := ""
	for i, cell := range cells {
		ob := &Observation{Cell: cell}
		out = append(out, ob)
		if broken != "" {
			ob.NotRun = broken
			continue
		}
		if ctx.Err() != nil {
			ob.NotRun = "canceled"
			continue
		}
		req, err := Request(o.Corpus, cell)
		if err != nil {
			ob.NotRun = err.Error()
			fail("%s %s %s: %v", cell.Entry.ID, cell.VariantKey, cell.Level, err)
			continue
		}
		if batch != nil && !cell.Isolate && !batch.alive() {
			// It answered its last request and then exited: a driver bug, not this cell's outcome.
			r := batch.child.Wait()
			fail("process %d exited between requests (exit %d%s) without being asked to shut down", batch.seq, r.ExitCode, sigSuffix(sigName(r.Signal)))
			batch = nil
		}
		for attempt := 1; ; attempt++ {
			d := batch
			if cell.Isolate || d == nil {
				if d, err = start(cell); err != nil {
					broken = err.Error()
					ob.NotRun = broken
					fail("%v; %d cell(s) not run", err, len(cells)-i)
					break
				}
				if !cell.Isolate {
					batch = d
				}
			}
			ob.Describe = d.Describe
			if !d.Describe.HasLevel(cell.Level) {
				ob.Outcome, ob.Reason, ob.Source = "n_a", "level_not_supported", "orchestrator"
			} else {
				runCell(ctx, d, req, ob)
			}
			if c := ob.Crash; c != nil && c.ExitCode == 0 && c.Signal == "" && !c.TimedOut && !c.MemoryCapHit {
				// Status 0 without an answer is the driver quitting (usually right after answering the previous
				// request, before its exit was seen), not an SDK fault: retry once on a fresh process.
				fail("process %d exited with status 0 instead of answering %s %s %s", d.seq, cell.Entry.ID, cell.VariantKey, cell.Level)
				if !cell.Isolate {
					batch = nil
				}
				if attempt == 1 {
					*ob = Observation{Cell: cell}
					continue
				}
				ob.Outcome, ob.Reason, ob.Source = "", "", ""
				ob.ProtocolError = "the driver exits with status 0 instead of answering this request"
			}
			if ob.ProtocolError != "" {
				fail("process %d: %s %s %s: %s", d.seq, cell.Entry.ID, cell.VariantKey, cell.Level, ob.ProtocolError)
			}
			dead := ob.Crash != nil || ob.ProtocolError != ""
			switch {
			case cell.Isolate && !dead:
				stop(d)
			case cell.Isolate:
			case dead:
				batch = nil // the next cell starts a fresh process
			}
			break
		}
	}
	if batch != nil {
		stop(batch)
	}
	return cr, out
}

// runCell sends one request and records what happened.
func runCell(ctx context.Context, d *driverProc, req *RunRequest, ob *Observation) {
	ob.Request, ob.Process = req, d.seq
	t0 := time.Now()
	var size int64
	if v := ob.Cell.Variant; v != nil {
		size = v.Blob.Bytes
	}
	resp, line, crash, err := d.run(ctx, req, d.limits.RequestTimeout(size))
	ob.WallMS = float64(time.Since(t0).Microseconds()) / 1000
	if err == nil && crash == nil {
		err = CheckEvidence(ob.Cell, req, d.Describe, resp, line)
	}
	switch {
	case err != nil && IsProtocolError(err):
		pe := err.(*ProtocolError)
		ob.ProtocolError, ob.BadLine = pe.Msg, string(pe.Line)
		d.kill("protocol error")
	case err != nil:
		ob.NotRun = err.Error()
	case crash != nil:
		ob.Crash = crash
		ob.Outcome, ob.Reason, ob.Source = "crash", crash.Reason, "orchestrator"
	default:
		ob.Response, ob.ResponseRaw = resp, line
		ob.Outcome, ob.Reason, ob.Source = resp.OutcomeString(), resp.ReasonCode(), "driver"
	}
}
