package main

// xdrcheck mutate (docs/mutation.md): structure-aware mutants of corpus values, through every conformance column
// and replay adapter, judged against the oracle and stellar-core, triaged into candidates.
//
//	xdrcheck mutate run      [--seed N] [--budget N] [--columns all|GLOBS|none] [--set NAME] [--adapters all|none|NAME,…]
//	                    [--entries GLOB,…] [--classes valid,metamorphic,wire-invalid] [--mutators ID,…]
//	                    [--max-bytes N] [--stale-hashes] [--no-cut] [--no-suppress] [--minimise N]
//	                    [--timeout D] [--memory-max SIZE] [--as-limit SIZE|GLOB=SIZE,…] [--adapter-memory-max SIZE] [--adapter-deadline D]
//	                    [--adapter-parallel N] [--jobs N] [--work DIR] [--report DIR] [--overlay DIR]
//	xdrcheck mutate replay   --entry SOURCE [--variant N] --seed N --mutation ID[,ID…] [--readers R,…|columns|all]
//	                    [--print READER] [--stale-hashes] [--work DIR]
//	xdrcheck mutate minimise --entry SOURCE [--variant N] --seed N --mutation ID,ID… --reader R [--work DIR]
//	xdrcheck mutate promote  --entry SOURCE [--variant N] --seed N --mutation ID[,ID…] --id NEW_ID [--into DIR] [--public]
//
// The mutation and oracle half is the xdrcheck-mutate binary ($XDRCHECK_MUTATE_BIN, else target/release/xdrcheck-mutate):
// it writes the mutants as a corpus of their own (entries mut/<mutant> and the unmutated controls
// mutctl/<source>/v<variant>), which the conformance runner and the replay harness read unchanged. Work files,
// reports and candidate records are written outside the repository: candidates go to the private overlay
// (<overlay>/mutate/candidates, the overlay being --overlay, $XDRCHECK_OVERLAY or ~/.local/share/xdrcheck/overlay).
//
// Exit codes: 0 the run is whole (candidates may have been found); 2 our own tooling failed somewhere (the
// mutation engine, the oracle check of a mutant, a driver protocol error, a harness fault) or a cell ended in
// no known verdict.

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/mutate"
	"github.com/tolgayayci/xdrcheck/go/internal/userdir"
)

func init() {
	register("mutate", "structure-aware mutants of corpus values through every reader", func(args []string) int {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return mutateMain(ctx, args, os.Stdout, os.Stderr)
	})
}

func mutateMain(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(stderr, "usage: xdrcheck mutate run|replay|minimise|promote [flags]")
		return 2
	}
	switch args[0] {
	case "run":
		return mutateRun(ctx, args[1:], stdout, stderr)
	case "replay":
		return mutateReplay(ctx, args[1:], stdout, stderr)
	case "minimise", "minimize":
		return mutateMinimise(ctx, args[1:], stdout, stderr)
	case "promote":
		return mutatePromote(ctx, args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "xdrcheck mutate: unknown subcommand %q\n", args[0])
	return 2
}

// adapterSpec is one replay adapter the mutants are fed to.
type adapterSpec struct {
	name, version, reader string
	argv                  string
}

// mutEnv is what every subcommand shares.
type mutEnv struct {
	conf    *conformEnv
	bin     string
	overlay string
	limits  conform.Limits
	// columnAS is the per-column address-space cap of --as-limit GLOB=SIZE.
	columnAS map[string]int64
	jobs     int

	adapterParallel int
	adapterMem      string
	adapterDeadline time.Duration
	adapters        map[string]adapterSpec
	log             io.Writer
	// runColumns is every column of the run, comma-separated: the readers a split is decided among again.
	runColumns string
}

func columnIDs(cols []*conform.Column) string {
	ids := make([]string, len(cols))
	for i, c := range cols {
		ids[i] = c.ID
	}
	return strings.Join(ids, ",")
}

type mutFlags struct {
	fs                                        *flag.FlagSet
	pins, overlay, work, bin                  string
	timeout, adapterDeadline                  time.Duration
	memMax, adapterMem                        sizeFlag
	asMax                                     asLimitFlag
	jobs, adapterParallel                     int
	entries, mutation, readers, print, source string
	variant                                   int
	seed                                      uint64
	stale                                     bool
}

func newMutFlags(name string) *mutFlags {
	f := &mutFlags{fs: flag.NewFlagSet("xdrcheck mutate "+name, flag.ContinueOnError)}
	f.memMax = 1 << 30
	f.adapterMem = 4 << 30
	f.fs.StringVar(&f.pins, "pins", "", "pins file (default pins.toml at the repository root)")
	f.fs.StringVar(&f.overlay, "overlay", "", "private overlay directory (default $XDRCHECK_OVERLAY, else ~/.local/share/xdrcheck/overlay)")
	f.fs.StringVar(&f.work, "work", "", "work directory for the mutant corpus and the runners' reports (outside the repository)")
	f.fs.StringVar(&f.bin, "mutate-bin", "", "the xdrcheck-mutate binary (default $XDRCHECK_MUTATE_BIN, else target/release/xdrcheck-mutate)")
	f.fs.DurationVar(&f.timeout, "timeout", conform.DefaultTimeout, "per-request base timeout of a driver")
	f.fs.Var(&f.memMax, "memory-max", "memory cap per driver process (0 = none)")
	f.fs.Var(&f.asMax, "as-limit", "address-space cap (RLIMIT_AS) per driver process: SIZE for every column, or GLOB=SIZE,… per column (0 = none)")
	f.fs.Var(&f.adapterMem, "adapter-memory-max", "memory cap for an adapter's process group")
	f.fs.DurationVar(&f.adapterDeadline, "adapter-deadline", 0, "ingest deadline per replay unit (default: sized from the adapter's describe)")
	f.fs.IntVar(&f.jobs, "jobs", 0, "conformance columns run in parallel (default the number of CPUs)")
	f.fs.IntVar(&f.adapterParallel, "adapter-parallel", 4, "replay units run at once per adapter")
	f.fs.Uint64Var(&f.seed, "seed", 1, "seed")
	f.fs.BoolVar(&f.stale, "stale-hashes", false, "leave ledger hashes stale after a valid-preserving mutation")
	return f
}

func (f *mutFlags) oneMutantFlags() {
	f.fs.StringVar(&f.source, "entry", "", "the mutant's source: an entry ID, or <entry>#<path> for a value cut from a ledger")
	f.fs.IntVar(&f.variant, "variant", 0, "the source's variant index")
	f.fs.StringVar(&f.mutation, "mutation", "", "mutation IDs, comma-separated, in order")
}

func (f *mutFlags) env(stderr io.Writer) (*mutEnv, error) {
	conf, err := loadConformEnv(f.pins, "")
	if err != nil {
		return nil, err
	}
	bin := cmp.Or(f.bin, os.Getenv("XDRCHECK_MUTATE_BIN"), filepath.Join(conf.root, "target", "release", "xdrcheck-mutate"))
	if _, err := os.Stat(bin); err != nil {
		return nil, fmt.Errorf("the mutation engine %s is not built (cargo build --release -p xdrcheck-mutate)", bin)
	}
	overlay := cmp.Or(f.overlay, os.Getenv("XDRCHECK_OVERLAY"))
	if overlay == "" {
		overlay = userdir.Overlay()
	}
	if mutate.Inside(conf.root, overlay) {
		return nil, fmt.Errorf("--overlay %s is inside the repository", overlay)
	}
	e := &mutEnv{
		conf: conf, bin: bin, overlay: overlay, jobs: f.jobs, log: stderr,
		limits:          conform.Limits{Timeout: f.timeout, MemoryMax: int64(f.memMax), AddressSpaceMax: f.asMax.all},
		adapterParallel: max(1, f.adapterParallel), adapterMem: f.adapterMem.String(), adapterDeadline: f.adapterDeadline,
	}
	if len(f.asMax.per) > 0 {
		e.columnAS = map[string]int64{}
		for id := range conf.sets.Columns {
			if n, ok := f.asMax.forColumn(id); ok {
				e.columnAS[id] = n
			}
		}
	}
	short := func(s string) string { return s[:min(12, len(s))] }
	gobin := filepath.Join(conf.root, "go", "bin")
	wb, etl := conf.pins.Pipelines.WalletBackend.Current, conf.pins.Pipelines.StellarETL.Commit
	e.adapters = map[string]adapterSpec{
		"wallet-backend": {name: "wallet-backend", version: wb, reader: "wallet-backend@" + short(wb),
			argv: filepath.Join(gobin, "wallet-backend-adapter") + " --pins " + conf.pinsPath},
		"stellar-etl": {name: "stellar-etl", version: etl, reader: "stellar-etl@" + short(etl), argv: filepath.Join(gobin, "stellaretl") + " --offline"},
		"baseline":    {name: "baseline", version: "0.1.0", reader: "baseline@0.1.0", argv: filepath.Join(gobin, "baseline")},
	}
	return e, nil
}

func (e *mutEnv) workDir(flagValue, name string) (string, error) {
	dir := flagValue
	if dir == "" {
		base := os.Getenv("XDRCHECK_CACHE")
		if base == "" {
			base, _ = userdir.HomeCache()
		}
		dir = filepath.Join(base, "mutate", name)
	}
	if mutate.Inside(e.conf.root, dir) {
		return "", fmt.Errorf("work directory %s is inside the repository; mutants and reports are written outside it", dir)
	}
	return dir, os.MkdirAll(dir, 0o755)
}

func (e *mutEnv) engine(args ...string) ([]byte, error) {
	full := append([]string{"--corpus", filepath.Join(e.conf.root, "corpus")}, args...)
	cmd := exec.Command(e.bin, full...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("xdrcheck-mutate %s: %v: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// build rebuilds one mutant (and its control) into its own mutant corpus under dir.
func (e *mutEnv) build(dir, source string, variant int, seed uint64, ids []string, stale bool, sel []string) (*mutate.Mutant, error) {
	entry, _, _ := strings.Cut(source, "#")
	args := append([]string{"build", "--out", dir, "--source", source, "--variant", fmt.Sprint(variant), "--seed", fmt.Sprint(seed),
		"--mutation", strings.Join(ids, ","), "--entries", entry}, sel...)
	if stale {
		args = append(args, "--stale-hashes")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if _, err := e.engine(args...); err != nil {
		return nil, err
	}
	ms, err := mutate.ReadMutants(filepath.Join(dir, "mutants.ndjson"))
	if err != nil || len(ms) != 1 {
		return nil, fmt.Errorf("xdrcheck-mutate build wrote no mutant record: %v", err)
	}
	return ms[0], nil
}

// readerSel is the readers a run feeds.
type readerSel struct {
	columns  []*conform.Column
	adapters []adapterSpec
}

func (s readerSel) core() string {
	for _, c := range s.columns {
		if c.Kind == "core" {
			return c.ID
		}
	}
	return ""
}

func (e *mutEnv) selectReaders(set, columns, adapters string) (readerSel, error) {
	var sel readerSel
	var err error
	switch columns {
	case "none":
	case "all":
		sel.columns, err = e.conf.sets.Select("all", "")
	default:
		sel.columns, err = e.conf.sets.Select(set, columns)
	}
	if err != nil {
		return sel, err
	}
	switch adapters {
	case "none", "":
	case "all":
		for _, n := range []string{"baseline", "stellar-etl", "wallet-backend"} {
			sel.adapters = append(sel.adapters, e.adapters[n])
		}
	default:
		for _, n := range strings.Split(adapters, ",") {
			a, ok := e.adapters[strings.TrimSpace(n)]
			if !ok {
				return sel, fmt.Errorf("--adapters: unknown adapter %q (wallet-backend, stellar-etl, baseline)", n)
			}
			sel.adapters = append(sel.adapters, a)
		}
	}
	return sel, nil
}

// readersByID resolves a --readers list: column IDs, adapter readers (name or name@version), "columns" (every
// column) or "all".
func (e *mutEnv) readersByID(list string) (readerSel, error) {
	var sel readerSel
	for _, r := range strings.Split(list, ",") {
		r = strings.TrimSpace(r)
		switch {
		case r == "":
		case r == "all" || r == "columns":
			cols, err := e.conf.sets.Select("all", "")
			if err != nil {
				return sel, err
			}
			sel.columns = append(sel.columns, cols...)
			if r == "all" {
				for _, n := range []string{"baseline", "stellar-etl", "wallet-backend"} {
					sel.adapters = append(sel.adapters, e.adapters[n])
				}
			}
		case e.conf.sets.Columns[r] != nil:
			sel.columns = append(sel.columns, e.conf.sets.Columns[r])
		default:
			name, _, _ := strings.Cut(r, "@")
			a, ok := e.adapters[name]
			if !ok {
				return sel, fmt.Errorf("--readers: unknown reader %q", r)
			}
			sel.adapters = append(sel.adapters, a)
		}
	}
	return sel, nil
}

// evaluate runs every selected reader over the mutant corpus in dir and returns the cells by entry ID, and
// the failures of our own tooling.
func (e *mutEnv) evaluate(ctx context.Context, dir string, mutants []*mutate.Mutant, sel readerSel) (map[string][]mutate.Cell, []string, error) {
	cells := map[string][]mutate.Cell{}
	var own []string
	corpus, err := manifest.Load(filepath.Join(dir, "corpus"), manifest.Options{})
	if err != nil {
		return nil, nil, fmt.Errorf("the mutant corpus does not load: %w", err)
	}
	if len(sel.columns) > 0 {
		v, err := validator(e.conf.root)
		if err != nil {
			return nil, nil, err
		}
		globs, _ := conform.CompileGlobs("mut/*,mutctl/*")
		res, err := conform.Run(ctx, conform.Options{
			Sets: e.conf.sets, Columns: sel.columns, Corpus: corpus, Entries: globs,
			Levels: map[string]bool{"L0": true, "L1": true}, Jobs: e.jobs, Limits: e.limits, ColumnAddressSpace: e.columnAS, Validator: v, Log: io.Discard,
		})
		if err != nil {
			return nil, nil, err
		}
		res.Apply(verdict.Engine{})
		for _, ie := range res.InfraErrors() {
			own = append(own, "conformance: "+ie)
		}
		for _, o := range res.Observations {
			col := o.Cell.Column
			c := mutate.Cell{Reader: col.ID, Kind: col.Kind, Family: col.SDK, Level: o.Cell.Level}
			switch {
			case o.ProtocolError != "":
				c.OwnFault = "driver protocol error: " + o.ProtocolError
			case o.NotRun != "":
				c.OwnFault = "not run: " + o.NotRun
			default:
				a := verdict.Engine{}.Assess(o)
				c.Verdict = mutate.FromConform(a.Verdict)
				c.Accepted = o.Outcome == "ok" || o.Outcome == "diverge"
				c.Refused = o.Outcome == "reject"
				c.Reason = o.Reason
				if o.Response != nil && o.Response.Actual != nil && o.Response.Actual.ReencodedSHA256 != nil {
					c.Reencoded = *o.Response.Actual.ReencodedSHA256
				}
				d := o.Outcome
				if o.Reason != "" {
					d += "/" + o.Reason
				}
				if len(a.Mismatches) > 0 {
					d += ": " + strings.Join(a.Mismatches, "; ")
				}
				c.Detail = d
			}
			cells[o.Cell.Entry.ID] = append(cells[o.Cell.Entry.ID], c)
		}
	}
	if len(sel.adapters) > 0 {
		// The harness serves a ledger by decoding it; a wire-invalid ledger cannot be delivered, so adapters see
		// the valid-preserving and metamorphic ledger mutants and their controls.
		var ids []string
		seen := map[string]bool{}
		for _, m := range mutants {
			if m.XDRType != "LedgerCloseMeta" || m.Class == mutate.ClassWire || !m.Oracle.Accepts {
				continue
			}
			for _, id := range []string{m.EntryID, deref(m.Control)} {
				if id != "" && !seen[id] {
					seen[id] = true
					ids = append(ids, id)
				}
			}
		}
		sort.Strings(ids)
		for _, a := range sel.adapters {
			if len(ids) == 0 {
				break
			}
			ac, ao, err := e.replayAdapter(ctx, dir, a, ids)
			if err != nil {
				own = append(own, a.reader+": "+err.Error())
				continue
			}
			own = append(own, ao...)
			for id, c := range ac {
				cells[id] = append(cells[id], c...)
			}
		}
	}
	return cells, own, nil
}

// asLimitFlag is --as-limit: one SIZE for every column, or GLOB=SIZE pairs (the first matching glob wins;
// columns no glob matches run without a cap). Node-based drivers cannot start under a small address-space
// cap, so a cap for the Rust and Go columns must leave the JS columns out.
type asLimitFlag struct {
	all  int64
	per  []asLimitRule
	text string
}

type asLimitRule struct {
	glob conform.Globs
	size int64
}

func (a *asLimitFlag) String() string { return a.text }

func (a *asLimitFlag) Set(v string) error {
	*a = asLimitFlag{text: v}
	if !strings.Contains(v, "=") {
		n, err := parseSize(v)
		a.all = n
		return err
	}
	for _, part := range strings.Split(v, ",") {
		glob, size, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return fmt.Errorf("%q: want GLOB=SIZE", part)
		}
		g, err := conform.CompileGlobs(glob)
		if err != nil {
			return err
		}
		n, err := parseSize(size)
		if err != nil {
			return err
		}
		a.per = append(a.per, asLimitRule{g, n})
	}
	return nil
}

// forColumn is the cap of one column, when a glob names it.
func (a *asLimitFlag) forColumn(id string) (int64, bool) {
	for _, r := range a.per {
		if r.glob.Match(id) {
			return r.size, true
		}
	}
	return 0, false
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (e *mutEnv) replayAdapter(ctx context.Context, dir string, a adapterSpec, ids []string) (map[string][]mutate.Cell, []string, error) {
	rep := filepath.Join(dir, "replay-"+a.name)
	os.RemoveAll(rep)
	logf, err := os.Create(rep + ".log")
	if err != nil {
		return nil, nil, err
	}
	defer logf.Close()
	if os.Getenv("XDRCHECK_WB_NAME_PREFIX") == "" {
		os.Setenv("XDRCHECK_WB_NAME_PREFIX", fmt.Sprintf("xdrcheck-m%d", os.Getpid()))
	}
	if os.Getenv("XDRCHECK_OBJSTORE") == "" {
		os.Setenv("XDRCHECK_OBJSTORE", "binary")
	}
	args := []string{"--pins", e.conf.pinsPath, "--corpus", filepath.Join(dir, "corpus"), "--adapter", a.argv,
		"--target-version", a.version, "--entries", strings.Join(ids, ","), "--unit", "single", "--keep-going",
		"--parallel", fmt.Sprint(e.adapterParallel), "--memory-max", e.adapterMem, "--report", rep}
	if e.adapterDeadline > 0 {
		args = append(args, "--deadline", e.adapterDeadline.String())
	}
	code := replay(ctx, args, io.Discard, logf)
	data, err := os.ReadFile(filepath.Join(rep, "report.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("xdrcheck replay exited %d and wrote no report (log %s)", code, rep+".log")
	}
	var doc struct {
		Rows []struct {
			Entry  string `json:"entry"`
			Replay struct {
				Class     string `json:"class"`
				Qualifier string `json:"qualifier"`
			} `json:"replay"`
			Evidence json.RawMessage `json:"evidence"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}
	out := map[string][]mutate.Cell{}
	var own []string
	for _, r := range doc.Rows {
		var ev struct {
			Fault  string `json:"fault"`
			Ingest struct {
				Refusal *json.RawMessage `json:"refusal"`
				Signals struct {
					ExitCode     *int  `json:"exit_code"`
					RuntimePanic *bool `json:"runtime_panic"`
					TermSignal   *int  `json:"term_signal"`
				} `json:"signals"`
			} `json:"ingest"`
		}
		_ = json.Unmarshal(r.Evidence, &ev)
		c := mutate.Cell{Reader: a.reader, Kind: "pipeline", Family: a.name, Level: "replay"}
		if r.Replay.Class == "harness_fault" {
			switch {
			case strings.Contains(ev.Fault, "serving the unit"):
				c.Verdict, c.Detail = mutate.NA, "the harness cannot serve this ledger"
			case strings.Contains(ev.Fault, "unsupported_input"):
				// The adapter declares the input outside what it supports (a network it has no flag for).
				c.Verdict, c.Detail = mutate.NA, "the adapter does not support this input"
			default:
				c.OwnFault = "harness fault: " + firstLine(ev.Fault)
			}
		} else {
			c.Verdict = mutate.FromReplay(r.Replay.Class, r.Replay.Qualifier, ev.Ingest.Refusal != nil)
			c.Accepted = c.Verdict == mutate.Conform
			d := r.Replay.Class
			if r.Replay.Qualifier != "" {
				d += "·" + r.Replay.Qualifier
			}
			if s := ev.Ingest.Signals; s.ExitCode != nil {
				d += fmt.Sprintf(" exit %d", *s.ExitCode)
				if s.RuntimePanic != nil && *s.RuntimePanic {
					d += " panic"
				}
			}
			c.Detail = d
		}
		out[r.Entry] = append(out[r.Entry], c)
	}
	return out, own, nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s[:min(len(s), 240)]
}

// judgeAll decides every mutant's verdicts.
func judgeAll(mutants []*mutate.Mutant, cells map[string][]mutate.Cell) (map[string][]mutate.ReaderVerdict, []string) {
	out := map[string][]mutate.ReaderVerdict{}
	var own []string
	for _, m := range mutants {
		v, o := mutate.Judge(m, cells[m.EntryID], cells[deref(m.Control)])
		out[m.ID] = v
		own = append(own, o...)
	}
	return out, own
}

// oracleFaults lists mutants whose class and oracle answer disagree: a bug of the mutation engine.
func oracleFaults(ms []*mutate.Mutant) []string {
	var out []string
	for _, m := range ms {
		if (m.Class == mutate.ClassWire) == m.Oracle.Accepts {
			out = append(out, fmt.Sprintf("mutation engine: %s mutant %s of %s: oracle accepts=%v (%s)", m.Class, m.ID, m.Source, m.Oracle.Accepts, m.Oracle.Reason))
		}
	}
	return out
}

func loadMutRules(e *mutEnv) (mutate.Rules, error) {
	dirs := []string{filepath.Join(e.conf.root, "findings"), filepath.Join(e.overlay, "findings")}
	pub, err := mutate.LoadRules(filepath.Join(e.conf.root, "crates", "xdrcheck-mutate", "data", "suppressions.json"), dirs...)
	if err != nil {
		return nil, err
	}
	priv, err := mutate.LoadRules(filepath.Join(e.overlay, "mutate", "suppressions.json"), dirs...)
	if err != nil {
		return nil, err
	}
	return append(pub, priv...), nil
}

// minimise reduces a mutant to a single mutation that gives the reader the same verdict, trying each mutation
// alone in order. It returns the minimised mutant and the verdict, or the original when no single mutation does.
func (e *mutEnv) minimise(ctx context.Context, dir string, m *mutate.Mutant, v mutate.ReaderVerdict, sel []string) (*mutate.Mutant, *mutate.ReaderVerdict, error) {
	if len(m.Mutations) < 2 {
		return m, &v, nil
	}
	readers, err := e.readersByID(mutate.ReadersFor(&v, e.coreID(), e.runColumns))
	if err != nil {
		return nil, nil, err
	}
	for i, id := range m.MutationIDs() {
		sub := filepath.Join(dir, fmt.Sprintf("%s-%d", m.ID, i))
		one, err := e.build(sub, m.Source, m.Variant, m.Seed, []string{id}, m.StaleHashes, sel)
		if err != nil {
			continue
		}
		cells, _, err := e.evaluate(ctx, sub, []*mutate.Mutant{one}, readers)
		if err != nil {
			return nil, nil, err
		}
		vs, _ := mutate.Judge(one, cells[one.EntryID], cells[deref(one.Control)])
		for _, w := range vs {
			if w.Reader == v.Reader && w.Verdict == v.Verdict {
				w := w
				return one, &w, nil
			}
		}
	}
	return m, &v, nil
}

func (e *mutEnv) coreID() string {
	for _, c := range e.conf.sets.Columns {
		if c.Kind == "core" {
			return c.ID
		}
	}
	return ""
}

// mutRunReport is report.json of a run.
type mutRunReport struct {
	Schema       string            `json:"schema"`
	Seed         uint64            `json:"seed"`
	Budget       int               `json:"budget"`
	Mutants      int               `json:"mutants"`
	ByClass      map[string]int    `json:"by_class"`
	Readers      []string          `json:"readers"`
	Verdicts     map[string]int    `json:"verdicts"`
	OwnFaults    []string          `json:"own_faults"`
	Unclassified []string          `json:"unclassified"`
	Candidates   []mutRunCandidate `json:"candidates"`
	// ReaderConsensus lists the signatures where every SDK disagrees with the oracle the same way while
	// stellar-core sides with the oracle, apart from the other candidates.
	ReaderConsensus []mutRunCandidate `json:"reader_consensus"`
	Suppressed      []mutRunSuppress  `json:"suppressed"`
	CandidateDir    string            `json:"candidate_dir,omitempty"`
}

type mutRunCandidate struct {
	Signature   string `json:"signature"`
	Hash        string `json:"hash"`
	Occurrences int    `json:"occurrences"`
	Minimised   bool   `json:"minimised"`
	Replay      string `json:"replay"`
	Line        string `json:"verdict_line"`
}

type mutRunSuppress struct {
	Signature   string `json:"signature"`
	Finding     string `json:"finding"`
	Occurrences int    `json:"occurrences"`
}

func mutateRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newMutFlags("run")
	var (
		budget, minimiseMax                               int
		columns, set, adapters, classes, mutators, report string
		maxBytes                                          int
		noCut, noSuppress, allVariants                    bool
	)
	f.fs.IntVar(&budget, "budget", 2000, "mutants to build")
	f.fs.StringVar(&columns, "columns", "all", "conformance columns: all, none, or comma-separated column globs")
	f.fs.StringVar(&set, "set", "", "named column set (with --columns other than all or none)")
	f.fs.StringVar(&adapters, "adapters", "all", "replay adapters: all, none, or wallet-backend,stellar-etl,baseline")
	f.fs.StringVar(&f.entries, "entries", "", "source entry ID globs, comma-separated")
	f.fs.StringVar(&classes, "classes", "valid,metamorphic,wire-invalid", "mutator classes")
	f.fs.StringVar(&mutators, "mutators", "", "mutator IDs (default every mutator of the classes)")
	f.fs.IntVar(&maxBytes, "max-bytes", 256<<10, "largest corpus value used as a source")
	f.fs.BoolVar(&noCut, "no-cut", false, "do not cut envelopes and SCVals out of ledgers as sources")
	f.fs.BoolVar(&allVariants, "all-variants", false, "every variant of an entry, not only the first")
	f.fs.BoolVar(&noSuppress, "no-suppress", false, "report signatures that match existing findings too")
	f.fs.IntVar(&minimiseMax, "minimise", 400, "candidates minimised at most (each costs a run of its readers per mutation)")
	f.fs.StringVar(&report, "report", "", "report directory (default <work>/report)")
	if err := f.fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int { fmt.Fprintf(stderr, "xdrcheck mutate run: %v\n", err); return 2 }
	e, err := f.env(stderr)
	if err != nil {
		return fail(err)
	}
	work, err := e.workDir(f.work, fmt.Sprintf("run-seed%d", f.seed))
	if err != nil {
		return fail(err)
	}
	report = cmp.Or(report, filepath.Join(work, "report"))
	if mutate.Inside(e.conf.root, report) {
		return fail(fmt.Errorf("--report %s is inside the repository", report))
	}
	sel, err := e.selectReaders(set, columns, adapters)
	if err != nil {
		return fail(err)
	}
	e.runColumns = columnIDs(sel.columns)
	selFlags := []string{"--max-bytes", fmt.Sprint(maxBytes)}
	if noCut {
		selFlags = append(selFlags, "--no-cut")
	}
	if allVariants {
		selFlags = append(selFlags, "--all-variants")
	}
	gen := filepath.Join(work, "gen")
	os.RemoveAll(gen)
	if err := os.MkdirAll(gen, 0o755); err != nil {
		return fail(err)
	}
	gargs := append([]string{"gen", "--out", gen, "--seed", fmt.Sprint(f.seed), "--budget", fmt.Sprint(budget),
		"--classes", classes, "--mutators", mutators, "--entries", f.entries}, selFlags...)
	if f.stale {
		gargs = append(gargs, "--stale-hashes")
	}
	start := time.Now()
	if _, err := e.engine(gargs...); err != nil {
		return fail(err)
	}
	mutants, err := mutate.ReadMutants(filepath.Join(gen, "mutants.ndjson"))
	if err != nil {
		return fail(err)
	}
	fmt.Fprintf(stderr, "xdrcheck mutate run: %d mutants built (seed %d) in %s; running %d column(s) and %d adapter(s)\n",
		len(mutants), f.seed, time.Since(start).Round(time.Millisecond), len(sel.columns), len(sel.adapters))
	cells, own, err := e.evaluate(ctx, gen, mutants, sel)
	if err != nil {
		return fail(err)
	}
	own = append(own, oracleFaults(mutants)...)
	verdicts, jo := judgeAll(mutants, cells)
	own = append(own, jo...)

	rep := mutRunReport{Schema: "xcc.mutate.report/v1", Seed: f.seed, Budget: budget, Mutants: len(mutants),
		ByClass: map[string]int{}, Verdicts: map[string]int{}, OwnFaults: own, Unclassified: []string{}}
	for _, c := range sel.columns {
		rep.Readers = append(rep.Readers, c.ID)
	}
	for _, a := range sel.adapters {
		rep.Readers = append(rep.Readers, a.reader)
	}
	byID := map[string]*mutate.Mutant{}
	for _, m := range mutants {
		byID[m.ID] = m
		rep.ByClass[m.Class]++
	}
	rules := mutate.Rules(nil)
	if !noSuppress {
		if rules, err = loadMutRules(e); err != nil {
			return fail(err)
		}
	}
	// Group candidate verdicts by their pre-minimisation signature; minimise one representative per group.
	type group struct {
		sig     mutate.Signature
		members []mutate.ReaderVerdict
	}
	groups := map[string]*group{}
	for _, m := range mutants {
		for _, v := range verdicts[m.ID] {
			rep.Verdicts[v.Verdict]++
			if !mutate.Known[v.Verdict] {
				rep.Unclassified = append(rep.Unclassified, m.ID+" "+v.Reader+": "+v.Verdict)
				continue
			}
			if !mutate.Candidates[v.Verdict] {
				continue
			}
			s := mutate.SignatureOf(m, &v)
			g := groups[s.String()]
			if g == nil {
				g = &group{sig: s}
				groups[s.String()] = g
			}
			g.members = append(g.members, v)
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	final := map[string]*mutate.Candidate{}
	suppressed := map[string]*mutRunSuppress{}
	minimised := 0
	minDir := filepath.Join(work, "minimise")
	os.RemoveAll(minDir)
	for _, k := range keys {
		g := groups[k]
		sort.SliceStable(g.members, func(i, j int) bool {
			a, b := byID[g.members[i].Mutant], byID[g.members[j].Mutant]
			if len(a.Mutations) != len(b.Mutations) {
				return len(a.Mutations) < len(b.Mutations)
			}
			return a.ID < b.ID
		})
		rv := g.members[0]
		m := byID[rv.Mutant]
		vv := &rv
		if len(m.Mutations) > 1 && minimised < minimiseMax {
			minimised++
			if mm, mv, err := e.minimise(ctx, minDir, m, rv, selFlags); err == nil {
				m, vv = mm, mv
			} else {
				own = append(own, "minimise "+m.ID+": "+err.Error())
			}
		}
		s := mutate.SignatureOf(m, vv)
		if r := rules.Match(s); r != nil {
			sp := suppressed[s.String()]
			if sp == nil {
				sp = &mutRunSuppress{Signature: s.String(), Finding: r.Finding}
				suppressed[s.String()] = sp
			}
			sp.Occurrences += len(g.members)
			continue
		}
		c := final[s.String()]
		if c == nil {
			readers := mutate.ReadersFor(vv, sel.core(), e.runColumns)
			c = &mutate.Candidate{Schema: mutate.CandidateSchema, Signature: s, SigHash: s.Hash(), Verdict: *vv, Line: vv.Line(),
				Mutant: m, Minimised: len(m.Mutations) == 1, Readers: readers,
				Replay: mutate.ReplayCommand(m, readers) + " --print '" + vv.Reader + "'", Run: fmt.Sprintf("seed %d budget %d", f.seed, budget)}
			final[s.String()] = c
		}
		c.Occurrences += len(g.members)
		for _, mv := range g.members {
			c.Mutants = append(c.Mutants, mv.Mutant)
		}
	}
	var cs []*mutate.Candidate
	for _, c := range final {
		cs = append(cs, c)
	}
	mutate.SortCandidates(cs)
	candDir := filepath.Join(e.overlay, "mutate", "candidates")
	if len(cs) > 0 {
		if err := mutate.WriteCandidates(candDir, e.conf.root, cs); err != nil {
			return fail(err)
		}
		rep.CandidateDir = candDir
	}
	rep.ReaderConsensus = []mutRunCandidate{}
	for _, c := range cs {
		rc := mutRunCandidate{Signature: c.Signature.String(), Hash: c.SigHash, Occurrences: c.Occurrences,
			Minimised: c.Minimised, Replay: c.Replay, Line: c.Line}
		if c.Signature.Verdict == mutate.ReaderConsensus {
			rep.ReaderConsensus = append(rep.ReaderConsensus, rc)
		} else {
			rep.Candidates = append(rep.Candidates, rc)
		}
	}
	for _, s := range suppressed {
		rep.Suppressed = append(rep.Suppressed, *s)
	}
	sort.Slice(rep.Suppressed, func(i, j int) bool { return rep.Suppressed[i].Signature < rep.Suppressed[j].Signature })
	rep.OwnFaults = own
	if rep.OwnFaults == nil {
		rep.OwnFaults = []string{}
	}
	if err := writeMutReport(report, &rep); err != nil {
		return fail(err)
	}
	if err := writeVerdicts(filepath.Join(report, "verdicts.ndjson"), mutants, verdicts); err != nil {
		return fail(err)
	}
	fmt.Fprintf(stdout, "xdrcheck mutate run: %d mutants, %d reader(s); verdicts %s; %d candidate signature(s), %d reader-consensus signature(s), %d suppressed; %d own fault(s), %d unclassified; report %s\n",
		len(mutants), len(rep.Readers), countList(rep.Verdicts), len(rep.Candidates), len(rep.ReaderConsensus), len(rep.Suppressed), len(rep.OwnFaults), len(rep.Unclassified), report)
	for _, c := range rep.Candidates {
		fmt.Fprintf(stdout, "  %s  x%d  %s\n", c.Signature, c.Occurrences, c.Replay)
	}
	if len(rep.ReaderConsensus) > 0 {
		fmt.Fprintln(stdout, "reader consensus (every SDK against the oracle, stellar-core with the oracle):")
		for _, c := range rep.ReaderConsensus {
			fmt.Fprintf(stdout, "  %s  x%d  %s\n", c.Signature, c.Occurrences, c.Replay)
		}
	}
	if len(rep.OwnFaults) > 0 || len(rep.Unclassified) > 0 {
		for _, o := range append(rep.OwnFaults, rep.Unclassified...) {
			fmt.Fprintf(stderr, "  %s\n", o)
		}
		return 2
	}
	return 0
}

func countList(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// writeVerdicts writes every (mutant, reader) verdict line, mutants in plan order.
func writeVerdicts(path string, ms []*mutate.Mutant, vs map[string][]mutate.ReaderVerdict) error {
	var b strings.Builder
	for _, m := range ms {
		for _, v := range vs[m.ID] {
			b.WriteString(v.Line())
			b.WriteByte('\n')
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func writeMutReport(dir string, r *mutRunReport) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), append(b, '\n'), 0o644); err != nil {
		return err
	}
	var md strings.Builder
	fmt.Fprintf(&md, "# xdrcheck mutate run (seed %d)\n\n%d mutants (%s) through %d readers.\n\n", r.Seed, r.Mutants, countList(r.ByClass), len(r.Readers))
	fmt.Fprintf(&md, "Verdicts: %s.\n\nOwn-tool faults: %d. Unclassified verdicts: %d.\n\n", countList(r.Verdicts), len(r.OwnFaults), len(r.Unclassified))
	fmt.Fprintf(&md, "## Candidates (%d signatures)\n\n", len(r.Candidates))
	for _, c := range r.Candidates {
		fmt.Fprintf(&md, "- `%s` x%d\n  `%s`\n", c.Signature, c.Occurrences, c.Replay)
	}
	fmt.Fprintf(&md, "\n## Reader consensus (%d signatures)\n\nEvery SDK that ran disagrees with the oracle the same way; stellar-core sides with the oracle.\n\n", len(r.ReaderConsensus))
	for _, c := range r.ReaderConsensus {
		fmt.Fprintf(&md, "- `%s` x%d\n  `%s`\n", c.Signature, c.Occurrences, c.Replay)
	}
	fmt.Fprintf(&md, "\n## Suppressed (%d signatures)\n\n", len(r.Suppressed))
	for _, s := range r.Suppressed {
		fmt.Fprintf(&md, "- `%s` x%d (%s)\n", s.Signature, s.Occurrences, s.Finding)
	}
	return os.WriteFile(filepath.Join(dir, "REPORT.md"), []byte(md.String()), 0o644)
}

func (f *mutFlags) oneMutant(e *mutEnv, name string) (string, []string, error) {
	if f.source == "" || f.mutation == "" {
		return "", nil, errors.New("--entry and --mutation are required")
	}
	work, err := e.workDir(f.work, name)
	if err != nil {
		return "", nil, err
	}
	return work, strings.Split(f.mutation, ","), nil
}

// sourceSelect is the engine's source selection for one mutant: a value cut from a ledger needs cutting on.
func sourceSelect() []string { return []string{"--max-bytes", fmt.Sprint(64 << 20)} }

func mutateReplay(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newMutFlags("replay")
	f.oneMutantFlags()
	f.fs.StringVar(&f.readers, "readers", "all", "readers: column IDs and adapters (name or name@version), 'columns' or 'all'")
	f.fs.StringVar(&f.print, "print", "", "print only this reader's verdict line")
	if err := f.fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int { fmt.Fprintf(stderr, "xdrcheck mutate replay: %v\n", err); return 2 }
	e, err := f.env(stderr)
	if err != nil {
		return fail(err)
	}
	work, ids, err := f.oneMutant(e, fmt.Sprintf("replay-%d", os.Getpid()))
	if err != nil {
		return fail(err)
	}
	if f.work == "" {
		defer os.RemoveAll(work)
	}
	sel, err := e.readersByID(f.readers)
	if err != nil {
		return fail(err)
	}
	m, err := e.build(filepath.Join(work, "mutant"), f.source, f.variant, f.seed, ids, f.stale, sourceSelect())
	if err != nil {
		return fail(err)
	}
	cells, own, err := e.evaluate(ctx, filepath.Join(work, "mutant"), []*mutate.Mutant{m}, sel)
	if err != nil {
		return fail(err)
	}
	vs, jo := mutate.Judge(m, cells[m.EntryID], cells[deref(m.Control)])
	own = append(own, jo...)
	own = append(own, oracleFaults([]*mutate.Mutant{m})...)
	printed := 0
	for _, v := range vs {
		if f.print != "" && v.Reader != f.print {
			continue
		}
		fmt.Fprintln(stdout, v.Line())
		printed++
	}
	for _, o := range own {
		fmt.Fprintf(stderr, "  own fault: %s\n", o)
	}
	if len(own) > 0 || printed == 0 {
		return 2
	}
	return 0
}

func mutateMinimise(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newMutFlags("minimise")
	f.oneMutantFlags()
	var reader string
	f.fs.StringVar(&reader, "reader", "", "the reader whose verdict is kept")
	f.fs.StringVar(&f.readers, "readers", "", "readers to judge with (default the reader and the stellar-core column; a split needs the run's columns)")
	if err := f.fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int { fmt.Fprintf(stderr, "xdrcheck mutate minimise: %v\n", err); return 2 }
	if reader == "" {
		return fail(errors.New("--reader is required"))
	}
	e, err := f.env(stderr)
	if err != nil {
		return fail(err)
	}
	work, ids, err := f.oneMutant(e, fmt.Sprintf("minimise-%d", os.Getpid()))
	if err != nil {
		return fail(err)
	}
	if f.work == "" {
		defer os.RemoveAll(work)
	}
	m, err := e.build(filepath.Join(work, "full"), f.source, f.variant, f.seed, ids, f.stale, sourceSelect())
	if err != nil {
		return fail(err)
	}
	probe := mutate.ReaderVerdict{Reader: reader}
	list := mutate.ReadersFor(&probe, e.coreID(), "")
	if f.readers != "" {
		// A split is decided among every column the run had.
		list = f.readers
	}
	sel, err := e.readersByID(list)
	if err != nil {
		return fail(err)
	}
	e.runColumns = columnIDs(sel.columns)
	cells, _, err := e.evaluate(ctx, filepath.Join(work, "full"), []*mutate.Mutant{m}, sel)
	if err != nil {
		return fail(err)
	}
	vs, _ := mutate.Judge(m, cells[m.EntryID], cells[deref(m.Control)])
	var target *mutate.ReaderVerdict
	for i := range vs {
		if vs[i].Reader == reader {
			target = &vs[i]
		}
	}
	if target == nil {
		return fail(fmt.Errorf("reader %s gave no verdict on the mutant", reader))
	}
	mm, mv, err := e.minimise(ctx, filepath.Join(work, "min"), m, *target, sourceSelect())
	if err != nil {
		return fail(err)
	}
	fmt.Fprintf(stdout, "%s\n", mv.Line())
	fmt.Fprintf(stdout, "%s\n", mutate.ReplayCommand(mm, mutate.ReadersFor(mv, e.coreID(), e.runColumns)))
	return 0
}

func mutatePromote(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newMutFlags("promote")
	f.oneMutantFlags()
	var id, into string
	var public bool
	f.fs.StringVar(&id, "id", "", "the new entry's ID")
	f.fs.StringVar(&into, "into", "", "corpus root to write into (default <overlay>/corpus)")
	f.fs.BoolVar(&public, "public", false, "allow writing into the repository's corpus (the ID must then be in corpus/plan.json)")
	if err := f.fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int { fmt.Fprintf(stderr, "xdrcheck mutate promote: %v\n", err); return 2 }
	if id == "" || f.source == "" || f.mutation == "" {
		return fail(errors.New("--id, --entry and --mutation are required"))
	}
	e, err := f.env(stderr)
	if err != nil {
		return fail(err)
	}
	into = cmp.Or(into, filepath.Join(e.overlay, "corpus"))
	if mutate.Inside(e.conf.root, into) {
		if !public {
			return fail(fmt.Errorf("--into %s is inside the repository; pass --public to promote into the public corpus", into))
		}
		plan, err := os.ReadFile(filepath.Join(e.conf.root, "corpus", "plan.json"))
		if err != nil || !bytes.Contains(plan, []byte(`"`+id+`"`)) {
			return fail(fmt.Errorf("%s is not in corpus/plan.json; a public entry ID must be planned first", id))
		}
	}
	args2 := append([]string{"promote", "--into", into, "--id", id, "--source", f.source, "--variant", fmt.Sprint(f.variant),
		"--seed", fmt.Sprint(f.seed), "--mutation", f.mutation}, sourceSelect()...)
	if f.stale {
		args2 = append(args2, "--stale-hashes")
	}
	out, err := e.engine(args2...)
	if err != nil {
		return fail(err)
	}
	stdout.Write(out)
	_ = ctx
	return 0
}
