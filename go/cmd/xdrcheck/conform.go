package main

// `xdrcheck conform` (docs/cli.md; the driver protocol and its evidence rules: docs/driver-protocol.md and
// docs/conformance-protocol.md).
//
//	xdrcheck conform fetch     [--columns GLOB | --set NAME]     the only networked step: make fetch per driver directory
//	xdrcheck conform build     [--columns GLOB | --set NAME]     offline: make build per driver directory
//	xdrcheck conform run       [--columns GLOB | --set NAME] [--entries GLOB] [--levels L0,…] [--tier curated|bulk]
//	                      [--jobs N] [--timeout DUR] [--memory-max SIZE] [--as-limit SIZE] [--report DIR]
//	                      [--overlay DIR]                    with an overlay, its corpus/ is merged with the public one
//	                      [--expected-failures FILE | --write-expected-failures FILE]
//	                                                         one column's expected-failure list: the run passes only
//	                                                         when its failing cells are exactly the list
//	                      [--require-all-read]               fail when a column never read a selected entry variant
//	                      The run prints the summary (SUMMARY.md: what is wrong, expected value, repro) first.
//	xdrcheck conform describe  [--columns GLOB]
//	xdrcheck conform check     [--mode development|acceptance] [--overlay DIR] [--pending FILE] <matrix.json>
//	                                                         exit 1 on undeclared / unexpected-conform / known-changed
//	                                                         cells; undeclared cells pending a finding are reported
//	                                                         and, in development mode, do not fail (conform_check.go)
//	xdrcheck conform sdk-regression      [--report DIR] [--timeout DUR]     the sdk-regression acceptance assertions on the JS pins (conform_sdk_regression.go)
//	xdrcheck conform diff      <matrix-a> <matrix-b>              cells whose verdict or check changed; exit 1 if any
//	xdrcheck conform readiness [--protocol N] [--report DIR] [matrix.json]
//	                                                         which pinned SDK versions decode each protocol's and
//	                                                         CAP's shapes; readiness.md and .json (conform_views.go)
//	xdrcheck conform scoreboard --report DIR [--matrix FILE] [--replay FILE]… [--findings DIR]
//	                                                         scoreboard.html: per implementation, bug classes and
//	                                                         the public filed findings (conform_views.go)
//	xdrcheck conform siblings  (--finding ID | --divergence URL) [--matrix FILE] [--manual FILE]… [--overlay DIR] [--plan] …
//	                                                         sibling drafts for the other SDK families; prints the
//	                                                         commands that would file them and runs none (conform_siblings.go)
//
// Every subcommand also takes --pins FILE (default pins.toml at the repository root). The repository root is
// the nearest directory, from the working directory up, that holds drivers/sets.toml; XDRCHECK_SETS names another
// sets file; with $XDRCHECK_OVERLAY (or run --overlay) set, the overlay's drivers/sets.toml is merged in. Exit codes: 0 every cell as expected; 1 an unexpected verdict; 2 the tool could not run (bad
// arguments, a driver that does not start or breaks the protocol, a describe that does not match its pin).

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
	"github.com/tolgayayci/xdrcheck/go/internal/findings"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/pins"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

func init() {
	register("conform", "run the corpus through SDK conformance drivers", conformMain)
}

func conformMain(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "usage: xdrcheck conform fetch|build|run|describe|check|sdk-regression|diff|readiness|scoreboard|siblings [flags]")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sub, rest := args[0], args[1:]
	switch sub {
	case "fetch", "build":
		return conformMake(ctx, sub, rest)
	case "run":
		return conformRun(ctx, rest)
	case "describe":
		return conformDescribe(ctx, rest)
	case "check":
		return conformCheck(rest)
	case "sdk-regression":
		return conformSDKRegression(ctx, rest)
	case "diff":
		return conformDiff(rest)
	case "readiness":
		return conformReadiness(rest)
	case "scoreboard":
		return conformScoreboard(rest)
	case "siblings":
		return conformSiblings(rest, os.Stdout, os.Stderr)
	}
	fmt.Fprintf(os.Stderr, "xdrcheck conform: unknown subcommand %q\n", sub)
	return 2
}

// conformEnv is what every subcommand loads: the repository root, the pins and the column sets.
type conformEnv struct {
	root     string
	pinsPath string
	pins     *pins.Pins
	sets     *conform.Sets
}

// loadConformEnv finds the repository root and loads its pins and column sets. When overlay names a private
// overlay directory with a sets file (drivers/sets.toml under it), that file's columns and sets are merged in.
func loadConformEnv(pinsFlag, overlay string) (*conformEnv, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	root := ""
	for d := wd; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "drivers", "sets.toml")); err == nil {
			root = d
			break
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	if root == "" {
		return nil, errors.New("no drivers/sets.toml in the working directory or above it; run from the repository")
	}
	env := &conformEnv{root: root, pinsPath: pinsFlag}
	if env.pinsPath == "" {
		env.pinsPath = filepath.Join(root, "pins.toml")
	}
	if env.pins, err = pins.Load(env.pinsPath); err != nil {
		return nil, err
	}
	setsPath := os.Getenv("XDRCHECK_SETS")
	if setsPath == "" {
		setsPath = filepath.Join(root, "drivers", "sets.toml")
	}
	if env.sets, err = conform.LoadSetsWithOverlay(setsPath, root, overlay); err != nil {
		return nil, err
	}
	if err := env.sets.CheckPins(env.pins); err != nil {
		return nil, fmt.Errorf("%s: %w", setsPath, err)
	}
	return env, nil
}

type commonFlags struct {
	fs      *flag.FlagSet
	name    string
	pins    string
	overlay string
	set     string
	columns string
	sdk     string
}

func newFlags(name string, withSet bool) *commonFlags {
	c := &commonFlags{fs: flag.NewFlagSet("xdrcheck conform "+name, flag.ContinueOnError), name: name}
	c.fs.StringVar(&c.pins, "pins", "", "pins file (default pins.toml at the repository root)")
	ovHelp := "private overlay directory (only xdrcheck conform run and xdrcheck conform check read one)"
	if name == "run" {
		ovHelp = "private overlay directory, required to run a column of its sets file (default $XDRCHECK_OVERLAY for those); its corpus/ (manifests, blobs, sidecars) is merged with the public corpus, and the report must be written outside the working tree"
	}
	c.fs.StringVar(&c.overlay, "overlay", c.overlay, ovHelp)
	c.fs.StringVar(&c.columns, "columns", "", "comma-separated column globs, for example 'js@17.*,go@*'")
	c.fs.Func("column", "one SDK's columns by name, for example soroban-spec (every version and profile of it); repeatable", func(s string) error {
		if s == "" || strings.ContainsAny(s, "@,*") {
			return fmt.Errorf("--column takes an SDK name without a version, for example soroban-spec")
		}
		c.columns = strings.Trim(c.columns+","+s+"@*", ",")
		return nil
	})
	if withSet {
		c.fs.StringVar(&c.set, "set", "", "named column set from drivers/sets.toml (default "+conform.DefaultSet+")")
	}
	if name == "fetch" || name == "build" || name == "run" || name == "describe" {
		c.fs.StringVar(&c.sdk, "sdk", "", "build and run the selected columns from this SDK checkout instead of their pinned package (one SDK's columns, for example --column go --sdk ../go-stellar-sdk); fetch, build and run all need it")
	}
	return c
}

// withSource applies --sdk to the selected columns: they build from the checkout in a private copy of their
// driver directory, and (run, describe) must have been built from it.
func (c *commonFlags) withSource(sets *conform.Sets, cols []*conform.Column) ([]*conform.Column, error) {
	if c.sdk == "" {
		return cols, nil
	}
	cols, err := sets.WithSource(cols, c.sdk)
	if err != nil {
		return nil, err
	}
	if c.name == "run" || c.name == "describe" {
		for _, col := range cols {
			if err := sets.CheckSource(col); err != nil {
				return nil, err
			}
		}
	}
	return cols, nil
}

func (c *commonFlags) parse(args []string) bool {
	if err := c.fs.Parse(args); err != nil {
		return false
	}
	if c.fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "%s: unexpected arguments %q\n", c.fs.Name(), c.fs.Args())
		return false
	}
	if c.overlay != "" && c.name != "run" {
		fmt.Fprintf(os.Stderr, "%s: --overlay is read only by xdrcheck conform run and xdrcheck conform check\n", c.fs.Name())
		return false
	}
	return true
}

func conformMake(ctx context.Context, target string, args []string) int {
	f := newFlags(target, true)
	if !f.parse(args) {
		return 2
	}
	env, err := loadConformEnv(f.pins, os.Getenv("XDRCHECK_OVERLAY"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "xdrcheck conform %s: %v\n", target, err)
		return 2
	}
	cols, err := env.sets.Select(f.set, f.columns)
	if err == nil {
		cols, err = f.withSource(env.sets, cols)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "xdrcheck conform %s: %v\n", target, err)
		return 2
	}
	o := conform.MakeOptions{Sets: env.sets, Columns: cols, PinsPath: env.pinsPath, Stdout: os.Stderr, Stderr: os.Stderr}
	run := conform.Fetch
	if target == "build" {
		run = conform.Build
	}
	if err := run(ctx, o); err != nil {
		fmt.Fprintf(os.Stderr, "xdrcheck conform %s: %v\n", target, err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "xdrcheck conform %s: %d column(s) in %d driver directories done\n", target, len(cols), len(conform.DirJobs(cols)))
	return 0
}

func conformDescribe(ctx context.Context, args []string) int {
	f := newFlags("describe", false)
	if !f.parse(args) {
		return 2
	}
	env, err := loadConformEnv(f.pins, os.Getenv("XDRCHECK_OVERLAY"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "xdrcheck conform describe: %v\n", err)
		return 2
	}
	cols, err := env.sets.Select("", f.columns)
	if err == nil {
		cols, err = f.withSource(env.sets, cols)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "xdrcheck conform describe: %v\n", err)
		return 2
	}
	v, err := validator(env.root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xdrcheck conform describe: %v\n", err)
		return 2
	}
	code := 0
	for _, col := range cols {
		raw, err := conform.DescribeColumn(ctx, env.sets, col, conform.Limits{}, v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "xdrcheck conform describe: %v\n", err)
			code = 2
			continue
		}
		out, _ := json.MarshalIndent(map[string]any{"column": col.ID, "describe": raw}, "", "  ")
		fmt.Println(string(out))
	}
	return code
}

func validator(root string) (*conform.Validator, error) {
	ops, err := conform.LoadAPIOps(filepath.Join(root, "corpus", "schema", "manifest-entry.schema.json"))
	if err != nil {
		return nil, err
	}
	return &conform.Validator{APIOps: ops}, nil
}

func conformRun(ctx context.Context, args []string) int {
	f := newFlags("run", true)
	var (
		entries, levels, tier, reportDir, goldens string
		jobs                                      int
		timeout                                   time.Duration
		memMax, asMax                             sizeFlag
	)
	memMax = 1 << 30
	f.fs.StringVar(&entries, "entries", "", "comma-separated entry ID globs ('*' crosses '/')")
	f.fs.StringVar(&levels, "levels", "", "comma-separated levels, for example L0,L1 or spec or json (default every applicable level)")
	f.fs.StringVar(&levels, "level", "", "the same as --levels; --level json with neither --set nor --columns selects the json set")
	var kind string
	f.fs.StringVar(&kind, "kind", "", "only entries of this kind (ledger, xdr, api, strkey, spec); --kind spec with neither --set nor --columns selects the spec set")
	f.fs.StringVar(&tier, "tier", "curated", "corpus tier: curated or bulk")
	f.fs.IntVar(&jobs, "jobs", 0, "columns run in parallel (default the number of CPUs)")
	f.fs.DurationVar(&timeout, "timeout", conform.DefaultTimeout, "per-request base timeout; a request gets it once more per MiB of input")
	f.fs.Var(&memMax, "memory-max", "memory cap per driver process, for example 1G or 512M (0 = none)")
	f.fs.Var(&asMax, "as-limit", "address-space cap (RLIMIT_AS) per driver process (0 = none)")
	f.fs.StringVar(&reportDir, "report", "", "directory for matrix.json, matrix.md, cross-sdk.md, report.json, cells.ndjson and describe.json")
	f.fs.StringVar(&goldens, "goldens", "", "golden cache root for --tier bulk (default $XDRCHECK_GOLDENS, else ~/.cache/xdrcheck/goldens)")
	var lists failureLists
	f.fs.StringVar(&lists.expected, "expected-failures", "", "the column's expected-failure list: the run passes only when its failing cells are exactly the list (a new failure or a listed cell that passes fails it); needs one column")
	f.fs.StringVar(&lists.write, "write-expected-failures", "", "write the column's failing cells to this file as an expected-failure list; needs one column")
	f.fs.BoolVar(&lists.requireAllRead, "require-all-read", false, "fail the run when a column never read a selected entry variant (every level n/a, or no level its driver answers)")
	if !f.parse(args) {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(os.Stderr, "xdrcheck conform run: %v\n", err)
		return 2
	}
	timeoutSet := false
	f.fs.Visit(func(fl *flag.Flag) { timeoutSet = timeoutSet || fl.Name == "timeout" })
	switch tier {
	case "curated":
	case "bulk":
		if !timeoutSet {
			timeout = conform.BulkTimeout
		}
	default:
		return fail(fmt.Errorf("--tier %q: want curated or bulk", tier))
	}
	var want map[string]bool
	if levels != "" {
		want = map[string]bool{}
		for _, l := range strings.Split(levels, ",") {
			l = strings.TrimSpace(l)
			if levelIndexOK(l) {
				want[l] = true
			} else {
				return fail(fmt.Errorf("--levels: unknown level %q", l))
			}
		}
	}
	env, err := loadConformEnv(f.pins, cmp.Or(f.overlay, os.Getenv("XDRCHECK_OVERLAY")))
	if err != nil {
		return fail(err)
	}
	// The spec and json levels have their own columns: name them unless the selection is explicit.
	if f.set == "" && f.columns == "" {
		switch {
		case kind == "spec":
			f.set = "spec"
		case want[conform.JSONLevel] && len(want) == 1:
			f.set = "json"
		}
	}
	cols, err := env.sets.Select(f.set, f.columns)
	if err == nil {
		cols, err = f.withSource(env.sets, cols)
	}
	if err != nil {
		return fail(err)
	}
	// $XDRCHECK_OVERLAY fills in --overlay only for a selection that needs it, so a public run stays public.
	if f.overlay == "" && env.sets.CheckOverlay(f.set, cols, false) != nil {
		f.overlay = os.Getenv("XDRCHECK_OVERLAY")
	}
	if err := env.sets.CheckOverlay(f.set, cols, f.overlay != ""); err != nil {
		return fail(err)
	}
	if f.overlay != "" {
		if err := privateOutputs(env.root, f.overlay, reportDir); err != nil {
			return fail(err)
		}
	}
	globs, err := conform.CompileGlobs(entries)
	if err != nil {
		return fail(err)
	}
	if lists.expected != "" || lists.write != "" {
		if len(cols) != 1 {
			return fail(fmt.Errorf("--expected-failures and --write-expected-failures are per column: select exactly one (--columns ID), not %d", len(cols)))
		}
		if lists.expected != "" && lists.write != "" {
			return fail(errors.New("--expected-failures and --write-expected-failures do not go together: write the list, then check against it"))
		}
		if lists.expected != "" {
			if lists.expectedList, err = verdict.ReadExpectedFailures(lists.expected); err != nil {
				return fail(err)
			}
		}
	}
	v, err := validator(env.root)
	if err != nil {
		return fail(err)
	}
	corpus, err := manifest.Load(filepath.Join(env.root, "corpus"), manifest.Options{Overlay: overlayCorpus(f.overlay)})
	if err != nil {
		return fail(err)
	}
	if kind != "" {
		// A shallow copy holding only the entries of that kind.
		only := *corpus
		only.Entries = nil
		for _, e := range corpus.Entries {
			if e.Kind == kind {
				only.Entries = append(only.Entries, e)
			}
		}
		if len(only.Entries) == 0 {
			return fail(fmt.Errorf("--kind %q: no entry of that kind", kind))
		}
		corpus = &only
	}
	// A known divergence whose version range cannot be read would assert nothing: refuse the run instead.
	var selected []*manifest.Entry
	for _, e := range corpus.Entries {
		if globs.Match(e.ID) {
			selected = append(selected, e)
		}
	}
	if err := verdict.CheckRanges(selected); err != nil {
		return fail(err)
	}
	inRun := map[string]bool{}
	for _, e := range selected {
		inRun[e.ID] = true
	}
	lists.selected = func(id string) bool { return inRun[id] }
	cells := corpus
	if tier == "bulk" {
		if cells, err = conform.BulkCorpus(corpus, conform.GoldensRoot(goldens), globs); err != nil {
			return fail(err)
		}
		globs = nil // already applied to the golden files
	}
	suite := f.set
	switch {
	case f.columns != "":
		suite = "columns " + f.columns
	case suite == "":
		suite = conform.DefaultSet
	}
	header, err := conform.Header(corpus, env.pins, cols, suite, tier)
	if err != nil {
		return fail(err)
	}
	header.Mode.Overlay = f.overlay != ""
	res, err := conform.Run(ctx, conform.Options{
		Sets: env.sets, Columns: cols, Corpus: cells, Entries: globs, Levels: want, Jobs: jobs,
		Limits:    conform.Limits{Timeout: timeout, MemoryMax: int64(memMax), AddressSpaceMax: int64(asMax)},
		Validator: v, Log: os.Stderr,
	})
	if err != nil {
		return fail(err)
	}
	res.Apply(verdict.Engine{})
	// Cells the committed pending lists name are pending finding review, not unexpected.
	pending, err := findings.LoadPending(env.root)
	if err != nil {
		return fail(err)
	}
	res.MarkPending(pending.Mark)
	wall := float64(res.Wall.Microseconds()) / 1000
	run := &report.Run{Started: res.Started.UTC().Format(time.RFC3339), WallMS: &wall, Host: report.RunHost(), Toolchains: toolchains(res)}
	m := verdict.Build(res, header, run)
	// What a reader acts on comes first (stderr, so it stays on the console when the cell lines are redirected);
	// then one line per cell on stdout.
	m.SummaryText(os.Stderr)
	for _, ob := range res.Observations {
		printCell(os.Stdout, ob)
	}
	if reportDir != "" {
		sum, err := conform.WriteOutputs(reportDir, res, header, run)
		if err != nil {
			return fail(err)
		}
		if err := m.Write(reportDir); err != nil {
			return fail(err)
		}
		fmt.Fprintf(os.Stderr, "xdrcheck conform run: %d cells, %d judged, %d protocol errors, %d not run; %d unexpected; wrote %s (start with %s)\n",
			sum.Cells, sum.Judged, sum.ProtocolErrors, sum.NotRun, sum.Report.Unexpected, reportDir, verdict.SummaryFile)
	}
	if errs := res.InfraErrors(); len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "xdrcheck conform run: %d infrastructure problem(s):\n  %s\n", len(errs), strings.Join(errs, "\n  "))
		return 2
	}
	for _, ob := range res.Observations {
		if ob.NotRun != "" {
			return 2
		}
	}
	code := 0
	if res.Unexpected() > 0 {
		code = 1
	}
	if lists.write != "" {
		if err := writeExpectedFailures(m, cols[0].ID, lists.write); err != nil {
			return fail(err)
		}
		code = 0 // generating the list is the point of the run; its cells are what the list now records
	}
	if lists.expected != "" {
		r := m.CompareFailures(cols[0].ID, lists.expectedList, lists.selected, lists.requireAllRead)
		r.Print(os.Stderr, lists.expected)
		// The SDK's own list decides, not the corpus's declarations: a cell the corpus declares as a known
		// divergence is still a failure of this SDK, and must be listed.
		code = 0
		if !r.Passed() {
			code = 1
		}
	}
	if allRead(os.Stderr, res, lists.requireAllRead && lists.expected == "") {
		code = max(code, 1)
	}
	return code
}

// failureLists holds run's expected-failure and all-read options.
type failureLists struct {
	expected, write string
	expectedList    []verdict.ExpectedFailure
	requireAllRead  bool
	selected        func(entry string) bool
}

// writeExpectedFailures writes the column's failing cells to path (docs/use-in-sdk-ci.md, expected failures).
func writeExpectedFailures(m *verdict.Matrix, column, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	n, err := m.WriteExpectedFailures(f, column)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		fmt.Fprintf(os.Stderr, "xdrcheck conform run: wrote %d expected failure(s) of %s to %s\n", n, column, path)
	}
	return err
}

// allRead reports the entry variants a column never read (conform.Result.Unread): one line per column with
// how many it read, and with require every unread item, which then fails the run. It returns whether the run
// fails on them.
func allRead(w io.Writer, res *conform.Result, require bool) bool {
	unread := res.Unread()
	if len(unread) == 0 {
		return false
	}
	per := map[string]int{}
	for _, u := range unread {
		per[u.Column]++
	}
	counts := res.ReadCounts()
	for _, c := range res.Columns {
		if n := per[c.Column.ID]; n > 0 {
			fmt.Fprintf(w, "xdrcheck conform run: %s never read %d of the %d entry variants selected for it (every level n/a, or no level its driver answers)\n",
				c.Column.ID, n, counts[c.Column.ID][0])
		}
	}
	if !require {
		fmt.Fprintf(w, "xdrcheck conform run: they are listed in %s (with --report); --require-all-read fails the run on them unless an --expected-failures list names them as unread\n", verdict.SummaryFile)
		return false
	}
	for _, u := range unread {
		fmt.Fprintf(w, "UNREAD   %s\n", u)
	}
	return true
}

func knownSuffix(k *verdict.KnownRef) string {
	if k == nil {
		return ""
	}
	return fmt.Sprintf(" [known %s %s, %s, %s]", k.Outcome, k.Versions, k.Status, k.Reference)
}

func conformDiff(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: xdrcheck conform diff <matrix-a> <matrix-b>")
		return 2
	}
	a, err := verdict.ReadMatrix(args[0])
	if err == nil {
		var b *verdict.Matrix
		if b, err = verdict.ReadMatrix(args[1]); err == nil {
			changes := verdict.Diff(a, b)
			for _, ch := range changes {
				from, to := "-", "-"
				if ch.From != nil {
					from = ch.From.Verdict + "/" + ch.From.Check
				}
				if ch.To != nil {
					to = ch.To.Verdict + "/" + ch.To.Check
				}
				fmt.Printf("%-8s %s: %s -> %s\n", ch.WhatMoved, ch.Key, from, to)
			}
			fmt.Fprintf(os.Stderr, "xdrcheck conform diff: %d change(s)\n", len(changes))
			if len(changes) > 0 {
				return 1
			}
			return 0
		}
	}
	fmt.Fprintf(os.Stderr, "xdrcheck conform diff: %v\n", err)
	return 2
}

func levelIndexOK(l string) bool {
	for _, x := range conform.Levels {
		if x == l {
			return true
		}
	}
	return false
}

func printCell(w io.Writer, ob *conform.Observation) {
	c := ob.Cell
	variant := c.VariantKey
	if variant == "" {
		variant = "-"
	}
	status := ""
	switch {
	case ob.ProtocolError != "":
		status = "PROTOCOL-ERROR " + ob.ProtocolError
	case ob.NotRun != "":
		status = "NOT-RUN " + ob.NotRun
	default:
		status = fmt.Sprintf("%s %s -> %s", ob.Outcome, orDash(ob.Reason), ob.Judgement.Verdict)
	}
	fmt.Fprintf(w, "%-28s %-55s %-10s %s %s\n", c.Column.ID, c.Entry.ID, variant, c.Level, status)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func toolchains(res *conform.Result) map[string]string {
	m := map[string]string{}
	for _, c := range res.Columns {
		if d := c.Describe; d != nil && d.Runtime != nil {
			m[c.Column.ID] = *d.Runtime.Name + " " + *d.Runtime.Version
		}
	}
	return m
}

// sizeFlag parses a byte size: a plain number of bytes, or a number with K, M, G or T (powers of 1024; "iB"
// and "B" suffixes accepted).
type sizeFlag int64

func (s *sizeFlag) String() string { return strconv.FormatInt(int64(*s), 10) }

func (s *sizeFlag) Set(v string) error {
	n, err := parseSize(v)
	if err != nil {
		return err
	}
	*s = sizeFlag(n)
	return nil
}

func parseSize(v string) (int64, error) {
	t := strings.TrimSuffix(strings.TrimSuffix(strings.ToUpper(strings.TrimSpace(v)), "B"), "I")
	mult := int64(1)
	if t != "" {
		switch t[len(t)-1] {
		case 'K':
			mult = 1 << 10
		case 'M':
			mult = 1 << 20
		case 'G':
			mult = 1 << 30
		case 'T':
			mult = 1 << 40
		}
		if mult > 1 {
			t = t[:len(t)-1]
		}
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("size %q: want bytes or a number with K, M, G or T", v)
	}
	return n * mult, nil
}

// overlayCorpus is the overlay's corpus directory (<overlay>/corpus) when the overlay has one, else "": a run
// with the overlay reads the public corpus merged with it (docs/conformance-protocol.md, private overlay).
func overlayCorpus(overlay string) string {
	if overlay == "" {
		return ""
	}
	dir := filepath.Join(overlay, "corpus")
	if st, err := os.Stat(filepath.Join(dir, "manifest")); err != nil || !st.IsDir() {
		return ""
	}
	return dir
}

// privateOutputs checks the overlay directory and the report directory of a run made with the overlay: both
// must lie outside the public working tree, so that nothing such a run writes can be committed or uploaded.
func privateOutputs(root, overlay, reportDir string) error {
	inside := func(p string) (bool, error) {
		abs, err := filepath.Abs(p)
		if err != nil {
			return false, err
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil {
			return false, err
		}
		return rel == "." || !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..", nil
	}
	st, err := os.Stat(overlay)
	if err != nil || !st.IsDir() {
		return fmt.Errorf("--overlay %s is not a directory", overlay)
	}
	if in, err := inside(overlay); err != nil || in {
		return fmt.Errorf("--overlay %s is inside the public working tree; the overlay must live outside it", overlay)
	}
	if reportDir == "" {
		return nil
	}
	if in, err := inside(reportDir); err != nil || in {
		return fmt.Errorf("--report %s is inside the public working tree; a run with the overlay writes its report outside it (for example under the overlay's reports/)", reportDir)
	}
	return nil
}
