package main

// xdrcheck replay (docs/replay-harness.md §4–§11, docs/cli.md):
//
//	xdrcheck replay --corpus DIR --adapter "COMMAND" --target-version V
//	           [--network all|testnet|pubnet|core-test] [--entries GLOB] [--caps N,N]
//	           [--input sep54-s3|sep54-gcs|sep54-dir|rpc] [--unit auto|single|chain|stream] [--repeat K]
//	           [--out-of-envelope probe|skip] [--assert-known] [--confirm K]
//	           [--parallel N] [--deadline DUR] [--memory-max SIZE] [--pids-max N]
//	           [--report DIR] [--resume] [--keep-going] [--keep-state] [--selftest]
//	           [--findings DIR] [--overlay DIR] [--pins FILE]
//
// Exit codes: 0 every result is the expected one; 1 at least one unexpected result (inside a declared range a
// result other than the declared class·qualifier, outside every range anything but a pass, or under
// --assert-known an entry that could not be checked); 2 the harness could not run or hit a harness fault (bad
// arguments, an adapter that does not start or breaks the protocol, a failed call, a ledger never served).
// --selftest exits 0 when every check passes and 1 otherwise.
//
// With --report DIR the run writes DIR/report.json (xcc.report/v1), DIR/describe.json, DIR/REPORT.md and
// DIR/logs/ (adapter stderr per process, delivery logs). --findings DIR (needs --report) applies the
// development-mode findings check to this run's report against the records in DIR and exits 1 when a failure
// row has no finding ID that resolves. --overlay DIR merges the overlay's corpus (DIR/corpus: manifests, blobs,
// sidecars) with the public one; such a run's report must be written outside the working tree. Only the flag
// turns it on ($XDRCHECK_OVERLAY is not read here), so a replay stays public unless asked. --resume and the
// sep54-gcs input are not built and exit 2.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	pendinglist "github.com/tolgayayci/xdrcheck/go/internal/findings"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/pins"
	"github.com/tolgayayci/xdrcheck/go/internal/replay/run"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
	"github.com/tolgayayci/xdrcheck/go/internal/userdir"
)

// harnessVersion is the replay harness's version, sent in describe and written in reports.
const harnessVersion = "0.1.0"

func init() {
	register("replay", "replay the corpus through an indexer's adapter, or ledgers through a target or a rig", func(args []string) int {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if isTargetReplay(args) {
			return huntReplay(ctx, args, os.Stdout, os.Stderr)
		}
		return replay(ctx, args, os.Stdout, os.Stderr)
	})
}

// replayUsage is the help of xdrcheck replay: its three forms, then the corpus form's flags.
func replayUsage(fs *flag.FlagSet) {
	w := fs.Output()
	fmt.Fprint(w, `usage: xdrcheck replay --adapter "COMMAND" --target-version V [flags]
         replay the corpus through an indexer's adapter (the flags below)
       xdrcheck replay --target T --version V (--ledgers L | --tx T | --set S | --cap N | --issue I | --ledger-file F) [flags]
         run an SDK or pipeline target over ledgers and write a run directory (xdrcheck replay --target T --help)
       xdrcheck replay --rig wallet-backend|stellar-etl|horizon --ledgers L --commit C --lake DIR --out DIR [flags]
         run a service rig directly: raw rig output, not a run directory (xdrcheck replay --rig R --help)

Flags of the corpus form:
`)
	fs.PrintDefaults()
}

func replay(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if usesRig(args) {
		return replayRig(ctx, args, stdout, stderr)
	}
	fs := flag.NewFlagSet("xdrcheck replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		corpus        = fs.String("corpus", "corpus", "corpus root")
		adapterCmd    = fs.String("adapter", "", "the adapter's command line (required)")
		targetVersion = fs.String("target-version", "", "version or full commit of the indexer under test (required)")
		network       = fs.String("network", "all", "all, testnet, pubnet or core-test")
		entries       = fs.String("entries", "", "comma-separated entry ID globs")
		caps          = fs.String("caps", "", "comma-separated CAP numbers")
		input         = fs.String("input", "", "sep54-s3, sep54-gcs, sep54-dir or rpc (default: the first the adapter declares)")
		unit          = fs.String("unit", "auto", "auto, single, chain or stream")
		repeat        = fs.Int("repeat", 1, "stream: repeat the pass's ledgers K times")
		outOfEnv      = fs.String("out-of-envelope", "probe", "probe or skip: out-of-envelope entries of an indexer_gate adapter")
		assertKnown   = fs.Bool("assert-known", false, "run only entries with a known divergence for this target; fail on any other result than the declared one")
		confirm       = fs.Int("confirm", 0, "re-run a unit with a non-pass result K more times; differing results are flaky")
		parallel      = fs.Int("parallel", 1, "units run at once, each with its own adapter process")
		deadline      = fs.Duration("deadline", 0, "ingest deadline per unit (default: sized from describe.timing)")
		pidsMax       = fs.Int("pids-max", 0, "process cap for the adapter's group")
		reportDir     = fs.String("report", "", "write report.json, describe.json, REPORT.md and logs/ here")
		resume        = fs.Bool("resume", false, "skip entries already in the report (not built)")
		keepGoing     = fs.Bool("keep-going", false, "continue after a harness fault")
		keepState     = fs.Bool("keep-state", false, "keep each session's state and directories")
		selftest      = fs.Bool("selftest", false, "check the adapter's protocol conformance without scoring the indexer")
		findings      = fs.String("findings", "", "after the run, apply the development-mode findings check to this run's report against the records in this directory")
		overlay       = fs.String("overlay", "", "private overlay directory: merge its corpus/ with the public corpus (the report must then be written outside the working tree)")
		pinsFile      = fs.String("pins", "", "pins file (default pins.toml beside the corpus)")
		memMax        sizeFlag
	)
	fs.Var(&memMax, "memory-max", "memory cap for the adapter's group, for example 1G")
	fs.Usage = func() { replayUsage(fs) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "xdrcheck replay: "+format+"\n", a...)
		return 2
	}
	switch {
	case fs.NArg() > 0:
		return fail("unexpected arguments %v", fs.Args())
	case *adapterCmd == "":
		return fail("--adapter is required")
	case *targetVersion == "" && !*selftest:
		return fail("--target-version is required")
	case *resume:
		return fail("--resume is not built")
	case *findings != "" && *reportDir == "":
		return fail("--findings needs --report DIR: the check reads this run's report")
	case *outOfEnv != "probe" && *outOfEnv != "skip":
		return fail("--out-of-envelope must be probe or skip")
	}
	argv, err := splitCommand(*adapterCmd)
	if err != nil {
		return fail("--adapter: %v", err)
	}
	var networks []string
	switch *network {
	case "all", "":
	case "testnet", "pubnet", "core-test":
		networks = []string{*network}
	default:
		return fail("--network must be all, testnet, pubnet or core-test")
	}
	var capList []int
	if *caps != "" {
		for _, c := range strings.Split(*caps, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(c))
			if err != nil {
				return fail("--caps: %q is not a number", c)
			}
			capList = append(capList, n)
		}
	}
	var entryList []string
	if *entries != "" {
		entryList = strings.Split(*entries, ",")
	}

	if *overlay != "" {
		root, err := filepath.Abs(filepath.Dir(filepath.Clean(*corpus)))
		if err != nil {
			return fail("%v", err)
		}
		if err := privateOutputs(root, *overlay, *reportDir); err != nil {
			return fail("%v", err)
		}
	}
	c, err := manifest.Load(*corpus, manifest.Options{Overlay: overlayCorpus(*overlay)})
	if err != nil {
		return fail("%v", err)
	}
	pinsPath := *pinsFile
	if pinsPath == "" {
		pinsPath = filepath.Join(filepath.Dir(filepath.Clean(*corpus)), "pins.toml")
	}
	pn, err := pins.Load(pinsPath)
	if err != nil {
		return fail("pins: %v", err)
	}

	// Rows the committed pending lists name are marked pending finding review, not unexpected.
	pending, err := pendinglist.LoadPending(filepath.Dir(pinsPath))
	if err != nil {
		return fail("%v", err)
	}

	work, err := os.MkdirTemp("", "xdrcheck-replay-")
	if err != nil {
		return fail("%v", err)
	}
	if !*keepState {
		defer os.RemoveAll(work)
	}
	logDir := filepath.Join(work, "logs")
	if *reportDir != "" {
		if err := os.MkdirAll(*reportDir, 0o755); err != nil {
			return fail("%v", err)
		}
		logDir = filepath.Join(*reportDir, "logs")
	}
	cache := ""
	if d, err := userdir.UserCache(); err == nil {
		cache = filepath.Join(d, "adapters")
	}
	o := run.Options{
		Corpus: c, Adapter: adapter.Config{Argv: argv}, HarnessVersion: harnessVersion, TargetVersion: *targetVersion,
		Networks: networks, Entries: entryList, Caps: capList, Input: *input, Unit: *unit, Repeat: *repeat,
		OutOfEnvelope: *outOfEnv, AssertKnown: *assertKnown, Confirm: *confirm, Parallel: *parallel, Deadline: *deadline,
		MemoryMax: int64(memMax), PidsMax: *pidsMax, KeepGoing: *keepGoing, KeepState: *keepState,
		WorkDir: work, CacheDir: cache, LogDir: logDir, StoreImage: pn.Images["seaweedfs"], Out: stdout, Log: stderr,
		Pending: pending.Mark,
	}

	if *selftest {
		rep, err := run.Selftest(ctx, o)
		if err != nil {
			return fail("selftest: %v", err)
		}
		for _, ch := range rep.Checks {
			fmt.Fprintf(stdout, "%-20s %-5s %s %s\n", ch.Name, ch.Status, ch.Reason, ch.Detail)
		}
		if *reportDir != "" {
			b, _ := json.MarshalIndent(rep, "", "  ")
			os.WriteFile(filepath.Join(*reportDir, "selftest.json"), append(b, '\n'), 0o644)
		}
		if !rep.OK() {
			f := rep.FirstFailure()
			fmt.Fprintf(stderr, "xdrcheck replay --selftest: failed: %s: %s\n", f.Name, f.Reason)
			return 1
		}
		return 0
	}

	started := time.Now()
	var hdr report.Header
	if *reportDir != "" {
		sum, err := conform.ManifestSHA256(c)
		if err != nil {
			return fail("%v", err)
		}
		version := "unversioned"
		if c.Index != nil && c.Index.CorpusVersion != "" {
			version = c.Index.CorpusVersion
		}
		suite := "replay"
		if *assertKnown {
			suite = "assert-known"
		}
		hdr = report.Header{
			Tool:   report.Tool{Name: "xcc replay", Version: harnessVersion},
			Corpus: report.CorpusRef{Version: version, ManifestSHA256: sum, Schema: manifest.EntrySchema, Tier: "curated"},
			Pins:   report.PinsRef{FileSHA256: pn.FileSHA256, Values: map[string]string{}},
			Mode:   report.Mode{Suite: suite, Overlay: *overlay != "", Offline: conform.OfflineMode()},
		}
		w, err := report.Create(filepath.Join(*reportDir, "report.json"), hdr)
		if err != nil {
			return fail("%v", err)
		}
		o.Report = w
	}

	res, err := run.Run(ctx, o)
	if o.Report != nil {
		if res != nil && res.Describe != nil {
			hdr.Pins.Values["target"] = res.Target.Name + "@" + res.Target.Version
			hdr.Pins.Values["adapter"] = res.Describe.Adapter.Name + " " + res.Describe.Adapter.Version
			hdr.Pins.Values["input"] = res.Input
			o.Report.SetHeader(hdr)
		}
		wall := float64(time.Since(started).Microseconds()) / 1000
		host := report.RunHost()
		o.Report.SetRun(&report.Run{Started: started.UTC().Format(time.RFC3339), WallMS: &wall, Host: host})
		if cerr := o.Report.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	if err != nil {
		if res == nil {
			return fail("%v", err)
		}
		fmt.Fprintf(stderr, "xdrcheck replay: %v\n", err)
	}
	if *reportDir != "" && res != nil {
		prog := "xdrcheck"
		if filepath.Base(os.Args[0]) == "xdrcheck" {
			prog = os.Args[0]
		}
		writeExtras(*reportDir, res, reproArgs{prog: prog, adapter: *adapterCmd, targetVersion: *targetVersion, corpus: *corpus, input: res.Input, pins: *pinsFile, overlay: *overlay}, stderr)
	}
	printSummary(stderr, res, *reportDir)
	if err != nil && res.ExitCode() == 0 {
		return 2
	}
	if *findings != "" && res.ExitCode() != 2 {
		ok, ferr := checkRunFindings(filepath.Join(*reportDir, "report.json"), *findings, findingSchemaPath(*corpus), stderr)
		if ferr != nil {
			return fail("--findings: %v", ferr)
		}
		if !ok {
			return 1
		}
	}
	return res.ExitCode()
}

// printSummary prints the counts, then where the failures are explained.
func printSummary(w io.Writer, res *run.Result, reportDir string) {
	if res == nil {
		return
	}
	keys := make([]string, 0, len(res.ByResult))
	failing := 0
	for k, n := range res.ByResult {
		keys = append(keys, k)
		if strings.HasPrefix(k, "mishandled") || k == "dropped·silent" || k == "dropped·partial" {
			failing += n
		}
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, res.ByResult[k]))
	}
	fmt.Fprintf(w, "xdrcheck replay: %d rows: %s. Failing: %d. Not the expected result: %d. Harness faults: %d. Input: %s.\n",
		res.Rows, strings.Join(parts, ", "), failing, res.Unexpected, res.Faults, res.Input)
	for _, n := range res.Notes {
		fmt.Fprintln(w, "  note:", n)
	}
	switch {
	case failing+res.Unexpected+res.Faults == 0:
	case reportDir != "":
		fmt.Fprintf(w, "xdrcheck replay: each failure, with what the ledger holds, what the indexer held and the command that reproduces it: %s\n",
			filepath.Join(reportDir, "REPORT.md"))
	default:
		fmt.Fprintln(w, "xdrcheck replay: add --report DIR for each failure's expected and observed facts and the command that reproduces it (DIR/REPORT.md)")
	}
}

// writeExtras writes describe.json and REPORT.md beside report.json.
func writeExtras(dir string, res *run.Result, ra reproArgs, stderr io.Writer) {
	if res.Describe != nil {
		b, _ := json.MarshalIndent(res.Describe, "", "  ")
		os.WriteFile(filepath.Join(dir, "describe.json"), append(b, '\n'), 0o644)
	}
	if err := writeReportMD(dir, res, ra); err != nil {
		fmt.Fprintf(stderr, "xdrcheck replay: REPORT.md: %v\n", err)
	}
}

// splitCommand splits a command line on spaces, honouring single and double quotes and backslash escapes.
func splitCommand(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	in := false
	var quote rune
	esc := false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc, in = false, true
		case r == '\\' && quote != '\'':
			esc = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, in = r, true
		case r == ' ' || r == '\t' || r == '\n':
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(r)
			in = true
		}
	}
	if quote != 0 || esc {
		return nil, errors.New("unterminated quote or escape")
	}
	if in {
		out = append(out, cur.String())
	}
	if len(out) == 0 {
		return nil, errors.New("empty command")
	}
	return out, nil
}
