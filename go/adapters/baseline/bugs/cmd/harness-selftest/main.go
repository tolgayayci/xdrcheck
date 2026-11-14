// Command harness-selftest replays every seeded-bug indexer through `xdrcheck replay` and checks each lands in the
// class its table row documents (go/adapters/baseline/bugs/table.json). scripts/harness-selftest.sh builds and
// runs it for `make harness-selftest`.
//
//	harness-selftest --xdrcheck go/bin/xdrcheck --baseline go/bin/baseline --corpus corpus --out reports/selftest
//	                 [--input sep54-dir] [--only bug,bug] [--strict]
//
// Exit codes: 0 every bug as documented (known harness holes and not-yet-demonstrable bugs are listed, and fail
// only with --strict or XDRCHECK_SELFTEST_STRICT=1); 1 a bug outside its documented class; 2 the self-test could not
// run. Writes OUT/summary.json and one `xdrcheck replay --report` directory per bug.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/tolgayayci/xdrcheck/go/adapters/baseline/bugs"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

func main() { os.Exit(run()) }

func run() int {
	fs := flag.NewFlagSet("harness-selftest", flag.ContinueOnError)
	var o bugs.Options
	fs.StringVar(&o.XDRCHECK, "xdrcheck", "go/bin/xdrcheck", "the xdrcheck binary")
	fs.StringVar(&o.Baseline, "baseline", "go/bin/baseline", "the baseline adapter binary")
	fs.StringVar(&o.Corpus, "corpus", "corpus", "corpus root")
	fs.StringVar(&o.Out, "out", "reports/selftest", "output directory")
	fs.StringVar(&o.Input, "input", "sep54-dir", "replay input")
	only := fs.String("only", "", "comma-separated bugs to run (default all)")
	strict := fs.Bool("strict", os.Getenv("XDRCHECK_SELFTEST_STRICT") == "1", "fail on known harness holes and bugs not yet demonstrable")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if *only != "" {
		o.Only = strings.Split(*only, ",")
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(os.Stderr, "harness-selftest: "+format+"\n", a...)
		return 2
	}
	t, err := bugs.LoadTable()
	if err != nil {
		return fail("%v", err)
	}
	c, err := manifest.Load(o.Corpus, manifest.Options{})
	if err != nil {
		return fail("%v", err)
	}
	o.Have = func(id string) bool { return c.Entry(id) != nil }
	for _, p := range []*string{&o.XDRCHECK, &o.Baseline} {
		if abs, err := filepath.Abs(*p); err == nil {
			*p = abs
		}
	}
	if err := os.MkdirAll(o.Out, 0o755); err != nil {
		return fail("%v", err)
	}
	o.Log = os.Stderr
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	verdicts, err := bugs.Run(ctx, t, o)
	if err != nil {
		return fail("%v", err)
	}

	code := 0
	// list prints the first few lines of a kind; summary.json has them all.
	list := func(kind string, lines []string) {
		for i, l := range lines {
			if i == 8 {
				fmt.Printf("    … %d more %s line(s) in summary.json\n", len(lines)-i, kind)
				return
			}
			fmt.Printf("    %s: %s\n", kind, l)
		}
	}
	fmt.Printf("%-28s %-17s %s\n", "bug", "status", "results")
	for _, v := range verdicts {
		fmt.Printf("%-28s %-17s %s\n", v.Bug, v.Status, strings.Join(v.Results, ", "))
		list("problem", v.Problems)
		list("known hole", v.Holes)
		for _, p := range v.Pending {
			fmt.Printf("    pending: %s is not in the corpus yet\n", p)
		}
		for _, n := range v.Notes {
			fmt.Printf("    note: %s\n", n)
		}
		switch v.Status {
		case bugs.Fail:
			code = 1
		case bugs.KnownHole, bugs.NotDemonstrated:
			if *strict {
				code = 1
			}
		}
	}
	b, _ := json.MarshalIndent(map[string]any{"schema": "xcc.harness-selftest/v1", "strict": *strict, "bugs": verdicts}, "", "  ")
	if err := os.WriteFile(filepath.Join(o.Out, "summary.json"), append(b, '\n'), 0o644); err != nil {
		return fail("%v", err)
	}
	if code != 0 {
		fmt.Fprintln(os.Stderr, "harness-selftest: FAILED")
	}
	return code
}
