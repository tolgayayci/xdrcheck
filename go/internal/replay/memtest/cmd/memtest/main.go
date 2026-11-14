// Command memtest is the replay harness's memory-bound test (package memtest; `make verify-memory` runs it
// through scripts/verify-memory.sh).
//
//	memtest --xdrcheck go/bin/xdrcheck --baseline go/bin/baseline [--corpus corpus] [--goldens DIR] [--pins pins.toml]
//	        --out DIR [--sample N] [--repeat K] [--trials N] [--big-repeat N] [--harness-limit-mib N] [--growth-mib N]
//	        [--only T-mem-1,…] [--negative-control]
//	memtest oversize-adapter --marker FILE --bytes N -- ADAPTER [ARGS…]
//
// Exit codes: 0 every test passed; 1 a test failed (for --negative-control, the intended outcome); 2 the test
// could not be set up.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/replay/memtest"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) > 0 && args[0] == "oversize-adapter" {
		fs := flag.NewFlagSet("memtest oversize-adapter", flag.ContinueOnError)
		marker := fs.String("marker", "", "file created by the process that answers the oversized observe")
		size := fs.Int64("bytes", 512<<20, "length of the oversized response line")
		if err := fs.Parse(args[1:]); err != nil || *marker == "" {
			return 2
		}
		return memtest.OversizeAdapter(*marker, *size, fs.Args())
	}
	fs := flag.NewFlagSet("memtest", flag.ContinueOnError)
	var cfg memtest.Config
	fs.StringVar(&cfg.XDRCHECK, "xdrcheck", "go/bin/xdrcheck", "the xdrcheck binary")
	fs.StringVar(&cfg.Baseline, "baseline", "go/bin/baseline", "the baseline adapter binary")
	fs.StringVar(&cfg.Corpus, "corpus", "corpus", "corpus root")
	goldens := fs.String("goldens", "", "golden cache root (default $XDRCHECK_GOLDENS or ~/.cache/xdrcheck/goldens)")
	fs.StringVar(&cfg.Pins, "pins", "", "pins file (default pins.toml beside the corpus)")
	fs.StringVar(&cfg.Out, "out", "reports/memory", "report directory")
	fs.IntVar(&cfg.Sample, "sample", 1500, "bulk-tier ledgers to sample, about; 0 takes the whole tier")
	fs.IntVar(&cfg.Repeat, "repeat", 10, "repeat count of the larger stream")
	fs.IntVar(&cfg.Trials, "trials", 5, "runs of each T-mem-1 stream size; the lowest peaks are compared")
	fs.IntVar(&cfg.BigRepeat, "big-repeat", 100, "repeat count of the corpus's largest ledger")
	limit := fs.Int64("harness-limit-mib", 256, "memory group of each xdrcheck run, MiB")
	growth := fs.Int64("growth-mib", 16, "allowed peak growth from one repeat to --repeat, MiB")
	only := fs.String("only", "", "comma-separated tests to run (T-mem-1 … T-mem-4)")
	fs.BoolVar(&cfg.NegativeControl, "negative-control", false, "run T-mem-1 with streaming switched off; expected to fail")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg.HarnessLimit, cfg.Growth = *limit<<20, *growth<<20
	if *only != "" {
		cfg.Only = strings.Split(*only, ",")
	}
	cfg.Goldens = conform.GoldensRoot(*goldens)
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "memtest:", err)
		return 2
	}
	cfg.Self, cfg.Log = self, os.Stderr
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rep, err := memtest.Main(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "memtest:", err)
		return 2
	}
	fmt.Print(rep.Markdown())
	for _, t := range rep.Tests {
		if t.Error != "" {
			fmt.Fprintf(os.Stderr, "memtest: %s could not run: %s\n", t.Name, t.Error)
			return 2
		}
	}
	if !rep.OK {
		return 1
	}
	return 0
}
