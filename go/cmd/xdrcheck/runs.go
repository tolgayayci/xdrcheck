package main

// xdrcheck runs (docs/run-directory.md): check run directories against the schemas, and compare two runs.

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/rundir"
)

func init() {
	register("runs", "validate run directories and compare two runs by cluster", func(args []string) int {
		return runsMain(args, os.Stdout, os.Stderr)
	})
}

func runsMain(args []string, stdout, stderr io.Writer) int {
	usage := func() int {
		fmt.Fprintf(stderr, "usage: %s runs validate DIR...\n       %s runs compare DIR_A DIR_B\n", hunt.Tool, hunt.Tool)
		return 2
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		return usage()
	}
	switch args[0] {
	case "validate":
		fs := flag.NewFlagSet(hunt.Tool+" runs validate", flag.ContinueOnError)
		fs.SetOutput(stderr)
		fs.Usage = func() {
			fmt.Fprintf(stderr, "usage: %s runs validate DIR...\n\nChecks manifest.json, verdicts.jsonl, clusters.json and summary.json of each run directory against\nthe embedded schemas, and that the three counts agree. Raw rig output (manifest schema xcc.rig/v1, from\n%s replay --rig) is recognised and checked as that format: manifest, one status.jsonl line per ledger with a\nknown status, rows.jsonl rows with a kind. Exit 0 when every directory is valid, 1 otherwise.\n", hunt.Tool, hunt.Tool)
		}
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() == 0 {
			fs.Usage()
			return 2
		}
		rc := 0
		for _, d := range fs.Args() {
			if rundir.IsRigDir(d) {
				// raw rig output (xdrcheck replay --rig) is its own format: validated as such, never as a run directory
				counts, bad := rundir.ValidateRigDir(d)
				if len(bad) > 0 {
					rc = 1
					fmt.Fprintf(stdout, "INVALID %s (raw rig output, %s)\n", d, rundir.RigSchema)
					for _, b := range bad {
						fmt.Fprintf(stdout, "  %s\n", b)
					}
					continue
				}
				fmt.Fprintf(stdout, "valid %s (raw rig output, %s: %s; not a run directory: %s replay --target <pipeline> runs the rig and the judge and writes one)\n",
					d, rundir.RigSchema, rundir.RigStatusText(counts), hunt.Tool)
				continue
			}
			if bad := rundir.ValidateDir(d); len(bad) > 0 {
				rc = 1
				fmt.Fprintf(stdout, "INVALID %s\n", d)
				for _, b := range bad {
					fmt.Fprintf(stdout, "  %s\n", b)
				}
			} else {
				fmt.Fprintf(stdout, "valid %s\n", d)
			}
		}
		return rc
	case "compare":
		fs := flag.NewFlagSet(hunt.Tool+" runs compare", flag.ContinueOnError)
		fs.SetOutput(stderr)
		onlyNew := fs.Bool("new-only", false, "exit 1 only when B has a key A does not (a new class), not when a key went away")
		fs.Usage = func() {
			fmt.Fprintf(stderr, "usage: %s runs compare [--new-only] DIR_A DIR_B\n\nLists every cluster key with its row count in each run: the same target at two versions gives the\nclasses a fix removed (-) or a change brought (+). Exit 0 when both runs have the same keys, 1 otherwise.\n", hunt.Tool)
		}
		pos, err := interspersed(fs, args[1:])
		if err != nil || len(pos) != 2 {
			fs.Usage()
			return 2
		}
		a, err := rundir.Load(pos[0])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		b, err := rundir.Load(pos[1])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		count := func(r *rundir.Run) map[string]int {
			m := map[string]int{}
			for _, c := range r.Clusters.Clusters {
				m[c.Key] = c.Count
			}
			return m
		}
		ca, cb := count(a), count(b)
		keys := map[string]bool{}
		for k := range ca {
			keys[k] = true
		}
		for k := range cb {
			keys[k] = true
		}
		var ks []string
		for k := range keys {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		fmt.Fprintf(stdout, "A %s@%s\nB %s@%s\n", a.Manifest.Target, a.Manifest.Version.Resolved, b.Manifest.Target, b.Manifest.Version.Resolved)
		rc := 0
		for _, k := range ks {
			mark := "="
			switch {
			case ca[k] == 0:
				mark, rc = "+", 1
			case cb[k] == 0:
				mark = "-"
				if !*onlyNew {
					rc = 1
				}
			}
			fmt.Fprintf(stdout, "%s %6d %6d  %s\n", mark, ca[k], cb[k], k)
		}
		return rc
	}
	return usage()
}
