package main

// xdrcheck overlay (SECURITY.md):
//
//	xdrcheck overlay audit [--overlay DIR] [--root DIR] [--rev REV | --revs RANGE | --emit-tokens]
//
// audit checks the working tree against the private overlay before a push: no trigger of an embargoed overlay
// record (its corpus entries with a public column, recipes, columns only the overlay runs, linter rows and
// sinks, evidence files, record ID) may be in the tree, every recipe has a manifest entry, no public file is a
// row subset of, or identical to, the overlay file at the same path, and no public file at any path has the
// git blob id of an overlay file (kind blob-id). It prints record IDs, problem kinds and paths, never a
// record's description. The overlay defaults to $XDRCHECK_OVERLAY; the root to the nearest directory, from the
// working directory up, that holds pins.toml.
//
// --rev REV audits the tree of one commit and --revs RANGE every commit `git rev-list RANGE` lists, read from
// the repository at the root without a checkout; each problem is printed once with the first commit (in
// rev-list order) that holds it and the number of commits that do. --emit-tokens prints the overlay's tokens
// (record IDs, entries, recipes, evidence paths, linter row sites, sinks, overlay-only columns) as
// tab-separated lines: token, kind, public (the tree at the root holds it), records; for a history scan.
//
// Exit codes: 0 no problem; 1 at least one problem; 2 the tool could not run (no overlay, an unreadable record
// or sets file, an overlay inside the tree, a range that is not one).

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/overlay"
)

func init() {
	register("overlay", "audit the working tree against the private overlay before a push", func(args []string) int {
		return overlayMain(args, os.Stdout, os.Stderr)
	})
}

func overlayMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(stderr, "usage: xdrcheck overlay audit [flags]")
		return 2
	}
	switch args[0] {
	case "audit":
		return overlayAudit(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "xdrcheck overlay: unknown subcommand %q\n", args[0])
	return 2
}

func overlayAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck overlay audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("overlay", os.Getenv("XDRCHECK_OVERLAY"), "private overlay directory (default $XDRCHECK_OVERLAY)")
	root := fs.String("root", "", "the tree to audit, or with --rev/--revs the repository (default the repository root)")
	rev := fs.String("rev", "", "audit the tree of this commit instead of the working tree")
	revs := fs.String("revs", "", "audit the tree of every commit `git rev-list RANGE` lists")
	emit := fs.Bool("emit-tokens", false, "print the overlay's tokens for a history scan instead of auditing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "xdrcheck overlay audit: "+format+"\n", a...)
		return 2
	}
	if fs.NArg() != 0 {
		return fail("unexpected arguments %q", fs.Args())
	}
	if n := btoi(*rev != "") + btoi(*revs != "") + btoi(*emit); n > 1 {
		return fail("--rev, --revs and --emit-tokens exclude each other")
	}
	if *dir == "" {
		return fail("no overlay: pass --overlay DIR or set XDRCHECK_OVERLAY")
	}
	if st, err := os.Stat(*dir); err != nil || !st.IsDir() {
		return fail("overlay %s is not a directory", *dir)
	}
	if *root == "" {
		r, err := repoRoot()
		if err != nil {
			return fail("%v", err)
		}
		*root = r
	}
	switch {
	case *emit:
		toks, err := overlay.EmitTokens(*root, *dir)
		if err != nil {
			return fail("%v", err)
		}
		for _, t := range toks {
			pub := "-"
			if t.Public {
				pub = "public"
			}
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", t.Value, t.Kind, pub, strings.Join(t.Records, ","))
		}
		return 0
	case *rev != "" || *revs != "":
		return overlayAuditRevs(*root, *dir, *rev, *revs, stdout, stderr)
	}
	res, err := overlay.Audit(*root, *dir)
	if err != nil {
		return fail("%v", err)
	}
	for _, k := range res.Kept {
		fmt.Fprintf(stdout, "kept %s %s (no public column, rule or driver targets it)\n", k.Record, k.Path)
	}
	for _, p := range res.Problems {
		fmt.Fprintf(stdout, "PROBLEM %s\n", p)
	}
	fmt.Fprintf(stdout, "overlay audit: %d record(s), %d embargoed, %d problem(s)\n", res.Records, len(res.Embargoed), len(res.Problems))
	if len(res.Problems) > 0 {
		return 1
	}
	return 0
}

func overlayAuditRevs(repo, dir, rev, spec string, stdout, stderr io.Writer) int {
	var list []string
	var err error
	if rev != "" {
		var c string
		if c, err = overlay.ResolveCommit(repo, rev); err == nil {
			list = []string{c}
		}
	} else {
		list, err = overlay.RevList(repo, spec)
	}
	if err != nil {
		fmt.Fprintf(stderr, "xdrcheck overlay audit: %v\n", err)
		return 2
	}
	start := time.Now()
	type seen struct {
		first string
		count int
	}
	problems, notes := map[string]*seen{}, map[string]*seen{}
	var order, noteOrder []string
	records, embargoed, bad := 0, 0, 0
	err = overlay.AuditRevs(repo, dir, list, func(c string, res *overlay.Result) error {
		records, embargoed = res.Records, len(res.Embargoed)
		if len(res.Problems) > 0 {
			bad++
		}
		for _, p := range res.Problems {
			k := p.String()
			if problems[k] == nil {
				problems[k] = &seen{first: c}
				order = append(order, k)
			}
			problems[k].count++
		}
		for _, n := range res.Notes {
			if notes[n] == nil {
				notes[n] = &seen{first: c}
				noteOrder = append(noteOrder, n)
			}
			notes[n].count++
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(stderr, "xdrcheck overlay audit: %v\n", err)
		return 2
	}
	for _, n := range noteOrder {
		fmt.Fprintf(stdout, "note %s %s (in %d commit(s))\n", short(notes[n].first), n, notes[n].count)
	}
	for _, k := range order {
		fmt.Fprintf(stdout, "PROBLEM %s %s (in %d commit(s))\n", short(problems[k].first), k, problems[k].count)
	}
	fmt.Fprintf(stdout, "overlay audit: %d commit(s), %d record(s), %d embargoed, %d with problems, %d distinct problem(s), %s\n",
		len(list), records, embargoed, bad, len(order), time.Since(start).Round(time.Second))
	if len(order) > 0 {
		return 1
	}
	return 0
}

func short(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
