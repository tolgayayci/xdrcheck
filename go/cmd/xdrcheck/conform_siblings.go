package main

// xdrcheck conform siblings: look for a defect found in one SDK in the other SDK families, de-duplicate each
// affected family against its upstream tracker (read-only), and write one draft per affected family.
//
//	xdrcheck conform siblings (--finding ID | --divergence URL) [--matrix FILE] [--manual FILE]... [--overlay DIR]
//	                     [--query TERMS]... [--confirm URL]... [--offline] [--plan] [--templates DIR]
//
// The matrix is a conformance matrix (`xdrcheck conform run` writes matrix.json; default
// reports/conformance/matrix.json). An SDK the kit has no driver for is checked from a manual evidence file
// (--manual; the format is in go/internal/conform/siblings/manual.go, with a worked example in
// findings/templates/manual-evidence.example.json). Drafts are rendered from findings/templates/.
//
// Tracker access is unauthenticated HTTP GET against the GitHub REST API (--offline uses only the upstream
// states already recorded). A family with no confirmed public upstream item, and every sibling of a finding that
// lives in the private overlay, is drafted in the overlay only (--overlay DIR or $XDRCHECK_OVERLAY). --plan prints
// the plan and writes nothing.
//
// Nothing is filed, commented on or reacted to, and no process is started: each draft's command is printed for
// a person to run after the user has approved that exact draft.
//
// Exit codes: 0 the plan was made (and written, without --plan); 2 the tool could not run.

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/conform/siblings"
	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func conformSiblings(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck conform siblings", flag.ContinueOnError)
	fs.SetOutput(stderr)
	finding := fs.String("finding", "", "the finding record the defect was found in")
	divergence := fs.String("divergence", "", "start from a known divergence: the upstream reference the matrix cells cite")
	matrixPath := fs.String("matrix", "", "conformance matrix (default reports/conformance/matrix.json)")
	overlay := overlayFlag(fs)
	templates := fs.String("templates", "", "draft templates (default findings/templates)")
	api := fs.String("github-api", siblings.DefaultAPI, "GitHub REST API base URL, read with unauthenticated GET only")
	offline := fs.Bool("offline", false, "do not query the tracker; use the upstream states already recorded")
	plan := fs.Bool("plan", false, "print the plan and write nothing")
	date := fs.String("date", "", "date to record, YYYY-MM-DD (default today, UTC)")
	var manual, queries, confirm multiFlag
	fs.Var(&manual, "manual", "manual evidence file for an SDK without a driver (repeatable)")
	fs.Var(&queries, "query", "tracker search terms (repeatable; default: the first words of each draft's title)")
	fs.Var(&confirm, "confirm", "an issue or pull request URL a person confirmed describes this defect (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "xdrcheck conform siblings: "+format+"\n", a...)
		return 2
	}
	switch {
	case fs.NArg() > 0:
		return fail("unexpected arguments %v", fs.Args())
	case (*finding == "") == (*divergence == ""):
		return fail("give exactly one of --finding ID and --divergence URL")
	}
	today := *date
	if today == "" {
		today = time.Now().UTC().Format("2006-01-02")
	}

	store, root, err := openStore(*overlay)
	if err != nil {
		return fail("%v", err)
	}
	if len(store.Problems) > 0 {
		return fail("the finding records do not check: %s", strings.Join(store.Problems, "; "))
	}
	if *matrixPath == "" {
		*matrixPath = filepath.Join(root, "reports", "conformance", verdict.MatrixFile)
	}
	m, err := verdict.ReadMatrix(*matrixPath)
	if err != nil {
		return fail("%v", err)
	}
	var sig *siblings.Signature
	if *finding != "" {
		l, ok := store.Records[*finding]
		if !ok {
			return fail("%s: no such record", *finding)
		}
		sig, err = siblings.FromFinding(m, l)
	} else {
		sig, err = siblings.FromDivergence(m, *divergence)
	}
	if err != nil {
		return fail("%v", err)
	}
	var evidence []*siblings.Manual
	for _, p := range manual {
		mv, err := siblings.LoadManual(p)
		if err != nil {
			return fail("%v", err)
		}
		evidence = append(evidence, mv)
	}
	if *templates == "" {
		*templates = filepath.Join(root, "findings", "templates")
	}
	tmpl, err := siblings.LoadTemplates(*templates)
	if err != nil {
		return fail("%v", err)
	}
	var tr siblings.Tracker = siblings.NewGitHub(*api)
	if *offline {
		rec := siblings.RecordedFrom(store, m, confirm)
		for _, mv := range evidence { // a person confirmed these when writing the evidence
			for _, u := range mv.Upstream {
				rec.Add(u, "open")
			}
		}
		tr = rec
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// A column the public sets file does not define is one only the overlay runs (no sets file: no column is
	// known to be private).
	var publicColumn func(string) bool
	setsPath := filepath.Join(root, "drivers", "sets.toml")
	if _, err := os.Stat(setsPath); err == nil {
		publicSets, err := conform.LoadSets(setsPath, root)
		if err != nil {
			return fail("%v", err)
		}
		publicColumn = func(id string) bool { return publicSets.Columns[id] != nil }
	}
	p, err := siblings.Run(ctx, tr, store, sig, m, evidence, siblings.Options{Today: today, Queries: queries, Confirm: confirm, Offline: *offline, Templates: tmpl, PublicColumn: publicColumn})
	if err != nil {
		return fail("%v", err)
	}
	printPlan(stdout, p, *offline)

	if *plan {
		fmt.Fprintln(stdout, "\n(plan only: nothing was written)")
		return 0
	}
	if _, err := siblings.Apply(store, p); err != nil {
		return fail("%v", err)
	}
	fmt.Fprintln(stdout)
	for _, dr := range p.Drafts {
		where := filepath.ToSlash(filepath.Join("findings", dr.Record.ID, dr.File))
		if dr.Overlay {
			where = "overlay " + where
		}
		state := "existing record"
		if dr.New {
			state = "new candidate record"
		}
		fmt.Fprintf(stdout, "%s (%s, %s): %s draft written to %s\n", dr.Record.ID, dr.SDK, state, dr.Kind, where)
	}
	return 0
}

// printPlan prints what was found per family and, for each draft, the command that would file it. The
// commands are printed, never run.
func printPlan(w io.Writer, p *siblings.Plan, offline bool) {
	sig := p.Signature
	from := sig.Name()
	if sig.Project != "" {
		from += " (" + sig.Project + ")"
	}
	fmt.Fprintf(w, "xdrcheck conform siblings: %s, defect group %s, %d signature cell(s)\n", from, p.Group, len(sig.Keys))
	for _, k := range sig.Keys {
		fmt.Fprintf(w, "  cell %s: %s\n", k, strings.Join(sig.Classes[k], ", "))
	}
	if offline {
		fmt.Fprintln(w, "offline: upstream states are as recorded, not checked today; nothing was searched")
	}
	fmt.Fprintln(w)
	for _, r := range p.Results {
		fmt.Fprintf(w, "%-8s %-14s %s\n", r.Family.SDK, r.Status, describe(r, len(sig.Keys)))
		if d := p.Decisions[r.Family.SDK]; d != nil {
			kind := d.Kind
			if kind == "" {
				kind = "no draft"
			}
			fmt.Fprintf(w, "%-8s %-14s upstream: %s: %s\n", "", "", kind, d.Why)
			for _, q := range d.Queries {
				fmt.Fprintf(w, "%-8s %-14s   looked up %s\n", "", "", q)
			}
		}
	}
	if len(p.Drafts) == 0 {
		fmt.Fprintln(w, "\nno drafts: no other SDK family shows this defect in its latest version, or each already has its draft")
		return
	}
	fmt.Fprintln(w, "\ndrafts:")
	for _, dr := range p.Drafts {
		where := "public tree"
		if dr.Overlay {
			where = "private overlay"
		}
		rec := "existing record"
		if dr.New {
			rec = "new candidate"
		}
		fmt.Fprintf(w, "\n%s  %s  %s  (%s, %s) %s\n", dr.Record.ID, dr.SDK, dr.Kind, rec, where, dr.BodyPath)
		for _, n := range dr.Notes {
			fmt.Fprintf(w, "  note: %s\n", n)
		}
		fmt.Fprintln(w, "  # NOT RUN. Nothing is filed by this tool. After the user approves this exact draft and channel,")
		fmt.Fprintln(w, "  # a person runs the command below and records the result in the finding record.")
		if dr.Overlay {
			fmt.Fprintln(w, "  # The body is in the private overlay; the path is relative to the overlay directory.")
		}
		for _, line := range strings.Split(dr.Command, "\n") {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
}

func describe(r *siblings.Result, cells int) string {
	cols := strings.Join(r.LatestColumns, ", ")
	if r.Manual != nil {
		cols += " (manual evidence, " + r.Manual.Method + ")"
	}
	var s string
	switch r.Status {
	case siblings.Affected:
		s = fmt.Sprintf("%s shows it on %d of %d cells", cols, len(r.Matches), cells)
	case siblings.Fixed:
		var older []string
		for _, o := range r.Earlier {
			older = appendOnce(older, o.Column)
		}
		s = fmt.Sprintf("%s shows it, %s does not", strings.Join(older, ", "), cols)
	case siblings.NotAffected:
		s = cols + " conforms on the exercised cells"
	case siblings.NotExercised:
		s = "no signature cell is exercised on " + cols
	case siblings.NoColumn:
		s = "no column in the matrix and no manual evidence (--manual FILE)"
	}
	if l := r.Record; l != nil {
		where := ""
		if l.Overlay {
			where = ", overlay"
		}
		s += fmt.Sprintf("; record %s (%s%s)", l.Record.ID, l.Record.State, where)
	}
	return s
}

func appendOnce(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
