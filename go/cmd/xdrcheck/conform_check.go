package main

// xdrcheck conform check [--mode development|acceptance] [--overlay DIR] [--pending FILE] <matrix.json>
//
// Fails on every cell whose check is undeclared, unexpected-conform or known-changed. An undeclared cell is a
// divergence no entry declares; in development mode (the default) it does not fail the check when it is
// accounted for as pending, and it is then listed as such:
//
//   - "undeclared: pending finding F-NNNN": a finding record lists the cell's report row in
//     evidence.report_rows. Records are read from findings/ and, with --overlay DIR (or XDRCHECK_OVERLAY), from the
//     private overlay, which is where a defect that is not reported upstream yet is recorded
//     (`xdrcheck findings new --from <report.json> --row <row_id> --overlay DIR`).
//   - "undeclared: pending finding review": the cell is in the committed pending list (--pending FILE; default
//     findings/pending/conformance.json), {"pending": [{"entry", "variant", "column", "level"}]} with no
//     description, the list public CI uses because it never loads the overlay. An item whose cells the run has
//     but none undeclared is stale and fails the check.
//
// In acceptance mode pending cells fail too. A required column of the run that judged fewer than --min-judged
// cells (default 1; n_a cells do not count) fails the check too: a column that judged nothing cannot pass.
// Exit codes: 0 pass, 1 failing, stale or starved, 2 the check could not run.

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
)

func conformCheck(args []string) int {
	fs := flag.NewFlagSet("xdrcheck conform check", flag.ContinueOnError)
	mode := fs.String("mode", verdict.ModeDevelopment, "development (pending cells are reported and pass) or acceptance (they fail)")
	overlay := overlayFlag(fs)
	pending := fs.String("pending", "", "pending list (default "+verdict.PendingFile+" at the repository root, when it exists)")
	minJudged := fs.Int("min-judged", verdict.MinJudged, "judged (not n_a) cells every required column must have")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(os.Stderr, "xdrcheck conform check: "+format+"\n", a...)
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: xdrcheck conform check [--mode development|acceptance] [--overlay DIR] [--pending FILE] <matrix.json>")
		return 2
	}
	if *mode != verdict.ModeDevelopment && *mode != verdict.ModeAcceptance {
		return fail("--mode %q: want development or acceptance", *mode)
	}
	m, err := verdict.ReadMatrix(fs.Arg(0))
	if err != nil {
		return fail("%v", err)
	}
	rows, err := findingRows(*overlay)
	if err != nil {
		return fail("%v", err)
	}
	listPath := *pending
	if listPath == "" {
		if root, err := repoRoot(); err == nil {
			listPath = filepath.Join(root, verdict.PendingFile)
		}
	}
	var list []verdict.PendingCell
	if listPath != "" {
		if list, err = verdict.ReadPending(listPath); err != nil {
			return fail("%v", err)
		}
	}
	verdict.MinJudged = *minJudged
	res := m.Check(*mode, rows, list)
	printCheck(os.Stdout, res, *overlay != "")
	if len(m.Infrastructure) > 0 {
		return fail("the run had %d infrastructure problem(s):\n  %s", len(m.Infrastructure), strings.Join(m.Infrastructure, "\n  "))
	}
	review, finding := 0, 0
	for _, c := range append(append([]verdict.CheckedCell{}, res.Pending...), res.Failing...) {
		switch c.Status {
		case "pending-review":
			review++
		case "pending-finding":
			finding++
		}
	}
	verb := "passing"
	if *mode == verdict.ModeAcceptance {
		verb = "failing"
	}
	fmt.Fprintf(os.Stderr, "xdrcheck conform check (%s mode): %d cells, %d failing, %d known but not yet triaged and %d recorded as a finding but not yet declared (%s in this mode), %d stale list items, %d required columns under the judged-cell floor\n",
		*mode, len(m.Cells), len(res.Failing), review, finding, verb, len(res.Stale), len(res.Starved))
	if !res.Passed() {
		return 1
	}
	return 0
}

// findingRows maps report row IDs to the finding records (public, and the overlay's when given) that list them.
func findingRows(overlay string) (map[string][]verdict.FindingRef, error) {
	store, _, err := openStore(overlay)
	if err != nil {
		return nil, err
	}
	recs := map[string]verdict.FindingRef{}
	rows := map[string][]string{}
	for id, l := range store.Records {
		recs[id] = verdict.FindingRef{ID: id, State: l.Record.State, Overlay: l.Overlay}
		if ev := l.Record.Evidence; ev != nil {
			rows[id] = ev.ReportRows
		}
	}
	return verdict.PendingRows(recs, rows), nil
}

func printCheck(w io.Writer, res *verdict.CheckResult, overlay bool) {
	line := func(tag string, c verdict.CheckedCell, what string) {
		fmt.Fprintf(w, "%-8s %s %s %s %s: %s (verdict %s, expected %s)%s\n", tag, c.Column, c.Entry, orDash(c.Variant), c.Level, what,
			c.Verdict, c.ExpectedVerdict, knownSuffix(c.KnownDivergence))
	}
	what := func(c verdict.CheckedCell) string {
		switch c.Status {
		case "pending-finding":
			return "known divergence, recorded as finding " + findingList(c.Findings) + " but not yet declared on the entry"
		case "pending-review":
			return "known divergence, not yet triaged (listed in " + verdict.PendingFile + ")"
		}
		switch c.Check {
		case "undeclared":
			return "new divergence: no entry declares it and no finding records it (report row " + c.RowID() + ")"
		case "unexpected-conform":
			return "conforms although a known divergence covers this version: the declared range is stale"
		case "known-changed":
			return "differs from the declared known divergence"
		}
		return c.Check
	}
	undeclared := 0
	for _, c := range res.Failing {
		s := what(c)
		if c.Status != "fail" {
			s += "; acceptance mode: every divergence must be declared"
		} else if c.Check == "undeclared" {
			undeclared++
		}
		line("FAIL", c, s)
	}
	for _, c := range res.Pending {
		line("KNOWN", c, what(c))
	}
	for _, s := range res.Starved {
		fmt.Fprintf(w, "FAIL     required column %s judged %d of its %d cells (n_a cells are not judged; the floor is %d)\n",
			s.Column, s.Judged, s.Cells, verdict.MinJudged)
	}
	for _, p := range res.Stale {
		fmt.Fprintf(w, "STALE    %s is listed as not yet triaged in %s, but the run's cell no longer shows a new divergence; remove the item (or declare the divergence)\n", p, verdict.PendingFile)
	}
	if undeclared > 0 {
		where := "the private overlay (--overlay DIR, outside the working tree)"
		if !overlay {
			where = "the private overlay (this check ran without one)"
		}
		fmt.Fprintf(w, `
%d new divergence(s) above: no entry declares them and no finding records them. To pass:
  - an SDK defect not reported upstream: record it in %s with
      xdrcheck findings new --from <report dir>/report.json --row <report row> --overlay DIR
    (add the defect's other rows to the record's evidence.report_rows), then run this check with --overlay DIR;
    public CI, which has no overlay, passes only if the cell is an item of %s
    ({"entry", "variant", "column", "level"}, no description);
  - a defect already reported or fixed upstream: declare it on the entry as a known divergence;
  - a wrong expectation or a driver bug: fix the entry or the driver.
`, undeclared, where, verdict.PendingFile)
	}
}

func findingList(f []verdict.FindingRef) string {
	parts := make([]string, len(f))
	for i, r := range f {
		where := ""
		if r.Overlay {
			where = ", overlay"
		}
		parts[i] = fmt.Sprintf("%s (%s%s)", r.ID, r.State, where)
	}
	return strings.Join(parts, ", ")
}
