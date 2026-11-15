package main

// xdrcheck report:
//
//	xdrcheck report acceptance <reports-dir> [--out FILE] [--full-ci TARGETS]   the acceptance table, one row per acceptance check
//	xdrcheck report redact <report> [--out FILE]            a copy of an xcc.report/v1 file that is safe to share
//	xdrcheck report diff <report-a> <report-b>              rows that newly pass, newly fail or changed result
//
// acceptance writes <reports-dir>/acceptance.md by default (and the same rows as JSON beside it, acceptance.json) and
// prints it; it exits 0 once the table is written,
// whatever the checks' status (each check has its own make target that fails), and 2 on a report made with
// the private overlay or one that does not read. --full-ci names the make targets (comma-separated) that only the
// full CI runs: a check whose only absent reports are theirs, and whose own verdict in this run is `met`, is
// `proven in full CI` instead of `missing` (the pull-request CI's table, .github/workflows/pr.yml). redact exits 0 when the copy is written. diff exits 0 when the
// two reports agree row by row, 1 when they differ, and 2 when they cannot be compared (another tool, a report
// that does not read).

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/findings"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

func init() {
	register("report", "build, redact and diff reports", func(args []string) int { return reportMain(args, os.Stdout, os.Stderr) })
}

func reportMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(stderr, "usage: xdrcheck report acceptance|redact|diff [flags] <args>")
		return 2
	}
	switch args[0] {
	case "acceptance":
		return reportAcceptance(args[1:], stdout, stderr)
	case "redact":
		return reportRedact(args[1:], stdout, stderr)
	case "diff":
		return reportDiff(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "xdrcheck report: unknown subcommand %q\n", args[0])
	return 2
}

// parseInterspersed parses flags that may come before or after the positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// ---- acceptance ----

// EmbargoSentence is always present in the acceptance report, so that its presence reveals nothing.
const EmbargoSentence = "Findings under embargo, if any, are not represented in this report; the private acceptance run covers them."

type acceptanceRow struct{ check, status, checked, artefact string }

// Statuses of the acceptance table. Anything open, including rows that wait on people outside the build, is
// `not met`; the row's text says which part waits on whom.
const (
	statusMet         = "met"
	statusNotMet      = "not met"
	statusMissing     = "missing"      // no report for the check
	statusNotRecorded = "not recorded" // the check's make target left no report
	// statusFullCI: what this run checked holds, and the rest of the check's runs are made only by the full CI
	// (--full-ci); the table of that run is the check's verdict.
	statusFullCI = "proven in full CI"
)

// waitingFindings names the outside action that rows pending finding review wait for.
const waitingFindings = "filing waits on the maintainers' approval of each draft"

// reportStats is what the acceptance table needs from one report.
type reportStats struct {
	path, rel                  string
	header                     *report.Header
	rows, failures, unexpected int
	pending                    int // rows the producing tool marked pending finding review
	versions, columns          map[string]bool
	corpusOK, corpusFail       map[string]int
	failuresByVersion          map[string]int
	// ag4Whole holds the AG-4 rows a whole-corpus run adds (ag4WholeRows), by entry: true when the row passed.
	ag4Whole map[string]bool
}

// ag4WholeRows are the rows a whole-corpus AG-4 run adds beside its per-entry rows: the committed mirror list
// (every local-core entry listed once) and the floor (at least one AG-4 row, every mapped entry passing).
var ag4WholeRows = []string{"mirrors.json", "floor:ag4"}

func readStats(path, rel string) (*reportStats, error) {
	s := &reportStats{path: path, rel: rel, versions: map[string]bool{}, columns: map[string]bool{},
		corpusOK: map[string]int{}, corpusFail: map[string]int{}, failuresByVersion: map[string]int{}, ag4Whole: map[string]bool{}}
	h, _, err := report.ReadFile(path, func(r *report.Row) error {
		s.rows++
		if r.Failure {
			s.failures++
			s.failuresByVersion[r.Target.Version]++
		}
		switch r.Expectation {
		case "unexpected":
			s.unexpected++
		case report.ExpectationPending:
			s.pending++
		}
		s.versions[r.Target.Version] = true
		if r.Target.Column != "" {
			s.columns[r.Target.Column] = true
		}
		if r.Corpus != nil {
			if r.Corpus.OK {
				s.corpusOK[r.Corpus.Check]++
			} else {
				s.corpusFail[r.Corpus.Check]++
			}
			if r.Corpus.Check == "ag4" && slices.Contains(ag4WholeRows, r.Entry) {
				s.ag4Whole[r.Entry] = r.Corpus.OK
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.header = h
	return s, nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// count is "1 <one>" or "N <many>".
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// pendingText names the rows pending finding review and the outside action they wait for.
func pendingText(n int) string {
	return count(n, "row", "rows") + " pending finding review; " + waitingFindings
}

// missingRuns returns the runs of the required set (findings/required-runs.d/, expanded by
// findings.RequiredRuns) that have no report under dir, as "<report> (make <target>)". A check that needs one of
// them is `missing`.
func missingRuns(dir string, runs []findings.RequiredRun) []string {
	var out []string
	for _, r := range runs {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(r.Report))); err != nil {
			out = append(out, r.Report+" (make "+r.Make+")")
		}
	}
	return out
}

// needRuns turns a row `missing` when a required run its check reads has no report under the reports directory.
// A run that only the full CI makes (--full-ci) does not: when every absent run is one of those and the row is
// `met` on what this run checked, it is `proven in full CI`; a row that is `not met` or `missing` on its own stays so.
func (c *acceptanceCtx) needRuns(r acceptanceRow, runs []findings.RequiredRun) acceptanceRow {
	var absent, deferred []findings.RequiredRun
	for _, run := range runs {
		if _, err := os.Stat(filepath.Join(c.dir, filepath.FromSlash(run.Report))); err == nil {
			continue
		}
		if c.fullCI[run.Make] {
			deferred = append(deferred, run)
		} else {
			absent = append(absent, run)
		}
	}
	switch {
	case len(absent) > 0:
		r.status, r.checked = statusMissing, "the check needs these runs' reports: "+strings.Join(missingRuns(c.dir, runs), ", ")
	case len(deferred) > 0 && r.status == statusMet:
		var names []string
		for _, run := range deferred {
			names = append(names, run.Report+" (make "+run.Make+")")
		}
		r.status = statusFullCI
		r.checked = "this run: " + r.checked + "; the full CI also makes " + strings.Join(names, ", ")
	}
	return r
}
