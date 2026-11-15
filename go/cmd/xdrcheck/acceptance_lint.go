package main

// Acceptance rows lint-fixtures and lint-current: the linter's fixture tests and its clean run.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/findings"
)

// lintRows: the fixture tests (lint-fixtures) and the clean run at the pinned current wallet-backend commit (lint-current).
func lintRows(c *acceptanceCtx) []acceptanceRow {
	// lint-fixtures, lint-current: the linter's fixture tests, and the clean run at the pinned current wallet-backend commit.
	// A lint report withheld from CI's upload is accounted for by its run's verdict (lintStandIns).
	runs, standIns, n := c.lintStandIns(c.runsOf("lint-current"))
	clean := c.needRuns(cleanRunRow(c.dir, c.shown, c.pins.Pipelines.WalletBackend.Current), runs)
	if n > 0 && clean.status != statusMissing {
		clean.checked += fmt.Sprintf("; %s not in this directory (withheld from the upload while a row awaits finding review), each run's verdict read instead (%s)",
			count(n, "lint report", "lint reports"), strings.Join(standIns, ", "))
	}
	return []acceptanceRow{fixtureRow(c.dir, c.shown), clean}
}

// fixtureRow is lint-fixtures from the `go test -json` output make lint-fixtures leaves at <dir>/lint-fixtures.jsonl.
func fixtureRow(dir, shown string) acceptanceRow {
	const name = "lint-fixtures.jsonl"
	r := acceptanceRow{check: "lint-fixtures", artefact: "`" + shown + "/" + name + "` (make lint-fixtures)"}
	f, err := os.Open(filepath.Join(dir, name))
	if errors.Is(err, os.ErrNotExist) {
		r.status, r.checked = statusNotRecorded, "no "+shown+"/"+name+": make lint-fixtures was not run against these reports"
		return r
	}
	if err != nil {
		r.status, r.checked = statusNotMet, err.Error()
		return r
	}
	defer f.Close()
	passed, failed := 0, map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for n := 1; sc.Scan(); n++ {
		var ev struct{ Action, Package, Test string }
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			r.status, r.checked = statusNotMet, fmt.Sprintf("%s line %d does not read: %v", name, n, err)
			return r
		}
		switch {
		case ev.Action == "pass" && ev.Test != "":
			passed++
		case ev.Action == "fail":
			failed[strings.TrimSpace(ev.Package+" "+ev.Test)] = true
		}
	}
	if err := sc.Err(); err != nil {
		r.status, r.checked = statusNotMet, fmt.Sprintf("%s: %v", name, err)
		return r
	}
	switch {
	case len(failed) > 0:
		var names []string
		for k := range failed {
			names = append(names, k)
		}
		sort.Strings(names)
		r.status, r.checked = statusNotMet, fmt.Sprintf("%s failed (%s); %d passed", count(len(failed), "test or package", "tests or packages"), strings.Join(names, ", "), passed)
	case passed == 0:
		r.status, r.checked = statusNotMet, name+" records no passing test (the run stopped before the tests)"
	default:
		r.status, r.checked = statusMet, fmt.Sprintf("the linter's tests, seeded-violation fixtures included: all %d passed", passed)
	}
	return r
}

// lintSummary is what lint-current reads of a lint run: <name>.summary.json, or <name>.verdict.json when the summary is
// not there. Both come from scripts/lint-pipeline.sh; the verdict carries the same outcome with no site in it (no
// file, line, function, message or reason), so CI uploads it while it withholds a report that names a site
// pending finding review (scripts/ci/withhold-pending.py).
type lintSummary struct {
	Schema  string `json:"schema"` // lintVerdictSchema in a verdict; absent in a summary
	Mode    string `json:"mode"`
	Overlay bool   `json:"overlay"`
	Commits []struct {
		Commit string `json:"commit"`
		// Report is whether the run wrote the commit's xcc.report/v1 report (verdict only).
		Report  bool `json:"report"`
		Reports int  `json:"reports"`
		Pending int  `json:"pending"`
		// Clean is whether xdrlint runs clean at the commit (exits 0 with the shipped profile after the
		// suppressions, no pending error excused); nil in a summary that does not state it.
		Clean          *bool  `json:"clean"`
		CleanStatement string `json:"clean_statement"`
		// Unsuppressed counts the unsuppressed reports; PendingErrors is how many of the pending ones are errors.
		Unsuppressed *struct {
			PendingErrors *int `json:"pending_errors"`
		} `json:"unsuppressed"`
	} `json:"commits"`
	// Problems is the list of problems in a summary and their count in a verdict.
	Problems json.RawMessage `json:"problems"`
}

const lintVerdictSchema = "xdrlint.verdict/v1"

// problems returns the run's problems: their number, and their text when the file states it (a summary).
func (s *lintSummary) problems() (int, []string, error) {
	raw := strings.TrimSpace(string(s.Problems))
	switch {
	case raw == "" || raw == "null":
		return 0, nil, nil
	case strings.HasPrefix(raw, "["):
		var list []string
		err := json.Unmarshal(s.Problems, &list)
		return len(list), list, err
	default:
		var n int
		err := json.Unmarshal(s.Problems, &n)
		return n, nil, err
	}
}

// readLintSummary reads <dir>/<name>.summary.json, or <dir>/<name>.verdict.json when there is no summary. It
// returns the file read ("" when neither exists).
func readLintSummary(dir, name string) (*lintSummary, string, error) {
	for _, file := range []string{name + ".summary.json", name + ".verdict.json"} {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		var s lintSummary
		if err == nil {
			err = json.Unmarshal(data, &s)
		}
		if err == nil {
			_, _, err = s.problems()
		}
		if err != nil {
			return nil, file, fmt.Errorf("%s does not read: %v", file, err)
		}
		return &s, file, nil
	}
	return nil, "", nil
}

// cleanRunRow is lint-current's verdict from the pinned current wallet-backend commit's lint summary (make
// lint-wallet-backend): met only when the run passes its accounting and states that the commit runs clean, that
// is, no unsuppressed error after the suppressions, a pending error included (docs/acceptance.md). A pending error
// keeps it `not met`; a pending warning does not make the run unclean, so the row is met and says how many
// warnings await finding review (they still count in findings-linked). A summary that does not state clean or how many
// pending reports are errors keeps it `not met` while anything is pending. (The before/after reports are required
// runs of lint-current too; their presence is checked from the required run set.)
func cleanRunRow(dir, shown, current string) acceptanceRow {
	const name = "lint-wallet-backend"
	r := acceptanceRow{check: "lint-current", artefact: "`" + shown + "/" + name + ".summary.json` (make lint-wallet-backend)"}
	s, file, err := readLintSummary(dir, name)
	if file != "" {
		r.artefact = "`" + shown + "/" + file + "` (make lint-wallet-backend)"
	}
	switch {
	case err != nil:
		r.status, r.checked = statusNotMet, err.Error()
		return r
	case s == nil:
		r.status, r.checked = statusMissing, "no "+shown+"/"+name+".summary.json"
		return r
	}
	at := -1
	for i, c := range s.Commits {
		if c.Commit == current {
			at = i
		}
	}
	nProblems, problems, _ := s.problems()
	switch {
	case s.Overlay:
		r.status, r.checked = statusNotMet, file+" was made with the private overlay"
	case at < 0:
		r.status, r.checked = statusMissing, fmt.Sprintf("%s has no run at the pinned current commit %.8s", file, current)
	case nProblems > 0 && len(problems) > 0:
		r.status, r.checked = statusNotMet, fmt.Sprintf("%s at %.8s: %s", count(len(problems), "problem", "problems"), current, strings.Join(problems, "; "))
	case nProblems > 0:
		r.status, r.checked = statusNotMet, fmt.Sprintf("%s at %.8s (listed in the lint run's log and %s.summary.json)", count(nProblems, "problem", "problems"), current, name)
	default:
		c := s.Commits[at]
		pendingErrors := -1
		if c.Unsuppressed != nil && c.Unsuppressed.PendingErrors != nil {
			pendingErrors = *c.Unsuppressed.PendingErrors
		}
		switch {
		case c.Clean != nil && !*c.Clean:
			r.status, r.checked = statusNotMet, fmt.Sprintf("wallet-backend %.8s: %s", current, orDefault(c.CleanStatement, "not clean"))
		case c.Pending > 0 && (c.Clean == nil || pendingErrors < 0 || pendingErrors > 0):
			r.status, r.checked = statusNotMet, fmt.Sprintf("wallet-backend %.8s: %d reports, every one expected or suppressed except %s",
				current, c.Reports, pendingText(c.Pending))
		case c.Pending > 0:
			r.status, r.checked = statusMet, fmt.Sprintf("wallet-backend %.8s: %d reports, every one expected or suppressed except %s awaiting finding review "+
				"(%s; a warning does not make the run unclean, and it counts in findings-linked)", current, c.Reports, count(c.Pending, "warning", "warnings"), waitingFindings)
		default:
			r.status, r.checked = statusMet, fmt.Sprintf("wallet-backend %.8s: all %d reports are in the frozen expected list and suppressed with a reason and a finding", current, c.Reports)
		}
		if c.CleanStatement != "" && !strings.Contains(r.checked, c.CleanStatement) {
			r.checked += "; " + c.CleanStatement
		}
	}
	return r
}

// lintStandIns splits lint-current's required runs: a lint run whose report is not under the reports directory but
// whose verdict (<make target>.verdict.json) records that the run wrote it, passed its accounting and had a row
// pending finding review at that commit stands in for it. That is what CI's reports directory holds after
// scripts/ci/withhold-pending.py withheld a report naming a site pending finding review; a report absent for
// any other reason stays missing. Every other run is returned for needRuns; standIns names each verdict read and
// how many reports it stood in for, n in all.
func (c *acceptanceCtx) lintStandIns(runs []findings.RequiredRun) (rest []findings.RequiredRun, standIns []string, n int) {
	verdicts := map[string]*lintSummary{}
	used := map[string]int{}
	var order []string
	for _, run := range runs {
		if run.Tool != "lint" || run.Version == "" {
			rest = append(rest, run)
			continue
		}
		if _, err := os.Stat(filepath.Join(c.dir, filepath.FromSlash(run.Report))); err == nil {
			rest = append(rest, run)
			continue
		}
		v, seen := verdicts[run.Make]
		if !seen {
			data, err := os.ReadFile(filepath.Join(c.dir, run.Make+".verdict.json"))
			if err == nil {
				v = &lintSummary{}
				if json.Unmarshal(data, v) != nil {
					v = nil
				}
			}
			verdicts[run.Make] = v
		}
		ok := false
		if v != nil && !v.Overlay {
			if np, _, err := v.problems(); err == nil && np == 0 && v.Schema == lintVerdictSchema {
				for _, cm := range v.Commits {
					ok = ok || (cm.Commit == run.Version && cm.Report && cm.Pending > 0)
				}
			}
		}
		if !ok {
			rest = append(rest, run)
			continue
		}
		if used[run.Make] == 0 {
			order = append(order, run.Make)
		}
		used[run.Make]++
		n++
	}
	for _, m := range order {
		standIns = append(standIns, fmt.Sprintf("%s.verdict.json: %d", m, used[m]))
	}
	return rest, standIns, n
}
