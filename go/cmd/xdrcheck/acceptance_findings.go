package main

// Acceptance row findings-linked: the acceptance-mode findings check.

import (
	"fmt"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/findings"
)

// findingsLinkedRow: the findings check in acceptance mode.
func findingsLinkedRow(c *acceptanceCtx) (acceptanceRow, error) {
	// findings-linked: the acceptance-mode findings check, through the same code path as make verify-findings-acceptance
	// (checkReportsDir: the same pending lists and private-row rule), so the two always agree.
	r6 := acceptanceRow{check: "findings-linked", artefact: "`findings/*/finding.json`; make verify-findings-acceptance"}
	if gone := missingRunsOrTally(c.dir, c.runsOf("findings-linked")); len(c.all) == 0 || len(gone) > 0 {
		r6.status, r6.checked = statusMissing, "the check needs these runs' reports: "+orDefault(strings.Join(gone, ", "), "any")
	} else {
		res, err := checkReportsDir(c.store, c.pending, c.dir, findings.Acceptance, false, privateRows(c.root), noDriver(c.root))
		if err != nil {
			return acceptanceRow{}, err
		}
		r6.status, r6.checked = findingsStatus(res)
	}
	return r6, nil
}

// missingRunsOrTally is missingRuns, with a run whose report CI withheld but whose tally is in dir counted as
// present: the findings check reads the tally in its place (checkReportsDir).
func missingRunsOrTally(dir string, runs []findings.RequiredRun) []string {
	tallies, err := findings.ReadTallies(dir)
	if err != nil {
		return []string{"the tallies do not read: " + err.Error()}
	}
	var rest []findings.RequiredRun
	for _, r := range runs {
		if tallies[r.Report] == nil {
			rest = append(rest, r)
		}
	}
	return missingRuns(dir, rest)
}

// findingsStatus is findings-linked from the acceptance-mode findings check's own result (the same check as
// make verify-findings-acceptance). Any open item is `not met`; the text keeps what the build must fix (rows
// without a finding, rows naming no record, invalid and orphaned records) apart from what waits on the
// maintainers (rows pending finding review, records not yet filed).
func findingsStatus(res *findings.Result) (string, string) {
	exempt := ""
	if len(res.SourceReadingOnly) > 0 {
		exempt = "; exempt from the orphan check, observed by source reading only on a target with no driver column: " + strings.Join(res.SourceReadingOnly, ", ")
	}
	if len(res.PrivateRunOnly) > 0 {
		exempt += "; exempt from the orphan check, rows only in the private acceptance run: " + strings.Join(res.PrivateRunOnly, ", ")
	}
	if res.Passed() {
		return statusMet, fmt.Sprintf("%d failure rows, every one linked; all %d records filed, duplicate-of or not-a-defect", res.FailureRows, res.Records) + exempt
	}
	var parts []string
	if res.UnlinkedRows > 0 {
		parts = append(parts, count(res.UnlinkedRows, "failure row", "failure rows")+" without a finding")
	}
	if res.DanglingRows > 0 {
		parts = append(parts, count(res.DanglingRows, "row names", "rows name")+" a finding that has no record")
	}
	if len(res.Invalid) > 0 {
		parts = append(parts, count(len(res.Invalid), "record does", "records do")+" not validate")
	}
	if len(res.Orphans) > 0 {
		parts = append(parts, count(len(res.Orphans), "orphaned record", "orphaned records")+" that no report row refers to: "+strings.Join(res.Orphans, ", "))
	}
	if len(res.MissingRuns) > 0 {
		parts = append(parts, count(len(res.MissingRuns), "required run", "required runs")+" missing: "+strings.Join(res.MissingRuns, ", "))
	}
	if len(res.StalePending) > 0 {
		parts = append(parts, count(len(res.StalePending), "stale pending entry", "stale pending entries")+": "+strings.Join(res.StalePending, "; "))
	}
	if n := len(res.ExpiredPending) + len(res.UndatedPending) + len(res.FuturePending); n > 0 {
		parts = append(parts, count(n, "pending entry", "pending entries")+" undated, dated in the future or older than "+
			fmt.Sprintf("%d days", int(findings.MaxPendingAge.Hours()/24)))
	}
	var wait []string
	if res.PendingRows > 0 {
		wait = append(wait, count(res.PendingRows, "row", "rows")+" pending finding review")
	}
	if len(res.NonTerminal) > 0 {
		wait = append(wait, fmt.Sprintf("%d of %d records not yet filed: %s", len(res.NonTerminal), res.Records, strings.Join(res.NonTerminal, ", ")))
	}
	if len(wait) > 0 {
		parts = append(parts, strings.Join(wait, "; ")+"; "+waitingFindings)
	}
	if len(parts) == 0 { // a failure this table does not know how to name
		parts = append(parts, "the acceptance-mode findings check failed (see make verify-findings-acceptance)")
	}
	text := strings.Join(parts, "; ")
	if len(res.PrivateOnly) > 0 {
		text += "; not checked for orphans here, because their rows come only from runs with the private overlay: " + strings.Join(res.PrivateOnly, ", ")
	}
	return statusNotMet, text + exempt
}
