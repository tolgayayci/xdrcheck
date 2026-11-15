package main

// Acceptance rows guide-table and guide-review: the guide's generated field table and its claims review.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// guideRows: the guide table's own report (guide-table) and the claims review (guide-review).
func guideRows(c *acceptanceCtx) []acceptanceRow {
	// guide-table, guide-review: the guide table's own report (xdrcheck-corpus guide-table --report, make verify-guide).
	guide := c.byTool("xdrcheck-corpus guide-table")
	r4a := c.corpusRowOf(guide, "guide-table", "the generated field table agrees with the manifest", "guide-table")
	switch {
	case len(guide) == 0:
		r4a = acceptanceRow{check: "guide-table", status: statusNotRecorded,
			checked: "no " + c.shown + "/guide-table.json: make verify-guide was not run against these reports", artefact: "make verify-guide"}
	case r4a.status == statusMissing:
		r4a.status, r4a.checked = statusNotMet, "the guide-table report holds no rows (no entry cites the table)"
	}
	return []acceptanceRow{r4a, claimsRow(filepath.Join(c.root, "guide", "claims.yaml"))}
}

var reviewerStatus = regexp.MustCompile(`^\s*reviewer_status:\s*([a-z]+)\s*$`)

// claimsRow is guide-review: the guide's claims all reviewed (confirmed or corrected) by a core or platform engineer.
func claimsRow(path string) acceptanceRow {
	r := acceptanceRow{check: "guide-review", artefact: "`guide/claims.yaml` (reviewer status per claim)"}
	f, err := os.Open(path)
	if err != nil {
		r.status, r.checked = "missing", "no guide/claims.yaml"
		return r
	}
	defer f.Close()
	counts := map[string]int{}
	total := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := reviewerStatus.FindStringSubmatch(sc.Text()); m != nil {
			counts[m[1]]++
			total++
		}
	}
	done := counts["confirmed"] + counts["corrected"]
	switch {
	case total == 0:
		r.status, r.checked = "missing", "guide/claims.yaml lists no claims"
	case done == total:
		r.status, r.checked = "met", fmt.Sprintf("all %d claims confirmed or corrected by the review", total)
	default:
		r.status = statusNotMet
		r.checked = fmt.Sprintf("%d of %d claims reviewed (%d unreviewed, %d disputed); publication waits on the review by a core or platform engineer, outside the build",
			done, total, counts["unreviewed"], counts["disputed"])
	}
	return r
}
