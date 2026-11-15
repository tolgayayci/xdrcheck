package main

// Acceptance rows replay-regression/wallet-backend-729, -731 and -716: the known wallet-backend defects'
// regression pairs (xdrcheck replay --assert-known).

import (
	"fmt"

	"github.com/tolgayayci/xdrcheck/go/internal/findings"
)

// replayRegressionBugs maps the wallet-backend acceptance bugs onto their checks.
var replayRegressionBugs = []struct{ check, bug string }{{"replay-regression/wallet-backend-729", "729"}, {"replay-regression/wallet-backend-731", "731"}, {"replay-regression/wallet-backend-716", "716"}}

// replayRegressionRows: one row per acceptance bug, from the --assert-known reports at both commits of its pair.
func replayRegressionRows(c *acceptanceCtx) []acceptanceRow {
	// replay-regression: one --assert-known replay report per pinned commit of each pair.
	replays := c.byTool("xcc replay")
	var rows []acceptanceRow
	for _, b := range replayRegressionBugs {
		pair, ok := c.pins.Pipelines.WalletBackend.AcceptancePair(b.bug)
		r := acceptanceRow{check: b.check, artefact: "`" + c.shown + "/replay-regression/<commit>/` (make verify-replay)"}
		if !ok {
			r.status, r.checked = "missing", "pins.toml has no wallet-backend acceptance pair for #"+b.bug
			rows = append(rows, r)
			continue
		}
		find := func(commit string) []*reportStats {
			var rs []*reportStats
			for _, s := range replays {
				if s.versions[commit] && s.header.Mode.Suite == "assert-known" {
					rs = append(rs, s)
				}
			}
			return rs
		}
		pre, fixed := find(pair.Prefix), find(pair.Fixed)
		if len(pre)+len(fixed) > 0 {
			r.artefact = rels(append(append([]*reportStats{}, pre...), fixed...))
		}
		unexpected, preFailures := 0, 0
		for _, s := range append(append([]*reportStats{}, pre...), fixed...) {
			unexpected += s.unexpected
		}
		for _, s := range pre {
			preFailures += s.failuresByVersion[pair.Prefix]
		}
		switch {
		case len(pre) == 0 || len(fixed) == 0:
			r.status = "missing"
			r.checked = fmt.Sprintf("#%s: an --assert-known report for %s and for %s", b.bug, pair.Prefix[:8], pair.Fixed[:8])
		case unexpected > 0 || preFailures == 0:
			r.status = "not met"
			r.checked = fmt.Sprintf("#%s: %d unexpected results; %d failure rows at the pre-fix commit %s", b.bug, unexpected, preFailures, pair.Prefix[:8])
		default:
			r.status = "met"
			r.checked = fmt.Sprintf("#%s: the declared failure shows at %s (%d rows) and every result at %s is the declared one", b.bug, pair.Prefix[:8], preFailures, pair.Fixed[:8])
		}
		var pairRuns []findings.RequiredRun
		for _, run := range c.runsOf("replay-regression") {
			if run.Version == pair.Prefix || run.Version == pair.Fixed {
				pairRuns = append(pairRuns, run)
			}
		}
		rows = append(rows, c.needRuns(r, pairRuns))
	}
	return rows
}
