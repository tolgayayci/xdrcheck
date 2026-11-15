package main

// Acceptance rows roundtrip and golden-agreement: corpus verification (xdrcheck-corpus verify reports).

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// corpusRows: the round-trip and reject checks (roundtrip) and the golden checks (golden-agreement).
func corpusRows(c *acceptanceCtx) []acceptanceRow {
	// roundtrip, golden-agreement: corpus verification rows by check.
	corpus := c.byTool("xcc-corpus verify")
	return []acceptanceRow{
		c.needRuns(c.corpusRow("roundtrip", "round-trip and reject checks", "roundtrip", "reject"), c.runsOf("roundtrip")),
		c.needRuns(ag4Row(c.corpusRow("golden-agreement", "golden checks (AG-1, AG-3, AG-4)", "ag1", "ag3", "ag4"), corpus, c.root), c.runsOf("golden-agreement")),
	}
}

// corpusRowOf is one corpus-verification row from the given reports' rows of the named check kinds.
func (c *acceptanceCtx) corpusRowOf(reports []*reportStats, check, what string, kinds ...string) acceptanceRow {
	ok, bad := 0, 0
	for _, s := range reports {
		for _, k := range kinds {
			ok += s.corpusOK[k]
			bad += s.corpusFail[k]
		}
	}
	r := acceptanceRow{check: check, artefact: orDefault(rels(reports), "`"+c.shown+"/corpus-verify.json` (make verify-corpus)")}
	switch {
	case ok+bad == 0:
		r.status, r.checked = statusMissing, "no corpus verification rows for "+strings.Join(kinds, ", ")
	case bad > 0:
		r.status, r.checked = statusNotMet, fmt.Sprintf("%s: %d of %d rows failed", what, bad, ok+bad)
	default:
		r.status, r.checked = statusMet, fmt.Sprintf("%s: all %d rows passed", what, ok)
	}
	return r
}

// corpusRow is corpusRowOf over the corpus verification reports.
func (c *acceptanceCtx) corpusRow(check, what string, kinds ...string) acceptanceRow {
	return c.corpusRowOf(c.byTool("xcc-corpus verify"), check, what, kinds...)
}

// ag4Row adds AG-4's whole-corpus verdict to golden-agreement: a failing or absent mirrors.json or floor:ag4 row (see
// ag4WholeRows) is `not met`, and the text gives the committed golden-counterpart list's counts
// (corpus/mirrors.json: local-core entries mapped to a golden, and the unmapped ones by reason).
func ag4Row(r acceptanceRow, corpus []*reportStats, root string) acceptanceRow {
	if r.status == statusMissing {
		return r
	}
	seen := map[string]bool{}
	var failed []string
	for _, s := range corpus {
		for e, ok := range s.ag4Whole {
			seen[e] = true
			if !ok {
				failed = append(failed, e)
			}
		}
	}
	sort.Strings(failed)
	var absent []string
	for _, e := range ag4WholeRows {
		if !seen[e] {
			absent = append(absent, e)
		}
	}
	switch {
	case len(failed) > 0:
		r.status = statusNotMet
		r.checked += "; AG-4 whole-corpus rows failed: " + strings.Join(failed, ", ")
	case len(absent) > 0:
		r.status = statusNotMet
		r.checked += "; no AG-4 whole-corpus row " + strings.Join(absent, ", ") + " (the AG-4 report is not a whole-corpus run)"
	}
	r.checked += "; " + mirrorCounts(filepath.Join(root, "corpus", "mirrors.json"))
	return r
}

// mirrorCounts summarises corpus/mirrors.json: how many local-core entries match a golden transaction, and the
// unmapped ones by reason.
func mirrorCounts(path string) string {
	var m struct {
		Counts struct {
			LocalCore int `json:"local_core_entries"`
			Mapped    int `json:"mapped"`
			Unmapped  int `json:"unmapped"`
		} `json:"counts"`
		Unmapped []struct {
			Reason string `json:"reason"`
		} `json:"unmapped"`
	}
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &m)
	}
	if errors.Is(err, os.ErrNotExist) {
		return "no corpus/mirrors.json"
	}
	if err != nil {
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return fmt.Sprintf("corpus/mirrors.json does not read: %v", se)
		}
		return "corpus/mirrors.json does not read"
	}
	reasons := map[string]int{}
	for _, u := range m.Unmapped {
		reasons[orDefault(u.Reason, "no reason")]++
	}
	keys := make([]string, 0, len(reasons))
	for k := range reasons {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%d %q", reasons[k], k)
	}
	return fmt.Sprintf("corpus/mirrors.json: %d of %d local-core entries match a golden transaction (mapped); %d unmapped (%s)",
		m.Counts.Mapped, m.Counts.LocalCore, m.Counts.Unmapped, strings.Join(parts, ", "))
}
