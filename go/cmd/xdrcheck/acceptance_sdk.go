package main

// Acceptance row sdk-regression (cases js-1766, js-1785, js-1789): the conformance assertions' own verdict.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// sdkRegressionColumns are the JavaScript columns the sdk-regression assertions are made on.
var sdkRegressionColumns = []string{"js@17.2.0", "js@17.2.1", "js@17.3.0"}

// sdkRegressionRows: the assertions' own verdict.
func sdkRegressionRows(c *acceptanceCtx) []acceptanceRow {
	// sdk-regression: the assertions' own verdict.
	return []acceptanceRow{c.needRuns(sdkRegressionRow(c.dir, c.shown, c.byTool("xcc conform"), rels), c.runsOf("sdk-regression"))}
}

// sdkRegressionResult is what sdk-regression reads of the sdk-regression.json `xdrcheck conform sdk-regression` writes.
type sdkRegressionResult struct {
	Passed bool `json:"passed"`
	Rows   []struct {
		ID, Check, Entry, Column, Level string
		Pass                            bool
	} `json:"rows"`
}

// sdkRegressionRow is sdk-regression from `xdrcheck conform sdk-regression`'s own verdict (make verify-conformance). Cells pending finding
// review in the conformance runs are named, per run, but are not this check's verdict.
func sdkRegressionRow(dir, shown string, conf []*reportStats, rels func([]*reportStats) string) acceptanceRow {
	const name = "conformance/sdk-regression.json"
	r := acceptanceRow{check: "sdk-regression", artefact: "`" + shown + "/" + name + "` (make verify-conformance)"}
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
	if errors.Is(err, os.ErrNotExist) {
		r.status, r.checked = statusMissing, "no "+shown+"/"+name
		return r
	}
	var c sdkRegressionResult
	if err == nil {
		err = json.Unmarshal(data, &c)
	}
	if err != nil {
		r.status, r.checked = statusNotMet, fmt.Sprintf("%s does not read: %v", name, err)
		return r
	}
	var pend []string
	for _, s := range conf {
		if s.pending > 0 {
			pend = append(pend, fmt.Sprintf("%s: %d", rels([]*reportStats{s}), s.pending))
		}
	}
	elsewhere := ""
	if len(pend) > 0 {
		elsewhere = "; cells pending finding review elsewhere in the matrix, per run: " + strings.Join(pend, "; ")
	}
	var failed []string
	for _, row := range c.Rows {
		if !row.Pass {
			failed = append(failed, fmt.Sprintf("%s %s %s %s", row.ID, row.Entry, row.Column, row.Level))
		}
	}
	switch {
	case len(c.Rows) == 0:
		r.status, r.checked = statusNotMet, name+" holds no assertion rows"
	case !c.Passed || len(failed) > 0:
		r.status, r.checked = statusNotMet, fmt.Sprintf("%s of %d failed: %s", count(len(failed), "assertion row", "assertion rows"), len(c.Rows), strings.Join(failed, ", "))+elsewhere
	default:
		r.status, r.checked = statusMet, fmt.Sprintf("all %d assertion rows of `xdrcheck conform sdk-regression` hold on %s", len(c.Rows), strings.Join(sdkRegressionColumns, ", "))+elsewhere
	}
	return r
}
