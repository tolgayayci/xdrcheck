package verdict

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"
)

// Pending divergences: the check of a matrix (`xdrcheck conform check`) against what is known to be awaiting a
// finding. An undeclared cell is a divergence nobody has accounted for and fails the check, with two exceptions
// in development mode, both reported cell by cell as pending, never passed silently:
//
//   - pending finding: a finding record lists the cell's report row (evidence.report_rows), usually a candidate
//     kept in the private overlay because the defect is not reported upstream yet;
//   - pending finding review: the cell is in the committed pending list findings/pending/conformance.json,
//     {"pending": [{"entry", "variant", "column", "level"}, …]} with no description, no reason and no finding ID,
//     which public CI uses because it never loads the overlay (xdrcheck findings check reads the same kind of list).
//     A list item whose cells the run has but none of them undeclared is stale and fails, so the list cannot
//     outlive what it acknowledges.
//
// In acceptance mode pending cells fail like any other undeclared cell: every divergence must then be declared
// on its entry with a finding.

// Check modes.
const (
	ModeDevelopment = "development"
	ModeAcceptance  = "acceptance"
)

// PendingFile is the conformance pending list, relative to the repository root.
const PendingFile = "findings/pending/conformance.json"

// PendingCell is one item of the pending list. Variant is "" (or "-") for entries without variants (api, strkey).
// Since is the date the item was listed (YYYY-MM-DD; the list's top-level since when the item names none); it
// is not part of the cell, and xdrcheck findings check judges its age.
type PendingCell struct {
	Entry   string `json:"entry"`
	Variant string `json:"variant"`
	Column  string `json:"column"`
	Level   string `json:"level"`
	Since   string `json:"since,omitempty"`
}

func (p PendingCell) variant() string {
	if p.Variant == "-" {
		return ""
	}
	return p.Variant
}

func (p PendingCell) String() string {
	v := p.Variant
	if v == "" {
		v = "-"
	}
	return fmt.Sprintf("%s %s %s %s", p.Entry, v, p.Column, p.Level)
}

// ReadPending reads a pending list. A missing file lists nothing; unknown fields and empty names are errors.
func ReadPending(path string) ([]PendingCell, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var doc struct {
		Since   string        `json:"since"`
		Pending []PendingCell `json:"pending"`
	}
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i := range doc.Pending {
		p := &doc.Pending[i]
		if p.Entry == "" || p.Column == "" || p.Level == "" {
			return nil, fmt.Errorf("%s: pending[%d] needs entry, column and level", path, i)
		}
		if p.Since == "" {
			p.Since = doc.Since
		}
		if p.Since != "" {
			if _, err := time.Parse("2006-01-02", p.Since); err != nil {
				return nil, fmt.Errorf("%s: pending[%d]: since %q: want a date YYYY-MM-DD", path, i, p.Since)
			}
		}
	}
	return doc.Pending, nil
}

// FindingRef is a finding record that accounts for report rows.
type FindingRef struct {
	ID, State string
	Overlay   bool
}

// CheckedCell is a cell the check reports.
type CheckedCell struct {
	Cell
	Status   string       // fail, pending-finding, pending-review
	Findings []FindingRef // for pending-finding
}

// CheckResult is the outcome of checking a matrix.
type CheckResult struct {
	Mode    string
	Failing []CheckedCell // cells that fail the check
	Pending []CheckedCell // undeclared cells accounted for as pending (development mode)
	Stale   []PendingCell // pending-list items that no longer match an undeclared cell
	// Starved lists the required columns of the run that judged fewer cells than the floor (MinJudged): a
	// column whose every cell is n_a, or that ran nothing, says nothing about its SDK and cannot pass.
	Starved []StarvedColumn
}

// StarvedColumn is a required column under the judged-cell floor.
type StarvedColumn struct {
	Column        string
	Judged, Cells int
}

// MinJudged is the floor of judged (not n_a) cells every required column of a run must reach for the check to
// pass.
var MinJudged = 1

// Passed reports whether the check passes.
func (r *CheckResult) Passed() bool {
	return len(r.Failing) == 0 && len(r.Stale) == 0 && len(r.Starved) == 0
}

// RowID is the cell's report row ID, as the xcc.report/v1 rows and finding records spell it.
func (c *Cell) RowID() string {
	v := c.Variant
	if v == "" {
		v = "-"
	}
	return fmt.Sprintf("conform:%s:%s:%s:%s", c.Entry, v, c.Column, c.Level)
}

// Check checks the matrix: failing checks fail, except undeclared cells accounted for as pending in development
// mode. rows maps a report row ID to the finding records that list it.
func (m *Matrix) Check(mode string, rows map[string][]FindingRef, pending []PendingCell) *CheckResult {
	res := &CheckResult{Mode: mode}
	type key struct{ entry, variant, column, level string }
	listed := map[key]int{}
	for i, p := range pending {
		listed[key{p.Entry, p.variant(), p.Column, p.Level}] = i
	}
	used := map[int]bool{}
	present := map[key]bool{}
	for _, c := range m.Cells {
		k := key{c.Entry, c.Variant, c.Column, c.Level}
		present[k] = true
		if !FailingCheck(c.Check) {
			continue
		}
		cc := CheckedCell{Cell: c, Status: "fail"}
		if c.Check == "undeclared" {
			i, ok := listed[k]
			if ok {
				used[i] = true
				cc.Status = "pending-review"
			}
			if f := rows[c.RowID()]; len(f) > 0 {
				cc.Status, cc.Findings = "pending-finding", f
			}
		}
		if cc.Status == "fail" || mode == ModeAcceptance {
			res.Failing = append(res.Failing, cc)
		} else {
			res.Pending = append(res.Pending, cc)
		}
	}
	for i, p := range pending {
		if !used[i] && present[key{p.Entry, p.variant(), p.Column, p.Level}] {
			res.Stale = append(res.Stale, p)
		}
	}
	res.Starved = m.starved(MinJudged)
	return res
}

// starved lists the required columns with fewer than floor judged cells.
func (m *Matrix) starved(floor int) []StarvedColumn {
	judged, cells := map[string]int{}, map[string]int{}
	for _, c := range m.Cells {
		cells[c.Column]++
		if c.Verdict != "n_a" {
			judged[c.Column]++
		}
	}
	var out []StarvedColumn
	for _, col := range m.Columns {
		if col.Required && judged[col.ID] < floor {
			out = append(out, StarvedColumn{Column: col.ID, Judged: judged[col.ID], Cells: cells[col.ID]})
		}
	}
	return out
}

// PendingRows indexes finding records by the report rows they list.
func PendingRows(records map[string]FindingRef, reportRows map[string][]string) map[string][]FindingRef {
	out := map[string][]FindingRef{}
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, r := range reportRows[id] {
			out[r] = append(out[r], records[id])
		}
	}
	return out
}
