// Package report renders views over a finished conformance run for people outside the kit: the SDK
// decode-readiness table (`xdrcheck conform readiness`, this file) and the scoreboard page (`xdrcheck conform scoreboard`,
// scoreboard.go). Both read matrix.json (docs/driver-protocol.md §6) and write into the run's report directory;
// neither runs a driver.
//
// The readiness table answers "which released versions of each SDK decode protocol N's shapes": one row per
// pinned SDK version (every column of drivers/sets.toml, and every column the matrix holds), one column per
// protocol the corpus's entries were introduced at, and one per CAP. A cell is one of
//
//	full              every judged entry of the group decodes as the corpus expects
//	partial           n of m entries do; the rest are refused as too new, or wrong
//	refuses-new-arms  every judged entry is refused cleanly as an undeclared union arm or enum value: the
//	                  version predates the shapes (docs/conformance-protocol.md §4, schema reach)
//	not-run           the version is pinned but the run has no judged cell for the group
//
// Only the shapes a decoder must read count: entries of kind ledger and xdr that are not negative (an input a
// reader must refuse says nothing about readiness).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
)

// ReadinessSchema is the readiness file's schema ID.
const ReadinessSchema = "xcc.conformance.readiness/v1"

// Readiness output files, written beside matrix.json.
const (
	ReadinessJSON     = "readiness.json"
	ReadinessMarkdown = "readiness.md"
)

// Cell states.
const (
	StateFull    = "full"
	StatePartial = "partial"
	StateRefuses = "refuses-new-arms"
	StateNotRun  = "not-run"
)

// Pinned is one column the readiness table must show a row for, whether or not the matrix ran it.
type Pinned struct {
	ID      string
	SDK     string
	Version string
	Profile string
	Kind    string
}

// Readiness is the table: groups are its columns, rows its SDK versions.
type Readiness struct {
	Schema   string           `json:"schema"`
	Corpus   string           `json:"corpus"`
	Protocol int              `json:"protocol,omitempty"` // 0: every protocol
	Groups   []ReadinessGroup `json:"groups"`
	Rows     []ReadinessRow   `json:"rows"`
}

// ReadinessGroup is one column of the table: the entries introduced at one protocol, or tagged with one CAP.
type ReadinessGroup struct {
	Key      string   `json:"key"`  // P30, CAP-0084
	Kind     string   `json:"kind"` // protocol, cap
	Protocol int      `json:"protocol,omitempty"`
	CAP      int      `json:"cap,omitempty"`
	Entries  []string `json:"entries"`
}

// ReadinessRow is one SDK version (one column of the run, with its profile).
type ReadinessRow struct {
	Column  string                    `json:"column"`
	SDK     string                    `json:"sdk"`
	Version string                    `json:"version"`
	Profile string                    `json:"profile,omitempty"`
	Kind    string                    `json:"kind"`
	InRun   bool                      `json:"in_run"`
	Cells   map[string]*ReadinessCell `json:"cells"`
}

// ReadinessCell is one SDK version against one group.
type ReadinessCell struct {
	State   string   `json:"state"`
	Decoded int      `json:"decoded"` // entries every judged cell of which conforms
	Refused int      `json:"refused"` // entries refused as beyond the version's schema reach
	Wrong   int      `json:"wrong"`   // entries with a failing verdict (a known divergence included)
	Judged  int      `json:"judged"`  // decoded + refused + wrong
	Failing []string `json:"failing,omitempty"`
}

// Text is the cell as the Markdown table shows it.
func (c *ReadinessCell) Text() string {
	switch c.State {
	case StateFull:
		return fmt.Sprintf("full (%d)", c.Judged)
	case StateRefuses:
		return "refuses new arms"
	case StatePartial:
		var why []string
		if c.Refused > 0 {
			why = append(why, fmt.Sprintf("%d refused", c.Refused))
		}
		if c.Wrong > 0 {
			why = append(why, fmt.Sprintf("%d wrong", c.Wrong))
		}
		return fmt.Sprintf("**partial %d of %d** (%s)", c.Decoded, c.Judged, strings.Join(why, ", "))
	}
	return "not run"
}

// readinessEntry reports whether an entry counts: a ledger or xdr shape a reader must decode.
func readinessEntry(e verdict.MatrixEntry) bool {
	return (e.Kind == "ledger" || e.Kind == "xdr") && !e.Negative && e.Validity != "malformed" && e.Validity != "invalid"
}

// entryClass is what one column did with one entry, over all its cells: ok, refused, wrong, or "" (every cell
// n/a for another reason: nothing judged).
func entryClass(cells []*verdict.Cell) string {
	ok, refused := false, false
	for _, c := range cells {
		switch {
		case c.Verdict == "conform":
			ok = true
		case c.Verdict == "n_a" && c.OutOfReach:
			refused = true
		case c.Verdict == "n_a":
		default:
			return "wrong"
		}
	}
	switch {
	case ok:
		return "ok"
	case refused:
		return "refused"
	}
	return ""
}

// BuildReadiness makes the table from a matrix and the pinned columns. protocol, when not 0, keeps only that
// protocol's group and, for the CAP groups, only the entries introduced at it.
func BuildReadiness(m *verdict.Matrix, pinned []Pinned, protocol int) *Readiness {
	r := &Readiness{Schema: ReadinessSchema, Corpus: m.Corpus.Version, Protocol: protocol, Groups: []ReadinessGroup{}, Rows: []ReadinessRow{}}

	// Groups.
	byProto := map[int][]string{}
	byCAP := map[int][]string{}
	for _, e := range m.Entries {
		if !readinessEntry(e) || e.ProtocolIntroduced <= 0 {
			continue
		}
		if protocol != 0 && e.ProtocolIntroduced != protocol {
			continue
		}
		byProto[e.ProtocolIntroduced] = append(byProto[e.ProtocolIntroduced], e.ID)
		for _, c := range e.Caps {
			byCAP[c] = append(byCAP[c], e.ID)
		}
	}
	for _, p := range sortedKeys(byProto) {
		r.Groups = append(r.Groups, ReadinessGroup{Key: "P" + strconv.Itoa(p), Kind: "protocol", Protocol: p, Entries: sortedCopy(byProto[p])})
	}
	for _, c := range sortedKeys(byCAP) {
		r.Groups = append(r.Groups, ReadinessGroup{Key: fmt.Sprintf("CAP-%04d", c), Kind: "cap", CAP: c, Entries: sortedCopy(byCAP[c])})
	}

	// Rows: every pinned column and every column of the matrix, the stub left out.
	rows := map[string]*ReadinessRow{}
	add := func(id, sdk, version, profile, kind string, inRun bool) {
		if kind == "selftest" {
			return
		}
		row := rows[id]
		if row == nil {
			row = &ReadinessRow{Column: id, SDK: sdk, Version: version, Profile: profile, Kind: kind, Cells: map[string]*ReadinessCell{}}
			rows[id] = row
		}
		row.InRun = row.InRun || inRun
	}
	for _, p := range pinned {
		add(p.ID, p.SDK, p.Version, p.Profile, p.Kind, false)
	}
	for _, c := range m.Columns {
		add(c.ID, c.SDK, c.Version, c.Profile, c.Kind, true)
	}

	// Cells per column and entry.
	cells := map[string]map[string][]*verdict.Cell{} // column -> entry -> cells
	for i := range m.Cells {
		c := &m.Cells[i]
		if cells[c.Column] == nil {
			cells[c.Column] = map[string][]*verdict.Cell{}
		}
		cells[c.Column][c.Entry] = append(cells[c.Column][c.Entry], c)
	}
	for _, row := range rows {
		for _, g := range r.Groups {
			rc := &ReadinessCell{}
			for _, e := range g.Entries {
				switch entryClass(cells[row.Column][e]) {
				case "ok":
					rc.Decoded++
				case "refused":
					rc.Refused++
				case "wrong":
					rc.Wrong++
					rc.Failing = append(rc.Failing, e)
				}
			}
			rc.Judged = rc.Decoded + rc.Refused + rc.Wrong
			switch {
			case rc.Judged == 0:
				rc.State = StateNotRun
			case rc.Decoded == rc.Judged:
				rc.State = StateFull
			case rc.Refused == rc.Judged:
				rc.State = StateRefuses
			default:
				rc.State = StatePartial
			}
			row.Cells[g.Key] = rc
		}
	}

	for _, row := range rows {
		r.Rows = append(r.Rows, *row)
	}
	sort.Slice(r.Rows, func(i, j int) bool {
		a, b := r.Rows[i], r.Rows[j]
		if a.SDK != b.SDK {
			return a.SDK < b.SDK
		}
		if d, err := verdict.CompareVersions(a.Version, b.Version); err == nil && d != 0 {
			return d < 0
		}
		return a.Column < b.Column
	})
	return r
}

// Markdown writes the table: one table for the protocols, one for the CAPs, and a key.
func (r *Readiness) Markdown(w io.Writer) {
	scope := "every protocol the corpus's entries were introduced at"
	if r.Protocol != 0 {
		scope = fmt.Sprintf("the entries introduced at Protocol %d", r.Protocol)
	}
	fmt.Fprintf(w, "# SDK decode readiness\n\nCorpus %s; %s. One row per pinned SDK version. Counted: the ledger and xdr entries a reader must decode (negative entries left out).\n\n", r.Corpus, scope)
	fmt.Fprintln(w, "| Cell | Means |")
	fmt.Fprintln(w, "|---|---|")
	fmt.Fprintln(w, "| full (m) | all m judged entries decode as the corpus expects, at every level the column runs |")
	fmt.Fprintln(w, "| **partial n of m** | n of the m judged entries do; the others are refused as too new for the version, or wrong (see readiness.json `failing`) |")
	fmt.Fprintln(w, "| refuses new arms | every judged entry is refused cleanly as an undeclared union arm or enum value: the version predates these shapes |")
	fmt.Fprintln(w, "| not run | the version is pinned but the run judged none of these entries for it |")
	for _, kind := range []string{"protocol", "cap"} {
		var groups []ReadinessGroup
		for _, g := range r.Groups {
			if g.Kind == kind {
				groups = append(groups, g)
			}
		}
		if len(groups) == 0 {
			continue
		}
		title := "By protocol introduced"
		if kind == "cap" {
			title = "By CAP"
		}
		fmt.Fprintf(w, "\n## %s\n\n| SDK version |", title)
		for _, g := range groups {
			fmt.Fprintf(w, " %s (%d) |", g.Key, len(g.Entries))
		}
		fmt.Fprint(w, "\n|---|")
		for range groups {
			fmt.Fprint(w, "---|")
		}
		fmt.Fprintln(w)
		for _, row := range r.Rows {
			name := "`" + row.Column + "`"
			if !row.InRun {
				name += " (not in this run)"
			}
			fmt.Fprintf(w, "| %s |", name)
			for _, g := range groups {
				fmt.Fprintf(w, " %s |", row.Cells[g.Key].Text())
			}
			fmt.Fprintln(w)
		}
	}
	if len(r.Groups) == 0 {
		fmt.Fprintln(w, "\nNo entry of the run matches.")
	}
}

// Write writes readiness.json and readiness.md into dir.
func (r *Readiness) Write(dir string) error {
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, ReadinessJSON), append(b, '\n'), 0o644); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(dir, ReadinessMarkdown))
	if err != nil {
		return err
	}
	r.Markdown(f)
	return f.Close()
}

func sortedKeys(m map[int][]string) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}
