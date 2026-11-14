package bugs

// The harness self-test (`make harness-selftest`): every seeded bug is replayed through the real command line,
// `xdrcheck replay --adapter "baseline --bug NAME"`, over its entries, and the report's rows are checked against
// table.json. The expectations live here, beside the bugs, rather than as known divergences in the corpus: a
// seeded bug is a property of the harness, not of an entry, and the corpus stays free of `xdrcheck/…` targets.

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

//go:embed table.json
var tableJSON []byte

// Table is table.json.
type Table struct {
	Schema        string     `json:"schema"`
	About         string     `json:"about"`
	TargetVersion string     `json:"target_version"`
	Bugs          []TableBug `json:"bugs"`
}

// TableBug is one bug's run and expectations.
type TableBug struct {
	Bug     string   `json:"bug"`
	Entries []string `json:"entries,omitempty"`
	Args    []string `json:"args,omitempty"`
	Expect  []Item   `json:"expect"`
}

// Item is one expected result.
type Item struct {
	Entry   string `json:"entry"`             // entry ID, a glob, or "*" for every entry
	Variant string `json:"variant,omitempty"` // variant key; empty matches every variant
	Result  string `json:"result"`            // class·qualifier, or the class alone
	Note    string `json:"note,omitempty"`    // a substring one of the row's notes must contain
	Min     *int   `json:"min,omitempty"`     // rows that must match; default 1
	Max     int    `json:"max,omitempty"`     // rows that may match; 0 is unlimited
	Why     string `json:"why,omitempty"`
	Hole    string `json:"hole,omitempty"` // a known harness hole: a mismatch here does not fail the run unless strict
}

func (it Item) min() int {
	if it.Min == nil {
		return 1
	}
	return *it.Min
}

func (it Item) glob() bool { return strings.ContainsAny(it.Entry, "*?[") }

// LoadTable reads the embedded table.
func LoadTable() (*Table, error) {
	var t Table
	if err := json.Unmarshal(tableJSON, &t); err != nil {
		return nil, fmt.Errorf("table.json: %w", err)
	}
	if t.Schema != "xcc.seeded-bugs/v1" {
		return nil, fmt.Errorf("table.json: schema %q", t.Schema)
	}
	return &t, nil
}

// Row is what the check reads from one report row.
type Row struct {
	Entry, Variant, Result string
	Notes                  []string
}

// plannedOut reports a not_applicable row the harness decided before running the indexer.
func plannedOut(r Row) bool {
	if !strings.HasPrefix(r.Result, "not_applicable") {
		return false
	}
	for _, n := range r.Notes {
		if strings.HasPrefix(n, "not run:") {
			return true
		}
	}
	return false
}

// Status of one bug's check.
const (
	OK              = "ok"
	Fail            = "FAIL"
	KnownHole       = "HOLE"             // a mismatch on an item marked as a known harness hole
	NotDemonstrated = "NOT-DEMONSTRATED" // none of its entries is in the corpus yet
)

// Verdict is one bug's result.
type Verdict struct {
	Bug      string   `json:"bug"`
	Status   string   `json:"status"`
	Rows     int      `json:"rows"`
	Results  []string `json:"results"`            // distinct class·qualifier observed, with counts
	Problems []string `json:"problems,omitempty"` // failures
	Holes    []string `json:"holes,omitempty"`    // mismatches on known holes
	Pending  []string `json:"pending,omitempty"`  // named entries the corpus does not hold yet
	Notes    []string `json:"notes,omitempty"`
}

// Plan returns the entries to replay for a bug, given the corpus's entry IDs: nil means the whole corpus. pending
// lists named entries the corpus does not hold.
func (b TableBug) Plan(have func(id string) bool) (entries, pending []string) {
	if slices.Contains(b.Entries, "*") {
		return nil, nil
	}
	named := b.Entries
	if len(named) == 0 {
		for _, it := range b.Expect {
			if !slices.Contains(named, it.Entry) {
				named = append(named, it.Entry)
			}
		}
	}
	for _, id := range named {
		if strings.ContainsAny(id, "*?[") || have(id) {
			entries = append(entries, id)
		} else {
			pending = append(pending, id)
		}
	}
	return entries, pending
}

func (it Item) matchesEntry(r Row) bool {
	if it.Variant != "" && it.Variant != r.Variant {
		return false
	}
	if it.Entry == r.Entry || it.Entry == "*" {
		return true
	}
	ok, _ := filepath.Match(it.Entry, r.Entry)
	return ok
}

func (it Item) matches(r Row) bool {
	if !it.matchesEntry(r) {
		return false
	}
	if it.Result != r.Result {
		return false
	}
	if it.Note == "" {
		return true
	}
	for _, n := range r.Notes {
		if strings.Contains(n, it.Note) {
			return true
		}
	}
	return false
}

// Check judges one bug's rows. pending are its named entries the corpus does not hold. Mismatched rows are
// grouped by what was got and what was wanted, with the first entry as the example.
func (b TableBug) Check(rows []Row, pending []string) Verdict {
	v := Verdict{Bug: b.Bug, Rows: len(rows), Pending: pending}
	counts := make([]int, len(b.Expect))
	seen := map[string]int{}
	var order []string
	type group struct {
		n       int
		example string
		holes   []string
	}
	groups := map[string]*group{}
	var gorder []string
	for _, r := range rows {
		// Variants the harness planned out (for example an entry that needs prior state, in a stream
		// unit) were never given to the indexer, so they say nothing about the bug.
		if plannedOut(r) {
			v.Rows--
			continue
		}
		if seen[r.Result] == 0 {
			order = append(order, r.Result)
		}
		seen[r.Result]++
		hit := -1
		for i, it := range b.Expect {
			if it.matches(r) {
				hit = i
				break
			}
		}
		if hit >= 0 {
			counts[hit]++
			continue
		}
		var want, holes []string
		for _, it := range b.Expect {
			if !it.matchesEntry(r) {
				continue
			}
			w := it.Result
			if it.Note != "" {
				w += " (note: " + it.Note + ")"
			}
			want = append(want, w)
			if it.Hole != "" && !slices.Contains(holes, it.Hole) {
				holes = append(holes, it.Hole)
			}
		}
		key := "got " + r.Result + ", want " + strings.Join(want, " or ")
		if len(want) == 0 {
			key = "got " + r.Result + ", and the table expects nothing for this entry"
		}
		g, ok := groups[key]
		if !ok {
			ex := r.Entry + " " + r.Variant
			if len(r.Notes) > 0 {
				ex += " [" + strings.Join(r.Notes, "; ") + "]"
			}
			g = &group{example: ex, holes: holes}
			groups[key] = g
			gorder = append(gorder, key)
		}
		g.n++
	}
	for _, res := range order {
		v.Results = append(v.Results, fmt.Sprintf("%s ×%d", res, seen[res]))
	}
	for _, key := range gorder {
		g := groups[key]
		msg := fmt.Sprintf("%d row(s) %s; first: %s", g.n, key, g.example)
		if len(g.holes) > 0 {
			v.Holes = append(v.Holes, msg+" — known hole: "+strings.Join(g.holes, " / "))
		} else {
			v.Problems = append(v.Problems, msg)
		}
	}
	rowHoles := len(v.Holes) > 0
	for i, it := range b.Expect {
		if !it.glob() && slices.Contains(pending, it.Entry) {
			continue
		}
		var msg string
		switch {
		case counts[i] < it.min():
			msg = fmt.Sprintf("%s: %d row(s) %s, want at least %d", it.Entry, counts[i], it.Result, it.min())
		case it.Max > 0 && counts[i] > it.Max:
			msg = fmt.Sprintf("%s: %d row(s) %s, want at most %d", it.Entry, counts[i], it.Result, it.Max)
		default:
			continue
		}
		switch {
		case it.Hole != "":
			v.Holes = append(v.Holes, msg+" — known hole: "+it.Hole)
		case rowHoles:
			v.Holes = append(v.Holes, msg+" — follows from the known hole above")
		default:
			v.Problems = append(v.Problems, msg)
		}
	}
	switch {
	case len(v.Problems) > 0:
		v.Status = Fail
	case len(rows) == 0 && len(pending) > 0:
		v.Status = NotDemonstrated
	case len(rows) == 0:
		v.Status, v.Problems = Fail, []string{"no report rows"}
	case len(v.Holes) > 0:
		v.Status = KnownHole
	default:
		v.Status = OK
		for i, it := range b.Expect {
			if it.Hole != "" && counts[i] > 0 {
				v.Notes = append(v.Notes, "an item marked as a known hole now matches; remove its hole note: "+it.Hole)
			}
		}
	}
	return v
}

// Options run the self-test.
type Options struct {
	XDRCHECK, Baseline, Corpus, Out string
	Input                           string   // default sep54-dir
	Only                            []string // bugs to run; empty is all
	Have                            func(id string) bool
	Log                             io.Writer
}

// Run replays every bug of the table and checks it. An error means the self-test itself could not run.
func Run(ctx context.Context, t *Table, o Options) ([]Verdict, error) {
	if o.Input == "" {
		o.Input = "sep54-dir"
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	var out []Verdict
	for _, b := range t.Bugs {
		if len(o.Only) > 0 && !slices.Contains(o.Only, b.Bug) {
			continue
		}
		if _, err := Lookup(b.Bug); err != nil {
			return out, err
		}
		entries, pending := b.Plan(o.Have)
		if entries == nil && len(pending) > 0 {
			out = append(out, b.Check(nil, pending))
			continue
		}
		dir := filepath.Join(o.Out, b.Bug)
		os.RemoveAll(dir)
		cmd := o.Baseline
		if b.Bug != None {
			cmd += " --bug " + b.Bug
		}
		args := []string{"replay", "--corpus", o.Corpus, "--adapter", cmd, "--target-version", t.TargetVersion,
			"--input", o.Input, "--keep-going", "--report", dir}
		if entries != nil {
			args = append(args, "--entries", strings.Join(entries, ","))
		}
		args = append(args, b.Args...)
		fmt.Fprintf(o.Log, "harness-selftest: %s: xdrcheck %s\n", b.Bug, strings.Join(quoteArgs(args), " "))
		c := exec.CommandContext(ctx, o.XDRCHECK, args...)
		c.Stdout, c.Stderr = io.Discard, o.Log
		err := c.Run()
		var xe *exec.ExitError
		code := 0
		switch {
		case errors.As(err, &xe):
			code = xe.ExitCode()
		case err != nil:
			return out, fmt.Errorf("%s: %w", b.Bug, err)
		}
		rows, rerr := ReadRows(filepath.Join(dir, "report.json"))
		v := b.Check(rows, pending)
		if rerr != nil {
			v.Status, v.Problems = Fail, append(v.Problems, fmt.Sprintf("xdrcheck replay exited %d and its report is unreadable: %v", code, rerr))
		}
		out = append(out, v)
	}
	return out, nil
}

func quoteArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.ContainsAny(a, " \t") {
			a = "'" + a + "'"
		}
		out[i] = a
	}
	return out
}

// ReadRows reads the rows of an xcc.report/v1 file for Check.
func ReadRows(path string) ([]Row, error) {
	var rows []Row
	_, _, err := report.ReadFile(path, func(r *report.Row) error {
		res := ""
		if r.Replay != nil {
			res = r.Replay.Class
			if r.Replay.Qualifier != "" {
				res += "·" + r.Replay.Qualifier
			}
		}
		rows = append(rows, Row{Entry: r.Entry, Variant: r.Variant, Result: res, Notes: r.Notes})
		return nil
	})
	return rows, err
}
