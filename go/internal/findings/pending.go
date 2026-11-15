package findings

// Pending finding review (findings/README.md). A defect our own runs found that is not yet reported upstream
// stays a candidate record in the private overlay until a maintainer approves it; the public tree only lists the
// failure rows it accounts for, in committed, description-free pending lists. In development mode a failure row
// with no finding ID passes when a pending entry matches it; in acceptance mode every such row fails, as a
// draft record does.
//
// A pending list is a JSON file
//
//	{"commit": "<optional default>", "target": "<optional default>", "tool": "<optional default>",
//	 "since": "<optional default date>", "pending": [{<key>: <value>, …}, …]}
//
// found at one of PendingGlobs under the repository root. An entry matches a row when every key it names
// equals the row's value for that key; the top-level "commit", "target" and "tool" fill in entries that do not
// name them. Keys (and nothing else: a reason or a finding ID has no place here):
//
//	target   the row's target name            version, commit   the row's target version
//	tool     replay, conform, lint, corpus     column            the row's target column
//	entry    corpus entry ID                   variant           variant ID
//	level    conformance level (L0…L4)
//	rule     lint rule ID                      file, line, function   lint location
//	site     a lint location not named yet: the hex SHA-256 of "xdrlint.site/v1:<rule>:<file>:<line>"
//
// An entry must name at least one of entry, rule or file: a target and a version alone would cover every row of
// a run. Linter lists name (rule, file, line) and their commit; conformance lists (entry, variant, column, level).
//
// Governance:
//
//   - since: the date (YYYY-MM-DD) the entry was listed, on the entry or at the top level for all of them; it
//     is not a row key. An entry older than MaxPendingAge, or one without a date, fails an acceptance check; a
//     date in the future fails every check.
//   - stale: an entry that accounts for no failure row of the required run set (required.go) fails, once every
//     required run that could hold its rows is among the checked reports.
//   - an entry may not cover a cell that `xdrcheck conform sdk-regression` asserts: those cells are the acceptance
//     reproductions and must come out exactly as asserted, never as pending. Such a list does not load.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

// PendingGlobs are where pending lists live, relative to the repository root: the generic location, and the
// linter's per-commit lists next to its frozen expected lists.
var PendingGlobs = []string{"findings/pending/*.json", "lint/expected/*/*.pending.json"}

// MaxPendingAge is how long an entry may stay pending finding review before an acceptance check fails on it.
const MaxPendingAge = 90 * 24 * time.Hour

// sinceLayout is the format of the since key.
const sinceLayout = "2006-01-02"

var pendingKeys = map[string]bool{
	"target": true, "version": true, "tool": true, "column": true, "entry": true, "variant": true,
	"level": true, "rule": true, "file": true, "line": true, "function": true, "site": true,
	"message": true, "site2": true,
}

// PendingEntry is one entry: key → value, with "commit" stored as "version".
type PendingEntry map[string]string

// PendingSource is where an entry was listed, and since when.
type PendingSource struct {
	File  string // relative to the repository root
	Index int
	Since time.Time // zero: no date
}

// Pending is the set of loaded entries.
type Pending struct {
	Files   []string
	Entries []PendingEntry
	// Sources[i] is where Entries[i] was listed.
	Sources []PendingSource
	// Required is the required run set the entries are checked against for staleness (RequiredRuns); nil when
	// the root declares none, and then neither staleness nor missing runs are checked.
	Required []RequiredRun
}

// LoadPending reads every pending list under root, and the required run set of root's pins.toml. A malformed
// list is an error: a list that silently matched nothing would turn rows red for the wrong reason, and one that
// matched too much would hide them.
func LoadPending(root string) (*Pending, error) {
	p := &Pending{}
	var files []string
	for _, g := range PendingGlobs {
		m, err := filepath.Glob(filepath.Join(root, g))
		if err != nil {
			return nil, err
		}
		files = append(files, m...)
	}
	sort.Strings(files)
	for _, f := range files {
		entries, since, err := readPending(f)
		if err != nil {
			return nil, err
		}
		rel, _ := filepath.Rel(root, f)
		rel = filepath.ToSlash(rel)
		p.Files = append(p.Files, rel)
		for i, e := range entries {
			if cell := sdkRegressionCell(e); cell != "" {
				return nil, fmt.Errorf("%s: pending[%d]: covers a cell that `xdrcheck conform sdk-regression` asserts (%s); an acceptance assertion is never pending", f, i, cell)
			}
			p.Entries = append(p.Entries, e)
			p.Sources = append(p.Sources, PendingSource{File: rel, Index: i, Since: since[i]})
		}
	}
	var err error
	if p.Required, err = RequiredRuns(root); err != nil {
		return nil, fmt.Errorf("the required run set: %v", err)
	}
	return p, nil
}

func readPending(path string) ([]PendingEntry, []time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("%s: %v", path, err)
	}
	defaults := PendingEntry{}
	var defaultSince time.Time
	var raw []map[string]any
	for k, v := range doc {
		switch k {
		case "schema":
		case "commit", "target", "tool", "since":
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				return nil, nil, fmt.Errorf("%s: %s: want a string", path, k)
			}
			if k == "since" {
				if defaultSince, err = parseSince(s); err != nil {
					return nil, nil, fmt.Errorf("%s: %v", path, err)
				}
				continue
			}
			defaults[normKey(k)] = s
		case "pending":
			if err := json.Unmarshal(v, &raw); err != nil {
				return nil, nil, fmt.Errorf("%s: pending: want a list of objects: %v", path, err)
			}
		default:
			return nil, nil, fmt.Errorf("%s: unknown key %q (a pending list holds row keys only)", path, k)
		}
	}
	var out []PendingEntry
	var since []time.Time
	for i, r := range raw {
		e := PendingEntry{}
		for k, v := range defaults {
			e[k] = v
		}
		when := defaultSince
		for k, v := range r {
			if k == "since" {
				s, ok := v.(string)
				if !ok {
					return nil, nil, fmt.Errorf("%s: pending[%d]: since: want a string", path, i)
				}
				t, err := parseSince(s)
				if err != nil {
					return nil, nil, fmt.Errorf("%s: pending[%d]: %v", path, i, err)
				}
				when = t
				continue
			}
			nk := normKey(k)
			if !pendingKeys[nk] {
				return nil, nil, fmt.Errorf("%s: pending[%d]: unknown key %q (a pending list holds row keys only)", path, i, k)
			}
			switch v := v.(type) {
			case string:
				if nk == "message" {
					v = NormaliseMessage(v)
				}
				e[nk] = v
			case float64:
				e[nk] = strconv.FormatFloat(v, 'f', -1, 64)
			default:
				return nil, nil, fmt.Errorf("%s: pending[%d]: %s: want a string or a number", path, i, k)
			}
		}
		if e["entry"] == "" && e["rule"] == "" && e["file"] == "" {
			return nil, nil, fmt.Errorf("%s: pending[%d]: names none of entry, rule or file", path, i)
		}
		out = append(out, e)
		since = append(since, when)
	}
	return out, since, nil
}

// parseSince reads a since value.
func parseSince(v string) (time.Time, error) {
	t, err := time.Parse(sinceLayout, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("since %q: want a date YYYY-MM-DD", v)
	}
	return t, nil
}

// sdkRegressionCell returns the sdk-regression assertion (ID and column) a pending entry could match, or "". An entry covers a
// cell when it names the cell's entry, and the same column and level wherever it names them; the variant is
// not compared, so an entry naming any variant of an asserted cell is refused too. Entries of another tool
// cover none.
func sdkRegressionCell(e PendingEntry) string {
	if t := e.tool(); t != "" && t != "conform" {
		return ""
	}
	for _, r := range conform.SDKRegressionRows() {
		if e["entry"] != r.Entry || (e["level"] != "" && e["level"] != r.Level) {
			continue
		}
		for _, col := range r.Columns {
			if e["column"] == "" || e["column"] == col {
				return r.ID + " on " + col
			}
		}
	}
	return ""
}

func normKey(k string) string {
	if k == "commit" {
		return "version"
	}
	return k
}

// rowValue returns a row's value for a pending key.
func rowValue(r *report.Row, k string) string {
	switch k {
	case "target":
		return r.Target.Name
	case "version":
		return r.Target.Version
	case "tool":
		return r.Tool
	case "column":
		return r.Target.Column
	case "entry":
		return r.Entry
	case "variant":
		return r.Variant
	case "level":
		if r.Conform != nil {
			return r.Conform.Level
		}
	case "rule":
		if r.Lint != nil {
			return r.Lint.Rule
		}
	case "file":
		if r.Lint != nil {
			return r.Lint.Location.File
		}
	case "line":
		if r.Lint != nil {
			return strconv.Itoa(r.Lint.Location.Line)
		}
	case "function":
		if r.Lint != nil {
			return r.Lint.Location.Function
		}
	case "site":
		if r.Lint != nil {
			return SiteHash(r.Lint.Rule, r.Lint.Location.File, r.Lint.Location.Line)
		}
	case "message":
		if r.Lint != nil {
			return NormaliseMessage(r.Lint.Message)
		}
	case "site2":
		if r.Lint != nil {
			return SiteHash2(r.Lint.Rule, r.Lint.Location.File, r.Lint.Location.Function, r.Lint.Message)
		}
	}
	return ""
}

// Matches reports whether some entry matches the row.
func (p *Pending) Matches(r *report.Row) bool {
	return len(p.matching(r)) > 0
}

// matching returns the indexes of the entries that match the row.
func (p *Pending) matching(r *report.Row) []int {
	if p == nil {
		return nil
	}
	var out []int
	for i, e := range p.Entries {
		ok := true
		for k, v := range e {
			if rowValue(r, k) != v {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, i)
		}
	}
	return out
}

// Describe names entry i for messages: its file, index and keys.
func (p *Pending) Describe(i int) string {
	e := p.Entries[i]
	keys := make([]string, 0, len(e))
	for k := range e {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for j, k := range keys {
		parts[j] = k + "=" + e[k]
	}
	if i >= len(p.Sources) {
		return fmt.Sprintf("pending entry {%s}", strings.Join(parts, " "))
	}
	return fmt.Sprintf("%s pending[%d] {%s}", p.Sources[i].File, p.Sources[i].Index, strings.Join(parts, " "))
}

// Review reports whether the row is pending finding review: a failure that needs a finding (sdk, pipeline or core
// target), carries no finding ID, and is named by a pending list. The findings check counts exactly these rows.
func (p *Pending) Review(r *report.Row) bool {
	return len(p.reviewMatches(r)) > 0
}

// reviewMatches returns the indexes of the entries that put the row pending finding review (see Review).
func (p *Pending) reviewMatches(r *report.Row) []int {
	if r.Finding != nil || !report.NeedsFinding(r) {
		return nil
	}
	return p.matching(r)
}

// Mark sets the expectation of an unexpected row that is pending finding review to report.ExpectationPending,
// and reports whether it did. Tools call it where they assign a row's expectation.
func (p *Pending) Mark(r *report.Row) bool {
	if r.Expectation == "unexpected" && p.Review(r) {
		r.Expectation = report.ExpectationPending
		return true
	}
	return false
}

// String summarises the lists for messages.
func (p *Pending) String() string {
	if p == nil || len(p.Files) == 0 {
		return "no pending lists"
	}
	return fmt.Sprintf("%d pending entries in %s", len(p.Entries), strings.Join(p.Files, ", "))
}

// SiteHash is a lint location in the form a pending entry's "site" key gives it (xdrlint's framework.SiteHash):
// it matches the row without the public list naming the file.
func SiteHash(rule, file string, line int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("xdrlint.site/v1:%s:%s:%d", rule, file, max(line, 1))))
	return hex.EncodeToString(sum[:])
}

// SiteHash2 is a lint report in the form a pending entry's "site2" key gives it (xdrlint's
// framework.SiteHash2): rule, file, function and message without line numbers, so the entry survives code
// moving within the file.
func SiteHash2(rule, file, function, message string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("xdrlint.site/v2:%s:%s:%s:%s", rule, file, function, NormaliseMessage(message))))
	return hex.EncodeToString(sum[:])
}

// NormaliseMessage is xdrlint's framework.NormaliseMessage: a message without the line numbers it names.
func NormaliseMessage(msg string) string {
	msg = msgGoLine.ReplaceAllString(msg, "$1")
	msg = msgLines.ReplaceAllString(msg, "lines")
	msg = msgLine.ReplaceAllString(msg, "line")
	return strings.Join(strings.Fields(msg), " ")
}

var (
	msgGoLine = regexp.MustCompile(`\b([A-Za-z0-9_.\-]+\.go):[0-9]+(?::[0-9]+)?`)
	msgLines  = regexp.MustCompile(`\blines [0-9]+(?:[-–][0-9]+)?`)
	msgLine   = regexp.MustCompile(`\bline [0-9]+`)
)
