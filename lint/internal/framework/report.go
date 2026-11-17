package framework

// The shared report (`-report FILE`, schema xcc.report/v1) and the expected
// list (`-expect FILE`).
//
// Every finding becomes a row, suppressed or not, so that `xdrcheck findings
// check` can require a finding record for each report on third-party code.
// A rule report is a failure row (the reader under test got it wrong);
// an XDR000 row is about our own suppression files and is never a failure.
//
// Expectation of a row:
//
//	with -expect:  expected while the list still has a count left for its
//	               (rule, file, function, suppressed), or for its (rule, file,
//	               function, suppressed, message) when the entry names a
//	               message (compared by NormaliseMessage, without line
//	               numbers): the list is a multiset, so one report more than it
//	               counts is unexpected
//	without:       suppressed → expected (source "suppression");
//	               unsuppressed at or above -fail-on → unexpected;
//	               unsuppressed below -fail-on → expected (source "default")
//	-pending:      an unsuppressed report that is not expected and whose (rule, file, line) the pending list
//	               names → pending (pending finding review; not counted as unexpected)

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

// ReportSchema is the value of the report's "schema" field.
const ReportSchema = "xcc.report/v1"

// ExpectSchema is the value of an expected list's "schema" field.
const ExpectSchema = "xdrlint.expect/v1"

// XDRCheckReport is an xcc.report/v1 document.
type XDRCheckReport struct {
	Schema  string     `json:"schema"`
	Header  Header     `json:"header"`
	Rows    []Row      `json:"rows"`
	Summary RowSummary `json:"summary"`
}

type Header struct {
	Tool   HeaderTool   `json:"tool"`
	Corpus HeaderCorpus `json:"corpus"`
	Pins   HeaderPins   `json:"pins"`
	Mode   HeaderMode   `json:"mode"`
	Run    *HeaderRun   `json:"run,omitempty"`
}

type HeaderTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

type HeaderCorpus struct {
	Version        string `json:"version"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

type HeaderPins struct {
	FileSHA256 string            `json:"file_sha256"`
	Values     map[string]string `json:"values,omitempty"`
}

type HeaderMode struct {
	Suite   string `json:"suite"`
	Overlay bool   `json:"overlay"`
}

type HeaderRun struct {
	Started    string            `json:"started,omitempty"`
	WallMS     float64           `json:"wall_ms"`
	Toolchains map[string]string `json:"toolchains,omitempty"`
}

type Row struct {
	RowID       string       `json:"row_id"`
	Tool        string       `json:"tool"`
	Entry       string       `json:"entry,omitempty"`
	Target      RowTarget    `json:"target"`
	Failure     bool         `json:"failure"`
	Expectation string       `json:"expectation"`
	Expected    *RowExpected `json:"expected,omitempty"`
	Finding     *string      `json:"finding"`
	Lint        RowLint      `json:"lint"`
}

type RowTarget struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
	Profile string `json:"profile,omitempty"`
}

type RowExpected struct {
	Source string `json:"source"`
	Result string `json:"result,omitempty"`
}

type RowLint struct {
	Rule              string      `json:"rule"`
	Severity          Severity    `json:"severity"`
	Location          RowLocation `json:"location"`
	Message           string      `json:"message,omitempty"`
	Assumption        string      `json:"assumption,omitempty"`
	Suppressed        bool        `json:"suppressed"`
	SuppressionReason string      `json:"suppression_reason,omitempty"`
}

type RowLocation struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Function string `json:"function,omitempty"`
}

type RowSummary struct {
	Rows                   int            `json:"rows"`
	Failures               int            `json:"failures"`
	Unexpected             int            `json:"unexpected"`
	FailuresWithoutFinding int            `json:"failures_without_finding"`
	ByResult               map[string]int `json:"by_result,omitempty"`
}

// ReportMeta is what the report says about the run besides the findings.
type ReportMeta struct {
	ToolVersion   string
	ToolCommit    string
	PinsSHA256    string
	PinValues     map[string]string
	Suite         string
	Overlay       bool
	TargetName    string
	TargetVersion string
	TargetKind    string
	Profile       string
	Started       time.Time
	Wall          time.Duration
	Toolchains    map[string]string
	FailOn        Severity        // threshold that fails the run (default error)
	Expect        []ExpectEntry   // nil: no -expect
	Pending       []PendingEntry  // reports pending finding review (-pending)
	Rules         map[string]Rule // corpus entry per rule
}

// BuildReport turns findings into an xcc.report/v1 document.
func BuildReport(m ReportMeta, findings []Finding) *XDRCheckReport {
	zero := strings.Repeat("0", 64)
	rep := &XDRCheckReport{
		Schema: ReportSchema,
		Header: Header{
			Tool: HeaderTool{Name: "xdrlint", Version: m.ToolVersion, Commit: m.ToolCommit},
			// The linter reads no corpus; the block is required by the schema.
			Corpus: HeaderCorpus{Version: "none", ManifestSHA256: zero},
			Pins:   HeaderPins{FileSHA256: orDefault(m.PinsSHA256, zero), Values: m.PinValues},
			Mode:   HeaderMode{Suite: orDefault(m.Suite, "xdrlint"), Overlay: m.Overlay},
		},
		Rows: []Row{},
	}
	if !m.Started.IsZero() {
		rep.Header.Run = &HeaderRun{
			Started:    m.Started.UTC().Format(time.RFC3339),
			WallMS:     float64(m.Wall.Microseconds()) / 1000,
			Toolchains: m.Toolchains,
		}
	}
	failOn := m.FailOn
	if !failOn.Valid() {
		failOn = SeverityError
	}
	var expect map[ExpectEntry]int
	if m.Expect != nil {
		expect = ExpectCounts(m.Expect)
	}
	// take consumes one count of the entry that accounts for f: the entry
	// naming its message first, then the one without.
	take := func(f Finding) bool {
		for _, k := range []ExpectEntry{f.MessageKey(), f.Key()} {
			if expect[k] > 0 {
				expect[k]--
				return true
			}
		}
		return false
	}
	kind := orDefault(m.TargetKind, "pipeline")
	version := orDefault(m.TargetVersion, "unknown")
	short := version
	if len(short) == 40 {
		short = short[:8]
	}
	seen := map[string]int{}
	rep.Summary.ByResult = map[string]int{}
	for _, f := range SortFindings(findings) {
		row := Row{
			Tool:    "lint",
			Target:  RowTarget{Name: orDefault(m.TargetName, "unknown"), Version: version, Kind: kind, Profile: m.Profile},
			Failure: f.Rule != XDR000.ID,
			Lint: RowLint{
				Rule:       f.Rule,
				Severity:   f.Severity,
				Location:   RowLocation{File: f.File, Line: max(f.Position.Line, 1), Function: f.Function},
				Message:    f.Message,
				Assumption: f.Assumption,
				Suppressed: f.Suppressed,
			},
		}
		if r, ok := m.Rules[f.Rule]; ok && r.Corpus != "" {
			row.Entry = r.Corpus
		}
		base := fmt.Sprintf("lint:%s@%s:%s:%s:%s", row.Target.Name, short, f.Rule, f.File, f.Function)
		seen[base]++
		row.RowID = base
		if n := seen[base]; n > 1 {
			row.RowID = fmt.Sprintf("%s#%d", base, n)
		}
		if f.Suppression != nil {
			row.Lint.SuppressionReason = f.Suppression.Reason
			if f.Suppression.Finding != "" {
				id := f.Suppression.Finding
				row.Finding = &id
			}
		}
		result := f.Rule + " reported"
		switch {
		case expect != nil && take(f):
			row.Expectation = "expected"
			row.Expected = &RowExpected{Source: "fixture", Result: result}
			if f.Suppressed {
				row.Expected.Source = "suppression"
			}
		case !f.Suppressed && IsPending(m.Pending, f):
			row.Expectation = ExpectationPending
		case expect != nil:
			row.Expectation = "unexpected"
		case f.Suppressed:
			row.Expectation = "expected"
			row.Expected = &RowExpected{Source: "suppression", Result: result}
		case f.Severity.Rank() >= failOn.Rank():
			row.Expectation = "unexpected"
		default:
			row.Expectation = "expected"
			row.Expected = &RowExpected{Source: "default", Result: fmt.Sprintf("%s (%s, below -fail-on %s)", result, f.Severity, failOn)}
		}
		rep.Rows = append(rep.Rows, row)

		rep.Summary.Rows++
		if row.Failure {
			rep.Summary.Failures++
			if row.Finding == nil && (kind == "sdk" || kind == "pipeline" || kind == "core") {
				rep.Summary.FailuresWithoutFinding++
			}
		}
		if row.Expectation == "unexpected" {
			rep.Summary.Unexpected++
		}
		if f.Suppressed {
			rep.Summary.ByResult[f.Rule+" suppressed"]++
		} else {
			rep.Summary.ByResult[result]++
		}
	}
	return rep
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// SortFindings orders findings by file, line, column and rule.
func SortFindings(fs []Finding) []Finding {
	out := slices.Clone(fs)
	slices.SortStableFunc(out, func(a, b Finding) int {
		if c := strings.Compare(a.File, b.File); c != 0 {
			return c
		}
		if a.Position.Line != b.Position.Line {
			return a.Position.Line - b.Position.Line
		}
		if a.Position.Column != b.Position.Column {
			return a.Position.Column - b.Position.Column
		}
		return strings.Compare(a.Rule, b.Rule)
	})
	return out
}

// ExpectEntry is one line of an expected list: what `-expect` compares.
// Count is the number of reports with that key (0 means 1); a key may also
// be listed more than once, and the counts add up.
//
// An entry that names a message accounts only for reports with that message
// (compared by NormaliseMessage, so without the line numbers it names): the
// baseline key rule + file + function + message, which survives code moving
// within a file but not a second, different report in the same function.
type ExpectEntry struct {
	Rule       string `json:"rule"`
	File       string `json:"file"`
	Function   string `json:"function"`
	Suppressed bool   `json:"suppressed"`
	Message    string `json:"message,omitempty"`
	Count      int    `json:"count,omitempty"`
}

// key is the entry without its count, its message normalised.
func (e ExpectEntry) key() ExpectEntry {
	e.Count = 0
	if e.Message != "" {
		e.Message = NormaliseMessage(e.Message)
	}
	return e
}

// n is the number of reports the entry stands for.
func (e ExpectEntry) n() int { return max(e.Count, 1) }

// ExpectCounts returns the number of reports expected per key.
func ExpectCounts(entries []ExpectEntry) map[ExpectEntry]int {
	out := map[ExpectEntry]int{}
	for _, e := range entries {
		out[e.key()] += e.n()
	}
	return out
}

func (e ExpectEntry) String() string {
	s := fmt.Sprintf("%s %s", e.Rule, e.File)
	if e.Function != "" {
		s += " in " + e.Function
	}
	if e.Suppressed {
		s += " (suppressed)"
	}
	if e.Message != "" {
		s += fmt.Sprintf(" %q", NormaliseMessage(e.Message))
	}
	if e.Count > 1 {
		s += fmt.Sprintf(" ×%d", e.Count)
	}
	return s
}

// Key returns the comparison key of a finding.
func (f Finding) Key() ExpectEntry {
	return ExpectEntry{Rule: f.Rule, File: f.File, Function: f.Function, Suppressed: f.Suppressed}
}

// MessageKey is Key with the finding's normalised message.
func (f Finding) MessageKey() ExpectEntry {
	k := f.Key()
	k.Message = NormaliseMessage(f.Message)
	return k
}

// ExpectationPending is the expectation of a row pending finding review.
const ExpectationPending = "pending"

// PendingSchema is the value of a pending list's "schema" field.
const PendingSchema = "xdrlint.pending/v1"

// PendingEntry is one report pending finding review: the site and nothing else (no reason, no finding ID). A
// site the public tree must not name yet is given as Site, SiteHash of its rule, file and line, instead of File
// and Line.
//
// The line-free forms name the report by rule, file, function and message
// (compared by NormaliseMessage): File, Function and Message in the clear, or
// Site2, SiteHash2 of the four.
type PendingEntry struct {
	Rule     string `json:"rule"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Function string `json:"function,omitempty"`
	Message  string `json:"message,omitempty"`
	Site     string `json:"site,omitempty"`
	Site2    string `json:"site2,omitempty"`
}

// SiteHash2 is the hex SHA-256 of
// "xdrlint.site/v2:<rule>:<file>:<function>:<normalised message>".
func SiteHash2(rule, file, function, message string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("xdrlint.site/v2:%s:%s:%s:%s", rule, file, function, NormaliseMessage(message))))
	return hex.EncodeToString(sum[:])
}

// SiteHash is the hex SHA-256 of "xdrlint.site/v1:<rule>:<file>:<line>": a pending entry's site in a form
// that matches the report without naming the file.
func SiteHash(rule, file string, line int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("xdrlint.site/v1:%s:%s:%d", rule, file, line)))
	return hex.EncodeToString(sum[:])
}

// PendingFile is the pending-list format, kept next to a commit's expected list:
//
//	{"schema": "xdrlint.pending/v1", "commit": "<commit>", "since": "2026-11-13",
//	 "pending": [{"rule": "XDR201", "file": "…", "line": 143}, {"rule": "XDR102", "site": "<SiteHash>"}]}
//
// since (the date the entries were listed, on the list or on an entry) is read by the findings check's governance
// of the pending lists, not by xdrlint; other keys are ignored here and refused by that check.
type PendingFile struct {
	Schema  string         `json:"schema"`
	Commit  string         `json:"commit"`
	Since   string         `json:"since,omitempty"`
	Pending []PendingEntry `json:"pending"`
}

// LoadPending reads a pending list. A list for another commit than targetVersion (when both are set) is an error:
// its sites would silently match nothing.
func LoadPending(path, targetVersion string) ([]PendingEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pf PendingFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if pf.Schema != PendingSchema {
		return nil, fmt.Errorf("%s: schema %q, want %s", path, pf.Schema, PendingSchema)
	}
	if pf.Commit != "" && targetVersion != "" && pf.Commit != targetVersion {
		return nil, fmt.Errorf("%s: the list is for commit %s, the run for %s", path, pf.Commit, targetVersion)
	}
	return pf.Pending, nil
}

// IsPending reports whether a pending list names the finding's site.
func IsPending(pending []PendingEntry, f Finding) bool {
	line := max(f.Position.Line, 1)
	for _, p := range pending {
		if p.Rule != f.Rule {
			continue
		}
		switch {
		case p.Site2 != "":
			if p.Site2 == SiteHash2(f.Rule, f.File, f.Function, f.Message) {
				return true
			}
		case p.Site != "":
			if p.Site == SiteHash(f.Rule, f.File, line) {
				return true
			}
		case p.Message != "":
			if p.File == f.File && p.Function == f.Function && NormaliseMessage(p.Message) == NormaliseMessage(f.Message) {
				return true
			}
		case p.File == f.File && p.Line == line:
			return true
		}
	}
	return false
}

// ExpectFile is the expected-list format:
//
//	{"schema": "xdrlint.expect/v1", "reports": [{"rule": "XDR201", "file": "…", "function": "…", "suppressed": true, "count": 2}]}
//
// LoadExpect also accepts an xcc.report/v1 document, taking its lint rows.
type ExpectFile struct {
	Schema  string        `json:"schema"`
	Reports []ExpectEntry `json:"reports"`
}

// LoadExpect reads an expected list.
func LoadExpect(path string) ([]ExpectEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var head struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	switch head.Schema {
	case ExpectSchema:
		var ef ExpectFile
		if err := json.Unmarshal(data, &ef); err != nil {
			return nil, fmt.Errorf("%s: %v", path, err)
		}
		if ef.Reports == nil {
			ef.Reports = []ExpectEntry{}
		}
		return ef.Reports, nil
	case ReportSchema:
		var rep XDRCheckReport
		if err := json.Unmarshal(data, &rep); err != nil {
			return nil, fmt.Errorf("%s: %v", path, err)
		}
		out := []ExpectEntry{}
		for _, r := range rep.Rows {
			if r.Tool == "lint" {
				out = append(out, ExpectEntry{Rule: r.Lint.Rule, File: r.Lint.Location.File, Function: r.Lint.Location.Function, Suppressed: r.Lint.Suppressed, Message: r.Lint.Message})
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("%s: schema is %q, want %q or %q", path, head.Schema, ExpectSchema, ReportSchema)
}

// CompareExpect compares the findings with the expected list by count (as
// multisets). missing are expected but not reported, extra reported but not
// expected; the Count of each is how many reports of that key are missing
// or extra.
func CompareExpect(expected []ExpectEntry, findings []Finding) (missing, extra []ExpectEntry) {
	want := ExpectCounts(expected)
	// Keys some entry names a message for: a finding of such a key counts
	// against the entry with its own message (else it is extra under it).
	// When the list names messages, a finding no entry accounts for is
	// reported with its message.
	anyMsg := false
	for e := range want {
		anyMsg = anyMsg || e.Message != ""
	}
	got := map[ExpectEntry]int{}
	for _, f := range findings {
		if k := f.MessageKey(); want[k] > got[k] || anyMsg && want[f.Key()] <= got[f.Key()] {
			got[k]++
		} else {
			got[f.Key()]++
		}
	}
	for e, n := range want {
		if d := n - got[e]; d > 0 {
			e.Count = d
			missing = append(missing, e)
		}
	}
	for e, n := range got {
		if d := n - want[e]; d > 0 {
			e.Count = d
			extra = append(extra, e)
		}
	}
	less := func(a, b ExpectEntry) int { return strings.Compare(a.String(), b.String()) }
	slices.SortFunc(missing, less)
	slices.SortFunc(extra, less)
	return missing, extra
}
