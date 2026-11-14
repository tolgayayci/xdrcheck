package report

// The scoreboard: one self-contained HTML page (inline CSS, light and dark) over a conformance matrix, any
// number of indexer replay reports, and the public finding records, in the manner of a public
// per-implementation compliance report. Per implementation it counts the cells that pass, that fail as a
// declared known divergence, that fail unexpectedly, and that are under review; it breaks the failures down by
// the bug classes the corpus entries carry (`flags`, docs/manifest.md §9.5); and it lists the bugs found, linking
// only records that are public, filed and carry an upstream URL. Nothing else from a finding record is shown.

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
	"github.com/tolgayayci/xdrcheck/go/internal/findings"
	xreport "github.com/tolgayayci/xdrcheck/go/internal/report"
)

// ScoreboardSchema is the scoreboard data file's schema ID.
const ScoreboardSchema = "xcc.scoreboard/v1"

// Scoreboard output files.
const (
	ScoreboardHTML = "scoreboard.html"
	ScoreboardJSON = "scoreboard.json"
)

// NoFlag is the bug-class row of failing cells whose entry carries no flag.
const NoFlag = "(no flag)"

// Scoreboard is what the page shows; scoreboard.json holds the same.
type Scoreboard struct {
	Schema          string           `json:"schema"`
	Corpus          string           `json:"corpus"`
	Implementations []Implementation `json:"implementations"`
	Classes         []BugClass       `json:"bug_classes"`
	Families        []string         `json:"families"` // the bug-class table's columns: SDKs and indexers
	Bugs            []Bug            `json:"bugs"`
}

// Implementation is one conformance column or one replayed indexer version.
type Implementation struct {
	Name       string         `json:"name"`   // column ID, or indexer name@version
	Family     string         `json:"family"` // the SDK, or the indexer's name
	Version    string         `json:"version"`
	Kind       string         `json:"kind"`   // sdk, core, pipeline
	Source     string         `json:"source"` // conformance, replay
	Pass       int            `json:"pass"`
	Known      int            `json:"known"`
	Unexpected int            `json:"unexpected"`
	Review     int            `json:"under_review"`
	NA         int            `json:"not_applicable"`
	Classes    map[string]int `json:"failing_by_flag"`
}

// Judged is every cell that passed or failed.
func (i Implementation) Judged() int { return i.Pass + i.Known + i.Unexpected + i.Review }

func (i Implementation) pct(n int) float64 {
	if i.Judged() == 0 {
		return 0
	}
	return float64(n) * 100 / float64(i.Judged())
}

// BugClass is one row of the bug-class table: failing cells of entries with one flag, per family.
type BugClass struct {
	Flag     string         `json:"flag"`
	Total    int            `json:"total"`
	ByFamily map[string]int `json:"by_family"`
}

// Bug is one public, filed finding.
type Bug struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Project  string `json:"project"`
	Class    string `json:"class"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
	FiledAt  string `json:"filed_at,omitempty"`
}

// ScoreboardInput is what the scoreboard is built from. Matrix may be nil when only replay reports are given.
type ScoreboardInput struct {
	Matrix  *verdict.Matrix
	Replays []*xreport.Report
	// Records are finding records; only public, filed ones with an upstream URL are listed.
	Records []*findings.Record
	// Flags gives an entry's bug classes for replay rows (the matrix carries its own entries' flags); may be nil.
	Flags func(entry string) []string
}

// PublicBug reports whether a finding record may be listed: public, filed and with an upstream URL.
func PublicBug(r *findings.Record) bool {
	return r != nil && r.Visibility == "public" && r.State == "filed" && r.Upstream != nil && strings.HasPrefix(r.Upstream.URL, "https://")
}

// BuildScoreboard counts the implementations and collects the bugs.
func BuildScoreboard(in ScoreboardInput) *Scoreboard {
	s := &Scoreboard{Schema: ScoreboardSchema, Implementations: []Implementation{}, Classes: []BugClass{}, Families: []string{}, Bugs: []Bug{}}
	flagsOf := map[string][]string{}
	if m := in.Matrix; m != nil {
		s.Corpus = m.Corpus.Version
		for _, e := range m.Entries {
			flagsOf[e.ID] = e.Flags
		}
	}
	entryFlags := func(id string) []string {
		if f, ok := flagsOf[id]; ok {
			return f
		}
		if in.Flags != nil {
			return in.Flags(id)
		}
		return nil
	}
	count := func(impl *Implementation, entry, outcome string) {
		switch outcome {
		case "pass":
			impl.Pass++
		case "known":
			impl.Known++
		case "unexpected":
			impl.Unexpected++
		case "review":
			impl.Review++
		default:
			impl.NA++
			return
		}
		if outcome == "pass" {
			return
		}
		fl := entryFlags(entry)
		if len(fl) == 0 {
			fl = []string{NoFlag}
		}
		for _, f := range fl {
			impl.Classes[f]++
		}
	}

	if m := in.Matrix; m != nil {
		idx := map[string]int{}
		for _, c := range m.Columns {
			if c.Kind == "selftest" {
				continue
			}
			idx[c.ID] = len(s.Implementations)
			s.Implementations = append(s.Implementations, Implementation{Name: c.ID, Family: c.SDK, Version: c.Version,
				Kind: c.Kind, Source: "conformance", Classes: map[string]int{}})
		}
		for i := range m.Cells {
			c := &m.Cells[i]
			k, ok := idx[c.Column]
			if !ok {
				continue
			}
			count(&s.Implementations[k], c.Entry, cellOutcome(c))
		}
	}
	for _, rep := range in.Replays {
		idx := map[string]int{}
		for i := range rep.Rows {
			r := &rep.Rows[i]
			if r.Tool != "replay" || r.Replay == nil {
				continue
			}
			name := r.Target.Name + "@" + r.Target.Version
			k, ok := idx[name]
			if !ok {
				k = len(s.Implementations)
				idx[name] = k
				kind := r.Target.Kind
				if kind == "" {
					kind = "pipeline"
				}
				s.Implementations = append(s.Implementations, Implementation{Name: name, Family: r.Target.Name, Version: r.Target.Version,
					Kind: kind, Source: "replay", Classes: map[string]int{}})
			}
			count(&s.Implementations[k], r.Entry, replayOutcome(r))
		}
	}
	sort.SliceStable(s.Implementations, func(i, j int) bool {
		a, b := s.Implementations[i], s.Implementations[j]
		if a.Source != b.Source {
			return a.Source < b.Source // conformance before replay
		}
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if d, err := verdict.CompareVersions(a.Version, b.Version); err == nil && d != 0 {
			return d > 0 // newest first
		}
		return a.Name < b.Name
	})

	// Bug classes per family.
	byFlag := map[string]*BugClass{}
	fams := map[string]bool{}
	for _, impl := range s.Implementations {
		for f, n := range impl.Classes {
			bc := byFlag[f]
			if bc == nil {
				bc = &BugClass{Flag: f, ByFamily: map[string]int{}}
				byFlag[f] = bc
			}
			bc.Total += n
			bc.ByFamily[impl.Family] += n
			fams[impl.Family] = true
		}
	}
	for _, bc := range byFlag {
		s.Classes = append(s.Classes, *bc)
	}
	sort.Slice(s.Classes, func(i, j int) bool {
		a, b := s.Classes[i], s.Classes[j]
		if (a.Flag == NoFlag) != (b.Flag == NoFlag) {
			return b.Flag == NoFlag
		}
		if a.Total != b.Total {
			return a.Total > b.Total
		}
		return a.Flag < b.Flag
	})
	for f := range fams {
		s.Families = append(s.Families, f)
	}
	sort.Strings(s.Families)

	for _, r := range in.Records {
		if !PublicBug(r) {
			continue
		}
		s.Bugs = append(s.Bugs, Bug{ID: r.ID, Title: r.Title, Project: r.Target.Project, Class: r.Class, Severity: r.Severity,
			URL: r.Upstream.URL, FiledAt: r.Upstream.FiledAt})
	}
	sort.Slice(s.Bugs, func(i, j int) bool {
		a, b := s.Bugs[i], s.Bugs[j]
		if sa, sb := severityRank(a.Severity), severityRank(b.Severity); sa != sb {
			return sa < sb
		}
		return a.ID < b.ID
	})
	return s
}

// cellOutcome is a matrix cell's scoreboard bucket.
func cellOutcome(c *verdict.Cell) string {
	switch {
	case c.Check == "conform":
		return "pass"
	case c.Check == "known":
		return "known"
	case verdict.FailingCheck(c.Check) && c.PendingReview:
		return "review"
	case verdict.FailingCheck(c.Check):
		return "unexpected"
	}
	return "na"
}

// replayOutcome is a replay row's scoreboard bucket: a pass, an expected failure (a declared known divergence),
// an unexpected failure, one under review, or not judged (not applicable, not reached, flaky, a harness fault).
func replayOutcome(r *xreport.Row) string {
	switch {
	case r.Expectation == xreport.ExpectationPending:
		return "review"
	case r.Failure && r.Expectation == "unexpected":
		return "unexpected"
	case r.Failure:
		return "known"
	case r.Replay.Class == "pass":
		return "pass"
	}
	return "na"
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}

//go:embed scoreboard.html.tmpl
var scoreboardTemplate string

var scoreboardTmpl = template.Must(template.New("scoreboard").Funcs(template.FuncMap{
	"pct": func(i Implementation, n int) string { return fmt.Sprintf("%.2f", i.pct(n)) },
	"at":  func(m map[string]int, k string) int { return m[k] },
}).Parse(scoreboardTemplate))

// HTML writes the page.
func (s *Scoreboard) HTML(w io.Writer) error { return scoreboardTmpl.Execute(w, s) }

// Write writes scoreboard.html and scoreboard.json into dir.
func (s *Scoreboard) Write(dir string) error {
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, ScoreboardJSON), append(b, '\n'), 0o644); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(dir, ScoreboardHTML))
	if err != nil {
		return err
	}
	if err := s.HTML(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
