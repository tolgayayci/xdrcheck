package main

// xdrcheck report acceptance (the table, one row per check, each check's rows in acceptance_<check>.go) and
// xdrcheck report diff.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/findings"
	"github.com/tolgayayci/xdrcheck/go/internal/pins"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

func reportAcceptance(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck report acceptance", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "output file (default <reports-dir>/acceptance.md)")
	fullCI := fs.String("full-ci", "", "comma-separated `targets`: make targets only the full CI runs; a check met here whose other runs are theirs is \"proven in full CI\"")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "xdrcheck report acceptance: "+format+"\n", a...)
		return 2
	}
	if len(pos) != 1 {
		return fail("want exactly one reports directory")
	}
	dir := pos[0]
	paths, err := findings.FindReports(dir)
	if err != nil {
		return fail("%v", err)
	}
	shown := filepath.ToSlash(filepath.Clean(dir))
	if filepath.IsAbs(dir) {
		shown = filepath.Base(dir)
	}
	store, root, err := openStore("")
	if err != nil {
		return fail("%v", err)
	}
	pending, err := findings.LoadPending(root)
	if err != nil {
		return fail("%v", err)
	}
	var all []*reportStats
	for _, p := range paths {
		rel, _ := filepath.Rel(dir, p)
		s, err := readStats(p, shown+"/"+filepath.ToSlash(rel))
		if err != nil {
			return fail("%v", err)
		}
		if s.header.Mode.Overlay {
			return fail("%s was made with the private overlay; the acceptance report never includes such a report", p)
		}
		all = append(all, s)
	}
	p, err := pins.Load(filepath.Join(root, "pins.toml"))
	if err != nil {
		return fail("%v", err)
	}
	c := &acceptanceCtx{dir: dir, shown: shown, root: root, all: all, pins: p, pending: pending, store: store, fullCI: map[string]bool{}}
	for _, t := range strings.Split(*fullCI, ",") {
		if t = strings.TrimSpace(t); t != "" {
			c.fullCI[t] = true
		}
	}
	var rows []acceptanceRow
	rows = append(rows, corpusRows(c)...)
	rows = append(rows, replayRegressionRows(c)...)
	rows = append(rows, lintRows(c)...)
	rows = append(rows, guideRows(c)...)
	rows = append(rows, sdkRegressionRows(c)...)
	r6, err := findingsLinkedRow(c)
	if err != nil {
		return fail("%v", err)
	}
	rows = append(rows, r6)

	var b strings.Builder
	fmt.Fprintf(&b, "# Acceptance report\n\nBuilt by `xdrcheck report acceptance` from %d report(s) under `%s`. Each row is read from that check's own verdict artefact. A status is `met`; `not met` (anything open, including what waits on people outside the build: the row names that action, such as rows pending finding review whose filing waits on the maintainers' approval, or the guide's external review); `missing` (a report the check needs is not there); `not recorded` (the check's make target was not run against these reports); or `proven in full CI` (what this run checked holds, and the check's other runs are made only by the full CI, whose table is the check's verdict).\n\n", len(all), shown)
	b.WriteString("| Check | Status | What was checked | Artefact |\n|---|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", r.check, r.status, strings.ReplaceAll(r.checked, "|", "\\|"), r.artefact)
	}
	b.WriteString("\n" + EmbargoSentence + "\n")
	dest := *out
	if dest == "" {
		dest = filepath.Join(dir, "acceptance.md")
	}
	if err := os.WriteFile(dest, []byte(b.String()), 0o644); err != nil {
		return fail("%v", err)
	}
	// The same rows for programs (make results-acceptance reads it): <dest without .md>.json.
	doc := acceptanceDoc{Schema: acceptanceSchema, Reports: shown, ReportCount: len(all), Rows: []acceptanceJSONRow{}}
	for _, r := range rows {
		doc.Rows = append(doc.Rows, acceptanceJSONRow{Check: r.check, Status: r.status, Checked: r.checked, Artefact: r.artefact})
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fail("%v", err)
	}
	if err := os.WriteFile(strings.TrimSuffix(dest, ".md")+".json", append(data, '\n'), 0o644); err != nil {
		return fail("%v", err)
	}
	fmt.Fprint(stdout, b.String())
	return 0
}

// acceptanceSchema is the schema ID of the acceptance table's JSON form (acceptance.json beside acceptance.md).
const acceptanceSchema = "xdrcheck.acceptance/v1"

type acceptanceDoc struct {
	Schema      string              `json:"schema"`
	Reports     string              `json:"reports"`
	ReportCount int                 `json:"report_count"`
	Rows        []acceptanceJSONRow `json:"rows"`
}

type acceptanceJSONRow struct {
	Check    string `json:"check"`
	Status   string `json:"status"`
	Checked  string `json:"checked"`
	Artefact string `json:"artefact"`
}

// acceptanceCtx is what every acceptance check reads: the reports directory (and how the table shows it), the
// repository root, the reports' stats, the pins, the pending lists with the required run set, and the findings
// store.
type acceptanceCtx struct {
	dir, shown, root string
	all              []*reportStats
	pins             *pins.Pins
	pending          *findings.Pending
	store            *findings.Store
	fullCI           map[string]bool // make targets only the full CI runs (--full-ci)
}

// byTool returns the reports of one tool, in order.
func (c *acceptanceCtx) byTool(tool string) []*reportStats {
	var r []*reportStats
	for _, s := range c.all {
		if s.header.Tool.Name == tool {
			r = append(r, s)
		}
	}
	return r
}

// runsOf returns the runs of the required set (findings/required-runs.d/) whose reports check's verdict reads.
func (c *acceptanceCtx) runsOf(check string) []findings.RequiredRun {
	return findings.RunsFor(c.pending.Required, check)
}

// rels lists reports by their shown paths.
func rels(rs []*reportStats) string {
	var r []string
	for _, s := range rs {
		r = append(r, "`"+s.rel+"`")
	}
	return strings.Join(r, ", ")
}

type rowSummary struct {
	failure     bool
	result      string
	expectation string
}

func reportDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck report diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "xdrcheck report diff: "+format+"\n", a...)
		return 2
	}
	if len(pos) != 2 {
		return fail("want two reports")
	}
	a := map[string]rowSummary{}
	ha, _, err := report.ReadFile(pos[0], func(r *report.Row) error {
		a[r.RowID] = rowSummary{r.Failure, report.ResultKey(r), r.Expectation}
		return nil
	})
	if err != nil {
		return fail("%v", err)
	}
	var newlyFail, newlyPass, changed, onlyB []string
	seen := map[string]bool{}
	hb, _, err := report.ReadFile(pos[1], func(r *report.Row) error {
		seen[r.RowID] = true
		b := rowSummary{r.Failure, report.ResultKey(r), r.Expectation}
		old, ok := a[r.RowID]
		switch {
		case !ok:
			onlyB = append(onlyB, fmt.Sprintf("%s (%s)", r.RowID, b.result))
		case !old.failure && b.failure:
			newlyFail = append(newlyFail, fmt.Sprintf("%s: %s → %s", r.RowID, old.result, b.result))
		case old.failure && !b.failure:
			newlyPass = append(newlyPass, fmt.Sprintf("%s: %s → %s", r.RowID, old.result, b.result))
		case old.result != b.result || old.expectation != b.expectation:
			changed = append(changed, fmt.Sprintf("%s: %s %s → %s %s", r.RowID, old.result, old.expectation, b.result, b.expectation))
		}
		return nil
	})
	if err != nil {
		return fail("%v", err)
	}
	if ha.Tool.Name != hb.Tool.Name {
		return fail("the reports are from different tools (%s, %s)", ha.Tool.Name, hb.Tool.Name)
	}
	var onlyA []string
	for id, s := range a {
		if !seen[id] {
			onlyA = append(onlyA, fmt.Sprintf("%s (%s)", id, s.result))
		}
	}
	if ha.Corpus != hb.Corpus || ha.Pins.FileSHA256 != hb.Pins.FileSHA256 || ha.Mode != hb.Mode {
		fmt.Fprintln(stdout, "note: the headers differ (corpus, pins file or mode); rows are compared regardless")
	}
	n := 0
	section := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		sort.Strings(items)
		fmt.Fprintf(stdout, "%s: %d\n", title, len(items))
		for _, it := range items {
			fmt.Fprintln(stdout, "  "+it)
		}
		n += len(items)
	}
	section("newly fail", newlyFail)
	section("newly pass", newlyPass)
	section("changed result", changed)
	section("only in "+pos[0], onlyA)
	section("only in "+pos[1], onlyB)
	fmt.Fprintf(stdout, "report diff: %d rows compared, %d differences\n", len(a), n)
	if n > 0 {
		return 1
	}
	return 0
}
