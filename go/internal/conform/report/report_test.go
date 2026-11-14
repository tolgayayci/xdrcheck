package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
	"github.com/tolgayayci/xdrcheck/go/internal/findings"
	xreport "github.com/tolgayayci/xdrcheck/go/internal/report"
)

// fixtureMatrix is a small synthetic run: three SDK columns and the stub, five entries.
//
//	p30/a  ledger, CAP 84, P30   go new: ok      go old: refused   js: ok
//	p30/b  ledger, CAP 88, P30   go new: ok      go old: refused   js: known divergence (L1)
//	p30/neg xdr negative, P30    left out of readiness
//	p28/d  xdr, CAP 83, P28      go new: ok      go old: ok        js: ok
//	api/e  api, P30              left out of readiness
func fixtureMatrix() *verdict.Matrix {
	m := &verdict.Matrix{Schema: verdict.MatrixSchema}
	m.Corpus.Version = "0.0.0-test"
	m.Columns = []verdict.MatrixColumn{
		{ID: "go@v0.9.0", SDK: "go", Version: "v0.9.0", Kind: "sdk"},
		{ID: "go@v0.7.1", SDK: "go", Version: "v0.7.1", Kind: "sdk"},
		{ID: "js@16.3.0", SDK: "js", Version: "16.3.0", Kind: "sdk"},
		{ID: "stub@0.1.0", SDK: "stub", Version: "0.1.0", Kind: "selftest"},
	}
	m.Entries = []verdict.MatrixEntry{
		{ID: "p30/a", Kind: "ledger", Caps: []int{84}, ProtocolIntroduced: 30},
		{ID: "p30/b", Kind: "ledger", Caps: []int{88}, ProtocolIntroduced: 30, Flags: []string{"depth"}},
		{ID: "p30/neg", Kind: "xdr", Negative: true, Validity: "malformed", ProtocolIntroduced: 30, Flags: []string{"bool-range"}},
		{ID: "p28/d", Kind: "xdr", Caps: []int{83}, ProtocolIntroduced: 28},
		{ID: "api/e", Kind: "api", ProtocolIntroduced: 30},
	}
	ok := func(e, col, lvl string) verdict.Cell {
		return verdict.Cell{Entry: e, Column: col, Level: lvl, Outcome: "ok", Verdict: "conform", Check: "conform"}
	}
	beyond := func(e, col, lvl string) verdict.Cell {
		return verdict.Cell{Entry: e, Column: col, Level: lvl, Outcome: "reject", Verdict: "n_a", Check: "n_a", OutOfReach: true}
	}
	m.Cells = []verdict.Cell{
		ok("p30/a", "go@v0.9.0", "L0"), ok("p30/a", "go@v0.9.0", "L1"),
		ok("p30/b", "go@v0.9.0", "L0"), ok("p30/b", "go@v0.9.0", "L1"),
		ok("p28/d", "go@v0.9.0", "L0"),
		beyond("p30/a", "go@v0.7.1", "L0"), {Entry: "p30/a", Column: "go@v0.7.1", Level: "L1", Verdict: "n_a", Check: "n_a", BlockedByL0: true},
		beyond("p30/b", "go@v0.7.1", "L0"),
		ok("p28/d", "go@v0.7.1", "L0"),
		ok("p30/a", "js@16.3.0", "L0"),
		ok("p30/b", "js@16.3.0", "L0"),
		{Entry: "p30/b", Column: "js@16.3.0", Level: "L1", Outcome: "reject", Verdict: "reject_valid", Check: "known"},
		ok("p28/d", "js@16.3.0", "L0"),
		// Negative and api entries: never in readiness; the scoreboard counts them.
		{Entry: "p30/neg", Column: "js@16.3.0", Level: "L0", Outcome: "ok", Verdict: "accepts_invalid", Check: "undeclared"},
		{Entry: "p30/neg", Column: "go@v0.9.0", Level: "L0", Outcome: "ok", Verdict: "accepts_invalid", Check: "undeclared", PendingReview: true},
		ok("api/e", "go@v0.9.0", "L4"),
		{Entry: "api/e", Column: "js@16.3.0", Level: "L4", Outcome: "n_a", Verdict: "n_a", Check: "n_a"},
		ok("p30/a", "stub@0.1.0", "L0"),
	}
	return m
}

func TestReadiness(t *testing.T) {
	pinned := []Pinned{
		{ID: "python@17.0.0", SDK: "python", Version: "17.0.0", Kind: "sdk"},
		{ID: "go@v0.9.0", SDK: "go", Version: "v0.9.0", Kind: "sdk"},
		{ID: "stub@0.1.0", SDK: "stub", Version: "0.1.0", Kind: "selftest"},
	}
	r := BuildReadiness(fixtureMatrix(), pinned, 0)

	var keys []string
	for _, g := range r.Groups {
		keys = append(keys, g.Key)
	}
	if got, want := strings.Join(keys, ","), "P28,P30,CAP-0083,CAP-0084,CAP-0088"; got != want {
		t.Fatalf("groups %s, want %s", got, want)
	}
	for _, g := range r.Groups {
		if g.Key == "P30" && strings.Join(g.Entries, ",") != "p30/a,p30/b" {
			t.Errorf("P30 entries %v: the negative and api entries must be left out", g.Entries)
		}
	}
	var cols []string
	for _, row := range r.Rows {
		cols = append(cols, row.Column)
	}
	if got, want := strings.Join(cols, ","), "go@v0.7.1,go@v0.9.0,js@16.3.0,python@17.0.0"; got != want {
		t.Fatalf("rows %s, want %s (sorted by SDK and version, stub left out)", got, want)
	}
	state := func(col, group string) *ReadinessCell {
		for _, row := range r.Rows {
			if row.Column == col {
				return row.Cells[group]
			}
		}
		t.Fatalf("no row %s", col)
		return nil
	}
	cases := []struct {
		col, group, state string
		decoded, judged   int
	}{
		{"go@v0.9.0", "P30", StateFull, 2, 2},
		{"go@v0.9.0", "P28", StateFull, 1, 1},
		{"go@v0.7.1", "P30", StateRefuses, 0, 2},
		{"go@v0.7.1", "CAP-0084", StateRefuses, 0, 1},
		{"go@v0.7.1", "P28", StateFull, 1, 1},
		{"js@16.3.0", "P30", StatePartial, 1, 2},
		{"js@16.3.0", "CAP-0088", StatePartial, 0, 1},
		{"js@16.3.0", "CAP-0084", StateFull, 1, 1},
		{"python@17.0.0", "P30", StateNotRun, 0, 0},
	}
	for _, c := range cases {
		got := state(c.col, c.group)
		if got.State != c.state || got.Decoded != c.decoded || got.Judged != c.judged {
			t.Errorf("%s %s: %+v, want %s %d of %d", c.col, c.group, got, c.state, c.decoded, c.judged)
		}
	}
	if f := state("js@16.3.0", "P30").Failing; len(f) != 1 || f[0] != "p30/b" {
		t.Errorf("js P30 failing %v, want [p30/b]", f)
	}
	for _, row := range r.Rows {
		if row.Column == "python@17.0.0" && row.InRun {
			t.Errorf("python is pinned only, not in the run")
		}
	}

	var md bytes.Buffer
	r.Markdown(&md)
	for _, want := range []string{
		"| SDK version | P28 (1) | P30 (2) |",
		"| `go@v0.7.1` | full (1) | refuses new arms |",
		"| `js@16.3.0` | full (1) | **partial 1 of 2** (1 wrong) |",
		"| `python@17.0.0` (not in this run) | not run | not run |",
		"## By CAP",
	} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("markdown lacks %q:\n%s", want, md.String())
		}
	}

	// --protocol keeps that protocol and the CAPs of its entries only.
	r30 := BuildReadiness(fixtureMatrix(), nil, 30)
	keys = nil
	for _, g := range r30.Groups {
		keys = append(keys, g.Key)
	}
	if got, want := strings.Join(keys, ","), "P30,CAP-0084,CAP-0088"; got != want {
		t.Errorf("--protocol 30 groups %s, want %s", got, want)
	}

	dir := t.TempDir()
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	var back Readiness
	b, err := os.ReadFile(filepath.Join(dir, ReadinessJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &back); err != nil || back.Schema != ReadinessSchema || len(back.Rows) != len(r.Rows) {
		t.Errorf("readiness.json does not read back: %v %+v", err, back.Schema)
	}
	if _, err := os.Stat(filepath.Join(dir, ReadinessMarkdown)); err != nil {
		t.Error(err)
	}
}

func fixtureReplay() *xreport.Report {
	row := func(entry string, failure bool, expectation, class string) xreport.Row {
		return xreport.Row{RowID: "replay:" + entry, Tool: "replay", Entry: entry, Target: xreport.Target{Name: "demo indexer", Version: "1.2.3", Kind: "pipeline"},
			Failure: failure, Expectation: expectation, Replay: &xreport.ReplayResult{Unit: "single", Class: class}}
	}
	return &xreport.Report{Schema: xreport.Schema, Rows: []xreport.Row{
		row("p30/a", false, "expected", "pass"),
		row("p30/b", true, "unexpected", "mishandled"),
		row("p26/z", true, "expected", "dropped"),
		row("p28/x", false, "expected", "not_applicable"),
		{RowID: "lint:1", Tool: "lint", Target: xreport.Target{Name: "lint"}}, // not a replay row
	}}
}

func fixtureRecords() []*findings.Record {
	rec := func(id, vis, state, url, sev, title string) *findings.Record {
		r := &findings.Record{ID: id, Title: title, Visibility: vis, State: state, Severity: sev, Class: "wrong_value",
			Target: findings.Target{Project: "example/sdk"}}
		if url != "" {
			r.Upstream = &findings.Upstream{URL: url}
		}
		return r
	}
	return []*findings.Record{
		rec("F-0001", "public", "filed", "https://example.invalid/issues/1", "low", "Low <b>bug</b>"),
		rec("F-0002", "public", "filed", "https://example.invalid/issues/2", "high", "High bug"),
		rec("F-0003", "public", "duplicate-of", "https://example.invalid/issues/3", "high", "Duplicate"),
		rec("F-0004", "public", "filed", "", "medium", "No URL yet"),
		rec("F-5001", "embargoed", "filed", "https://example.invalid/issues/5001", "critical", "Embargoed one"),
		rec("F-0005", "public", "candidate", "", "critical", "Candidate"),
		rec("F-0006", "public", "filed", "javascript:alert(1)", "high", "Bad URL"),
	}
}

func TestScoreboard(t *testing.T) {
	s := BuildScoreboard(ScoreboardInput{Matrix: fixtureMatrix(), Replays: []*xreport.Report{fixtureReplay()}, Records: fixtureRecords(),
		Flags: func(id string) []string {
			if id == "p26/z" {
				return []string{"ordering"}
			}
			return nil
		}})
	impl := map[string]Implementation{}
	var order []string
	for _, i := range s.Implementations {
		impl[i.Name] = i
		order = append(order, i.Name)
	}
	if got, want := strings.Join(order, ","), "go@v0.9.0,go@v0.7.1,js@16.3.0,demo indexer@1.2.3"; got != want {
		t.Fatalf("implementations %s, want %s (stub left out, newest first, replay last)", got, want)
	}
	check := func(name string, pass, known, unexpected, review, na int) {
		i := impl[name]
		if i.Pass != pass || i.Known != known || i.Unexpected != unexpected || i.Review != review || i.NA != na {
			t.Errorf("%s: %+v, want pass %d known %d unexpected %d review %d n/a %d", name, i, pass, known, unexpected, review, na)
		}
	}
	check("go@v0.9.0", 6, 0, 0, 1, 0)
	check("go@v0.7.1", 1, 0, 0, 0, 3)
	check("js@16.3.0", 3, 1, 1, 0, 1)
	check("demo indexer@1.2.3", 1, 1, 1, 0, 1)

	flags := map[string]BugClass{}
	for _, c := range s.Classes {
		flags[c.Flag] = c
	}
	if c := flags["bool-range"]; c.Total != 2 || c.ByFamily["js"] != 1 || c.ByFamily["go"] != 1 {
		t.Errorf("bool-range %+v", c)
	}
	if c := flags["depth"]; c.Total != 2 || c.ByFamily["js"] != 1 || c.ByFamily["demo indexer"] != 1 {
		t.Errorf("depth %+v: the matrix's flags apply to replay rows of the same entry", c)
	}
	if c := flags["ordering"]; c.Total != 1 || c.ByFamily["demo indexer"] != 1 {
		t.Errorf("ordering %+v: replay entries outside the matrix take the Flags lookup", c)
	}

	var ids []string
	for _, b := range s.Bugs {
		ids = append(ids, b.ID)
	}
	if got, want := strings.Join(ids, ","), "F-0002,F-0001"; got != want {
		t.Errorf("bugs %s, want %s (public, filed, https URL; most severe first)", got, want)
	}

	var page bytes.Buffer
	if err := s.HTML(&page); err != nil {
		t.Fatal(err)
	}
	html := page.String()
	for _, want := range []string{"<!doctype html>", "prefers-color-scheme: dark", "https://example.invalid/issues/2", "Low &lt;b&gt;bug&lt;/b&gt;",
		"<code>demo indexer@1.2.3</code>", "<code>bool-range</code>"} {
		if !strings.Contains(html, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, never := range []string{"ZgotmplZ", "F-5001", "Embargoed one", "issues/5001", "issues/3", "No URL yet", "Candidate", "javascript:", "<script", "http://", "<link"} {
		if strings.Contains(html, never) {
			t.Errorf("page holds %q", never)
		}
	}

	dir := t.TempDir()
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{ScoreboardHTML, ScoreboardJSON} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Error(err)
		}
	}
}

func TestScoreboardReplayOnly(t *testing.T) {
	s := BuildScoreboard(ScoreboardInput{Replays: []*xreport.Report{fixtureReplay()}})
	if len(s.Implementations) != 1 || s.Corpus != "" {
		t.Fatalf("%+v", s)
	}
	var page bytes.Buffer
	if err := s.HTML(&page); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.String(), "no conformance matrix") || !strings.Contains(page.String(), "None listed.") {
		t.Errorf("replay-only page:\n%s", page.String())
	}
}
