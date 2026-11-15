package findings

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

const lintCommit = "e967ce8b7362b79c277e700e789181d76fbb5967"

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func lintRow(id string, line int, finding *string) report.Row {
	return report.Row{RowID: id, Tool: "lint", Target: report.Target{Name: "github.com/stellar/wallet-backend", Version: lintCommit, Kind: "pipeline"},
		Failure: true, Expectation: "unexpected", Finding: finding,
		Lint: &report.LintResult{Rule: "XDR201", Severity: "warning", Location: report.Location{File: "internal/x.go", Line: line, Function: "walk"}}}
}

func pendingConformRow(id, column, level string) report.Row {
	return report.Row{RowID: id, Tool: "conform", Entry: "cap-0067/to-muxed-id-absent", Variant: "lcm",
		Target:  report.Target{Name: "@stellar/stellar-sdk", Version: "17.4.0", Kind: "sdk", Column: column},
		Failure: true, Expectation: "unexpected",
		Conform: &report.ConformResult{Level: level, Outcome: "diverge", Verdict: "diverge", Check: "undeclared"}}
}

// pendingRoot writes the two kinds of list the check reads: a linter list next to the expected lists and a
// generic list under findings/pending.
func pendingRoot(t *testing.T) string {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "lint/expected/wallet-backend", lintCommit+".pending.json"),
		`{"schema": "xdrlint.pending/v1", "commit": "`+lintCommit+`", "pending": [{"rule": "XDR201", "file": "internal/x.go", "line": 7}]}`)
	writeFile(t, filepath.Join(root, "findings/pending/conformance.json"),
		`{"pending": [{"entry": "cap-0067/to-muxed-id-absent", "variant": "lcm", "column": "js-17.4.0", "level": "L1"}]}`)
	return root
}

func TestPendingMatches(t *testing.T) {
	p, err := LoadPending(pendingRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Files) != 2 || len(p.Entries) != 2 {
		t.Fatalf("%s", p)
	}
	for _, c := range []struct {
		row  report.Row
		want bool
	}{
		{lintRow("l-7", 7, nil), true},
		{lintRow("l-8", 8, nil), false}, // another line
		{func() report.Row { r := lintRow("l-other", 7, nil); r.Target.Version = "666a64d4"; return r }(), false}, // another commit
		{pendingConformRow("c-l1", "js-17.4.0", "L1"), true},
		{pendingConformRow("c-l2", "js-17.4.0", "L2"), false},
		{pendingConformRow("c-col", "js-17.3.0", "L1"), false},
	} {
		if got := p.Matches(&c.row); got != c.want {
			t.Errorf("%s: matches %v, want %v", c.row.RowID, got, c.want)
		}
	}
	var none *Pending
	if r := lintRow("l", 7, nil); none.Matches(&r) {
		t.Error("nil pending matched")
	}
}

// A linter entry may give its site hashed (rule and site), so a public list need not name the file.
func TestPendingHashedSite(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "lint/expected/wallet-backend", lintCommit+".pending.json"),
		`{"schema": "xdrlint.pending/v1", "commit": "`+lintCommit+`", "pending": [{"rule": "XDR201", "site": "`+
			SiteHash("XDR201", "internal/x.go", 7)+`"}]}`)
	p, err := LoadPending(root)
	if err != nil {
		t.Fatal(err)
	}
	if r := lintRow("l-7", 7, nil); !p.Matches(&r) {
		t.Error("the hashed site does not match its row")
	}
	if r := lintRow("l-8", 8, nil); p.Matches(&r) {
		t.Error("the hashed site matches another line")
	}
	if len(SiteHash("a", "b", 1)) != 64 {
		t.Error("SiteHash is not a hex SHA-256")
	}
}

// Mark turns an unexpected row a list names into a pending one, and leaves every other row alone.
func TestPendingMark(t *testing.T) {
	p, err := LoadPending(pendingRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	f := "F-0001"
	expected := lintRow("l-expected", 7, nil)
	expected.Expectation = "expected"
	oracle := lintRow("l-oracle", 7, nil)
	oracle.Target.Kind = "oracle"
	for _, c := range []struct {
		row  report.Row
		want string
	}{
		{lintRow("l-7", 7, nil), report.ExpectationPending},
		{pendingConformRow("c-l1", "js-17.4.0", "L1"), report.ExpectationPending},
		{lintRow("l-8", 8, nil), "unexpected"}, // no list names it
		{lintRow("l-f", 7, &f), "unexpected"},  // it carries a finding
		{expected, "expected"},                 // it is not unexpected
		{oracle, "unexpected"},                 // it needs no finding
	} {
		r := c.row
		if p.Mark(&r); r.Expectation != c.want {
			t.Errorf("%s: %s, want %s", r.RowID, r.Expectation, c.want)
		}
	}
	var none *Pending
	if r := lintRow("l", 7, nil); none.Mark(&r) || r.Expectation != "unexpected" {
		t.Error("nil pending marked a row")
	}
}

// A pending list carries row keys only: a reason, a finding ID or an entry naming no row is refused.
func TestPendingRejectsDescriptions(t *testing.T) {
	for name, body := range map[string]string{
		"reason":   `{"pending": [{"rule": "XDR201", "file": "x.go", "line": 1, "reason": "why"}]}`,
		"finding":  `{"pending": [{"entry": "e", "finding": "F-0001"}]}`,
		"toplevel": `{"note": "x", "pending": []}`,
		"too wide": `{"commit": "abc", "pending": [{"target": "t"}]}`,
		"type":     `{"pending": [{"entry": ["e"]}]}`,
	} {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "findings/pending/x.json"), body)
		if _, err := LoadPending(root); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if p, err := LoadPending(t.TempDir()); err != nil || len(p.Entries) != 0 {
		t.Errorf("no lists: %v %v", p, err)
	}
}

// A row pending finding review passes the development mode and fails the acceptance mode; a failure row no list
// names fails both.
func TestCheckPendingRows(t *testing.T) {
	f := newFixture(t)
	f.report("lint/report.json", false, lintRow("l-7", 7, nil))
	f.report("conform/report.json", false, pendingConformRow("c-l1", "js-17.4.0", "L1"))
	pending, err := LoadPending(pendingRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	check := func(mode string) *Result {
		s, err := Load(f.schema, f.public, "")
		if err != nil {
			t.Fatal(err)
		}
		paths, _ := FindReports(f.reports)
		c := NewChecker(s)
		c.Pending = pending
		for _, p := range paths {
			if err := c.AddReport(p); err != nil {
				t.Fatal(err)
			}
		}
		return c.Finish(mode, true)
	}
	dev := check(Development)
	if !dev.Passed() || dev.PendingRows != 2 || dev.UnlinkedRows != 0 {
		t.Errorf("development: passed=%v %+v", dev.Passed(), dev)
	}
	var out bytes.Buffer
	dev.Print(&out)
	if !strings.Contains(out.String(), "2 pending finding review") {
		t.Errorf("development output:\n%s", out.String())
	}
	acc := check(Acceptance)
	out.Reset()
	acc.Print(&out)
	if acc.Passed() || acc.PendingRows != 2 || !strings.Contains(out.String(), "FAIL pending finding review: rows that need an approved finding: 2") {
		t.Errorf("acceptance: passed=%v\n%s", acc.Passed(), out.String())
	}

	f.report("lint/more.json", false, lintRow("l-8", 8, nil))
	if dev := check(Development); dev.Passed() || dev.UnlinkedRows != 1 {
		t.Errorf("unlisted row: passed=%v %+v", dev.Passed(), dev)
	}
}
