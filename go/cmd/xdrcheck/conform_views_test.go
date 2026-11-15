package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	conformreport "github.com/tolgayayci/xdrcheck/go/internal/conform/report"
	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
)

// writeViewsMatrix writes a small synthetic matrix into dir: one pinned column that decodes the Protocol 30
// entry and one that refuses it as beyond its schema.
func writeViewsMatrix(t *testing.T, dir string) string {
	t.Helper()
	m := verdict.Matrix{Schema: verdict.MatrixSchema, Summary: map[string]int{},
		Columns: []verdict.MatrixColumn{
			{ID: "go@v0.9.0", SDK: "go", Version: "v0.9.0", Kind: "sdk"},
			{ID: "go@v0.7.1", SDK: "go", Version: "v0.7.1", Kind: "sdk"},
		},
		Entries: []verdict.MatrixEntry{{ID: "fixture/p30", Kind: "ledger", Caps: []int{88}, ProtocolIntroduced: 30, Flags: []string{"depth"}}},
		Cells: []verdict.Cell{
			{Entry: "fixture/p30", Column: "go@v0.9.0", Level: "L0", Outcome: "ok", Verdict: "conform", Check: "conform"},
			{Entry: "fixture/p30", Column: "go@v0.7.1", Level: "L0", Outcome: "reject", Verdict: "n_a", Check: "n_a", OutOfReach: true},
		},
	}
	m.Corpus.Version = "0.0.0-test"
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, verdict.MatrixFile)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConformReadinessCommand(t *testing.T) {
	dir := t.TempDir()
	writeViewsMatrix(t, dir)
	if code := conformReadiness([]string{"--protocol", "30", "--report", dir}); code != 0 {
		t.Fatalf("readiness: exit %d", code)
	}
	var r conformreport.Readiness
	b, err := os.ReadFile(filepath.Join(dir, conformreport.ReadinessJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, row := range r.Rows {
		states[row.Column] = row.Cells["P30"].State
	}
	if states["go@v0.9.0"] != conformreport.StateFull || states["go@v0.7.1"] != conformreport.StateRefuses {
		t.Errorf("states %v", states)
	}
	// Every column of the repository's sets file is a row, run or not.
	if len(r.Rows) <= 2 {
		t.Errorf("rows %d: the pinned columns of drivers/sets.toml are missing", len(r.Rows))
	}
	md, _ := os.ReadFile(filepath.Join(dir, conformreport.ReadinessMarkdown))
	if !strings.Contains(string(md), "| `go@v0.7.1` | refuses new arms |") {
		t.Errorf("readiness.md:\n%s", md)
	}
	if code := conformReadiness([]string{"--protocol", "30", filepath.Join(dir, "missing.json")}); code != 2 {
		t.Errorf("a missing matrix: exit %d", code)
	}
}

func TestConformScoreboardCommand(t *testing.T) {
	dir := t.TempDir()
	writeViewsMatrix(t, dir)
	empty := t.TempDir()
	if code := conformScoreboard([]string{"--report", dir, "--findings", empty}); code != 0 {
		t.Fatalf("scoreboard: exit %d", code)
	}
	page, err := os.ReadFile(filepath.Join(dir, conformreport.ScoreboardHTML))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), "<code>go@v0.9.0</code>") || !strings.Contains(string(page), "None listed.") {
		t.Errorf("scoreboard.html:\n%s", page)
	}

	// The repository's own findings: only public, filed records with an upstream URL are listed.
	if code := conformScoreboard([]string{"--report", dir}); code != 0 {
		t.Fatalf("scoreboard with the repository's findings: exit %d", code)
	}
	var s conformreport.Scoreboard
	b, _ := os.ReadFile(filepath.Join(dir, conformreport.ScoreboardJSON))
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	for _, bug := range s.Bugs {
		if !strings.HasPrefix(bug.URL, "https://") {
			t.Errorf("listed without an upstream URL: %+v", bug)
		}
	}
	if code := conformScoreboard([]string{"--matrix", filepath.Join(dir, verdict.MatrixFile)}); code != 2 {
		t.Errorf("without --report: exit %d", code)
	}
}
