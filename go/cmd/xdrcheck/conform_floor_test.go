package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
)

// xdrcheck conform check fails a run in which a required column judged no cell (every cell n_a), and passes the same
// run once that column judged one; a non-required column with nothing judged does not matter.
func TestConformCheckJudgedFloor(t *testing.T) {
	write := func(cells []verdict.Cell) string {
		m := verdict.Matrix{Schema: verdict.MatrixSchema, Summary: map[string]int{}, Entries: []verdict.MatrixEntry{},
			CrossSDK: []verdict.CrossSDK{}, NotExercised: []verdict.NotExercised{}, Infrastructure: []string{},
			Columns: []verdict.MatrixColumn{
				{ID: "go@v0.9.0", SDK: "go", Kind: "sdk", Role: "required", Required: true},
				{ID: "js@17.4.0", SDK: "js", Kind: "sdk", Role: "required", Required: true},
				{ID: "go@v0.9.0:views", SDK: "go", Kind: "sdk", Role: "extra"},
			},
			Cells: cells}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "matrix.json")
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cell := func(col, v string) verdict.Cell {
		return verdict.Cell{Entry: "x/a", Level: "L0", Column: col, Verdict: v, Check: v, ExpectedVerdict: "conform"}
	}
	empty := filepath.Join(t.TempDir(), "pending.json")
	os.WriteFile(empty, []byte(`{"pending": []}`), 0o644)

	starved := write([]verdict.Cell{cell("go@v0.9.0", "conform"), cell("js@17.4.0", "n_a"), cell("go@v0.9.0:views", "n_a")})
	if code := conformCheck([]string{"--pending", empty, starved}); code != 1 {
		t.Errorf("a required column with no judged cell: exit %d, want 1", code)
	}
	fed := write([]verdict.Cell{cell("go@v0.9.0", "conform"), cell("js@17.4.0", "conform"), cell("go@v0.9.0:views", "n_a")})
	if code := conformCheck([]string{"--pending", empty, fed}); code != 0 {
		t.Errorf("every required column judged a cell: exit %d, want 0", code)
	}
	if code := conformCheck([]string{"--pending", empty, "--min-judged", "2", fed}); code != 1 {
		t.Errorf("--min-judged 2 with one judged cell per column: exit %d, want 1", code)
	}
	verdict.MinJudged = 1
}
