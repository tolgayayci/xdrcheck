package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every kind a rig writes for the judge, including those a scope file compares with another fact family, goes
// to rows.jsonl sorted by ledger; the rest to rows-other.jsonl.
func TestMergeRowsRoutesJudgedKinds(t *testing.T) {
	dir := t.TempDir()
	shard := filepath.Join(dir, "shard-0")
	if err := os.MkdirAll(shard, 0o755); err != nil {
		t.Fatal(err)
	}
	in := strings.Join([]string{
		`{"kind":"effect_balance_change","ledger":3}`,
		`{"kind":"op_token_event","ledger":2}`,
		`{"kind":"entry_change","ledger":1}`,
		`{"kind":"state_change","ledger":1}`,
		`{"kind":"effect","ledger":1}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(shard, "rows.jsonl"), []byte(in), 0o644); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	if err := mergeRows(dir, 1, counts); err != nil {
		t.Fatal(err)
	}
	rows, _ := os.ReadFile(filepath.Join(dir, "rows.jsonl"))
	want := `{"kind":"entry_change","ledger":1}` + "\n" + `{"kind":"op_token_event","ledger":2}` + "\n" + `{"kind":"effect_balance_change","ledger":3}` + "\n"
	if string(rows) != want {
		t.Errorf("rows.jsonl:\n%s", rows)
	}
	if counts["lines:rows-other.jsonl"] != 2 {
		t.Errorf("other: %v", counts)
	}
}
