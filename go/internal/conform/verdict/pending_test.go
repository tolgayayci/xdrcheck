package verdict

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckPending(t *testing.T) {
	cell := func(entry, variant, column, verdict, check string) Cell {
		return Cell{Entry: entry, Variant: variant, Level: "L4", Column: column, Verdict: verdict, Check: check, ExpectedVerdict: "conform"}
	}
	m := &Matrix{Cells: []Cell{
		cell("x/a", "", "python@17.0.1", "accepts_invalid", "undeclared"),     // a finding lists its row
		cell("x/b", "", "java@6.0.0", "accepts_invalid", "undeclared"),        // in the pending list
		cell("x/c", "", "java@6.0.0", "diverge", "undeclared"),                // nobody accounts for it
		cell("x/d", "", "js@17.2.0", "conform", "unexpected-conform"),         // never pending
		cell("x/e", "", "js@17.4.0", "conform", "conform"),                    // a stale item points here
		cell("x/f", "testnet", "java@6.0.0", "accepts_invalid", "undeclared"), // listed under another variant
	}}
	rows := PendingRows(map[string]FindingRef{"F-5001": {ID: "F-5001", State: "candidate", Overlay: true}},
		map[string][]string{"F-5001": {"conform:x/a:-:python@17.0.1:L4"}})
	pending := []PendingCell{
		{Entry: "x/b", Variant: "-", Column: "java@6.0.0", Level: "L4"},
		{Entry: "x/e", Variant: "", Column: "js@17.4.0", Level: "L4"},
		{Entry: "x/f", Variant: "pubnet", Column: "java@6.0.0", Level: "L4"},
		{Entry: "x/z", Variant: "", Column: "js@16.3.0", Level: "L4"}, // column not in this run
	}
	dev := m.Check(ModeDevelopment, rows, pending)
	status := map[string]string{}
	for _, c := range append(append([]CheckedCell{}, dev.Failing...), dev.Pending...) {
		status[c.Entry] = c.Status
	}
	want := map[string]string{"x/a": "pending-finding", "x/b": "pending-review", "x/c": "fail", "x/d": "fail", "x/f": "fail"}
	for k, v := range want {
		if status[k] != v {
			t.Errorf("%s: %s, want %s", k, status[k], v)
		}
	}
	if len(dev.Failing) != 3 || len(dev.Pending) != 2 || len(dev.Stale) != 1 || dev.Stale[0].Entry != "x/e" || dev.Passed() {
		t.Errorf("development: %d failing, %d pending, stale %v", len(dev.Failing), len(dev.Pending), dev.Stale)
	}
	acc := m.Check(ModeAcceptance, rows, pending)
	if len(acc.Failing) != 5 || len(acc.Pending) != 0 {
		t.Errorf("acceptance: %d failing, %d pending", len(acc.Failing), len(acc.Pending))
	}
	if bare := m.Check(ModeDevelopment, nil, nil); len(bare.Failing) != 5 || !(&CheckResult{}).Passed() {
		t.Errorf("no findings, no list: %d failing", len(bare.Failing))
	}
}

func TestReadPending(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "conformance.json")
	if l, err := ReadPending(p); err != nil || l != nil {
		t.Errorf("missing file: %v %v", l, err)
	}
	os.WriteFile(p, []byte(`{"pending":[{"entry":"x/a","variant":"","column":"python@17.0.1","level":"L4"}]}`), 0o644)
	if l, err := ReadPending(p); err != nil || len(l) != 1 || l[0].Column != "python@17.0.1" {
		t.Errorf("%v %v", l, err)
	}
	os.WriteFile(p, []byte(`{"since":"2026-11-13","pending":[{"entry":"x/a","variant":"","column":"python@17.0.1","level":"L4"},
		{"entry":"x/b","variant":"","column":"python@17.0.1","level":"L4","since":"2026-11-01"}]}`), 0o644)
	if l, err := ReadPending(p); err != nil || len(l) != 2 || l[0].Since != "2026-11-13" || l[1].Since != "2026-11-01" {
		t.Errorf("since: %v %v", l, err)
	}
	for _, bad := range []string{
		`{"pending":[{"entry":"x/a","variant":"","column":"python@17.0.1","level":"L4","since":"13/11/2026"}]}`,
		`{"pending":[{"entry":"x/a","variant":"","column":"python@17.0.1","level":"L4","reason":"a description"}]}`,
		`{"pending":[{"entry":"x/a","variant":"","column":"","level":"L4"}]}`,
		`{"pending":[{"entry":"x/a"}],"note":"x"}`,
	} {
		os.WriteFile(p, []byte(bad), 0o644)
		if _, err := ReadPending(p); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
