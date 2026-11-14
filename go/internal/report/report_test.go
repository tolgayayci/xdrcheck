package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testHeader() Header {
	return Header{
		Tool:   Tool{Name: "xcc replay", Version: "0.1.0"},
		Corpus: CorpusRef{Version: "30.0.0", ManifestSHA256: strings.Repeat("0", 64), Tier: "curated"},
		Pins:   PinsRef{FileSHA256: strings.Repeat("1", 64)},
		Mode:   Mode{Suite: "selftest", Overlay: false},
	}
}

// testRow returns row i of a synthetic run: a mix of passes, halts with findings and partial drops without.
func testRow(i int) Row {
	r := Row{
		RowID:       fmt.Sprintf("replay:cap-0040/signed-payload-signer-added:testnet:stellar/wallet-backend@%08d:single", i),
		Tool:        "replay",
		Entry:       "cap-0040/signed-payload-signer-added",
		Variant:     "testnet",
		Target:      Target{Name: "stellar/wallet-backend", Version: fmt.Sprintf("%040d", i), Kind: "pipeline"},
		Expectation: "expected",
		Expected:    &Expected{Source: "default", Result: "pass"},
		Caps:        []int{40},
		Replay:      &ReplayResult{Unit: "single", Input: "sep54-dir", Range: &Range{Start: 4437357, End: 4437357}, Class: "pass"},
		Evidence:    json.RawMessage(fmt.Sprintf(`{"exit_code":0,"wall_ms":%d,"delivered":true}`, i)),
	}
	switch i % 3 {
	case 1:
		f := "F-0003"
		r.Replay.Class, r.Replay.Qualifier, r.Failure, r.Finding = "mishandled", "halt", true, &f
	case 2:
		r.Replay.Class, r.Replay.Qualifier, r.Failure, r.Expectation = "dropped", "partial", true, "unexpected"
	}
	return r
}

func heapAlloc() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

const (
	nRows     = 10000
	maxGrowth = 512 << 10 // retaining 9,000 rows would take several MiB
)

func TestTenThousandRowsFlatMemory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	w, err := Create(path, testHeader())
	if err != nil {
		t.Fatal(err)
	}
	var atWrite1000 uint64
	for i := 0; i < nRows; i++ {
		if i == 1000 {
			atWrite1000 = heapAlloc()
		}
		if err := w.Write(testRow(i)); err != nil {
			t.Fatal(err)
		}
	}
	atWriteEnd := heapAlloc()
	wall := 1234.0
	w.SetRun(&Run{ID: "test", WallMS: &wall})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if atWriteEnd > atWrite1000 && atWriteEnd-atWrite1000 > maxGrowth {
		t.Errorf("writer heap grew by %d bytes over 9,000 rows", atWriteEnd-atWrite1000)
	}
	t.Logf("writer heap: %d after 1,000 rows, %d after 10,000", atWrite1000, atWriteEnd)

	// The file is one JSON document.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatal("report is not valid JSON")
	}

	var atRead1000, atReadEnd uint64
	n := 0
	h, s, err := ReadFile(path, func(r *Row) error {
		want := testRow(n)
		if r.RowID != want.RowID || r.Replay.Class != want.Replay.Class || r.Failure != want.Failure {
			return fmt.Errorf("row %d: got %s %s", n, r.RowID, r.Replay.Class)
		}
		n++
		switch n {
		case 1000:
			atRead1000 = heapAlloc()
		case nRows:
			atReadEnd = heapAlloc()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != nRows {
		t.Fatalf("read %d rows", n)
	}
	if atReadEnd > atRead1000 && atReadEnd-atRead1000 > maxGrowth {
		t.Errorf("reader heap grew by %d bytes over 9,000 rows", atReadEnd-atRead1000)
	}
	t.Logf("reader heap: %d after 1,000 rows, %d after 10,000", atRead1000, atReadEnd)
	if h.Tool.Name != "xcc replay" || h.Run == nil || *h.Run.WallMS != wall {
		t.Errorf("header: %+v", h)
	}
	want := Summary{Rows: nRows, Failures: 6666, Unexpected: 3333, FailuresWithoutFinding: 3333,
		ByResult: map[string]int{"pass": 3334, "mishandled·halt": 3333, "dropped·partial": 3333}}
	if fmt.Sprint(*s) != fmt.Sprint(want) {
		t.Errorf("summary %+v, want %+v", *s, want)
	}
}

func TestWriteAllocsPerRowConstant(t *testing.T) {
	w, err := NewWriter(discard{}, testHeader())
	if err != nil {
		t.Fatal(err)
	}
	row := testRow(1)
	allocs := testing.AllocsPerRun(1000, func() {
		if err := w.Write(row); err != nil {
			t.Fatal(err)
		}
	})
	// Encoding a row allocates a fixed handful of objects; nothing is kept per row.
	if allocs > 40 {
		t.Errorf("%.0f allocations per row", allocs)
	}
	t.Logf("%.0f allocations per row", allocs)
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func TestSchemaExamplesRead(t *testing.T) {
	files, _ := filepath.Glob("../../../corpus/schema/examples/report/valid-*.json")
	if len(files) == 0 {
		t.Fatal("no examples")
	}
	for _, f := range files {
		rep, err := ReadAll(f)
		if err != nil {
			t.Error(err)
			continue
		}
		if len(rep.Rows) == 0 {
			t.Errorf("%s: no rows", f)
		}
	}
}

func TestRoundTripSmall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.json")
	w, err := Create(path, testHeader())
	if err != nil {
		t.Fatal(err)
	}
	w.MaxEvidence = 64
	big := testRow(0)
	big.Evidence = json.RawMessage(`{"log":"` + strings.Repeat("x", 200) + `"}`)
	if err := w.Write(big); err != nil {
		t.Fatal(err)
	}
	lint := Row{RowID: "lint:x", Tool: "lint", Target: Target{Name: "stellar/wallet-backend", Version: "e967ce8b", Kind: "pipeline"},
		Failure: true, Expectation: "expected", Lint: &LintResult{Rule: "XDR201", Severity: "error", Location: Location{File: "a.go", Line: 3}, Suppressed: true}}
	if err := w.Write(lint); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	rep, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	var stub map[string]any
	if err := json.Unmarshal(rep.Rows[0].Evidence, &stub); err != nil || stub["truncated"] != true || stub["original_bytes"] != float64(210) || len(stub) != 3 || len(rep.Rows[0].Notes) != 1 {
		t.Errorf("evidence not capped: %s %v", rep.Rows[0].Evidence, rep.Rows[0].Notes)
	}
	// The whole evidence is kept next to the report.
	if side, _ := stub["full_evidence"].(string); side == "" {
		t.Errorf("no side file named: %s", rep.Rows[0].Evidence)
	} else if b, err := os.ReadFile(filepath.Join(filepath.Dir(path), side)); err != nil || string(b) != string(big.Evidence) {
		t.Errorf("side file %s: %q %v", side, b, err)
	}
	if rep.Summary.ByResult["XDR201 suppressed"] != 1 || rep.Summary.FailuresWithoutFinding != 1 {
		t.Errorf("summary %+v", rep.Summary)
	}
}

func TestRejects(t *testing.T) {
	w, _ := NewWriter(discard{}, testHeader())
	bad := testRow(0)
	bad.Replay.Class, bad.Replay.Qualifier, bad.Failure = "mishandled", "refused", true
	if err := w.Write(bad); err == nil {
		t.Error("mishandled·refused accepted")
	}
	bad = testRow(0)
	bad.Failure = true
	if err := w.Write(bad); err == nil {
		t.Error("failing pass accepted")
	}
	bad = testRow(0)
	bad.Conform = &ConformResult{Level: "L0", Outcome: "ok", Verdict: "conform"}
	if err := w.Write(bad); err == nil {
		t.Error("two tool blocks accepted")
	}

	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	gw, _ := Create(good, testHeader())
	gw.Write(testRow(1))
	gw.Close()
	data, _ := os.ReadFile(good)
	cases := map[string]string{
		"unknown row field": strings.Replace(string(data), `"tool":"replay"`, `"tool":"replay","colour":1`, 1),
		"unknown key":       strings.Replace(string(data), `"rows":[`, `"colour":1,"rows":[`, 1),
		"summary mismatch":  strings.Replace(string(data), `"failures":1`, `"failures":2`, 1),
		"truncated":         string(data[:len(data)/2]),
	}
	for name, body := range cases {
		p := filepath.Join(dir, "bad.json")
		os.WriteFile(p, []byte(body), 0o644)
		if _, err := ReadAll(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ReadAll(good); err != nil {
		t.Errorf("good report: %v", err)
	}
}

// Oversized evidence keeps its diffs and missing_or_wrong facts inline in full, with only the other long lists cut;
// the side file holds everything.
func TestOversizedEvidenceKeepsDiffs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.json")
	w, err := Create(path, testHeader())
	if err != nil {
		t.Fatal(err)
	}
	w.MaxEvidence = 4 << 10
	type ref struct {
		Index int `json:"index"`
	}
	var observed []ref
	for i := 0; i < 1000; i++ {
		observed = append(observed, ref{i})
	}
	var diffs []map[string]string
	for i := 0; i < 15; i++ {
		diffs = append(diffs, map[string]string{"field": "detail.delta", "expected": "84208029", "observed": fmt.Sprint(i)})
	}
	ev := map[string]any{"facts": map[string]any{"missing_or_wrong": []any{map[string]any{"label": "balance_changed", "diffs": diffs, "observed": observed}}}}
	b, _ := json.Marshal(ev)
	row := testRow(0)
	row.Evidence = b
	if err := w.Write(row); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	rep, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Rows[0].Evidence
	if len(got) > w.MaxEvidence {
		t.Fatalf("inline evidence %d bytes over the cap", len(got))
	}
	var short struct {
		Truncated    bool   `json:"truncated"`
		FullEvidence string `json:"full_evidence"`
		Facts        struct {
			MissingOrWrong []struct {
				Diffs         []map[string]string `json:"diffs"`
				Observed      []ref               `json:"observed"`
				ObservedTotal int                 `json:"observed_total"`
			} `json:"missing_or_wrong"`
		} `json:"facts"`
	}
	if err := json.Unmarshal(got, &short); err != nil {
		t.Fatal(err)
	}
	f := short.Facts.MissingOrWrong
	if !short.Truncated || len(f) != 1 || len(f[0].Diffs) != 15 || len(f[0].Observed) != keepListed || f[0].ObservedTotal != 1000 {
		t.Errorf("shortened copy: %s", got)
	}
	if side, err := os.ReadFile(filepath.Join(filepath.Dir(path), short.FullEvidence)); err != nil || !bytes.Equal(side, b) {
		t.Errorf("side file %q: %v", short.FullEvidence, err)
	}
}
