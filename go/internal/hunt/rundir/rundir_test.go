package rundir

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The embedded schemas are a copy of the repository's schemas/ directory.
func TestSchemasMatchRepository(t *testing.T) {
	files, err := SchemaFiles()
	if err != nil {
		t.Fatal(err)
	}
	repo, _ := filepath.Glob("../../../../schemas/*.schema.json")
	if len(repo) != len(files) {
		t.Fatalf("schemas/ has %d files, the embedded copy %d: copy schemas/*.schema.json into go/internal/hunt/rundir/schemas/", len(repo), len(files))
	}
	for _, p := range repo {
		b, _ := os.ReadFile(p)
		if !bytes.Equal(b, files[filepath.Base(p)]) {
			t.Errorf("%s differs from the embedded copy", p)
		}
		if _, err := Compile(filepath.Base(p)); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

func ip(n int) *int { return &n }

func sampleRun(t *testing.T, overlay string) *Run {
	d, err := LoadDispositions(overlay)
	if err != nil {
		t.Fatal(err)
	}
	rows := []Verdict{
		{Ledger: 10, Tx: ip(1), Check: "tx-parse", Class: "Error:x", Verdict: "fail", Evidence: map[string]any{"detail": "boom"}},
		{Ledger: 10, Tx: ip(2), Check: "tx-parse", Class: "Error:x", Verdict: "fail"},
		{Ledger: 11, Tx: nil, Check: "codec", Class: "re-encode-differs", Verdict: "fail"},
		{Ledger: 12, Tx: ip(0), Op: ip(1), Check: "helper-error", Class: "GetContractEvents:error:not a soroban transaction", Verdict: "fail"},
	}
	r := &Run{Manifest: Manifest{Tool: ToolInfo{Name: "x", Version: "1"}, Target: "go", Version: VersionInfo{Requested: "v1", Resolved: "v1"},
		Network: "pubnet", Command: []string{"x"}, Host: ThisHost(), Started: "2026-11-17T00:00:00Z", Finished: "2026-11-17T00:00:01Z"}}
	r.Verdicts = rows
	r.Clusters = Clusters{Target: "go", Version: "v1", Clusters: Group("go", rows, d, nil)}
	r.Summary.Status = StatusComplete
	Summarise(&r.Summary, rows, r.Clusters.Clusters, map[string]int64{"tx-parse": 5})
	return r
}

func TestRunDirectoryValidates(t *testing.T) {
	dir := t.TempDir()
	d, err := Create(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	r := sampleRun(t, "")
	if err := d.Save(r); err != nil {
		t.Fatal(err)
	}
	if bad := ValidateDir(dir); len(bad) > 0 {
		t.Fatal(bad)
	}
	if len(r.Clusters.Clusters) != 3 || r.Clusters.Clusters[0].Key != "tx-parse|Error:x" || r.Clusters.Clusters[0].Txs != 2 {
		t.Fatalf("clusters: %+v", r.Clusters.Clusters)
	}
	last := r.Clusters.Clusters[len(r.Clusters.Clusters)-1]
	if last.Disposition != "expected-refusal" || last.Finding != nil {
		t.Fatalf("public disposition: %+v", last)
	}
	// a broken count is caught
	os.WriteFile(filepath.Join(dir, VerdictsFile), []byte(`{"ledger":1,"tx":null,"op":null,"check":"codec","class":"c","verdict":"fail"}`+"\n"), 0o644)
	if bad := ValidateDir(dir); len(bad) == 0 || !strings.Contains(strings.Join(bad, " "), "counts") {
		t.Fatalf("want a count mismatch, got %v", bad)
	}
	// a malformed row is caught
	os.WriteFile(filepath.Join(dir, VerdictsFile), []byte(`{"ledger":0,"check":"Bad Check","verdict":"maybe"}`+"\n"), 0o644)
	if bad := ValidateDir(dir); len(bad) == 0 {
		t.Fatal("want schema errors")
	}
}

func TestOnlyOverlayNamesFindings(t *testing.T) {
	ov := filepath.Join(t.TempDir(), "d.tsv")
	os.WriteFile(ov, []byte("go\ttx-parse\tError:x\tknown\tnote\tF-0001\n"), 0o644)
	r := sampleRun(t, ov)
	c := r.Clusters.Clusters[0]
	if c.Disposition != "known" || c.Finding == nil || *c.Finding != "F-0001" {
		t.Fatalf("overlay: %+v", c)
	}
	d := &Dispositions{}
	if err := d.parse("go\ta\tb\tknown\tnote\tF-0001\n", "public", false); err == nil {
		t.Fatal("a public table must not name a finding")
	}
}
