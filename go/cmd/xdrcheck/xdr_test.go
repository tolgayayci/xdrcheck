package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/xdrdef"
)

const xdrFixtures = "../../internal/xdrdef/testdata/diff"

func runXDR(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := xdrMain(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestXDRDiffCommand(t *testing.T) {
	base, head := filepath.Join(xdrFixtures, "base"), filepath.Join(xdrFixtures, "head")
	jsonFile := filepath.Join(t.TempDir(), "d.json")
	code, out, errs := runXDR("diff", base, head, "--exit-code", "--json", jsonFile)
	if code != 1 || !strings.Contains(out, "### CAP-0088") {
		t.Fatalf("diff --exit-code: %d\n%s%s", code, out, errs)
	}
	var r xdrdef.Report
	b, _ := os.ReadFile(jsonFile)
	if err := json.Unmarshal(b, &r); err != nil || r.Schema != xdrdef.DiffSchema || len(r.Changes) == 0 {
		t.Fatalf("--json: %v", err)
	}
	code, out, _ = runXDR("diff", "--format", "json", "--head-features", "none", "--base-features", "none", head, head)
	if code != 0 || !strings.Contains(out, `"changes": []`) {
		t.Errorf("self diff: %d %s", code, out)
	}
	for _, args := range [][]string{{"diff", base}, {"diff", base, head, "--format", "yaml"}, {"diff", base, "/nonexistent-dir.json"}, {"nope"}, {}} {
		if code, _, _ := runXDR(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

// TestXDRCeilingsCheck is the drift check `make test` runs: the drivers' ceiling blocks, label included,
// agree with the pinned definitions.
func TestXDRCeilingsCheck(t *testing.T) {
	code, out, errs := runXDR("ceilings", "--check")
	if code != 0 {
		t.Fatalf("xdrcheck xdr ceilings --check: exit %d\n%s%s", code, out, errs)
	}
	if code, _, _ := runXDR("ceilings"); code != 2 {
		t.Errorf("ceilings without --check or --write must exit 2")
	}
}

func TestXDRCandidatesCommand(t *testing.T) {
	dir := t.TempDir()
	diff := filepath.Join(dir, "d.json")
	if code, _, errs := runXDR("diff", filepath.Join(xdrFixtures, "base"), filepath.Join(xdrFixtures, "head"), "--json", diff); code != 0 {
		t.Fatal(errs)
	}
	corpus := filepath.Join(dir, "corpus")
	os.MkdirAll(corpus, 0o755)
	for _, f := range []string{"caps.toml", "arms.toml", "plan.json"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "corpus", f))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(corpus, f), b, 0o644)
	}
	before, _ := os.ReadFile(filepath.Join(corpus, "plan.json"))
	code, out, errs := runXDR("candidates", "--corpus", corpus, diff)
	if code != 0 || !strings.Contains(out, "would add") {
		t.Fatalf("dry run: %d %s %s", code, out, errs)
	}
	if after, _ := os.ReadFile(filepath.Join(corpus, "plan.json")); !bytes.Equal(before, after) {
		t.Fatalf("a dry run wrote plan.json")
	}
	code, out, errs = runXDR("candidates", "--corpus", corpus, "--write", diff)
	if code != 0 || !strings.Contains(out, "plan.json: cap-0088/ext-v1") {
		t.Fatalf("--write: %d %s %s", code, out, errs)
	}
	var rows []map[string]any
	b, _ := os.ReadFile(filepath.Join(corpus, "plan.json"))
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatalf("plan.json after --write: %v", err)
	}
	code, out, _ = runXDR("candidates", "--corpus", corpus, "--write", diff)
	if code != 0 || !strings.Contains(out, "added 0 rows") {
		t.Errorf("second --write: %s", out)
	}
}
