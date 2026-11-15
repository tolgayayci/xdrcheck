package findings

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/pins"
)

// The repository declares a required run set; it holds the full-corpus replay on both inputs, every run is in
// findings-linked, and a tree without the declaration has none.
func TestRequiredRunsOfRepository(t *testing.T) {
	runs, err := RequiredRuns("../../..")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range runs {
		if !r.Has("findings-linked") {
			t.Errorf("%s is not in findings-linked", r.Report)
		}
		if seen[r.Report] {
			t.Errorf("%s listed twice", r.Report)
		}
		seen[r.Report] = true
	}
	for _, in := range ReplayInputs {
		if !seen[ReplayFullDir+"/wallet-backend-"+in+"/report.json"] {
			t.Errorf("the full-corpus replay on %s is not required", in)
		}
	}
	pinned, err := pins.Load("../../../pins.toml")
	if err != nil {
		t.Fatal(err)
	}
	etl := false
	for _, r := range runs {
		if r.Make == "replay-etl-known" {
			etl = true
			if r.Tool != "replay" || r.Target != StellarETLTarget || r.Version != pinned.Pipelines.StellarETL.Commit || r.Report != ReplayETLKnownDir+"/stellar-etl-"+r.Version+"/report.json" {
				t.Errorf("stellar-etl replay run %+v: not the pinned commit's report", r)
			}
		}
	}
	if !etl {
		t.Error("the stellar-etl replay of the declared divergences is not required")
	}
	if n := len(RunsFor(runs, "replay-regression")); n == 0 {
		t.Error("no replay-regression run")
	}
	if r, err := RequiredRuns(t.TempDir()); err != nil || r != nil {
		t.Errorf("no declaration: %v %v", r, err)
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, RequiredRunsFile), `{"targets": ["verify-nothing"]}`)
	if _, err := RequiredRuns(root); err == nil {
		t.Error("an unknown target was accepted")
	}
}

// The split declaration: the single file, then required-runs.d/*.json in name order, give the targets in that
// order; a target declared twice, an empty file and an unknown key are refused.
func TestRequiredTargetsSplit(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, RequiredRunsFile), `{"targets": ["a"]}`)
	writeFile(t, filepath.Join(root, RequiredRunsDir, "20-y.json"), `{"targets": ["c"]}`)
	writeFile(t, filepath.Join(root, RequiredRunsDir, "10-x.json"), `{"targets": ["b"]}`)
	writeFile(t, filepath.Join(root, RequiredRunsDir, "README"), `not json, not read`)
	got, ok, err := requiredTargets(root)
	if err != nil || !ok || strings.Join(got, ",") != "a,b,c" {
		t.Errorf("targets %v %v %v", got, ok, err)
	}
	only := t.TempDir()
	writeFile(t, filepath.Join(only, RequiredRunsDir, "10-x.json"), `{"targets": ["b"]}`)
	if got, ok, err := requiredTargets(only); err != nil || !ok || len(got) != 1 {
		t.Errorf("directory only: %v %v %v", got, ok, err)
	}
	for want, body := range map[string]string{
		"already declared": `{"targets": ["b"]}`,
		"no targets":       `{"targets": []}`,
		"unknown field":    `{"targets": ["d"], "extra": 1}`,
	} {
		writeFile(t, filepath.Join(root, RequiredRunsDir, "30-z.json"), body)
		if _, _, err := requiredTargets(root); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}
}

// governanceCheck runs the check over the reports with the pending entries and required runs given.
func governanceCheck(t *testing.T, f *fixture, p *Pending, mode string, now time.Time) *Result {
	t.Helper()
	s, err := Load(f.schema, f.public, "")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := FindReports(f.reports)
	if err != nil {
		t.Fatal(err)
	}
	c := NewChecker(s)
	c.Pending, c.Now = p, now
	for _, path := range paths {
		if err := c.AddReport(path); err != nil {
			t.Fatal(err)
		}
	}
	return c.Finish(mode, true)
}

func day(s string) time.Time {
	t, err := time.Parse(sinceLayout, s)
	if err != nil {
		panic(err)
	}
	return t
}

// An entry that accounts for no failure row of its required runs is stale and fails both modes; an entry whose
// runs were not all checked is not judged, and a missing run fails the acceptance mode only.
func TestPendingStaleAndMissingRuns(t *testing.T) {
	const commit = "2a0a84ea12523b6c92e278c0c84b443041240095"
	runs := []RequiredRun{
		{Report: "replay-full/wallet-backend-sep54-s3/report.json", Make: "replay-full", Checks: []string{"findings-linked"}, Tool: "replay", Target: WalletBackendTarget, Version: commit},
		{Report: "lint-wallet-backend/abc.json", Make: "lint-wallet-backend", Checks: []string{"findings-linked"}, Tool: "lint", Version: "abc"},
	}
	now := day("2026-11-13")
	pending := func(entries ...PendingEntry) *Pending {
		p := &Pending{Required: runs}
		for i, e := range entries {
			p.Entries = append(p.Entries, e)
			p.Sources = append(p.Sources, PendingSource{File: "findings/pending/replay.json", Index: i, Since: now})
		}
		return p
	}
	held := PendingEntry{"tool": "replay", "target": WalletBackendTarget, "version": commit, "entry": "cap-0040/signed-payload-signer-added"}
	gone := PendingEntry{"tool": "replay", "target": WalletBackendTarget, "version": commit, "entry": "cap-0023/claimants-max-10"}
	lint := PendingEntry{"version": "abc", "rule": "XDR201", "file": "x.go", "line": "1"}

	f := newFixture(t)
	f.report("replay-full/wallet-backend-sep54-s3/report.json", false, replayRow("r-fail", true, nil, "pipeline"))
	res := governanceCheck(t, f, pending(held, gone, lint), Development, now)
	if len(res.StalePending) != 1 || !strings.Contains(res.StalePending[0], "claimants-max-10") || res.UncheckedPending != 1 {
		t.Errorf("stale %v, unchecked %d", res.StalePending, res.UncheckedPending)
	}
	if res.Passed() || len(res.MissingRuns) != 1 {
		t.Errorf("development: passed=%v missing %v", res.Passed(), res.MissingRuns)
	}
	if res := governanceCheck(t, f, pending(held), Development, now); !res.Passed() {
		t.Errorf("development with a held entry and a missing run: %+v", res)
	}
	acc := governanceCheck(t, f, pending(held), Acceptance, now)
	if acc.Passed() || len(acc.MissingRuns) != 1 || !strings.Contains(acc.MissingRuns[0], "lint-wallet-backend/abc.json (make lint-wallet-backend)") {
		t.Errorf("acceptance with a missing run: missing %v", acc.MissingRuns)
	}

	// A row of another report (not a required run) keeps no entry alive.
	g := newFixture(t)
	g.report("replay-full/wallet-backend-sep54-s3/report.json", false, replayRow("r-pass", false, nil, "pipeline"))
	g.report("scratch/report.json", false, replayRow("r-fail", true, nil, "pipeline"))
	if res := governanceCheck(t, g, pending(held), Development, now); len(res.StalePending) != 1 {
		t.Errorf("held only by a report outside the set: stale %v", res.StalePending)
	}

	// An entry no required run can hold is stale whatever was checked.
	other := PendingEntry{"tool": "conform", "entry": "e", "column": "js@17.4.0", "level": "L4"}
	if res := governanceCheck(t, f, pending(held, other), Development, now); len(res.StalePending) != 1 || !strings.Contains(res.StalePending[0], "no required run") {
		t.Errorf("unscoped entry: stale %v", res.StalePending)
	}

	// Without a required run set nothing is judged stale or missing.
	p := pending(gone)
	p.Required = nil
	if res := governanceCheck(t, f, p, Acceptance, now); len(res.StalePending)+len(res.MissingRuns) != 0 {
		t.Errorf("no required set: %+v", res)
	}
}

// since: read at the top level or per entry; an entry older than the maximum age or undated fails the
// acceptance mode only, one dated in the future fails both.
func TestPendingSince(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "findings/pending/replay.json"), `{"since": "2026-01-02", "tool": "replay", "pending": [
		{"entry": "a"}, {"entry": "b", "since": "2026-11-01"}, {"entry": "c", "since": "2027-01-01"}]}`)
	writeFile(t, filepath.Join(root, "findings/pending/other.json"), `{"pending": [{"entry": "d"}]}`)
	p, err := LoadPending(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 4 || p.Required != nil {
		t.Fatalf("%s, required %v", p, p.Required)
	}
	for i, e := range p.Entries {
		if e["since"] != "" {
			t.Errorf("entry %d: since is a row key: %v", i, e)
		}
	}
	f := newFixture(t)
	f.report("x/report.json", false, replayRow("r-pass", false, nil, "pipeline"))
	dev := governanceCheck(t, f, p, Development, day("2026-11-13"))
	if len(dev.ExpiredPending) != 1 || !strings.Contains(dev.ExpiredPending[0], "entry=a") ||
		len(dev.UndatedPending) != 1 || len(dev.FuturePending) != 1 || dev.Passed() {
		t.Errorf("development: expired %v undated %v future %v", dev.ExpiredPending, dev.UndatedPending, dev.FuturePending)
	}
	p.Entries, p.Sources = p.Entries[:2], p.Sources[:2] // a and b: no future date
	if dev := governanceCheck(t, f, p, Development, day("2026-11-13")); !dev.Passed() {
		t.Errorf("development with an expired entry: %+v", dev)
	}
	if acc := governanceCheck(t, f, p, Acceptance, day("2026-11-13")); acc.Passed() || len(acc.ExpiredPending) != 1 {
		t.Errorf("acceptance with an expired entry: %+v", acc)
	}
	if acc := governanceCheck(t, f, p, Acceptance, day("2026-03-01")); len(acc.ExpiredPending) != 0 {
		t.Errorf("within the maximum age: %v", acc.ExpiredPending)
	}

	for name, body := range map[string]string{
		"bad date":  `{"pending": [{"entry": "e", "since": "13/11/2026"}]}`,
		"number":    `{"pending": [{"entry": "e", "since": 20261113}]}`,
		"top level": `{"since": "2026-13-01", "pending": [{"entry": "e"}]}`,
	} {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "findings/pending/x.json"), body)
		if _, err := LoadPending(root); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A pending entry may not cover a cell `xdrcheck conform sdk-regression` asserts.
func TestPendingRefusesSDKRegressionCells(t *testing.T) {
	for name, c := range map[string]struct {
		body string
		ok   bool
	}{
		"asserted cell":   {`{"pending": [{"entry": "classic/api-offer-id-encoding.id-negative", "variant": "", "column": "js@17.3.0", "level": "L4"}]}`, false},
		"whole entry":     {`{"pending": [{"entry": "classic/api-offer-id-encoding.id-negative"}]}`, false},
		"other column":    {`{"pending": [{"entry": "classic/api-offer-id-encoding.id-negative", "column": "python@17.0.0", "level": "L4"}]}`, true},
		"other level":     {`{"pending": [{"entry": "classic/api-offer-id-encoding.id-negative", "column": "js@17.3.0", "level": "L3"}]}`, true},
		"replay of entry": {`{"pending": [{"tool": "replay", "entry": "classic/api-offer-id-encoding.id-negative"}]}`, true},
	} {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "findings/pending/x.json"), c.body)
		_, err := LoadPending(root)
		if (err == nil) != c.ok {
			t.Errorf("%s: err %v, want ok=%v", name, err, c.ok)
		}
	}
}

// The committed lists load, and none of their entries is stale against the repository's own required set by
// construction of scope: every entry is held by at least one required run.
func TestCommittedPendingListsLoad(t *testing.T) {
	p, err := LoadPending("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range p.Entries {
		held := false
		for _, r := range p.Required {
			held = held || inScope(e, r)
		}
		if !held {
			t.Errorf("%s: no required run can hold it", p.Describe(i))
		}
	}
	if m, _ := filepath.Glob("../../../" + RequiredRunsDir + "/*.json"); len(m) == 0 {
		t.Error("no required-runs.d declaration")
	}
}
