package findings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// A check over a required run's tally, with the report itself withheld, gives the same result as a check over the
// report: the same counts, the same records referred to (no false orphan), the same pending entries held (no
// false stale entry), and the run counted as checked. The tally names no row.
func TestTallyStandsInForWithheldReport(t *testing.T) {
	const commit = "2a0a84ea12523b6c92e278c0c84b443041240095"
	const rel = "replay-full/wallet-backend-sep54-s3/report.json"
	runs := []RequiredRun{{Report: rel, Make: "replay-full", Checks: []string{"findings-linked"}, Tool: "replay", Target: WalletBackendTarget, Version: commit}}
	now := day("2026-11-13")
	held := PendingEntry{"tool": "replay", "target": WalletBackendTarget, "version": commit, "entry": "cap-0040/signed-payload-signer-added"}
	p := &Pending{Required: runs, Entries: []PendingEntry{held},
		Sources: []PendingSource{{File: "findings/pending/replay.json", Index: 0, Since: now}}}

	f := newFixture(t)
	f.record(recordIn(t, "F-0001", "filed"), false)
	f.record(recordIn(t, "F-0002", "filed"), false)
	pend := replayRow("r-pending", true, nil, "pipeline")
	pend.Variant = "pending-variant"
	f.report(rel, false,
		replayRow("r-linked", true, str("F-0001"), "pipeline"),
		pend,
		replayRow("r-pass", false, nil, "pipeline"))
	f.report("other/report.json", false, replayRow("r-other", true, str("F-0002"), "pipeline"))

	check := func(mode string, tallies map[string]*ReportTally) *Result {
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
		for _, tl := range tallies {
			if err := c.AddTally(tl); err != nil {
				t.Fatal(err)
			}
		}
		return c.Finish(mode, true)
	}

	s, err := Load(f.schema, f.public, "")
	if err != nil {
		t.Fatal(err)
	}
	c := NewChecker(s)
	c.Pending = p
	if _, err := c.WriteTallies(f.reports, "replay-full", nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(f.reports, "replay-full"+TallySuffix))
	if err != nil {
		t.Fatal(err)
	}
	for _, rowID := range []string{"r-linked", "r-pending", "r-pass", "pending-variant"} {
		if strings.Contains(string(data), rowID) {
			t.Errorf("the tally names row data %q", rowID)
		}
	}

	for _, mode := range []string{Development, Acceptance} {
		want := check(mode, nil)
		if err := os.Remove(filepath.Join(f.reports, filepath.FromSlash(rel))); err != nil {
			t.Fatal(err)
		}
		tallies, err := ReadTallies(f.reports)
		if err != nil {
			t.Fatal(err)
		}
		got := check(mode, tallies)
		if len(got.MissingRuns) != 0 || len(got.StalePending) != 0 || got.UncheckedPending != 0 {
			t.Errorf("%s: missing %v stale %v unchecked %d", mode, got.MissingRuns, got.StalePending, got.UncheckedPending)
		}
		for _, r := range []*Result{want, got} {
			r.Reports, r.PendingExamples, r.UnlinkedExamples, r.DanglingExamples = nil, nil, nil, nil
		}
		if !reflect.DeepEqual(want, got) {
			a, _ := json.Marshal(want)
			b, _ := json.Marshal(got)
			t.Errorf("%s: report and tally disagree:\n report %s\n tally  %s", mode, a, b)
		}
		if want.LinkedRows != 2 || want.PendingRows != 1 || len(want.Orphans) != 0 {
			t.Errorf("%s: fixture not as designed: %+v", mode, want)
		}
		// Put the report back for the next mode.
		f.report(rel, false,
			replayRow("r-linked", true, str("F-0001"), "pipeline"),
			pend,
			replayRow("r-pass", false, nil, "pipeline"))
	}

	// A tally of a run outside the set, of an overlay report without the overlay, or naming an unknown pending
	// entry is refused.
	for name, tl := range map[string]*ReportTally{
		"not required":    {Report: "scratch/report.json"},
		"overlay":         {Report: rel, Overlay: true},
		"unknown pending": {Report: rel, PendingHits: []PendingHit{{List: "findings/pending/replay.json", Index: 7, Rows: 1}}},
	} {
		c := NewChecker(s)
		c.Pending = p
		if err := c.AddTally(tl); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// PendingOnly separates an acceptance check that fails only on rows awaiting finding review from every other
// failure, and from a check that passed or ran in development mode.
func TestPendingOnly(t *testing.T) {
	const commit = "2a0a84ea12523b6c92e278c0c84b443041240095"
	const rel = "replay-full/wallet-backend-sep54-s3/report.json"
	runs := []RequiredRun{{Report: rel, Make: "replay-full", Checks: []string{"findings-linked"}, Tool: "replay", Target: WalletBackendTarget, Version: commit}}
	now := day("2026-11-13")
	entry := func(e string) PendingEntry {
		return PendingEntry{"tool": "replay", "target": WalletBackendTarget, "version": commit, "entry": e}
	}
	pending := func(entries ...PendingEntry) *Pending {
		p := &Pending{Required: runs}
		for i, e := range entries {
			p.Entries = append(p.Entries, e)
			p.Sources = append(p.Sources, PendingSource{File: "findings/pending/replay.json", Index: i, Since: now})
		}
		return p
	}
	held := entry("cap-0040/signed-payload-signer-added")

	f := newFixture(t)
	f.report(rel, false, replayRow("r-pending", true, nil, "pipeline"))
	if res := governanceCheck(t, f, pending(held), Acceptance, now); res.Passed() || !res.PendingOnly() {
		t.Errorf("only a pending row: passed=%v pendingOnly=%v", res.Passed(), res.PendingOnly())
	}
	if res := governanceCheck(t, f, pending(held), Development, now); res.PendingOnly() {
		t.Error("development mode is never pending-only")
	}
	// A stale pending entry beside the pending row is another failure.
	if res := governanceCheck(t, f, pending(held, entry("cap-0023/claimants-max-10")), Acceptance, now); res.PendingOnly() {
		t.Errorf("a stale entry too: stale %v", res.StalePending)
	}

	// A failure row with neither a finding ID nor a pending entry is another failure.
	g := newFixture(t)
	other := replayRow("r-unlinked", true, nil, "pipeline")
	other.Entry = "cap-0023/claimants-max-10"
	g.report(rel, false, replayRow("r-pending", true, nil, "pipeline"), other)
	if res := governanceCheck(t, g, pending(held), Acceptance, now); res.PendingOnly() || res.UnlinkedRows != 1 {
		t.Errorf("an unlinked row too: pendingOnly=%v unlinked=%d", res.PendingOnly(), res.UnlinkedRows)
	}

	// A missing required run is another failure; a check that passes is not pending-only.
	h := newFixture(t)
	h.report("other/report.json", false, replayRow("r-pass", false, nil, "pipeline"))
	if res := governanceCheck(t, h, pending(), Acceptance, now); res.PendingOnly() || len(res.MissingRuns) != 1 {
		t.Errorf("a missing run: pendingOnly=%v missing %v", res.PendingOnly(), res.MissingRuns)
	}
	k := newFixture(t)
	k.report(rel, false, replayRow("r-pass", false, nil, "pipeline"))
	if res := governanceCheck(t, k, pending(), Acceptance, now); !res.Passed() || res.PendingOnly() {
		t.Errorf("a passing check: passed=%v pendingOnly=%v", res.Passed(), res.PendingOnly())
	}
}
