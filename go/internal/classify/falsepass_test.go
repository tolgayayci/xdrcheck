package classify

// Regression tests for stops and fact sets that could be scored as a pass, or blamed on the wrong ledger. Each
// test fails on the classifier before the fix it names.

import (
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/match"
)

// An ingest that did not complete is a stop even when the cursor reached the entry's ledger: with failing_ledger
// S, or with S the last ledger the cursor reached, the entry at S takes the stop's class, not its facts.
func TestStopAtTheEntrysOwnLedger(t *testing.T) {
	for _, tc := range []struct {
		status, want string
		failing      bool
	}{
		{adapter.StatusCrashed, "mishandled·crash", true},
		{adapter.StatusTimeout, "mishandled·hang", true},
		{adapter.StatusHalted, "mishandled·halt", true},
		{adapter.StatusCrashed, "mishandled·crash", false},
		{adapter.StatusHalted, "mishandled·halt", false},
	} {
		in := base()
		in.Ingest = ingest(tc.status, i64(S), func(s *adapter.Signals) {
			s.TermSignal = adapter.Some("SIGSEGV")
			if tc.failing {
				s.FailingLedger = adapter.Some[int64](S)
			}
		})
		in.Observed = withRows()
		in.Match = facts(true, "present", match.Matched)
		if o := Classify(in); o.String() != tc.want {
			t.Errorf("%s, cursor S, failing_ledger given %v: %s (row %d, %v), want %s", tc.status, tc.failing, o, o.Row, o.Notes, tc.want)
		}
	}

	// In a chain the cursor's ledger was ingested; the stop is the ledger after it, unless failing_ledger says
	// otherwise.
	chain := func(seq uint32, failing *int64) Outcome {
		in := base()
		in.Seq, in.UnitFirst, in.UnitLast, in.UnitKind = seq, 2, 24, "chain"
		in.Ingest = ingest(adapter.StatusCrashed, i64(14), func(s *adapter.Signals) {
			if failing != nil {
				s.FailingLedger = adapter.Some(*failing)
			}
		})
		in.Observed = withRows()
		in.Match = facts(true, "present", match.Matched)
		return Classify(in)
	}
	for seq, want := range map[uint32]string{14: "pass", 15: "mishandled·crash", 16: "not_reached"} {
		if o := chain(seq, nil); o.String() != want {
			t.Errorf("chain crash after cursor 14, ledger %d: %s, want %s", seq, o, want)
		}
	}
	for seq, want := range map[uint32]string{13: "pass", 14: "mishandled·crash", 15: "not_reached"} {
		if o := chain(seq, i64(14)); o.String() != want {
			t.Errorf("chain crash at failing_ledger 14 = cursor, ledger %d: %s, want %s", seq, o, want)
		}
	}
	// The cursor at the chain's end with a non-completed status: the last ledger takes the stop.
	in := base()
	in.Seq, in.UnitFirst, in.UnitLast, in.UnitKind = 24, 2, 24, "chain"
	in.Ingest = ingest(adapter.StatusHalted, i64(24), nil)
	in.Observed, in.Match = withRows(), facts(true, "present", match.Matched)
	if o := Classify(in); o.String() != "mishandled·halt" {
		t.Errorf("halted with the cursor at the chain's last ledger: %s", o)
	}
}

// A stop the harness observed itself (no adapter answer by the deadline, or a memory kill) in a chain is located
// by the delivery log, not put on the chain's first ledger.
func TestHarnessStopLocatedByDeliveryLog(t *testing.T) {
	at := func(seq uint32, mod func(*Input)) Outcome {
		in := base()
		in.Seq, in.UnitFirst, in.UnitLast, in.UnitKind = seq, S-2, S, "chain"
		in.LastServed = S - 1
		in.Served = seq <= S-1
		mod(&in)
		return Classify(in)
	}
	timeout := func(in *Input) { in.Harness.TimedOut = true }
	memory := func(in *Input) { in.Harness.MemoryCap = true }
	for _, tc := range []struct {
		name string
		mod  func(*Input)
		want map[uint32]string
	}{
		{"timeout", timeout, map[uint32]string{S - 2: "not_reached", S - 1: "mishandled·hang", S: "not_reached"}},
		{"memory", memory, map[uint32]string{S - 2: "not_reached", S - 1: "mishandled·crash", S: "not_reached"}},
	} {
		for seq, want := range tc.want {
			if o := at(seq, tc.mod); o.String() != want {
				t.Errorf("%s, ledger %d: %s (%v), want %s", tc.name, seq, o, o.Notes, want)
			}
		}
	}
	if o := at(S-2, timeout); !strings.Contains(firstNote(o), "harness killed the adapter at ledger") {
		t.Errorf("an earlier ledger does not say why it has no result: %v", o.Notes)
	}
	// Nothing of the unit served: the first ledger is a harness fault, as before.
	o := at(S-2, func(in *Input) { timeout(in); in.LastServed, in.Served = 0, false })
	if o.String() != "harness_fault" {
		t.Errorf("nothing served: %s", o)
	}
	// No delivery evidence: the stop cannot be located; it stays on the first ledger, and says so.
	o = at(S-2, func(in *Input) { timeout(in); in.Delivery, in.LastServed = DeliveryNone, 0 })
	if o.String() != "mishandled·hang" || !hasNotePrefix(o, "stop_not_located") {
		t.Errorf("no delivery evidence: %s %v", o, o.Notes)
	}
}

// A pass needs a positive fact matched: negative facts alone (must_not_include, count: 0) are not_applicable.
func TestNegativeFactsAloneDoNotPass(t *testing.T) {
	neg := func(st match.Status) match.Fact {
		return match.Fact{Kind: match.FactMustNot, Status: st, Negative: true}
	}
	in := base()
	in.Ingest, in.Observed = ingest(adapter.StatusCompleted, i64(S), nil), withRows()
	in.Match = &match.Result{LedgerSeq: S, LedgerObserved: true, FocusTxSeen: "present",
		Facts: []match.Fact{neg(match.Matched), {Kind: match.FactMovement, Status: match.Matched, Negative: true}, {Kind: match.FactStateChange, Status: match.NotApplicable}}}
	if o := Classify(in); o.String() != "not_applicable" || o.Row != 11 {
		t.Errorf("negative facts only: %s (row %d)", o, o.Row)
	}
	in.Match.Facts = append(in.Match.Facts, match.Fact{Kind: match.FactStateChange, Status: match.Matched})
	if o := Classify(in); o.String() != "pass" {
		t.Errorf("with a positive fact: %s", o)
	}
	in.Match.Facts[0] = neg(match.Wrong)
	if o := Classify(in); o.String() != "mishandled·wrong_value" {
		t.Errorf("a forbidden fact present: %s", o)
	}
}

func hasNotePrefix(o Outcome, p string) bool {
	for _, n := range o.Notes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}
