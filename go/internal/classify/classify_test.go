package classify

import (
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/match"
)

const S = 4437357

func i64(v int64) *int64 { return &v }
func ip(v int) *int      { return &v }

func ingest(status string, cursor *int64, mod func(*adapter.Signals)) *adapter.IngestResult {
	r := &adapter.IngestResult{Status: status, LastLedger: cursor, Signals: adapter.Signals{CursorBefore: i64(S - 1), CursorAfter: cursor}}
	if mod != nil {
		mod(&r.Signals)
	}
	return r
}

func provided() *adapter.Observation {
	return &adapter.Observation{Schema: adapter.ObservationSchema, Range: adapter.Range{Start: S, End: S},
		Kinds: adapter.KindsSet{Receipts: adapter.KindStatus{Status: "provided"}, Transactions: adapter.KindStatus{Status: "provided"},
			Participants: adapter.KindStatus{Status: "not_applicable", Reason: "x"}, StateChanges: adapter.KindStatus{Status: "provided"},
			Movements: adapter.KindStatus{Status: "not_applicable", Reason: "x"}, Addresses: adapter.KindStatus{Status: "not_applicable", Reason: "x"}},
		Ledgers: []adapter.Ledger{}}
}

// withRows is an observation that holds records for the ledger.
func withRows() *adapter.Observation {
	o := provided()
	o.Ledgers = []adapter.Ledger{{LedgerSeq: S, Transactions: []adapter.ObsTransaction{{Hash: "ab"}}}}
	return o
}

func facts(ledger bool, focus string, st ...match.Status) *match.Result {
	r := &match.Result{LedgerSeq: S, LedgerObserved: ledger, FocusTxSeen: focus}
	for i, s := range st {
		r.Facts = append(r.Facts, match.Fact{Kind: match.FactStateChange, Index: i, Status: s})
	}
	return r
}

var gate = &adapter.Envelope{Enforcement: "indexer_gate", MaxProtocol: ip(28)}
var p30 = &manifest.Variant{Network: "testnet", Protocol: 30}
var p28 = &manifest.Variant{Network: "testnet", Protocol: 28}

func refusal(gateName string, ledger int64) func(*adapter.IngestResult) {
	return func(r *adapter.IngestResult) {
		r.Status = adapter.StatusRefused
		r.Refusal = &adapter.Refusal{Gate: gateName, Reason: "protocol 30 is newer than 28", Ledger: ledger}
		r.Signals.ProcessExited = true
		r.Signals.RuntimePanic = adapter.Some(false)
		r.Signals.TermSignal = adapter.Null[string]()
		r.Signals.RowsForFailingLedger = adapter.Some[int64](0)
	}
}

func base() Input {
	return Input{Seq: S, UnitFirst: S, UnitLast: S, UnitKind: "single", Network: "testnet", Variant: p28,
		Envelope: &adapter.Envelope{Enforcement: "sdk_limit", MaxProtocol: ip(29)}, Delivery: DeliveryExact, Served: true}
}

// The truth table of replay-harness.md §7 for the single-ledger case, one row per line, plus the rows of the
// classification table it does not spell out.
func TestTruthTable(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*Input)
		want string
		row  int
	}{
		{"killed by signal, cursor < S → crash", func(in *Input) {
			in.Ingest = ingest(adapter.StatusCrashed, i64(S-1), func(s *adapter.Signals) { s.TermSignal = adapter.Some("SIGSEGV") })
		}, "mishandled·crash", 2},
		{"uncaught runtime fault → crash", func(in *Input) {
			in.Ingest = ingest(adapter.StatusCrashed, i64(S-1), func(s *adapter.Signals) { s.RuntimePanic = adapter.Some(true) })
		}, "mishandled·crash", 2},
		{"adapter group killed for memory → crash (memory)", func(in *Input) { in.Harness.MemoryCap = true }, "mishandled·crash", 2},
		{"exited on its own with an error, 0 rows → halt", func(in *Input) {
			in.Ingest = ingest(adapter.StatusHalted, i64(S-1), func(s *adapter.Signals) { s.RowsForFailingLedger = adapter.Some[int64](0) })
		}, "mishandled·halt", 5},
		{"exited on its own with an error, rows written → halt (partial write)", func(in *Input) {
			in.Ingest = ingest(adapter.StatusHalted, i64(S-1), func(s *adapter.Signals) { s.RowsForFailingLedger = adapter.Some[int64](3) })
		}, "mishandled·halt", 5},
		{"clean refusal, outside the declared gate → refused", func(in *Input) {
			in.Variant, in.Envelope = p30, gate
			in.Ingest = ingest("", nil, nil)
			refusal("max_protocol", S)(in.Ingest)
			in.Observed = provided()
		}, "dropped·refused", 4},
		{"'refusal' of an entry inside the envelope → halt", func(in *Input) {
			in.Variant, in.Envelope = p28, gate
			in.Ingest = ingest("", nil, nil)
			refusal("max_protocol", S)(in.Ingest)
		}, "mishandled·halt", 5},
		{"refusal under sdk_limit → halt", func(in *Input) {
			in.Variant = p30
			in.Ingest = ingest("", nil, nil)
			refusal("max_protocol", S)(in.Ingest)
		}, "mishandled·halt", 5},
		{"refusal naming an undeclared gate → halt", func(in *Input) {
			in.Variant, in.Envelope = p30, gate
			in.Ingest = ingest("", nil, nil)
			refusal("ledger_close_meta_version", S)(in.Ingest)
		}, "mishandled·halt", 5},
		{"refusal that left rows → halt", func(in *Input) {
			in.Variant, in.Envelope = p30, gate
			in.Ingest = ingest("", nil, nil)
			refusal("max_protocol", S)(in.Ingest)
			in.Observed = withRows()
		}, "mishandled·halt", 5},
		{"refusal by a crashed process → halt", func(in *Input) {
			in.Variant, in.Envelope = p30, gate
			in.Ingest = ingest("", nil, nil)
			refusal("max_protocol", S)(in.Ingest)
			in.Ingest.Signals.RuntimePanic = adapter.Some(true)
		}, "mishandled·halt", 5},
		{"alive at the deadline, served → hang", func(in *Input) { in.Ingest = ingest(adapter.StatusTimeout, i64(S-1), nil) }, "mishandled·hang", 3},
		{"adapter did not answer ingest → hang", func(in *Input) { in.Harness.TimedOut = true }, "mishandled·hang", 3},
		{"alive at the deadline, never served → harness_fault", func(in *Input) {
			in.Ingest, in.Served = ingest(adapter.StatusTimeout, i64(S-1), nil), false
		}, "harness_fault", 0},
		{"alive at the deadline, no delivery log → hang (delivery_not_observed)", func(in *Input) {
			in.Ingest, in.Delivery, in.Served = ingest(adapter.StatusTimeout, i64(S-1), nil), DeliveryNone, false
		}, "mishandled·hang", 3},
		{"past S, nothing for S → silent", func(in *Input) {
			in.Ingest, in.Observed, in.Match = ingest(adapter.StatusCompleted, i64(S), nil), provided(), facts(false, "absent", match.Missing)
		}, "dropped·silent", 7},
		{"past S, focus transaction absent → silent", func(in *Input) {
			in.Ingest, in.Observed, in.Match = ingest(adapter.StatusCompleted, i64(S), nil), withRows(), facts(true, "absent", match.Missing)
		}, "dropped·silent", 7},
		{"past S, a receipt counter lower → silent", func(in *Input) {
			m := facts(true, "present", match.Matched)
			m.Facts = append(m.Facts, match.Fact{Kind: match.FactReceipt, Field: "transactions", Status: match.Missing, Shortfall: true})
			in.Ingest, in.Observed, in.Match = ingest(adapter.StatusCompleted, i64(S), nil), withRows(), m
		}, "dropped·silent", 7},
		{"a silent gap the indexer recorded an error for → partial", func(in *Input) {
			o := provided()
			o.Errors = []adapter.ObsError{{LedgerSeq: S, Message: "skipped"}}
			in.Ingest, in.Observed, in.Match = ingest(adapter.StatusCompleted, i64(S), nil), o, facts(false, "absent", match.Missing)
		}, "dropped·partial", 9},
		{"past S, a fact wrong → wrong_value", func(in *Input) {
			in.Ingest, in.Observed, in.Match = ingest(adapter.StatusCompleted, i64(S), nil), withRows(), facts(true, "present", match.Matched, match.Wrong, match.Missing)
		}, "mishandled·wrong_value", 8},
		{"past S, a forbidden fact present → wrong_value", func(in *Input) {
			m := facts(true, "present", match.Matched)
			m.Extras = []match.Extra{{Status: match.Forbidden}}
			in.Ingest, in.Observed, in.Match = ingest(adapter.StatusCompleted, i64(S), nil), withRows(), m
		}, "mishandled·wrong_value", 8},
		{"past S, an exactness extra → wrong_value", func(in *Input) {
			m := facts(true, "present", match.Matched)
			m.Extras = []match.Extra{{Status: match.ExtraInScope}}
			in.Ingest, in.Observed, in.Match = ingest(adapter.StatusCompleted, i64(S), nil), withRows(), m
		}, "mishandled·wrong_value", 8},
		{"past S, a receipt counter higher → wrong_value", func(in *Input) {
			m := facts(true, "present", match.Matched)
			m.Facts = append(m.Facts, match.Fact{Kind: match.FactReceipt, Field: "operations", Status: match.Wrong})
			in.Ingest, in.Observed, in.Match = ingest(adapter.StatusCompleted, i64(S), nil), withRows(), m
		}, "mishandled·wrong_value", 8},
		{"past S, a fact missing, none wrong → partial", func(in *Input) {
			in.Ingest, in.Observed, in.Match = ingest(adapter.StatusCompleted, i64(S), nil), withRows(), facts(true, "present", match.Matched, match.Missing, match.NotApplicable)
		}, "dropped·partial", 9},
		{"past S, all ok → pass", func(in *Input) {
			in.Ingest, in.Observed, in.Match = ingest(adapter.StatusCompleted, i64(S+4), nil), withRows(), facts(true, "present", match.Matched, match.NotApplicable)
		}, "pass", 10},
		{"every fact not applicable → not_applicable", func(in *Input) {
			in.Ingest, in.Observed, in.Match = ingest(adapter.StatusCompleted, i64(S), nil), withRows(), facts(true, "present", match.NotApplicable)
		}, "not_applicable", 11},
		{"not run (sdk_limit) → not_applicable", func(in *Input) {
			in.PlannedNA, in.NAReason = true, "outside_declared_envelope: protocol 30 is above max_protocol 29"
		}, "not_applicable", 1},
		{"adapter error response → harness_fault", func(in *Input) { in.Fault = "adapter error in prepare: prepare_failed" }, "harness_fault", 0},
		{"expectations cannot be evaluated → harness_fault", func(in *Input) {
			in.Ingest, in.Observed, in.MatchError = ingest(adapter.StatusCompleted, i64(S), nil), withRows(), "bad tx_index"
		}, "harness_fault", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			tc.mod(&in)
			o := Classify(in)
			if o.String() != tc.want || o.Row != tc.row {
				t.Errorf("%s (row %d, %v), want %s (row %d)", o, o.Row, o.Notes, tc.want, tc.row)
			}
		})
	}
}

func TestNotesAndChainStops(t *testing.T) {
	in := base()
	in.Harness.MemoryCap = true
	if o := Classify(in); len(o.Notes) == 0 || o.Notes[0][:6] != "memory" {
		t.Errorf("memory note: %v", o.Notes)
	}
	in = base()
	in.Ingest = ingest(adapter.StatusHalted, i64(S-1), func(s *adapter.Signals) { s.RowsForFailingLedger = adapter.Some[int64](3) })
	if o := Classify(in); !hasNote(o, "partial_write") {
		t.Errorf("partial_write note: %v", o.Notes)
	}
	in.Delivery = DeliveryNone
	if o := Classify(in); !hasNote(o, "delivery_not_observed") {
		t.Errorf("delivery note: %v", o.Notes)
	}

	// A chain of ledgers 2..24 that halts at 15: 14 is scored from its facts, 15 takes the halt, 16 is not reached.
	chain := func(seq uint32) Outcome {
		in := base()
		in.Seq, in.UnitFirst, in.UnitLast, in.UnitKind = seq, 2, 24, "chain"
		in.Served = seq <= 15
		in.Ingest = ingest(adapter.StatusHalted, i64(14), func(s *adapter.Signals) { s.FailingLedger = adapter.Some[int64](15) })
		in.Observed = withRows()
		in.Match = facts(true, "present", match.Matched)
		return Classify(in)
	}
	for seq, want := range map[uint32]string{14: "pass", 15: "mishandled·halt", 16: "not_reached", 24: "not_reached"} {
		if o := chain(seq); o.String() != want {
			t.Errorf("chain ledger %d: %s, want %s", seq, o, want)
		}
	}
	// Without failing_ledger the stop is the ledger after the cursor; with no cursor, the unit's first ledger.
	in = base()
	in.Seq, in.UnitFirst, in.UnitLast = 5, 2, 9
	in.Ingest = ingest(adapter.StatusCrashed, nil, nil)
	if o := Classify(in); o.String() != "not_reached" {
		t.Errorf("no cursor: %s", o)
	}
	in.Seq = 2
	if o := Classify(in); o.String() != "mishandled·crash" {
		t.Errorf("no cursor, first ledger: %s", o)
	}
}

func hasNote(o Outcome, n string) bool {
	for _, x := range o.Notes {
		if x == n {
			return true
		}
	}
	return false
}

func div(versions, outcome, qualifier, observed string) manifest.KnownDivergence {
	return manifest.KnownDivergence{Target: "stellar/wallet-backend", Versions: versions, Level: "replay", Outcome: outcome, Qualifier: qualifier,
		Reference: "https://example.org/" + outcome, Status: "fixed", Observed: observed}
}

func TestJudge(t *testing.T) {
	e := &manifest.Entry{ID: "cap-0040/x", Conformance: &manifest.Conformance{KnownDivergences: []manifest.KnownDivergence{
		div("A..B", "halt", "halt", "executed"),
		div("..C", "wrong_value", "wrong_value", "executed"),
		div("..D", "dropped", "partial", "reported"),
		{Target: "@stellar/stellar-sdk", Versions: "<1.0.0", Level: "L1", Outcome: "reject", Observed: "executed"},
	}}}
	ranges := func(in map[string]bool) func(string) (bool, bool) {
		return func(r string) (bool, bool) { v, ok := in[r]; return v, ok }
	}
	halt := Outcome{Class: Mishandled, Qualifier: Halt, Row: 5}
	pass := Outcome{Class: Pass, Row: 10}
	wrong := Outcome{Class: Mishandled, Qualifier: WrongValue, Row: 8}
	na := Outcome{Class: NotApplicable, Row: 1, Notes: []string{"outside_declared_envelope"}}
	nsk := Outcome{Class: NotApplicable, Row: 11}
	cases := []struct {
		name   string
		in     map[string]bool
		o      Outcome
		assert bool
		want   bool
	}{
		{"inside, declared class", map[string]bool{"A..B": true, "..C": false, "..D": false}, halt, true, true},
		{"inside, a pass is unexpected", map[string]bool{"A..B": true, "..C": false, "..D": false}, pass, true, false},
		{"inside, another class (flipped)", map[string]bool{"A..B": true, "..C": false, "..D": false}, wrong, true, false},
		{"outside, pass", map[string]bool{"A..B": false, "..C": false, "..D": false}, pass, true, true},
		{"outside, an undeclared divergence", map[string]bool{"A..B": false, "..C": false, "..D": false}, halt, true, false},
		{"two ranges hold, either class", map[string]bool{"A..B": true, "..C": true, "..D": false}, wrong, true, true},
		{"only an unexecuted divergence holds: not asserted", map[string]bool{"A..B": false, "..C": false, "..D": true}, pass, true, true},
		{"not run outside the envelope", map[string]bool{"A..B": true, "..C": false, "..D": false}, na, true, true},
		{"no supported kind under --assert-known", map[string]bool{"A..B": false, "..C": false, "..D": false}, nsk, true, false},
		{"no supported kind in a plain run", map[string]bool{"A..B": false, "..C": false, "..D": false}, nsk, false, true},
		{"an unresolved range", map[string]bool{"A..B": false, "..D": false}, pass, true, false},
		{"harness fault", map[string]bool{"A..B": false, "..C": false, "..D": false}, Outcome{Class: HarnessFault}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := ForEntry(e, "stellar/wallet-backend", ranges(tc.in))
			v := Judge(x, tc.o, tc.assert)
			if v.Expected != tc.want {
				t.Errorf("expected=%v (%s), want %v", v.Expected, v.Note, tc.want)
			}
		})
	}
	if !HasReplayDivergence(e, "stellar/wallet-backend") || HasReplayDivergence(e, "@stellar/stellar-sdk") {
		t.Error("replay divergence selection")
	}
}

func TestSemver(t *testing.T) {
	cases := []struct {
		rng, v string
		in     bool
	}{
		{">=0.7.0 <0.7.2", "v0.7.1", true},
		{">=0.7.0 <0.7.2", "v0.7.2", false},
		{"<0.6.1", "0.6.0", true},
		{"0.7.1 - 0.7.3", "0.7.3", true},
		{"0.7.1 - 0.7.3", "0.8.0", false},
		{"<16.3.1 || >=17.0.0 <17.2.1", "17.1.0", true},
		{"<16.3.1 || >=17.0.0 <17.2.1", "16.4.0", false},
		{"17.0.0", "17.0.0", true},
		{"<=6.0.0", "6.0.0-rc.1", true},
	}
	for _, c := range cases {
		in, ok := SemverContains(c.rng, c.v)
		if !ok || in != c.in {
			t.Errorf("%q contains %s = %v %v, want %v", c.rng, c.v, in, ok, c.in)
		}
	}
	if _, ok := SemverContains("..abc", "0.1.0"); ok {
		t.Error("a commit range read as semver")
	}
}
