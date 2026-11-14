// Package classify turns what happened to one entry in one replay unit — the planner's decision, the ingest
// result's facts, the delivery evidence and the matcher's fact results — into the report's class and qualifier,
// by the first matching row of replay-harness.md §7:
//
//	 0 adapter error, protocol violation, or positive evidence the ledger was never served → harness_fault
//	 1 planned not_applicable (outside an sdk_limit envelope, --out-of-envelope skip, …)    → not_applicable
//	 2 ingest crashed at or before this ledger (signal, runtime fault, memory kill)           → mishandled · crash
//	 3 ingest timeout with progress stopped at this ledger                                   → mishandled · hang
//	 4 refused at this ledger, declared indexer_gate, the manifest confirms the entry is
//	   outside that gate, nothing written, no crash                                          → dropped · refused
//	 5 refused failing any of row 4's conditions, or halted at this ledger                   → mishandled · halt
//	 6 the indexer stopped at an earlier ledger of the unit                                  → not_reached
//	 7 got past the ledger, but the ledger or the focus transaction is absent, or a receipt
//	   counter is lower, and the indexer recorded no error for it                            → dropped · silent
//	 8 a fact wrong, an exactness extra, a forbidden fact, or a receipt counter higher       → mishandled · wrong_value
//	 9 a fact missing                                                                         → dropped · partial
//	10 every fact matched or not_applicable, at least one positive fact matched               → pass
//	11 no positive fact matched (all not_applicable, or only must-not facts held)             → not_applicable
//
// Any ingest status but completed is a stop, wherever the cursor is; so is a completed status whose cursor is
// short of the ledger. "This ledger" for a stop is the ledger the indexer stopped on: the ingest result's
// failing_ledger when given; else the one after its cursor, or the unit's last ledger when the cursor reached
// it; for a stop the harness observed itself (deadline, memory kill), the last ledger the delivery log shows
// served; else the unit's first ledger. Entries before it are scored from their facts (not_reached when the
// harness killed the adapter and nothing could be observed), the entry at it takes the stop's class, entries
// after it are not_reached (replay-harness.md §3.2).
//
// The side categories flaky (from --confirm) is applied by the runner, which alone sees repeated runs.
package classify

import (
	"fmt"
	"slices"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/match"
)

// Classes and qualifiers (report.schema.json row.replay).
const (
	Pass          = "pass"
	Mishandled    = "mishandled"
	Dropped       = "dropped"
	NotApplicable = "not_applicable"
	NotReached    = "not_reached"
	HarnessFault  = "harness_fault"
	Flaky         = "flaky"

	WrongValue = "wrong_value"
	Crash      = "crash"
	Hang       = "hang"
	Halt       = "halt"
	Silent     = "silent"
	Partial    = "partial"
	Refused    = "refused"
)

// Delivery evidence kinds.
const (
	DeliveryExact = "exact" // a request log the harness keeps (mock RPC, logging proxy): served or not is known
	DeliveryNone  = "none"  // a filesystem layout: nothing observes reads
)

// Input is everything known about one entry variant after its unit ran.
type Input struct {
	// Row 0.
	Fault string // an adapter error response, protocol violation, adapter exit, failed call; "" when none

	// Row 1: the planner's decision.
	PlannedNA  bool
	NAReason   string // the planner's qualifier and detail (outside_declared_envelope: …)
	Seq        uint32 // the entry's ledger as served
	UnitFirst  uint32
	UnitLast   uint32
	UnitKind   string
	Network    string
	Variant    *manifest.Variant // for the refusal check
	Expect     *manifest.Expect
	Envelope   *adapter.Envelope
	Ingest     *adapter.IngestResult // nil when no ingest result exists (Fault, or HarnessTimeout/AdapterOOM)
	Harness    HarnessIngest         // what the harness itself saw of ingest
	Delivery   string                // DeliveryExact or DeliveryNone
	Served     bool                  // with DeliveryExact: the ledger was delivered successfully
	LastServed uint32                // with DeliveryExact: the unit's highest delivered ledger (0: none); locates a Harness stop
	Observed   *adapter.Observation  // nil when observe failed
	Match      *match.Result         // nil when not evaluated
	MatchError string                // the expectations could not be evaluated (a corpus fault)
}

// HarnessIngest is what the harness observed of ingest when the adapter could not report it.
type HarnessIngest struct {
	TimedOut  bool // the adapter did not answer ingest by its deadline; the harness killed its group
	MemoryCap bool // the adapter's group was killed for its memory cap during ingest
}

// Outcome is a class, a qualifier and the notes that explain it.
type Outcome struct {
	Class     string
	Qualifier string
	Row       int // the truth-table row that decided
	Notes     []string
}

// String is "class·qualifier" or the class.
func (o Outcome) String() string {
	if o.Qualifier == "" {
		return o.Class
	}
	return o.Class + "·" + o.Qualifier
}

// Classify applies the table.
func Classify(in Input) Outcome {
	out := func(row int, class, q string, notes ...string) Outcome {
		return Outcome{Class: class, Qualifier: q, Row: row, Notes: notes}
	}
	if in.Fault != "" {
		return out(0, HarnessFault, "", in.Fault)
	}
	if in.PlannedNA {
		return out(1, NotApplicable, "", in.NAReason)
	}

	ing := in.Ingest
	status, cursor := "", (*int64)(nil)
	var failing *int64
	switch {
	case in.Harness.MemoryCap:
		status = adapter.StatusCrashed
	case in.Harness.TimedOut:
		status = adapter.StatusTimeout
	case ing != nil:
		status = ing.Status
		cursor = ing.Signals.CursorAfter
		if cursor == nil {
			cursor = ing.LastLedger
		}
		if v, ok := ing.Signals.FailingLedger.Get(); ok {
			failing = &v
		}
	default:
		return out(0, HarnessFault, "", "no ingest result")
	}

	s := int64(in.Seq)
	first, last := int64(in.UnitFirst), int64(in.UnitLast)
	within := func(v int64) int64 { return max(first, min(v, last)) }
	// Any status but completed is a stop somewhere in the unit; so is a completed status whose cursor is short
	// of this ledger. Locate it.
	stopped, stop := false, first
	var stopNotes []string
	switch {
	case status != adapter.StatusCompleted:
		stopped = true
		switch {
		case failing != nil && *failing >= first && *failing <= last:
			stop = *failing
		case cursor != nil:
			// The ledger after the last one the cursor reached; when that is past the unit, the last ledger.
			stop = within(*cursor + 1)
		case ing == nil:
			stop, stopNotes = harnessStop(in)
		}
	case cursor != nil && *cursor < s:
		stopped, stop = true, within(*cursor+1)
	}
	if stopped && s < stop && ing == nil && in.Observed == nil {
		// Ingested before the stop, so scored from its facts (replay-harness.md §3.2) — but after a harness kill
		// there are none to score.
		return out(6, NotReached, "", fmt.Sprintf("the harness killed the adapter at ledger %d (%s); nothing could be observed for this earlier ledger", stop, status))
	}
	if stopped && s >= stop {
		if stop < s {
			return out(6, NotReached, "", fmt.Sprintf("the indexer stopped at ledger %d (%s), before this entry's ledger %d", stop, status, s))
		}
		if in.Delivery == DeliveryExact && !in.Served {
			return out(0, HarnessFault, "", fmt.Sprintf("the delivery log shows ledger %d was never served", s))
		}
		var notes []string
		if in.Delivery != DeliveryExact {
			notes = append(notes, "delivery_not_observed")
		}
		if cursor != nil && *cursor >= s {
			notes = append(notes, fmt.Sprintf("the cursor reached ledger %d, but ingest ended %s there", *cursor, status))
		}
		notes = append(notes, stopNotes...)
		switch status {
		case adapter.StatusCrashed:
			if in.Harness.MemoryCap {
				notes = append(notes, "memory: the adapter's group was killed for its memory cap")
			} else if ing != nil {
				if sig, ok := ing.Signals.TermSignal.Get(); ok {
					notes = append(notes, "ended by "+sig)
				}
			}
			return out(2, Mishandled, Crash, notes...)
		case adapter.StatusTimeout:
			if in.Harness.TimedOut {
				notes = append(notes, "the adapter did not answer ingest by its deadline; the harness killed it")
			}
			return out(3, Mishandled, Hang, notes...)
		case adapter.StatusRefused:
			if why := refusalProblem(in); why != "" {
				return out(5, Mishandled, Halt, append(notes, "refusal not confirmed: "+why)...)
			}
			return out(4, Dropped, Refused, append(notes, "expected (declared gate "+ing.Refusal.Gate+")")...)
		default: // halted, or a status that claims completion with the cursor short of the ledger
			if status != adapter.StatusHalted {
				notes = append(notes, fmt.Sprintf("status %q but the cursor is below ledger %d", status, s))
			}
			if partialWrite(in) {
				notes = append(notes, "partial_write")
			}
			return out(5, Mishandled, Halt, notes...)
		}
	}

	if in.MatchError != "" {
		return out(0, HarnessFault, "", "the expectations cannot be evaluated: "+in.MatchError)
	}
	m := in.Match
	if m == nil {
		return out(0, HarnessFault, "", "no observation to match")
	}
	sum := m.Summary()
	provided := in.Observed != nil && anyProvided(in.Observed)
	if !indexerRecordedError(in) && provided && (!m.LedgerObserved || m.FocusTxSeen == "absent" || sum.ReceiptShortfall) {
		why := "the ledger is absent from the observation"
		switch {
		case m.LedgerObserved && m.FocusTxSeen == "absent":
			why = "the focus transaction is absent"
		case m.LedgerObserved:
			why = "a receipt counter is lower than expected"
		}
		return out(7, Dropped, Silent, why)
	}
	switch {
	case sum.AnyWrong() || sum.ReceiptExcess:
		return out(8, Mishandled, WrongValue)
	case sum.Missing > 0:
		return out(9, Dropped, Partial)
	case sum.MatchedPositive > 0:
		return out(10, Pass, "")
	case sum.Matched > 0:
		return out(11, NotApplicable, "", "no_supported_kind: only must-not facts held, and those alone are no evidence the reader handled the entry")
	}
	return out(11, NotApplicable, "", "no_supported_kind: the adapter models none of the facts this entry expects")
}

// harnessStop locates a stop the harness observed itself — the adapter did not answer ingest by its deadline,
// or its group was killed for memory — where no cursor or failing ledger was reported: the last ledger of the
// unit the delivery log shows served. Without delivery evidence it cannot be located and is put at the unit's
// first ledger, with a note.
func harnessStop(in Input) (int64, []string) {
	first := int64(in.UnitFirst)
	switch {
	case in.UnitLast == in.UnitFirst:
		return first, nil
	case in.Delivery != DeliveryExact:
		return first, []string{"stop_not_located: no delivery evidence, so the stop is put at the unit's first ledger; confirm on the rpc input"}
	case in.LastServed >= in.UnitFirst && in.LastServed <= in.UnitLast:
		return int64(in.LastServed), []string{fmt.Sprintf("stop located by the delivery log: ledger %d was the last served (a client that reads ahead may have stopped earlier)", in.LastServed)}
	}
	return first, []string{"the delivery log shows no ledger of the unit served"}
}

func anyProvided(o *adapter.Observation) bool {
	for _, k := range adapter.AllKinds {
		if o.Kinds.Kind(k).Status == "provided" {
			return true
		}
	}
	return false
}

func indexerRecordedError(in Input) bool {
	if in.Observed == nil {
		return false
	}
	for _, e := range in.Observed.Errors {
		if e.LedgerSeq == int64(in.Seq) {
			return true
		}
	}
	return false
}

// ledgerHasRecords reports whether the observation holds any record for the entry's ledger.
func ledgerHasRecords(in Input) bool {
	if in.Observed == nil {
		return false
	}
	l := in.Observed.Ledger(int64(in.Seq))
	if l == nil {
		return false
	}
	return len(l.Transactions)+len(l.Participants)+len(l.StateChanges)+len(l.Movements)+len(l.Addresses) > 0 ||
		(l.Receipt != nil && (nonZero(l.Receipt.Transactions) || nonZero(l.Receipt.Operations) || nonZero(l.Receipt.Events)))
}

func nonZero(p *int64) bool { return p != nil && *p > 0 }

func partialWrite(in Input) bool {
	if in.Ingest != nil {
		if n, ok := in.Ingest.Signals.RowsForFailingLedger.Get(); ok && n > 0 {
			return true
		}
	}
	return ledgerHasRecords(in)
}

// refusalProblem re-checks a refusal against the envelope and the manifest (adapter-protocol.md §3.1 rule 2);
// "" means confirmed.
func refusalProblem(in Input) string {
	ing, env := in.Ingest, in.Envelope
	r := ing.Refusal
	switch {
	case r == nil:
		return "no refusal block"
	case env == nil || env.Enforcement != "indexer_gate":
		return "the envelope is not enforced by an indexer_gate"
	case r.Ledger != int64(in.Seq):
		return fmt.Sprintf("the refusal names ledger %d, not %d", r.Ledger, in.Seq)
	}
	if p, ok := ing.Signals.RuntimePanic.Get(); ok && p {
		return "the process died of a runtime fault"
	}
	if sig, ok := ing.Signals.TermSignal.Get(); ok && sig != "" {
		return "the process was ended by " + sig
	}
	if n, ok := ing.Signals.RowsForFailingLedger.Get(); !ok || n != 0 {
		return "rows_for_failing_ledger is not 0"
	}
	if ledgerHasRecords(in) {
		return "the indexer holds records for the refused ledger"
	}
	if in.Variant == nil {
		return "no manifest variant to check the gate against"
	}
	v := in.Variant
	lo, hi := v.Protocol, v.Protocol
	if v.HeaderProtocol != nil {
		lo, hi = min(lo, *v.HeaderProtocol), max(hi, *v.HeaderProtocol)
	}
	var lcm, txm *int
	if v.Meta != nil {
		lcm, txm = v.Meta.LedgerCloseMetaVersion, v.Meta.TransactionMetaVersion
	}
	declared, outside := false, false
	switch r.Gate {
	case "max_protocol":
		declared = env.MaxProtocol != nil
		outside = declared && hi > *env.MaxProtocol
	case "min_protocol":
		declared = env.MinProtocol != nil
		outside = declared && lo < *env.MinProtocol
	case "min_protocol_with_transactions":
		declared = env.MinProtocolWithTransactions != nil
		hasTx := in.Expect == nil || in.Expect.Ledger == nil || in.Expect.Ledger.Transactions == nil || *in.Expect.Ledger.Transactions > 0
		outside = declared && lo < *env.MinProtocolWithTransactions && hasTx
	case "ledger_close_meta_version":
		declared = len(env.LedgerCloseMetaVersions) > 0
		outside = declared && lcm != nil && !slices.Contains(env.LedgerCloseMetaVersions, *lcm)
	case "transaction_meta_version":
		declared = len(env.TransactionMetaVersions) > 0
		outside = declared && txm != nil && !slices.Contains(env.TransactionMetaVersions, *txm)
	case "operation_type":
		declared = len(env.OperationTypes) > 0
		if declared {
			return "an operation_type gate cannot be confirmed from the manifest"
		}
	}
	switch {
	case !declared:
		return "gate " + r.Gate + " was not declared in describe"
	case !outside:
		return "the manifest puts this entry inside gate " + r.Gate
	}
	return ""
}
