package conform

import (
	"encoding/json"

	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

// Observation is what the orchestrator saw for one cell.
//
// Exactly one of these holds: the driver answered (Response is set and validated; Source "driver"); the
// orchestrator assigned the outcome itself (Source "orchestrator": crash when the process died or was killed,
// with Crash set; n_a when the driver does not declare the level); the response broke the protocol
// (ProtocolError is set, the cell is not judged and the run exits 2); or the cell was not run (NotRun is set:
// the driver could not start or describe itself, or the run was canceled).
type Observation struct {
	Cell    *Cell
	Request *RunRequest // nil when no request was sent

	Response    *RunResponse
	ResponseRaw json.RawMessage // the validated line, verbatim

	Outcome string // ok, diverge, reject, crash, n_a: the driver's, or the orchestrator's
	Reason  string // the driver's reason code, or the orchestrator's (timeout, out_of_memory, process_died, level_not_supported)
	Source  string // driver, orchestrator

	Crash         *Crash
	ProtocolError string
	BadLine       string // the offending line, possibly truncated
	NotRun        string

	Describe *Describe // the describe of the process that served the cell (its xdr_schema probes give the column's reach)

	Process int     // driver process number within the column (1 = the first), 0 when none ran
	WallMS  float64 // request to response, as the orchestrator measured it

	Judgement *Judgement // set by Result.Apply for judged cells

	// L0 is the L0 cell of the same entry, variant and column, when the run has one (set by Result.Apply, which
	// judges it first): a level above L0 is read in its light (a value refused at L0 cannot reach L1).
	L0 *Observation
}

// Judged reports whether the cell has an outcome to judge.
func (o *Observation) Judged() bool {
	return o.ProtocolError == "" && o.NotRun == "" && o.Outcome != ""
}

// Judgement is the verdict engine's decision on one observed cell.
type Judgement struct {
	Verdict         string // conform, diverge, accepts_invalid, reject_valid, crash, n_a
	Check           string // conform, known, undeclared, unexpected-conform, known-changed, n_a; "" when not decided
	Expectation     string // expected, unexpected, pending (report.ExpectationPending)
	Expected        *report.Expected
	KnownDivergence *report.DivergenceMatch
	Finding         *string
	Notes           []string
}

// Judge turns an observed outcome into a verdict and a check. This is the hook the verdict engine
// (conform/verdict) implements: it gets each judged observation, with the cell's entry, variant, level and
// column, and the validated driver response; it returns the verdict against the entry's reference, the check
// against the manifest's known divergences, and the report row's expectation. The orchestrator calls it once
// per judged cell, in report order, after every cell has run.
type Judge interface {
	Judge(o *Observation) Judgement
}

// ObservedJudge is the judge used until the verdict engine is installed. It looks only at the outcome class
// and at whether the entry is negative; it compares no values and reads no known divergence, so it leaves
// Check empty and notes on each row that the verdict is provisional. A failure verdict is unexpected, because
// nothing has declared it.
type ObservedJudge struct{}

// ProvisionalNote is added to every row ObservedJudge decides.
const ProvisionalNote = "provisional verdict from the outcome class only; values, known divergences and check are left to the verdict engine"

// Judge implements Judge.
func (ObservedJudge) Judge(o *Observation) Judgement {
	e := o.Cell.Entry
	mustRefuse := e.Negative || (e.API != nil && e.API.ExpectReject) || (e.Expect.Reject != nil)
	var v string
	switch o.Outcome {
	case "n_a":
		v = "n_a"
	case "crash":
		v = "crash"
	case "diverge":
		v = "diverge"
	case "ok":
		v = "conform"
		if mustRefuse {
			v = "accepts_invalid"
		}
	case "reject":
		v = "reject_valid"
		if mustRefuse {
			v = "conform"
		}
	}
	j := Judgement{Verdict: v, Expectation: "expected", Notes: []string{ProvisionalNote}}
	if report.ConformFailure(v) {
		j.Expectation = "unexpected"
	}
	return j
}

// Apply runs the judge over every judged observation, in report order, and stores the judgements. L0 cells
// are judged before the higher levels of the same entry, variant and column, which are linked to them.
func (r *Result) Apply(j Judge) {
	l0 := map[string]*Observation{}
	key := func(o *Observation) string {
		return o.Cell.Entry.ID + "\x00" + o.Cell.VariantKey + "\x00" + o.Cell.Column.ID
	}
	for _, o := range r.Observations {
		if o.Cell.Level == "L0" {
			l0[key(o)] = o
		}
	}
	ordered := make([]*Observation, 0, len(r.Observations))
	for _, o := range r.Observations {
		if o.Cell.Level == "L0" {
			ordered = append(ordered, o)
		}
	}
	for _, o := range r.Observations {
		if o.Cell.Level != "L0" {
			o.L0 = l0[key(o)]
			ordered = append(ordered, o)
		}
	}
	for _, o := range ordered {
		if o.Judged() {
			jj := j.Judge(o)
			o.Judgement = &jj
		}
	}
}

// MarkPending gives every unexpected judged cell whose report row mark names (a committed pending list, see
// findings.Pending.Mark) the expectation pending finding review. Call it after Apply.
func (r *Result) MarkPending(mark func(*report.Row) bool) {
	for _, o := range r.Observations {
		if j := o.Judgement; j != nil && j.Expectation == "unexpected" {
			row := Row(o, j)
			if mark(&row) {
				j.Expectation = row.Expectation
			}
		}
	}
}

// Unexpected counts the judged cells whose expectation is unexpected.
func (r *Result) Unexpected() int {
	n := 0
	for _, o := range r.Observations {
		if o.Judgement != nil && o.Judgement.Expectation == "unexpected" {
			n++
		}
	}
	return n
}
