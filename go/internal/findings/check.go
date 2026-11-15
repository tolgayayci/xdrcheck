package findings

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

// Check modes (findings/README.md).
const (
	// Development: every failure row on an sdk, pipeline or core target has a finding ID that resolves to a
	// record in any state, or is listed as pending finding review; every record validates, and no record is
	// orphaned. Not acceptance evidence.
	Development = "development"
	// Acceptance: the same, every record is in a terminal state (filed, duplicate-of, not-a-defect), and no row
	// is pending finding review.
	Acceptance = "acceptance"
)

// DevelopmentBanner heads the development mode's output.
const DevelopmentBanner = "DEVELOPMENT MODE — NOT ACCEPTANCE EVIDENCE"

// ErrOverlayReport is returned for a report made with the private overlay when the check runs without one.
var ErrOverlayReport = errors.New("the report was made with the private overlay; it is checked only with --overlay")

// maxListed caps how many rows of one kind a result keeps for printing; the counts are always complete.
const maxListed = 50

// Checker maps the rows of one or more reports onto the records of a store.
type Checker struct {
	store *Store
	// AllowOverlay accepts reports whose header says the overlay was loaded.
	AllowOverlay bool
	// Pending lists the failure rows awaiting finding review (LoadPending); nil means none.
	Pending *Pending
	// PrivateRow reports whether a report row can come only from a run with the private overlay (a column that
	// runs only with it). A record whose every evidence.report_rows entry is such a row is not an orphan when the
	// checked reports do not refer to it: a public run cannot. Nil means no row is private.
	PrivateRow func(rowID string) bool
	// NoDriver reports whether the kit has no conformance column for a target (its ecosystem and package). A
	// record whose evidence says it was observed by source reading only (evidence.observed "source-reading"),
	// listing no report rows, on such a target can never be referred to by a report row: it is not an orphan,
	// and the result lists it apart (SourceReadingOnly), so the exemption is never silent. Nil exempts no record.
	NoDriver func(ecosystem, pkg string) bool
	// A record whose evidence.observed is "private-run" and that lists no report rows was executed in the
	// maintainer's private acceptance run only: no public report can refer to it. It is not an orphan, and the
	// result lists it apart (PrivateRunOnly).
	//
	// Now is the date pending entries' ages are measured at; zero means the current time.
	Now time.Time

	reports    []string
	rows       int
	failures   int
	linked     int
	unlinked   int
	unlinkedEx []string
	pending    int
	pendingEx  []string
	dangling   int
	danglingEx []string
	referenced map[string]int
	// runs marks the required runs (Pending.Required) among the added reports; hits counts, per pending entry,
	// the failure rows of those reports it accounts for.
	runs map[int]bool
	hits map[int]int
}

// NewChecker starts a check against the records in store.
func NewChecker(store *Store) *Checker {
	return &Checker{store: store, referenced: map[string]int{}, runs: map[int]bool{}, hits: map[int]int{}}
}

// AddReport streams one report's rows into the check. It fails (and the check cannot run) on a report that
// does not read, and on an overlay report unless AllowOverlay is set.
func (c *Checker) AddReport(path string) error {
	var (
		rows, failures, linked, unlinked, pending, dangling int
		unlinkedEx, pendingEx, danglingEx                   []string
		refs                                                = map[string]int{}
		hits                                                = map[int]int{}
		run                                                 = -1
	)
	if c.Pending != nil {
		run = runFor(c.Pending.Required, path)
	}
	h, _, err := report.ReadFile(path, func(r *report.Row) error {
		rows++
		if r.Failure {
			failures++
		}
		if r.Finding != nil {
			id := *r.Finding
			refs[id]++
			if _, ok := c.store.Records[id]; !ok {
				dangling++
				if len(danglingEx) < maxListed {
					danglingEx = append(danglingEx, fmt.Sprintf("%s: %s names %s, which has no record", path, r.RowID, id))
				}
			} else if report.NeedsFinding(r) {
				linked++
			}
		} else if m := c.Pending.reviewMatches(r); len(m) > 0 {
			pending++
			if len(pendingEx) < maxListed {
				pendingEx = append(pendingEx, fmt.Sprintf("%s: %s", path, r.RowID))
			}
			if run >= 0 {
				for _, i := range m {
					hits[i]++
				}
			}
		} else if report.NeedsFinding(r) {
			unlinked++
			if len(unlinkedEx) < maxListed {
				unlinkedEx = append(unlinkedEx, fmt.Sprintf("%s: %s (%s %s, %s)", path, r.RowID, r.Target.Kind, r.Target.Name, report.ResultKey(r)))
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if h.Mode.Overlay && !c.AllowOverlay {
		return fmt.Errorf("%s: %w", path, ErrOverlayReport)
	}
	c.reports = append(c.reports, path)
	c.rows += rows
	c.failures += failures
	c.linked += linked
	c.unlinked += unlinked
	c.pending += pending
	for _, e := range pendingEx {
		if len(c.pendingEx) < maxListed {
			c.pendingEx = append(c.pendingEx, e)
		}
	}
	c.dangling += dangling
	for _, e := range unlinkedEx {
		if len(c.unlinkedEx) < maxListed {
			c.unlinkedEx = append(c.unlinkedEx, e)
		}
	}
	for _, e := range danglingEx {
		if len(c.danglingEx) < maxListed {
			c.danglingEx = append(c.danglingEx, e)
		}
	}
	for id, n := range refs {
		c.referenced[id] += n
	}
	if run >= 0 {
		c.runs[run] = true
		for i, n := range hits {
			c.hits[i] += n
		}
	}
	return nil
}

// Result is the outcome of a check.
type Result struct {
	Mode    string
	Reports []string
	Rows    int
	// FailureRows counts every failure row; LinkedRows those on sdk, pipeline or core targets whose finding
	// resolves; UnlinkedRows those that carry no finding ID.
	FailureRows, LinkedRows, UnlinkedRows int
	UnlinkedExamples                      []string
	// PendingRows carry no finding ID but match a pending list: accepted in development mode, a failure in
	// acceptance mode.
	PendingRows     int
	PendingExamples []string
	// DanglingRows carry a finding ID with no record.
	DanglingRows     int
	DanglingExamples []string
	Invalid          []string // record problems
	Orphans          []string // records no row refers to
	// PrivateOnly lists records no row refers to whose rows come only from runs with the private overlay.
	PrivateOnly []string
	// SourceReadingOnly lists records no row refers to that were observed by source reading only on a target the
	// kit has no driver column for (Checker.NoDriver): no run can produce their rows.
	SourceReadingOnly []string
	// PrivateRunOnly lists records no row refers to whose evidence.observed is "private-run" and that list no
	// report rows: their rows exist only in the private acceptance run.
	PrivateRunOnly []string
	NonTerminal    []string // "F-NNNN state" for records not in a terminal state
	Records        int
	ByState        map[string]int

	// Governance of the pending lists (pending.go, required.go); empty when no pending lists are loaded.
	//
	// MissingRuns are the required runs whose report is not among the checked ones ("<report> (make <target>)"):
	// a failure in acceptance mode. StalePending are entries that account for no failure row of the required
	// runs that could hold them, all of which were checked: a failure in both modes. UncheckedPending counts the
	// entries whose runs were not all checked. ExpiredPending (older than MaxPendingAge) and UndatedPending (no
	// since) fail acceptance mode; FuturePending (dated after today) fails both.
	MissingRuns      []string
	StalePending     []string
	UncheckedPending int
	ExpiredPending   []string
	UndatedPending   []string
	FuturePending    []string
}

// Passed reports whether the check passed in its mode.
func (r *Result) Passed() bool {
	// Orphans depend on which runs produced the checked reports (a development check usually holds a
	// subset), so they fail only an acceptance check, which runs everything.
	ok := r.UnlinkedRows == 0 && r.DanglingRows == 0 && len(r.Invalid) == 0 &&
		(r.Mode != Acceptance || len(r.Orphans) == 0)
	ok = ok && len(r.StalePending) == 0 && len(r.FuturePending) == 0
	if r.Mode == Acceptance {
		ok = ok && len(r.NonTerminal) == 0 && r.PendingRows == 0 &&
			len(r.MissingRuns) == 0 && len(r.ExpiredPending) == 0 && len(r.UndatedPending) == 0
	}
	return ok
}

// PendingOnly reports whether an acceptance-mode check failed only because rows await finding review: it would
// pass with no such row. Every other failure (a row without a finding ID or pending entry, a row naming no record,
// an invalid or orphaned record, a record not filed, a missing required run, a stale, expired, undated or future
// pending entry) makes it false, as does a check that passed.
func (r *Result) PendingOnly() bool {
	if r.Mode != Acceptance || r.Passed() || r.PendingRows == 0 {
		return false
	}
	c := *r
	c.PendingRows = 0
	return c.Passed()
}

// Finish computes the result. With orphans set, a record that no row of the checked reports refers to fails
// the check, except a not-a-defect record (after the corpus is corrected nothing may show the defect any
// more). A check over a single run's report (xdrcheck replay --findings) leaves orphans unset.
func (c *Checker) Finish(mode string, orphans bool) *Result {
	r := &Result{
		Mode: mode, Reports: c.reports, Rows: c.rows,
		FailureRows: c.failures, LinkedRows: c.linked, UnlinkedRows: c.unlinked, UnlinkedExamples: c.unlinkedEx,
		PendingRows: c.pending, PendingExamples: c.pendingEx,
		DanglingRows: c.dangling, DanglingExamples: c.danglingEx,
		Invalid: append([]string(nil), c.store.Problems...), Records: len(c.store.Records), ByState: map[string]int{},
	}
	c.governance(r)
	for _, id := range c.store.IDs() {
		rec := c.store.Records[id].Record
		r.ByState[rec.State]++
		if !Terminal(rec.State) {
			r.NonTerminal = append(r.NonTerminal, id+" "+rec.State)
		}
		if orphans && c.referenced[id] == 0 && rec.State != "not-a-defect" {
			if c.privateOnly(rec) {
				r.PrivateOnly = append(r.PrivateOnly, id)
			} else if c.sourceReadingOnly(rec) {
				r.SourceReadingOnly = append(r.SourceReadingOnly, id)
			} else if privateRunOnly(rec) {
				r.PrivateRunOnly = append(r.PrivateRunOnly, id)
			} else {
				r.Orphans = append(r.Orphans, id+" ("+rec.State+")")
			}
		}
	}
	return r
}

// governance fills the result's pending-list fields: missing required runs, stale entries and entry ages.
func (c *Checker) governance(r *Result) {
	p := c.Pending
	if p == nil {
		return
	}
	for i, run := range p.Required {
		if !c.runs[i] {
			r.MissingRuns = append(r.MissingRuns, run.Report+" (make "+run.Make+")")
		}
	}
	now := c.Now
	if now.IsZero() {
		now = time.Now()
	}
	today := now.UTC().Truncate(24 * time.Hour)
	for i, e := range p.Entries {
		var since time.Time
		if i < len(p.Sources) {
			since = p.Sources[i].Since
		}
		switch {
		case since.IsZero():
			r.UndatedPending = append(r.UndatedPending, p.Describe(i))
		case since.After(today):
			r.FuturePending = append(r.FuturePending, p.Describe(i)+" since "+since.Format(sinceLayout))
		case today.Sub(since) > MaxPendingAge:
			r.ExpiredPending = append(r.ExpiredPending, p.Describe(i)+" since "+since.Format(sinceLayout))
		}
		if p.Required == nil {
			continue
		}
		scoped, checked := 0, true
		for j, run := range p.Required {
			if inScope(e, run) {
				scoped++
				checked = checked && c.runs[j]
			}
		}
		switch {
		case scoped == 0:
			r.StalePending = append(r.StalePending, p.Describe(i)+": no required run can hold its rows")
		case !checked:
			r.UncheckedPending++
		case c.hits[i] == 0:
			r.StalePending = append(r.StalePending, p.Describe(i)+": accounts for no failure row of the required runs")
		}
	}
}

// sourceReadingOnly reports whether a record was observed by source reading only, lists no report rows, and
// names a target the kit has no driver column for (see Checker.NoDriver).
func (c *Checker) sourceReadingOnly(rec *Record) bool {
	if c.NoDriver == nil || rec.Evidence == nil || rec.Evidence.Observed != ObservedSourceReading || len(rec.Evidence.ReportRows) > 0 {
		return false
	}
	return rec.Target.Package != "" && c.NoDriver(rec.Target.Ecosystem, rec.Target.Package)
}

// privateRunOnly reports whether a record was executed only in the private acceptance run (evidence.observed
// "private-run") and lists no report rows.
func privateRunOnly(rec *Record) bool {
	return rec.Evidence != nil && rec.Evidence.Observed == ObservedPrivateRun && len(rec.Evidence.ReportRows) == 0
}

// privateOnly reports whether every report row a record lists can come only from a private run.
func (c *Checker) privateOnly(rec *Record) bool {
	if c.PrivateRow == nil || rec.Evidence == nil || len(rec.Evidence.ReportRows) == 0 {
		return false
	}
	for _, row := range rec.Evidence.ReportRows {
		if !c.PrivateRow(row) {
			return false
		}
	}
	return true
}

// Print writes the result for a person: the development banner, counts, every problem, and the verdict.
func (r *Result) Print(w io.Writer) {
	if r.Mode == Development {
		fmt.Fprintln(w, DevelopmentBanner)
	}
	states := make([]string, 0, len(r.ByState))
	for s, n := range r.ByState {
		states = append(states, fmt.Sprintf("%s %d", s, n))
	}
	sort.Strings(states)
	fmt.Fprintf(w, "findings check (%s): %d report(s), %d rows, %d failure rows (%d linked to a record, %d pending finding review, %d without a finding ID); %d record(s)",
		r.Mode, len(r.Reports), r.Rows, r.FailureRows, r.LinkedRows, r.PendingRows, r.UnlinkedRows, r.Records)
	if len(states) > 0 {
		fmt.Fprintf(w, " (%s)", strings.Join(states, ", "))
	}
	fmt.Fprintln(w)
	list := func(title string, n int, items []string) {
		if n == 0 {
			return
		}
		fmt.Fprintf(w, "%s: %d\n", title, n)
		for _, it := range items {
			fmt.Fprintln(w, "  "+it)
		}
		if n > len(items) {
			fmt.Fprintf(w, "  … and %d more\n", n-len(items))
		}
	}
	list("FAIL failure rows without a finding ID", r.UnlinkedRows, r.UnlinkedExamples)
	if r.Mode == Acceptance {
		list("FAIL pending finding review: rows that need an approved finding", r.PendingRows, r.PendingExamples)
	} else if r.PendingRows > 0 {
		fmt.Fprintf(w, "pending finding review: %d rows match a pending list (accepted in development mode only)\n", r.PendingRows)
	}
	list("FAIL rows naming a finding that has no record", r.DanglingRows, r.DanglingExamples)
	list("FAIL records that do not validate", len(r.Invalid), r.Invalid)
	if r.Mode == Acceptance {
		list("FAIL records no report row refers to (orphans)", len(r.Orphans), r.Orphans)
	} else {
		list("note: records no checked report row refers to (not a failure in development mode; their runs were not checked)", len(r.Orphans), r.Orphans)
	}
	if len(r.PrivateOnly) > 0 {
		fmt.Fprintf(w, "records whose rows come only from runs with the private overlay (not checked for orphans here): %s\n", strings.Join(r.PrivateOnly, ", "))
	}
	if len(r.SourceReadingOnly) > 0 {
		fmt.Fprintf(w, "records observed by source reading only, on a target with no driver column (no report row can refer to them; exempt from the orphan check): %s\n", strings.Join(r.SourceReadingOnly, ", "))
	}
	if len(r.PrivateRunOnly) > 0 {
		fmt.Fprintf(w, "records with rows only in the private acceptance run (no public report row can refer to them; exempt from the orphan check): %s\n", strings.Join(r.PrivateRunOnly, ", "))
	}
	if r.Mode == Acceptance {
		list("FAIL records not in a terminal state (filed, duplicate-of, not-a-defect)", len(r.NonTerminal), r.NonTerminal)
	}
	list("FAIL stale pending entries (remove them from their list)", len(r.StalePending), r.StalePending)
	list("FAIL pending entries dated in the future", len(r.FuturePending), r.FuturePending)
	days := int(MaxPendingAge.Hours() / 24)
	if r.Mode == Acceptance {
		list("FAIL required runs missing", len(r.MissingRuns), r.MissingRuns)
		list(fmt.Sprintf("FAIL pending entries older than %d days", days), len(r.ExpiredPending), r.ExpiredPending)
		list("FAIL pending entries without a since date", len(r.UndatedPending), r.UndatedPending)
	} else {
		if len(r.MissingRuns) > 0 {
			fmt.Fprintf(w, "note: %d required run(s) not among the checked reports (a failure in acceptance mode): %s\n", len(r.MissingRuns), strings.Join(r.MissingRuns, ", "))
		}
		if n := len(r.ExpiredPending) + len(r.UndatedPending); n > 0 {
			fmt.Fprintf(w, "note: %d pending entries older than %d days or without a since date (a failure in acceptance mode)\n", n, days)
		}
	}
	if r.UncheckedPending > 0 {
		fmt.Fprintf(w, "note: %d pending entries not checked for staleness: not every required run that could hold their rows was checked\n", r.UncheckedPending)
	}
	verdict := "passed"
	if !r.Passed() {
		verdict = "FAILED"
	}
	fmt.Fprintf(w, "findings check (%s): %s\n", r.Mode, verdict)
}
