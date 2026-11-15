package findings

// Report tallies: what a findings check takes from one report, with no row in it.
//
// CI uploads a reports directory only after scripts/ci/withhold-pending.py has run on it, and that script deletes
// every linter report that names a site pending finding review: the report's rows carry the file, line and
// message the findings check needs to match the row to its site hash, so the report cannot be redacted and stay
// checkable. A downstream findings check (make verify-findings, make verify-findings-acceptance, findings-linked of the
// acceptance table) would then count that run as not checked. A tally stands in for such a report: the job that
// still has the report computes, through this Checker, everything AddReport takes from it (row and failure
// counts, the finding IDs its rows name, and how many rows each pending entry accounts for, keyed by the
// committed list and index), and writes it to <reports>/<make target>.tally.json, a file that names no site,
// row or message, so it is uploaded while the report is withheld. A check that finds a required run's report
// absent and its tally present adds the tally instead; with the report present the tally is ignored. A check
// over the report and one over its tally give the same Result counts.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

// TallySchema is the schema ID of a tally file.
const TallySchema = "xdrcheck.findings-tally/v1"

// TallySuffix ends a tally file's name: <make target>.tally.json at the top of the reports directory.
const TallySuffix = ".tally.json"

// TallyFile is one make target's tallies.
type TallyFile struct {
	Schema string        `json:"schema"`
	Make   string        `json:"make"`
	Runs   []ReportTally `json:"runs"`
}

// ReportTally is what a findings check takes from one required run's report.
type ReportTally struct {
	// Report is the run's report path relative to the reports directory (RequiredRun.Report); SHA256 the hex
	// SHA-256 of the report file the tally was computed from.
	Report string `json:"report"`
	SHA256 string `json:"sha256"`
	// Overlay is whether the report was made with the private overlay.
	Overlay bool `json:"overlay"`
	Rows    int  `json:"rows"`
	// Failures, Linked, Unlinked, Pending and Dangling count rows as Checker.AddReport does.
	Failures int `json:"failures"`
	Linked   int `json:"linked"`
	Unlinked int `json:"unlinked"`
	Pending  int `json:"pending"`
	Dangling int `json:"dangling"`
	// Refs counts the rows naming each finding ID.
	Refs map[string]int `json:"refs"`
	// PendingHits are the failure rows each pending entry accounts for, by the entry's list and index.
	PendingHits []PendingHit `json:"pending_hits"`
}

// PendingHit is the number of rows one pending entry accounts for.
type PendingHit struct {
	List  string `json:"list"` // the pending list, relative to the repository root
	Index int    `json:"index"`
	Rows  int    `json:"rows"`
}

// Tally computes the tally of the report at path, which must be one of the required runs of c.Pending. The
// tally is computed by a Checker over this report alone, with c's records, pending lists and overlay setting.
func (c *Checker) Tally(path string) (*ReportTally, error) {
	if c.Pending == nil || c.Pending.Required == nil {
		return nil, errors.New("no required run set: a tally stands in only for a required run's report")
	}
	run := runFor(c.Pending.Required, path)
	if run < 0 {
		return nil, fmt.Errorf("%s is not the report of a required run", path)
	}
	sum, err := fileSHA256(path)
	if err != nil {
		return nil, err
	}
	one := NewChecker(c.store)
	one.AllowOverlay, one.Pending = c.AllowOverlay, c.Pending
	if err := one.AddReport(path); err != nil {
		return nil, err
	}
	h, _, err := report.ReadFile(path, func(*report.Row) error { return nil })
	if err != nil {
		return nil, err
	}
	overlay := h.Mode.Overlay
	t := &ReportTally{
		Report: c.Pending.Required[run].Report, SHA256: sum, Overlay: overlay,
		Rows: one.rows, Failures: one.failures, Linked: one.linked, Unlinked: one.unlinked,
		Pending: one.pending, Dangling: one.dangling, Refs: map[string]int{},
	}
	for id, n := range one.referenced {
		t.Refs[id] = n
	}
	for i, n := range one.hits {
		src := c.Pending.Sources[i]
		t.PendingHits = append(t.PendingHits, PendingHit{List: src.File, Index: src.Index, Rows: n})
	}
	sort.Slice(t.PendingHits, func(a, b int) bool {
		x, y := t.PendingHits[a], t.PendingHits[b]
		return x.List < y.List || x.List == y.List && x.Index < y.Index
	})
	return t, nil
}

// AddTally adds a tally in place of its report, as AddReport would have added the report. It fails on a tally
// that is not a required run's, one made with the overlay unless AllowOverlay is set, and one naming a pending
// entry the loaded lists do not have.
func (c *Checker) AddTally(t *ReportTally) error {
	if c.Pending == nil || c.Pending.Required == nil {
		return errors.New("no required run set: a tally stands in only for a required run's report")
	}
	run := -1
	for i, r := range c.Pending.Required {
		if r.Report == t.Report {
			run = i
		}
	}
	if run < 0 {
		return fmt.Errorf("tally of %s: not the report of a required run", t.Report)
	}
	if t.Overlay && !c.AllowOverlay {
		return fmt.Errorf("tally of %s: %w", t.Report, ErrOverlayReport)
	}
	entry := map[[2]any]int{}
	for i, s := range c.Pending.Sources {
		entry[[2]any{s.File, s.Index}] = i
	}
	hits := map[int]int{}
	for _, h := range t.PendingHits {
		i, ok := entry[[2]any{h.List, h.Index}]
		if !ok {
			return fmt.Errorf("tally of %s: pending entry %s[%d] is not in the loaded lists", t.Report, h.List, h.Index)
		}
		hits[i] += h.Rows
	}
	c.reports = append(c.reports, t.Report+" (withheld; its tally read)")
	c.rows += t.Rows
	c.failures += t.Failures
	c.linked += t.Linked
	c.unlinked += t.Unlinked
	c.pending += t.Pending
	c.dangling += t.Dangling
	where := t.Report + " (withheld from this directory; counted from its tally, the rows are in the job's log)"
	if t.Unlinked > 0 && len(c.unlinkedEx) < maxListed {
		c.unlinkedEx = append(c.unlinkedEx, fmt.Sprintf("%s: %d row(s)", where, t.Unlinked))
	}
	if t.Pending > 0 && len(c.pendingEx) < maxListed {
		c.pendingEx = append(c.pendingEx, fmt.Sprintf("%s: %d row(s)", where, t.Pending))
	}
	if t.Dangling > 0 && len(c.danglingEx) < maxListed {
		c.danglingEx = append(c.danglingEx, fmt.Sprintf("%s: %d row(s)", where, t.Dangling))
	}
	for id, n := range t.Refs {
		c.referenced[id] += n
	}
	c.runs[run] = true
	for i, n := range hits {
		c.hits[i] += n
	}
	return nil
}

// ReadTallies reads every <name>.tally.json at the top of dir, keyed by report path. A tally file that does not
// read, or two tallies of one report, are errors.
func ReadTallies(dir string) (map[string]*ReportTally, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*"+TallySuffix))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	out := map[string]*ReportTally{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var tf TallyFile
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&tf); err != nil {
			return nil, fmt.Errorf("%s: %v", f, err)
		}
		if tf.Schema != TallySchema {
			return nil, fmt.Errorf("%s: schema %q, want %q", f, tf.Schema, TallySchema)
		}
		for i := range tf.Runs {
			t := &tf.Runs[i]
			if _, dup := out[t.Report]; dup {
				return nil, fmt.Errorf("%s: a second tally of %s", f, t.Report)
			}
			out[t.Report] = t
		}
	}
	return out, nil
}

// WriteTallies writes the tallies of make target's required runs whose reports are under dir to
// dir/<target>.tally.json, and returns the reports tallied. A target with no report under dir is an error.
func (c *Checker) WriteTallies(dir, target string, w io.Writer) ([]string, error) {
	if c.Pending == nil || c.Pending.Required == nil {
		return nil, errors.New("no required run set: a tally stands in only for a required run's report")
	}
	tf := TallyFile{Schema: TallySchema, Make: target, Runs: []ReportTally{}}
	var done []string
	known := false
	for _, r := range c.Pending.Required {
		if r.Make != target {
			continue
		}
		known = true
		p := filepath.Join(dir, filepath.FromSlash(r.Report))
		if _, err := os.Stat(p); err != nil {
			continue
		}
		t, err := c.Tally(p)
		if err != nil {
			return nil, err
		}
		tf.Runs = append(tf.Runs, *t)
		done = append(done, r.Report)
	}
	switch {
	case !known:
		return nil, fmt.Errorf("make target %s writes no report of the required run set", target)
	case len(done) == 0:
		return nil, fmt.Errorf("no report of make %s under %s", target, dir)
	}
	data, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		return nil, err
	}
	out := filepath.Join(dir, target+TallySuffix)
	if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
		return nil, err
	}
	if w != nil {
		fmt.Fprintf(w, "findings tally: %s: %d report(s) of make %s\n", out, len(done), target)
	}
	return done, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
