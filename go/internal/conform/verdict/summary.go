package verdict

// The conformance summary (SUMMARY.md, and the first thing `xdrcheck conform run` prints): only the rows a reader acts
// on, each with what the corpus expects, what each SDK answered, which SDK is wrong, the declared divergence or
// finding if any, and the command that reruns just that row. The full grid stays in matrix.md.

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Row kinds, in the order the summary lists them.
const (
	RowNew      = "new"      // a cell `xdrcheck conform check` fails on: a divergence no entry declares, or a stale declaration
	RowUntriage = "untriage" // only undeclared cells that the committed list names as not yet triaged
	RowKnown    = "known"    // every wrong cell is a declared known divergence
	RowSplit    = "split"    // no column is wrong against the corpus, but the SDKs' latest columns disagree
)

// ActionRow is one entry, variant and level that needs a reader's attention.
type ActionRow struct {
	Kind     string
	Entry    string
	Variant  string
	Level    string
	Caps     []int
	Class    string // the entry's validity and bug-class flags (BugClass)
	Expected string // what the corpus expects (ExpectedValue), never what a reader produced
	Wrong    []Cell // cells whose verdict is a failure, and conforming cells inside a declared range
	Conform  []string
	NA       []string
	Classes  map[string][]string // the cross-SDK classes, for a split row
}

// FailureVerdict reports whether a verdict says the column got the cell wrong against the corpus.
func FailureVerdict(v string) bool {
	return v != "conform" && v != "n_a" && v != ""
}

// ActionRows returns the rows that need attention, new problems first, then divergences not yet triaged,
// then known divergences, then cross-SDK splits no column is judged wrong for; within a kind, by entry,
// variant and level.
func (m *Matrix) ActionRows() []ActionRow {
	caps := map[string][]int{}
	class := map[string]string{}
	for _, e := range m.Entries {
		caps[e.ID] = e.Caps
		class[e.ID] = BugClass(&e)
	}
	rows := map[string]*ActionRow{}
	var keys []string
	for _, c := range m.Cells {
		k := RowKey(c.Entry, c.Variant, c.Level)
		r := rows[k]
		if r == nil {
			r = &ActionRow{Entry: c.Entry, Variant: c.Variant, Level: c.Level, Caps: caps[c.Entry], Class: class[c.Entry], Expected: m.Expectations[k]}
			rows[k] = r
			keys = append(keys, k)
		}
		switch {
		case FailureVerdict(c.Verdict) || c.Check == "unexpected-conform":
			r.Wrong = append(r.Wrong, c)
		case c.Verdict == "n_a":
			r.NA = append(r.NA, c.Column)
		default:
			r.Conform = append(r.Conform, c.Column)
		}
	}
	split := map[string]map[string][]string{}
	for _, x := range m.CrossSDK {
		if !x.Agree {
			split[RowKey(x.Entry, x.Variant, x.Level)] = x.Classes
		}
	}
	rank := map[string]int{RowNew: 0, RowUntriage: 1, RowKnown: 2, RowSplit: 3}
	var out []ActionRow
	for _, k := range keys {
		r := rows[k]
		r.Classes = split[k]
		switch {
		case len(r.Wrong) == 0 && r.Classes != nil:
			r.Kind = RowSplit
		case len(r.Wrong) == 0:
			continue
		default:
			r.Kind = RowKnown
			for _, c := range r.Wrong {
				switch {
				case FailingCheck(c.Check) && !(c.Check == "undeclared" && c.PendingReview):
					r.Kind = RowNew
				case c.Check == "undeclared" && r.Kind != RowNew:
					r.Kind = RowUntriage
				}
			}
		}
		out = append(out, *r)
	}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Kind] < rank[out[j].Kind] })
	return out
}

// Answer is a column's answer to a cell in words: what it did, and for a wrong value the first difference
// from the corpus.
func Answer(c *Cell) string {
	msg := ""
	if len(c.Evidence) > 0 {
		var ev struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(c.Evidence, &ev) == nil && ev.Message != "" {
			msg = ": " + oneLine(ev.Message, 70)
		}
	}
	switch {
	case c.Verdict == "crash":
		return "crashed (" + orDash(c.Reason) + ")" + msg
	case c.Outcome == "reject":
		return "refused (" + orDash(c.Reason) + ")" + msg
	case c.Verdict == "accepts_invalid":
		return "accepted an input that must be refused"
	case c.Verdict == "n_a":
		return "n/a (" + orDash(c.Reason) + ")"
	case c.Verdict == "conform":
		return "conforms"
	}
	for _, n := range c.Notes {
		if mismatchNote(n) {
			return "accepted, but " + oneLine(n, 140)
		}
	}
	return "accepted with a value that differs from the corpus"
}

// mismatchNote reports whether an engine note is a difference from the corpus (compare's notes start with the
// level they are about; a driver-reported mismatch with "driver:").
func mismatchNote(n string) bool {
	for _, p := range []string{"L0:", "L1:", "L2:", "L3:", "L4:", "spec:", "json:", "driver:"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// Status says where a wrong cell stands: a declared known divergence (with its reference and finding), a
// divergence not yet triaged, a new one, or a declaration that no longer matches.
func Status(c *Cell) string {
	ref := ""
	if k := c.KnownDivergence; k != nil {
		ref = k.Reference
		if c.Finding != "" {
			ref += ", finding " + c.Finding
		}
	}
	switch c.Check {
	case "known":
		return "known divergence (" + ref + ")"
	case "unexpected-conform":
		return "conforms although a known divergence covers this version (" + ref + "): the declared range is stale"
	case "known-changed":
		return "differs from the declared known divergence (" + ref + ")"
	case "undeclared":
		if c.PendingReview {
			return "known divergence, not yet triaged"
		}
		return "new: no entry declares it"
	}
	return c.Check
}

// Repro is the command that reruns one row on the given columns.
func Repro(entry, level string, columns []string) string {
	return fmt.Sprintf("xdrcheck conform run --columns '%s' --entries '%s' --levels %s", strings.Join(columns, ","), entry, level)
}

// SchemaGated counts the cells that are n_a because the variant needs XDR newer than the column's SDK has and
// the SDK refused it cleanly, as expected (matrix.md shows them as "–").
func (m *Matrix) SchemaGated() int {
	n := 0
	for _, c := range m.Cells {
		if c.Verdict == "n_a" && c.OutOfReach {
			n++
		}
	}
	return n
}

func capList(caps []int) string {
	if len(caps) == 0 {
		return "-"
	}
	parts := make([]string, len(caps))
	for i, c := range caps {
		parts[i] = fmt.Sprintf("CAP-%04d", c)
	}
	return strings.Join(parts, ", ")
}

// describedVersion is the sdk.version a column's describe reported, or "-".
func describedVersion(raw json.RawMessage) string {
	var sdk struct {
		Package string `json:"package"`
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &sdk) != nil || sdk.Version == "" {
		return "-"
	}
	return sdk.Package + " " + sdk.Version
}

// BugClass is an entry's validity and bug-class flags in words (docs/manifest.md §9.5): "malformed:
// trailing-bytes", "valid: depth", "valid"; "-" when the matrix does not have them.
func BugClass(e *MatrixEntry) string {
	v := e.Validity
	if v == "" {
		v = "-"
	}
	if len(e.Flags) == 0 {
		return v
	}
	return v + ": " + strings.Join(e.Flags, ", ")
}

func rowTitle(r *ActionRow) string {
	return fmt.Sprintf("%s · %s · %s", r.Entry, orDash(r.Variant), r.Level)
}

func wrongColumns(r *ActionRow) []string {
	var cols []string
	for _, c := range r.Wrong {
		cols = append(cols, c.Column)
	}
	return cols
}

var kindTitle = map[string]string{
	RowNew:      "New: not declared on any entry, or a declaration that no longer matches",
	RowUntriage: "Known, not yet triaged",
	RowKnown:    "Known divergences",
	RowSplit:    "SDKs disagree, none judged wrong against the corpus",
}

// counts returns the number of rows of each kind.
func counts(rows []ActionRow) map[string]int {
	n := map[string]int{}
	for _, r := range rows {
		n[r.Kind]++
	}
	return n
}

func headline(rows []ActionRow) string {
	n := counts(rows)
	return fmt.Sprintf("%d new, %d known but not yet triaged, %d known divergences, %d cross-SDK splits with no SDK judged wrong",
		n[RowNew], n[RowUntriage], n[RowKnown], n[RowSplit])
}

// SummaryMarkdown writes SUMMARY.md.
func (m *Matrix) SummaryMarkdown(w io.Writer) {
	rows := m.ActionRows()
	fmt.Fprintf(w, "# Conformance summary\n\nCorpus %s. %d columns, %d cells. Rows that need a look: %s.\n\n",
		m.Corpus.Version, len(m.Columns), len(m.Cells), headline(rows))
	fmt.Fprintf(w, "Each row is one entry, variant and level. **Expected** comes from the corpus (the bytes and the entry's stated expectation), never from an SDK. The full grid is in [%s](%s); SDK-against-SDK splits are in [%s](%s).\n",
		MarkdownFile, MarkdownFile, CrossSDKFile, CrossSDKFile)
	for _, c := range m.Columns {
		if c.Source != "" {
			fmt.Fprintf(w, "\nColumn %s was built from the SDK checkout %s (it reports itself as %s); known divergences are judged against the pinned version %s, so a bug the checkout fixes shows as unexpected-conform.\n",
				c.ID, c.Source, describedVersion(c.Describe), c.Version)
		}
	}
	if len(m.Infrastructure) > 0 {
		fmt.Fprintf(w, "\n## The run itself had problems\n\n")
		for _, p := range m.Infrastructure {
			fmt.Fprintf(w, "- %s\n", p)
		}
	}
	kind := ""
	for i := range rows {
		r := &rows[i]
		if r.Kind != kind {
			kind = r.Kind
			fmt.Fprintf(w, "\n## %s (%d)\n", kindTitle[kind], counts(rows)[kind])
		}
		fmt.Fprintf(w, "\n### `%s` · %s · %s\n\n", r.Entry, orDash(r.Variant), r.Level)
		fmt.Fprintf(w, "- CAPs: %s\n- Bug class: %s\n- Expected: %s\n", capList(r.Caps), r.Class, r.Expected)
		for j := range r.Wrong {
			c := &r.Wrong[j]
			fmt.Fprintf(w, "- **%s**: %s — %s\n", c.Column, Answer(c), Status(c))
		}
		if r.Kind == RowSplit {
			fmt.Fprintf(w, "- Answers by class: %s\n", classList(r.Classes))
		}
		if len(r.Conform) > 0 {
			fmt.Fprintf(w, "- Conform: %s\n", strings.Join(r.Conform, ", "))
		}
		if len(r.NA) > 0 {
			fmt.Fprintf(w, "- n/a: %s\n", strings.Join(r.NA, ", "))
		}
		if cols := wrongColumns(r); len(cols) > 0 {
			fmt.Fprintf(w, "- Wrong: %s\n- Repro: `%s`\n", strings.Join(cols, ", "), Repro(r.Entry, r.Level, cols))
		} else {
			fmt.Fprintf(w, "- Repro: `%s`\n", Repro(r.Entry, r.Level, splitColumns(r.Classes)))
		}
	}
	if len(rows) == 0 {
		fmt.Fprintf(w, "\nEvery column conforms or is a declared known divergence on every cell, and the SDKs agree.\n")
	}
	if n := m.SchemaGated(); n > 0 {
		fmt.Fprintf(w, "\n## Not shown\n\n- %d cells where the variant needs XDR newer than the column's SDK has, and the SDK refused it cleanly (an undeclared union arm or enum value), as expected. matrix.md shows them as \"–\".\n", n)
	}
	if len(m.NotExercised) > 0 {
		fmt.Fprintf(w, "- %d known divergences this run did not exercise (no selected column in their version range, or every such cell n/a); listed at the end of matrix.md.\n", len(m.NotExercised))
	}
	if len(m.Unread) > 0 {
		fmt.Fprintf(w, "\n## Entries a column never read (%d)\n\nNo cell of the column read these entry variants: every level answered n/a, or the driver declares no level they need. `xdrcheck conform run --require-all-read` fails on them unless an expected-failure list names them.\n\n", len(m.Unread))
		per := map[string]int{}
		var cols []string
		for _, u := range m.Unread {
			if per[u.Column] == 0 {
				cols = append(cols, u.Column)
			}
			per[u.Column]++
		}
		for _, c := range cols {
			fmt.Fprintf(w, "- %s: %d\n", c, per[c])
		}
		fmt.Fprintf(w, "\n<details><summary>The %d entry variants, with why</summary>\n\n", len(m.Unread))
		for _, u := range m.Unread {
			fmt.Fprintf(w, "- %s `%s` %s: %s\n", u.Column, u.Entry, orDash(u.Variant), strings.Join(u.Reasons, ", "))
		}
		fmt.Fprintf(w, "\n</details>\n")
	}
}

// SummaryText writes the console form of the summary: one block per new or untriaged row, one line per known
// divergence and split.
func (m *Matrix) SummaryText(w io.Writer) {
	rows := m.ActionRows()
	fmt.Fprintf(w, "Conformance summary: %s.\n", headline(rows))
	for i := range rows {
		r := &rows[i]
		switch r.Kind {
		case RowNew, RowUntriage:
			tag := "NEW"
			if r.Kind == RowUntriage {
				tag = "UNTRIAGED"
			}
			fmt.Fprintf(w, "%-9s %s (%s)\n          expected: %s\n", tag, rowTitle(r), capList(r.Caps), r.Expected)
			for j := range r.Wrong {
				c := &r.Wrong[j]
				fmt.Fprintf(w, "          %s: %s — %s\n", c.Column, Answer(c), Status(c))
			}
			fmt.Fprintf(w, "          repro: %s\n", Repro(r.Entry, r.Level, wrongColumns(r)))
		case RowKnown:
			var refs []string
			seen := map[string]bool{}
			for _, c := range r.Wrong {
				if k := c.KnownDivergence; k != nil && !seen[k.Reference] {
					seen[k.Reference] = true
					refs = append(refs, k.Reference)
				}
			}
			fmt.Fprintf(w, "KNOWN     %s: %s (%s)\n", rowTitle(r), strings.Join(wrongColumns(r), ", "), strings.Join(refs, ", "))
		case RowSplit:
			fmt.Fprintf(w, "SPLIT     %s: %s\n", rowTitle(r), classList(r.Classes))
		}
	}
	if n := m.SchemaGated(); n > 0 {
		fmt.Fprintf(w, "(%d cells refused cleanly because the column's SDK predates the variant's XDR are expected and not listed.)\n", n)
	}
}

func classList(classes map[string][]string) string {
	var ks []string
	for k := range classes {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var parts []string
	for _, k := range ks {
		parts = append(parts, fmt.Sprintf("%s: %s", k, strings.Join(classes[k], ", ")))
	}
	return strings.Join(parts, "; ")
}

func splitColumns(classes map[string][]string) []string {
	var cols []string
	for _, cs := range classes {
		cols = append(cols, cs...)
	}
	sort.Strings(cols)
	return cols
}

func oneLine(s string, max int) string {
	r := []rune(strings.Join(strings.Fields(s), " "))
	if len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return string(r)
}
