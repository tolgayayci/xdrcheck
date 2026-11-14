package verdict

// Expected-failure lists, in the manner of the protobuf conformance suite's failure lists: an SDK's own CI keeps
// a file naming the cells its column is known to get wrong, and `xdrcheck conform run --expected-failures FILE`
// passes only when the run's failures are exactly that list. A new failure fails the run, and so does a listed
// cell that no longer fails (an unexpected pass): the list must shrink when a bug is fixed, so it never hides a
// regression behind a stale line.
//
// A failure is a cell whose verdict differs from the corpus (FailureVerdict): wrong value, accepts an invalid
// input, refuses a valid one, crashes, or a json-level failure. Whether the corpus declares the divergence on its
// entry does not matter here; the list is the SDK's own account of where it stands.
//
// The same list accounts for the entry variants the column never reads (conform.Result.Unread: every level n/a,
// for example an api operation the SDK has no function for), with the level written `unread`. Under
// --require-all-read an unread entry variant the list does not name fails the run; a listed one that the column
// now reads fails it always, like an unexpected pass.
//
// File format: one item per line, `<entry> <variant> <level or unread>` separated by blanks, the variant `-` for
// an entry without variants (api, strkey); `#` starts a comment, to the end of the line; blank lines are
// ignored. The file is for one column; `--write-expected-failures FILE` writes it from a run.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
)

// UnreadLevel is the level field of a list line that names an entry variant the column never reads.
const UnreadLevel = "unread"

// ExpectedFailure is one line of an expected-failure list.
type ExpectedFailure struct {
	Entry, Variant, Level string // Variant "" for an entry without variants; Level UnreadLevel for an unread item
	Line                  int
}

func (f ExpectedFailure) String() string {
	return fmt.Sprintf("%s %s %s", f.Entry, orDash(f.Variant), f.Level)
}

func (f ExpectedFailure) key() string { return RowKey(f.Entry, f.Variant, f.Level) }

// ReadExpectedFailures reads an expected-failure list. A line that is not three fields, or a cell listed twice,
// is an error.
func ReadExpectedFailures(path string) ([]ExpectedFailure, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseExpectedFailures(f, path)
}

// ParseExpectedFailures parses an expected-failure list; name is used in errors.
func ParseExpectedFailures(r io.Reader, name string) ([]ExpectedFailure, error) {
	var out []ExpectedFailure
	seen := map[string]int{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 {
			return nil, fmt.Errorf("%s:%d: want `<entry> <variant or -> <level or unread>`, got %q", name, n, strings.TrimSpace(line))
		}
		ef := ExpectedFailure{Entry: fields[0], Variant: fields[1], Level: fields[2], Line: n}
		if ef.Variant == "-" {
			ef.Variant = ""
		}
		if prev, dup := seen[ef.key()]; dup {
			return nil, fmt.Errorf("%s:%d: %s is already listed on line %d", name, n, ef, prev)
		}
		seen[ef.key()] = n
		out = append(out, ef)
	}
	return out, sc.Err()
}

// FailureListResult is a run's failures compared with an expected-failure list.
type FailureListResult struct {
	Column     string
	Matched    int               // listed cells that still fail, and listed entry variants still unread
	New        []Cell            // failing cells the list does not name
	NowPassing []Cell            // listed cells that no longer fail: conform, or n/a
	NowRead    []ExpectedFailure // listed as unread, but the column read them
	NewUnread  []conform.Unread  // unread entry variants the list does not name (counted only under require-all-read)
	NotRun     []ExpectedFailure // listed items of selected entries that the run does not have
}

// Passed reports whether the run's failures (and, under require-all-read, its unread entries) are exactly the
// list.
func (r *FailureListResult) Passed() bool {
	return len(r.New) == 0 && len(r.NowPassing) == 0 && len(r.NowRead) == 0 && len(r.NewUnread) == 0 && len(r.NotRun) == 0
}

// CompareFailures compares the column's failing cells and unread entry variants with the list. selected says
// whether an entry was selected by the run (its --entries globs): a listed item of an entry the run did not
// select is ignored, so one list serves runs of a subset; a listed item of a selected entry that the run does not
// have is NotRun. requireAllRead makes an unread entry variant the list does not name a difference.
func (m *Matrix) CompareFailures(column string, list []ExpectedFailure, selected func(entry string) bool, requireAllRead bool) *FailureListResult {
	res := &FailureListResult{Column: column}
	listed := map[string]bool{}
	for _, f := range list {
		listed[f.key()] = true
	}
	present := map[string]bool{}
	for _, c := range m.Cells {
		if c.Column != column {
			continue
		}
		k := RowKey(c.Entry, c.Variant, c.Level)
		present[k] = true
		present[RowKey(c.Entry, c.Variant, UnreadLevel)] = true
		switch fails := FailureVerdict(c.Verdict); {
		case fails && listed[k]:
			res.Matched++
		case fails:
			res.New = append(res.New, c)
		case listed[k]:
			res.NowPassing = append(res.NowPassing, c)
		}
	}
	unread := map[string]bool{}
	for _, u := range m.Unread {
		if u.Column != column {
			continue
		}
		k := RowKey(u.Entry, u.Variant, UnreadLevel)
		unread[k] = true
		switch {
		case listed[k]:
			res.Matched++
		case requireAllRead:
			res.NewUnread = append(res.NewUnread, u)
		}
	}
	for _, f := range list {
		switch {
		case !present[f.key()]:
			if selected == nil || selected(f.Entry) {
				res.NotRun = append(res.NotRun, f)
			}
		case f.Level == UnreadLevel && !unread[f.key()]:
			res.NowRead = append(res.NowRead, f)
		}
	}
	return res
}

// Print writes the comparison: every new failure, unexpected pass and listed cell not run, with what to do.
func (r *FailureListResult) Print(w io.Writer, listPath string) {
	for i := range r.New {
		c := &r.New[i]
		fmt.Fprintf(w, "NEW-FAILURE   %s %s %s: %s\n", c.Entry, orDash(c.Variant), c.Level, Answer(c))
	}
	for i := range r.NowPassing {
		c := &r.NowPassing[i]
		what := "now conforms"
		if c.Verdict == "n_a" {
			what = "is now n/a (" + orDash(c.Reason) + ")"
		}
		fmt.Fprintf(w, "UNEXPECTED-PASS %s %s %s: listed as failing but %s; remove the line from %s\n", c.Entry, orDash(c.Variant), c.Level, what, listPath)
	}
	for _, f := range r.NowRead {
		fmt.Fprintf(w, "UNEXPECTED-PASS %s: listed as unread but the column now reads it; remove the line from %s\n", f, listPath)
	}
	for _, u := range r.NewUnread {
		fmt.Fprintf(w, "NEW-UNREAD    %s %s: never read (%s)\n", u.Entry, orDash(u.Variant), strings.Join(u.Reasons, ", "))
	}
	for _, f := range r.NotRun {
		fmt.Fprintf(w, "NOT-RUN       %s (%s line %d): the run has no such cell for %s; remove the line or fix its spelling\n", f, listPath, f.Line, r.Column)
	}
	fmt.Fprintf(w, "expected failures %s: %d still as listed, %d new failures, %d new unread, %d unexpected passes, %d listed but not run\n",
		r.Column, r.Matched, len(r.New), len(r.NewUnread), len(r.NowPassing)+len(r.NowRead), len(r.NotRun))
}

// WriteExpectedFailures writes the column's failing cells, and the entry variants it never read, as an
// expected-failure list, each line with a comment saying what the column did and the divergence or finding,
// when the corpus declares one. It returns the number of lines.
func (m *Matrix) WriteExpectedFailures(w io.Writer, column string) (int, error) {
	type line struct{ key, text string }
	var lines []line
	for i := range m.Cells {
		c := &m.Cells[i]
		if c.Column != column || !FailureVerdict(c.Verdict) {
			continue
		}
		note := Answer(c)
		if c.KnownDivergence != nil || c.Check == "undeclared" {
			note += "; " + Status(c)
		}
		lines = append(lines, line{RowKey(c.Entry, c.Variant, c.Level), fmt.Sprintf("%s %s %s  # %s", c.Entry, orDash(c.Variant), c.Level, oneLine(note, 400))})
	}
	for _, u := range m.Unread {
		if u.Column == column {
			lines = append(lines, line{RowKey(u.Entry, u.Variant, UnreadLevel), fmt.Sprintf("%s %s %s  # never read: %s", u.Entry, orDash(u.Variant), UnreadLevel, strings.Join(u.Reasons, ", "))})
		}
	}
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].key < lines[j].key })
	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, "# Expected conformance failures of %s against corpus %s.\n", column, m.Corpus.Version)
	fmt.Fprintf(bw, "# xdrcheck conform run --columns '%s' --expected-failures FILE passes only when the run's failures are exactly\n", column)
	fmt.Fprintf(bw, "# these lines: a new failure fails, and so does a listed cell that passes (remove its line when a bug is fixed).\n")
	fmt.Fprintf(bw, "# <entry> <variant or -> <level>  # what the column did; the divergence the corpus declares, if any\n")
	fmt.Fprintf(bw, "# <entry> <variant or -> unread   # an entry variant the column never reads (every level n/a)\n")
	for _, l := range lines {
		fmt.Fprintln(bw, l.text)
	}
	return len(lines), bw.Flush()
}
