package xdrcheckcorpus

// Expected-failure lists, in the format `xdrcheck conform run --expected-failures` reads (docs/use-in-sdk-ci.md §7):
// one item per line, `<entry> <variant or -> <level or unread>`, `#` starts a comment, blank lines are ignored.
// An SDK's test records what it did with each variant in Results; Compare passes only when the failures are
// exactly the list: a failure the list does not name is NEW-FAILURE, a listed cell that now passes is
// UNEXPECTED-PASS (remove its line), a listed item of a selected entry the run never saw is NOT-RUN, and, with
// requireAllRead, a variant the SDK never read that the list does not name is NEW-UNREAD.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// UnreadLevel is the level field of a line naming a variant the SDK never reads.
const UnreadLevel = "unread"

// ExpectedFailure is one line of a list.
type ExpectedFailure struct {
	Entry, Variant, Level string // Variant "" for an entry without variants
	Line                  int
}

func (f ExpectedFailure) String() string {
	return fmt.Sprintf("%s %s %s", f.Entry, dash(f.Variant), f.Level)
}

func key(entry, variant, level string) string { return entry + "\x00" + variant + "\x00" + level }

// ReadExpectedFailures reads a list file.
func ReadExpectedFailures(p string) ([]ExpectedFailure, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, errorf("%v", err)
	}
	defer f.Close()
	return ParseExpectedFailures(f, p)
}

// ParseExpectedFailures parses a list; name is used in errors. A line that is not three fields, or an item
// listed twice, is an error.
func ParseExpectedFailures(r io.Reader, name string) ([]ExpectedFailure, error) {
	var out []ExpectedFailure
	seen := map[string]int{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 {
			return nil, errorf("%s:%d: want `<entry> <variant or -> <level or unread>`, got %q", name, n, strings.TrimSpace(line))
		}
		ef := ExpectedFailure{Entry: f[0], Variant: f[1], Level: f[2], Line: n}
		if ef.Variant == "-" {
			ef.Variant = ""
		}
		k := key(ef.Entry, ef.Variant, ef.Level)
		if prev, dup := seen[k]; dup {
			return nil, errorf("%s:%d: %s is already listed on line %d", name, n, ef, prev)
		}
		seen[k] = n
		out = append(out, ef)
	}
	if err := sc.Err(); err != nil {
		return nil, errorf("%s: %v", name, err)
	}
	return out, nil
}

// Cell is one recorded result.
type Cell struct {
	Entry, Variant, Level string
	Failed                bool
	Detail                string
}

// Unread is a variant the SDK never read, with why.
type Unread struct {
	Entry, Variant, Reason string
}

// Results collects what a test did with each variant. It is not safe for concurrent use.
type Results struct {
	Cells    []Cell
	Unreads  []Unread
	selected map[string]bool
}

func (r *Results) mark(entry string) {
	if r.selected == nil {
		r.selected = map[string]bool{}
	}
	r.selected[entry] = true
}

// Select records that the run selected an entry, even if it records nothing for it.
func (r *Results) Select(entry string) { r.mark(entry) }

// Pass records a conforming cell.
func (r *Results) Pass(entry, variant, level string) {
	r.mark(entry)
	r.Cells = append(r.Cells, Cell{Entry: entry, Variant: variant, Level: level})
}

// Fail records a failing cell and what happened.
func (r *Results) Fail(entry, variant, level, detail string) {
	r.mark(entry)
	r.Cells = append(r.Cells, Cell{Entry: entry, Variant: variant, Level: level, Failed: true, Detail: detail})
}

// Unread records a variant the SDK could not read at all (for example a type it does not generate).
func (r *Results) Unread(entry, variant, reason string) {
	r.mark(entry)
	r.Unreads = append(r.Unreads, Unread{Entry: entry, Variant: variant, Reason: reason})
}

// Comparison is a run compared with an expected-failure list.
type Comparison struct {
	Matched    int
	New        []Cell
	NowPassing []Cell
	NowRead    []ExpectedFailure
	NewUnread  []Unread
	NotRun     []ExpectedFailure
}

// Passed reports whether the run's failures (and, under requireAllRead, its unread variants) are exactly the list.
func (c *Comparison) Passed() bool {
	return len(c.New) == 0 && len(c.NowPassing) == 0 && len(c.NowRead) == 0 && len(c.NewUnread) == 0 && len(c.NotRun) == 0
}

// Compare compares the results with a list.
func (r *Results) Compare(list []ExpectedFailure, requireAllRead bool) *Comparison {
	c := &Comparison{}
	listed := map[string]bool{}
	for _, f := range list {
		listed[key(f.Entry, f.Variant, f.Level)] = true
	}
	present := map[string]bool{}
	for _, x := range r.Cells {
		k := key(x.Entry, x.Variant, x.Level)
		present[k] = true
		present[key(x.Entry, x.Variant, UnreadLevel)] = true
		switch {
		case x.Failed && listed[k]:
			c.Matched++
		case x.Failed:
			c.New = append(c.New, x)
		case listed[k]:
			c.NowPassing = append(c.NowPassing, x)
		}
	}
	unread := map[string]bool{}
	for _, u := range r.Unreads {
		k := key(u.Entry, u.Variant, UnreadLevel)
		unread[k], present[k] = true, true
		switch {
		case listed[k]:
			c.Matched++
		case requireAllRead:
			c.NewUnread = append(c.NewUnread, u)
		}
	}
	for _, f := range list {
		k := key(f.Entry, f.Variant, f.Level)
		switch {
		case !present[k]:
			if r.selected[f.Entry] {
				c.NotRun = append(c.NotRun, f)
			}
		case f.Level == UnreadLevel && !unread[k]:
			c.NowRead = append(c.NowRead, f)
		}
	}
	return c
}

// Print writes every difference, with what to do about it, and a summary line naming the SDK under test.
func (c *Comparison) Print(w io.Writer, name, listPath string) {
	for _, x := range c.New {
		fmt.Fprintf(w, "NEW-FAILURE   %s %s %s: %s\n", x.Entry, dash(x.Variant), x.Level, x.Detail)
	}
	for _, x := range c.NowPassing {
		fmt.Fprintf(w, "UNEXPECTED-PASS %s %s %s: listed as failing but now conforms; remove the line from %s\n", x.Entry, dash(x.Variant), x.Level, listPath)
	}
	for _, f := range c.NowRead {
		fmt.Fprintf(w, "UNEXPECTED-PASS %s: listed as unread but the column now reads it; remove the line from %s\n", f, listPath)
	}
	for _, u := range c.NewUnread {
		fmt.Fprintf(w, "NEW-UNREAD    %s %s: never read (%s)\n", u.Entry, dash(u.Variant), u.Reason)
	}
	for _, f := range c.NotRun {
		fmt.Fprintf(w, "NOT-RUN       %s (%s line %d): the run has no such cell; remove the line or fix its spelling\n", f, listPath, f.Line)
	}
	fmt.Fprintf(w, "expected failures %s: %d still as listed, %d new failures, %d new unread, %d unexpected passes, %d listed but not run\n",
		name, c.Matched, len(c.New), len(c.NewUnread), len(c.NowPassing)+len(c.NowRead), len(c.NotRun))
}

// WriteExpectedFailures writes the results' failures and unread variants as a list, each line commented with
// what happened. It returns the number of lines.
func (r *Results) WriteExpectedFailures(w io.Writer, name, corpusVersion string) (int, error) {
	type line struct{ k, text string }
	var lines []line
	for _, x := range r.Cells {
		if x.Failed {
			lines = append(lines, line{key(x.Entry, x.Variant, x.Level), fmt.Sprintf("%s %s %s  # %s", x.Entry, dash(x.Variant), x.Level, oneLine(x.Detail))})
		}
	}
	for _, u := range r.Unreads {
		lines = append(lines, line{key(u.Entry, u.Variant, UnreadLevel), fmt.Sprintf("%s %s %s  # never read: %s", u.Entry, dash(u.Variant), UnreadLevel, oneLine(u.Reason))})
	}
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].k < lines[j].k })
	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, "# Expected corpus failures of %s against corpus %s.\n", name, corpusVersion)
	fmt.Fprintf(bw, "# The test passes only when its failures are exactly these lines: a new failure fails, and so does a listed\n")
	fmt.Fprintf(bw, "# cell that passes (remove its line when a bug is fixed).\n")
	fmt.Fprintf(bw, "# <entry> <variant or -> <level>  # what the SDK did\n")
	fmt.Fprintf(bw, "# <entry> <variant or -> unread   # a variant the SDK never reads\n")
	for _, l := range lines {
		fmt.Fprintln(bw, l.text)
	}
	return len(lines), bw.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
